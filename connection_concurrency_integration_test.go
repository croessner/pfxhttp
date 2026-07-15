package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const (
	concurrencyTestHost       = "127.0.0.1"
	concurrencyTestMap        = "lookup_map"
	concurrencyTestSASL       = "smtp_auth"
	concurrencyFreshKey       = "fresh@example.test"
	concurrencyMappedReply    = "OK mapped"
	concurrencyProbeTimeout   = 100 * time.Millisecond
	concurrencyCleanupTimeout = 2 * time.Second
)

func TestPersistentConnectionsDoNotStarveSocketMapRequestsAcrossListeners(t *testing.T) {
	deps, backendStarted := newConcurrencyTestDeps(t)
	saslListener := startObservedServer(t, deps, 1, Listen{
		Kind: listenKindDovecotSASL,
		Name: concurrencyTestSASL,
		Type: listenTypeTCP,
	})
	mapListener := startObservedServer(t, deps, 2, Listen{
		Kind: listenKindSocketMap,
		Name: concurrencyTestMap,
		Type: listenTypeTCP,
	})

	saslConn, saslAccepted := dialObservedConnection(t, saslListener)
	t.Cleanup(func() { _ = saslConn.Close() })
	completeDovecotClientHandshake(t, saslConn)
	waitForHandlerStart(t, saslAccepted)

	idleMapConn, idleAccepted := dialObservedConnection(t, mapListener)
	t.Cleanup(func() { _ = idleMapConn.Close() })
	completeSocketMapLookup(t, idleMapConn, "holder@example.test")
	waitForActiveRead(t, idleAccepted)

	assertFreshLookupServiceable(t, mapListener, backendStarted, idleMapConn, idleAccepted)
}

func TestIdleSocketMapConnectionsDoNotStarveRequestsWithinListener(t *testing.T) {
	deps, backendStarted := newConcurrencyTestDeps(t)
	mapListener := startObservedServer(t, deps, 3, Listen{
		Kind: listenKindSocketMap,
		Name: concurrencyTestMap,
		Type: listenTypeTCP,
	})

	firstIdle, firstAccepted := dialObservedConnection(t, mapListener)
	t.Cleanup(func() { _ = firstIdle.Close() })
	completeSocketMapLookup(t, firstIdle, "first-holder@example.test")
	waitForActiveRead(t, firstAccepted)
	secondIdle, secondAccepted := dialObservedConnection(t, mapListener)
	t.Cleanup(func() { _ = secondIdle.Close() })
	completeSocketMapLookup(t, secondIdle, "second-holder@example.test")
	waitForActiveRead(t, secondAccepted)

	assertFreshLookupServiceable(t, mapListener, backendStarted, firstIdle, firstAccepted)
}

func TestSocketMapListenerHandlesBackToBackRequestsOnOneConnection(t *testing.T) {
	deps, _ := newConcurrencyTestDeps(t)
	listener := startObservedServer(t, deps, 1, Listen{
		Kind: listenKindSocketMap,
		Name: concurrencyTestMap,
		Type: listenTypeTCP,
	})

	conn, accepted := dialObservedConnection(t, listener)
	t.Cleanup(func() { _ = conn.Close() })
	completeSocketMapLookup(t, conn, "first@example.test")
	completeSocketMapLookup(t, conn, "second@example.test")
	waitForActiveRead(t, accepted)
}

func TestSocketMapHalfCloseStillReceivesResponse(t *testing.T) {
	deps, _ := newConcurrencyTestDeps(t)
	baseTransport := deps.HTTPClient.Transport
	deps.HTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		select {
		case <-time.After(50 * time.Millisecond):
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}

		return baseTransport.RoundTrip(request)
	})}
	listener := startObservedServer(t, deps, 1, Listen{
		Kind: listenKindSocketMap,
		Name: concurrencyTestMap,
		Type: listenTypeTCP,
	})

	conn, _ := dialObservedConnection(t, listener)

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		t.Fatalf("SocketMap client connection type = %T, want *net.TCPConn", conn)
	}

	t.Cleanup(func() { _ = tcpConn.Close() })

	payload := concurrencyTestMap + " half-close@example.test"
	if _, err := fmt.Fprintf(tcpConn, "%d:%s,", len(payload), payload); err != nil {
		t.Fatalf("write SocketMap request: %v", err)
	}

	if err := tcpConn.CloseWrite(); err != nil {
		t.Fatalf("half-close SocketMap request stream: %v", err)
	}

	if err := tcpConn.SetReadDeadline(time.Now().Add(concurrencyCleanupTimeout)); err != nil {
		t.Fatalf("set SocketMap response deadline: %v", err)
	}

	response, err := readSocketMapReply(tcpConn)
	if err != nil {
		t.Fatalf("read SocketMap response after half-close: %v", err)
	}

	if response != concurrencyMappedReply {
		t.Fatalf("SocketMap response after half-close = %q, want %q", response, concurrencyMappedReply)
	}
}

func TestSocketMapListenerRejectsConnectionsAboveAdmissionLimit(t *testing.T) {
	deps, _ := newConcurrencyTestDeps(t)
	listener := startObservedServer(t, deps, 1, Listen{
		Kind: listenKindSocketMap,
		Name: concurrencyTestMap,
		Type: listenTypeTCP,
	})

	holder, holderAccepted := dialObservedConnection(t, listener)
	t.Cleanup(func() { _ = holder.Close() })
	waitForHandlerStart(t, holderAccepted)
	waitForActiveRead(t, holderAccepted)

	rejected, rejectedAccepted := dialObservedConnection(t, listener)
	t.Cleanup(func() { _ = rejected.Close() })

	if err := rejected.SetReadDeadline(time.Now().Add(concurrencyCleanupTimeout)); err != nil {
		t.Fatalf("set rejected connection deadline: %v", err)
	}

	var probe [1]byte
	if _, err := rejected.Read(probe[:]); !errors.Is(err, io.EOF) && !isConnectionResetError(err) {
		t.Fatalf("rejected connection read error = %v, want closed peer", err)
	}

	select {
	case <-rejectedAccepted.started:
		t.Fatal("rejected connection handler started")
	default:
	}
}

type observedListener struct {
	net.Listener
	accepted chan *observedConnection
}

type observedConnection struct {
	net.Conn
	started   chan struct{}
	finished  chan struct{}
	readState chan struct{}
	reading   atomic.Int32
	once      sync.Once
}

func (l *observedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	observed := &observedConnection{
		Conn:      conn,
		started:   make(chan struct{}),
		finished:  make(chan struct{}),
		readState: make(chan struct{}, 1),
	}
	l.accepted <- observed

	return observed, nil
}

func (c *observedConnection) Read(buffer []byte) (int, error) {
	c.markStarted()
	c.reading.Add(1)

	c.notifyReadState()
	defer func() {
		c.reading.Add(-1)
		c.notifyReadState()
	}()

	return c.Conn.Read(buffer)
}

func (c *observedConnection) Write(buffer []byte) (int, error) {
	c.markStarted()

	return c.Conn.Write(buffer)
}

func (c *observedConnection) SyscallConn() (syscall.RawConn, error) {
	provider, ok := c.Conn.(syscall.Conn)
	if !ok {
		return nil, errors.New("observed connection does not expose syscall access")
	}

	return provider.SyscallConn()
}

func (c *observedConnection) markStarted() {
	c.once.Do(func() { close(c.started) })
}

func (c *observedConnection) notifyReadState() {
	select {
	case c.readState <- struct{}{}:
	default:
	}
}

func startObservedServer(t *testing.T, deps *Deps, maxConnections int, instance Listen) *observedListener {
	t.Helper()

	listener, _ := startObservedServerRuntime(t, deps, maxConnections, instance)

	return listener
}

func startObservedServerRuntime(t *testing.T, deps *Deps, maxConnections int, instance Listen) (*observedListener, GenericServer) {
	t.Helper()

	baseListener, err := net.Listen(listenTypeTCP, concurrencyTestHost+":0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}

	listener := &observedListener{
		Listener: baseListener,
		accepted: make(chan *observedConnection),
	}
	instance.Address = concurrencyTestHost
	instance.Port = baseListener.Addr().(*net.TCPAddr).Port

	supervisor := NewConnectionSupervisor(t.Context(), maxConnections)

	server := NewMultiServer(t.Context(), deps, supervisor)
	if err = server.Listen(instance, listener); err != nil {
		_ = baseListener.Close()

		t.Fatalf("configure %s listener: %v", instance.Kind, err)
	}

	handler := handlerForListener(t, server, instance.Kind)
	observedHandler := func(conn net.Conn) {
		handler(conn)
		close(conn.(*observedConnection).finished)
	}

	done := make(chan error, 1)
	go func() { done <- server.Start(observedHandler) }()

	t.Cleanup(func() {
		server.Stop()

		select {
		case startErr := <-done:
			if startErr != nil {
				t.Errorf("stop %s listener: %v", instance.Kind, startErr)
			}
		case <-time.After(concurrencyCleanupTimeout):
			t.Errorf("%s listener did not stop", instance.Kind)
		}
	})

	return listener, server
}

func handlerForListener(t *testing.T, server GenericServer, kind string) func(net.Conn) {
	t.Helper()

	switch kind {
	case listenKindSocketMap:
		return server.HandleNetStringConnection
	case listenKindPolicyService:
		return server.HandlePolicyServiceConnection
	case listenKindDovecotSASL:
		return server.HandleDovecotSASLConnection
	default:
		t.Fatalf("unsupported test listener kind %q", kind)

		return nil
	}
}

func dialObservedConnection(t *testing.T, listener *observedListener) (net.Conn, *observedConnection) {
	t.Helper()

	conn, err := net.DialTimeout(listenTypeTCP, listener.Addr().String(), concurrencyCleanupTimeout)
	if err != nil {
		t.Fatalf("dial %s: %v", listener.Addr(), err)
	}

	select {
	case accepted := <-listener.accepted:
		if conn.LocalAddr().String() != accepted.RemoteAddr().String() || conn.RemoteAddr().String() != accepted.LocalAddr().String() {
			_ = conn.Close()
			t.Fatalf("accepted connection does not match dialed TCP peer: client=%s->%s server=%s->%s",
				conn.LocalAddr(), conn.RemoteAddr(), accepted.LocalAddr(), accepted.RemoteAddr())
		}

		return conn, accepted
	case <-time.After(concurrencyCleanupTimeout):
		_ = conn.Close()

		t.Fatalf("connection to %s was not accepted", listener.Addr())

		return nil, nil
	}
}

func waitForHandlerStart(t *testing.T, conn *observedConnection) {
	t.Helper()

	select {
	case <-conn.started:
	case <-time.After(concurrencyCleanupTimeout):
		t.Fatal("accepted connection handler did not start")
	}
}

func waitForActiveRead(t *testing.T, conn *observedConnection) {
	t.Helper()

	for conn.reading.Load() == 0 {
		select {
		case <-conn.readState:
		case <-time.After(concurrencyCleanupTimeout):
			t.Fatal("connection did not return to idle read state")
		}
	}
}

func completeDovecotClientHandshake(t *testing.T, conn net.Conn) {
	t.Helper()

	if err := conn.SetDeadline(time.Now().Add(concurrencyCleanupTimeout)); err != nil {
		t.Fatalf("set Dovecot handshake deadline: %v", err)
	}

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read Dovecot server handshake: %v", err)
		}

		if line == string(DovecotCmdDone)+"\n" {
			break
		}
	}

	clientHandshake := "VERSION\t1\t2\nCPID\t4242\n"
	if _, err := io.WriteString(conn, clientHandshake); err != nil {
		t.Fatalf("write Dovecot client handshake: %v", err)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear Dovecot handshake deadline: %v", err)
	}
}

func completeSocketMapLookup(t *testing.T, conn net.Conn, key string) {
	t.Helper()

	payload := concurrencyTestMap + " " + key
	if _, err := fmt.Fprintf(conn, "%d:%s,", len(payload), payload); err != nil {
		t.Fatalf("write SocketMap holder request: %v", err)
	}

	response, err := readSocketMapReply(conn)
	if err != nil {
		t.Fatalf("read SocketMap holder response: %v", err)
	}

	if response != concurrencyMappedReply {
		t.Fatalf("SocketMap holder response = %q, want %q", response, concurrencyMappedReply)
	}
}

func assertFreshLookupServiceable(
	t *testing.T,
	listener *observedListener,
	backendStarted <-chan struct{},
	holderClient net.Conn,
	holder *observedConnection,
) {
	t.Helper()

	conn, accepted := dialObservedConnection(t, listener)
	defer func() { _ = conn.Close() }()

	payload := concurrencyTestMap + " " + concurrencyFreshKey
	if _, err := fmt.Fprintf(conn, "%d:%s,", len(payload), payload); err != nil {
		t.Fatalf("write SocketMap request: %v", err)
	}

	response := make(chan lookupResult, 1)

	go func() {
		value, err := readSocketMapReply(conn)
		response <- lookupResult{value: value, err: err}
	}()

	starved := false

	select {
	case <-backendStarted:
	case <-time.After(concurrencyProbeTimeout):
		starved = true
	}

	if starved {
		releaseStarvedHolder(t, accepted, backendStarted, holderClient, holder)
	}

	result := waitForLookupResult(t, response)
	if result.err != nil {
		t.Fatalf("read SocketMap response: %v", result.err)
	}

	if result.value != concurrencyMappedReply {
		t.Fatalf("SocketMap response = %q, want %q", result.value, concurrencyMappedReply)
	}

	if starved {
		t.Error("a fresh accepted SocketMap request reached its backend only after a persistent connection was released")
	}
}

func releaseStarvedHolder(
	t *testing.T,
	accepted *observedConnection,
	backendStarted <-chan struct{},
	holderClient net.Conn,
	holder *observedConnection,
) {
	t.Helper()

	select {
	case <-accepted.started:
		t.Error("fresh SocketMap handler started while its backend remained blocked")
	default:
	}

	if err := holderClient.Close(); err != nil {
		t.Fatalf("release persistent connection: %v", err)
	}

	if err := holder.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("release accepted persistent connection: %v", err)
	}

	select {
	case <-holder.finished:
	case <-time.After(concurrencyCleanupTimeout):
		t.Fatal("released persistent connection handler did not finish")
	}

	select {
	case <-backendStarted:
	case <-time.After(concurrencyCleanupTimeout):
		t.Fatal("backend did not start after a persistent connection was released")
	}
}

type lookupResult struct {
	value string
	err   error
}

func waitForLookupResult(t *testing.T, response <-chan lookupResult) lookupResult {
	t.Helper()

	select {
	case result := <-response:
		return result
	case <-time.After(concurrencyCleanupTimeout):
		t.Fatal("SocketMap response did not complete")

		return lookupResult{}
	}
}

func readSocketMapReply(conn net.Conn) (string, error) {
	reader := bufio.NewReader(conn)

	prefix, err := reader.ReadString(':')
	if err != nil {
		return "", err
	}

	length, err := strconv.Atoi(strings.TrimSuffix(prefix, ":"))
	if err != nil {
		return "", fmt.Errorf("parse SocketMap response length: %w", err)
	}

	payload := make([]byte, length)
	if _, err = io.ReadFull(reader, payload); err != nil {
		return "", err
	}

	trailing, err := reader.ReadByte()
	if err != nil {
		return "", err
	}

	if trailing != ',' {
		return "", fmt.Errorf("SocketMap response missing trailing comma")
	}

	return string(payload), nil
}

func newConcurrencyTestDeps(t *testing.T) (*Deps, <-chan struct{}) {
	t.Helper()

	backendStarted := make(chan struct{}, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var payload struct {
			Key string `json:"key"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			http.Error(writer, "invalid request", http.StatusBadRequest)

			return
		}

		if payload.Key == concurrencyFreshKey {
			select {
			case backendStarted <- struct{}{}:
			default:
			}
		}

		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"value":"mapped"}`))
	}))
	t.Cleanup(backend.Close)

	config := &Config{
		Server: Server{SockmapMaxReplySize: 100000},
		SocketMaps: map[string]Request{
			concurrencyTestMap: {
				Target:     backend.URL,
				Payload:    testMapPayload,
				StatusCode: http.StatusOK,
				ValueField: testValueField,
			},
		},
		DovecotSASL: map[string]Request{
			concurrencyTestSASL: {
				Target:     backend.URL,
				Mechanisms: []string{saslMechanismPlain},
			},
		},
	}

	return &Deps{
		Config:     config,
		Logger:     slog.New(slog.DiscardHandler),
		HTTPClient: backend.Client(),
	}, backendStarted
}
