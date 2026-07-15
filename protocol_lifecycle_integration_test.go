package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	lifecyclePolicyName          = "lifecycle_policy"
	lifecyclePolicyDunnoResponse = "action=DUNNO\n\n"
	lifecycleCachedData          = "cached"
	lifecycleCachedResponse      = "OK " + lifecycleCachedData
	lifecycleBackendURL          = "http://backend.example.test/map"
)

func TestPolicyListenerReusesConnectionAndPreservesBufferedRequests(t *testing.T) {
	deps := newLifecyclePolicyDeps(t, nil)
	listener := startObservedServer(t, deps, 1, Listen{
		Kind: listenKindPolicyService,
		Name: lifecyclePolicyName,
		Type: listenTypeTCP,
	})

	conn, accepted := dialObservedConnection(t, listener)
	t.Cleanup(func() { _ = conn.Close() })
	setLifecycleDeadline(t, conn)
	reader := bufio.NewReader(conn)

	first := lifecyclePolicyRequest("192.0.2.10")

	second := lifecyclePolicyRequest("192.0.2.11")
	if _, err := io.WriteString(conn, first+second); err != nil {
		t.Fatalf("write buffered policy requests: %v", err)
	}

	for index := 1; index <= 2; index++ {
		if response := readPolicyResponse(t, reader); response != lifecyclePolicyDunnoResponse {
			t.Fatalf("policy response %d = %q, want DUNNO", index, response)
		}
	}

	waitForActiveRead(t, accepted)
}

func TestPolicyListenerRemainsReusableAfterIdleGap(t *testing.T) {
	deps := newLifecyclePolicyDeps(t, nil)
	listener := startObservedServer(t, deps, 1, Listen{
		Kind: listenKindPolicyService,
		Name: lifecyclePolicyName,
		Type: listenTypeTCP,
	})

	conn, accepted := dialObservedConnection(t, listener)
	t.Cleanup(func() { _ = conn.Close() })
	setLifecycleDeadline(t, conn)
	reader := bufio.NewReader(conn)

	if _, err := io.WriteString(conn, lifecyclePolicyRequest("192.0.2.20")); err != nil {
		t.Fatalf("write first policy request: %v", err)
	}

	if response := readPolicyResponse(t, reader); response != lifecyclePolicyDunnoResponse {
		t.Fatalf("first policy response = %q, want DUNNO", response)
	}

	waitForActiveRead(t, accepted)

	select {
	case <-time.After(25 * time.Millisecond):
	case <-t.Context().Done():
		t.Fatal("test canceled during policy idle gap")
	}

	if _, err := io.WriteString(conn, lifecyclePolicyRequest("192.0.2.21")); err != nil {
		t.Fatalf("write reused policy request: %v", err)
	}

	if response := readPolicyResponse(t, reader); response != lifecyclePolicyDunnoResponse {
		t.Fatalf("reused policy response = %q, want DUNNO", response)
	}
}

func TestDovecotListenerSupportsRepeatedLoginAuthContinuations(t *testing.T) {
	deps := newLifecycleSASLDeps(t)
	listener := startObservedServer(t, deps, 1, Listen{
		Kind: listenKindDovecotSASL,
		Name: concurrencyTestSASL,
		Type: listenTypeTCP,
		Limits: LimitsConfig{
			MaxInflightRequests: 1,
			MaxQueuedRequests:   new(1),
			RequestTimeout:      time.Second,
		},
	})

	conn, _ := dialObservedConnection(t, listener)
	t.Cleanup(func() { _ = conn.Close() })
	reader := completeDovecotHandshakeWithReader(t, conn)
	setLifecycleDeadline(t, conn)

	for _, id := range []string{"1", "2"} {
		if _, err := fmt.Fprintf(conn, "AUTH\t%s\tLOGIN\tservice=smtp\n", id); err != nil {
			t.Fatalf("write AUTH %s: %v", id, err)
		}

		assertDovecotLine(t, reader, "CONT\t"+id+"\tVXNlcm5hbWU6\n")

		username := base64.StdEncoding.EncodeToString([]byte("user@example.test"))
		if _, err := fmt.Fprintf(conn, "CONT\t%s\t%s\n", id, username); err != nil {
			t.Fatalf("write username continuation %s: %v", id, err)
		}

		assertDovecotLine(t, reader, "CONT\t"+id+"\tUGFzc3dvcmQ6\n")

		password := base64.StdEncoding.EncodeToString([]byte("synthetic-password"))
		if _, err := fmt.Fprintf(conn, "CONT\t%s\t%s\n", id, password); err != nil {
			t.Fatalf("write password continuation %s: %v", id, err)
		}

		line := readDovecotLine(t, reader)
		if !strings.HasPrefix(line, "OK\t"+id+"\tuser=") {
			t.Fatalf("AUTH %s terminal response command = %q, want OK for same id", id, strings.SplitN(line, "\t", 2)[0])
		}
	}
}

func TestDovecotContinuationWaitStaysInsideAuthenticationBudget(t *testing.T) {
	deps := newLifecycleSASLDeps(t)
	listener := startObservedServer(t, deps, 1, Listen{
		Kind: listenKindDovecotSASL,
		Name: concurrencyTestSASL,
		Type: listenTypeTCP,
		Limits: LimitsConfig{
			MaxInflightRequests:  1,
			MaxQueuedRequests:    new(1),
			RequestTimeout:       250 * time.Millisecond,
			ResponseWriteReserve: 75 * time.Millisecond,
		},
	})

	conn, _ := dialObservedConnection(t, listener)
	t.Cleanup(func() { _ = conn.Close() })
	reader := completeDovecotHandshakeWithReader(t, conn)
	setLifecycleDeadline(t, conn)

	started := time.Now()

	if _, err := io.WriteString(conn, "AUTH\tbudget\tLOGIN\tservice=smtp\n"); err != nil {
		t.Fatalf("write budget AUTH: %v", err)
	}

	assertDovecotLine(t, reader, "CONT\tbudget\tVXNlcm5hbWU6\n")

	line := readDovecotLine(t, reader)
	if line != "FAIL\tbudget\treason=temporary failure\ttemp\n" {
		t.Fatalf("expired AUTH response command = %q, want FAIL temp", strings.SplitN(line, "\t", 2)[0])
	}

	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("continuation timeout took %s, want one authentication budget", elapsed)
	}
}

func TestListenerShutdownCancelsActivePolicyBackend(t *testing.T) {
	backendStarted := make(chan struct{}, 1)
	backendCanceled := make(chan struct{}, 1)
	deps := newLifecyclePolicyDeps(t, nil)
	deps.HTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		backendStarted <- struct{}{}

		<-request.Context().Done()

		backendCanceled <- struct{}{}

		return nil, request.Context().Err()
	})}
	listener, server := startObservedServerRuntime(t, deps, 1, Listen{
		Kind: listenKindPolicyService,
		Name: lifecyclePolicyName,
		Type: listenTypeTCP,
		Limits: LimitsConfig{
			MaxInflightRequests: 1,
			MaxQueuedRequests:   new(1),
			RequestTimeout:      time.Second,
		},
	})

	conn, _ := dialObservedConnection(t, listener)
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := io.WriteString(conn, lifecyclePolicyRequest("192.0.2.30")); err != nil {
		t.Fatalf("write policy request: %v", err)
	}

	select {
	case <-backendStarted:
	case <-time.After(time.Second):
		t.Fatal("policy backend did not start")
	}

	server.Stop()

	select {
	case <-backendCanceled:
	case <-time.After(time.Second):
		t.Fatal("listener shutdown did not cancel active policy backend")
	}
}

func TestClientCloseCancelsActivePolicyBackend(t *testing.T) {
	backendStarted := make(chan struct{}, 1)
	backendCanceled := make(chan struct{}, 1)
	obs := newPrometheusTestObservability(t)
	deps := newLifecyclePolicyDeps(t, nil)
	deps.Observability = obs
	deps.HTTPClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		backendStarted <- struct{}{}

		<-request.Context().Done()

		backendCanceled <- struct{}{}

		return nil, request.Context().Err()
	})}
	listener := startObservedServer(t, deps, 1, Listen{
		Kind: listenKindPolicyService,
		Name: lifecyclePolicyName,
		Type: listenTypeTCP,
		Limits: LimitsConfig{
			MaxInflightRequests: 1,
			MaxQueuedRequests:   new(1),
			RequestTimeout:      time.Second,
		},
	})

	conn, _ := dialObservedConnection(t, listener)
	if _, err := io.WriteString(conn, lifecyclePolicyRequest("192.0.2.31")); err != nil {
		t.Fatalf("write policy request: %v", err)
	}

	select {
	case <-backendStarted:
	case <-time.After(time.Second):
		t.Fatal("policy backend did not start")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("close policy client: %v", err)
	}

	select {
	case <-backendCanceled:
	case <-time.After(time.Second):
		t.Fatal("client close did not cancel active policy backend")
	}

	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(listenKindPolicyService, lifecyclePolicyName, "inflight"), 0)
	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(listenKindPolicyService, lifecyclePolicyName, "queued"), 0)
}

func TestListenerShutdownCancelsQueuedPolicyRequest(t *testing.T) {
	backendStarted := make(chan struct{}, 1)
	obs := newPrometheusTestObservability(t)
	deps := newLifecyclePolicyDeps(t, func(*http.Request) { backendStarted <- struct{}{} })
	deps.Observability = obs
	listener, genericServer := startObservedServerRuntime(t, deps, 1, Listen{
		Kind: listenKindPolicyService,
		Name: lifecyclePolicyName,
		Type: listenTypeTCP,
		Limits: LimitsConfig{
			MaxInflightRequests: 1,
			MaxQueuedRequests:   new(1),
			RequestQueueTimeout: time.Second,
			RequestTimeout:      2 * time.Second,
		},
	})
	server := genericServer.(*MultiServer)

	occupied, outcome := server.limiter.Acquire(t.Context())
	if occupied == nil || outcome != requestAdmitted {
		t.Fatal("failed to occupy listener request capacity")
	}

	conn, _ := dialObservedConnection(t, listener)
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := io.WriteString(conn, lifecyclePolicyRequest("192.0.2.32")); err != nil {
		t.Fatalf("write queued policy request: %v", err)
	}

	waitForLimiterSnapshot(t, server.limiter, 1, 1)
	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(listenKindPolicyService, lifecyclePolicyName, "queued"), 1)

	server.Stop()
	occupied.Release()
	waitForLimiterSnapshot(t, server.limiter, 0, 0)
	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(listenKindPolicyService, lifecyclePolicyName, "inflight"), 0)
	waitForMetricValue(t, obs.metrics.requestState.WithLabelValues(listenKindPolicyService, lifecyclePolicyName, "queued"), 0)

	select {
	case <-backendStarted:
		t.Fatal("queued backend started during listener shutdown")
	default:
	}
}

func TestCacheHitAndBackendFailureReleaseListenerPermit(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		seedCache bool
		want      string
	}{
		{name: "cache hit", seedCache: true, want: lifecycleCachedResponse},
		{name: "backend failure", want: socketMapTemporaryResponse},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			cache := NewInMemoryResponseCache(time.Second)
			if testCase.seedCache {
				cache.Set(concurrencyTestMap, "cached-key", CachedResponse{Status: string(DovecotCmdOK), Data: lifecycleCachedData})
			}

			deps := &Deps{
				Config: &Config{
					Server: Server{SockmapMaxReplySize: 1024},
					SocketMaps: map[string]Request{
						concurrencyTestMap: {
							Target:     lifecycleBackendURL,
							Payload:    testMapPayload,
							StatusCode: http.StatusOK,
							ValueField: testValueField,
						},
					},
				},
				Logger: slog.New(slog.DiscardHandler),
				HTTPClient: newTestHTTPClient(func(*http.Request) (*http.Response, error) {
					return nil, errors.New("synthetic backend failure")
				}),
				RespCache: cache,
			}
			limiter := NewRequestLimiter(t.Context(), 1, 0, time.Second)
			server := &MultiServer{
				name:           concurrencyTestMap,
				kind:           listenKindSocketMap,
				deps:           deps,
				ctx:            t.Context(),
				limiter:        limiter,
				requestTimeout: time.Second,
			}

			response := runNetStringHandlerForTest(t, server, concurrencyTestMap+" cached-key")
			if response.String() != testCase.want {
				t.Fatalf("SocketMap response status = %q, want expected bounded status", strings.SplitN(response.String(), " ", 2)[0])
			}

			permit, nextOutcome := limiter.Acquire(t.Context())
			if permit == nil || nextOutcome != requestAdmitted {
				t.Fatal("cache/backend completion leaked listener request capacity")
			}

			permit.Release()
		})
	}
}

func newLifecyclePolicyDeps(t *testing.T, block func(*http.Request)) *Deps {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if block != nil {
			block(request)

			return
		}

		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"action":"DUNNO"}`))
	}))
	t.Cleanup(backend.Close)

	return &Deps{
		Config: &Config{PolicyServices: map[string]Request{
			lifecyclePolicyName: {
				Target:     backend.URL,
				Payload:    testPolicyPayload,
				StatusCode: http.StatusOK,
				ValueField: testPolicyActionField,
			},
		}},
		Logger:     slog.New(slog.DiscardHandler),
		HTTPClient: backend.Client(),
	}
}

func newLifecycleSASLDeps(t *testing.T) *Deps {
	t.Helper()

	backend := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Auth-User", "user@example.test")
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	return &Deps{
		Config: &Config{DovecotSASL: map[string]Request{
			concurrencyTestSASL: {
				Target:     backend.URL,
				StatusCode: http.StatusOK,
				Mechanisms: []string{saslMechanismLogin},
			},
		}},
		Logger:     slog.New(slog.DiscardHandler),
		HTTPClient: backend.Client(),
	}
}

func lifecyclePolicyRequest(clientAddress string) string {
	return "request=smtpd_access_policy\nclient_address=" + clientAddress + "\n\n"
}

func readPolicyResponse(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	var response strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read policy response: %v", err)
		}

		response.WriteString(line)

		if line == "\n" {
			return response.String()
		}
	}
}

func completeDovecotHandshakeWithReader(t *testing.T, conn net.Conn) *bufio.Reader {
	t.Helper()

	if err := conn.SetDeadline(time.Now().Add(concurrencyCleanupTimeout)); err != nil {
		t.Fatalf("set Dovecot handshake deadline: %v", err)
	}

	reader := bufio.NewReader(conn)
	for {
		if line := readDovecotLine(t, reader); line == string(DovecotCmdDone)+"\n" {
			break
		}
	}

	if _, err := io.WriteString(conn, "VERSION\t1\t2\nCPID\t4242\n"); err != nil {
		t.Fatalf("write Dovecot client handshake: %v", err)
	}

	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear Dovecot handshake deadline: %v", err)
	}

	return reader
}

func assertDovecotLine(t *testing.T, reader *bufio.Reader, want string) {
	t.Helper()

	if got := readDovecotLine(t, reader); got != want {
		t.Fatalf("Dovecot response command = %q, want %q", strings.SplitN(got, "\t", 2)[0], strings.SplitN(want, "\t", 2)[0])
	}
}

func readDovecotLine(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read Dovecot protocol line: %v", err)
	}

	return line
}

func setLifecycleDeadline(t *testing.T, conn net.Conn) {
	t.Helper()

	if err := conn.SetDeadline(time.Now().Add(concurrencyCleanupTimeout)); err != nil {
		t.Fatalf("set lifecycle client deadline: %v", err)
	}
}
