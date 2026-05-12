package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const LogKeyClient = "client"
const LogKeySession = "session"
const LogKeySubSession = "sub_session"

// generateSessionID creates a short random hex string for session tracking.
func generateSessionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)

	return hex.EncodeToString(b)
}

// GenericServer defines an interface for managing a TCP server with methods to start and stop the server.
type GenericServer interface {
	// Listen initializes the listener for the server based on the provided configuration.
	Listen(instance Listen, activatedListener net.Listener) error

	// Start starts the accept loop for the server using the provided handler.
	Start(handler func(conn net.Conn)) error

	// Stop gracefully shuts down the server, ensuring all active connections are closed and all routines are completed.
	Stop()

	// GetContext returns the context used by the server to manage its lifecycle and handle cancellations or deadlines.
	GetContext() context.Context

	// HandleNetStringConnection processes an individual client connection by reading, interpreting, and responding in NetString format.
	HandleNetStringConnection(conn net.Conn)

	// HandlePolicyServiceConnection manages a client connection for the Postfix policy service, handling requests and responses.
	HandlePolicyServiceConnection(conn net.Conn)

	// HandleDovecotSASLConnection manages a client connection for the Dovecot SASL authentication protocol.
	HandleDovecotSASLConnection(conn net.Conn)
}

// MultiServer represents a TCP server that processes requests encoded in NetString format.
// It manages connections, reads incoming NetStrings, and sends processed responses back to clients.
type MultiServer struct {
	name    string
	kind    string
	address string

	deps       *Deps
	ctx        context.Context
	closer     context.CancelFunc
	listener   net.Listener
	wg         sync.WaitGroup
	workerPool WorkerPool
}

// NewMultiServer creates and initializes a new MultiServer instance with the provided context and dependencies.
func NewMultiServer(ctx context.Context, deps *Deps, wp WorkerPool) GenericServer {
	childCtx, closer := context.WithCancel(ctx)

	return &MultiServer{
		deps:       deps,
		ctx:        childCtx,
		closer:     closer,
		wg:         sync.WaitGroup{},
		workerPool: wp,
	}
}

// Listen initializes the listener for the MultiServer based on the provided configuration.
func (s *MultiServer) Listen(instance Listen, activatedListener net.Listener) error {
	s.setEndpoint(instance)
	s.kind = instance.Kind

	if instance.Name != "" {
		s.name = instance.Name
	}

	if activatedListener != nil {
		s.listener = activatedListener
	} else if err := s.listenNative(instance); err != nil {
		return err
	}

	s.deps.GetLogger().Info("Server is listening", slog.String("type", instance.Type), slog.String("address", s.address), slog.String("name", s.name), slog.String("kind", instance.Kind))

	if instance.WorkerPool.MaxWorkers > 0 {
		s.workerPool = NewWorkerPool(s.ctx, instance.WorkerPool.MaxWorkers, instance.WorkerPool.MaxQueue, &s.wg)
	}

	return nil
}

// setEndpoint derives the concrete network address used for binding and logging.
func (s *MultiServer) setEndpoint(instance Listen) {
	if instance.Type == listenTypeUnix {
		s.address = instance.Address

		return
	}

	s.address = fmt.Sprintf("%s:%d", instance.Address, instance.Port)
}

// listenNative creates a listener directly from the configured endpoint.
func (s *MultiServer) listenNative(instance Listen) error {
	if err := ensureEndpointAvailable(instance.Type, s.address); err != nil {
		return err
	}

	if instance.Type == listenTypeUnix {
		if err := prepareUnixSocket(instance.Address); err != nil {
			return err
		}

		oldMask := syscall.Umask(0)
		defer syscall.Umask(oldMask)
	}

	listener, err := net.Listen(instance.Type, s.address)
	if err != nil {
		return fmt.Errorf("could not start server: %w", err)
	}

	s.listener = listener

	s.applyUnixSocketMode(instance)
	s.applyUnixSocketOwnership(instance)

	return nil
}

// ensureEndpointAvailable fails fast when another service already accepts connections on the endpoint.
func ensureEndpointAvailable(network, address string) error {
	conn, err := net.DialTimeout(network, address, 1*time.Second)
	if err != nil {
		return nil
	}

	_ = conn.Close()

	return fmt.Errorf("address %s is already in use", address)
}

// prepareUnixSocket removes a stale Unix socket path before a native bind.
func prepareUnixSocket(address string) error {
	fileInfo, err := os.Stat(address)
	if err != nil || fileInfo.Mode()&os.ModeSocket == 0 {
		return nil
	}

	return os.Remove(address)
}

// applyUnixSocketMode applies configured filesystem permissions to a native Unix socket.
func (s *MultiServer) applyUnixSocketMode(instance Listen) {
	if instance.Type != listenTypeUnix || instance.Mode == "" {
		return
	}

	mode, err := strconv.ParseInt(instance.Mode, 8, 64)
	if err != nil {
		s.deps.GetLogger().Error("Could not parse socket mode", slog.String("error", err.Error()))

		return
	}

	if err = os.Chmod(instance.Address, os.FileMode(mode)); err != nil {
		s.deps.GetLogger().Error("Could not set permissions on socket", slog.String("error", err.Error()))
	}
}

// applyUnixSocketOwnership applies configured ownership to a native Unix socket.
func (s *MultiServer) applyUnixSocketOwnership(instance Listen) {
	if instance.Type != listenTypeUnix || (instance.User == "" && instance.Group == "") {
		return
	}

	uid, gid := lookupSocketOwner(instance, s.deps.GetLogger())
	if uid == -1 && gid == -1 {
		return
	}

	if err := os.Chown(instance.Address, uid, gid); err != nil {
		s.deps.GetLogger().Error("Could not set ownership on socket", slog.String("error", err.Error()))
	}
}

// lookupSocketOwner resolves configured Unix socket user and group names to numeric IDs.
func lookupSocketOwner(instance Listen, logger *slog.Logger) (int, int) {
	uid, gid := -1, -1

	if instance.User != "" {
		u, err := user.Lookup(instance.User)
		if err != nil {
			logger.Error("Could not lookup user", slog.String("user", instance.User), slog.String("error", err.Error()))
		} else {
			uid, _ = strconv.Atoi(u.Uid)
		}
	}

	if instance.Group != "" {
		g, err := user.LookupGroup(instance.Group)
		if err != nil {
			logger.Error("Could not lookup group", slog.String("group", instance.Group), slog.String("error", err.Error()))
		} else {
			gid, _ = strconv.Atoi(g.Gid)
		}
	}

	return uid, gid
}

// Start starts the accept loop for the MultiServer using the provided handler.
func (s *MultiServer) Start(handler func(conn net.Conn)) error {
	var (
		conn net.Conn
		err  error
	)

	for {
		conn, err = s.listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			s.deps.GetLogger().Info("Server is shutting down", slog.String("address", s.address), slog.String("name", s.name))

			return nil
		}

		if err != nil {
			s.deps.GetLogger().Error("Error accepting connection", slog.String("error", err.Error()))

			if obs := s.deps.GetObservability(); obs != nil {
				obs.ObserveListenerConnection(s.ctx, s.kind, safeMetricName(s.name), eventAccept, resultError, 0)
			}

			continue
		}

		if obs := s.deps.GetObservability(); obs != nil {
			obs.ObserveListenerConnection(s.ctx, s.kind, safeMetricName(s.name), eventAccept, resultOK, 1)
		}

		s.wg.Add(1)

		if s.workerPool != nil {
			job := Job{
				Conn:    conn,
				Handler: handler,
			}

			if !s.workerPool.Submit(job) {
				_ = conn.Close()

				if obs := s.deps.GetObservability(); obs != nil {
					obs.ObserveListenerConnection(s.ctx, s.kind, safeMetricName(s.name), eventQueueFull, resultError, -1)
				}

				s.wg.Done()
			}
		} else {
			go func(c net.Conn) {
				defer s.wg.Done()
				handler(c)
			}(conn)
		}
	}
}

// Stop gracefully shuts down the MultiServer by stopping connections, waiting for all routines to complete, and closing the listener.
func (s *MultiServer) Stop() {
	if s.closer != nil {
		s.closer()
	}

	_ = s.listener.Close()

	s.wg.Wait()
}

func (s *MultiServer) GetContext() context.Context {
	return s.ctx
}

var _ GenericServer = (*MultiServer)(nil)

// setupConnection initializes a new client connection by generating a session ID, creating a session logger,
// and logging the connection establishment. It returns the client address, the session logger factory,
// and a cleanup function that should be deferred by the caller.
func (s *MultiServer) setupConnection(conn net.Conn) (clientAddr string, sessionLogger func() *slog.Logger, cleanup func()) {
	clientAddr = conn.RemoteAddr().String()
	sessionID := generateSessionID()
	start := time.Now()

	sessionLogger = func() *slog.Logger {
		return s.deps.GetLogger().With(slog.String(LogKeySession, sessionID))
	}

	sessionLogger().Info("New connection established", slog.String(LogKeyClient, clientAddr))

	cleanup = func() {
		sessionLogger().Info("Connection closed", slog.String(LogKeyClient, clientAddr))

		_ = conn.Close()

		if obs := s.deps.GetObservability(); obs != nil {
			obs.ObserveListenerConnection(s.ctx, s.kind, safeMetricName(s.name), eventClose, resultOK, -1)
			obs.ObserveListenerDuration(s.ctx, s.kind, safeMetricName(s.name), resultOK, time.Since(start))
		}

		s.wg.Done()
	}

	return
}

// HandleNetStringConnection manages an individual client connection, processing requests and sending responses in NetString format.
func (s *MultiServer) HandleNetStringConnection(conn net.Conn) {
	clientAddr, sessionLogger, cleanup := s.setupConnection(conn)
	defer cleanup()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			requestCtx, obs, span := s.startApplicationSpan(componentSocketMap, defaultBackendName, clientAddr)
			start := time.Now()

			_, readObs, readSpan := startInternalSpanFromContext(requestCtx,
				socketMapReadSpanName,
				attribute.String("pfxhttp.component", componentSocketMap),
				attribute.String("pfxhttp.listener", safeMetricName(s.name)),
			)
			netString, err := s.readNetString(conn)
			finishObservedSpan(readObs, readSpan, err)
			if err != nil {
				if obs != nil {
					obs.RecordSpanError(span, err)
					span.End()
				}

				if errors.Is(err, io.EOF) {
					break
				}

				sessionLogger().Error("Error reading NetString", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))

				return
			}

			// Client closed connection
			if netString == nil {
				if obs != nil {
					span.End()
				}

				return
			}

			subSessionID := generateSessionID()
			reqLogger := sessionLogger().With(slog.String(LogKeySubSession, subSessionID))

			reqLogger.Debug("Received request", slog.String(LogKeyClient, clientAddr), slog.String("request", netString.String()))

			received := NewPostfixMapReceiver()

			_, decodeObs, decodeSpan := startInternalSpanFromContext(requestCtx,
				socketMapDecodeSpanName,
				attribute.String("pfxhttp.component", componentSocketMap),
				attribute.String("pfxhttp.listener", safeMetricName(s.name)),
			)
			err = received.ReadNetString(netString)
			finishObservedSpan(decodeObs, decodeSpan, err)
			if err != nil {
				if obs != nil {
					obs.RecordSpanError(span, err)
				}
				reqLogger.Error("Error reading request", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
				s.finishApplicationSpan(requestCtx, obs, span, componentSocketMap, defaultBackendName, outcomeError, start)

				return
			}

			span.SetName(applicationSpanName(componentSocketMap, received.GetName()))
			span.SetAttributes(attribute.String("pfxhttp.name", safeMetricName(received.GetName())))

			client := NewMapClient(s.deps, reqLogger)
			client.SetReceiver(received)

			backendCtx, backendObs, backendSpan := startInternalSpanFromContext(requestCtx,
				socketMapBackendSpanName,
				attribute.String("pfxhttp.component", componentSocketMap),
				attribute.String("pfxhttp.name", safeMetricName(received.GetName())),
			)
			err = client.SendAndReceiveContext(backendCtx)
			finishObservedSpan(backendObs, backendSpan, err)
			if err != nil {
				if obs != nil {
					obs.RecordSpanError(span, err)
				}
				reqLogger.Error("Error sending request", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
				s.finishApplicationSpan(requestCtx, obs, span, componentSocketMap, received.GetName(), outcomeError, start)

				return
			}

			outcome := outcomeFromSender(client.GetSender())

			_, encodeObs, encodeSpan := startInternalSpanFromContext(requestCtx,
				socketMapEncodeSpanName,
				attribute.String("pfxhttp.component", componentSocketMap),
				attribute.String("pfxhttp.name", safeMetricName(received.GetName())),
			)
			responseData := client.GetSender().String()
			response := NewNetStringFromString(responseData)

			finishObservedSpan(encodeObs, encodeSpan, nil)

			_, writeObs, writeSpan := startInternalSpanFromContext(requestCtx,
				socketMapWriteSpanName,
				attribute.String("pfxhttp.component", componentSocketMap),
				attribute.String("pfxhttp.name", safeMetricName(received.GetName())),
			)
			err = s.writeNetString(conn, response)
			finishObservedSpan(writeObs, writeSpan, err)
			if err != nil {
				outcome = outcomeError

				if obs != nil {
					obs.RecordSpanError(span, err)
				}

				reqLogger.Error("Error writing response", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
				s.finishApplicationSpan(requestCtx, obs, span, componentSocketMap, received.GetName(), outcome, start)

				return
			}

			reqLogger.Debug("Response sent", slog.String(LogKeyClient, clientAddr), slog.String("response", responseData))
			s.finishApplicationSpan(requestCtx, obs, span, componentSocketMap, received.GetName(), outcome, start)
		}
	}
}

// HandlePolicyServiceConnection manages a client connection for the Postfix policy service, handling requests and responses.
func (s *MultiServer) HandlePolicyServiceConnection(conn net.Conn) {
	clientAddr, sessionLogger, cleanup := s.setupConnection(conn)
	defer cleanup()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			requestCtx, obs, span := s.startApplicationSpan(componentPolicyService, s.name, clientAddr)
			start := time.Now()

			_, readObs, readSpan := startInternalSpanFromContext(requestCtx,
				policyServiceReadSpanName,
				attribute.String("pfxhttp.component", componentPolicyService),
				attribute.String("pfxhttp.name", safeMetricName(s.name)),
			)
			policy, err := s.readPolicy(conn)
			finishObservedSpan(readObs, readSpan, err)
			if err != nil {
				if obs != nil {
					obs.RecordSpanError(span, err)
					span.End()
				}

				if errors.Is(err, io.EOF) {
					break
				}

				sessionLogger().Error("Error reading policy", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))

				return
			}

			subSessionID := generateSessionID()
			reqLogger := sessionLogger().With(slog.String(LogKeySubSession, subSessionID))

			reqLogger.Debug("Received request", slog.String(LogKeyClient, clientAddr), slog.String("request", policy.String()))

			received := NewPostfixPolicyReceiver(s.name)

			_, decodeObs, decodeSpan := startInternalSpanFromContext(requestCtx,
				policyServiceDecodeSpanName,
				attribute.String("pfxhttp.component", componentPolicyService),
				attribute.String("pfxhttp.name", safeMetricName(received.GetName())),
			)
			err = received.ReadPolcy(policy)
			finishObservedSpan(decodeObs, decodeSpan, err)

			if err != nil {
				if obs != nil {
					obs.RecordSpanError(span, err)
				}

				reqLogger.Error("Error reading request", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
				s.finishApplicationSpan(requestCtx, obs, span, componentPolicyService, received.GetName(), outcomeError, start)

				return
			}

			client := NewPolicyClient(s.deps, reqLogger)
			client.SetReceiver(received)

			backendCtx, backendObs, backendSpan := startInternalSpanFromContext(requestCtx,
				policyServiceBackendSpanName,
				attribute.String("pfxhttp.component", componentPolicyService),
				attribute.String("pfxhttp.name", safeMetricName(received.GetName())),
			)
			err = client.SendAndReceiveContext(backendCtx)
			finishObservedSpan(backendObs, backendSpan, err)
			if err != nil {
				if obs != nil {
					obs.RecordSpanError(span, err)
				}
				reqLogger.Error("Error sending request", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
				s.finishApplicationSpan(requestCtx, obs, span, componentPolicyService, received.GetName(), outcomeError, start)

				return
			}

			outcome := outcomeFromSender(client.GetSender())

			_, encodeObs, encodeSpan := startInternalSpanFromContext(requestCtx,
				policyServiceEncodeSpanName,
				attribute.String("pfxhttp.component", componentPolicyService),
				attribute.String("pfxhttp.name", safeMetricName(received.GetName())),
			)
			responseData := fmt.Sprintf("action=%s\n\n", strings.TrimSpace(client.GetSender().String()))

			finishObservedSpan(encodeObs, encodeSpan, nil)

			_, writeObs, writeSpan := startInternalSpanFromContext(requestCtx,
				policyServiceWriteSpanName,
				attribute.String("pfxhttp.component", componentPolicyService),
				attribute.String("pfxhttp.name", safeMetricName(received.GetName())),
			)
			err = s.writePolicyResult(conn, responseData)
			finishObservedSpan(writeObs, writeSpan, err)
			if err != nil {
				outcome = outcomeError

				if obs != nil {
					obs.RecordSpanError(span, err)
				}

				if errors.Is(err, os.ErrDeadlineExceeded) {
					reqLogger.Warn("Write deadline exceeded, closing connection", slog.String(LogKeyClient, conn.RemoteAddr().String()))
				} else if strings.Contains(err.Error(), "broken pipe") {
					reqLogger.Info("Broken pipe detected, client likely disconnected", slog.String(LogKeyClient, conn.RemoteAddr().String()))
				} else {
					reqLogger.Error("Error writing response", slog.String(LogKeyClient, conn.RemoteAddr().String()), slog.String("error", err.Error()))
				}

				s.finishApplicationSpan(requestCtx, obs, span, componentPolicyService, received.GetName(), outcome, start)

				return
			}

			reqLogger.Debug("Response sent", slog.String(LogKeyClient, clientAddr), slog.String("response", responseData))
			s.finishApplicationSpan(requestCtx, obs, span, componentPolicyService, received.GetName(), outcome, start)
		}
	}
}

// dovecotCUIDCounter is a global atomic counter for generating unique connection IDs in the Dovecot SASL protocol.
var dovecotCUIDCounter atomic.Uint64

type saslObservabilityState struct {
	ctx      context.Context
	obs      *Observability
	span     trace.Span
	start    time.Time
	waitObs  *Observability
	waitSpan trace.Span
}

// generateCookie generates a random hex cookie for the Dovecot SASL handshake.
func generateCookie() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)

	return hex.EncodeToString(b)
}

// HandleDovecotSASLConnection manages a client connection for the Dovecot SASL authentication protocol.
// It performs the server handshake, reads client handshake, then processes AUTH/CONT requests.
func (s *MultiServer) HandleDovecotSASLConnection(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()
	sessionID := generateSessionID()
	connectionStart := time.Now()

	// Helper that always returns a fresh logger with the session ID attached.
	sessionLogger := func() *slog.Logger {
		return s.deps.GetLogger().With(slog.String(LogKeySession, sessionID))
	}

	var activeObservabilityStates map[string]*saslObservabilityState

	config := s.deps.GetConfig()

	sessionLogger().Info("New Dovecot SASL connection established", slog.String(LogKeyClient, clientAddr))

	defer func() {
		sessionLogger().Info("Dovecot SASL connection closed", slog.String(LogKeyClient, clientAddr))
		_ = conn.Close()

		if obs := s.deps.GetObservability(); obs != nil {
			obs.ObserveListenerConnection(s.ctx, s.kind, safeMetricName(s.name), eventClose, resultOK, -1)
			obs.ObserveListenerDuration(s.ctx, s.kind, safeMetricName(s.name), resultOK, time.Since(connectionStart))
		}

		for id, state := range activeObservabilityStates {
			sessionLogger().Warn("Dovecot SASL authentication abandoned", slog.String("id", id), slog.String(LogKeyClient, clientAddr))
			finishSASLContinuationWait(state, errors.New("authentication abandoned"))
			s.finishApplicationSpan(state.ctx, state.obs, state.span, componentDovecotSASL, s.name, outcomeError, state.start)
		}

		s.wg.Done()
	}()

	decoder := &DovecotDecoder{}
	encoder := &DovecotEncoder{}
	reader := bufio.NewReader(conn)

	// Determine supported mechanisms from config
	mechanisms := []DovecotMechanism{
		{Name: "PLAIN", PlainText: true, Dictionary: true, Active: true},
		{Name: "LOGIN", PlainText: true, Dictionary: true, Active: true},
	}

	// Add OAuth mechanisms if SASL OIDC validation is configured for this service
	if settings, ok := config.DovecotSASL[s.name]; ok && settings.SASLOIDCAuth.Enabled {
		mechanisms = append(mechanisms,
			DovecotMechanism{Name: "XOAUTH2", ForwardSecrecy: true},
			DovecotMechanism{Name: "OAUTHBEARER", ForwardSecrecy: true},
		)
	}

	cuid := dovecotCUIDCounter.Add(1)
	handshake := &DovecotHandshake{
		Mechanisms: mechanisms,
		SPID:       strconv.Itoa(os.Getpid()),
		CUID:       strconv.FormatUint(cuid, 10),
		Cookie:     generateCookie(),
	}

	// Send server handshake
	for _, line := range encoder.EncodeHandshake(handshake) {
		if _, err := conn.Write([]byte(line)); err != nil {
			sessionLogger().Error("Error writing handshake", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
			return
		}
	}

	sessionLogger().Debug("Handshake sent", slog.String(LogKeyClient, clientAddr))

	// Read client handshake (VERSION + CPID)
	clientHandshakeDone := false
	for !clientHandshakeDone {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			sessionLogger().Error("Error reading client handshake", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
			return
		}

		cmd, args := decoder.ParseLine(line)
		switch cmd {
		case DovecotCmdVersion:
			major, _, err := decoder.DecodeVersion(args)
			if err != nil {
				sessionLogger().Error("Invalid client VERSION", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
				return
			}
			if major != DovecotProtoVersionMajor {
				sessionLogger().Error("Unsupported protocol version", slog.String(LogKeyClient, clientAddr), slog.Int("major", major))
				return
			}
		case DovecotCmdCPID:
			cpid, err := decoder.DecodeCPID(args)
			if err != nil {
				sessionLogger().Error("Invalid CPID", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
				return
			}
			sessionLogger().Debug("Client CPID received", slog.String(LogKeyClient, clientAddr), slog.String("cpid", cpid))
			clientHandshakeDone = true
		default:
			sessionLogger().Warn("Unexpected command during handshake", slog.String(LogKeyClient, clientAddr), slog.String("command", string(cmd)))
		}
	}

	// Track active mechanism sessions for multi-step auth (keyed by request ID)
	activeMechanisms := make(map[string]SASLMechanism)
	activeAuthRequests := make(map[string]*DovecotAuthRequest)
	activeObservabilityStates = make(map[string]*saslObservabilityState)

	// Process AUTH and CONT commands
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return
			}

			line, err := reader.ReadString('\n')
			if err != nil {
				if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
					continue
				}
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || isConnectionResetError(err) {
					return
				}
				sessionLogger().Error("Error reading command", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
				return
			}

			subSessionID := generateSessionID()
			reqLogger := sessionLogger().With(slog.String(LogKeySubSession, subSessionID))

			redacted := redactDovecotLine(strings.TrimSpace(line))
			reqLogger.Debug("Incoming Dovecot SASL request", slog.String(LogKeyClient, clientAddr), slog.String("request", redacted))

			cmd, args := decoder.ParseLine(line)
			if cmd == "" {
				continue
			}

			switch cmd {
			case DovecotCmdAuth:
				authReq, err := decoder.DecodeAuthRequest(args)
				if err != nil {
					reqLogger.Error("Invalid AUTH request", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
					if _, wErr := conn.Write([]byte(encoder.EncodeFail("0", "invalid request", "", false))); wErr != nil {
						return
					}
					continue
				}

				ensureDovecotAuthExternalSessionID(authReq, sessionID)

				reqLogger.Debug("AUTH request received",
					slog.String(LogKeyClient, clientAddr),
					slog.String("id", authReq.ID),
					slog.String("mechanism", authReq.Mechanism),
					slog.String("service", authReq.Service))

				mech := NewSASLMechanism(authReq.Mechanism)
				if mech == nil {
					if _, wErr := conn.Write([]byte(encoder.EncodeFail(authReq.ID, "unsupported mechanism", "", false))); wErr != nil {
						return
					}
					continue
				}

				state := activeObservabilityStates[authReq.ID]
				if state == nil {
					state = s.startDovecotSASLObservabilityState(clientAddr)
					activeObservabilityStates[authReq.ID] = state
				}

				state.ctx = context.WithValue(state.ctx, loggerKey, reqLogger)

				_, mechanismObs, mechanismSpan := startInternalSpanFromContext(state.ctx,
					dovecotSASLMechanismSpanName,
					attribute.String("pfxhttp.component", componentDovecotSASL),
					attribute.String("pfxhttp.name", safeMetricName(s.name)),
					attribute.String("pfxhttp.sasl.mechanism", authReq.Mechanism),
					attribute.String("pfxhttp.sasl.step", "start"),
				)
				result, creds := mech.Start(authReq.InitialResponse)

				finishObservedSpan(mechanismObs, mechanismSpan, nil)
				s.handleSASLResult(conn, encoder, reqLogger, clientAddr, authReq, mech, result, creds, activeMechanisms, activeAuthRequests, activeObservabilityStates)

			case DovecotCmdCont:
				contReq, err := decoder.DecodeContRequest(args)
				if err != nil {
					reqLogger.Error("Invalid CONT request", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
					continue
				}

				mech, ok := activeMechanisms[contReq.ID]
				if !ok {
					if _, wErr := conn.Write([]byte(encoder.EncodeFail(contReq.ID, "no active auth session", "", false))); wErr != nil {
						return
					}
					continue
				}

				authReq := activeAuthRequests[contReq.ID]

				state := activeObservabilityStates[contReq.ID]
				if state != nil {
					finishSASLContinuationWait(state, nil)
					state.ctx = context.WithValue(state.ctx, loggerKey, reqLogger)
				}

				mechanismCtx := s.ctx
				if state != nil {
					mechanismCtx = state.ctx
				}

				mechanismName := ""
				if authReq != nil {
					mechanismName = authReq.Mechanism
				}

				_, mechanismObs, mechanismSpan := startInternalSpanFromContext(mechanismCtx,
					dovecotSASLMechanismSpanName,
					attribute.String("pfxhttp.component", componentDovecotSASL),
					attribute.String("pfxhttp.name", safeMetricName(s.name)),
					attribute.String("pfxhttp.sasl.mechanism", mechanismName),
					attribute.String("pfxhttp.sasl.step", "continue"),
				)
				result, creds := mech.Continue(contReq.Data)

				finishObservedSpan(mechanismObs, mechanismSpan, nil)
				s.handleSASLResult(conn, encoder, reqLogger, clientAddr, authReq, mech, result, creds, activeMechanisms, activeAuthRequests, activeObservabilityStates)

			default:
				reqLogger.Warn("Unknown command", slog.String(LogKeyClient, clientAddr), slog.String("command", string(cmd)))
			}
		}
	}
}

// redactDovecotLine removes or masks sensitive parts from a raw Dovecot SASL protocol line for safe logging.
func redactDovecotLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return line
	}

	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return line
	}

	cmd := fields[0]

	// Mask AUTH resp=... parameter which can carry base64 credentials
	if cmd == string(DovecotCmdAuth) {
		var b strings.Builder
		for i, p := range fields {
			if i > 0 {
				b.WriteByte(' ')
			}
			if strings.HasPrefix(p, "resp=") {
				b.WriteString("resp=<redacted>")
			} else {
				b.WriteString(p)
			}
		}
		return b.String()
	}

	// Mask CONT <id> <base64data>
	if cmd == string(DovecotCmdCont) {
		if len(fields) >= 3 {
			fields[2] = "<redacted>"
		}
	}

	return strings.Join(fields, " ")
}

func (s *MultiServer) startDovecotSASLObservabilityState(clientAddr string) *saslObservabilityState {
	authCtx, obs, span := s.startApplicationSpan(componentDovecotSASL, s.name, clientAddr)

	return &saslObservabilityState{
		ctx:   authCtx,
		obs:   obs,
		span:  span,
		start: time.Now(),
	}
}

func startSASLContinuationWait(state *saslObservabilityState, name string, authReq *DovecotAuthRequest) {
	if state == nil || authReq == nil {
		return
	}

	_, obs, span := startInternalSpanFromContext(state.ctx,
		dovecotSASLWaitSpanName,
		attribute.String("pfxhttp.component", componentDovecotSASL),
		attribute.String("pfxhttp.name", safeMetricName(name)),
		attribute.String("pfxhttp.sasl.id", authReq.ID),
		attribute.String("pfxhttp.sasl.mechanism", authReq.Mechanism),
	)
	state.waitObs = obs
	state.waitSpan = span
}

func finishSASLContinuationWait(state *saslObservabilityState, err error) {
	if state == nil || state.waitSpan == nil {
		return
	}

	finishObservedSpan(state.waitObs, state.waitSpan, err)
	state.waitObs = nil
	state.waitSpan = nil
}

// handleSASLResult processes the result of a SASL mechanism step and sends the appropriate protocol response.
func (s *MultiServer) handleSASLResult(
	conn net.Conn,
	encoder *DovecotEncoder,
	logger *slog.Logger,
	clientAddr string,
	authReq *DovecotAuthRequest,
	mech SASLMechanism,
	result *SASLAuthResult,
	creds *SASLCredentials,
	activeMechanisms map[string]SASLMechanism,
	activeAuthRequests map[string]*DovecotAuthRequest,
	activeObservabilityStates map[string]*saslObservabilityState,
) {
	if activeObservabilityStates == nil {
		activeObservabilityStates = make(map[string]*saslObservabilityState)
	}

	state := activeObservabilityStates[authReq.ID]
	if state == nil {
		state = s.startDovecotSASLObservabilityState(clientAddr)
	}

	finishSASLContinuationWait(state, nil)

	authCtx := state.ctx
	obs := state.obs
	span := state.span
	authCtx = context.WithValue(authCtx, loggerKey, logger)
	state.ctx = authCtx
	outcome := outcomeFromSASLResult(result, nil)
	finishSpan := true

	defer func() {
		if !finishSpan {
			return
		}

		delete(activeObservabilityStates, authReq.ID)
		s.finishApplicationSpan(state.ctx, state.obs, state.span, componentDovecotSASL, s.name, outcome, state.start)
	}()

	// If mechanism needs continuation, send CONT and store state
	if result != nil && result.NeedContinuation {
		activeMechanisms[authReq.ID] = mech
		activeAuthRequests[authReq.ID] = authReq
		activeObservabilityStates[authReq.ID] = state
		finishSpan = false

		resp := encoder.EncodeCont(authReq.ID, result.ContinuationChallenge)
		logger.Debug("Outgoing Dovecot SASL response", slog.String(LogKeyClient, clientAddr), slog.String("response", redactDovecotLine(resp)))

		_, writeObs, writeSpan := startInternalSpanFromContext(authCtx,
			dovecotSASLResponseSpanName,
			attribute.String("pfxhttp.component", componentDovecotSASL),
			attribute.String("pfxhttp.name", safeMetricName(s.name)),
			attribute.String("pfxhttp.sasl.command", string(DovecotCmdCont)),
		)
		_, err := conn.Write([]byte(resp))
		finishObservedSpan(writeObs, writeSpan, err)

		if err != nil {
			logger.Error("Error writing CONT", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
		} else {
			startSASLContinuationWait(state, s.name, authReq)
		}

		return
	}

	// If mechanism returned a direct failure
	if result != nil && !result.Success {
		delete(activeMechanisms, authReq.ID)
		delete(activeAuthRequests, authReq.ID)

		sendDovecotFail(authCtx, conn, encoder, logger, clientAddr, authReq.ID, result.Reason, result.Username, result.Temporary)

		return
	}

	// Credentials extracted - authenticate against backend
	if creds != nil {
		delete(activeMechanisms, authReq.ID)
		delete(activeAuthRequests, authReq.ID)

		currentConfig := s.deps.GetConfig()
		if currentConfig == nil {
			outcome = outcomeTempfail
			logger.Error("Authentication error",
				slog.String(LogKeyClient, clientAddr),
				slog.String("username", creds.Username),
				slog.String("error", "configuration not loaded"))

			sendDovecotFail(authCtx, conn, encoder, logger, clientAddr, authReq.ID, "internal error", creds.Username, true)

			return
		}

		authenticator := newSASLAuthenticatorForEntry(currentConfig, s.name, s.deps)

		var authResult *SASLAuthResult
		var err error

		backendCtx, backendObs, backendSpan := startInternalSpanFromContext(authCtx,
			dovecotSASLBackendSpanName,
			attribute.String("pfxhttp.component", componentDovecotSASL),
			attribute.String("pfxhttp.name", safeMetricName(s.name)),
			attribute.String("pfxhttp.sasl.mechanism", authReq.Mechanism),
		)
		if IsOAuthMechanism(authReq.Mechanism) {
			authResult, err = authenticator.AuthenticateToken(backendCtx, creds.Username, creds.Token, authReq)
		} else {
			authResult, err = authenticator.AuthenticatePassword(backendCtx, creds.Username, creds.Password, authReq)
		}

		finishObservedSpan(backendObs, backendSpan, err)

		outcome = outcomeFromSASLResult(authResult, err)

		if err != nil {
			if obs != nil {
				obs.RecordSpanError(span, err)
			}
			logger.Error("Authentication error",
				slog.String(LogKeyClient, clientAddr),
				slog.String("username", creds.Username),
				slog.String("error", err.Error()))

			resp := encoder.EncodeFail(authReq.ID, "internal error", creds.Username, true)
			logger.Debug("Outgoing Dovecot SASL response", slog.String(LogKeyClient, clientAddr), slog.String("response", redactDovecotLine(resp)))

			_, writeObs, writeSpan := startInternalSpanFromContext(authCtx,
				dovecotSASLResponseSpanName,
				attribute.String("pfxhttp.component", componentDovecotSASL),
				attribute.String("pfxhttp.name", safeMetricName(s.name)),
				attribute.String("pfxhttp.sasl.command", string(DovecotCmdFail)),
			)
			_, wErr := conn.Write([]byte(resp))
			finishObservedSpan(writeObs, writeSpan, wErr)

			if wErr != nil {
				logger.Error("Error writing FAIL", slog.String(LogKeyClient, clientAddr), slog.String("error", wErr.Error()))
			}

			return
		}

		if authResult.Success {
			username := creds.Username
			if authResult.Username != "" {
				username = authResult.Username
			}

			logger.Info("Authentication successful",
				slog.String(LogKeyClient, clientAddr),
				slog.String("username", username),
				slog.String("mechanism", authReq.Mechanism))

			resp := encoder.EncodeOK(authReq.ID, username)
			logger.Debug("Outgoing Dovecot SASL response", slog.String(LogKeyClient, clientAddr), slog.String("response", redactDovecotLine(resp)))

			_, writeObs, writeSpan := startInternalSpanFromContext(authCtx,
				dovecotSASLResponseSpanName,
				attribute.String("pfxhttp.component", componentDovecotSASL),
				attribute.String("pfxhttp.name", safeMetricName(s.name)),
				attribute.String("pfxhttp.sasl.command", string(DovecotCmdOK)),
			)
			_, wErr := conn.Write([]byte(resp))
			finishObservedSpan(writeObs, writeSpan, wErr)

			if wErr != nil {
				logger.Error("Error writing OK", slog.String(LogKeyClient, clientAddr), slog.String("error", wErr.Error()))
			}
		} else {
			logger.Info("Authentication failed",
				slog.String(LogKeyClient, clientAddr),
				slog.String("username", creds.Username),
				slog.String("mechanism", authReq.Mechanism),
				slog.String("reason", authResult.Reason))

			sendDovecotFail(authCtx, conn, encoder, logger, clientAddr, authReq.ID, authResult.Reason, creds.Username, authResult.Temporary)
		}
	}
}

// startApplicationSpan creates a protocol request context and server span.
func (s *MultiServer) startApplicationSpan(component, name, clientAddr string) (context.Context, *Observability, trace.Span) {
	ctx := s.ctx

	obs := s.deps.GetObservability()
	if obs == nil {
		return ctx, nil, trace.SpanFromContext(ctx)
	}

	ctx = ContextWithObservability(ctx, obs)
	spanName := applicationSpanName(component, name)
	ctx, span := obs.StartSpanWithKind(ctx,
		spanName,
		trace.SpanKindServer,
		attribute.String("pfxhttp.component", component),
		attribute.String("pfxhttp.name", safeMetricName(name)),
		attribute.String("network.peer.address", clientAddr),
	)

	return ctx, obs, span
}

// finishApplicationSpan records protocol request metrics and completes the span.
func (s *MultiServer) finishApplicationSpan(ctx context.Context, obs *Observability, span trace.Span, component, name, outcome string, start time.Time) {
	if obs == nil {
		return
	}

	span.SetAttributes(attribute.String(labelOutcome, outcome))

	if outcome == outcomeError || outcome == outcomeTempfail {
		span.SetStatus(codes.Error, outcome)
	}

	obs.ObserveApplicationRequest(ctx, component, safeMetricName(name), safeMetricName(s.name), outcome, time.Since(start))
	span.End()
}

// applicationSpanName returns the low-cardinality server span name for one protocol request.
func applicationSpanName(component, name string) string {
	switch component {
	case componentSocketMap:
		return socketMapSpanName(name)
	case componentPolicyService:
		return policyServiceSpanName(name)
	case componentDovecotSASL:
		return dovecotSASLSpanName(name)
	default:
		return component + " " + safeMetricName(name)
	}
}

// sendDovecotFail encodes and sends a FAIL response over the Dovecot SASL protocol, logging the response and any write errors.
func sendDovecotFail(ctx context.Context, conn net.Conn, encoder *DovecotEncoder, logger *slog.Logger, clientAddr string, id string, reason string, username string, temporary bool) {
	resp := encoder.EncodeFail(id, reason, username, temporary)
	logger.Debug("Outgoing Dovecot SASL response", slog.String(LogKeyClient, clientAddr), slog.String("response", redactDovecotLine(resp)))

	_, writeObs, writeSpan := startInternalSpanFromContext(ctx,
		dovecotSASLResponseSpanName,
		attribute.String("pfxhttp.component", componentDovecotSASL),
		attribute.String("pfxhttp.sasl.command", string(DovecotCmdFail)),
	)
	_, err := conn.Write([]byte(resp))
	finishObservedSpan(writeObs, writeSpan, err)

	if err != nil {
		logger.Error("Error writing FAIL", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
	}
}

// isConnectionResetError checks if the given error is a "connection reset by peer" error in a network operation.
func isConnectionResetError(err error) bool {
	if netOpErr, ok := errors.AsType[*net.OpError](err); ok {
		if netOpErr.Err.Error() == "read: connection reset by peer" {
			return true
		}
	}

	return false
}

// readNetString reads and parses a NetString from the specified network connection, returning the parsed NetString or an error.
func (s *MultiServer) readNetString(conn net.Conn) (*NetString, error) {
	lengthBuf := make([]byte, 0, 10)

	for {
		endLoop := false

		select {
		case <-s.ctx.Done():
			return nil, io.EOF
		default:
			singleByte := make([]byte, 1)

			err := conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if err != nil {
				return nil, err
			}

			_, err = conn.Read(singleByte)
			if err != nil {
				if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
					continue
				}

				if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || isConnectionResetError(err) {
					return nil, nil
				}

				return nil, err
			}

			if singleByte[0] == ':' {
				endLoop = true

				break
			}

			lengthBuf = append(lengthBuf, singleByte[0])
		}

		if endLoop {
			break
		}
	}

	length, err := strconv.Atoi(string(lengthBuf))
	if err != nil {
		return nil, fmt.Errorf("invalid length: %w", err)
	}

	data := make([]byte, length)

	_, err = io.ReadFull(conn, data)
	if err != nil {
		return nil, fmt.Errorf("could not read data: %w", err)
	}

	trailingByte := make([]byte, 1)

	_, err = conn.Read(trailingByte)
	if err != nil {
		return nil, fmt.Errorf("error reading trailing comma: %w", err)
	}

	if trailingByte[0] != ',' {
		return nil, fmt.Errorf("missing trailing comma")
	}

	return NewNetString(data), nil
}

// writeNetString encodes the given NetString and writes it to the specified network connection.
// It combines the NetString's length, data, and trailing comma into a single message and sends it via the connection.
// Returns an error if the write operation fails.
func (s *MultiServer) writeNetString(conn net.Conn, netString NetData) error {
	length := strconv.Itoa(int(netString.Length()))
	payload := netString.Data()

	// Combine <length>:<data>, into a single byte slice
	message := append([]byte(length+":"), payload...)
	message = append(message, ',')

	_, err := conn.Write(message)
	if err != nil {
		return fmt.Errorf("could not write NetString: %w", err)
	}

	return nil
}

// writePolicyResult writes the specified policy result to the given network connection.
// Returns an error if the write operation fails.
func (s *MultiServer) writePolicyResult(conn net.Conn, result string) error {
	// Set a write deadline to avoid long hangs
	err := conn.SetWriteDeadline(time.Now().Add(300 * time.Second))
	if err != nil {
		return err
	}

	_, err = conn.Write([]byte(result))
	if err != nil {
		return err
	}

	return nil
}

func (s *MultiServer) readPolicy(conn net.Conn) (Policy, error) {
	policy := NewPostfixPolicy()
	reader := bufio.NewReader(conn)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return nil, fmt.Errorf("error while reading from the connection: %w", err)
		}

		line = strings.TrimSpace(line)

		if line == "" {
			break
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format: '%s'", line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		policy.SetData(key, value)
	}

	return policy, nil
}

// requiredChrootFiles lists files that must exist inside the chroot directory
// for the Go runtime to function correctly (DNS resolution, name lookups).
var requiredChrootFiles = []string{
	"etc/resolv.conf",
	"etc/hosts",
	"etc/nsswitch.conf",
}

// PerformChroot changes the root directory of the current process to the specified path.
func PerformChroot(chrootDir string, logger *slog.Logger) error {
	if chrootDir == "" {
		return nil
	}

	if os.Getuid() != 0 {
		return fmt.Errorf("chroot requires root privileges")
	}

	// Verify that essential runtime files exist inside the chroot
	var missing []string

	for _, f := range requiredChrootFiles {
		path := filepath.Join(chrootDir, f)
		if _, err := os.Stat(path); err != nil {
			missing = append(missing, f)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("chroot %s is missing required files: %s", chrootDir, strings.Join(missing, ", "))
	}

	if err := syscall.Chroot(chrootDir); err != nil {
		return fmt.Errorf("could not chroot to %s: %w", chrootDir, err)
	}

	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("could not chdir to / after chroot: %w", err)
	}

	logger.Info("Changed root directory", slog.String("chroot", chrootDir))

	return nil
}

// Credentials holds resolved numeric user and group IDs for privilege dropping.
type Credentials struct {
	UID               int
	GID               int
	SupplementaryGIDs []int
	HasUser           bool
	HasGroup          bool
	UserName          string
	GroupName         string
}

// ResolveCredentials looks up the numeric UID and GID for the given user and group names.
// This must be called before chroot, because it needs access to /etc/passwd and /etc/group.
func ResolveCredentials(runAsUser, runAsGroup string) (*Credentials, error) {
	creds := &Credentials{}

	if runAsUser != "" {
		u, err := user.Lookup(runAsUser)
		if err != nil {
			return nil, fmt.Errorf("could not lookup user %s: %w", runAsUser, err)
		}

		uid, err := strconv.ParseInt(u.Uid, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("could not parse uid %q: %w", u.Uid, err)
		}

		creds.UID = int(uid)
		creds.HasUser = true
		creds.UserName = runAsUser

		groupIDs, err := u.GroupIds()
		if err != nil {
			return nil, fmt.Errorf("could not lookup supplementary groups for user %s: %w", runAsUser, err)
		}

		for _, gidStr := range groupIDs {
			sgid, err := strconv.ParseInt(gidStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("could not parse supplementary gid %q: %w", gidStr, err)
			}

			creds.SupplementaryGIDs = append(creds.SupplementaryGIDs, int(sgid))
		}
	}

	if runAsGroup != "" {
		g, err := user.LookupGroup(runAsGroup)
		if err != nil {
			return nil, fmt.Errorf("could not lookup group %s: %w", runAsGroup, err)
		}

		gid, err := strconv.ParseInt(g.Gid, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("could not parse gid %q: %w", g.Gid, err)
		}

		creds.GID = int(gid)
		creds.HasGroup = true
		creds.GroupName = runAsGroup
	}

	return creds, nil
}

// DropPrivileges drops the process's root privileges using pre-resolved credentials.
func DropPrivileges(creds *Credentials, logger *slog.Logger) error {
	if creds == nil || (!creds.HasUser && !creds.HasGroup) {
		return nil
	}

	if os.Getuid() != 0 {
		return nil
	}

	currentUID := os.Getuid()
	currentGID := os.Getgid()

	// If we are already running as the target user/group, there's nothing to do.
	// This also avoids clearing supplementary groups if stay as root.
	if (!creds.HasUser || creds.UID == currentUID) && (!creds.HasGroup || creds.GID == currentGID) {
		return nil
	}

	// Set supplementary groups for the target user (or clear them if none were resolved)
	if err := syscall.Setgroups(creds.SupplementaryGIDs); err != nil {
		return fmt.Errorf("could not set supplementary groups: %w", err)
	}

	if creds.HasGroup {
		if err := syscall.Setgid(creds.GID); err != nil {
			return fmt.Errorf("could not set gid to %d: %w", creds.GID, err)
		}
		logger.Info("Dropped group privileges", slog.String("group", creds.GroupName), slog.Int("gid", creds.GID))
	}

	if creds.HasUser {
		if err := syscall.Setuid(creds.UID); err != nil {
			return fmt.Errorf("could not set uid to %d: %w", creds.UID, err)
		}
		logger.Info("Dropped user privileges", slog.String("user", creds.UserName), slog.Int("uid", creds.UID))
	}

	return nil
}
