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

const socketMapTemporaryResponse = "TEMP service temporarily unavailable"
const policyTemporaryResponse = "action=DEFER_IF_PERMIT Service temporarily unavailable\n\n"
const defaultDovecotWriteTimeout = 10 * time.Second
const unknownBackendName = "unknown"

// generateExternalSessionID creates an opaque backend correlation value. It is
// never attached to logs, metrics, or traces.
func generateExternalSessionID() string {
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
	supervisor *ConnectionSupervisor
	limiter    *RequestLimiter

	requestTimeout       time.Duration
	backendTimeout       time.Duration
	responseWriteReserve time.Duration
	protocolLimits       ProtocolLimitsConfig
	stopOnce             sync.Once
	overloadLogCounter   atomic.Uint64
}

// NewMultiServer creates and initializes a new MultiServer instance with the provided context and dependencies.
func NewMultiServer(ctx context.Context, deps *Deps, supervisor *ConnectionSupervisor) GenericServer {
	childCtx, closer := context.WithCancel(ctx)
	if supervisor == nil {
		supervisor = NewConnectionSupervisor(childCtx, defaultMaxConnections)
	}

	return &MultiServer{
		deps:       deps,
		ctx:        childCtx,
		closer:     closer,
		supervisor: supervisor,
	}
}

// Listen initializes the listener for the MultiServer based on the provided configuration.
func (s *MultiServer) Listen(instance Listen, activatedListener net.Listener) error {
	s.setEndpoint(instance)
	s.kind = instance.Kind
	s.protocolLimits = instance.ProtocolLimits

	s.requestTimeout = instance.Limits.RequestTimeout
	if s.requestTimeout <= 0 {
		s.requestTimeout = defaultRequestTimeout
	}

	s.backendTimeout = instance.Limits.BackendTimeout
	if s.backendTimeout <= 0 {
		s.backendTimeout = defaultBackendTimeout
	}

	s.responseWriteReserve = instance.Limits.ResponseWriteReserve
	if s.responseWriteReserve <= 0 {
		s.responseWriteReserve = defaultResponseWriteReserve
	}

	if s.limiter == nil {
		queueTimeout := instance.Limits.RequestQueueTimeout
		if queueTimeout <= 0 {
			queueTimeout = defaultRequestQueueTimeout
		}

		s.limiter = NewRequestLimiter(
			s.ctx,
			instance.Limits.MaxInflightRequests,
			maxQueuedRequests(instance.Limits),
			queueTimeout,
		)
	}

	if instance.Name != "" {
		s.name = instance.Name
	}

	if obs := s.deps.GetObservability(); obs != nil {
		s.limiter.SetObserver(func(event requestLimiterEvent) {
			obs.ObserveRequestLimiter(s.ctx, s.kind, safeMetricName(s.name), event)
		})
	}

	if activatedListener != nil {
		s.listener = activatedListener
	} else if err := s.listenNative(instance); err != nil {
		return err
	}

	logAttributes := []any{
		slog.String("type", instance.Type),
		slog.String("address", s.address),
		slog.String("name", s.name),
		slog.String("kind", instance.Kind),
		slog.Int("max_connections", instance.Limits.MaxConnections),
		slog.Int("max_inflight_requests", instance.Limits.MaxInflightRequests),
		slog.Int("max_queued_requests", maxQueuedRequests(instance.Limits)),
		slog.Duration("request_queue_timeout", instance.Limits.RequestQueueTimeout),
		slog.Duration("request_timeout", s.requestTimeout),
		slog.Duration("backend_timeout", s.backendTimeout),
		slog.Duration("response_write_reserve", s.responseWriteReserve),
	}
	logAttributes = append(logAttributes, protocolLimitLogAttributes(instance.Kind, s.effectiveProtocolLimits())...)
	s.deps.GetLogger().Info("Server is listening", logAttributes...)

	return nil
}

func protocolLimitLogAttributes(kind string, limits ProtocolLimitsConfig) []any {
	switch kind {
	case listenKindSocketMap:
		return []any{
			slog.Duration("idle_timeout", protocolIdleTimeout(limits.SocketMap.IdleTimeout)),
			slog.Duration("partial_request_timeout", limits.SocketMap.PartialRequestTimeout),
			slog.Duration("write_timeout", limits.SocketMap.WriteTimeout),
			slog.Int("max_request_bytes", limits.SocketMap.MaxRequestBytes),
			slog.Int("max_length_digits", limits.SocketMap.MaxLengthDigits),
		}
	case listenKindPolicyService:
		return []any{
			slog.Duration("idle_timeout", protocolIdleTimeout(limits.PolicyService.IdleTimeout)),
			slog.Duration("partial_request_timeout", limits.PolicyService.PartialRequestTimeout),
			slog.Duration("write_timeout", limits.PolicyService.WriteTimeout),
			slog.Int("max_request_bytes", limits.PolicyService.MaxRequestBytes),
			slog.Int("max_line_bytes", limits.PolicyService.MaxLineBytes),
			slog.Int("max_attributes", limits.PolicyService.MaxAttributes),
		}
	case listenKindDovecotSASL:
		return []any{
			slog.Duration("idle_timeout", protocolIdleTimeout(limits.DovecotSASL.IdleTimeout)),
			slog.Duration("partial_request_timeout", limits.DovecotSASL.PartialRequestTimeout),
			slog.Duration("write_timeout", limits.DovecotSASL.WriteTimeout),
			slog.Int("max_line_bytes", limits.DovecotSASL.MaxLineBytes),
		}
	default:
		return nil
	}
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
		s.deps.GetLogger().Error("Could not parse socket mode", slog.String("reason", boundedErrorKind(err)))

		return
	}

	if err = os.Chmod(instance.Address, os.FileMode(mode)); err != nil {
		s.deps.GetLogger().Error("Could not set permissions on socket", slog.String("reason", boundedErrorKind(err)))
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
		s.deps.GetLogger().Error("Could not set ownership on socket", slog.String("reason", boundedErrorKind(err)))
	}
}

// lookupSocketOwner resolves configured Unix socket user and group names to numeric IDs.
func lookupSocketOwner(instance Listen, logger *slog.Logger) (int, int) {
	uid, gid := -1, -1

	if instance.User != "" {
		u, err := user.Lookup(instance.User)
		if err != nil {
			logger.Error("Could not lookup socket owner", slog.String("reason", boundedErrorKind(err)))
		} else {
			uid, _ = strconv.Atoi(u.Uid)
		}
	}

	if instance.Group != "" {
		g, err := user.LookupGroup(instance.Group)
		if err != nil {
			logger.Error("Could not lookup socket group", slog.String("reason", boundedErrorKind(err)))
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
			s.deps.GetLogger().Error("Error accepting connection", slog.String("reason", boundedErrorKind(err)))

			if obs := s.deps.GetObservability(); obs != nil {
				obs.ObserveListenerConnection(s.ctx, s.kind, safeMetricName(s.name), eventAccept, resultError, 0)
			}

			continue
		}

		if obs := s.deps.GetObservability(); obs != nil {
			obs.ObserveListenerConnection(s.ctx, s.kind, safeMetricName(s.name), eventAccept, resultOK, 1)
		}

		if !s.supervisor.Admit(conn, handler) {
			if obs := s.deps.GetObservability(); obs != nil {
				obs.ObserveListenerConnection(s.ctx, s.kind, safeMetricName(s.name), "admission_reject", resultError, -1)
			}
		}
	}
}

// Stop gracefully shuts down the MultiServer by stopping connections, waiting for all routines to complete, and closing the listener.
func (s *MultiServer) Stop() {
	s.stopOnce.Do(func() {
		if s.closer != nil {
			s.closer()
		}

		if s.listener != nil {
			_ = s.listener.Close()
		}

		if s.limiter != nil {
			s.limiter.Stop()
		}

		drainCtx, cancelDrain := context.WithTimeout(context.Background(), defaultConnectionDrainTimeout)
		defer cancelDrain()

		drained := s.supervisor.StopContext(drainCtx)
		if obs := s.deps.GetObservability(); obs != nil {
			result := resultOK
			if !drained {
				result = resultError
			}

			obs.ObserveListenerDrain(context.Background(), s.kind, safeMetricName(s.name), result)
		}
	})
}

func (s *MultiServer) GetContext() context.Context {
	return s.ctx
}

func (s *MultiServer) requestContext(parent context.Context) (context.Context, context.CancelFunc) {
	timeout := s.requestTimeout
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}

	return context.WithTimeout(parent, timeout)
}

func (s *MultiServer) requestContextForConnection(parent context.Context, conn net.Conn) (context.Context, context.CancelFunc) {
	peerCtx, cancelPeer := contextWithPeerClose(parent, conn)
	requestCtx, cancelRequest := s.requestContext(peerCtx)

	return requestCtx, func() {
		cancelRequest()
		cancelPeer()
	}
}

func (s *MultiServer) backendContext(parent context.Context) (context.Context, context.CancelFunc) {
	backendTimeout := s.backendTimeout
	if backendTimeout <= 0 {
		backendTimeout = defaultBackendTimeout
	}

	backendDeadline := time.Now().Add(backendTimeout)
	if deadline, ok := parent.Deadline(); ok && s.responseWriteReserve > 0 {
		reservedDeadline := deadline.Add(-s.responseWriteReserve)
		if reservedDeadline.Before(backendDeadline) {
			backendDeadline = reservedDeadline
		}
	}

	return context.WithDeadline(parent, backendDeadline)
}

func (s *MultiServer) executeRequest(
	ctx context.Context,
	work func(context.Context) error,
) (outcome RequestAdmissionOutcome, err error) {
	if s.limiter == nil {
		return requestAdmitted, work(ctx)
	}

	permit, outcome := s.acquireRequest(ctx)
	if permit == nil {
		return outcome, nil
	}
	defer permit.Release()
	defer func() {
		if recover() != nil {
			err = errRequestExecutionPanic
		}
	}()

	return outcome, work(ctx)
}

func (s *MultiServer) acquireRequest(ctx context.Context) (*RequestPermit, RequestAdmissionOutcome) {
	if s.limiter == nil {
		return nil, requestAdmitted
	}

	queueCtx, obs, span := startInternalSpanFromContext(ctx,
		requestQueueSpanName,
		attribute.String("pfxhttp.component", s.kind),
		attribute.String("pfxhttp.listener", safeMetricName(s.name)),
	)
	permit, outcome := s.limiter.Acquire(queueCtx)
	setSpanAttributes(span, attribute.String(labelOutcome, string(outcome)))
	finishObservedSpan(obs, span, nil)

	return permit, outcome
}

func requestOverloaded(outcome RequestAdmissionOutcome) bool {
	return outcome == requestQueueFull || outcome == requestQueueTimeout ||
		outcome == requestCallerCanceled || outcome == requestServerShutdown
}

func configuredSocketMapName(config *Config, requested string) string {
	if config == nil {
		return unknownBackendName
	}

	if _, ok := config.SocketMaps[requested]; !ok {
		return unknownBackendName
	}

	return safeMetricName(requested)
}

func (s *MultiServer) logRequestOverload(logger *slog.Logger, outcome RequestAdmissionOutcome) {
	count := s.overloadLogCounter.Add(1)
	if count != 1 && count%100 != 0 {
		return
	}

	logger.Warn("Listener request admission rejected",
		slog.String("listener", safeMetricName(s.name)),
		slog.String("component", s.kind),
		slog.String("outcome", string(outcome)),
		slog.Uint64("occurrences", count))
}

func setWriteDeadlineFromContext(ctx context.Context, conn net.Conn) (func(), error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return func() {}, nil
	}

	if err := conn.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}

	return func() { _ = conn.SetWriteDeadline(time.Time{}) }, nil
}

func contextWithOptionalTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(parent)
	}

	deadline := time.Now().Add(timeout)
	if parentDeadline, ok := parent.Deadline(); ok && parentDeadline.Before(deadline) {
		return context.WithCancel(parent)
	}

	return context.WithDeadline(parent, deadline)
}

var _ GenericServer = (*MultiServer)(nil)

func (s *MultiServer) effectiveProtocolLimits() ProtocolLimitsConfig {
	return resolveProtocolLimits(defaultProtocolLimitsConfig(), s.protocolLimits)
}

func (s *MultiServer) socketMapFramingLimits() socketMapFramingLimits {
	limits := s.effectiveProtocolLimits().SocketMap

	return socketMapFramingLimits{
		idleTimeout:     protocolIdleTimeout(limits.IdleTimeout),
		partialTimeout:  limits.PartialRequestTimeout,
		maxRequestBytes: limits.MaxRequestBytes,
		maxLengthDigits: limits.MaxLengthDigits,
	}
}

func (s *MultiServer) policyFramingLimits() policyFramingLimits {
	limits := s.effectiveProtocolLimits().PolicyService

	return policyFramingLimits{
		idleTimeout:     protocolIdleTimeout(limits.IdleTimeout),
		partialTimeout:  limits.PartialRequestTimeout,
		maxRequestBytes: limits.MaxRequestBytes,
		maxLineBytes:    limits.MaxLineBytes,
		maxAttributes:   limits.MaxAttributes,
	}
}

// setupConnection initializes connection logging and returns the client address,
// a reload-aware logger factory, and a cleanup function that should be deferred by the caller.
func (s *MultiServer) setupConnection(conn net.Conn) (clientAddr string, sessionLogger func() *slog.Logger, cleanup func()) {
	clientAddr = conn.RemoteAddr().String()
	start := time.Now()

	sessionLogger = func() *slog.Logger {
		return s.deps.GetLogger()
	}

	sessionLogger().Info("New connection established")

	cleanup = func() {
		sessionLogger().Info("Connection closed")

		_ = conn.Close()

		if obs := s.deps.GetObservability(); obs != nil {
			obs.ObserveListenerConnection(s.ctx, s.kind, safeMetricName(s.name), eventClose, resultOK, -1)
			obs.ObserveListenerDuration(s.ctx, s.kind, safeMetricName(s.name), resultOK, time.Since(start))
		}
	}

	return
}

// HandleNetStringConnection manages an individual client connection, processing requests and sending responses in NetString format.
func (s *MultiServer) HandleNetStringConnection(conn net.Conn) {
	clientAddr, sessionLogger, cleanup := s.setupConnection(conn)
	defer cleanup()

	reader := newSocketMapReader(conn, s.socketMapFramingLimits())
	if obs := s.deps.GetObservability(); obs != nil {
		reader.SetStateObserver(func(state string, delta int64) {
			obs.ObserveListenerState(s.ctx, s.kind, safeMetricName(s.name), state, delta)
		})
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			netString, err := reader.Read(s.ctx)
			if err != nil {
				if reason, ok := protocolErrorKindOf(err); ok {
					if obs := s.deps.GetObservability(); obs != nil {
						obs.ObserveProtocolFailure(s.ctx, s.kind, safeMetricName(s.name), reason)
					}
				}

				if errors.Is(err, io.EOF) || protocolErrorIs(err, protocolErrorClientClosed) || protocolErrorIs(err, protocolErrorServerShutdown) {
					return
				}

				sessionLogger().Error("Error reading NetString", slog.String("reason", boundedErrorKind(err)))

				return
			}

			requestCtx, obs, span := s.startApplicationSpan(componentSocketMap, defaultBackendName, clientAddr)
			requestCtx, cancelRequest := s.requestContextForConnection(requestCtx, conn)
			start := time.Now()

			reqLogger := sessionLogger()

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

				reqLogger.Error("Error reading request", slog.String("reason", boundedErrorKind(err)))
				s.finishApplicationSpan(requestCtx, obs, span, componentSocketMap, defaultBackendName, outcomeError, start)
				cancelRequest()

				return
			}

			telemetryName := configuredSocketMapName(s.deps.GetConfig(), received.GetName())
			span.SetName(applicationSpanName(componentSocketMap, telemetryName))
			span.SetAttributes(attribute.String("pfxhttp.name", telemetryName))
			reqLogger.Debug("SocketMap request decoded",
				slog.String("map", telemetryName))

			outcome := outcomeError
			responseData := ""
			admission, requestErr := s.executeRequest(requestCtx, func(executionCtx context.Context) error {
				client := NewMapClient(s.deps, reqLogger)
				client.SetReceiver(received)

				backendCtx, cancelBackend := s.backendContext(executionCtx)
				defer cancelBackend()

				backendCtx, backendObs, backendSpan := startInternalSpanFromContext(backendCtx,
					socketMapBackendSpanName,
					attribute.String("pfxhttp.component", componentSocketMap),
					attribute.String("pfxhttp.name", telemetryName),
				)
				backendErr := client.SendAndReceiveContext(backendCtx)
				finishObservedSpan(backendObs, backendSpan, backendErr)

				if backendErr != nil {
					return backendErr
				}

				outcome = outcomeFromSender(client.GetSender())
				_, encodeObs, encodeSpan := startInternalSpanFromContext(executionCtx,
					socketMapEncodeSpanName,
					attribute.String("pfxhttp.component", componentSocketMap),
					attribute.String("pfxhttp.name", telemetryName),
				)
				responseData = client.GetSender().String()
				response := NewNetStringFromString(responseData)

				finishObservedSpan(encodeObs, encodeSpan, nil)

				_, writeObs, writeSpan := startInternalSpanFromContext(executionCtx,
					socketMapWriteSpanName,
					attribute.String("pfxhttp.component", componentSocketMap),
					attribute.String("pfxhttp.name", telemetryName),
				)
				writeErr := s.writeNetStringContext(executionCtx, conn, response)
				finishObservedSpan(writeObs, writeSpan, writeErr)

				return writeErr
			})

			if requestOverloaded(admission) {
				s.logRequestOverload(reqLogger, admission)

				outcome = outcomeTempfail
				requestErr = s.writeNetStringContext(requestCtx, conn, NewNetStringFromString(socketMapTemporaryResponse))
			} else if requestErr != nil && errors.Is(requestErr, context.DeadlineExceeded) && requestCtx.Err() == nil {
				outcome = outcomeTempfail
				requestErr = s.writeNetStringContext(requestCtx, conn, NewNetStringFromString(socketMapTemporaryResponse))
			}

			if requestErr != nil {
				if obs != nil {
					obs.RecordSpanError(span, requestErr)
				}

				reqLogger.Error("SocketMap request failed", slog.String("reason", boundedErrorKind(requestErr)))
				s.finishApplicationSpan(requestCtx, obs, span, componentSocketMap, telemetryName, outcome, start)
				cancelRequest()

				return
			}

			reqLogger.Debug("SocketMap response sent")
			s.finishApplicationSpan(requestCtx, obs, span, componentSocketMap, telemetryName, outcome, start)
			cancelRequest()
		}
	}
}

// HandlePolicyServiceConnection manages a client connection for the Postfix policy service, handling requests and responses.
func (s *MultiServer) HandlePolicyServiceConnection(conn net.Conn) {
	clientAddr, sessionLogger, cleanup := s.setupConnection(conn)
	defer cleanup()

	reader := newPolicyReader(conn, s.policyFramingLimits())
	if obs := s.deps.GetObservability(); obs != nil {
		reader.SetStateObserver(func(state string, delta int64) {
			obs.ObserveListenerState(s.ctx, s.kind, safeMetricName(s.name), state, delta)
		})
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			policy, err := reader.Read(s.ctx)
			if err != nil {
				if reason, ok := protocolErrorKindOf(err); ok {
					if obs := s.deps.GetObservability(); obs != nil {
						obs.ObserveProtocolFailure(s.ctx, s.kind, safeMetricName(s.name), reason)
					}
				}

				if errors.Is(err, io.EOF) || protocolErrorIs(err, protocolErrorClientClosed) || protocolErrorIs(err, protocolErrorServerShutdown) {
					return
				}

				sessionLogger().Error("Error reading policy", slog.String("reason", boundedErrorKind(err)))

				return
			}

			requestCtx, obs, span := s.startApplicationSpan(componentPolicyService, s.name, clientAddr)
			requestCtx, cancelRequest := s.requestContextForConnection(requestCtx, conn)
			start := time.Now()

			reqLogger := sessionLogger()

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

				reqLogger.Error("Error reading request", slog.String("reason", boundedErrorKind(err)))
				s.finishApplicationSpan(requestCtx, obs, span, componentPolicyService, received.GetName(), outcomeError, start)
				cancelRequest()

				return
			}

			reqLogger.Debug("Policy request decoded",
				slog.String("service", safeMetricName(received.GetName())))

			outcome := outcomeError
			responseData := ""
			admission, requestErr := s.executeRequest(requestCtx, func(executionCtx context.Context) error {
				client := NewPolicyClient(s.deps, reqLogger)
				client.SetReceiver(received)

				backendCtx, cancelBackend := s.backendContext(executionCtx)
				defer cancelBackend()

				backendCtx, backendObs, backendSpan := startInternalSpanFromContext(backendCtx,
					policyServiceBackendSpanName,
					attribute.String("pfxhttp.component", componentPolicyService),
					attribute.String("pfxhttp.name", safeMetricName(received.GetName())),
				)
				backendErr := client.SendAndReceiveContext(backendCtx)
				finishObservedSpan(backendObs, backendSpan, backendErr)

				if backendErr != nil {
					return backendErr
				}

				outcome = outcomeFromSender(client.GetSender())
				_, encodeObs, encodeSpan := startInternalSpanFromContext(executionCtx,
					policyServiceEncodeSpanName,
					attribute.String("pfxhttp.component", componentPolicyService),
					attribute.String("pfxhttp.name", safeMetricName(received.GetName())),
				)
				responseData = fmt.Sprintf("action=%s\n\n", strings.TrimSpace(client.GetSender().String()))

				finishObservedSpan(encodeObs, encodeSpan, nil)

				_, writeObs, writeSpan := startInternalSpanFromContext(executionCtx,
					policyServiceWriteSpanName,
					attribute.String("pfxhttp.component", componentPolicyService),
					attribute.String("pfxhttp.name", safeMetricName(received.GetName())),
				)
				writeErr := s.writePolicyResultContext(executionCtx, conn, responseData)
				finishObservedSpan(writeObs, writeSpan, writeErr)

				return writeErr
			})

			if requestOverloaded(admission) {
				s.logRequestOverload(reqLogger, admission)

				outcome = outcomeTempfail
				responseData = policyTemporaryResponse
				requestErr = s.writePolicyResultContext(requestCtx, conn, responseData)
			} else if requestErr != nil && errors.Is(requestErr, context.DeadlineExceeded) && requestCtx.Err() == nil {
				outcome = outcomeTempfail
				responseData = policyTemporaryResponse
				requestErr = s.writePolicyResultContext(requestCtx, conn, responseData)
			}

			if requestErr != nil {
				outcome = outcomeError

				if obs != nil {
					obs.RecordSpanError(span, requestErr)
				}

				reqLogger.Error("Policy request failed", slog.String("reason", boundedErrorKind(requestErr)))
				s.finishApplicationSpan(requestCtx, obs, span, componentPolicyService, received.GetName(), outcome, start)
				cancelRequest()

				return
			}

			reqLogger.Debug("Policy response sent")
			s.finishApplicationSpan(requestCtx, obs, span, componentPolicyService, received.GetName(), outcome, start)
			cancelRequest()
		}
	}
}

// dovecotCUIDCounter is a global atomic counter for generating unique connection IDs in the Dovecot SASL protocol.
var dovecotCUIDCounter atomic.Uint64

type saslObservabilityState struct {
	ctx      context.Context
	cancel   context.CancelFunc
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
	externalSessionID := generateExternalSessionID()
	connectionStart := time.Now()

	// Always resolve the current logger so reloads take effect on persistent connections.
	sessionLogger := func() *slog.Logger {
		return s.deps.GetLogger()
	}

	var activeObservabilityStates map[string]*saslObservabilityState

	config := s.deps.GetConfig()

	sessionLogger().Info("New Dovecot SASL connection established")

	defer func() {
		sessionLogger().Info("Dovecot SASL connection closed")
		_ = conn.Close()

		if obs := s.deps.GetObservability(); obs != nil {
			obs.ObserveListenerConnection(s.ctx, s.kind, safeMetricName(s.name), eventClose, resultOK, -1)
			obs.ObserveListenerDuration(s.ctx, s.kind, safeMetricName(s.name), resultOK, time.Since(connectionStart))
		}

		for _, state := range activeObservabilityStates {
			sessionLogger().Warn("Dovecot SASL authentication abandoned")
			finishSASLContinuationWait(state, errors.New("authentication abandoned"))
			s.finishApplicationSpan(state.ctx, state.obs, state.span, componentDovecotSASL, s.name, outcomeError, state.start)
			state.cancel()
		}

	}()

	decoder := &DovecotDecoder{}
	encoder := &DovecotEncoder{}
	reader := bufio.NewReader(conn)
	dovecotLimits := s.effectiveProtocolLimits().DovecotSASL

	settings := config.DovecotSASL[s.name]
	mechanisms := dovecotSASLMechanisms(settings)
	allowedMechanisms := dovecotSASLMechanismSet(mechanisms)

	cuid := dovecotCUIDCounter.Add(1)
	handshake := &DovecotHandshake{
		Mechanisms: mechanisms,
		SPID:       strconv.Itoa(os.Getpid()),
		CUID:       strconv.FormatUint(cuid, 10),
		Cookie:     generateCookie(),
	}

	// Send server handshake
	for _, line := range encoder.EncodeHandshake(handshake) {
		if err := s.writeDovecotConnectionResponse(conn, line); err != nil {
			sessionLogger().Error("Error writing handshake", slog.String("reason", boundedErrorKind(err)))
			return
		}
	}

	sessionLogger().Debug("Handshake sent")

	// Read client handshake (VERSION + CPID)
	clientHandshakeDone := false

	if err := conn.SetReadDeadline(time.Now().Add(dovecotLimits.PartialRequestTimeout)); err != nil {
		return
	}
	for !clientHandshakeDone {
		line, err := readBoundedLine(reader, dovecotLimits.MaxLineBytes)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}

			sessionLogger().Error("Error reading client handshake", slog.String("reason", boundedErrorKind(err)))
			return
		}

		cmd, args := decoder.ParseLine(line)
		switch cmd {
		case DovecotCmdVersion:
			major, _, err := decoder.DecodeVersion(args)
			if err != nil {
				sessionLogger().Error("Invalid client VERSION", slog.String("reason", string(protocolErrorInvalidFrame)))
				return
			}
			if major != DovecotProtoVersionMajor {
				sessionLogger().Error("Unsupported protocol version", slog.Int("major", major))
				return
			}
		case DovecotCmdCPID:
			_, err := decoder.DecodeCPID(args)
			if err != nil {
				sessionLogger().Error("Invalid CPID", slog.String("reason", string(protocolErrorInvalidFrame)))
				return
			}

			sessionLogger().Debug("Client CPID received")
			clientHandshakeDone = true
		default:
			sessionLogger().Warn("Unexpected command during handshake", slog.String("command", unknownBackendName))
		}
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return
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
			obs := s.deps.GetObservability()
			if obs != nil {
				obs.ObserveListenerState(s.ctx, s.kind, safeMetricName(s.name), "idle", 1)
			}

			if err := conn.SetReadDeadline(s.nextDovecotReadDeadline(activeObservabilityStates)); err != nil {
				if obs != nil {
					obs.ObserveListenerState(s.ctx, s.kind, safeMetricName(s.name), "idle", -1)
				}
				return
			}

			first, err := reader.ReadByte()

			if obs != nil {
				obs.ObserveListenerState(s.ctx, s.kind, safeMetricName(s.name), "idle", -1)
			}

			line := ""

			if err == nil {
				if obs != nil {
					obs.ObserveListenerState(s.ctx, s.kind, safeMetricName(s.name), "partial", 1)
				}

				if deadlineErr := conn.SetReadDeadline(s.nextDovecotPartialDeadline(activeObservabilityStates)); deadlineErr != nil {
					err = deadlineErr
				} else {
					line, err = readBoundedLineFromFirst(reader, first, dovecotLimits.MaxLineBytes)
				}

				if obs != nil {
					obs.ObserveListenerState(s.ctx, s.kind, safeMetricName(s.name), "partial", -1)
				}
			}

			if err != nil {
				if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
					if len(line) > 0 {
						if obs != nil {
							obs.ObserveProtocolFailure(s.ctx, s.kind, safeMetricName(s.name), protocolErrorPartialTimeout)
						}

						sessionLogger().Warn("Dovecot SASL partial command timed out",
							slog.String("reason", string(protocolErrorPartialTimeout)))

						return
					}

					if len(activeObservabilityStates) == 0 && protocolIdleTimeout(dovecotLimits.IdleTimeout) > 0 {
						if obs != nil {
							obs.ObserveProtocolFailure(s.ctx, s.kind, safeMetricName(s.name), protocolErrorIdleTimeout)
						}

						return
					}

					s.expireDovecotAuthRequests(conn, encoder, sessionLogger(), activeMechanisms, activeAuthRequests, activeObservabilityStates)
					continue
				}

				if reason, ok := protocolErrorKindOf(err); ok && obs != nil {
					obs.ObserveProtocolFailure(s.ctx, s.kind, safeMetricName(s.name), reason)
				}

				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || isConnectionResetError(err) {
					if obs != nil {
						reason := protocolErrorClientClosed

						if s.ctx.Err() != nil {
							reason = protocolErrorServerShutdown
						}

						obs.ObserveProtocolFailure(s.ctx, s.kind, safeMetricName(s.name), reason)
					}
					return
				}

				sessionLogger().Error("Error reading command", slog.String("reason", boundedErrorKind(err)))
				return
			}

			reqLogger := sessionLogger()

			cmd, args := decoder.ParseLine(line)
			if cmd == "" {
				continue
			}

			reqLogger.Debug("Incoming Dovecot SASL command",
				slog.String("command", boundedDovecotCommand(cmd)))

			switch cmd {
			case DovecotCmdAuth:
				authReq, err := decoder.DecodeAuthRequest(args)
				if err != nil {
					reqLogger.Error("Invalid AUTH request", slog.String("reason", string(protocolErrorInvalidFrame)))

					if wErr := s.writeDovecotConnectionResponse(conn, encoder.EncodeFail("0", "invalid request", "", false)); wErr != nil {
						return
					}
					continue
				}

				ensureDovecotAuthExternalSessionID(authReq, externalSessionID)

				if !dovecotSASLMechanismAllowed(allowedMechanisms, authReq.Mechanism) {
					if wErr := s.writeDovecotConnectionResponse(conn, encoder.EncodeFail(authReq.ID, "unsupported mechanism", "", false)); wErr != nil {
						return
					}

					continue
				}

				reqLogger.Debug("AUTH request received",
					slog.String("mechanism", authReq.Mechanism))

				mech := NewSASLMechanism(authReq.Mechanism)
				if mech == nil {
					if wErr := s.writeDovecotConnectionResponse(conn, encoder.EncodeFail(authReq.ID, "unsupported mechanism", "", false)); wErr != nil {
						return
					}
					continue
				}

				state := activeObservabilityStates[authReq.ID]
				if state == nil {
					state = s.startDovecotSASLObservabilityState(clientAddr, conn)
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
					reqLogger.Error("Invalid CONT request", slog.String("reason", string(protocolErrorInvalidFrame)))
					continue
				}

				mech, ok := activeMechanisms[contReq.ID]
				if !ok {
					if wErr := s.writeDovecotConnectionResponse(conn, encoder.EncodeFail(contReq.ID, "no active auth session", "", false)); wErr != nil {
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
				reqLogger.Warn("Unknown command", slog.String("command", unknownBackendName))
			}
		}
	}
}

func boundedDovecotCommand(command DovecotCommand) string {
	switch command {
	case DovecotCmdVersion, DovecotCmdCPID, DovecotCmdAuth, DovecotCmdCont:
		return string(command)
	default:
		return unknownBackendName
	}
}

func dovecotSASLMechanisms(settings Request) []DovecotMechanism {
	names := settings.Mechanisms
	if len(names) == 0 {
		names = []string{saslMechanismPlain, saslMechanismLogin}
		if settings.SASLOIDCAuth.Enabled {
			names = append(names, saslMechanismXOAuth2, saslMechanismOAuthBearer)
		}
	}

	mechanisms := make([]DovecotMechanism, 0, len(names))
	for _, name := range names {
		mechanisms = append(mechanisms, dovecotSASLMechanismDefinition(name))
	}

	return mechanisms
}

func dovecotSASLMechanismSet(mechanisms []DovecotMechanism) map[string]struct{} {
	allowed := make(map[string]struct{}, len(mechanisms))
	for _, mechanism := range mechanisms {
		if normalized, ok := normalizeSASLMechanismName(mechanism.Name); ok {
			allowed[normalized] = struct{}{}
		}
	}

	return allowed
}

func dovecotSASLMechanismAllowed(allowed map[string]struct{}, name string) bool {
	mechanism, ok := normalizeSASLMechanismName(name)
	if !ok {
		return false
	}

	_, ok = allowed[mechanism]

	return ok
}

func dovecotSASLMechanismDefinition(name string) DovecotMechanism {
	mechanism, ok := normalizeSASLMechanismName(name)
	if !ok {
		mechanism = strings.ToUpper(strings.TrimSpace(name))
	}

	switch mechanism {
	case saslMechanismPlain, saslMechanismLogin:
		return DovecotMechanism{Name: mechanism, PlainText: true, Dictionary: true, Active: true}
	case saslMechanismXOAuth2, saslMechanismOAuthBearer:
		return DovecotMechanism{Name: mechanism, ForwardSecrecy: true}
	default:
		return DovecotMechanism{Name: mechanism}
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

func (s *MultiServer) startDovecotSASLObservabilityState(clientAddr string, conn net.Conn) *saslObservabilityState {
	authCtx, obs, span := s.startApplicationSpan(componentDovecotSASL, s.name, clientAddr)
	authCtx, cancel := s.requestContextForConnection(authCtx, conn)

	return &saslObservabilityState{
		ctx:    authCtx,
		cancel: cancel,
		obs:    obs,
		span:   span,
		start:  time.Now(),
	}
}

func (s *MultiServer) nextDovecotReadDeadline(states map[string]*saslObservabilityState) time.Time {
	var deadline time.Time

	idleTimeout := protocolIdleTimeout(s.effectiveProtocolLimits().DovecotSASL.IdleTimeout)
	if len(states) == 0 && idleTimeout > 0 {
		deadline = time.Now().Add(idleTimeout)
	}

	for _, state := range states {
		stateDeadline, ok := state.ctx.Deadline()
		if !ok {
			continue
		}

		stateDeadline = stateDeadline.Add(-s.responseWriteReserve)
		if deadline.IsZero() || stateDeadline.Before(deadline) {
			deadline = stateDeadline
		}
	}

	return deadline
}

func (s *MultiServer) nextDovecotPartialDeadline(states map[string]*saslObservabilityState) time.Time {
	deadline := time.Now().Add(s.effectiveProtocolLimits().DovecotSASL.PartialRequestTimeout)

	for _, state := range states {
		stateDeadline, ok := state.ctx.Deadline()
		if !ok {
			continue
		}

		stateDeadline = stateDeadline.Add(-s.responseWriteReserve)
		if stateDeadline.Before(deadline) {
			deadline = stateDeadline
		}
	}

	return deadline
}

func (s *MultiServer) expireDovecotAuthRequests(
	conn net.Conn,
	encoder *DovecotEncoder,
	logger *slog.Logger,
	activeMechanisms map[string]SASLMechanism,
	activeAuthRequests map[string]*DovecotAuthRequest,
	states map[string]*saslObservabilityState,
) {
	now := time.Now()

	for id, state := range states {
		deadline, hasDeadline := state.ctx.Deadline()
		if state.ctx.Err() == nil && (!hasDeadline || now.Before(deadline.Add(-s.responseWriteReserve))) {
			continue
		}

		if state.ctx.Err() != nil && !errors.Is(state.ctx.Err(), context.DeadlineExceeded) {
			cause := context.Cause(state.ctx)
			finishSASLContinuationWait(state, cause)
			s.finishApplicationSpan(state.ctx, state.obs, state.span, componentDovecotSASL, s.name, outcomeError, state.start)
			state.cancel()
			delete(activeMechanisms, id)
			delete(activeAuthRequests, id)
			delete(states, id)

			continue
		}

		finishSASLContinuationWait(state, context.DeadlineExceeded)
		s.sendDovecotFail(state.ctx, conn, encoder, logger, id, "temporary failure", "", true)
		s.finishApplicationSpan(state.ctx, state.obs, state.span, componentDovecotSASL, s.name, outcomeTempfail, state.start)
		state.cancel()
		delete(activeMechanisms, id)
		delete(activeAuthRequests, id)
		delete(states, id)
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
		state = s.startDovecotSASLObservabilityState(clientAddr, conn)
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
		state.cancel()
	}()

	// If mechanism needs continuation, send CONT and store state
	if result != nil && result.NeedContinuation {
		activeMechanisms[authReq.ID] = mech
		activeAuthRequests[authReq.ID] = authReq
		activeObservabilityStates[authReq.ID] = state
		finishSpan = false

		resp := encoder.EncodeCont(authReq.ID, result.ContinuationChallenge)

		logger.Debug("Outgoing Dovecot SASL response",
			slog.String("command", string(DovecotCmdCont)))

		_, writeObs, writeSpan := startInternalSpanFromContext(authCtx,
			dovecotSASLResponseSpanName,
			attribute.String("pfxhttp.component", componentDovecotSASL),
			attribute.String("pfxhttp.name", safeMetricName(s.name)),
			attribute.String("pfxhttp.sasl.command", string(DovecotCmdCont)),
		)
		err := s.writeDovecotResponse(authCtx, conn, resp)
		finishObservedSpan(writeObs, writeSpan, err)

		if err != nil {
			logger.Error("Error writing CONT", slog.String("reason", boundedErrorKind(err)))
		} else {
			startSASLContinuationWait(state, s.name, authReq)
		}

		return
	}

	// If mechanism returned a direct failure
	if result != nil && !result.Success {
		delete(activeMechanisms, authReq.ID)
		delete(activeAuthRequests, authReq.ID)

		s.sendDovecotFail(authCtx, conn, encoder, logger, authReq.ID, result.Reason, result.Username, result.Temporary)

		return
	}

	// Credentials extracted - authenticate against backend
	if creds != nil {
		delete(activeMechanisms, authReq.ID)
		delete(activeAuthRequests, authReq.ID)

		permit, admission := s.acquireRequest(authCtx)
		if requestOverloaded(admission) {
			s.logRequestOverload(logger, admission)

			outcome = outcomeTempfail

			s.sendDovecotFail(authCtx, conn, encoder, logger, authReq.ID, "temporary failure", "", true)

			return
		}
		defer permit.Release()
		defer func() {
			if recover() != nil {
				outcome = outcomeTempfail

				s.sendDovecotFail(authCtx, conn, encoder, logger, authReq.ID, "temporary failure", "", true)
			}
		}()

		currentConfig := s.deps.GetConfig()
		if currentConfig == nil {
			outcome = outcomeTempfail
			logger.Error("Authentication error",
				slog.String("reason", "configuration_unavailable"))

			s.sendDovecotFail(authCtx, conn, encoder, logger, authReq.ID, "internal error", creds.Username, true)

			return
		}

		authenticator := newSASLAuthenticatorForEntry(currentConfig, s.name, s.deps)

		var authResult *SASLAuthResult
		var err error

		backendCtx, cancelBackend := s.backendContext(authCtx)
		defer cancelBackend()

		backendCtx, backendObs, backendSpan := startInternalSpanFromContext(backendCtx,
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

			logger.Error("Authentication backend failed",
				slog.String("result", resultError))

			resp := encoder.EncodeFail(authReq.ID, "internal error", creds.Username, true)

			logger.Debug("Outgoing Dovecot SASL response",
				slog.String("command", string(DovecotCmdFail)))

			_, writeObs, writeSpan := startInternalSpanFromContext(authCtx,
				dovecotSASLResponseSpanName,
				attribute.String("pfxhttp.component", componentDovecotSASL),
				attribute.String("pfxhttp.name", safeMetricName(s.name)),
				attribute.String("pfxhttp.sasl.command", string(DovecotCmdFail)),
			)
			wErr := s.writeDovecotResponse(authCtx, conn, resp)
			finishObservedSpan(writeObs, writeSpan, wErr)

			if wErr != nil {
				logger.Error("Error writing FAIL", slog.String("reason", boundedErrorKind(wErr)))
			}

			return
		}

		if authResult.Success {
			username := creds.Username
			if authResult.Username != "" {
				username = authResult.Username
			}

			logger.Info("Authentication successful",
				slog.String("mechanism", authReq.Mechanism))

			resp := encoder.EncodeOK(authReq.ID, username)

			logger.Debug("Outgoing Dovecot SASL response",
				slog.String("command", string(DovecotCmdOK)))

			_, writeObs, writeSpan := startInternalSpanFromContext(authCtx,
				dovecotSASLResponseSpanName,
				attribute.String("pfxhttp.component", componentDovecotSASL),
				attribute.String("pfxhttp.name", safeMetricName(s.name)),
				attribute.String("pfxhttp.sasl.command", string(DovecotCmdOK)),
			)
			wErr := s.writeDovecotResponse(authCtx, conn, resp)
			finishObservedSpan(writeObs, writeSpan, wErr)

			if wErr != nil {
				logger.Error("Error writing OK", slog.String("reason", boundedErrorKind(wErr)))
			}
		} else {
			logger.Info("Authentication failed",
				slog.String("mechanism", authReq.Mechanism),
				slog.Bool("temporary", authResult.Temporary))

			s.sendDovecotFail(authCtx, conn, encoder, logger, authReq.ID, authResult.Reason, creds.Username, authResult.Temporary)
		}
	}
}

// startApplicationSpan creates a protocol request context and server span.
func (s *MultiServer) startApplicationSpan(component, name, _ string) (context.Context, *Observability, trace.Span) {
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

func (s *MultiServer) writeDovecotResponse(ctx context.Context, conn net.Conn, response string) error {
	ctx, cancel := contextWithOptionalTimeout(ctx, s.effectiveProtocolLimits().DovecotSASL.WriteTimeout)
	defer cancel()

	clearDeadline, err := setWriteDeadlineFromContext(ctx, conn)
	if err != nil {
		return err
	}
	defer clearDeadline()

	_, err = conn.Write([]byte(response))

	return err
}

func (s *MultiServer) writeDovecotConnectionResponse(conn net.Conn, response string) error {
	ctx, cancel := contextWithOptionalTimeout(s.ctx, s.effectiveProtocolLimits().DovecotSASL.WriteTimeout)
	defer cancel()

	return s.writeDovecotResponse(ctx, conn, response)
}

// sendDovecotFail encodes and sends a FAIL response over the Dovecot SASL protocol, logging the response and any write errors.
func (s *MultiServer) sendDovecotFail(ctx context.Context, conn net.Conn, encoder *DovecotEncoder, logger *slog.Logger, id string, reason string, username string, temporary bool) {
	resp := encoder.EncodeFail(id, reason, username, temporary)

	logger.Debug("Outgoing Dovecot SASL response",
		slog.String("command", string(DovecotCmdFail)))

	_, writeObs, writeSpan := startInternalSpanFromContext(ctx,
		dovecotSASLResponseSpanName,
		attribute.String("pfxhttp.component", componentDovecotSASL),
		attribute.String("pfxhttp.sasl.command", string(DovecotCmdFail)),
	)
	err := s.writeDovecotResponse(ctx, conn, resp)
	finishObservedSpan(writeObs, writeSpan, err)

	if err != nil {
		logger.Error("Error writing FAIL", slog.String("reason", boundedErrorKind(err)))
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
	return newSocketMapReader(conn, defaultSocketMapFraming()).Read(s.ctx)
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

func (s *MultiServer) writeNetStringContext(ctx context.Context, conn net.Conn, netString NetData) error {
	ctx, cancel := contextWithOptionalTimeout(ctx, s.effectiveProtocolLimits().SocketMap.WriteTimeout)
	defer cancel()

	clearDeadline, err := setWriteDeadlineFromContext(ctx, conn)
	if err != nil {
		return err
	}
	defer clearDeadline()

	return s.writeNetString(conn, netString)
}

// writePolicyResult writes the specified policy result to the given network connection.
// Returns an error if the write operation fails.
func (s *MultiServer) writePolicyResult(conn net.Conn, result string) error {
	_, err := conn.Write([]byte(result))

	return err
}

func (s *MultiServer) writePolicyResultContext(ctx context.Context, conn net.Conn, result string) error {
	ctx, cancel := contextWithOptionalTimeout(ctx, s.effectiveProtocolLimits().PolicyService.WriteTimeout)
	defer cancel()

	clearDeadline, err := setWriteDeadlineFromContext(ctx, conn)
	if err != nil {
		return err
	}
	defer clearDeadline()

	return s.writePolicyResult(conn, result)
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

		logger.Info("Dropped group privileges")
	}

	if creds.HasUser {
		if err := syscall.Setuid(creds.UID); err != nil {
			return fmt.Errorf("could not set uid to %d: %w", creds.UID, err)
		}

		logger.Info("Dropped user privileges")
	}

	return nil
}
