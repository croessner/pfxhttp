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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const LogKeyClient = "client"

// GenericServer defines an interface for managing a TCP server with methods to start and stop the server.
type GenericServer interface {
	// Listen initializes the listener for the server based on the provided configuration.
	Listen(instance Listen) error

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
	address string

	config     *Config
	ctx        context.Context
	closer     context.CancelFunc
	listener   net.Listener
	wg         sync.WaitGroup
	workerPool WorkerPool
}

// NewMultiServer creates and initializes a new MultiServer instance with the provided context and config.
func NewMultiServer(ctx *Context, config *Config, wp WorkerPool) GenericServer {
	childCtx, closer := context.WithCancel(ctx)

	return &MultiServer{
		config:     config,
		ctx:        childCtx,
		closer:     closer,
		wg:         sync.WaitGroup{},
		workerPool: wp,
	}
}

// Listen initializes the listener for the MultiServer based on the provided configuration.
func (s *MultiServer) Listen(instance Listen) error {
	var (
		mode     int64
		conn     net.Conn
		fileInfo os.FileInfo
		err      error
	)

	logger := s.GetContext().Value(loggerKey).(*slog.Logger)

	if instance.Type != "unix" {
		s.address = fmt.Sprintf("%s:%d", instance.Address, instance.Port)
	} else {
		s.address = instance.Address
	}

	conn, err = net.DialTimeout(instance.Type, s.address, 1*time.Second)
	if err == nil {
		_ = conn.Close()

		return fmt.Errorf("address %s is already in use", s.address)
	}

	if instance.Type == "unix" {
		if fileInfo, err = os.Stat(instance.Address); err == nil && fileInfo.Mode()&os.ModeSocket != 0 {
			if err = os.Remove(instance.Address); err != nil {
				return err
			}
		}

		oldMask := syscall.Umask(0)
		defer syscall.Umask(oldMask)
	}

	if instance.Name != "" {
		s.name = instance.Name
	}

	s.listener, err = net.Listen(instance.Type, s.address)
	if err != nil {
		return fmt.Errorf("could not start server: %w", err)
	}

	if instance.Type == "unix" && instance.Mode != "" {
		mode, err = strconv.ParseInt(instance.Mode, 8, 64)
		if err != nil {
			logger.Error("Could not parse socket mode", slog.String("error", err.Error()))
		}

		if err = os.Chmod(instance.Address, os.FileMode(mode)); err != nil {
			logger.Error("Could not set permissions on socket", slog.String("error", err.Error()))
		}
	}

	if instance.Type == "unix" && (instance.User != "" || instance.Group != "") {
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

		if uid != -1 || gid != -1 {
			if err = os.Chown(instance.Address, uid, gid); err != nil {
				logger.Error("Could not set ownership on socket", slog.String("error", err.Error()))
			}
		}
	}

	logger.Info("Server is listening", slog.String("type", instance.Type), slog.String("address", s.address), slog.String("name", s.name), slog.String("kind", instance.Kind))

	if instance.WorkerPool.MaxWorkers > 0 {
		s.workerPool = NewWorkerPool(s.ctx, instance.WorkerPool.MaxWorkers, instance.WorkerPool.MaxQueue, &s.wg)
	}

	return nil
}

// Start starts the accept loop for the MultiServer using the provided handler.
func (s *MultiServer) Start(handler func(conn net.Conn)) error {
	var (
		conn net.Conn
		err  error
	)

	logger := s.GetContext().Value(loggerKey).(*slog.Logger)

	for {
		conn, err = s.listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			logger.Info("Server is shutting down", slog.String("address", s.address), slog.String("name", s.name))

			return nil
		}

		if err != nil {
			logger.Error("Error accepting connection", slog.String("error", err.Error()))

			continue
		}

		s.wg.Add(1)

		if s.workerPool != nil {
			job := Job{
				Conn:    conn,
				Handler: handler,
			}

			if !s.workerPool.Submit(job) {
				_ = conn.Close()
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

	s.wg.Wait()

	_ = s.listener.Close()
}

func (s *MultiServer) GetContext() context.Context {
	return s.ctx
}

var _ GenericServer = (*MultiServer)(nil)

// HandleNetStringConnection manages an individual client connection, processing requests and sending responses in NetString format.
func (s *MultiServer) HandleNetStringConnection(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()

	logger := s.GetContext().Value(loggerKey).(*slog.Logger)

	logger.Info("New connection established", slog.String(LogKeyClient, clientAddr))

	defer func() {
		logger.Info("Connection closed", slog.String(LogKeyClient, clientAddr))

		_ = conn.Close()

		s.wg.Done()
	}()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			netString, err := s.readNetString(conn)
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}

				logger.Error("Error reading NetString", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))

				return
			}

			// Client closed connection
			if netString == nil {
				return
			}

			logger.Debug("Received request", slog.String(LogKeyClient, clientAddr), slog.String("request", netString.String()))

			received := NewPostfixMapReceiver()

			err = received.ReadNetString(netString)
			if err != nil {
				logger.Error("Error reading request", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))

				return
			}

			client := NewMapClient(s.ctx, s.config)
			client.SetReceiver(received)

			err = client.SendAndReceive()
			if err != nil {
				logger.Error("Error sending request", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))

				return
			}

			responseData := client.GetSender().String()
			response := NewNetStringFromString(responseData)

			err = s.writeNetString(conn, response)
			if err != nil {
				logger.Error("Error writing response", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))

				return
			}

			logger.Debug("Response sent", slog.String(LogKeyClient, clientAddr), slog.String("response", responseData))
		}
	}
}

// HandlePolicyServiceConnection manages a client connection for the Postfix policy service, handling requests and responses.
func (s *MultiServer) HandlePolicyServiceConnection(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()

	logger := s.GetContext().Value(loggerKey).(*slog.Logger)

	logger.Info("New connection established", slog.String(LogKeyClient, clientAddr))

	defer func() {
		logger.Info("Connection closed", slog.String(LogKeyClient, clientAddr))

		_ = conn.Close()

		s.wg.Done()
	}()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			policy, err := s.readPolicy(conn)
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}

				logger.Error("Error reading policy", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))

				return
			}

			logger.Debug("Received request", slog.String(LogKeyClient, clientAddr), slog.String("request", policy.String()))

			received := NewPostfixPolicyReceiver(s.name)
			_ = received.ReadPolcy(policy)

			client := NewPolicyClient(s.ctx, s.config)
			client.SetReceiver(received)

			err = client.SendAndReceive()
			if err != nil {
				logger.Error("Error sending request", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))

				return
			}

			responseData := fmt.Sprintf("action=%s\n\n", strings.TrimSpace(client.GetSender().String()))

			err = s.writePolicyResult(conn, responseData)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					logger.Warn("Write deadline exceeded, closing connection", slog.String(LogKeyClient, conn.RemoteAddr().String()))
				} else if strings.Contains(err.Error(), "broken pipe") {
					logger.Info("Broken pipe detected, client likely disconnected", slog.String(LogKeyClient, conn.RemoteAddr().String()))
				} else {
					logger.Error("Error writing response", slog.String(LogKeyClient, conn.RemoteAddr().String()), slog.String("error", err.Error()))
				}

				return
			}

			logger.Debug("Response sent", slog.String(LogKeyClient, clientAddr), slog.String("response", responseData))
		}
	}
}

// dovecotCUIDCounter is a global atomic counter for generating unique connection IDs in the Dovecot SASL protocol.
var dovecotCUIDCounter atomic.Uint64

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
	logger := s.GetContext().Value(loggerKey).(*slog.Logger)

	logger.Info("New Dovecot SASL connection established", slog.String(LogKeyClient, clientAddr))

	defer func() {
		logger.Info("Dovecot SASL connection closed", slog.String(LogKeyClient, clientAddr))
		_ = conn.Close()
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
	if settings, ok := s.config.DovecotSASL[s.name]; ok && settings.SASLOIDCAuth.Enabled {
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
			logger.Error("Error writing handshake", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
			return
		}
	}

	logger.Debug("Handshake sent", slog.String(LogKeyClient, clientAddr))

	// Read client handshake (VERSION + CPID)
	clientHandshakeDone := false
	for !clientHandshakeDone {
		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			logger.Error("Error reading client handshake", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
			return
		}

		cmd, args := decoder.ParseLine(line)
		switch cmd {
		case DovecotCmdVersion:
			major, _, err := decoder.DecodeVersion(args)
			if err != nil {
				logger.Error("Invalid client VERSION", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
				return
			}
			if major != DovecotProtoVersionMajor {
				logger.Error("Unsupported protocol version", slog.String(LogKeyClient, clientAddr), slog.Int("major", major))
				return
			}
		case DovecotCmdCPID:
			cpid, err := decoder.DecodeCPID(args)
			if err != nil {
				logger.Error("Invalid CPID", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
				return
			}
			logger.Debug("Client CPID received", slog.String(LogKeyClient, clientAddr), slog.String("cpid", cpid))
			clientHandshakeDone = true
		default:
			logger.Warn("Unexpected command during handshake", slog.String(LogKeyClient, clientAddr), slog.String("command", string(cmd)))
		}
	}

	// Track active mechanism sessions for multi-step auth (keyed by request ID)
	activeMechanisms := make(map[string]SASLMechanism)
	activeAuthRequests := make(map[string]*DovecotAuthRequest)
	authenticator := NewNauthilusSASLAuthenticator(s.config, s.name)

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
				logger.Error("Error reading command", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
				return
			}

			redacted := redactDovecotLine(strings.TrimSpace(line))
			logger.Debug("Incoming Dovecot SASL request", slog.String(LogKeyClient, clientAddr), slog.String("request", redacted))

			cmd, args := decoder.ParseLine(line)
			if cmd == "" {
				continue
			}

			switch cmd {
			case DovecotCmdAuth:
				authReq, err := decoder.DecodeAuthRequest(args)
				if err != nil {
					logger.Error("Invalid AUTH request", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
					if _, wErr := conn.Write([]byte(encoder.EncodeFail("0", "invalid request", "", false))); wErr != nil {
						return
					}
					continue
				}

				logger.Debug("AUTH request received",
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

				result, creds := mech.Start(authReq.InitialResponse)
				s.handleSASLResult(conn, encoder, authenticator, logger, clientAddr, authReq, mech, result, creds, activeMechanisms, activeAuthRequests)

			case DovecotCmdCont:
				contReq, err := decoder.DecodeContRequest(args)
				if err != nil {
					logger.Error("Invalid CONT request", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
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
				result, creds := mech.Continue(contReq.Data)
				s.handleSASLResult(conn, encoder, authenticator, logger, clientAddr, authReq, mech, result, creds, activeMechanisms, activeAuthRequests)

			default:
				logger.Warn("Unknown command", slog.String(LogKeyClient, clientAddr), slog.String("command", string(cmd)))
			}
		}
	}
}

// redactDovecotLine removes or masks sensitive parts from a raw Dovecot SASL protocol line for safe logging.
func redactDovecotLine(line string) string {
	// Mask AUTH resp=... parameter which can carry base64 credentials
	if strings.HasPrefix(line, string(DovecotCmdAuth)+" ") {
		// replace resp=<...> (until space or end) with resp=<redacted>
		// also handle resp= without value gracefully
		fields := strings.Fields(line)
		var b strings.Builder
		for i, p := range fields {
			if strings.HasPrefix(p, "resp=") {
				if i > 0 {
					b.WriteByte(' ')
				}
				b.WriteString("resp=<redacted>")
				continue
			}
			if i > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(p)
		}
		return b.String()
	}

	// Mask CONT <id> <base64data>
	if strings.HasPrefix(line, string(DovecotCmdCont)+" ") {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			fields[2] = "<redacted>"
			return strings.Join(fields, " ")
		}
		return line
	}
	return line
}

// handleSASLResult processes the result of a SASL mechanism step and sends the appropriate protocol response.
func (s *MultiServer) handleSASLResult(
	conn net.Conn,
	encoder *DovecotEncoder,
	authenticator SASLAuthenticator,
	logger *slog.Logger,
	clientAddr string,
	authReq *DovecotAuthRequest,
	mech SASLMechanism,
	result *SASLAuthResult,
	creds *SASLCredentials,
	activeMechanisms map[string]SASLMechanism,
	activeAuthRequests map[string]*DovecotAuthRequest,
) {
	// If mechanism needs continuation, send CONT and store state
	if result != nil && result.NeedContinuation {
		activeMechanisms[authReq.ID] = mech
		activeAuthRequests[authReq.ID] = authReq

		resp := encoder.EncodeCont(authReq.ID, result.ContinuationChallenge)
		logger.Debug("Outgoing Dovecot SASL response", slog.String(LogKeyClient, clientAddr), slog.String("response", strings.TrimSpace(resp)))

		if _, err := conn.Write([]byte(resp)); err != nil {
			logger.Error("Error writing CONT", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
		}

		return
	}

	// If mechanism returned a direct failure
	if result != nil && !result.Success {
		delete(activeMechanisms, authReq.ID)
		delete(activeAuthRequests, authReq.ID)

		resp := encoder.EncodeFail(authReq.ID, result.Reason, result.Username, result.Temporary)
		logger.Debug("Outgoing Dovecot SASL response", slog.String(LogKeyClient, clientAddr), slog.String("response", strings.TrimSpace(resp)))

		if _, err := conn.Write([]byte(resp)); err != nil {
			logger.Error("Error writing FAIL", slog.String(LogKeyClient, clientAddr), slog.String("error", err.Error()))
		}

		return
	}

	// Credentials extracted - authenticate against backend
	if creds != nil {
		delete(activeMechanisms, authReq.ID)
		delete(activeAuthRequests, authReq.ID)

		var authResult *SASLAuthResult
		var err error

		if IsOAuthMechanism(authReq.Mechanism) {
			authResult, err = authenticator.AuthenticateToken(s.ctx, creds.Username, creds.Token, authReq)
		} else {
			authResult, err = authenticator.AuthenticatePassword(s.ctx, creds.Username, creds.Password, authReq)
		}

		if err != nil {
			logger.Error("Authentication error",
				slog.String(LogKeyClient, clientAddr),
				slog.String("username", creds.Username),
				slog.String("error", err.Error()))

			resp := encoder.EncodeFail(authReq.ID, "internal error", creds.Username, true)
			logger.Debug("Outgoing Dovecot SASL response", slog.String(LogKeyClient, clientAddr), slog.String("response", strings.TrimSpace(resp)))

			if _, wErr := conn.Write([]byte(resp)); wErr != nil {
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
			logger.Debug("Outgoing Dovecot SASL response", slog.String(LogKeyClient, clientAddr), slog.String("response", strings.TrimSpace(resp)))

			if _, wErr := conn.Write([]byte(resp)); wErr != nil {
				logger.Error("Error writing OK", slog.String(LogKeyClient, clientAddr), slog.String("error", wErr.Error()))
			}
		} else {
			logger.Info("Authentication failed",
				slog.String(LogKeyClient, clientAddr),
				slog.String("username", creds.Username),
				slog.String("mechanism", authReq.Mechanism),
				slog.String("reason", authResult.Reason))

			resp := encoder.EncodeFail(authReq.ID, authResult.Reason, creds.Username, authResult.Temporary)
			logger.Debug("Outgoing Dovecot SASL response", slog.String(LogKeyClient, clientAddr), slog.String("response", strings.TrimSpace(resp)))

			if _, wErr := conn.Write([]byte(resp)); wErr != nil {
				logger.Error("Error writing FAIL", slog.String(LogKeyClient, clientAddr), slog.String("error", wErr.Error()))
			}
		}
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

// DropPrivileges drops the process's root privileges to the specified user and group.
func DropPrivileges(runAsUser, runAsGroup string, logger *slog.Logger) error {
	if os.Getuid() != 0 {
		return nil
	}

	var uid, gid int

	if runAsUser != "" {
		u, err := user.Lookup(runAsUser)
		if err != nil {
			return fmt.Errorf("could not lookup user %s: %w", runAsUser, err)
		}
		uid, _ = strconv.Atoi(u.Uid)
	}

	if runAsGroup != "" {
		g, err := user.LookupGroup(runAsGroup)
		if err != nil {
			return fmt.Errorf("could not lookup group %s: %w", runAsGroup, err)
		}
		gid, _ = strconv.Atoi(g.Gid)
	}

	currentUID := os.Getuid()
	currentGID := os.Getgid()

	// If we are already running as the target user/group, there's nothing to do.
	// This also avoids clearing supplementary groups if stay as root.
	if (runAsUser == "" || uid == currentUID) && (runAsGroup == "" || gid == currentGID) {
		return nil
	}

	// Set supplementary groups to empty
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("could not clear supplementary groups: %w", err)
	}

	if runAsGroup != "" {
		if err := syscall.Setgid(gid); err != nil {
			return fmt.Errorf("could not set gid to %d: %w", gid, err)
		}
		logger.Info("Dropped group privileges", slog.String("group", runAsGroup), slog.Int("gid", gid))
	}

	if runAsUser != "" {
		if err := syscall.Setuid(uid); err != nil {
			return fmt.Errorf("could not set uid to %d: %w", uid, err)
		}
		logger.Info("Dropped user privileges", slog.String("user", runAsUser), slog.Int("uid", uid))
	}

	return nil
}
