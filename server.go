package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GenericServer defines an interface for managing a TCP server with methods to start and stop the server.
type GenericServer interface {
	// Start initializes and starts the server, enabling it to accept and process client connections.
	Start(instance Listen, handler func(conn net.Conn)) error

	// Stop gracefully shuts down the server, ensuring all active connections are closed and all routines are completed.
	Stop()

	// GetContext returns the context used by the server to manage its lifecycle and handle cancellations or deadlines.
	GetContext() context.Context

	// HandleNetStringConnection processes an individual client connection by reading, interpreting, and responding in NetString format.
	HandleNetStringConnection(conn net.Conn)

	// HandlePolicyServiceConnection manages a client connection for the Postfix policy service, handling requests and responses.
	HandlePolicyServiceConnection(conn net.Conn)
}

// MultiServer represents a TCP server that processes requests encoded in NetString format.
// It manages connections, reads incoming NetStrings, and sends processed responses back to clients.
type MultiServer struct {
	name    string
	address string

	config   *Config
	ctx      context.Context
	closer   context.CancelFunc
	listener net.Listener
	wg       sync.WaitGroup
}

// NewMultiServer creates and initializes a new MultiServer instance with the provided context and config.
func NewMultiServer(ctx *Context, config *Config) GenericServer {
	childCtx, closer := context.WithCancel(ctx)

	return &MultiServer{
		config: config,
		ctx:    childCtx,
		closer: closer,
		wg:     sync.WaitGroup{},
	}
}

// Start initializes and starts the MultiServer, accepting client connections and processing them.
func (s *MultiServer) Start(instance Listen, handler func(conn net.Conn)) error {
	var (
		mode     int64
		conn     net.Conn
		fileInfo os.FileInfo
		err      error
	)

	logger := s.GetContext().Value(loggerKey).(*slog.Logger)

	conn, err = net.DialTimeout(instance.Type, s.address, 1*time.Second)
	if err == nil {
		_ = conn.Close()

		return fmt.Errorf("address %s is already in use", s.address)
	}

	if instance.Type == "unix" {
		s.address = instance.Address
		if fileInfo, err = os.Stat(instance.Address); err == nil && fileInfo.Mode()&os.ModeSocket != 0 {
			if err = os.Remove(instance.Address); err != nil {
				return err
			}
		}
	} else {
		s.address = fmt.Sprintf("%s:%d", instance.Address, instance.Port)
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

	logger.Info("Server is listening", slog.String("type", instance.Type), slog.String("address", s.address), slog.String("name", s.name), slog.String("kind", instance.Kind))

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

		go handler(conn)
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

	logger.Info("New connection established", slog.String("client", clientAddr))

	defer func() {
		logger.Info("Connection closed", slog.String("client", clientAddr))

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
				if err == io.EOF {
					break
				}

				logger.Error("Error reading NetString", slog.String("client", clientAddr), slog.String("error", err.Error()))

				return
			}

			// Client closed connection
			if netString == nil {
				return
			}

			logger.Debug("Received request", slog.String("client", clientAddr), slog.String("request", netString.String()))

			received := NewPostfixMapReceiver()

			err = received.ReadNetString(netString)
			if err != nil {
				logger.Error("Error reading request", slog.String("client", clientAddr), slog.String("error", err.Error()))

				return
			}

			client := NewMapClient(s.config)
			client.SetReceiver(received)

			err = client.SendAndReceive()
			if err != nil {
				logger.Error("Error sending request", slog.String("client", clientAddr), slog.String("error", err.Error()))

				return
			}

			responseData := client.GetSender().String()
			response := NewNetStringFromString(responseData)

			err = s.writeNetString(conn, response)
			if err != nil {
				logger.Error("Error writing response", slog.String("client", clientAddr), slog.String("error", err.Error()))

				return
			}

			logger.Debug("Response sent", slog.String("client", clientAddr), slog.String("response", responseData))
		}
	}
}

// HandlePolicyServiceConnection manages a client connection for the Postfix policy service, handling requests and responses.
func (s *MultiServer) HandlePolicyServiceConnection(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()

	logger := s.GetContext().Value(loggerKey).(*slog.Logger)

	logger.Info("New connection established", slog.String("client", clientAddr))

	defer func() {
		logger.Info("Connection closed", slog.String("client", clientAddr))

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
				if err == io.EOF {
					break
				}

				logger.Error("Error reading policy", slog.String("client", clientAddr), slog.String("error", err.Error()))

				return
			}

			received := NewPostfixPolicyReceiver(s.name)
			_ = received.ReadPolcy(policy)

			client := NewPolicyClient(s.config)
			client.SetReceiver(received)

			err = client.SendAndReceive()
			if err != nil {
				logger.Error("Error sending request", slog.String("client", clientAddr), slog.String("error", err.Error()))

				return
			}

			responseData := fmt.Sprintf("action=%s\n\n", strings.TrimSpace(client.GetSender().String()))

			err = s.writePolicyResult(conn, responseData)
			if err != nil {
				logger.Error("Error writing response", slog.String("client", clientAddr), slog.String("error", err.Error()))

				return
			}

			logger.Debug("Response sent", slog.String("client", clientAddr), slog.String("response", responseData))
		}
	}
}

// isConnectionResetError checks if the given error is a "connection reset by peer" error in a network operation.
func isConnectionResetError(err error) bool {
	var netOpErr *net.OpError

	if errors.As(err, &netOpErr) {
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
				var netErr net.Error

				if errors.As(err, &netErr) && netErr.Timeout() {
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
	_, err := conn.Write([]byte(result))
	if err != nil {
		return fmt.Errorf("could not write policy result: %w", err)
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
