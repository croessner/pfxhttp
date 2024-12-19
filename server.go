package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// GenericServer defines an interface for managing a TCP server with methods to start and stop the server.
type GenericServer interface {
	// Start initializes and starts the server, enabling it to accept and process client connections.
	Start() error

	// Stop gracefully shuts down the server, ensuring all active connections are closed and all routines are completed.
	Stop()
}

// NetStringServer represents a TCP server that processes requests encoded in NetString format.
// It manages connections, reads incoming NetStrings, and sends processed responses back to clients.
type NetStringServer struct {
	address string

	config   *Config
	logger   *slog.Logger
	ctx      context.Context
	closer   context.CancelFunc
	listener net.Listener
	wg       sync.WaitGroup
}

// NewNetStringServer creates and initializes a new NetStringServer instance with the provided context, config, and logger.
func NewNetStringServer(ctx context.Context, config *Config, logger *slog.Logger) GenericServer {
	childCtx, closer := context.WithCancel(ctx)

	return &NetStringServer{
		config: config,
		logger: logger,
		ctx:    childCtx,
		closer: closer,
		wg:     sync.WaitGroup{},
	}
}

// Start initializes and starts the NetStringServer, accepting client connections and processing them.
func (s *NetStringServer) Start() error {
	var (
		mode int64
		conn net.Conn
		err  error
	)

	if s.config.Server.Listen.Type == "unix" {
		s.address = s.config.Server.Listen.Address
	} else {
		s.address = fmt.Sprintf("%s:%d", s.config.Server.Listen.Address, s.config.Server.Listen.Port)
	}

	s.logger.Info("Starting server...", slog.String("address", s.address))

	s.listener, err = net.Listen(s.config.Server.Listen.Type, s.address)
	if err != nil {
		s.logger.Error("Could not start server", slog.String("error", err.Error()))

		return fmt.Errorf("could not start server: %w", err)
	}

	if s.config.Server.Listen.Type == "unix" && s.config.Server.Listen.Mode != "" {
		mode, err = strconv.ParseInt(s.config.Server.Listen.Mode, 8, 64)
		if err != nil {
			s.logger.Error("Could not parse socket mode", slog.String("error", err.Error()))
		}

		if err = os.Chmod(s.config.Server.Listen.Address, os.FileMode(mode)); err != nil {
			s.logger.Error("Could not set permissions on socket", slog.String("error", err.Error()))
		}
	}

	s.logger.Info("Server is listening...", slog.String("type", s.config.Server.Listen.Type), slog.String("address", s.address))

	for {
		conn, err = s.listener.Accept()
		if errors.Is(err, net.ErrClosed) {
			s.logger.Info("Server is shutting down...")

			return nil
		}

		if err != nil {
			s.logger.Error("Error accepting connection", slog.String("error", err.Error()))

			continue
		}

		s.wg.Add(1)

		go s.handleConnection(conn)
	}
}

// Stop gracefully shuts down the NetStringServer by stopping connections, waiting for all routines to complete, and closing the listener.
func (s *NetStringServer) Stop() {
	if s.closer != nil {
		s.closer()
	}

	s.wg.Wait()

	_ = s.listener.Close()
}

var _ GenericServer = (*NetStringServer)(nil)

// handleConnection manages an individual client connection, processing requests and sending responses in NetString format.
func (s *NetStringServer) handleConnection(conn net.Conn) {
	clientAddr := conn.RemoteAddr().String()

	s.logger.Info("New connection established", slog.String("client", clientAddr))

	defer func() {
		s.logger.Info("Connection closed", slog.String("client", clientAddr))

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

				s.logger.Error("Error reading NetString", slog.String("client", clientAddr), slog.String("error", err.Error()))

				return
			}

			// Client closed connection
			if netString == nil {
				return
			}

			s.logger.Info("Received request", slog.String("client", clientAddr), slog.String("request", netString.String()))

			received := NewPostfixReceiver()

			err = received.ReadNetString(netString)
			if err != nil {
				s.logger.Error("Error reading request", slog.String("client", clientAddr), slog.String("error", err.Error()))

				return
			}

			client := NewBridgeClient(s.config)
			client.SetReceiver(received)

			err = client.SendAndReceive()
			if err != nil {
				s.logger.Error("Error sending request", slog.String("client", clientAddr), slog.String("error", err.Error()))

				return
			}

			responseData := client.GetSender().String()
			response := NewNetStringFromString(responseData)

			err = s.writeNetString(conn, response)
			if err != nil {
				s.logger.Error("Error writing response", slog.String("client", clientAddr), slog.String("error", err.Error()))

				return
			}

			s.logger.Info("Response sent", slog.String("client", clientAddr), slog.String("response", responseData))
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
func (s *NetStringServer) readNetString(conn net.Conn) (*NetString, error) {
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
func (s *NetStringServer) writeNetString(conn net.Conn, netString NetData) error {
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
