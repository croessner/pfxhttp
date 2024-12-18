package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"
)

type TCPNetStringServer struct {
	address string

	config   *Config
	logger   *slog.Logger
	ctx      context.Context
	closer   context.CancelFunc
	listener net.Listener
	wg       sync.WaitGroup
}

func NewTCPNetStringServer(ctx context.Context, config *Config, logger *slog.Logger) *TCPNetStringServer {
	childCtx, closer := context.WithCancel(ctx)

	return &TCPNetStringServer{
		config: config,
		logger: logger,
		ctx:    childCtx,
		closer: closer,
		wg:     sync.WaitGroup{},
	}
}

func (s *TCPNetStringServer) Start() error {
	var (
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

func (s *TCPNetStringServer) Stop() {
	if s.closer != nil {
		s.closer()
	}

	s.wg.Wait()

	_ = s.listener.Close()
}

func (s *TCPNetStringServer) handleConnection(conn net.Conn) {
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

			client := NewClient(s.config)
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

func isConnectionResetError(err error) bool {
	var netOpErr *net.OpError

	if errors.As(err, &netOpErr) {
		if netOpErr.Err.Error() == "read: connection reset by peer" {
			return true
		}
	}

	return false
}

func (s *TCPNetStringServer) readNetString(conn net.Conn) (*NetString, error) {
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

func (s *TCPNetStringServer) writeNetString(conn net.Conn, netString *NetString) error {
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
