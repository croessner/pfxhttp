package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"log/slog"
)

type MockConn struct {
	readBuffer  *bytes.Buffer
	writeBuffer *bytes.Buffer
	closeCalled bool
}

func (m *MockConn) LocalAddr() net.Addr {
	panic("implement me")
}

func (m *MockConn) SetDeadline(t time.Time) error {
	panic("implement me")
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	panic("implement me")
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	panic("implement me")
}

func NewMockConn(readData []byte) *MockConn {
	return &MockConn{
		readBuffer:  bytes.NewBuffer(readData),
		writeBuffer: &bytes.Buffer{},
	}
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	return m.readBuffer.Read(b)
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	return m.writeBuffer.Write(b)
}

func (m *MockConn) Close() error {
	m.closeCalled = true

	return nil
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.ParseIP("127.0.0.1")}
}

func TestHandleConnection(t *testing.T) {
	tests := []struct {
		name          string
		input         []byte
		setupServer   func() *TCPNetStringServer
		expectError   bool
		expectedWrite []byte
	}{
		{
			name: "valid netstring processed successfully",
			input: func() []byte {
				lengthBytes := make([]byte, 2)
				data := []byte("6:hello,")

				binary.BigEndian.PutUint16(lengthBytes, uint16(len(data)-1))

				return append(lengthBytes, data...)
			}(),
			setupServer: func() *TCPNetStringServer {
				ctx, cancel := context.WithCancel(context.Background())

				return &TCPNetStringServer{
					address: "127.0.0.1:8080",
					config: &Config{
						Server: Server{
							Listen: Listen{
								Type:    "tcp",
								Address: "127.0.0.1",
								Port:    8080,
							},
						},
					},
					logger: slog.Default(),
					ctx:    ctx,
					closer: cancel,
				}
			},
			expectError: false,
			expectedWrite: func() []byte {
				lengthBytes := make([]byte, 2)
				data := []byte("11:response,")

				binary.BigEndian.PutUint16(lengthBytes, uint16(len(data)-1))

				return append(lengthBytes, data...)
			}(),
		},
		{
			name: "invalid netstring length",
			input: func() []byte {
				lengthBytes := make([]byte, 2)
				data := []byte("6:he,")

				binary.BigEndian.PutUint16(lengthBytes, uint16(len(data)+1))

				return append(lengthBytes, data...)
			}(),
			setupServer: func() *TCPNetStringServer {
				ctx, cancel := context.WithCancel(context.Background())

				return &TCPNetStringServer{
					address: "127.0.0.1:8080",
					config:  &Config{},
					logger:  slog.Default(),
					ctx:     ctx,
					closer:  cancel,
				}
			},
			expectError: true,
		},
		{
			name: "EOF received during read",
			input: func() []byte {
				return nil
			}(),
			setupServer: func() *TCPNetStringServer {
				ctx, cancel := context.WithCancel(context.Background())
				return &TCPNetStringServer{
					address: "127.0.0.1:8080",
					config:  &Config{},
					logger:  slog.Default(),
					ctx:     ctx,
					closer:  cancel,
				}
			},
			expectError: true,
		},
		{
			name: "server context canceled",
			input: func() []byte {
				lengthBytes := make([]byte, 2)
				data := []byte("6:hello,")

				binary.BigEndian.PutUint16(lengthBytes, uint16(len(data)-1))

				return append(lengthBytes, data...)
			}(),
			setupServer: func() *TCPNetStringServer {
				ctx, cancel := context.WithCancel(context.Background())
				s := &TCPNetStringServer{
					address: "127.0.0.1:8080",
					config:  &Config{},
					logger:  slog.Default(),
					ctx:     ctx,
					closer:  cancel,
				}

				go func() {
					time.Sleep(50 * time.Millisecond)

					cancel()
				}()

				return s
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var wg sync.WaitGroup

			mockConn := NewMockConn(tt.input)
			server := tt.setupServer()

			wg.Add(1)

			defer wg.Wait()

			go func() {
				defer wg.Done()

				server.handleConnection(mockConn)
			}()

			time.Sleep(100 * time.Millisecond)

			if tt.expectError {
				if !mockConn.closeCalled {
					t.Errorf("expected connection to be closed, but was not")
				}
			} else {
				if !bytes.Equal(mockConn.writeBuffer.Bytes(), tt.expectedWrite) {
					t.Errorf("expected %v, got %v", tt.expectedWrite, mockConn.writeBuffer.Bytes())
				}
			}
		})
	}
}
