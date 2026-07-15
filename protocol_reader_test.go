package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReadBoundedLineRejectsOversizedDovecotCommand(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(strings.Repeat("x", defaultDovecotLineBytes) + "\n"))

	_, err := readBoundedLine(reader, defaultDovecotLineBytes)
	if !protocolErrorIs(err, protocolErrorLineTooLarge) {
		t.Fatalf("oversized Dovecot line error = %v, want line_too_large", err)
	}
}

func TestReadBoundedLineReportsConsumedPartialDataOnTimeout(t *testing.T) {
	server, client := net.Pipe()

	t.Cleanup(func() { _ = server.Close() })
	t.Cleanup(func() { _ = client.Close() })

	if err := server.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("set partial-line deadline: %v", err)
	}

	go func() { _, _ = io.WriteString(client, "AUTH\tpartial") }()

	partial, err := readBoundedLine(bufio.NewReader(server), defaultDovecotLineBytes)
	if !isTimeoutError(err) {
		t.Fatalf("partial Dovecot line error = %v, want timeout", err)
	}

	if len(partial) == 0 {
		t.Fatal("partial Dovecot line timeout lost already-consumed framing state")
	}
}

const framingTestTimeout = 2 * time.Second
const boundedPolicyInput = "one=1\ntwo=2\n\n"
const testFirst = "first"
const testSecond = "second"

func TestSocketMapReaderHandlesBackToBackFrames(t *testing.T) {
	server, client := net.Pipe()

	t.Cleanup(func() { _ = server.Close() })
	t.Cleanup(func() { _ = client.Close() })

	writeAsync(t, client, "5:first,6:second,")

	reader := newSocketMapReader(server, socketMapFramingLimits{
		partialTimeout:  time.Second,
		maxRequestBytes: 32,
		maxLengthDigits: 2,
	})

	for index, want := range []string{testFirst, testSecond} {
		frame, err := reader.Read(t.Context())
		if err != nil {
			t.Fatalf("read frame %d: %v", index, err)
		}

		if got := frame.String(); got != want {
			t.Fatalf("frame %d = %q, want %q", index, got, want)
		}
	}
}

func TestSocketMapReaderRejectsMalformedAndOversizedFrames(t *testing.T) {
	tests := []struct {
		name  string
		input string
		kind  protocolErrorKind
	}{
		{name: "non digit length", input: "x:value,", kind: protocolErrorInvalidFrame},
		{name: "negative like length", input: "-1:x,", kind: protocolErrorInvalidFrame},
		{name: "empty length", input: ":,", kind: protocolErrorInvalidFrame},
		{name: "excessive digits", input: "001:value,", kind: protocolErrorFrameTooLarge},
		{name: "oversized payload", input: "5:value,", kind: protocolErrorFrameTooLarge},
		{name: "missing colon", input: "2", kind: protocolErrorInvalidFrame},
		{name: "missing comma", input: "2:ok.", kind: protocolErrorInvalidFrame},
		{name: "truncated payload", input: "3:ab", kind: protocolErrorInvalidFrame},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := &staticReadConn{Reader: bytes.NewReader([]byte(test.input))}
			reader := newSocketMapReader(conn, socketMapFramingLimits{
				partialTimeout:  time.Second,
				maxRequestBytes: 4,
				maxLengthDigits: 2,
			})

			_, err := reader.Read(t.Context())
			if !protocolErrorIs(err, test.kind) {
				t.Fatalf("Read() error = %v, want kind %q", err, test.kind)
			}
		})
	}
}

func TestSocketMapReaderRejectsNumericLengthOverflow(t *testing.T) {
	conn := &staticReadConn{Reader: bytes.NewReader([]byte("99999999999999999999999999999999:"))}
	reader := newSocketMapReader(conn, socketMapFramingLimits{
		partialTimeout:  time.Second,
		maxRequestBytes: int(^uint(0) >> 1),
		maxLengthDigits: 32,
	})

	_, err := reader.Read(t.Context())
	if !protocolErrorIs(err, protocolErrorFrameTooLarge) {
		t.Fatalf("Read() error = %v, want frame too large", err)
	}
}

func TestSocketMapReaderDistinguishesIdleCloseAndTimeout(t *testing.T) {
	t.Run("idle close", func(t *testing.T) {
		server, client := net.Pipe()

		t.Cleanup(func() { _ = server.Close() })
		writeAndCloseAsync(t, client, "")

		_, err := newSocketMapReader(server, socketMapFramingLimits{
			idleTimeout:     time.Second,
			partialTimeout:  time.Second,
			maxRequestBytes: 16,
			maxLengthDigits: 2,
		}).Read(t.Context())
		if !protocolErrorIs(err, protocolErrorClientClosed) {
			t.Fatalf("Read() error = %v, want client_closed", err)
		}
	})

	t.Run("idle timeout", func(t *testing.T) {
		server, client := net.Pipe()

		t.Cleanup(func() { _ = server.Close() })
		t.Cleanup(func() { _ = client.Close() })

		_, err := newSocketMapReader(server, socketMapFramingLimits{
			idleTimeout:     20 * time.Millisecond,
			partialTimeout:  time.Second,
			maxRequestBytes: 16,
			maxLengthDigits: 2,
		}).Read(t.Context())
		if !protocolErrorIs(err, protocolErrorIdleTimeout) {
			t.Fatalf("Read() error = %v, want idle timeout", err)
		}
	})
}

func TestSocketMapReaderUsesOneAbsolutePartialDeadline(t *testing.T) {
	server, client := net.Pipe()
	recorded := &deadlineRecordingConn{Conn: server}

	t.Cleanup(func() { _ = server.Close() })
	t.Cleanup(func() { _ = client.Close() })

	go func() {
		_, _ = client.Write([]byte("1"))

		time.Sleep(30 * time.Millisecond)

		_, _ = client.Write([]byte(":"))

		time.Sleep(30 * time.Millisecond)

		_, _ = client.Write([]byte("x,"))
	}()

	_, err := newSocketMapReader(recorded, socketMapFramingLimits{
		partialTimeout:  50 * time.Millisecond,
		maxRequestBytes: 16,
		maxLengthDigits: 2,
	}).Read(t.Context())
	if !protocolErrorIs(err, protocolErrorPartialTimeout) {
		t.Fatalf("Read() error = %v, want partial timeout", err)
	}

	if got := recorded.nonZeroReadDeadlines(); got != 1 {
		t.Fatalf("non-zero read deadlines = %d, want 1", got)
	}
}

func TestPolicyReaderPreservesBufferedRequestsAndValues(t *testing.T) {
	server, client := net.Pipe()

	t.Cleanup(func() { _ = server.Close() })
	t.Cleanup(func() { _ = client.Close() })

	writeAsync(t, client, "request=smtpd_access_policy\nreason=value with spaces\n\nrequest=smtpd_access_policy\nrecipient=user@example.test\n\n")

	reader := newPolicyReader(server, policyFramingLimits{
		partialTimeout:  time.Second,
		maxRequestBytes: 256,
		maxLineBytes:    128,
		maxAttributes:   8,
	})

	first, err := reader.Read(t.Context())
	if err != nil {
		t.Fatalf("read first policy request: %v", err)
	}

	if got := first.GetData()["reason"]; got != "value with spaces" {
		t.Fatalf("first reason = %q, want preserved spaces", got)
	}

	second, err := reader.Read(t.Context())
	if err != nil {
		t.Fatalf("read second policy request: %v", err)
	}

	if got := second.GetData()["recipient"]; got != "user@example.test" {
		t.Fatalf("second recipient = %q", got)
	}
}

func TestPolicyReaderEnforcesBoundsAndSyntax(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		limits policyFramingLimits
		kind   protocolErrorKind
	}{
		{
			name:  "line length",
			input: "name=value\n\n",
			limits: policyFramingLimits{
				partialTimeout: time.Second, maxRequestBytes: 64, maxLineBytes: 5, maxAttributes: 4,
			},
			kind: protocolErrorLineTooLarge,
		},
		{
			name:  "attribute count",
			input: boundedPolicyInput,
			limits: policyFramingLimits{
				partialTimeout: time.Second, maxRequestBytes: 64, maxLineBytes: 16, maxAttributes: 1,
			},
			kind: protocolErrorFrameTooLarge,
		},
		{
			name:  "total bytes",
			input: boundedPolicyInput,
			limits: policyFramingLimits{
				partialTimeout: time.Second, maxRequestBytes: 5, maxLineBytes: 16, maxAttributes: 4,
			},
			kind: protocolErrorFrameTooLarge,
		},
		{
			name:  "missing separator",
			input: "malformed\n\n",
			limits: policyFramingLimits{
				partialTimeout: time.Second, maxRequestBytes: 64, maxLineBytes: 16, maxAttributes: 4,
			},
			kind: protocolErrorInvalidFrame,
		},
		{
			name:  "empty name",
			input: "=value\n\n",
			limits: policyFramingLimits{
				partialTimeout: time.Second, maxRequestBytes: 64, maxLineBytes: 16, maxAttributes: 4,
			},
			kind: protocolErrorInvalidFrame,
		},
		{
			name:  "empty request",
			input: "\n",
			limits: policyFramingLimits{
				partialTimeout: time.Second, maxRequestBytes: 64, maxLineBytes: 16, maxAttributes: 4,
			},
			kind: protocolErrorInvalidFrame,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) { assertPolicyReaderError(t, test.input, test.limits, test.kind) })
	}
}

func assertPolicyReaderError(t *testing.T, input string, limits policyFramingLimits, kind protocolErrorKind) {
	t.Helper()

	server, client := net.Pipe()

	t.Cleanup(func() { _ = server.Close() })
	t.Cleanup(func() { _ = client.Close() })
	writeAsync(t, client, input)

	_, err := newPolicyReader(server, limits).Read(t.Context())
	if !protocolErrorIs(err, kind) {
		t.Fatalf("Read() error = %v, want kind %q", err, kind)
	}
}

func TestPolicyReaderUsesOneAbsolutePartialDeadline(t *testing.T) {
	server, client := net.Pipe()
	recorded := &deadlineRecordingConn{Conn: server}

	t.Cleanup(func() { _ = server.Close() })
	t.Cleanup(func() { _ = client.Close() })

	go func() {
		_, _ = client.Write([]byte("n"))

		time.Sleep(30 * time.Millisecond)

		_, _ = client.Write([]byte("a"))

		time.Sleep(30 * time.Millisecond)

		_, _ = client.Write([]byte("me=value\n\n"))
	}()

	_, err := newPolicyReader(recorded, policyFramingLimits{
		partialTimeout:  50 * time.Millisecond,
		maxRequestBytes: 64,
		maxLineBytes:    32,
		maxAttributes:   4,
	}).Read(t.Context())
	if !protocolErrorIs(err, protocolErrorPartialTimeout) {
		t.Fatalf("Read() error = %v, want partial timeout", err)
	}

	if got := recorded.nonZeroReadDeadlines(); got != 1 {
		t.Fatalf("non-zero read deadlines = %d, want 1", got)
	}
}

type deadlineRecordingConn struct {
	net.Conn
	mu            sync.Mutex
	readDeadlines []time.Time
}

type staticReadConn struct {
	io.Reader
}

func (*staticReadConn) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (*staticReadConn) Close() error                     { return nil }
func (*staticReadConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*staticReadConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*staticReadConn) SetDeadline(time.Time) error      { return nil }
func (*staticReadConn) SetReadDeadline(time.Time) error  { return nil }
func (*staticReadConn) SetWriteDeadline(time.Time) error { return nil }

func (c *deadlineRecordingConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadlines = append(c.readDeadlines, deadline)
	c.mu.Unlock()

	return c.Conn.SetReadDeadline(deadline)
}

func (c *deadlineRecordingConn) nonZeroReadDeadlines() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0

	for _, deadline := range c.readDeadlines {
		if !deadline.IsZero() {
			count++
		}
	}

	return count
}

func writeAsync(t *testing.T, conn net.Conn, value string) {
	t.Helper()

	go func() {
		if err := conn.SetWriteDeadline(time.Now().Add(framingTestTimeout)); err != nil {
			t.Errorf("set write deadline: %v", err)
			return
		}

		if _, err := io.WriteString(conn, value); err != nil {
			t.Errorf("write fixture: %v", err)
		}
	}()
}

func writeAndCloseAsync(t *testing.T, conn net.Conn, value string) {
	t.Helper()

	go func() {
		defer func() { _ = conn.Close() }()

		if err := conn.SetWriteDeadline(time.Now().Add(framingTestTimeout)); err != nil {
			t.Errorf("set write deadline: %v", err)
			return
		}

		if _, err := io.WriteString(conn, value); err != nil {
			t.Errorf("write fixture: %v", err)
		}
	}()
}

var _ net.Conn = (*deadlineRecordingConn)(nil)
var _ net.Conn = (*staticReadConn)(nil)
