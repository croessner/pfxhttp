package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	defaultPartialRequestTimeout = 10 * time.Second
	defaultDovecotLineBytes      = 16 << 10
	defaultSocketMapRequestBytes = 1 << 20
	defaultSocketMapLengthDigits = 10
	defaultPolicyRequestBytes    = 1 << 20
	defaultPolicyLineBytes       = 64 << 10
	defaultPolicyAttributes      = 256
)

func readBoundedLine(reader *bufio.Reader, maxBytes int) (string, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return "", err
	}

	return readBoundedLineFromFirst(reader, first, maxBytes)
}

func readBoundedLineFromFirst(reader *bufio.Reader, first byte, maxBytes int) (string, error) {
	if maxBytes < 1 {
		return "", newProtocolReadError(protocolErrorLineTooLarge)
	}

	line := make([]byte, 1, min(maxBytes, 256))

	line[0] = first
	if first == '\n' {
		return string(line), nil
	}

	for {
		fragment, err := reader.ReadSlice('\n')
		if len(line)+len(fragment) > maxBytes {
			return "", newProtocolReadError(protocolErrorLineTooLarge)
		}

		line = append(line, fragment...)
		if err == nil {
			return string(line), nil
		}

		if !errors.Is(err, bufio.ErrBufferFull) {
			return string(line), err
		}
	}
}

type protocolErrorKind string

const (
	protocolErrorIdleTimeout    protocolErrorKind = "idle_timeout"
	protocolErrorPartialTimeout protocolErrorKind = "partial_timeout"
	protocolErrorFrameTooLarge  protocolErrorKind = "frame_too_large"
	protocolErrorLineTooLarge   protocolErrorKind = "line_too_large"
	protocolErrorInvalidFrame   protocolErrorKind = "invalid_frame"
	protocolErrorClientClosed   protocolErrorKind = "client_closed"
	protocolErrorServerShutdown protocolErrorKind = "server_shutdown"
)

type protocolReadError struct {
	kind protocolErrorKind
}

func (e *protocolReadError) Error() string {
	return string(e.kind)
}

func newProtocolReadError(kind protocolErrorKind) error {
	return &protocolReadError{kind: kind}
}

func protocolErrorIs(err error, kind protocolErrorKind) bool {
	var protocolErr *protocolReadError

	return errors.As(err, &protocolErr) && protocolErr.kind == kind
}

func protocolErrorKindOf(err error) (protocolErrorKind, bool) {
	var protocolErr *protocolReadError
	if !errors.As(err, &protocolErr) {
		return "", false
	}

	return protocolErr.kind, true
}

type socketMapFramingLimits struct {
	idleTimeout     time.Duration
	partialTimeout  time.Duration
	maxRequestBytes int
	maxLengthDigits int
}

func defaultSocketMapFraming() socketMapFramingLimits {
	return socketMapFramingLimits{
		partialTimeout:  defaultPartialRequestTimeout,
		maxRequestBytes: defaultSocketMapRequestBytes,
		maxLengthDigits: defaultSocketMapLengthDigits,
	}
}

type socketMapReader struct {
	conn   net.Conn
	reader *bufio.Reader
	limits socketMapFramingLimits
	state  func(string, int64)
}

func newSocketMapReader(conn net.Conn, limits socketMapFramingLimits) *socketMapReader {
	return &socketMapReader{conn: conn, reader: bufio.NewReader(conn), limits: limits}
}

func (r *socketMapReader) SetStateObserver(observer func(string, int64)) {
	r.state = observer
}

func (r *socketMapReader) Read(ctx context.Context) (*NetString, error) {
	r.observeState("idle", 1)
	first, err := readIdleByte(ctx, r.conn, r.reader, r.limits.idleTimeout)
	r.observeState("idle", -1)

	if err != nil {
		return nil, err
	}

	r.observeState("partial", 1)
	defer r.observeState("partial", -1)

	if err = setPartialDeadline(r.conn, r.limits.partialTimeout); err != nil {
		return nil, err
	}

	length, err := r.readLength(ctx, first)
	if err != nil {
		return nil, err
	}

	payload := make([]byte, length)
	if _, err = io.ReadFull(r.reader, payload); err != nil {
		return nil, classifyPartialReadError(ctx, err)
	}

	trailing, err := r.reader.ReadByte()
	if err != nil {
		return nil, classifyPartialReadError(ctx, err)
	}

	if trailing != ',' {
		return nil, newProtocolReadError(protocolErrorInvalidFrame)
	}

	if err = r.conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return NewNetString(payload), nil
}

func (r *socketMapReader) observeState(state string, delta int64) {
	if r.state != nil {
		r.state(state, delta)
	}
}

func (r *socketMapReader) readLength(ctx context.Context, first byte) (int, error) {
	length := 0
	digits := 0
	current := first

	for current != ':' {
		if current < '0' || current > '9' {
			return 0, newProtocolReadError(protocolErrorInvalidFrame)
		}

		digits++
		if digits > r.limits.maxLengthDigits {
			return 0, newProtocolReadError(protocolErrorFrameTooLarge)
		}

		digit := int(current - '0')
		if digit > r.limits.maxRequestBytes || length > (r.limits.maxRequestBytes-digit)/10 {
			return 0, newProtocolReadError(protocolErrorFrameTooLarge)
		}

		length = length*10 + digit

		next, err := r.reader.ReadByte()
		if err != nil {
			return 0, classifyPartialReadError(ctx, err)
		}

		current = next
	}

	if digits == 0 || length == 0 {
		return 0, newProtocolReadError(protocolErrorInvalidFrame)
	}

	return length, nil
}

type policyFramingLimits struct {
	idleTimeout     time.Duration
	partialTimeout  time.Duration
	maxRequestBytes int
	maxLineBytes    int
	maxAttributes   int
}

func defaultPolicyFraming() policyFramingLimits {
	return policyFramingLimits{
		partialTimeout:  defaultPartialRequestTimeout,
		maxRequestBytes: defaultPolicyRequestBytes,
		maxLineBytes:    defaultPolicyLineBytes,
		maxAttributes:   defaultPolicyAttributes,
	}
}

type policyReader struct {
	conn   net.Conn
	reader *bufio.Reader
	limits policyFramingLimits
	state  func(string, int64)
}

func newPolicyReader(conn net.Conn, limits policyFramingLimits) *policyReader {
	return &policyReader{conn: conn, reader: bufio.NewReader(conn), limits: limits}
}

func (r *policyReader) SetStateObserver(observer func(string, int64)) {
	r.state = observer
}

func (r *policyReader) Read(ctx context.Context) (Policy, error) {
	r.observeState("idle", 1)
	first, err := readIdleByte(ctx, r.conn, r.reader, r.limits.idleTimeout)
	r.observeState("idle", -1)

	if err != nil {
		return nil, err
	}

	r.observeState("partial", 1)
	defer r.observeState("partial", -1)

	if err = setPartialDeadline(r.conn, r.limits.partialTimeout); err != nil {
		return nil, err
	}

	policy, err := r.readPolicy(ctx, first)
	if err != nil {
		return nil, err
	}

	if err = r.conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}

	return policy, nil
}

func (r *policyReader) readPolicy(ctx context.Context, first byte) (Policy, error) {
	policy := NewPostfixPolicy()
	totalBytes := 0
	attributes := 0

	for {
		line, consumed, err := r.readLine(ctx, first)
		if err != nil {
			return nil, err
		}

		totalBytes += consumed
		if totalBytes > r.limits.maxRequestBytes {
			return nil, newProtocolReadError(protocolErrorFrameTooLarge)
		}

		if len(line) == 0 {
			if attributes == 0 {
				return nil, newProtocolReadError(protocolErrorInvalidFrame)
			}

			return policy, nil
		}

		name, value, ok := splitPolicyAttribute(line)
		if !ok {
			return nil, newProtocolReadError(protocolErrorInvalidFrame)
		}

		attributes++
		if attributes > r.limits.maxAttributes {
			return nil, newProtocolReadError(protocolErrorFrameTooLarge)
		}

		policy.SetData(name, value)

		first, err = r.reader.ReadByte()
		if err != nil {
			return nil, classifyPartialReadError(ctx, err)
		}
	}
}

func (r *policyReader) observeState(state string, delta int64) {
	if r.state != nil {
		r.state(state, delta)
	}
}

func (r *policyReader) readLine(ctx context.Context, first byte) ([]byte, int, error) {
	line := make([]byte, 0, min(r.limits.maxLineBytes, 256))
	current := first
	consumed := 0

	for {
		consumed++

		if current == '\n' {
			break
		}

		if len(line) >= r.limits.maxLineBytes {
			return nil, consumed, newProtocolReadError(protocolErrorLineTooLarge)
		}

		line = append(line, current)

		next, err := r.reader.ReadByte()
		if err != nil {
			return nil, consumed, classifyPartialReadError(ctx, err)
		}

		current = next
	}

	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}

	return line, consumed, nil
}

func splitPolicyAttribute(line []byte) (string, string, bool) {
	separator := -1

	for index, value := range line {
		if value == 0 || value == '\n' || value == '\r' {
			return "", "", false
		}

		if value == '=' && separator < 0 {
			separator = index
		}
	}

	if separator <= 0 {
		return "", "", false
	}

	return string(line[:separator]), string(line[separator+1:]), true
}

func readIdleByte(ctx context.Context, conn net.Conn, reader *bufio.Reader, timeout time.Duration) (byte, error) {
	select {
	case <-ctx.Done():
		return 0, canceledProtocolReadError(ctx)
	default:
	}

	deadline := time.Time{}
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}

	if err := conn.SetReadDeadline(deadline); err != nil {
		return 0, err
	}

	value, err := reader.ReadByte()
	if err == nil {
		return value, nil
	}

	if isTimeoutError(err) {
		return 0, newProtocolReadError(protocolErrorIdleTimeout)
	}

	if ctx.Err() != nil {
		return 0, canceledProtocolReadError(ctx)
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || isConnectionResetError(err) {
		return 0, newProtocolReadError(protocolErrorClientClosed)
	}

	return 0, fmt.Errorf("read request: %w", err)
}

func setPartialDeadline(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return conn.SetReadDeadline(time.Time{})
	}

	return conn.SetReadDeadline(time.Now().Add(timeout))
}

func classifyPartialReadError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return canceledProtocolReadError(ctx)
	}

	if isTimeoutError(err) {
		return newProtocolReadError(protocolErrorPartialTimeout)
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return newProtocolReadError(protocolErrorInvalidFrame)
	}

	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || isConnectionResetError(err) {
		return newProtocolReadError(protocolErrorClientClosed)
	}

	return fmt.Errorf("read partial request: %w", err)
}

func canceledProtocolReadError(ctx context.Context) error {
	if errors.Is(context.Cause(ctx), errClientClosed) {
		return newProtocolReadError(protocolErrorClientClosed)
	}

	return newProtocolReadError(protocolErrorServerShutdown)
}

func isTimeoutError(err error) bool {
	var netErr net.Error

	return errors.As(err, &netErr) && netErr.Timeout()
}
