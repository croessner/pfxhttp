//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"
)

var errClientClosed = errors.New("client closed connection")

type syscallConnProvider interface {
	SyscallConn() (syscall.RawConn, error)
}

// contextWithPeerClose cancels when a stream peer closes without consuming
// bytes that may already belong to the next pipelined protocol request.
func contextWithPeerClose(parent context.Context, conn net.Conn) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancelCause(parent)

	provider, ok := conn.(syscallConnProvider)
	if !ok {
		return ctx, func() { cancel(context.Canceled) }
	}

	raw, err := provider.SyscallConn()
	if err != nil {
		return ctx, func() { cancel(context.Canceled) }
	}

	go watchPeerClose(ctx, cancel, raw)

	return ctx, func() { cancel(context.Canceled) }
}

func watchPeerClose(ctx context.Context, cancel context.CancelCauseFunc, raw syscall.RawConn) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		closed := false

		controlErr := raw.Control(func(fd uintptr) {
			var probe [1]byte

			n, _, recvErr := syscall.Recvfrom(int(fd), probe[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
			switch {
			case recvErr == nil && n == 0:
				closed = true
			case errors.Is(recvErr, syscall.ECONNRESET), errors.Is(recvErr, syscall.ENOTCONN):
				closed = true
			}
		})
		if controlErr != nil || closed {
			cancel(errClientClosed)

			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
