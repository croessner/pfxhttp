//go:build !darwin && !linux

package main

import (
	"context"
	"errors"
	"net"
)

var errClientClosed = errors.New("client closed connection")

func contextWithPeerClose(parent context.Context, _ net.Conn) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}
