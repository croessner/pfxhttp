package main

import (
	"context"
	"net"
	"sync"
	"time"
)

const defaultConnectionDrainTimeout = 5 * time.Second

// ConnectionSupervisor owns the lifecycle and admission accounting of connections for one listener.
type ConnectionSupervisor struct {
	ctx    context.Context
	cancel context.CancelFunc
	limit  chan struct{}

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	wg          sync.WaitGroup
	stopOnce    sync.Once
	stopped     chan struct{}
}

// NewConnectionSupervisor creates independent connection accounting for one listener.
func NewConnectionSupervisor(parent context.Context, maxConnections int) *ConnectionSupervisor {
	ctx, cancel := context.WithCancel(parent)

	return &ConnectionSupervisor{
		ctx:         ctx,
		cancel:      cancel,
		limit:       make(chan struct{}, max(1, maxConnections)),
		connections: make(map[net.Conn]struct{}),
		stopped:     make(chan struct{}),
	}
}

// Admit starts a supervised connection handler when listener capacity is available.
// A rejected connection is closed before Admit returns.
func (s *ConnectionSupervisor) Admit(conn net.Conn, handler func(net.Conn)) bool {
	select {
	case <-s.ctx.Done():
		_ = conn.Close()

		return false
	case s.limit <- struct{}{}:
	default:
		_ = conn.Close()

		return false
	}

	s.mu.Lock()

	select {
	case <-s.ctx.Done():
		s.mu.Unlock()
		<-s.limit

		_ = conn.Close()

		return false
	default:
	}

	s.connections[conn] = struct{}{}
	s.wg.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.release(conn)

		handler(conn)
	}()

	return true
}

func (s *ConnectionSupervisor) release(conn net.Conn) {
	_ = conn.Close()

	s.mu.Lock()
	delete(s.connections, conn)
	s.mu.Unlock()

	<-s.limit
	s.wg.Done()
}

// Stop cancels admission, closes admitted connections and waits up to the drain deadline.
func (s *ConnectionSupervisor) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), defaultConnectionDrainTimeout)
	defer cancel()

	s.StopContext(ctx)
}

// StopContext begins shutdown once and reports whether all handlers drained before ctx ended.
func (s *ConnectionSupervisor) StopContext(ctx context.Context) bool {
	s.stopOnce.Do(func() {
		s.cancel()

		s.mu.Lock()

		connections := make([]net.Conn, 0, len(s.connections))
		for conn := range s.connections {
			connections = append(connections, conn)
		}
		s.mu.Unlock()

		for _, conn := range connections {
			_ = conn.Close()
		}

		go func() {
			s.wg.Wait()
			close(s.stopped)
		}()
	})

	select {
	case <-s.stopped:
		return true
	case <-ctx.Done():
		return false
	}
}

// Active returns the current number of admitted connections.
func (s *ConnectionSupervisor) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.connections)
}
