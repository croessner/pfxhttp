package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestConnectionSupervisorRejectsConnectionsAtItsLimit(t *testing.T) {
	supervisor := NewConnectionSupervisor(t.Context(), 1)
	t.Cleanup(supervisor.Stop)

	firstServer, firstClient := net.Pipe()

	t.Cleanup(func() { _ = firstClient.Close() })

	started := make(chan struct{})

	if !supervisor.Admit(firstServer, func(conn net.Conn) {
		close(started)

		_, _ = io.Copy(io.Discard, conn)
	}) {
		t.Fatal("first connection was rejected")
	}

	<-started

	secondServer, secondClient := net.Pipe()

	t.Cleanup(func() { _ = secondClient.Close() })

	if supervisor.Admit(secondServer, func(net.Conn) {}) {
		t.Fatal("connection above the admission limit was accepted")
	}

	if err := secondClient.SetWriteDeadline(time.Now().Add(time.Second)); err == nil {
		if _, writeErr := secondClient.Write([]byte("probe")); writeErr == nil {
			t.Fatal("rejected connection remained open")
		}
	}
}

func TestConnectionSupervisorsOwnIndependentCapacity(t *testing.T) {
	first := NewConnectionSupervisor(t.Context(), 1)
	second := NewConnectionSupervisor(t.Context(), 1)
	t.Cleanup(first.Stop)
	t.Cleanup(second.Stop)

	firstServer, firstClient := net.Pipe()

	t.Cleanup(func() { _ = firstClient.Close() })

	if !first.Admit(firstServer, blockingConnectionHandler) {
		t.Fatal("first listener rejected its initial connection")
	}

	secondServer, secondClient := net.Pipe()

	t.Cleanup(func() { _ = secondClient.Close() })

	if !second.Admit(secondServer, blockingConnectionHandler) {
		t.Fatal("one listener consumed another listener's capacity")
	}
}

func TestConnectionSupervisorStopClosesIdleHandlers(t *testing.T) {
	supervisor := NewConnectionSupervisor(context.Background(), 2)
	server, client := net.Pipe()

	t.Cleanup(func() { _ = client.Close() })

	finished := make(chan struct{})

	if !supervisor.Admit(server, func(conn net.Conn) {
		defer close(finished)

		_, _ = io.Copy(io.Discard, conn)
	}) {
		t.Fatal("idle connection was rejected")
	}

	stopped := make(chan struct{})

	go func() {
		supervisor.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("supervisor shutdown did not finish")
	}

	select {
	case <-finished:
	default:
		t.Fatal("idle handler was not stopped")
	}

	if got := supervisor.Active(); got != 0 {
		t.Fatalf("active connections = %d, want 0", got)
	}
}

func TestConnectionSupervisorStopInterruptsPartialProtocolReaders(t *testing.T) {
	tests := []struct {
		name    string
		partial string
		handler func(net.Conn)
	}{
		{
			name:    testSocketMapLabel,
			partial: "12:partial",
			handler: func(conn net.Conn) {
				_, _ = newSocketMapReader(conn, defaultSocketMapFraming()).Read(context.Background())
			},
		},
		{
			name:    testSocketName,
			partial: testPartialPolicyFrame,
			handler: func(conn net.Conn) {
				_, _ = newPolicyReader(conn, defaultPolicyFraming()).Read(context.Background())
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			supervisor := NewConnectionSupervisor(context.Background(), 1)
			server, client := net.Pipe()

			t.Cleanup(func() { _ = client.Close() })

			finished := make(chan struct{})

			if !supervisor.Admit(server, func(conn net.Conn) {
				defer close(finished)

				test.handler(conn)
			}) {
				t.Fatal("partial connection was rejected")
			}

			writeDone := make(chan struct{})

			go func() {
				_, _ = io.WriteString(client, test.partial)

				close(writeDone)
			}()

			<-writeDone

			supervisor.Stop()

			select {
			case <-finished:
			default:
				t.Fatal("partial reader remained blocked after shutdown")
			}
		})
	}
}

func TestConnectionSupervisorStopContextBoundsUncooperativeDrain(t *testing.T) {
	supervisor := NewConnectionSupervisor(context.Background(), 1)
	server, client := net.Pipe()

	t.Cleanup(func() { _ = client.Close() })

	release := make(chan struct{})
	finished := make(chan struct{})

	if !supervisor.Admit(server, func(net.Conn) {
		defer close(finished)

		<-release
	}) {
		t.Fatal("connection was rejected")
	}

	drainCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if supervisor.StopContext(drainCtx) {
		t.Fatal("uncooperative handler unexpectedly drained")
	}

	close(release)

	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("released handler did not finish")
	}

	if !supervisor.StopContext(context.Background()) {
		t.Fatal("finished supervisor did not report drained state")
	}
}

func blockingConnectionHandler(conn net.Conn) {
	_, _ = io.Copy(io.Discard, conn)
}
