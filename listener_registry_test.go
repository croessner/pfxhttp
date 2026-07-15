package main

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNativeListenerRestartDoesNotDisturbAnotherListener(t *testing.T) {
	deps, _ := newConcurrencyTestDeps(t)
	logger := slog.New(slog.DiscardHandler)

	sockets, err := newSystemdSocketSetFromEnv(1, func(string) string { return "" }, logger)
	if err != nil {
		t.Fatalf("create inactive socket set: %v", err)
	}

	registry := NewListenerRegistry()
	t.Cleanup(registry.StopAll)

	directory, err := os.MkdirTemp("/tmp", "pfxhttp-")
	if err != nil {
		t.Fatalf("create short Unix socket directory: %v", err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(directory) })

	first := nativeUnixSocketMap(filepath.Join(directory, "first.sock"))
	second := nativeUnixSocketMap(filepath.Join(directory, "second.sock"))

	for _, listener := range []Listen{first, second} {
		if err = registry.startListener(t.Context(), deps, listener, sockets, logger); err != nil {
			t.Fatalf("start %s: %v", listener.Address, err)
		}
	}

	assertUnixSocketMapLookup(t, second.Address, "before@example.test")
	registry.Remove(listenKey(first))
	assertUnixSocketMapLookup(t, second.Address, "during@example.test")

	if err = registry.startListener(t.Context(), deps, first, sockets, logger); err != nil {
		t.Fatalf("restart %s: %v", first.Address, err)
	}

	assertUnixSocketMapLookup(t, first.Address, "after@example.test")
	assertUnixSocketMapLookup(t, second.Address, "still-serving@example.test")
}

func TestFailedPostBindValidationReleasesNativeListener(t *testing.T) {
	deps, _ := newConcurrencyTestDeps(t)
	logger := slog.New(slog.DiscardHandler)

	sockets, err := newSystemdSocketSetFromEnv(1, func(string) string { return "" }, logger)
	if err != nil {
		t.Fatalf("create inactive socket set: %v", err)
	}

	directory, err := os.MkdirTemp("/tmp", "pfxhttp-invalid-")
	if err != nil {
		t.Fatalf("create short Unix socket directory: %v", err)
	}

	t.Cleanup(func() { _ = os.RemoveAll(directory) })

	address := filepath.Join(directory, "policy.sock")
	invalid := Listen{
		Kind:    listenKindPolicyService,
		Type:    listenTypeUnix,
		Address: address,
		Limits:  LimitsConfig{MaxConnections: 1},
	}

	registry := NewListenerRegistry()

	err = registry.startListener(t.Context(), deps, invalid, sockets, logger)
	if err == nil {
		t.Fatal("expected missing policy service name to fail after bind")
	}

	rebound, err := net.Listen(listenTypeUnix, address)
	if err != nil {
		t.Fatalf("failed listener retained its native endpoint: %v", err)
	}

	_ = rebound.Close()
}

func TestListenerDiffUsesResolvedValuesAndRelevantProtocolBlock(t *testing.T) {
	idleA := 15 * time.Second
	idleB := 15 * time.Second
	queuedA := 4
	queuedB := 4
	current := Listen{
		Kind: listenKindSocketMap, Name: testFirst, Type: listenTypeTCP, Address: concurrencyTestHost, Port: 23450,
		Limits: LimitsConfig{MaxConnections: 10, MaxInflightRequests: 2, MaxQueuedRequests: &queuedA},
		ProtocolLimits: ProtocolLimitsConfig{
			SocketMap:     SocketMapProtocolLimits{IdleTimeout: &idleA, MaxRequestBytes: 1024},
			PolicyService: PolicyServiceProtocolLimits{MaxRequestBytes: 1024},
		},
	}
	next := current
	next.Limits.MaxQueuedRequests = &queuedB
	next.ProtocolLimits.SocketMap.IdleTimeout = &idleB
	next.ProtocolLimits.PolicyService.MaxRequestBytes = 4096

	registry := NewListenerRegistry()
	registry.Register(current, &ListenerEntry{Config: current})

	diff := registry.Diff([]Listen{next})
	if len(diff.Unchanged) != 1 || len(diff.Changed) != 0 {
		t.Fatalf("equal resolved values or irrelevant policy defaults restarted socket map: %+v", diff)
	}

	next.ProtocolLimits.SocketMap.MaxRequestBytes = 2048

	diff = registry.Diff([]Listen{next})
	if len(diff.Changed) != 1 || len(diff.Unchanged) != 0 {
		t.Fatalf("relevant socket map limit change was ignored: %+v", diff)
	}
}

func nativeUnixSocketMap(path string) Listen {
	return Listen{
		Kind:    listenKindSocketMap,
		Name:    concurrencyTestMap,
		Type:    listenTypeUnix,
		Address: path,
		Limits:  LimitsConfig{MaxConnections: 4},
	}
}

func assertUnixSocketMapLookup(t *testing.T, address, key string) {
	t.Helper()

	deadline := time.Now().Add(concurrencyCleanupTimeout)

	var (
		conn net.Conn
		err  error
	)

	for time.Now().Before(deadline) {
		conn, err = net.DialTimeout(listenTypeUnix, address, 100*time.Millisecond)
		if err == nil {
			break
		}

		select {
		case <-t.Context().Done():
			t.Fatal("test canceled while dialing native listener")
		case <-time.After(10 * time.Millisecond):
		}
	}

	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}

	t.Cleanup(func() { _ = conn.Close() })
	completeSocketMapLookup(t, conn, key)
}
