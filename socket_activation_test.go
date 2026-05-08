package main

import (
	"net"
	"os"
	"strconv"
	"syscall"
	"testing"
)

const (
	testSocketName = "policy"
	testLocalhost  = "127.0.0.1"
)

func TestNewSystemdSocketSetFromEnvIgnoresOtherPID(t *testing.T) {
	set, err := newSystemdSocketSetFromEnv(os.Getpid(), func(key string) string {
		switch key {
		case systemdEnvListenPID:
			return strconv.Itoa(os.Getpid() + 1)
		case systemdEnvListenFDs:
			return "1"
		case systemdEnvListenFDNames:
			return testSocketName
		default:
			return ""
		}
	}, nil)
	if err != nil {
		t.Fatalf("newSystemdSocketSetFromEnv returned error: %v", err)
	}

	if set.active {
		t.Fatal("expected socket activation to be ignored for a different LISTEN_PID")
	}
}

func TestSystemdSocketSetRequiresExplicitActivation(t *testing.T) {
	var set *SystemdSocketSet

	_, activated, err := set.ClaimListener(Listen{
		Kind:              listenKindPolicyService,
		Name:              testSocketName,
		Type:              listenTypeTCP,
		Address:           testLocalhost,
		Port:              2525,
		SystemdSocketName: testSocketName,
	})
	if !activated {
		t.Fatal("expected activated=true for a listener with systemd_socket_name")
	}

	if err == nil {
		t.Fatal("expected an error when no activated socket set is available")
	}
}

func TestSystemdSocketSetClaimTCPListener(t *testing.T) {
	baseListener, err := net.Listen(listenTypeTCP, testLocalhost+":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = baseListener.Close() }()

	fd := duplicatedTCPListenerFD(t, baseListener)

	port := baseListener.Addr().(*net.TCPAddr).Port
	set := &SystemdSocketSet{
		active: true,
		byName: map[string]systemdSocketFD{
			testSocketName: {name: testSocketName, fd: fd},
		},
		claimed: make(map[string]struct{}),
	}

	claimedListener, activated, err := set.ClaimListener(Listen{
		Kind:              listenKindPolicyService,
		Name:              testSocketName,
		Type:              listenTypeTCP,
		Address:           testLocalhost,
		Port:              port,
		SystemdSocketName: testSocketName,
	})
	if err != nil {
		t.Fatalf("claim listener: %v", err)
	}
	defer func() { _ = claimedListener.Close() }()

	if !activated {
		t.Fatal("expected activated=true")
	}

	if claimedListener.Addr().String() == "" {
		t.Fatal("expected claimed listener to have an address")
	}
}

func TestSystemdSocketSetRejectsPortMismatch(t *testing.T) {
	baseListener, err := net.Listen(listenTypeTCP, testLocalhost+":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = baseListener.Close() }()

	fd := duplicatedTCPListenerFD(t, baseListener)

	set := &SystemdSocketSet{
		active: true,
		byName: map[string]systemdSocketFD{
			testSocketName: {name: testSocketName, fd: fd},
		},
		claimed: make(map[string]struct{}),
	}

	_, _, err = set.ClaimListener(Listen{
		Kind:              listenKindPolicyService,
		Name:              testSocketName,
		Type:              listenTypeTCP,
		Address:           testLocalhost,
		Port:              1,
		SystemdSocketName: testSocketName,
	})
	if err == nil {
		t.Fatal("expected port mismatch error")
	}
}

func TestRegistryDetectsSystemdSocketListenerChanges(t *testing.T) {
	registry := NewListenerRegistry()
	oldConfig := Listen{
		Kind:              listenKindPolicyService,
		Name:              testSocketName,
		Type:              listenTypeUnix,
		Address:           "/run/pfxhttp/policy.sock",
		SystemdSocketName: testSocketName,
	}

	registry.Register(oldConfig, &ListenerEntry{Config: oldConfig})
	diff := registry.Diff(nil)

	if !registry.DiffTouchesSystemdSockets(diff) {
		t.Fatal("expected removed systemd listener to require service restart")
	}
}

func TestRegistryAllowsNativeListenerChanges(t *testing.T) {
	registry := NewListenerRegistry()
	oldConfig := Listen{
		Kind:    listenKindPolicyService,
		Name:    testSocketName,
		Type:    listenTypeTCP,
		Address: testLocalhost,
		Port:    2525,
	}
	newConfig := oldConfig
	newConfig.Port = 2526

	registry.Register(oldConfig, &ListenerEntry{Config: oldConfig})
	diff := registry.Diff([]Listen{newConfig})

	if registry.DiffTouchesSystemdSockets(diff) {
		t.Fatal("native listener changes should remain reloadable")
	}
}

// duplicatedTCPListenerFD returns an independent descriptor that emulates a systemd-passed listener.
func duplicatedTCPListenerFD(t *testing.T, listener net.Listener) uintptr {
	t.Helper()

	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		t.Fatalf("expected TCP listener, got %T", listener)
	}

	file, err := tcpListener.File()
	if err != nil {
		t.Fatalf("listener file: %v", err)
	}
	defer func() { _ = file.Close() }()

	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatalf("duplicate listener fd: %v", err)
	}

	return uintptr(fd)
}
