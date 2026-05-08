package main

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	// systemdListenFDsStart is the first file descriptor index used by systemd socket activation.
	systemdListenFDsStart = 3

	// systemdEnvListenPID identifies the process that should consume activated descriptors.
	systemdEnvListenPID = "LISTEN_PID"
	// systemdEnvListenFDs contains the number of activated descriptors passed by systemd.
	systemdEnvListenFDs = "LISTEN_FDS"
	// systemdEnvListenFDNames contains colon-separated FileDescriptorName values.
	systemdEnvListenFDNames = "LISTEN_FDNAMES"
)

// systemdSocketFD stores one named descriptor advertised by systemd.
type systemdSocketFD struct {
	name string
	fd   uintptr
}

// SystemdSocketSet tracks named listeners handed to pfxhttp by systemd socket
// activation. A listener is used only when the matching listen entry explicitly
// configures systemd_socket_name; native listeners remain the default.
type SystemdSocketSet struct {
	mu      sync.Mutex
	active  bool
	byName  map[string]systemdSocketFD
	claimed map[string]struct{}
	logger  *slog.Logger
}

// NewSystemdSocketSet returns the socket activation descriptors available to the current process.
func NewSystemdSocketSet(logger *slog.Logger) (*SystemdSocketSet, error) {
	return newSystemdSocketSetFromEnv(os.Getpid(), os.Getenv, logger)
}

// newSystemdSocketSetFromEnv builds a socket set from environment variables and is injectable for tests.
func newSystemdSocketSetFromEnv(pid int, getenv func(string) string, logger *slog.Logger) (*SystemdSocketSet, error) {
	set := &SystemdSocketSet{
		byName:  make(map[string]systemdSocketFD),
		claimed: make(map[string]struct{}),
		logger:  logger,
	}

	pidRaw := strings.TrimSpace(getenv(systemdEnvListenPID))
	fdsRaw := strings.TrimSpace(getenv(systemdEnvListenFDs))

	if pidRaw == "" || fdsRaw == "" {
		return set, nil
	}

	listenPID, err := strconv.Atoi(pidRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid LISTEN_PID %q: %w", pidRaw, err)
	}

	if listenPID != pid {
		return set, nil
	}

	fdCount, err := strconv.Atoi(fdsRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid LISTEN_FDS %q: %w", fdsRaw, err)
	}

	if fdCount <= 0 {
		return set, nil
	}

	set.active = true

	names := parseSystemdFDNames(strings.TrimSpace(getenv(systemdEnvListenFDNames)), fdCount)
	for i, name := range names {
		if name == "" {
			continue
		}

		if _, exists := set.byName[name]; exists {
			return nil, fmt.Errorf("duplicate systemd FileDescriptorName %q", name)
		}

		set.byName[name] = systemdSocketFD{
			name: name,
			fd:   uintptr(systemdListenFDsStart + i),
		}
	}

	return set, nil
}

// parseSystemdFDNames expands LISTEN_FDNAMES into a descriptor-name slice aligned with LISTEN_FDS.
func parseSystemdFDNames(raw string, count int) []string {
	names := make([]string, count)
	if raw == "" {
		return names
	}

	parts := strings.Split(raw, ":")
	for i := 0; i < len(parts) && i < count; i++ {
		names[i] = strings.TrimSpace(parts[i])
	}

	return names
}

// ClaimListener returns the activated listener requested by instance, if one is configured.
func (s *SystemdSocketSet) ClaimListener(instance Listen) (net.Listener, bool, error) {
	name := instance.SystemdSocketName
	if name == "" {
		return nil, false, nil
	}

	if s == nil || !s.active {
		return nil, true, fmt.Errorf("listener %s is configured for systemd socket %q, but no activated sockets were provided", listenKey(instance), name)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	info, ok := s.byName[name]
	if !ok {
		return nil, true, fmt.Errorf("listener %s is configured for systemd socket %q, but LISTEN_FDNAMES did not provide that name", listenKey(instance), name)
	}

	if _, ok := s.claimed[name]; ok {
		return nil, true, fmt.Errorf("systemd socket %q is configured by more than one listener", name)
	}

	file := os.NewFile(info.fd, fmt.Sprintf("systemd-listener-%s", info.name))
	if file == nil {
		return nil, true, fmt.Errorf("failed to access activated systemd fd %d for %q", info.fd, name)
	}

	listener, err := net.FileListener(file)
	_ = file.Close()

	if err != nil {
		return nil, true, fmt.Errorf("systemd fd %d for %q is not a supported listener: %w", info.fd, name, err)
	}

	if err = validateActivatedListener(instance, listener); err != nil {
		_ = listener.Close()

		return nil, true, err
	}

	s.claimed[name] = struct{}{}
	if s.logger != nil {
		s.logger.Info("Using systemd-activated listener",
			slog.String("listener", listenKey(instance)),
			slog.String("systemd_socket_name", name),
			slog.String("fd_address", listener.Addr().String()),
		)
	}

	return listener, true, nil
}

// validateActivatedListener checks that a claimed descriptor matches the configured listener endpoint.
func validateActivatedListener(instance Listen, listener net.Listener) error {
	network := listener.Addr().Network()

	switch instance.Type {
	case listenTypeUnix:
		if !strings.HasPrefix(network, listenTypeUnix) {
			return fmt.Errorf("systemd socket %q for listener %s is %q, expected unix", instance.SystemdSocketName, listenKey(instance), network)
		}

		if listener.Addr().String() != instance.Address {
			return fmt.Errorf("systemd socket %q for listener %s has address %q, expected %q", instance.SystemdSocketName, listenKey(instance), listener.Addr().String(), instance.Address)
		}

	case listenTypeTCP, listenTypeTCP6:
		if !strings.HasPrefix(network, listenTypeTCP) {
			return fmt.Errorf("systemd socket %q for listener %s is %q, expected tcp", instance.SystemdSocketName, listenKey(instance), network)
		}

		port := listenerTCPPort(listener.Addr().String())

		if instance.Port != 0 && port != strconv.Itoa(instance.Port) {
			return fmt.Errorf("systemd socket %q for listener %s uses port %q, expected %d", instance.SystemdSocketName, listenKey(instance), port, instance.Port)
		}

	default:
		return fmt.Errorf("unsupported listener type %q", instance.Type)
	}

	return nil
}

// listenerTCPPort extracts the TCP port from an address string for activated socket validation.
func listenerTCPPort(addr string) string {
	normalized := strings.TrimSpace(addr)
	if strings.HasPrefix(normalized, ":") {
		normalized = "0.0.0.0" + normalized
	}

	_, port, err := net.SplitHostPort(normalized)
	if err != nil {
		return ""
	}

	return port
}
