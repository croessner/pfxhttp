package main

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"reflect"
	"sync"
)

// listenKey returns a unique identifier for a listener based on its network endpoint.
func listenKey(l Listen) string {
	if l.Type == listenTypeUnix {
		return fmt.Sprintf("%s://%s", l.Type, l.Address)
	}

	return fmt.Sprintf("%s://%s:%d", l.Type, l.Address, l.Port)
}

// ListenerEntry tracks a running listener along with its configuration snapshot.
type ListenerEntry struct {
	Config    Listen
	Server    GenericServer
	Handler   func(conn net.Conn)
	Cancel    context.CancelFunc
	Done      chan struct{}
	Activated bool
}

// ListenerRegistry manages active listeners and supports diffing on reload.
type ListenerRegistry struct {
	mu      sync.Mutex
	entries map[string]*ListenerEntry
}

// NewListenerRegistry creates a new empty registry.
func NewListenerRegistry() *ListenerRegistry {
	return &ListenerRegistry{
		entries: make(map[string]*ListenerEntry),
	}
}

// DiffResult contains the result of comparing old and new listener configurations.
type DiffResult struct {
	Added     []Listen
	Removed   []string
	Changed   []Listen
	Unchanged []string
}

// Diff compares the current registry state with a new set of listener configs.
func (r *ListenerRegistry) Diff(newListeners []Listen) DiffResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	var result DiffResult

	newByKey := make(map[string]Listen, len(newListeners))
	for _, l := range newListeners {
		newByKey[listenKey(l)] = l
	}

	for key, entry := range r.entries {
		newCfg, exists := newByKey[key]
		if !exists {
			result.Removed = append(result.Removed, key)
		} else if !listenersSemanticallyEqual(entry.Config, newCfg) {
			result.Changed = append(result.Changed, newCfg)
		} else {
			result.Unchanged = append(result.Unchanged, key)
		}
	}

	for key, cfg := range newByKey {
		if _, exists := r.entries[key]; !exists {
			result.Added = append(result.Added, cfg)
		}
	}

	return result
}

func listenersSemanticallyEqual(current, next Listen) bool {
	current.ProtocolLimits = relevantProtocolLimits(current.Kind, current.ProtocolLimits)
	next.ProtocolLimits = relevantProtocolLimits(next.Kind, next.ProtocolLimits)

	return reflect.DeepEqual(current, next)
}

func relevantProtocolLimits(kind string, limits ProtocolLimitsConfig) ProtocolLimitsConfig {
	switch kind {
	case listenKindSocketMap:
		return ProtocolLimitsConfig{SocketMap: limits.SocketMap}
	case listenKindPolicyService:
		return ProtocolLimitsConfig{PolicyService: limits.PolicyService}
	case listenKindDovecotSASL:
		return ProtocolLimitsConfig{DovecotSASL: limits.DovecotSASL}
	default:
		return limits
	}
}

// Register adds a listener entry to the registry.
func (r *ListenerRegistry) Register(l Listen, entry *ListenerEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.entries[listenKey(l)] = entry
}

// DiffTouchesSystemdSockets reports whether a reload diff changes any systemd-activated listener.
func (r *ListenerRegistry) DiffTouchesSystemdSockets(diff DiffResult) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, key := range diff.Removed {
		if entry, ok := r.entries[key]; ok && entry.Config.SystemdSocketName != "" {
			return true
		}
	}

	for _, cfg := range diff.Changed {
		if cfg.SystemdSocketName != "" {
			return true
		}

		if entry, ok := r.entries[listenKey(cfg)]; ok && entry.Config.SystemdSocketName != "" {
			return true
		}
	}

	for _, cfg := range diff.Added {
		if cfg.SystemdSocketName != "" {
			return true
		}
	}

	return false
}

// Remove stops and removes a listener entry by key.
func (r *ListenerRegistry) Remove(key string) {
	r.mu.Lock()
	entry, ok := r.entries[key]
	if ok {
		delete(r.entries, key)
	}
	r.mu.Unlock()

	if ok && entry != nil {
		entry.Cancel()
		entry.Server.Stop()
		<-entry.Done
	}
}

// StopAll stops all registered listeners and clears the registry.
func (r *ListenerRegistry) StopAll() {
	r.mu.Lock()
	entries := make(map[string]*ListenerEntry, len(r.entries))
	maps.Copy(entries, r.entries)
	clear(r.entries)
	r.mu.Unlock()

	for _, entry := range entries {
		entry.Cancel()
		entry.Server.Stop()
		<-entry.Done
	}
}

// startListener creates and starts a single listener, registering it in the registry.
func (r *ListenerRegistry) startListener(
	parentCtx context.Context,
	deps *Deps,
	instance Listen,
	systemdSockets *SystemdSocketSet,
	logger *slog.Logger,
) error {
	listenerCtx, listenerCancel := context.WithCancel(parentCtx)

	activatedListener, activated, err := systemdSockets.ClaimListener(instance)
	if err != nil {
		listenerCancel()

		return err
	}

	supervisor := NewConnectionSupervisor(listenerCtx, instance.Limits.MaxConnections)

	srv := NewMultiServer(listenerCtx, deps, supervisor)
	if err := srv.Listen(instance, activatedListener); err != nil {
		if activatedListener != nil {
			_ = activatedListener.Close()
		}
		listenerCancel()
		supervisor.Stop()

		return fmt.Errorf("failed to listen %s: %w", listenKey(instance), err)
	}

	var handler func(conn net.Conn)

	switch instance.Kind {
	case listenKindSocketMap:
		handler = srv.HandleNetStringConnection
	case listenKindPolicyService:
		if instance.Name == "" {
			listenerCancel()
			srv.Stop()

			return fmt.Errorf("policy service requires a name")
		}

		handler = srv.HandlePolicyServiceConnection
	case listenKindDovecotSASL:
		if instance.Name == "" {
			listenerCancel()
			srv.Stop()

			return fmt.Errorf("dovecot SASL requires a name")
		}

		handler = srv.HandleDovecotSASLConnection
	default:
		listenerCancel()
		srv.Stop()

		return fmt.Errorf("invalid listen kind: %s", instance.Kind)
	}

	done := make(chan struct{})

	entry := &ListenerEntry{
		Config:    instance,
		Server:    srv,
		Handler:   handler,
		Cancel:    listenerCancel,
		Done:      done,
		Activated: activated,
	}

	r.Register(instance, entry)

	go func() {
		defer close(done)

		go func() {
			<-listenerCtx.Done()
			srv.Stop()
		}()

		if err := srv.Start(handler); err != nil {
			logger.Error("Server error", slog.String("listener", listenKey(instance)), slog.String("reason", boundedErrorKind(err)))
		}
	}()

	return nil
}
