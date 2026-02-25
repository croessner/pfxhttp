package main

import (
	"log/slog"
	"net/http"
	"sync"
)

// Deps bundles all shared application dependencies for injection via UberFX.
// Fields are protected by mu for safe concurrent access during reload.
type Deps struct {
	mu          sync.RWMutex
	Config      *Config
	Logger      *slog.Logger
	HTTPClient  *http.Client
	OIDCManager *OIDCManager
	RespCache   ResponseCache
}

// GetConfig returns the current Config in a thread-safe manner.
func (d *Deps) GetConfig() *Config {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.Config
}

// GetLogger returns the current Logger in a thread-safe manner.
func (d *Deps) GetLogger() *slog.Logger {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.Logger
}

// GetHTTPClient returns the current HTTP client in a thread-safe manner.
func (d *Deps) GetHTTPClient() *http.Client {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.HTTPClient
}

// GetOIDCManager returns the OIDC manager.
func (d *Deps) GetOIDCManager() *OIDCManager {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.OIDCManager
}

// GetRespCache returns the current response cache in a thread-safe manner.
func (d *Deps) GetRespCache() ResponseCache {
	d.mu.RLock()
	defer d.mu.RUnlock()

	return d.RespCache
}

// Reload updates all mutable dependencies atomically under a write lock.
func (d *Deps) Reload(cfg *Config, logger *slog.Logger, httpClient *http.Client, respCache ResponseCache) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.Config = cfg
	d.Logger = logger
	d.HTTPClient = httpClient
	d.RespCache = respCache
}
