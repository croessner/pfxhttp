package main

import (
	"log/slog"
	"net/http"
)

// Deps bundles all shared application dependencies for injection via UberFX.
type Deps struct {
	Config      *Config
	Logger      *slog.Logger
	HTTPClient  *http.Client
	OIDCManager *OIDCManager
	RespCache   ResponseCache
}
