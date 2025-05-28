//go:build jwt
// +build jwt

package main

import (
	"log/slog"
)

// initJWT initializes the JWT manager with the provided configuration
func initJWT(ctx *Context, cfg *Config) {
	if cfg.Server.JWTDBPath == "" {
		// JWT is not configured, nothing to do
		return
	}

	// Initialize JWT manager
	err := InitJWTManager(cfg)
	if err != nil {
		logger := ctx.Value(loggerKey).(*slog.Logger)
		logger.Error("Failed to initialize JWT manager", "error", err)
	}
}

// closeJWT closes the JWT manager and releases any resources
func closeJWT() {
	CloseJWTManager()
}
