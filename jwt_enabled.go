//go:build jwt
// +build jwt

package main

import (
	"log/slog"
)

// initJWT initializes the JWT manager with the provided configuration
func initJWT(ctx *Context, cfg *Config) {
	logger := ctx.Value(loggerKey).(*slog.Logger)

	if cfg.Server.JWTDBPath == "" {
		// JWT is not configured, nothing to do
		logger.Info("JWT support is enabled but not configured (jwt_db_path is empty)")

		return
	}

	logger.Info("JWT support is enabled and configured")

	// Initialize JWT manager
	err := InitJWTManager(cfg)
	if err != nil {
		logger.Error("Failed to initialize JWT manager", "error", err)
	}
}

// closeJWT closes the JWT manager and releases any resources
func closeJWT() {
	CloseJWTManager()
}
