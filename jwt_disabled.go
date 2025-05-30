//go:build !jwt
// +build !jwt

package main

import (
	"log/slog"
)

// initJWT is a no-op when JWT support is disabled
func initJWT(ctx *Context, cfg *Config) {
	// JWT support is disabled, nothing to do
	logger := ctx.Value(loggerKey).(*slog.Logger)
	logger.Info("JWT support is disabled (not compiled in)")
}

// closeJWT is a no-op when JWT support is disabled
func closeJWT() {
	// JWT support is disabled, nothing to do
}

// GetJWTToken is a stub implementation when JWT support is disabled
func GetJWTToken(requestName string, jwtAuth JWTAuth) (string, error) {
	// JWT support is disabled, return empty token
	return "", nil
}
