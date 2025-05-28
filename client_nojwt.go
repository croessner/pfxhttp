//go:build !jwt
// +build !jwt

package main

import (
	"net/http"
)

// addJWTAuth is a no-op when JWT support is disabled
func addJWTAuth(req *http.Request, requestName string, jwtAuth JWTAuth) (bool, string, error) {
	// JWT support is disabled, nothing to do
	return false, "", nil
}
