//go:build jwt
// +build jwt

package main

import (
	"net/http"
)

// addJWTAuth adds JWT authentication to the request if enabled
func addJWTAuth(req *http.Request, requestName string, jwtAuth JWTAuth) (bool, string, error) {
	if !jwtAuth.Enabled {
		return false, "", nil
	}

	token, err := GetJWTToken(requestName, jwtAuth)
	if err != nil {
		return true, "JWT authentication failed: " + err.Error(), err
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return false, "", nil
}
