package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestOIDCManager(t *testing.T) {
	// Mock OIDC Server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			resp := OIDCDiscoveryResponse{
				Issuer:        "http://" + r.Host,
				TokenEndpoint: "http://" + r.Host + "/token",
			}
			json.NewEncoder(w).Encode(resp)
		case "/token":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			r.ParseForm()
			if r.FormValue("grant_type") != "client_credentials" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Simple check for client_secret_basic
			user, pass, ok := r.BasicAuth()
			if !ok || user != "client-id" || pass != "client-secret" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			resp := OIDCTokenResponse{
				AccessToken: "mock-token",
				TokenType:   "Bearer",
				ExpiresIn:   3600,
			}
			json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	InitializeHttpClient(&Config{})
	InitOIDCManager()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.WithValue(context.Background(), loggerKey, logger)

	auth := OIDCAuth{
		Enabled:          true,
		ConfigurationURI: server.URL + "/.well-known/openid-configuration",
		ClientID:         "client-id",
		ClientSecret:     "client-secret",
	}

	// First call should fetch from server
	token, err := oidcManager.GetToken(ctx, logger, auth)
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token != "mock-token" {
		t.Errorf("Expected token 'mock-token', got '%s'", token)
	}

	// Second call should come from cache
	token2, err := oidcManager.GetToken(ctx, logger, auth)
	if err != nil {
		t.Fatalf("Failed to get token again: %v", err)
	}
	if token2 != "mock-token" {
		t.Errorf("Expected token 'mock-token', got '%s'", token2)
	}

	// Check if addOIDCAuth works
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://example.com", nil)
	ok, _, err := addOIDCAuth(req, "test-request", auth)
	if err != nil {
		t.Fatalf("addOIDCAuth failed: %v", err)
	}
	if !ok {
		t.Error("addOIDCAuth should have returned true")
	}
	if req.Header.Get("Authorization") != "Bearer mock-token" {
		t.Errorf("Expected Authorization header 'Bearer mock-token', got '%s'", req.Header.Get("Authorization"))
	}
}

func TestOIDCManagerExpiration(t *testing.T) {
	tokenCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			resp := OIDCDiscoveryResponse{
				TokenEndpoint: "http://" + r.Host + "/token",
			}
			json.NewEncoder(w).Encode(resp)
		case "/token":
			tokenCount++
			resp := OIDCTokenResponse{
				AccessToken: "token-" + string(rune('0'+tokenCount)),
				ExpiresIn:   1, // Very short expiration
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	InitializeHttpClient(&Config{})
	InitOIDCManager()
	logger := slog.New(slog.DiscardHandler)
	ctx := context.WithValue(context.Background(), loggerKey, logger)

	auth := OIDCAuth{
		Enabled:          true,
		ConfigurationURI: server.URL + "/.well-known/openid-configuration",
		ClientID:         "client-id",
	}

	token, _ := oidcManager.GetToken(ctx, logger, auth)
	if token != "token-1" {
		t.Errorf("Expected token-1, got %s", token)
	}

	// Manually expire the token in cache
	oidcManager.mu.Lock()
	key := server.URL + "/.well-known/openid-configuration|client-id"
	oidcManager.tokens[key].ExpiresAt = time.Now().Add(-1 * time.Minute)
	oidcManager.mu.Unlock()

	token2, _ := oidcManager.GetToken(ctx, logger, auth)
	if token2 != "token-2" {
		t.Errorf("Expected token-2, got %s", token2)
	}
}
