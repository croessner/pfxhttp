package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --- PLAIN mechanism tests ---

func TestPlainMechanismName(t *testing.T) {
	m := &PlainMechanism{}
	if m.Name() != "PLAIN" {
		t.Errorf("Name() = %q, want PLAIN", m.Name())
	}
}

func TestPlainMechanismStartWithInitialResponse(t *testing.T) {
	m := &PlainMechanism{}

	tests := []struct {
		name        string
		data        []byte
		wantCreds   bool
		wantUser    string
		wantPass    string
		wantAuthzID string
		wantFail    bool
		wantCont    bool
	}{
		{
			name:        "Valid PLAIN with authzid",
			data:        []byte("authz\x00user\x00pass"),
			wantCreds:   true,
			wantUser:    "user",
			wantPass:    "pass",
			wantAuthzID: "authz",
		},
		{
			name:      "Valid PLAIN without authzid",
			data:      []byte("\x00user\x00pass"),
			wantCreds: true,
			wantUser:  "user",
			wantPass:  "pass",
		},
		{
			name:     "Empty initial response triggers continuation",
			data:     []byte{},
			wantCont: true,
		},
		{
			name:     "Missing NUL separator",
			data:     []byte("userpass"),
			wantFail: true,
		},
		{
			name:     "Only one NUL",
			data:     []byte("user\x00pass"),
			wantFail: true,
		},
		{
			name:     "Empty username",
			data:     []byte("authz\x00\x00pass"),
			wantFail: true,
		},
		{
			name:     "Empty password",
			data:     []byte("authz\x00user\x00"),
			wantFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, creds := m.Start(tt.data)

			if tt.wantCont {
				if result == nil || !result.NeedContinuation {
					t.Error("Expected continuation")
				}
				return
			}

			if tt.wantFail {
				if result == nil || result.Success {
					t.Error("Expected failure")
				}
				return
			}

			if tt.wantCreds {
				if creds == nil {
					t.Fatal("Expected credentials")
				}
				if creds.Username != tt.wantUser {
					t.Errorf("Username = %q, want %q", creds.Username, tt.wantUser)
				}
				if creds.Password != tt.wantPass {
					t.Errorf("Password = %q, want %q", creds.Password, tt.wantPass)
				}
				if creds.AuthzID != tt.wantAuthzID {
					t.Errorf("AuthzID = %q, want %q", creds.AuthzID, tt.wantAuthzID)
				}
			}
		})
	}
}

func TestPlainMechanismContinue(t *testing.T) {
	m := &PlainMechanism{}

	// Start without initial response
	result, _ := m.Start([]byte{})
	if !result.NeedContinuation {
		t.Fatal("Expected continuation")
	}

	// Continue with valid data
	result, creds := m.Continue([]byte("\x00user\x00secret"))
	if result != nil {
		t.Errorf("Expected nil result, got %+v", result)
	}
	if creds == nil || creds.Username != "user" || creds.Password != "secret" {
		t.Errorf("Invalid credentials: %+v", creds)
	}
}

// --- LOGIN mechanism tests ---

func TestLoginMechanismName(t *testing.T) {
	m := &LoginMechanism{}
	if m.Name() != "LOGIN" {
		t.Errorf("Name() = %q, want LOGIN", m.Name())
	}
}

func TestLoginMechanismFullExchange(t *testing.T) {
	m := &LoginMechanism{}

	// Step 1: Start without initial response -> Username: challenge
	result, creds := m.Start(nil)
	if creds != nil {
		t.Fatal("Should not have credentials yet")
	}
	if !result.NeedContinuation {
		t.Fatal("Expected continuation")
	}
	if string(result.ContinuationChallenge) != "Username:" {
		t.Errorf("Challenge = %q, want Username:", string(result.ContinuationChallenge))
	}

	// Step 2: Send username -> Password: challenge
	result, creds = m.Continue([]byte("testuser"))
	if creds != nil {
		t.Fatal("Should not have credentials yet")
	}
	if !result.NeedContinuation {
		t.Fatal("Expected continuation")
	}
	if string(result.ContinuationChallenge) != "Password:" {
		t.Errorf("Challenge = %q, want Password:", string(result.ContinuationChallenge))
	}

	// Step 3: Send password -> credentials extracted
	result, creds = m.Continue([]byte("testpass"))
	if result != nil {
		t.Errorf("Expected nil result, got %+v", result)
	}
	if creds == nil {
		t.Fatal("Expected credentials")
	}
	if creds.Username != "testuser" {
		t.Errorf("Username = %q, want testuser", creds.Username)
	}
	if creds.Password != "testpass" {
		t.Errorf("Password = %q, want testpass", creds.Password)
	}
}

func TestLoginMechanismWithInitialResponse(t *testing.T) {
	m := &LoginMechanism{}

	// Start with initial response (username) -> Password: challenge
	result, _ := m.Start([]byte("earlyuser"))
	if !result.NeedContinuation {
		t.Fatal("Expected continuation")
	}
	if string(result.ContinuationChallenge) != "Password:" {
		t.Errorf("Challenge = %q, want Password:", string(result.ContinuationChallenge))
	}

	// Send password
	result, creds := m.Continue([]byte("earlypass"))
	if result != nil {
		t.Errorf("Expected nil result, got %+v", result)
	}
	if creds.Username != "earlyuser" || creds.Password != "earlypass" {
		t.Errorf("Creds = %+v", creds)
	}
}

func TestLoginMechanismEmptyCredentials(t *testing.T) {
	m := &LoginMechanism{}

	// Start
	m.Start(nil)
	// Empty username
	m.Continue([]byte(""))
	// Any password with empty username should fail
	result, creds := m.Continue([]byte("pass"))
	if creds != nil {
		t.Error("Expected no credentials with empty username")
	}
	if result == nil || result.Success {
		t.Error("Expected failure")
	}
}

// --- XOAUTH2 mechanism tests ---

func TestXOAuth2MechanismName(t *testing.T) {
	m := &XOAuth2Mechanism{}
	if m.Name() != "XOAUTH2" {
		t.Errorf("Name() = %q, want XOAUTH2", m.Name())
	}
}

func TestXOAuth2MechanismStart(t *testing.T) {
	m := &XOAuth2Mechanism{}

	tests := []struct {
		name      string
		data      []byte
		wantCreds bool
		wantUser  string
		wantToken string
		wantFail  bool
		wantCont  bool
	}{
		{
			name:      "Valid XOAUTH2",
			data:      []byte("user=testuser\x01auth=Bearer mytoken123\x01\x01"),
			wantCreds: true,
			wantUser:  "testuser",
			wantToken: "mytoken123",
		},
		{
			name:      "Case insensitive bearer",
			data:      []byte("user=testuser\x01auth=bearer mytoken\x01\x01"),
			wantCreds: true,
			wantUser:  "testuser",
			wantToken: "mytoken",
		},
		{
			name:     "Empty triggers continuation",
			data:     []byte{},
			wantCont: true,
		},
		{
			name:     "Missing user",
			data:     []byte("auth=Bearer mytoken\x01\x01"),
			wantFail: true,
		},
		{
			name:     "Missing token",
			data:     []byte("user=testuser\x01\x01"),
			wantFail: true,
		},
		{
			name:     "Completely invalid",
			data:     []byte("garbage"),
			wantFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, creds := m.Start(tt.data)

			if tt.wantCont {
				if result == nil || !result.NeedContinuation {
					t.Error("Expected continuation")
				}
				return
			}

			if tt.wantFail {
				if result == nil || result.Success {
					t.Error("Expected failure")
				}
				return
			}

			if tt.wantCreds {
				if creds == nil {
					t.Fatal("Expected credentials")
				}
				if creds.Username != tt.wantUser {
					t.Errorf("Username = %q, want %q", creds.Username, tt.wantUser)
				}
				if creds.Token != tt.wantToken {
					t.Errorf("Token = %q, want %q", creds.Token, tt.wantToken)
				}
			}
		})
	}
}

// --- OAUTHBEARER mechanism tests ---

func TestOAuthBearerMechanismName(t *testing.T) {
	m := &OAuthBearerMechanism{}
	if m.Name() != "OAUTHBEARER" {
		t.Errorf("Name() = %q, want OAUTHBEARER", m.Name())
	}
}

func TestOAuthBearerMechanismStart(t *testing.T) {
	m := &OAuthBearerMechanism{}

	tests := []struct {
		name      string
		data      []byte
		wantCreds bool
		wantUser  string
		wantToken string
		wantFail  bool
		wantCont  bool
	}{
		{
			name:      "Valid OAUTHBEARER with authzid",
			data:      []byte("n,a=user@example.com,\x01auth=Bearer token123\x01\x01"),
			wantCreds: true,
			wantUser:  "user@example.com",
			wantToken: "token123",
		},
		{
			name:      "Valid OAUTHBEARER without authzid",
			data:      []byte("n,,\x01auth=Bearer token456\x01\x01"),
			wantCreds: true,
			wantUser:  "",
			wantToken: "token456",
		},
		{
			name:      "Case insensitive bearer",
			data:      []byte("n,,\x01auth=bearer lowercasetoken\x01\x01"),
			wantCreds: true,
			wantToken: "lowercasetoken",
		},
		{
			name:     "Empty triggers continuation",
			data:     []byte{},
			wantCont: true,
		},
		{
			name:     "Missing GS2 header",
			data:     []byte("auth=Bearer token"),
			wantFail: true,
		},
		{
			name:     "Incomplete GS2 header",
			data:     []byte("n"),
			wantFail: true,
		},
		{
			name:     "Missing bearer token",
			data:     []byte("n,,\x01\x01"),
			wantFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, creds := m.Start(tt.data)

			if tt.wantCont {
				if result == nil || !result.NeedContinuation {
					t.Error("Expected continuation")
				}
				return
			}

			if tt.wantFail {
				if result == nil || result.Success {
					t.Error("Expected failure")
				}
				return
			}

			if tt.wantCreds {
				if creds == nil {
					t.Fatal("Expected credentials")
				}
				if creds.Username != tt.wantUser {
					t.Errorf("Username = %q, want %q", creds.Username, tt.wantUser)
				}
				if creds.Token != tt.wantToken {
					t.Errorf("Token = %q, want %q", creds.Token, tt.wantToken)
				}
			}
		})
	}
}

// --- NewSASLMechanism factory tests ---

func TestNewSASLMechanism(t *testing.T) {
	tests := []struct {
		name     string
		mechName string
		wantNil  bool
		wantType string
	}{
		{name: "PLAIN", mechName: "PLAIN", wantType: "PLAIN"},
		{name: "plain lowercase", mechName: "plain", wantType: "PLAIN"},
		{name: "LOGIN", mechName: "LOGIN", wantType: "LOGIN"},
		{name: "XOAUTH2", mechName: "XOAUTH2", wantType: "XOAUTH2"},
		{name: "OAUTHBEARER", mechName: "OAUTHBEARER", wantType: "OAUTHBEARER"},
		{name: "Unknown", mechName: "UNKNOWN", wantNil: true},
		{name: "Empty", mechName: "", wantNil: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mech := NewSASLMechanism(tt.mechName)
			if tt.wantNil {
				if mech != nil {
					t.Errorf("Expected nil for %q", tt.mechName)
				}
				return
			}
			if mech == nil {
				t.Fatalf("Expected non-nil for %q", tt.mechName)
			}
			if mech.Name() != tt.wantType {
				t.Errorf("Name() = %q, want %q", mech.Name(), tt.wantType)
			}
		})
	}
}

// --- IsOAuthMechanism tests ---

func TestIsOAuthMechanism(t *testing.T) {
	tests := []struct {
		mechanism string
		want      bool
	}{
		{"XOAUTH2", true},
		{"xoauth2", true},
		{"OAUTHBEARER", true},
		{"oauthbearer", true},
		{"PLAIN", false},
		{"LOGIN", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.mechanism, func(t *testing.T) {
			if got := IsOAuthMechanism(tt.mechanism); got != tt.want {
				t.Errorf("IsOAuthMechanism(%q) = %v, want %v", tt.mechanism, got, tt.want)
			}
		})
	}
}

// --- NauthilusSASLAuthenticator tests ---

func TestNauthilusSASLAuthenticatorPassword(t *testing.T) {
	// Mock Nauthilus backend
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]string
		json.NewDecoder(r.Body).Decode(&payload)

		// Check if fields are passed correctly (Nauthilus JSON auth)
		if payload["protocol"] != "smtp" || payload["client_ip"] != "127.0.0.1" || payload["local_ip"] != "10.0.0.1" ||
			payload["client_port"] != "1234" || payload["local_port"] != "25" || payload["ssl"] != "on" ||
			payload["ssl_protocol"] != "TLSv1.3" || payload["ssl_cipher"] != "ECDHE-RSA-AES256-GCM-SHA384" ||
			payload["client_id"] != "client1" || payload["method"] != "PLAIN" {
			w.WriteHeader(http.StatusBadRequest)
			w.Header().Set("Auth-Status", "missing or incorrect context fields")
			json.NewEncoder(w).Encode(map[string]any{
				"error": "missing or incorrect context fields",
			})
			return
		}

		if payload["username"] == "gooduser" && payload["password"] == "goodpass" {
			w.Header().Set("Auth-User", "gooduser")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{
				"username": "gooduser",
				"error":    "none",
			})
		} else {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{
				"error": "authentication failed",
			})
		}
	}))
	defer server.Close()

	// Save and restore global httpClient
	oldClient := httpClient
	httpClient = server.Client()
	defer func() { httpClient = oldClient }()

	cfg := &Config{
		DovecotSASL: map[string]Request{
			"test_sasl": {
				Target:       server.URL,
				StatusCode:   200,
				ValueField:   "username",
				ErrorField:   "error",
				NoErrorValue: "none",
			},
		},
	}

	logger := slog.DiscardHandler
	ctx := context.WithValue(context.Background(), loggerKey, slog.New(logger))

	authenticator := NewNauthilusSASLAuthenticator(cfg, "test_sasl")
	authReq := &DovecotAuthRequest{
		ID:            "1",
		Mechanism:     "PLAIN",
		Service:       "smtp",
		RemoteIP:      "127.0.0.1",
		LocalIP:       "10.0.0.1",
		RemotePort:    "1234",
		LocalPort:     "25",
		Secured:       true,
		LocalName:     "mail.example.com",
		User:          "testuser",
		NoLogin:       true,
		NoPenalty:     true,
		SSLProtocol:   "TLSv1.3",
		SSLCipher:     "ECDHE-RSA-AES256-GCM-SHA384",
		SSLCipherBits: "256",
		SSLPXTID:      "pxt1",
		ClientID:      "client1",
	}

	// Successful auth
	result, err := authenticator.AuthenticatePassword(ctx, "gooduser", "goodpass", authReq)
	if err != nil {
		t.Fatalf("AuthenticatePassword error: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success, got failure: %s", result.Reason)
	}
	if result.Username != "gooduser" {
		t.Errorf("Username = %q, want gooduser", result.Username)
	}

	// Failed auth
	result, err = authenticator.AuthenticatePassword(ctx, "baduser", "badpass", authReq)
	if err != nil {
		t.Fatalf("AuthenticatePassword error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure")
	}
}

func TestNauthilusSASLAuthenticatorTokenIntrospection(t *testing.T) {
	// Mock OIDC + Introspection server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 "http://" + r.Host,
				"token_endpoint":         "http://" + r.Host + "/token",
				"introspection_endpoint": "http://" + r.Host + "/introspect",
			})
		case "/introspect":
			r.ParseForm()
			token := r.FormValue("token")

			// Check context fields
			if r.FormValue("service") != "smtp" || r.FormValue("client_ip") != "127.0.0.1" ||
				r.FormValue("local_ip") != "10.0.0.1" || r.FormValue("client_port") != "1234" ||
				r.FormValue("local_port") != "25" || r.FormValue("secured") != "true" ||
				r.FormValue("local_name") != "mail.example.com" || r.FormValue("user") != "testuser" ||
				r.FormValue("nologin") != "true" || r.FormValue("no_penalty") != "true" || r.FormValue("ssl_protocol") != "TLSv1.3" ||
				r.FormValue("ssl_cipher") != "ECDHE-RSA-AES256-GCM-SHA384" || r.FormValue("ssl_cipher_bits") != "256" ||
				r.FormValue("ssl_pxt_id") != "pxt1" || r.FormValue("client_id") != "client1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if token == "valid-token" {
				json.NewEncoder(w).Encode(map[string]any{
					"active":   true,
					"username": "oauth-user",
					"sub":      "oauth-sub",
				})
			} else {
				json.NewEncoder(w).Encode(map[string]any{
					"active": false,
				})
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Save and restore globals
	oldClient := httpClient
	httpClient = server.Client()
	defer func() { httpClient = oldClient }()

	InitOIDCManager()
	// Override OIDC manager's http client for test server
	oidcManager.httpClient = server.Client()

	cfg := &Config{
		DovecotSASL: map[string]Request{
			"test_oauth": {
				Target:     server.URL,
				StatusCode: 200,
				SASLOIDCAuth: SASLOIDCAuth{
					Enabled:          true,
					ConfigurationURI: server.URL + "/.well-known/openid-configuration",
					ClientID:         "client-id",
					ClientSecret:     "client-secret",
				},
			},
		},
	}

	logger := slog.DiscardHandler
	ctx := context.WithValue(context.Background(), loggerKey, slog.New(logger))

	authenticator := NewNauthilusSASLAuthenticator(cfg, "test_oauth")
	authReq := &DovecotAuthRequest{
		ID:            "1",
		Mechanism:     "XOAUTH2",
		Service:       "smtp",
		RemoteIP:      "127.0.0.1",
		LocalIP:       "10.0.0.1",
		RemotePort:    "1234",
		LocalPort:     "25",
		Secured:       true,
		LocalName:     "mail.example.com",
		User:          "testuser",
		NoLogin:       true,
		NoPenalty:     true,
		SSLProtocol:   "TLSv1.3",
		SSLCipher:     "ECDHE-RSA-AES256-GCM-SHA384",
		SSLCipherBits: "256",
		SSLPXTID:      "pxt1",
		ClientID:      "client1",
	}

	// Valid token
	result, err := authenticator.AuthenticateToken(ctx, "user@example.com", "valid-token", authReq)
	if err != nil {
		t.Fatalf("AuthenticateToken error: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success, got failure: %s", result.Reason)
	}
	// username field should take precedence over sub
	if result.Username != "oauth-user" {
		t.Errorf("Username = %q, want oauth-user", result.Username)
	}

	// Invalid token
	result, err = authenticator.AuthenticateToken(ctx, "user@example.com", "invalid-token", authReq)
	if err != nil {
		t.Fatalf("AuthenticateToken error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for invalid token")
	}
	if result.Reason != "token is not active" {
		t.Errorf("Reason = %q, want 'token is not active'", result.Reason)
	}
}

func TestNauthilusSASLAuthenticatorMissingConfig(t *testing.T) {
	cfg := &Config{
		DovecotSASL: map[string]Request{},
	}

	logger := slog.DiscardHandler
	ctx := context.WithValue(context.Background(), loggerKey, slog.New(logger))

	authenticator := NewNauthilusSASLAuthenticator(cfg, "nonexistent")
	authReq := &DovecotAuthRequest{ID: "1", Mechanism: "PLAIN", Service: "smtp"}

	_, err := authenticator.AuthenticatePassword(ctx, "user", "pass", authReq)
	if err == nil {
		t.Error("Expected error for missing config")
	}

	_, err = authenticator.AuthenticateToken(ctx, "user", "token", authReq)
	if err == nil {
		t.Error("Expected error for missing config")
	}
}

func TestNauthilusSASLAuthenticatorOAuthNotConfigured(t *testing.T) {
	cfg := &Config{
		DovecotSASL: map[string]Request{
			"no_oauth": {
				Target:     "http://localhost",
				StatusCode: 200,
				SASLOIDCAuth: SASLOIDCAuth{
					Enabled: false,
				},
			},
		},
	}

	logger := slog.DiscardHandler
	ctx := context.WithValue(context.Background(), loggerKey, slog.New(logger))

	authenticator := NewNauthilusSASLAuthenticator(cfg, "no_oauth")
	authReq := &DovecotAuthRequest{ID: "1", Mechanism: "XOAUTH2", Service: "smtp"}

	result, err := authenticator.AuthenticateToken(ctx, "user", "token", authReq)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure when OAuth not configured")
	}
	if result.Reason != "OAuth not configured" {
		t.Errorf("Reason = %q, want 'OAuth not configured'", result.Reason)
	}
}

func TestNauthilusSASLAuthenticatorTokenJWKS(t *testing.T) {
	// Generate RSA key and JWT
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	claims := jwt.MapClaims{
		"sub":                "jwks-sub",
		"preferred_username": "jwks-user",
		"exp":                time.Now().Add(1 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-key"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	// Build JWKS
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	eBytes := big.NewInt(int64(priv.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":         "http://" + r.Host,
				"jwks_uri":       "http://" + r.Host + "/jwks",
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/jwks":
			json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]string{{
					"kty": "RSA", "kid": "test-key", "use": "sig", "alg": "RS256",
					"n": n, "e": e,
				}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Override clients
	oldClient := httpClient
	httpClient = server.Client()
	defer func() { httpClient = oldClient }()
	InitOIDCManager()
	oidcManager.httpClient = server.Client()

	cfg := &Config{DovecotSASL: map[string]Request{
		"jwks": {
			Target:     server.URL,
			StatusCode: 200,
			SASLOIDCAuth: SASLOIDCAuth{
				Enabled:          true,
				ConfigurationURI: server.URL + "/.well-known/openid-configuration",
				ClientID:         "client-id",
				Validation:       "jwks",
			},
		},
	}}

	ctx := context.WithValue(context.Background(), loggerKey, slog.New(slog.DiscardHandler))
	auth := NewNauthilusSASLAuthenticator(cfg, "jwks")
	res, err := auth.AuthenticateToken(ctx, "ignored", signed, &DovecotAuthRequest{Mechanism: "XOAUTH2", Service: "smtp"})
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got failure: %v", res.Reason)
	}
	if res.Username != "jwks-user" {
		t.Fatalf("username = %q, want jwks-user", res.Username)
	}
}

func TestNauthilusSASLAuthenticatorTokenAutoFallbackToIntrospection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 "http://" + r.Host,
				"introspection_endpoint": "http://" + r.Host + "/introspect",
				"jwks_uri":               "http://" + r.Host + "/jwks",
			})
		case "/introspect":
			_ = r.ParseForm()
			if r.FormValue("token") == "opaque" {
				json.NewEncoder(w).Encode(map[string]any{"active": true, "username": "opaque-user"})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"active": false})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	oldClient := httpClient
	httpClient = server.Client()
	defer func() { httpClient = oldClient }()
	InitOIDCManager()
	oidcManager.httpClient = server.Client()

	cfg := &Config{DovecotSASL: map[string]Request{
		"auto": {
			Target:     server.URL,
			StatusCode: 200,
			SASLOIDCAuth: SASLOIDCAuth{
				Enabled:          true,
				ConfigurationURI: server.URL + "/.well-known/openid-configuration",
				ClientID:         "client-id",
				Validation:       "auto",
			},
		},
	}}
	ctx := context.WithValue(context.Background(), loggerKey, slog.New(slog.DiscardHandler))
	auth := NewNauthilusSASLAuthenticator(cfg, "auto")
	res, err := auth.AuthenticateToken(ctx, "ignored", "opaque", &DovecotAuthRequest{Mechanism: "XOAUTH2", Service: "smtp"})
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got failure: %v", res.Reason)
	}
	if res.Username != "opaque-user" {
		t.Fatalf("username = %q, want opaque-user", res.Username)
	}
}
