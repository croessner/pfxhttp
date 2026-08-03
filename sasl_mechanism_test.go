package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSASLHTTPRequestLogOmitsURLAndHeaderValues(t *testing.T) {
	const secret = "synthetic-secret-value"

	request, err := http.NewRequest(http.MethodPost, "https://user:"+secret+"@example.test/auth?token="+secret, nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	request.Header.Set("X-Api-Key", secret)

	var output bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logSASLHTTPRequest(logger, "Outgoing request", request)

	if strings.Contains(output.String(), secret) || strings.Contains(output.String(), "example.test") {
		t.Fatalf("request log exposes URL or header value: %s", output.String())
	}

	for _, expected := range []string{"method=POST", "header_count=1"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("request log %q does not contain %q", output.String(), expected)
		}
	}
}

const (
	testPrivateKeyIntrospectionClientID = "pfxhttp-introspection"
	testPrivateKeyIntrospectionEntry    = "private_key"
	testPrivateKeyIntrospectionUser     = "private-key-user"
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
		{name: saslMechanismExternal, mechName: saslMechanismExternal, wantType: saslMechanismExternal},
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
		{saslMechanismExternal, false},
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
			payload["client_port"] != "1234" || payload["local_port"] != "25" || payload["ssl"] != saslTLSOn ||
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

	testClient := server.Client()
	mgr := NewOIDCManager(testClient)

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

	authenticator := NewNauthilusSASLAuthenticator(cfg, "test_sasl", testClient, mgr)
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

func TestNauthilusSASLAuthenticatorLookupIdentityUsesNoAuthMode(t *testing.T) { //nolint:gocyclo // One HTTP contract assertion.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("mode"); got != nauthilusNoAuthMode {
			t.Errorf("mode = %q, want no-auth", got)
		}

		if got := r.URL.Query().Get("existing"); got != testValueField {
			t.Errorf("existing query value = %q, want value", got)
		}

		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if _, exists := payload["password"]; exists {
			t.Error("LookupIdentity request contained password field")
		}

		if payload["username"] != testCertificateIdentity ||
			payload["method"] != saslMechanismExternal ||
			payload["ssl_client_verify"] != tlsClientVerifySuccess ||
			payload["ssl_fingerprint"] != testSHA256Fingerprint {
			t.Errorf("lookup payload = %#v", payload)
		}

		w.Header().Set("Auth-User", testCanonicalIdentity)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &Config{DovecotSASL: map[string]Request{
		testExternalEntry: {Target: server.URL + "?existing=" + testValueField, StatusCode: http.StatusOK},
	}}
	authenticator := NewNauthilusSASLAuthenticator(cfg, testExternalEntry, server.Client(), nil)

	result, err := authenticator.LookupIdentity(t.Context(), testCertificateIdentity, &DovecotAuthRequest{
		Service:              "smtp",
		Mechanism:            saslMechanismExternal,
		Secured:              true,
		SSLClientVerify:      tlsClientVerifySuccess,
		SSLClientFingerprint: testSHA256Fingerprint,
		SSLClientSANEmail:    testCertificateIdentity,
	})
	if err != nil {
		t.Fatalf("LookupIdentity returned error: %v", err)
	}

	if result == nil || !result.Success || result.Username != testCanonicalIdentity {
		t.Fatalf("LookupIdentity result = %+v", result)
	}
}

func TestHTTPIdentityLookupStatusClassification(t *testing.T) {
	const identityDeniedStatus = "identity denied"

	authenticator := &NauthilusSASLAuthenticator{config: &Config{}}
	settings := Request{StatusCode: http.StatusOK}

	tests := []struct {
		name      string
		status    int
		authStatus string
		lookup    bool
		temporary bool
	}{
		{name: "lookup caller unauthorized", status: http.StatusUnauthorized, lookup: true, temporary: true},
		{name: "lookup caller forbidden", status: http.StatusForbidden, lookup: true, temporary: true},
		{name: "lookup domain forbidden", status: http.StatusForbidden, authStatus: identityDeniedStatus, lookup: true},
		{name: "lookup domain unauthorized", status: http.StatusUnauthorized, authStatus: identityDeniedStatus, lookup: true},
		{name: "lookup request timeout", status: http.StatusRequestTimeout, lookup: true, temporary: true},
		{name: "lookup too early", status: http.StatusTooEarly, lookup: true, temporary: true},
		{name: "lookup rate limited", status: http.StatusTooManyRequests, lookup: true, temporary: true},
		{name: "lookup backend unavailable", status: http.StatusServiceUnavailable, lookup: true, temporary: true},
		{name: "lookup malformed request", status: http.StatusBadRequest, lookup: true},
		{name: "password unauthorized remains credential failure", status: http.StatusUnauthorized},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := &http.Response{StatusCode: test.status, Header: make(http.Header)}
			if test.authStatus != "" {
				response.Header.Set("Auth-Status", test.authStatus)
			}

			result, err := authenticator.handleSASLResponse(
				response,
				settings,
				test.lookup,
			)
			if err != nil {
				t.Fatalf("handleSASLResponse returned error: %v", err)
			}

			if result.Success || result.Temporary != test.temporary {
				t.Fatalf("result = %+v, want temporary=%v", result, test.temporary)
			}
		})
	}
}

func TestHTTPIdentityLookupRejectsUnsafeCanonicalAccount(t *testing.T) {
	authenticator := &NauthilusSASLAuthenticator{config: &Config{}}
	settings := Request{StatusCode: http.StatusOK}

	for _, username := range []string{
		" " + testCanonicalIdentity,
		testCanonicalIdentity + " ",
		testCanonicalIdentity + "\tuser=attacker",
		testCanonicalIdentity + "\rFAIL",
		testCanonicalIdentity + "\nFAIL",
		testCanonicalIdentity + "\x00suffix",
	} {
		response := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
		response.Header["Auth-User"] = []string{username}

		result, err := authenticator.handleSASLResponse(
			response,
			settings,
			true,
		)
		if err != nil {
			t.Fatalf("handleSASLResponse(%q) returned error: %v", username, err)
		}

		if result.Success || !result.Temporary || result.Reason != invalidCanonicalAccountReason {
			t.Fatalf("handleSASLResponse(%q) = %+v", username, result)
		}
	}

	notFound := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}
	notFound.Header.Set("Auth-Status", identityNotFoundReason)

	result, err := authenticator.handleSASLResponse(
		notFound,
		settings,
		true,
	)
	if err != nil {
		t.Fatalf("not-found response returned error: %v", err)
	}

	if result.Success || result.Temporary || result.Reason != identityNotFoundReason {
		t.Fatalf("not-found result = %+v", result)
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

	testClient := server.Client()
	mgr := NewOIDCManager(testClient)

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

	authenticator := NewNauthilusSASLAuthenticator(cfg, "test_oauth", testClient, mgr)
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

func TestNauthilusSASLAuthenticatorTokenIntrospectionPrivateKeyJWT(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	keyFile := writeRSAPrivateKeyFile(t, priv)

	requests := make(chan privateKeyIntrospectionRequest, 1)

	server := newPrivateKeyIntrospectionServer(t, requests)
	defer server.Close()

	testClient := server.Client()
	mgr := NewOIDCManager(testClient)
	cfg := newPrivateKeyIntrospectionConfig(server.URL, keyFile)

	ctx := context.WithValue(t.Context(), loggerKey, slog.New(slog.DiscardHandler))
	authenticator := NewNauthilusSASLAuthenticator(cfg, testPrivateKeyIntrospectionEntry, testClient, mgr)

	result, err := authenticator.AuthenticateToken(ctx, "user@example.com", "valid-token", &DovecotAuthRequest{Mechanism: "XOAUTH2", Service: "smtp"})

	assertPrivateKeyIntrospectionResult(t, result, err)

	got := readPrivateKeyIntrospectionRequest(t, requests)
	assertPrivateKeyIntrospectionRequest(t, got)
	assertPrivateKeyClientAssertion(t, got.clientAssertion, server.URL+"/introspect", &priv.PublicKey)
}

type privateKeyIntrospectionRequest struct {
	authorization       string
	clientID            string
	clientAssertionType string
	clientAssertion     string
}

func newPrivateKeyIntrospectionServer(t *testing.T, requests chan<- privateKeyIntrospectionRequest) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeSASLTestJSON(t, w, map[string]string{
				"issuer":                 "http://" + r.Host,
				"introspection_endpoint": "http://" + r.Host + "/introspect",
			})
		case "/introspect":
			recordPrivateKeyIntrospectionRequest(requests, r)
			writeSASLTestJSON(t, w, map[string]any{
				"active":   true,
				"username": testPrivateKeyIntrospectionUser,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func recordPrivateKeyIntrospectionRequest(requests chan<- privateKeyIntrospectionRequest, r *http.Request) {
	_ = r.ParseForm()
	requests <- privateKeyIntrospectionRequest{
		authorization:       r.Header.Get("Authorization"),
		clientID:            r.FormValue("client_id"),
		clientAssertionType: r.FormValue("client_assertion_type"),
		clientAssertion:     r.FormValue("client_assertion"),
	}
}

func writeSASLTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()

	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode SASL test response: %v", err)
	}
}

func newPrivateKeyIntrospectionConfig(serverURL, keyFile string) *Config {
	return &Config{
		DovecotSASL: map[string]Request{
			testPrivateKeyIntrospectionEntry: {
				Target:     serverURL,
				StatusCode: 200,
				SASLOIDCAuth: SASLOIDCAuth{
					Enabled:          true,
					ConfigurationURI: serverURL + "/.well-known/openid-configuration",
					ClientID:         testPrivateKeyIntrospectionClientID,
					PrivateKeyFile:   keyFile,
					AuthMethod:       oidcAuthMethodPrivateKeyJWT,
				},
			},
		},
	}
}

func assertPrivateKeyIntrospectionResult(t *testing.T, result *SASLAuthResult, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("AuthenticateToken error: %v", err)
	}

	if !result.Success {
		t.Fatalf("expected success, got failure: %s", result.Reason)
	}

	if result.Username != testPrivateKeyIntrospectionUser {
		t.Fatalf("Username = %q, want %s", result.Username, testPrivateKeyIntrospectionUser)
	}
}

func readPrivateKeyIntrospectionRequest(t *testing.T, requests <-chan privateKeyIntrospectionRequest) privateKeyIntrospectionRequest {
	t.Helper()

	select {
	case got := <-requests:
		return got
	case <-time.After(time.Second):
		t.Fatal("introspection endpoint was not called")
	}

	return privateKeyIntrospectionRequest{}
}

func assertPrivateKeyIntrospectionRequest(t *testing.T, got privateKeyIntrospectionRequest) {
	t.Helper()

	if got.authorization != "" {
		t.Fatalf("Authorization header = %q, want empty", got.authorization)
	}

	if got.clientID != testPrivateKeyIntrospectionClientID {
		t.Fatalf("client_id = %q, want %q", got.clientID, testPrivateKeyIntrospectionClientID)
	}

	if got.clientAssertionType != oidcClientAssertionTypeJWT {
		t.Fatalf("client_assertion_type = %q", got.clientAssertionType)
	}

	if got.clientAssertion == "" {
		t.Fatal("client_assertion must be set")
	}
}

func assertPrivateKeyClientAssertion(t *testing.T, assertion, audience string, publicKey *rsa.PublicKey) {
	t.Helper()

	claims := jwt.MapClaims{}

	parsed, err := jwt.ParseWithClaims(assertion, claims, func(_ *jwt.Token) (any, error) {
		return publicKey, nil
	})
	if err != nil {
		t.Fatalf("parse client_assertion: %v", err)
	}

	if !parsed.Valid {
		t.Fatal("client_assertion is not valid")
	}

	if parsed.Method.Alg() != jwt.SigningMethodRS256.Alg() {
		t.Fatalf("client_assertion alg = %q, want RS256", parsed.Method.Alg())
	}

	if claims["iss"] != testPrivateKeyIntrospectionClientID || claims["sub"] != testPrivateKeyIntrospectionClientID {
		t.Fatalf("client_assertion iss/sub = %v/%v, want %s", claims["iss"], claims["sub"], testPrivateKeyIntrospectionClientID)
	}

	if claims["aud"] != audience {
		t.Fatalf("client_assertion aud = %v, want %s", claims["aud"], audience)
	}

	if claims["jti"] == "" {
		t.Fatal("client_assertion jti must be set")
	}
}

func writeRSAPrivateKeyFile(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()

	keyFile := t.TempDir() + "/client.key"

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  testRSAPrivateKeyBlock,
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}

	return keyFile
}

func TestNauthilusSASLAuthenticatorMissingConfig(t *testing.T) {
	cfg := &Config{
		DovecotSASL: map[string]Request{},
	}

	logger := slog.DiscardHandler
	ctx := context.WithValue(context.Background(), loggerKey, slog.New(logger))

	authenticator := NewNauthilusSASLAuthenticator(cfg, "nonexistent", &http.Client{}, nil)
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

	authenticator := NewNauthilusSASLAuthenticator(cfg, "no_oauth", &http.Client{}, nil)
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

	testClient := server.Client()
	mgr := NewOIDCManager(testClient)

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
	auth := NewNauthilusSASLAuthenticator(cfg, "jwks", testClient, mgr)
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

	testClient := server.Client()
	mgr := NewOIDCManager(testClient)

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
	auth := NewNauthilusSASLAuthenticator(cfg, "auto", testClient, mgr)
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

func TestNauthilusSASLAuthenticatorTokenIntrospectionAccountField(t *testing.T) {
	// Mock OIDC + Introspection server that returns a custom account field
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 "http://" + r.Host,
				"token_endpoint":         "http://" + r.Host + "/token",
				"introspection_endpoint": "http://" + r.Host + "/introspect",
			})
		case "/introspect":
			_ = r.ParseForm()
			token := r.FormValue("token")
			if token == "valid-token" {
				json.NewEncoder(w).Encode(map[string]any{
					"active":          true,
					"username":        "should-be-ignored",
					"sub":             "also-ignored",
					"dovecot_account": "custom@example.com",
				})
			} else {
				json.NewEncoder(w).Encode(map[string]any{"active": false})
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	testClient := server.Client()
	mgr := NewOIDCManager(testClient)

	cfg := &Config{
		DovecotSASL: map[string]Request{
			"test_af": {
				Target:     server.URL,
				StatusCode: 200,
				SASLOIDCAuth: SASLOIDCAuth{
					Enabled:          true,
					ConfigurationURI: server.URL + "/.well-known/openid-configuration",
					ClientID:         "client-id",
					ClientSecret:     "client-secret",
					AccountClaim:     "dovecot_account",
				},
			},
		},
	}

	ctx := context.WithValue(t.Context(), loggerKey, slog.New(slog.DiscardHandler))
	authenticator := NewNauthilusSASLAuthenticator(cfg, "test_af", testClient, mgr)
	authReq := &DovecotAuthRequest{Mechanism: "XOAUTH2", Service: "smtp"}

	// Valid token with account_field configured
	result, err := authenticator.AuthenticateToken(ctx, "user@example.com", "valid-token", authReq)
	if err != nil {
		t.Fatalf("AuthenticateToken error: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success, got failure: %s", result.Reason)
	}
	if result.Username != "custom@example.com" {
		t.Errorf("Username = %q, want custom@example.com", result.Username)
	}
}

func TestNauthilusSASLAuthenticatorTokenIntrospectionAccountFieldMissing(t *testing.T) {
	// When account_field is configured but not present in response, fallback to original username
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 "http://" + r.Host,
				"token_endpoint":         "http://" + r.Host + "/token",
				"introspection_endpoint": "http://" + r.Host + "/introspect",
			})
		case "/introspect":
			json.NewEncoder(w).Encode(map[string]any{
				"active":   true,
				"username": "introspection-user",
				"sub":      "introspection-sub",
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	testClient := server.Client()
	mgr := NewOIDCManager(testClient)

	cfg := &Config{
		DovecotSASL: map[string]Request{
			"test_af_missing": {
				Target:     server.URL,
				StatusCode: 200,
				SASLOIDCAuth: SASLOIDCAuth{
					Enabled:          true,
					ConfigurationURI: server.URL + "/.well-known/openid-configuration",
					ClientID:         "client-id",
					ClientSecret:     "client-secret",
					AccountClaim:     "nonexistent_field",
				},
			},
		},
	}

	ctx := context.WithValue(t.Context(), loggerKey, slog.New(slog.DiscardHandler))
	authenticator := NewNauthilusSASLAuthenticator(cfg, "test_af_missing", testClient, mgr)
	authReq := &DovecotAuthRequest{Mechanism: "XOAUTH2", Service: "smtp"}

	result, err := authenticator.AuthenticateToken(ctx, "original@example.com", "any-token", authReq)
	if err != nil {
		t.Fatalf("AuthenticateToken error: %v", err)
	}
	if !result.Success {
		t.Errorf("Expected success, got failure: %s", result.Reason)
	}
	// Should keep original username since configured field is not in the response
	if result.Username != "original@example.com" {
		t.Errorf("Username = %q, want original@example.com", result.Username)
	}
}

func TestNauthilusSASLAuthenticatorTokenJWKSAccountField(t *testing.T) {
	// Generate RSA key and JWT with a custom account field
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	claims := jwt.MapClaims{
		"sub":                "jwks-sub",
		"preferred_username": "jwks-user",
		"dovecot_account":    "custom-jwks@example.com",
		"exp":                time.Now().Add(1 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-key"
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

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

	testClient := server.Client()
	mgr := NewOIDCManager(testClient)

	cfg := &Config{DovecotSASL: map[string]Request{
		"jwks_af": {
			Target:     server.URL,
			StatusCode: 200,
			SASLOIDCAuth: SASLOIDCAuth{
				Enabled:          true,
				ConfigurationURI: server.URL + "/.well-known/openid-configuration",
				ClientID:         "client-id",
				Validation:       "jwks",
				AccountClaim:     "dovecot_account",
			},
		},
	}}

	ctx := context.WithValue(t.Context(), loggerKey, slog.New(slog.DiscardHandler))
	auth := NewNauthilusSASLAuthenticator(cfg, "jwks_af", testClient, mgr)
	res, err := auth.AuthenticateToken(ctx, "ignored", signed, &DovecotAuthRequest{Mechanism: "XOAUTH2", Service: "smtp"})
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected success, got failure: %v", res.Reason)
	}
	if res.Username != "custom-jwks@example.com" {
		t.Fatalf("username = %q, want custom-jwks@example.com", res.Username)
	}
}
