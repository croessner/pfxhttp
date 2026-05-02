// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authv1 "PostfixToHTTP/proto/auth/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// --- Mapping unit tests ---

func TestBuildGRPCAuthRequestMapsAllFields(t *testing.T) {
	req := &DovecotAuthRequest{
		Service:     "smtp",
		Mechanism:   "PLAIN",
		LocalIP:     "127.0.0.1",
		LocalPort:   "25",
		RemoteIP:    "10.0.0.1",
		RemotePort:  "44321",
		Secured:     true,
		SSLProtocol: "TLSv1.3",
		SSLCipher:   "TLS_AES_256_GCM_SHA384",
		ClientID:    "client-x",
	}

	got := buildGRPCAuthRequest("alice", "secret", req, "587")

	if got.GetUsername() != "alice" || got.GetPassword() != "secret" {
		t.Fatalf("username/password mismatch: %+v", got)
	}

	if got.GetProtocol() != "smtp" || got.GetMethod() != "PLAIN" {
		t.Fatalf("protocol/method mismatch: %+v", got)
	}

	if got.GetClientIp() != "10.0.0.1" || got.GetClientPort() != "44321" {
		t.Fatalf("client ip/port mismatch: %+v", got)
	}

	if got.GetLocalIp() != "127.0.0.1" || got.GetLocalPort() != "25" {
		t.Fatalf("local ip/port mismatch: %+v", got)
	}

	if got.GetSsl() != "on" {
		t.Fatalf("ssl flag: got %q want \"on\"", got.GetSsl())
	}

	if got.GetSslProtocol() != "TLSv1.3" || got.GetSslCipher() != "TLS_AES_256_GCM_SHA384" {
		t.Fatalf("ssl protocol/cipher mismatch: %+v", got)
	}

	if got.GetClientId() != "client-x" {
		t.Fatalf("client_id mismatch: %q", got.GetClientId())
	}
}

func TestBuildGRPCAuthRequestUsesDefaultLocalPort(t *testing.T) {
	got := buildGRPCAuthRequest("u", "p", &DovecotAuthRequest{Service: "smtp"}, "587")
	if got.GetLocalPort() != "587" {
		t.Fatalf("expected fallback local_port=587, got %q", got.GetLocalPort())
	}
}

func TestBuildGRPCAuthRequestNilDovecot(t *testing.T) {
	got := buildGRPCAuthRequest("u", "p", nil, "")
	if got.GetUsername() != "u" || got.GetPassword() != "p" {
		t.Fatalf("nil request must not crash and still carry credentials")
	}
}

func TestMapAuthResponseDecisionOK(t *testing.T) {
	resp := &authv1.AuthResponse{
		Ok:           true,
		Decision:     authv1.AuthDecision_AUTH_DECISION_OK,
		AccountField: "Auth-User",
		Attributes: map[string]*authv1.AttributeValues{
			"Auth-User": {Values: []string{"alice@example.com"}},
		},
	}

	res := mapAuthResponse(resp)
	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}

	if res.Username != "alice@example.com" {
		t.Fatalf("username: got %q want alice@example.com", res.Username)
	}
}

func TestMapAuthResponseDecisionTempfail(t *testing.T) {
	resp := &authv1.AuthResponse{
		Decision:      authv1.AuthDecision_AUTH_DECISION_TEMPFAIL,
		StatusMessage: "ldap unavailable",
	}

	res := mapAuthResponse(resp)
	if res.Success || !res.Temporary {
		t.Fatalf("expected tempfail, got %+v", res)
	}

	if res.Reason != "ldap unavailable" {
		t.Fatalf("reason mismatch: %q", res.Reason)
	}
}

func TestMapAuthResponseDecisionFail(t *testing.T) {
	resp := &authv1.AuthResponse{
		Decision: authv1.AuthDecision_AUTH_DECISION_FAIL,
		Error:    "invalid credentials",
	}

	res := mapAuthResponse(resp)
	if res.Success || res.Temporary {
		t.Fatalf("expected hard fail, got %+v", res)
	}

	if res.Reason != "invalid credentials" {
		t.Fatalf("reason mismatch: %q", res.Reason)
	}
}

func TestMapAuthResponseAccountFieldFallback(t *testing.T) {
	resp := &authv1.AuthResponse{
		Ok:       true,
		Decision: authv1.AuthDecision_AUTH_DECISION_OK,
		// AccountField empty: fall back to "Auth-User".
		Attributes: map[string]*authv1.AttributeValues{
			"Auth-User": {Values: []string{"resolved@example.com"}},
		},
	}

	res := mapAuthResponse(resp)
	if res.Username != "resolved@example.com" {
		t.Fatalf("username: got %q want resolved@example.com", res.Username)
	}
}

func TestMapAuthResponseNil(t *testing.T) {
	res := mapAuthResponse(nil)
	if res.Success || !res.Temporary {
		t.Fatalf("nil response must produce temporary failure: %+v", res)
	}
}

func TestClassifyGRPCError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantTemp bool
	}{
		{"unavailable", status.Error(codes.Unavailable, "down"), true},
		{"deadline", status.Error(codes.DeadlineExceeded, "slow"), true},
		{"unauthenticated", status.Error(codes.Unauthenticated, "no creds"), true},
		{"permission", status.Error(codes.PermissionDenied, "scope"), true},
		{"invalid argument", status.Error(codes.InvalidArgument, "bad"), false},
		{"non-status error", errors.New("plain"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := classifyGRPCError(tt.err, nil)
			if res.Success {
				t.Fatalf("classified error must never indicate success")
			}

			if res.Temporary != tt.wantTemp {
				t.Fatalf("temp mismatch: got %v want %v", res.Temporary, tt.wantTemp)
			}
		})
	}
}

func TestFindAuthorizationHeader(t *testing.T) {
	headers := []string{
		"Content-Type: application/json",
		"authorization: Basic Zm9vOmJhcg==",
		"X-Trace: yes",
	}

	got, ok := findAuthorizationHeader(headers)
	if !ok {
		t.Fatalf("expected to find Authorization header")
	}

	if got != "Basic Zm9vOmJhcg==" {
		t.Fatalf("authorization value: got %q", got)
	}
}

// --- Integration test against a real gRPC server bound to 127.0.0.1:0 ---

type fakeAuthServer struct {
	authv1.UnimplementedAuthServiceServer

	wantAuth  string
	authSeen  atomic.Value // string, captured authorization metadata
	response  *authv1.AuthResponse
	rpcErr    error
	callCount atomic.Int64
}

func (f *fakeAuthServer) Authenticate(ctx context.Context, req *authv1.AuthRequest) (*authv1.AuthResponse, error) {
	f.callCount.Add(1)

	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("authorization")
	if len(values) > 0 {
		f.authSeen.Store(values[0])
	} else {
		f.authSeen.Store("")
	}

	if f.wantAuth != "" {
		if len(values) == 0 || values[0] != f.wantAuth {
			return nil, status.Error(codes.Unauthenticated, "bad caller credentials")
		}
	}

	if f.rpcErr != nil {
		return nil, f.rpcErr
	}

	return f.response, nil
}

func startFakeAuthServer(t *testing.T, srv *fakeAuthServer) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	gs := grpc.NewServer()
	authv1.RegisterAuthServiceServer(gs, srv)

	go func() { _ = gs.Serve(listener) }()

	return listener.Addr().String(), func() {
		gs.GracefulStop()
		_ = listener.Close()
	}
}

func TestNauthilusGRPCSASLAuthenticatorPasswordSuccess(t *testing.T) {
	const expectedAuth = "Basic " + "YWRtaW46cw==" // admin:s

	fake := &fakeAuthServer{
		wantAuth: expectedAuth,
		response: &authv1.AuthResponse{
			Ok:           true,
			Decision:     authv1.AuthDecision_AUTH_DECISION_OK,
			AccountField: "Auth-User",
			Attributes: map[string]*authv1.AttributeValues{
				"Auth-User": {Values: []string{"alice@example.com"}},
			},
		},
	}

	addr, stop := startFakeAuthServer(t, fake)
	defer stop()

	cfg := &Config{
		DovecotSASL: map[string]Request{
			"smtp_auth": {
				Transport: transportGRPC,
				CustomHeaders: []string{
					"Authorization: " + expectedAuth,
				},
				GRPC: GRPCRequest{Address: addr, Timeout: 2 * time.Second},
			},
		},
	}

	pool := NewGRPCConnPool()
	defer pool.CloseAll()

	auth := NewNauthilusGRPCSASLAuthenticator(cfg, "smtp_auth", pool, nil, nil)

	res, err := auth.AuthenticatePassword(context.Background(), "alice", "secret",
		&DovecotAuthRequest{Service: "smtp", Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("AuthenticatePassword: %v", err)
	}

	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}

	if res.Username != "alice@example.com" {
		t.Fatalf("username mismatch: %q", res.Username)
	}

	if got, _ := fake.authSeen.Load().(string); got != expectedAuth {
		t.Fatalf("authorization metadata not propagated: got %q", got)
	}
}

func TestNauthilusGRPCSASLAuthenticatorRejectsBadCallerAuth(t *testing.T) {
	fake := &fakeAuthServer{wantAuth: "Basic correct"}

	addr, stop := startFakeAuthServer(t, fake)
	defer stop()

	cfg := &Config{
		DovecotSASL: map[string]Request{
			"smtp_auth": {
				Transport: transportGRPC,
				CustomHeaders: []string{
					"Authorization: Basic wrong",
				},
				GRPC: GRPCRequest{Address: addr, Timeout: 2 * time.Second},
			},
		},
	}

	pool := NewGRPCConnPool()
	defer pool.CloseAll()

	auth := NewNauthilusGRPCSASLAuthenticator(cfg, "smtp_auth", pool, nil, nil)

	res, err := auth.AuthenticatePassword(context.Background(), "alice", "secret",
		&DovecotAuthRequest{Service: "smtp", Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("AuthenticatePassword: %v", err)
	}

	if res.Success {
		t.Fatalf("expected failure for wrong caller credentials")
	}

	if !res.Temporary {
		t.Fatalf("caller-auth rejection must surface as temporary failure")
	}

	if !strings.Contains(strings.ToLower(res.Reason), "caller authorization") {
		t.Fatalf("reason should hint at caller authorization, got %q", res.Reason)
	}
}

func TestNauthilusGRPCSASLAuthenticatorTokenDelegatesToFallback(t *testing.T) {
	fallback := &recordingAuthenticator{tokenResult: &SASLAuthResult{Success: true, Username: "from-fallback"}}

	cfg := &Config{
		DovecotSASL: map[string]Request{
			"smtp_auth": {Transport: transportGRPC},
		},
	}

	auth := NewNauthilusGRPCSASLAuthenticator(cfg, "smtp_auth", NewGRPCConnPool(), nil, fallback)

	res, err := auth.AuthenticateToken(context.Background(), "user", "tok", &DovecotAuthRequest{Service: "smtp"})
	if err != nil {
		t.Fatalf("AuthenticateToken: %v", err)
	}

	if !res.Success || res.Username != "from-fallback" {
		t.Fatalf("token auth must delegate to HTTP fallback, got %+v", res)
	}

	if !fallback.tokenCalled {
		t.Fatalf("expected fallback.AuthenticateToken to be called")
	}
}

// recordingAuthenticator is a tiny SASLAuthenticator double for delegation tests.
type recordingAuthenticator struct {
	passwordResult *SASLAuthResult
	tokenResult    *SASLAuthResult
	passwordCalled bool
	tokenCalled    bool
}

func (r *recordingAuthenticator) AuthenticatePassword(_ context.Context, _, _ string, _ *DovecotAuthRequest) (*SASLAuthResult, error) {
	r.passwordCalled = true

	return r.passwordResult, nil
}

func (r *recordingAuthenticator) AuthenticateToken(_ context.Context, _, _ string, _ *DovecotAuthRequest) (*SASLAuthResult, error) {
	r.tokenCalled = true

	return r.tokenResult, nil
}

var _ SASLAuthenticator = (*recordingAuthenticator)(nil)

// --- Connection pool tests ---

func TestGRPCConnPoolReusesConnections(t *testing.T) {
	addr, stop := startFakeAuthServer(t, &fakeAuthServer{response: &authv1.AuthResponse{Decision: authv1.AuthDecision_AUTH_DECISION_OK}})
	defer stop()

	pool := NewGRPCConnPool()
	defer pool.CloseAll()

	settings := GRPCRequest{Address: addr}

	c1, err := pool.Get("entry", settings)
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}

	c2, err := pool.Get("entry", settings)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}

	if c1 != c2 {
		t.Fatalf("pool must reuse the connection for the same fingerprint")
	}
}

func TestGRPCConnPoolRetainOnlyDropsOrphans(t *testing.T) {
	addr1, stop1 := startFakeAuthServer(t, &fakeAuthServer{})
	defer stop1()

	addr2, stop2 := startFakeAuthServer(t, &fakeAuthServer{})
	defer stop2()

	pool := NewGRPCConnPool()
	defer pool.CloseAll()

	if _, err := pool.Get("keep_me", GRPCRequest{Address: addr1}); err != nil {
		t.Fatalf("seed keep_me: %v", err)
	}

	if _, err := pool.Get("drop_me", GRPCRequest{Address: addr2}); err != nil {
		t.Fatalf("seed drop_me: %v", err)
	}

	pool.RetainOnly(map[string]struct{}{"keep_me": {}})

	pool.mu.Lock()
	defer pool.mu.Unlock()

	if _, ok := pool.conns["keep_me"]; !ok {
		t.Fatalf("RetainOnly removed an entry that should be kept")
	}

	if _, ok := pool.conns["drop_me"]; ok {
		t.Fatalf("RetainOnly did not drop the orphan entry")
	}
}

func TestGRPCConnPoolRebuildsOnFingerprintChange(t *testing.T) {
	addr1, stop1 := startFakeAuthServer(t, &fakeAuthServer{})
	defer stop1()

	addr2, stop2 := startFakeAuthServer(t, &fakeAuthServer{})
	defer stop2()

	pool := NewGRPCConnPool()
	defer pool.CloseAll()

	c1, err := pool.Get("entry", GRPCRequest{Address: addr1})
	if err != nil {
		t.Fatalf("first Get: %v", err)
	}

	c2, err := pool.Get("entry", GRPCRequest{Address: addr2})
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}

	if c1 == c2 {
		t.Fatalf("pool must rebuild the connection when settings change")
	}
}

// Smoke check: the test ensures the dial path uses insecure creds when TLS
// is disabled — protecting against a regression where dial would silently
// require TLS.
func TestDialGRPCInsecureByDefault(t *testing.T) {
	addr, stop := startFakeAuthServer(t, &fakeAuthServer{response: &authv1.AuthResponse{Decision: authv1.AuthDecision_AUTH_DECISION_OK}})
	defer stop()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("control dial: %v", err)
	}
	_ = conn.Close()
}

// --- Helper unit tests ---

func TestEffectiveGRPCTimeoutDefault(t *testing.T) {
	if got := effectiveGRPCTimeout(GRPCRequest{}); got != 5*time.Second {
		t.Fatalf("default timeout: got %v want 5s", got)
	}
}

func TestEffectiveGRPCTimeoutCustom(t *testing.T) {
	if got := effectiveGRPCTimeout(GRPCRequest{Timeout: 250 * time.Millisecond}); got != 250*time.Millisecond {
		t.Fatalf("explicit timeout: got %v want 250ms", got)
	}
}

func TestBuildClientTLSConfigEmpty(t *testing.T) {
	tlsCfg, err := buildClientTLSConfig(GRPCTLS{})
	if err != nil {
		t.Fatalf("empty TLS section must succeed: %v", err)
	}

	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("default min TLS version: got %x want %x", tlsCfg.MinVersion, tls.VersionTLS12)
	}
}

func TestBuildClientTLSConfigMinVersion13(t *testing.T) {
	tlsCfg, err := buildClientTLSConfig(GRPCTLS{MinVersion: "1.3"})
	if err != nil {
		t.Fatalf("min_tls_version=1.3 must succeed: %v", err)
	}

	if tlsCfg.MinVersion != tls.VersionTLS13 {
		t.Fatalf("min TLS version: got %x want %x", tlsCfg.MinVersion, tls.VersionTLS13)
	}
}

func TestBuildClientTLSConfigRejectsLegacyVersions(t *testing.T) {
	for _, value := range []string{"1.0", "1.1", "ssl3", "garbage"} {
		t.Run(value, func(t *testing.T) {
			if _, err := buildClientTLSConfig(GRPCTLS{MinVersion: value}); err == nil {
				t.Fatalf("expected rejection for min_tls_version=%q", value)
			}
		})
	}
}

func TestResolveTLSMinVersion(t *testing.T) {
	cases := []struct {
		in   string
		want uint16
		err  bool
	}{
		{"", tls.VersionTLS12, false},
		{"1.2", tls.VersionTLS12, false},
		{"1.3", tls.VersionTLS13, false},
		{"1.1", 0, true},
		{"TLS1.2", 0, true},
		{"foo", 0, true},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := resolveTLSMinVersion(tc.in)
			if tc.err {
				if err == nil {
					t.Fatalf("expected error for %q", tc.in)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tc.want {
				t.Fatalf("got %x want %x", got, tc.want)
			}
		})
	}
}

func TestBuildClientTLSConfigCAErrors(t *testing.T) {
	_, err := buildClientTLSConfig(GRPCTLS{CACert: "/nonexistent/file/path/to/ca.pem"})
	if err == nil {
		t.Fatalf("expected error for missing CA file")
	}

	tmp := t.TempDir()
	bogus := filepath.Join(tmp, "bogus.pem")
	if writeErr := os.WriteFile(bogus, []byte("not a pem"), 0o600); writeErr != nil {
		t.Fatalf("write bogus pem: %v", writeErr)
	}

	_, err = buildClientTLSConfig(GRPCTLS{CACert: bogus})
	if err == nil {
		t.Fatalf("expected error for malformed CA pem")
	}
}

func TestBuildClientTLSConfigClientCertWithoutKey(t *testing.T) {
	tmp := t.TempDir()
	certFile := filepath.Join(tmp, "client.pem")
	if err := os.WriteFile(certFile, []byte("dummy"), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	_, err := buildClientTLSConfig(GRPCTLS{ClientCert: certFile})
	if err == nil {
		t.Fatalf("expected error when client_cert is set without client_key")
	}
}

// --- Factory tests ---

func TestNewSASLAuthenticatorForEntryReturnsHTTPForJSON(t *testing.T) {
	cfg := &Config{
		DovecotSASL: map[string]Request{
			"http_entry": {Target: "http://nauthilus.example/api/v1/auth/json"},
			"json_entry": {Target: "http://nauthilus.example/api/v1/auth/json", Transport: transportJSON},
		},
	}

	deps := &Deps{HTTPClient: &http.Client{}, GRPCConnPool: NewGRPCConnPool()}

	for _, name := range []string{"http_entry", "json_entry"} {
		t.Run(name, func(t *testing.T) {
			got := newSASLAuthenticatorForEntry(cfg, name, deps)
			if _, isGRPC := got.(*NauthilusGRPCSASLAuthenticator); isGRPC {
				t.Fatalf("expected HTTP authenticator for transport=%q", cfg.DovecotSASL[name].Transport)
			}
		})
	}
}

func TestNewSASLAuthenticatorForEntryReturnsGRPC(t *testing.T) {
	cfg := &Config{
		DovecotSASL: map[string]Request{
			"grpc_entry": {
				Transport: transportGRPC,
				GRPC:      GRPCRequest{Address: "127.0.0.1:9444"},
			},
		},
	}

	deps := &Deps{HTTPClient: &http.Client{}, GRPCConnPool: NewGRPCConnPool()}

	got := newSASLAuthenticatorForEntry(cfg, "grpc_entry", deps)
	if _, isGRPC := got.(*NauthilusGRPCSASLAuthenticator); !isGRPC {
		t.Fatalf("expected gRPC authenticator for transport=grpc, got %T", got)
	}
}

// --- OIDC backend bearer auth end-to-end ---

func TestNauthilusGRPCSASLAuthenticatorOIDCBearer(t *testing.T) {
	const issuedToken = "test-access-token-xyz"

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discovery := map[string]any{
				"issuer":                 "https://idp.local",
				"token_endpoint":         "http://" + r.Host + "/token",
				"introspection_endpoint": "http://" + r.Host + "/introspect",
				"jwks_uri":               "http://" + r.Host + "/jwks",
			}
			w.Header().Set("Content-Type", "application/json")

			if err := json.NewEncoder(w).Encode(discovery); err != nil {
				t.Fatalf("encode discovery: %v", err)
			}
		case "/token":
			body := map[string]any{
				"access_token": issuedToken,
				"token_type":   "Bearer",
				"expires_in":   3600,
			}
			w.Header().Set("Content-Type", "application/json")

			if err := json.NewEncoder(w).Encode(body); err != nil {
				t.Fatalf("encode token: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer idp.Close()

	fake := &fakeAuthServer{
		wantAuth: "Bearer " + issuedToken,
		response: &authv1.AuthResponse{
			Ok:           true,
			Decision:     authv1.AuthDecision_AUTH_DECISION_OK,
			AccountField: "Auth-User",
			Attributes: map[string]*authv1.AttributeValues{
				"Auth-User": {Values: []string{"oidc-user@example.com"}},
			},
		},
	}

	addr, stop := startFakeAuthServer(t, fake)
	defer stop()

	cfg := &Config{
		DovecotSASL: map[string]Request{
			"smtp_oidc": {
				Transport: transportGRPC,
				BackendOIDCAuth: BackendOIDCAuth{
					Enabled:          true,
					ConfigurationURI: idp.URL + "/.well-known/openid-configuration",
					ClientID:         "pfxhttp-test",
					ClientSecret:     "shh",
					AuthMethod:       "client_secret_basic",
				},
				GRPC: GRPCRequest{Address: addr, Timeout: 2 * time.Second},
			},
		},
	}

	httpClient := &http.Client{Timeout: 5 * time.Second}
	mgr := NewOIDCManager(httpClient)

	pool := NewGRPCConnPool()
	defer pool.CloseAll()

	auth := NewNauthilusGRPCSASLAuthenticator(cfg, "smtp_oidc", pool, mgr, nil)

	res, err := auth.AuthenticatePassword(context.Background(), "alice", "secret",
		&DovecotAuthRequest{Service: "smtp", Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("AuthenticatePassword: %v", err)
	}

	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}

	if res.Username != "oidc-user@example.com" {
		t.Fatalf("username mismatch: %q", res.Username)
	}

	got, _ := fake.authSeen.Load().(string)
	if got != "Bearer "+issuedToken {
		t.Fatalf("expected Bearer metadata to match issued token, got %q", got)
	}
}
