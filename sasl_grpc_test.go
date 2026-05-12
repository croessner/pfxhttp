// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
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

	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// --- Mapping unit tests ---

func TestBuildGRPCAuthRequestMapsAllFields(t *testing.T) {
	req := &DovecotAuthRequest{
		Service:            "smtp",
		Mechanism:          "PLAIN",
		LocalIP:            "127.0.0.1",
		LocalPort:          "25",
		RemoteIP:           "10.0.0.1",
		RemotePort:         "44321",
		LocalName:          "mx1.example.org",
		ClientHostname:     "client.example.org",
		ExternalSessionID:  "session-1",
		UserAgent:          "Postfix/3.11",
		Secured:            true,
		SSLSessionID:       "tls-session",
		SSLClientVerify:    "SUCCESS",
		SSLClientDN:        "CN=client,O=Example",
		SSLClientCN:        "client",
		SSLIssuer:          "Example CA",
		SSLClientNotBefore: "20260502000000Z",
		SSLClientNotAfter:  "20270502000000Z",
		SSLSubjectDN:       "CN=server,O=Example",
		SSLIssuerDN:        "CN=Example CA,O=Example",
		SSLClientSubjectDN: "CN=client,O=Example",
		SSLClientIssuerDN:  "CN=Example Client CA,O=Example",
		SSLProtocol:        "TLSv1.3",
		SSLCipher:          "TLS_AES_256_GCM_SHA384",
		SSLSerial:          "01:02:03",
		SSLFingerprint:     "AA:BB:CC",
		ClientID:           "client-x",
		OIDCCID:            "oidc-client",
		AuthLoginAttempt:   3,
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

	if got.GetClientHostname() != "client.example.org" {
		t.Fatalf("client hostname mismatch: %+v", got)
	}

	if got.GetLocalIp() != "127.0.0.1" || got.GetLocalPort() != "25" {
		t.Fatalf("local ip/port mismatch: %+v", got)
	}

	if got.GetExternalSessionId() != "session-1" || got.GetUserAgent() != "Postfix/3.11" {
		t.Fatalf("session/user-agent mismatch: %+v", got)
	}

	if got.GetSsl() != "on" {
		t.Fatalf("ssl flag: got %q want \"on\"", got.GetSsl())
	}

	if got.GetSslSessionId() != "tls-session" || got.GetSslClientVerify() != "SUCCESS" {
		t.Fatalf("ssl session/verify mismatch: %+v", got)
	}

	if got.GetSslClientDn() != "CN=client,O=Example" || got.GetSslClientCn() != "client" {
		t.Fatalf("ssl client identity mismatch: %+v", got)
	}

	if got.GetSslIssuer() != "Example CA" ||
		got.GetSslClientNotbefore() != "20260502000000Z" ||
		got.GetSslClientNotafter() != "20270502000000Z" {
		t.Fatalf("ssl issuer/validity mismatch: %+v", got)
	}

	if got.GetSslSubjectDn() != "CN=server,O=Example" ||
		got.GetSslIssuerDn() != "CN=Example CA,O=Example" ||
		got.GetSslClientSubjectDn() != "CN=client,O=Example" ||
		got.GetSslClientIssuerDn() != "CN=Example Client CA,O=Example" {
		t.Fatalf("ssl DN mismatch: %+v", got)
	}

	if got.GetSslProtocol() != "TLSv1.3" || got.GetSslCipher() != "TLS_AES_256_GCM_SHA384" {
		t.Fatalf("ssl protocol/cipher mismatch: %+v", got)
	}

	if got.GetSslSerial() != "01:02:03" || got.GetSslFingerprint() != "AA:BB:CC" {
		t.Fatalf("ssl serial/fingerprint mismatch: %+v", got)
	}

	if got.GetClientId() != "client-x" {
		t.Fatalf("client_id mismatch: %q", got.GetClientId())
	}

	if got.GetOidcCid() != "oidc-client" || got.GetAuthLoginAttempt() != 3 {
		t.Fatalf("oidc/auth attempt mismatch: %+v", got)
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

func TestBasicAuthorizationValue(t *testing.T) {
	got := basicAuthorizationValue("admin:s")
	if got != "Basic YWRtaW46cw==" {
		t.Fatalf("basic auth value: got %q", got)
	}
}

// --- Integration test against a real gRPC server bound to 127.0.0.1:0 ---

type fakeAuthServer struct {
	authv1.UnimplementedAuthServiceServer

	wantAuth  string
	authSeen  atomic.Value // string, captured authorization metadata
	mdSeen    atomic.Value // metadata.MD, captured incoming metadata
	response  *authv1.AuthResponse
	rpcErr    error
	callCount atomic.Int64
}

func (f *fakeAuthServer) Authenticate(ctx context.Context, req *authv1.AuthRequest) (*authv1.AuthResponse, error) {
	f.callCount.Add(1)

	md, _ := metadata.FromIncomingContext(ctx)
	f.mdSeen.Store(md.Copy())
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
				Transport:     transportGRPC,
				HTTPAuthBasic: "admin:s",
				GRPC: GRPCRequest{
					Address: addr,
					Timeout: 2 * time.Second,
					Metadata: map[string][]string{
						"accept-language": {"de"},
					},
				},
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

	md, _ := fake.mdSeen.Load().(metadata.MD)
	if got := md.Get("accept-language"); len(got) != 1 || got[0] != "de" {
		t.Fatalf("accept-language metadata not propagated: got %v", got)
	}
}

func TestNauthilusGRPCSASLAuthenticatorPropagatesTraceContext(t *testing.T) {
	obs, recorder := newTraceTestObservability(t)
	fake, auth := newTracedGRPCAuthFixture(t)

	ctx, parentSpan := obs.StartSpanWithKind(t.Context(), dovecotSASLSpanName("smtp_auth"), oteltrace.SpanKindServer)
	ctx = ContextWithObservability(ctx, obs)

	res, err := auth.AuthenticatePassword(ctx, "alice", "secret",
		&DovecotAuthRequest{Service: "smtp", Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("AuthenticatePassword: %v", err)
	}

	parentSpan.End()

	if !res.Success {
		t.Fatalf("expected success, got %+v", res)
	}

	md, _ := fake.mdSeen.Load().(metadata.MD)
	if got := md.Get("traceparent"); len(got) != 1 || got[0] == "" {
		t.Fatalf("traceparent metadata not propagated: got %v", got)
	}

	parent, ok := recorder.findSpan(dovecotSASLSpanName("smtp_auth"))
	if !ok {
		t.Fatalf("parent span %q not recorded", dovecotSASLSpanName("smtp_auth"))
	}

	child, ok := recorder.findSpan(grpcClientSpanName("Authenticate"))
	if !ok {
		t.Fatalf("child span %q not recorded", grpcClientSpanName("Authenticate"))
	}

	if child.traceID != parent.traceID {
		t.Fatalf("child trace ID = %s, want %s", child.traceID, parent.traceID)
	}

	if child.parent.SpanID() != parent.spanID {
		t.Fatalf("child parent span ID = %s, want %s", child.parent.SpanID(), parent.spanID)
	}

	for _, name := range []string{"gRPC connection", "gRPC metadata", "gRPC request build"} {
		assertPreparationSpan(t, recorder, parent, name)
	}
}

func assertPreparationSpan(t *testing.T, recorder *spanRecorder, parent recordedSpan, name string) {
	t.Helper()

	prepareSpan, ok := recorder.findSpan(name)
	if !ok {
		t.Fatalf("preparation span %q not recorded", name)
	}

	if prepareSpan.traceID != parent.traceID {
		t.Fatalf("preparation span %q trace ID = %s, want %s", name, prepareSpan.traceID, parent.traceID)
	}

	if prepareSpan.parent.SpanID() != parent.spanID {
		t.Fatalf("preparation span %q parent span ID = %s, want %s", name, prepareSpan.parent.SpanID(), parent.spanID)
	}
}

// newTracedGRPCAuthFixture starts a fake gRPC AuthService and returns a matching authenticator.
func newTracedGRPCAuthFixture(t *testing.T) (*fakeAuthServer, SASLAuthenticator) {
	t.Helper()

	fake := &fakeAuthServer{
		response: &authv1.AuthResponse{
			Ok:       true,
			Decision: authv1.AuthDecision_AUTH_DECISION_OK,
		},
	}

	addr, stop := startFakeAuthServer(t, fake)
	t.Cleanup(stop)

	pool := NewGRPCConnPool()
	t.Cleanup(pool.CloseAll)

	cfg := &Config{
		DovecotSASL: map[string]Request{
			"smtp_auth": {
				Transport: transportGRPC,
				GRPC: GRPCRequest{
					Address: addr,
					Timeout: 2 * time.Second,
				},
			},
		},
	}

	return fake, NewNauthilusGRPCSASLAuthenticator(cfg, "smtp_auth", pool, nil, nil)
}

func TestNauthilusGRPCSASLAuthenticatorRejectsBadCallerAuth(t *testing.T) {
	fake := &fakeAuthServer{wantAuth: "Basic correct"}

	addr, stop := startFakeAuthServer(t, fake)
	defer stop()

	cfg := &Config{
		DovecotSASL: map[string]Request{
			"smtp_auth": {
				Transport:     transportGRPC,
				HTTPAuthBasic: "wrong",
				GRPC:          GRPCRequest{Address: addr, Timeout: 2 * time.Second},
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

func TestHandleSASLResultUsesReloadedConfig(t *testing.T) {
	oldBackend := &fakeAuthServer{
		response: &authv1.AuthResponse{
			Decision:     authv1.AuthDecision_AUTH_DECISION_OK,
			AccountField: "Auth-User",
			Attributes: map[string]*authv1.AttributeValues{
				"Auth-User": {Values: []string{"old@example.com"}},
			},
		},
	}
	oldAddr, stopOld := startFakeAuthServer(t, oldBackend)
	defer stopOld()

	newBackend := &fakeAuthServer{
		response: &authv1.AuthResponse{
			Decision:     authv1.AuthDecision_AUTH_DECISION_OK,
			AccountField: "Auth-User",
			Attributes: map[string]*authv1.AttributeValues{
				"Auth-User": {Values: []string{"new@example.com"}},
			},
		},
	}
	newAddr, stopNew := startFakeAuthServer(t, newBackend)
	defer stopNew()

	deps := &Deps{
		Config: &Config{DovecotSASL: map[string]Request{
			"smtp_auth": {
				Transport: transportGRPC,
				GRPC:      GRPCRequest{Address: oldAddr, Timeout: 2 * time.Second},
			},
		}},
		Logger:       slog.New(slog.DiscardHandler),
		HTTPClient:   &http.Client{Timeout: 2 * time.Second},
		OIDCManager:  NewOIDCManager(&http.Client{Timeout: 2 * time.Second}),
		GRPCConnPool: NewGRPCConnPool(),
	}
	defer deps.GRPCConnPool.CloseAll()

	server := &MultiServer{name: "smtp_auth", deps: deps, ctx: context.Background()}
	logger := slog.New(slog.DiscardHandler)

	first := runHandleSASLResultForTest(t, server, logger, "1")
	if !strings.Contains(first, "user=old@example.com") {
		t.Fatalf("first response = %q, want old backend user", first)
	}

	deps.Reload(&Config{DovecotSASL: map[string]Request{
		"smtp_auth": {
			Transport: transportGRPC,
			GRPC:      GRPCRequest{Address: newAddr, Timeout: 2 * time.Second},
		},
	}}, deps.Logger, deps.HTTPClient, nil)

	second := runHandleSASLResultForTest(t, server, logger, "2")
	if !strings.Contains(second, "user=new@example.com") {
		t.Fatalf("second response = %q, want reloaded backend user", second)
	}

	if newBackend.callCount.Load() == 0 {
		t.Fatal("reloaded gRPC backend was not called")
	}
}

func TestHandleSASLResultKeepsContinuationSpanOpen(t *testing.T) {
	obs, recorder := newTraceTestObservability(t)
	server := &MultiServer{
		name: "smtp_auth",
		deps: &Deps{
			Logger:        slog.New(slog.DiscardHandler),
			Observability: obs,
		},
		ctx: context.Background(),
	}
	logger := slog.New(slog.DiscardHandler)
	authReq := &DovecotAuthRequest{ID: "1", Service: "smtp", Mechanism: new(LoginMechanism).Name()}
	activeMechanisms := make(map[string]SASLMechanism)
	activeAuthRequests := make(map[string]*DovecotAuthRequest)
	activeObservabilityStates := make(map[string]*saslObservabilityState)

	first := runObservedHandleSASLResultForTest(t, server, logger, authReq, &SASLAuthResult{
		NeedContinuation:      true,
		ContinuationChallenge: []byte("Password:"),
	}, nil, activeMechanisms, activeAuthRequests, activeObservabilityStates)
	if !strings.HasPrefix(first, "CONT\t1\t") {
		t.Fatalf("first response = %q, want CONT", first)
	}

	if got := recorder.countSpans(dovecotSASLSpanName("smtp_auth")); got != 0 {
		t.Fatalf("ended Dovecot SASL spans after CONT = %d, want 0", got)
	}

	second := runObservedHandleSASLResultForTest(t, server, logger, authReq, &SASLAuthResult{
		Success: false,
		Reason:  "denied",
	}, nil, activeMechanisms, activeAuthRequests, activeObservabilityStates)
	if !strings.HasPrefix(second, "FAIL\t1\t") {
		t.Fatalf("second response = %q, want FAIL", second)
	}

	if got := recorder.countSpans(dovecotSASLSpanName("smtp_auth")); got != 1 {
		t.Fatalf("ended Dovecot SASL spans after final result = %d, want 1", got)
	}

	parent, ok := recorder.findSpan(dovecotSASLSpanName("smtp_auth"))
	if !ok {
		t.Fatalf("parent span %q not recorded", dovecotSASLSpanName("smtp_auth"))
	}

	assertChildSpan(t, recorder, parent, dovecotSASLWaitSpanName)
	assertChildSpan(t, recorder, parent, dovecotSASLResponseSpanName)
}

func TestHandleSASLResultRecordsBackendAndResponseSpans(t *testing.T) {
	obs, recorder := newTraceTestObservability(t)
	backend := &fakeAuthServer{
		response: &authv1.AuthResponse{
			Decision:     authv1.AuthDecision_AUTH_DECISION_OK,
			AccountField: "Auth-User",
			Attributes: map[string]*authv1.AttributeValues{
				"Auth-User": {Values: []string{"alice@example.com"}},
			},
		},
	}

	addr, stop := startFakeAuthServer(t, backend)
	defer stop()

	deps := &Deps{
		Config: &Config{DovecotSASL: map[string]Request{
			"smtp_auth": {
				Transport: transportGRPC,
				GRPC:      GRPCRequest{Address: addr, Timeout: 2 * time.Second},
			},
		}},
		Logger:        slog.New(slog.DiscardHandler),
		HTTPClient:    &http.Client{Timeout: 2 * time.Second},
		OIDCManager:   NewOIDCManager(&http.Client{Timeout: 2 * time.Second}),
		GRPCConnPool:  NewGRPCConnPool(),
		Observability: obs,
	}
	defer deps.GRPCConnPool.CloseAll()

	server := &MultiServer{name: "smtp_auth", deps: deps, ctx: context.Background()}

	response := runHandleSASLResultForTest(t, server, slog.New(slog.DiscardHandler), "1")
	if !strings.Contains(response, "user=alice@example.com") {
		t.Fatalf("response = %q, want gRPC backend user", response)
	}

	parent, ok := recorder.findSpan(dovecotSASLSpanName("smtp_auth"))
	if !ok {
		t.Fatalf("parent span %q not recorded", dovecotSASLSpanName("smtp_auth"))
	}

	backendSpan := assertChildSpan(t, recorder, parent, dovecotSASLBackendSpanName)
	assertChildSpan(t, recorder, parent, dovecotSASLResponseSpanName)
	assertChildSpan(t, recorder, backendSpan, grpcClientSpanName("Authenticate"))
}

func runHandleSASLResultForTest(t *testing.T, server *MultiServer, logger *slog.Logger, id string) string {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = serverConn.Close() }()

		server.handleSASLResult(
			serverConn,
			&DovecotEncoder{},
			logger,
			"pipe",
			&DovecotAuthRequest{ID: id, Service: "smtp", Mechanism: "PLAIN"},
			nil,
			&SASLAuthResult{Success: true},
			&SASLCredentials{Username: "alice", Password: "secret"},
			make(map[string]SASLMechanism),
			make(map[string]*DovecotAuthRequest),
			make(map[string]*saslObservabilityState),
		)
	}()

	if err := clientConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	line, err := bufio.NewReader(clientConn).ReadString('\n')
	if err != nil {
		t.Fatalf("read SASL response: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleSASLResult did not return")
	}

	return line
}

func runObservedHandleSASLResultForTest(
	t *testing.T,
	server *MultiServer,
	logger *slog.Logger,
	authReq *DovecotAuthRequest,
	result *SASLAuthResult,
	creds *SASLCredentials,
	activeMechanisms map[string]SASLMechanism,
	activeAuthRequests map[string]*DovecotAuthRequest,
	activeObservabilityStates map[string]*saslObservabilityState,
) string {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = serverConn.Close() }()

		server.handleSASLResult(
			serverConn,
			&DovecotEncoder{},
			logger,
			"pipe",
			authReq,
			nil,
			result,
			creds,
			activeMechanisms,
			activeAuthRequests,
			activeObservabilityStates,
		)
	}()

	if err := clientConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	line, err := bufio.NewReader(clientConn).ReadString('\n')
	if err != nil {
		t.Fatalf("read SASL response: %v", err)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleSASLResult did not return")
	}

	return line
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
	_, err := buildClientTLSConfig(GRPCTLS{RootCA: "/nonexistent/file/path/to/ca.pem"})
	if err == nil {
		t.Fatalf("expected error for missing CA file")
	}

	tmp := t.TempDir()
	bogus := filepath.Join(tmp, "bogus.pem")
	if writeErr := os.WriteFile(bogus, []byte("not a pem"), 0o600); writeErr != nil {
		t.Fatalf("write bogus pem: %v", writeErr)
	}

	_, err = buildClientTLSConfig(GRPCTLS{RootCA: bogus})
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
				GRPC: GRPCRequest{
					Address: addr,
					Timeout: 2 * time.Second,
					Metadata: map[string][]string{
						"accept-language": {"de"},
					},
				},
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

	md, _ := fake.mdSeen.Load().(metadata.MD)
	if got := md.Get("accept-language"); len(got) != 1 || got[0] != "de" {
		t.Fatalf("expected accept-language metadata beside bearer auth, got %v", got)
	}
}
