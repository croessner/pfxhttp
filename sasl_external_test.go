// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"strings"
	"testing"
)

const (
	testSHA256Fingerprint   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testCertificateIdentity = "certificate@example.test"
	testCanonicalIdentity   = "canonical@example.test"
	testAliasIdentity       = "alias@example.test"
	testOtherIdentity       = "other@example.test"
	testExternalEntry       = "external"
	testRemoteIPv4          = "192.0.2.10"
	testTLSSessionID        = "tls-session"
	testAccountFieldMail    = "mail"
)

func TestExternalMechanismRFC4422AuthorizationID(t *testing.T) { //nolint:gocyclo // One compact parser matrix.
	mechanism := &ExternalMechanism{}

	result, credentials := mechanism.Start(nil)
	if result == nil || !result.NeedContinuation || credentials != nil {
		t.Fatalf("missing initial response = (%+v, %+v), want continuation", result, credentials)
	}

	result, credentials = mechanism.Start([]byte{})
	if result != nil || credentials == nil || credentials.AuthzID != "" {
		t.Fatalf("explicit empty response = (%+v, %+v), want empty authzid", result, credentials)
	}

	result, credentials = mechanism.Start([]byte(testAliasIdentity))
	if result != nil || credentials == nil || credentials.AuthzID != testAliasIdentity {
		t.Fatalf("authzid response = (%+v, %+v)", result, credentials)
	}

	for _, invalid := range [][]byte{{0xff}, []byte("bad\x00identity"), []byte("bad\nidentity")} {
		result, credentials = mechanism.Continue(invalid)
		if result == nil || result.Success || credentials != nil {
			t.Fatalf("invalid response %q = (%+v, %+v), want rejection", invalid, result, credentials)
		}
	}
}

func TestValidateExternalCertificateContextFailsClosed(t *testing.T) {
	valid := DovecotAuthRequest{
		SSLClientVerify:      tlsClientVerifySuccess,
		SSLClientSANEmail:    testCertificateIdentity,
		SSLClientFingerprint: testSHA256Fingerprint,
	}

	tests := []struct {
		name   string
		mutate func(*DovecotAuthRequest)
	}{
		{name: "missing verification", mutate: func(req *DovecotAuthRequest) { req.SSLClientVerify = "" }},
		{name: "non-success verification", mutate: func(req *DovecotAuthRequest) { req.SSLClientVerify = "FAILED" }},
		{name: "missing identity", mutate: func(req *DovecotAuthRequest) { req.SSLClientSANEmail = "" }},
		{name: "leading identity whitespace", mutate: func(req *DovecotAuthRequest) { req.SSLClientSANEmail = " " + testCertificateIdentity }},
		{name: "trailing identity whitespace", mutate: func(req *DovecotAuthRequest) { req.SSLClientSANEmail = testCertificateIdentity + " " }},
		{name: "multiple identities", mutate: func(req *DovecotAuthRequest) { req.SSLClientSANEmail = "one@example.test,two@example.test" }},
		{name: "display name", mutate: func(req *DovecotAuthRequest) { req.SSLClientSANEmail = "User <one@example.test>" }},
		{name: "sha1 fingerprint", mutate: func(req *DovecotAuthRequest) { req.SSLClientFingerprint = strings.Repeat("a", 40) }},
		{name: "malformed fingerprint", mutate: func(req *DovecotAuthRequest) { req.SSLClientFingerprint = strings.Repeat("z", 64) }},
		{name: "conflicting legacy fingerprint", mutate: func(req *DovecotAuthRequest) { req.SSLFingerprint = strings.Repeat("a", 64) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := valid
			test.mutate(&req)

			if identity, err := validateExternalCertificateContext(&req); err == nil {
				t.Fatalf("identity = %q, want fail-closed error", identity)
			}
		})
	}

	colonFingerprint := strings.ToUpper(strings.Join(splitFingerprintPairs(testSHA256Fingerprint), ":"))
	valid.SSLClientFingerprint = colonFingerprint
	valid.SSLFingerprint = testSHA256Fingerprint

	identity, err := validateExternalCertificateContext(&valid)
	if err != nil || identity != testCertificateIdentity {
		t.Fatalf("valid certificate context = (%q, %v)", identity, err)
	}

	if valid.SSLClientFingerprint != testSHA256Fingerprint {
		t.Fatalf("fingerprint not normalized: %q", valid.SSLClientFingerprint)
	}
}

func splitFingerprintPairs(value string) []string {
	pairs := make([]string, 0, len(value)/2)
	for index := 0; index < len(value); index += 2 {
		pairs = append(pairs, value[index:index+2])
	}

	return pairs
}

func TestAuthenticateExternalAuthorizationPolicy(t *testing.T) { //nolint:funlen // Table covers one authorization policy matrix.
	req := &DovecotAuthRequest{
		SSLClientVerify:      tlsClientVerifySuccess,
		SSLClientSANEmail:    testCertificateIdentity,
		SSLClientFingerprint: testSHA256Fingerprint,
	}

	tests := []struct {
		name        string
		authzID     string
		allow       bool
		results     map[string]*SASLAuthResult
		wantOK      bool
		wantTemp    bool
		wantLookups []string
	}{
		{
			name:    "empty authzid",
			results: map[string]*SASLAuthResult{testCertificateIdentity: {Success: true, Username: testCanonicalIdentity}},
			wantOK:  true, wantLookups: []string{testCertificateIdentity},
		},
		{
			name: "identical authzid", authzID: testCertificateIdentity,
			results: map[string]*SASLAuthResult{testCertificateIdentity: {Success: true, Username: testCanonicalIdentity}},
			wantOK:  true, wantLookups: []string{testCertificateIdentity},
		},
		{
			name: "delegation disabled", authzID: testAliasIdentity,
			results:     map[string]*SASLAuthResult{testCertificateIdentity: {Success: true, Username: testCanonicalIdentity}},
			wantLookups: []string{testCertificateIdentity},
		},
		{
			name: "delegation same canonical account", authzID: testAliasIdentity, allow: true,
			results: map[string]*SASLAuthResult{
				testCertificateIdentity: {Success: true, Username: testCanonicalIdentity},
				testAliasIdentity:       {Success: true, Username: testCanonicalIdentity},
			},
			wantOK: true, wantLookups: []string{testCertificateIdentity, testAliasIdentity},
		},
		{
			name: "delegation different account", authzID: testOtherIdentity, allow: true,
			results: map[string]*SASLAuthResult{
				testCertificateIdentity: {Success: true, Username: testCanonicalIdentity},
				testOtherIdentity:       {Success: true, Username: "other-account@example.test"},
			},
			wantLookups: []string{testCertificateIdentity, testOtherIdentity},
		},
		{
			name: "delegation backend tempfail stays temporary", authzID: testAliasIdentity, allow: true,
			results: map[string]*SASLAuthResult{
				testCertificateIdentity: {Success: true, Username: testCanonicalIdentity},
				testAliasIdentity:       {Success: false, Temporary: true},
			},
			wantTemp: true, wantLookups: []string{testCertificateIdentity, testAliasIdentity},
		},
		{
			name: "delegation padded canonical account fails closed", authzID: testAliasIdentity, allow: true,
			results: map[string]*SASLAuthResult{
				testCertificateIdentity: {Success: true, Username: testCanonicalIdentity},
				testAliasIdentity:       {Success: true, Username: " " + testCanonicalIdentity},
			},
			wantTemp: true, wantLookups: []string{testCertificateIdentity, testAliasIdentity},
		},
		{
			name: "certificate canonical account with wire delimiter fails closed",
			results: map[string]*SASLAuthResult{
				testCertificateIdentity: {Success: true, Username: testCanonicalIdentity + "\tuser=attacker"},
			},
			wantTemp: true, wantLookups: []string{testCertificateIdentity},
		},
		{
			name: "whitespace authzid fails closed", authzID: " " + testAliasIdentity + " ", allow: true,
			results:     map[string]*SASLAuthResult{testCertificateIdentity: {Success: true, Username: testCanonicalIdentity}},
			wantLookups: []string{testCertificateIdentity},
		},
		{
			name:     "missing canonical account is temporary",
			results:  map[string]*SASLAuthResult{testCertificateIdentity: {Success: true}},
			wantTemp: true, wantLookups: []string{testCertificateIdentity},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authenticator := &externalTestAuthenticator{results: test.results}

			result, err := authenticateExternal(t.Context(), authenticator, test.authzID, req, test.allow)
			if err != nil {
				t.Fatalf("authenticateExternal returned error: %v", err)
			}

			if result == nil || result.Success != test.wantOK || result.Temporary != test.wantTemp {
				t.Fatalf("result = %+v, want success=%v temporary=%v", result, test.wantOK, test.wantTemp)
			}

			if strings.Join(authenticator.lookups, ",") != strings.Join(test.wantLookups, ",") {
				t.Fatalf("lookups = %v, want %v", authenticator.lookups, test.wantLookups)
			}
		})
	}
}

type externalTestAuthenticator struct {
	results map[string]*SASLAuthResult
	lookups []string
}

func (a *externalTestAuthenticator) AuthenticatePassword(context.Context, string, string, *DovecotAuthRequest) (*SASLAuthResult, error) {
	panic("unexpected password authentication")
}

func (a *externalTestAuthenticator) AuthenticateToken(context.Context, string, string, *DovecotAuthRequest) (*SASLAuthResult, error) {
	panic("unexpected token authentication")
}

func (a *externalTestAuthenticator) LookupIdentity(_ context.Context, username string, _ *DovecotAuthRequest) (*SASLAuthResult, error) {
	a.lookups = append(a.lookups, username)
	return a.results[username], nil
}

var _ SASLAuthenticator = (*externalTestAuthenticator)(nil)
