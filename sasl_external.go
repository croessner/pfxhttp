// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"net/mail"
	"strings"
)

var (
	errExternalCertificateUnverified = errors.New("external client certificate is not verified")
	errExternalIdentityUnavailable   = errors.New("external client certificate identity is unavailable")
	errExternalFingerprintInvalid    = errors.New("external client certificate fingerprint is invalid")
)

const (
	tlsClientVerifySuccess            = "SUCCESS"
	nauthilusNoAuthMode               = "no-auth"
	externalAuthorizationDeniedReason = "external authorization identity denied"
	emptyIdentityLookupReason         = "empty identity lookup response"
	missingCanonicalAccountReason     = "identity lookup returned no canonical account"
	identityNotFoundReason            = "identity not found"
)

// authenticateExternal resolves the verified certificate identity and, when
// explicitly enabled, proves that a distinct RFC 4422 authorization identity
// resolves to the same canonical Nauthilus account.
func authenticateExternal(
	ctx context.Context,
	authenticator SASLAuthenticator,
	authzID string,
	req *DovecotAuthRequest,
	allowAuthorizationID bool,
) (*SASLAuthResult, error) {
	identity, err := validateExternalCertificateContext(req)
	if err != nil {
		return &SASLAuthResult{Success: false, Reason: "external certificate authentication failed"}, nil
	}

	if authenticator == nil {
		return nil, errors.New("external identity lookup backend is unavailable")
	}

	certificateResult, err := authenticator.LookupIdentity(ctx, identity, req)
	if err != nil {
		return nil, err
	}

	certificateResult = validateCanonicalSASLResult(certificateResult, true)
	if !certificateResult.Success {
		return certificateResult, nil
	}

	if result := requireCanonicalExternalResult(certificateResult); result != nil {
		return result, nil
	}

	if authzID != strings.TrimSpace(authzID) {
		return &SASLAuthResult{Success: false, Reason: externalAuthorizationDeniedReason}, nil
	}

	authorizationID := authzID

	if authorizationID == "" || authorizationID == identity {
		return certificateResult, nil
	}

	if !allowAuthorizationID {
		return &SASLAuthResult{Success: false, Reason: externalAuthorizationDeniedReason}, nil
	}

	return authorizeExternalIdentity(ctx, authenticator, authorizationID, req, certificateResult)
}

func authorizeExternalIdentity(
	ctx context.Context,
	authenticator SASLAuthenticator,
	authorizationID string,
	req *DovecotAuthRequest,
	certificateResult *SASLAuthResult,
) (*SASLAuthResult, error) {
	authorizationResult, err := authenticator.LookupIdentity(ctx, authorizationID, req)
	if err != nil {
		return nil, err
	}

	if authorizationResult == nil {
		return &SASLAuthResult{Success: false, Reason: emptyIdentityLookupReason, Temporary: true}, nil
	}

	authorizationResult = validateCanonicalSASLResult(authorizationResult, true)

	if !authorizationResult.Success && authorizationResult.Temporary {
		return &SASLAuthResult{Success: false, Reason: "identity lookup temporarily unavailable", Temporary: true}, nil
	}

	if !authorizationResult.Success {
		return &SASLAuthResult{Success: false, Reason: externalAuthorizationDeniedReason}, nil
	}

	if authorizationResult.Username != certificateResult.Username {
		return &SASLAuthResult{Success: false, Reason: externalAuthorizationDeniedReason}, nil
	}

	return certificateResult, nil
}

func requireCanonicalExternalResult(result *SASLAuthResult) *SASLAuthResult {
	if result == nil {
		return &SASLAuthResult{Success: false, Reason: emptyIdentityLookupReason, Temporary: true}
	}

	if !result.Success {
		return result
	}

	if !validDovecotCanonicalAccount(result.Username) {
		return &SASLAuthResult{Success: false, Reason: missingCanonicalAccountReason, Temporary: true}
	}

	return nil
}

// validateExternalCertificateContext accepts only the explicit metadata
// contract emitted by the trusted Postfix TLS terminator. The singular SAN
// field and decoder duplicate checks make ambiguous certificate identities
// fail closed before any passwordless backend lookup occurs.
func validateExternalCertificateContext(req *DovecotAuthRequest) (string, error) {
	if req == nil || req.SSLClientVerify != tlsClientVerifySuccess {
		return "", errExternalCertificateUnverified
	}

	identity := req.SSLClientSANEmail
	if !validRFC822SANIdentity(identity) {
		return "", errExternalIdentityUnavailable
	}

	fingerprint, ok := normalizeClientCertificateFingerprint(req.SSLClientFingerprint)
	if !ok {
		return "", errExternalFingerprintInvalid
	}

	if req.SSLFingerprint != "" {
		legacyFingerprint, valid := normalizeClientCertificateFingerprint(req.SSLFingerprint)
		if !valid || legacyFingerprint != fingerprint {
			return "", errExternalFingerprintInvalid
		}
	}

	req.SSLClientSANEmail = identity
	req.SSLClientFingerprint = fingerprint

	return identity, nil
}

func validRFC822SANIdentity(identity string) bool {
	if identity == "" || len(identity) > 254 || strings.TrimSpace(identity) != identity {
		return false
	}

	for i := range len(identity) {
		if identity[i] < 0x21 || identity[i] > 0x7e {
			return false
		}
	}

	at := strings.LastIndexByte(identity, '@')
	if at <= 0 || at == len(identity)-1 {
		return false
	}

	address, err := mail.ParseAddress(identity)

	return err == nil && address.Name == "" && address.Address == identity
}

// normalizeClientCertificateFingerprint accepts SHA-256, SHA-384, or SHA-512
// fingerprints in compact or colon-delimited hexadecimal form. SHA-1 and
// shorter digests are deliberately rejected for this authentication boundary.
func normalizeClientCertificateFingerprint(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}

	compact := value
	if strings.Contains(value, ":") {
		groups := strings.Split(value, ":")
		for _, group := range groups {
			if len(group) != 2 {
				return "", false
			}
		}

		compact = strings.Join(groups, "")
	}

	switch len(compact) {
	case 64, 96, 128:
	default:
		return "", false
	}

	if _, err := hex.DecodeString(compact); err != nil {
		return "", false
	}

	return strings.ToLower(compact), true
}
