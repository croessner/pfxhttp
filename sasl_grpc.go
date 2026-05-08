// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"

	authv1 "PostfixToHTTP/proto/auth/v1"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// newSASLAuthenticatorForEntry returns the SASLAuthenticator that matches the
// configured transport for the given dovecot_sasl entry. Unknown or empty
// transports default to the HTTP/JSON authenticator. Configuration validation
// rejects truly unsupported values before this is called.
func newSASLAuthenticatorForEntry(cfg *Config, name string, deps *Deps) SASLAuthenticator {
	httpAuth := NewNauthilusSASLAuthenticator(cfg, name, deps.GetHTTPClient(), deps.GetOIDCManager())

	settings, ok := cfg.DovecotSASL[name]
	if !ok || settings.Transport != transportGRPC {
		return httpAuth
	}

	return NewNauthilusGRPCSASLAuthenticator(cfg, name, deps.GetGRPCConnPool(), deps.GetOIDCManager(), httpAuth)
}

// NauthilusGRPCSASLAuthenticator authenticates SASL credentials by calling
// the Nauthilus gRPC AuthService. It satisfies the SASLAuthenticator
// interface; OAuth-based mechanisms still use HTTP introspection by
// delegating to a sibling HTTP authenticator.
type NauthilusGRPCSASLAuthenticator struct {
	config       *Config
	name         string
	pool         *GRPCConnPool
	oidcManager  *OIDCManager
	httpFallback SASLAuthenticator // used for AuthenticateToken (HTTP introspection / JWKS)
}

// NewNauthilusGRPCSASLAuthenticator builds a gRPC-backed authenticator.
// The httpFallback handles OAuth token validation via the existing HTTP
// path (OIDC introspection / JWKS); only password mechanisms travel over
// gRPC.
func NewNauthilusGRPCSASLAuthenticator(
	config *Config,
	name string,
	pool *GRPCConnPool,
	oidcManager *OIDCManager,
	httpFallback SASLAuthenticator,
) SASLAuthenticator {
	return &NauthilusGRPCSASLAuthenticator{
		config:       config,
		name:         name,
		pool:         pool,
		oidcManager:  oidcManager,
		httpFallback: httpFallback,
	}
}

// AuthenticatePassword performs a username/password authentication via the
// gRPC AuthService.Authenticate RPC. The request is decorated with the
// configured caller credentials (Bearer or Basic).
func (a *NauthilusGRPCSASLAuthenticator) AuthenticatePassword(
	ctx context.Context,
	username, password string,
	req *DovecotAuthRequest,
) (*SASLAuthResult, error) {
	settings, ok := a.config.DovecotSASL[a.name]
	if !ok {
		return nil, fmt.Errorf("dovecot_sasl settings not found for '%s'", a.name)
	}

	if settings.Transport != transportGRPC {
		return nil, fmt.Errorf("dovecot_sasl '%s' is not configured for gRPC transport", a.name)
	}

	logger, _ := ctx.Value(loggerKey).(*slog.Logger)

	conn, err := a.pool.Get(a.name, settings.GRPC)
	if err != nil {
		if logger != nil {
			logger.Error("Failed to obtain gRPC connection",
				slog.String("entry", a.name),
				slog.String("address", settings.GRPC.Address),
				slog.String("error", err.Error()))
		}

		return &SASLAuthResult{Success: false, Reason: "grpc backend unavailable", Temporary: true}, nil
	}

	authCtx, cancel := context.WithTimeout(ctx, effectiveGRPCTimeout(settings.GRPC))
	defer cancel()

	authCtx, err = a.attachOutgoingMetadata(authCtx, settings, logger)
	if err != nil {
		return &SASLAuthResult{Success: false, Reason: err.Error(), Temporary: true}, nil
	}

	grpcReq := buildGRPCAuthRequest(username, password, req, settings.DefaultLocalPort)

	if logger != nil {
		logger.Debug("Outgoing Nauthilus gRPC Authenticate request",
			slog.String("address", settings.GRPC.Address),
			slog.String("username", grpcReq.GetUsername()),
			slog.String("protocol", grpcReq.GetProtocol()),
			slog.String("method", grpcReq.GetMethod()))
	}

	client := authv1.NewAuthServiceClient(conn)

	resp, err := client.Authenticate(authCtx, grpcReq)
	if err != nil {
		return classifyGRPCError(err, logger), nil
	}

	return mapAuthResponse(resp), nil
}

// AuthenticateToken delegates to the HTTP introspection / JWKS fallback so
// OAuth-based mechanisms keep their existing semantics regardless of the
// configured SASL transport.
func (a *NauthilusGRPCSASLAuthenticator) AuthenticateToken(
	ctx context.Context,
	username, token string,
	req *DovecotAuthRequest,
) (*SASLAuthResult, error) {
	if a.httpFallback == nil {
		return &SASLAuthResult{Success: false, Reason: "OAuth fallback not configured"}, nil
	}

	return a.httpFallback.AuthenticateToken(ctx, username, token, req)
}

var _ SASLAuthenticator = (*NauthilusGRPCSASLAuthenticator)(nil)

// attachOutgoingMetadata adds configured gRPC metadata plus caller
// authorization. Static Basic auth is sourced from http_auth_basic; OIDC bearer
// auth is sourced from backend_oidc_auth. custom_headers are intentionally not
// used on the gRPC transport.
func (a *NauthilusGRPCSASLAuthenticator) attachOutgoingMetadata(
	ctx context.Context,
	settings Request,
	logger *slog.Logger,
) (context.Context, error) {
	if len(settings.CustomHeaders) > 0 {
		return ctx, errors.New("custom_headers are HTTP-only for gRPC; use grpc.metadata")
	}
	if settings.BackendOIDCAuth.Enabled && settings.HTTPAuthBasic != "" {
		return ctx, errors.New("http_auth_basic and backend_oidc_auth cannot both be configured")
	}

	configuredMetadata, err := normalizeGRPCMetadata(settings.GRPC.Metadata)
	if err != nil {
		return ctx, fmt.Errorf("invalid grpc.metadata: %w", err)
	}
	for key, values := range configuredMetadata {
		for _, value := range values {
			ctx = metadata.AppendToOutgoingContext(ctx, key, value)
		}
	}

	if settings.BackendOIDCAuth.Enabled {
		if a.oidcManager == nil {
			return ctx, errors.New("OIDC manager not initialized")
		}

		token, err := a.oidcManager.GetToken(ctx, effectiveLogger(logger), settings.BackendOIDCAuth)
		if err != nil {
			return ctx, fmt.Errorf("failed to get OIDC token: %w", err)
		}

		return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token), nil
	}

	if settings.HTTPAuthBasic != "" {
		return metadata.AppendToOutgoingContext(ctx, "authorization", basicAuthorizationValue(settings.HTTPAuthBasic)), nil
	}

	return ctx, nil
}

// effectiveLogger guards against nil loggers passed via context. The OIDC
// manager always expects a non-nil *slog.Logger.
func effectiveLogger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}

	return slog.Default()
}

// buildGRPCAuthRequest maps a Dovecot SASL request and the extracted
// credentials into the gRPC AuthRequest contract. Field names mirror the
// HTTP JSON schema used by the existing HTTP authenticator.
func buildGRPCAuthRequest(
	username, password string,
	req *DovecotAuthRequest,
	defaultLocalPort string,
) *authv1.AuthRequest {
	if req == nil {
		req = &DovecotAuthRequest{}
	}

	out := &authv1.AuthRequest{
		Username:           username,
		Password:           password,
		ClientIp:           req.RemoteIP,
		ClientPort:         req.RemotePort,
		ClientHostname:     cmp.Or(req.ClientHostname, req.LocalName),
		ClientId:           req.ClientID,
		ExternalSessionId:  req.ExternalSessionID,
		UserAgent:          req.UserAgent,
		LocalIp:            req.LocalIP,
		LocalPort:          cmp.Or(req.LocalPort, defaultLocalPort),
		Protocol:           req.Service,
		Method:             req.Mechanism,
		Ssl:                req.SSL,
		SslSessionId:       req.SSLSessionID,
		SslClientVerify:    req.SSLClientVerify,
		SslClientDn:        req.SSLClientDN,
		SslClientCn:        req.SSLClientCN,
		SslIssuer:          req.SSLIssuer,
		SslClientNotbefore: req.SSLClientNotBefore,
		SslClientNotafter:  req.SSLClientNotAfter,
		SslSubjectDn:       req.SSLSubjectDN,
		SslIssuerDn:        req.SSLIssuerDN,
		SslClientSubjectDn: req.SSLClientSubjectDN,
		SslClientIssuerDn:  req.SSLClientIssuerDN,
		SslProtocol:        req.SSLProtocol,
		SslCipher:          req.SSLCipher,
		SslSerial:          req.SSLSerial,
		SslFingerprint:     req.SSLFingerprint,
		OidcCid:            req.OIDCCID,
		AuthLoginAttempt:   req.AuthLoginAttempt,
	}

	if req.Secured && out.Ssl == "" {
		out.Ssl = "on"
	}

	return out
}

// mapAuthResponse converts the gRPC AuthResponse into a SASLAuthResult.
// Username resolution mirrors the HTTP path: when AccountField is set the
// resolved username is taken from Attributes[AccountField].
func mapAuthResponse(resp *authv1.AuthResponse) *SASLAuthResult {
	if resp == nil {
		return &SASLAuthResult{Success: false, Reason: "empty gRPC response", Temporary: true}
	}

	switch resp.GetDecision() {
	case authv1.AuthDecision_AUTH_DECISION_OK:
		return &SASLAuthResult{Success: true, Username: resolveAccountName(resp)}
	case authv1.AuthDecision_AUTH_DECISION_TEMPFAIL:
		return &SASLAuthResult{
			Success:   false,
			Temporary: true,
			Reason:    failureReason(resp),
		}
	case authv1.AuthDecision_AUTH_DECISION_FAIL:
		return &SASLAuthResult{Success: false, Reason: failureReason(resp)}
	default:
		// Fall back to the boolean Ok flag for legacy/unspecified decisions.
		if resp.GetOk() {
			return &SASLAuthResult{Success: true, Username: resolveAccountName(resp)}
		}

		return &SASLAuthResult{Success: false, Reason: failureReason(resp)}
	}
}

// resolveAccountName extracts the canonical account name from the response
// attributes using the AccountField hint, falling back to the original value
// of the "Auth-User" attribute used in the HTTP transport.
func resolveAccountName(resp *authv1.AuthResponse) string {
	attrs := resp.GetAttributes()
	if attrs == nil {
		return ""
	}

	if field := resp.GetAccountField(); field != "" {
		if values, ok := attrs[field]; ok && values != nil && len(values.GetValues()) > 0 {
			return values.GetValues()[0]
		}
	}

	if values, ok := attrs["Auth-User"]; ok && values != nil && len(values.GetValues()) > 0 {
		return values.GetValues()[0]
	}

	return ""
}

// failureReason returns the user-visible reason string from a non-OK
// AuthResponse, preferring StatusMessage over the lower-level Error field.
func failureReason(resp *authv1.AuthResponse) string {
	if msg := resp.GetStatusMessage(); msg != "" {
		return msg
	}

	if e := resp.GetError(); e != "" {
		return e
	}

	return "authentication failed"
}

// classifyGRPCError maps a gRPC error to a SASLAuthResult. Only transport-
// level conditions and infrastructure errors are translated to a temporary
// failure; permission-denied or unauthenticated codes indicate a caller
// configuration issue and are also surfaced as temporary so Postfix retries
// without locking the user out.
func classifyGRPCError(err error, logger *slog.Logger) *SASLAuthResult {
	st, ok := status.FromError(err)
	if !ok {
		return &SASLAuthResult{Success: false, Reason: "grpc transport error", Temporary: true}
	}

	if logger != nil {
		logger.Warn("gRPC AuthService call failed",
			slog.String("code", st.Code().String()),
			slog.String("message", st.Message()))
	}

	switch st.Code() {
	case codes.Unauthenticated, codes.PermissionDenied:
		// caller credentials are wrong: tempfail so admins get an alert
		return &SASLAuthResult{Success: false, Reason: "grpc caller authorization rejected: " + st.Message(), Temporary: true}
	case codes.Unavailable, codes.DeadlineExceeded, codes.Aborted, codes.ResourceExhausted:
		return &SASLAuthResult{Success: false, Reason: "grpc backend unavailable", Temporary: true}
	case codes.Canceled:
		return &SASLAuthResult{Success: false, Reason: "grpc request canceled", Temporary: true}
	case codes.InvalidArgument:
		return &SASLAuthResult{Success: false, Reason: "invalid request: " + st.Message()}
	default:
		return &SASLAuthResult{Success: false, Reason: st.Message(), Temporary: true}
	}
}
