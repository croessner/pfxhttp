package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// SASLAuthResult represents the outcome of a SASL authentication attempt.
type SASLAuthResult struct {
	// Success indicates if authentication was successful.
	Success bool

	// Username is the authenticated username (set on success).
	Username string

	// Reason is a human-readable failure reason (set on failure).
	Reason string

	// Temporary indicates a temporary failure (backend error); client may retry.
	Temporary bool

	// NeedContinuation indicates that the mechanism needs more data from the client.
	NeedContinuation bool

	// ContinuationChallenge is the challenge data to send in a CONT response.
	ContinuationChallenge []byte
}

// SASLCredentials holds extracted credentials from a SASL mechanism exchange.
type SASLCredentials struct {
	// Username is the authentication identity.
	Username string

	// Password is the plaintext password (for PLAIN/LOGIN).
	Password string

	// Token is the OAuth token (for XOAUTH2/OAUTHBEARER).
	Token string

	// AuthzID is the authorization identity (optional).
	AuthzID string
}

// SASLMechanism defines the interface for SASL authentication mechanisms.
// Each mechanism handles its own credential extraction and multi-step exchanges.
type SASLMechanism interface {
	// Name returns the SASL mechanism name (e.g., "PLAIN", "LOGIN").
	Name() string

	// Start begins authentication with an optional initial response.
	// Returns an auth result that may indicate success, failure, or continuation needed.
	Start(initialResponse []byte) (*SASLAuthResult, *SASLCredentials)

	// Continue handles continuation data in a multi-step exchange.
	// Returns an auth result that may indicate success, failure, or further continuation.
	Continue(data []byte) (*SASLAuthResult, *SASLCredentials)
}

// PlainMechanism implements the PLAIN SASL mechanism (RFC 4616).
//
// The PLAIN mechanism expects credentials in the format:
// [authzid] NUL authcid NUL passwd
// where NUL is the zero byte (0x00).
type PlainMechanism struct{}

// Name returns "PLAIN".
func (m *PlainMechanism) Name() string { return "PLAIN" }

// Start parses the initial response containing the PLAIN credentials.
// Returns extracted credentials or requests continuation if no initial response was provided.
func (m *PlainMechanism) Start(initialResponse []byte) (*SASLAuthResult, *SASLCredentials) {
	if len(initialResponse) == 0 {
		return &SASLAuthResult{
			NeedContinuation:      true,
			ContinuationChallenge: []byte{},
		}, nil
	}

	return m.parseCredentials(initialResponse)
}

// Continue handles the continuation response containing PLAIN credentials.
func (m *PlainMechanism) Continue(data []byte) (*SASLAuthResult, *SASLCredentials) {
	return m.parseCredentials(data)
}

// parseCredentials extracts username and password from PLAIN mechanism data.
func (m *PlainMechanism) parseCredentials(data []byte) (*SASLAuthResult, *SASLCredentials) {
	// PLAIN format: [authzid] NUL authcid NUL passwd
	parts := bytes.Split(data, []byte{0})
	if len(parts) != 3 {
		return &SASLAuthResult{
			Success: false,
			Reason:  "invalid PLAIN data format",
		}, nil
	}

	creds := &SASLCredentials{
		AuthzID:  string(parts[0]),
		Username: string(parts[1]),
		Password: string(parts[2]),
	}

	if creds.Username == "" || creds.Password == "" {
		return &SASLAuthResult{
			Success: false,
			Reason:  "empty username or password",
		}, nil
	}

	return nil, creds
}

var _ SASLMechanism = (*PlainMechanism)(nil)

// LoginMechanism implements the LOGIN SASL mechanism.
//
// LOGIN is a deprecated mechanism that uses a two-step challenge-response exchange:
// Step 1: Server sends "Username:" challenge, client responds with username
// Step 2: Server sends "Password:" challenge, client responds with password
type LoginMechanism struct {
	username string
	step     int
}

// Name returns "LOGIN".
func (m *LoginMechanism) Name() string { return "LOGIN" }

// Start begins the LOGIN exchange. If an initial response is provided, it is treated
// as the username; otherwise a "Username:" challenge is sent.
func (m *LoginMechanism) Start(initialResponse []byte) (*SASLAuthResult, *SASLCredentials) {
	if len(initialResponse) > 0 {
		m.username = string(initialResponse)
		m.step = 1

		return &SASLAuthResult{
			NeedContinuation:      true,
			ContinuationChallenge: []byte("Password:"),
		}, nil
	}

	m.step = 0

	return &SASLAuthResult{
		NeedContinuation:      true,
		ContinuationChallenge: []byte("Username:"),
	}, nil
}

// Continue handles each step of the LOGIN exchange.
func (m *LoginMechanism) Continue(data []byte) (*SASLAuthResult, *SASLCredentials) {
	switch m.step {
	case 0:
		// Received username
		m.username = string(data)
		m.step = 1

		return &SASLAuthResult{
			NeedContinuation:      true,
			ContinuationChallenge: []byte("Password:"),
		}, nil

	case 1:
		// Received password
		password := string(data)
		if m.username == "" || password == "" {
			return &SASLAuthResult{
				Success: false,
				Reason:  "empty username or password",
			}, nil
		}

		return nil, &SASLCredentials{
			Username: m.username,
			Password: password,
		}

	default:
		return &SASLAuthResult{
			Success: false,
			Reason:  "unexpected LOGIN continuation",
		}, nil
	}
}

var _ SASLMechanism = (*LoginMechanism)(nil)

// XOAuth2Mechanism implements the XOAUTH2 SASL mechanism.
//
// XOAUTH2 uses a single initial response containing the OAuth2 bearer token:
// Format: "user=" <user> "\x01auth=Bearer " <token> "\x01\x01"
type XOAuth2Mechanism struct{}

// Name returns "XOAUTH2".
func (m *XOAuth2Mechanism) Name() string { return "XOAUTH2" }

// Start parses the initial XOAUTH2 response containing user and token.
func (m *XOAuth2Mechanism) Start(initialResponse []byte) (*SASLAuthResult, *SASLCredentials) {
	if len(initialResponse) == 0 {
		return &SASLAuthResult{
			NeedContinuation:      true,
			ContinuationChallenge: []byte{},
		}, nil
	}

	return m.parseToken(initialResponse)
}

// Continue handles continuation data for XOAUTH2.
func (m *XOAuth2Mechanism) Continue(data []byte) (*SASLAuthResult, *SASLCredentials) {
	return m.parseToken(data)
}

// parseToken extracts user and token from the XOAUTH2 format.
func (m *XOAuth2Mechanism) parseToken(data []byte) (*SASLAuthResult, *SASLCredentials) {
	// Format: "user=" <user> "\x01auth=Bearer " <token> "\x01\x01"
	str := string(data)
	parts := strings.Split(str, "\x01")

	var user, token string

	for _, part := range parts {
		if after, found := strings.CutPrefix(part, "user="); found {
			user = after
		} else if after, found := strings.CutPrefix(part, "auth=Bearer "); found {
			token = after
		} else if after, found := strings.CutPrefix(part, "auth=bearer "); found {
			token = after
		}
	}

	if user == "" || token == "" {
		return &SASLAuthResult{
			Success: false,
			Reason:  "invalid XOAUTH2 data format",
		}, nil
	}

	return nil, &SASLCredentials{
		Username: user,
		Token:    token,
	}
}

var _ SASLMechanism = (*XOAuth2Mechanism)(nil)

// OAuthBearerMechanism implements the OAUTHBEARER SASL mechanism (RFC 7628).
//
// OAUTHBEARER uses a GS2 header followed by key-value pairs:
// Format: "n,a=<authzid>,\x01auth=Bearer <token>\x01\x01" or
//
//	"n,,\x01auth=Bearer <token>\x01\x01"
type OAuthBearerMechanism struct{}

// Name returns "OAUTHBEARER".
func (m *OAuthBearerMechanism) Name() string { return "OAUTHBEARER" }

// Start parses the initial OAUTHBEARER response.
func (m *OAuthBearerMechanism) Start(initialResponse []byte) (*SASLAuthResult, *SASLCredentials) {
	if len(initialResponse) == 0 {
		return &SASLAuthResult{
			NeedContinuation:      true,
			ContinuationChallenge: []byte{},
		}, nil
	}

	return m.parseToken(initialResponse)
}

// Continue handles continuation data for OAUTHBEARER.
func (m *OAuthBearerMechanism) Continue(data []byte) (*SASLAuthResult, *SASLCredentials) {
	return m.parseToken(data)
}

// parseToken extracts the bearer token from OAUTHBEARER format.
func (m *OAuthBearerMechanism) parseToken(data []byte) (*SASLAuthResult, *SASLCredentials) {
	str := string(data)

	// GS2 header: "n,a=<authzid>," or "n,,"
	gs2End := strings.Index(str, ",")
	if gs2End == -1 {
		return &SASLAuthResult{
			Success: false,
			Reason:  "invalid OAUTHBEARER data: missing GS2 header",
		}, nil
	}

	// Find the second comma (end of GS2 header)
	rest := str[gs2End+1:]
	commaIdx := strings.Index(rest, ",")
	if commaIdx == -1 {
		return &SASLAuthResult{
			Success: false,
			Reason:  "invalid OAUTHBEARER data: incomplete GS2 header",
		}, nil
	}

	authzIDPart := rest[:commaIdx]
	kvPart := rest[commaIdx+1:]

	var authzID string

	if after, found := strings.CutPrefix(authzIDPart, "a="); found {
		authzID = after
	}

	// Parse key-value pairs separated by \x01
	var token string

	parts := strings.Split(kvPart, "\x01")
	for _, part := range parts {
		if after, found := strings.CutPrefix(part, "auth=Bearer "); found {
			token = after
		} else if after, found := strings.CutPrefix(part, "auth=bearer "); found {
			token = after
		}
	}

	if token == "" {
		return &SASLAuthResult{
			Success: false,
			Reason:  "invalid OAUTHBEARER data: missing bearer token",
		}, nil
	}

	return nil, &SASLCredentials{
		Username: authzID,
		Token:    token,
		AuthzID:  authzID,
	}
}

var _ SASLMechanism = (*OAuthBearerMechanism)(nil)

// NewSASLMechanism creates a new SASL mechanism handler for the given mechanism name.
// Returns nil if the mechanism is not supported.
func NewSASLMechanism(name string) SASLMechanism {
	switch strings.ToUpper(name) {
	case "PLAIN":
		return &PlainMechanism{}
	case "LOGIN":
		return &LoginMechanism{}
	case "XOAUTH2":
		return &XOAuth2Mechanism{}
	case "OAUTHBEARER":
		return &OAuthBearerMechanism{}
	default:
		return nil
	}
}

// IsOAuthMechanism returns true if the given mechanism name is an OAuth-based mechanism.
func IsOAuthMechanism(mechanism string) bool {
	switch strings.ToUpper(mechanism) {
	case "XOAUTH2", "OAUTHBEARER":
		return true
	default:
		return false
	}
}

// SASLAuthenticator defines the interface for performing authentication against a backend.
type SASLAuthenticator interface {
	// AuthenticatePassword validates username/password credentials against the backend.
	AuthenticatePassword(ctx context.Context, username, password string, req *DovecotAuthRequest) (*SASLAuthResult, error)

	// AuthenticateToken validates an OAuth token via introspection.
	AuthenticateToken(ctx context.Context, username, token string, req *DovecotAuthRequest) (*SASLAuthResult, error)
}

// NauthilusSASLAuthenticator authenticates SASL credentials against a Nauthilus HTTP backend
// for password-based mechanisms and performs OAuth2 token introspection for token-based mechanisms.
type NauthilusSASLAuthenticator struct {
	config *Config
	name   string
}

// AuthenticatePassword sends the credentials to the Nauthilus HTTP backend.
func (a *NauthilusSASLAuthenticator) AuthenticatePassword(ctx context.Context, username, password string, req *DovecotAuthRequest) (*SASLAuthResult, error) {
	settings, ok := a.config.DovecotSASL[a.name]
	if !ok {
		return nil, fmt.Errorf("dovecot_sasl settings not found for '%s'", a.name)
	}

	if settings.Target == "" {
		return nil, errors.New("target URL is not specified")
	}

	payload := map[string]string{
		"username": username,
		"password": password,
		"service":  req.Service,
	}

	if req.RemoteIP != "" {
		payload["client_ip"] = req.RemoteIP
	}

	if req.LocalIP != "" {
		payload["local_ip"] = req.LocalIP
	}

	if req.RemotePort != "" {
		payload["client_port"] = req.RemotePort
	}

	if req.LocalPort != "" {
		payload["local_port"] = req.LocalPort
	}

	if req.Secured {
		payload["secured"] = "true"
	}
	if req.LocalName != "" {
		payload["local_name"] = req.LocalName
	}
	if req.User != "" {
		payload["user"] = req.User
	}
	if req.NoLogin {
		payload["nologin"] = "true"
	}
	if req.NoPenalty {
		payload["no_penalty"] = "true"
	}
	if req.SSLProtocol != "" {
		payload["ssl_protocol"] = req.SSLProtocol
	}
	if req.SSLCipher != "" {
		payload["ssl_cipher"] = req.SSLCipher
	}
	if req.SSLCipherBits != "" {
		payload["ssl_cipher_bits"] = req.SSLCipherBits
	}
	if req.SSLPXTID != "" {
		payload["ssl_pxt_id"] = req.SSLPXTID
	}
	if req.ClientID != "" {
		payload["client_id"] = req.ClientID
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	var bodyReader io.Reader

	if settings.HTTPRequestCompression {
		compressed, err := gzipCompressor.Compress(jsonPayload)
		if err != nil {
			return nil, fmt.Errorf("failed to compress payload: %w", err)
		}

		bodyReader = bytes.NewBuffer(compressed)
	} else {
		bodyReader = bytes.NewBuffer(jsonPayload)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, settings.Target, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	if settings.HTTPRequestCompression {
		httpReq.Header.Set("Content-Encoding", gzipCompressor.Name())
	}

	if settings.HTTPResponseCompression {
		httpReq.Header.Set("Accept-Encoding", gzipCompressor.Name())
	}

	for _, header := range settings.CustomHeaders {
		headerKey, headerValue := splitHeader(header)
		if headerKey != "" && headerValue != "" {
			httpReq.Header.Set(headerKey, headerValue)
		}
	}

	// Add OIDC auth for backend communication
	failed, errMsg, _ := addOIDCAuth(httpReq, a.name, settings.OIDCAuth)
	if failed {
		return &SASLAuthResult{
			Success:   false,
			Reason:    errMsg,
			Temporary: true,
		}, nil
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return &SASLAuthResult{
			Success:   false,
			Reason:    "backend unavailable",
			Temporary: true,
		}, nil
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	return a.handlePasswordResponse(resp, settings)
}

// handlePasswordResponse processes the HTTP response from the Nauthilus backend.
func (a *NauthilusSASLAuthenticator) handlePasswordResponse(resp *http.Response, settings Request) (*SASLAuthResult, error) {
	var reader io.Reader = resp.Body

	if settings.HTTPResponseCompression && strings.EqualFold(resp.Header.Get("Content-Encoding"), gzipCompressor.Name()) {
		zr, err := gzipCompressor.Decompress(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress response: %w", err)
		}

		defer func(zr io.ReadCloser) {
			_ = zr.Close()
		}(zr)

		reader = zr
	}

	bodyBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var responseData map[string]any

	if err = json.Unmarshal(bodyBytes, &responseData); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check error field
	if settings.ErrorField != "" {
		if rawValue, found := getNestedValue(responseData, settings.ErrorField, 0); found {
			value := convertResponse(rawValue, 0)
			if value != "" && settings.NoErrorValue != "" && value != settings.NoErrorValue {
				return &SASLAuthResult{
					Success:   false,
					Reason:    "authentication error",
					Temporary: true,
				}, nil
			}
		}
	}

	if resp.StatusCode != settings.StatusCode {
		return &SASLAuthResult{
			Success: false,
			Reason:  "authentication failed",
		}, nil
	}

	// Extract username from response if available
	username := ""

	if settings.ValueField != "" {
		if rawValue, found := getNestedValue(responseData, settings.ValueField, 0); found {
			username = convertResponse(rawValue, 0)
		}
	}

	return &SASLAuthResult{
		Success:  true,
		Username: username,
	}, nil
}

// AuthenticateToken validates an OAuth2 token via the OIDC introspection endpoint.
func (a *NauthilusSASLAuthenticator) AuthenticateToken(ctx context.Context, username, token string, req *DovecotAuthRequest) (*SASLAuthResult, error) {
	settings, ok := a.config.DovecotSASL[a.name]
	if !ok {
		return nil, fmt.Errorf("dovecot_sasl settings not found for '%s'", a.name)
	}

	if !settings.OIDCAuth.Enabled {
		return &SASLAuthResult{
			Success: false,
			Reason:  "OAuth not configured",
		}, nil
	}

	logger, _ := ctx.Value(loggerKey).(*slog.Logger)

	introspectionEndpoint, err := getIntrospectionEndpoint(ctx, settings.OIDCAuth.ConfigurationURI)
	if err != nil {
		if logger != nil {
			logger.Error("Failed to get introspection endpoint", "error", err)
		}

		return &SASLAuthResult{
			Success:   false,
			Reason:    "introspection endpoint unavailable",
			Temporary: true,
		}, nil
	}

	// Build introspection request
	data := url.Values{}
	data.Set("token", token)
	data.Set("token_type_hint", "access_token")

	// Pass context information from Dovecot
	if req.Service != "" {
		data.Set("service", req.Service)
	}
	if req.RemoteIP != "" {
		data.Set("client_ip", req.RemoteIP)
	}
	if req.LocalIP != "" {
		data.Set("local_ip", req.LocalIP)
	}
	if req.RemotePort != "" {
		data.Set("client_port", req.RemotePort)
	}
	if req.LocalPort != "" {
		data.Set("local_port", req.LocalPort)
	}
	if req.Secured {
		data.Set("secured", "true")
	}
	if req.LocalName != "" {
		data.Set("local_name", req.LocalName)
	}
	if req.User != "" {
		data.Set("user", req.User)
	}
	if req.NoLogin {
		data.Set("nologin", "true")
	}
	if req.NoPenalty {
		data.Set("no_penalty", "true")
	}
	if req.SSLProtocol != "" {
		data.Set("ssl_protocol", req.SSLProtocol)
	}
	if req.SSLCipher != "" {
		data.Set("ssl_cipher", req.SSLCipher)
	}
	if req.SSLCipherBits != "" {
		data.Set("ssl_cipher_bits", req.SSLCipherBits)
	}
	if req.SSLPXTID != "" {
		data.Set("ssl_pxt_id", req.SSLPXTID)
	}
	if req.ClientID != "" {
		data.Set("client_id", req.ClientID)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, introspectionEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create introspection request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Authenticate to the introspection endpoint using client credentials
	if settings.OIDCAuth.ClientSecret != "" {
		httpReq.SetBasicAuth(settings.OIDCAuth.ClientID, settings.OIDCAuth.ClientSecret)
	} else {
		data.Set("client_id", settings.OIDCAuth.ClientID)
		httpReq.Body = io.NopCloser(strings.NewReader(data.Encode()))
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return &SASLAuthResult{
			Success:   false,
			Reason:    "introspection request failed",
			Temporary: true,
		}, nil
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read introspection response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return &SASLAuthResult{
			Success:   false,
			Reason:    "introspection request returned non-200 status",
			Temporary: true,
		}, nil
	}

	var introspectionResult map[string]any

	if err = json.Unmarshal(bodyBytes, &introspectionResult); err != nil {
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	// Check the "active" field
	active, ok := introspectionResult["active"]
	if !ok {
		return &SASLAuthResult{
			Success: false,
			Reason:  "introspection response missing 'active' field",
		}, nil
	}

	activeBool, ok := active.(bool)
	if !ok || !activeBool {
		return &SASLAuthResult{
			Success:  false,
			Username: username,
			Reason:   "token is not active",
		}, nil
	}

	// Extract username from introspection response if available
	resolvedUsername := username

	if sub, ok := introspectionResult["sub"].(string); ok && sub != "" {
		resolvedUsername = sub
	}

	if un, ok := introspectionResult["username"].(string); ok && un != "" {
		resolvedUsername = un
	}

	return &SASLAuthResult{
		Success:  true,
		Username: resolvedUsername,
	}, nil
}

var _ SASLAuthenticator = (*NauthilusSASLAuthenticator)(nil)

// NewNauthilusSASLAuthenticator creates a new authenticator for the given config and service name.
func NewNauthilusSASLAuthenticator(config *Config, name string) SASLAuthenticator {
	return &NauthilusSASLAuthenticator{
		config: config,
		name:   name,
	}
}

// getIntrospectionEndpoint fetches the introspection_endpoint from the OIDC discovery document.
func getIntrospectionEndpoint(ctx context.Context, configurationURI string) (string, error) {
	if oidcManager == nil {
		return "", errors.New("OIDC manager not initialized")
	}

	disc, err := oidcManager.getIntrospectionDiscovery(ctx, configurationURI)
	if err != nil {
		return "", err
	}

	return disc.IntrospectionEndpoint, nil
}
