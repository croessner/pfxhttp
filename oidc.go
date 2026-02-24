package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OIDCDiscoveryResponse represents the response from the OpenID configuration endpoint
type OIDCDiscoveryResponse struct {
	Issuer                string `json:"issuer"`
	TokenEndpoint         string `json:"token_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

// OIDCTokenResponse represents the response from the token endpoint
type OIDCTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// OIDCToken represents a cached token with its expiration time
type OIDCToken struct {
	AccessToken string
	ExpiresAt   time.Time
}

// OIDCManager handles fetching and caching of OIDC tokens
type OIDCManager struct {
	httpClient *http.Client
	tokens     map[string]*OIDCToken
	mu         sync.RWMutex
	discovery  map[string]*OIDCDiscoveryResponse
	discMu     sync.RWMutex
}

var oidcManager *OIDCManager

// InitOIDCManager initializes the OIDC manager
func InitOIDCManager() {
	oidcManager = &OIDCManager{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		tokens:    make(map[string]*OIDCToken),
		discovery: make(map[string]*OIDCDiscoveryResponse),
	}
}

// GetToken returns a valid OIDC token for the given configuration
func (m *OIDCManager) GetToken(ctx context.Context, logger *slog.Logger, auth OIDCAuth) (string, error) {
	cacheKey := fmt.Sprintf("%s|%s", auth.ConfigurationURI, auth.ClientID)

	// Check cache
	m.mu.RLock()
	token, ok := m.tokens[cacheKey]
	m.mu.RUnlock()

	if ok && time.Now().Before(token.ExpiresAt.Add(-30*time.Second)) {
		return token.AccessToken, nil
	}

	// Fetch new token
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double check cache after acquiring lock
	token, ok = m.tokens[cacheKey]
	if ok && time.Now().Before(token.ExpiresAt.Add(-30*time.Second)) {
		return token.AccessToken, nil
	}

	logger.Debug("Fetching new OIDC token", "client_id", auth.ClientID)

	newToken, err := m.fetchToken(ctx, logger, auth)
	if err != nil {
		return "", err
	}

	m.tokens[cacheKey] = newToken

	return newToken.AccessToken, nil
}

func (m *OIDCManager) getDiscovery(ctx context.Context, uri string) (*OIDCDiscoveryResponse, error) {
	m.discMu.RLock()
	disc, ok := m.discovery[uri]
	m.discMu.RUnlock()

	if ok {
		return disc, nil
	}

	m.discMu.Lock()
	defer m.discMu.Unlock()

	// Double check
	if disc, ok = m.discovery[uri]; ok {
		return disc, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read discovery body: %w", err)
	}

	var d OIDCDiscoveryResponse
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("failed to decode discovery response: %w", err)
	}

	if d.TokenEndpoint == "" {
		return nil, errors.New("discovery response missing token_endpoint")
	}

	m.discovery[uri] = &d

	return &d, nil
}

func (m *OIDCManager) fetchToken(ctx context.Context, logger *slog.Logger, auth OIDCAuth) (*OIDCToken, error) {
	disc, err := m.getDiscovery(ctx, auth.ConfigurationURI)
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	if len(auth.Scopes) > 0 {
		data.Set("scope", strings.Join(auth.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Authentication method
	if auth.PrivateKeyFile != "" {
		// private_key_jwt
		assertion, err := m.createAssertion(auth.ClientID, disc.TokenEndpoint, auth.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create assertion: %w", err)
		}
		data.Set("client_id", auth.ClientID)
		data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		data.Set("client_assertion", assertion)
		req.Body = io.NopCloser(strings.NewReader(data.Encode()))
	} else if auth.ClientSecret != "" {
		// client_secret_post or basic? Nauthilus supports both. Let's use basic.
		req.SetBasicAuth(auth.ClientID, auth.ClientSecret)
	} else {
		// No secret or private key, just client_id?
		data.Set("client_id", auth.ClientID)
		req.Body = io.NopCloser(strings.NewReader(data.Encode()))
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request returned status %d: %s", resp.StatusCode, string(body))
	}

	var tr OIDCTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	expiresIn := tr.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600 // Default to 1h
	}

	return &OIDCToken{
		AccessToken: tr.AccessToken,
		ExpiresAt:   time.Now().Add(time.Duration(expiresIn) * time.Second),
	}, nil
}

func (m *OIDCManager) createAssertion(clientID, tokenEndpoint, keyFile string) (string, error) {
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return "", fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return "", errors.New("failed to decode PEM block from private key")
	}

	var privKey any
	if block.Type == "RSA PRIVATE KEY" {
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "EC PRIVATE KEY" {
		privKey, err = x509.ParseECPrivateKey(block.Bytes)
	} else {
		privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": tokenEndpoint,
		"exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": fmt.Sprintf("%d", now.UnixNano()),
	}

	var method jwt.SigningMethod
	switch privKey.(type) {
	case *rsa.PrivateKey:
		method = jwt.SigningMethodRS256
	case *ecdsa.PrivateKey:
		method = jwt.SigningMethodES256
	case ed25519.PrivateKey:
		method = jwt.SigningMethodEdDSA
	default:
		return "", fmt.Errorf("unsupported private key type: %T", privKey)
	}

	token := jwt.NewWithClaims(method, claims)
	return token.SignedString(privKey)
}

// getIntrospectionDiscovery fetches the OIDC discovery document and returns it if it contains
// an introspection_endpoint. This is used by OAuth-based SASL mechanisms to validate tokens.
func (m *OIDCManager) getIntrospectionDiscovery(ctx context.Context, configurationURI string) (*OIDCDiscoveryResponse, error) {
	disc, err := m.getDiscovery(ctx, configurationURI)
	if err != nil {
		return nil, err
	}

	if disc.IntrospectionEndpoint == "" {
		return nil, errors.New("discovery response missing introspection_endpoint")
	}

	return disc, nil
}

// addOIDCAuth adds the OIDC Authorization header to the request if OIDC is enabled
func addOIDCAuth(req *http.Request, requestName string, auth OIDCAuth) (bool, string, error) {
	if !auth.Enabled {
		return false, "", nil
	}

	if oidcManager == nil {
		return false, "", errors.New("OIDC manager not initialized")
	}

	// We use the request's context
	logger := req.Context().Value(loggerKey).(*slog.Logger)

	token, err := oidcManager.GetToken(req.Context(), logger, auth)
	if err != nil {
		return false, "", fmt.Errorf("failed to get OIDC token for %s: %w", requestName, err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	return true, token, nil
}
