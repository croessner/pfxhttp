package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
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
	JWKSURI               string `json:"jwks_uri"`
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
	jwks       map[string]*cachedJWKS
	jwksMu     sync.RWMutex
}

var oidcManager *OIDCManager

// InitOIDCManager initializes the OIDC manager
func InitOIDCManager() {
	oidcManager = &OIDCManager{
		httpClient: httpClient,
		tokens:     make(map[string]*OIDCToken),
		discovery:  make(map[string]*OIDCDiscoveryResponse),
		jwks:       make(map[string]*cachedJWKS),
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

	m.discovery[uri] = &d

	return &d, nil
}

func (m *OIDCManager) fetchToken(ctx context.Context, logger *slog.Logger, auth OIDCAuth) (*OIDCToken, error) {
	disc, err := m.getDiscovery(ctx, auth.ConfigurationURI)
	if err != nil {
		return nil, err
	}
	if disc.TokenEndpoint == "" {
		return nil, errors.New("discovery response missing token_endpoint")
	}

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	if len(auth.Scopes) > 0 {
		data.Set("scope", strings.Join(auth.Scopes, " "))
	}

	// Decide authentication method (respect config defaults from HandleConfig)
	authMethod := auth.AuthMethod
	switch authMethod {
	case "private_key_jwt":
		assertion, err := m.createAssertion(auth.ClientID, disc.TokenEndpoint, auth.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create assertion: %w", err)
		}
		data.Set("client_id", auth.ClientID)
		data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		data.Set("client_assertion", assertion)
	case "client_secret_post":
		data.Set("client_id", auth.ClientID)
		data.Set("client_secret", auth.ClientSecret)
	case "client_secret_basic":
		// handled after request creation via SetBasicAuth
	case "none":
		if auth.ClientID != "" {
			data.Set("client_id", auth.ClientID)
		}
	default:
		// Fallback to defaults
		if auth.PrivateKeyFile != "" {
			assertion, err := m.createAssertion(auth.ClientID, disc.TokenEndpoint, auth.PrivateKeyFile)
			if err != nil {
				return nil, fmt.Errorf("failed to create assertion: %w", err)
			}
			data.Set("client_id", auth.ClientID)
			data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
			data.Set("client_assertion", assertion)
		} else if auth.ClientSecret != "" {
			authMethod = "client_secret_basic"
		} else if auth.ClientID != "" {
			data.Set("client_id", auth.ClientID)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, disc.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if authMethod == "client_secret_basic" {
		req.SetBasicAuth(auth.ClientID, auth.ClientSecret)
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

// --- JWKS support ---

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type cachedJWKS struct {
	set       JWKS
	expiresAt time.Time
}

var (
	errTokenNotJWT = errors.New("token is not a JWT")
	errInvalidSig  = errors.New("invalid token signature")
	errNoJWKSURI   = errors.New("jwks_uri not provided by discovery")
)

func (m *OIDCManager) getJWKS(ctx context.Context, jwksURI string, ttl time.Duration) (JWKS, error) {
	// Check cache
	m.jwksMu.RLock()
	c, ok := m.jwks[jwksURI]
	m.jwksMu.RUnlock()
	if ok && time.Now().Before(c.expiresAt) {
		return c.set, nil
	}

	// Fetch
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return JWKS{}, fmt.Errorf("failed to create JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return JWKS{}, fmt.Errorf("JWKS request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return JWKS{}, fmt.Errorf("JWKS returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return JWKS{}, fmt.Errorf("failed to read JWKS: %w", err)
	}
	var set JWKS
	if err := json.Unmarshal(body, &set); err != nil {
		return JWKS{}, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	m.jwksMu.Lock()
	m.jwks[jwksURI] = &cachedJWKS{set: set, expiresAt: time.Now().Add(ttl)}
	m.jwksMu.Unlock()
	return set, nil
}

func (j JWK) publicKey() (any, error) {
	switch j.Kty {
	case "RSA":
		if j.N == "" || j.E == "" {
			return nil, errors.New("JWK missing RSA params")
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			return nil, fmt.Errorf("invalid RSA n: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil {
			return nil, fmt.Errorf("invalid RSA e: %w", err)
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", j.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return nil, fmt.Errorf("invalid EC x: %w", err)
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(j.Y)
		if err != nil {
			return nil, fmt.Errorf("invalid EC y: %w", err)
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
		return pub, nil
	case "OKP": // EdDSA
		xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return nil, fmt.Errorf("invalid EdDSA x: %w", err)
		}
		return ed25519.PublicKey(xBytes), nil
	default:
		return nil, fmt.Errorf("unsupported JWK kty: %s", j.Kty)
	}
}

func (m *OIDCManager) VerifyJWTWithJWKS(ctx context.Context, configurationURI, tokenStr string, ttl time.Duration) (map[string]any, error) {
	if strings.Count(tokenStr, ".") != 2 {
		return nil, errTokenNotJWT
	}
	disc, err := m.getDiscovery(ctx, configurationURI)
	if err != nil {
		return nil, err
	}
	if disc.JWKSURI == "" {
		return nil, errNoJWKSURI
	}
	set, err := m.getJWKS(ctx, disc.JWKSURI, ttl)
	if err != nil {
		return nil, err
	}

	keyfunc := func(t *jwt.Token) (any, error) {
		kidAny, _ := t.Header["kid"]
		kid, _ := kidAny.(string)
		if kid != "" {
			for _, k := range set.Keys {
				if k.Kid == kid {
					return k.publicKey()
				}
			}
		}
		// Fallback: if only one key, try it
		if len(set.Keys) == 1 {
			return set.Keys[0].publicKey()
		}
		return nil, fmt.Errorf("no matching JWK for kid '%s'", kid)
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(tokenStr, &claims, keyfunc)
	if err != nil {
		return nil, errInvalidSig
	}
	if !parsed.Valid {
		return nil, errInvalidSig
	}
	// Basic time checks
	if expAny, ok := claims["exp"]; ok {
		switch v := expAny.(type) {
		case float64:
			if time.Now().Unix() >= int64(v) {
				return nil, errors.New("token expired")
			}
		case json.Number:
			iv, _ := v.Int64()
			if time.Now().Unix() >= iv {
				return nil, errors.New("token expired")
			}
		}
	}
	if nbfAny, ok := claims["nbf"]; ok {
		switch v := nbfAny.(type) {
		case float64:
			if time.Now().Unix() < int64(v) {
				return nil, errors.New("token not yet valid")
			}
		case json.Number:
			iv, _ := v.Int64()
			if time.Now().Unix() < iv {
				return nil, errors.New("token not yet valid")
			}
		}
	}
	// Optional issuer match when discovery provides it
	if disc.Issuer != "" {
		if iss, _ := claims["iss"].(string); iss != "" && iss != disc.Issuer {
			return nil, fmt.Errorf("issuer mismatch: %s", iss)
		}
	}

	// return raw map[string]any
	return map[string]any(claims), nil
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
