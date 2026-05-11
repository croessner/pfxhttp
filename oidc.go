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
	"go.opentelemetry.io/otel/attribute"
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

const (
	oidcAuthMethodAuto              = "auto"
	oidcAuthMethodClientSecretBasic = "client_secret_basic"
	oidcAuthMethodClientSecretPost  = "client_secret_post"
	oidcAuthMethodNone              = "none"
	oidcAuthMethodPrivateKeyJWT     = "private_key_jwt"
)

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

// NewOIDCManager creates a new OIDCManager with the given HTTP client.
func NewOIDCManager(httpClient *http.Client) *OIDCManager {
	return &OIDCManager{
		httpClient: httpClient,
		tokens:     make(map[string]*OIDCToken),
		discovery:  make(map[string]*OIDCDiscoveryResponse),
		jwks:       make(map[string]*cachedJWKS),
	}
}

// GetToken returns a valid OIDC token for the given configuration
func (m *OIDCManager) GetToken(ctx context.Context, logger *slog.Logger, auth BackendOIDCAuth) (accessToken string, err error) {
	cacheKey := fmt.Sprintf("%s|%s", auth.ConfigurationURI, auth.ClientID)

	ctx, spanObs, span := startInternalSpanFromContext(ctx,
		"OIDC token",
		attribute.String("pfxhttp.component", componentOIDC),
		attribute.String("pfxhttp.oidc.client_id", auth.ClientID),
		attribute.String("pfxhttp.oidc.configuration_uri", auth.ConfigurationURI),
		attribute.String("pfxhttp.oidc.auth_method", oidcAuthMethodLabel(auth.AuthMethod)),
		attribute.Int("pfxhttp.oidc.scope_count", len(auth.Scopes)),
	)
	defer func() {
		finishObservedSpan(spanObs, span, err)
	}()

	// Check cache
	m.mu.RLock()
	token, ok := m.tokens[cacheKey]
	m.mu.RUnlock()

	if ok && time.Now().Before(token.ExpiresAt.Add(-30*time.Second)) {
		setSpanAttributes(span,
			attribute.Bool("pfxhttp.oidc.cache_hit", true),
			attribute.String("pfxhttp.oidc.cache_stage", "read"),
		)
		return token.AccessToken, nil
	}

	// Fetch new token
	_, waitSpanObs, waitSpan := startInternalSpanFromContext(ctx,
		"OIDC token cache wait",
		attribute.String("pfxhttp.component", componentOIDC),
		attribute.String("pfxhttp.oidc.client_id", auth.ClientID),
	)
	m.mu.Lock()
	finishObservedSpan(waitSpanObs, waitSpan, nil)
	defer m.mu.Unlock()

	// Double check cache after acquiring lock
	token, ok = m.tokens[cacheKey]
	if ok && time.Now().Before(token.ExpiresAt.Add(-30*time.Second)) {
		setSpanAttributes(span,
			attribute.Bool("pfxhttp.oidc.cache_hit", true),
			attribute.String("pfxhttp.oidc.cache_stage", "locked"),
		)
		return token.AccessToken, nil
	}

	setSpanAttributes(span,
		attribute.Bool("pfxhttp.oidc.cache_hit", false),
		attribute.String("pfxhttp.oidc.cache_stage", "miss"),
	)

	effectiveLogger(logger).Debug("Fetching new OIDC token", "client_id", auth.ClientID)

	newToken, err := m.fetchToken(ctx, auth)
	if err != nil {
		return "", err
	}

	setSpanAttributes(span, attribute.Int64("pfxhttp.oidc.expires_in_seconds", int64(time.Until(newToken.ExpiresAt).Seconds())))
	m.tokens[cacheKey] = newToken

	return newToken.AccessToken, nil
}

func (m *OIDCManager) getDiscovery(ctx context.Context, uri string) (discovery *OIDCDiscoveryResponse, err error) {
	ctx, spanObs, span := startInternalSpanFromContext(ctx,
		"OIDC discovery",
		attribute.String("pfxhttp.component", componentOIDC),
		attribute.String("pfxhttp.oidc.discovery_uri", uri),
	)
	defer func() {
		finishObservedSpan(spanObs, span, err)
	}()

	m.discMu.RLock()
	disc, ok := m.discovery[uri]
	m.discMu.RUnlock()

	if ok {
		setSpanAttributes(span,
			attribute.Bool("pfxhttp.oidc.cache_hit", true),
			attribute.String("pfxhttp.oidc.cache_stage", "read"),
		)
		return disc, nil
	}

	_, waitSpanObs, waitSpan := startInternalSpanFromContext(ctx,
		"OIDC discovery cache wait",
		attribute.String("pfxhttp.component", componentOIDC),
		attribute.String("pfxhttp.oidc.discovery_uri", uri),
	)
	m.discMu.Lock()
	finishObservedSpan(waitSpanObs, waitSpan, nil)
	defer m.discMu.Unlock()

	// Double check
	if disc, ok = m.discovery[uri]; ok {
		setSpanAttributes(span,
			attribute.Bool("pfxhttp.oidc.cache_hit", true),
			attribute.String("pfxhttp.oidc.cache_stage", "locked"),
		)
		return disc, nil
	}

	setSpanAttributes(span,
		attribute.Bool("pfxhttp.oidc.cache_hit", false),
		attribute.String("pfxhttp.oidc.cache_stage", "miss"),
	)

	d, err := m.fetchDiscoveryDocument(ctx, uri)
	if err != nil {
		return nil, err
	}

	m.discovery[uri] = d
	setSpanAttributes(span,
		attribute.String("pfxhttp.oidc.issuer", d.Issuer),
		attribute.Bool("pfxhttp.oidc.has_token_endpoint", d.TokenEndpoint != ""),
		attribute.Bool("pfxhttp.oidc.has_introspection_endpoint", d.IntrospectionEndpoint != ""),
		attribute.Bool("pfxhttp.oidc.has_jwks_uri", d.JWKSURI != ""),
	)

	return d, nil
}

func (m *OIDCManager) fetchDiscoveryDocument(ctx context.Context, uri string) (*OIDCDiscoveryResponse, error) {
	ctx = ContextWithBackendOperation(ctx, componentOIDC, "discovery")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Default().Error("failed to close discovery response body", "error", cerr)
		}
	}()

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

	return &d, nil
}

func (m *OIDCManager) fetchToken(ctx context.Context, auth BackendOIDCAuth) (token *OIDCToken, err error) {
	ctx, spanObs, span := startInternalSpanFromContext(ctx,
		"OIDC token fetch",
		attribute.String("pfxhttp.component", componentOIDC),
		attribute.String("pfxhttp.oidc.client_id", auth.ClientID),
	)
	defer func() {
		finishObservedSpan(spanObs, span, err)
	}()

	disc, err := m.getDiscovery(ctx, auth.ConfigurationURI)
	if err != nil {
		return nil, err
	}
	if disc.TokenEndpoint == "" {
		return nil, errors.New("discovery response missing token_endpoint")
	}

	setSpanAttributes(span, attribute.String("pfxhttp.oidc.token_endpoint", disc.TokenEndpoint))

	data, authMethod, err := m.prepareTokenRequestData(ctx, auth, disc.TokenEndpoint)
	if err != nil {
		return nil, err
	}

	setSpanAttributes(span, attribute.String("pfxhttp.oidc.auth_method", oidcAuthMethodLabel(authMethod)))

	return m.doTokenRequest(ctx, disc.TokenEndpoint, data, auth, authMethod)
}

func (m *OIDCManager) doTokenRequest(ctx context.Context, tokenEndpoint string, data url.Values, auth BackendOIDCAuth, authMethod string) (*OIDCToken, error) {
	ctx = ContextWithBackendOperation(ctx, componentOIDC, "token")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// Ensure no conflicting Authorization header is present
	req.Header.Del("Authorization")

	if authMethod == oidcAuthMethodClientSecretBasic {
		req.SetBasicAuth(auth.ClientID, auth.ClientSecret)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Default().Error("failed to close token response body", "error", cerr)
		}
	}()

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

func (m *OIDCManager) prepareTokenRequestData(ctx context.Context, auth BackendOIDCAuth, tokenEndpoint string) (url.Values, string, error) {
	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	if len(auth.Scopes) > 0 {
		data.Set("scope", strings.Join(auth.Scopes, " "))
	}

	authMethod := auth.AuthMethod
	switch authMethod {
	case oidcAuthMethodPrivateKeyJWT:
		if err := m.addClientAssertion(ctx, data, auth, tokenEndpoint); err != nil {
			return nil, "", err
		}
	case oidcAuthMethodClientSecretPost:
		data.Set("client_id", auth.ClientID)
		data.Set("client_secret", auth.ClientSecret)
	case oidcAuthMethodClientSecretBasic:
		// handled after request creation via SetBasicAuth
	case oidcAuthMethodNone:
		addClientID(data, auth.ClientID)
	default:
		method, err := m.applyDefaultTokenAuth(ctx, data, auth, tokenEndpoint)
		if err != nil {
			return nil, "", err
		}

		authMethod = method
	}

	return data, authMethod, nil
}

func (m *OIDCManager) applyDefaultTokenAuth(ctx context.Context, data url.Values, auth BackendOIDCAuth, tokenEndpoint string) (string, error) {
	switch {
	case auth.PrivateKeyFile != "":
		if err := m.addClientAssertion(ctx, data, auth, tokenEndpoint); err != nil {
			return "", err
		}

		return oidcAuthMethodPrivateKeyJWT, nil
	case auth.ClientSecret != "":
		return oidcAuthMethodClientSecretBasic, nil
	case auth.ClientID != "":
		addClientID(data, auth.ClientID)

		return oidcAuthMethodNone, nil
	default:
		return oidcAuthMethodAuto, nil
	}
}

func (m *OIDCManager) addClientAssertion(ctx context.Context, data url.Values, auth BackendOIDCAuth, tokenEndpoint string) error {
	assertion, err := m.createAssertion(ctx, auth.ClientID, tokenEndpoint, auth.PrivateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to create assertion: %w", err)
	}

	data.Set("client_id", auth.ClientID)
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", assertion)

	return nil
}

func addClientID(data url.Values, clientID string) {
	if clientID != "" {
		data.Set("client_id", clientID)
	}
}

func (m *OIDCManager) createAssertion(ctx context.Context, clientID, tokenEndpoint, keyFile string) (assertion string, err error) {
	_, spanObs, span := startInternalSpanFromContext(ctx,
		"OIDC client assertion",
		attribute.String("pfxhttp.component", componentOIDC),
		attribute.String("pfxhttp.oidc.client_id", clientID),
	)
	defer func() {
		finishObservedSpan(spanObs, span, err)
	}()

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

	setSpanAttributes(span, attribute.String("pfxhttp.oidc.jwt_alg", method.Alg()))

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

func oidcAuthMethodLabel(method string) string {
	if method == "" {
		return oidcAuthMethodAuto
	}

	return method
}

func (m *OIDCManager) getJWKS(ctx context.Context, jwksURI string, ttl time.Duration) (set JWKS, err error) {
	ctx, spanObs, span := startInternalSpanFromContext(ctx,
		"OIDC JWKS",
		attribute.String("pfxhttp.component", componentOIDC),
		attribute.String("pfxhttp.oidc.jwks_uri", jwksURI),
	)
	defer func() {
		finishObservedSpan(spanObs, span, err)
	}()

	// Check cache
	m.jwksMu.RLock()
	c, ok := m.jwks[jwksURI]
	m.jwksMu.RUnlock()
	if ok && time.Now().Before(c.expiresAt) {
		setSpanAttributes(span,
			attribute.Bool("pfxhttp.oidc.cache_hit", true),
			attribute.String("pfxhttp.oidc.cache_stage", "read"),
		)
		return c.set, nil
	}

	setSpanAttributes(span,
		attribute.Bool("pfxhttp.oidc.cache_hit", false),
		attribute.String("pfxhttp.oidc.cache_stage", "miss"),
	)

	// Fetch
	ctx = ContextWithBackendOperation(ctx, componentOIDC, "jwks")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return JWKS{}, fmt.Errorf("failed to create JWKS request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return JWKS{}, fmt.Errorf("JWKS request failed: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			slog.Default().Error("failed to close JWKS response body", "error", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return JWKS{}, fmt.Errorf("JWKS returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return JWKS{}, fmt.Errorf("failed to read JWKS: %w", err)
	}

	var fetched JWKS
	if err := json.Unmarshal(body, &fetched); err != nil {
		return JWKS{}, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	m.jwksMu.Lock()
	m.jwks[jwksURI] = &cachedJWKS{set: fetched, expiresAt: time.Now().Add(ttl)}
	m.jwksMu.Unlock()
	setSpanAttributes(span, attribute.Int("pfxhttp.oidc.jwks.keys", len(fetched.Keys)))

	return fetched, nil
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
		// Build uncompressed EC point: 0x04 || X || Y (each coordinate padded to curve byte size)
		byteLen := (curve.Params().BitSize + 7) / 8
		point := make([]byte, 1+2*byteLen)
		point[0] = 0x04
		copy(point[1+byteLen-len(xBytes):1+byteLen], xBytes)
		copy(point[1+2*byteLen-len(yBytes):1+2*byteLen], yBytes)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("invalid EC public key: %w", err)
		}
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

func (m *OIDCManager) VerifyJWTWithJWKS(ctx context.Context, configurationURI, tokenStr string, ttl time.Duration) (claims map[string]any, err error) {
	ctx, spanObs, span := startInternalSpanFromContext(ctx,
		"OIDC JWT validation",
		attribute.String("pfxhttp.component", componentOIDC),
		attribute.String("pfxhttp.oidc.configuration_uri", configurationURI),
		attribute.String("pfxhttp.oidc.validation", "jwks"),
	)
	defer func() {
		finishObservedSpan(spanObs, span, err)
	}()

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
		kid, _ := t.Header["kid"].(string)
		setSpanAttributes(span, attribute.Bool("pfxhttp.oidc.jwt_has_kid", kid != ""))

		return jwksPublicKeyForToken(set, t)
	}

	jwtClaims := jwt.MapClaims{}

	parsed, err := jwt.ParseWithClaims(tokenStr, &jwtClaims, keyfunc)
	if err != nil {
		return nil, errInvalidSig
	}
	if !parsed.Valid {
		return nil, errInvalidSig
	}

	setSpanAttributes(span, attribute.Bool("pfxhttp.oidc.jwt_valid", true))

	if err := validateJWTTimeClaims(jwtClaims); err != nil {
		return nil, err
	}

	if err := validateJWTIssuer(jwtClaims, disc.Issuer); err != nil {
		return nil, err
	}

	// return raw map[string]any
	return jwtClaims, nil
}

func jwksPublicKeyForToken(set JWKS, token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)
	if kid != "" {
		for _, key := range set.Keys {
			if key.Kid == kid {
				return key.publicKey()
			}
		}
	}

	if len(set.Keys) == 1 {
		return set.Keys[0].publicKey()
	}

	return nil, fmt.Errorf("no matching JWK for kid '%s'", kid)
}

func validateJWTTimeClaims(claims jwt.MapClaims) error {
	now := time.Now().Unix()
	if expAny, ok := claims["exp"]; ok {
		if expired, ok := claimUnixTimeReached(expAny, now); ok && expired {
			return errors.New("token expired")
		}
	}

	if nbfAny, ok := claims["nbf"]; ok {
		if reached, ok := claimUnixTimeReached(nbfAny, now); ok && !reached {
			return errors.New("token not yet valid")
		}
	}

	return nil
}

func claimUnixTimeReached(value any, now int64) (bool, bool) {
	switch v := value.(type) {
	case float64:
		return now >= int64(v), true
	case json.Number:
		iv, _ := v.Int64()

		return now >= iv, true
	default:
		return false, false
	}
}

func validateJWTIssuer(claims jwt.MapClaims, issuer string) error {
	if issuer == "" {
		return nil
	}

	if iss, _ := claims["iss"].(string); iss != "" && iss != issuer {
		return fmt.Errorf("issuer mismatch: %s", iss)
	}

	return nil
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

// addOIDCAuth adds the OIDC Authorization header to the request if OIDC is enabled.
// The OIDCManager and logger are passed explicitly for dependency injection.
func addOIDCAuth(req *http.Request, requestName string, auth BackendOIDCAuth, mgr *OIDCManager, logger *slog.Logger) (bool, string, error) {
	if !auth.Enabled {
		return false, "", nil
	}

	if mgr == nil {
		return false, "", errors.New("OIDC manager not initialized")
	}

	token, err := mgr.GetToken(req.Context(), logger, auth)
	if err != nil {
		return false, "", fmt.Errorf("failed to get OIDC token for %s: %w", requestName, err)
	}

	// Ensure no conflicting Authorization header is present
	req.Header.Del("Authorization")
	req.Header.Set("Authorization", "Bearer "+token)

	return true, token, nil
}
