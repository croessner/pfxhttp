//go:build jwt
// +build jwt

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"PostfixToHTTP/customsql"
)

// JWTToken represents the JWT token response from the token endpoint
type JWTToken struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

// TokenStorage defines the interface for storing and retrieving tokens
type TokenStorage interface {
	// GetToken retrieves a token from storage by its ID
	GetToken(id string) (*JWTToken, error)

	// StoreToken stores a token with the given ID
	StoreToken(id string, token *JWTToken) error

	// Close closes the storage
	Close() error
}

// TokenFetcher defines the interface for fetching tokens from an authentication service
type TokenFetcher interface {
	// FetchToken fetches a new token using the provided authentication details
	FetchToken(jwtAuth JWTAuth) (*JWTToken, error)
}

// TokenManager defines the interface for managing JWT tokens
type TokenManager interface {
	// GetToken retrieves a token for the given request name and authentication details
	GetToken(requestName string, jwtAuth JWTAuth) (string, error)

	// Close closes the token manager and releases any resources
	Close() error
}

// CustomTokenStorageAdapter adapts our customsql.TokenStorage to the TokenStorage interface
type CustomTokenStorageAdapter struct {
	storage *customsql.CustomTokenStorage
}

// NewCustomTokenStorageAdapter creates a new custom token storage adapter
func NewCustomTokenStorageAdapter(dbPath string) (TokenStorage, error) {
	storage, err := customsql.NewCustomTokenStorage(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create custom token storage: %w", err)
	}

	return &CustomTokenStorageAdapter{
		storage: storage.(*customsql.CustomTokenStorage),
	}, nil
}

// GetToken retrieves a token from the custom database
func (s *CustomTokenStorageAdapter) GetToken(id string) (*JWTToken, error) {
	token, err := s.storage.GetToken(id)
	if err != nil {
		return nil, fmt.Errorf("failed to query token: %w", err)
	}

	if token == nil {
		return nil, nil // No token found
	}

	return &JWTToken{
		Token:        token.Token,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.ExpiresAt,
	}, nil
}

// StoreToken stores a token in the custom database
func (s *CustomTokenStorageAdapter) StoreToken(id string, token *JWTToken) error {
	customToken := &customsql.JWTToken{
		Token:        token.Token,
		RefreshToken: token.RefreshToken,
		ExpiresAt:    token.ExpiresAt,
	}

	err := s.storage.StoreToken(id, customToken)
	if err != nil {
		return fmt.Errorf("failed to store token: %w", err)
	}

	return nil
}

// Close closes the custom database connection
func (s *CustomTokenStorageAdapter) Close() error {
	return s.storage.Close()
}

// HTTPTokenFetcher implements TokenFetcher using HTTP requests
type HTTPTokenFetcher struct {
	client *http.Client
}

// NewHTTPTokenFetcher creates a new HTTP token fetcher
func NewHTTPTokenFetcher(client *http.Client) TokenFetcher {
	return &HTTPTokenFetcher{
		client: client,
	}
}

// FetchToken fetches a new JWT token from the token endpoint
func (f *HTTPTokenFetcher) FetchToken(jwtAuth JWTAuth) (*JWTToken, error) {
	var reqBody string
	var contentType string

	// Default to application/x-www-form-urlencoded if not specified
	if jwtAuth.ContentType == "" || jwtAuth.ContentType == "application/x-www-form-urlencoded" {
		data := url.Values{}

		for key, value := range jwtAuth.Credentials {
			data.Set(key, value)
		}

		reqBody = data.Encode()
		contentType = "application/x-www-form-urlencoded"
	} else if jwtAuth.ContentType == "application/json" {
		// Create JSON payload
		jsonData := make(map[string]string)

		// Add credential fields
		for key, value := range jwtAuth.Credentials {
			jsonData[key] = value
		}

		jsonBytes, err := json.Marshal(jsonData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JSON payload: %w", err)
		}

		reqBody = string(jsonBytes)
		contentType = "application/json"
	}

	req, err := http.NewRequest("POST", jwtAuth.TokenEndpoint, strings.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch token: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned non-200 status code: %d", resp.StatusCode)
	}

	var tokenResponse JWTToken

	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResponse, nil
}

// JWTManager handles JWT token fetching, storage, and retrieval
// It uses an in-memory cache to improve performance by reducing database access
// The cacheMutex is used for thread-safe access to the in-memory token cache
type JWTManager struct {
	storage    TokenStorage
	fetcher    TokenFetcher
	tokenCache map[string]*JWTToken // In-memory cache for tokens
	cacheMutex sync.RWMutex         // For thread-safe access to the cache
}

// NewJWTManager creates a new JWT manager with the provided storage and fetcher
func NewJWTManager(storage TokenStorage, fetcher TokenFetcher) TokenManager {
	return &JWTManager{
		storage:    storage,
		fetcher:    fetcher,
		tokenCache: make(map[string]*JWTToken),
	}
}

// GetToken retrieves a JWT token for the given request configuration
// It first checks the in-memory cache for a valid token to avoid storage access
// If no valid token is found in the cache, it checks the storage
// It will fetch a new token if one doesn't exist or if the existing token is expired
// This approach significantly improves performance by reducing storage access
func (m *JWTManager) GetToken(requestName string, jwtAuth JWTAuth) (string, error) {
	if !jwtAuth.Enabled {
		return "", nil
	}

	// First check the in-memory cache
	m.cacheMutex.RLock()
	cachedToken, exists := m.tokenCache[requestName]
	m.cacheMutex.RUnlock()

	// If we have a valid token in the cache, return it
	if exists && time.Now().Unix()+30 < cachedToken.ExpiresAt {
		return cachedToken.Token, nil
	}

	// Check if we have a valid token in the storage
	storedToken, err := m.storage.GetToken(requestName)
	if err != nil {
		return "", err
	}

	if storedToken != nil && time.Now().Unix()+30 < storedToken.ExpiresAt {
		// Update the cache with the token from the storage
		m.cacheMutex.Lock()
		m.tokenCache[requestName] = storedToken
		m.cacheMutex.Unlock()

		return storedToken.Token, nil
	}

	// Token is expired or doesn't exist, fetch a new one
	if storedToken != nil {
		slog.Debug("JWT token expired, refreshing", "requestName", requestName)
	}

	// Fetch a new token
	newToken, err := m.fetcher.FetchToken(jwtAuth)
	if err != nil {
		return "", err
	}

	// Update the cache with the new token
	m.cacheMutex.Lock()
	m.tokenCache[requestName] = newToken
	m.cacheMutex.Unlock()

	// Store the new token in the storage for persistence across restarts
	// Even with the in-memory cache, we still need storage persistence to avoid
	// unnecessary token fetches when the service restarts or when the cache is cleared
	err = m.storage.StoreToken(requestName, newToken)
	if err != nil {
		return "", err
	}

	return newToken.Token, nil
}

// Close closes the JWT manager and releases any resources
func (m *JWTManager) Close() error {
	// Clear the token cache
	m.cacheMutex.Lock()
	m.tokenCache = nil
	m.cacheMutex.Unlock()

	// Close the storage
	return m.storage.Close()
}

// Global JWT manager instance for backward compatibility
var jwtManager TokenManager

// InitJWTManager initializes the JWT manager with the provided configuration
func InitJWTManager(cfg *Config) error {
	if cfg.Server.JWTDBPath == "" {
		// JWT is not configured, return nil
		return nil
	}

	// Create the token storage
	storage, err := NewCustomTokenStorageAdapter(cfg.Server.JWTDBPath)
	if err != nil {
		return err
	}

	// Create the token fetcher
	fetcher := NewHTTPTokenFetcher(httpClient)

	// Create the JWT manager
	jwtManager = NewJWTManager(storage, fetcher)

	return nil
}

// CloseJWTManager closes the JWT manager and releases any resources
func CloseJWTManager() {
	if jwtManager != nil {
		_ = jwtManager.Close()
		jwtManager = nil
	}
}

// GetJWTToken is a helper function to get a JWT token for a request
func GetJWTToken(requestName string, jwtAuth JWTAuth) (string, error) {
	if jwtManager == nil || !jwtAuth.Enabled {
		return "", nil
	}

	return jwtManager.GetToken(requestName, jwtAuth)
}
