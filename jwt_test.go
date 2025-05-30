package main

import (
	"errors"
	"testing"
	"time"
)

// MockTokenStorage is a mock implementation of TokenStorage for testing
type MockTokenStorage struct {
	tokens map[string]*JWTToken
	closed bool
}

// NewMockTokenStorage creates a new mock token storage
func NewMockTokenStorage() *MockTokenStorage {
	return &MockTokenStorage{
		tokens: make(map[string]*JWTToken),
		closed: false,
	}
}

// GetToken retrieves a token from the mock storage
func (s *MockTokenStorage) GetToken(id string) (*JWTToken, error) {
	if s.closed {
		return nil, errors.New("storage is closed")
	}

	token, exists := s.tokens[id]
	if !exists {
		return nil, nil
	}

	return token, nil
}

// StoreToken stores a token in the mock storage
func (s *MockTokenStorage) StoreToken(id string, token *JWTToken) error {
	if s.closed {
		return errors.New("storage is closed")
	}

	s.tokens[id] = token

	return nil
}

// Close marks the mock storage as closed
func (s *MockTokenStorage) Close() error {
	s.closed = true

	return nil
}

// MockTokenFetcher is a mock implementation of TokenFetcher for testing
type MockTokenFetcher struct {
	tokens map[string]*JWTToken
	err    error
}

// NewMockTokenFetcher creates a new mock token fetcher
func NewMockTokenFetcher() *MockTokenFetcher {
	return &MockTokenFetcher{
		tokens: make(map[string]*JWTToken),
	}
}

// SetToken sets a token to be returned for a specific username
func (f *MockTokenFetcher) SetToken(username string, token *JWTToken) {
	f.tokens[username] = token
}

// SetError sets an error to be returned by the fetcher
func (f *MockTokenFetcher) SetError(err error) {
	f.err = err
}

// FetchToken returns a mock token or error
func (f *MockTokenFetcher) FetchToken(jwtAuth JWTAuth) (*JWTToken, error) {
	if f.err != nil {
		return nil, f.err
	}

	// Get the first credential value from the map for testing purposes
	var username string
	for _, value := range jwtAuth.Credentials {
		username = value
		break
	}

	token, exists := f.tokens[username]
	if !exists {
		// Create a default token if none is set for this username
		token = &JWTToken{
			Token:        "mock-token-" + username,
			RefreshToken: "mock-refresh-" + username,
			ExpiresAt:    time.Now().Unix() + 3600, // Valid for 1 hour
		}
	}

	return token, nil
}

func TestJWTManager_GetToken(t *testing.T) {
	// Create mock storage and fetcher
	storage := NewMockTokenStorage()
	fetcher := NewMockTokenFetcher()

	// Create JWT manager
	manager := NewJWTManager(storage, fetcher)

	// Test cases
	tests := []struct {
		name        string
		requestName string
		jwtAuth     JWTAuth
		setupFunc   func()
		wantToken   string
		wantErr     bool
	}{
		{
			name:        "JWT disabled",
			requestName: "test",
			jwtAuth:     JWTAuth{Enabled: false},
			setupFunc:   func() {},
			wantToken:   "",
			wantErr:     false,
		},
		{
			name:        "Token in storage",
			requestName: "test",
			jwtAuth:     JWTAuth{Enabled: true, Credentials: map[string]string{"username": "user1", "password": "pass1"}},
			setupFunc: func() {
				// Store a valid token in storage
				storage.StoreToken("test", &JWTToken{
					Token:        "stored-token",
					RefreshToken: "stored-refresh",
					ExpiresAt:    time.Now().Unix() + 3600, // Valid for 1 hour
				})
			},
			wantToken: "stored-token",
			wantErr:   false,
		},
		{
			name:        "Expired token in storage",
			requestName: "test-expired",
			jwtAuth:     JWTAuth{Enabled: true, Credentials: map[string]string{"username": "user2", "password": "pass2"}},
			setupFunc: func() {
				// Store an expired token in storage
				storage.StoreToken("test-expired", &JWTToken{
					Token:        "expired-token",
					RefreshToken: "expired-refresh",
					ExpiresAt:    time.Now().Unix() - 3600, // Expired 1 hour ago
				})

				// Set up the fetcher to return a specific token
				fetcher.SetToken("user2", &JWTToken{
					Token:        "new-token",
					RefreshToken: "new-refresh",
					ExpiresAt:    time.Now().Unix() + 3600, // Valid for 1 hour
				})
			},
			wantToken: "new-token",
			wantErr:   false,
		},
		{
			name:        "Fetch error",
			requestName: "test-error",
			jwtAuth:     JWTAuth{Enabled: true, Credentials: map[string]string{"username": "user3", "password": "pass3"}},
			setupFunc: func() {
				// Set up the fetcher to return an error
				fetcher.SetError(errors.New("fetch error"))
			},
			wantToken: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset the fetcher error
			fetcher.SetError(nil)

			// Run the setup function
			tt.setupFunc()

			// Call the method being tested
			gotToken, err := manager.GetToken(tt.requestName, tt.jwtAuth)

			// Check the results
			if (err != nil) != tt.wantErr {
				t.Errorf("JWTManager.GetToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if gotToken != tt.wantToken && !tt.wantErr {
				t.Errorf("JWTManager.GetToken() = %v, want %v", gotToken, tt.wantToken)
			}
		})
	}
}

func TestGetJWTToken(t *testing.T) {
	// Save the original jwtManager
	originalManager := jwtManager
	defer func() {
		// Restore the original jwtManager
		jwtManager = originalManager
	}()

	// Create mock storage and fetcher
	storage := NewMockTokenStorage()
	fetcher := NewMockTokenFetcher()

	// Create JWT manager
	jwtManager = NewJWTManager(storage, fetcher)

	// Test with JWT enabled
	token, err := GetJWTToken("test", JWTAuth{Enabled: true, Credentials: map[string]string{"username": "user", "password": "pass"}})
	if err != nil {
		t.Errorf("GetJWTToken() error = %v", err)
	}
	if token == "" {
		t.Errorf("GetJWTToken() returned empty token")
	}

	// Test with JWT disabled
	token, err = GetJWTToken("test", JWTAuth{Enabled: false})
	if err != nil {
		t.Errorf("GetJWTToken() error = %v", err)
	}
	if token != "" {
		t.Errorf("GetJWTToken() returned non-empty token: %v", token)
	}

	// Test with nil jwtManager
	jwtManager = nil
	token, err = GetJWTToken("test", JWTAuth{Enabled: true, Credentials: map[string]string{}})
	if err != nil {
		t.Errorf("GetJWTToken() error = %v", err)
	}
	if token != "" {
		t.Errorf("GetJWTToken() returned non-empty token: %v", token)
	}
}

func TestJWTManager_Close(t *testing.T) {
	// Create mock storage and fetcher
	storage := NewMockTokenStorage()
	fetcher := NewMockTokenFetcher()

	// Create JWT manager
	manager := NewJWTManager(storage, fetcher).(*JWTManager)

	// Add some tokens to the cache
	manager.cacheMutex.Lock()
	manager.tokenCache["test1"] = &JWTToken{Token: "token1"}
	manager.tokenCache["test2"] = &JWTToken{Token: "token2"}
	manager.cacheMutex.Unlock()

	// Close the manager
	err := manager.Close()
	if err != nil {
		t.Errorf("JWTManager.Close() error = %v", err)
	}

	// Verify the cache is cleared
	manager.cacheMutex.RLock()
	if manager.tokenCache != nil {
		t.Errorf("JWTManager.Close() did not clear the token cache")
	}
	manager.cacheMutex.RUnlock()

	// Verify the storage is closed
	if !storage.closed {
		t.Errorf("JWTManager.Close() did not close the storage")
	}
}

func TestInitJWTManager(t *testing.T) {
	// Save the original jwtManager
	originalManager := jwtManager
	defer func() {
		// Restore the original jwtManager
		jwtManager = originalManager
	}()

	// Test with empty JWTDBPath
	cfg := &Config{
		Server: Server{
			JWTDBPath: "",
		},
	}

	err := InitJWTManager(cfg)
	if err != nil {
		t.Errorf("InitJWTManager() error = %v", err)
	}

	if jwtManager != nil {
		t.Errorf("InitJWTManager() should not initialize jwtManager when JWTDBPath is empty")
	}

	// We can't easily test with a valid JWTDBPath in a unit test without mocking more dependencies
	// A more comprehensive test would require integration testing with a real SQLite database
}

func TestCloseJWTManager(t *testing.T) {
	// Save the original jwtManager
	originalManager := jwtManager
	defer func() {
		// Restore the original jwtManager
		jwtManager = originalManager
	}()

	// Test with nil jwtManager
	jwtManager = nil
	CloseJWTManager() // Should not panic

	// Test with a mock manager
	storage := NewMockTokenStorage()
	fetcher := NewMockTokenFetcher()
	jwtManager = NewJWTManager(storage, fetcher)

	CloseJWTManager()

	// Verify jwtManager is nil
	if jwtManager != nil {
		t.Errorf("CloseJWTManager() did not set jwtManager to nil")
	}

	// Verify storage is closed
	if !storage.closed {
		t.Errorf("CloseJWTManager() did not close the storage")
	}
}
