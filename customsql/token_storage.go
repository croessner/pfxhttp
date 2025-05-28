package customsql

import (
	"errors"
	"fmt"
	"sync"
)

// JWTToken represents the JWT token response from the token endpoint
type JWTToken struct {
	Token        string
	RefreshToken string
	ExpiresAt    int64
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

// CustomTokenStorage implements TokenStorage using our custom SQL implementation
type CustomTokenStorage struct {
	db    *DB
	mutex sync.Mutex // For database operations
}

// NewCustomTokenStorage creates a new custom token storage
func NewCustomTokenStorage(dbPath string) (TokenStorage, error) {
	db, err := Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JWT database: %w", err)
	}

	// Create the tokens table if it doesn't exist
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS tokens (
			id TEXT PRIMARY KEY,
			token TEXT NOT NULL,
			refresh_token TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		)
	`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create tokens table: %w", err)
	}

	return &CustomTokenStorage{
		db: db,
	}, nil
}

// GetToken retrieves a token from the custom database
func (s *CustomTokenStorage) GetToken(id string) (*JWTToken, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var token, refreshToken string
	var expiresAt int64

	row := s.db.QueryRow("SELECT token, refresh_token, expires_at FROM tokens WHERE id = ?", id)
	err := row.Scan(&token, &refreshToken, &expiresAt)
	if err != nil {
		if errors.Is(err, ErrNoRows) {
			return nil, nil // No token found
		}

		return nil, fmt.Errorf("failed to query token: %w", err)
	}

	return &JWTToken{
		Token:        token,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// StoreToken stores a token in the custom database
func (s *CustomTokenStorage) StoreToken(id string, token *JWTToken) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO tokens (id, token, refresh_token, expires_at) VALUES (?, ?, ?, ?)",
		id, token.Token, token.RefreshToken, token.ExpiresAt,
	)

	if err != nil {
		return fmt.Errorf("failed to store token: %w", err)
	}

	return nil
}

// Close closes the custom database connection
func (s *CustomTokenStorage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}

	return nil
}
