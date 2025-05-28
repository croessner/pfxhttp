package customsql

import (
	"os"
	"testing"
	"time"
)

func TestCustomTokenStorage(t *testing.T) {
	// Create a temporary file for testing
	tempFile := "test_token_storage.tmp"
	defer os.Remove(tempFile) // Clean up after test

	// Create a new token storage
	storage, err := NewCustomTokenStorage(tempFile)
	if err != nil {
		t.Fatalf("Failed to create token storage: %v", err)
	}
	defer storage.Close()

	// Test storing a token
	token := &JWTToken{
		Token:        "test-token",
		RefreshToken: "test-refresh-token",
		ExpiresAt:    time.Now().Unix() + 3600, // Valid for 1 hour
	}

	err = storage.StoreToken("test-id", token)
	if err != nil {
		t.Fatalf("Failed to store token: %v", err)
	}

	// Test retrieving the token
	retrievedToken, err := storage.GetToken("test-id")
	if err != nil {
		t.Fatalf("Failed to retrieve token: %v", err)
	}

	if retrievedToken == nil {
		t.Fatal("Expected token to be retrieved, got nil")
	}

	if retrievedToken.Token != token.Token {
		t.Errorf("Expected token to be '%s', got '%s'", token.Token, retrievedToken.Token)
	}

	if retrievedToken.RefreshToken != token.RefreshToken {
		t.Errorf("Expected refresh token to be '%s', got '%s'", token.RefreshToken, retrievedToken.RefreshToken)
	}

	if retrievedToken.ExpiresAt != token.ExpiresAt {
		t.Errorf("Expected expires at to be %d, got %d", token.ExpiresAt, retrievedToken.ExpiresAt)
	}

	// Test retrieving a non-existent token
	nonExistentToken, err := storage.GetToken("non-existent-id")
	if err != nil {
		t.Fatalf("Failed to retrieve non-existent token: %v", err)
	}

	if nonExistentToken != nil {
		t.Errorf("Expected non-existent token to be nil, got %+v", nonExistentToken)
	}

	// Test updating an existing token
	updatedToken := &JWTToken{
		Token:        "updated-token",
		RefreshToken: "updated-refresh-token",
		ExpiresAt:    time.Now().Unix() + 7200, // Valid for 2 hours
	}

	err = storage.StoreToken("test-id", updatedToken)
	if err != nil {
		t.Fatalf("Failed to update token: %v", err)
	}

	// Test retrieving the updated token
	retrievedUpdatedToken, err := storage.GetToken("test-id")
	if err != nil {
		t.Fatalf("Failed to retrieve updated token: %v", err)
	}

	if retrievedUpdatedToken == nil {
		t.Fatal("Expected updated token to be retrieved, got nil")
	}

	if retrievedUpdatedToken.Token != updatedToken.Token {
		t.Errorf("Expected updated token to be '%s', got '%s'", updatedToken.Token, retrievedUpdatedToken.Token)
	}

	if retrievedUpdatedToken.RefreshToken != updatedToken.RefreshToken {
		t.Errorf("Expected updated refresh token to be '%s', got '%s'", updatedToken.RefreshToken, retrievedUpdatedToken.RefreshToken)
	}

	if retrievedUpdatedToken.ExpiresAt != updatedToken.ExpiresAt {
		t.Errorf("Expected updated expires at to be %d, got %d", updatedToken.ExpiresAt, retrievedUpdatedToken.ExpiresAt)
	}

	// Test closing the storage
	err = storage.Close()
	if err != nil {
		t.Fatalf("Failed to close token storage: %v", err)
	}

	// Verify the file exists
	_, err = os.Stat(tempFile)
	if err != nil {
		t.Errorf("Expected token storage file to exist: %v", err)
	}

	// Test reopening the storage and retrieving the token
	reopenedStorage, err := NewCustomTokenStorage(tempFile)
	if err != nil {
		t.Fatalf("Failed to reopen token storage: %v", err)
	}
	defer reopenedStorage.Close()

	retrievedTokenAfterReopen, err := reopenedStorage.GetToken("test-id")
	if err != nil {
		t.Fatalf("Failed to retrieve token after reopen: %v", err)
	}

	if retrievedTokenAfterReopen == nil {
		t.Fatal("Expected token to be retrieved after reopen, got nil")
	}

	if retrievedTokenAfterReopen.Token != updatedToken.Token {
		t.Errorf("Expected token after reopen to be '%s', got '%s'", updatedToken.Token, retrievedTokenAfterReopen.Token)
	}
}
