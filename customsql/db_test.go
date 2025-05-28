package customsql

import (
	"errors"
	"os"
	"testing"
)

func TestDB_Open(t *testing.T) {
	// Test in-memory database (empty path)
	db, err := Open("")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}

	defer db.Close()

	// Test file-based database
	tempFile := "test_db.tmp"

	defer os.Remove(tempFile) // Clean up after test

	db, err = Open(tempFile)
	if err != nil {
		t.Fatalf("Failed to open file-based database: %v", err)
	}

	defer db.Close()

	// Verify we can execute a query on the database
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS test_table (id TEXT PRIMARY KEY)")
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}
}

func TestDB_Exec_CreateTable(t *testing.T) {
	db, err := Open("")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	defer db.Close()

	// Test CREATE TABLE
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS test_table (id TEXT PRIMARY KEY)")
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Verify the table was created by executing a query on it
	_, err = db.Exec("INSERT INTO test_table (id) VALUES (?)", "test_id")
	if err != nil {
		t.Fatalf("Failed to insert data, table might not exist: %v", err)
	}
}

func TestDB_Exec_Insert(t *testing.T) {
	db, err := Open("")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	defer db.Close()

	// Create table first
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS test_table (id TEXT PRIMARY KEY, value1 TEXT, value2 TEXT)")
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Test INSERT
	result, err := db.Exec("INSERT INTO test_table (id, value1, value2) VALUES (?, ?, ?)", "test_id", "test_value1", "test_value2")
	if err != nil {
		t.Fatalf("Failed to insert data: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		t.Fatalf("Failed to get rows affected: %v", err)
	}

	if rowsAffected != 1 {
		t.Errorf("Expected 1 row affected, got %d", rowsAffected)
	}

	// Verify the data was inserted by querying it
	row := db.QueryRow("SELECT value1, value2 FROM test_table WHERE id = ?", "test_id")

	var value1, value2 string

	err = row.Scan(&value1, &value2)
	if err != nil {
		t.Fatalf("Failed to query inserted data: %v", err)
	}

	if value1 != "test_value1" {
		t.Errorf("Expected value1 to be 'test_value1', got '%s'", value1)
	}

	if value2 != "test_value2" {
		t.Errorf("Expected value2 to be 'test_value2', got '%s'", value2)
	}
}

func TestDB_QueryRow(t *testing.T) {
	db, err := Open("")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	defer db.Close()

	// Create table and insert data
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS test_table (id TEXT PRIMARY KEY, value1 TEXT, value2 TEXT)")
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	_, err = db.Exec("INSERT INTO test_table (id, value1, value2) VALUES (?, ?, ?)", "test_id", "test_value1", "test_value2")
	if err != nil {
		t.Fatalf("Failed to insert data: %v", err)
	}

	// Test QueryRow with existing ID
	row := db.QueryRow("SELECT value1, value2 FROM test_table WHERE id = ?", "test_id")

	var value1, value2 string
	err = row.Scan(&value1, &value2)
	if err != nil {
		t.Fatalf("Failed to scan row: %v", err)
	}

	if value1 != "test_value1" {
		t.Errorf("Expected value1 to be 'test_value1', got '%s'", value1)
	}

	if value2 != "test_value2" {
		t.Errorf("Expected value2 to be 'test_value2', got '%s'", value2)
	}

	// Test QueryRow with non-existent ID
	row = db.QueryRow("SELECT value1 FROM test_table WHERE id = ?", "non_existent_id")

	var value string

	err = row.Scan(&value)
	if err == nil {
		t.Error("Expected error for non-existent ID, got nil")
	}

	if !errors.Is(err, ErrNoRows) {
		t.Errorf("Expected ErrNoRows, got %v", err)
	}
}

func TestDB_Close(t *testing.T) {
	// Test in-memory database
	db, err := Open("")
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	err = db.Close()
	if err != nil {
		t.Fatalf("Failed to close database: %v", err)
	}

	// Verify the database is closed by trying to execute a query
	_, err = db.Exec("CREATE TABLE test_table (id TEXT PRIMARY KEY)")
	if err == nil {
		t.Error("Expected error when executing query on closed database, got nil")
	}

	// Test file-based database
	tempFile := "test_db_close.tmp"

	defer os.Remove(tempFile) // Clean up after test

	db, err = Open(tempFile)
	if err != nil {
		t.Fatalf("Failed to open file-based database: %v", err)
	}

	// Insert some data
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS test_table (id TEXT PRIMARY KEY, value TEXT)")
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	_, err = db.Exec("INSERT INTO test_table (id, value) VALUES (?, ?)", "test_id", "test_value")
	if err != nil {
		t.Fatalf("Failed to insert data: %v", err)
	}

	// Close the database
	err = db.Close()
	if err != nil {
		t.Fatalf("Failed to close database: %v", err)
	}

	// Verify the file exists
	_, err = os.Stat(tempFile)
	if err != nil {
		t.Errorf("Expected database file to exist: %v", err)
	}

	// Verify we can reopen the database and query the data
	db, err = Open(tempFile)
	if err != nil {
		t.Fatalf("Failed to reopen database: %v", err)
	}

	defer db.Close()

	row := db.QueryRow("SELECT value FROM test_table WHERE id = ?", "test_id")

	var value string

	err = row.Scan(&value)
	if err != nil {
		t.Fatalf("Failed to query data after reopening: %v", err)
	}

	if value != "test_value" {
		t.Errorf("Expected value to be 'test_value', got '%s'", value)
	}
}
