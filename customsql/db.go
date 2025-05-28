package customsql

// #cgo LDFLAGS: -lsqlite3
// #include <sqlite3.h>
// #include <stdlib.h>
// #include <string.h>
import "C"
import (
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

var (
	ErrNoRows = errors.New("sql: no rows in result set")
)

// DB represents a database connection
type DB struct {
	db     *C.sqlite3
	mutex  sync.RWMutex
	closed bool
}

// Row represents a row returned from a query
type Row struct {
	values []interface{}
	err    error
}

// Open opens a database connection
func Open(filePath string) (*DB, error) {
	var db *C.sqlite3
	var cFilePath *C.char

	if filePath == "" {
		cFilePath = C.CString(":memory:")
	} else {
		cFilePath = C.CString(filePath)
	}

	defer C.free(unsafe.Pointer(cFilePath))

	result := C.sqlite3_open(cFilePath, &db)
	if result != C.SQLITE_OK {
		return nil, fmt.Errorf("failed to open database: %v", result)
	}

	return &DB{
		db: db,
	}, nil
}

// Close closes the database connection
func (db *DB) Close() error {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if db.closed {
		return nil
	}

	result := C.sqlite3_close(db.db)
	if result != C.SQLITE_OK {
		return fmt.Errorf("failed to close database: %v", result)
	}

	db.closed = true

	return nil
}

// Exec executes a query without returning any rows
func (db *DB) Exec(query string, args ...interface{}) (Result, error) {
	db.mutex.Lock()
	defer db.mutex.Unlock()

	if db.closed {
		return nil, errors.New("sql: database is closed")
	}

	cQuery := C.CString(query)
	defer C.free(unsafe.Pointer(cQuery))

	var stmt *C.sqlite3_stmt

	result := C.sqlite3_prepare_v2(db.db, cQuery, -1, &stmt, nil)
	if result != C.SQLITE_OK {
		return nil, fmt.Errorf("failed to prepare statement: %v", result)
	}

	defer C.sqlite3_finalize(stmt)

	// Bind parameters
	for i, arg := range args {
		var bindResult C.int

		switch v := arg.(type) {
		case string:
			cStr := C.CString(v)
			bindResult = C.sqlite3_bind_text(stmt, C.int(i+1), cStr, -1, C.SQLITE_TRANSIENT)
			C.free(unsafe.Pointer(cStr))
		case int:
			bindResult = C.sqlite3_bind_int(stmt, C.int(i+1), C.int(v))
		case int64:
			bindResult = C.sqlite3_bind_int64(stmt, C.int(i+1), C.sqlite3_int64(v))
		default:
			return nil, fmt.Errorf("unsupported type for parameter %d: %T", i+1, arg)
		}

		if bindResult != C.SQLITE_OK {
			return nil, fmt.Errorf("failed to bind parameter %d: %v", i+1, bindResult)
		}
	}

	// Execute the statement
	result = C.sqlite3_step(stmt)
	if result != C.SQLITE_DONE && result != C.SQLITE_ROW {
		return nil, fmt.Errorf("failed to execute statement: %v", result)
	}

	// Get the number of rows affected and the last insert ID
	rowsAffected := C.sqlite3_changes(db.db)
	lastInsertId := C.sqlite3_last_insert_rowid(db.db)

	return &sqlResult{
		rowsAffected: int64(rowsAffected),
		lastInsertId: int64(lastInsertId),
	}, nil
}

// QueryRow executes a query that is expected to return at most one row
func (db *DB) QueryRow(query string, args ...interface{}) *Row {
	db.mutex.RLock()
	defer db.mutex.RUnlock()

	if db.closed {
		return &Row{err: errors.New("sql: database is closed")}
	}

	cQuery := C.CString(query)
	defer C.free(unsafe.Pointer(cQuery))

	var stmt *C.sqlite3_stmt

	result := C.sqlite3_prepare_v2(db.db, cQuery, -1, &stmt, nil)
	if result != C.SQLITE_OK {
		return &Row{err: fmt.Errorf("failed to prepare statement: %v", result)}
	}

	defer C.sqlite3_finalize(stmt)

	// Bind parameters
	for i, arg := range args {
		var bindResult C.int

		switch v := arg.(type) {
		case string:
			cStr := C.CString(v)
			bindResult = C.sqlite3_bind_text(stmt, C.int(i+1), cStr, -1, C.SQLITE_TRANSIENT)

			C.free(unsafe.Pointer(cStr))
		case int:
			bindResult = C.sqlite3_bind_int(stmt, C.int(i+1), C.int(v))
		case int64:
			bindResult = C.sqlite3_bind_int64(stmt, C.int(i+1), C.sqlite3_int64(v))
		default:
			return &Row{err: fmt.Errorf("unsupported type for parameter %d: %T", i+1, arg)}
		}

		if bindResult != C.SQLITE_OK {
			return &Row{err: fmt.Errorf("failed to bind parameter %d: %v", i+1, bindResult)}
		}
	}

	// Execute the statement
	result = C.sqlite3_step(stmt)
	if result != C.SQLITE_ROW {
		if result == C.SQLITE_DONE {
			return &Row{err: ErrNoRows}
		}

		return &Row{err: fmt.Errorf("failed to execute statement: %v", result)}
	}

	// Get the column values
	columnCount := int(C.sqlite3_column_count(stmt))
	values := make([]interface{}, columnCount)

	for i := 0; i < columnCount; i++ {
		columnType := C.sqlite3_column_type(stmt, C.int(i))

		switch columnType {
		case C.SQLITE_TEXT:
			cText := C.sqlite3_column_text(stmt, C.int(i))
			values[i] = C.GoString((*C.char)(unsafe.Pointer(cText)))
		case C.SQLITE_INTEGER:
			values[i] = int64(C.sqlite3_column_int64(stmt, C.int(i)))
		case C.SQLITE_FLOAT:
			values[i] = float64(C.sqlite3_column_double(stmt, C.int(i)))
		case C.SQLITE_NULL:
			values[i] = nil
		default:
			return &Row{err: fmt.Errorf("unsupported column type: %v", columnType)}
		}
	}

	return &Row{values: values}
}

// Scan copies the columns from the matched row into the values pointed at by dest
func (r *Row) Scan(dest ...interface{}) error {
	if r.err != nil {
		return r.err
	}

	if len(dest) > len(r.values) {
		return errors.New("sql: not enough columns in row")
	}

	for i, d := range dest {
		switch v := d.(type) {
		case *string:
			if str, ok := r.values[i].(string); ok {
				*v = str
			} else if r.values[i] == nil {
				*v = ""
			} else {
				*v = fmt.Sprintf("%v", r.values[i])
			}
		case *int64:
			if i64, ok := r.values[i].(int64); ok {
				*v = i64
			} else if i, ok := r.values[i].(int); ok {
				*v = int64(i)
			} else if r.values[i] == nil {
				*v = 0
			} else {
				return fmt.Errorf("sql: cannot convert %T to int64", r.values[i])
			}
		default:
			return fmt.Errorf("sql: unsupported Scan destination type: %T", d)
		}
	}

	return nil
}

// Result represents the result of an SQL query execution
type Result interface {
	LastInsertId() (int64, error)
	RowsAffected() (int64, error)
}

type sqlResult struct {
	lastInsertId int64
	rowsAffected int64
}

func (r *sqlResult) LastInsertId() (int64, error) {
	return r.lastInsertId, nil
}

func (r *sqlResult) RowsAffected() (int64, error) {
	return r.rowsAffected, nil
}
