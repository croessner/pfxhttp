package main

import (
	"math"
	"testing"
)

func TestConvertResponse(t *testing.T) {
	tests := []struct {
		name     string
		rawValue any
		level    uint16
		expected string
	}{
		{
			name:     "bool true",
			rawValue: true,
			level:    0,
			expected: "true",
		},
		{
			name:     "bool false",
			rawValue: false,
			level:    0,
			expected: "false",
		},
		{
			name:     "float64",
			rawValue: 3.14,
			level:    0,
			expected: "3.140000",
		},
		{
			name:     "string",
			rawValue: "hello",
			level:    0,
			expected: "hello",
		},
		{
			name:     "string slice",
			rawValue: []string{"hello", "world"},
			level:    0,
			expected: "hello,world",
		},
		{
			name:     "nil value",
			rawValue: nil,
			level:    0,
			expected: "",
		},
		{
			name:     "nested any",
			rawValue: any("nested"),
			level:    0,
			expected: "nested",
		},
		{
			name:     "nested slice of any",
			rawValue: []any{"a", 1.23, true},
			level:    0,
			expected: "a,1.230000,true",
		},
		{
			name:     "empty string slice",
			rawValue: []string{},
			level:    0,
			expected: "",
		},
		{
			name:     "empty any slice",
			rawValue: []any{},
			level:    0,
			expected: "",
		},
		{
			name:     "unsupported type",
			rawValue: struct{}{},
			level:    0,
			expected: "",
		},
		{
			name:     "max level reached",
			rawValue: "test",
			level:    math.MaxUint16,
			expected: "",
		},
		{
			name:     "deep recursion",
			rawValue: []any{[]any{[]any{"deep"}}},
			level:    0,
			expected: "deep",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := convertResponse(tc.rawValue, tc.level)
			if result != tc.expected {
				t.Errorf("expected: %s, got: %s", tc.expected, result)
			}
		})
	}
}

func TestFindKeyInResponse(t *testing.T) {
	tests := []struct {
		name           string
		responseData   map[string]any
		searchKey      string
		expectedValue  any
		expectedExists bool
	}{
		{
			name: "key exists at root",
			responseData: map[string]any{
				"key1": "value1",
				"key2": "value2",
			},
			searchKey:      "key1",
			expectedValue:  "value1",
			expectedExists: true,
		},
		{
			name: "key exists in nested map",
			responseData: map[string]any{
				"key1": map[string]any{
					"nestedKey": "nestedValue",
				},
			},
			searchKey:      "nestedKey",
			expectedValue:  "nestedValue",
			expectedExists: true,
		},
		{
			name: "key does not exist",
			responseData: map[string]any{
				"key1": "value1",
			},
			searchKey:      "missingKey",
			expectedValue:  nil,
			expectedExists: false,
		},
		{
			name:           "empty map",
			responseData:   map[string]any{},
			searchKey:      "key1",
			expectedValue:  nil,
			expectedExists: false,
		},
		{
			name: "nested map with missing key",
			responseData: map[string]any{
				"key1": map[string]any{
					"nestedKey": "nestedValue",
				},
			},
			searchKey:      "missingKey",
			expectedValue:  nil,
			expectedExists: false,
		},
		{
			name: "multiple levels of nesting key present",
			responseData: map[string]any{
				"key1": map[string]any{
					"nestedKey1": map[string]any{
						"nestedKey2": "finalValue",
					},
				},
			},
			searchKey:      "nestedKey2",
			expectedValue:  "finalValue",
			expectedExists: true,
		},
		{
			name: "multiple levels of nesting key missing",
			responseData: map[string]any{
				"key1": map[string]any{
					"nestedKey1": map[string]any{
						"nestedKey2": "finalValue",
					},
				},
			},
			searchKey:      "nestedKey3",
			expectedValue:  nil,
			expectedExists: false,
		},
		{
			name: "non-map value at intermediate level",
			responseData: map[string]any{
				"key1": "nonMapValue",
			},
			searchKey:      "nestedKey",
			expectedValue:  nil,
			expectedExists: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, exists := getNestedValue(tc.responseData, tc.searchKey, 0)
			if exists != tc.expectedExists || result != tc.expectedValue {
				t.Errorf("expected: (%v, %v), got: (%v, %v)", tc.expectedValue, tc.expectedExists, result, exists)
			}
		})
	}
}
