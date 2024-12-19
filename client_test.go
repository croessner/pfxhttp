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
