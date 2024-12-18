package main

import (
	"testing"
)

type MockNetString struct {
	data string
}

func (m *MockNetString) Length() uint16 {
	return 0
}

func (m *MockNetString) Data() []byte {
	return []byte(m.data)
}

func (m *MockNetString) String() string {
	return m.data
}

func TestReadNetString(t *testing.T) {
	tests := []struct {
		name         string
		netString    *MockNetString
		expectErr    bool
		expectedName string
		expectedKey  string
	}{
		{
			name:         "Valid netstring",
			netString:    &MockNetString{data: "username apikey123"},
			expectErr:    false,
			expectedName: "username",
			expectedKey:  "apikey123",
		},
		{
			name:         "Trailing whitespace",
			netString:    &MockNetString{data: "username apikey123 "},
			expectErr:    true,
			expectedName: "",
			expectedKey:  "",
		},
		{
			name:         "Missing space",
			netString:    &MockNetString{data: "usernameapikey123"},
			expectErr:    true,
			expectedName: "",
			expectedKey:  "",
		},
		{
			name:         "Empty strings",
			netString:    &MockNetString{data: ""},
			expectErr:    true,
			expectedName: "",
			expectedKey:  "",
		},
		{
			name:         "Only space",
			netString:    &MockNetString{data: " "},
			expectErr:    true,
			expectedName: "",
			expectedKey:  "",
		},
		{
			name:         "Multiple spaces",
			netString:    &MockNetString{data: "username    apikey123"},
			expectErr:    true,
			expectedName: "",
			expectedKey:  "",
		},
		{
			name:         "Special characters in key",
			netString:    &MockNetString{data: "username @apikey!"},
			expectErr:    false,
			expectedName: "username",
			expectedKey:  "@apikey!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receiver := &PostfixReceiver{}
			err := receiver.ReadNetString(tt.netString)

			if (err != nil) != tt.expectErr {
				t.Errorf("ReadNetString() error = %v, expectErr %v", err, tt.expectErr)
			}

			if !tt.expectErr {
				if receiver.GetName() != tt.expectedName {
					t.Errorf("Expected name %s, got %s", tt.expectedName, receiver.GetName())
				}

				if receiver.GetKey() != tt.expectedKey {
					t.Errorf("Expected key %s, got %s", tt.expectedKey, receiver.GetKey())
				}
			}
		})
	}
}
