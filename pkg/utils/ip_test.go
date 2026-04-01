package utils

import (
	"testing"
)

func TestIPToUint32(t *testing.T) {
	tests := []struct {
		name        string
		ipStr       string
		expected    uint32
		expectError bool
	}{
		{
			name:        "valid_ipv4",
			ipStr:       "192.168.1.1",
			expected:    0xC0A80101, // 192.168.1.1 in hex
			expectError: false,
		},
		{
			name:        "valid_ipv4_max",
			ipStr:       "255.255.255.255",
			expected:    0xFFFFFFFF,
			expectError: false,
		},
		{
			name:        "invalid_empty",
			ipStr:       "",
			expectError: true,
		},
		{
			name:        "invalid_partial",
			ipStr:       "192.168.1",
			expectError: true,
		},
		{
			name:        "invalid_out_of_range",
			ipStr:       "256.1.1.1",
			expectError: true,
		},
		{
			name:        "invalid_ipv6",
			ipStr:       "::1",
			expectError: true,
		},
		{
			name:        "invalid_ipv6_full",
			ipStr:       "2001:db8::1",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := IPToUint32(tt.ipStr)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for IP %q, but got none", tt.ipStr)
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error for IP %q: %v", tt.ipStr, err)
				return
			}

			if result != tt.expected {
				t.Errorf("IPToUint32(%q) = 0x%08X, expected 0x%08X", tt.ipStr, result, tt.expected)
			}
		})
	}
}
