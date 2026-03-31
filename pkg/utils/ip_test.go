package utils

import (
	"net"
	"strings"
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

func TestDetectMinMTU(t *testing.T) {
	t.Run("no interfaces returns error", func(t *testing.T) {
		_, err := DetectMinMTU(nil)
		if err == nil {
			t.Error("expected error for empty interfaces, got nil")
		}
	})

	t.Run("empty slice returns error", func(t *testing.T) {
		_, err := DetectMinMTU([]string{})
		if err == nil {
			t.Error("expected error for empty slice, got nil")
		}
	})

	t.Run("nonexistent interface returns error", func(t *testing.T) {
		_, err := DetectMinMTU([]string{"nonexistent_iface_xyz"})
		if err == nil {
			t.Error("expected error for nonexistent interface, got nil")
		}
		if !strings.Contains(err.Error(), "nonexistent_iface_xyz") {
			t.Errorf("error should mention the interface name, got: %v", err)
		}
	})

	t.Run("loopback interface returns valid MTU", func(t *testing.T) {
		// lo / lo0 should always exist
		loName := "lo"
		if _, err := net.InterfaceByName("lo"); err != nil {
			loName = "lo0"
		}
		mtu, err := DetectMinMTU([]string{loName})
		if err != nil {
			t.Fatalf("unexpected error for loopback: %v", err)
		}
		if mtu == 0 {
			t.Error("expected non-zero MTU for loopback")
		}
	})

	t.Run("duplicate interface returns consistent result", func(t *testing.T) {
		// Use loopback twice - result should equal its own MTU
		loName := "lo"
		if _, err := net.InterfaceByName("lo"); err != nil {
			loName = "lo0"
		}
		mtu1, err := DetectMinMTU([]string{loName})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mtu2, err := DetectMinMTU([]string{loName, loName})
		if err != nil {
			t.Fatalf("unexpected error for duplicate interface: %v", err)
		}
		if mtu1 != mtu2 {
			t.Errorf("expected same MTU %d, got %d for duplicate interfaces", mtu1, mtu2)
		}
	})
}
