package proxy

import (
	"net"
	"strings"
	"testing"
)

func TestDetectMinMTU(t *testing.T) {
	t.Run("no interfaces returns error", func(t *testing.T) {
		_, err := detectMinMTU(nil)
		if err == nil {
			t.Error("expected error for empty interfaces, got nil")
		}
	})

	t.Run("empty slice returns error", func(t *testing.T) {
		_, err := detectMinMTU([]string{})
		if err == nil {
			t.Error("expected error for empty slice, got nil")
		}
	})

	t.Run("nonexistent interface returns error", func(t *testing.T) {
		_, err := detectMinMTU([]string{"nonexistent_iface_xyz"})
		if err == nil {
			t.Error("expected error for nonexistent interface, got nil")
		}
		if !strings.Contains(err.Error(), "nonexistent_iface_xyz") {
			t.Errorf("error should mention the interface name, got: %v", err)
		}
	})

	t.Run("loopback interface returns valid MTU", func(t *testing.T) {
		loName := "lo"
		if _, err := net.InterfaceByName("lo"); err != nil {
			loName = "lo0"
		}
		mtu, err := detectMinMTU([]string{loName})
		if err != nil {
			t.Fatalf("unexpected error for loopback: %v", err)
		}
		if mtu == 0 {
			t.Error("expected non-zero MTU for loopback")
		}
	})

	t.Run("duplicate interface returns consistent result", func(t *testing.T) {
		loName := "lo"
		if _, err := net.InterfaceByName("lo"); err != nil {
			loName = "lo0"
		}
		mtu1, err := detectMinMTU([]string{loName})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		mtu2, err := detectMinMTU([]string{loName, loName})
		if err != nil {
			t.Fatalf("unexpected error for duplicate interface: %v", err)
		}
		if mtu1 != mtu2 {
			t.Errorf("expected same MTU %d, got %d for duplicate interfaces", mtu1, mtu2)
		}
	})
}
