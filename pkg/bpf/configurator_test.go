package bpf

import (
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestConfigure_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		spec    *ebpf.CollectionSpec
		cfg     interface{}
		wantErr string
	}{
		{
			name:    "nil spec",
			spec:    nil,
			cfg:     &struct{}{},
			wantErr: "spec cannot be nil",
		},
		{
			name:    "nil config",
			spec:    &ebpf.CollectionSpec{Variables: make(map[string]*ebpf.VariableSpec)},
			cfg:     nil,
			wantErr: "config cannot be nil",
		},
		{
			name:    "non-struct config",
			spec:    &ebpf.CollectionSpec{Variables: make(map[string]*ebpf.VariableSpec)},
			cfg:     stringPtr("invalid"),
			wantErr: "config must be a struct",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Configure(tt.spec, tt.cfg)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q should contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestConfigure_MissingVariable(t *testing.T) {
	spec := &ebpf.CollectionSpec{Variables: make(map[string]*ebpf.VariableSpec)}
	cfg := struct {
		Port uint16 `ebpf:"wg_port"`
	}{Port: 51820}

	err := Configure(spec, &cfg)
	if err == nil {
		t.Fatal("expected error for missing variable")
	}
	if !strings.Contains(err.Error(), "__cfg_wg_port") {
		t.Errorf("error should mention __cfg_wg_port, got: %v", err)
	}
}

func TestConfigure_UntaggedFields(t *testing.T) {
	spec := &ebpf.CollectionSpec{Variables: make(map[string]*ebpf.VariableSpec)}
	cfg := struct {
		Untagged1 string
		Untagged2 int
	}{Untagged1: "test", Untagged2: 123}

	if err := Configure(spec, &cfg); err != nil {
		t.Fatalf("untagged fields should be skipped: %v", err)
	}
}

func TestConfigure_NilPointerSetsEnabledFalse(t *testing.T) {
	spec := &ebpf.CollectionSpec{Variables: make(map[string]*ebpf.VariableSpec)}

	type inner struct {
		Enabled bool `ebpf:"feature_enabled"`
	}
	cfg := struct {
		Feature *inner
	}{Feature: nil}

	err := Configure(spec, &cfg)
	if err == nil {
		t.Fatal("expected error for missing __cfg_feature_enabled")
	}
	if !strings.Contains(err.Error(), "__cfg_feature_enabled") {
		t.Errorf("error should mention __cfg_feature_enabled, got: %v", err)
	}
}

func TestParseTag(t *testing.T) {
	tests := []struct {
		tag           string
		wantName      string
		wantTransform string
	}{
		{"port", "port", ""},
		{"key,bytes32", "key", "bytes32"},
		{"name,transform,extra", "name", "transform,extra"},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			name, transform := parseTag(tt.tag)
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if transform != tt.wantTransform {
				t.Errorf("transform = %q, want %q", transform, tt.wantTransform)
			}
		})
	}
}

func TestApplyTransform(t *testing.T) {
	t.Run("bytes32 from string", func(t *testing.T) {
		input := "hello"
		result, err := applyTransform(reflect.ValueOf(input), transformBytes32)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		arr, ok := result.([32]byte)
		if !ok {
			t.Fatalf("expected [32]byte, got %T", result)
		}
		if string(arr[:5]) != input {
			t.Errorf("got %q, want %q", string(arr[:5]), input)
		}
		for i := 5; i < 32; i++ {
			if arr[i] != 0 {
				t.Errorf("expected zero padding at index %d", i)
			}
		}
	})

	t.Run("bytes32 from non-string fails", func(t *testing.T) {
		_, err := applyTransform(reflect.ValueOf(123), transformBytes32)
		if err == nil {
			t.Fatal("expected error for non-string input")
		}
		if !strings.Contains(err.Error(), "requires string") {
			t.Errorf("error should mention 'requires string', got: %v", err)
		}
	})

	t.Run("unknown transform fails", func(t *testing.T) {
		_, err := applyTransform(reflect.ValueOf("test"), "unknown")
		if err == nil {
			t.Fatal("expected error for unknown transform")
		}
		if !strings.Contains(err.Error(), "unknown transform") {
			t.Errorf("error should mention 'unknown transform', got: %v", err)
		}
	})

	t.Run("empty transform passes through", func(t *testing.T) {
		result, err := applyTransform(reflect.ValueOf(42), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != 42 {
			t.Errorf("got %v, want 42", result)
		}
	})
}

func TestConfigure_NestedStruct(t *testing.T) {
	spec := &ebpf.CollectionSpec{Variables: make(map[string]*ebpf.VariableSpec)}

	type XOR struct {
		Enabled bool   `ebpf:"xor_enabled"`
		Key     string `ebpf:"xor_key,bytes32"`
	}
	type Instrumentations struct {
		XOR *XOR
	}
	cfg := struct {
		Instrumentations Instrumentations
	}{
		Instrumentations: Instrumentations{
			XOR: &XOR{Enabled: true, Key: "secret"},
		},
	}

	err := Configure(spec, &cfg)
	if err == nil {
		t.Fatal("expected error for missing variables")
	}
	if !strings.Contains(err.Error(), "__cfg_xor_enabled") {
		t.Errorf("should fail on first nested variable, got: %v", err)
	}
}

func stringPtr(s string) *string { return &s }
