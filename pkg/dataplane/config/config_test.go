package config

import (
	"strings"
	"testing"
)

func TestPaddingConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		padding *PaddingConfig
		wantErr string
	}{
		{
			name:    "nil padding config",
			padding: nil,
			wantErr: "",
		},
		{
			name: "disabled padding config",
			padding: &PaddingConfig{
				Enabled: false,
				Size:    0,
			},
			wantErr: "",
		},
		{
			name: "valid padding config",
			padding: &PaddingConfig{
				Enabled: true,
				Size:    32,
			},
			wantErr: "",
		},
		{
			name: "valid padding config min size",
			padding: &PaddingConfig{
				Enabled: true,
				Size:    1,
			},
			wantErr: "",
		},
		{
			name: "valid padding config max size",
			padding: &PaddingConfig{
				Enabled: true,
				Size:    255,
			},
			wantErr: "",
		},
		{
			name: "invalid padding config zero size",
			padding: &PaddingConfig{
				Enabled: true,
				Size:    0,
			},
			wantErr: "padding size must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ProxyConfig{
				Mode:       "forward",
				Interfaces: []string{"eth0"},
				Forward: ForwardConfig{
					Backends: []BackendServer{
						{
							IP: "10.0.0.1",
						},
					},
				},
				Instrumentations: InstrumentationConfig{
					Padding: tt.padding,
				},
			}

			err := cfg.validate("forward")

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestInstrumentationConfig_Combined(t *testing.T) {
	tests := []struct {
		name    string
		instr   InstrumentationConfig
		wantErr string
	}{
		{
			name: "xor and padding both enabled",
			instr: InstrumentationConfig{
				XOR: &XORConfig{
					Enabled: true,
					Key:     "test-key",
				},
				Padding: &PaddingConfig{
					Enabled: true,
					Size:    32,
				},
			},
			wantErr: "",
		},
		{
			name: "xor enabled padding disabled",
			instr: InstrumentationConfig{
				XOR: &XORConfig{
					Enabled: true,
					Key:     "test-key",
				},
				Padding: &PaddingConfig{
					Enabled: false,
					Size:    0,
				},
			},
			wantErr: "",
		},
		{
			name: "xor disabled padding enabled",
			instr: InstrumentationConfig{
				XOR: &XORConfig{
					Enabled: false,
				},
				Padding: &PaddingConfig{
					Enabled: true,
					Size:    64,
				},
			},
			wantErr: "",
		},
		{
			name: "both nil",
			instr: InstrumentationConfig{
				XOR:     nil,
				Padding: nil,
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ProxyConfig{
				Mode:       "forward",
				Interfaces: []string{"eth0"},
				Forward: ForwardConfig{Backends: []BackendServer{
					{
						IP: "10.0.0.1",
					},
				}},
				Instrumentations: tt.instr,
			}

			err := cfg.validate("forward")

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q should contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}
