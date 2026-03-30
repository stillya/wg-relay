package config

import (
	"os"
	"path/filepath"
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

func TestBackendServer_NameField(t *testing.T) {
	tests := []struct {
		name    string
		backend BackendServer
		wantErr string
	}{
		{
			name: "backend with name",
			backend: BackendServer{
				Name: "backend-1",
				IP:   "10.0.0.1",
				Port: 51820,
			},
			wantErr: "",
		},
		{
			name: "backend without name",
			backend: BackendServer{
				IP:   "10.0.0.2",
				Port: 51820,
			},
			wantErr: "",
		},
		{
			name: "backend with empty name",
			backend: BackendServer{
				Name: "",
				IP:   "10.0.0.3",
				Port: 51820,
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &ProxyConfig{
				Mode:       "forward",
				Interfaces: []string{"eth0"},
				Forward: ForwardConfig{
					Backends: []BackendServer{tt.backend},
				},
				Instrumentations: InstrumentationConfig{},
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

func TestLoad_BackendNames(t *testing.T) {
	tests := []struct {
		name        string
		yamlContent string
		wantErr     string
		validate    func(t *testing.T, cfg *Config)
	}{
		{
			name: "config with named backends",
			yamlContent: `
daemon:
  listen: ":8080"
proxy:
  enabled: true
  mode: forward
  wg_port: 51820
  interfaces:
    - eth0
  forward:
    backends:
      - name: backend-1
        ip: 10.0.0.1
        port: 51820
      - name: backend-2
        ip: 10.0.0.2
        port: 51821
`,
			wantErr: "",
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.Proxy.Forward.Backends) != 2 {
					t.Errorf("expected 2 backends, got %d", len(cfg.Proxy.Forward.Backends))
				}
				if cfg.Proxy.Forward.Backends[0].Name != "backend-1" {
					t.Errorf("expected backend name 'backend-1', got %q", cfg.Proxy.Forward.Backends[0].Name)
				}
				if cfg.Proxy.Forward.Backends[1].Name != "backend-2" {
					t.Errorf("expected backend name 'backend-2', got %q", cfg.Proxy.Forward.Backends[1].Name)
				}
			},
		},
		{
			name: "config with unnamed backends",
			yamlContent: `
daemon:
  listen: ":8080"
proxy:
  enabled: true
  mode: forward
  wg_port: 51820
  interfaces:
    - eth0
  forward:
    backends:
      - ip: 10.0.0.1
        port: 51820
      - ip: 10.0.0.2
        port: 51821
`,
			wantErr: "",
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.Proxy.Forward.Backends) != 2 {
					t.Errorf("expected 2 backends, got %d", len(cfg.Proxy.Forward.Backends))
				}
				if cfg.Proxy.Forward.Backends[0].Name != "" {
					t.Errorf("expected empty backend name, got %q", cfg.Proxy.Forward.Backends[0].Name)
				}
				if cfg.Proxy.Forward.Backends[1].Name != "" {
					t.Errorf("expected empty backend name, got %q", cfg.Proxy.Forward.Backends[1].Name)
				}
			},
		},
		{
			name: "config with mixed named and unnamed backends",
			yamlContent: `
daemon:
  listen: ":8080"
proxy:
  enabled: true
  mode: forward
  wg_port: 51820
  interfaces:
    - eth0
  forward:
    backends:
      - name: primary
        ip: 10.0.0.1
        port: 51820
      - ip: 10.0.0.2
        port: 51821
      - name: tertiary
        ip: 10.0.0.3
        port: 51822
`,
			wantErr: "",
			validate: func(t *testing.T, cfg *Config) {
				if len(cfg.Proxy.Forward.Backends) != 3 {
					t.Errorf("expected 3 backends, got %d", len(cfg.Proxy.Forward.Backends))
				}
				if cfg.Proxy.Forward.Backends[0].Name != "primary" {
					t.Errorf("expected backend name 'primary', got %q", cfg.Proxy.Forward.Backends[0].Name)
				}
				if cfg.Proxy.Forward.Backends[1].Name != "" {
					t.Errorf("expected empty backend name, got %q", cfg.Proxy.Forward.Backends[1].Name)
				}
				if cfg.Proxy.Forward.Backends[2].Name != "tertiary" {
					t.Errorf("expected backend name 'tertiary', got %q", cfg.Proxy.Forward.Backends[2].Name)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")

			err := os.WriteFile(configPath, []byte(tt.yamlContent), 0600)
			if err != nil {
				t.Fatalf("failed to write test config: %v", err)
			}

			cfg, err := Load(configPath)

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if tt.validate != nil && cfg != nil {
					tt.validate(t, cfg)
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
