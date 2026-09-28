package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		{
			name: "valid padding mode direct",
			padding: &PaddingConfig{
				Enabled: true,
				Size:    32,
				Mode:    "direct",
			},
			wantErr: "",
		},
		{
			name: "valid padding mode randomize",
			padding: &PaddingConfig{
				Enabled: true,
				Size:    32,
				Mode:    "randomize",
			},
			wantErr: "",
		},
		{
			name: "valid padding mode empty defaults to direct",
			padding: &PaddingConfig{
				Enabled: true,
				Size:    32,
				Mode:    "",
			},
			wantErr: "",
		},
		{
			name: "invalid padding mode",
			padding: &PaddingConfig{
				Enabled: true,
				Size:    32,
				Mode:    "fixed",
			},
			wantErr: "padding mode must be 'direct' or 'randomize'",
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

func TestPaddingConfig_Adaptive(t *testing.T) {
	tests := []struct {
		name         string
		paddingExtra string
		want         bool
	}{
		{"adaptive omitted defaults to true", "", true},
		{"adaptive false", "adaptive: false", false},
		{"adaptive true", "adaptive: true", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yamlContent := fmt.Sprintf(`
daemon:
  listen: ":8080"
proxy:
  enabled: true
  mode: forward
  wg_port: 51820
  interfaces:
    - eth0
  instrumentations:
    padding:
      enabled: true
      size: 32
      %s
  forward:
    backends:
      - ip: 10.0.0.1
`, tt.paddingExtra)

			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "config.yaml")
			if err := os.WriteFile(configPath, []byte(yamlContent), 0600); err != nil {
				t.Fatalf("failed to write test config: %v", err)
			}

			cfg, err := Load(configPath)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := cfg.Proxy.Instrumentations.Padding.Adaptive; got != tt.want {
				t.Errorf("Adaptive = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPaddingConfig_ValidateMTU(t *testing.T) {
	tests := []struct {
		name    string
		padding PaddingConfig
		wantErr string
	}{
		{
			name:    "link MTU zero skips MTU validation",
			padding: PaddingConfig{Size: 200, LinkMTU: 0},
			wantErr: "",
		},
		{
			name:    "padding size less than link MTU is valid",
			padding: PaddingConfig{Size: 100, LinkMTU: 1500},
			wantErr: "",
		},
		{
			name:    "padding size one below link MTU is valid boundary",
			padding: PaddingConfig{Size: 254, LinkMTU: 255},
			wantErr: "",
		},
		{
			name:    "padding size equals link MTU is invalid",
			padding: PaddingConfig{Size: 100, LinkMTU: 100},
			wantErr: "padding size 100 must be less than link MTU 100",
		},
		{
			name:    "padding size exceeds link MTU is invalid",
			padding: PaddingConfig{Size: 200, LinkMTU: 100},
			wantErr: "padding size 200 must be less than link MTU 100",
		},
		{
			name:    "padding size equal to link MTU boundary is invalid",
			padding: PaddingConfig{Size: 255, LinkMTU: 255},
			wantErr: "padding size 255 must be less than link MTU 255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.padding.ValidateMTU()
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
	namedCfg := &ProxyConfig{
		Mode:       "forward",
		Interfaces: []string{"eth0"},
		Forward:    ForwardConfig{Backends: []BackendServer{{Name: "backend-1", IP: "10.0.0.1", Port: 51820}}},
	}
	if err := namedCfg.validate("forward"); err != nil {
		t.Errorf("named backend: unexpected error: %v", err)
	}

	unnamedCfg := &ProxyConfig{
		Mode:       "forward",
		Interfaces: []string{"eth0"},
		Forward:    ForwardConfig{Backends: []BackendServer{{IP: "10.0.0.2", Port: 51820}}},
	}
	if err := unnamedCfg.validate("forward"); err != nil {
		t.Errorf("unnamed backend: unexpected error: %v", err)
	}
}

func TestLoad_BackendNames(t *testing.T) {
	namedYAML := `
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
      - ip: 10.0.0.2
        port: 51821
`
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(namedYAML), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Proxy.Forward.Backends) != 2 {
		t.Fatalf("expected 2 backends, got %d", len(cfg.Proxy.Forward.Backends))
	}
	if cfg.Proxy.Forward.Backends[0].Name != "backend-1" {
		t.Errorf("expected backend name 'backend-1', got %q", cfg.Proxy.Forward.Backends[0].Name)
	}
	if cfg.Proxy.Forward.Backends[1].Name != "" {
		t.Errorf("expected empty backend name, got %q", cfg.Proxy.Forward.Backends[1].Name)
	}
}

func TestMonitoringConfig_Validation(t *testing.T) {
	tests := []struct {
		name       string
		monitoring MonitoringConfig
		wantErr    string
	}{
		{
			name:       "zero value, everything disabled",
			monitoring: MonitoringConfig{},
			wantErr:    "",
		},
		{
			name: "statistics enabled with zero interval",
			monitoring: MonitoringConfig{
				Statistics: StatisticsConfig{Enabled: true, Interval: 0},
			},
			wantErr: "monitoring.statistics.interval must be positive",
		},
		{
			name: "statistics enabled with negative interval",
			monitoring: MonitoringConfig{
				Statistics: StatisticsConfig{Enabled: true, Interval: -5 * time.Second},
			},
			wantErr: "monitoring.statistics.interval must be positive",
		},
		{
			name: "statistics disabled with zero interval",
			monitoring: MonitoringConfig{
				Statistics: StatisticsConfig{Enabled: false, Interval: 0},
			},
			wantErr: "",
		},
		{
			name: "prometheus enabled has no interval to check",
			monitoring: MonitoringConfig{
				Prometheus: PrometheusConfig{Enabled: true, Listen: ":9090"},
			},
			wantErr: "",
		},
		{
			name: "padding watcher enabled with zero interval",
			monitoring: MonitoringConfig{
				PaddingWatcher: PaddingWatcherConfig{Enabled: true, Interval: 0},
			},
			wantErr: "monitoring.padding_watcher.interval must be positive",
		},
		{
			name: "padding watcher enabled with negative interval",
			monitoring: MonitoringConfig{
				PaddingWatcher: PaddingWatcherConfig{Enabled: true, Interval: -5 * time.Second},
			},
			wantErr: "monitoring.padding_watcher.interval must be positive",
		},
		{
			name: "padding watcher disabled with zero interval",
			monitoring: MonitoringConfig{
				PaddingWatcher: PaddingWatcherConfig{Enabled: false, Interval: 0},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.monitoring.validate()

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
