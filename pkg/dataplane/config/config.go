package config

import (
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

// Config represents the dataplane configuration
type Config struct {
	Daemon     DaemonConfig     `yaml:"daemon"`     // Daemon configuration
	Proxy      ProxyConfig      `yaml:"proxy"`      // Proxy configuration
	Monitoring MonitoringConfig `yaml:"monitoring"` // Monitoring configuration
}

// DaemonConfig represents daemon-specific configuration
type DaemonConfig struct {
	Listen string `yaml:"listen"` // Address and port for daemon to bind to
}

// InstrumentationConfig represents instrumentation configuration
type InstrumentationConfig struct {
	XOR     *XORConfig     `yaml:"xor,omitempty"`
	Padding *PaddingConfig `yaml:"padding,omitempty"`
}

// XORConfig represents XOR obfuscation configuration
type XORConfig struct {
	Enabled bool   `yaml:"enabled"`
	Key     string `yaml:"key"`
}

// PaddingConfig represents packet padding configuration
type PaddingConfig struct {
	Enabled    bool   `yaml:"enabled"`
	MinPadding uint16 `yaml:"min_padding"`
	MaxPadding uint16 `yaml:"max_padding"`
	FillMode   string `yaml:"fill_mode"` // "zero" or "random"
}

// ProxyConfig represents proxy-specific configuration
type ProxyConfig struct {
	Enabled          bool                  `yaml:"enabled"`          // Enable/disable proxy
	Mode             string                `yaml:"mode"`             // "forward" or "reverse"
	WGPort           uint16                `yaml:"wg_port"`          // WireGuard port to intercept (default: 51820)
	Instrumentations InstrumentationConfig `yaml:"instrumentations"` // Instrumentation configuration
	Interfaces       []string              `yaml:"interfaces"`       // Network interfaces to attach to
	DriverMode       string                `yaml:"driver_mode"`      // "driver", "generic" and "offload" for XDP mode
	Forward          ForwardConfig         `yaml:"forward"`          // Forward proxy configuration
}

// ForwardConfig represents forward proxy configuration (forward mode)
type ForwardConfig struct {
	TargetServerIP string `yaml:"target_server_ip"` // Target WireGuard server IP
}

// MonitoringConfig represents monitoring configuration
type MonitoringConfig struct {
	Prometheus PrometheusConfig `yaml:"prometheus"` // Prometheus HTTP exporter
	Statistics StatisticsConfig `yaml:"statistics"` // vnstat-style console output
}

// PrometheusConfig represents Prometheus monitoring configuration
type PrometheusConfig struct {
	Enabled bool   `yaml:"enabled"` // Enable/disable Prometheus metrics server
	Listen  string `yaml:"listen"`  // Address and port for metrics server
}

// StatisticsConfig represents statistics monitoring configuration
type StatisticsConfig struct {
	Enabled  bool          `yaml:"enabled"`  // Enable/disable statistics display
	Interval time.Duration `yaml:"interval"` // Statistics update interval
}

// ObfuscationMethod represents the obfuscation method
type ObfuscationMethod uint32

// Obfuscation method constants.
const (
	MethodNone ObfuscationMethod = 0
	MethodXOR  ObfuscationMethod = 1
)

// MaxKeySize defines the maximum key size for obfuscation
const MaxKeySize = 32

// MaxPaddingSize defines the maximum padding size
const MaxPaddingSize = 256

// validate validates the dataplane configuration
func (cfg *Config) validate() error {
	// Validate mode
	if cfg.Proxy.Mode != "forward" && cfg.Proxy.Mode != "reverse" {
		return errors.New("mode must be 'forward' or 'reverse'")
	}

	// Validate proxy configuration
	return cfg.Proxy.validate(cfg.Proxy.Mode)
}

// validate validates the proxy configuration
func (cfg *ProxyConfig) validate(mode string) error {
	// Validate interfaces
	if len(cfg.Interfaces) == 0 {
		return errors.New("at least one interface must be specified")
	}

	// Validate driver mode
	if cfg.DriverMode != "" && cfg.DriverMode != "driver" && cfg.DriverMode != "generic" && cfg.DriverMode != "offload" {
		return errors.New("driver_mode must be 'driver', 'generic' or 'offload'")
	}

	// Validate XOR config
	if cfg.Instrumentations.XOR != nil && cfg.Instrumentations.XOR.Enabled {
		if len(cfg.Instrumentations.XOR.Key) == 0 {
			return errors.New("xor key is required when xor is enabled")
		}
		if len(cfg.Instrumentations.XOR.Key) > MaxKeySize {
			return errors.Errorf("xor key too long: %d bytes, max %d", len(cfg.Instrumentations.XOR.Key), MaxKeySize)
		}
	}

	if cfg.Instrumentations.Padding != nil && cfg.Instrumentations.Padding.Enabled {
		if cfg.Instrumentations.Padding.MinPadding == 0 {
			return errors.New("padding min_padding must be greater than 0 when padding is enabled")
		}
		if cfg.Instrumentations.Padding.MaxPadding == 0 {
			return errors.New("padding max_padding must be greater than 0 when padding is enabled")
		}
		if cfg.Instrumentations.Padding.MinPadding > cfg.Instrumentations.Padding.MaxPadding {
			return errors.New("padding min_padding must be less than or equal to max_padding")
		}
		if cfg.Instrumentations.Padding.MaxPadding > MaxPaddingSize {
			return errors.Errorf("padding max_padding too large: %d bytes, max %d", cfg.Instrumentations.Padding.MaxPadding, MaxPaddingSize)
		}
		if cfg.Instrumentations.Padding.FillMode != "zero" && cfg.Instrumentations.Padding.FillMode != "random" {
			return errors.New("padding fill_mode must be 'zero' or 'random'")
		}
	}

	// Forward mode specific validations
	if mode == "forward" {
		return cfg.Forward.validate()
	}

	return nil
}

// validate validates the forward proxy configuration
func (fc *ForwardConfig) validate() error {
	if fc.TargetServerIP == "" {
		return errors.New("target_server_ip is required in forward mode")
	}

	// Validate target server IP
	targetIP := net.ParseIP(fc.TargetServerIP)
	if targetIP == nil {
		return errors.Errorf("invalid target server IP: %s", fc.TargetServerIP)
	}
	if targetIP.To4() == nil {
		return errors.Errorf("target server IP must be IPv4: %s", fc.TargetServerIP)
	}

	return nil
}

// GetInstrumentationMethods returns enabled instrumentations as bitfield
func (cfg *ProxyConfig) GetInstrumentationMethods() uint8 {
	var methods uint8 = 0

	if cfg.Instrumentations.XOR != nil && cfg.Instrumentations.XOR.Enabled {
		methods |= 0x01 // INSTRUMENT_XOR
	}

	if cfg.Instrumentations.Padding != nil && cfg.Instrumentations.Padding.Enabled {
		methods |= 0x02 // INSTRUMENT_PADDING
	}

	return methods
}

// GetXORKey returns the XOR key as bytes
func (cfg *ProxyConfig) GetXORKey() []byte {
	if cfg.Instrumentations.XOR != nil && cfg.Instrumentations.XOR.Enabled {
		return []byte(cfg.Instrumentations.XOR.Key)
	}
	return nil
}

// GetPaddingConfig returns padding configuration
func (cfg *ProxyConfig) GetPaddingConfig() (uint16, uint16, uint8) {
	if cfg.Instrumentations.Padding != nil && cfg.Instrumentations.Padding.Enabled {
		fillMode := uint8(0) // zero
		if cfg.Instrumentations.Padding.FillMode == "random" {
			fillMode = 1
		}
		return cfg.Instrumentations.Padding.MinPadding,
			cfg.Instrumentations.Padding.MaxPadding,
			fillMode
	}
	return 0, 0, 0
}

// GetTargetServerIP returns the target server IP as a uint32 in network byte order
func (cfg *ProxyConfig) GetTargetServerIP() (uint32, error) {
	if cfg.Forward.TargetServerIP == "" {
		return 0, nil
	}

	targetIP := net.ParseIP(cfg.Forward.TargetServerIP)
	if targetIP == nil {
		return 0, errors.Errorf("invalid target server IP: %s", cfg.Forward.TargetServerIP)
	}

	targetIP = targetIP.To4()
	if targetIP == nil {
		return 0, errors.Errorf("target server IP must be IPv4: %s", cfg.Forward.TargetServerIP)
	}

	// Convert to uint32 in network byte order
	return uint32(targetIP[0])<<24 | uint32(targetIP[1])<<16 | uint32(targetIP[2])<<8 | uint32(targetIP[3]), nil
}

// NewConfig creates a new dataplane configuration with defaults
func NewConfig() *Config {
	return &Config{
		Daemon: DaemonConfig{
			Listen: ":8080",
		},
		Proxy: ProxyConfig{
			Enabled:    true,
			Mode:       "forward",
			WGPort:     51820,
			Interfaces: []string{},
			DriverMode: "driver",
			Forward:    ForwardConfig{},
			Instrumentations: InstrumentationConfig{
				XOR: &XORConfig{
					Enabled: false,
					Key:     "",
				},
				Padding: &PaddingConfig{
					Enabled:    false,
					MinPadding: 8,
					MaxPadding: 64,
					FillMode:   "random",
				},
			},
		},
		Monitoring: MonitoringConfig{
			Prometheus: PrometheusConfig{
				Enabled: false,
				Listen:  ":9090",
			},
			Statistics: StatisticsConfig{
				Enabled:  true,
				Interval: 30 * time.Second,
			},
		},
	}
}

// Load loads and validates configuration from a YAML file
func Load(filename string) (*Config, error) {
	data, err := os.ReadFile(filename) //nolint:gosec // G304: config file path is provided by CLI argument
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read config file %s", filename)
	}

	cfg := NewConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, errors.Wrap(err, "failed to parse config file")
	}

	if err := cfg.validate(); err != nil {
		return nil, errors.Wrap(err, "configuration validation failed")
	}

	return cfg, nil
}
