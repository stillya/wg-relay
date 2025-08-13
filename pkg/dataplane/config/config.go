package config

import (
	"net"
	"os"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"
)

// Config represents the dataplane configuration
type Config struct {
	Mode    string       `yaml:"mode"`    // "forward" or "reverse"
	Enabled bool         `yaml:"enabled"` // Enable/disable obfuscation
	Daemon  DaemonConfig `yaml:"daemon"`  // Daemon configuration
	Proxy   ProxyConfig  `yaml:"proxy"`   // Proxy configuration
}

// DaemonConfig represents daemon-specific configuration
type DaemonConfig struct {
	Listen string `yaml:"listen"` // Address and port for daemon to bind to
}

// ProxyConfig represents proxy-specific configuration
type ProxyConfig struct {
	Method     string        `yaml:"method"`      // "xor" or "none"
	Key        string        `yaml:"key"`         // Obfuscation key (string)
	Interfaces []string      `yaml:"interfaces"`  // Network interfaces to attach to
	DriverMode string        `yaml:"driver_mode"` // "driver" or "generic" for XDP mode
	Forward    ForwardConfig `yaml:"forward"`     // Forward proxy configuration
}

// ForwardConfig represents forward proxy configuration (forward mode)
type ForwardConfig struct {
	TargetServerIP string `yaml:"target_server_ip"` // Target WireGuard server IP
}

// ObfuscationMethod represents the obfuscation method
type ObfuscationMethod uint32

const (
	MethodNone ObfuscationMethod = 0
	MethodXOR  ObfuscationMethod = 1
)

// MaxKeySize defines the maximum key size for obfuscation
const MaxKeySize = 32

// validate validates the dataplane configuration
func (cfg *Config) validate() error {
	// Validate mode
	if cfg.Mode != "forward" && cfg.Mode != "reverse" {
		return errors.New("mode must be 'forward' or 'reverse'")
	}

	// Validate proxy configuration
	return cfg.Proxy.validate(cfg.Mode)
}

// validate validates the proxy configuration
func (pc *ProxyConfig) validate(mode string) error {
	// Validate method
	if pc.Method != "xor" && pc.Method != "none" {
		return errors.New("method must be 'xor' or 'none'")
	}

	// Validate interfaces
	if len(pc.Interfaces) == 0 {
		return errors.New("at least one interface must be specified")
	}

	// Validate key is required
	if len(pc.Key) == 0 {
		return errors.New("key is required")
	}

	// Validate key length
	if len(pc.Key) > MaxKeySize {
		return errors.Errorf("key too long: %d bytes, max %d", len(pc.Key), MaxKeySize)
	}

	// Validate driver mode
	if pc.DriverMode != "" && pc.DriverMode != "driver" && pc.DriverMode != "generic" {
		return errors.New("driver_mode must be 'driver' or 'generic'")
	}

	// Forward mode specific validations
	if mode == "forward" {
		return pc.Forward.validate()
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

// GetMethod returns the obfuscation method as a constant
func (cfg *Config) GetMethod() ObfuscationMethod {
	switch cfg.Proxy.Method {
	case "xor":
		return MethodXOR
	default:
		return MethodNone
	}
}

// GetKeyBytes returns the obfuscation key as bytes
func (cfg *Config) GetKeyBytes() []byte {
	return []byte(cfg.Proxy.Key)
}

// GetTargetServerIP returns the target server IP as a uint32 in network byte order
func (cfg *Config) GetTargetServerIP() (uint32, error) {
	if cfg.Proxy.Forward.TargetServerIP == "" {
		return 0, nil
	}

	targetIP := net.ParseIP(cfg.Proxy.Forward.TargetServerIP)
	if targetIP == nil {
		return 0, errors.Errorf("invalid target server IP: %s", cfg.Proxy.Forward.TargetServerIP)
	}

	targetIP = targetIP.To4()
	if targetIP == nil {
		return 0, errors.Errorf("target server IP must be IPv4: %s", cfg.Proxy.Forward.TargetServerIP)
	}

	// Convert to uint32 in network byte order
	return uint32(targetIP[0])<<24 | uint32(targetIP[1])<<16 | uint32(targetIP[2])<<8 | uint32(targetIP[3]), nil
}

// NewConfig creates a new dataplane configuration with defaults
func NewConfig() *Config {
	return &Config{
		Mode:    "forward",
		Enabled: true,
		Daemon: DaemonConfig{
			Listen: ":8080",
		},
		Proxy: ProxyConfig{
			Method:     "xor",
			Interfaces: []string{},
			DriverMode: "driver",
			Forward:    ForwardConfig{},
		},
	}
}

// Load loads and validates configuration from a YAML file
func Load(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
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
