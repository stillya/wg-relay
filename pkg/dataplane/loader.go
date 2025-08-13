package dataplane

import (
	"context"
	"fmt"
	log "log/slog"

	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"

	"github.com/stillya/wg-relay/pkg/dataplane/config"
	"github.com/stillya/wg-relay/pkg/dataplane/maps"
	"github.com/stillya/wg-relay/pkg/dataplane/proxy"
)

// Loader interface for eBPF proxy loaders
type Loader interface {
	LoadAndAttach(ctx context.Context, cfg config.Config) error
	Close() error
	Maps() *maps.Maps
}

// Manager manages the eBPF dataplane
type Manager struct {
	cfg    config.Config
	loader Loader
}

// ProxyMode defines the operation mode
type ProxyMode string

const (
	ModeForward ProxyMode = "forward" // XDP-based forward proxy
	ModeReverse ProxyMode = "reverse" // TC-based reverse proxy
)

// NewManager creates a new dataplane manager
func NewManager(cfg config.Config) (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, errors.Wrap(err, "failed to remove memlock limit")
	}

	var loader Loader
	var err error

	// Initialize appropriate loader based on mode
	switch ProxyMode(cfg.Mode) {
	case ModeForward:
		loader, err = proxy.NewForwardLoader(cfg)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create forward proxy loader")
		}
	case ModeReverse:
		loader, err = proxy.NewReverseLoader(cfg)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create reverse proxy loader")
		}
	default:
		return nil, fmt.Errorf("unsupported proxy mode: %s", cfg.Mode)
	}

	return &Manager{
		cfg:    cfg,
		loader: loader,
	}, nil
}

// LoadAndAttach loads eBPF programs and attaches them to interfaces
func (dm *Manager) LoadAndAttach(ctx context.Context) error {
	log.Info("Loading eBPF dataplane", "mode", dm.cfg.Mode)
	return dm.loader.LoadAndAttach(ctx, dm.cfg)
}

// Start initializes and starts the dataplane
func (dm *Manager) Start(ctx context.Context) error {
	return dm.LoadAndAttach(ctx)
}

// Stop stops the dataplane
func (dm *Manager) Stop() error {
	return dm.Close()
}

// Close cleans up all resources
func (dm *Manager) Close() error {
	if dm.loader != nil {
		return dm.loader.Close()
	}
	return nil
}

// Maps returns eBPF maps from the underlying loader
func (dm *Manager) Maps() *maps.Maps {
	if dm.loader != nil {
		return dm.loader.Maps()
	}
	return maps.NewMaps()
}
