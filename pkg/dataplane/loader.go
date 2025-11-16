package dataplane

import (
	"context"
	log "log/slog"

	"github.com/cilium/ebpf/rlimit"
	"github.com/pkg/errors"
	"github.com/stillya/wg-relay/pkg/dataplane/config"

	"github.com/stillya/wg-relay/pkg/dataplane/maps"
)

// Loader interface for eBPF proxy loaders
type Loader interface {
	LoadAndAttach(ctx context.Context, cfg config.ProxyConfig) error
	Close() error
	Maps() *maps.Maps
}

// Manager manages the eBPF dataplane
type Manager struct {
	cfg    config.ProxyConfig
	loader Loader
}

// ManagerConfig holds configuration for the dataplane manager
type ManagerConfig struct {
	Cfg    config.ProxyConfig
	Loader Loader
}

// NewManager creates a new dataplane manager
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, errors.Wrap(err, "failed to remove memlock limit")
	}

	return &Manager{
		cfg:    cfg.Cfg,
		loader: cfg.Loader,
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

	return nil
}
