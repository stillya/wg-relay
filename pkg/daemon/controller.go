package daemon

import (
	"context"
	"sync"
	"time"

	log "log/slog"

	"github.com/pkg/errors"
	"github.com/stillya/wg-relay/pkg/api"
	"github.com/stillya/wg-relay/pkg/dataplane"
	"github.com/stillya/wg-relay/pkg/dataplane/config"
	"github.com/stillya/wg-relay/pkg/dataplane/proxy"
	"github.com/stillya/wg-relay/pkg/maps/metricsmap"
)

type ControllerConfig struct {
	DefaultConfigPath string
}

type Controller struct {
	mu            sync.RWMutex
	state         api.DataplaneState
	manager       *dataplane.Manager
	cfg           *config.Config
	startTime     time.Time
	metricsSource *metricsmap.BPFMapSource
	lastError     string
	defaultConfig string
}

func NewController(cfg ControllerConfig) *Controller {
	return &Controller{
		state:         api.StateDisabled,
		startTime:     time.Now(),
		defaultConfig: cfg.DefaultConfigPath,
	}
}

func (c *Controller) HandleEnable(ctx context.Context, args api.EnableArgs) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == api.StateEnabled {
		return errors.New("dataplane already enabled")
	}

	configPath := args.ConfigPath
	if configPath == "" {
		configPath = c.defaultConfig
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		c.state = api.StateFailed
		c.lastError = err.Error()
		return errors.Wrap(err, "failed to load config")
	}

	var loader dataplane.Loader
	switch cfg.Proxy.Mode {
	case "forward":
		loader, err = proxy.NewForwardLoader()
	case "reverse":
		loader, err = proxy.NewReverseLoader()
	default:
		c.state = api.StateFailed
		c.lastError = "invalid proxy mode"
		return errors.Errorf("unsupported proxy mode: %s", cfg.Proxy.Mode)
	}

	if err != nil {
		c.state = api.StateFailed
		c.lastError = err.Error()
		return errors.Wrap(err, "failed to create loader")
	}

	managerCfg := dataplane.ManagerConfig{
		Cfg:    cfg.Proxy,
		Loader: loader,
	}

	manager, err := dataplane.NewManager(managerCfg)
	if err != nil {
		c.state = api.StateFailed
		c.lastError = err.Error()
		return errors.Wrap(err, "failed to create dataplane manager")
	}

	if err := manager.Start(ctx); err != nil {
		c.state = api.StateFailed
		c.lastError = err.Error()
		return errors.Wrap(err, "failed to start dataplane")
	}

	c.manager = manager
	c.cfg = cfg
	c.state = api.StateEnabled
	c.lastError = ""

	maps := manager.Maps()
	if maps != nil && maps.Metrics != nil {
		c.metricsSource = metricsmap.NewBPFMapSource("wg-relay-metrics", maps.Metrics)
	}

	log.Info("Dataplane enabled",
		"mode", cfg.Proxy.Mode,
		"interfaces", cfg.Proxy.Interfaces)

	return nil
}

func (c *Controller) HandleDisable(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == api.StateDisabled {
		return errors.New("dataplane already disabled")
	}

	if c.manager != nil {
		if err := c.manager.Stop(); err != nil {
			log.Warn("Failed to stop manager cleanly", "error", err)
		}
		c.manager = nil
	}

	c.state = api.StateDisabled
	c.cfg = nil
	c.metricsSource = nil
	c.lastError = ""

	log.Info("Dataplane disabled")

	return nil
}

func (c *Controller) HandleReload(ctx context.Context, args api.ReloadArgs) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != api.StateEnabled {
		return errors.New("dataplane not enabled")
	}

	configPath := args.ConfigPath
	if configPath == "" {
		configPath = c.defaultConfig
	}

	if c.manager != nil {
		if err := c.manager.Stop(); err != nil {
			log.Warn("Failed to stop manager cleanly during reload", "error", err)
		}
		c.manager = nil
	}

	c.mu.Unlock()
	err := c.HandleEnable(ctx, api.EnableArgs{ConfigPath: configPath})
	c.mu.Lock()

	if err != nil {
		return errors.Wrap(err, "failed to reload")
	}

	log.Info("Dataplane reloaded")

	return nil
}

func (c *Controller) GetStatus(ctx context.Context) (*api.StatusResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	status := &api.StatusResponse{
		State:        c.state,
		Uptime:       time.Since(c.startTime),
		ErrorMessage: c.lastError,
	}

	if c.cfg != nil {
		status.Mode = c.cfg.Proxy.Mode
		status.Interfaces = c.cfg.Proxy.Interfaces
	}

	return status, nil
}

func (c *Controller) GetStats(ctx context.Context) (*api.StatsResponse, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.metricsSource == nil {
		return nil, errors.New("metrics not available")
	}

	metricsData, err := c.metricsSource.Collect(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "failed to collect metrics")
	}

	metrics := make([]api.MetricData, 0, len(metricsData))
	for _, m := range metricsData {
		metrics = append(metrics, api.MetricData{
			Direction: metricsmap.DirectionToString(m.Key.Dir),
			Reason:    metricsmap.ReasonToString(m.Key.Reason),
			SrcAddr:   metricsmap.SrcAddrToString(m.Key.SrcAddr),
			Packets:   m.Value.Packets,
			Bytes:     m.Value.Bytes,
		})
	}

	return &api.StatsResponse{
		Metrics: metrics,
		Uptime:  time.Since(c.startTime),
	}, nil
}

func (c *Controller) GetMetricsSource() *metricsmap.BPFMapSource {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.metricsSource
}

func (c *Controller) GetConfig() *config.Config {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cfg
}
