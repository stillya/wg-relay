package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "log/slog"

	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
	"github.com/stillya/wg-relay/pkg/dataplane/proxy"

	"github.com/stillya/wg-relay/pkg/dataplane"
	"github.com/stillya/wg-relay/pkg/dataplane/config"
	"github.com/stillya/wg-relay/pkg/monitor"
)

// ProxyMode defines the operation mode
type ProxyMode string

const (
	ModeForward ProxyMode = "forward" // XDP-based forward proxy
	ModeReverse ProxyMode = "reverse" // TC-based reverse proxy
)

// Opts represents command line options
type Opts struct {
	ConfigFile string `short:"c" long:"config" description:"Path to configuration file" default:"config.yaml"`
	Debug      bool   `short:"d" long:"debug" description:"Enable debug logging"`
	Version    bool   `short:"v" long:"version" description:"Show version information"`
}

type DaemonConfig struct {
	Dataplane  config.Config `yaml:"dataplane"`
	Monitoring struct {
		Enabled  bool          `yaml:"enabled"`
		Interval time.Duration `yaml:"interval"`
	} `yaml:"monitoring"`
}

const version = "0.0.1"

func main() {
	var opts Opts
	parser := flags.NewParser(&opts, flags.Default)

	_, err := parser.Parse()
	if _, err := parser.Parse(); err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && errors.Is(flagsErr.Type, flags.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if opts.Version {
		fmt.Printf("wg-proxy daemon version %s\n", version)
		os.Exit(0)
	}

	logLevel := log.LevelInfo
	if opts.Debug {
		logLevel = log.LevelDebug
	}

	logger := log.New(log.NewTextHandler(os.Stdout, &log.HandlerOptions{
		Level: logLevel,
	}))
	log.SetDefault(logger)

	log.Info("Starting wg-proxy daemon", "version", version)

	cfg, err := loadConfig(opts)
	if err != nil {
		log.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Create and start dataplane manager
	var loader dataplane.Loader

	switch ProxyMode(cfg.Dataplane.Mode) {
	case ModeForward:
		loader, err = proxy.NewForwardLoader()
	case ModeReverse:
		loader, err = proxy.NewReverseLoader()
	default:
		log.Error("Unsupported proxy mode", "mode", cfg.Dataplane.Mode)
	}

	if err != nil {
		log.Error("Failed to create loader", "error", err)
		os.Exit(1)
	}

	managerCfg := dataplane.ManagerConfig{
		Cfg:    cfg.Dataplane,
		Loader: loader,
	}

	dataplaneManager, err := dataplane.NewManager(managerCfg)
	if err != nil {
		log.Error("Failed to create dataplane manager", "error", err)
		os.Exit(1)
	}

	if err := dataplaneManager.Start(ctx); err != nil {
		log.Error("Failed to start dataplane", "error", err)
		os.Exit(1)
	}
	defer dataplaneManager.Stop()

	// Start statistics monitoring
	var statsMonitor *monitor.StatsMonitor
	if cfg.Monitoring.Enabled {
		statsMonitor = monitor.NewStatsMonitor(dataplaneManager, cfg.Monitoring.Interval)
		go statsMonitor.Start(ctx)
		defer statsMonitor.Stop()
	}

	log.Info("Daemon started successfully",
		"mode", cfg.Dataplane.Mode,
		"interfaces", cfg.Dataplane.Proxy.Interfaces,
		"listen", cfg.Dataplane.Daemon.Listen,
		"monitoring", cfg.Monitoring.Enabled)

	<-sigCh
	log.Info("Received shutdown signal, stopping daemon...")

	cancel()

	log.Info("Daemon stopped")
}

func loadConfig(opts Opts) (*DaemonConfig, error) {
	cfg := &DaemonConfig{
		Dataplane: *config.NewConfig(),
		Monitoring: struct {
			Enabled  bool          `yaml:"enabled"`
			Interval time.Duration `yaml:"interval"`
		}{
			Enabled:  true,
			Interval: 30 * time.Second,
		},
	}

	dataplaneConfig, err := config.Load(opts.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	cfg.Dataplane = *dataplaneConfig

	return cfg, nil
}
