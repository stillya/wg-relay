package main

import (
	"context"
	"fmt"
	log "log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stillya/wg-relay/pkg/dataplane/config"
	"github.com/stillya/wg-relay/pkg/dataplane/proxy"
	"github.com/stillya/wg-relay/pkg/metrics"

	"github.com/stillya/wg-relay/pkg/dataplane"
	"github.com/stillya/wg-relay/pkg/maps/metricsmap"
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

const version = "0.1.0"

func main() {
	var opts Opts
	parser := flags.NewParser(&opts, flags.Default)

	if _, err := parser.Parse(); err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) && errors.Is(flagsErr.Type, flags.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if opts.Version {
		fmt.Printf("wg-relay daemon version %s\n", version)
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

	log.Info("Starting wg-relay daemon", "version", version)

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

	switch ProxyMode(cfg.Proxy.Mode) {
	case ModeForward:
		loader, err = proxy.NewForwardLoader()
	case ModeReverse:
		loader, err = proxy.NewReverseLoader()
	default:
		log.Error("Unsupported proxy mode", "mode", cfg.Proxy.Mode)
	}

	if err != nil {
		log.Error("Failed to create loader", "error", err)
		os.Exit(1)
	}

	dataplaneManager, err := dataplane.NewManager(cfg.Proxy, loader)
	if err != nil {
		log.Error("Failed to create dataplane manager", "error", err)
		os.Exit(1)
	}

	if err := dataplaneManager.Start(ctx); err != nil {
		log.Error("Failed to start dataplane", "error", err)
		os.Exit(1)
	}
	defer dataplaneManager.Stop()

	var metricsSource *metricsmap.BPFMapSource
	var bpfCollector *metrics.BpfCollector
	var statsMonitor *monitor.StatMonitor

	maps := dataplaneManager.Maps()
	if maps != nil && maps.Metrics != nil {
		metricsSource = metricsmap.NewBPFMapSource("wg-relay-metrics", maps.Metrics)

		if cfg.Monitoring.Prometheus.Enabled {
			bpfCollector = metrics.NewBpfCollector(metricsSource, cfg.Proxy.Mode)
			prometheus.MustRegister(bpfCollector)

			// Start Prometheus HTTP server
			go func() {
				mux := http.NewServeMux()
				mux.Handle("/metrics", promhttp.Handler())

				server := &http.Server{
					Addr:              cfg.Monitoring.Prometheus.Listen,
					Handler:           mux,
					ReadHeaderTimeout: 10 * time.Second,
				}

				log.Info("Starting Prometheus metrics server", "listen", cfg.Monitoring.Prometheus.Listen)
				if err := server.ListenAndServe(); err != nil {
					log.Error("Prometheus metrics server failed", "error", err)
				}
			}()
		}

		if cfg.Monitoring.Statistics.Enabled {
			statsMonitor = monitor.NewStatMonitor(monitor.StatMonitorParams{
				Interval: cfg.Monitoring.Statistics.Interval,
				Mode:     cfg.Proxy.Mode,
			}, metricsSource)
			go statsMonitor.Start(ctx)
			defer statsMonitor.Stop()
		}
	}

	log.Info("Daemon started successfully",
		"mode", cfg.Proxy.Mode,
		"interfaces", cfg.Proxy.Interfaces,
		"listen", cfg.Daemon.Listen,
		"statistics", cfg.Monitoring.Statistics.Enabled,
		"prometheus", cfg.Monitoring.Prometheus.Enabled)

	<-sigCh
	log.Info("Received shutdown signal, stopping daemon...")

	cancel()

	log.Info("Daemon stopped")
}

func loadConfig(opts Opts) (*config.Config, error) {
	configData, err := config.Load(opts.ConfigFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	return configData, nil
}
