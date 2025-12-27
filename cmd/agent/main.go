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
	"github.com/stillya/wg-relay/pkg/api"
	"github.com/stillya/wg-relay/pkg/daemon"
	"github.com/stillya/wg-relay/pkg/metrics"
)

type Opts struct {
	SocketPath string `short:"s" long:"socket" description:"Unix socket path for control API" default:"/var/run/wg-relay/control.sock"`
	ConfigPath string `short:"c" long:"config" description:"Default config path" default:"/etc/wg-relay/config.yaml"`
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
		fmt.Printf("wg-relay-agent version %s\n", version)
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

	log.Info("Starting wg-relay-agent", "version", version)

	controller := daemon.NewController(daemon.ControllerConfig{
		DefaultConfigPath: opts.ConfigPath,
	})

	server, err := api.NewServer(opts.SocketPath, controller)
	if err != nil {
		log.Error("Failed to create control API server", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := server.Start(ctx); err != nil {
		log.Error("Failed to start control API server", "error", err)
		os.Exit(1)
	}
	defer server.Stop()

	// Start monitoring goroutine for Prometheus
	go monitorPrometheus(ctx, controller)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	log.Info("Agent started successfully",
		"socket", opts.SocketPath,
		"state", "disabled (waiting for enable command)")

	<-sigCh
	log.Info("Received shutdown signal, stopping agent...")

	cancel()

	log.Info("Agent stopped")
}

func monitorPrometheus(ctx context.Context, controller *daemon.Controller) {
	var (
		currentCollector *metrics.BpfCollector
		httpServer       *http.Server
		lastConfig       string
	)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if httpServer != nil {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				httpServer.Shutdown(shutdownCtx)
				cancel()
			}
			return

		case <-ticker.C:
			cfg := controller.GetConfig()

			if cfg == nil {
				if httpServer != nil {
					log.Info("Stopping Prometheus server - dataplane disabled")
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					httpServer.Shutdown(shutdownCtx)
					cancel()
					httpServer = nil
					currentCollector = nil
					lastConfig = ""
				}
				continue
			}

			configID := fmt.Sprintf("%s:%v", cfg.Monitoring.Prometheus.Listen, cfg.Monitoring.Prometheus.Enabled)
			if configID == lastConfig && httpServer != nil {
				continue
			}

			if httpServer != nil {
				log.Info("Stopping Prometheus server for reconfiguration")
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				httpServer.Shutdown(shutdownCtx)
				cancel()
				httpServer = nil
			}

			if currentCollector != nil {
				prometheus.Unregister(currentCollector)
				currentCollector = nil
			}

			if !cfg.Monitoring.Prometheus.Enabled {
				lastConfig = configID
				continue
			}

			metricsSource := controller.GetMetricsSource()
			if metricsSource == nil {
				continue
			}

			currentCollector = metrics.NewBpfCollector(metricsSource, cfg.Proxy.Mode)
			prometheus.MustRegister(currentCollector)

			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.Handler())

			httpServer = &http.Server{
				Addr:    cfg.Monitoring.Prometheus.Listen,
				Handler: mux,
			}

			go func() {
				log.Info("Starting Prometheus metrics server", "listen", cfg.Monitoring.Prometheus.Listen)
				if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Error("Prometheus metrics server failed", "error", err)
				}
			}()

			lastConfig = configID
		}
	}
}
