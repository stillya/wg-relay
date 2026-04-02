package monitor

import (
	"context"
	"time"

	log "log/slog"

	"github.com/stillya/wg-relay/pkg/maps/metricsmap"
)

// OutputMode controls how statistics are reported.
type OutputMode int

const (
	// OutputModeTerminal prints an ANSI table to stdout (interactive use).
	OutputModeTerminal OutputMode = iota
	// OutputModeStructured emits a single structured slog entry per interval (systemd/journald use).
	OutputModeStructured
)

// StatMonitorSource defines the interface for collecting metrics data.
type StatMonitorSource interface {
	Collect(ctx context.Context) ([]metricsmap.MetricData, error)
	Name() string
}

// BackendDiscovery provides backend label resolution.
type BackendDiscovery interface {
	Backends() map[uint8]string
}

// StatMonitor periodically collects and displays traffic statistics.
type StatMonitor struct {
	StatMonitorParams
	source  StatMonitorSource
	printer *TablePrinter
	stopCh  chan struct{}

	startTime time.Time
}

// StatMonitorParams contains configuration parameters for StatMonitor.
type StatMonitorParams struct {
	Mode       string
	Interval   time.Duration
	MaxSources int
	OutputMode OutputMode
}

// NewStatMonitor creates a new StatMonitor with the given parameters.
func NewStatMonitor(params StatMonitorParams, source StatMonitorSource, backends BackendDiscovery) *StatMonitor {
	return &StatMonitor{
		StatMonitorParams: params,
		source:            source,
		printer: &TablePrinter{
			maxSources: params.MaxSources,
			backends:   backends,
		},
		stopCh:    make(chan struct{}),
		startTime: time.Now(),
	}
}

// Start begins the periodic collection and display of statistics.
func (sm *StatMonitor) Start(ctx context.Context) {
	log.Info("Starting stat monitor", "interval", sm.Interval)

	ticker := time.NewTicker(sm.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Stat monitor stopped by context")
			return
		case <-sm.stopCh:
			log.Info("Stat monitor stopped")
			return
		case <-ticker.C:
			sm.printStats(ctx)
		}
	}
}

// Stop signals the monitor to stop collecting statistics.
func (sm *StatMonitor) Stop() {
	close(sm.stopCh)
}

func (sm *StatMonitor) printStats(ctx context.Context) {
	metricsData, err := sm.source.Collect(ctx)
	if err != nil {
		log.Error("Failed to collect metrics", "error", err)
		return
	}

	if len(metricsData) == 0 {
		return
	}

	elapsed := time.Since(sm.startTime)

	if sm.OutputMode == OutputModeStructured {
		sm.logStructured(metricsData, elapsed)
		return
	}

	sm.printer.PrintTrafficTable(sm.Mode, metricsData, elapsed)
}

func (sm *StatMonitor) logStructured(metricsData []metricsmap.MetricData, elapsed time.Duration) {
	var downstreamRx, downstreamTx, upstreamRx, upstreamTx uint64
	for _, m := range metricsData {
		switch m.Key.Direction {
		case metricsmap.MetricDownstream:
			downstreamRx += m.Value.RxBytes
			downstreamTx += m.Value.TxBytes
		case metricsmap.MetricUpstream:
			upstreamRx += m.Value.RxBytes
			upstreamTx += m.Value.TxBytes
		}
	}

	total := downstreamRx + downstreamTx + upstreamRx + upstreamTx
	var avgRateBps float64
	if elapsed.Seconds() > 0 {
		avgRateBps = float64(total) / elapsed.Seconds()
	}

	log.Info("traffic stats",
		"mode", sm.Mode,
		"downstream_rx_bytes", downstreamRx,
		"downstream_tx_bytes", downstreamTx,
		"upstream_rx_bytes", upstreamRx,
		"upstream_tx_bytes", upstreamTx,
		"total_bytes", total,
		"avg_rate_bps", uint64(avgRateBps),
		"elapsed", elapsed.String(),
	)
}
