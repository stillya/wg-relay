package monitor

import (
	"context"
	"time"

	log "log/slog"

	"github.com/stillya/wg-relay/pkg/maps/metricsmap"
)

// StatMonitorSource defines the interface for collecting metrics data.
type StatMonitorSource interface {
	Collect(ctx context.Context) ([]metricsmap.MetricData, error)
	Name() string
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
	Mode     string
	Interval time.Duration
}

// NewStatMonitor creates a new StatMonitor with the given parameters.
func NewStatMonitor(params StatMonitorParams, source StatMonitorSource) *StatMonitor {
	return &StatMonitor{
		StatMonitorParams: params,
		source:            source,
		printer:           &TablePrinter{},
		stopCh:            make(chan struct{}),
		startTime:         time.Now(),
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
	sm.printer.PrintTrafficTable(sm.Mode, metricsData, elapsed)
}
