package monitor

import (
	"context"
	"time"

	log "log/slog"

	"github.com/stillya/wg-relay/pkg/maps/metricsmap"
)

type StatMonitorSource interface {
	Collect(ctx context.Context) ([]metricsmap.MetricData, error)
	Name() string
}

type StatMonitor struct {
	source   StatMonitorSource
	printer  *TablePrinter
	interval time.Duration
	stopCh   chan struct{}

	startTime time.Time
}

type StatMonitorParams struct {
	Source   StatMonitorSource
	Interval time.Duration
}

func NewStatMonitor(params StatMonitorParams) *StatMonitor {
	return &StatMonitor{
		source:    params.Source,
		printer:   &TablePrinter{},
		interval:  params.Interval,
		stopCh:    make(chan struct{}),
		startTime: time.Now(),
	}
}

func (sm *StatMonitor) Start(ctx context.Context) {
	log.Info("Starting stat monitor", "interval", sm.interval)

	ticker := time.NewTicker(sm.interval)
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
	sm.printer.PrintTrafficTable(metricsData, elapsed)
}
