package monitor

import (
	"context"
	"fmt"
	"strings"
	"time"

	log "log/slog"

	"github.com/cilium/ebpf"
	"github.com/stillya/wg-relay/pkg/dataplane/maps"
)

// MapsRetriever interface for components that provide access to eBPF maps
type MapsRetriever interface {
	Maps() *maps.Maps
}

// StatsMonitor monitors and prints statistics from eBPF maps
type StatsMonitor struct {
	mapsRetriever MapsRetriever
	interval      time.Duration
	stopCh        chan struct{}
}

// NewStatsMonitor creates a new statistics monitor
func NewStatsMonitor(mapsRetriever MapsRetriever, interval time.Duration) *StatsMonitor {
	return &StatsMonitor{
		mapsRetriever: mapsRetriever,
		interval:      interval,
		stopCh:        make(chan struct{}),
	}
}

// Start begins periodic statistics printing
func (sm *StatsMonitor) Start(ctx context.Context) {
	log.Info("Starting statistics monitor", "interval", sm.interval)

	ticker := time.NewTicker(sm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Statistics monitor stopped by context")
			return
		case <-sm.stopCh:
			log.Info("Statistics monitor stopped")
			return
		case <-ticker.C:
			sm.printMapStats()
		}
	}
}

// Stop stops the statistics monitor
func (sm *StatsMonitor) Stop() {
	close(sm.stopCh)
}

// printMapStats prints statistics from eBPF maps in a readable format
func (sm *StatsMonitor) printMapStats() {
	if sm.mapsRetriever == nil {
		return
	}

	mapsCollection := sm.mapsRetriever.Maps()
	if mapsCollection == nil {
		return
	}

	for _, mapInfo := range mapsCollection.Stats {
		if mapInfo.Map == nil {
			continue
		}

		sm.printStatsMapValues(mapInfo.Name, mapInfo.Map)
	}
}

// printStatsMapValues reads and prints values from a statistics map
func (sm *StatsMonitor) printStatsMapValues(mapName string, statsMap *ebpf.Map) {
	// Statistics keys from metrics.h with shortened names
	statsKeys := []struct {
		key  uint32
		name string
	}{
		{0, "to_wg"},
		{1, "from_wg"},
		{2, "nat_lookup_suc"},
		{3, "nat_lookup_fail"},
	}

	// Collect all stats values
	stats := make([]string, 0, len(statsKeys))
	for _, stat := range statsKeys {
		var value uint64
		err := statsMap.Lookup(&stat.key, &value)
		if err != nil {
			value = 0
		}
		stats = append(stats, fmt.Sprintf("%s: %d", stat.name, value))
	}

	log.Info("Stats: " + strings.Join(stats, ", "))
}
