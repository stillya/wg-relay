package monitor

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/stillya/wg-relay/pkg/maps/metricsmap"
)

// TablePrinter formats and prints traffic statistics tables.
type TablePrinter struct {
	maxSources    int
	backendLabels map[uint8]string
}

// PrintTrafficTable prints a formatted table of traffic statistics.
func (tp *TablePrinter) PrintTrafficTable(mode string, metricsData []metricsmap.MetricData, elapsed time.Duration) {
	tp.clearScreen()

	type directionStats struct {
		downstreamRxBytes uint64
		downstreamTxBytes uint64
		upstreamRxBytes   uint64
		upstreamTxBytes   uint64
	}

	perBackendStats := make(map[string]*directionStats)
	var totalDownstreamRx, totalDownstreamTx, totalUpstreamRx, totalUpstreamTx uint64

	for _, metric := range metricsData {
		var backendKey string
		if mode == "forward" {
			if label, exists := tp.backendLabels[metric.Key.BackendIndex]; exists {
				backendKey = label
			} else {
				backendKey = fmt.Sprintf("backend_%d", metric.Key.BackendIndex)
			}
		} else {
			backendKey = metricsmap.DirectionToString(metric.Key.Direction)
		}

		if _, exists := perBackendStats[backendKey]; !exists {
			perBackendStats[backendKey] = &directionStats{}
		}

		switch metric.Key.Direction {
		case metricsmap.MetricDownstream:
			totalDownstreamRx += metric.Value.RxBytes
			totalDownstreamTx += metric.Value.TxBytes
			perBackendStats[backendKey].downstreamRxBytes += metric.Value.RxBytes
			perBackendStats[backendKey].downstreamTxBytes += metric.Value.TxBytes
		case metricsmap.MetricUpstream:
			totalUpstreamRx += metric.Value.RxBytes
			totalUpstreamTx += metric.Value.TxBytes
			perBackendStats[backendKey].upstreamRxBytes += metric.Value.RxBytes
			perBackendStats[backendKey].upstreamTxBytes += metric.Value.TxBytes
		}
	}

	totalBytes := totalDownstreamRx + totalDownstreamTx + totalUpstreamRx + totalUpstreamTx

	var avgRate float64
	var estimatedDownstreamRxDaily, estimatedDownstreamTxDaily, estimatedUpstreamRxDaily, estimatedUpstreamTxDaily, estimatedTotalDaily uint64

	if elapsed.Seconds() > 0 {
		avgRate = float64(totalBytes) / elapsed.Seconds()

		secondsInDay := float64(24 * 60 * 60)
		estimatedDownstreamRxDaily = uint64(float64(totalDownstreamRx) / elapsed.Seconds() * secondsInDay)
		estimatedDownstreamTxDaily = uint64(float64(totalDownstreamTx) / elapsed.Seconds() * secondsInDay)
		estimatedUpstreamRxDaily = uint64(float64(totalUpstreamRx) / elapsed.Seconds() * secondsInDay)
		estimatedUpstreamTxDaily = uint64(float64(totalUpstreamTx) / elapsed.Seconds() * secondsInDay)
		estimatedTotalDaily = estimatedDownstreamRxDaily + estimatedDownstreamTxDaily + estimatedUpstreamRxDaily + estimatedUpstreamTxDaily
	}

	fmt.Printf("\n")
	fmt.Printf("                         wg-relay(%s) traffic statistics\n", mode)
	fmt.Printf("\n")
	fmt.Printf(" %-18s | %12s | %12s | %12s | %12s | %12s | %12s\n", "", "down_rx", "down_tx", "up_rx", "up_tx", "total", "avg. rate")
	fmt.Printf(" %s+%s+%s+%s+%s+%s+%s\n",
		strings.Repeat("-", 18),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14))
	fmt.Printf(" %-18s | %12s | %12s | %12s | %12s | %12s | %9s/s\n", "traffic",
		formatBytes(totalDownstreamRx),
		formatBytes(totalDownstreamTx),
		formatBytes(totalUpstreamRx),
		formatBytes(totalUpstreamTx),
		formatBytes(totalBytes),
		formatBytes(uint64(avgRate)))
	fmt.Printf(" %s+%s+%s+%s+%s+%s+%s\n",
		strings.Repeat("-", 18),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14))
	fmt.Printf(" %-18s | %12s | %12s | %12s | %12s | %12s |\n", "estimated",
		formatBytes(estimatedDownstreamRxDaily),
		formatBytes(estimatedDownstreamTxDaily),
		formatBytes(estimatedUpstreamRxDaily),
		formatBytes(estimatedUpstreamTxDaily),
		formatBytes(estimatedTotalDaily))

	if len(perBackendStats) > 0 {
		fmt.Printf("\n")
		if mode == "forward" {
			fmt.Printf(" Per-backend statistics:\n")
			fmt.Printf(" %-18s | %12s | %12s | %12s | %12s | %12s\n", "backend", "down_rx", "down_tx", "up_rx", "up_tx", "total")
		} else {
			fmt.Printf(" Per-direction statistics:\n")
			fmt.Printf(" %-18s | %12s | %12s | %12s | %12s | %12s\n", "direction", "down_rx", "down_tx", "up_rx", "up_tx", "total")
		}
		fmt.Printf(" %s+%s+%s+%s+%s+%s\n",
			strings.Repeat("-", 18),
			strings.Repeat("-", 14),
			strings.Repeat("-", 14),
			strings.Repeat("-", 14),
			strings.Repeat("-", 14),
			strings.Repeat("-", 14))

		type backendEntry struct {
			label string
			stats *directionStats
			total uint64
		}
		sortedBackends := make([]backendEntry, 0, len(perBackendStats))
		for label, stats := range perBackendStats {
			sortedBackends = append(sortedBackends, backendEntry{
				label: label,
				stats: stats,
				total: stats.downstreamRxBytes + stats.downstreamTxBytes + stats.upstreamRxBytes + stats.upstreamTxBytes,
			})
		}
		sort.Slice(sortedBackends, func(i, j int) bool {
			return sortedBackends[i].total > sortedBackends[j].total
		})

		displayCount := len(sortedBackends)
		if tp.maxSources > 0 && displayCount > tp.maxSources {
			displayCount = tp.maxSources
		}

		for i := 0; i < displayCount; i++ {
			entry := sortedBackends[i]
			fmt.Printf(" %-18s | %12s | %12s | %12s | %12s | %12s\n",
				entry.label,
				formatBytes(entry.stats.downstreamRxBytes),
				formatBytes(entry.stats.downstreamTxBytes),
				formatBytes(entry.stats.upstreamRxBytes),
				formatBytes(entry.stats.upstreamTxBytes),
				formatBytes(entry.total))
		}

		if tp.maxSources > 0 && len(sortedBackends) > tp.maxSources {
			fmt.Printf(" ... and %d more backends\n", len(sortedBackends)-tp.maxSources)
		}
	}

	fmt.Printf("\n")
}

func (tp *TablePrinter) clearScreen() {
	fmt.Print("\033c")
}

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
