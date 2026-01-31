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
	maxSources int
}

// PrintTrafficTable prints a formatted table of traffic statistics.
func (tp *TablePrinter) PrintTrafficTable(mode string, metricsData []metricsmap.MetricData, elapsed time.Duration) {
	tp.clearScreen()

	type srcStats struct {
		rxBytes uint64
		txBytes uint64
	}

	perSrcStats := make(map[string]*srcStats)
	var rxBytes, txBytes uint64

	for _, metric := range metricsData {
		if metric.Key.Reason == metricsmap.MetricForwarded {
			srcAddr := metricsmap.SrcAddrToString(metric.Key.SrcAddr)

			if _, exists := perSrcStats[srcAddr]; !exists {
				perSrcStats[srcAddr] = &srcStats{}
			}

			switch metric.Key.Dir {
			case metricsmap.MetricFromWg:
				rxBytes += metric.Value.Bytes
				perSrcStats[srcAddr].rxBytes += metric.Value.Bytes
			case metricsmap.MetricToWg:
				txBytes += metric.Value.Bytes
				perSrcStats[srcAddr].txBytes += metric.Value.Bytes
			}
		}
	}

	totalBytes := rxBytes + txBytes
	avgRate := float64(totalBytes) / elapsed.Seconds()

	secondsInDay := float64(24 * 60 * 60)
	estimatedRxDaily := uint64(float64(rxBytes) / elapsed.Seconds() * secondsInDay)
	estimatedTxDaily := uint64(float64(txBytes) / elapsed.Seconds() * secondsInDay)
	estimatedTotalDaily := estimatedRxDaily + estimatedTxDaily

	fmt.Printf("\n")
	fmt.Printf("                         wg-relay(%s) traffic statistics\n", mode)
	fmt.Printf("\n")
	fmt.Printf(" %-18s | %12s | %12s | %12s | %12s\n", "", "from_wg", "to_wg", "total", "avg. rate")
	fmt.Printf(" %s+%s+%s+%s+%s\n",
		strings.Repeat("-", 18),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14))
	fmt.Printf(" %-18s | %12s | %12s | %12s | %9s/s\n", "traffic",
		formatBytes(rxBytes),
		formatBytes(txBytes),
		formatBytes(totalBytes),
		formatBytes(uint64(avgRate)))
	fmt.Printf(" %s+%s+%s+%s+%s\n",
		strings.Repeat("-", 18),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14))
	fmt.Printf(" %-18s | %12s | %12s | %12s |\n", "estimated",
		formatBytes(estimatedRxDaily),
		formatBytes(estimatedTxDaily),
		formatBytes(estimatedTotalDaily))

	if len(perSrcStats) > 0 {
		fmt.Printf("\n")
		fmt.Printf(" Per-source statistics:\n")
		fmt.Printf(" %-18s | %12s | %12s | %12s\n", "src_addr", "from_wg", "to_wg", "total")
		fmt.Printf(" %s+%s+%s+%s\n",
			strings.Repeat("-", 18),
			strings.Repeat("-", 14),
			strings.Repeat("-", 14),
			strings.Repeat("-", 14))

		type srcEntry struct {
			addr  string
			stats *srcStats
			total uint64
		}
		sortedSources := make([]srcEntry, 0, len(perSrcStats))
		for addr, stats := range perSrcStats {
			sortedSources = append(sortedSources, srcEntry{
				addr:  addr,
				stats: stats,
				total: stats.rxBytes + stats.txBytes,
			})
		}
		sort.Slice(sortedSources, func(i, j int) bool {
			return sortedSources[i].total > sortedSources[j].total
		})

		displayCount := len(sortedSources)
		if tp.maxSources > 0 && displayCount > tp.maxSources {
			displayCount = tp.maxSources
		}

		for i := 0; i < displayCount; i++ {
			entry := sortedSources[i]
			fmt.Printf(" %-18s | %12s | %12s | %12s\n",
				entry.addr,
				formatBytes(entry.stats.rxBytes),
				formatBytes(entry.stats.txBytes),
				formatBytes(entry.total))
		}

		if tp.maxSources > 0 && len(sortedSources) > tp.maxSources {
			fmt.Printf(" ... and %d more sources\n", len(sortedSources)-tp.maxSources)
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
