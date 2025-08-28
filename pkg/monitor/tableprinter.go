package monitor

import (
	"fmt"
	"strings"
	"time"

	"github.com/stillya/wg-relay/pkg/maps/metricsmap"
)

type TablePrinter struct{}

func (tp *TablePrinter) PrintTrafficTable(metricsData []metricsmap.MetricData, elapsed time.Duration) {
	tp.clearScreen()

	var rxBytes, txBytes uint64
	for _, metric := range metricsData {
		if metric.Key.Dir == metricsmap.MetricFromWg && metric.Key.Reason == metricsmap.MetricForwarded {
			rxBytes += metric.Value.Bytes
		} else if metric.Key.Dir == metricsmap.MetricToWg && metric.Key.Reason == metricsmap.MetricForwarded {
			txBytes += metric.Value.Bytes
		}
	}

	totalBytes := rxBytes + txBytes
	avgRate := float64(totalBytes) / elapsed.Seconds()

	// Calculate estimated daily usage based on current rate
	secondsInDay := float64(24 * 60 * 60)
	estimatedRxDaily := uint64(float64(rxBytes) / elapsed.Seconds() * secondsInDay)
	estimatedTxDaily := uint64(float64(txBytes) / elapsed.Seconds() * secondsInDay)
	estimatedTotalDaily := estimatedRxDaily + estimatedTxDaily

	fmt.Printf("\n")
	fmt.Printf("                         wg-relay traffic statistics\n")
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
