package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/stillya/wg-relay/pkg/api"
)

type Printer struct {
	out io.Writer
	err io.Writer
}

func NewPrinter() *Printer {
	return &Printer{
		out: os.Stdout,
		err: os.Stderr,
	}
}

func (p *Printer) printf(w io.Writer, format string, args ...interface{}) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
	}
}

func (p *Printer) Print(msg string) {
	p.printf(p.out, "%s\n", msg)
}

func (p *Printer) Printf(format string, args ...interface{}) {
	p.printf(p.out, format, args...)
}

func (p *Printer) Error(format string, args ...interface{}) {
	p.printf(p.err, format, args...)
}

func (p *Printer) PrintStatus(status *api.StatusResponse) {
	p.Printf("State:      %s\n", status.State)
	p.Printf("Uptime:     %s\n", formatDuration(status.Uptime))

	if status.Mode != "" {
		p.Printf("Mode:       %s\n", status.Mode)
	}

	if len(status.Interfaces) > 0 {
		p.Printf("Interfaces: %v\n", status.Interfaces)
	}

	if status.ErrorMessage != "" {
		p.Printf("Error:      %s\n", status.ErrorMessage)
	}
}

func (p *Printer) PrintStats(stats *api.StatsResponse) {
	if len(stats.Metrics) == 0 {
		p.Print("No metrics available")
		return
	}

	type srcStats struct {
		rxBytes uint64
		txBytes uint64
	}

	perSrcStats := make(map[string]*srcStats)
	var rxBytes, txBytes uint64

	for _, metric := range stats.Metrics {
		if metric.Reason == "forwarded" {
			srcAddr := metric.SrcAddr

			if _, exists := perSrcStats[srcAddr]; !exists {
				perSrcStats[srcAddr] = &srcStats{}
			}

			if metric.Direction == "from_wg" {
				rxBytes += metric.Bytes
				perSrcStats[srcAddr].rxBytes += metric.Bytes
			} else if metric.Direction == "to_wg" {
				txBytes += metric.Bytes
				perSrcStats[srcAddr].txBytes += metric.Bytes
			}
		}
	}

	totalBytes := rxBytes + txBytes
	avgRate := float64(totalBytes) / stats.Uptime.Seconds()

	secondsInDay := float64(24 * 60 * 60)
	estimatedRxDaily := uint64(float64(rxBytes) / stats.Uptime.Seconds() * secondsInDay)
	estimatedTxDaily := uint64(float64(txBytes) / stats.Uptime.Seconds() * secondsInDay)
	estimatedTotalDaily := estimatedRxDaily + estimatedTxDaily

	p.Printf("\n")
	p.Printf("                         wg-relay traffic statistics\n")
	p.Printf("\n")
	p.Printf(" %-18s | %12s | %12s | %12s | %12s\n", "", "from_wg", "to_wg", "total", "avg. rate")
	p.Printf(" %s+%s+%s+%s+%s\n",
		strings.Repeat("-", 18),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14))
	p.Printf(" %-18s | %12s | %12s | %12s | %9s/s\n", "traffic",
		formatBytes(rxBytes),
		formatBytes(txBytes),
		formatBytes(totalBytes),
		formatBytes(uint64(avgRate)))
	p.Printf(" %s+%s+%s+%s+%s\n",
		strings.Repeat("-", 18),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14),
		strings.Repeat("-", 14))
	p.Printf(" %-18s | %12s | %12s | %12s |\n", "estimated",
		formatBytes(estimatedRxDaily),
		formatBytes(estimatedTxDaily),
		formatBytes(estimatedTotalDaily))

	if len(perSrcStats) > 0 {
		p.Printf("\n")
		p.Printf(" Per-source statistics:\n")
		p.Printf(" %-18s | %12s | %12s | %12s\n", "src_addr", "from_wg", "to_wg", "total")
		p.Printf(" %s+%s+%s+%s\n",
			strings.Repeat("-", 18),
			strings.Repeat("-", 14),
			strings.Repeat("-", 14),
			strings.Repeat("-", 14))

		for srcAddr, stats := range perSrcStats {
			total := stats.rxBytes + stats.txBytes
			p.Printf(" %-18s | %12s | %12s | %12s\n",
				srcAddr,
				formatBytes(stats.rxBytes),
				formatBytes(stats.txBytes),
				formatBytes(total))
		}
	}

	p.Printf("\n")
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
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
