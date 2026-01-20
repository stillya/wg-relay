package metrics

import (
	"context"
	log "log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stillya/wg-relay/pkg/maps/metricsmap"
)

// MetricCollectorSource defines the interface for collecting metrics from BPF maps.
type MetricCollectorSource interface {
	Collect(ctx context.Context) ([]metricsmap.MetricData, error)
	Name() string
}

// BpfCollector implements prometheus.Collector for BPF metrics.
type BpfCollector struct {
	source MetricCollectorSource
	mode   string

	rxPacketsDesc *prometheus.Desc
	txPacketsDesc *prometheus.Desc
	rxBytesDesc   *prometheus.Desc
	txBytesDesc   *prometheus.Desc
}

// NewBpfCollector creates a new BpfCollector with the given source and mode.
func NewBpfCollector(source MetricCollectorSource, mode string) *BpfCollector {
	return &BpfCollector{
		source: source,
		mode:   mode,
		rxPacketsDesc: prometheus.NewDesc(
			"wg_relay_rx_packets_total",
			"Total number of WireGuard packets received",
			[]string{"mode", "reason", "src_addr"},
			nil,
		),
		txPacketsDesc: prometheus.NewDesc(
			"wg_relay_tx_packets_total",
			"Total number of WireGuard packets transmitted",
			[]string{"mode", "reason", "src_addr"},
			nil,
		),
		rxBytesDesc: prometheus.NewDesc(
			"wg_relay_rx_bytes_total",
			"Total bytes of WireGuard packets received",
			[]string{"mode", "reason", "src_addr"},
			nil,
		),
		txBytesDesc: prometheus.NewDesc(
			"wg_relay_tx_bytes_total",
			"Total bytes of WireGuard packets transmitted",
			[]string{"mode", "reason", "src_addr"},
			nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *BpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.rxPacketsDesc
	ch <- c.txPacketsDesc
	ch <- c.rxBytesDesc
	ch <- c.txBytesDesc
}

// Collect implements prometheus.Collector.
func (c *BpfCollector) Collect(ch chan<- prometheus.Metric) {
	ctx := context.Background()
	metricsData, err := c.source.Collect(ctx)
	if err != nil {
		log.Error("Failed to collect metrics", "error", err)
		return
	}

	for _, metric := range metricsData {
		reasonLabel := metricsmap.ReasonToString(metric.Key.Reason)
		srcAddrLabel := metricsmap.SrcAddrToString(metric.Key.SrcAddr)

		var packetsDesc, bytesDesc *prometheus.Desc
		if metric.Key.Dir == metricsmap.MetricFromWg {
			packetsDesc = c.txPacketsDesc
			bytesDesc = c.txBytesDesc
		} else {
			packetsDesc = c.rxPacketsDesc
			bytesDesc = c.rxBytesDesc
		}

		ch <- prometheus.MustNewConstMetric(
			packetsDesc,
			prometheus.CounterValue,
			float64(metric.Value.Packets),
			c.mode, reasonLabel, srcAddrLabel,
		)

		ch <- prometheus.MustNewConstMetric(
			bytesDesc,
			prometheus.CounterValue,
			float64(metric.Value.Bytes),
			c.mode, reasonLabel, srcAddrLabel,
		)
	}
}
