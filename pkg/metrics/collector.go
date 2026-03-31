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
	source        MetricCollectorSource
	mode          string
	backendLabels map[uint8]string

	forwardDownstreamRxPacketsDesc *prometheus.Desc
	forwardDownstreamTxPacketsDesc *prometheus.Desc
	forwardDownstreamRxBytesDesc   *prometheus.Desc
	forwardDownstreamTxBytesDesc   *prometheus.Desc
	forwardUpstreamRxPacketsDesc   *prometheus.Desc
	forwardUpstreamTxPacketsDesc   *prometheus.Desc
	forwardUpstreamRxBytesDesc     *prometheus.Desc
	forwardUpstreamTxBytesDesc     *prometheus.Desc

	reverseDownstreamRxPacketsDesc *prometheus.Desc
	reverseDownstreamTxPacketsDesc *prometheus.Desc
	reverseDownstreamRxBytesDesc   *prometheus.Desc
	reverseDownstreamTxBytesDesc   *prometheus.Desc
	reverseUpstreamRxPacketsDesc   *prometheus.Desc
	reverseUpstreamTxPacketsDesc   *prometheus.Desc
	reverseUpstreamRxBytesDesc     *prometheus.Desc
	reverseUpstreamTxBytesDesc     *prometheus.Desc
}

// NewBpfCollector creates a new BpfCollector with the given source, mode, and backend labels.
func NewBpfCollector(source MetricCollectorSource, mode string, backendLabels map[uint8]string) *BpfCollector {
	if backendLabels == nil {
		backendLabels = make(map[uint8]string)
	}

	return &BpfCollector{
		source:        source,
		mode:          mode,
		backendLabels: backendLabels,

		forwardDownstreamRxPacketsDesc: prometheus.NewDesc(
			"wg_relay_forward_downstream_rq_rx_packets_total",
			"Total packets received on downstream (client to proxy) in forward mode",
			[]string{"backend"},
			nil,
		),
		forwardDownstreamTxPacketsDesc: prometheus.NewDesc(
			"wg_relay_forward_downstream_rq_tx_packets_total",
			"Total packets transmitted on downstream (proxy to client) in forward mode",
			[]string{"backend"},
			nil,
		),
		forwardDownstreamRxBytesDesc: prometheus.NewDesc(
			"wg_relay_forward_downstream_rq_rx_bytes_total",
			"Total bytes received on downstream (client to proxy) in forward mode",
			[]string{"backend"},
			nil,
		),
		forwardDownstreamTxBytesDesc: prometheus.NewDesc(
			"wg_relay_forward_downstream_rq_tx_bytes_total",
			"Total bytes transmitted on downstream (proxy to client) in forward mode",
			[]string{"backend"},
			nil,
		),
		forwardUpstreamRxPacketsDesc: prometheus.NewDesc(
			"wg_relay_forward_upstream_rq_rx_packets_total",
			"Total packets received on upstream (backend to proxy) in forward mode",
			[]string{"backend"},
			nil,
		),
		forwardUpstreamTxPacketsDesc: prometheus.NewDesc(
			"wg_relay_forward_upstream_rq_tx_packets_total",
			"Total packets transmitted on upstream (proxy to backend) in forward mode",
			[]string{"backend"},
			nil,
		),
		forwardUpstreamRxBytesDesc: prometheus.NewDesc(
			"wg_relay_forward_upstream_rq_rx_bytes_total",
			"Total bytes received on upstream (backend to proxy) in forward mode",
			[]string{"backend"},
			nil,
		),
		forwardUpstreamTxBytesDesc: prometheus.NewDesc(
			"wg_relay_forward_upstream_rq_tx_bytes_total",
			"Total bytes transmitted on upstream (proxy to backend) in forward mode",
			[]string{"backend"},
			nil,
		),

		reverseDownstreamRxPacketsDesc: prometheus.NewDesc(
			"wg_relay_reverse_downstream_rq_rx_packets_total",
			"Total packets received on downstream (client to proxy) in reverse mode",
			nil,
			nil,
		),
		reverseDownstreamTxPacketsDesc: prometheus.NewDesc(
			"wg_relay_reverse_downstream_rq_tx_packets_total",
			"Total packets transmitted on downstream (proxy to client) in reverse mode",
			nil,
			nil,
		),
		reverseDownstreamRxBytesDesc: prometheus.NewDesc(
			"wg_relay_reverse_downstream_rq_rx_bytes_total",
			"Total bytes received on downstream (client to proxy) in reverse mode",
			nil,
			nil,
		),
		reverseDownstreamTxBytesDesc: prometheus.NewDesc(
			"wg_relay_reverse_downstream_rq_tx_bytes_total",
			"Total bytes transmitted on downstream (proxy to client) in reverse mode",
			nil,
			nil,
		),
		reverseUpstreamRxPacketsDesc: prometheus.NewDesc(
			"wg_relay_reverse_upstream_rq_rx_packets_total",
			"Total packets received on upstream (WireGuard to proxy) in reverse mode",
			nil,
			nil,
		),
		reverseUpstreamTxPacketsDesc: prometheus.NewDesc(
			"wg_relay_reverse_upstream_rq_tx_packets_total",
			"Total packets transmitted on upstream (proxy to WireGuard) in reverse mode",
			nil,
			nil,
		),
		reverseUpstreamRxBytesDesc: prometheus.NewDesc(
			"wg_relay_reverse_upstream_rq_rx_bytes_total",
			"Total bytes received on upstream (WireGuard to proxy) in reverse mode",
			nil,
			nil,
		),
		reverseUpstreamTxBytesDesc: prometheus.NewDesc(
			"wg_relay_reverse_upstream_rq_tx_bytes_total",
			"Total bytes transmitted on upstream (proxy to WireGuard) in reverse mode",
			nil,
			nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *BpfCollector) Describe(ch chan<- *prometheus.Desc) {
	if c.mode == "forward" {
		ch <- c.forwardDownstreamRxPacketsDesc
		ch <- c.forwardDownstreamTxPacketsDesc
		ch <- c.forwardDownstreamRxBytesDesc
		ch <- c.forwardDownstreamTxBytesDesc
		ch <- c.forwardUpstreamRxPacketsDesc
		ch <- c.forwardUpstreamTxPacketsDesc
		ch <- c.forwardUpstreamRxBytesDesc
		ch <- c.forwardUpstreamTxBytesDesc
	} else {
		ch <- c.reverseDownstreamRxPacketsDesc
		ch <- c.reverseDownstreamTxPacketsDesc
		ch <- c.reverseDownstreamRxBytesDesc
		ch <- c.reverseDownstreamTxBytesDesc
		ch <- c.reverseUpstreamRxPacketsDesc
		ch <- c.reverseUpstreamTxPacketsDesc
		ch <- c.reverseUpstreamRxBytesDesc
		ch <- c.reverseUpstreamTxBytesDesc
	}
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
		var rxPacketsDesc, txPacketsDesc, rxBytesDesc, txBytesDesc *prometheus.Desc
		var labels []string

		if c.mode == "forward" {
			backendLabel := c.backendLabels[metric.Key.BackendIndex]
			if backendLabel == "" {
				backendLabel = metricsmap.BackendIndexToString(metric.Key.BackendIndex)
			}
			labels = []string{backendLabel}

			if metric.Key.Direction == metricsmap.MetricDownstream {
				rxPacketsDesc = c.forwardDownstreamRxPacketsDesc
				txPacketsDesc = c.forwardDownstreamTxPacketsDesc
				rxBytesDesc = c.forwardDownstreamRxBytesDesc
				txBytesDesc = c.forwardDownstreamTxBytesDesc
			} else {
				rxPacketsDesc = c.forwardUpstreamRxPacketsDesc
				txPacketsDesc = c.forwardUpstreamTxPacketsDesc
				rxBytesDesc = c.forwardUpstreamRxBytesDesc
				txBytesDesc = c.forwardUpstreamTxBytesDesc
			}
		} else {
			labels = nil

			if metric.Key.Direction == metricsmap.MetricDownstream {
				rxPacketsDesc = c.reverseDownstreamRxPacketsDesc
				txPacketsDesc = c.reverseDownstreamTxPacketsDesc
				rxBytesDesc = c.reverseDownstreamRxBytesDesc
				txBytesDesc = c.reverseDownstreamTxBytesDesc
			} else {
				rxPacketsDesc = c.reverseUpstreamRxPacketsDesc
				txPacketsDesc = c.reverseUpstreamTxPacketsDesc
				rxBytesDesc = c.reverseUpstreamRxBytesDesc
				txBytesDesc = c.reverseUpstreamTxBytesDesc
			}
		}

		ch <- prometheus.MustNewConstMetric(
			rxPacketsDesc,
			prometheus.CounterValue,
			float64(metric.Value.RxPackets),
			labels...,
		)

		ch <- prometheus.MustNewConstMetric(
			txPacketsDesc,
			prometheus.CounterValue,
			float64(metric.Value.TxPackets),
			labels...,
		)

		ch <- prometheus.MustNewConstMetric(
			rxBytesDesc,
			prometheus.CounterValue,
			float64(metric.Value.RxBytes),
			labels...,
		)

		ch <- prometheus.MustNewConstMetric(
			txBytesDesc,
			prometheus.CounterValue,
			float64(metric.Value.TxBytes),
			labels...,
		)
	}
}
