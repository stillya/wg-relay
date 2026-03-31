package metrics

import (
	"context"
	log "log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stillya/wg-relay/pkg/maps/metricsmap"
)

// BackendDiscovery provides backend label resolution.
type BackendDiscovery interface {
	Backends() map[uint8]string
}

// MetricCollectorSource defines the interface for collecting metrics from BPF maps.
type MetricCollectorSource interface {
	Collect(ctx context.Context) ([]metricsmap.MetricData, error)
	Name() string
}

// BpfCollector implements prometheus.Collector for BPF metrics.
type BpfCollector struct {
	source   MetricCollectorSource
	mode     string
	backends BackendDiscovery

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

// NewBpfCollector creates a new BpfCollector with the given source, mode, and backend discovery.
func NewBpfCollector(source MetricCollectorSource, mode string, backends BackendDiscovery) *BpfCollector {

	return &BpfCollector{
		source:   source,
		mode:     mode,
		backends: backends,

		forwardDownstreamRxPacketsDesc: prometheus.NewDesc(
			"wg_relay_forward_downstream_rq_rx_packets_total",
			"Total packets received on downstream (client to proxy) in forward mode",
			[]string{"backend", "reason"},
			nil,
		),
		forwardDownstreamTxPacketsDesc: prometheus.NewDesc(
			"wg_relay_forward_downstream_rq_tx_packets_total",
			"Total packets transmitted on downstream (proxy to client) in forward mode",
			[]string{"backend", "reason"},
			nil,
		),
		forwardDownstreamRxBytesDesc: prometheus.NewDesc(
			"wg_relay_forward_downstream_rq_rx_bytes_total",
			"Total bytes received on downstream (client to proxy) in forward mode",
			[]string{"backend", "reason"},
			nil,
		),
		forwardDownstreamTxBytesDesc: prometheus.NewDesc(
			"wg_relay_forward_downstream_rq_tx_bytes_total",
			"Total bytes transmitted on downstream (proxy to client) in forward mode",
			[]string{"backend", "reason"},
			nil,
		),
		forwardUpstreamRxPacketsDesc: prometheus.NewDesc(
			"wg_relay_forward_upstream_rq_rx_packets_total",
			"Total packets received on upstream (backend to proxy) in forward mode",
			[]string{"backend", "reason"},
			nil,
		),
		forwardUpstreamTxPacketsDesc: prometheus.NewDesc(
			"wg_relay_forward_upstream_rq_tx_packets_total",
			"Total packets transmitted on upstream (proxy to backend) in forward mode",
			[]string{"backend", "reason"},
			nil,
		),
		forwardUpstreamRxBytesDesc: prometheus.NewDesc(
			"wg_relay_forward_upstream_rq_rx_bytes_total",
			"Total bytes received on upstream (backend to proxy) in forward mode",
			[]string{"backend", "reason"},
			nil,
		),
		forwardUpstreamTxBytesDesc: prometheus.NewDesc(
			"wg_relay_forward_upstream_rq_tx_bytes_total",
			"Total bytes transmitted on upstream (proxy to backend) in forward mode",
			[]string{"backend", "reason"},
			nil,
		),

		reverseDownstreamRxPacketsDesc: prometheus.NewDesc(
			"wg_relay_reverse_downstream_rq_rx_packets_total",
			"Total packets received on downstream (client to proxy) in reverse mode",
			[]string{"reason"},
			nil,
		),
		reverseDownstreamTxPacketsDesc: prometheus.NewDesc(
			"wg_relay_reverse_downstream_rq_tx_packets_total",
			"Total packets transmitted on downstream (proxy to client) in reverse mode",
			[]string{"reason"},
			nil,
		),
		reverseDownstreamRxBytesDesc: prometheus.NewDesc(
			"wg_relay_reverse_downstream_rq_rx_bytes_total",
			"Total bytes received on downstream (client to proxy) in reverse mode",
			[]string{"reason"},
			nil,
		),
		reverseDownstreamTxBytesDesc: prometheus.NewDesc(
			"wg_relay_reverse_downstream_rq_tx_bytes_total",
			"Total bytes transmitted on downstream (proxy to client) in reverse mode",
			[]string{"reason"},
			nil,
		),
		reverseUpstreamRxPacketsDesc: prometheus.NewDesc(
			"wg_relay_reverse_upstream_rq_rx_packets_total",
			"Total packets received on upstream (WireGuard to proxy) in reverse mode",
			[]string{"reason"},
			nil,
		),
		reverseUpstreamTxPacketsDesc: prometheus.NewDesc(
			"wg_relay_reverse_upstream_rq_tx_packets_total",
			"Total packets transmitted on upstream (proxy to WireGuard) in reverse mode",
			[]string{"reason"},
			nil,
		),
		reverseUpstreamRxBytesDesc: prometheus.NewDesc(
			"wg_relay_reverse_upstream_rq_rx_bytes_total",
			"Total bytes received on upstream (WireGuard to proxy) in reverse mode",
			[]string{"reason"},
			nil,
		),
		reverseUpstreamTxBytesDesc: prometheus.NewDesc(
			"wg_relay_reverse_upstream_rq_tx_bytes_total",
			"Total bytes transmitted on upstream (proxy to WireGuard) in reverse mode",
			[]string{"reason"},
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

	backendLabels := c.backends.Backends()

	for _, metric := range metricsData {
		var rxPacketsDesc, txPacketsDesc, rxBytesDesc, txBytesDesc *prometheus.Desc
		var labels []string

		reasonLabel := metricsmap.ReasonToString(metric.Key.Reason)

		if c.mode == "forward" {
			backendLabel := backendLabels[metric.Key.BackendIndex]
			if backendLabel == "" {
				backendLabel = metricsmap.BackendIndexToString(metric.Key.BackendIndex)
			}
			labels = []string{backendLabel, reasonLabel}

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
			labels = []string{reasonLabel}

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
