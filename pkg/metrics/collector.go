package metrics

import (
	"context"
	log "log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stillya/wg-relay/pkg/maps/metricsmap"
)

type MetricCollectorSource interface {
	Collect(ctx context.Context) ([]metricsmap.MetricData, error)
	Name() string
}

type BpfCollector struct {
	source MetricCollectorSource

	packetsDesc *prometheus.Desc
	bytesDesc   *prometheus.Desc
}

func NewBpfCollector(source MetricCollectorSource) *BpfCollector {
	return &BpfCollector{
		source: source,
		packetsDesc: prometheus.NewDesc(
			"wg_relay_packets_total",
			"Total number of WireGuard packets processed",
			[]string{"direction", "reason"},
			nil,
		),
		bytesDesc: prometheus.NewDesc(
			"wg_relay_bytes_total",
			"Total bytes of WireGuard packets processed",
			[]string{"direction", "reason"},
			nil,
		),
	}
}

func (c *BpfCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.packetsDesc
	ch <- c.bytesDesc
}

func (c *BpfCollector) Collect(ch chan<- prometheus.Metric) {
	ctx := context.Background()
	metricsData, err := c.source.Collect(ctx)
	if err != nil {
		log.Error("Failed to collect metrics", "error", err)
		return
	}

	for _, metric := range metricsData {
		dirLabel := metricsmap.DirectionToString(metric.Key.Dir)
		reasonLabel := metricsmap.ReasonToString(metric.Key.Reason)

		ch <- prometheus.MustNewConstMetric(
			c.packetsDesc,
			prometheus.CounterValue,
			float64(metric.Value.Packets),
			dirLabel, reasonLabel,
		)

		ch <- prometheus.MustNewConstMetric(
			c.bytesDesc,
			prometheus.CounterValue,
			float64(metric.Value.Bytes),
			dirLabel, reasonLabel,
		)
	}
}
