package metrics

import (
	"context"
	log "log/slog"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stillya/wg-relay/pkg/maps/paddingmap"
)

// PaddingStateSource collects adaptive padding state and resolves interface names.
type PaddingStateSource interface {
	Collect(ctx context.Context) ([]paddingmap.StateData, error)
	IfName(ifindex uint32) string
	Name() string
}

// PaddingCollector exposes the current adaptive padding working size per
// interface and CPU. Aggregates (min/max/avg) are intentionally left to PromQL.
type PaddingCollector struct {
	source PaddingStateSource

	sizeDesc *prometheus.Desc
}

// NewPaddingCollector creates a new PaddingCollector.
func NewPaddingCollector(source PaddingStateSource) *PaddingCollector {
	return &PaddingCollector{
		source: source,
		sizeDesc: prometheus.NewDesc(
			"wg_relay_padding_size_bytes",
			"Current adaptive padding working size in bytes (AIMD), per interface and CPU",
			[]string{"interface", "cpu"},
			nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *PaddingCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.sizeDesc
}

// Collect implements prometheus.Collector.
func (c *PaddingCollector) Collect(ch chan<- prometheus.Metric) {
	states, err := c.source.Collect(context.Background())
	if err != nil {
		log.Error("Failed to collect padding state", "error", err)
		return
	}

	for _, s := range states {
		ch <- prometheus.MustNewConstMetric(
			c.sizeDesc,
			prometheus.GaugeValue,
			float64(s.State.CurrentSize),
			c.source.IfName(s.IfIndex),
			strconv.Itoa(s.CPU),
		)
	}
}
