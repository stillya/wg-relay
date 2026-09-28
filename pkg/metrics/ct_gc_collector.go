package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stillya/wg-relay/pkg/maps/ctmap"
	"github.com/stillya/wg-relay/pkg/maps/ctmap/gc"
)

var _ gc.Observer = (*CTGCCollector)(nil)

// CTGCCollector exposes the results of conntrack GC runs.
type CTGCCollector struct {
	entries  prometheus.Gauge
	deleted  *prometheus.CounterVec
	runs     *prometheus.CounterVec
	duration prometheus.Histogram
}

// NewCTGCCollector creates a new CTGCCollector.
func NewCTGCCollector() *CTGCCollector {
	c := &CTGCCollector{
		entries: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "wg_relay_forward_ct_entries",
			Help: "Alive conntrack entries after the last GC run",
		}),
		deleted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wg_relay_forward_ct_gc_deleted_total",
			Help: "Conntrack entries deleted by GC, by reason",
		}, []string{"reason"}),
		runs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "wg_relay_forward_ct_gc_runs_total",
			Help: "Conntrack GC runs, by status",
		}, []string{"status"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "wg_relay_forward_ct_gc_duration_seconds",
			Help: "Duration of successful conntrack GC runs",
		}),
	}

	for _, reason := range []string{"expired", "orphan"} {
		c.deleted.WithLabelValues(reason)
	}
	for _, status := range []string{"success", "error"} {
		c.runs.WithLabelValues(status)
	}

	return c
}

// Describe implements prometheus.Collector.
func (c *CTGCCollector) Describe(ch chan<- *prometheus.Desc) {
	c.entries.Describe(ch)
	c.deleted.Describe(ch)
	c.runs.Describe(ch)
	c.duration.Describe(ch)
}

// Collect implements prometheus.Collector.
func (c *CTGCCollector) Collect(ch chan<- prometheus.Metric) {
	c.entries.Collect(ch)
	c.deleted.Collect(ch)
	c.runs.Collect(ch)
	c.duration.Collect(ch)
}

// ObserveGC implements gc.Observer. Stats of a failed run are ignored.
func (c *CTGCCollector) ObserveGC(stats ctmap.Stats, err error) {
	if err != nil {
		c.runs.WithLabelValues("error").Inc()
		return
	}

	c.runs.WithLabelValues("success").Inc()
	c.entries.Set(float64(stats.Alive))
	c.deleted.WithLabelValues("expired").Add(float64(stats.Deleted))
	c.deleted.WithLabelValues("orphan").Add(float64(stats.OrphansDeleted))
	c.duration.Observe(stats.Duration.Seconds())
}
