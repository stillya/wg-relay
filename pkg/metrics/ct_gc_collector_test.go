package metrics

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stillya/wg-relay/pkg/maps/ctmap"
)

func TestCTGCCollectorSuccess(t *testing.T) {
	c := NewCTGCCollector()

	c.ObserveGC(ctmap.Stats{Alive: 10, Deleted: 3, OrphansDeleted: 1, Duration: time.Millisecond}, nil)
	c.ObserveGC(ctmap.Stats{Alive: 7, Deleted: 2, OrphansDeleted: 4, Duration: time.Millisecond}, nil)

	if got := testutil.ToFloat64(c.entries); got != 7 {
		t.Errorf("entries = %v, want 7", got)
	}
	if got := testutil.ToFloat64(c.deleted.WithLabelValues("expired")); got != 5 {
		t.Errorf("deleted expired = %v, want 5", got)
	}
	if got := testutil.ToFloat64(c.deleted.WithLabelValues("orphan")); got != 5 {
		t.Errorf("deleted orphan = %v, want 5", got)
	}
	if got := testutil.ToFloat64(c.runs.WithLabelValues("success")); got != 2 {
		t.Errorf("runs success = %v, want 2", got)
	}
	if got := testutil.ToFloat64(c.runs.WithLabelValues("error")); got != 0 {
		t.Errorf("runs error = %v, want 0", got)
	}
	if got := testutil.CollectAndCount(c.duration); got != 1 {
		t.Errorf("duration series = %d, want 1", got)
	}
}

func TestCTGCCollectorError(t *testing.T) {
	c := NewCTGCCollector()

	c.ObserveGC(ctmap.Stats{Alive: 10, Deleted: 3, OrphansDeleted: 1}, nil)
	c.ObserveGC(ctmap.Stats{Alive: 99, Deleted: 99, OrphansDeleted: 99}, errors.New("boom"))

	if got := testutil.ToFloat64(c.runs.WithLabelValues("error")); got != 1 {
		t.Errorf("runs error = %v, want 1", got)
	}
	if got := testutil.ToFloat64(c.runs.WithLabelValues("success")); got != 1 {
		t.Errorf("runs success = %v, want 1", got)
	}
	if got := testutil.ToFloat64(c.entries); got != 10 {
		t.Errorf("entries = %v, want 10", got)
	}
	if got := testutil.ToFloat64(c.deleted.WithLabelValues("expired")); got != 3 {
		t.Errorf("deleted expired = %v, want 3", got)
	}
	if got := testutil.ToFloat64(c.deleted.WithLabelValues("orphan")); got != 1 {
		t.Errorf("deleted orphan = %v, want 1", got)
	}
}

func TestCTGCCollectorRegisters(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(NewCTGCCollector()); err != nil {
		t.Fatalf("register: %v", err)
	}
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if len(mfs) != 4 {
		t.Errorf("metric families = %d, want 4", len(mfs))
	}
}
