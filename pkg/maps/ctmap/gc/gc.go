package gc

import (
	"context"
	log "log/slog"
	"time"

	"github.com/stillya/wg-relay/pkg/maps/ctmap"
)

// Sweeper deletes expired conntrack entries.
type Sweeper interface {
	GC(ctx context.Context, timeout time.Duration) (ctmap.Stats, error)
}

// Observer receives the outcome of every GC run.
type Observer interface {
	ObserveGC(stats ctmap.Stats, err error)
}

// Params contains configuration for Runner.
type Params struct {
	Interval time.Duration
	Timeout  time.Duration
}

// Runner periodically runs the conntrack GC sweep.
type Runner struct {
	Params
	sweeper  Sweeper
	observer Observer
	stopCh   chan struct{}
}

// New creates a new Runner. The observer may be nil.
func New(params Params, sweeper Sweeper, observer Observer) *Runner {
	return &Runner{
		Params:   params,
		sweeper:  sweeper,
		observer: observer,
		stopCh:   make(chan struct{}),
	}
}

// Start runs the GC on every interval until the context is cancelled or Stop is called.
func (r *Runner) Start(ctx context.Context) {
	log.Info("Starting conntrack GC", "interval", r.Interval, "timeout", r.Timeout)

	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Conntrack GC stopped by context")
			return
		case <-r.stopCh:
			log.Info("Conntrack GC stopped")
			return
		case <-ticker.C:
			r.runOnce(ctx)
		}
	}
}

// Stop signals the runner to stop.
func (r *Runner) Stop() {
	close(r.stopCh)
}

func (r *Runner) runOnce(ctx context.Context) {
	stats, err := r.sweeper.GC(ctx, r.Timeout)
	if r.observer != nil {
		r.observer.ObserveGC(stats, err)
	}
	if err != nil {
		log.Error("conntrack gc failed", "error", err)
		return
	}

	logFn := log.Debug
	if stats.OrphansDeleted > 0 {
		logFn = log.Info
	}
	logFn("conntrack gc run",
		"alive", stats.Alive,
		"deleted", stats.Deleted,
		"orphans", stats.OrphansDeleted,
		"duration", stats.Duration)
}
