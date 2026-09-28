package monitor

import (
	"context"
	log "log/slog"
	"time"

	"github.com/stillya/wg-relay/pkg/maps/paddingmap"
)

// PaddingStateSource collects adaptive padding state and resolves interface names.
type PaddingStateSource interface {
	Collect(ctx context.Context) ([]paddingmap.StateData, error)
	IfName(ifindex uint32) string
	Name() string
}

// PaddingWatcherParams contains configuration for PaddingWatcher.
type PaddingWatcherParams struct {
	Interval       time.Duration
	ConfiguredSize uint8
}

type paddingKey struct {
	IfIndex uint32
	CPU     int
}

// PaddingWatcher periodically reads the adaptive padding state and logs whenever the AIMD working size changes.
type PaddingWatcher struct {
	PaddingWatcherParams
	source PaddingStateSource
	last   map[paddingKey]uint8
	stopCh chan struct{}
}

// NewPaddingWatcher creates a new PaddingWatcher.
func NewPaddingWatcher(params PaddingWatcherParams, source PaddingStateSource) *PaddingWatcher {
	return &PaddingWatcher{
		PaddingWatcherParams: params,
		source:               source,
		last:                 make(map[paddingKey]uint8),
		stopCh:               make(chan struct{}),
	}
}

// Start begins periodic polling of the padding state until the context is cancelled or Stop is called.
func (w *PaddingWatcher) Start(ctx context.Context) {
	log.Info("Starting padding watcher", "interval", w.Interval, "configured_size", w.ConfiguredSize)

	ticker := time.NewTicker(w.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Padding watcher stopped by context")
			return
		case <-w.stopCh:
			log.Info("Padding watcher stopped")
			return
		case <-ticker.C:
			w.poll(ctx)
		}
	}
}

// Stop signals the watcher to stop.
func (w *PaddingWatcher) Stop() {
	close(w.stopCh)
}

func (w *PaddingWatcher) poll(ctx context.Context) {
	states, err := w.source.Collect(ctx)
	if err != nil {
		log.Error("Failed to collect padding state", "error", err)
		return
	}

	for _, s := range states {
		key := paddingKey{IfIndex: s.IfIndex, CPU: s.CPU}
		cur := s.State.CurrentSize

		prev, seen := w.last[key]
		if seen && prev == cur {
			continue
		}
		w.last[key] = cur

		iface := w.source.IfName(s.IfIndex)
		switch {
		case !seen:
			log.Info("padding state initialized",
				"interface", iface,
				"cpu", s.CPU,
				"size", cur,
				"configured", w.ConfiguredSize)
		case cur < prev:
			log.Warn("padding size reduced",
				"interface", iface,
				"cpu", s.CPU,
				"from", prev,
				"to", cur,
				"configured", w.ConfiguredSize,
				"backoffs", s.State.Backoffs)
		default:
			log.Info("padding size recovered",
				"interface", iface,
				"cpu", s.CPU,
				"from", prev,
				"to", cur,
				"configured", w.ConfiguredSize)
		}
	}
}
