package gc

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stillya/wg-relay/pkg/maps/ctmap"
)

type mockSweeper struct {
	stats   ctmap.Stats
	err     error
	timeout time.Duration
	calls   int
}

func (m *mockSweeper) GC(_ context.Context, timeout time.Duration) (ctmap.Stats, error) {
	m.calls++
	m.timeout = timeout
	return m.stats, m.err
}

type mockObserver struct {
	stats ctmap.Stats
	err   error
	calls int
}

func (m *mockObserver) ObserveGC(stats ctmap.Stats, err error) {
	m.calls++
	m.stats = stats
	m.err = err
}

// captureLogs installs a buffered slog handler for the duration of fn.
func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)
	fn()
	return buf.String()
}

func newTestRunner(s Sweeper, o Observer) *Runner {
	return New(Params{Interval: time.Hour, Timeout: 5 * time.Minute}, s, o)
}

func TestRunner_RunOncePassesStatsToObserver(t *testing.T) {
	stats := ctmap.Stats{Alive: 3, Deleted: 2, Duration: time.Millisecond}
	sw := &mockSweeper{stats: stats}
	obs := &mockObserver{}
	r := newTestRunner(sw, obs)

	out := captureLogs(t, func() {
		r.runOnce(context.Background())
	})

	if obs.calls != 1 || obs.stats != stats || obs.err != nil {
		t.Errorf("unexpected observation: %+v", obs)
	}
	if sw.timeout != 5*time.Minute {
		t.Errorf("expected timeout to reach the sweeper, got %v", sw.timeout)
	}
	if !strings.Contains(out, "level=DEBUG") || !strings.Contains(out, "conntrack gc run") ||
		!strings.Contains(out, "alive=3") || !strings.Contains(out, "deleted=2") {
		t.Errorf("expected debug run log with stats, got:\n%s", out)
	}
}

func TestRunner_NilObserverDoesNotPanic(t *testing.T) {
	r := newTestRunner(&mockSweeper{}, nil)

	captureLogs(t, func() {
		r.runOnce(context.Background())
	})
}

func TestRunner_StartStopsOnContextCancel(t *testing.T) {
	sw := &mockSweeper{}
	r := New(Params{Interval: time.Millisecond, Timeout: time.Minute}, sw, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		r.Start(ctx)
		close(done)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after context cancel")
	}
}

func TestRunner_StartStopsOnStop(t *testing.T) {
	r := New(Params{Interval: time.Hour, Timeout: time.Minute}, &mockSweeper{}, nil)
	done := make(chan struct{})

	go func() {
		r.Start(context.Background())
		close(done)
	}()
	r.Stop()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after Stop")
	}
}

func TestRunner_StartRunsOnTick(t *testing.T) {
	obs := make(chan struct{}, 1)
	r := New(Params{Interval: time.Millisecond, Timeout: time.Minute}, &mockSweeper{}, observerFunc(func() {
		select {
		case obs <- struct{}{}:
		default:
		}
	}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		r.Start(ctx)
		close(done)
	}()

	select {
	case <-obs:
	case <-time.After(5 * time.Second):
		t.Fatal("expected a GC run on tick")
	}
	cancel()
	<-done
}

type observerFunc func()

func (f observerFunc) ObserveGC(ctmap.Stats, error) { f() }

func TestRunner_SweeperErrorReachesObserverAndLogsError(t *testing.T) {
	sweepErr := errors.New("boom")
	obs := &mockObserver{}
	r := newTestRunner(&mockSweeper{err: sweepErr}, obs)

	out := captureLogs(t, func() {
		r.runOnce(context.Background())
	})

	if obs.calls != 1 || !errors.Is(obs.err, sweepErr) {
		t.Errorf("expected observer to receive the error, got %+v", obs)
	}
	if !strings.Contains(out, "level=ERROR") || !strings.Contains(out, "conntrack gc failed") {
		t.Errorf("expected error log, got:\n%s", out)
	}
	if strings.Contains(out, "conntrack gc run") {
		t.Errorf("failed run must not log the run summary:\n%s", out)
	}
}

func TestRunner_OrphansLogAtInfo(t *testing.T) {
	r := newTestRunner(&mockSweeper{stats: ctmap.Stats{OrphansDeleted: 4}}, nil)

	out := captureLogs(t, func() {
		r.runOnce(context.Background())
	})

	if !strings.Contains(out, "level=INFO") || !strings.Contains(out, "orphans=4") {
		t.Errorf("expected info log with orphans, got:\n%s", out)
	}
}
