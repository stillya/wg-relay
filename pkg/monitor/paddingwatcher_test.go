package monitor

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stillya/wg-relay/pkg/maps/paddingmap"
)

type mockPaddingSource struct {
	frames [][]paddingmap.StateData // one entry per Collect call
	call   int
	names  map[uint32]string
	err    error
}

func (m *mockPaddingSource) Collect(_ context.Context) ([]paddingmap.StateData, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.call >= len(m.frames) {
		return nil, nil
	}
	f := m.frames[m.call]
	m.call++
	return f, nil
}

func (m *mockPaddingSource) IfName(ifindex uint32) string {
	if n, ok := m.names[ifindex]; ok {
		return n
	}
	return "unknown"
}

func (m *mockPaddingSource) Name() string { return "mock" }

func state(ifindex uint32, cpu int, size uint8, backoffs uint32) paddingmap.StateData {
	return paddingmap.StateData{
		IfIndex: ifindex,
		CPU:     cpu,
		State:   paddingmap.State{CurrentSize: size, Backoffs: backoffs},
	}
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

func newTestWatcher(src PaddingStateSource) *PaddingWatcher {
	return NewPaddingWatcher(PaddingWatcherParams{Interval: time.Hour, ConfiguredSize: 64}, src)
}

func TestPaddingWatcher_LogsOnlyOnChange(t *testing.T) {
	src := &mockPaddingSource{
		names: map[uint32]string{1: "eth0"},
		frames: [][]paddingmap.StateData{
			{state(1, 0, 64, 0)}, // initialized
			{state(1, 0, 32, 1)}, // reduced
			{state(1, 0, 32, 1)}, // unchanged -> silent
			{state(1, 0, 33, 1)}, // recovered
		},
	}
	w := newTestWatcher(src)
	ctx := context.Background()

	out := captureLogs(t, func() {
		w.poll(ctx)
		w.poll(ctx)
		w.poll(ctx)
		w.poll(ctx)
	})

	if got := strings.Count(out, "padding state initialized"); got != 1 {
		t.Errorf("expected 1 initialized log, got %d\n%s", got, out)
	}
	if got := strings.Count(out, "padding size reduced"); got != 1 {
		t.Errorf("expected 1 reduced log, got %d\n%s", got, out)
	}
	if got := strings.Count(out, "padding size recovered"); got != 1 {
		t.Errorf("expected 1 recovered log, got %d\n%s", got, out)
	}
	if !strings.Contains(out, "interface=eth0") {
		t.Errorf("expected resolved interface name in logs\n%s", out)
	}
}

func TestPaddingWatcher_WarnsAtFloor(t *testing.T) {
	src := &mockPaddingSource{
		names: map[uint32]string{1: "eth0"},
		frames: [][]paddingmap.StateData{
			{state(1, 0, 2, 5)}, // initialized above floor -> no floor warn
			{state(1, 0, 1, 6)}, // reduced to floor -> floor warn
		},
	}
	w := newTestWatcher(src)
	ctx := context.Background()

	out := captureLogs(t, func() {
		w.poll(ctx)
		w.poll(ctx)
	})

	if strings.Count(out, "protocol floor") != 1 {
		t.Errorf("expected exactly 1 protocol-floor warning, got:\n%s", out)
	}
}

func TestPaddingWatcher_HandlesInterfaceDisappearance(t *testing.T) {
	src := &mockPaddingSource{
		names: map[uint32]string{1: "eth0"},
		frames: [][]paddingmap.StateData{
			{state(1, 0, 64, 0)}, // initialized
			{},                   // interface gone from map
			{state(1, 0, 64, 0)}, // reappears at same size -> no new change log
		},
	}
	w := newTestWatcher(src)
	ctx := context.Background()

	out := captureLogs(t, func() {
		w.poll(ctx)
		w.poll(ctx)
		w.poll(ctx)
	})

	if got := strings.Count(out, "padding state initialized"); got != 1 {
		t.Errorf("expected exactly 1 initialized log across disappearance, got %d\n%s", got, out)
	}
	if strings.Contains(out, "padding size reduced") || strings.Contains(out, "padding size recovered") {
		t.Errorf("unchanged size after reappearance must not log a change:\n%s", out)
	}
}

func TestPaddingWatcher_CollectErrorIsLogged(t *testing.T) {
	src := &mockPaddingSource{err: context.DeadlineExceeded}
	w := newTestWatcher(src)

	out := captureLogs(t, func() {
		w.poll(context.Background())
	})

	if !strings.Contains(out, "Failed to collect padding state") {
		t.Errorf("expected collect error to be logged, got:\n%s", out)
	}
}
