package ctmap

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

const (
	testTimeout = 5 * time.Minute
	testNow     = uint64(1000 * time.Second)
	idle        = testNow - uint64(testTimeout) - 1
	fresh       = testNow - uint64(time.Second)
)

func newTestMap(t *testing.T) *Map {
	t.Helper()
	ct, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 12, ValueSize: 24, MaxEntries: 64})
	if err != nil {
		t.Skipf("Cannot create test map (requires appropriate environment): %v", err)
	}
	t.Cleanup(func() { ct.Close() })

	rev, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 12, ValueSize: 12, MaxEntries: 64})
	if err != nil {
		t.Skipf("Cannot create test map (requires appropriate environment): %v", err)
	}
	t.Cleanup(func() { rev.Close() })

	m := New(ct, rev)
	m.now = func() (uint64, error) { return testNow, nil }
	return m
}

func tuple(saddr, daddr string, sport, dport uint16) Tuple {
	return Tuple{Saddr: netIP(saddr), Daddr: netIP(daddr), Sport: htons(sport), Dport: htons(dport)}
}

func flowEntry(lastSeen uint64, backend string, backendPort, natPort uint16) Entry {
	return Entry{LastSeen: lastSeen, ToDaddr: netIP(backend), ToDport: htons(backendPort), NatPort: htons(natPort)}
}

func netIP(ip string) uint32 {
	return binary.NativeEndian.Uint32(net.ParseIP(ip).To4())
}

func htons(v uint16) uint16 {
	return binary.NativeEndian.Uint16(binary.BigEndian.AppendUint16(nil, v))
}

// putFlow stores a flow and its reverse entry and returns the reverse key.
func putFlow(t *testing.T, m *Map, key Tuple, entry Entry) Tuple {
	t.Helper()
	if err := m.ct.Put(&key, &entry); err != nil {
		t.Fatalf("Failed to put ct entry: %v", err)
	}
	revKey := revTuple(key, entry)
	putRev(t, m, revKey, key)
	return revKey
}

func putRev(t *testing.T, m *Map, revKey, key Tuple) {
	t.Helper()
	if err := m.rev.Put(&revKey, &key); err != nil {
		t.Fatalf("Failed to put reverse entry: %v", err)
	}
}

func exists(t *testing.T, em *ebpf.Map, key Tuple) bool {
	t.Helper()
	err := em.Lookup(&key, make([]byte, em.ValueSize()))
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return false
	}
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	return true
}

func runGC(t *testing.T, m *Map) Stats {
	t.Helper()
	stats, err := m.GC(context.Background(), testTimeout)
	if err != nil {
		t.Fatalf("GC failed: %v", err)
	}
	return stats
}

func TestGC_Expiry(t *testing.T) {
	tests := []struct {
		name     string
		lastSeen uint64
		kept     bool
	}{
		{name: "idle longer than timeout", lastSeen: idle, kept: false},
		{name: "idle exactly timeout", lastSeen: testNow - uint64(testTimeout), kept: true},
		{name: "fresh", lastSeen: fresh, kept: true},
		{name: "last_seen after now", lastSeen: testNow + uint64(time.Second), kept: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestMap(t)
			key := tuple("10.0.0.1", "10.0.0.2", 55000, 51820)
			revKey := putFlow(t, m, key, flowEntry(tc.lastSeen, "10.0.1.1", 51820, 55000))

			stats := runGC(t, m)

			if got := exists(t, m.ct, key); got != tc.kept {
				t.Errorf("ct entry present = %v, expected %v", got, tc.kept)
			}
			if got := exists(t, m.rev, revKey); got != tc.kept {
				t.Errorf("reverse entry present = %v, expected %v", got, tc.kept)
			}

			want := Stats{Alive: 1}
			if !tc.kept {
				want = Stats{Deleted: 1}
			}
			if stats.Alive != want.Alive || stats.Deleted != want.Deleted || stats.OrphansDeleted != 0 {
				t.Errorf("Expected %+v, got %+v", want, stats)
			}
		})
	}
}

func TestGC_CountsAlive(t *testing.T) {
	m := newTestMap(t)
	for i, lastSeen := range []uint64{fresh, idle, fresh, idle, fresh} {
		port := uint16(50000 + i)
		putFlow(t, m, tuple("10.0.0.1", "10.0.0.2", port, 51820), flowEntry(lastSeen, "10.0.1.1", 51820, port))
	}

	stats := runGC(t, m)

	if stats.Alive != 3 || stats.Deleted != 2 || stats.OrphansDeleted != 0 {
		t.Errorf("Expected Alive=3 Deleted=2 OrphansDeleted=0, got %+v", stats)
	}
	if stats.Duration <= 0 {
		t.Errorf("Expected positive duration, got %s", stats.Duration)
	}
	if len(m.pendingOrphans) != 0 {
		t.Errorf("Expected no pending orphans, got %d", len(m.pendingOrphans))
	}
}

func TestDeleteExpired_RecheckedBeforeDelete(t *testing.T) {
	m := newTestMap(t)
	key := tuple("10.0.0.1", "10.0.0.2", 55000, 51820)
	entry := flowEntry(idle, "10.0.1.1", 51820, 55000)
	revKey := putFlow(t, m, key, entry)

	// The datapath refreshes the flow after GC has read its clock and collected the key.
	entry.LastSeen = testNow + 1
	if err := m.ct.Put(&key, &entry); err != nil {
		t.Fatalf("Failed to refresh ct entry: %v", err)
	}

	deleted, err := m.deleteExpired(key, testNow, uint64(testTimeout))
	if err != nil {
		t.Fatalf("deleteExpired failed: %v", err)
	}
	if deleted {
		t.Error("Expected refreshed flow to be kept")
	}
	if !exists(t, m.ct, key) || !exists(t, m.rev, revKey) {
		t.Error("Expected refreshed flow and its reverse entry to remain")
	}

	gone := tuple("10.0.0.9", "10.0.0.2", 55000, 51820)
	deleted, err = m.deleteExpired(gone, testNow, uint64(testTimeout))
	if err != nil || deleted {
		t.Errorf("Expected a vanished flow to be skipped without error, got deleted=%v err=%v", deleted, err)
	}
}

func TestGC_KeepsReverseEntryOwnedByAnotherFlow(t *testing.T) {
	m := newTestMap(t)
	key := tuple("10.0.0.1", "10.0.0.2", 55000, 51820)
	revKey := putFlow(t, m, key, flowEntry(idle, "10.0.1.1", 51820, 55000))
	other := tuple("10.0.0.5", "10.0.0.2", 55000, 51820)
	putRev(t, m, revKey, other)

	stats := runGC(t, m)

	if stats.Deleted != 1 {
		t.Errorf("Expected 1 deleted flow, got %+v", stats)
	}
	if exists(t, m.ct, key) {
		t.Error("Expected expired ct entry to be deleted")
	}
	var owner Tuple
	if err := m.rev.Lookup(&revKey, &owner); err != nil || owner != other {
		t.Errorf("Expected reverse entry owned by another flow to remain, got %+v err=%v", owner, err)
	}
}

func TestGC_OrphanDeletedOnSecondRun(t *testing.T) {
	m := newTestMap(t)
	revKey := tuple("10.0.1.1", "10.0.0.2", 51820, 55000)
	putRev(t, m, revKey, tuple("10.0.0.1", "10.0.0.2", 55000, 51820))

	stats := runGC(t, m)
	if stats.OrphansDeleted != 0 || !exists(t, m.rev, revKey) {
		t.Fatalf("Expected orphan to survive the first run, got %+v", stats)
	}
	if _, ok := m.pendingOrphans[revKey]; !ok {
		t.Fatal("Expected orphan to be pending after the first run")
	}

	stats = runGC(t, m)
	if stats.OrphansDeleted != 1 || exists(t, m.rev, revKey) {
		t.Errorf("Expected orphan to be deleted on the second run, got %+v", stats)
	}
	if len(m.pendingOrphans) != 0 {
		t.Errorf("Expected no pending orphans, got %d", len(m.pendingOrphans))
	}
}

func TestGC_OrphanThatBecomesValidIsForgotten(t *testing.T) {
	m := newTestMap(t)
	key := tuple("10.0.0.1", "10.0.0.2", 55000, 51820)
	entry := flowEntry(fresh, "10.0.1.1", 51820, 55000)
	revKey := revTuple(key, entry)
	putRev(t, m, revKey, key)

	runGC(t, m)
	if _, ok := m.pendingOrphans[revKey]; !ok {
		t.Fatal("Expected reverse entry without a flow to be pending")
	}

	// The datapath finishes creating the flow after reserving its reverse entry.
	if err := m.ct.Put(&key, &entry); err != nil {
		t.Fatalf("Failed to put ct entry: %v", err)
	}

	stats := runGC(t, m)
	if stats.OrphansDeleted != 0 || !exists(t, m.rev, revKey) {
		t.Errorf("Expected valid reverse entry to be kept, got %+v", stats)
	}
	if len(m.pendingOrphans) != 0 {
		t.Errorf("Expected valid reverse entry to leave pending orphans, got %d", len(m.pendingOrphans))
	}
}

func TestGC_MismatchedNatPortIsOrphan(t *testing.T) {
	m := newTestMap(t)
	key := tuple("10.0.0.1", "10.0.0.2", 55000, 51820)
	revKey := putFlow(t, m, key, flowEntry(fresh, "10.0.1.1", 51820, 55000))
	stale := revKey
	stale.Dport = htons(55001)
	putRev(t, m, stale, key)

	runGC(t, m)
	if _, ok := m.pendingOrphans[stale]; !ok || len(m.pendingOrphans) != 1 {
		t.Fatalf("Expected only the stale reverse entry to be pending, got %v", m.pendingOrphans)
	}

	stats := runGC(t, m)
	if stats.OrphansDeleted != 1 || stats.Alive != 1 {
		t.Errorf("Expected 1 orphan deleted and 1 flow alive, got %+v", stats)
	}
	if exists(t, m.rev, stale) {
		t.Error("Expected stale reverse entry to be deleted")
	}
	if !exists(t, m.ct, key) || !exists(t, m.rev, revKey) {
		t.Error("Expected the flow and its own reverse entry to remain")
	}
}

// TestIsOrphan checks the same stale-entry rule as ct_restore in ebpf/include/ct.h.
func TestIsOrphan(t *testing.T) {
	key := tuple("10.0.0.1", "10.0.0.2", 55000, 51820)
	entry := flowEntry(fresh, "10.0.1.1", 51820, 55000)
	valid := revTuple(key, entry)

	with := func(change func(*Tuple)) Tuple {
		revKey := valid
		change(&revKey)
		return revKey
	}

	tests := []struct {
		name   string
		revKey Tuple
		value  Tuple
		orphan bool
	}{
		{name: "derived by its flow", revKey: valid, value: key, orphan: false},
		{name: "other nat port", revKey: with(func(r *Tuple) { r.Dport = htons(55001) }), value: key, orphan: true},
		{name: "other backend addr", revKey: with(func(r *Tuple) { r.Saddr = netIP("10.0.1.2") }), value: key, orphan: true},
		{name: "other backend port", revKey: with(func(r *Tuple) { r.Sport = htons(51821) }), value: key, orphan: true},
		{name: "other proxy addr", revKey: with(func(r *Tuple) { r.Daddr = netIP("10.0.0.3") }), value: key, orphan: true},
		{name: "flow missing", revKey: valid, value: tuple("10.0.0.9", "10.0.0.2", 55000, 51820), orphan: true},
	}

	m := newTestMap(t)
	if err := m.ct.Put(&key, &entry); err != nil {
		t.Fatalf("Failed to put ct entry: %v", err)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			orphan, err := m.isOrphan(tc.revKey, tc.value)
			if err != nil {
				t.Fatalf("isOrphan failed: %v", err)
			}
			if orphan != tc.orphan {
				t.Errorf("isOrphan = %v, expected %v", orphan, tc.orphan)
			}
		})
	}
}

func TestGC_CancelledContext(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, m *Map)
	}{
		{
			name: "during expiry",
			setup: func(t *testing.T, m *Map) {
				putFlow(t, m, tuple("10.0.0.1", "10.0.0.2", 55000, 51820), flowEntry(idle, "10.0.1.1", 51820, 55000))
			},
		},
		{
			name: "during orphan scan",
			setup: func(t *testing.T, m *Map) {
				putRev(t, m, tuple("10.0.1.1", "10.0.0.2", 51820, 55000), tuple("10.0.0.1", "10.0.0.2", 55000, 51820))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestMap(t)
			tc.setup(t, m)

			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			if _, err := m.GC(ctx, testTimeout); !errors.Is(err, context.Canceled) {
				t.Errorf("Expected context.Canceled, got %v", err)
			}
		})
	}
}

func TestGC_ClockError(t *testing.T) {
	m := newTestMap(t)
	m.now = func() (uint64, error) { return 0, errors.New("clock unavailable") }

	if _, err := m.GC(context.Background(), testTimeout); err == nil {
		t.Error("Expected error when the clock cannot be read")
	}
}

func TestGC_NilMaps(t *testing.T) {
	if _, err := New(nil, nil).GC(context.Background(), testTimeout); err == nil {
		t.Error("Expected error when maps are nil")
	}
}
