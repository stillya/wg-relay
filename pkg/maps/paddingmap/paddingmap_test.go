package paddingmap

import (
	"context"
	"testing"

	"github.com/cilium/ebpf"
)

func TestBPFMapSource_Name(t *testing.T) {
	source := NewBPFMapSource("test_map", nil)
	if source.Name() != "test_map" {
		t.Errorf("Expected name 'test_map', got '%s'", source.Name())
	}
}

func TestBPFMapSource_CollectNilMap(t *testing.T) {
	source := NewBPFMapSource("test_map", nil)

	_, err := source.Collect(context.Background())
	if err == nil {
		t.Fatal("Expected error when collecting from nil map")
	}
	if err.Error() != "map is nil" {
		t.Errorf("Expected 'map is nil' error, got: %v", err)
	}
}

func TestBPFMapSource_IfNameFallsBackToIndex(t *testing.T) {
	source := NewBPFMapSource("test_map", nil)
	// A very large, almost-certainly-nonexistent ifindex must fall back to its numeric form.
	if got := source.IfName(4294967000); got != "4294967000" {
		t.Errorf("Expected numeric fallback '4294967000', got '%s'", got)
	}
}

func newPaddingMap(t *testing.T) *ebpf.Map {
	t.Helper()
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUHash,
		KeySize:    4, // ifindex
		ValueSize:  8, // struct padding_state
		MaxEntries: 16,
	})
	if err != nil {
		t.Skipf("Cannot create test map (requires appropriate environment): %v", err)
	}
	return m
}

func TestBPFMapSource_CollectDoesNotAggregatePerCPU(t *testing.T) {
	m := newPaddingMap(t)
	defer m.Close()

	ifindex := uint32(42)

	// Discover the per-CPU width by priming a single-value Put then reading back.
	if err := m.Put(&ifindex, []State{{CurrentSize: 10}}); err != nil {
		t.Fatalf("Failed to prime map: %v", err)
	}
	var width []State
	if err := m.Lookup(&ifindex, &width); err != nil {
		t.Fatalf("Failed to look up primed key: %v", err)
	}

	// Give each CPU a distinct working size so aggregation (summing) would be detectable.
	vals := make([]State, len(width))
	for i := range vals {
		vals[i] = State{CurrentSize: uint8(i + 1)} //nolint:gosec // small loop index
	}
	if err := m.Put(&ifindex, vals); err != nil {
		t.Fatalf("Failed to put per-CPU values: %v", err)
	}

	source := NewBPFMapSource("test_map", m)
	results, err := source.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if len(results) != len(vals) {
		t.Fatalf("Expected %d per-CPU entries (no aggregation), got %d", len(vals), len(results))
	}

	for _, r := range results {
		if r.IfIndex != ifindex {
			t.Errorf("Expected ifindex %d, got %d", ifindex, r.IfIndex)
		}
		if r.CPU < 0 || r.CPU >= len(vals) {
			t.Errorf("CPU index %d out of range", r.CPU)
			continue
		}
		if want := uint8(r.CPU + 1); r.State.CurrentSize != want { //nolint:gosec // small loop index
			t.Errorf("CPU %d: expected CurrentSize %d, got %d (values must not be summed)",
				r.CPU, want, r.State.CurrentSize)
		}
	}
}

func TestBPFMapSource_CollectSkipsUnseededCPUSlots(t *testing.T) {
	m := newPaddingMap(t)
	defer m.Close()

	ifindex := uint32(42)

	// Discover the per-CPU width by priming a single-value Put then reading back.
	if err := m.Put(&ifindex, []State{{CurrentSize: 10}}); err != nil {
		t.Fatalf("Failed to prime map: %v", err)
	}
	var width []State
	if err := m.Lookup(&ifindex, &width); err != nil {
		t.Fatalf("Failed to look up primed key: %v", err)
	}

	// Only the first CPU is seeded; the rest are left zero-filled (never ran).
	vals := make([]State, len(width))
	vals[0] = State{CurrentSize: 10}
	if err := m.Put(&ifindex, vals); err != nil {
		t.Fatalf("Failed to put per-CPU values: %v", err)
	}

	source := NewBPFMapSource("test_map", m)
	results, err := source.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected the zeroed (unseeded) CPU slots to be skipped, got %d entries", len(results))
	}
	if results[0].State.CurrentSize != 10 {
		t.Errorf("Expected the seeded slot's CurrentSize 10, got %d", results[0].State.CurrentSize)
	}
}
