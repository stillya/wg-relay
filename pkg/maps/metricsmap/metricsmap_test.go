package metricsmap

import (
	"context"
	"testing"

	"github.com/cilium/ebpf"
)

func TestDirectionToString(t *testing.T) {
	testCases := []struct {
		direction uint8
		expected  string
	}{
		{MetricDownstream, "downstream"},
		{MetricUpstream, "upstream"},
		{99, "unknown"},
	}

	for _, tc := range testCases {
		result := DirectionToString(tc.direction)
		if result != tc.expected {
			t.Errorf("DirectionToString(%d) = %s, expected %s", tc.direction, result, tc.expected)
		}
	}
}

func TestBackendIndexToString(t *testing.T) {
	testCases := []struct {
		index    uint8
		expected string
	}{
		{0, "backend_0"},
		{1, "backend_1"},
		{5, "backend_5"},
		{9, "backend_9"},
		{10, "backend_10"},
		{255, "backend_255"},
	}

	for _, tc := range testCases {
		result := BackendIndexToString(tc.index)
		if result != tc.expected {
			t.Errorf("BackendIndexToString(%d) = %s, expected %s", tc.index, result, tc.expected)
		}
	}
}

func TestBPFMapSource_Name(t *testing.T) {
	source := NewBPFMapSource("test_map", nil)
	if source.Name() != "test_map" {
		t.Errorf("Expected name 'test_map', got '%s'", source.Name())
	}
}

func TestBPFMapSource_CollectNilMap(t *testing.T) {
	source := NewBPFMapSource("test_map", nil)
	ctx := context.Background()

	_, err := source.Collect(ctx)
	if err == nil {
		t.Error("Expected error when collecting from nil map")
	}
	if err.Error() != "map is nil" {
		t.Errorf("Expected 'map is nil' error, got: %v", err)
	}
}

func TestBPFMapSource_Collect(t *testing.T) {
	spec := &ebpf.MapSpec{
		Type:       ebpf.PerCPUHash,
		KeySize:    8,
		ValueSize:  32,
		MaxEntries: 16,
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("Cannot create test map (requires appropriate environment): %v", err)
		return
	}
	defer m.Close()

	testKey := MetricsKey{
		BackendIndex: 1,
		Direction:    MetricDownstream,
		Pad:          0,
		Pad2:         0,
	}

	testValue := []MetricsValue{
		{RxPackets: 100, TxPackets: 50, RxBytes: 5000, TxBytes: 2500},
	}

	if err := m.Put(&testKey, testValue); err != nil {
		t.Fatalf("Failed to put test data in map: %v", err)
	}

	source := NewBPFMapSource("test_map", m)
	ctx := context.Background()

	results, err := source.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	result := results[0]

	if result.Key.BackendIndex != 1 {
		t.Errorf("Expected BackendIndex=1, got %d", result.Key.BackendIndex)
	}
	if result.Key.Direction != MetricDownstream {
		t.Errorf("Expected Direction=%d, got %d", MetricDownstream, result.Key.Direction)
	}
	if result.Value.RxPackets != 100 {
		t.Errorf("Expected RxPackets=100, got %d", result.Value.RxPackets)
	}
	if result.Value.TxPackets != 50 {
		t.Errorf("Expected TxPackets=50, got %d", result.Value.TxPackets)
	}
	if result.Value.RxBytes != 5000 {
		t.Errorf("Expected RxBytes=5000, got %d", result.Value.RxBytes)
	}
	if result.Value.TxBytes != 2500 {
		t.Errorf("Expected TxBytes=2500, got %d", result.Value.TxBytes)
	}
}

func TestBPFMapSource_CollectMultipleEntries(t *testing.T) {
	spec := &ebpf.MapSpec{
		Type:       ebpf.PerCPUHash,
		KeySize:    8,
		ValueSize:  32,
		MaxEntries: 16,
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("Cannot create test map (requires appropriate environment): %v", err)
		return
	}
	defer m.Close()

	testData := []struct {
		key   MetricsKey
		value []MetricsValue
	}{
		{
			key:   MetricsKey{BackendIndex: 1, Direction: MetricDownstream, Pad: 0, Pad2: 0},
			value: []MetricsValue{{RxPackets: 100, TxPackets: 50, RxBytes: 5000, TxBytes: 2500}},
		},
		{
			key:   MetricsKey{BackendIndex: 2, Direction: MetricUpstream, Pad: 0, Pad2: 0},
			value: []MetricsValue{{RxPackets: 200, TxPackets: 100, RxBytes: 10000, TxBytes: 5000}},
		},
		{
			key:   MetricsKey{BackendIndex: 0, Direction: MetricDownstream, Pad: 0, Pad2: 0},
			value: []MetricsValue{{RxPackets: 10, TxPackets: 5, RxBytes: 500, TxBytes: 250}},
		},
	}

	for _, td := range testData {
		if err := m.Put(&td.key, td.value); err != nil {
			t.Fatalf("Failed to put test data in map: %v", err)
		}
	}

	source := NewBPFMapSource("test_map", m)
	ctx := context.Background()

	results, err := source.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if len(results) != len(testData) {
		t.Fatalf("Expected %d results, got %d", len(testData), len(results))
	}
}

func TestBPFMapSource_CollectPerCPUAggregation(t *testing.T) {
	spec := &ebpf.MapSpec{
		Type:       ebpf.PerCPUHash,
		KeySize:    8,
		ValueSize:  32,
		MaxEntries: 16,
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("Cannot create test map (requires appropriate environment): %v", err)
		return
	}
	defer m.Close()

	testKey := MetricsKey{
		BackendIndex: 1,
		Direction:    MetricDownstream,
		Pad:          0,
		Pad2:         0,
	}

	perCPUValues := []MetricsValue{
		{RxPackets: 100, TxPackets: 50, RxBytes: 5000, TxBytes: 2500},
		{RxPackets: 200, TxPackets: 100, RxBytes: 10000, TxBytes: 5000},
	}

	if err := m.Put(&testKey, perCPUValues); err != nil {
		t.Fatalf("Failed to put test data in map: %v", err)
	}

	source := NewBPFMapSource("test_map", m)
	ctx := context.Background()

	results, err := source.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect failed: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	result := results[0]

	expectedRxPackets := uint64(300)
	expectedTxPackets := uint64(150)
	expectedRxBytes := uint64(15000)
	expectedTxBytes := uint64(7500)

	if result.Value.RxPackets != expectedRxPackets {
		t.Errorf("Expected aggregated RxPackets=%d, got %d", expectedRxPackets, result.Value.RxPackets)
	}
	if result.Value.TxPackets != expectedTxPackets {
		t.Errorf("Expected aggregated TxPackets=%d, got %d", expectedTxPackets, result.Value.TxPackets)
	}
	if result.Value.RxBytes != expectedRxBytes {
		t.Errorf("Expected aggregated RxBytes=%d, got %d", expectedRxBytes, result.Value.RxBytes)
	}
	if result.Value.TxBytes != expectedTxBytes {
		t.Errorf("Expected aggregated TxBytes=%d, got %d", expectedTxBytes, result.Value.TxBytes)
	}
}

func TestBPFMapSource_CollectContextCancellation(t *testing.T) {
	spec := &ebpf.MapSpec{
		Type:       ebpf.PerCPUHash,
		KeySize:    8,
		ValueSize:  16,
		MaxEntries: 16,
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("Cannot create test map (requires appropriate environment): %v", err)
		return
	}
	defer m.Close()

	source := NewBPFMapSource("test_map", m)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = source.Collect(ctx)
	if err != nil && err != context.Canceled {
		t.Logf("Context cancellation returned different error: %v", err)
	}
}

func TestBPFMapSource_CollectEmptyMap(t *testing.T) {
	spec := &ebpf.MapSpec{
		Type:       ebpf.PerCPUHash,
		KeySize:    8,
		ValueSize:  16,
		MaxEntries: 16,
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("Cannot create test map (requires appropriate environment): %v", err)
		return
	}
	defer m.Close()

	source := NewBPFMapSource("test_map", m)
	ctx := context.Background()

	results, err := source.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect failed on empty map: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("Expected 0 results from empty map, got %d", len(results))
	}
}
