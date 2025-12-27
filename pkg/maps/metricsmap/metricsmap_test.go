package metricsmap

import (
	"context"
	"testing"

	"github.com/cilium/ebpf"
)

func TestDirectionToString(t *testing.T) {
	testCases := []struct {
		dir      uint8
		expected string
	}{
		{MetricToWg, "to_wg"},
		{MetricFromWg, "from_wg"},
		{0, "unknown"},
		{99, "unknown"},
	}

	for _, tc := range testCases {
		result := DirectionToString(tc.dir)
		if result != tc.expected {
			t.Errorf("DirectionToString(%d) = %s, expected %s", tc.dir, result, tc.expected)
		}
	}
}

func TestReasonToString(t *testing.T) {
	testCases := []struct {
		reason   uint8
		expected string
	}{
		{MetricForwarded, "forwarded"},
		{MetricDrop, "drop"},
		{0, "unknown"},
		{99, "unknown"},
	}

	for _, tc := range testCases {
		result := ReasonToString(tc.reason)
		if result != tc.expected {
			t.Errorf("ReasonToString(%d) = %s, expected %s", tc.reason, result, tc.expected)
		}
	}
}

func TestSrcAddrToString(t *testing.T) {
	testCases := []struct {
		srcAddr  uint32
		expected string
	}{
		{0x00000000, "unknown"},
		{0xC0A80A01, "192.168.10.1"},
		{0x7F000001, "127.0.0.1"},
		{0x0A000001, "10.0.0.1"},
		{0xFFFFFFFF, "255.255.255.255"},
		{0x08080808, "8.8.8.8"},
	}

	for _, tc := range testCases {
		result := SrcAddrToString(tc.srcAddr)
		if result != tc.expected {
			t.Errorf("SrcAddrToString(0x%08X) = %s, expected %s", tc.srcAddr, result, tc.expected)
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
		ValueSize:  16,
		MaxEntries: 16,
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("Cannot create test map (requires appropriate environment): %v", err)
		return
	}
	defer m.Close()

	testKey := MetricsKey{
		Dir:     MetricFromWg,
		Reason:  MetricForwarded,
		Pad:     0,
		SrcAddr: 0xC0A80A01,
	}

	testValue := []MetricsValue{
		{Packets: 100, Bytes: 5000},
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

	if result.Key.Dir != MetricFromWg {
		t.Errorf("Expected Dir=%d, got %d", MetricFromWg, result.Key.Dir)
	}
	if result.Key.Reason != MetricForwarded {
		t.Errorf("Expected Reason=%d, got %d", MetricForwarded, result.Key.Reason)
	}
	if result.Key.SrcAddr != 0xC0A80A01 {
		t.Errorf("Expected SrcAddr=0xC0A80A01, got 0x%08X", result.Key.SrcAddr)
	}
	if result.Value.Packets != 100 {
		t.Errorf("Expected Packets=100, got %d", result.Value.Packets)
	}
	if result.Value.Bytes != 5000 {
		t.Errorf("Expected Bytes=5000, got %d", result.Value.Bytes)
	}
}

func TestBPFMapSource_CollectMultipleEntries(t *testing.T) {
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

	testData := []struct {
		key   MetricsKey
		value []MetricsValue
	}{
		{
			key:   MetricsKey{Dir: MetricFromWg, Reason: MetricForwarded, Pad: 0, SrcAddr: 0xC0A80A01},
			value: []MetricsValue{{Packets: 100, Bytes: 5000}},
		},
		{
			key:   MetricsKey{Dir: MetricToWg, Reason: MetricForwarded, Pad: 0, SrcAddr: 0xC0A80A02},
			value: []MetricsValue{{Packets: 200, Bytes: 10000}},
		},
		{
			key:   MetricsKey{Dir: MetricFromWg, Reason: MetricDrop, Pad: 0, SrcAddr: 0xC0A80A01},
			value: []MetricsValue{{Packets: 10, Bytes: 500}},
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
		ValueSize:  16,
		MaxEntries: 16,
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("Cannot create test map (requires appropriate environment): %v", err)
		return
	}
	defer m.Close()

	testKey := MetricsKey{
		Dir:     MetricFromWg,
		Reason:  MetricForwarded,
		Pad:     0,
		SrcAddr: 0xC0A80A01,
	}

	perCPUValues := []MetricsValue{
		{Packets: 100, Bytes: 5000},
		{Packets: 200, Bytes: 10000},
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

	expectedPackets := uint64(300)
	expectedBytes := uint64(15000)

	if result.Value.Packets != expectedPackets {
		t.Errorf("Expected aggregated Packets=%d, got %d", expectedPackets, result.Value.Packets)
	}
	if result.Value.Bytes != expectedBytes {
		t.Errorf("Expected aggregated Bytes=%d, got %d", expectedBytes, result.Value.Bytes)
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
