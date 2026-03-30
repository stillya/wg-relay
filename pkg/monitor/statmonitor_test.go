package monitor

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stillya/wg-relay/pkg/maps/metricsmap"
)

type mockSource struct {
	name string
	data []metricsmap.MetricData
	err  error
}

func (m *mockSource) Collect(ctx context.Context) ([]metricsmap.MetricData, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.data, nil
}

func (m *mockSource) Name() string {
	return m.name
}

func TestStatMonitor_PrintTrafficTable(t *testing.T) {
	source := &mockSource{
		name: "test",
		data: []metricsmap.MetricData{
			{
				Key:   metricsmap.MetricsKey{BackendIndex: 1, Direction: metricsmap.MetricDownstream, Pad: 0, Pad2: 0},
				Value: metricsmap.MetricsValue{RxPackets: 1234, TxPackets: 987, RxBytes: 56789, TxBytes: 43210},
			},
			{
				Key:   metricsmap.MetricsKey{BackendIndex: 1, Direction: metricsmap.MetricUpstream, Pad: 0, Pad2: 0},
				Value: metricsmap.MetricsValue{RxPackets: 500, TxPackets: 300, RxBytes: 25000, TxBytes: 15000},
			},
		},
	}

	backendLabels := map[uint8]string{
		1: "test_backend",
	}

	sm := NewStatMonitor(StatMonitorParams{
		Mode:     "forward",
		Interval: 10 * time.Second,
	}, source, backendLabels)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	ctx := context.Background()
	sm.printStats(ctx)

	w.Close()
	os.Stdout = oldStdout

	output, _ := io.ReadAll(r)
	outputStr := string(output)

	expectedStrings := []string{
		"wg-relay(forward) traffic statistics",
		"total",
		"avg. rate",
		"traffic",
		"down_rx",
		"down_tx",
		"up_rx",
		"up_tx",
		"test_backend",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(outputStr, expected) {
			t.Errorf("Output missing expected string: %s", expected)
		}
	}
}

func TestStatMonitor_EmptyData(t *testing.T) {
	source := &mockSource{
		name: "test",
		data: []metricsmap.MetricData{},
	}

	sm := NewStatMonitor(StatMonitorParams{
		Mode:     "forward",
		Interval: time.Second,
	}, source, nil)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	ctx := context.Background()
	sm.printStats(ctx)

	w.Close()
	os.Stdout = oldStdout

	output, _ := io.ReadAll(r)
	outputStr := string(output)

	if strings.TrimSpace(outputStr) != "" {
		t.Errorf("Expected no output for empty data, got: %s", outputStr)
	}
}

func TestStatMonitor_MaxSources(t *testing.T) {
	source := &mockSource{
		name: "test",
		data: []metricsmap.MetricData{
			{
				Key:   metricsmap.MetricsKey{BackendIndex: 1, Direction: metricsmap.MetricDownstream, Pad: 0, Pad2: 0},
				Value: metricsmap.MetricsValue{RxPackets: 100, TxPackets: 50, RxBytes: 1000, TxBytes: 500},
			},
			{
				Key:   metricsmap.MetricsKey{BackendIndex: 2, Direction: metricsmap.MetricDownstream, Pad: 0, Pad2: 0},
				Value: metricsmap.MetricsValue{RxPackets: 200, TxPackets: 100, RxBytes: 2000, TxBytes: 1000},
			},
			{
				Key:   metricsmap.MetricsKey{BackendIndex: 3, Direction: metricsmap.MetricDownstream, Pad: 0, Pad2: 0},
				Value: metricsmap.MetricsValue{RxPackets: 300, TxPackets: 150, RxBytes: 3000, TxBytes: 1500},
			},
		},
	}

	backendLabels := map[uint8]string{
		1: "backend_1",
		2: "backend_2",
		3: "backend_3",
	}

	sm := NewStatMonitor(StatMonitorParams{
		Mode:       "forward",
		Interval:   10 * time.Second,
		MaxSources: 2,
	}, source, backendLabels)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	ctx := context.Background()
	sm.printStats(ctx)

	w.Close()
	os.Stdout = oldStdout

	output, _ := io.ReadAll(r)
	outputStr := string(output)

	if !strings.Contains(outputStr, "backend_3") {
		t.Error("Expected backend_3 (highest traffic) to be shown")
	}
	if !strings.Contains(outputStr, "backend_2") {
		t.Error("Expected backend_2 (second highest traffic) to be shown")
	}

	if !strings.Contains(outputStr, "... and 1 more") {
		t.Error("Expected '... and 1 more' message for remaining backends")
	}
}

func TestStatMonitor_ForwardModeWithBackendLabels(t *testing.T) {
	source := &mockSource{
		name: "test",
		data: []metricsmap.MetricData{
			{
				Key:   metricsmap.MetricsKey{BackendIndex: 1, Direction: metricsmap.MetricDownstream, Pad: 0, Pad2: 0},
				Value: metricsmap.MetricsValue{RxPackets: 100, TxPackets: 50, RxBytes: 10000, TxBytes: 5000},
			},
			{
				Key:   metricsmap.MetricsKey{BackendIndex: 1, Direction: metricsmap.MetricUpstream, Pad: 0, Pad2: 0},
				Value: metricsmap.MetricsValue{RxPackets: 80, TxPackets: 40, RxBytes: 8000, TxBytes: 4000},
			},
			{
				Key:   metricsmap.MetricsKey{BackendIndex: 2, Direction: metricsmap.MetricDownstream, Pad: 0, Pad2: 0},
				Value: metricsmap.MetricsValue{RxPackets: 200, TxPackets: 100, RxBytes: 20000, TxBytes: 10000},
			},
		},
	}

	backendLabels := map[uint8]string{
		1: "us-west",
		2: "eu-central",
	}

	sm := NewStatMonitor(StatMonitorParams{
		Mode:     "forward",
		Interval: 10 * time.Second,
	}, source, backendLabels)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	ctx := context.Background()
	sm.printStats(ctx)

	w.Close()
	os.Stdout = oldStdout

	output, _ := io.ReadAll(r)
	outputStr := string(output)

	expectedStrings := []string{
		"wg-relay(forward) traffic statistics",
		"down_rx",
		"down_tx",
		"up_rx",
		"up_tx",
		"us-west",
		"eu-central",
		"Per-backend statistics:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(outputStr, expected) {
			t.Errorf("Output missing expected string: %s", expected)
		}
	}
}

func TestStatMonitor_ReverseModeDirectionAggregation(t *testing.T) {
	source := &mockSource{
		name: "test",
		data: []metricsmap.MetricData{
			{
				Key:   metricsmap.MetricsKey{BackendIndex: 0, Direction: metricsmap.MetricDownstream, Pad: 0, Pad2: 0},
				Value: metricsmap.MetricsValue{RxPackets: 100, TxPackets: 50, RxBytes: 10000, TxBytes: 5000},
			},
			{
				Key:   metricsmap.MetricsKey{BackendIndex: 0, Direction: metricsmap.MetricUpstream, Pad: 0, Pad2: 0},
				Value: metricsmap.MetricsValue{RxPackets: 80, TxPackets: 40, RxBytes: 8000, TxBytes: 4000},
			},
		},
	}

	sm := NewStatMonitor(StatMonitorParams{
		Mode:     "reverse",
		Interval: 10 * time.Second,
	}, source, nil)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	ctx := context.Background()
	sm.printStats(ctx)

	w.Close()
	os.Stdout = oldStdout

	output, _ := io.ReadAll(r)
	outputStr := string(output)

	expectedStrings := []string{
		"wg-relay(reverse) traffic statistics",
		"down_rx",
		"down_tx",
		"up_rx",
		"up_tx",
		"downstream",
		"upstream",
		"Per-direction statistics:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(outputStr, expected) {
			t.Errorf("Output missing expected string: %s", expected)
		}
	}
}

func TestStatMonitor_DownstreamUpstreamSplit(t *testing.T) {
	source := &mockSource{
		name: "test",
		data: []metricsmap.MetricData{
			{
				Key:   metricsmap.MetricsKey{BackendIndex: 1, Direction: metricsmap.MetricDownstream, Pad: 0, Pad2: 0},
				Value: metricsmap.MetricsValue{RxPackets: 100, TxPackets: 50, RxBytes: 1000, TxBytes: 500},
			},
			{
				Key:   metricsmap.MetricsKey{BackendIndex: 1, Direction: metricsmap.MetricUpstream, Pad: 0, Pad2: 0},
				Value: metricsmap.MetricsValue{RxPackets: 200, TxPackets: 100, RxBytes: 2000, TxBytes: 1000},
			},
		},
	}

	backendLabels := map[uint8]string{
		1: "test_backend",
	}

	sm := NewStatMonitor(StatMonitorParams{
		Mode:     "forward",
		Interval: 10 * time.Second,
	}, source, backendLabels)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	ctx := context.Background()
	sm.printStats(ctx)

	w.Close()
	os.Stdout = oldStdout

	output, _ := io.ReadAll(r)
	outputStr := string(output)

	if !strings.Contains(outputStr, "down_rx") {
		t.Error("Expected downstream rx column")
	}
	if !strings.Contains(outputStr, "down_tx") {
		t.Error("Expected downstream tx column")
	}
	if !strings.Contains(outputStr, "up_rx") {
		t.Error("Expected upstream rx column")
	}
	if !strings.Contains(outputStr, "up_tx") {
		t.Error("Expected upstream tx column")
	}
}
