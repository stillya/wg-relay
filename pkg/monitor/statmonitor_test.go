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

	sm := NewStatMonitor(StatMonitorParams{
		Mode:     "forward",
		Interval: 10 * time.Second,
	}, source)

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
	}, source)

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

	sm := NewStatMonitor(StatMonitorParams{
		Mode:       "forward",
		Interval:   10 * time.Second,
		MaxSources: 2,
	}, source)

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

	if !strings.Contains(outputStr, "3") {
		t.Error("Expected backend 3 (highest traffic) to be shown")
	}
	if !strings.Contains(outputStr, "2") {
		t.Error("Expected backend 2 (second highest traffic) to be shown")
	}

	if !strings.Contains(outputStr, "... and 1 more") {
		t.Error("Expected '... and 1 more' message for remaining sources")
	}
}
