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
				Key:   metricsmap.MetricsKey{Dir: metricsmap.MetricFromWg, Reason: metricsmap.MetricForwarded, Pad: 0, SrcAddr: 0xC0A80A01},
				Value: metricsmap.MetricsValue{Packets: 1234, Bytes: 56789},
			},
			{
				Key:   metricsmap.MetricsKey{Dir: metricsmap.MetricToWg, Reason: metricsmap.MetricForwarded, Pad: 0, SrcAddr: 0xC0A80A01},
				Value: metricsmap.MetricsValue{Packets: 987, Bytes: 43210},
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
		"from_wg",
		"to_wg",
		"total",
		"avg. rate",
		"traffic",
		"estimated",
		"Per-source statistics",
		"src_addr",
		"192.168.10.1",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(outputStr, expected) {
			t.Errorf("Output missing expected string: %s", expected)
		}
	}

	if !strings.Contains(outputStr, "55.5 KB") && !strings.Contains(outputStr, "56789") {
		t.Error("Expected formatted byte count not found")
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
				Key:   metricsmap.MetricsKey{Dir: metricsmap.MetricFromWg, Reason: metricsmap.MetricForwarded, Pad: 0, SrcAddr: 0xC0A80A01},
				Value: metricsmap.MetricsValue{Packets: 100, Bytes: 1000},
			},
			{
				Key:   metricsmap.MetricsKey{Dir: metricsmap.MetricFromWg, Reason: metricsmap.MetricForwarded, Pad: 0, SrcAddr: 0xC0A80A02},
				Value: metricsmap.MetricsValue{Packets: 200, Bytes: 2000},
			},
			{
				Key:   metricsmap.MetricsKey{Dir: metricsmap.MetricFromWg, Reason: metricsmap.MetricForwarded, Pad: 0, SrcAddr: 0xC0A80A03},
				Value: metricsmap.MetricsValue{Packets: 300, Bytes: 3000},
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

	if !strings.Contains(outputStr, "192.168.10.3") {
		t.Error("Expected source 192.168.10.3 (highest traffic) to be shown")
	}
	if !strings.Contains(outputStr, "192.168.10.2") {
		t.Error("Expected source 192.168.10.2 (second highest traffic) to be shown")
	}

	if strings.Contains(outputStr, "192.168.10.1") {
		t.Error("Source 192.168.10.1 should be hidden when MaxSources=2")
	}

	if !strings.Contains(outputStr, "... and 1 more sources") {
		t.Error("Expected '... and 1 more sources' message")
	}
}
