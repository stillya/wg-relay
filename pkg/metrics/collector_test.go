package metrics

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stillya/wg-relay/pkg/maps/metricsmap"
)

type mockMetricSource struct {
	name string
	data []metricsmap.MetricData
	err  error
}

func (m *mockMetricSource) Collect(ctx context.Context) ([]metricsmap.MetricData, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.data, nil
}

func (m *mockMetricSource) Name() string {
	return m.name
}

func TestBpfCollector_Describe(t *testing.T) {
	source := &mockMetricSource{name: "test"}
	collector := NewBpfCollector(source, "forward")

	ch := make(chan *prometheus.Desc, 2)
	collector.Describe(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count != 2 {
		t.Errorf("Expected 2 descriptors, got %d", count)
	}
}

func TestBpfCollector_Collect(t *testing.T) {
	testCases := []struct {
		name          string
		mode          string
		metricsData   []metricsmap.MetricData
		expectedCount int
	}{
		{
			name: "single metric",
			mode: "forward",
			metricsData: []metricsmap.MetricData{
				{
					Key: metricsmap.MetricsKey{
						Dir:     metricsmap.MetricFromWg,
						Reason:  metricsmap.MetricForwarded,
						Pad:     0,
						SrcAddr: 0xC0A80A01,
					},
					Value: metricsmap.MetricsValue{
						Packets: 100,
						Bytes:   5000,
					},
				},
			},
			expectedCount: 2,
		},
		{
			name: "multiple metrics with different src_addr",
			mode: "reverse",
			metricsData: []metricsmap.MetricData{
				{
					Key: metricsmap.MetricsKey{
						Dir:     metricsmap.MetricFromWg,
						Reason:  metricsmap.MetricForwarded,
						Pad:     0,
						SrcAddr: 0xC0A80A01,
					},
					Value: metricsmap.MetricsValue{
						Packets: 100,
						Bytes:   5000,
					},
				},
				{
					Key: metricsmap.MetricsKey{
						Dir:     metricsmap.MetricToWg,
						Reason:  metricsmap.MetricForwarded,
						Pad:     0,
						SrcAddr: 0xC0A80A02,
					},
					Value: metricsmap.MetricsValue{
						Packets: 200,
						Bytes:   10000,
					},
				},
			},
			expectedCount: 4,
		},
		{
			name: "metrics with drop reason",
			mode: "forward",
			metricsData: []metricsmap.MetricData{
				{
					Key: metricsmap.MetricsKey{
						Dir:     metricsmap.MetricFromWg,
						Reason:  metricsmap.MetricDrop,
						Pad:     0,
						SrcAddr: 0xC0A80A01,
					},
					Value: metricsmap.MetricsValue{
						Packets: 10,
						Bytes:   500,
					},
				},
			},
			expectedCount: 2,
		},
		{
			name:          "empty metrics",
			mode:          "forward",
			metricsData:   []metricsmap.MetricData{},
			expectedCount: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			source := &mockMetricSource{
				name: "test",
				data: tc.metricsData,
			}
			collector := NewBpfCollector(source, tc.mode)

			ch := make(chan prometheus.Metric, 10)
			collector.Collect(ch)
			close(ch)

			count := 0
			for metric := range ch {
				count++

				var m dto.Metric
				if err := metric.Write(&m); err != nil {
					t.Fatalf("Failed to write metric: %v", err)
				}

				if m.Gauge == nil {
					t.Error("Expected gauge metric")
					continue
				}

				labels := m.GetLabel()
				foundMode := false
				foundDirection := false
				foundReason := false
				foundSrcAddr := false

				for _, label := range labels {
					switch label.GetName() {
					case "mode":
						if label.GetValue() != tc.mode {
							t.Errorf("Expected mode %s, got %s", tc.mode, label.GetValue())
						}
						foundMode = true
					case "direction":
						foundDirection = true
					case "reason":
						foundReason = true
					case "src_addr":
						foundSrcAddr = true
					}
				}

				if !foundMode {
					t.Error("Missing mode label")
				}
				if !foundDirection {
					t.Error("Missing direction label")
				}
				if !foundReason {
					t.Error("Missing reason label")
				}
				if !foundSrcAddr {
					t.Error("Missing src_addr label")
				}
			}

			if count != tc.expectedCount {
				t.Errorf("Expected %d metrics, got %d", tc.expectedCount, count)
			}
		})
	}
}

func TestBpfCollector_CollectWithError(t *testing.T) {
	source := &mockMetricSource{
		name: "test",
		err:  context.DeadlineExceeded,
	}
	collector := NewBpfCollector(source, "forward")

	ch := make(chan prometheus.Metric, 10)
	collector.Collect(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count != 0 {
		t.Errorf("Expected 0 metrics when source returns error, got %d", count)
	}
}
