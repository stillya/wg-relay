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

	ch := make(chan *prometheus.Desc, 4)
	collector.Describe(ch)
	close(ch)

	count := 0
	for range ch {
		count++
	}

	if count != 4 {
		t.Errorf("Expected 4 descriptors, got %d", count)
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
						BackendIndex: 1,
						Direction:    metricsmap.MetricDownstream,
						Pad:          0,
						Pad2:         0,
					},
					Value: metricsmap.MetricsValue{
						RxPackets: 100,
						TxPackets: 50,
						RxBytes:   5000,
						TxBytes:   2500,
					},
				},
			},
			expectedCount: 2,
		},
		{
			name: "multiple metrics with different backends",
			mode: "reverse",
			metricsData: []metricsmap.MetricData{
				{
					Key: metricsmap.MetricsKey{
						BackendIndex: 1,
						Direction:    metricsmap.MetricDownstream,
						Pad:          0,
						Pad2:         0,
					},
					Value: metricsmap.MetricsValue{
						RxPackets: 100,
						TxPackets: 50,
						RxBytes:   5000,
						TxBytes:   2500,
					},
				},
				{
					Key: metricsmap.MetricsKey{
						BackendIndex: 2,
						Direction:    metricsmap.MetricUpstream,
						Pad:          0,
						Pad2:         0,
					},
					Value: metricsmap.MetricsValue{
						RxPackets: 200,
						TxPackets: 100,
						RxBytes:   10000,
						TxBytes:   5000,
					},
				},
			},
			expectedCount: 4,
		},
		{
			name: "metrics with upstream direction",
			mode: "forward",
			metricsData: []metricsmap.MetricData{
				{
					Key: metricsmap.MetricsKey{
						BackendIndex: 1,
						Direction:    metricsmap.MetricUpstream,
						Pad:          0,
						Pad2:         0,
					},
					Value: metricsmap.MetricsValue{
						RxPackets: 10,
						TxPackets: 5,
						RxBytes:   500,
						TxBytes:   250,
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

				if m.Counter == nil {
					t.Error("Expected counter metric")
					continue
				}

				labels := m.GetLabel()
				foundMode := false
				foundDirection := false
				foundBackend := false

				for _, label := range labels {
					switch label.GetName() {
					case "mode":
						if label.GetValue() != tc.mode {
							t.Errorf("Expected mode %s, got %s", tc.mode, label.GetValue())
						}
						foundMode = true
					case "direction":
						foundDirection = true
					case "backend":
						foundBackend = true
					}
				}

				if !foundMode {
					t.Error("Missing mode label")
				}
				if !foundDirection {
					t.Error("Missing direction label")
				}
				if !foundBackend {
					t.Error("Missing backend label")
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
