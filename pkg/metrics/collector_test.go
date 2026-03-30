package metrics

import (
	"context"
	"strings"
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
	testCases := []struct {
		name          string
		mode          string
		expectedCount int
	}{
		{
			name:          "forward mode",
			mode:          "forward",
			expectedCount: 8,
		},
		{
			name:          "reverse mode",
			mode:          "reverse",
			expectedCount: 8,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			source := &mockMetricSource{name: "test"}
			backendLabels := map[uint8]string{0: "backend_0", 1: "backend_1"}
			collector := NewBpfCollector(source, tc.mode, backendLabels)

			ch := make(chan *prometheus.Desc, 10)
			collector.Describe(ch)
			close(ch)

			count := 0
			for range ch {
				count++
			}

			if count != tc.expectedCount {
				t.Errorf("Expected %d descriptors, got %d", tc.expectedCount, count)
			}
		})
	}
}

func TestBpfCollector_Collect(t *testing.T) {
	testCases := []struct {
		name          string
		mode          string
		backendLabels map[uint8]string
		metricsData   []metricsmap.MetricData
		expectedCount int
	}{
		{
			name:          "forward mode with downstream metrics",
			mode:          "forward",
			backendLabels: map[uint8]string{1: "backend_us_east"},
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
			expectedCount: 4,
		},
		{
			name:          "forward mode with upstream metrics",
			mode:          "forward",
			backendLabels: map[uint8]string{1: "backend_us_west"},
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
			expectedCount: 4,
		},
		{
			name:          "reverse mode with downstream metrics",
			mode:          "reverse",
			backendLabels: nil,
			metricsData: []metricsmap.MetricData{
				{
					Key: metricsmap.MetricsKey{
						BackendIndex: 0,
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
			expectedCount: 4,
		},
		{
			name:          "reverse mode with upstream metrics",
			mode:          "reverse",
			backendLabels: nil,
			metricsData: []metricsmap.MetricData{
				{
					Key: metricsmap.MetricsKey{
						BackendIndex: 0,
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
			name:          "forward mode with multiple backends and directions",
			mode:          "forward",
			backendLabels: map[uint8]string{1: "backend_1", 2: "backend_2"},
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
			expectedCount: 8,
		},
		{
			name:          "empty metrics",
			mode:          "forward",
			backendLabels: map[uint8]string{},
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
			collector := NewBpfCollector(source, tc.mode, tc.backendLabels)

			ch := make(chan prometheus.Metric, 20)
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
				if tc.mode == "forward" {
					foundBackend := false
					for _, label := range labels {
						if label.GetName() == "backend" {
							foundBackend = true
						}
					}
					if !foundBackend {
						t.Error("Forward mode should have backend label")
					}
				} else {
					for _, label := range labels {
						if label.GetName() == "backend" {
							t.Error("Reverse mode should not have backend label")
						}
					}
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
	backendLabels := map[uint8]string{0: "backend_0"}
	collector := NewBpfCollector(source, "forward", backendLabels)

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

func TestBpfCollector_BackendLabelFallback(t *testing.T) {
	source := &mockMetricSource{
		name: "test",
		data: []metricsmap.MetricData{
			{
				Key: metricsmap.MetricsKey{
					BackendIndex: 5,
					Direction:    metricsmap.MetricDownstream,
				},
				Value: metricsmap.MetricsValue{
					RxPackets: 100,
					TxPackets: 50,
					RxBytes:   5000,
					TxBytes:   2500,
				},
			},
		},
	}

	backendLabels := map[uint8]string{0: "backend_0", 1: "backend_1"}
	collector := NewBpfCollector(source, "forward", backendLabels)

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

		for _, label := range m.GetLabel() {
			if label.GetName() == "backend" {
				expectedFallback := metricsmap.BackendIndexToString(5)
				if label.GetValue() != expectedFallback {
					t.Errorf("Expected fallback label %s for unknown backend, got %s", expectedFallback, label.GetValue())
				}
			}
		}
	}

	if count != 4 {
		t.Errorf("Expected 4 metrics, got %d", count)
	}
}

func TestBpfCollector_MetricValues(t *testing.T) {
	source := &mockMetricSource{
		name: "test",
		data: []metricsmap.MetricData{
			{
				Key: metricsmap.MetricsKey{
					BackendIndex: 1,
					Direction:    metricsmap.MetricDownstream,
				},
				Value: metricsmap.MetricsValue{
					RxPackets: 100,
					TxPackets: 50,
					RxBytes:   5000,
					TxBytes:   2500,
				},
			},
		},
	}

	backendLabels := map[uint8]string{1: "backend_1"}
	collector := NewBpfCollector(source, "forward", backendLabels)

	ch := make(chan prometheus.Metric, 10)
	collector.Collect(ch)
	close(ch)

	expectedValues := map[string]float64{
		"wg_relay_forward_downstream_rq_rx_packets_total": 100,
		"wg_relay_forward_downstream_rq_tx_packets_total": 50,
		"wg_relay_forward_downstream_rq_rx_bytes_total":   5000,
		"wg_relay_forward_downstream_rq_tx_bytes_total":   2500,
	}

	count := 0
	for metric := range ch {
		count++
		var m dto.Metric
		if err := metric.Write(&m); err != nil {
			t.Fatalf("Failed to write metric: %v", err)
		}

		desc := metric.Desc().String()
		for expectedName, expectedValue := range expectedValues {
			if strings.Contains(desc, expectedName) {
				if m.Counter.GetValue() != expectedValue {
					t.Errorf("Metric %s: expected value %.0f, got %.0f", expectedName, expectedValue, m.Counter.GetValue())
				}
			}
		}
	}

	if count != 4 {
		t.Errorf("Expected 4 metrics, got %d", count)
	}
}
