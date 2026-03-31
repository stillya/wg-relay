package metricsmap

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

// Metrics constants.
const (
	MetricDownstream         uint8 = 0
	MetricUpstream           uint8 = 1
	MetricReasonForwarded    uint8 = 0
	MetricReasonDropped      uint8 = 1
	DirectionLabelDownstream       = "downstream"
	DirectionLabelUpstream         = "upstream"
	ReasonLabelForwarded           = "forwarded"
	ReasonLabelDropped             = "dropped"
)

// MetricsKey represents the key structure for the BPF metrics map.
type MetricsKey struct {
	BackendIndex uint8
	Direction    uint8
	Reason       uint8
	Pad          uint8
	Pad2         uint32
}

// MetricsValue represents the value structure for the BPF metrics map.
type MetricsValue struct {
	RxPackets uint64
	TxPackets uint64
	RxBytes   uint64
	TxBytes   uint64
}

// MetricData combines a metrics key with its corresponding value.
type MetricData struct {
	Key   MetricsKey
	Value MetricsValue
}

// BPFMapSource provides access to BPF metrics maps.
type BPFMapSource struct {
	name string
	m    *ebpf.Map
}

// NewBPFMapSource creates a new BPFMapSource with the given name and map.
func NewBPFMapSource(name string, m *ebpf.Map) *BPFMapSource {
	return &BPFMapSource{
		name: name,
		m:    m,
	}
}

// Name returns the name of this metrics source.
func (s *BPFMapSource) Name() string {
	return s.name
}

// Collect retrieves all metrics from the BPF map, aggregating per-CPU values.
func (s *BPFMapSource) Collect(ctx context.Context) ([]MetricData, error) {
	if s.m == nil {
		return nil, errors.New("map is nil")
	}

	var results []MetricData
	var key MetricsKey
	var perCPUValues []MetricsValue

	iter := s.m.Iterate()
	for iter.Next(&key, &perCPUValues) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		var totalValue MetricsValue
		for _, cpuValue := range perCPUValues {
			totalValue.RxPackets += cpuValue.RxPackets
			totalValue.TxPackets += cpuValue.TxPackets
			totalValue.RxBytes += cpuValue.RxBytes
			totalValue.TxBytes += cpuValue.TxBytes
		}

		results = append(results, MetricData{
			Key:   key,
			Value: totalValue,
		})
	}

	if err := iter.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate metrics map")
	}

	return results, nil
}

// DirectionToString converts a direction constant to its string representation.
func DirectionToString(direction uint8) string {
	switch direction {
	case MetricDownstream:
		return DirectionLabelDownstream
	case MetricUpstream:
		return DirectionLabelUpstream
	default:
		return "unknown"
	}
}

// ReasonToString converts a reason constant to its string representation.
func ReasonToString(reason uint8) string {
	switch reason {
	case MetricReasonForwarded:
		return ReasonLabelForwarded
	case MetricReasonDropped:
		return ReasonLabelDropped
	default:
		return "unknown"
	}
}

// BackendIndexToString converts a backend index to its string representation.
func BackendIndexToString(index uint8) string {
	return fmt.Sprintf("backend_%d", index)
}
