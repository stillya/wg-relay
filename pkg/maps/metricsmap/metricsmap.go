package metricsmap

import (
	"context"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

const (
	MetricToWg   uint8 = 1
	MetricFromWg uint8 = 2

	MetricForwarded uint8 = 1
	MetricDrop      uint8 = 2
)

type MetricsKey struct {
	Dir    uint8
	Reason uint8
	Pad    uint16
}

type MetricsValue struct {
	Packets uint64
	Bytes   uint64
}

type MetricData struct {
	Key   MetricsKey
	Value MetricsValue
}

type BPFMapSource struct {
	name string
	m    *ebpf.Map
}

func NewBPFMapSource(name string, m *ebpf.Map) *BPFMapSource {
	return &BPFMapSource{
		name: name,
		m:    m,
	}
}

func (s *BPFMapSource) Name() string {
	return s.name
}

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
			totalValue.Packets += cpuValue.Packets
			totalValue.Bytes += cpuValue.Bytes
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

func DirectionToString(dir uint8) string {
	switch dir {
	case MetricToWg:
		return "to_wg"
	case MetricFromWg:
		return "from_wg"
	default:
		return "unknown"
	}
}

func ReasonToString(reason uint8) string {
	switch reason {
	case MetricForwarded:
		return "forwarded"
	case MetricDrop:
		return "drop"
	default:
		return "unknown"
	}
}
