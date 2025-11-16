package maps

import (
	"github.com/cilium/ebpf"
)

// MapInfo represents information about an eBPF map
type MapInfo struct {
	Name string
	Map  *ebpf.Map
}

// Maps holds collections of different types of eBPF maps
type Maps struct {
	Metrics *ebpf.Map // Metrics map
	Other   []MapInfo // Other maps (conntrack, etc.)
}

// NewMaps creates a new Maps collection
func NewMaps(metricsMap *ebpf.Map) *Maps {
	return &Maps{
		Metrics: metricsMap,
		Other:   make([]MapInfo, 0),
	}
}

// AddOtherMap adds other types of maps
func (m *Maps) AddOtherMap(name string, ebpfMap *ebpf.Map) {
	m.Other = append(m.Other, MapInfo{
		Name: name,
		Map:  ebpfMap,
	})
}
