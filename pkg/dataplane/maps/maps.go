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
	Stats []MapInfo // Statistics maps for metrics collection
	Other []MapInfo // Other maps (conntrack, etc.)
}

// NewMaps creates a new Maps collection
func NewMaps() *Maps {
	return &Maps{
		Stats: make([]MapInfo, 0),
		Other: make([]MapInfo, 0),
	}
}

// AddStatsMap adds a statistics map
func (m *Maps) AddStatsMap(name string, ebpfMap *ebpf.Map) {
	m.Stats = append(m.Stats, MapInfo{
		Name: name,
		Map:  ebpfMap,
	})
}

// AddOtherMap adds other types of maps
func (m *Maps) AddOtherMap(name string, ebpfMap *ebpf.Map) {
	m.Other = append(m.Other, MapInfo{
		Name: name,
		Map:  ebpfMap,
	})
}
