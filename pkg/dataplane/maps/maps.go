package maps

import (
	"github.com/cilium/ebpf"
)

// Maps holds collections of different types of eBPF maps
type Maps struct {
	Metrics      *ebpf.Map // Metrics map
	PaddingState *ebpf.Map // Adaptive padding state map (forward mode only, may be nil)
	CT           *ebpf.Map // Conntrack map (forward mode only, may be nil)
	CTRev        *ebpf.Map // Conntrack reverse map (forward mode only, may be nil)
}

// NewMaps creates a new Maps collection
func NewMaps(metricsMap *ebpf.Map) *Maps {
	return &Maps{
		Metrics: metricsMap,
	}
}
