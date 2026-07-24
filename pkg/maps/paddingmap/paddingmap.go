package paddingmap

import (
	"context"
	"net"
	"strconv"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

// State mirrors `struct padding_state` in ebpf/include/instrumentation/padding.h.
// The byte layout must stay in sync with the eBPF definition.
type State struct {
	CurrentSize uint8  // current working padding ceiling, 1..configured size
	Pad         uint8  // alignment padding (unused)
	OkStreak    uint16 // consecutive successes since last increase
	Backoffs    uint32 // total multiplicative decreases
}

// StateData is a single per-CPU state entry for one interface.
type StateData struct {
	IfIndex uint32
	CPU     int
	State   State
}

// StateSource provides access to the adaptive padding state.
type StateSource interface {
	Collect(ctx context.Context) ([]StateData, error)
	Name() string
}

// BPFMapSource reads the adaptive padding state from a per-CPU BPF hash map.
type BPFMapSource struct {
	name string
	m    *ebpf.Map

	mu       sync.Mutex
	nameByIf map[uint32]string
}

// NewBPFMapSource creates a new BPFMapSource with the given name and map.
func NewBPFMapSource(name string, m *ebpf.Map) *BPFMapSource {
	return &BPFMapSource{
		name:     name,
		m:        m,
		nameByIf: make(map[uint32]string),
	}
}

// Name returns the name of this source.
func (s *BPFMapSource) Name() string {
	return s.name
}

// Collect reads every per-interface, per-CPU padding state entry. Unlike the
// metrics map, per-CPU values are NOT summed: each CPU holds an independent
// working state, so every CPU is returned as its own StateData.
func (s *BPFMapSource) Collect(ctx context.Context) ([]StateData, error) {
	if s.m == nil {
		return nil, errors.New("map is nil")
	}

	var results []StateData
	var ifindex uint32
	var perCPU []State

	iter := s.m.Iterate()
	for iter.Next(&ifindex, &perCPU) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		for cpu, st := range perCPU {
			results = append(results, StateData{
				IfIndex: ifindex,
				CPU:     cpu,
				State:   st,
			})
		}
	}

	if err := iter.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate padding state map")
	}

	return results, nil
}

// IfName resolves an ifindex to its interface name, caching results. On
// resolution failure it falls back to the numeric index so callers always get
// a stable, non-empty label.
func (s *BPFMapSource) IfName(ifindex uint32) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if name, ok := s.nameByIf[ifindex]; ok {
		return name
	}

	name := strconv.FormatUint(uint64(ifindex), 10)
	if iface, err := net.InterfaceByIndex(int(ifindex)); err == nil { //nolint:gosec // ifindex is a small kernel-assigned id
		name = iface.Name
	}
	s.nameByIf[ifindex] = name
	return name
}
