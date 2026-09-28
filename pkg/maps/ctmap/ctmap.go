package ctmap

import (
	"context"
	"time"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"

	"github.com/stillya/wg-relay/pkg/maps/timestamp"
)

// Tuple mirrors struct ipv4_ct_tuple in ebpf/include/ct.h; fields hold network-order bytes.
type Tuple struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

// Entry mirrors struct ipv4_ct_entry in ebpf/include/ct.h.
type Entry struct {
	LastSeen   uint64
	ToDaddr    uint32
	ToDport    uint16
	NatPort    uint16
	BackendIdx uint8
	Pad        [7]uint8
}

// Stats describes the outcome of one GC run.
type Stats struct {
	Alive          int
	Deleted        int
	OrphansDeleted int
	Duration       time.Duration
}

// Map provides typed access to the forward-mode conntrack maps.
type Map struct {
	ct             *ebpf.Map
	rev            *ebpf.Map
	now            func() (uint64, error)
	pendingOrphans map[Tuple]struct{}
}

// New creates a new Map over the conntrack map and its reverse map.
func New(ct, rev *ebpf.Map) *Map {
	return &Map{
		ct:             ct,
		rev:            rev,
		now:            timestamp.MonoNow,
		pendingOrphans: make(map[Tuple]struct{}),
	}
}

// GC deletes flows idle for longer than timeout and orphaned reverse entries. It must not be called concurrently.
func (m *Map) GC(ctx context.Context, timeout time.Duration) (Stats, error) {
	if m.ct == nil || m.rev == nil {
		return Stats{}, errors.New("conntrack maps are nil")
	}

	start := time.Now()
	now, err := m.now()
	if err != nil {
		return Stats{}, errors.Wrap(err, "failed to read datapath clock")
	}
	ttl := uint64(timeout) //nolint:gosec // timeout is validated positive

	total, expired, err := m.collectExpired(ctx, now, ttl)
	if err != nil {
		return Stats{}, err
	}

	deleted := 0
	for _, key := range expired {
		ok, err := m.deleteExpired(key, now, ttl)
		if err != nil {
			return Stats{}, err
		}
		if ok {
			deleted++
		}
	}

	orphans, err := m.collectOrphans(ctx)
	if err != nil {
		return Stats{}, err
	}

	// The datapath reserves a reverse entry before inserting its flow, so orphans are deleted on the second sighting.
	orphansDeleted := 0
	pending := make(map[Tuple]struct{})
	for revKey := range orphans {
		if _, seen := m.pendingOrphans[revKey]; !seen {
			pending[revKey] = struct{}{}
			continue
		}
		if err := deleteKey(m.rev, revKey); err != nil {
			return Stats{}, errors.Wrap(err, "failed to delete orphaned reverse conntrack entry")
		}
		orphansDeleted++
	}
	m.pendingOrphans = pending

	return Stats{
		Alive:          total - deleted,
		Deleted:        deleted,
		OrphansDeleted: orphansDeleted,
		Duration:       time.Since(start),
	}, nil
}

func (m *Map) collectExpired(ctx context.Context, now, ttl uint64) (int, []Tuple, error) {
	var expired []Tuple
	var key Tuple
	var entry Entry
	total := 0

	iter := m.ct.Iterate()
	for iter.Next(&key, &entry) {
		if err := ctx.Err(); err != nil {
			return 0, nil, errors.Wrap(err, "conntrack gc interrupted")
		}
		total++
		if isExpired(entry, now, ttl) {
			expired = append(expired, key)
		}
	}
	if err := iter.Err(); err != nil {
		return 0, nil, errors.Wrap(err, "failed to iterate conntrack map")
	}

	return total, expired, nil
}

// deleteExpired re-checks the flow, since the datapath may have refreshed it after it was collected, and deletes the
// reverse entry only while it still points to this flow.
func (m *Map) deleteExpired(key Tuple, now, ttl uint64) (bool, error) {
	var entry Entry
	if err := m.ct.Lookup(&key, &entry); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, errors.Wrap(err, "failed to look up conntrack entry")
	}
	if !isExpired(entry, now, ttl) {
		return false, nil
	}

	if err := deleteKey(m.ct, key); err != nil {
		return false, errors.Wrap(err, "failed to delete conntrack entry")
	}

	revKey := revTuple(key, entry)
	var owner Tuple
	if err := m.rev.Lookup(&revKey, &owner); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, errors.Wrap(err, "failed to look up reverse conntrack entry")
	}
	if owner != key {
		return true, nil
	}
	if err := deleteKey(m.rev, revKey); err != nil {
		return false, errors.Wrap(err, "failed to delete reverse conntrack entry")
	}

	return true, nil
}

func (m *Map) collectOrphans(ctx context.Context) (map[Tuple]struct{}, error) {
	orphans := make(map[Tuple]struct{})
	var revKey, key Tuple

	iter := m.rev.Iterate()
	for iter.Next(&revKey, &key) {
		if err := ctx.Err(); err != nil {
			return nil, errors.Wrap(err, "conntrack gc interrupted")
		}
		orphan, err := m.isOrphan(revKey, key)
		if err != nil {
			return nil, err
		}
		if orphan {
			orphans[revKey] = struct{}{}
		}
	}
	if err := iter.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to iterate reverse conntrack map")
	}

	return orphans, nil
}

func (m *Map) isOrphan(revKey, key Tuple) (bool, error) {
	var entry Entry
	if err := m.ct.Lookup(&key, &entry); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, errors.Wrap(err, "failed to look up conntrack entry")
	}
	return revTuple(key, entry) != revKey, nil
}

// revTuple derives a flow's reverse key the same way ct_restore in ebpf/include/ct.h does.
func revTuple(key Tuple, entry Entry) Tuple {
	return Tuple{
		Saddr: entry.ToDaddr,
		Daddr: key.Daddr,
		Sport: entry.ToDport,
		Dport: entry.NatPort,
	}
}

func isExpired(entry Entry, now, ttl uint64) bool {
	return now > entry.LastSeen && now-entry.LastSeen > ttl
}

func deleteKey(m *ebpf.Map, key Tuple) error {
	if err := m.Delete(&key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}
	return nil
}
