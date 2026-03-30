# Reimplement Metrics with Envoy-Style Low Cardinality

## Overview
Refactor the metrics system from high-cardinality src_addr labels to Envoy-style low-cardinality backend labels. Split metrics into downstream/upstream directions with separate rx/tx tracking for both packets and bytes.

## Context
- Files involved:
  - ebpf/include/metrics.h (eBPF metrics structures and update function)
  - ebpf/wg_forward_proxy.c (forward proxy eBPF code)
  - ebpf/wg_reverse_proxy.c (reverse proxy eBPF code)
  - pkg/maps/metricsmap/metricsmap.go (Go metrics map interface)
  - pkg/metrics/collector.go (Prometheus collector)
  - pkg/dataplane/config/config.go (configuration structures)
  - pkg/dataplane/proxy/forward.go (forward proxy loader)
  - pkg/monitor/statmonitor.go (console statistics monitor)
  - pkg/monitor/tableprinter.go (statistics table printer)
- Current issue: Metrics use src_addr labels causing high cardinality and don't split downstream/upstream
- Target: Envoy-style metrics with backend labels only, split downstream/upstream with rx/tx
- New metric structure:
  - Forward path: wg_relay_forward_{downstream,upstream}_rq_{rx,tx}_{packets,bytes}_total with backend label
  - Reverse path: wg_relay_reverse_{downstream,upstream}_rq_{rx,tx}_{packets,bytes}_total without labels
  - All metrics follow Prometheus naming with _total suffix

## Development Approach
- Testing approach: Regular (code first, then tests)
- Complete each task fully before moving to the next
- CRITICAL: every task MUST include new/updated tests
- CRITICAL: all tests must pass before starting next task

## Implementation Steps

### Task 1: Add Name field to BackendServer config

**Files:**
- Modify: pkg/dataplane/config/config.go
- Modify: pkg/dataplane/config/config_test.go

- [x] add optional Name field to BackendServer struct
- [x] update validation to allow empty names
- [x] update test fixtures to include named and unnamed backends
- [x] write tests for new Name field validation
- [x] run project test suite - must pass before task 2

### Task 2: Update eBPF metrics structures for downstream/upstream split

**Files:**
- Modify: ebpf/include/metrics.h
- Modify: pkg/maps/metricsmap/metricsmap.go

- [ ] change metrics_key struct to replace src_addr with backend_index (u8)
- [ ] add direction field to distinguish downstream vs upstream (u8: 0=downstream, 1=upstream)
- [ ] update metrics_value struct to track rx_packets, tx_packets, rx_bytes, tx_bytes separately
- [ ] update update_metrics function signature to accept backend_index and direction
- [ ] update MetricsKey and MetricsValue structs in metricsmap.go to match eBPF structure
- [ ] remove SrcAddrToString function from metricsmap.go
- [ ] add BackendIndexToString and DirectionToString functions to metricsmap.go
- [ ] update tests in metricsmap_test.go
- [ ] run project test suite - must pass before task 3

### Task 3: Update forward proxy eBPF code for downstream/upstream tracking

**Files:**
- Modify: ebpf/wg_forward_proxy.c
- Modify: ebpf/wg_forward_proxy_test.go

- [ ] update METRIC_TO_WG path to call update_metrics with direction=downstream (client->proxy) for rx, direction=upstream for tx (proxy->backend)
- [ ] update METRIC_FROM_WG path to call update_metrics with direction=upstream (backend->proxy) for rx, direction=downstream for tx (proxy->client)
- [ ] pass backend_index from select_backend_hash to metrics calls
- [ ] store backend_index in connection_value for reverse path lookup
- [ ] update connection_value struct to include backend_index field
- [ ] update tests to verify downstream/upstream split
- [ ] run project test suite - must pass before task 4

### Task 4: Update reverse proxy eBPF code for downstream/upstream tracking

**Files:**
- Modify: ebpf/wg_reverse_proxy.c
- Modify: ebpf/wg_reverse_proxy_test.go

- [ ] update METRIC_TO_WG path to call update_metrics with direction=downstream (client->proxy) for rx, direction=upstream for tx (proxy->wg)
- [ ] update METRIC_FROM_WG path to call update_metrics with direction=upstream (wg->proxy) for rx, direction=downstream for tx (proxy->client)
- [ ] pass backend_index=0 (unused) for reverse mode
- [ ] update tests to verify downstream/upstream split without backend differentiation
- [ ] run project test suite - must pass before task 5

### Task 5: Implement backend name resolution in forward proxy loader

**Files:**
- Modify: pkg/dataplane/proxy/forward.go

- [ ] create method to generate backend labels (name or fallback to index)
- [ ] store backend label mapping (index -> label string)
- [ ] expose backend label mapping for metrics collector and stat monitor
- [ ] update tests to verify backend label generation
- [ ] run project test suite - must pass before task 6

### Task 6: Update Prometheus collector with new metric names

**Files:**
- Modify: pkg/metrics/collector.go
- Modify: pkg/metrics/collector_test.go

- [ ] define 8 new metrics for forward mode: wg_relay_forward_{downstream,upstream}_rq_{rx,tx}_{packets,bytes}_total with backend label
- [ ] define 8 new metrics for reverse mode: wg_relay_reverse_{downstream,upstream}_rq_{rx,tx}_{packets,bytes}_total without backend label
- [ ] remove old wg_relay_{rx,tx}_{packets,bytes}_total metrics
- [ ] accept backend label mapping in NewBpfCollector constructor
- [ ] update Collect method to use backend_index to lookup backend label
- [ ] update Collect method to populate separate rx/tx metrics based on direction
- [ ] remove mode and reason labels
- [ ] update tests to verify new metric names and labels
- [ ] run project test suite - must pass before task 7

### Task 7: Update statistics monitor for new metrics structure

**Files:**
- Modify: pkg/monitor/statmonitor.go
- Modify: pkg/monitor/tableprinter.go
- Modify: pkg/monitor/statmonitor_test.go

- [ ] update TablePrinter to accept backend label mapping
- [ ] update table display to show backend labels instead of src_addr in forward mode
- [ ] update table display to show downstream/upstream split with rx/tx separation
- [ ] update table display to aggregate by direction only in reverse mode
- [ ] update tests to verify new table format
- [ ] run project test suite - must pass before task 8

### Task 8: Wire up backend labels throughout the system

**Files:**
- Modify: cmd/daemon/main.go
- Modify: pkg/dataplane/proxy/forward.go
- Modify: pkg/dataplane/proxy/reverse.go

- [ ] pass backend label mapping from proxy loader to metrics collector
- [ ] pass backend label mapping from proxy loader to stat monitor
- [ ] ensure both Prometheus and console stats receive the mapping
- [ ] update integration to verify end-to-end metric flow
- [ ] run project test suite - must pass before task 9

### Task 9: Verify acceptance criteria

- [ ] run full test suite: make test
- [ ] run linter: make lint
- [ ] verify test coverage meets 80%+
- [ ] manually verify new metric names appear in Prometheus with correct labels
- [ ] manually verify console stats show backend labels and downstream/upstream split

### Task 10: Update documentation

- [ ] update config.yaml with example backend names
- [ ] update CLAUDE.md if metrics patterns changed
- [ ] move this plan to docs/plans/completed/
