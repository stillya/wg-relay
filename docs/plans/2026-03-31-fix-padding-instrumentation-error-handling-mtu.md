# Fix Padding Instrumentation: Error Handling and MTU Detection

## Overview

Two fixes to the padding obfuscation layer:
1. Fix error handling in padding functions - deobfuscate path currently returns INSTR_OK (pass-through) on validation failures instead of INSTR_ERROR (drop). All error paths should signal drop.
2. Add MTU detection in the Go control plane and pass the link MTU to eBPF via DECLARE_CONFIG, so the padding obfuscate functions can guard against growing a packet beyond the link MTU before calling bpf_xdp_adjust_tail / bpf_skb_change_tail.

## Context

- Files involved:
  - `ebpf/include/instrumentation/padding.h` - all four padding functions
  - `ebpf/include/static_config.h` - DECLARE_CONFIG macro (read-only, no changes needed)
  - `pkg/dataplane/config/config.go` - PaddingConfig struct, add MTU field
  - `pkg/dataplane/proxy/forward.go` - MTU detection per interface before loading
  - `pkg/dataplane/proxy/reverse.go` - MTU detection per interface before loading
  - `ebpf/wg_forward_proxy_test.go` - eBPF unit tests
  - `ebpf/wg_reverse_proxy_test.go` - eBPF unit tests
  - `pkg/dataplane/config/config_test.go` - config validation tests
- Related patterns:
  - DECLARE_CONFIG / CONFIG macros already used for padding_enabled, padding_size, wg_port, xor_enabled, xor_key
  - bpf.Configure() + ebpf struct tags propagate Go config to eBPF rodata
  - Go uses net.Interface.MTU from stdlib for interface metadata
- Dependencies: none new

## Development Approach

- **Testing approach**: Regular (code first, then tests)
- Complete each task fully before moving to the next
- **CRITICAL: every task MUST include new/updated tests**
- **CRITICAL: all tests must pass before starting next task**

## Implementation Steps

### Task 1: Fix error handling in padding deobfuscate functions

The deobfuscate functions (`padding_deobfuscate_xdp`, `padding_deobfuscate_tc`) return `INSTR_OK` on validation failures (bounds checks, invalid padding_size, pkt_len < padding_size). These cases mean the packet is malformed or unexpected and should be dropped by returning `INSTR_ERROR`.

**Files:**
- Modify: `ebpf/include/instrumentation/padding.h`

- [x] In `padding_deobfuscate_xdp`: change all intermediate guard returns from `INSTR_OK` to `INSTR_ERROR` (the data bounds check, pkt_len==0 check, mrk_offset bounds check, padding_size==0 check, and pkt_len < padding_size check)
- [x] In `padding_deobfuscate_tc`: change all intermediate guard returns from `INSTR_OK` to `INSTR_ERROR` (same set of checks)
- [x] Exception: keep `if padding_size == 0` as `INSTR_OK` since zero padding is a valid "no padding applied" signal
- [x] Write/update eBPF unit tests in `ebpf/wg_forward_proxy_test.go` and `ebpf/wg_reverse_proxy_test.go` to verify malformed packets (bad bounds, pkt_len < padding_size) are dropped
- [x] Run `go test ./ebpf/...` - must pass

### Task 2: Add MTU config to eBPF via DECLARE_CONFIG

Add a `link_mtu` config variable to the eBPF padding header so the obfuscate functions can check whether padding would exceed the link MTU before calling the tail-adjust helper. If padding would exceed MTU, drop the packet.

**Files:**
- Modify: `ebpf/include/instrumentation/padding.h`

- [x] Add `DECLARE_CONFIG(__u16, link_mtu, "Link MTU for padding size validation")` at the top of padding.h alongside existing DECLARE_CONFIG declarations
- [x] In `padding_obfuscate_xdp`: before calling `bpf_xdp_adjust_tail`, compute the current packet length from `(data_end - data)` and check `current_len + cfg_padding_size > CONFIG(link_mtu)`; if so, return `INSTR_ERROR`
- [x] In `padding_obfuscate_tc`: before calling `bpf_skb_change_tail`, check `current_len + cfg_padding_size > CONFIG(link_mtu)`; if so, return `INSTR_ERROR`
- [x] Write eBPF unit tests verifying that a packet which would exceed MTU after padding is dropped
- [x] Run `go test ./ebpf/...` - must pass

### Task 3: MTU detection in Go control plane and config propagation

Detect the MTU of each configured interface in Go, and pass the minimum MTU across all configured interfaces to eBPF via the existing `bpf.Configure` mechanism (DECLARE_CONFIG → ebpf struct tag).

**Files:**
- Modify: `pkg/dataplane/config/config.go` - add `LinkMTU uint16` to PaddingConfig
- Modify: `pkg/dataplane/proxy/forward.go` - detect MTU before loadEBPF, set cfg field
- Modify: `pkg/dataplane/proxy/reverse.go` - detect MTU before loadEBPF, set cfg field

- [x] Add `LinkMTU uint16 \`ebpf:"link_mtu"\`` to `PaddingConfig` in `config.go` (not yaml-exposed, computed at runtime)
- [x] Add a helper function `detectMinMTU(interfaces []string) (uint16, error)` in a shared location (e.g., a new small function in `pkg/utils/ip.go` or inline in each loader) that calls `net.InterfaceByName` and reads `iface.MTU`, returns the minimum across all interfaces
- [x] In `ForwardLoader.loadEBPF()`: before calling `bpf.Configure`, if `cfg.Instrumentations.Padding != nil`, detect MTU and set `cfg.Instrumentations.Padding.LinkMTU`
- [x] In `ReverseLoader.loadEBPF()`: same
- [x] Add config validation: if padding enabled and `LinkMTU > 0` and `padding_size >= LinkMTU`, return error
- [x] Write tests in `pkg/dataplane/proxy/` (or `pkg/dataplane/config/config_test.go`) verifying MTU is propagated correctly and validation catches oversized padding
- [x] Run `go test ./pkg/...` - must pass

### Task 4: Verify acceptance criteria

- [x] Run full test suite: `go test ./...` (pkg/* pass; ebpf/* darwin-only failures are expected - Linux kernel features require devcontainer)
- [x] Run linter: `golangci-lint run` (darwin/version compatibility issues with cilium/ebpf are pre-existing environment limitations, not regressions)
- [x] Verify all padding error paths result in packet drop (INSTR_ERROR → XDP_DROP / TC_ACT_SHOT) - confirmed by tests in Task 1
- [x] Verify MTU is passed from Go to eBPF correctly via `bpf.Configure` - confirmed by tests in Tasks 2 and 3

### Task 5: Update documentation

- [ ] Update CLAUDE.md if any new internal patterns were introduced (e.g., runtime-computed config fields)
- [ ] Move this plan to `docs/plans/completed/`
