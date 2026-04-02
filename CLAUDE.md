# WireGuard Traffic Obfuscator (wg-relay)

## What This Project Does

This is an eBPF-based traffic obfuscation system that disguises WireGuard protocol traffic to bypass deep packet
inspection (DPI) and network censorship. The system intercepts WireGuard packets, applies lightweight obfuscation, and
transparently routes them through a proxy server before reaching the actual WireGuard endpoint.

## How It Works

```
Client → Obfuscator Proxy → WireGuard Server
   |            |                 |
   | WG packets |                 |
   |----------->|                 |
   |            | Obfuscated      |
   |            | packets         |
   |            |---------------->|
   |            |                 | Real WG packets
   |            |                 |--------------> WG Server
   |            |                 |
   |            | WG Response     |
   |            |<----------------|
   | Clear       |                 |
   | response    |                 |
   |<-----------|                 |
```

## Development Environment

- Uses `devcontainer` for development to access Linux kernel features on macOS
- Do not attempt to build or run code - the developer handles this
- Focus on code analysis, suggestions, and improvements

## Go Code Style Requirements

### File Organization

- **Imports**: Use standard Go grouping (stdlib, external, project packages)
- **Package Structure**: Group related functionality into logical packages

### Naming Conventions

- **Exported**: Use CamelCase for public functions, types, variables
- **Private**: Use camelCase for internal functions, types, variables
- **Interfaces**: Use descriptive names, often ending in -er (e.g., Handler, Writer)

### Error Handling

- Use `pkg/errors` package for error wrapping
- Provide descriptive error messages with context
- Wrap errors to preserve stack traces

### Code Quality

- **Types**: Use strong typing, prefer interfaces for flexibility
- **Testing**: Write unit tests for all exported functions
- **Comments**: Document all exported functions following Go doc conventions
- **Context**: Properly handle context.Context for cancellation and timeouts

### eBPF Specific

- Use `github.com/cilium/ebpf` library for eBPF operations
- Follow cilium/ebpf guidelines when writing eBPF programs
- Handle eBPF map operations safely with proper error checking

## Project-Specific Patterns

- **Dependency Injection**: Prefer constructor injection for better testability
- **Error Wrapping**: Always wrap errors with context using pkg/errors
- **Runtime-Computed Config Fields**: Some config struct fields are computed at runtime (not loaded from YAML). Mark them with `yaml:"-"` to exclude from YAML parsing while still using `ebpf:"..."` tags for eBPF propagation via `bpf.Configure`. Example: `LinkMTU uint16 \`yaml:"-" ebpf:"link_mtu"\`` in `PaddingConfig` is detected from the network interface at loader startup and passed to eBPF rodata.

### Metrics Architecture

- **Low Cardinality**: Metrics use backend labels instead of src_addr to prevent cardinality explosion
- **Directional Split**: All metrics split into downstream (client to proxy) and upstream (proxy to backend/WireGuard)
- **RX/TX Separation**: Each direction tracks received (rx) and transmitted (tx) separately
- **Metric Naming**: Follow pattern `wg_relay_{mode}_{direction}_rq_{rx|tx}_{packets|bytes}_total`
  - Forward mode: Uses backend label with values from BackendServer.Name or backend_<index>
  - Reverse mode: No labels (aggregated by direction only)
- **Backend Labels**: Map from backend index (uint8) to human-readable name, passed from loader to collector/monitor

## Key Constraints

- **Security Focus**: This is a defensive security tool for bypassing censorship
- **No File Creation**: Prefer editing existing files over creating new ones
- **No Documentation**: Do not create README or documentation files unless explicitly requested
- **Code Analysis**: Focus on understanding and improving existing code structure