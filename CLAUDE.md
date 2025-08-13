# wg-relay Development Guidelines

# WireGuard Traffic Obfuscator

## Project Overview

An eBPF-based traffic obfuscation system that disguises WireGuard protocol traffic to bypass deep packet inspection (DPI) and network
censorship. The system intercepts WireGuard packets, applies lightweight obfuscation, and transparently routes them through a proxy server before
reaching the actual WireGuard endpoint.

## Architecture

```
Client                 Obfuscator Proxy           WireGuard Server
  |                          |                          |
  | WG packets               |                          |
  |------------------------->|                          |
  |                          | Obfuscated packets       |
  |                          |------------------------->|
  |                          |                          | Real WG packets
  |                          |                          |----------> WG Server
  |                          |                          |
  |                          | WG Response              |
  |                          |<-------------------------|
  | Deobfuscated response    |                          |
  |<-------------------------|                          |
```

## Code Style Guidelines

- **Imports**: Standard Go grouping (stdlib, external, project)
- **Error Handling**: Use descriptive errors with pkg/errors for wrapping
- **Naming**: Follow Go conventions (CamelCase for exported, camelCase for private)
- **Types**: Use strong typing, prefer interfaces for flexibility
- **Code Structure**: Group related functionality in packages
- **Tests**: Write unit tests for all exported functions
- **Comments**: Document exported functions following Go conventions
- **eBPF**: Use `github.com/cilium/ebpf` for eBPF-related code and follow its guidelines when writes eBPF programs.

## Project-Specific Patterns

- Follow error wrapping conventions with pkg/errors
- Prefer dependency injection for testability
- Handle context properly for cancellation
