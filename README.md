# WGRelay

An eBPF-based traffic obfuscation system that disguises WireGuard protocol traffic to bypass deep packet inspection (
DPI) and government censorship

## Overview

The WireGuard eBPF Proxy intercepts WireGuard packets at the kernel level, applies lightweight obfuscation, and
transparently routes them through a proxy server before reaching the actual WireGuard endpoint. This helps circumvent
network restrictions while maintaining the security and performance benefits of WireGuard.

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

## Requirements

- Linux kernel 5.4+ with eBPF support
- Root privileges for eBPF operations
- Go 1.21+
- WireGuard tools

## Quick Start

### 1. Build

```bash
make build
```

### 2. Configuration

Create a `config.yaml` file:

```yaml
mode: "forward"                  # "forward" or "reverse"
enabled: true                    # Enable/disable obfuscation

daemon:
  listen: ":8080"                # Daemon bind address

proxy:
  method: "xor"                           # Obfuscation method(Currently only "xor" is supported)
  key: "my_secret_key_32_bytes_long_123"  # Obfuscation key
  driver_mode: "driver"                    # use generic if you at containerized environment
  interfaces:
    - "eth0"                # Main interface to intercept
  forward:
    target_server_ip: "192.168.200.2" # Target WireGuard server IP
```

### 3. Run

```bash
# Run daemon
sudo make run-daemon

# Or run in specific network namespace
sudo make run-forward-proxy    # ebpf-proxy namespace
sudo make run-reverse-proxy    # wg-server namespace
```

## Configuration

### Proxy Modes

- **Forward Mode**: Intercepts outbound WireGuard traffic, obfuscates it, and forwards to target server
- **Reverse Mode**: Handles bidirectional traffic processing for server-side deployment

### Obfuscation Methods

- **XOR**: Simple XOR-based obfuscation with configurable key
- **None**: Pass-through mode for testing

### XDP Driver Modes

- **Driver**: Native XDP mode (better performance, requires driver support)
- **Generic**: Generic XDP mode (broader compatibility, slightly lower performance)

## Statistics

The daemon provides real-time eBPF statistics:

```
Stats: to_wg: 1245, from_wg: 1198, nat_lookup_suc: 1245, nat_lookup_fail: 0
```

Statistics include:

- `to_wg` - Packets sent to WireGuard
- `from_wg` - Packets received from WireGuard
- `nat_lookup_suc` - Successful NAT lookups
- `nat_lookup_fail` - Failed NAT lookups

## Development

### Devcontainer Setup

For development, you can use the provided devcontainer setup in `.devcontainer` directory. This allows you to work in a
consistent environment with all dependencies pre-installed. Specially in non-linux environments.

```bash

### Testing with Network Namespaces

The proxy is designed to work with network namespaces for isolation:

```bash
# Create test namespaces
sudo bash setup-netns.sh

# Run proxy in namespace
sudo make run-forward-proxy
```