# WGRelay

[![Build Status](https://github.com/stillya/wg-relay/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/stillya/wg-relay/actions/workflows/build.yml)
[![Coverage](https://coveralls.io/repos/github/stillya/wg-relay/badge.svg?branch=master)](https://coveralls.io/github/stillya/wg-relay?branch=master)

An eBPF-based traffic obfuscation system that disguises WireGuard protocol traffic to bypass DPI and government
censorship

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

- Linux kernel 6.6+ with eBPF support
- Root privileges for eBPF operations
- Go 1.23+
- WireGuard tools

## Quick Start

### 1. Build

```bash
make build
```

### Testing

```bash
# Run all tests (requires root privileges)
make test

# Run only eBPF unit tests
make test-ebpf
```

### 2. Configuration

Create a `config.yaml` file:

```yaml
mode: "forward"                           # "forward" or "reverse"
enabled: true                             # Enable/disable obfuscation

daemon:
  listen: ":8080"                         # Daemon bind address

proxy:
  method: "xor"                           # Obfuscation method (Currently only "xor" is supported)
  key: "my_secret_key_32_bytes_long_123"  # Obfuscation key
  driver_mode: "driver"                   # use generic if you at containerized environment
  interfaces:
  - "eth0"                                # Main interface to intercept
  forward:
    target_server_ip: "192.168.200.2"     # Target WireGuard server IP
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

- **XOR**: Simple XOR-based obfuscation with a configurable key
- **None**: Pass-through mode for testing

### XDP Driver Modes

- **Driver**: Native XDP mode (better performance, requires driver support)
- **Offload**: Offload XDP mode (hardware offload, requires NIC support)
- **Generic**: Generic XDP mode (broader compatibility, slightly lower performance)

## Monitoring & Statistics

### Console Statistics (vnstat-style)

The daemon provides real-time traffic statistics in a vnstat-style table format:

```
                         wg-relay traffic statistics

                    |      from_wg |        to_wg |        total |    avg. rate
 ------------------+--------------+--------------+--------------+--------------
 traffic            |       7.4 GB |     480.9 MB |       7.9 GB |   68.1 KB/s
 ------------------+--------------+--------------+--------------+--------------
 estimated          |       5.3 GB |     341.6 MB |       5.6 GB |

 Per-source statistics:
 src_addr           |      from_wg |        to_wg |        total
 ------------------+--------------+--------------+--------------
 192.0.2.10         |      35.3 KB |      12.5 KB |      47.8 KB
 192.0.2.20         |      29.0 KB |       7.1 KB |      36.1 KB
 192.0.2.30         |      33.1 KB |       8.4 KB |      41.5 KB
 203.0.113.100      |       5.1 GB |      73.9 MB |       5.2 GB
```

Enable statistics monitoring in config:

```yaml
monitoring:
  statistics:
    enabled: true
    interval: 5s
```

### Prometheus Metrics

Expose Prometheus metrics for monitoring with Grafana dashboards:

```yaml
monitoring:
  prometheus:
    enabled: true
    listen: ":9090"
```

Available metrics:

- `wg_relay_rx_packets_total{mode, reason, src_addr}` - Total packets received
- `wg_relay_tx_packets_total{mode, reason, src_addr}` - Total packets transmitted
- `wg_relay_rx_bytes_total{mode, reason, src_addr}` - Total bytes received
- `wg_relay_tx_bytes_total{mode, reason, src_addr}` - Total bytes transmitted

Labels:

- `mode`: "forward" or "reverse"
- `reason`: "forwarded" or "drop"
- `src_addr`: Source IP address (e.g., "192.168.1.100")

## Development

### Devcontainer Setup

For development, you can use the provided devcontainer setup in `.devcontainer` directory. This allows you to work in a
consistent environment with all dependencies pre-installed. Especially in non-linux environments.

```bash
### Testing with Network Namespaces

# Create test namespaces
sudo bash setup-netns.sh

# Run forward-proxy in namespace
sudo make run-local-forward

# Run reverse-proxy in namespace
sudo make run-local-reverse
```
