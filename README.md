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
- Go 1.25+
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
daemon:                          # Daemon configuration
  listen: ":8080"                # Address and port for daemon to bind to

monitoring:                      # Monitoring configuration
  statistics:                    # vnstat-style console output
    enabled: true                # Enable/disable statistics display
    interval: "5s"               # Statistics update interval
  prometheus:                    # Prometheus HTTP exporter
    enabled: true                # Enable/disable Prometheus metrics server
    listen: ":8081"              # Address and port for metrics server

proxy:
  enabled: true                  # Enable/disable proxy
  mode: "forward"                # "forward" for forward proxy, "reverse" for reverse proxy
  wg_port: 51820                 # WireGuard port to intercept (default: 51820)

  instrumentations:              # Instrumentation configuration
    xor:                         # XOR obfuscation
      enabled: true
      key: "your_xor_key"
    padding:                     # Padding obfuscation
      enabled: true
      size: 32
      mode: "direct"             # "direct" (fixed size) or "randomize" (random 1..size)

  driver_mode: "driver"          # "driver", "generic" or "offload" for XDP mode
  interfaces:                    # Network interfaces to attach to
    - "eth0"
  forward:                       # Forward proxy configuration (forward mode)
    backends:
      - name: "wg-gateway-1"     # Optional: backend name for metrics (defaults to backend_<index>)
        ip: "192.168.200.2"      # Backend 1 IP address
        port: 51820              # Optional: port (defaults to wg_port)
      - name: "wg-gateway-2"     # Named backend for low-cardinality metrics
        ip: "192.168.200.3"      # Backend 2 IP address
        port: 51820
```

Backend names: The optional name field allows you to assign human-readable labels to backends for Prometheus metrics and console statistics. If omitted, backends are labeled as backend_0, backend_1, etc. Named backends help with metric clarity and dashboard creation.

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

- **Forward Mode**: Intercepts outbound WireGuard traffic, obfuscates it, and forwards to one of backend
- **Reverse Mode**: Handles bidirectional traffic processing for server-side deployment

### Obfuscation Methods

- **XOR**: Simple XOR-based obfuscation with a configurable key
- **Padding**: Adds padding to packets to alter traffic patterns. Supports `direct` mode (fixed size) and `randomize` mode (random size between 1 and `size` per packet)
- **None**: Pass-through mode for testing

### XDP Driver Modes

- **Driver**: Native XDP mode (better performance, requires driver support)
- **Offload**: Offload XDP mode (hardware offload, requires NIC support)
- **Generic**: Generic XDP mode (broader compatibility, slightly lower performance)

## Monitoring & Statistics

### Console Statistics (vnstat-style)

The daemon provides real-time traffic statistics with downstream/upstream split:

Forward Mode (shows per-backend statistics):

```
                         wg-relay(forward) traffic statistics

                    |      down_rx |      down_tx |        up_rx |        up_tx |        total |    avg. rate
 ------------------+--------------+--------------+--------------+--------------+--------------+--------------
 traffic            |       7.4 GB |     480.9 MB |       3.2 GB |       1.8 GB |      13.3 GB |   68.1 KB/s
 ------------------+--------------+--------------+--------------+--------------+--------------+--------------
 estimated          |       5.3 GB |     341.6 MB |       2.3 GB |       1.3 GB |       9.2 GB |

 Per-backend statistics:
 backend            |      down_rx |      down_tx |        up_rx |        up_tx |        total
 ------------------+--------------+--------------+--------------+--------------+--------------
 wg-gateway-1       |      35.3 KB |      12.5 KB |      18.2 KB |       9.1 KB |      75.1 KB
 wg-gateway-2       |      29.0 KB |       7.1 KB |      15.3 KB |       7.6 KB |      59.0 KB
 backend_2          |      33.1 KB |       8.4 KB |      17.1 KB |       8.5 KB |      67.1 KB
```

Column meanings:

- down_rx: Bytes received from client (downstream receive)
- down_tx: Bytes sent to client (downstream transmit)
- up_rx: Bytes received from backend/WireGuard (upstream receive)
- up_tx: Bytes sent to backend/WireGuard (upstream transmit)

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

Forward Mode (with backend label):

- `wg_relay_forward_downstream_rq_rx_packets_total{backend}` - Packets received from client
- `wg_relay_forward_downstream_rq_tx_packets_total{backend}` - Packets sent to client
- `wg_relay_forward_downstream_rq_rx_bytes_total{backend}` - Bytes received from client
- `wg_relay_forward_downstream_rq_tx_bytes_total{backend}` - Bytes sent to client
- `wg_relay_forward_upstream_rq_rx_packets_total{backend}` - Packets received from backend
- `wg_relay_forward_upstream_rq_tx_packets_total{backend}` - Packets sent to backend
- `wg_relay_forward_upstream_rq_rx_bytes_total{backend}` - Bytes received from backend
- `wg_relay_forward_upstream_rq_tx_bytes_total{backend}` - Bytes sent to backend

Reverse Mode (no labels):

- `wg_relay_reverse_downstream_rq_rx_packets_total` - Packets received from client
- `wg_relay_reverse_downstream_rq_tx_packets_total` - Packets sent to client
- `wg_relay_reverse_downstream_rq_rx_bytes_total` - Bytes received from client
- `wg_relay_reverse_downstream_rq_tx_bytes_total` - Bytes sent to client
- `wg_relay_reverse_upstream_rq_rx_packets_total` - Packets received from WireGuard server
- `wg_relay_reverse_upstream_rq_tx_packets_total` - Packets sent to WireGuard server
- `wg_relay_reverse_upstream_rq_rx_bytes_total` - Bytes received from WireGuard server
- `wg_relay_reverse_upstream_rq_tx_bytes_total` - Bytes sent to WireGuard server

Labels:

- `backend`: Backend server name (forward mode only) - either the configured name from config or backend_<index> fallback

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
