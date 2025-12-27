# WGRelay

[![Build Status](https://github.com/stillya/wg-relay/actions/workflows/build.yml/badge.svg)](https://github.com/stillya/wg-relay/actions/workflows/build.yml)
[![Coverage](https://coveralls.io/repos/github/stillya/wg-relay/badge.svg?branch=master)](https://coveralls.io/github/stillya/wg-relay?branch=master)

An eBPF-based traffic obfuscation system that disguises WireGuard protocol traffic to bypass DPI and government
censorship

## Overview

The WireGuard eBPF Proxy intercepts WireGuard packets at the kernel level, applies lightweight obfuscation, and
transparently routes them through a proxy server before reaching the actual WireGuard endpoint. This helps circumvent
network restrictions while maintaining the security and performance benefits of WireGuard.

### Traffic Flow

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

### Component Interaction

```
┌─────────────────┐
│   wg-relay CLI  │  (user commands)
└────────┬────────┘
         │ Unix Socket
         │ /var/run/wg-relay/control.sock
         ▼
┌─────────────────┐
│ wg-relay-agent  │  (systemd service)
│   ┌─────────┐   │
│   │ Control │   │
│   │   API   │   │
│   └────┬────┘   │
│        │        │
│   ┌────▼────┐   │
│   │Dataplane│   │
│   │ Manager │   │
│   └────┬────┘   │
│        │        │
│   ┌────▼────┐   │
│   │  eBPF   │   │
│   │Programs │   │
│   └─────────┘   │
└─────────────────┘
         │
         ▼
    Linux Kernel
    (XDP/TC hooks)
```

## Requirements

- Linux kernel 6.6+ with eBPF support
- Root privileges for eBPF operations
- Go 1.23+
- WireGuard tools

## Quick Start

### Installation

**From Source:**

```bash
make build
sudo cp .bin/wg-relay-agent /usr/local/bin/
sudo cp .bin/wg-relay /usr/local/bin/
```

### Usage

**1. Start the agent:**

```bash
sudo systemctl start wg-relay-agent
```

**2. Create configuration:**

```bash
sudo nano /etc/wg-relay/config.yaml
```

```yaml
proxy:
  mode: "forward"                           # "forward" or "reverse"
  method: "xor"                             # Obfuscation method
  key: "my_secret_key_32_bytes_long_123"   # Obfuscation key
  driver_mode: "driver"                     # "driver" or "generic"
  interfaces:
    - "eth0"                                # Interface to intercept
  forward:
    target_server_ip: "192.168.200.2"      # Target WireGuard server
```

**3. Enable dataplane:**

```bash
sudo wg-relay enable -c /etc/wg-relay/config.yaml
```

**4. Check status:**

```bash
wg-relay status
wg-relay stats
```

### Development

```bash
# Build from source
make build

# Run agent locally
sudo make run-agent

# In another terminal, use CLI
sudo .bin/wg-relay enable -c config.yaml

# Run tests
make test
make test-ebpf
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

## Monitoring & Statistics

### CLI Statistics

View traffic statistics using the CLI:

```bash
# One-time snapshot
wg-relay stats

# Live monitoring (updates every 5s)
wg-relay stats --watch --interval 5s
```

Output format:

```
DIRECTION  REASON     SOURCE         PACKETS  BYTES
---------  ------     ------         -------  -----
from_wg    forwarded  192.168.1.10   1234     55.5 KB
to_wg      forwarded  192.168.1.10   987      43.2 KB
```

### Prometheus Metrics

The agent automatically exposes Prometheus metrics when enabled in configuration:

```yaml
monitoring:
  prometheus:
    enabled: true
    listen: ":9090"
```

**Behavior:**

- Metrics server starts automatically when dataplane is enabled with Prometheus config
- Stops when dataplane is disabled
- Automatically reconfigures on reload

**Access metrics:**

```bash
curl http://localhost:9090/metrics
```

**Available metrics:**

- `wg_relay_packets_total{mode, direction, reason, src_addr}` - Total packets processed
- `wg_relay_bytes_total{mode, direction, reason, src_addr}` - Total bytes processed

**Labels:**

- `mode`: "forward" or "reverse"
- `direction`: "from_wg" or "to_wg"
- `reason`: "forwarded", "drop"
- `src_addr`: Source IP address

## Development

### Devcontainer Setup

For development, you can use the provided devcontainer setup in `.devcontainer` directory. This allows you to work in a
consistent environment with all dependencies pre-installed. Especially in non-linux environments.

```bash
### Testing with Network Namespaces

# Create test namespaces
sudo bash setup-netns.sh

# Run proxy in namespace
sudo make run-forward-proxy
```