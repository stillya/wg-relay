#!/bin/bash

# Network namespace setup script for WireGuard proxy testing
# Creates eBPF proxy and WireGuard server namespaces
# Client runs on host, eBPF proxy in ebpf-proxy namespace, server in wg-server namespace

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
   exit 1
fi

# Function to cleanup existing setup
cleanup() {
    log "Cleaning up existing network namespaces and interfaces..."

    # Remove namespaces (this also removes their interfaces)
    ip netns del ebpf-proxy 2>/dev/null || true
    ip netns del wg-server 2>/dev/null || true

    # Remove any remaining veth interfaces in default namespace
    ip link del veth-ebpf@1 2>/dev/null || true
    ip link del veth-ebpf@2 2>/dev/null || true
    ip link del veth-wg@1 2>/dev/null || true
    ip link del veth-wg@2 2>/dev/null || true

    log "Cleanup completed"
}

# Function to setup network namespaces
setup_netns() {
    log "Creating network namespaces..."

    # Create namespaces
    ip netns add ebpf-proxy
    ip netns add wg-server

    # Create veth pairs
    # Host to eBPF proxy connection
    ip link add name veth-ebpf@1 type veth peer name veth-ebpf@2

    # eBPF proxy to WireGuard server connection
    ip link add name veth-wg@1 type veth peer name veth-wg@2

    # Move interfaces to namespaces
    ip link set veth-ebpf@2 netns ebpf-proxy
    ip link set veth-wg@1 netns ebpf-proxy
    ip link set veth-wg@2 netns wg-server

    # Configure host interface (where client runs)
    ip addr add 192.168.100.1/24 dev veth-ebpf@1
    ip link set veth-ebpf@1 up

    # Configure eBPF proxy namespace
    ip netns exec ebpf-proxy ip addr add 192.168.100.2/24 dev veth-ebpf@2
    ip netns exec ebpf-proxy ip addr add 192.168.200.1/24 dev veth-wg@1
    ip netns exec ebpf-proxy ip link set veth-ebpf@2 up
    ip netns exec ebpf-proxy ip link set veth-wg@1 up
    ip netns exec ebpf-proxy ip link set lo up

    # Configure server namespace
    ip netns exec wg-server ip addr add 192.168.200.2/24 dev veth-wg@2
    ip netns exec wg-server ip link set veth-wg@2 up
    ip netns exec wg-server ip link set lo up
    ip netns exec wg-server ip route add default via 192.168.200.1

    # Enable IP forwarding on host and in eBPF proxy namespace
    echo 1 > /proc/sys/net/ipv4/ip_forward
    ip netns exec ebpf-proxy sysctl -w net.ipv4.ip_forward=1

    # Add routing from host to server through eBPF proxy
    ip route add 192.168.200.0/24 via 192.168.100.2 dev veth-ebpf@1 2>/dev/null || true

    # Add routing in eBPF proxy namespace
    ip netns exec ebpf-proxy ip route add 192.168.100.0/24 dev veth-ebpf@2 2>/dev/null || true
    ip netns exec ebpf-proxy ip route add 192.168.200.0/24 dev veth-wg@1 2>/dev/null || true

    log "Network namespaces configured successfully"
}

# Function to display network configuration
show_config() {
    log "Network Configuration:"
    echo ""
    echo "Host (client runs here):"
    echo "  Interface: veth-ebpf@1"
    echo "  IP: 192.168.100.1/24"
    echo "  Route to server: 192.168.200.0/24 via 192.168.100.2"
    echo ""
    echo "eBPF Proxy Namespace (ebpf-proxy):"
    echo "  Host-side: veth-ebpf@2 (192.168.100.2/24)"
    echo "  Server-side: veth-wg@1 (192.168.200.1/24)"
    echo "  eBPF attachment: veth-ebpf@2 (ingress)"
    echo ""
    echo "Server Namespace (wg-server):"
    echo "  Interface: veth-wg@2"
    echo "  IP: 192.168.200.2/24"
    echo "  Gateway: 192.168.200.1 (eBPF proxy)"
    echo ""
    echo "Traffic Flow:"
    echo "  Client (host) -> eBPF Proxy (ebpf-proxy namespace) -> Server (wg-server namespace)"
    echo "  192.168.100.1 -> 192.168.100.2 -> 192.168.200.1 -> 192.168.200.2"
    echo ""
}

# Function to test connectivity
test_connectivity() {
    log "Testing basic connectivity..."

    # Test host to eBPF proxy
    if ping -c 1 -W 2 192.168.100.2 >/dev/null 2>&1; then
        log "✓ Host can reach eBPF proxy"
    else
        warn "✗ Host cannot reach eBPF proxy (192.168.100.2)"
    fi

    # Test eBPF proxy to server
    if ip netns exec ebpf-proxy ping -c 1 -W 2 192.168.200.2 >/dev/null 2>&1; then
        log "✓ eBPF proxy can reach server"
    else
        warn "✗ eBPF proxy cannot reach server (192.168.200.2)"
    fi

    # Test server to eBPF proxy
    if ip netns exec wg-server ping -c 1 -W 2 192.168.200.1 >/dev/null 2>&1; then
        log "✓ Server can reach eBPF proxy"
    else
        warn "✗ Server cannot reach eBPF proxy (192.168.200.1)"
    fi

    # Test end-to-end (without eBPF)
    if ping -c 1 -W 2 192.168.200.2 >/dev/null 2>&1; then
        log "✓ End-to-end connectivity working (host -> server)"
    else
        warn "✗ End-to-end connectivity not working (expected before eBPF redirection)"
    fi
}

# Function to show interface details
show_interfaces() {
    log "Interface Details:"
    echo ""
    echo "=== Host Namespace ==="
    ip addr show veth-ebpf@1 2>/dev/null | grep -E "(inet|link)" || echo "veth-ebpf@1 not found"
    echo ""
    echo "=== eBPF Proxy Namespace ==="
    ip netns exec ebpf-proxy ip addr show veth-ebpf@2 2>/dev/null | grep -E "(inet|link)" || echo "veth-ebpf@2 not found"
    ip netns exec ebpf-proxy ip addr show veth-wg@1 2>/dev/null | grep -E "(inet|link)" || echo "veth-wg@1 not found"
    echo ""
    echo "=== Server Namespace ==="
    ip netns exec wg-server ip addr show veth-wg@2 2>/dev/null | grep -E "(inet|link)" || echo "veth-wg@2 not found"
}

# Main execution
case "${1:-setup}" in
    "setup")
        cleanup
        setup_netns
        show_config
        test_connectivity
        ;;
    "cleanup")
        cleanup
        ;;
    "status")
        show_config
        show_interfaces
        test_connectivity
        ;;
    "test")
        test_connectivity
        ;;
    *)
        echo "Usage: $0 [setup|cleanup|status|test]"
        echo "  setup   - Create network namespaces and configure interfaces"
        echo "  cleanup - Remove all created namespaces and interfaces"
        echo "  status  - Show current configuration and test connectivity"
        echo "  test    - Test connectivity only"
        exit 1
        ;;
esac

log "Done!"
