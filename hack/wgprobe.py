#!/usr/bin/env python3
"""
WireGuard Relay Probe Tool

A simple UDP probe tool for testing wg-relay obfuscation.
Operates in two modes: client (send) and server (receive).
Almost fully vibecoded, don't trust it.
"""

import argparse
import socket
import sys
import time
from datetime import datetime

# ANSI color codes
COLOR_RESET = '\033[0m'
COLOR_GREEN = '\033[92m'  # XOR-modified bytes
COLOR_YELLOW = '\033[93m'  # Padding bytes
COLOR_BLUE = '\033[94m'  # Headers/metadata
COLOR_RED = '\033[91m'  # Errors

# Default configuration
DEFAULT_HOST = '192.168.100.2'
DEFAULT_PORT = 51820
DEFAULT_PAYLOAD = b'WGPROBE_TEST_PACKET_'
BUFFER_SIZE = 2048


def format_hex_dump(data: bytes, original_payload: bytes) -> str:
    """
    Format bytes as colored hex dump.

    Args:
        data: Raw bytes to display
        original_payload: Expected original payload for comparison

    Returns:
        Formatted hex dump string with color coding
    """
    lines = []
    offset = 0

    # Determine where padding starts (trailing zeros)
    padding_start = len(data)
    for i in range(len(data) - 1, -1, -1):
        if data[i] != 0:
            padding_start = i + 1
            break

    while offset < len(data):
        chunk = data[offset:offset + 16]
        hex_parts = []
        ascii_parts = []

        for i, byte in enumerate(chunk):
            abs_pos = offset + i

            # Determine color based on byte position and value
            color = COLOR_RESET
            if abs_pos >= padding_start and byte == 0:
                # Padding byte (trailing zeros)
                color = COLOR_YELLOW
            elif original_payload and abs_pos < len(original_payload):
                # Check if byte differs from original (XOR'd)
                if byte != original_payload[abs_pos]:
                    color = COLOR_GREEN
            elif original_payload and abs_pos >= len(original_payload):
                # Beyond original payload length (could be XOR'd or padding)
                if byte != 0:
                    color = COLOR_GREEN
                else:
                    color = COLOR_YELLOW

            # Format hex
            hex_parts.append(f'{color}{byte:02x}{COLOR_RESET}')

            # Format ASCII (printable or dot)
            if 32 <= byte <= 126:
                ascii_parts.append(chr(byte))
            else:
                ascii_parts.append('.')

        # Build line with offset, hex, and ASCII
        hex_str = ' '.join(hex_parts)
        ascii_str = ''.join(ascii_parts)
        lines.append(f'{offset:04x}  {hex_str:<70}  |{ascii_str}|')

        offset += 16

    return '\n'.join(lines)


def run_client(host: str, port: int, payload: bytes, count: int = 1):
    """
    Run in client mode - send UDP packets.

    Args:
        host: Destination IP address
        port: Destination port
        payload: Payload to send
        count: Number of packets to send
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        print(f'{COLOR_BLUE}=== WireGuard Relay Probe - Client Mode ==={COLOR_RESET}')
        print(f'Target: {host}:{port}')
        print(f'Payload size: {len(payload)} bytes')
        print(f'Packets to send: {count}')
        print()

        for i in range(count):
            # Add timestamp to payload
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            full_payload = payload + timestamp.encode()

            sock.sendto(full_payload, (host, port))

            print(f'[{i+1}/{count}] Sent {len(full_payload)} bytes at {timestamp}')

            if count > 1 and i < count - 1:
                time.sleep(0.1)

        print(f'\n{COLOR_GREEN}✓ All packets sent successfully{COLOR_RESET}')

    except PermissionError:
        print(f'{COLOR_RED}Error: Permission denied. Try running with sudo if using privileged ports.{COLOR_RESET}',
              file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f'{COLOR_RED}Error: {e}{COLOR_RESET}', file=sys.stderr)
        sys.exit(1)
    finally:
        # pyright: ignore
        sock.close()


def run_server(port: int, original_payload: bytes):
    """
    Run in server mode - receive and display UDP packets.

    Args:
        port: Port to listen on
        original_payload: Expected original payload for obfuscation detection
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))

        print(f'{COLOR_BLUE}=== WireGuard Relay Probe - Server Mode ==={COLOR_RESET}')
        print(f'Listening on: 0.0.0.0:{port}')
        print()
        print('Legend:')
        print(f'  {COLOR_GREEN}Green{COLOR_RESET}  = XOR-modified bytes')
        print(f'  {COLOR_YELLOW}Yellow{COLOR_RESET} = Padding bytes (zeros)')
        print('  White  = Original/unchanged bytes')
        print()
        print('Waiting for packets... (Press Ctrl+C to stop)')
        print('=' * 80)
        print()

        packet_count = 0

        while True:
            try:
                data, addr = sock.recvfrom(BUFFER_SIZE)
                packet_count += 1
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

                print(f'{COLOR_BLUE}[Packet #{packet_count}] {timestamp}{COLOR_RESET}')
                print(f'From: {addr[0]}:{addr[1]}')
                print(f'Size: {len(data)} bytes')

                # Analyze packet structure
                obfuscated = False
                padding_detected = 0

                # Check for trailing zeros (padding)
                for i in range(len(data) - 1, -1, -1):
                    if data[i] == 0:
                        padding_detected += 1
                    else:
                        break

                if padding_detected >= 32:
                    print(f'Padding detected: {padding_detected} trailing zero bytes')
                    obfuscated = True

                # Check if data differs from expected payload
                if original_payload:
                    for i in range(min(len(data), len(original_payload))):
                        if data[i] != original_payload[i]:
                            obfuscated = True
                            break

                if obfuscated:
                    print(f'{COLOR_RED}Status: OBFUSCATED{COLOR_RESET} (XOR and/or padding applied)')
                else:
                    print(f'{COLOR_GREEN}Status: CLEAR{COLOR_RESET} (no obfuscation detected)')

                print()
                print('Hex dump:')
                print(format_hex_dump(data, original_payload))
                print()
                print('=' * 80)
                print()

            except KeyboardInterrupt:
                break

        print(f'\n{COLOR_BLUE}Received {packet_count} packets total{COLOR_RESET}')

    except PermissionError:
        print(f'{COLOR_RED}Error: Permission denied. Port {port} requires root privileges.{COLOR_RESET}',
              file=sys.stderr)
        print(f'{COLOR_YELLOW}Try: sudo python3 {sys.argv[0]} --server{COLOR_RESET}', file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f'{COLOR_RED}Error: {e}{COLOR_RESET}', file=sys.stderr)
        sys.exit(1)
    finally:
        # pyright: ignore
        sock.close()


def main():
    parser = argparse.ArgumentParser(
        description='WireGuard Relay Probe - UDP test tool for obfuscation testing',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples (run from project root):
  # Client mode (send from host)
  python3 hack/wgprobe.py
  python3 hack/wgprobe.py --host 192.168.200.2 --port 51820
  python3 hack/wgprobe.py --payload "CUSTOM_PAYLOAD" --count 5

  # Server mode (receive in namespace)
  sudo python3 hack/wgprobe.py --server
  sudo ip netns exec wg-server python3 hack/wgprobe.py --server
  sudo python3 hack/wgprobe.py --server --port 8888
        '''
    )

    parser.add_argument('--server', action='store_true',
                        help='Run in server mode (receive packets)')
    parser.add_argument('--host', type=str, default=DEFAULT_HOST,
                        help=f'Target host for client mode (default: {DEFAULT_HOST})')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT,
                        help=f'Port number (default: {DEFAULT_PORT})')
    parser.add_argument('--payload', type=str, default=DEFAULT_PAYLOAD.decode(),
                        help=f'Custom payload for client mode (default: {DEFAULT_PAYLOAD.decode()})')
    parser.add_argument('--count', type=int, default=1,
                        help='Number of packets to send in client mode (default: 1)')

    args = parser.parse_args()

    if args.server:
        # Server mode
        run_server(args.port, DEFAULT_PAYLOAD)
    else:
        # Client mode
        payload = args.payload.encode() if isinstance(args.payload, str) else args.payload
        run_client(args.host, args.port, payload, args.count)


if __name__ == '__main__':
    main()
