package ebpf

import (
	"encoding/binary"
	"net"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

const (
	wgPort  = 51820
	xdpPass = 2
	xdpTx   = 3

	// Stats map keys from metrics.h
	statToWgPackets       = 0
	statFromWgPackets     = 1
	statNatLookupsSuccess = 2
	statNatLookupsFailed  = 3
)

func TestWgForwardProxy(t *testing.T) {
	objs := &WgForwardProxyObjects{}
	if err := LoadWgForwardProxyObjects(objs, nil); err != nil {
		t.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	tests := []struct {
		name           string
		packet         []byte
		obfuscationCfg WgForwardProxyObfuscationConfig
		expectedResult int
		expectedStats  map[uint32]uint64 // Expected final stat values
		description    string
	}{
		{
			name:           "non_wg_traffic_http",
			packet:         createHTTPPacket("192.168.1.1", "192.168.1.2", 8080, 80),
			obfuscationCfg: createObfuscationConfig(true, "test-key-123", "10.0.0.1"),
			expectedResult: xdpPass,
			expectedStats:  map[uint32]uint64{}, // No WG stats should be incremented
			description:    "HTTP traffic should pass through unchanged",
		},
		{
			name:           "wg_traffic_obfuscation_enabled",
			packet:         createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort),
			obfuscationCfg: createObfuscationConfig(true, "test-key-123", "10.0.0.1"),
			expectedResult: xdpTx,
			expectedStats:  map[uint32]uint64{statFromWgPackets: 1, statToWgPackets: 1}, // Should increment TO_WG counter
			description:    "WG traffic with obfuscation enabled should be processed",
		},
		{
			name:           "wg_traffic_obfuscation_disabled",
			packet:         createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort),
			obfuscationCfg: createObfuscationConfig(false, "test-key-123", "10.0.0.1"),
			expectedResult: xdpPass,
			expectedStats:  map[uint32]uint64{}, // No stats when obfuscation disabled
			description:    "WG traffic with obfuscation disabled should pass through",
		},
		{
			name:           "small_packet",
			packet:         []byte{0x00, 0x01, 0x02}, // Too small to be valid
			obfuscationCfg: createObfuscationConfig(true, "test-key-123", "10.0.0.1"),
			expectedResult: xdpPass,
			expectedStats:  map[uint32]uint64{}, // No stats for invalid packets
			description:    "Small invalid packets should pass through",
		},
		{
			name:           "wg_reverse_traffic",
			packet:         createWGPacket("192.168.1.2", "192.168.1.1", wgPort, 12345),
			obfuscationCfg: createObfuscationConfig(true, "test-key-123", "10.0.0.1"),
			expectedResult: xdpPass,
			expectedStats:  map[uint32]uint64{statFromWgPackets: 1, statNatLookupsFailed: 1}, // FROM_WG packet, NAT lookup fails
			description:    "Reverse WG traffic without NAT mapping should pass through",
		},
		{
			name:           "non_udp_traffic",
			packet:         createTCPPacket("192.168.1.1", "192.168.1.2", 12345, 80),
			obfuscationCfg: createObfuscationConfig(true, "test-key-123", "10.0.0.1"),
			expectedResult: xdpPass,
			expectedStats:  map[uint32]uint64{}, // No WG stats for TCP traffic
			description:    "TCP traffic should pass through unchanged",
		},
		{
			name:           "wg_traffic_with_long_key",
			packet:         createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort),
			obfuscationCfg: createObfuscationConfig(true, "very-long-obfuscation-key-for-testing", "10.0.0.1"),
			expectedResult: xdpTx,
			expectedStats:  map[uint32]uint64{statToWgPackets: 1}, // Should increment TO_WG counter
			description:    "WG traffic with long key should be processed",
		},
		{
			name:           "wg_traffic_different_target_server",
			packet:         createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort),
			obfuscationCfg: createObfuscationConfig(true, "test-key-123", "192.168.200.100"),
			expectedResult: xdpTx,
			expectedStats:  map[uint32]uint64{statToWgPackets: 1}, // Should increment TO_WG counter
			description:    "WG traffic with different target server should be processed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configKey := uint32(0)
			if err := objs.ObfuscationConfigMap.Put(&configKey, &tt.obfuscationCfg); err != nil {
				t.Fatalf("Failed to update config map: %v", err)
			}

			// Run eBPF program
			result, err := runXDPProgram(objs.WgForwardProxy, tt.packet)
			if err != nil {
				t.Fatalf("Failed to run eBPF program: %v", err)
			}

			// Verify result
			if result != tt.expectedResult {
				t.Errorf("%s: Expected result %d, got %d", tt.description, tt.expectedResult, result)
			} else {
				t.Logf("✓ %s: got expected result %d", tt.description, result)
			}

			// Verify current stats values
			currentStats := captureStats(objs.StatsMap)
			verifyStats(t, currentStats, tt.expectedStats, tt.description)
		})
	}
}

func runXDPProgram(prog *ebpf.Program, packet []byte) (int, error) {
	_ = &xdpContext{
		data:     uintptr(unsafe.Pointer(&packet[0])),
		dataEnd:  uintptr(unsafe.Pointer(&packet[len(packet)-1])) + 1,
		dataSize: uint32(len(packet)),
	}

	result, _, err := prog.Test(packet)
	return int(result), err
}

// xdpContext represents the XDP context structure
// https://github.com/xdp-project/xdp-tools/blob/main/headers/linux/bpf.h#L5944
type xdpContext struct {
	data         uintptr
	dataEnd      uintptr
	dataSize     uint32
	ingressIfidx uint32
	rxQueueIndex uint32
	egressIfidx  uint32
}

func createWGPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	packet := make([]byte, 0, 64)

	// Ethernet header (14 bytes) - struct ethhdr
	eth := make([]byte, 14)
	// h_dest[6] - destination MAC address
	copy(eth[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}) // dst MAC
	// h_source[6] - source MAC address
	copy(eth[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}) // src MAC
	// h_proto - protocol type (big endian)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800) // ETH_P_IP
	packet = append(packet, eth...)

	// IP header (20 bytes)
	ip := make([]byte, 20)
	ip[0] = 0x45                            // Version 4, Header length 5
	ip[1] = 0x00                            // DSCP
	binary.BigEndian.PutUint16(ip[2:4], 40) // Total length (IP + UDP headers + minimal payload)
	ip[8] = 64                              // TTL
	ip[9] = 17                              // Protocol (UDP)
	copy(ip[12:16], net.ParseIP(srcIP).To4())
	copy(ip[16:20], net.ParseIP(dstIP).To4())
	packet = append(packet, ip...)

	// UDP header (8 bytes)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], 20) // UDP length (header + payload)
	// Checksum at udp[6:8] left as 0
	packet = append(packet, udp...)

	// WireGuard payload (12 bytes minimal)
	wgPayload := []byte{0x01, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	packet = append(packet, wgPayload...)

	return packet
}

func createHTTPPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	packet := make([]byte, 0, 64)

	// Ethernet header (14 bytes) - struct ethhdr
	eth := make([]byte, 14)
	// h_dest[6] - destination MAC address
	copy(eth[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}) // dst MAC
	// h_source[6] - source MAC address
	copy(eth[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}) // src MAC
	// h_proto - protocol type (big endian)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800) // ETH_P_IP
	packet = append(packet, eth...)

	// IP header
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[8] = 64
	ip[9] = 6 // Protocol (TCP)
	copy(ip[12:16], net.ParseIP(srcIP).To4())
	copy(ip[16:20], net.ParseIP(dstIP).To4())
	packet = append(packet, ip...)

	// TCP header (minimal 20 bytes)
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50 // Header length (5 * 4 = 20 bytes)
	packet = append(packet, tcp...)

	return packet
}

func createTCPPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	return createHTTPPacket(srcIP, dstIP, srcPort, dstPort)
}

func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func createObfuscationConfig(enabled bool, key, targetServerIP string) WgForwardProxyObfuscationConfig {
	cfg := WgForwardProxyObfuscationConfig{
		Method:         1, // XOR method
		TargetServerIp: ipToUint32(targetServerIP),
	}

	if enabled {
		cfg.Enabled = 1
	} else {
		cfg.Enabled = 0
	}

	keyBytes := []byte(key)
	if len(keyBytes) > 32 {
		keyBytes = keyBytes[:32]
	}
	cfg.KeyLen = uint32(len(keyBytes))
	copy(cfg.Key[:], keyBytes)

	return cfg
}

func captureStats(statsMap *ebpf.Map) map[uint32]uint64 {
	stats := make(map[uint32]uint64)

	statKeys := []uint32{statToWgPackets, statFromWgPackets, statNatLookupsSuccess, statNatLookupsFailed}

	for _, key := range statKeys {
		var value uint64
		err := statsMap.Lookup(&key, &value)
		if err != nil {
			value = 0
		}
		stats[key] = value
	}

	return stats
}

func verifyStats(t *testing.T, actual, expected map[uint32]uint64, description string) {
	for statKey, expectedValue := range expected {
		if actualValue, exists := actual[statKey]; !exists {
			t.Errorf("%s: Expected stat %d to be %d, but stat key not found",
				description, statKey, expectedValue)
		} else if actualValue != expectedValue {
			t.Errorf("%s: Stat %d expected %d, got %d",
				description, statKey, expectedValue, actualValue)
		} else {
			t.Logf("✓ %s: Stat %d correctly has value %d", description, statKey, actualValue)
		}
	}
}
