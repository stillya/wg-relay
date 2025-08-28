package ebpf

import (
	"encoding/binary"
	"net"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

const (
	wgPort      = 51820
	xdpPass     = 2
	xdpTx       = 3
	xdpRedirect = 4 // fib_lookup redirects to default gateway

	statNatLookupsSuccess = 2
	statNatLookupsFailed  = 3

	metricToWg      = 1
	metricFromWg    = 2
	metricForwarded = 1
	metricDrop      = 2
)

// MetricsKey matches the eBPF struct metrics_key
type MetricsKey struct {
	Dir    uint8
	Reason uint8
	Pad    uint16
}

// MetricsValue matches the eBPF struct metrics_value
type MetricsValue struct {
	Packets uint64
	Bytes   uint64
}

func TestWgForwardProxy(t *testing.T) {
	objs := &WgForwardProxyObjects{}
	if err := LoadWgForwardProxyObjects(objs, nil); err != nil {
		t.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	tests := []struct {
		name            string
		packet          []byte
		obfuscationCfg  WgForwardProxyObfuscationConfig
		expectedResult  int
		expectedStats   map[uint32]uint64
		expectedMetrics map[MetricsKey]uint64
		checkObfuscated bool
		description     string
	}{
		{
			name:            "non_wg_traffic_http",
			packet:          createHTTPPacket("192.168.1.1", "192.168.1.2", 8080, 80),
			obfuscationCfg:  createObfuscationConfig(true, "test-key-123", "10.0.0.1"),
			expectedResult:  xdpPass,
			expectedStats:   map[uint32]uint64{},
			expectedMetrics: map[MetricsKey]uint64{},
			checkObfuscated: false,
			description:     "HTTP traffic should pass through unchanged",
		},
		{
			name:           "wg_traffic_obfuscation_enabled",
			packet:         createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort),
			obfuscationCfg: createObfuscationConfig(true, "test-key-123", "10.0.0.1"),
			expectedResult: xdpRedirect,
			expectedStats:  map[uint32]uint64{},
			expectedMetrics: map[MetricsKey]uint64{
				{Dir: metricToWg, Reason: metricForwarded}: 1,
			},
			checkObfuscated: true,
			description:     "WG traffic with obfuscation enabled should be processed",
		},
		{
			name:            "wg_traffic_obfuscation_disabled",
			packet:          createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort),
			obfuscationCfg:  createObfuscationConfig(false, "test-key-123", "10.0.0.1"),
			expectedResult:  xdpPass,
			expectedStats:   map[uint32]uint64{},
			expectedMetrics: map[MetricsKey]uint64{},
			checkObfuscated: false,
			description:     "WG traffic with obfuscation disabled should pass through",
		},
		{
			name:           "wg_reverse_traffic",
			packet:         createWGPacket("192.168.1.2", "192.168.1.1", wgPort, 12345),
			obfuscationCfg: createObfuscationConfig(true, "test-key-123", "10.0.0.1"),
			expectedResult: xdpPass,
			expectedStats:  map[uint32]uint64{statNatLookupsFailed: 1},
			expectedMetrics: map[MetricsKey]uint64{
				{Dir: metricFromWg, Reason: metricDrop}: 1,
			},
			checkObfuscated: false,
			description:     "Reverse WG traffic without NAT mapping should pass through",
		},
		{
			name:            "non_udp_traffic",
			packet:          createTCPPacket("192.168.1.1", "192.168.1.2", 12345, 80),
			obfuscationCfg:  createObfuscationConfig(true, "test-key-123", "10.0.0.1"),
			expectedResult:  xdpPass,
			expectedStats:   map[uint32]uint64{},
			expectedMetrics: map[MetricsKey]uint64{},
			checkObfuscated: false,
			description:     "TCP traffic should pass through unchanged",
		},
		{
			name:           "wg_traffic_different_target_server",
			packet:         createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort),
			obfuscationCfg: createObfuscationConfig(true, "test-key-123", "192.168.200.100"),
			expectedResult: xdpRedirect,
			expectedStats:  map[uint32]uint64{},
			expectedMetrics: map[MetricsKey]uint64{
				{Dir: metricToWg, Reason: metricForwarded}: 1,
			},
			checkObfuscated: true,
			description:     "WG traffic with different target server should be processed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldStats := captureStats(objs.StatsMap)
			oldMetrics := captureMetrics(objs.MetricsMap)

			configKey := uint32(0)
			if err := objs.ObfuscationConfigMap.Put(&configKey, &tt.obfuscationCfg); err != nil {
				t.Fatalf("Failed to update config map: %v", err)
			}

			result, outputPacket, err := runXDPProgram(objs.WgForwardProxy, tt.packet)
			if err != nil {
				t.Fatalf("Failed to run eBPF program: %v", err)
			}

			if result != tt.expectedResult {
				t.Errorf("%s: Expected result %d, got %d", tt.description, tt.expectedResult, result)
			} else {
				t.Logf("✓ %s: got expected result %d", tt.description, result)
			}

			// Check obfuscation in output buffer if required
			if tt.checkObfuscated && outputPacket != nil {
				verifyObfuscation(t, tt.packet, outputPacket, tt.obfuscationCfg, tt.description)
			}

			currentStats := captureStats(objs.StatsMap)
			verifyStats(t, oldStats, currentStats, tt.expectedStats, tt.description)

			currentMetrics := captureMetrics(objs.MetricsMap)
			verifyMetrics(t, oldMetrics, currentMetrics, tt.expectedMetrics, tt.description)
		})
	}
}

func runXDPProgram(prog *ebpf.Program, packet []byte) (int, []byte, error) {
	result, out, err := prog.Test(packet)
	return int(result), out, err
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
	wgPayload := []byte{0x01, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01, 0x00,
		0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
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

	// Only capture legacy NAT stats that are still used
	statKeys := []uint32{statNatLookupsSuccess, statNatLookupsFailed}

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

func captureMetrics(metricsMap *ebpf.Map) map[MetricsKey]uint64 {
	metrics := make(map[MetricsKey]uint64)

	directions := []uint8{metricToWg, metricFromWg}
	reasons := []uint8{metricForwarded, metricDrop}

	for _, dir := range directions {
		for _, reason := range reasons {
			key := MetricsKey{Dir: dir, Reason: reason}

			var perCPUValues []MetricsValue
			err := metricsMap.Lookup(unsafe.Pointer(&key), &perCPUValues)
			if err != nil {
				metrics[key] = 0
				continue
			}

			var totalPackets uint64
			for _, cpuValue := range perCPUValues {
				totalPackets += cpuValue.Packets
			}
			metrics[key] = totalPackets
		}
	}

	return metrics
}

func verifyStats(t *testing.T, oldStats, actual, expected map[uint32]uint64, description string) {
	for statKey, expectedValue := range expected {
		if actualValue, exists := actual[statKey]; !exists {
			t.Errorf("%s: Expected stat %d to be %d, but stat key not found",
				description, statKey, expectedValue)
		} else if actualValue-oldStats[statKey] != expectedValue {
			t.Errorf("%s: Stat %d expected %d, got %d",
				description, statKey, expectedValue, actualValue)
		} else {
			t.Logf("✓ %s: Stat %d correctly has value %d", description, statKey, actualValue)
		}
	}
}

func verifyMetrics(t *testing.T, oldMetrics, actual, expected map[MetricsKey]uint64, description string) {
	for metricKey, expectedValue := range expected {
		if actualValue, exists := actual[metricKey]; !exists {
			t.Errorf("%s: Expected metric {Dir: %d, Reason: %d} to be %d, but metric key not found",
				description, metricKey.Dir, metricKey.Reason, expectedValue)
		} else {
			oldValue := oldMetrics[metricKey]
			deltaValue := actualValue - oldValue
			if deltaValue != expectedValue {
				t.Errorf("%s: Metric {Dir: %d, Reason: %d} expected delta %d, got %d (old: %d, new: %d)",
					description, metricKey.Dir, metricKey.Reason, expectedValue, deltaValue, oldValue, actualValue)
			} else {
				t.Logf("✓ %s: Metric {Dir: %d, Reason: %d} correctly incremented by %d (old: %d, new: %d)",
					description, metricKey.Dir, metricKey.Reason, deltaValue, oldValue, actualValue)
			}
		}
	}
}

func verifyObfuscation(t *testing.T, inputPacket, outputPacket []byte, cfg WgForwardProxyObfuscationConfig, description string) {
	if len(inputPacket) < 42 || len(outputPacket) < 42 { // Eth(14) + IP(20) + UDP(8) = 42
		t.Logf("Packets too small for payload comparison")
		return
	}

	inputPayload := inputPacket[42:]
	outputPayload := outputPacket[42:]

	if len(inputPayload) != len(outputPayload) {
		t.Errorf("%s: Payload length mismatch - input: %d, output: %d",
			description, len(inputPayload), len(outputPayload))
		return
	}

	if cfg.Method == 1 && cfg.Enabled == 1 { // XOR method enabled
		key := cfg.Key[:cfg.KeyLen]
		obfuscatedBytes := int(cfg.KeyLen)

		if obfuscatedBytes > len(inputPayload) {
			obfuscatedBytes = len(inputPayload)
		}

		expectedPayload := make([]byte, len(inputPayload))

		for i := 0; i < obfuscatedBytes; i++ {
			expectedPayload[i] = inputPayload[i] ^ key[i%len(key)]
		}

		obfuscatedMatches := true
		for i := 0; i < obfuscatedBytes; i++ {
			if i < len(outputPayload) && expectedPayload[i] != outputPayload[i] {
				obfuscatedMatches = false
				break
			}
		}

		// Compare non-obfuscated portion (should be unchanged)
		unchangedMatches := true
		for i := obfuscatedBytes; i < len(inputPayload); i++ {
			if i < len(outputPayload) && inputPayload[i] != outputPayload[i] {
				unchangedMatches = false
				break
			}
		}

		if obfuscatedMatches && unchangedMatches {
			t.Logf("✓ %s: Payload correctly obfuscated with XOR (first %d bytes)", description, obfuscatedBytes)
		} else {
			t.Errorf("%s: Payload obfuscation mismatch", description)
			if !obfuscatedMatches {
				t.Errorf("  Obfuscated portion (first %d bytes) doesn't match expected", obfuscatedBytes)
			}
			if !unchangedMatches {
				t.Errorf("  Non-obfuscated portion (bytes %d+) was unexpectedly changed", obfuscatedBytes)
			}
			t.Logf("Input payload:    %x", inputPayload[:min(32, len(inputPayload))])
			t.Logf("Expected payload: %x", expectedPayload[:min(32, len(expectedPayload))])
			t.Logf("Output payload:   %x", outputPayload[:min(32, len(outputPayload))])
			t.Logf("Key: %x, Obfuscated bytes: %d", key, obfuscatedBytes)
		}
	} else {
		payloadUnchanged := true
		for i := range inputPayload {
			if i < len(outputPayload) && inputPayload[i] != outputPayload[i] {
				payloadUnchanged = false
				break
			}
		}

		if payloadUnchanged {
			t.Logf("✓ %s: Payload correctly unchanged (obfuscation disabled)", description)
		} else {
			t.Errorf("%s: Payload unexpectedly changed when obfuscation disabled", description)
		}
	}
}
