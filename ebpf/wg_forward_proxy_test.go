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
	xdpRedirect = 4 // fib_lookup redirects to default gateway

	metricToWg      = 1
	metricFromWg    = 2
	metricForwarded = 1
	metricDrop      = 2
)

type MetricsKey struct {
	Dir     uint8
	Reason  uint8
	Pad     uint16
	SrcAddr uint32
}

type MetricsValue struct {
	Packets uint64
	Bytes   uint64
}

func TestBasicForwarding(t *testing.T) {
	spec, err := LoadWgForwardProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}

	if err := spec.Variables["__cfg_xor_enabled"].Set(false); err != nil {
		t.Fatalf("Failed to set xor_enabled: %v", err)
	}
	if err := spec.Variables["__cfg_xor_key_len"].Set(uint8(0)); err != nil {
		t.Fatalf("Failed to set xor_key_len: %v", err)
	}
	if err := spec.Variables["__cfg_wg_port"].Set(uint16(wgPort)); err != nil {
		t.Fatalf("Failed to set wg_port: %v", err)
	}

	objs := &WgForwardProxyObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		t.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	backendKey := uint32(0)
	targetIP := ipToUint32("10.0.0.1")
	if err := objs.BackendMap.Put(&backendKey, &targetIP); err != nil {
		t.Fatalf("Failed to set backend map: %v", err)
	}

	tests := []struct {
		name            string
		packet          []byte
		expectedResult  int
		expectedMetrics map[MetricsKey]uint64
	}{
		{
			name:            "non_wg_traffic",
			packet:          createHTTPPacket("192.168.1.1", "192.168.1.2", 8080, 80),
			expectedResult:  xdpPass,
			expectedMetrics: map[MetricsKey]uint64{},
		},
		{
			name:           "wg_traffic_to_server",
			packet:         createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort),
			expectedResult: xdpRedirect,
			expectedMetrics: map[MetricsKey]uint64{
				{Dir: metricToWg, Reason: metricForwarded}: 1,
			},
		},
		{
			name:           "wg_reverse_traffic_no_nat",
			packet:         createWGPacket("192.168.1.2", "192.168.1.1", wgPort, 12345),
			expectedResult: xdpPass,
			expectedMetrics: map[MetricsKey]uint64{
				{Dir: metricFromWg, Reason: metricDrop}: 1,
			},
		},
		{
			name:            "tcp_traffic",
			packet:          createTCPPacket("192.168.1.1", "192.168.1.2", 12345, 80),
			expectedResult:  xdpPass,
			expectedMetrics: map[MetricsKey]uint64{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldMetrics := captureMetrics(objs.MetricsMap)

			result, _, err := objs.WgForwardProxy.Test(tt.packet)
			if err != nil {
				t.Fatalf("Failed to run program: %v", err)
			}

			if int(result) != tt.expectedResult {
				t.Errorf("Expected result %d, got %d", tt.expectedResult, result)
			}

			currentMetrics := captureMetrics(objs.MetricsMap)
			verifyMetrics(t, oldMetrics, currentMetrics, tt.expectedMetrics)
		})
	}
}

func TestXORObfuscation(t *testing.T) {
	tests := []struct {
		name       string
		xorEnabled bool
		xorKey     string
	}{
		{
			name:       "xor_enabled",
			xorEnabled: true,
			xorKey:     "test-key-1234567",
		},
		{
			name:       "xor_disabled",
			xorEnabled: false,
			xorKey:     "test-key-1234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := LoadWgForwardProxy()
			if err != nil {
				t.Fatalf("Failed to load spec: %v", err)
			}

			keyBytes := []byte(tt.xorKey)
			var keyArray [32]byte
			copy(keyArray[:], keyBytes)

			if err := spec.Variables["__cfg_xor_enabled"].Set(tt.xorEnabled); err != nil {
				t.Fatalf("Failed to set xor_enabled: %v", err)
			}
			if err := spec.Variables["__cfg_xor_key"].Set(keyArray); err != nil {
				t.Fatalf("Failed to set xor_key: %v", err)
			}
			keyLen := len(keyBytes)
			if keyLen > 255 {
				keyLen = 255
			}
			if err := spec.Variables["__cfg_xor_key_len"].Set(uint8(keyLen)); err != nil { //nolint:gosec // key length is bounded
				t.Fatalf("Failed to set xor_key_len: %v", err)
			}
			if err := spec.Variables["__cfg_wg_port"].Set(uint16(wgPort)); err != nil {
				t.Fatalf("Failed to set wg_port: %v", err)
			}

			objs := &WgForwardProxyObjects{}
			if err := spec.LoadAndAssign(objs, nil); err != nil {
				t.Fatalf("Failed to load objects: %v", err)
			}
			defer objs.Close()

			backendKey := uint32(0)
			targetIP := ipToUint32("10.0.0.1")
			if err := objs.BackendMap.Put(&backendKey, &targetIP); err != nil {
				t.Fatalf("Failed to set backend map: %v", err)
			}

			inputPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)
			_, outputPacket, err := objs.WgForwardProxy.Test(inputPacket)
			if err != nil {
				t.Fatalf("Failed to run program: %v", err)
			}

			if tt.xorEnabled {
				verifyXORObfuscation(t, inputPacket, outputPacket, keyBytes)
			} else {
				verifyPayloadUnchanged(t, inputPacket, outputPacket)
			}
		})
	}
}

func TestPortAndBackendConfig(t *testing.T) {
	tests := []struct {
		name           string
		wgPort         uint16
		targetServerIP string
		packetDstPort  uint16
		shouldForward  bool
	}{
		{
			name:           "default_port",
			wgPort:         51820,
			targetServerIP: "10.0.0.1",
			packetDstPort:  51820,
			shouldForward:  true,
		},
		{
			name:           "wrong_port",
			wgPort:         51820,
			targetServerIP: "10.0.0.1",
			packetDstPort:  9999,
			shouldForward:  false,
		},
		{
			name:           "custom_port",
			wgPort:         51821,
			targetServerIP: "10.0.0.1",
			packetDstPort:  51821,
			shouldForward:  true,
		},
		{
			name:           "different_target_server",
			wgPort:         51820,
			targetServerIP: "192.168.200.100",
			packetDstPort:  51820,
			shouldForward:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := LoadWgForwardProxy()
			if err != nil {
				t.Fatalf("Failed to load spec: %v", err)
			}

			if err := spec.Variables["__cfg_xor_enabled"].Set(false); err != nil {
				t.Fatalf("Failed to set xor_enabled: %v", err)
			}
			if err := spec.Variables["__cfg_xor_key_len"].Set(uint8(0)); err != nil {
				t.Fatalf("Failed to set xor_key_len: %v", err)
			}
			if err := spec.Variables["__cfg_wg_port"].Set(tt.wgPort); err != nil {
				t.Fatalf("Failed to set wg_port: %v", err)
			}

			objs := &WgForwardProxyObjects{}
			if err := spec.LoadAndAssign(objs, nil); err != nil {
				t.Fatalf("Failed to load objects: %v", err)
			}
			defer objs.Close()

			backendKey := uint32(0)
			targetIP := ipToUint32(tt.targetServerIP)
			if err := objs.BackendMap.Put(&backendKey, &targetIP); err != nil {
				t.Fatalf("Failed to set backend map: %v", err)
			}

			packet := createWGPacket("192.168.1.1", "192.168.1.2", 12345, tt.packetDstPort)
			result, _, err := objs.WgForwardProxy.Test(packet)
			if err != nil {
				t.Fatalf("Failed to run program: %v", err)
			}

			if tt.shouldForward {
				if int(result) != xdpRedirect {
					t.Errorf("Expected packet to be forwarded (XDP_REDIRECT), got result %d", result)
				}
			} else {
				if int(result) != xdpPass {
					t.Errorf("Expected packet to pass through (XDP_PASS), got result %d", result)
				}
			}
		})
	}
}

func createWGPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	packet := make([]byte, 0, 64)

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

func captureMetrics(metricsMap *ebpf.Map) map[MetricsKey]uint64 {
	metrics := make(map[MetricsKey]uint64)

	directions := []uint8{metricToWg, metricFromWg}
	reasons := []uint8{metricForwarded, metricDrop}
	srcAddrs := []uint32{
		ipToUint32("192.168.1.1"),
		ipToUint32("192.168.1.2"),
		0, // unknown/any
	}

	for _, dir := range directions {
		for _, reason := range reasons {
			var dirTotal uint64

			for _, srcAddr := range srcAddrs {
				key := MetricsKey{Dir: dir, Reason: reason, SrcAddr: srcAddr}

				var perCPUValues []MetricsValue
				err := metricsMap.Lookup(unsafe.Pointer(&key), &perCPUValues) //nolint:gosec // unsafe.Pointer required for eBPF map lookup
				if err != nil {
					continue
				}

				var totalPackets uint64
				for _, cpuValue := range perCPUValues {
					totalPackets += cpuValue.Packets
				}
				dirTotal += totalPackets
			}

			key := MetricsKey{Dir: dir, Reason: reason}
			metrics[key] = dirTotal
		}
	}

	return metrics
}

func verifyMetrics(t *testing.T, oldMetrics, actual, expected map[MetricsKey]uint64) {
	for metricKey, expectedValue := range expected {
		if actualValue, exists := actual[metricKey]; !exists {
			t.Errorf("Expected metric {Dir: %d, Reason: %d} to be %d, but metric key not found",
				metricKey.Dir, metricKey.Reason, expectedValue)
		} else {
			oldValue := oldMetrics[metricKey]
			deltaValue := actualValue - oldValue
			if deltaValue != expectedValue {
				t.Errorf("Metric {Dir: %d, Reason: %d} expected delta %d, got %d (old: %d, new: %d)",
					metricKey.Dir, metricKey.Reason, expectedValue, deltaValue, oldValue, actualValue)
			}
		}
	}
}

func verifyXORObfuscation(t *testing.T, inputPacket, outputPacket, key []byte) {
	if len(inputPacket) < 42 || len(outputPacket) < 42 {
		t.Logf("Packets too small for payload comparison")
		return
	}

	inputPayload := inputPacket[42:]
	outputPayload := outputPacket[42:]

	xorLen := 16
	if xorLen > len(inputPayload) {
		xorLen = len(inputPayload)
	}

	for i := 0; i < xorLen; i++ {
		expected := inputPayload[i] ^ key[i%len(key)]
		if outputPayload[i] != expected {
			t.Errorf("XOR obfuscation mismatch at byte %d: expected %02x, got %02x", i, expected, outputPayload[i])
		}
	}
}

func verifyPayloadUnchanged(t *testing.T, inputPacket, outputPacket []byte) {
	if len(inputPacket) < 42 || len(outputPacket) < 42 {
		return
	}

	inputPayload := inputPacket[42:]
	outputPayload := outputPacket[42:]

	minLen := len(inputPayload)
	if len(outputPayload) < minLen {
		minLen = len(outputPayload)
	}

	for i := 0; i < minLen; i++ {
		if inputPayload[i] != outputPayload[i] {
			t.Errorf("Payload unexpectedly changed at byte %d when obfuscation disabled", i)
			break
		}
	}
}
