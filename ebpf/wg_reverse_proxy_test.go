package ebpf

import (
	"testing"
)

// Reverse proxy specific constants (TC return codes)
const (
	tcActOk   = 0 // TC_ACT_OK - packet continues
	tcActShot = 2 // TC_ACT_SHOT - packet dropped
)

func TestBasicReversing(t *testing.T) {
	spec, err := LoadWgReverseProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}

	if err := spec.Variables["__cfg_xor_enabled"].Set(false); err != nil {
		t.Fatalf("Failed to set xor_enabled: %v", err)
	}
	if err := spec.Variables["__cfg_padding_enabled"].Set(false); err != nil {
		t.Fatalf("Failed to set padding_enabled: %v", err)
	}
	if err := spec.Variables["__cfg_wg_port"].Set(uint16(wgPort)); err != nil {
		t.Fatalf("Failed to set wg_port: %v", err)
	}

	objs := &WgReverseProxyObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		t.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	tests := []struct {
		name            string
		packet          []byte
		expectedResult  int
		expectedMetrics map[MetricsKey]uint64
		verifyOutput    bool
	}{
		{
			name:            "non_wg_traffic",
			packet:          createHTTPPacket("192.168.1.1", "192.168.1.2", 8080, 80),
			expectedResult:  tcActOk,
			expectedMetrics: map[MetricsKey]uint64{},
			verifyOutput:    false,
		},
		{
			name:           "wg_traffic_from_server",
			packet:         createWGPacket("192.168.1.2", "192.168.1.1", wgPort, 12345),
			expectedResult: tcActOk,
			expectedMetrics: map[MetricsKey]uint64{
				{Dir: metricFromWg, Reason: metricForwarded}: 1,
			},
			verifyOutput: true,
		},
		{
			name:           "wg_traffic_to_server",
			packet:         createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort),
			expectedResult: tcActOk,
			expectedMetrics: map[MetricsKey]uint64{
				{Dir: metricToWg, Reason: metricForwarded}: 1,
			},
			verifyOutput: true,
		},
		{
			name:            "tcp_traffic",
			packet:          createTCPPacket("192.168.1.1", "192.168.1.2", 12345, 80),
			expectedResult:  tcActOk,
			expectedMetrics: map[MetricsKey]uint64{},
			verifyOutput:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldMetrics := captureMetrics(objs.MetricsMap)

			result, outputPacket, err := objs.WgReverseProxy.Test(tt.packet)
			if err != nil {
				t.Fatalf("Failed to run program: %v", err)
			}

			if int(result) != tt.expectedResult {
				t.Errorf("Expected result %d, got %d", tt.expectedResult, result)
			}

			if tt.verifyOutput {
				verifyPayloadUnchanged(t, tt.packet, outputPacket)
			}

			currentMetrics := captureMetrics(objs.MetricsMap)
			verifyMetrics(t, oldMetrics, currentMetrics, tt.expectedMetrics)
		})
	}
}

func TestReverseProxyXORObfuscation(t *testing.T) {
	tests := []struct {
		name       string
		direction  string // "from_wg" or "to_wg"
		xorEnabled bool
		xorKey     string
	}{
		{
			name:       "xor_enabled_from_wg",
			direction:  "from_wg",
			xorEnabled: true,
			xorKey:     "test-key-1234567",
		},
		{
			name:       "xor_disabled_from_wg",
			direction:  "from_wg",
			xorEnabled: false,
			xorKey:     "test-key-1234567",
		},
		{
			name:       "xor_enabled_to_wg",
			direction:  "to_wg",
			xorEnabled: true,
			xorKey:     "test-key-1234567",
		},
		{
			name:       "xor_disabled_to_wg",
			direction:  "to_wg",
			xorEnabled: false,
			xorKey:     "test-key-1234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := LoadWgReverseProxy()
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
			if err := spec.Variables["__cfg_padding_enabled"].Set(false); err != nil {
				t.Fatalf("Failed to set padding_enabled: %v", err)
			}
			if err := spec.Variables["__cfg_wg_port"].Set(uint16(wgPort)); err != nil {
				t.Fatalf("Failed to set wg_port: %v", err)
			}

			objs := &WgReverseProxyObjects{}
			if err := spec.LoadAndAssign(objs, nil); err != nil {
				t.Fatalf("Failed to load objects: %v", err)
			}
			defer objs.Close()

			var inputPacket []byte
			if tt.direction == "from_wg" {
				// FROM_WG: packet from WG server to client - should be obfuscated
				inputPacket = createWGPacket("192.168.1.2", "192.168.1.1", wgPort, 12345)
			} else {
				// TO_WG: packet from client to WG server - should be deobfuscated
				// Create a pre-obfuscated packet for deobfuscation testing
				inputPacket = createObfuscatedWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort, keyBytes)
			}

			_, outputPacket, err := objs.WgReverseProxy.Test(inputPacket)
			if err != nil {
				t.Fatalf("Failed to run program: %v", err)
			}

			if tt.direction == "from_wg" {
				// FROM_WG: verify obfuscation was applied
				if tt.xorEnabled {
					verifyXORObfuscation(t, inputPacket, outputPacket, keyBytes)
				} else {
					verifyPayloadUnchanged(t, inputPacket, outputPacket)
				}
			} else {
				// TO_WG: verify deobfuscation was applied
				if tt.xorEnabled {
					verifyXORDeobfuscation(t, inputPacket, outputPacket, keyBytes)
				} else {
					verifyPayloadUnchanged(t, inputPacket, outputPacket)
				}
			}
		})
	}
}

func TestReverseProxyPaddingObfuscation(t *testing.T) {
	tests := []struct {
		name           string
		direction      string // "from_wg" or "to_wg"
		paddingEnabled bool
		paddingSize    uint8
	}{
		{
			name:           "padding_enabled_from_wg",
			direction:      "from_wg",
			paddingEnabled: true,
			paddingSize:    64,
		},
		{
			name:           "padding_disabled_from_wg",
			direction:      "from_wg",
			paddingEnabled: false,
			paddingSize:    32,
		},
		{
			name:           "padding_enabled_to_wg",
			direction:      "to_wg",
			paddingEnabled: true,
			paddingSize:    64,
		},
		{
			name:           "padding_disabled_to_wg",
			direction:      "to_wg",
			paddingEnabled: false,
			paddingSize:    32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := LoadWgReverseProxy()
			if err != nil {
				t.Fatalf("Failed to load spec: %v", err)
			}

			if err := spec.Variables["__cfg_xor_enabled"].Set(false); err != nil {
				t.Fatalf("Failed to set xor_enabled: %v", err)
			}
			if err := spec.Variables["__cfg_padding_enabled"].Set(tt.paddingEnabled); err != nil {
				t.Fatalf("Failed to set padding_enabled: %v", err)
			}
			if err := spec.Variables["__cfg_padding_size"].Set(tt.paddingSize); err != nil {
				t.Fatalf("Failed to set padding_size: %v", err)
			}
			if err := spec.Variables["__cfg_wg_port"].Set(uint16(wgPort)); err != nil {
				t.Fatalf("Failed to set wg_port: %v", err)
			}

			objs := &WgReverseProxyObjects{}
			if err := spec.LoadAndAssign(objs, nil); err != nil {
				t.Fatalf("Failed to load objects: %v", err)
			}
			defer objs.Close()

			var inputPacket []byte
			if tt.direction == "from_wg" {
				// FROM_WG: packet from WG server to client - should add padding
				inputPacket = createWGPacket("192.168.1.2", "192.168.1.1", wgPort, 12345)
			} else {
				// TO_WG: packet from client to WG server - should remove padding
				// Create a pre-padded packet for deobfuscation testing
				inputPacket = createPaddedWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort, tt.paddingSize)
			}

			_, outputPacket, err := objs.WgReverseProxy.Test(inputPacket)
			if err != nil {
				t.Fatalf("Failed to run program: %v", err)
			}

			if tt.direction == "from_wg" {
				// FROM_WG: verify padding was added
				if tt.paddingEnabled {
					verifyPaddingObfuscation(t, inputPacket, outputPacket, tt.paddingSize)
				} else {
					if len(outputPacket) != len(inputPacket) {
						t.Errorf("Packet length changed when padding disabled: input %d, output %d",
							len(inputPacket), len(outputPacket))
					}
				}
			} else {
				// TO_WG: verify padding was removed
				if tt.paddingEnabled {
					verifyPaddingDeobfuscation(t, inputPacket, outputPacket, tt.paddingSize)
				} else {
					if len(outputPacket) != len(inputPacket) {
						t.Errorf("Packet length changed when padding disabled: input %d, output %d",
							len(inputPacket), len(outputPacket))
					}
				}
			}
		})
	}
}

func TestReverseProxyCombinedObfuscation(t *testing.T) {
	tests := []struct {
		name        string
		direction   string
		paddingSize uint8
		xorKey      string
	}{
		{
			name:        "combined_from_wg",
			direction:   "from_wg",
			paddingSize: 32,
			xorKey:      "test-key-1234567",
		},
		{
			name:        "combined_to_wg",
			direction:   "to_wg",
			paddingSize: 32,
			xorKey:      "test-key-1234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := LoadWgReverseProxy()
			if err != nil {
				t.Fatalf("Failed to load spec: %v", err)
			}

			keyBytes := []byte(tt.xorKey)
			var keyArray [32]byte
			copy(keyArray[:], keyBytes)

			if err := spec.Variables["__cfg_xor_enabled"].Set(true); err != nil {
				t.Fatalf("Failed to set xor_enabled: %v", err)
			}
			if err := spec.Variables["__cfg_xor_key"].Set(keyArray); err != nil {
				t.Fatalf("Failed to set xor_key: %v", err)
			}
			if err := spec.Variables["__cfg_padding_enabled"].Set(true); err != nil {
				t.Fatalf("Failed to set padding_enabled: %v", err)
			}
			if err := spec.Variables["__cfg_padding_size"].Set(tt.paddingSize); err != nil {
				t.Fatalf("Failed to set padding_size: %v", err)
			}
			if err := spec.Variables["__cfg_wg_port"].Set(uint16(wgPort)); err != nil {
				t.Fatalf("Failed to set wg_port: %v", err)
			}

			objs := &WgReverseProxyObjects{}
			if err := spec.LoadAndAssign(objs, nil); err != nil {
				t.Fatalf("Failed to load objects: %v", err)
			}
			defer objs.Close()

			var inputPacket []byte
			if tt.direction == "from_wg" {
				// FROM_WG: packet from WG server to client - should obfuscate (XOR then padding)
				inputPacket = createWGPacket("192.168.1.2", "192.168.1.1", wgPort, 12345)
			} else {
				// TO_WG: packet from client to WG server - should deobfuscate
				// Create a packet that has been obfuscated (XOR'd and padded)
				inputPacket = createObfuscatedAndPaddedWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort, keyBytes, tt.paddingSize)
			}

			_, outputPacket, err := objs.WgReverseProxy.Test(inputPacket)
			if err != nil {
				t.Fatalf("Failed to run program: %v", err)
			}

			if tt.direction == "from_wg" {
				// FROM_WG: verify both XOR and padding were applied
				verifyPaddingObfuscation(t, inputPacket, outputPacket, tt.paddingSize)
				verifyXORObfuscation(t, inputPacket, outputPacket, keyBytes)
			} else {
				// TO_WG: verify both padding removal and XOR deobfuscation
				verifyPaddingDeobfuscation(t, inputPacket, outputPacket, tt.paddingSize)
				// After removing padding and XORing back, the payload should match original
				originalPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)
				verifyPayloadUnchanged(t, originalPacket, outputPacket)
			}
		})
	}
}

// createObfuscatedAndPaddedWGPacket creates a WireGuard packet with XOR and padding applied
// This simulates what a forward proxy would send that needs to be deobfuscated
func createObfuscatedAndPaddedWGPacket(srcIP, dstIP string, srcPort, dstPort uint16, xorKey []byte, paddingSize uint8) []byte {
	// Start with a base packet, XOR it, then add padding
	packet := createWGPacket(srcIP, dstIP, srcPort, dstPort)

	// XOR the payload (first 16 bytes after headers)
	if len(packet) > 42 && len(xorKey) > 0 {
		payload := packet[42:]
		xorLen := 16
		if xorLen > len(payload) {
			xorLen = len(payload)
		}
		for i := 0; i < xorLen; i++ {
			payload[i] ^= xorKey[i%len(xorKey)]
		}
	}

	// Add padding bytes
	padding := make([]byte, paddingSize)
	padding[paddingSize-1] = paddingSize
	packet = append(packet, padding...)

	return packet
}
