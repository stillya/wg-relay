package ebpf

import (
	"testing"

	"github.com/stillya/wg-relay/pkg/dataplane/config"
	"github.com/stillya/wg-relay/pkg/utils"
)

// Forward proxy specific constants
const (
	xdpPass     = 2
	xdpRedirect = 4 // fib_lookup redirects to default gateway
)

func TestBasicForwarding(t *testing.T) {
	spec, err := LoadWgForwardProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}

	if err := spec.Variables["__cfg_xor_enabled"].Set(false); err != nil {
		t.Fatalf("Failed to set xor_enabled: %v", err)
	}
	if err := spec.Variables["__cfg_wg_port"].Set(uint16(wgPort)); err != nil {
		t.Fatalf("Failed to set wg_port: %v", err)
	}

	objs := &WgForwardProxyObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		t.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	if err := configureBackends(objs, []config.BackendServer{
		{IP: "10.0.0.1", Port: 51820},
	}); err != nil {
		t.Fatalf("Failed to configure backends: %v", err)
	}

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
			expectedResult:  xdpPass,
			expectedMetrics: map[MetricsKey]uint64{},
			verifyOutput:    false,
		},
		{
			name:           "wg_traffic_to_server",
			packet:         createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort),
			expectedResult: xdpRedirect,
			expectedMetrics: map[MetricsKey]uint64{
				{Dir: metricToWg, Reason: metricForwarded}: 1,
			},
			verifyOutput: true,
		},
		{
			name:           "wg_reverse_traffic_no_nat",
			packet:         createWGPacket("192.168.1.2", "192.168.1.1", wgPort, 12345),
			expectedResult: xdpPass,
			expectedMetrics: map[MetricsKey]uint64{
				{Dir: metricFromWg, Reason: metricDrop}: 1,
			},
			verifyOutput: false,
		},
		{
			name:            "tcp_traffic",
			packet:          createTCPPacket("192.168.1.1", "192.168.1.2", 12345, 80),
			expectedResult:  xdpPass,
			expectedMetrics: map[MetricsKey]uint64{},
			verifyOutput:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldMetrics := captureMetrics(objs.MetricsMap)

			result, outputPacket, err := objs.WgForwardProxy.Test(tt.packet)
			if err != nil {
				t.Fatalf("Failed to run program: %v", err)
			}

			if int(result) != tt.expectedResult {
				t.Errorf("Expected result %d, got %d", tt.expectedResult, result)
			}

			if tt.verifyOutput {
				verifyPacket(t, outputPacket, "10.0.0.1", 51820)
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
			if err := spec.Variables["__cfg_wg_port"].Set(uint16(wgPort)); err != nil {
				t.Fatalf("Failed to set wg_port: %v", err)
			}

			objs := &WgForwardProxyObjects{}
			if err := spec.LoadAndAssign(objs, nil); err != nil {
				t.Fatalf("Failed to load objects: %v", err)
			}
			defer objs.Close()

			if err := configureBackends(objs, []config.BackendServer{
				{IP: "10.0.0.1", Port: 51820},
			}); err != nil {
				t.Fatalf("Failed to configure backends: %v", err)
			}

			inputPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)
			_, outputPacket, err := objs.WgForwardProxy.Test(inputPacket)
			if err != nil {
				t.Fatalf("Failed to run program: %v", err)
			}

			verifyPacket(t, outputPacket, "10.0.0.1", 51820)

			if tt.xorEnabled {
				verifyXORObfuscation(t, inputPacket, outputPacket, keyBytes)
			} else {
				verifyPayloadUnchanged(t, inputPacket, outputPacket)
			}
		})
	}
}

func TestPaddingObfuscation(t *testing.T) {
	tests := []struct {
		name           string
		paddingEnabled bool
		paddingSize    uint8
	}{
		{
			name:           "padding_enabled",
			paddingEnabled: true,
			paddingSize:    64,
		},
		{
			name:           "padding_disabled",
			paddingEnabled: false,
			paddingSize:    32,
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
			if err := spec.Variables["__cfg_padding_enabled"].Set(tt.paddingEnabled); err != nil {
				t.Fatalf("Failed to set padding_enabled: %v", err)
			}
			if err := spec.Variables["__cfg_padding_size"].Set(tt.paddingSize); err != nil {
				t.Fatalf("Failed to set padding_size: %v", err)
			}
			if err := spec.Variables["__cfg_wg_port"].Set(uint16(wgPort)); err != nil {
				t.Fatalf("Failed to set wg_port: %v", err)
			}

			objs := &WgForwardProxyObjects{}
			if err := spec.LoadAndAssign(objs, nil); err != nil {
				t.Fatalf("Failed to load objects: %v", err)
			}
			defer objs.Close()

			if err := configureBackends(objs, []config.BackendServer{
				{IP: "10.0.0.1", Port: 51820},
			}); err != nil {
				t.Fatalf("Failed to configure backends: %v", err)
			}

			inputPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)
			_, outputPacket, err := objs.WgForwardProxy.Test(inputPacket)
			if err != nil {
				t.Fatalf("Failed to run program: %v", err)
			}

			verifyPacket(t, outputPacket, "10.0.0.1", 51820)

			if tt.paddingEnabled {
				verifyPaddingObfuscation(t, inputPacket, outputPacket, tt.paddingSize)
			} else {
				if len(outputPacket) != len(inputPacket) {
					t.Errorf("Packet length changed when padding disabled: input %d, output %d",
						len(inputPacket), len(outputPacket))
				}
			}
		})
	}
}

func TestPaddingWithXOR(t *testing.T) {
	spec, err := LoadWgForwardProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}

	xorKey := "test-key-1234567"
	keyBytes := []byte(xorKey)
	var keyArray [32]byte
	copy(keyArray[:], keyBytes)

	paddingSize := uint8(32)

	if err := spec.Variables["__cfg_xor_enabled"].Set(true); err != nil {
		t.Fatalf("Failed to set xor_enabled: %v", err)
	}
	if err := spec.Variables["__cfg_xor_key"].Set(keyArray); err != nil {
		t.Fatalf("Failed to set xor_key: %v", err)
	}
	if err := spec.Variables["__cfg_padding_enabled"].Set(true); err != nil {
		t.Fatalf("Failed to set padding_enabled: %v", err)
	}
	if err := spec.Variables["__cfg_padding_size"].Set(paddingSize); err != nil {
		t.Fatalf("Failed to set padding_size: %v", err)
	}
	if err := spec.Variables["__cfg_wg_port"].Set(uint16(wgPort)); err != nil {
		t.Fatalf("Failed to set wg_port: %v", err)
	}

	objs := &WgForwardProxyObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		t.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	if err := configureBackends(objs, []config.BackendServer{
		{IP: "10.0.0.1", Port: 51820},
	}); err != nil {
		t.Fatalf("Failed to configure backends: %v", err)
	}

	inputPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)
	_, outputPacket, err := objs.WgForwardProxy.Test(inputPacket)
	if err != nil {
		t.Fatalf("Failed to run program: %v", err)
	}

	verifyPacket(t, outputPacket, "10.0.0.1", 51820)

	verifyPaddingObfuscation(t, inputPacket, outputPacket, paddingSize)
	verifyXORObfuscation(t, inputPacket, outputPacket, keyBytes)
}

func TestMultipleBackends(t *testing.T) {
	spec, err := LoadWgForwardProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}

	if err := spec.Variables["__cfg_xor_enabled"].Set(false); err != nil {
		t.Fatalf("Failed to set xor_enabled: %v", err)
	}
	if err := spec.Variables["__cfg_wg_port"].Set(uint16(wgPort)); err != nil {
		t.Fatalf("Failed to set wg_port: %v", err)
	}

	objs := &WgForwardProxyObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		t.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	backends := []config.BackendServer{
		{IP: "10.0.0.1", Port: 51820},
		{IP: "10.0.0.2", Port: 51821},
		{IP: "10.0.0.3", Port: 51822},
	}
	if err := configureBackends(objs, backends); err != nil {
		t.Fatalf("Failed to configure backends: %v", err)
	}

	packet := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)
	result, outputPacket, err := objs.WgForwardProxy.Test(packet)
	if err != nil {
		t.Fatalf("Failed to run program: %v", err)
	}

	if int(result) != xdpRedirect {
		t.Errorf("Expected XDP_REDIRECT, got %d", result)
	}

	info, err := parseUDPPacket(outputPacket)
	if err != nil {
		t.Fatalf("Failed to parse output packet: %v", err)
	}
	if info == nil {
		t.Fatal("Output packet is not a UDP packet")
	}

	found := false
	for _, backend := range backends {
		if info.dstIP == backend.IP && info.dstPort == backend.Port {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Output packet destination %s:%d not found in configured backends", info.dstIP, info.dstPort)
	}
}

func TestWgPortConfig(t *testing.T) {
	tests := []struct {
		name          string
		wgPort        uint16
		packetDstPort uint16
		shouldForward bool
	}{
		{
			name:          "default_port",
			wgPort:        51820,
			packetDstPort: 51820,
			shouldForward: true,
		},
		{
			name:          "wrong_port",
			wgPort:        51820,
			packetDstPort: 9999,
			shouldForward: false,
		},
		{
			name:          "custom_port",
			wgPort:        51821,
			packetDstPort: 51821,
			shouldForward: true,
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
			if err := spec.Variables["__cfg_wg_port"].Set(tt.wgPort); err != nil {
				t.Fatalf("Failed to set wg_port: %v", err)
			}

			objs := &WgForwardProxyObjects{}
			if err := spec.LoadAndAssign(objs, nil); err != nil {
				t.Fatalf("Failed to load objects: %v", err)
			}
			defer objs.Close()

			if err := configureBackends(objs, []config.BackendServer{
				{IP: "10.0.0.1", Port: 51820},
			}); err != nil {
				t.Fatalf("Failed to configure backends: %v", err)
			}

			packet := createWGPacket("192.168.1.1", "192.168.1.2", 12345, tt.packetDstPort)
			result, outputPacket, err := objs.WgForwardProxy.Test(packet)
			if err != nil {
				t.Fatalf("Failed to run program: %v", err)
			}

			if tt.shouldForward {
				if int(result) != xdpRedirect {
					t.Errorf("Expected packet to be forwarded (XDP_REDIRECT), got result %d", result)
				}
				verifyPacket(t, outputPacket, "10.0.0.1", 51820)
			} else {
				if int(result) != xdpPass {
					t.Errorf("Expected packet to pass through (XDP_PASS), got result %d", result)
				}
			}
		})
	}
}

// verifyPacket is a forward-proxy specific wrapper that uses the shared verifyPacketDestination
func verifyPacket(t *testing.T, outputPacket []byte, expectedIP string, expectedPort int) {
	t.Helper()
	verifyPacketDestination(t, outputPacket, expectedIP, uint16(expectedPort)) //nolint:gosec // G115: it's fine
}

// configureBackends configures backend servers for the forward proxy
func configureBackends(objs *WgForwardProxyObjects, backends []config.BackendServer) error {
	for i, backend := range backends {
		ip, err := utils.IPToUint32(backend.IP)
		if err != nil {
			return err
		}
		entry := &WgForwardProxyBackendEntry{
			Ip:   ip,
			Port: backend.Port,
		}
		key := uint32(i) //nolint:gosec // G304: it's fine
		if err := objs.BackendMap.Put(&key, entry); err != nil {
			return err
		}
	}

	countKey := uint32(0)
	count := uint32(len(backends)) //nolint:gosec // G304: it's fine
	return objs.BackendCount.Put(&countKey, &count)
}
