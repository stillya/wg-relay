package ebpf

import (
	"testing"

	"github.com/stillya/wg-relay/pkg/dataplane/config"
	"github.com/stillya/wg-relay/pkg/utils"
)

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
		expectedMetrics map[MetricsKey]MetricsValue
		verifyOutput    bool
	}{
		{
			name:            "non_wg_traffic",
			packet:          createHTTPPacket("192.168.1.1", "192.168.1.2", 8080, 80),
			expectedResult:  xdpPass,
			expectedMetrics: map[MetricsKey]MetricsValue{},
			verifyOutput:    false,
		},
		{
			name:           "wg_traffic_to_server",
			packet:         createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort),
			expectedResult: xdpRedirect,
			expectedMetrics: map[MetricsKey]MetricsValue{
				{BackendIndex: 0, Direction: metricDownstream}: {RxPackets: 1, RxBytes: 74},
				{BackendIndex: 0, Direction: metricUpstream}:   {TxPackets: 1, TxBytes: 74},
			},
			verifyOutput: true,
		},
		{
			name:            "wg_reverse_traffic_no_nat",
			packet:          createWGPacket("192.168.1.2", "192.168.1.1", wgPort, 12345),
			expectedResult:  xdpPass,
			expectedMetrics: map[MetricsKey]MetricsValue{},
			verifyOutput:    false,
		},
		{
			name:            "tcp_traffic",
			packet:          createTCPPacket("192.168.1.1", "192.168.1.2", 12345, 80),
			expectedResult:  xdpPass,
			expectedMetrics: map[MetricsKey]MetricsValue{},
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
	xorKey := "test-key-1234567890abcdef12345678"

	tests := []struct {
		name       string
		xorEnabled bool
		xorKey     string
	}{
		{
			name:       "xor_enabled",
			xorEnabled: true,
			xorKey:     xorKey,
		},
		{
			name:       "xor_disabled",
			xorEnabled: false,
			xorKey:     xorKey,
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

	xorKey := "test-key-1234567890abcdef12345678"
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

func TestDownstreamUpstreamMetrics(t *testing.T) {
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

	oldMetrics := captureMetrics(objs.MetricsMap)

	toWgPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)
	result, toWgOutput, err := objs.WgForwardProxy.Test(toWgPacket)
	if err != nil {
		t.Fatalf("Failed to run TO_WG: %v", err)
	}
	if int(result) != xdpRedirect {
		t.Errorf("TO_WG: Expected XDP_REDIRECT, got %d", result)
	}
	verifyPacket(t, toWgOutput, "10.0.0.1", 51820)

	info, _ := parseUDPPacket(toWgOutput)
	fromWgPacket := createWGPacket("10.0.0.1", "192.168.1.2", 51820, info.srcPort)
	result, fromWgOutput, err := objs.WgForwardProxy.Test(fromWgPacket)
	if err != nil {
		t.Fatalf("Failed to run FROM_WG: %v", err)
	}
	if int(result) != xdpRedirect {
		t.Errorf("FROM_WG: Expected XDP_REDIRECT, got %d", result)
	}
	verifyPacket(t, fromWgOutput, "192.168.1.1", 12345)

	currentMetrics := captureMetrics(objs.MetricsMap)

	pktLen := uint64(len(toWgPacket))
	expectedMetrics := map[MetricsKey]MetricsValue{
		{BackendIndex: 0, Direction: metricDownstream}: {RxPackets: 1, TxPackets: 1, RxBytes: pktLen, TxBytes: pktLen},
		{BackendIndex: 0, Direction: metricUpstream}:   {RxPackets: 1, TxPackets: 1, RxBytes: pktLen, TxBytes: pktLen},
	}
	verifyMetrics(t, oldMetrics, currentMetrics, expectedMetrics)
}

// TestPaddingDeobfuscateMalformedDrop verifies that malformed padded packets arriving
// from the WG server (FROM_WG path) are dropped instead of passed through.
// A malformed packet has a padding_size marker larger than the actual packet length.
func TestPaddingDeobfuscateMalformedDrop(t *testing.T) {
	spec, err := LoadWgForwardProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}

	if err := spec.Variables["__cfg_xor_enabled"].Set(false); err != nil {
		t.Fatalf("Failed to set xor_enabled: %v", err)
	}
	if err := spec.Variables["__cfg_padding_enabled"].Set(true); err != nil {
		t.Fatalf("Failed to set padding_enabled: %v", err)
	}
	if err := spec.Variables["__cfg_padding_size"].Set(uint8(32)); err != nil {
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

	// Establish a NAT connection by sending a TO_WG packet first.
	toWgPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)
	_, outputPacket, err := objs.WgForwardProxy.Test(toWgPacket)
	if err != nil {
		t.Fatalf("Failed to run TO_WG packet: %v", err)
	}

	natInfo, err := parseUDPPacket(outputPacket)
	if err != nil || natInfo == nil {
		t.Fatalf("Failed to parse TO_WG output: %v", err)
	}

	// Now send a malformed FROM_WG packet with a claimed padding_size of 200
	// but only 1 byte of actual padding appended. pkt_len <= padding_size → INSTR_ERROR → XDP_DROP.
	malformedPacket := createMalformedPaddedWGPacket("10.0.0.1", "192.168.1.2", 51820, natInfo.srcPort, 200)

	result, _, err := objs.WgForwardProxy.Test(malformedPacket)
	if err != nil {
		t.Fatalf("Failed to run FROM_WG malformed packet: %v", err)
	}

	const xdpDrop = 1
	if int(result) != xdpDrop {
		t.Errorf("Expected malformed padded packet to be dropped (XDP_DROP=%d), got %d", xdpDrop, result)
	}
}

// verifyPacket is a forward-proxy specific wrapper that uses the shared verifyPacketDestination
func verifyPacket(t *testing.T, outputPacket []byte, expectedIP string, expectedPort int) {
	t.Helper()
	verifyPacketDestination(t, outputPacket, expectedIP, uint16(expectedPort)) //nolint:gosec // G115: it's fine
}

// TestPaddingObfuscateMTUExceededDrop verifies that a packet is dropped when adding padding
// would cause it to exceed the configured link MTU.
func TestPaddingObfuscateMTUExceededDrop(t *testing.T) {
	spec, err := LoadWgForwardProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}

	if spec.Variables["__cfg_link_mtu"] == nil {
		t.Skip("__cfg_link_mtu variable not present in compiled eBPF object; recompile after updating padding.h")
	}

	if err := spec.Variables["__cfg_xor_enabled"].Set(false); err != nil {
		t.Fatalf("Failed to set xor_enabled: %v", err)
	}
	if err := spec.Variables["__cfg_padding_enabled"].Set(true); err != nil {
		t.Fatalf("Failed to set padding_enabled: %v", err)
	}
	if err := spec.Variables["__cfg_padding_size"].Set(uint8(64)); err != nil {
		t.Fatalf("Failed to set padding_size: %v", err)
	}
	if err := spec.Variables["__cfg_wg_port"].Set(uint16(wgPort)); err != nil {
		t.Fatalf("Failed to set wg_port: %v", err)
	}
	// Set MTU small enough that adding 64 bytes of padding would exceed it.
	// A WG packet is 74 bytes total (14 Eth + 60 IP/UDP/payload).
	// The MTU check compares IP-layer size: (74 - 14) + 64 = 110 > 100.
	if err := spec.Variables["__cfg_link_mtu"].Set(uint16(100)); err != nil {
		t.Fatalf("Failed to set link_mtu: %v", err)
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

	// This packet is 74 bytes. With 64 bytes padding it would be 138, exceeding MTU of 100.
	inputPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)

	result, _, err := objs.WgForwardProxy.Test(inputPacket)
	if err != nil {
		t.Fatalf("Failed to run program: %v", err)
	}

	const xdpDrop = 1
	if int(result) != xdpDrop {
		t.Errorf("Expected packet to be dropped (XDP_DROP=%d) when padding exceeds MTU, got %d", xdpDrop, result)
	}
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
