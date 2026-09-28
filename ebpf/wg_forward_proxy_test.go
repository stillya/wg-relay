package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
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

	setVar(t, spec, "__cfg_xor_enabled", false)
	setVar(t, spec, "__cfg_wg_port", uint16(wgPort))

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

			setVar(t, spec, "__cfg_xor_enabled", tt.xorEnabled)
			setVar(t, spec, "__cfg_xor_key", keyArray)
			setVar(t, spec, "__cfg_wg_port", uint16(wgPort))

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
		direction      string
		paddingEnabled bool
		paddingSize    uint8
	}{
		{"obfuscate_enabled", "to_backend", true, 64},
		{"obfuscate_disabled", "to_backend", false, 32},
		{"deobfuscate_size_64", "from_backend", true, 64},
		{"deobfuscate_size_32", "from_backend", true, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := LoadWgForwardProxy()
			if err != nil {
				t.Fatalf("Failed to load spec: %v", err)
			}

			setVar(t, spec, "__cfg_xor_enabled", false)
			setVar(t, spec, "__cfg_padding_enabled", tt.paddingEnabled)
			setVar(t, spec, "__cfg_padding_size", tt.paddingSize)
			setVar(t, spec, "__cfg_wg_port", uint16(wgPort))

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

			if tt.direction == "to_backend" {
				inputPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)
				_, outputPacket, err := objs.WgForwardProxy.Test(inputPacket)
				if err != nil {
					t.Fatalf("Failed to run program: %v", err)
				}
				verifyPacket(t, outputPacket, "10.0.0.1", 51820)
				if tt.paddingEnabled {
					verifyPaddingObfuscation(t, inputPacket, outputPacket, tt.paddingSize)
				} else if len(outputPacket) != len(inputPacket) {
					t.Errorf("Packet length changed when padding disabled: input %d, output %d",
						len(inputPacket), len(outputPacket))
				}
			} else {
				toWgPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)
				_, toWgOutput, err := objs.WgForwardProxy.Test(toWgPacket)
				if err != nil {
					t.Fatalf("Failed to run TO_WG packet: %v", err)
				}
				natInfo, err := parseUDPPacket(toWgOutput)
				if err != nil || natInfo == nil {
					t.Fatalf("Failed to parse TO_WG output: %v", err)
				}

				paddedResponse := createPaddedWGPacket("10.0.0.1", "192.168.1.2", 51820, natInfo.srcPort, tt.paddingSize)
				_, fromWgOutput, err := objs.WgForwardProxy.Test(paddedResponse)
				if err != nil {
					t.Fatalf("Failed to run FROM_WG padded packet: %v", err)
				}

				markerSize := paddedResponse[len(paddedResponse)-1]
				verifyPaddingDeobfuscation(t, paddedResponse, fromWgOutput, markerSize)
				verifyPacket(t, fromWgOutput, "192.168.1.1", 12345)
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

	setVar(t, spec, "__cfg_xor_enabled", true)
	setVar(t, spec, "__cfg_xor_key", keyArray)
	setVar(t, spec, "__cfg_padding_enabled", true)
	setVar(t, spec, "__cfg_padding_size", paddingSize)
	setVar(t, spec, "__cfg_wg_port", uint16(wgPort))

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

	setVar(t, spec, "__cfg_xor_enabled", false)
	setVar(t, spec, "__cfg_wg_port", uint16(wgPort))

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

func TestBackendCustomPort(t *testing.T) {
	spec, err := LoadWgForwardProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}

	setVar(t, spec, "__cfg_xor_enabled", false)
	setVar(t, spec, "__cfg_wg_port", uint16(wgPort))

	objs := &WgForwardProxyObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		t.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	if err := configureBackends(objs, []config.BackendServer{
		{IP: "10.0.0.1", Port: 11580},
	}); err != nil {
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

	verifyPacket(t, outputPacket, "10.0.0.1", 11580)
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

			setVar(t, spec, "__cfg_xor_enabled", false)
			setVar(t, spec, "__cfg_wg_port", tt.wgPort)

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

	setVar(t, spec, "__cfg_xor_enabled", false)
	setVar(t, spec, "__cfg_wg_port", uint16(wgPort))

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

// TestPaddingDeobfuscateMalformedDrop verifies that malformed padded packets are dropped.
func TestPaddingDeobfuscateMalformedDrop(t *testing.T) {
	spec, err := LoadWgForwardProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}

	setVar(t, spec, "__cfg_xor_enabled", false)
	setVar(t, spec, "__cfg_padding_enabled", true)
	setVar(t, spec, "__cfg_padding_size", uint8(32))
	setVar(t, spec, "__cfg_wg_port", uint16(wgPort))

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

	toWgPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)
	_, outputPacket, err := objs.WgForwardProxy.Test(toWgPacket)
	if err != nil {
		t.Fatalf("Failed to run TO_WG packet: %v", err)
	}

	natInfo, err := parseUDPPacket(outputPacket)
	if err != nil || natInfo == nil {
		t.Fatalf("Failed to parse TO_WG output: %v", err)
	}

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

func verifyPacket(t *testing.T, outputPacket []byte, expectedIP string, expectedPort int) {
	t.Helper()
	verifyPacketDestination(t, outputPacket, expectedIP, uint16(expectedPort)) //nolint:gosec // G115: it's fine
}

func TestPaddingObfuscateMTUExceededDrop(t *testing.T) {
	spec, err := LoadWgForwardProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}

	if spec.Variables["__cfg_link_mtu"] == nil {
		t.Skip("__cfg_link_mtu variable not present in compiled eBPF object; recompile after updating padding.h")
	}

	setVar(t, spec, "__cfg_xor_enabled", false)
	setVar(t, spec, "__cfg_padding_enabled", true)
	setVar(t, spec, "__cfg_padding_size", uint8(64))
	setVar(t, spec, "__cfg_wg_port", uint16(wgPort))
	setVar(t, spec, "__cfg_link_mtu", uint16(100))

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
	if err := objs.BackendCount.Put(&countKey, &count); err != nil {
		return err
	}

	dummy := uint8(1)
	for _, backend := range backends {
		port := backend.Port
		if port == 0 {
			port = wgPort
		}
		if err := objs.BackendPortSet.Put(&port, &dummy); err != nil {
			return err
		}
	}

	return nil
}

// paddingState mirrors `struct padding_state` in
// ebpf/include/instrumentation/padding.h.
type paddingState struct {
	CurrentSize uint8
	Pad         uint8
	OkStreak    uint16
	Backoffs    uint32
}

// readPaddingStates returns every per-CPU padding_state entry, flattened. Note
// that a per-CPU map zero-fills the slots of CPUs that never ran, so most
// entries will have CurrentSize == 0.
func readPaddingStates(t *testing.T, m *ebpf.Map) (states []paddingState, ncpu int) {
	t.Helper()
	var key uint32
	var vals []paddingState
	iter := m.Iterate()
	for iter.Next(&key, &vals) {
		ncpu = len(vals)
		states = append(states, vals...)
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("Failed to iterate padding state map: %v", err)
	}
	return states, ncpu
}

// firstPaddingKey returns the ifindex key of the first padding_state entry and
// the number of possible CPUs (slice width) for that map.
func firstPaddingKey(t *testing.T, m *ebpf.Map) (key uint32, ncpu int) {
	t.Helper()
	var vals []paddingState
	iter := m.Iterate()
	if !iter.Next(&key, &vals) {
		t.Fatal("padding state map is empty")
	}
	if err := iter.Err(); err != nil {
		t.Fatalf("Failed to iterate padding state map: %v", err)
	}
	return key, len(vals)
}

func maxPaddingSize(states []paddingState) uint8 {
	var maxSize uint8
	for _, s := range states {
		if s.CurrentSize > maxSize {
			maxSize = s.CurrentSize
		}
	}
	return maxSize
}

// TestPaddingAdaptiveDisabledMatchesFixed checks adaptive=false matches fixed-size padding.
func TestPaddingAdaptiveDisabledMatchesFixed(t *testing.T) {
	spec, err := LoadWgForwardProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}
	if spec.Variables["__cfg_padding_adaptive"] == nil {
		t.Skip("__cfg_padding_adaptive not present; recompile after updating padding.h")
	}

	setVar(t, spec, "__cfg_xor_enabled", false)
	setVar(t, spec, "__cfg_padding_enabled", true)
	setVar(t, spec, "__cfg_padding_size", uint8(64))
	setVar(t, spec, "__cfg_padding_adaptive", false)
	setVar(t, spec, "__cfg_wg_port", uint16(wgPort))

	objs := &WgForwardProxyObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		t.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	if err := configureBackends(objs, []config.BackendServer{{IP: "10.0.0.1", Port: 51820}}); err != nil {
		t.Fatalf("Failed to configure backends: %v", err)
	}

	inputPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)
	_, outputPacket, err := objs.WgForwardProxy.Test(inputPacket)
	if err != nil {
		t.Fatalf("Failed to run program: %v", err)
	}

	verifyPacket(t, outputPacket, "10.0.0.1", 51820)
	verifyPaddingObfuscation(t, inputPacket, outputPacket, 64)

	// No state must be created when adaptive is off.
	if states, _ := readPaddingStates(t, objs.PaddingStateMap); maxPaddingSize(states) != 0 {
		t.Errorf("Expected no padding state when adaptive disabled, got max size %d", maxPaddingSize(states))
	}
}

// TestPaddingAdaptiveStateInitialized verifies state is created at the configured size on first use.
func TestPaddingAdaptiveStateInitialized(t *testing.T) {
	spec, err := LoadWgForwardProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}
	if spec.Variables["__cfg_padding_adaptive"] == nil {
		t.Skip("__cfg_padding_adaptive not present; recompile after updating padding.h")
	}

	setVar(t, spec, "__cfg_xor_enabled", false)
	setVar(t, spec, "__cfg_padding_enabled", true)
	setVar(t, spec, "__cfg_padding_size", uint8(64))
	setVar(t, spec, "__cfg_padding_adaptive", true)
	setVar(t, spec, "__cfg_wg_port", uint16(wgPort))

	objs := &WgForwardProxyObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		t.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	if err := configureBackends(objs, []config.BackendServer{{IP: "10.0.0.1", Port: 51820}}); err != nil {
		t.Fatalf("Failed to configure backends: %v", err)
	}

	inputPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)
	_, outputPacket, err := objs.WgForwardProxy.Test(inputPacket)
	if err != nil {
		t.Fatalf("Failed to run program: %v", err)
	}

	// Under BPF_PROG_TEST_RUN frame_sz == PAGE_SIZE, so the full size fits.
	verifyPaddingObfuscation(t, inputPacket, outputPacket, 64)

	states, _ := readPaddingStates(t, objs.PaddingStateMap)
	if len(states) == 0 {
		t.Fatal("Expected an adaptive padding state entry, found none")
	}
	if got := maxPaddingSize(states); got != 64 {
		t.Errorf("Expected initialized working size 64, got %d", got)
	}
}

// TestPaddingAdaptiveHonorsWorkingCeiling verifies padding is capped at the working size, not the configured size.
func TestPaddingAdaptiveHonorsWorkingCeiling(t *testing.T) {
	spec, err := LoadWgForwardProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}
	if spec.Variables["__cfg_padding_adaptive"] == nil {
		t.Skip("__cfg_padding_adaptive not present; recompile after updating padding.h")
	}

	setVar(t, spec, "__cfg_xor_enabled", false)
	setVar(t, spec, "__cfg_padding_enabled", true)
	setVar(t, spec, "__cfg_padding_size", uint8(64))
	setVar(t, spec, "__cfg_padding_adaptive", true)
	setVar(t, spec, "__cfg_wg_port", uint16(wgPort))

	objs := &WgForwardProxyObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		t.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	if err := configureBackends(objs, []config.BackendServer{{IP: "10.0.0.1", Port: 51820}}); err != nil {
		t.Fatalf("Failed to configure backends: %v", err)
	}

	inputPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)

	// Priming packet creates the state; use it to learn the map key and CPU width.
	if _, _, err := objs.WgForwardProxy.Test(inputPacket); err != nil {
		t.Fatalf("Failed to run priming packet: %v", err)
	}
	key, ncpu := firstPaddingKey(t, objs.PaddingStateMap)

	// Force the working ceiling down to 4 on every CPU, as a real backoff would.
	forced := make([]paddingState, ncpu)
	for i := range forced {
		forced[i] = paddingState{CurrentSize: 4}
	}
	if err := objs.PaddingStateMap.Put(&key, forced); err != nil {
		t.Fatalf("Failed to force padding ceiling: %v", err)
	}

	_, outputPacket, err := objs.WgForwardProxy.Test(inputPacket)
	if err != nil {
		t.Fatalf("Failed to run capped packet: %v", err)
	}

	verifyPacket(t, outputPacket, "10.0.0.1", 51820)
	// Only 4 bytes must be added even though the configured size is 64.
	verifyPaddingObfuscation(t, inputPacket, outputPacket, 4)
}

// TestPaddingAdaptiveReseedsZeroedState verifies a zeroed working size (an
// unseeded per-CPU slot) is reseeded to the configured size, not used as-is.
func TestPaddingAdaptiveReseedsZeroedState(t *testing.T) {
	spec, err := LoadWgForwardProxy()
	if err != nil {
		t.Fatalf("Failed to load spec: %v", err)
	}
	if spec.Variables["__cfg_padding_adaptive"] == nil {
		t.Skip("__cfg_padding_adaptive not present; recompile after updating padding.h")
	}

	setVar(t, spec, "__cfg_xor_enabled", false)
	setVar(t, spec, "__cfg_padding_enabled", true)
	setVar(t, spec, "__cfg_padding_size", uint8(64))
	setVar(t, spec, "__cfg_padding_adaptive", true)
	setVar(t, spec, "__cfg_wg_port", uint16(wgPort))

	objs := &WgForwardProxyObjects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		t.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	if err := configureBackends(objs, []config.BackendServer{{IP: "10.0.0.1", Port: 51820}}); err != nil {
		t.Fatalf("Failed to configure backends: %v", err)
	}

	inputPacket := createWGPacket("192.168.1.1", "192.168.1.2", 12345, wgPort)

	// Prime to learn the map key / CPU width, then zero every CPU slot.
	if _, _, err := objs.WgForwardProxy.Test(inputPacket); err != nil {
		t.Fatalf("Failed to run priming packet: %v", err)
	}
	key, ncpu := firstPaddingKey(t, objs.PaddingStateMap)
	zeroed := make([]paddingState, ncpu) // all fields zero, incl. CurrentSize
	if err := objs.PaddingStateMap.Put(&key, zeroed); err != nil {
		t.Fatalf("Failed to zero padding state: %v", err)
	}

	_, outputPacket, err := objs.WgForwardProxy.Test(inputPacket)
	if err != nil {
		t.Fatalf("Failed to run packet against zeroed state: %v", err)
	}

	verifyPacket(t, outputPacket, "10.0.0.1", 51820)
	// Must reseed to the configured 64 and add 64 bytes — NOT 0.
	verifyPaddingObfuscation(t, inputPacket, outputPacket, 64)
}
