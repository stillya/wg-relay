package ebpf

import (
	"encoding/binary"
	"net"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stillya/wg-relay/pkg/utils"
)

// Shared constants for both forward and reverse proxy tests
const (
	wgPort = 51820

	metricToWg      = 1
	metricFromWg    = 2
	metricForwarded = 1
	metricDrop      = 2
)

// MetricsKey represents the key structure for eBPF metrics map
type MetricsKey struct {
	Dir     uint8
	Reason  uint8
	Pad     uint16
	SrcAddr uint32
}

// MetricsValue represents the value structure for eBPF metrics map
type MetricsValue struct {
	Packets uint64
	Bytes   uint64
}

// packetInfo holds parsed packet information
type packetInfo struct {
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPort uint16
}

// createWGPacket creates a WireGuard UDP packet for testing
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

	// WireGuard payload (24 bytes)
	wgPayload := []byte{0x01, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x01, 0x00,
		0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	packet = append(packet, wgPayload...)

	return packet
}

// createTCPPacket creates a TCP packet for testing
func createTCPPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
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

// createHTTPPacket creates an HTTP-like TCP packet for testing (alias for createTCPPacket)
func createHTTPPacket(srcIP, dstIP string, srcPort, dstPort uint16) []byte {
	return createTCPPacket(srcIP, dstIP, srcPort, dstPort)
}

// createObfuscatedWGPacket creates a WireGuard packet with XOR-obfuscated payload
func createObfuscatedWGPacket(srcIP, dstIP string, srcPort, dstPort uint16, xorKey []byte) []byte {
	packet := createWGPacket(srcIP, dstIP, srcPort, dstPort)

	// XOR the payload (starting at byte 42 after eth+ip+udp headers)
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

	return packet
}

// createPaddedWGPacket creates a WireGuard packet with padding appended
func createPaddedWGPacket(srcIP, dstIP string, srcPort, dstPort uint16, paddingSize uint8) []byte {
	packet := createWGPacket(srcIP, dstIP, srcPort, dstPort)

	// Add padding bytes
	padding := make([]byte, paddingSize)
	// Fill padding with zeros, last byte is the size marker
	padding[paddingSize-1] = paddingSize
	packet = append(packet, padding...)

	return packet
}

// parseUDPPacket extracts packet information from a raw packet
func parseUDPPacket(packet []byte) (*packetInfo, error) {
	if len(packet) < 42 {
		return nil, nil
	}

	// Check if it's IP protocol (ETH_P_IP = 0x0800)
	if binary.BigEndian.Uint16(packet[12:14]) != 0x0800 {
		return nil, nil
	}

	// Check if it's UDP protocol (17)
	if packet[23] != 17 {
		return nil, nil
	}

	// Parse IPs in little-endian format
	srcIPBytes := packet[26:30]
	dstIPBytes := packet[30:34]

	info := &packetInfo{
		srcIP:   net.IPv4(srcIPBytes[3], srcIPBytes[2], srcIPBytes[1], srcIPBytes[0]).String(),
		dstIP:   net.IPv4(dstIPBytes[3], dstIPBytes[2], dstIPBytes[1], dstIPBytes[0]).String(),
		srcPort: binary.BigEndian.Uint16(packet[34:36]),
		dstPort: binary.BigEndian.Uint16(packet[36:38]),
	}

	return info, nil
}

// captureMetrics captures current metrics from an eBPF metrics map
func captureMetrics(metricsMap *ebpf.Map) map[MetricsKey]uint64 {
	metrics := make(map[MetricsKey]uint64)

	directions := []uint8{metricToWg, metricFromWg}
	reasons := []uint8{metricForwarded, metricDrop}

	firstAddr, _ := utils.IPToUint32("192.168.1.1")
	secondAddr, _ := utils.IPToUint32("192.168.1.2")
	srcAddrs := []uint32{
		firstAddr,
		secondAddr,
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

// verifyMetrics compares actual metrics against expected values
func verifyMetrics(t *testing.T, oldMetrics, actual, expected map[MetricsKey]uint64) {
	t.Helper()
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

// verifyPacketDestination verifies the destination IP and port of a packet
func verifyPacketDestination(t *testing.T, packet []byte, expectedIP string, expectedPort uint16) {
	t.Helper()
	info, err := parseUDPPacket(packet)
	if err != nil {
		t.Fatalf("Failed to parse UDP packet: %v", err)
	}
	if info == nil {
		t.Fatal("Output packet is not a UDP packet")
	}

	if info.dstIP != expectedIP {
		t.Errorf("Expected destination IP %s, got %s", expectedIP, info.dstIP)
	}
	if info.dstPort != expectedPort {
		t.Errorf("Expected destination port %d, got %d", expectedPort, info.dstPort)
	}
}

// verifyPayloadUnchanged verifies that the payload was not modified
func verifyPayloadUnchanged(t *testing.T, inputPacket, outputPacket []byte) {
	t.Helper()
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

// verifyXORObfuscation verifies that the payload was XOR-obfuscated correctly
func verifyXORObfuscation(t *testing.T, inputPacket, outputPacket, key []byte) {
	t.Helper()
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

// verifyXORDeobfuscation verifies that an XOR-obfuscated payload was correctly deobfuscated
func verifyXORDeobfuscation(t *testing.T, obfuscatedInput, output, key []byte) {
	t.Helper()
	if len(obfuscatedInput) < 42 || len(output) < 42 {
		t.Logf("Packets too small for payload comparison")
		return
	}

	obfuscatedPayload := obfuscatedInput[42:]
	outputPayload := output[42:]

	xorLen := 16
	if xorLen > len(obfuscatedPayload) {
		xorLen = len(obfuscatedPayload)
	}

	// After deobfuscation, the output should be the original (obfuscated XOR key = original)
	for i := 0; i < xorLen; i++ {
		expected := obfuscatedPayload[i] ^ key[i%len(key)]
		if outputPayload[i] != expected {
			t.Errorf("XOR deobfuscation mismatch at byte %d: expected %02x, got %02x", i, expected, outputPayload[i])
		}
	}
}

// verifyPaddingObfuscation verifies that padding was added correctly
func verifyPaddingObfuscation(t *testing.T, inputPacket, outputPacket []byte, paddingSize uint8) {
	t.Helper()
	t.Logf("Input packet length: %d, Output packet length: %d, Expected padding size: %d",
		len(inputPacket), len(outputPacket), paddingSize)

	expectedLen := len(inputPacket) + int(paddingSize)
	if len(outputPacket) != expectedLen {
		t.Errorf("Expected output packet length %d, got %d", expectedLen, len(outputPacket))
		return
	}

	sizeMarker := outputPacket[len(outputPacket)-1]
	if sizeMarker != paddingSize {
		t.Errorf("Expected size marker %d at position %d, got %d", paddingSize, len(outputPacket)-1, sizeMarker)
	}
}

// verifyPaddingDeobfuscation verifies that padding was removed correctly
func verifyPaddingDeobfuscation(t *testing.T, paddedInput, output []byte, paddingSize uint8) {
	t.Helper()
	t.Logf("Padded input length: %d, Output length: %d, Expected padding size: %d",
		len(paddedInput), len(output), paddingSize)

	expectedLen := len(paddedInput) - int(paddingSize)
	if len(output) != expectedLen {
		t.Errorf("Expected output packet length %d, got %d", expectedLen, len(output))
	}
}
