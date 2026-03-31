package utils

import (
	"math"
	"net"

	"github.com/pkg/errors"
)

// IPToUint32 converts an IP string to uint32 in network byte order
func IPToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, errors.Errorf("invalid IP address: %s", ipStr)
	}

	ip = ip.To4()
	if ip == nil {
		return 0, errors.Errorf("IP must be IPv4: %s", ipStr)
	}

	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3]), nil
}

// DetectMinMTU returns the minimum MTU across the given interface names.
// Returns an error if any interface cannot be found or has an invalid MTU.
func DetectMinMTU(interfaces []string) (uint16, error) {
	if len(interfaces) == 0 {
		return 0, errors.New("no interfaces specified")
	}

	minMTU := math.MaxInt32
	for _, name := range interfaces {
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return 0, errors.Wrapf(err, "failed to get interface %s", name)
		}
		if iface.MTU <= 0 {
			return 0, errors.Errorf("interface %s has invalid MTU: %d", name, iface.MTU)
		}
		if iface.MTU < minMTU {
			minMTU = iface.MTU
		}
	}

	if minMTU > math.MaxUint16 {
		minMTU = math.MaxUint16
	}

	return uint16(minMTU), nil //nolint:gosec // clamped to MaxUint16 above
}
