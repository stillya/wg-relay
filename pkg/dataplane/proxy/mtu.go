package proxy

import (
	"math"
	"net"

	"github.com/pkg/errors"
)

// detectMinMTU returns the minimum MTU across the given interface names.
func detectMinMTU(interfaces []string) (uint16, error) {
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
