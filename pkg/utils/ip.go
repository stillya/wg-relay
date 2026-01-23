package utils

import (
	"net"

	"github.com/pkg/errors"
)

// IpToUint32 converts an IP string to uint32 in network byte order
func IpToUint32(ipStr string) (uint32, error) {
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
