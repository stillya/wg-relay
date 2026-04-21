package linux

import (
	"os"

	"github.com/pkg/errors"
)

// EnableIPForwarding sets the kernel sysctl knobs required for packet forwarding.
func EnableIPForwarding() error {
	sysctls := []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv4/conf/all/forwarding",
		"/proc/sys/net/ipv6/conf/all/forwarding",
	}
	for _, path := range sysctls {
		if err := os.WriteFile(path, []byte("1"), 0o600); err != nil {
			return errors.Wrapf(err, "failed to set %s", path)
		}
	}

	return nil
}
