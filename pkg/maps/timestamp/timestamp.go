package timestamp

import (
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// MonoNow returns CLOCK_MONOTONIC in nanoseconds, the clock of bpf_mono_now() in ebpf/include/time.h.
func MonoNow() (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, errors.Wrap(err, "failed to read CLOCK_MONOTONIC")
	}
	return uint64(ts.Nano()), nil //nolint:gosec // CLOCK_MONOTONIC is never negative
}
