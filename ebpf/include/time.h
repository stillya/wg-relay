#ifndef __TIME_H__
#define __TIME_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common.h"

#define NSEC_PER_SEC 1000000000ULL

// CLOCK_MONOTONIC in nanoseconds; the Go side must read the same clock (pkg/maps/timestamp).
static __always_inline __maybe_unused __u64 bpf_mono_now(void) {
	return bpf_ktime_get_ns();
}

#endif // __TIME_H__
