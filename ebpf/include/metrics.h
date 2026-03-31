#ifndef __METRICS_H__
#define __METRICS_H__

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

#define METRICS_MAP_SIZE 65536

enum metric_direction { METRIC_DOWNSTREAM = 0, METRIC_UPSTREAM = 1 };
enum metric_reason { METRIC_REASON_FORWARDED = 0, METRIC_REASON_DROPPED = 1 };

struct metrics_key {
	__u8 backend_index;
	__u8 direction;
	__u8 reason;
	__u8 pad;
	__u32 pad2;
};

struct metrics_value {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
};

// Per-CPU metrics map for high performance
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, METRICS_MAP_SIZE);
	__type(key, struct metrics_key);
	__type(value, struct metrics_value);
} metrics_map SEC(".maps");

// Update metrics with packet count and bytes
// direction: 0=downstream (client->proxy), 1=upstream (proxy->backend)
// rx: 1 for rx (incoming), 0 for tx (outgoing)
// reason: 0=forwarded, 1=dropped
static __always_inline __maybe_unused void update_metrics(__u8 backend_index, __u8 direction, __u64 bytes, __u8 rx,
							  __u8 reason) {
	struct metrics_key key = {
		.backend_index = backend_index, .direction = direction, .reason = reason, .pad = 0, .pad2 = 0
	};

	struct metrics_value *value = bpf_map_lookup_elem(&metrics_map, &key);
	if (value) {
		if (rx) {
			value->rx_packets += 1;
			value->rx_bytes += bytes;
		} else {
			value->tx_packets += 1;
			value->tx_bytes += bytes;
		}
	} else {
		struct metrics_value new_value = { 0 };
		if (rx) {
			new_value.rx_packets = 1;
			new_value.rx_bytes = bytes;
		} else {
			new_value.tx_packets = 1;
			new_value.tx_bytes = bytes;
		}
		bpf_map_update_elem(&metrics_map, &key, &new_value, BPF_ANY);
	}
}

#endif // __METRICS_H__
