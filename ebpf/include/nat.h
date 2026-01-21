#ifndef __NAT_H__
#define __NAT_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

// NAT port generation range (50000-65535)
#define NAT_PORT_START 50000
#define NAT_PORT_RANGE 15536

// Connection tracking for NAT
struct connection_key {
	__u32 client_ip;
	__u32 client_port;
	__u32 server_ip;
	__u32 server_port;
};

struct connection_value {
	__u64 timestamp;
	__u16 nat_port;
	__u32 pad; // Padding for alignment
};

// Reverse lookup key for return traffic
struct nat_key {
	__u32 server_ip;
	__u32 nat_port;
};

// Counter for generating unique NAT ports
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} nat_port_counter SEC(".maps");

static __always_inline __maybe_unused __u16 generate_nat_port() {
	__u32 counter_key = 0;
	__u32 *counter = bpf_map_lookup_elem(&nat_port_counter, &counter_key);

	__u32 port = NAT_PORT_START;
	if (counter) {
		__sync_fetch_and_add(counter, 1);
		port = NAT_PORT_START + (*counter % NAT_PORT_RANGE);
	} else {
		__u32 initial = 1;
		bpf_map_update_elem(&nat_port_counter, &counter_key, &initial, BPF_NOEXIST);
		port = NAT_PORT_START;
	}

	return (__u16)port;
}

static __always_inline __maybe_unused void swap_eth(struct ethhdr *eth) {
	__u8 tmp[ETH_ALEN];
	memcpy(&tmp, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, &tmp, ETH_ALEN);
}

static __always_inline __maybe_unused __u64 get_timestamp() {
	return bpf_ktime_get_ns();
}

#endif // __NAT_H__
