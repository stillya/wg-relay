#ifndef __BACKEND_H__
#define __BACKEND_H__

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

// Maximum number of backends
#define MAX_BACKENDS 256

struct backend_entry {
	__u32 ip;
	__u16 port;
	__u16 pad;
};

// Backend map: array of backend entries
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_BACKENDS);
	__type(key, __u32);
	__type(value, struct backend_entry);
} backend_map SEC(".maps");

// Backend count: number of active backends
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} backend_count SEC(".maps");

// jhash - Jenkins hash for consistent backend selection
static __always_inline __u32 jhash_2words(__u32 a, __u32 b, __u32 initval) {
	__u32 c = initval;
	a += 0xdeadbeef;
	b += 0xdeadbeef;
	c += 2;

	c ^= b;
	c -= (b << 14) | (b >> 18);
	a ^= c;
	a -= (c << 11) | (c >> 21);
	b ^= a;
	b -= (a << 25) | (a >> 7);
	c ^= b;
	c -= (b << 16) | (b >> 16);
	a ^= c;
	a -= (c << 4) | (c >> 28);
	b ^= a;
	b -= (a << 14) | (a >> 18);
	c ^= b;
	c -= (b << 24) | (b >> 8);

	return c;
}

// Select a backend using hash-based selection
// Returns the backend index, or -1 if no backends available
static __always_inline __maybe_unused int select_backend_hash(__u32 client_ip, __u16 client_port,
							      struct backend_entry *backend) {
	__u32 key = 0;

	__u32 *count = bpf_map_lookup_elem(&backend_count, &key);
	if (!count || *count == 0) {
		return -1;
	}

	__u32 num_backends = *count;

	__u32 hash = jhash_2words(client_ip, (__u32)client_port, 0x12345678);
	__u32 idx = hash % num_backends;

	// Lookup the selected backend
	struct backend_entry *entry = bpf_map_lookup_elem(&backend_map, &idx);
	if (!entry) {
		return -1;
	}

	backend->ip = entry->ip;
	backend->port = entry->port;

	return (__s32)idx;
}

#endif // __BACKEND_H__
