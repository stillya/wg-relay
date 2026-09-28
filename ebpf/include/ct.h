#ifndef __CT_H__
#define __CT_H__

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "common.h"
#include "time.h"

#define CT_PORT_MIN	 50000
#define CT_PORT_MAX	 65535
#define CT_ALLOC_RETRIES 8
#define CT_REFRESH_NS	 NSEC_PER_SEC
#define CT_MAP_SIZE	 65536

// Addresses and ports are in network byte order, as in the packet headers.
struct ipv4_ct_tuple {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
};

struct ipv4_ct_entry {
	__u64 last_seen; // bpf_mono_now()
	__be32 to_daddr;
	__be16 to_dport;
	__be16 nat_port;
	__u8 backend_idx; // metrics label only
	__u8 pad[7];
};

// Where a new flow is NATed to; never stored in a map.
struct ipv4_ct_target {
	__be32 addr;
	__be16 port;
	__u8 backend_idx;
	__u8 pad;
};

// Client tuple {client, proxy, client_port, wg_port} -> flow state
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CT_MAP_SIZE);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ipv4_ct_entry);
} ipv4_ct_map SEC(".maps");

// Return tuple {backend, proxy, backend_port, nat_port} -> client tuple
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, CT_MAP_SIZE);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ipv4_ct_tuple);
} ipv4_ct_rev_map SEC(".maps");

static __always_inline void ct_touch(struct ipv4_ct_entry *entry) {
	__u64 now = bpf_mono_now();

	if (now - entry->last_seen >= CT_REFRESH_NS)
		entry->last_seen = now;
}

static __always_inline __maybe_unused struct ipv4_ct_entry *ct_lookup(const struct ipv4_ct_tuple *tuple) {
	struct ipv4_ct_entry *entry = bpf_map_lookup_elem(&ipv4_ct_map, tuple);

	if (entry)
		ct_touch(entry);
	return entry;
}

static __always_inline __u32 ct_clamp_port(__u32 val) {
	return CT_PORT_MIN + val % (CT_PORT_MAX - CT_PORT_MIN + 1);
}

// Reserves a NAT port with a BPF_NOEXIST reverse insert; returns it in host order, or 0 if none is free.
// wg_port is never used, since a backend reply to it would be classified as client traffic.
static __always_inline __u16 ct_alloc_port(const struct ipv4_ct_tuple *tuple, const struct ipv4_ct_target *target,
					   __u16 wg_port, struct ipv4_ct_tuple *rev_tuple) {
	__u32 port = ct_clamp_port(bpf_get_prandom_u32());

	rev_tuple->saddr = target->addr;
	rev_tuple->daddr = tuple->daddr;
	rev_tuple->sport = target->port;

#pragma unroll
	for (int i = 0; i < CT_ALLOC_RETRIES; i++) {
		if (port != wg_port) {
			rev_tuple->dport = bpf_htons((__u16)port);
			long ret = bpf_map_update_elem(&ipv4_ct_rev_map, rev_tuple, tuple, BPF_NOEXIST);
			if (ret == 0)
				return (__u16)port;
			if (ret != -EEXIST)
				return 0;
		}

		port = port >= CT_PORT_MAX ? CT_PORT_MIN : port + 1;
	}

	return 0;
}

static __always_inline __maybe_unused struct ipv4_ct_entry *
ct_lookup_or_create(const struct ipv4_ct_tuple *tuple, const struct ipv4_ct_target *target, __u16 wg_port) {
	struct ipv4_ct_entry *entry = ct_lookup(tuple);
	if (entry)
		return entry;

	struct ipv4_ct_tuple rev_tuple = { 0 };
	__u16 port = ct_alloc_port(tuple, target, wg_port, &rev_tuple);
	if (!port)
		return NULL;

	struct ipv4_ct_entry new_entry = {
		.last_seen = bpf_mono_now(),
		.to_daddr = target->addr,
		.to_dport = target->port,
		.nat_port = bpf_htons(port),
		.backend_idx = target->backend_idx,
	};

	long ret = bpf_map_update_elem(&ipv4_ct_map, tuple, &new_entry, BPF_NOEXIST);
	if (ret != 0) {
		// Release the reserved port; on -EEXIST a concurrent packet created the flow first, so use its entry.
		bpf_map_delete_elem(&ipv4_ct_rev_map, &rev_tuple);
		if (ret != -EEXIST)
			return NULL;
	}

	return bpf_map_lookup_elem(&ipv4_ct_map, tuple);
}

// A reverse entry that its flow would not derive is stale and treated as a miss.
static __always_inline __maybe_unused struct ipv4_ct_entry *ct_restore(const struct ipv4_ct_tuple *rev_tuple,
								       struct ipv4_ct_tuple *out_tuple) {
	struct ipv4_ct_tuple *tuple = bpf_map_lookup_elem(&ipv4_ct_rev_map, rev_tuple);
	if (!tuple)
		return NULL;

	*out_tuple = *tuple;

	struct ipv4_ct_entry *entry = bpf_map_lookup_elem(&ipv4_ct_map, out_tuple);
	if (!entry || entry->to_daddr != rev_tuple->saddr || entry->to_dport != rev_tuple->sport ||
	    entry->nat_port != rev_tuple->dport || out_tuple->daddr != rev_tuple->daddr)
		return NULL;

	ct_touch(entry);
	return entry;
}

#endif // __CT_H__
