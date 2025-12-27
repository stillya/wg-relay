#ifndef __METRICS_H__
#define __METRICS_H__

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

enum metric_dir {
    METRIC_TO_WG = 1,
    METRIC_FROM_WG
};

enum metric_reason {
    METRIC_FORWARDED = 1,
    METRIC_DROP
};

struct metrics_key {
    __u8 dir;
    __u8 reason;
    __u16 pad;
    __u32 src_addr;
};

struct metrics_value {
    __u64 packets;
    __u64 bytes;
};

// Per-CPU metrics map for high performance
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 16);
    __type(key, struct metrics_key);
    __type(value, struct metrics_value);
} metrics_map SEC(".maps");

// Legacy simple stats for NAT lookups
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

// Legacy stats keys
#define STAT_NAT_LOOKUPS_SUCCESS  2
#define STAT_NAT_LOOKUPS_FAILED   3

// Update metrics with packet count and bytes
static __always_inline void update_metrics(__u8 dir, __u8 reason, __u64 bytes, __u32 src_addr) {
    struct metrics_key key = {
        .dir = dir,
        .reason = reason,
        .pad = 0,
        .src_addr = src_addr
    };
    
    struct metrics_value *value = bpf_map_lookup_elem(&metrics_map, &key);
    if (value) {
        __sync_fetch_and_add(&value->packets, 1);
        __sync_fetch_and_add(&value->bytes, bytes);
    } else {
        struct metrics_value new_value = {
            .packets = 1,
            .bytes = bytes
        };
        bpf_map_update_elem(&metrics_map, &key, &new_value, BPF_NOEXIST);
    }
}

// Legacy increment function for simple stats
static __always_inline void increment_stat(__u32 key) {
    __u64 *count = bpf_map_lookup_elem(&stats_map, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&stats_map, &key, &initial, BPF_ANY);
    }
}

#endif // __METRICS_H__