#ifndef __METRICS_H__
#define __METRICS_H__

#include <linux/types.h>
#include <bpf/bpf_helpers.h>

// Metrics keys
#define STAT_TO_WG_PACKETS        0
#define STAT_FROM_WG_PACKETS      1
#define STAT_NAT_LOOKUPS_SUCCESS  2
#define STAT_NAT_LOOKUPS_FAILED   3

// Statistics map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

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