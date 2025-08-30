#ifndef __NAT_H__
#define __NAT_H__

#include <linux/types.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

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
};

// Reverse lookup key for return traffic
struct nat_key {
    __u32 server_ip;
    __u32 nat_port;
};

static __always_inline void swap_eth(struct ethhdr* eth) {
    __u8 tmp[ETH_ALEN];
    memcpy(&tmp, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, &tmp, ETH_ALEN);
}

static __always_inline __u64 get_timestamp() {
    return bpf_ktime_get_ns();
}

#endif // __NAT_H__