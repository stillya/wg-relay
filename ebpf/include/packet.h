#ifndef __PACKET_H__
#define __PACKET_H__

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

#ifndef AF_INET
#define AF_INET 2
#endif

// Check if the IP packet is a fragment
static __always_inline __maybe_unused bool ip_is_fragment(struct iphdr *iph) {
	return (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) != 0;
}

static __always_inline __maybe_unused void swap_eth(struct ethhdr *eth) {
	__u8 tmp[ETH_ALEN];
	memcpy(&tmp, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, &tmp, ETH_ALEN);
}

#endif // __PACKET_H__
