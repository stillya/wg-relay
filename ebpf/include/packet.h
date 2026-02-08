#ifndef __PACKET_H__
#define __PACKET_H__

#include "common.h"

// Check if the IP packet is a fragment
static __always_inline __maybe_unused bool ip_is_fragment(struct iphdr *iph) {
	return (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET)) != 0;
}

#endif // __PACKET_H__
