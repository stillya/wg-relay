#ifndef __PACKET_H__
#define __PACKET_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <linux/udp.h>
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

#endif // __PACKET_H__
