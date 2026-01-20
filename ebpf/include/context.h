#ifndef __CONTEXT_H__
#define __CONTEXT_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <linux/udp.h>
#include "common.h"
#include "packet.h"

#define MAX_PAYLOAD_SIZE 1420

// WireGuard context structure combining packet info and XDP/TC context
struct wg_ctx {
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	void *payload;
	void *payload_end;
	__u32 payload_len;
	__u16 src_port;
	__u16 dst_port;
	__u8 message_type;

	union {
		struct xdp_md *xdp;
		struct __sk_buff *skb;
	};
};

// Parse XDP packet
static __always_inline __maybe_unused int parse_xdp_packet(struct xdp_md *xdp_ctx, struct wg_ctx *ctx) {
	void *data = (void *)(long)xdp_ctx->data;
	void *data_end = (void *)(long)xdp_ctx->data_end;

	ctx->xdp = xdp_ctx;

	ctx->eth = data;
	if ((void *)(ctx->eth + 1) > data_end)
		return -1;

	if (ctx->eth->h_proto != bpf_htons(ETH_P_IP))
		return -1;

	ctx->ip = (void *)(ctx->eth + 1);
	if ((void *)(ctx->ip + 1) > data_end)
		return -1;

	if (ctx->ip->protocol != IPPROTO_UDP)
		return -1;

	ctx->udp = (void *)ctx->ip + (ctx->ip->ihl * 4);
	if ((void *)(ctx->udp + 1) > data_end)
		return -1;

	if (ip_is_fragment(ctx->ip))
		return -1;

	ctx->src_port = bpf_ntohs(ctx->udp->source);
	ctx->dst_port = bpf_ntohs(ctx->udp->dest);

	ctx->payload = (void *)(ctx->udp + 1);
	if (ctx->payload > data_end)
		return -1;

	ctx->payload_end = data_end;
	ctx->payload_len = data_end - ctx->payload;
	if (ctx->payload_len > MAX_PAYLOAD_SIZE)
		ctx->payload_len = MAX_PAYLOAD_SIZE;

	// it's shitty, don't read it, just to move forward
	if (ctx->payload_len > 0 && ctx->payload + 1 <= data_end) {
		__u8 *msg_type = ctx->payload;
		ctx->message_type = *msg_type;
	} else {
		ctx->message_type = 0;
	}

	return 0;
}

// Parse TC packet
static __always_inline __maybe_unused int parse_tc_packet(struct __sk_buff *skb, struct wg_ctx *ctx) {
	if (bpf_skb_pull_data(skb, skb->len) < 0)
		return -1;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	ctx->skb = skb;

	ctx->eth = data;
	if ((void *)(ctx->eth + 1) > data_end)
		return -1;

	if (ctx->eth->h_proto != bpf_htons(ETH_P_IP))
		return -1;

	ctx->ip = (void *)(ctx->eth + 1);
	if ((void *)(ctx->ip + 1) > data_end)
		return -1;

	if (ip_is_fragment(ctx->ip))
		return -1;

	if (ctx->ip->protocol != IPPROTO_UDP)
		return -1;

	ctx->udp = (void *)ctx->ip + (ctx->ip->ihl * 4);
	if ((void *)(ctx->udp + 1) > data_end)
		return -1;

	ctx->src_port = bpf_ntohs(ctx->udp->source);
	ctx->dst_port = bpf_ntohs(ctx->udp->dest);

	ctx->payload = (void *)(ctx->udp + 1);
	if (ctx->payload > data_end)
		return -1;

	ctx->payload_end = data_end;
	ctx->payload_len = data_end - ctx->payload;
	if (ctx->payload_len > MAX_PAYLOAD_SIZE)
		ctx->payload_len = MAX_PAYLOAD_SIZE;

	// it's shitty, don't read it, just to move forward
	if (ctx->payload_len > 0 && ctx->payload + 1 <= data_end) {
		__u8 *msg_type = ctx->payload;
		ctx->message_type = *msg_type;
	} else {
		ctx->message_type = 0;
	}

	return 0;
}

#endif /* __CONTEXT_H__ */
