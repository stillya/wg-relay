// clang-format off
//go:build ignore
//  clang-format on
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "csum.h"
#include "instrumentation/instrumentation.h"
#include "instrumentation/xor.h"
#include "instrumentation/padding.h"
#include "metrics.h"
#include "packet.h"
#include "static_config.h"

// Reverse proxy static configuration
DECLARE_CONFIG(__u16, wg_port, "WireGuard port to intercept");

static __always_inline void finalize_tc_packet(struct wg_ctx *ctx) {
	__u16 new_tot_len = (__u16)ctx->skb->len - ETH_HLEN;
	ctx->ip->tot_len  = bpf_htons(new_tot_len);
	ctx->udp->len     = bpf_htons(new_tot_len - (ctx->ip->ihl * 4));
	ctx->ip->frag_off |= bpf_htons(IP_DF);
	ctx->ip->check    = iph_csum(ctx->ip);
	ctx->udp->check   = 0;
}

// Apply obfuscation in TC mode (manual ordering)
// NOTE: Order matters! XOR first, then padding (so size marker is at end)
static __always_inline int instr_obfuscate_tc(struct wg_ctx *ctx) {
	int ret;

	ret = xor_obfuscate_tc(ctx);
	if (ret == INSTR_ERROR) {
		return INSTR_ERROR;
	}
	if (ret == INSTR_PKT_INVD) {
		if (parse_tc_packet(ctx->skb, ctx) < 0) {
			return INSTR_ERROR;
		}
	}

	ret = padding_obfuscate_tc(ctx);
	if (ret == INSTR_ERROR) {
		return INSTR_ERROR;
	}
	if (ret == INSTR_PKT_INVD) {
		if (parse_tc_packet(ctx->skb, ctx) < 0) {
			return INSTR_ERROR;
		}
	}

	return INSTR_OK;
}

// Apply deobfuscation in TC mode (reverse order)
// NOTE: Order matters! Remove padding first, then XOR
static __always_inline int instr_deobfuscate_tc(struct wg_ctx *ctx) {
	int ret;

	ret = padding_deobfuscate_tc(ctx);
	if (ret == INSTR_ERROR) {
		return INSTR_ERROR;
	}
	if (ret == INSTR_PKT_INVD) {
		if (parse_tc_packet(ctx->skb, ctx) < 0) {
			return INSTR_ERROR;
		}
	}

	ret = xor_deobfuscate_tc(ctx);
	if (ret == INSTR_ERROR) {
		return INSTR_ERROR;
	}
	if (ret == INSTR_PKT_INVD) {
		if (parse_tc_packet(ctx->skb, ctx) < 0) {
			return INSTR_ERROR;
		}
	}

	return INSTR_OK;
}

SEC("tc")
int wg_reverse_proxy(struct __sk_buff *skb) {
	struct wg_ctx ctx = {};
	if (parse_tc_packet(skb, &ctx) < 0)
		return TC_ACT_OK;

	__u16 src_port = ctx.src_port;
	__u16 dst_port = ctx.dst_port;
	__u16 wg_port = CONFIG(wg_port);
	if (dst_port != wg_port && src_port != wg_port)
		return TC_ACT_OK;

	__u8 is_to_wg = (dst_port == wg_port) ? 1 : 0;
	__u8 is_from_wg = (src_port == wg_port) ? 1 : 0;

	if (likely(is_from_wg)) {
		// FROM_WG path: wg->proxy (upstream rx), proxy->client (downstream tx)
		update_metrics(0, METRIC_UPSTREAM, skb->len, 1, METRIC_REASON_FORWARDED);

		if (instr_obfuscate_tc(&ctx) < 0) {
			DEBUG_PRINTK("Obfuscation failed, dropping packet");
			update_metrics(0, METRIC_UPSTREAM, skb->len, 1, METRIC_REASON_DROPPED);
			return TC_ACT_SHOT;
		}

		finalize_tc_packet(&ctx);
		update_metrics(0, METRIC_DOWNSTREAM, skb->len, 0, METRIC_REASON_FORWARDED);
	}

	if (unlikely(is_to_wg)) {
		// TO_WG path: client->proxy (downstream rx), proxy->wg (upstream tx)
		update_metrics(0, METRIC_DOWNSTREAM, skb->len, 1, METRIC_REASON_FORWARDED);

		if (instr_deobfuscate_tc(&ctx) < 0) {
			DEBUG_PRINTK("Deobfuscation failed, dropping packet");
			update_metrics(0, METRIC_DOWNSTREAM, skb->len, 1, METRIC_REASON_DROPPED);
			return TC_ACT_SHOT;
		}

		finalize_tc_packet(&ctx);
		update_metrics(0, METRIC_UPSTREAM, skb->len, 0, METRIC_REASON_FORWARDED);
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
