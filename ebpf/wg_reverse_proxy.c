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
		if (instr_obfuscate_tc(&ctx) < 0) {
			DEBUG_PRINTK("Obfuscation failed, dropping packet");
			return TC_ACT_SHOT;
		}

		update_metrics(METRIC_FROM_WG, METRIC_FORWARDED, skb->len, bpf_ntohl(ctx.ip->daddr));
	}

	if (unlikely(is_to_wg)) {
		if (instr_deobfuscate_tc(&ctx) < 0) {
			DEBUG_PRINTK("Deobfuscation failed, dropping packet");
			return TC_ACT_SHOT;
		}

		update_metrics(METRIC_TO_WG, METRIC_FORWARDED, skb->len, bpf_ntohl(ctx.ip->saddr));
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
