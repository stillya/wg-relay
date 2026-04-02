#ifndef __INSTRUMENTATION_PADDING_H__
#define __INSTRUMENTATION_PADDING_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"
#include "context.h"
#include "instrumentation.h"
#include "static_config.h"

DECLARE_CONFIG(bool, padding_enabled, "Enable padding obfuscation");
DECLARE_CONFIG(__u8, padding_size, "Padding size in bytes");
DECLARE_CONFIG(__u16, link_mtu, "Link MTU size in bytes");

static __always_inline __maybe_unused int padding_obfuscate_xdp(struct wg_ctx *ctx) {
	if (!CONFIG(padding_enabled)) {
		return INSTR_OK;
	}

	__u8 cfg_padding_size = CONFIG(padding_size);

	void *data = (void *)(long)ctx->xdp->data;
	void *data_end = (void *)(long)ctx->xdp->data_end;
	__u64 current_len = (data_end - data);
	__u16 cfg_link_mtu = CONFIG(link_mtu);
	// current_len includes the L2 Ethernet header; subtract it before comparing to the IP-layer MTU.
	if (cfg_link_mtu > 0 && current_len > ETH_HLEN &&
	    (current_len - ETH_HLEN) + (__u64)cfg_padding_size > cfg_link_mtu) {
		return INSTR_ERROR;
	}

	if (bpf_xdp_adjust_tail(ctx->xdp, cfg_padding_size) != 0) {
		return INSTR_ERROR;
	}

	// After adjust_tail, the new packet length is current_len + cfg_padding_size.
	// Write the marker at the last byte using bpf_xdp_store_bytes to avoid direct
	// variable-offset PTR_TO_PACKET access, which the BPF verifier rejects when
	// the offset has a non-zero var_off.mask (i.e. any runtime-computed value)
	// look at that: https://github.com/cilium/cilium/blob/main/bpf/include/bpf/ctx/xdp.h#L66
	// here's a little description about var_off mask: https://github.com/google/security-research/security/advisories/GHSA-hfqc-63c7-rj9f
	__u32 mrk_offset = (__u32)current_len + cfg_padding_size - 1;
	__u8 marker = cfg_padding_size;
	if (bpf_xdp_store_bytes(ctx->xdp, mrk_offset, &marker, sizeof(marker)) != 0) {
		return INSTR_ERROR;
	}

	return INSTR_PKT_INVD;
}

static __always_inline __maybe_unused int padding_deobfuscate_xdp(struct wg_ctx *ctx) {
	if (!CONFIG(padding_enabled)) {
		return INSTR_OK;
	}

	void *data = (void *)(long)ctx->xdp->data;
	void *data_end = (void *)(long)ctx->xdp->data_end;

	__u32 pkt_len = (__u32)(data_end - data);
	if (pkt_len == 0 || pkt_len >= 65535) {
		return INSTR_ERROR;
	}

	// Read the marker from the last byte using bpf_xdp_load_bytes to avoid direct
	// variable-offset PTR_TO_PACKET access, which the BPF verifier rejects when
	// the offset has a non-zero var_off.mask (i.e. any runtime-computed value).
	__u8 padding_size = 0;
	if (bpf_xdp_load_bytes(ctx->xdp, pkt_len - 1, &padding_size, sizeof(padding_size)) != 0) {
		return INSTR_ERROR;
	}

	if (padding_size == 0) {
		return INSTR_OK;
	}

	if (pkt_len <= padding_size) {
		return INSTR_ERROR;
	}

	if (bpf_xdp_adjust_tail(ctx->xdp, -((int)padding_size)) != 0) {
		return INSTR_ERROR;
	}

	return INSTR_PKT_INVD;
}

static __always_inline __maybe_unused int padding_obfuscate_tc(struct wg_ctx *ctx) {
	if (!CONFIG(padding_enabled)) {
		return INSTR_OK;
	}

	__u8 cfg_padding_size = CONFIG(padding_size);

	__u32 current_len = ctx->skb->len;
	__u16 cfg_link_mtu = CONFIG(link_mtu);
	// current_len includes the L2 Ethernet header; subtract it before comparing to the IP-layer MTU.
	// Cast to __u64 to prevent __u32 overflow before comparison.
	if (cfg_link_mtu > 0 && current_len > ETH_HLEN &&
	    ((__u64)current_len - ETH_HLEN) + cfg_padding_size > cfg_link_mtu) {
		return INSTR_ERROR;
	}

	__u32 new_len = current_len + cfg_padding_size;
	if (bpf_skb_change_tail(ctx->skb, new_len, 0) != 0) {
		return INSTR_ERROR;
	}

	// Use bpf_skb_store_bytes so no direct variable-offset sk_buff pointer access is needed.
	__u8 marker = cfg_padding_size;
	if (bpf_skb_store_bytes(ctx->skb, new_len - 1, &marker, sizeof(marker), 0) != 0) {
		return INSTR_ERROR;
	}

	return INSTR_PKT_INVD;
}

static __always_inline __maybe_unused int padding_deobfuscate_tc(struct wg_ctx *ctx) {
	if (!CONFIG(padding_enabled)) {
		return INSTR_OK;
	}

	__u32 current_len = ctx->skb->len;
	if (current_len == 0 || current_len >= 65535) {
		return INSTR_ERROR;
	}

	// Use bpf_skb_load_bytes so no direct variable-offset sk_buff pointer access is needed.
	__u8 padding_size = 0;
	if (bpf_skb_load_bytes(ctx->skb, current_len - 1, &padding_size, sizeof(padding_size)) != 0) {
		return INSTR_ERROR;
	}

	if (padding_size == 0) {
		return INSTR_OK;
	}

	if (current_len <= padding_size) {
		return INSTR_ERROR;
	}

	if (bpf_skb_change_tail(ctx->skb, current_len - padding_size, 0) != 0) {
		return INSTR_ERROR;
	}

	return INSTR_PKT_INVD;
}

#endif /* __INSTRUMENTATION_PADDING_H__ */
