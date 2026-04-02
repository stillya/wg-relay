#ifndef __INSTRUMENTATION_PADDING_H__
#define __INSTRUMENTATION_PADDING_H__

#include <bpf/bpf_helpers.h>
#include "common.h"
#include "context.h"
#include "instrumentation.h"
#include "static_config.h"
#include "vmlinux.h"

DECLARE_CONFIG(bool, padding_enabled, "Enable padding obfuscation");
DECLARE_CONFIG(__u8, padding_size, "Padding size in bytes");
DECLARE_CONFIG(bool, padding_randomize, "Randomize padding size between 1 and padding_size");
DECLARE_CONFIG(__u16, link_mtu, "Link MTU size in bytes");

static __always_inline __maybe_unused int padding_obfuscate_xdp(struct wg_ctx *ctx) {
	if (!CONFIG(padding_enabled)) {
		return INSTR_OK;
	}

	__u8 cfg_padding_size = CONFIG(padding_size);
	__u8 actual_size =
		CONFIG(padding_randomize) ? ((__u8)(bpf_get_prandom_u32() % cfg_padding_size) + 1) : cfg_padding_size;

	void *data = (void *)(long)ctx->xdp->data;
	void *data_end = (void *)(long)ctx->xdp->data_end;
	__u64 current_len = (data_end - data);
	__u16 cfg_link_mtu = CONFIG(link_mtu);
	if (cfg_link_mtu > 0 && current_len > ETH_HLEN &&
	    (current_len - ETH_HLEN) + (__u64)actual_size > cfg_link_mtu) {
		return INSTR_ERROR;
	}

	if (bpf_xdp_adjust_tail(ctx->xdp, actual_size) != 0) {
		return INSTR_ERROR;
	}

	// Write the marker at the last byte using bpf_xdp_store_bytes to avoid direct
	// variable-offset PTR_TO_PACKET access, which the BPF verifier rejects when
	// the offset has a non-zero var_off.mask (i.e. any runtime-computed value).
	// Example: https://github.com/cilium/cilium/blob/main/bpf/include/bpf/ctx/xdp.h#L66
	// Little about var_off: https://github.com/google/security-research/security/advisories/GHSA-hfqc-63c7-rj9f
	__u32 mrk_offset = (__u32)current_len + actual_size - 1;
	__u8 marker = actual_size;
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
	// Example: https://github.com/cilium/cilium/blob/main/bpf/include/bpf/ctx/xdp.h#L66
	// Little about var_off: https://github.com/google/security-research/security/advisories/GHSA-hfqc-63c7-rj9f
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
	__u8 actual_size =
		CONFIG(padding_randomize) ? ((__u8)(bpf_get_prandom_u32() % cfg_padding_size) + 1) : cfg_padding_size;

	__u32 current_len = ctx->skb->len;
	__u16 cfg_link_mtu = CONFIG(link_mtu);
	if (cfg_link_mtu > 0 && current_len > ETH_HLEN &&
	    ((__u64)current_len - ETH_HLEN) + actual_size > cfg_link_mtu) {
		return INSTR_ERROR;
	}

	__u32 new_len = current_len + actual_size;
	if (bpf_skb_change_tail(ctx->skb, new_len, 0) != 0) {
		return INSTR_ERROR;
	}

	__u8 marker = actual_size;
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
