#ifndef __INSTRUMENTATION_PADDING_H__
#define __INSTRUMENTATION_PADDING_H__

#include "common.h"
#include "context.h"
#include "instrumentation.h"
#include "static_config.h"

DECLARE_CONFIG(bool, padding_enabled, "Enable padding obfuscation");
DECLARE_CONFIG(__u8, padding_size, "Padding size in bytes");

static __always_inline __maybe_unused int padding_obfuscate_xdp(struct wg_ctx *ctx) {
	if (!CONFIG(padding_enabled)) {
		return INSTR_OK;
	}

	__u8 cfg_padding_size = CONFIG(padding_size);

	if (bpf_xdp_adjust_tail(ctx->xdp, cfg_padding_size) != 0) {
		return INSTR_ERROR;
	}

	void *data = (void *)(long)ctx->xdp->data;
	void *data_end = (void *)(long)ctx->xdp->data_end;

	if (data + cfg_padding_size > data_end) {
		return INSTR_ERROR;
	}

	if (data + 1 > data_end) {
		return INSTR_ERROR;
	}

	__u64 pkt_len = (data_end - data);
	if (pkt_len <= 0 || pkt_len > 65535) {
		return INSTR_ERROR;
	}

	__u32 mrk_offset = (__u32)(pkt_len - 1);

	if (data + mrk_offset + 1 > data_end) {
		return INSTR_ERROR;
	}

	__u8 *mrk = (__u8 *)data + mrk_offset;
	*mrk = cfg_padding_size;

	return INSTR_PKT_INVD;
}

static __always_inline __maybe_unused int padding_deobfuscate_xdp(struct wg_ctx *ctx) {
	if (!CONFIG(padding_enabled)) {
		return INSTR_OK;
	}

	void *data = (void *)(long)ctx->xdp->data;
	void *data_end = (void *)(long)ctx->xdp->data_end;

	if (data + 1 > data_end) {
		return INSTR_OK;
	}

	__u64 pkt_len = (data_end - data);
	if (pkt_len == 0 || pkt_len > 65535) {
		return INSTR_OK;
	}

	__u32 mrk_offset = (__u32)(pkt_len - 1);

	if (data + mrk_offset + 1 > data_end) {
		return INSTR_OK;
	}

	__u8 *mrk = (__u8 *)data + mrk_offset;
	__u8 padding_size = *mrk;

	if (padding_size == 0) {
		return INSTR_OK;
	}

	if (pkt_len < padding_size) {
		return INSTR_OK;
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
	if (cfg_padding_size == 0) {
		return INSTR_OK;
	}

	__u32 current_len = ctx->skb->len;
	if (bpf_skb_change_tail(ctx->skb, current_len + cfg_padding_size, 0) != 0) {
		return INSTR_ERROR;
	}

	if (bpf_skb_pull_data(ctx->skb, current_len + cfg_padding_size) < 0) {
		return INSTR_ERROR;
	}

	void *data = (void *)(long)ctx->skb->data;
	void *data_end = (void *)(long)ctx->skb->data_end;

	if (data + cfg_padding_size > data_end) {
		return INSTR_ERROR;
	}

	if (data + 1 > data_end) {
		return INSTR_ERROR;
	}

	__u64 pkt_len = (data_end - data);
	if (pkt_len == 0 || pkt_len > 65535) {
		return INSTR_ERROR;
	}

	__u32 mrk_offset = (__u32)(pkt_len - 1);

	if (data + mrk_offset + 1 > data_end) {
		return INSTR_ERROR;
	}

	__u8 *mrk = (__u8 *)data + mrk_offset;
	*mrk = cfg_padding_size;

	return INSTR_PKT_INVD;
}

static __always_inline __maybe_unused int padding_deobfuscate_tc(struct wg_ctx *ctx) {
	if (!CONFIG(padding_enabled)) {
		return INSTR_OK;
	}

	void *data = (void *)(long)ctx->skb->data;
	void *data_end = (void *)(long)ctx->skb->data_end;

	if (data + 1 > data_end) {
		return INSTR_OK;
	}

	__u64 pkt_len = (data_end - data);
	if (pkt_len == 0 || pkt_len > 65535) {
		return INSTR_OK;
	}

	__u32 mrk_offset = (__u32)(pkt_len - 1);

	if (data + mrk_offset + 1 > data_end) {
		return INSTR_OK;
	}

	__u8 *mrk = (__u8 *)data + mrk_offset;
	__u8 padding_size = *mrk;

	if (padding_size == 0) {
		return INSTR_OK;
	}

	if (pkt_len < padding_size) {
		return INSTR_OK;
	}

	__u32 current_len = ctx->skb->len;
	if (bpf_skb_change_tail(ctx->skb, current_len - padding_size, 0) != 0) {
		return INSTR_ERROR;
	}

	return INSTR_PKT_INVD;
}

#endif /* __INSTRUMENTATION_PADDING_H__ */
