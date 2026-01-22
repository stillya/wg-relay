#ifndef __INSTRUMENTATION_PADDING_H__
#define __INSTRUMENTATION_PADDING_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"
#include "context.h"
#include "static_config.h"

// Padding configuration
DECLARE_CONFIG(bool, padding_enabled, "Enable padding obfuscation");
DECLARE_CONFIG(__u8, padding_size, "Padding size in bytes (1-255)");

// ================= XDP MODE =================

static __always_inline __maybe_unused int padding_obfuscate_xdp(struct wg_ctx *ctx) {
	if (!CONFIG(padding_enabled)) {
		return 0;
	}

	__u8 cfg_padding_size = CONFIG(padding_size);
	if (cfg_padding_size == 0) {
		return 0;
	}

	// Expand packet tail
	if (bpf_xdp_adjust_tail(ctx->xdp, cfg_padding_size) != 0) {
		return -1;
	}

	// NOTE: After adjust_tail, all previous pointers are invalidated.
	// The caller MUST re-parse the packet after this function returns.

	// Read fresh data/data_end from xdp context
	void *data = (void *)(long)ctx->xdp->data;
	void *data_end = (void *)(long)ctx->xdp->data_end;

	// Verify we have at least cfg_padding_size bytes
	// This establishes data + cfg_padding_size <= data_end for the verifier
	if (data + cfg_padding_size > data_end) {
		return -1;
	}

	// Since we just added cfg_padding_size bytes, the marker is at the last byte
	// We use cfg_padding_size - 1 as the offset from data_end
	// But we can't do data_end - N, so we compute from data

	// We know data + cfg_padding_size <= data_end (from check above)
	// The marker should be at: (original_end) + cfg_padding_size - 1
	// Which equals: data_end - 1 in the new packet
	// We access it as: data + (new_pkt_len - 1)

	// Check that there's at least 1 byte: data + 1 <= data_end
	if (data + 1 > data_end) {
		return -1;
	}

	// Compute total packet length from data_end - data (verifier allows this)
	__u64 pkt_len64 = (data_end - data);
	if (pkt_len64 == 0 || pkt_len64 > 65535) {
		return -1;
	}

	// Now access last byte: data + (pkt_len - 1)
	// We need: data + (pkt_len - 1) + 1 <= data_end
	// Which is: data + pkt_len <= data_end
	// Since pkt_len = data_end - data, this is always true

	__u32 marker_offset = (__u32)(pkt_len64 - 1);

	// Explicit bounds check that verifier can track
	if (data + marker_offset + 1 > data_end) {
		return -1;
	}

	// Now write the marker
	__u8 *marker = (__u8 *)data + marker_offset;
	*marker = cfg_padding_size;

	return 0;
}

static __always_inline __maybe_unused int padding_deobfuscate_xdp(struct wg_ctx *ctx) {
	if (!CONFIG(padding_enabled)) {
		return 0;
	}

	// Read data/data_end from xdp context
	void *data = (void *)(long)ctx->xdp->data;
	void *data_end = (void *)(long)ctx->xdp->data_end;

	// Need at least 1 byte to read the marker
	if (data + 1 > data_end) {
		return 0;
	}

	// Compute packet length
	__u64 pkt_len64 = (data_end - data);
	if (pkt_len64 == 0 || pkt_len64 > 65535) {
		return 0;
	}

	// Read the marker (last byte)
	__u32 marker_offset = (__u32)(pkt_len64 - 1);

	// Bounds check for marker access
	if (data + marker_offset + 1 > data_end) {
		return 0;
	}

	__u8 *marker = (__u8 *)data + marker_offset;
	__u8 padding_size = *marker;

	// Sanity checks
	if (padding_size == 0) {
		return 0;
	}

	if (pkt_len64 < padding_size) {
		return 0;
	}

	// Trim padding
	if (bpf_xdp_adjust_tail(ctx->xdp, -((int)padding_size)) != 0) {
		return -1;
	}

	return 0;
}

// ================= TC MODE =================

static __always_inline __maybe_unused int padding_obfuscate_tc(struct wg_ctx *ctx) {
	if (!CONFIG(padding_enabled)) {
		return 0;
	}

	__u8 cfg_padding_size = CONFIG(padding_size);
	if (cfg_padding_size == 0) {
		return 0;
	}

	// Expand packet tail
	__u32 current_len = ctx->skb->len;
	if (bpf_skb_change_tail(ctx->skb, current_len + cfg_padding_size, 0) != 0) {
		return -1;
	}

	// Ensure linear data
	if (bpf_skb_pull_data(ctx->skb, current_len + cfg_padding_size) < 0) {
		return -1;
	}

	// Read fresh data/data_end from skb context
	void *data = (void *)(long)ctx->skb->data;
	void *data_end = (void *)(long)ctx->skb->data_end;

	// Verify we have at least cfg_padding_size bytes
	if (data + cfg_padding_size > data_end) {
		return -1;
	}

	// Check minimum size
	if (data + 1 > data_end) {
		return -1;
	}

	// Compute packet length
	__u64 pkt_len64 = (data_end - data);
	if (pkt_len64 == 0 || pkt_len64 > 65535) {
		return -1;
	}

	// Access last byte
	__u32 marker_offset = (__u32)(pkt_len64 - 1);

	// Bounds check
	if (data + marker_offset + 1 > data_end) {
		return -1;
	}

	// Write marker
	__u8 *marker = (__u8 *)data + marker_offset;
	*marker = cfg_padding_size;

	return 0;
}

static __always_inline __maybe_unused int padding_deobfuscate_tc(struct wg_ctx *ctx) {
	if (!CONFIG(padding_enabled)) {
		return 0;
	}

	// Read data/data_end from skb context
	void *data = (void *)(long)ctx->skb->data;
	void *data_end = (void *)(long)ctx->skb->data_end;

	// Need at least 1 byte
	if (data + 1 > data_end) {
		return 0;
	}

	// Compute packet length
	__u64 pkt_len64 = (data_end - data);
	if (pkt_len64 == 0 || pkt_len64 > 65535) {
		return 0;
	}

	// Read marker
	__u32 marker_offset = (__u32)(pkt_len64 - 1);

	// Bounds check
	if (data + marker_offset + 1 > data_end) {
		return 0;
	}

	__u8 *marker = (__u8 *)data + marker_offset;
	__u8 padding_size = *marker;

	if (padding_size == 0) {
		return 0;
	}

	if (pkt_len64 < padding_size) {
		return 0;
	}

	// Trim padding
	__u32 current_len = ctx->skb->len;
	if (bpf_skb_change_tail(ctx->skb, current_len - padding_size, 0) != 0) {
		return -1;
	}

	return 0;
}

#endif /* __INSTRUMENTATION_PADDING_H__ */
