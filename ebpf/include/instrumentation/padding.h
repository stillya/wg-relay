#ifndef __INSTRUMENTATION_PADDING_H__
#define __INSTRUMENTATION_PADDING_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common.h"
#include "context.h"
#include "instrumentation.h"
#include "static_config.h"

DECLARE_CONFIG(bool, padding_enabled, "Enable padding obfuscation");
DECLARE_CONFIG(__u8, padding_size, "Padding size in bytes");
DECLARE_CONFIG(bool, padding_randomize, "Randomize padding size between 1 and padding_size");
DECLARE_CONFIG(bool, padding_adaptive, "Adaptively probe available XDP tailroom (AIMD)");
DECLARE_CONFIG(__u16, link_mtu, "Link MTU size in bytes");

// Number of consecutive successful packets before AIMD attempts to grow the
// working padding size by one (additive increase step).
#define PADDING_PROBE_STREAK 1024

// Per-interface adaptive padding state. Keyed by ingress ifindex because the
// available XDP tailroom is a property of the driver behind that interface;
// attaching to several interfaces with different drivers must not share a
// single oscillating limit. Per-CPU because each RX queue (and thus CPU)
// carries its own buffer, and the hot path needs lock-free access.
struct padding_state {
	__u8 current_size; // current working ceiling, 1..cfg_padding_size
	__u8 _pad;
	__u16 ok_streak; // consecutive successes since last increase
	__u32 backoffs;  // total multiplicative decreases (for control-plane logging)
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 64);
	__type(key, __u32); // ifindex
	__type(value, struct padding_state);
} padding_state_map SEC(".maps");

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

	// AIMD: probe the real tailroom the driver's frame_sz allows. The MTU check
	// above only guards the wire MTU; bpf_xdp_adjust_tail can still fail on the
	// driver buffer limit (frame_sz), which varies per driver/mode and is not
	// observable from the control plane. When adaptive is enabled we cap the
	// requested size at a per-interface working ceiling, halve it on failure,
	// and slowly grow it back.
	__u8 want = actual_size;
	struct padding_state *st = NULL;

	if (CONFIG(padding_adaptive)) {
		__u32 ifindex = ctx->xdp->ingress_ifindex;
		st = bpf_map_lookup_elem(&padding_state_map, &ifindex);
		if (!st) {
			struct padding_state init = { .current_size = cfg_padding_size };
			bpf_map_update_elem(&padding_state_map, &ifindex, &init, BPF_ANY);
			st = bpf_map_lookup_elem(&padding_state_map, &ifindex);
		}
		if (st) {
			// On a PERCPU_HASH, a BPF-side update seeds only the current
			// CPU's slot; other CPUs first see their zero-initialized slot.
			// current_size can never legitimately reach 0 (the decrease
			// floors at 1), so 0 unambiguously means "not seeded on this
			// CPU" — reseed it to the configured ceiling. This also keeps
			// `want` from ever being capped to 0, which would send an
			// unpadded packet whose marker overwrites a real payload byte.
			if (st->current_size == 0) {
				st->current_size = cfg_padding_size;
			}
			if (want > st->current_size) {
				want = st->current_size;
			}
		}
	}

	if (bpf_xdp_adjust_tail(ctx->xdp, want) != 0) {
		if (st) {
			st->current_size = want > 1 ? (__u8)(want >> 1) : 1; // multiplicative decrease
			st->ok_streak = 0;
			st->backoffs++;
		}
		// -EINVAL leaves the packet unmodified (bounds are checked before any
		// mutation in the kernel), so retrying with the protocol floor is safe.
		// The marker itself is a valid padding of size 1; we cannot send an
		// unpadded packet because the receiver reads the last byte as the size.
		if (bpf_xdp_adjust_tail(ctx->xdp, 1) != 0) {
			return INSTR_NO_TAILROOM;
		}
		want = 1;
	} else if (st && ++st->ok_streak >= PADDING_PROBE_STREAK) {
		st->ok_streak = 0;
		if (st->current_size < cfg_padding_size) {
			st->current_size++; // additive increase
		}
	}

	// Write the marker at the last byte using bpf_xdp_store_bytes to avoid direct
	// variable-offset PTR_TO_PACKET access, which the BPF verifier rejects when
	// the offset has a non-zero var_off.mask (i.e. any runtime-computed value).
	// Example: https://github.com/cilium/cilium/blob/main/bpf/include/bpf/ctx/xdp.h#L66
	// Little about var_off: https://github.com/google/security-research/security/advisories/GHSA-hfqc-63c7-rj9f
	__u32 mrk_offset = (__u32)current_len + want - 1;
	__u8 marker = want;
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
