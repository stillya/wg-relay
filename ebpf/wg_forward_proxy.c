// clang-format off
//go:build ignore
//  clang-format on

// NOTE: Disable preserve_access_index on BPF context types (xdp_md, __sk_buff, etc.)
// to prevent CO-RE relocations on context pointers, which cause the BPF verifier
// to reject programs with "dereference of modified ctx ptr" errors.
// But we should move to direct BPF_CORE_READ if there will be direct access to kernel structs.
#define BPF_NO_PRESERVE_ACCESS_INDEX
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "csum.h"
#include "instrumentation/instrumentation.h"
#include "instrumentation/xor.h"
#include "instrumentation/padding.h"
#include "metrics.h"
#include "backend.h"
#include "ct.h"
#include "packet.h"
#include "static_config.h"

// Forward proxy static configuration
DECLARE_CONFIG(__u16, wg_port, "WireGuard port to intercept");

// Forward packet using XDP-Proxy style forwarding
static __always_inline int forward_packet(struct wg_ctx *ctx, __u32 new_saddr, __u16 new_sport, __u32 new_daddr,
					  __u16 new_dport) {
	if (new_saddr != 0) {
		ctx->ip->saddr = bpf_htonl(new_saddr);
	}
	if (new_daddr != 0) {
		ctx->ip->daddr = bpf_htonl(new_daddr);
	}
	if (new_sport != 0) {
		ctx->udp->source = bpf_htons(new_sport);
	}
	if (new_dport != 0) {
		ctx->udp->dest = bpf_htons(new_dport);
	}

	struct bpf_fib_lookup params = { 0 };
	params.family = AF_INET;
	params.tos = ctx->ip->tos;
	params.l4_protocol = ctx->ip->protocol;
	params.tot_len = bpf_ntohs(ctx->ip->tot_len);
	params.ipv4_src = ctx->ip->saddr;
	params.ipv4_dst = ctx->ip->daddr;
	params.ifindex = ctx->xdp->ingress_ifindex;

	int fwd = bpf_fib_lookup(ctx->xdp, &params, sizeof(params), BPF_FIB_LOOKUP_DIRECT);

	if (fwd != BPF_FIB_LKUP_RET_SUCCESS) {
		// HACK: on fail go to default route, which probably is src mac
		swap_eth(ctx->eth);
	} else {
		memcpy(ctx->eth->h_source, params.smac, ETH_ALEN);
		memcpy(ctx->eth->h_dest, params.dmac, ETH_ALEN);
	}

	__u16 new_tot_len = (__u16)((void *)(long)ctx->xdp->data_end - (void *)(long)ctx->xdp->data) - ETH_HLEN;
	ctx->ip->tot_len = bpf_htons(new_tot_len);
	ctx->udp->len    = bpf_htons(new_tot_len - (ctx->ip->ihl * 4));

	// TODO: Disabled fragmentation for now, fix it later(or not)
	ctx->ip->frag_off |= bpf_htons(IP_DF);

	ctx->ip->check = iph_csum(ctx->ip);
	ctx->udp->check = 0;

	if (fwd == BPF_FIB_LKUP_RET_SUCCESS && params.ifindex != ctx->xdp->ingress_ifindex) {
		return bpf_redirect(params.ifindex, 0);
	} else {
		return XDP_TX;
	}
}

// Apply obfuscation in XDP mode (manual ordering)
// NOTE: Order matters!
static __always_inline int instr_obfuscate_xdp(struct wg_ctx *ctx) {
	int ret;

	ret = xor_obfuscate_xdp(ctx);
	if (ret < 0) {
		return ret;
	}
	if (ret == INSTR_PKT_INVD) {
		if (parse_xdp_packet(ctx->xdp, ctx) < 0) {
			return INSTR_ERROR;
		}
	}

	ret = padding_obfuscate_xdp(ctx);
	if (ret < 0) {
		return ret;
	}
	if (ret == INSTR_PKT_INVD) {
		if (parse_xdp_packet(ctx->xdp, ctx) < 0) {
			return INSTR_ERROR;
		}
	}

	return INSTR_OK;
}

// Apply deobfuscation in XDP mode (reverse order)
// NOTE: Order matters!
static __always_inline int instr_deobfuscate_xdp(struct wg_ctx *ctx) {
	int ret;

	ret = padding_deobfuscate_xdp(ctx);
	if (ret < 0) {
		return ret;
	}
	if (ret == INSTR_PKT_INVD) {
		if (parse_xdp_packet(ctx->xdp, ctx) < 0) {
			return INSTR_ERROR;
		}
	}

	ret = xor_deobfuscate_xdp(ctx);
	if (ret < 0) {
		return ret;
	}
	if (ret == INSTR_PKT_INVD) {
		if (parse_xdp_packet(ctx->xdp, ctx) < 0) {
			return INSTR_ERROR;
		}
	}

	return INSTR_OK;
}

SEC("xdp")
int wg_forward_proxy(struct xdp_md *xdp_ctx) {
	struct wg_ctx ctx = {};
	if (parse_xdp_packet(xdp_ctx, &ctx) < 0)
		return XDP_PASS;

	__u16 src_port = ctx.src_port;
	__u16 dst_port = ctx.dst_port;
	__u16 wg_port = CONFIG(wg_port);

	__u8 is_to_wg = (dst_port == wg_port) ? 1 : 0;
	__u32 pkt_len = (void *)(long)xdp_ctx->data_end - (void *)(long)xdp_ctx->data;

	if (unlikely(is_to_wg)) {
		struct ipv4_ct_tuple tuple = {
			.saddr = ctx.ip->saddr,
			.daddr = ctx.ip->daddr,
			.sport = ctx.udp->source,
			.dport = ctx.udp->dest,
		};

		struct ipv4_ct_entry *entry = ct_lookup(&tuple);
		if (!entry) {
			struct backend_entry backend = { 0 };
			if (select_backend_hash(bpf_ntohl(tuple.saddr), src_port, &backend) < 0) {
				DEBUG_PRINTK("No backend available for TO WG packet");
				return XDP_PASS;
			}

			struct ipv4_ct_target target = { 0 };
			backend_to_ct_target(&backend, wg_port, &target);

			entry = ct_lookup_or_create(&tuple, &target, wg_port);
			if (!entry) {
				DEBUG_PRINTK("Failed to create ct entry for TO WG packet");
				return XDP_PASS;
			}
		}

		__u8 backend_idx = entry->backend_idx;

		// TO_WG path: client->proxy (downstream rx), proxy->backend (upstream tx)
		update_metrics(backend_idx, METRIC_DOWNSTREAM, pkt_len, 1, METRIC_REASON_FORWARDED);

		int obf_ret = instr_obfuscate_xdp(&ctx);
		if (obf_ret < 0) {
			DEBUG_PRINTK("Obfuscation failed, dropping packet");
			update_metrics(backend_idx, METRIC_DOWNSTREAM, pkt_len, 1,
				       obf_ret == INSTR_NO_TAILROOM ? METRIC_REASON_NO_TAILROOM : METRIC_REASON_DROPPED);
			return XDP_DROP;
		}

		__u32 tx_pkt_len = (void *)(long)xdp_ctx->data_end - (void *)(long)xdp_ctx->data;

		update_metrics(backend_idx, METRIC_UPSTREAM, tx_pkt_len, 0, METRIC_REASON_FORWARDED);
		return forward_packet(&ctx, bpf_ntohl(tuple.daddr), bpf_ntohs(entry->nat_port), bpf_ntohl(entry->to_daddr),
				      bpf_ntohs(entry->to_dport));
	}

	__u8 is_from_wg = bpf_map_lookup_elem(&backend_port_set, &src_port) != NULL ? 1 : 0;

	if (likely(is_from_wg)) {
		struct ipv4_ct_tuple rev_tuple = {
			.saddr = ctx.ip->saddr,
			.daddr = ctx.ip->daddr,
			.sport = ctx.udp->source,
			.dport = ctx.udp->dest,
		};
		struct ipv4_ct_tuple client = { 0 };

		struct ipv4_ct_entry *entry = ct_restore(&rev_tuple, &client);
		if (!entry) {
			DEBUG_PRINTK("No ct entry for FROM WG packet, passing through");
			return XDP_PASS;
		}

		__u8 backend_idx = entry->backend_idx;

		// FROM_WG path: backend->proxy (upstream rx), proxy->client (downstream tx)
		update_metrics(backend_idx, METRIC_UPSTREAM, pkt_len, 1, METRIC_REASON_FORWARDED);

		if (instr_deobfuscate_xdp(&ctx) < 0) {
			DEBUG_PRINTK("Deobfuscation failed, dropping packet");
			update_metrics(backend_idx, METRIC_UPSTREAM, pkt_len, 1, METRIC_REASON_DROPPED);
			return XDP_DROP;
		}

		__u32 tx_pkt_len = (void *)(long)xdp_ctx->data_end - (void *)(long)xdp_ctx->data;

		update_metrics(backend_idx, METRIC_DOWNSTREAM, tx_pkt_len, 0, METRIC_REASON_FORWARDED);
		return forward_packet(&ctx, bpf_ntohl(client.daddr), bpf_ntohs(client.dport), bpf_ntohl(client.saddr),
				      bpf_ntohs(client.sport));
	}

	DEBUG_PRINTK("No matching handler for WG packet, passing through");
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
