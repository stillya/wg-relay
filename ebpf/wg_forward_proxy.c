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
#include "nat.h"
#include "backend.h"
#include "packet.h"
#include "static_config.h"

// Forward proxy static configuration
DECLARE_CONFIG(__u16, wg_port, "WireGuard port to intercept");

// Connection tracking map: client connection -> NAT info
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct connection_key);
	__type(value, struct connection_value);
} connection_map SEC(".maps");

// Reverse lookup map: NAT info -> original client connection
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct nat_key);
	__type(value, struct connection_key);
} nat_reverse_map SEC(".maps");

// Create or lookup NAT connection for outgoing packets (client -> server)
static __always_inline int create_nat_connection(struct wg_ctx *ctx,
						 struct backend_entry *backend) {
	struct connection_key conn_key = {
		.client_ip = ctx->ip->saddr,
		.client_port = ctx->src_port,
		.server_ip = ctx->ip->daddr,
		.server_port = ctx->dst_port,
	};

	if (select_backend_hash(conn_key.client_ip, conn_key.client_port, backend) < 0) {
		return -1;
	}

	// Check if connection already exists
	struct connection_value *existing = bpf_map_lookup_elem(&connection_map, &conn_key);
	if (existing) {
		existing->timestamp = get_timestamp();
		return 0;
	}

	__u16 nat_port = generate_nat_port();

	struct connection_value conn_value = {
		.timestamp = get_timestamp(),
		.nat_port = nat_port,
	};

	struct nat_key nat_key = {
		.server_ip = backend->ip,
		.nat_port = nat_port,
	};

	int ret = bpf_map_update_elem(&connection_map, &conn_key, &conn_value, BPF_NOEXIST);
	if (ret == -EEXIST) {
		existing = bpf_map_lookup_elem(&connection_map, &conn_key);
		if (existing) {
			existing->timestamp = get_timestamp();
			return 0;
		}
		return -1;
	} else if (ret != 0) {
		return -1;
	}

	ret = bpf_map_update_elem(&nat_reverse_map, &nat_key, &conn_key, BPF_ANY);
	if (ret != 0) {
		bpf_map_delete_elem(&connection_map, &conn_key);
		return -1;
	}

	return 0;
}

// Restore NAT connection for return packets (server -> client)
static __always_inline int restore_nat_connection(struct wg_ctx *ctx, struct connection_key *original_conn) {
	struct nat_key nat_key = { 0 };
	nat_key.server_ip = ctx->ip->saddr;
	nat_key.nat_port = ctx->dst_port;

	struct connection_key *conn_key = bpf_map_lookup_elem(&nat_reverse_map, &nat_key);
	if (!conn_key) {
		return -1;
	}

	original_conn->client_ip = conn_key->client_ip;
	original_conn->client_port = conn_key->client_port;
	original_conn->server_ip = conn_key->server_ip;
	original_conn->server_port = conn_key->server_port;

	struct connection_value *conn_value = bpf_map_lookup_elem(&connection_map, conn_key);
	if (conn_value) {
		conn_value->timestamp = get_timestamp();
	}

	return 0;
}

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
	if (ret == INSTR_ERROR) {
		return INSTR_ERROR;
	}
	if (ret == INSTR_PKT_INVD) {
		if (parse_xdp_packet(ctx->xdp, ctx) < 0) {
			return INSTR_ERROR;
		}
	}

	ret = padding_obfuscate_xdp(ctx);
	if (ret == INSTR_ERROR) {
		return INSTR_ERROR;
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
	if (ret == INSTR_ERROR) {
		return INSTR_ERROR;
	}
	if (ret == INSTR_PKT_INVD) {
		if (parse_xdp_packet(ctx->xdp, ctx) < 0) {
			return INSTR_ERROR;
		}
	}

	ret = xor_deobfuscate_xdp(ctx);
	if (ret == INSTR_ERROR) {
		return INSTR_ERROR;
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
	if (dst_port != wg_port && src_port != wg_port)
		return XDP_PASS;

	__u8 is_to_wg = (dst_port == wg_port) ? 1 : 0;
	__u8 is_from_wg = (src_port == wg_port) ? 1 : 0;

	__u32 pkt_len = (void *)(long)xdp_ctx->data_end - (void *)(long)xdp_ctx->data;

	if (likely(is_from_wg)) {
		struct connection_key original_conn = { 0 };
		if (restore_nat_connection(&ctx, &original_conn) < 0) {
			DEBUG_PRINTK("Failed to restore NAT connection for FROM WG packet, passing "
				     "through");
			update_metrics(METRIC_FROM_WG, METRIC_DROP, pkt_len, 0);

			return XDP_PASS;
		}

		if (instr_deobfuscate_xdp(&ctx) < 0) {
			DEBUG_PRINTK("Deobfuscation failed, dropping packet");
			update_metrics(METRIC_FROM_WG, METRIC_DROP, pkt_len, 0);
			return XDP_DROP;
		}

		__u32 dst_addr = bpf_ntohl(ctx.ip->daddr);
		__u32 client_ip = bpf_ntohl(original_conn.client_ip);
		__u16 server_port = original_conn.server_port;
		__u16 client_port = original_conn.client_port;

		update_metrics(METRIC_FROM_WG, METRIC_FORWARDED, pkt_len, client_ip);
		return forward_packet(&ctx, dst_addr, server_port, client_ip, client_port);
	}

	if (unlikely(is_to_wg)) {
		__u32 src_addr = bpf_ntohl(ctx.ip->saddr);

		struct backend_entry backend = { 0 };
		if (create_nat_connection(&ctx, &backend) < 0) {
			DEBUG_PRINTK("Failed to create NAT connection for TO WG packet");
			update_metrics(METRIC_TO_WG, METRIC_DROP, pkt_len, src_addr);
			return XDP_PASS;
		}

		struct connection_key conn_key = {
			.client_ip = ctx.ip->saddr,
			.client_port = src_port,
			.server_ip = ctx.ip->daddr,
			.server_port = dst_port,
		};

		struct connection_value *conn_value = bpf_map_lookup_elem(&connection_map, &conn_key);
		if (!conn_value) {
			DEBUG_PRINTK("No NAT connection found for client %pI4:%d -> server "
				     "%pI4:%d, passing through",
				     &conn_key.client_ip, conn_key.client_port, &conn_key.server_ip,
				     conn_key.server_port);
			update_metrics(METRIC_TO_WG, METRIC_DROP, pkt_len, src_addr);
			return XDP_PASS;
		}

		if (instr_obfuscate_xdp(&ctx) < 0) {
			DEBUG_PRINTK("Obfuscation failed, dropping packet");
			update_metrics(METRIC_TO_WG, METRIC_DROP, pkt_len, src_addr);
			return XDP_DROP;
		}

		__u32 proxy_ip = bpf_ntohl(ctx.ip->daddr);
		__u32 server_ip = bpf_ntohl(backend.ip);
		__u16 target_port = backend.port > 0 ? backend.port : CONFIG(wg_port);

		update_metrics(METRIC_TO_WG, METRIC_FORWARDED, pkt_len, src_addr);
		return forward_packet(&ctx, proxy_ip, conn_value->nat_port, server_ip, target_port);
	}

	DEBUG_PRINTK("No matching handler for WG packet, passing through");
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
