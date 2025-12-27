//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "csum.h"
#include "nat.h"
#include "packet.h"
#include "metrics.h"
#include "obfuscation.h"

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

// Create NAT connection for outgoing packets (client -> server)
static __always_inline int create_nat_connection(struct packet_info *pkt, struct obfuscation_config *config) {
    struct connection_key conn_key = {
        .client_ip = pkt->ip->saddr,
        .client_port = pkt->src_port,
        .server_ip = pkt->ip->daddr,
        .server_port = pkt->dst_port
    };
    
    // Check if connection already exists first
    struct connection_value *existing = bpf_map_lookup_elem(&connection_map, &conn_key);
    if (existing) {
        existing->timestamp = get_timestamp();
        return 0;
    }
    
    __u16 nat_port = generate_nat_port();
    
    struct connection_value conn_value = {
        .timestamp = get_timestamp(),
        .nat_port = nat_port
    };
    
    struct nat_key nat_key = {0};
    nat_key.server_ip = bpf_htonl(config->target_server_ip);
    nat_key.nat_port = nat_port;
    
    int conn_updated = bpf_map_update_elem(&connection_map, &conn_key, &conn_value, BPF_NOEXIST);
    if (conn_updated == -EEXIST) {
        existing = bpf_map_lookup_elem(&connection_map, &conn_key);
        if (existing) {
            existing->timestamp = get_timestamp();
            return 0;
        } else {
            return -1;
        }
    } else if (conn_updated != 0) {
        return -1;
    }
    
    int reverse_updated = bpf_map_update_elem(&nat_reverse_map, &nat_key, &conn_key, BPF_ANY);
    if (reverse_updated != 0) {
        // cleanup if reverse mapping fails
        bpf_map_delete_elem(&connection_map, &conn_key);
        return -1;
    }
    
    return 0;
}

// Restore NAT connection for return packets (server -> client)
static __always_inline int restore_nat_connection(struct packet_info *pkt, struct connection_key *original_conn) {
    struct nat_key nat_key = {0};
    nat_key.server_ip = pkt->ip->saddr;
    nat_key.nat_port = pkt->dst_port;
    
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
static __always_inline int forward_packet(struct xdp_md *ctx, struct packet_info *pkt, __u32 new_saddr, __u16 new_sport, __u32 new_daddr, __u16 new_dport) {
    __u32 old_saddr = pkt->ip->saddr;
    __u32 old_daddr = pkt->ip->daddr;
    __u16 old_sport = pkt->udp->source;
    __u16 old_dport = pkt->udp->dest;

    if (new_saddr != 0) {
        pkt->ip->saddr = bpf_htonl(new_saddr);
    }
    if (new_daddr != 0) {
        pkt->ip->daddr = bpf_htonl(new_daddr);
    }
    if (new_sport != 0) {
        pkt->udp->source = bpf_htons(new_sport);
    }
    if (new_dport != 0) {
        pkt->udp->dest = bpf_htons(new_dport);
    }

    struct bpf_fib_lookup params = {0};
    params.family = AF_INET;
    params.tos = pkt->ip->tos;
    params.l4_protocol = pkt->ip->protocol;
    params.tot_len = bpf_ntohs(pkt->ip->tot_len);
    params.ipv4_src = pkt->ip->saddr;
    params.ipv4_dst = pkt->ip->daddr;
    params.ifindex = ctx->ingress_ifindex;

    int fwd = bpf_fib_lookup(ctx, &params, sizeof(params), BPF_FIB_LOOKUP_DIRECT);

    if (fwd != BPF_FIB_LKUP_RET_SUCCESS) {
       // on fail go to default route, which probably is src mac
        swap_eth(pkt->eth);
    } else {
        memcpy(pkt->eth->h_source, params.smac, ETH_ALEN);
        memcpy(pkt->eth->h_dest, params.dmac, ETH_ALEN);
    }
    
    // TODO: Disabled fragmentation for now, fix it later
    pkt->ip->frag_off |= bpf_htons(IP_DF);

    pkt->ip->check = iph_csum(pkt->ip);
    pkt->udp->check = 0;

    if (fwd == BPF_FIB_LKUP_RET_SUCCESS && params.ifindex != ctx->ingress_ifindex) {
        return bpf_redirect(params.ifindex, 0);
    } else {
        return XDP_TX;
    }
}

SEC("xdp")
int wg_forward_proxy(struct xdp_md *ctx) {
    struct packet_info pkt = {};
    if (parse_xdp_packet(ctx, &pkt) < 0)
        return XDP_PASS;
    
    __u16 src_port = bpf_ntohs(pkt.udp->source);
    __u16 dst_port = bpf_ntohs(pkt.udp->dest);
    if (dst_port != WG_PORT && src_port != WG_PORT)
        return XDP_PASS;

    __u32 config_key = 0;
    struct obfuscation_config *config = bpf_map_lookup_elem(&obfuscation_config_map, &config_key);
    if (!config || !config->enabled) {
        DEBUG_PRINTK("Config disabled or missing, passing through WG packet");
        return XDP_PASS;
    }
    
    __u8 is_to_wg = (dst_port == WG_PORT) ? 1 : 0;
    __u8 is_from_wg = (src_port == WG_PORT) ? 1 : 0;
    
     __u32 pkt_len = (void *)(long)ctx->data_end - (void *)(long)ctx->data;
    
    if (likely(is_from_wg)) {
        struct connection_key original_conn = {0};
        if (restore_nat_connection(&pkt, &original_conn) < 0) {
            increment_stat(STAT_NAT_LOOKUPS_FAILED);
            DEBUG_PRINTK("Failed to restore NAT connection for FROM WG packet, passing through");
            update_metrics(METRIC_FROM_WG, METRIC_DROP, pkt_len, bpf_ntohl(pkt.ip->saddr));

            return XDP_PASS;
        }
        increment_stat(STAT_NAT_LOOKUPS_SUCCESS);

        apply_obfuscation(&pkt, config);

        __u32 proxy_ip = bpf_ntohl(pkt.ip->daddr);
        __u32 client_ip = bpf_ntohl(original_conn.client_ip);

        update_metrics(METRIC_FROM_WG, METRIC_FORWARDED, pkt_len, bpf_ntohl(pkt.ip->saddr));
        return forward_packet(ctx, &pkt, proxy_ip, original_conn.server_port, client_ip, original_conn.client_port);
    }
    
    if (unlikely(is_to_wg)) {
        if (create_nat_connection(&pkt, config) < 0) {
            DEBUG_PRINTK("Failed to create NAT connection for TO WG packet");
            update_metrics(METRIC_TO_WG, METRIC_DROP, pkt_len, bpf_ntohl(pkt.ip->saddr));
            return XDP_PASS;
        }

        struct connection_key conn_key = {
            .client_ip = pkt.ip->saddr,
            .client_port = src_port,
            .server_ip = pkt.ip->daddr,
            .server_port = dst_port
        };

        struct connection_value *conn_value = bpf_map_lookup_elem(&connection_map, &conn_key);
        if (!conn_value) {
            DEBUG_PRINTK("No NAT connection found for client %pI4:%d -> server %pI4:%d, passing through",
                         &conn_key.client_ip, conn_key.client_port,
                         &conn_key.server_ip, conn_key.server_port);
            update_metrics(METRIC_TO_WG, METRIC_DROP, pkt_len, bpf_ntohl(pkt.ip->saddr));
            return XDP_PASS;
        }

        apply_obfuscation(&pkt, config);

        __u32 proxy_ip = bpf_ntohl(pkt.ip->daddr);
        __u32 server_ip = config->target_server_ip;

        update_metrics(METRIC_TO_WG, METRIC_FORWARDED, pkt_len, bpf_ntohl(pkt.ip->saddr));
        return forward_packet(ctx, &pkt, proxy_ip, conn_value->nat_port, server_ip, WG_PORT);
    }
    
    DEBUG_PRINTK("No matching handler for WG packet, passing through");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";