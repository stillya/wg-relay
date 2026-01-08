//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "csum.h"
#include "packet.h"
#include "metrics.h"
#include "obfuscation.h"

SEC("tc")
int wg_reverse_proxy(struct __sk_buff *skb) {
    struct packet_info pkt = {};
    if (parse_tc_packet(skb, &pkt) < 0)
        return TC_ACT_OK;

    __u16 src_port = bpf_ntohs(pkt.udp->source);
    __u16 dst_port = bpf_ntohs(pkt.udp->dest);
    if (dst_port != WG_PORT && src_port != WG_PORT)
        return TC_ACT_OK;

    __u32 config_key = 0;
    struct obfuscation_config *config = bpf_map_lookup_elem(&obfuscation_config_map, &config_key);
    if (!config || !config->enabled) {
        DEBUG_PRINTK("Config disabled or missing, passing through WG packet");
        return TC_ACT_OK;
    }

    __u8 is_to_wg = (dst_port == WG_PORT) ? 1 : 0;
    __u8 is_from_wg = (src_port == WG_PORT) ? 1 : 0;

    if (likely(is_from_wg)) {
        if (config->method != OBFUSCATE_NONE && config->key_len > 0) {
            apply_obfuscation(&pkt, config);
        }

        update_metrics(METRIC_FROM_WG, METRIC_FORWARDED, skb->len, bpf_ntohl(pkt.ip->daddr));
    }

    if (unlikely(is_to_wg)) {
        if (config->method != OBFUSCATE_NONE && config->key_len > 0) {
            apply_obfuscation(&pkt, config);
        }

        update_metrics(METRIC_TO_WG, METRIC_FORWARDED, skb->len, bpf_ntohl(pkt.ip->saddr));
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
