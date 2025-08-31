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
#include "packet.h"
#include "metrics.h"
#include "obfuscation.h"

SEC("tc")
int wg_reverse_proxy(struct __sk_buff *skb) {
    // Ensure we have at least Ethernet + IP + UDP headers available (42 bytes)
    if (bpf_skb_pull_data(skb, 42) < 0) {
        DEBUG_PRINTK("Failed to pull packet data, passing through");
        return TC_ACT_OK;
    }

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        DEBUG_PRINTK("Packet too short for Ethernet header, passing through");
        return TC_ACT_OK;
    }
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        __u32 available_bytes = (__u32)((void *)data_end - (void *)ip);
        __u32 packet_len = skb->len;
        __u32 eth_proto = bpf_ntohs(eth->h_proto);
        __u32 data_len = (__u32)((void *)data_end - (void *)data);
        __u32 eth_len = (__u32)((void *)ip - (void *)data);
        DEBUG_PRINTK("Packet too short for IP header: available=%d bytes, needed=20 bytes, total_len=%d, eth_proto=0x%x, data_len=%d, eth_len=%d", 
                    available_bytes, packet_len, eth_proto, data_len, eth_len);
        return TC_ACT_OK;
    }

    if (ip_is_fragment(ip)) {
        DEBUG_PRINTK("Fragmented packet detected, passing through");
        return TC_ACT_OK;
    }
    
    if (ip->protocol != IPPROTO_UDP) {
        return TC_ACT_OK;
    }
    
    struct udphdr *udp = (void *)ip + (ip->ihl << 2);
    if ((void *)(udp + 1) > data_end) {
        DEBUG_PRINTK("Packet too short for UDP header, passing through");
        return TC_ACT_OK;
    }
    
    __u16 src_port = bpf_ntohs(udp->source);
    __u16 dst_port = bpf_ntohs(udp->dest);
    
    if (dst_port != WG_PORT && src_port != WG_PORT) {
        DEBUG_PRINTK("Not a WireGuard packet, passing through, src_port: %d, dst_port: %d", src_port, dst_port);
        return TC_ACT_OK;
    }
    
    __u32 config_key = 0;
    struct obfuscation_config *config = bpf_map_lookup_elem(&obfuscation_config_map, &config_key);
    if (!config || !config->enabled) {
        DEBUG_PRINTK("Config disabled or missing, passing through WG packet");
        return TC_ACT_OK;
    }
    
    __u8 is_to_wg = (dst_port == WG_PORT) ? 1 : 0;
    __u8 is_from_wg = (src_port == WG_PORT) ? 1 : 0;
        
    if (likely(is_from_wg)) {
        struct packet_info pkt = {};
        if (parse_tc_packet(skb, &pkt) < 0) {
            DEBUG_PRINTK("Failed to parse client FROM WG packet");
            update_metrics(METRIC_FROM_WG, METRIC_DROP, skb->len);
            return TC_ACT_OK;
        }
            
        if (config->method != OBFUSCATE_NONE && config->key_len > 0) {
            apply_obfuscation((void *)(long)skb->data_end, &pkt, config);
        }
        
        update_metrics(METRIC_FROM_WG, METRIC_FORWARDED, skb->len);
    }
    
    if (unlikely(is_to_wg)) {
        struct packet_info pkt = {};
        if (parse_tc_packet(skb, &pkt) < 0) {
            DEBUG_PRINTK("Failed to parse client TO WG packet");
            update_metrics(METRIC_TO_WG, METRIC_DROP, skb->len);
            return TC_ACT_OK;
        }
     
        if (config->method != OBFUSCATE_NONE && config->key_len > 0) {
            apply_obfuscation((void *)(long)skb->data_end, &pkt, config);
        }

        update_metrics(METRIC_TO_WG, METRIC_FORWARDED, skb->len);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";