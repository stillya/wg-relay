//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "include/common.h"
#include "include/types.h"
#include "include/csum.h"
#include "include/packet.h"
#include "include/maps.h"
#include "include/metrics.h"
#include "include/obfuscation.h"

SEC("tc")
int wg_reverse_proxy(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;
    
    struct udphdr *udp = (void *)ip + (ip->ihl << 2);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;
    
    __u16 src_port = bpf_ntohs(udp->source);
    __u16 dst_port = bpf_ntohs(udp->dest);
    
    if (dst_port != WG_PORT && src_port != WG_PORT) {
        DEBUG_PRINTK("Not a WireGuard packet, passing through");
        return TC_ACT_OK;
    }
    DEBUG_PRINTK("WireGuard packet detected: src_port=%u, dst_port=%u", src_port, dst_port);
    
    __u32 config_key = 0;
    struct obfuscation_config *config = bpf_map_lookup_elem(&obfuscation_config_map, &config_key);
    if (!config || !config->enabled) {
        DEBUG_PRINTK("Config disabled or missing, passing through WG packet");
        return TC_ACT_OK;
    }
    
    __u8 is_to_wg = (dst_port == WG_PORT) ? 1 : 0;
    __u8 is_from_wg = (src_port == WG_PORT) ? 1 : 0;
        
    if (is_from_wg) {
        increment_stat(STAT_FROM_WG_PACKETS);
        struct packet_info pkt = {};
        if (parse_tc_packet(skb, &pkt) < 0) {
            DEBUG_PRINTK("Failed to parse client FROM WG packet");
            return TC_ACT_OK;
        }
            
        if (config->method != OBFUSCATE_NONE && config->key_len > 0) {
            apply_obfuscation((void *)(long)skb->data_end, &pkt, config);
        }
    }
    
    if (is_to_wg) {
        increment_stat(STAT_TO_WG_PACKETS);
        struct packet_info pkt = {};
        if (parse_tc_packet(skb, &pkt) < 0) {
            DEBUG_PRINTK("Failed to parse client TO WG packet");
            return TC_ACT_OK;
        }
            
        if (config->method != OBFUSCATE_NONE && config->key_len > 0) {
            apply_obfuscation((void *)(long)skb->data_end, &pkt, config);
        }
    }
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";