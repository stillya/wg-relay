#ifndef __PACKET_H__
#define __PACKET_H__

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#define WG_PORT 51820
#define MAX_PAYLOAD_SIZE 1400

// Common packet info structure for both XDP and TC contexts
struct packet_info {
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    void *payload;
    __u32 payload_len;
    __u16 src_port;
    __u16 dst_port;
    __u8 message_type;
};

// Parse XDP packet
static __always_inline int parse_xdp_packet(struct xdp_md *ctx, struct packet_info *pkt) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;    
    
    pkt->eth = data;
    if ((void *)(pkt->eth + 1) > data_end)
        return -1;
    
    if (pkt->eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    
    pkt->ip = (void *)(pkt->eth + 1);
    if ((void *)(pkt->ip + 1) > data_end)
        return -1;
    
    if (pkt->ip->protocol != IPPROTO_UDP)
        return -1;
    
    pkt->udp = (void *)pkt->ip + (pkt->ip->ihl * 4);
    if ((void *)(pkt->udp + 1) > data_end)
        return -1;
    
    pkt->src_port = bpf_ntohs(pkt->udp->source);
    pkt->dst_port = bpf_ntohs(pkt->udp->dest);
    
    pkt->payload = (void *)(pkt->udp + 1);
    if (pkt->payload > data_end)
        return -1;
    
    pkt->payload_len = data_end - pkt->payload;
    if (pkt->payload_len > MAX_PAYLOAD_SIZE)
        pkt->payload_len = MAX_PAYLOAD_SIZE;
    
    // it's shitty, don't read it, just to move forward
    if (pkt->payload_len > 0 && pkt->payload + 1 <= data_end) {
        __u8 *msg_type = pkt->payload;
        pkt->message_type = *msg_type;
    } else {
        pkt->message_type = 0;
    }
    
    return 0;
}

// Parse TC packet
static __always_inline int parse_tc_packet(struct __sk_buff *skb, struct packet_info *pkt) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;    
    
    pkt->eth = data;
    if ((void *)(pkt->eth + 1) > data_end)
        return -1;
    
    if (pkt->eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    
    pkt->ip = (void *)(pkt->eth + 1);
    if ((void *)(pkt->ip + 1) > data_end)
        return -1;
    
    if (pkt->ip->protocol != IPPROTO_UDP)
        return -1;
    
    pkt->udp = (void *)pkt->ip + (pkt->ip->ihl * 4);
    if ((void *)(pkt->udp + 1) > data_end)
        return -1;
    
    pkt->src_port = bpf_ntohs(pkt->udp->source);
    pkt->dst_port = bpf_ntohs(pkt->udp->dest);
    
    pkt->payload = (void *)(pkt->udp + 1);
    if (pkt->payload > data_end)
        return -1;
    
    pkt->payload_len = data_end - pkt->payload;
    if (pkt->payload_len > MAX_PAYLOAD_SIZE)
        pkt->payload_len = MAX_PAYLOAD_SIZE;
    
    // it's shitty, don't read it, just to move forward
    if (pkt->payload_len > 0 && pkt->payload + 1 <= data_end) {
        __u8 *msg_type = pkt->payload;
        pkt->message_type = *msg_type;
    } else {
        pkt->message_type = 0;
    }
    
    return 0;
}

static __always_inline int is_wireguard_packet(struct packet_info *pkt) {
    return (pkt->dst_port == WG_PORT || pkt->src_port == WG_PORT);
}

#endif // __PACKET_H__