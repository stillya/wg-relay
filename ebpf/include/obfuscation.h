#ifndef __OBFUSCATION_H__
#define __OBFUSCATION_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "packet.h"

#define OBFUSCATE_NONE 0
#define OBFUSCATE_XOR  1

#define MAX_KEY_SIZE 32

struct obfuscation_config {
    bool enabled;
    __u8 method;
    __u8 key[MAX_KEY_SIZE];
    __u8 key_len;
    __u32 target_server_ip; // Target WireGuard server IP (network byte order) - used by forward proxy only
};

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct obfuscation_config);
} obfuscation_config_map SEC(".maps");

static __always_inline int apply_obfuscation(void *data_end, struct packet_info *pkt, struct obfuscation_config *config) {
    if (!config || config->method == OBFUSCATE_NONE || config->key_len == 0) {
        return 0;
    }
    
    __u8 *payload = pkt->payload;
    if (payload + 16 > (__u8*)data_end) {
        DEBUG_PRINTK("Payload exceeds data_end\n");
        return -1;
    }
    
    __u32 process_len = config->key_len < 16 ? config->key_len : 16;
    
    // Apply XOR operation using key from config map (same for obfuscate/deobfuscate)
    #pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++) {
        payload[i] ^= config->key[i];
    }
    
    return 0;
}

#endif /* __OBFUSCATION_H__ */