#ifndef __OBFUSCATION_H__
#define __OBFUSCATION_H__

#include "packet.h"
#include "types.h"

#define OBFUSCATE_NONE 0
#define OBFUSCATE_XOR  1

static __always_inline int apply_obfuscation(void *data_end, struct packet_info *pkt, struct obfuscation_config *config) {
    if (!config || config->method == OBFUSCATE_NONE || config->key_len == 0) {
        return 0;
    }
    
    __u8 *payload = pkt->payload;
    if (payload + 16 > (__u8*)data_end)
        return -1;
    
    __u32 process_len = config->key_len < 16 ? config->key_len : 16;
    
    // Apply XOR operation using key from config map (same for obfuscate/deobfuscate)
    #pragma clang loop unroll(full)
    for (int i = 0; i < 16; i++) {
        if (i < process_len) {
            payload[i] ^= config->key[i];
        }
    }
    
    return 0;
}

#endif /* __OBFUSCATION_H__ */