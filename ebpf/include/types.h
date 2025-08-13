#ifndef __TYPES_H__
#define __TYPES_H__

#define MAX_KEY_SIZE 32

struct obfuscation_config {
    __u32 enabled;
    __u32 method;
    __u8 key[MAX_KEY_SIZE];
    __u32 key_len;
    __u32 target_server_ip; // Target WireGuard server IP (network byte order) - used by forward proxy only
};

struct wg_packet_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 message_type;
    __u32 packet_len;
    __u8 obfuscated;
};

#endif // __TYPES_H__