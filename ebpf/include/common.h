#ifndef __COMMON_H__
#define __COMMON_H__

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef __maybe_unused
#define __maybe_unused __attribute__((__unused__))
#endif

#ifndef EEXIST
#define EEXIST 17 // File exists error code, used for BPF map updates
#endif

// Macros not available in vmlinux.h (only type/enum definitions come from BTF)
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

#ifndef likely
#define likely(X) __builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
#define unlikely(X) __builtin_expect(!!(X), 0)
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define DEBUG_PRINTK(fmt, ...) bpf_printk("DEBUG %s:%d " fmt, __func__, __LINE__, ##__VA_ARGS__)

// IP fragmentation flags (from linux/ip.h)
#define IP_RF	  0x8000 /* reserved fragment flag */
#define IP_DF	  0x4000 /* dont fragment flag */
#define IP_MF	  0x2000 /* more fragments flag */
#define IP_OFFSET 0x1FFF /* mask for fragment offset bits */

#endif // __COMMON_H__
