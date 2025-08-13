#ifndef __COMMON_H__
#define __COMMON_H__

#ifndef EEXIST
#define EEXIST 17  // File exists error code, used for BPF map updates
#endif

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define DEBUG_PRINTK(fmt, ...) \
    bpf_printk("DEBUG %s:%d " fmt, __func__, __LINE__, ##__VA_ARGS__)

#endif // __COMMON_H__