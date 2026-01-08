#ifndef __CSUM_H__
#define __CSUM_H__

#include <linux/types.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

static __always_inline __u16 csum_fold_helper(__u64 csum) {
    int i;
    for (i = 0; i < 4; i++) {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u32 csum_add(__u32 csum, __u32 addend) {
    __u32 res = csum;
    res += addend;
    return (res + (res < addend));
}

static __always_inline __u32 csum_sub(__u32 csum, __u32 addend) {
    return csum_add(csum, ~addend);
}

__attribute__((unused))
static __always_inline __u16 csum_diff4(__u32 from, __u32 to, __u16 oldsum) {
    __u32 csum = ~oldsum & 0xffff;
    csum = csum_sub(csum, from >> 16);
    csum = csum_sub(csum, from & 0xffff);
    csum = csum_add(csum, to >> 16);
    csum = csum_add(csum, to & 0xffff);
    return csum_fold_helper(csum);
}

__attribute__((unused))
static __always_inline __u16 iph_csum(struct iphdr *iph) {
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

#endif // __CSUM_H__
