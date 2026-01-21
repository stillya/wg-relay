#ifndef __INSTRUMENTATION_XOR_H__
#define __INSTRUMENTATION_XOR_H__

#include "common.h"
#include "context.h"
#include "static_config.h"

struct xor_key {
	__u8 key[32];
};

DECLARE_CONFIG(bool, xor_enabled, "Enable XOR obfuscation");
DECLARE_CONFIG(struct xor_key, xor_key, "XOR obfuscation key");

#define XOR_PROCESS_LEN 16

static __always_inline int __xor_process(struct wg_ctx *ctx) {
	if (!CONFIG(xor_enabled)) {
		return 0;
	}

	__u8 *payload = ctx->payload;
	if (payload + XOR_PROCESS_LEN > (__u8 *)ctx->payload_end) {
		return -1;
	}

	// Apply XOR with static key
	struct xor_key key = CONFIG(xor_key);
#pragma clang loop unroll(full)
	for (int i = 0; i < XOR_PROCESS_LEN; i++) {
		payload[i] ^= key.key[i];
	}

	return 0;
}

// XOR is symmetric
static __always_inline __maybe_unused int xor_obfuscate_xdp(struct wg_ctx *ctx) {
	return __xor_process(ctx);
}

static __always_inline __maybe_unused int xor_deobfuscate_xdp(struct wg_ctx *ctx) {
	return __xor_process(ctx);
}

static __always_inline __maybe_unused int xor_obfuscate_tc(struct wg_ctx *ctx) {
	return __xor_process(ctx);
}

static __always_inline __maybe_unused int xor_deobfuscate_tc(struct wg_ctx *ctx) {
	return __xor_process(ctx);
}

#endif /* __INSTRUMENTATION_XOR_H__ */
