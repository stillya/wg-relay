#ifndef __STATIC_CONFIG_H__
#define __STATIC_CONFIG_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "common.h"

// Helper to stringify tokens
#ifndef __stringify_1
#define __stringify_1(x...) #x
#endif
#ifndef __stringify
#define __stringify(x...) __stringify_1(x)
#endif

// Declare a static config variable in .rodata section
// Usage: DECLARE_CONFIG(bool, instrumentation_enabled, "Enable packet obfuscation");
#define DECLARE_CONFIG(type, name, description)                                                                        \
	__attribute__((section(".rodata.config"), used)) __attribute__((btf_decl_tag("kind:config")))                  \
	__attribute__((btf_decl_tag(description))) volatile const type __cfg_##name

// Access a static config variable
// Usage: if (CONFIG(instrumentation_enabled)) { ... }
#define CONFIG(name)                                                                                                   \
	(*({                                                                                                           \
		void *ptr;                                                                                             \
		asm volatile("%0 = " __stringify(__cfg_##name) " ll" : "=r"(ptr));                                     \
		(typeof(__cfg_##name) *)ptr;                                                                           \
	}))

#endif /* __STATIC_CONFIG_H__ */
