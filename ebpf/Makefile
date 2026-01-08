include ../Makefile.defs

BPF := wg_forward_proxy.o wg_reverse_proxy.o
LIB := $(wildcard include/*.h)

CLANG ?= clang
LLC ?= llc

FLAGS := -Iinclude -O2 -g
FLAGS += -D__BPF_TRACING__

CLANG_FLAGS := $(FLAGS)
CLANG_FLAGS += --target=bpf
CLANG_FLAGS += -std=gnu99
CLANG_FLAGS += -Wall -Wextra -Werror
CLANG_FLAGS += -Wno-unknown-attributes
CLANG_FLAGS += -Wno-address-of-packed-member
CLANG_FLAGS += -Wno-gnu-variable-sized-type-not-at-end
CLANG_FLAGS += -Wno-compare-distinct-pointer-types

LLC_FLAGS := -march=bpf -mcpu=v3 -filetype=obj

# Disable built-in implicit rules
.SUFFIXES:

.PHONY: all generate clean gen_compile_commands

all: generate

generate: $(BPF)
	@$(ECHO_GEN)
	$(QUIET)$(GO_GENERATE) .

wg_forward_proxy.o:: wg_forward_proxy.c $(LIB)

wg_reverse_proxy.o:: wg_reverse_proxy.c $(LIB)

%.ll: %.c
	@$(ECHO_CC)
	$(QUIET)$(CLANG) $(CLANG_FLAGS) -emit-llvm -c $< -o $@

%.o: %.ll
	@$(ECHO_LLC)
	$(QUIET)$(LLC) $(LLC_FLAGS) -o $@ $<

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f *.o *.ll
	$(QUIET)rm -f *_bpfel.o *_bpfeb.o

gen_compile_commands:
	@echo "Generating compile_commands.json for eBPF programs..."
	@command -v bear >/dev/null 2>&1 || { echo "Error: 'bear' is not installed. Make sure bear is in your PATH."; exit 1; }
	$(QUIET)bear -- $(MAKE) all
	@echo "compile_commands.json generated"
