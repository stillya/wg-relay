include Makefile.defs

SUBDIRS = ebpf

.PHONY: help all build clean run-daemon run-forward-proxy run-reverse-proxy test-ebpf test $(SUBDIRS)

# Variables
DAEMON_BINARY := wg-relay-daemon
BUILD_DIR := .bin
REV := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

help:
	@echo "WireGuard Relay - Available targets:"
	@echo "  all                   - Build eBPF programs and generate Go bindings"
	@echo "  build                 - Build the daemon"
	@echo "  clean                 - Clean generated files and build artifacts"
	@echo "  run-daemon            - Build and run the daemon with default config"
	@echo "  run-forward-proxy     - Run forward proxy in ebpf-proxy namespace"
	@echo "  run-reverse-proxy     - Run reverse proxy in wg-server namespace"
	@echo "  test-ebpf             - Run eBPF unit tests"
	@echo "  test                  - Run all tests"

$(SUBDIRS):
	$(QUIET)$(MAKE) -C $@ all

all: $(SUBDIRS)

build: all
	@echo "Building $(DAEMON_BINARY)..."
	$(QUIET)mkdir -p $(BUILD_DIR)
	$(QUIET)$(GO_BUILD) -ldflags "-X main.version=$(REV) -s -w" -o $(BUILD_DIR)/$(DAEMON_BINARY) ./cmd/daemon
	@echo "Build completed: $(BUILD_DIR)/$(DAEMON_BINARY)"

clean:
	@$(ECHO_CLEAN)
	$(QUIET)$(MAKE) -C ebpf clean
	$(QUIET)rm -rf $(BUILD_DIR)

run-daemon: build
	@echo "Running wg-proxy daemon..."
	@echo "Note: This requires root privileges for eBPF operations"
	@echo "Press Ctrl+C to stop"
	sudo ./$(BUILD_DIR)/$(DAEMON_BINARY) -c config.yaml

run-local-forward: build
	@echo "Running forward proxy daemon in ebpf-proxy namespace..."
	@echo "Note: This requires root privileges and namespace setup"
	@echo "Press Ctrl+C to stop"
	sudo ip netns exec ebpf-proxy ./$(BUILD_DIR)/$(DAEMON_BINARY) -c config.yaml -d

run-local-reverse: build
	@echo "Running reverse proxy daemon in wg-server namespace..."
	@echo "Note: This requires root privileges and namespace setup"
	@echo "Press Ctrl+C to stop"
	sudo ip netns exec wg-server ./$(BUILD_DIR)/$(DAEMON_BINARY) -c config.yaml -d

test-ebpf: all
	@echo "Running eBPF unit tests..."
	@echo "Note: This requires root privileges for eBPF operations"
	$(QUIET)sudo -E $(GO) test -v ./ebpf/

test: all
	@echo "Running tests with coverage..."
	$(QUIET)sudo -E $(GO) test -v -coverprofile=covprofile ./...
