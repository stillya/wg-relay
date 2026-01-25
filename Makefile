include Makefile.defs

SUBDIRS = ebpf

.PHONY: help all build clean run-daemon run-forward-proxy run-reverse-proxy run-local-forward run-local-reverse run-local-probe test-ebpf test $(SUBDIRS)

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
	@echo "  run-local-forward     - Run forward proxy in ebpf-proxy namespace"
	@echo "  run-local-reverse     - Run reverse proxy + probe server in wg-server namespace"
	@echo "  run-local-probe-only  - Run probe server only (see obfuscated packets)"
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
	@echo "Running wg-relay daemon..."
	@echo "Note: This requires root privileges for eBPF operations"
	@echo "Press Ctrl+C to stop"
	sudo ./$(BUILD_DIR)/$(DAEMON_BINARY) -c config.yaml

run-local-forward: build
	@echo "Running forward proxy daemon in ebpf-proxy namespace..."
	@echo "Note: This requires root privileges and namespace setup"
	@echo "Press Ctrl+C to stop"
	sudo ip netns exec ebpf-proxy ./$(BUILD_DIR)/$(DAEMON_BINARY) -c hack/config-forward.yaml -d

run-local-reverse: build
	@echo "Running reverse proxy daemon + probe server in wg-server namespace..."
	@echo "Note: This requires root privileges and namespace setup"
	@echo "Press Ctrl+C to stop both daemon and probe server"
	@bash -c '\
		sudo ip netns exec wg-server bash -c "./$(BUILD_DIR)/$(DAEMON_BINARY) -c hack/config-reverse.yaml -d & echo \$$! > /tmp/wg-relay-reverse.pid; wait" & \
		DAEMON_BG_PID=$$!; \
		sleep 3; \
		cleanup() { \
			echo ""; \
			echo "Shutting down daemon..."; \
			if [ -f /tmp/wg-relay-reverse.pid ]; then \
				DPID=$$(cat /tmp/wg-relay-reverse.pid 2>/dev/null); \
				if [ ! -z "$$DPID" ]; then \
					sudo kill $$DPID 2>/dev/null || true; \
				fi; \
				rm -f /tmp/wg-relay-reverse.pid; \
			fi; \
			wait $$DAEMON_BG_PID 2>/dev/null || true; \
		}; \
		trap cleanup EXIT; \
		sudo ip netns exec wg-server python3 hack/wgprobe.py --server || true; \
		cleanup'

run-local-probe:
	@echo "Running probe server in wg-server namespace (without daemon)..."
	@echo "This shows obfuscated packets before deobfuscation"
	@echo "Note: Use with 'make run-local-forward' to see obfuscated traffic"
	@echo "Press Ctrl+C to stop"
	sudo ip netns exec wg-server python3 hack/wgprobe.py --server

test-ebpf: all
	@echo "Running eBPF unit tests..."
	@echo "Note: This requires root privileges for eBPF operations"
	$(QUIET)sudo -E $(GO) test -v ./ebpf/

test: all
	@echo "Running tests with coverage..."
	$(QUIET)sudo -E $(GO) test -v -coverprofile=covprofile ./...
