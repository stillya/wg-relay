.PHONY: help build clean run-daemon run-forward-proxy run-reverse-proxy

# Variables
DAEMON_BINARY := wg-relay-daemon
BUILD_DIR := .bin
EBPF_DIR := ebpf
REV := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

help:
	@echo "WireGuard Relay - Available targets:"
	@echo "  build             - Generate eBPF bindings and build the daemon"
	@echo "  clean             - Clean generated files and build artifacts"
	@echo "  run-daemon        - Build and run the daemon with default config"
	@echo "  run-forward-proxy - Run forward proxy in ebpf-proxy namespace"
	@echo "  run-reverse-proxy - Run reverse proxy in wg-server namespace"

build:
	@echo "Generating eBPF Go bindings..."
	go generate ./$(EBPF_DIR)
	@echo "Building $(DAEMON_BINARY)..."
	mkdir -p $(BUILD_DIR)
	go build -ldflags "-X main.version=$(REV) -s -w" -o $(BUILD_DIR)/$(DAEMON_BINARY) ./cmd/daemon
	@echo "Build completed: $(BUILD_DIR)/$(DAEMON_BINARY)"

clean:
	@echo "Cleaning generated files..."
	rm -f $(EBPF_DIR)/wgforwardproxy_bpf*.o
	rm -f $(EBPF_DIR)/wgreverseproxy_bpf*.o
	rm -rf $(BUILD_DIR)
	@echo "Clean completed"

run-daemon: build
	@echo "Running wg-proxy daemon..."
	@echo "Note: This requires root privileges for eBPF operations"
	@echo "Press Ctrl+C to stop"
	sudo ./$(BUILD_DIR)/$(DAEMON_BINARY) -c config.yaml

run-local-forward: build
	@echo "Running forward proxy daemon in ebpf-proxy namespace..."
	@echo "Note: This requires root privileges and namespace setup"
	@echo "Press Ctrl+C to stop"
	sudo ip netns exec ebpf-proxy ./$(BUILD_DIR)/$(DAEMON_BINARY) -c config.yaml

run-local-reverse: build
	@echo "Running reverse proxy daemon in wg-server namespace..."
	@echo "Note: This requires root privileges and namespace setup"
	@echo "Press Ctrl+C to stop"
	sudo ip netns exec wg-server ./$(BUILD_DIR)/$(DAEMON_BINARY) -c config.yaml
