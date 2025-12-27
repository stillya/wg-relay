.PHONY: help build build-agent build-cli clean run-agent test-ebpf test

# Variables
AGENT_BINARY := wg-relay-agent
CLI_BINARY := wg-relay
BUILD_DIR := .bin
EBPF_DIR := ebpf
REV := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

help:
	@echo "WireGuard Relay - Available targets:"
	@echo "  build             - Build agent and CLI binaries"
	@echo "  build-agent       - Generate eBPF bindings and build the agent"
	@echo "  build-cli         - Build the CLI client"
	@echo "  generate          - Generate all code (eBPF bindings, mocks)"
	@echo "  clean             - Clean generated files and build artifacts"
	@echo "  run-agent         - Build and run the agent"
	@echo "  run-forward-proxy - Run forward proxy in ebpf-proxy namespace (legacy testing)"
	@echo "  run-reverse-proxy - Run reverse proxy in wg-server namespace (legacy testing)"
	@echo "  test-ebpf         - Run eBPF unit tests"
	@echo "  test              - Run all tests"

build: build-agent build-cli

build-agent:
	@echo "Generating eBPF Go bindings..."
	go generate ./$(EBPF_DIR)
	@echo "Building $(AGENT_BINARY)..."
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(AGENT_BINARY) ./cmd/agent
	@echo "Build completed: $(BUILD_DIR)/$(AGENT_BINARY)"

build-cli:
	@echo "Building $(CLI_BINARY)..."
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(CLI_BINARY) ./cmd/cli
	@echo "Build completed: $(BUILD_DIR)/$(CLI_BINARY)"

clean:
	@echo "Cleaning generated files..."
	rm -f $(EBPF_DIR)/wgforwardproxy_bpf*.o
	rm -f $(EBPF_DIR)/wgreverseproxy_bpf*.o
	rm -rf $(BUILD_DIR)
	@echo "Clean completed"

run-agent: build-agent
	@echo "Running wg-relay-agent..."
	@echo "Note: This requires root privileges for eBPF operations"
	@echo "Agent will start in disabled state - use 'wg-relay enable' to activate"
	@echo "Press Ctrl+C to stop"
	sudo ./$(BUILD_DIR)/$(AGENT_BINARY)

test-ebpf: build
	@echo "Running eBPF unit tests..."
	@echo "Note: This requires root privileges for eBPF operations"
	sudo -E go test -v ./$(EBPF_DIR)/

test: build
	@echo "Running tests with coverage..."
	sudo -E go test -v -coverprofile=covprofile ./...
