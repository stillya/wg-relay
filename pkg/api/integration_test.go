package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestServer(t *testing.T) (string, *Server, *ControlHandlerMock, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("/tmp", "wg-relay-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	socketPath := filepath.Join(tmpDir, "test.sock")

	controller := &ControlHandlerMock{
		HandleEnableFunc: func(ctx context.Context, args EnableArgs) error {
			return nil
		},
		HandleDisableFunc: func(ctx context.Context) error {
			return nil
		},
		HandleReloadFunc: func(ctx context.Context, args ReloadArgs) error {
			return nil
		},
		GetStatusFunc: func(ctx context.Context) (*StatusResponse, error) {
			return &StatusResponse{
				State:  StateDisabled,
				Uptime: 5 * time.Second,
			}, nil
		},
		GetStatsFunc: func(ctx context.Context) (*StatsResponse, error) {
			return &StatsResponse{
				Metrics: []MetricData{},
				Uptime:  5 * time.Second,
			}, nil
		},
	}

	server, err := NewServer(socketPath, controller)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := server.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Failed to start server: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		cancel()
		server.Stop()
		os.RemoveAll(tmpDir)
	}

	return socketPath, server, controller, cleanup
}

func TestClientServer_Enable(t *testing.T) {
	socketPath, _, controller, cleanup := setupTestServer(t)
	defer cleanup()

	client := NewClient(socketPath)
	ctx := context.Background()

	err := client.Enable(ctx, "/etc/test-config.yaml")
	if err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	if len(controller.HandleEnableCalls()) != 1 {
		t.Fatalf("Expected HandleEnable to be called once, got %d calls", len(controller.HandleEnableCalls()))
	}

	call := controller.HandleEnableCalls()[0]
	if call.Args.ConfigPath != "/etc/test-config.yaml" {
		t.Errorf("Expected config path '/etc/test-config.yaml', got '%s'", call.Args.ConfigPath)
	}
}

func TestClientServer_EnableEmptyConfig(t *testing.T) {
	socketPath, _, controller, cleanup := setupTestServer(t)
	defer cleanup()

	client := NewClient(socketPath)
	ctx := context.Background()

	err := client.Enable(ctx, "")
	if err != nil {
		t.Fatalf("Enable with empty config failed: %v", err)
	}

	if len(controller.HandleEnableCalls()) != 1 {
		t.Fatalf("Expected HandleEnable to be called once, got %d calls", len(controller.HandleEnableCalls()))
	}

	call := controller.HandleEnableCalls()[0]
	if call.Args.ConfigPath != "" {
		t.Errorf("Expected empty config path, got '%s'", call.Args.ConfigPath)
	}
}

func TestClientServer_Disable(t *testing.T) {
	socketPath, _, controller, cleanup := setupTestServer(t)
	defer cleanup()

	client := NewClient(socketPath)
	ctx := context.Background()

	err := client.Disable(ctx)
	if err != nil {
		t.Fatalf("Disable failed: %v", err)
	}

	if len(controller.HandleDisableCalls()) != 1 {
		t.Fatalf("Expected HandleDisable to be called once, got %d calls", len(controller.HandleDisableCalls()))
	}
}

func TestClientServer_Reload(t *testing.T) {
	socketPath, _, controller, cleanup := setupTestServer(t)
	defer cleanup()

	client := NewClient(socketPath)
	ctx := context.Background()

	err := client.Reload(ctx, "/etc/new-config.yaml")
	if err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	if len(controller.HandleReloadCalls()) != 1 {
		t.Fatalf("Expected HandleReload to be called once, got %d calls", len(controller.HandleReloadCalls()))
	}

	call := controller.HandleReloadCalls()[0]
	if call.Args.ConfigPath != "/etc/new-config.yaml" {
		t.Errorf("Expected config path '/etc/new-config.yaml', got '%s'", call.Args.ConfigPath)
	}
}

func TestClientServer_Status(t *testing.T) {
	socketPath, _, controller, cleanup := setupTestServer(t)
	defer cleanup()

	controller.GetStatusFunc = func(ctx context.Context) (*StatusResponse, error) {
		return &StatusResponse{
			State:      StateEnabled,
			Mode:       "forward",
			Interfaces: []string{"eth0", "eth1"},
			Uptime:     10 * time.Minute,
		}, nil
	}

	client := NewClient(socketPath)
	ctx := context.Background()

	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}

	if status.State != StateEnabled {
		t.Errorf("Expected state 'enabled', got '%s'", status.State)
	}

	if status.Mode != "forward" {
		t.Errorf("Expected mode 'forward', got '%s'", status.Mode)
	}

	if len(status.Interfaces) != 2 {
		t.Errorf("Expected 2 interfaces, got %d", len(status.Interfaces))
	}

	if status.Uptime != 10*time.Minute {
		t.Errorf("Expected uptime 10m, got %v", status.Uptime)
	}
}

func TestClientServer_Stats(t *testing.T) {
	socketPath, _, controller, cleanup := setupTestServer(t)
	defer cleanup()

	controller.GetStatsFunc = func(ctx context.Context) (*StatsResponse, error) {
		return &StatsResponse{
			Metrics: []MetricData{
				{
					Direction: "from_wg",
					Reason:    "forwarded",
					SrcAddr:   "192.168.1.1",
					Packets:   100,
					Bytes:     5000,
				},
				{
					Direction: "to_wg",
					Reason:    "forwarded",
					SrcAddr:   "192.168.1.1",
					Packets:   50,
					Bytes:     2500,
				},
			},
			Uptime: 5 * time.Minute,
		}, nil
	}

	client := NewClient(socketPath)
	ctx := context.Background()

	stats, err := client.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats failed: %v", err)
	}

	if len(stats.Metrics) != 2 {
		t.Errorf("Expected 2 metrics, got %d", len(stats.Metrics))
	}

	if stats.Metrics[0].Direction != "from_wg" {
		t.Errorf("Expected direction 'from_wg', got '%s'", stats.Metrics[0].Direction)
	}

	if stats.Metrics[0].Packets != 100 {
		t.Errorf("Expected 100 packets, got %d", stats.Metrics[0].Packets)
	}

	if stats.Uptime != 5*time.Minute {
		t.Errorf("Expected uptime 5m, got %v", stats.Uptime)
	}
}

func TestClientServer_MultipleClients(t *testing.T) {
	socketPath, _, controller, cleanup := setupTestServer(t)
	defer cleanup()

	client1 := NewClient(socketPath)
	client2 := NewClient(socketPath)
	ctx := context.Background()

	err1 := client1.Enable(ctx, "/etc/config1.yaml")
	if err1 != nil {
		t.Fatalf("Client1 enable failed: %v", err1)
	}

	err2 := client2.Disable(ctx)
	if err2 != nil {
		t.Fatalf("Client2 disable failed: %v", err2)
	}

	if len(controller.HandleEnableCalls()) != 1 {
		t.Errorf("Expected HandleEnable to be called once, got %d calls", len(controller.HandleEnableCalls()))
	}

	if len(controller.HandleDisableCalls()) != 1 {
		t.Errorf("Expected HandleDisable to be called once, got %d calls", len(controller.HandleDisableCalls()))
	}
}

func TestClientServer_ServerNotRunning(t *testing.T) {
	tmpDir, err := os.MkdirTemp("/tmp", "wg-relay-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	socketPath := filepath.Join(tmpDir, "nonexistent.sock")

	client := NewClient(socketPath)
	ctx := context.Background()

	err = client.Enable(ctx, "/etc/test.yaml")
	if err == nil {
		t.Error("Expected error when server is not running, got nil")
	}
}

func TestClientServer_InvalidCommand(t *testing.T) {
	_, server, _, cleanup := setupTestServer(t)
	defer cleanup()

	ctx := context.Background()
	req := &Request{
		Command: "invalid",
	}

	resp := server.handleRequest(ctx, req)
	if resp.Success {
		t.Error("Expected failure for invalid command")
	}

	if resp.Error == "" {
		t.Error("Expected error message for invalid command")
	}
}
