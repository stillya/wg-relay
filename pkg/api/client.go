package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
)

type Client struct {
	socketPath string
	timeout    time.Duration
}

func NewClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	return &Client{
		socketPath: socketPath,
		timeout:    30 * time.Second,
	}
}

func (c *Client) sendRequest(ctx context.Context, req *Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to daemon")
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(c.timeout))

	data, err := json.Marshal(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal request")
	}

	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		return nil, errors.Wrap(err, "failed to send request")
	}

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, errors.Wrap(err, "failed to read response")
		}
		return nil, errors.New("no response from daemon")
	}

	var resp Response
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal response")
	}

	return &resp, nil
}

func (c *Client) Enable(ctx context.Context, configPath string) error {
	req := &Request{
		Command:    CommandEnable,
		ConfigPath: configPath,
	}

	resp, err := c.sendRequest(ctx, req)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("enable failed: %s", resp.Error)
	}

	return nil
}

func (c *Client) Disable(ctx context.Context) error {
	req := &Request{
		Command: CommandDisable,
	}

	resp, err := c.sendRequest(ctx, req)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("disable failed: %s", resp.Error)
	}

	return nil
}

func (c *Client) Reload(ctx context.Context, configPath string) error {
	req := &Request{
		Command:    CommandReload,
		ConfigPath: configPath,
	}

	resp, err := c.sendRequest(ctx, req)
	if err != nil {
		return err
	}

	if !resp.Success {
		return fmt.Errorf("reload failed: %s", resp.Error)
	}

	return nil
}

func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	req := &Request{
		Command: CommandStatus,
	}

	resp, err := c.sendRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("status failed: %s", resp.Error)
	}

	data, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal status data")
	}

	var status StatusResponse
	if err := json.Unmarshal(data, &status); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal status")
	}

	return &status, nil
}

func (c *Client) Stats(ctx context.Context) (*StatsResponse, error) {
	req := &Request{
		Command: CommandStats,
	}

	resp, err := c.sendRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("stats failed: %s", resp.Error)
	}

	data, err := json.Marshal(resp.Data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal stats data")
	}

	var stats StatsResponse
	if err := json.Unmarshal(data, &stats); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal stats")
	}

	return &stats, nil
}
