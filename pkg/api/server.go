package api

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	log "log/slog"

	"github.com/pkg/errors"
)

const (
	DefaultSocketPath = "/var/run/wg-relay/control.sock"
	SocketDirMode     = 0755
	SocketFileMode    = 0600
)

//go:generate moq -out controlhandler_mock.go -fmt goimports . ControlHandler
type ControlHandler interface {
	HandleEnable(ctx context.Context, args EnableArgs) error
	HandleDisable(ctx context.Context) error
	HandleReload(ctx context.Context, args ReloadArgs) error
	GetStatus(ctx context.Context) (*StatusResponse, error)
	GetStats(ctx context.Context) (*StatsResponse, error)
}

type Server struct {
	socketPath string
	handler    ControlHandler
	listener   net.Listener
	mu         sync.Mutex
	running    bool
}

func NewServer(socketPath string, handler ControlHandler) (*Server, error) {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	return &Server{
		socketPath: socketPath,
		handler:    handler,
	}, nil
}

func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("server already running")
	}
	s.mu.Unlock()

	if err := os.RemoveAll(s.socketPath); err != nil {
		return errors.Wrap(err, "failed to remove existing socket")
	}

	socketDir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(socketDir, SocketDirMode); err != nil {
		return errors.Wrap(err, "failed to create socket directory")
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return errors.Wrap(err, "failed to listen on unix socket")
	}

	if err := os.Chmod(s.socketPath, SocketFileMode); err != nil {
		listener.Close()
		return errors.Wrap(err, "failed to set socket permissions")
	}

	s.mu.Lock()
	s.listener = listener
	s.running = true
	s.mu.Unlock()

	log.Info("Control API server started", "socket", s.socketPath)

	go s.acceptLoop(ctx)

	return nil
}

func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.running = false

	if s.listener != nil {
		s.listener.Close()
	}

	os.RemoveAll(s.socketPath)

	log.Info("Control API server stopped")

	return nil
}

func (s *Server) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			running := s.running
			s.mu.Unlock()

			if !running {
				return
			}

			log.Error("Accept error", "error", err)
			continue
		}

		go s.handleConnection(ctx, conn)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			log.Error("Failed to read request", "error", err)
		}
		return
	}

	var req Request
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		s.sendResponse(conn, Response{
			Success: false,
			Error:   fmt.Sprintf("invalid request: %v", err),
		})
		return
	}

	resp := s.handleRequest(ctx, &req)
	s.sendResponse(conn, resp)
}

func (s *Server) handleRequest(ctx context.Context, req *Request) Response {
	log.Info("Received command", "command", req.Command, "config_path", req.ConfigPath)

	switch req.Command {
	case CommandEnable:
		if err := s.handler.HandleEnable(ctx, EnableArgs{ConfigPath: req.ConfigPath}); err != nil {
			return Response{
				Success: false,
				Error:   err.Error(),
			}
		}
		return Response{Success: true}

	case CommandDisable:
		if err := s.handler.HandleDisable(ctx); err != nil {
			return Response{
				Success: false,
				Error:   err.Error(),
			}
		}
		return Response{Success: true}

	case CommandReload:
		if err := s.handler.HandleReload(ctx, ReloadArgs{ConfigPath: req.ConfigPath}); err != nil {
			return Response{
				Success: false,
				Error:   err.Error(),
			}
		}
		return Response{Success: true}

	case CommandStatus:
		status, err := s.handler.GetStatus(ctx)
		if err != nil {
			return Response{
				Success: false,
				Error:   err.Error(),
			}
		}
		return Response{
			Success: true,
			Data:    status,
		}

	case CommandStats:
		stats, err := s.handler.GetStats(ctx)
		if err != nil {
			return Response{
				Success: false,
				Error:   err.Error(),
			}
		}
		return Response{
			Success: true,
			Data:    stats,
		}

	default:
		return Response{
			Success: false,
			Error:   fmt.Sprintf("unknown command: %s", req.Command),
		}
	}
}

func (s *Server) sendResponse(conn net.Conn, resp Response) {
	data, err := json.Marshal(resp)
	if err != nil {
		log.Error("Failed to marshal response", "error", err)
		return
	}

	data = append(data, '\n')
	if _, err := conn.Write(data); err != nil {
		log.Error("Failed to write response", "error", err)
	}
}
