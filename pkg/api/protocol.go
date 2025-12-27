package api

import "time"

type Command string

const (
	CommandEnable   Command = "enable"
	CommandDisable  Command = "disable"
	CommandReload   Command = "reload"
	CommandStatus   Command = "status"
	CommandStats    Command = "stats"
	CommandShutdown Command = "shutdown"
)

type DataplaneState string

const (
	StateDisabled DataplaneState = "disabled"
	StateEnabled  DataplaneState = "enabled"
	StateFailed   DataplaneState = "failed"
)

type EnableArgs struct {
	ConfigPath string
}

type ReloadArgs struct {
	ConfigPath string
}

type Request struct {
	Command    Command `json:"command"`
	ConfigPath string  `json:"config_path,omitempty"`
}

type Response struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
	Data    any    `json:"data,omitempty"`
}

type StatusResponse struct {
	State        DataplaneState `json:"state"`
	Mode         string         `json:"mode,omitempty"`
	Interfaces   []string       `json:"interfaces,omitempty"`
	Uptime       time.Duration  `json:"uptime"`
	ErrorMessage string         `json:"error_message,omitempty"`
}

type StatsResponse struct {
	Metrics []MetricData  `json:"metrics"`
	Uptime  time.Duration `json:"uptime"`
}

type MetricData struct {
	Direction string `json:"direction"`
	Reason    string `json:"reason"`
	SrcAddr   string `json:"src_addr"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
}
