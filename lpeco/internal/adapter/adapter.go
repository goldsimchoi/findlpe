package adapter

import (
	"context"
	"errors"
	"time"

	"github.com/normalone/lpeco/internal/model"
)

var (
	ErrUnsupported     = errors.New("adapter capability is unsupported")
	ErrCommandTooLarge = errors.New("rendered command exceeds adapter limit")
	ErrInvalidCommand  = errors.New("invalid command")
)

type Capabilities struct {
	ProtocolVersion    string `json:"protocol_version"`
	TransportKind      string `json:"transport_kind"`
	Interactive        bool   `json:"interactive"`
	TTY                bool   `json:"tty"`
	ReliableExitStatus bool   `json:"reliable_exit_status"`
	SeparateStderr     bool   `json:"separate_stderr"`
	AsyncTasks         bool   `json:"async_tasks"`
	Cancel             bool   `json:"cancel"`
	MaxCommandBytes    int    `json:"max_command_bytes"`
	MaxOutputBytes     int    `json:"max_output_bytes"`
	Upload             bool   `json:"upload"`
	Download           bool   `json:"download"`
}

type ExecRequest struct {
	ProbeID   string        `json:"probe_id"`
	VariantID string        `json:"variant_id"`
	Command   Command       `json:"command"`
	Timeout   time.Duration `json:"timeout"`
	MaxOutput int           `json:"max_output"`
}

type ExecResult struct {
	Stdout       []byte            `json:"stdout,omitempty"`
	Stderr       []byte            `json:"stderr,omitempty"`
	ExitCode     *int              `json:"exit_code,omitempty"`
	Status       model.ProbeStatus `json:"status"`
	MergedOutput bool              `json:"merged_output"`
	Truncated    bool              `json:"truncated"`
	StartedAt    time.Time         `json:"started_at"`
	FinishedAt   time.Time         `json:"finished_at"`
}

type Adapter interface {
	Open(context.Context) (Capabilities, error)
	Exec(context.Context, ExecRequest) (ExecResult, error)
	Close(context.Context) error
}
