package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/normalone/lpeco/internal/adapter"
)

const (
	ProtocolVersion = "1"
	JSONRPCVersion  = "2.0"

	MethodHandshake    = "handshake"
	MethodOpenSession  = "open_session"
	MethodExec         = "exec"
	MethodPoll         = "poll"
	MethodCancel       = "cancel"
	MethodCloseSession = "close_session"
	MethodUpload       = "upload"
	MethodDownload     = "download"
)

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("plugin RPC error %d: %s", e.Code, e.Message)
}

type HandshakeResult struct {
	Capabilities adapter.Capabilities `json:"capabilities"`
}

type OpenSessionParams struct {
	Options map[string]string `json:"options,omitempty"`
}

type OpenSessionResult struct {
	SessionID string `json:"session_id"`
}

type ExecParams struct {
	SessionID string `json:"session_id"`
	ProbeID   string `json:"probe_id"`
	VariantID string `json:"variant_id"`
	Command   string `json:"command"`
	TimeoutMS int64  `json:"timeout_ms"`
	MaxOutput int    `json:"max_output"`
}

type ExecAccepted struct {
	TaskID string `json:"task_id"`
}

type PollParams struct {
	SessionID string `json:"session_id,omitempty"`
	TaskID    string `json:"task_id"`
}

type TaskState string

const (
	TaskPending   TaskState = "pending"
	TaskComplete  TaskState = "complete"
	TaskFailed    TaskState = "failed"
	TaskCancelled TaskState = "cancelled"
)

type PollResult struct {
	State  TaskState           `json:"state"`
	Result *adapter.ExecResult `json:"result,omitempty"`
	Error  string              `json:"error,omitempty"`
}

type CancelParams struct {
	SessionID string `json:"session_id,omitempty"`
	TaskID    string `json:"task_id"`
}

type CancelResult struct {
	Cancelled       bool `json:"cancelled"`
	AlreadyComplete bool `json:"already_complete,omitempty"`
}

type CloseSessionParams struct {
	SessionID string `json:"session_id"`
}

func ServeJSONL(ctx context.Context, input io.Reader, output io.Writer, maxLineBytes int, handler func(context.Context, Request) Response) error {
	if maxLineBytes <= 0 {
		maxLineBytes = 1024 * 1024
	}
	reader := bufio.NewReaderSize(input, min(maxLineBytes, 64*1024))
	encoder := json.NewEncoder(output)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		line, err := readBoundedLine(reader, maxLineBytes)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		var request Request
		if err := json.Unmarshal(line, &request); err != nil {
			return fmt.Errorf("%w: request: %v", ErrMalformedJSON, err)
		}
		if request.JSONRPC != JSONRPCVersion || request.ID == "" || request.Method == "" {
			return fmt.Errorf("%w: invalid request envelope", ErrMalformedJSON)
		}
		if err := encoder.Encode(handler(ctx, request)); err != nil {
			return fmt.Errorf("encode plugin response: %w", err)
		}
	}
}
