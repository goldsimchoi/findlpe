package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/adapter/plugin"
	"github.com/normalone/lpeco/internal/model"
)

type fixture struct {
	mu     sync.Mutex
	next   int
	tasks  map[string]adapter.ExecResult
	errors map[string]string
}

func main() {
	backend := &fixture{tasks: make(map[string]adapter.ExecResult), errors: make(map[string]string)}
	if err := plugin.ServeJSONL(context.Background(), os.Stdin, os.Stdout, 8*1024*1024, backend.handle); err != nil {
		os.Exit(1)
	}
}

func (f *fixture) handle(_ context.Context, request plugin.Request) plugin.Response {
	switch request.Method {
	case plugin.MethodHandshake:
		return success(request.ID, plugin.HandshakeResult{Capabilities: adapter.Capabilities{
			ProtocolVersion: plugin.ProtocolVersion, TransportKind: "integration-c2", ReliableExitStatus: true,
			SeparateStderr: true, AsyncTasks: true, Cancel: true, MaxCommandBytes: 256 * 1024, MaxOutputBytes: 4 * 1024 * 1024,
		}})
	case plugin.MethodOpenSession:
		return success(request.ID, plugin.OpenSessionResult{SessionID: "integration-c2-session"})
	case plugin.MethodExec:
		var params plugin.ExecParams
		if json.Unmarshal(request.Params, &params) != nil {
			return failure(request.ID, -32602, "invalid exec parameters")
		}
		timeout := time.Duration(params.TimeoutMS) * time.Millisecond
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		started := time.Now().UTC()
		command := exec.CommandContext(ctx, "sh", "-c", params.Command)
		stdout := &limitedBuffer{limit: params.MaxOutput}
		stderr := &limitedBuffer{limit: params.MaxOutput}
		command.Stdout, command.Stderr = stdout, stderr
		runErr := command.Run()
		cancel()
		exitCode := 0
		status := model.ProbeComplete
		message := ""
		if runErr != nil {
			var exitError *exec.ExitError
			if errors.As(runErr, &exitError) {
				exitCode = exitError.ExitCode()
				status = model.ProbePartial
			} else {
				message = runErr.Error()
				status = model.ProbeUnavailable
			}
		}
		if stdout.truncated || stderr.truncated {
			status = model.ProbeTruncated
		}
		f.mu.Lock()
		f.next++
		taskID := "task-" + strconv.Itoa(f.next)
		f.tasks[taskID] = adapter.ExecResult{
			Stdout: stdout.bytes, Stderr: stderr.bytes, ExitCode: &exitCode, Status: status,
			Truncated: stdout.truncated || stderr.truncated, StartedAt: started, FinishedAt: time.Now().UTC(),
		}
		f.errors[taskID] = message
		f.mu.Unlock()
		return success(request.ID, plugin.ExecAccepted{TaskID: taskID})
	case plugin.MethodPoll:
		var params plugin.PollParams
		if json.Unmarshal(request.Params, &params) != nil {
			return failure(request.ID, -32602, "invalid poll parameters")
		}
		f.mu.Lock()
		result, ok := f.tasks[params.TaskID]
		message := f.errors[params.TaskID]
		f.mu.Unlock()
		if !ok {
			return failure(request.ID, -32004, "unknown task")
		}
		if message != "" {
			return success(request.ID, plugin.PollResult{State: plugin.TaskFailed, Error: message})
		}
		return success(request.ID, plugin.PollResult{State: plugin.TaskComplete, Result: &result})
	case plugin.MethodCancel:
		return success(request.ID, plugin.CancelResult{AlreadyComplete: true})
	case plugin.MethodCloseSession:
		return success(request.ID, map[string]bool{"closed": true})
	default:
		return failure(request.ID, -32601, "method not found")
	}
}

type limitedBuffer struct {
	bytes     []byte
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(value []byte) (int, error) {
	written := len(value)
	remaining := b.limit - len(b.bytes)
	if b.limit <= 0 {
		remaining = len(value)
	}
	if remaining < len(value) {
		value = value[:max(0, remaining)]
		b.truncated = true
	}
	b.bytes = append(b.bytes, value...)
	return written, nil
}

func success(id string, value any) plugin.Response {
	encoded, _ := json.Marshal(value)
	return plugin.Response{JSONRPC: plugin.JSONRPCVersion, ID: id, Result: encoded}
}

func failure(id string, code int, message string) plugin.Response {
	return plugin.Response{JSONRPC: plugin.JSONRPCVersion, ID: id, Error: &plugin.RPCError{Code: code, Message: message}}
}
