package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/adapter/plugin"
	"github.com/normalone/lpeco/internal/model"
)

type backend struct {
	mu     sync.Mutex
	nextID uint64
	tasks  map[string]*fixtureTask
}

type fixtureTask struct {
	pollsRemaining int
	failed         bool
	cancelled      bool
	complete       bool
}

func newBackend() *backend {
	return &backend{tasks: make(map[string]*fixtureTask)}
}

func (b *backend) handle(request plugin.Request) plugin.Response {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch request.Method {
	case plugin.MethodHandshake:
		return rpcSuccess(request.ID, plugin.HandshakeResult{Capabilities: adapter.Capabilities{
			ProtocolVersion: "1", TransportKind: "c2-fixture", ReliableExitStatus: true,
			SeparateStderr: true, AsyncTasks: true, Cancel: true,
			MaxCommandBytes: 64 * 1024, MaxOutputBytes: 4 * 1024 * 1024,
		}})
	case plugin.MethodOpenSession:
		return rpcSuccess(request.ID, plugin.OpenSessionResult{SessionID: "fixture-session"})
	case plugin.MethodExec:
		var params plugin.ExecParams
		if err := json.Unmarshal(request.Params, &params); err != nil {
			return rpcFailure(request.ID, -32602, "invalid exec params")
		}
		b.nextID++
		taskID := fmt.Sprintf("fixture-task-%d", b.nextID)
		b.tasks[taskID] = &fixtureTask{
			pollsRemaining: parseDelay(params.Command),
			failed:         strings.Contains(params.Command, "fixture-fail"),
		}
		return rpcSuccess(request.ID, plugin.ExecAccepted{TaskID: taskID})
	case plugin.MethodPoll:
		var params plugin.PollParams
		if err := json.Unmarshal(request.Params, &params); err != nil {
			return rpcFailure(request.ID, -32602, "invalid poll params")
		}
		task, found := b.tasks[params.TaskID]
		if !found {
			return rpcFailure(request.ID, -32004, "unknown task")
		}
		if task.cancelled {
			return rpcSuccess(request.ID, plugin.PollResult{State: plugin.TaskCancelled})
		}
		if task.failed {
			return rpcSuccess(request.ID, plugin.PollResult{State: plugin.TaskFailed, Error: "fixture task failed"})
		}
		if task.pollsRemaining > 0 {
			task.pollsRemaining--
			return rpcSuccess(request.ID, plugin.PollResult{State: plugin.TaskPending})
		}
		task.complete = true
		exitCode := 0
		return rpcSuccess(request.ID, plugin.PollResult{State: plugin.TaskComplete, Result: &adapter.ExecResult{
			Stdout: []byte("fixture complete\n"), ExitCode: &exitCode, Status: model.ProbeComplete,
		}})
	case plugin.MethodCancel:
		var params plugin.CancelParams
		if err := json.Unmarshal(request.Params, &params); err != nil {
			return rpcFailure(request.ID, -32602, "invalid cancel params")
		}
		task, found := b.tasks[params.TaskID]
		if !found {
			return rpcFailure(request.ID, -32004, "unknown task")
		}
		if task.complete {
			return rpcSuccess(request.ID, plugin.CancelResult{AlreadyComplete: true})
		}
		task.cancelled = true
		return rpcSuccess(request.ID, plugin.CancelResult{Cancelled: true})
	case plugin.MethodCloseSession:
		return rpcSuccess(request.ID, map[string]bool{"closed": true})
	case plugin.MethodUpload, plugin.MethodDownload:
		return rpcFailure(request.ID, -32601, "reserved method is not implemented")
	default:
		return rpcFailure(request.ID, -32601, "method not found")
	}
}

func parseDelay(command string) int {
	const marker = "fixture-delay="
	index := strings.Index(command, marker)
	if index < 0 {
		return 0
	}
	value := command[index+len(marker):]
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	delay, err := strconv.Atoi(value[:end])
	if err != nil || delay < 0 {
		return 0
	}
	return delay
}

func rpcSuccess(id string, value any) plugin.Response {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return plugin.Response{JSONRPC: plugin.JSONRPCVersion, ID: id, Result: encoded}
}

func rpcFailure(id string, code int, message string) plugin.Response {
	return plugin.Response{JSONRPC: plugin.JSONRPCVersion, ID: id, Error: &plugin.RPCError{Code: code, Message: message}}
}
