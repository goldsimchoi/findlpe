package main

import (
	"encoding/json"
	"testing"

	"github.com/normalone/lpeco/internal/adapter/plugin"
)

func TestBackendDelayedExecPollLifecycle(t *testing.T) {
	backend := newBackend()
	handshake := backend.handle(plugin.Request{JSONRPC: "2.0", ID: "1", Method: plugin.MethodHandshake})
	var handshakeResult plugin.HandshakeResult
	decodeResult(t, handshake, &handshakeResult)
	if handshakeResult.Capabilities.ProtocolVersion != "1" || !handshakeResult.Capabilities.AsyncTasks || !handshakeResult.Capabilities.Cancel {
		t.Fatalf("handshake capabilities = %#v", handshakeResult.Capabilities)
	}

	execResponse := backend.handle(requestWithParams(t, "2", plugin.MethodExec, plugin.ExecParams{Command: "fixture-delay=2"}))
	var accepted plugin.ExecAccepted
	decodeResult(t, execResponse, &accepted)
	if accepted.TaskID == "" {
		t.Fatal("exec returned empty task ID")
	}
	for pollNumber := 1; pollNumber <= 3; pollNumber++ {
		response := backend.handle(requestWithParams(t, "poll", plugin.MethodPoll, plugin.PollParams{TaskID: accepted.TaskID}))
		var result plugin.PollResult
		decodeResult(t, response, &result)
		if pollNumber <= 2 && result.State != plugin.TaskPending {
			t.Fatalf("poll %d state = %q, want pending", pollNumber, result.State)
		}
		if pollNumber == 3 && (result.State != plugin.TaskComplete || string(result.Result.Stdout) != "fixture complete\n") {
			t.Fatalf("final poll = %#v", result)
		}
	}
}

func TestBackendCancelRaceIsIdempotent(t *testing.T) {
	backend := newBackend()
	execResponse := backend.handle(requestWithParams(t, "1", plugin.MethodExec, plugin.ExecParams{Command: "fixture-delay=5"}))
	var accepted plugin.ExecAccepted
	decodeResult(t, execResponse, &accepted)

	first := backend.handle(requestWithParams(t, "2", plugin.MethodCancel, plugin.CancelParams{TaskID: accepted.TaskID}))
	second := backend.handle(requestWithParams(t, "3", plugin.MethodCancel, plugin.CancelParams{TaskID: accepted.TaskID}))
	var firstResult, secondResult plugin.CancelResult
	decodeResult(t, first, &firstResult)
	decodeResult(t, second, &secondResult)
	if !firstResult.Cancelled || !secondResult.Cancelled {
		t.Fatalf("cancel results = %#v, %#v", firstResult, secondResult)
	}
	poll := backend.handle(requestWithParams(t, "4", plugin.MethodPoll, plugin.PollParams{TaskID: accepted.TaskID}))
	var pollResult plugin.PollResult
	decodeResult(t, poll, &pollResult)
	if pollResult.State != plugin.TaskCancelled {
		t.Fatalf("poll after cancel = %#v", pollResult)
	}
}

func TestBackendFailureAndUnknownTask(t *testing.T) {
	backend := newBackend()
	execResponse := backend.handle(requestWithParams(t, "1", plugin.MethodExec, plugin.ExecParams{Command: "fixture-fail"}))
	var accepted plugin.ExecAccepted
	decodeResult(t, execResponse, &accepted)
	poll := backend.handle(requestWithParams(t, "2", plugin.MethodPoll, plugin.PollParams{TaskID: accepted.TaskID}))
	var result plugin.PollResult
	decodeResult(t, poll, &result)
	if result.State != plugin.TaskFailed || result.Error == "" {
		t.Fatalf("failed task poll = %#v", result)
	}
	unknown := backend.handle(requestWithParams(t, "3", plugin.MethodPoll, plugin.PollParams{TaskID: "missing"}))
	if unknown.Error == nil {
		t.Fatal("unknown task did not return an RPC error")
	}
}

func requestWithParams(t *testing.T, id, method string, value any) plugin.Request {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	return plugin.Request{JSONRPC: "2.0", ID: id, Method: method, Params: encoded}
}

func decodeResult(t *testing.T, response plugin.Response, destination any) {
	t.Helper()
	if response.Error != nil {
		t.Fatalf("RPC error: %#v", response.Error)
	}
	if err := json.Unmarshal(response.Result, destination); err != nil {
		t.Fatalf("decode result: %v", err)
	}
}
