package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/adapter/contracttest"
	"github.com/normalone/lpeco/internal/model"
)

func TestRPCClientDispatchesOutOfOrderAndIgnoresDuplicateResponses(t *testing.T) {
	core, fixture := net.Pipe()
	client := NewRPCClient(core, core, strings.NewReader("not protocol JSON\n"), nil, ClientOptions{MaxLineBytes: 4096})
	t.Cleanup(func() { _ = client.Close() })
	serverDone := make(chan error, 1)
	go func() {
		decoder := json.NewDecoder(fixture)
		encoder := json.NewEncoder(fixture)
		var first, second Request
		if err := decoder.Decode(&first); err != nil {
			serverDone <- err
			return
		}
		if err := decoder.Decode(&second); err != nil {
			serverDone <- err
			return
		}
		responses := []Response{
			{JSONRPC: "2.0", ID: second.ID, Result: mustJSON(t, map[string]string{"value": second.Method})},
			{JSONRPC: "2.0", ID: first.ID, Result: mustJSON(t, map[string]string{"value": first.Method})},
			{JSONRPC: "2.0", ID: first.ID, Result: mustJSON(t, map[string]string{"value": "duplicate"})},
		}
		for _, response := range responses {
			if err := encoder.Encode(response); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	type callResult struct {
		method string
		value  string
		err    error
	}
	results := make(chan callResult, 2)
	for _, method := range []string{"first", "second"} {
		method := method
		go func() {
			var output struct {
				Value string `json:"value"`
			}
			err := client.Call(context.Background(), method, map[string]string{"input": method}, &output)
			results <- callResult{method: method, value: output.Value, err: err}
		}()
	}
	seen := map[string]string{}
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("Call %s: %v", result.method, result.err)
		}
		seen[result.method] = result.value
	}
	if !reflect.DeepEqual(seen, map[string]string{"first": "first", "second": "second"}) {
		t.Fatalf("dispatched results = %#v", seen)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("fixture server: %v", err)
	}
	if !strings.Contains(client.Diagnostics(), "not protocol JSON") {
		t.Fatalf("stderr diagnostics were not isolated: %q", client.Diagnostics())
	}
}

func TestRPCClientRejectsMalformedAndOversizedJSONL(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		maxLine int
		want    error
	}{
		{name: "malformed", line: "{not-json}\n", maxLine: 1024, want: ErrMalformedJSON},
		{name: "oversized", line: strings.Repeat("x", 65) + "\n", maxLine: 64, want: ErrLineTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, fixture := net.Pipe()
			client := NewRPCClient(core, core, nil, nil, ClientOptions{MaxLineBytes: tt.maxLine})
			defer client.Close()
			go func() {
				decoder := json.NewDecoder(fixture)
				var request Request
				_ = decoder.Decode(&request)
				_, _ = io.WriteString(fixture, tt.line)
				_ = fixture.Close()
			}()
			var output any
			err := client.Call(context.Background(), "test", nil, &output)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Call error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestAdapterRejectsProtocolMismatch(t *testing.T) {
	transport, _, cleanup := fakeAdapter(t, adapter.Capabilities{ProtocolVersion: "99", TransportKind: "fixture"}, nil)
	defer cleanup()
	if _, err := transport.Open(context.Background()); !errors.Is(err, ErrProtocolVersion) {
		t.Fatalf("Open error = %v, want ErrProtocolVersion", err)
	}
}

func TestAdapterCompletesDelayedTaskWithoutReservedMethods(t *testing.T) {
	polls := 0
	transport, methods, cleanup := fakeAdapter(t, validCapabilities(), func(request Request) Response {
		switch request.Method {
		case MethodExec:
			return successResponse(request.ID, ExecAccepted{TaskID: "task-one"})
		case MethodPoll:
			polls++
			if polls == 1 {
				return successResponse(request.ID, PollResult{State: TaskPending})
			}
			exit := 0
			return successResponse(request.ID, PollResult{State: TaskComplete, Result: &adapter.ExecResult{
				Stdout: []byte("plugin-ok\n"), ExitCode: &exit, Status: model.ProbeComplete,
			}})
		default:
			return Response{}
		}
	})
	defer cleanup()
	if _, err := transport.Open(context.Background()); err != nil {
		t.Fatalf("Open: %v", err)
	}
	result, err := transport.Exec(context.Background(), adapter.ExecRequest{
		ProbeID: "delayed", Command: adapter.Command{Script: "printf plugin-ok"}, Timeout: time.Second, MaxOutput: 1024,
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if result.Status != model.ProbeComplete || string(result.Stdout) != "plugin-ok\n" || polls != 2 {
		t.Fatalf("result = %#v, polls = %d", result, polls)
	}
	for _, method := range *methods {
		if method == MethodUpload || method == MethodDownload {
			t.Fatalf("core called reserved method %q", method)
		}
	}
}

func TestAdapterCancelsPendingTaskOnTimeout(t *testing.T) {
	cancelled := make(chan struct{}, 1)
	transport, _, cleanup := fakeAdapter(t, validCapabilities(), func(request Request) Response {
		switch request.Method {
		case MethodExec:
			return successResponse(request.ID, ExecAccepted{TaskID: "task-slow"})
		case MethodPoll:
			return successResponse(request.ID, PollResult{State: TaskPending})
		case MethodCancel:
			cancelled <- struct{}{}
			return successResponse(request.ID, CancelResult{Cancelled: true})
		default:
			return Response{}
		}
	})
	defer cleanup()
	if _, err := transport.Open(context.Background()); err != nil {
		t.Fatalf("Open: %v", err)
	}
	result, err := transport.Exec(context.Background(), adapter.ExecRequest{
		ProbeID: "slow", Command: adapter.Command{Script: "slow"}, Timeout: 25 * time.Millisecond,
	})
	if result.Status != model.ProbeTimeout || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout result = (%#v, %v)", result, err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("adapter did not send cancel for pending task")
	}
}

func TestPluginProcessCrashReturnsResumablePartialAndKeepsStderrDiagnostic(t *testing.T) {
	transport, err := Start(context.Background(), []string{"sh", "-c", "printf 'fixture diagnostic\\n' >&2; exit 7"}, Options{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer transport.Close(context.Background())
	if _, err := transport.Open(context.Background()); err == nil {
		t.Fatal("Open succeeded after plugin process crash")
	}
	if !strings.Contains(transport.Diagnostics(), "fixture diagnostic") {
		t.Fatalf("missing isolated diagnostic: %q", transport.Diagnostics())
	}
}

func TestPluginAdapterContract(t *testing.T) {
	contracttest.Run(t, func(t *testing.T) (adapter.Adapter, adapter.ExecRequest, []byte) {
		transport, _, cleanup := fakeAdapter(t, validCapabilities(), func(request Request) Response {
			switch request.Method {
			case MethodExec:
				return successResponse(request.ID, ExecAccepted{TaskID: "contract-task"})
			case MethodPoll:
				exit := 0
				return successResponse(request.ID, PollResult{State: TaskComplete, Result: &adapter.ExecResult{
					Stdout: []byte("plugin-contract\n"), ExitCode: &exit, Status: model.ProbeComplete,
				}})
			default:
				return Response{}
			}
		})
		t.Cleanup(cleanup)
		return transport, adapter.ExecRequest{
			ProbeID: "contract", Command: adapter.Command{Script: "printf plugin-contract"}, Timeout: time.Second,
		}, []byte("plugin-contract\n")
	})
}

func fakeAdapter(t *testing.T, capabilities adapter.Capabilities, handler func(Request) Response) (*Adapter, *[]string, func()) {
	t.Helper()
	core, fixture := net.Pipe()
	methods := &[]string{}
	var methodsMu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer fixture.Close()
		scanner := bufio.NewScanner(fixture)
		encoder := json.NewEncoder(fixture)
		for scanner.Scan() {
			var request Request
			if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
				return
			}
			methodsMu.Lock()
			*methods = append(*methods, request.Method)
			methodsMu.Unlock()
			var response Response
			switch request.Method {
			case MethodHandshake:
				response = successResponse(request.ID, HandshakeResult{Capabilities: capabilities})
			case MethodOpenSession:
				response = successResponse(request.ID, OpenSessionResult{SessionID: "fixture-session"})
			case MethodCloseSession:
				response = successResponse(request.ID, map[string]bool{"closed": true})
			default:
				if handler != nil {
					response = handler(request)
				}
			}
			if response.JSONRPC == "" {
				response = Response{JSONRPC: "2.0", ID: request.ID, Error: &RPCError{Code: -32601, Message: "method not found"}}
			}
			if err := encoder.Encode(response); err != nil {
				return
			}
		}
	}()
	client := NewRPCClient(core, core, nil, func() error { <-done; return nil }, ClientOptions{MaxLineBytes: 64 * 1024})
	transport := NewClientAdapter(client, Options{PollInterval: time.Millisecond})
	cleanup := func() {
		_ = client.Close()
		_ = fixture.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fixture plugin did not stop")
		}
	}
	return transport, methods, cleanup
}

func validCapabilities() adapter.Capabilities {
	return adapter.Capabilities{
		ProtocolVersion: "1", TransportKind: "c2-fixture", ReliableExitStatus: true,
		SeparateStderr: true, AsyncTasks: true, Cancel: true, MaxCommandBytes: 65536, MaxOutputBytes: 1 << 20,
	}
}

func successResponse(id string, value any) Response {
	return Response{JSONRPC: "2.0", ID: id, Result: mustJSON(nil, value)}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		if t != nil {
			t.Fatalf("marshal fixture JSON: %v", err)
		}
		panic(err)
	}
	return encoded
}
