package ssh

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/adapter/contracttest"
	"github.com/normalone/lpeco/internal/model"
)

func TestExecSeparatesStreamsExitStatusAndTruncation(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	server := passwordServer(t)
	transport := newPasswordAdapter(t, server)
	capabilities, err := transport.Open(context.Background())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer transport.Close(context.Background())
	if !capabilities.SeparateStderr || !capabilities.ReliableExitStatus || capabilities.Upload || capabilities.Download {
		t.Fatalf("unexpected capabilities: %#v", capabilities)
	}

	result, err := transport.Exec(context.Background(), adapter.ExecRequest{
		ProbeID: "streams", Command: adapter.Command{Script: "emit"}, Timeout: time.Second, MaxOutput: 64,
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if string(result.Stdout) != "abcdef" || string(result.Stderr) != "ERR" || result.MergedOutput || result.Truncated {
		t.Fatalf("stream result = %#v", result)
	}
	if result.ExitCode == nil || *result.ExitCode != 7 || result.Status != model.ProbeComplete {
		t.Fatalf("exit result = %#v", result)
	}

	truncated, err := transport.Exec(context.Background(), adapter.ExecRequest{
		ProbeID: "truncated", Command: adapter.Command{Script: "emit"}, Timeout: time.Second, MaxOutput: 5,
	})
	if err != nil {
		t.Fatalf("Exec truncated: %v", err)
	}
	if !truncated.Truncated || truncated.Status != model.ProbeTruncated || len(truncated.Stdout)+len(truncated.Stderr) != 5 {
		t.Fatalf("truncated result = %#v", truncated)
	}
}

func TestExecTimeoutAndCancellation(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	server := passwordServer(t)
	transport := newPasswordAdapter(t, server)
	if _, err := transport.Open(context.Background()); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer transport.Close(context.Background())

	t.Run("timeout", func(t *testing.T) {
		result, err := transport.Exec(context.Background(), adapter.ExecRequest{
			ProbeID: "timeout", Command: adapter.Command{Script: "slow"}, Timeout: 20 * time.Millisecond,
		})
		if result.Status != model.ProbeTimeout || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("timeout result = (%#v, %v)", result, err)
		}
		if string(result.Stdout) != "early" {
			t.Fatalf("timeout discarded partial stdout: %#v", result)
		}
	})

	t.Run("cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		result, err := transport.Exec(ctx, adapter.ExecRequest{
			ProbeID: "cancel", Command: adapter.Command{Script: "slow"}, Timeout: time.Second,
		})
		if result.Status != model.ProbePartial || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel result = (%#v, %v)", result, err)
		}
	})
}

func TestBuiltinAdaptersSatisfyContract(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	contracttest.Run(t, func(t *testing.T) (adapter.Adapter, adapter.ExecRequest, []byte) {
		server := passwordServer(t)
		return newPasswordAdapter(t, server), adapter.ExecRequest{
			ProbeID: "contract", Command: adapter.Command{Script: "printf ssh-ok"}, Timeout: time.Second,
		}, []byte("ssh-ok\n")
	})
}

func passwordServer(t *testing.T) *testServer {
	t.Helper()
	return startTestServer(t, serverOptions{
		passwordCallback: func(password []byte) error {
			if string(password) != "secret" {
				return errors.New("wrong password")
			}
			return nil
		},
	})
}

func newPasswordAdapter(t *testing.T, server *testServer) *Adapter {
	t.Helper()
	transport, err := New(Config{
		Target:         server.address,
		User:           "tester",
		KnownHostsPath: server.knownHostsFile(t),
		PasswordCallback: func(context.Context) ([]byte, error) {
			return []byte("secret"), nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return transport
}
