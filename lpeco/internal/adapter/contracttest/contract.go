package contracttest

import (
	"bytes"
	"context"
	"testing"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/model"
)

type Factory func(*testing.T) (adapter.Adapter, adapter.ExecRequest, []byte)

func Run(t *testing.T, factory Factory) {
	t.Helper()
	t.Run("open exec close", func(t *testing.T) {
		transport, request, wantStdout := factory(t)
		capabilities, err := transport.Open(context.Background())
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if capabilities.ProtocolVersion == "" || capabilities.TransportKind == "" {
			t.Fatalf("incomplete capabilities: %#v", capabilities)
		}
		result, err := transport.Exec(context.Background(), request)
		if err != nil {
			t.Fatalf("Exec: %v", err)
		}
		if result.Status != model.ProbeComplete {
			t.Fatalf("status = %q, want complete", result.Status)
		}
		if !bytes.Equal(result.Stdout, wantStdout) {
			t.Fatalf("stdout = %q, want %q", result.Stdout, wantStdout)
		}
		if result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) {
			t.Fatalf("invalid timestamps: %s..%s", result.StartedAt, result.FinishedAt)
		}
		if err := transport.Close(context.Background()); err != nil {
			t.Fatalf("Close: %v", err)
		}
	})
}
