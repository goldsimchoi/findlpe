package raw

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/adapter/contracttest"
	"github.com/normalone/lpeco/internal/model"
)

func TestRawAdapterSeparatesNoiseAndReportsMergedStderr(t *testing.T) {
	nonce := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fixture, err := os.ReadFile("../../../testdata/adapter/raw/prompt-echo.transcript")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	fixture = bytes.ReplaceAll(fixture, []byte("{{START}}"), startMarker(nonce))
	fixture = bytes.ReplaceAll(fixture, []byte("{{END:0}}"), append(endPrefix(nonce), []byte("0\x1f")...))
	transportIO := &memoryRWC{reader: bytes.NewReader(fixture)}
	transport := New(transportIO, Options{Nonce: fixedNonce(nonce)})
	if _, err := transport.Open(context.Background()); err != nil {
		t.Fatalf("Open: %v", err)
	}
	result, err := transport.Exec(context.Background(), adapter.ExecRequest{
		ProbeID:   "identity.current",
		VariantID: "portable",
		Command:   adapter.Command{Script: "id -u"},
		Timeout:   time.Second,
		MaxOutput: 1024,
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if string(result.Stdout) != "1000\n" || !result.MergedOutput || len(result.Stderr) != 0 {
		t.Fatalf("result = %#v", result)
	}
	if result.ExitCode == nil || *result.ExitCode != 0 || result.Status != model.ProbeComplete {
		t.Fatalf("exit result = %#v", result)
	}
	if !strings.Contains(transportIO.written.String(), "id -u") {
		t.Fatalf("sent command missing fixed script: %q", transportIO.written.String())
	}
}

func TestRawAdapterNeverCompletesWithoutValidEnd(t *testing.T) {
	nonce := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	tests := []struct {
		name       string
		transcript []byte
		wantStatus model.ProbeStatus
		wantErr    error
	}{
		{
			name:       "disconnect",
			transcript: append(append(startMarker(nonce), '\n'), []byte("partial")...),
			wantStatus: model.ProbePartial,
			wantErr:    ErrMissingEnd,
		},
		{
			name:       "malformed exit",
			transcript: framedTranscript(nonce, []byte("output"), "bad"),
			wantStatus: model.ProbeParseError,
			wantErr:    ErrMalformedExit,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := New(&memoryRWC{reader: bytes.NewReader(tt.transcript)}, Options{Nonce: fixedNonce(nonce)})
			_, _ = transport.Open(context.Background())
			result, err := transport.Exec(context.Background(), adapter.ExecRequest{
				ProbeID: "test", Command: adapter.Command{Script: "printf output"}, Timeout: time.Second, MaxOutput: 1024,
			})
			if result.Status != tt.wantStatus || !errors.Is(err, tt.wantErr) {
				t.Fatalf("result/status = (%#v, %v), want %s/%v", result, err, tt.wantStatus, tt.wantErr)
			}
		})
	}
}

func TestRawAdapterMarksTruncation(t *testing.T) {
	nonce := "cccccccccccccccccccccccccccccccc"
	transport := New(&memoryRWC{reader: bytes.NewReader(framedTranscript(nonce, []byte("0123456789"), "0"))}, Options{Nonce: fixedNonce(nonce)})
	_, _ = transport.Open(context.Background())
	result, err := transport.Exec(context.Background(), adapter.ExecRequest{
		ProbeID: "test", Command: adapter.Command{Script: "printf output"}, Timeout: time.Second, MaxOutput: 4,
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if result.Status != model.ProbeTruncated || !result.Truncated || string(result.Stdout) != "0123" {
		t.Fatalf("result = %#v", result)
	}
}

func TestRawAdapterTimesOutAndClosesBlockedTransport(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	transport := New(client, Options{Nonce: fixedNonce("dddddddddddddddddddddddddddddddd")})
	_, _ = transport.Open(context.Background())
	go func() {
		_, _ = io.Copy(io.Discard, server)
	}()
	result, err := transport.Exec(context.Background(), adapter.ExecRequest{
		ProbeID: "timeout", Command: adapter.Command{Script: "printf never"}, Timeout: 20 * time.Millisecond,
	})
	if result.Status != model.ProbeTimeout || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout result = (%#v, %v)", result, err)
	}
}

func TestRawAdapterContract(t *testing.T) {
	nonce := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	contracttest.Run(t, func(t *testing.T) (adapter.Adapter, adapter.ExecRequest, []byte) {
		return New(&memoryRWC{reader: bytes.NewReader(framedTranscript(nonce, []byte("raw-ok\n"), "0"))}, Options{Nonce: fixedNonce(nonce)}), adapter.ExecRequest{
			ProbeID: "contract", Command: adapter.Command{Script: "printf 'raw-ok\\n'"}, Timeout: time.Second,
		}, []byte("raw-ok\n")
	})
}

func TestStdioBridgeContract(t *testing.T) {
	contracttest.Run(t, func(t *testing.T) (adapter.Adapter, adapter.ExecRequest, []byte) {
		bridge, err := StartBridge(context.Background(), []string{"sh"})
		if err != nil {
			t.Fatalf("StartBridge: %v", err)
		}
		return New(bridge, Options{TransportKind: "stdio-bridge"}), adapter.ExecRequest{
			ProbeID: "contract", Command: adapter.Command{Script: "printf 'bridge-ok\\n'"}, Timeout: time.Second,
		}, []byte("bridge-ok\n")
	})
}

type memoryRWC struct {
	mu      sync.Mutex
	reader  io.Reader
	written bytes.Buffer
	closed  bool
}

func (m *memoryRWC) Read(buffer []byte) (int, error) {
	return m.reader.Read(buffer)
}

func (m *memoryRWC) Write(buffer []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, net.ErrClosed
	}
	return m.written.Write(buffer)
}

func (m *memoryRWC) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func fixedNonce(value string) func() (string, error) {
	return func() (string, error) { return value, nil }
}
