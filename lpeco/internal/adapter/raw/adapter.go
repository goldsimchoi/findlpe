package raw

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/model"
)

var ErrClosed = errors.New("raw adapter is closed")

type Options struct {
	Nonce           func() (string, error)
	TransportKind   string
	Interactive     bool
	TTY             bool
	MaxCommandBytes int
	MaxOutputBytes  int
	DefaultTimeout  time.Duration
}

type Adapter struct {
	mu           sync.Mutex
	transport    io.ReadWriteCloser
	options      Options
	capabilities adapter.Capabilities
	opened       bool
	closed       bool
}

func New(transport io.ReadWriteCloser, options Options) adapter.Adapter {
	if options.Nonce == nil {
		options.Nonce = randomNonce
	}
	if options.TransportKind == "" {
		options.TransportKind = "raw-listen"
	}
	if options.MaxCommandBytes <= 0 {
		options.MaxCommandBytes = 64 * 1024
	}
	if options.MaxOutputBytes <= 0 {
		options.MaxOutputBytes = 4 * 1024 * 1024
	}
	if options.DefaultTimeout <= 0 {
		options.DefaultTimeout = 30 * time.Second
	}
	return &Adapter{
		transport: transport,
		options:   options,
		capabilities: adapter.Capabilities{
			ProtocolVersion:    "1",
			TransportKind:      options.TransportKind,
			Interactive:        options.Interactive,
			TTY:                options.TTY,
			ReliableExitStatus: true,
			SeparateStderr:     false,
			AsyncTasks:         false,
			Cancel:             false,
			MaxCommandBytes:    options.MaxCommandBytes,
			MaxOutputBytes:     options.MaxOutputBytes,
			Upload:             false,
			Download:           false,
		},
	}
}

func (a *Adapter) Open(ctx context.Context) (adapter.Capabilities, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return adapter.Capabilities{}, err
	}
	if a.closed {
		return adapter.Capabilities{}, ErrClosed
	}
	if a.transport == nil {
		return adapter.Capabilities{}, errors.New("raw transport is required")
	}
	a.opened = true
	return a.capabilities, nil
}

func (a *Adapter) Exec(ctx context.Context, request adapter.ExecRequest) (adapter.ExecResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	started := time.Now().UTC()
	result := adapter.ExecResult{MergedOutput: true, StartedAt: started}
	if !a.opened {
		result.Status = model.ProbeUnavailable
		result.FinishedAt = time.Now().UTC()
		return result, errors.New("raw adapter is not open")
	}
	if a.closed {
		result.Status = model.ProbeUnavailable
		result.FinishedAt = time.Now().UTC()
		return result, ErrClosed
	}
	nonce, err := a.options.Nonce()
	if err != nil {
		result.Status = model.ProbeUnavailable
		result.FinishedAt = time.Now().UTC()
		return result, err
	}
	framed, err := frameCommand(request.Command, nonce)
	if err != nil {
		result.Status = model.ProbeUnavailable
		result.FinishedAt = time.Now().UTC()
		return result, err
	}
	if len(framed) > a.options.MaxCommandBytes {
		result.Status = model.ProbeUnavailable
		result.FinishedAt = time.Now().UTC()
		return result, adapter.ErrCommandTooLarge
	}
	outputLimit := request.MaxOutput
	if outputLimit <= 0 || outputLimit > a.options.MaxOutputBytes {
		outputLimit = a.options.MaxOutputBytes
	}
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = a.options.DefaultTimeout
	}
	execContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type outcome struct {
		frame frameResult
		err   error
	}
	progress := &frameProgress{}
	completed := make(chan outcome, 1)
	go func() {
		written, writeErr := io.WriteString(a.transport, framed)
		if writeErr == nil && written != len(framed) {
			writeErr = io.ErrShortWrite
		}
		if writeErr != nil {
			completed <- outcome{err: fmt.Errorf("write framed command: %w", writeErr)}
			return
		}
		parsed, parseErr := parseFrameWithProgress(a.transport, nonce, outputLimit, progress)
		completed <- outcome{frame: parsed, err: parseErr}
	}()

	select {
	case <-execContext.Done():
		a.closed = true
		_ = a.transport.Close()
		result.Stdout, result.Truncated = progress.snapshot()
		result.FinishedAt = time.Now().UTC()
		if errors.Is(execContext.Err(), context.DeadlineExceeded) {
			result.Status = model.ProbeTimeout
		} else {
			result.Status = model.ProbePartial
		}
		return result, execContext.Err()
	case outcome := <-completed:
		result.Stdout = outcome.frame.Output
		result.Truncated = outcome.frame.Truncated
		result.FinishedAt = time.Now().UTC()
		if outcome.err != nil {
			switch {
			case errors.Is(outcome.err, ErrMalformedExit):
				result.Status = model.ProbeParseError
			case errors.Is(outcome.err, ErrMissingStart), errors.Is(outcome.err, ErrMissingEnd):
				result.Status = model.ProbePartial
			default:
				result.Status = model.ProbePartial
			}
			return result, outcome.err
		}
		exitCode := outcome.frame.ExitCode
		result.ExitCode = &exitCode
		if outcome.frame.Truncated {
			result.Status = model.ProbeTruncated
		} else {
			result.Status = model.ProbeComplete
		}
		return result, nil
	}
}

func (a *Adapter) Close(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.closed {
		return nil
	}
	a.closed = true
	if a.transport == nil {
		return nil
	}
	return a.transport.Close()
}

var _ adapter.Adapter = (*Adapter)(nil)
