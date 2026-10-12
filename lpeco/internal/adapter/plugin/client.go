package plugin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/model"
)

var (
	ErrMalformedJSON   = errors.New("malformed plugin JSONL")
	ErrLineTooLarge    = errors.New("plugin JSONL line exceeds limit")
	ErrPluginExited    = errors.New("plugin process exited")
	ErrProtocolVersion = errors.New("unsupported plugin protocol version")
	ErrClientClosed    = errors.New("plugin client is closed")
)

type ClientOptions struct {
	MaxLineBytes int
	StderrLimit  int
}

type RPCClient struct {
	input  io.WriteCloser
	output io.Reader
	wait   func() error

	options   ClientOptions
	nextID    atomic.Uint64
	writeMu   sync.Mutex
	mu        sync.Mutex
	pending   map[string]chan responseOrError
	terminal  error
	done      chan struct{}
	failOnce  sync.Once
	closeOnce sync.Once

	diagnosticMu sync.Mutex
	diagnostics  []byte
	stderrDone   chan struct{}
}

type responseOrError struct {
	response Response
	err      error
}

func NewRPCClient(input io.WriteCloser, output io.Reader, stderr io.Reader, wait func() error, options ClientOptions) *RPCClient {
	if options.MaxLineBytes <= 0 {
		options.MaxLineBytes = 1024 * 1024
	}
	if options.StderrLimit <= 0 {
		options.StderrLimit = 64 * 1024
	}
	client := &RPCClient{
		input:      input,
		output:     output,
		wait:       wait,
		options:    options,
		pending:    make(map[string]chan responseOrError),
		done:       make(chan struct{}),
		stderrDone: make(chan struct{}),
	}
	go client.readLoop()
	if stderr != nil {
		go client.captureStderr(stderr)
	} else {
		close(client.stderrDone)
	}
	if wait != nil {
		go func() {
			waitErr := wait()
			if waitErr != nil {
				client.fail(fmt.Errorf("%w: %v", ErrPluginExited, waitErr))
			} else {
				client.fail(fmt.Errorf("%w: EOF", ErrPluginExited))
			}
		}()
	}
	return client
}

func (c *RPCClient) Call(ctx context.Context, method string, params, destination any) error {
	if strings.TrimSpace(method) == "" {
		return errors.New("plugin RPC method is required")
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("marshal plugin RPC params: %w", err)
	}
	id := strconv.FormatUint(c.nextID.Add(1), 10)
	request := Request{JSONRPC: JSONRPCVersion, ID: id, Method: method, Params: paramsJSON}
	encoded, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("marshal plugin RPC request: %w", err)
	}
	if len(encoded)+1 > c.options.MaxLineBytes {
		return ErrLineTooLarge
	}
	responseChannel := make(chan responseOrError, 1)
	c.mu.Lock()
	if c.terminal != nil {
		terminal := c.terminal
		c.mu.Unlock()
		return terminal
	}
	c.pending[id] = responseChannel
	c.mu.Unlock()

	c.writeMu.Lock()
	_, writeErr := c.input.Write(append(encoded, '\n'))
	c.writeMu.Unlock()
	if writeErr != nil {
		c.removePending(id)
		return fmt.Errorf("write plugin RPC request: %w", writeErr)
	}
	select {
	case <-ctx.Done():
		c.removePending(id)
		return ctx.Err()
	case <-c.done:
		c.mu.Lock()
		terminal := c.terminal
		c.mu.Unlock()
		if terminal == nil {
			return ErrClientClosed
		}
		return terminal
	case outcome := <-responseChannel:
		if outcome.err != nil {
			return outcome.err
		}
		if outcome.response.Error != nil {
			return outcome.response.Error
		}
		if destination == nil {
			return nil
		}
		if len(outcome.response.Result) == 0 {
			return fmt.Errorf("%w: response %s has no result", ErrMalformedJSON, id)
		}
		if err := json.Unmarshal(outcome.response.Result, destination); err != nil {
			return fmt.Errorf("%w: decode response %s: %v", ErrMalformedJSON, id, err)
		}
		return nil
	}
}

func (c *RPCClient) removePending(id string) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

func (c *RPCClient) readLoop() {
	reader := bufio.NewReaderSize(c.output, min(c.options.MaxLineBytes, 64*1024))
	for {
		line, err := readBoundedLine(reader, c.options.MaxLineBytes)
		if err != nil {
			if errors.Is(err, io.EOF) {
				c.fail(fmt.Errorf("%w: stdout closed", ErrPluginExited))
			} else {
				c.fail(err)
			}
			return
		}
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var response Response
		if err := json.Unmarshal(line, &response); err != nil {
			c.fail(fmt.Errorf("%w: %v", ErrMalformedJSON, err))
			return
		}
		if response.JSONRPC != JSONRPCVersion || response.ID == "" || (response.Error == nil && len(response.Result) == 0) {
			c.fail(fmt.Errorf("%w: invalid response envelope", ErrMalformedJSON))
			return
		}
		c.mu.Lock()
		responseChannel, found := c.pending[response.ID]
		if found {
			delete(c.pending, response.ID)
		}
		c.mu.Unlock()
		if found {
			responseChannel <- responseOrError{response: response}
		} else {
			c.appendDiagnostic([]byte("duplicate or unknown response id " + response.ID + "\n"))
		}
	}
}

func readBoundedLine(reader *bufio.Reader, limit int) ([]byte, error) {
	line := make([]byte, 0, min(limit, 4096))
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(line)+len(fragment) > limit {
			if !bytes.Contains(fragment, []byte{'\n'}) {
				for err == bufio.ErrBufferFull {
					fragment, err = reader.ReadSlice('\n')
				}
			}
			return nil, ErrLineTooLarge
		}
		line = append(line, fragment...)
		switch {
		case err == nil:
			return bytes.TrimSuffix(line, []byte{'\n'}), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) > 0:
			return line, nil
		default:
			return nil, err
		}
	}
}

func (c *RPCClient) fail(err error) {
	c.failOnce.Do(func() {
		c.mu.Lock()
		c.terminal = err
		pending := c.pending
		c.pending = make(map[string]chan responseOrError)
		c.mu.Unlock()
		for _, responseChannel := range pending {
			responseChannel <- responseOrError{err: err}
		}
		close(c.done)
	})
}

func (c *RPCClient) captureStderr(stderr io.Reader) {
	defer close(c.stderrDone)
	buffer := make([]byte, 4096)
	for {
		read, err := stderr.Read(buffer)
		if read > 0 {
			c.appendDiagnostic(buffer[:read])
		}
		if err != nil {
			return
		}
	}
}

func (c *RPCClient) appendDiagnostic(values []byte) {
	c.diagnosticMu.Lock()
	defer c.diagnosticMu.Unlock()
	remaining := c.options.StderrLimit - len(c.diagnostics)
	if remaining <= 0 {
		return
	}
	if len(values) > remaining {
		values = values[:remaining]
	}
	c.diagnostics = append(c.diagnostics, values...)
}

func (c *RPCClient) Diagnostics() string {
	select {
	case <-c.stderrDone:
	case <-time.After(50 * time.Millisecond):
	}
	c.diagnosticMu.Lock()
	defer c.diagnosticMu.Unlock()
	return string(append([]byte(nil), c.diagnostics...))
}

func (c *RPCClient) Close() error {
	var closeErr error
	c.closeOnce.Do(func() {
		if c.input != nil {
			closeErr = c.input.Close()
		}
		c.fail(ErrClientClosed)
	})
	return closeErr
}

type Options struct {
	PollInterval       time.Duration
	MaxLineBytes       int
	StderrLimit        int
	OpenSessionOptions map[string]string
	Environment        []string
}

type Adapter struct {
	mu           sync.Mutex
	client       *RPCClient
	options      Options
	capabilities adapter.Capabilities
	sessionID    string
	opened       bool
	closed       bool
}

func NewClientAdapter(client *RPCClient, options Options) *Adapter {
	if options.PollInterval <= 0 {
		options.PollInterval = 25 * time.Millisecond
	}
	return &Adapter{client: client, options: options}
}

func (a *Adapter) Open(ctx context.Context) (adapter.Capabilities, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return adapter.Capabilities{}, ErrClientClosed
	}
	if a.opened {
		return a.capabilities, nil
	}
	var handshake HandshakeResult
	if err := a.client.Call(ctx, MethodHandshake, map[string]string{"protocol_version": ProtocolVersion}, &handshake); err != nil {
		return adapter.Capabilities{}, err
	}
	if handshake.Capabilities.ProtocolVersion != ProtocolVersion {
		return adapter.Capabilities{}, fmt.Errorf("%w: got %q, want %q", ErrProtocolVersion, handshake.Capabilities.ProtocolVersion, ProtocolVersion)
	}
	if !handshake.Capabilities.AsyncTasks {
		return adapter.Capabilities{}, fmt.Errorf("%w: plugin must support async tasks", adapter.ErrUnsupported)
	}
	var opened OpenSessionResult
	if err := a.client.Call(ctx, MethodOpenSession, OpenSessionParams{Options: a.options.OpenSessionOptions}, &opened); err != nil {
		return adapter.Capabilities{}, err
	}
	if opened.SessionID == "" {
		return adapter.Capabilities{}, fmt.Errorf("%w: empty session ID", ErrMalformedJSON)
	}
	a.sessionID = opened.SessionID
	a.capabilities = handshake.Capabilities
	a.opened = true
	return a.capabilities, nil
}

func (a *Adapter) Exec(ctx context.Context, request adapter.ExecRequest) (adapter.ExecResult, error) {
	started := time.Now().UTC()
	result := adapter.ExecResult{StartedAt: started}
	a.mu.Lock()
	if !a.opened || a.closed {
		a.mu.Unlock()
		result.Status = model.ProbeUnavailable
		result.FinishedAt = time.Now().UTC()
		return result, errors.New("plugin adapter is not open")
	}
	sessionID := a.sessionID
	capabilities := a.capabilities
	a.mu.Unlock()
	rendered, err := adapter.RenderPOSIX(request.Command)
	if err != nil {
		result.Status = model.ProbeUnavailable
		result.FinishedAt = time.Now().UTC()
		return result, err
	}
	if capabilities.MaxCommandBytes > 0 && len(rendered) > capabilities.MaxCommandBytes {
		result.Status = model.ProbeUnavailable
		result.FinishedAt = time.Now().UTC()
		return result, adapter.ErrCommandTooLarge
	}
	maxOutput := request.MaxOutput
	if maxOutput <= 0 || capabilities.MaxOutputBytes > 0 && maxOutput > capabilities.MaxOutputBytes {
		maxOutput = capabilities.MaxOutputBytes
	}
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	execContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var accepted ExecAccepted
	if err := a.client.Call(execContext, MethodExec, ExecParams{
		SessionID: sessionID, ProbeID: request.ProbeID, VariantID: request.VariantID,
		Command: rendered, TimeoutMS: timeout.Milliseconds(), MaxOutput: maxOutput,
	}, &accepted); err != nil {
		return a.execFailure(result, execContext, err)
	}
	if accepted.TaskID == "" {
		result.Status = model.ProbeParseError
		result.FinishedAt = time.Now().UTC()
		return result, fmt.Errorf("%w: exec returned empty task ID", ErrMalformedJSON)
	}
	for {
		var polled PollResult
		err := a.client.Call(execContext, MethodPoll, PollParams{SessionID: sessionID, TaskID: accepted.TaskID}, &polled)
		if err != nil {
			if execContext.Err() != nil {
				a.cancelTask(sessionID, accepted.TaskID, capabilities.Cancel)
			}
			return a.execFailure(result, execContext, err)
		}
		switch polled.State {
		case TaskPending:
			timer := time.NewTimer(a.options.PollInterval)
			select {
			case <-execContext.Done():
				timer.Stop()
				a.cancelTask(sessionID, accepted.TaskID, capabilities.Cancel)
				return a.execFailure(result, execContext, execContext.Err())
			case <-timer.C:
			}
		case TaskComplete:
			if polled.Result == nil {
				result.Status = model.ProbeParseError
				result.FinishedAt = time.Now().UTC()
				return result, fmt.Errorf("%w: completed task has no result", ErrMalformedJSON)
			}
			result = *polled.Result
			if result.StartedAt.IsZero() {
				result.StartedAt = started
			}
			if result.FinishedAt.IsZero() {
				result.FinishedAt = time.Now().UTC()
			}
			applyOutputLimit(&result, maxOutput)
			if result.Status == "" {
				result.Status = model.ProbeComplete
			}
			return result, nil
		case TaskFailed:
			result.Status = model.ProbePartial
			result.FinishedAt = time.Now().UTC()
			return result, fmt.Errorf("plugin task failed: %s", polled.Error)
		case TaskCancelled:
			result.Status = model.ProbePartial
			result.FinishedAt = time.Now().UTC()
			return result, context.Canceled
		default:
			result.Status = model.ProbeParseError
			result.FinishedAt = time.Now().UTC()
			return result, fmt.Errorf("%w: unknown task state %q", ErrMalformedJSON, polled.State)
		}
	}
}

func (a *Adapter) cancelTask(sessionID, taskID string, supported bool) {
	if !supported {
		return
	}
	cancelContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var ignored CancelResult
	_ = a.client.Call(cancelContext, MethodCancel, CancelParams{SessionID: sessionID, TaskID: taskID}, &ignored)
}

func (a *Adapter) execFailure(result adapter.ExecResult, execContext context.Context, err error) (adapter.ExecResult, error) {
	result.FinishedAt = time.Now().UTC()
	if errors.Is(execContext.Err(), context.DeadlineExceeded) {
		result.Status = model.ProbeTimeout
		return result, context.DeadlineExceeded
	}
	if errors.Is(execContext.Err(), context.Canceled) {
		result.Status = model.ProbePartial
		return result, context.Canceled
	}
	result.Status = model.ProbePartial
	return result, err
}

func applyOutputLimit(result *adapter.ExecResult, limit int) {
	if limit <= 0 {
		return
	}
	remaining := limit
	if len(result.Stdout) > remaining {
		result.Stdout = result.Stdout[:remaining]
		result.Stderr = nil
		result.Truncated = true
		result.Status = model.ProbeTruncated
		return
	}
	remaining -= len(result.Stdout)
	if len(result.Stderr) > remaining {
		result.Stderr = result.Stderr[:remaining]
		result.Truncated = true
		result.Status = model.ProbeTruncated
	}
}

func (a *Adapter) Diagnostics() string {
	return a.client.Diagnostics()
}

func (a *Adapter) Close(ctx context.Context) error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	opened := a.opened
	sessionID := a.sessionID
	a.mu.Unlock()
	var callErr error
	if opened {
		callErr = a.client.Call(ctx, MethodCloseSession, CloseSessionParams{SessionID: sessionID}, nil)
	}
	closeErr := a.client.Close()
	if callErr != nil {
		return callErr
	}
	return closeErr
}

var _ adapter.Adapter = (*Adapter)(nil)
