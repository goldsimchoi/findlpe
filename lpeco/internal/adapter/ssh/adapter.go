package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/model"
	cryptossh "golang.org/x/crypto/ssh"
)

var ErrClosed = errors.New("SSH adapter is closed")

type Adapter struct {
	mu              sync.Mutex
	configuration   Config
	hostKeyCallback cryptossh.HostKeyCallback
	client          *cryptossh.Client
	closed          bool
}

func New(configuration Config) (*Adapter, error) {
	normalized, hostKeyCallback, err := normalizeConfig(configuration)
	if err != nil {
		return nil, err
	}
	return &Adapter{configuration: normalized, hostKeyCallback: hostKeyCallback}, nil
}

func (a *Adapter) Open(ctx context.Context) (adapter.Capabilities, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return adapter.Capabilities{}, ErrClosed
	}
	if a.client != nil {
		return a.capabilities(), nil
	}
	authMethods, agentConnections, err := buildAuthMethods(ctx, a.configuration)
	if err != nil {
		return adapter.Capabilities{}, err
	}
	defer closeConnections(agentConnections)
	clientConfiguration := &cryptossh.ClientConfig{
		User:            a.configuration.User,
		Auth:            authMethods,
		HostKeyCallback: a.hostKeyCallback,
		Timeout:         a.configuration.DialTimeout,
	}
	dialContext, cancel := context.WithTimeout(ctx, a.configuration.DialTimeout)
	defer cancel()
	rawConnection, err := (&net.Dialer{}).DialContext(dialContext, "tcp", a.configuration.Target)
	if err != nil {
		return adapter.Capabilities{}, fmt.Errorf("dial SSH target: %w", err)
	}
	type handshake struct {
		connection cryptossh.Conn
		channels   <-chan cryptossh.NewChannel
		requests   <-chan *cryptossh.Request
		err        error
	}
	completed := make(chan handshake, 1)
	go func() {
		connection, channels, requests, handshakeErr := cryptossh.NewClientConn(rawConnection, a.configuration.Target, clientConfiguration)
		completed <- handshake{connection: connection, channels: channels, requests: requests, err: handshakeErr}
	}()
	select {
	case <-dialContext.Done():
		_ = rawConnection.Close()
		return adapter.Capabilities{}, dialContext.Err()
	case result := <-completed:
		if result.err != nil {
			_ = rawConnection.Close()
			return adapter.Capabilities{}, fmt.Errorf("SSH handshake: %w", result.err)
		}
		a.client = cryptossh.NewClient(result.connection, result.channels, result.requests)
		return a.capabilities(), nil
	}
}

func (a *Adapter) capabilities() adapter.Capabilities {
	return adapter.Capabilities{
		ProtocolVersion:    "1",
		TransportKind:      "ssh",
		Interactive:        false,
		TTY:                false,
		ReliableExitStatus: true,
		SeparateStderr:     true,
		AsyncTasks:         false,
		Cancel:             true,
		MaxCommandBytes:    a.configuration.MaxCommandBytes,
		MaxOutputBytes:     a.configuration.MaxOutputBytes,
		Upload:             false,
		Download:           false,
	}
}

func (a *Adapter) Exec(ctx context.Context, request adapter.ExecRequest) (adapter.ExecResult, error) {
	started := time.Now().UTC()
	result := adapter.ExecResult{StartedAt: started}
	rendered, err := adapter.RenderPOSIX(request.Command)
	if err != nil {
		result.Status = model.ProbeUnavailable
		result.FinishedAt = time.Now().UTC()
		return result, err
	}
	if len(rendered) > a.configuration.MaxCommandBytes {
		result.Status = model.ProbeUnavailable
		result.FinishedAt = time.Now().UTC()
		return result, adapter.ErrCommandTooLarge
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		result.Status = model.ProbeUnavailable
		result.FinishedAt = time.Now().UTC()
		return result, ErrClosed
	}
	client := a.client
	a.mu.Unlock()
	if client == nil {
		result.Status = model.ProbeUnavailable
		result.FinishedAt = time.Now().UTC()
		return result, errors.New("SSH adapter is not open")
	}
	session, err := client.NewSession()
	if err != nil {
		result.Status = model.ProbeUnavailable
		result.FinishedAt = time.Now().UTC()
		return result, fmt.Errorf("create SSH session: %w", err)
	}
	defer session.Close()
	limit := request.MaxOutput
	if limit <= 0 || limit > a.configuration.MaxOutputBytes {
		limit = a.configuration.MaxOutputBytes
	}
	outputs := newOutputBudget(limit)
	session.Stdout = outputs.stdoutWriter()
	session.Stderr = outputs.stderrWriter()
	timeout := request.Timeout
	if timeout <= 0 {
		timeout = a.configuration.DefaultCommandTimeout
	}
	execContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	completed := make(chan error, 1)
	go func() { completed <- session.Run(rendered) }()
	select {
	case <-execContext.Done():
		_ = session.Close()
		<-completed
		result.Stdout, result.Stderr, result.Truncated = outputs.snapshot()
		result.FinishedAt = time.Now().UTC()
		if errors.Is(execContext.Err(), context.DeadlineExceeded) {
			result.Status = model.ProbeTimeout
		} else {
			result.Status = model.ProbePartial
		}
		return result, adapter.MarkRetryable(execContext.Err())
	case runErr := <-completed:
		result.Stdout, result.Stderr, result.Truncated = outputs.snapshot()
		result.FinishedAt = time.Now().UTC()
		exitCode := 0
		if runErr != nil {
			var exitError *cryptossh.ExitError
			if !errors.As(runErr, &exitError) {
				result.Status = model.ProbePartial
				return result, adapter.MarkRetryable(fmt.Errorf("run SSH command: %w", runErr))
			}
			exitCode = exitError.ExitStatus()
		}
		result.ExitCode = &exitCode
		if result.Truncated {
			result.Status = model.ProbeTruncated
		} else {
			result.Status = model.ProbeComplete
		}
		return result, nil
	}
}

func (a *Adapter) Close(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	a.closed = true
	if a.client == nil {
		return nil
	}
	return a.client.Close()
}

type outputBudget struct {
	mu        sync.Mutex
	remaining int
	stdout    []byte
	stderr    []byte
	truncated bool
}

type budgetWriter struct {
	budget *outputBudget
	stderr bool
}

func newOutputBudget(limit int) *outputBudget {
	return &outputBudget{remaining: limit}
}

func (b *outputBudget) stdoutWriter() *budgetWriter { return &budgetWriter{budget: b} }
func (b *outputBudget) stderrWriter() *budgetWriter { return &budgetWriter{budget: b, stderr: true} }

func (w *budgetWriter) Write(values []byte) (int, error) {
	w.budget.mu.Lock()
	defer w.budget.mu.Unlock()
	accepted := len(values)
	if accepted > w.budget.remaining {
		accepted = w.budget.remaining
		w.budget.truncated = true
	}
	if accepted > 0 {
		if w.stderr {
			w.budget.stderr = append(w.budget.stderr, values[:accepted]...)
		} else {
			w.budget.stdout = append(w.budget.stdout, values[:accepted]...)
		}
		w.budget.remaining -= accepted
	}
	if accepted < len(values) {
		w.budget.truncated = true
	}
	return len(values), nil
}

func (b *outputBudget) snapshot() ([]byte, []byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.stdout...), append([]byte(nil), b.stderr...), b.truncated
}

var _ adapter.Adapter = (*Adapter)(nil)
