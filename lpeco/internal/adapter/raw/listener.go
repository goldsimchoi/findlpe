package raw

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

var (
	ErrBindRequired     = errors.New("raw listener bind address is required")
	ErrPublicBindDenied = errors.New("wildcard bind requires explicit public-bind permission")
	ErrAcceptTimeout    = errors.New("raw listener accept timed out")
)

type ListenerOptions struct {
	Bind            string
	AllowPublicBind bool
	AcceptTimeout   time.Duration
	Ready           func(net.Addr)
}

func Listen(ctx context.Context, options ListenerOptions) (io.ReadWriteCloser, error) {
	if strings.TrimSpace(options.Bind) == "" {
		return nil, ErrBindRequired
	}
	host, _, err := net.SplitHostPort(options.Bind)
	if err != nil {
		return nil, fmt.Errorf("parse raw listener bind address: %w", err)
	}
	if isWildcardHost(host) && !options.AllowPublicBind {
		return nil, ErrPublicBindDenied
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", options.Bind)
	if err != nil {
		return nil, fmt.Errorf("bind raw listener: %w", err)
	}
	defer listener.Close()
	if options.Ready != nil {
		options.Ready(listener.Addr())
	}
	timeout := options.AcceptTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	acceptContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type accepted struct {
		connection net.Conn
		err        error
	}
	result := make(chan accepted, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		result <- accepted{connection: connection, err: acceptErr}
	}()
	select {
	case <-acceptContext.Done():
		_ = listener.Close()
		if errors.Is(acceptContext.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w after %s", ErrAcceptTimeout, timeout)
		}
		return nil, acceptContext.Err()
	case outcome := <-result:
		if outcome.err != nil {
			return nil, fmt.Errorf("accept raw shell: %w", outcome.err)
		}
		return outcome.connection, nil
	}
}

func isWildcardHost(host string) bool {
	if host == "" {
		return true
	}
	address := net.ParseIP(strings.Trim(host, "[]"))
	return address != nil && address.IsUnspecified()
}
