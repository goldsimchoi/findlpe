package raw

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestListenerRejectsUnsafeBindConfiguration(t *testing.T) {
	if _, err := Listen(context.Background(), ListenerOptions{}); !errors.Is(err, ErrBindRequired) {
		t.Fatalf("empty bind error = %v, want ErrBindRequired", err)
	}
	if _, err := Listen(context.Background(), ListenerOptions{Bind: "0.0.0.0:0", AcceptTimeout: time.Millisecond}); !errors.Is(err, ErrPublicBindDenied) {
		t.Fatalf("wildcard bind error = %v, want ErrPublicBindDenied", err)
	}
	if _, err := Listen(context.Background(), ListenerOptions{Bind: "[::]:0", AcceptTimeout: time.Millisecond}); !errors.Is(err, ErrPublicBindDenied) {
		t.Fatalf("IPv6 wildcard error = %v, want ErrPublicBindDenied", err)
	}
}

func TestListenerAcceptTimeout(t *testing.T) {
	ready := make(chan net.Addr, 1)
	_, err := Listen(context.Background(), ListenerOptions{
		Bind:          "127.0.0.1:0",
		AcceptTimeout: 20 * time.Millisecond,
		Ready:         func(address net.Addr) { ready <- address },
	})
	if !errors.Is(err, ErrAcceptTimeout) {
		t.Fatalf("Listen error = %v, want ErrAcceptTimeout", err)
	}
	select {
	case <-ready:
	default:
		t.Fatal("listener did not announce bound address")
	}
}

func TestListenerAcceptsExactlyOneConnection(t *testing.T) {
	ready := make(chan net.Addr, 1)
	accepted := make(chan ioResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		connection, err := Listen(ctx, ListenerOptions{
			Bind:          "127.0.0.1:0",
			AcceptTimeout: time.Second,
			Ready:         func(address net.Addr) { ready <- address },
		})
		accepted <- ioResult{connection: connection, err: err}
	}()
	address := <-ready
	client, err := net.Dial("tcp", address.String())
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	defer client.Close()
	result := <-accepted
	if result.err != nil {
		t.Fatalf("Listen: %v", result.err)
	}
	defer result.connection.Close()
	if second, err := net.DialTimeout("tcp", address.String(), 30*time.Millisecond); err == nil {
		second.Close()
		t.Fatal("listener accepted or remained open for a second connection")
	}
}

type ioResult struct {
	connection io.ReadWriteCloser
	err        error
}
