package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/adapter/plugin"
	"github.com/normalone/lpeco/internal/adapter/raw"
	sshtransport "github.com/normalone/lpeco/internal/adapter/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func integrationTransport(t *testing.T, kind string) adapter.Adapter {
	t.Helper()
	switch kind {
	case "ssh":
		return integrationSSHTransport(t)
	case "raw-listen":
		return integrationRawListenerTransport(t)
	case "stdio-raw":
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		bridge, err := raw.StartBridge(ctx, []string{"sh"})
		if err != nil {
			t.Fatalf("start raw stdio bridge: %v", err)
		}
		return raw.New(bridge, raw.Options{TransportKind: kind, MaxOutputBytes: 1 << 20})
	case "c2-plugin":
		return integrationExamplePlugin(t)
	default:
		t.Fatalf("unknown integration transport %q", kind)
		return nil
	}
}

func integrationExamplePlugin(t *testing.T) adapter.Adapter {
	t.Helper()
	root := integrationRoot(t)
	binary := filepath.Join(t.TempDir(), "lpeco-c2-example")
	command := exec.Command("go", "build", "-trimpath", "-o", binary, "./test/integration/c2fixture")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build example plugin: %v\n%s", err, output)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	transport, err := plugin.Start(ctx, []string{binary}, plugin.Options{PollInterval: time.Millisecond})
	if err != nil {
		t.Fatalf("start example plugin: %v", err)
	}
	return transport
}

func integrationRawListenerTransport(t *testing.T) adapter.Adapter {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan net.Addr, 1)
	type listenResult struct {
		connection net.Conn
		err        error
	}
	accepted := make(chan listenResult, 1)
	go func() {
		connection, err := raw.Listen(ctx, raw.ListenerOptions{
			Bind: "127.0.0.1:0", AcceptTimeout: 5 * time.Second,
			Ready: func(address net.Addr) { ready <- address },
		})
		if err != nil {
			accepted <- listenResult{err: err}
			return
		}
		accepted <- listenResult{connection: connection.(net.Conn)}
	}()

	var address net.Addr
	select {
	case address = <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("raw listener did not become ready")
	}
	peer, err := net.DialTimeout("tcp", address.String(), 5*time.Second)
	if err != nil {
		t.Fatalf("connect raw fixture shell: %v", err)
	}
	shell := exec.CommandContext(ctx, "sh")
	shell.Stdin, shell.Stdout, shell.Stderr = peer, peer, peer
	if err := shell.Start(); err != nil {
		peer.Close()
		t.Fatalf("start raw fixture shell: %v", err)
	}
	shellDone := make(chan error, 1)
	go func() { shellDone <- shell.Wait() }()
	t.Cleanup(func() {
		_ = peer.Close()
		cancel()
		select {
		case <-shellDone:
		case <-time.After(2 * time.Second):
			t.Error("raw fixture shell did not exit")
		}
	})

	select {
	case outcome := <-accepted:
		if outcome.err != nil {
			t.Fatalf("accept raw fixture shell: %v", outcome.err)
		}
		return raw.New(outcome.connection, raw.Options{TransportKind: "raw-listen", MaxOutputBytes: 1 << 20})
	case <-time.After(5 * time.Second):
		t.Fatal("raw listener did not accept fixture shell")
		return nil
	}
}

func integrationSSHTransport(t *testing.T) adapter.Adapter {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	configuration := &cryptossh.ServerConfig{PasswordCallback: func(metadata cryptossh.ConnMetadata, password []byte) (*cryptossh.Permissions, error) {
		if metadata.User() != "fixture" || !bytes.Equal(password, []byte("fixture-password")) {
			return nil, errors.New("authentication failed")
		}
		return nil, nil
	}}
	configuration.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		serverDone <- serveIntegrationSSH(connection, configuration)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-serverDone:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("SSH fixture server: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("SSH fixture server did not exit")
		}
	})

	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{listener.Addr().String()}, hostSigner.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	transport, err := sshtransport.New(sshtransport.Config{
		Target: listener.Addr().String(), User: "fixture", KnownHostsPath: knownHostsPath,
		PasswordCallback: func(context.Context) ([]byte, error) { return []byte("fixture-password"), nil },
		DialTimeout:      time.Second, DefaultCommandTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return transport
}

func serveIntegrationSSH(connection net.Conn, configuration *cryptossh.ServerConfig) error {
	server, channels, requests, err := cryptossh.NewServerConn(connection, configuration)
	if err != nil {
		return err
	}
	defer server.Close()
	go cryptossh.DiscardRequests(requests)
	for requested := range channels {
		if requested.ChannelType() != "session" {
			_ = requested.Reject(cryptossh.UnknownChannelType, "session channels only")
			continue
		}
		channel, channelRequests, err := requested.Accept()
		if err != nil {
			return err
		}
		if err := serveIntegrationSSHSession(channel, channelRequests); err != nil {
			return err
		}
	}
	return nil
}

func serveIntegrationSSHSession(channel cryptossh.Channel, requests <-chan *cryptossh.Request) error {
	defer channel.Close()
	for request := range requests {
		if request.Type != "exec" {
			_ = request.Reply(false, nil)
			continue
		}
		var payload struct{ Command string }
		if err := cryptossh.Unmarshal(request.Payload, &payload); err != nil {
			_ = request.Reply(false, nil)
			return err
		}
		_ = request.Reply(true, nil)
		command := exec.Command("sh", "-c", payload.Command)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		runErr := command.Run()
		_, _ = channel.Write(stdout.Bytes())
		_, _ = channel.Stderr().Write(stderr.Bytes())
		exitCode := 0
		if runErr != nil {
			var exitError *exec.ExitError
			if !errors.As(runErr, &exitError) {
				return runErr
			}
			exitCode = exitError.ExitCode()
		}
		_, _ = channel.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{Status: uint32(exitCode)}))
		return nil
	}
	return fmt.Errorf("SSH session closed without exec request")
}

func integrationRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve integration test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
