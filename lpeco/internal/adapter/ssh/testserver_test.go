package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type serverOptions struct {
	hostSigner        cryptossh.Signer
	publicKeyCallback func(cryptossh.PublicKey) error
	passwordCallback  func([]byte) error
	handler           func(string, cryptossh.Channel)
}

type testServer struct {
	address    string
	hostSigner cryptossh.Signer
	listener   net.Listener
	done       chan struct{}
	closeOnce  sync.Once
}

func startTestServer(t *testing.T, options serverOptions) *testServer {
	t.Helper()
	if options.hostSigner == nil {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate host key: %v", err)
		}
		options.hostSigner, err = cryptossh.NewSignerFromKey(privateKey)
		if err != nil {
			t.Fatalf("create host signer: %v", err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen SSH fixture: %v", err)
	}
	server := &testServer{
		address:    listener.Addr().String(),
		hostSigner: options.hostSigner,
		listener:   listener,
		done:       make(chan struct{}),
	}
	configuration := &cryptossh.ServerConfig{}
	configuration.AddHostKey(options.hostSigner)
	configuration.PublicKeyCallback = func(_ cryptossh.ConnMetadata, key cryptossh.PublicKey) (*cryptossh.Permissions, error) {
		if options.publicKeyCallback == nil {
			return nil, errors.New("public-key authentication disabled")
		}
		return nil, options.publicKeyCallback(key)
	}
	configuration.PasswordCallback = func(_ cryptossh.ConnMetadata, password []byte) (*cryptossh.Permissions, error) {
		if options.passwordCallback == nil {
			return nil, errors.New("password authentication disabled")
		}
		return nil, options.passwordCallback(password)
	}
	if options.handler == nil {
		options.handler = defaultSSHHandler
	}
	go func() {
		defer close(server.done)
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go serveSSHConnection(connection, configuration, options.handler)
		}
	}()
	t.Cleanup(func() { server.Close() })
	return server
}

func (s *testServer) Close() {
	s.closeOnce.Do(func() {
		_ = s.listener.Close()
		<-s.done
	})
}

func (s *testServer) knownHostsFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{s.address}, s.hostSigner.PublicKey()) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return path
}

func serveSSHConnection(raw net.Conn, configuration *cryptossh.ServerConfig, handler func(string, cryptossh.Channel)) {
	connection, channels, requests, err := cryptossh.NewServerConn(raw, configuration)
	if err != nil {
		_ = raw.Close()
		return
	}
	defer connection.Close()
	go cryptossh.DiscardRequests(requests)
	for channelRequest := range channels {
		if channelRequest.ChannelType() != "session" {
			_ = channelRequest.Reject(cryptossh.UnknownChannelType, "session channels only")
			continue
		}
		channel, channelRequests, err := channelRequest.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer channel.Close()
			for request := range channelRequests {
				if request.Type != "exec" {
					_ = request.Reply(false, nil)
					continue
				}
				var payload struct{ Command string }
				if err := cryptossh.Unmarshal(request.Payload, &payload); err != nil {
					_ = request.Reply(false, nil)
					continue
				}
				_ = request.Reply(true, nil)
				handler(payload.Command, channel)
				return
			}
		}()
	}
}

func defaultSSHHandler(command string, channel cryptossh.Channel) {
	exitCode := uint32(0)
	switch {
	case strings.Contains(command, "ssh-ok"):
		_, _ = channel.Write([]byte("ssh-ok\n"))
	case strings.Contains(command, "emit"):
		_, _ = channel.Write([]byte("abcdef"))
		_, _ = channel.Stderr().Write([]byte("ERR"))
		exitCode = 7
	case strings.Contains(command, "slow"):
		_, _ = channel.Write([]byte("early"))
		time.Sleep(250 * time.Millisecond)
		_, _ = channel.Write([]byte("late"))
	default:
		_, _ = channel.Write([]byte("ok\n"))
	}
	_, _ = channel.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{exitCode}))
}

func generateUserKey(t *testing.T) (ed25519.PrivateKey, cryptossh.Signer) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}
	signer, err := cryptossh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create user signer: %v", err)
	}
	return privateKey, signer
}

func writePrivateKey(t *testing.T, privateKey ed25519.PrivateKey) string {
	t.Helper()
	block, err := cryptossh.MarshalPrivateKey(privateKey, "lpeco fixture")
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return path
}

func fingerprint(key cryptossh.PublicKey) string {
	return cryptossh.FingerprintSHA256(key)
}

func rejectKey(key cryptossh.PublicKey) error {
	return fmt.Errorf("key %s rejected", fingerprint(key))
}
