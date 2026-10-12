package ssh

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"reflect"
	"sync"
	"testing"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestNewRequiresVerifiedHostKeyByDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SSH_AUTH_SOCK", "")
	_, err := New(Config{Target: "127.0.0.1:22", User: "tester"})
	if err == nil {
		t.Fatal("New accepted missing known_hosts without explicit insecure opt-in")
	}
	if _, err := New(Config{Target: "127.0.0.1:22", User: "tester", InsecureIgnoreHostKey: true}); err != nil {
		t.Fatalf("explicit insecure host-key opt-in rejected: %v", err)
	}
}

func TestOpenRejectsHostKeyMismatch(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	server := startTestServer(t, serverOptions{
		passwordCallback: func(password []byte) error {
			if string(password) != "secret" {
				return errors.New("wrong password")
			}
			return nil
		},
	})
	_, wrongSigner := generateUserKey(t)
	knownHostsPath := t.TempDir() + "/known_hosts"
	line := knownhosts.Line([]string{server.address}, wrongSigner.PublicKey()) + "\n"
	if err := os.WriteFile(knownHostsPath, []byte(line), 0o600); err != nil {
		t.Fatalf("write wrong known_hosts: %v", err)
	}
	transport, err := New(Config{
		Target:         server.address,
		User:           "tester",
		KnownHostsPath: knownHostsPath,
		PasswordCallback: func(context.Context) ([]byte, error) {
			return []byte("secret"), nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := transport.Open(context.Background()); err == nil {
		t.Fatal("Open accepted a mismatched host key")
	}
}

func TestAuthenticationTriesAgentThenExplicitKeyBeforePassword(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	agentPrivate, agentSigner := generateUserKey(t)
	explicitPrivate, explicitSigner := generateUserKey(t)
	var mu sync.Mutex
	var attempts []string
	server := startTestServer(t, serverOptions{
		publicKeyCallback: func(key cryptossh.PublicKey) error {
			value := fingerprint(key)
			mu.Lock()
			if len(attempts) == 0 || attempts[len(attempts)-1] != value {
				attempts = append(attempts, value)
			}
			mu.Unlock()
			if value != fingerprint(explicitSigner.PublicKey()) {
				return rejectKey(key)
			}
			return nil
		},
	})
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: agentPrivate}); err != nil {
		t.Fatalf("add agent key: %v", err)
	}
	clientConnection, serverConnection := net.Pipe()
	go func() { _ = agent.ServeAgent(keyring, serverConnection) }()
	t.Cleanup(func() {
		_ = clientConnection.Close()
		_ = serverConnection.Close()
	})
	passwordCalls := 0
	configuration := Config{
		Target:         server.address,
		User:           "tester",
		KnownHostsPath: server.knownHostsFile(t),
		AgentSocket:    "fixture-agent",
		KeyPath:        writePrivateKey(t, explicitPrivate),
		PasswordCallback: func(context.Context) ([]byte, error) {
			passwordCalls++
			return []byte("unused"), nil
		},
	}
	configuration.agentDial = func(context.Context, string, string) (net.Conn, error) {
		return clientConnection, nil
	}
	transport, err := New(configuration)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := transport.Open(context.Background()); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = transport.Close(context.Background()) })
	mu.Lock()
	gotAttempts := append([]string(nil), attempts...)
	mu.Unlock()
	wantAttempts := []string{fingerprint(agentSigner.PublicKey()), fingerprint(explicitSigner.PublicKey())}
	if !reflect.DeepEqual(gotAttempts, wantAttempts) {
		t.Fatalf("public key attempts = %#v, want %#v", gotAttempts, wantAttempts)
	}
	if passwordCalls != 0 {
		t.Fatalf("password callback called %d times after key authentication", passwordCalls)
	}
}

func TestPasswordCallbackIsEphemeralAndExcludedFromJSON(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	server := startTestServer(t, serverOptions{
		passwordCallback: func(password []byte) error {
			if string(password) != "memory-only" {
				return errors.New("wrong password")
			}
			return nil
		},
	})
	secret := []byte("memory-only")
	callbackCalls := 0
	configuration := Config{
		Target:         server.address,
		User:           "tester",
		KnownHostsPath: server.knownHostsFile(t),
		PasswordCallback: func(context.Context) ([]byte, error) {
			callbackCalls++
			return secret, nil
		},
	}
	encoded, err := json.Marshal(configuration)
	if err != nil {
		t.Fatalf("marshal Config: %v", err)
	}
	if string(encoded) == "" || containsBytes(encoded, []byte("memory-only")) {
		t.Fatalf("serialized config contains password: %s", encoded)
	}
	transport, err := New(configuration)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if callbackCalls != 0 {
		t.Fatal("password callback ran before SSH authentication")
	}
	if _, err := transport.Open(context.Background()); err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = transport.Close(context.Background()) })
	if callbackCalls != 1 {
		t.Fatalf("password callback calls = %d, want 1", callbackCalls)
	}
	for index, value := range secret {
		if value != 0 {
			t.Fatalf("password byte %d was not cleared", index)
		}
	}
}

func containsBytes(haystack, needle []byte) bool {
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if reflect.DeepEqual(haystack[index:index+len(needle)], needle) {
			return true
		}
	}
	return false
}
