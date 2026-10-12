package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func buildAuthMethods(ctx context.Context, configuration Config) ([]cryptossh.AuthMethod, []net.Conn, error) {
	methods := make([]cryptossh.AuthMethod, 0, 3)
	publicSigners := make([]cryptossh.Signer, 0)
	connections := make([]net.Conn, 0, 1)
	agentSocket := configuration.AgentSocket
	explicitAgent := agentSocket != ""
	if agentSocket == "" {
		agentSocket = os.Getenv("SSH_AUTH_SOCK")
	}
	if agentSocket != "" {
		connection, err := configuration.agentDial(ctx, "unix", agentSocket)
		if err != nil {
			if explicitAgent {
				return nil, nil, fmt.Errorf("connect SSH agent %q: %w", agentSocket, err)
			}
		} else {
			signers, signerErr := agent.NewClient(connection).Signers()
			if signerErr != nil {
				connection.Close()
				if explicitAgent {
					return nil, nil, fmt.Errorf("list SSH agent keys: %w", signerErr)
				}
			} else if len(signers) > 0 {
				publicSigners = append(publicSigners, signers...)
				connections = append(connections, connection)
			} else {
				connection.Close()
			}
		}
	}

	if configuration.KeyPath != "" {
		privateKey, err := os.ReadFile(configuration.KeyPath)
		if err != nil {
			closeConnections(connections)
			return nil, nil, fmt.Errorf("read SSH private key: %w", err)
		}
		signer, err := cryptossh.ParsePrivateKey(privateKey)
		clear(privateKey)
		if err != nil {
			closeConnections(connections)
			return nil, nil, fmt.Errorf("parse SSH private key: %w", err)
		}
		publicSigners = append(publicSigners, signer)
	}
	if len(publicSigners) > 0 {
		methods = append(methods, cryptossh.PublicKeys(publicSigners...))
	}

	if configuration.PasswordCallback != nil {
		callback := configuration.PasswordCallback
		methods = append(methods, cryptossh.PasswordCallback(func() (string, error) {
			secret, err := callback(ctx)
			if err != nil {
				return "", err
			}
			if len(secret) == 0 {
				return "", errors.New("SSH password callback returned an empty password")
			}
			password := string(secret)
			clear(secret)
			return password, nil
		}))
	}
	if len(methods) == 0 {
		closeConnections(connections)
		return nil, nil, errors.New("no SSH authentication method is available")
	}
	return methods, connections, nil
}

func closeConnections(connections []net.Conn) {
	for _, connection := range connections {
		_ = connection.Close()
	}
}
