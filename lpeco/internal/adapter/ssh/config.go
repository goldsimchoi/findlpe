package ssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type PasswordCallback func(context.Context) ([]byte, error)

type Config struct {
	Target                string           `json:"target"`
	User                  string           `json:"user"`
	KnownHostsPath        string           `json:"known_hosts_path,omitempty"`
	KeyPath               string           `json:"key_path,omitempty"`
	AgentSocket           string           `json:"agent_socket,omitempty"`
	PasswordCallback      PasswordCallback `json:"-"`
	InsecureIgnoreHostKey bool             `json:"insecure_ignore_host_key"`
	DialTimeout           time.Duration    `json:"dial_timeout,omitempty"`
	DefaultCommandTimeout time.Duration    `json:"default_command_timeout,omitempty"`
	MaxCommandBytes       int              `json:"max_command_bytes,omitempty"`
	MaxOutputBytes        int              `json:"max_output_bytes,omitempty"`

	agentDial func(context.Context, string, string) (net.Conn, error)
}

func normalizeConfig(configuration Config) (Config, cryptossh.HostKeyCallback, error) {
	configuration.Target = strings.TrimSpace(configuration.Target)
	configuration.User = strings.TrimSpace(configuration.User)
	if configuration.Target == "" || configuration.User == "" {
		return Config{}, nil, errors.New("SSH target and user are required")
	}
	if _, _, err := net.SplitHostPort(configuration.Target); err != nil {
		if strings.Contains(configuration.Target, ":") {
			return Config{}, nil, fmt.Errorf("SSH target must include a valid port: %w", err)
		}
		configuration.Target = net.JoinHostPort(configuration.Target, "22")
	}
	if configuration.DialTimeout <= 0 {
		configuration.DialTimeout = 10 * time.Second
	}
	if configuration.DefaultCommandTimeout <= 0 {
		configuration.DefaultCommandTimeout = 30 * time.Second
	}
	if configuration.MaxCommandBytes <= 0 {
		configuration.MaxCommandBytes = 64 * 1024
	}
	if configuration.MaxOutputBytes <= 0 {
		configuration.MaxOutputBytes = 4 * 1024 * 1024
	}
	if configuration.agentDial == nil {
		dialer := &net.Dialer{}
		configuration.agentDial = dialer.DialContext
	}

	if configuration.InsecureIgnoreHostKey {
		return configuration, cryptossh.InsecureIgnoreHostKey(), nil
	}
	knownHostsPath := configuration.KnownHostsPath
	if knownHostsPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Config{}, nil, fmt.Errorf("resolve home for known_hosts: %w", err)
		}
		knownHostsPath = filepath.Join(home, ".ssh", "known_hosts")
	}
	hostKeyCallback, err := knownhosts.New(knownHostsPath)
	if err != nil {
		return Config{}, nil, fmt.Errorf("load known_hosts %q: %w", knownHostsPath, err)
	}
	configuration.KnownHostsPath = knownHostsPath
	return configuration, hostKeyCallback, nil
}
