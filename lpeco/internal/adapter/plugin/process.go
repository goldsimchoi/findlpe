package plugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
)

func Start(ctx context.Context, arguments []string, options Options) (*Adapter, error) {
	if len(arguments) == 0 || arguments[0] == "" {
		return nil, errors.New("plugin command is required")
	}
	command := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	if options.Environment != nil {
		command.Env = append(os.Environ(), options.Environment...)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create plugin stdin: %w", err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("create plugin stdout: %w", err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("create plugin stderr: %w", err)
	}
	if err := command.Start(); err != nil {
		stdin.Close()
		return nil, fmt.Errorf("start plugin process: %w", err)
	}
	client := NewRPCClient(stdin, stdout, stderr, command.Wait, ClientOptions{
		MaxLineBytes: options.MaxLineBytes,
		StderrLimit:  options.StderrLimit,
	})
	client.setTerminator(command.Process.Kill)
	return NewClientAdapter(client, options), nil
}
