package raw

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

func StartBridge(ctx context.Context, arguments []string) (io.ReadWriteCloser, error) {
	if len(arguments) == 0 || arguments[0] == "" {
		return nil, errors.New("stdio bridge command is required")
	}
	command := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
	input, err := command.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create bridge stdin: %w", err)
	}
	outputReader, outputWriter := io.Pipe()
	command.Stdout = outputWriter
	command.Stderr = outputWriter
	if err := command.Start(); err != nil {
		input.Close()
		outputReader.Close()
		outputWriter.Close()
		return nil, fmt.Errorf("start stdio bridge: %w", err)
	}
	bridge := &processBridge{
		input:   input,
		output:  outputReader,
		writer:  outputWriter,
		command: command,
		done:    make(chan error, 1),
	}
	go func() {
		waitErr := command.Wait()
		_ = outputWriter.CloseWithError(waitErr)
		bridge.done <- waitErr
	}()
	return bridge, nil
}

type processBridge struct {
	input    io.WriteCloser
	output   *io.PipeReader
	writer   *io.PipeWriter
	command  *exec.Cmd
	done     chan error
	once     sync.Once
	closeErr error
}

func (b *processBridge) Read(buffer []byte) (int, error) {
	return b.output.Read(buffer)
}

func (b *processBridge) Write(buffer []byte) (int, error) {
	return b.input.Write(buffer)
}

func (b *processBridge) Close() error {
	b.once.Do(func() {
		_ = b.input.Close()
		select {
		case err := <-b.done:
			if err != nil {
				b.closeErr = err
			}
		case <-time.After(500 * time.Millisecond):
			if b.command.Process != nil {
				_ = b.command.Process.Kill()
			}
			<-b.done
		}
		_ = b.writer.Close()
		_ = b.output.Close()
	})
	return b.closeErr
}
