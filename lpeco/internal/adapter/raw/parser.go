package raw

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"sync"
)

type frameResult struct {
	Output    []byte
	ExitCode  int
	Truncated bool
}

type frameProgress struct {
	mu        sync.Mutex
	output    []byte
	truncated bool
}

func parseFrame(source io.Reader, nonce string, maxOutput int) (frameResult, error) {
	return parseFrameWithProgress(source, nonce, maxOutput, nil)
}

func parseFrameWithProgress(source io.Reader, nonce string, maxOutput int, progress *frameProgress) (frameResult, error) {
	reader := bufio.NewReader(source)
	if err := seekMarker(reader, startMarker(nonce)); err != nil {
		return frameResult{}, err
	}
	consumeNewline(reader)

	end := endPrefix(nonce)
	pending := make([]byte, 0, len(end))
	result := frameResult{}
	for {
		value, err := reader.ReadByte()
		if err != nil {
			flushFrameOutput(&result, progress, pending, maxOutput)
			if err == io.EOF {
				return result, ErrMissingEnd
			}
			return result, fmt.Errorf("%w: %v", ErrMissingEnd, err)
		}
		pending = append(pending, value)
		for len(pending) > 0 && !bytes.HasPrefix(end, pending) {
			flushFrameOutput(&result, progress, pending[:1], maxOutput)
			pending = pending[1:]
		}
		if len(pending) != len(end) {
			continue
		}

		exitCode, err := readExitStatus(reader)
		if err != nil {
			return result, err
		}
		result.ExitCode = exitCode
		return result, nil
	}
}

func readExitStatus(reader *bufio.Reader) (int, error) {
	var digits [3]byte
	length := 0
	for {
		value, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF {
				return 0, ErrMissingEnd
			}
			return 0, fmt.Errorf("%w: %v", ErrMissingEnd, err)
		}
		if value == 0x1f {
			if length == 0 {
				return 0, ErrMalformedExit
			}
			exitCode, err := strconv.Atoi(string(digits[:length]))
			if err != nil || exitCode > 255 {
				return 0, ErrMalformedExit
			}
			return exitCode, nil
		}
		if value < '0' || value > '9' || length == len(digits) {
			return 0, ErrMalformedExit
		}
		digits[length] = value
		length++
	}
}

func flushFrameOutput(result *frameResult, progress *frameProgress, values []byte, limit int) {
	flushOutput(result, values, limit)
	if progress != nil {
		progress.append(values, limit)
	}
}

func (p *frameProgress) append(values []byte, limit int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := frameResult{Output: p.output, Truncated: p.truncated}
	flushOutput(&result, values, limit)
	p.output = result.Output
	p.truncated = result.Truncated
}

func (p *frameProgress) snapshot() ([]byte, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.output...), p.truncated
}

func seekMarker(reader *bufio.Reader, marker []byte) error {
	pending := make([]byte, 0, len(marker))
	for {
		value, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF {
				return ErrMissingStart
			}
			return fmt.Errorf("%w: %v", ErrMissingStart, err)
		}
		pending = append(pending, value)
		for len(pending) > 0 && !bytes.HasPrefix(marker, pending) {
			pending = pending[1:]
		}
		if len(pending) == len(marker) {
			return nil
		}
	}
}

func consumeNewline(reader *bufio.Reader) {
	peek, err := reader.Peek(1)
	if err != nil {
		return
	}
	if peek[0] == '\n' {
		_, _ = reader.Discard(1)
		return
	}
	if peek[0] != '\r' {
		return
	}
	peek, err = reader.Peek(2)
	if err == nil && bytes.Equal(peek, []byte{'\r', '\n'}) {
		_, _ = reader.Discard(2)
	}
}

func flushOutput(result *frameResult, values []byte, limit int) {
	if len(values) == 0 {
		return
	}
	if limit <= 0 {
		result.Output = append(result.Output, values...)
		return
	}
	remaining := limit - len(result.Output)
	if remaining > 0 {
		if remaining > len(values) {
			remaining = len(values)
		}
		result.Output = append(result.Output, values[:remaining]...)
	}
	if remaining < len(values) {
		result.Truncated = true
	}
}
