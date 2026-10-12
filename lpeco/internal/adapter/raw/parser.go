package raw

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
)

type frameResult struct {
	Output    []byte
	ExitCode  int
	Truncated bool
}

func parseFrame(source io.Reader, nonce string, maxOutput int) (frameResult, error) {
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
			flushOutput(&result, pending, maxOutput)
			if err == io.EOF {
				return result, ErrMissingEnd
			}
			return result, fmt.Errorf("%w: %v", ErrMissingEnd, err)
		}
		pending = append(pending, value)
		for len(pending) > 0 && !bytes.HasPrefix(end, pending) {
			flushOutput(&result, pending[:1], maxOutput)
			pending = pending[1:]
		}
		if len(pending) != len(end) {
			continue
		}

		exitText, err := reader.ReadString(0x1f)
		if err != nil {
			return result, ErrMissingEnd
		}
		exitText = exitText[:len(exitText)-1]
		exitCode, err := strconv.Atoi(exitText)
		if err != nil || exitCode < 0 || exitCode > 255 {
			return result, fmt.Errorf("%w: %q", ErrMalformedExit, exitText)
		}
		result.ExitCode = exitCode
		return result, nil
	}
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
