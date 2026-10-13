package raw

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestParseFrameAcrossEveryReadBoundary(t *testing.T) {
	nonce := "00112233445566778899aabbccddeeff"
	payload := []byte{0x00, 'A', 0xff, '\n'}
	transcript := append([]byte("banner\r\n$ echoed command\r\n"), startMarker(nonce)...)
	transcript = append(transcript, '\r', '\n')
	transcript = append(transcript, payload...)
	transcript = append(transcript, endPrefix(nonce)...)
	transcript = append(transcript, []byte("17\x1f\r\nprompt> ")...)

	for split := 0; split <= len(transcript); split++ {
		reader := io.MultiReader(
			bytes.NewReader(transcript[:split]),
			bytes.NewReader(transcript[split:]),
		)
		got, err := parseFrame(reader, nonce, 1024)
		if err != nil {
			t.Fatalf("split %d: parseFrame: %v", split, err)
		}
		if !bytes.Equal(got.Output, payload) || got.ExitCode != 17 || got.Truncated {
			t.Fatalf("split %d: result = %#v, want payload %v and exit 17", split, got, payload)
		}
	}
}

func TestParseFrameReportsMissingAndMalformedMarkers(t *testing.T) {
	nonce := "deadbeef"
	tests := []struct {
		name string
		data []byte
		want error
	}{
		{name: "missing start", data: []byte("prompt only"), want: ErrMissingStart},
		{name: "missing end", data: append(append(startMarker(nonce), '\n'), []byte("partial output")...), want: ErrMissingEnd},
		{name: "malformed exit", data: framedTranscript(nonce, []byte("output"), "not-a-number"), want: ErrMalformedExit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseFrame(bytes.NewReader(tt.data), nonce, 1024)
			if !errors.Is(err, tt.want) {
				t.Fatalf("parseFrame error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParseFrameTruncatesButConsumesEndMarker(t *testing.T) {
	nonce := "feedface"
	got, err := parseFrame(bytes.NewReader(framedTranscript(nonce, []byte("0123456789"), "0")), nonce, 4)
	if err != nil {
		t.Fatalf("parseFrame: %v", err)
	}
	if string(got.Output) != "0123" || !got.Truncated || got.ExitCode != 0 {
		t.Fatalf("result = %#v", got)
	}
}

func TestParseFrameRejectsOversizedUnterminatedExitStatusWithoutDrainingInput(t *testing.T) {
	nonce := "cab005e"
	prefix := append(append(append([]byte{}, startMarker(nonce)...), '\n'), endPrefix(nonce)...)
	reader := &oneByteReader{data: append(prefix, bytes.Repeat([]byte{'9'}, 4096)...)}

	_, err := parseFrame(reader, nonce, 1024)
	if !errors.Is(err, ErrMalformedExit) {
		t.Fatalf("parseFrame error = %v, want %v", err, ErrMalformedExit)
	}
	if suffixReads := reader.offset - len(prefix); suffixReads > 4 {
		t.Fatalf("parseFrame consumed %d exit-status bytes, want at most 4", suffixReads)
	}
}

type oneByteReader struct {
	data   []byte
	offset int
}

func (r *oneByteReader) Read(buffer []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	buffer[0] = r.data[r.offset]
	r.offset++
	return 1, nil
}

func framedTranscript(nonce string, output []byte, exit string) []byte {
	data := append([]byte{}, startMarker(nonce)...)
	data = append(data, '\n')
	data = append(data, output...)
	data = append(data, endPrefix(nonce)...)
	data = append(data, []byte(exit)...)
	data = append(data, 0x1f, '\n')
	return data
}
