package raw

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"

	"github.com/normalone/lpeco/internal/adapter"
)

var (
	ErrMissingStart  = errors.New("raw frame start marker not found")
	ErrMissingEnd    = errors.New("raw frame end marker not found")
	ErrMalformedExit = errors.New("raw frame exit status is malformed")
)

var noncePattern = regexp.MustCompile(`^[A-Fa-f0-9]{8,128}$`)

func randomNonce() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate frame nonce: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

func startMarker(nonce string) []byte {
	return []byte("\x1eLPECO:" + nonce + ":START\x1f")
}

func endPrefix(nonce string) []byte {
	return []byte("\x1eLPECO:" + nonce + ":END:")
}

func frameCommand(command adapter.Command, nonce string) (string, error) {
	if !noncePattern.MatchString(nonce) {
		return "", fmt.Errorf("%w: malformed frame nonce", adapter.ErrInvalidCommand)
	}
	rendered, err := adapter.RenderPOSIX(command)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"printf '\\036LPECO:%s:START\\037\\n'; if %s; then _lpeco_rc=0; else _lpeco_rc=$?; fi; printf '\\036LPECO:%s:END:%%s\\037\\n' \"$_lpeco_rc\"\n",
		nonce,
		rendered,
		nonce,
	), nil
}
