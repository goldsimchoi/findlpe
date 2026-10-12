package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type layout struct {
	root       string
	session    string
	facts      string
	candidates string
	evidence   string
}

func newLayout(baseDir, sessionID string) (layout, error) {
	if strings.TrimSpace(baseDir) == "" {
		return layout{}, errors.New("state directory is required")
	}
	if !sessionIDPattern.MatchString(sessionID) {
		return layout{}, fmt.Errorf("invalid session ID %q", sessionID)
	}
	root := filepath.Join(baseDir, sessionID)
	return layout{
		root:       root,
		session:    filepath.Join(root, "session.json"),
		facts:      filepath.Join(root, "facts.jsonl"),
		candidates: filepath.Join(root, "candidates.json"),
		evidence:   filepath.Join(root, "evidence"),
	}, nil
}

func DefaultStateDir() (string, error) {
	if xdg := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "lpeco", "sessions"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}
	if home == "" {
		return "", errors.New("resolve user home directory: empty path")
	}
	return filepath.Join(home, ".local", "state", "lpeco", "sessions"), nil
}

func safeProbeID(value string) string {
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			builder.WriteRune(r)
		default:
			builder.WriteByte('_')
		}
	}
	if builder.Len() == 0 {
		return "probe"
	}
	return builder.String()
}
