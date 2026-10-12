package adapter

import (
	"fmt"
	"strings"
)

type Command struct {
	Script string   `json:"script"`
	Args   []string `json:"args,omitempty"`
}

func RenderPOSIX(command Command) (string, error) {
	if command.Script == "" {
		return "", fmt.Errorf("%w: script is empty", ErrInvalidCommand)
	}
	if strings.IndexByte(command.Script, 0) >= 0 {
		return "", fmt.Errorf("%w: script contains NUL", ErrInvalidCommand)
	}

	parts := make([]string, 0, len(command.Args)+3)
	parts = append(parts, "sh", "-c", quotePOSIX(command.Script), "lpeco")
	for _, argument := range command.Args {
		if strings.IndexByte(argument, 0) >= 0 {
			return "", fmt.Errorf("%w: argument contains NUL", ErrInvalidCommand)
		}
		parts = append(parts, quotePOSIX(argument))
	}
	return strings.Join(parts, " "), nil
}

func quotePOSIX(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
