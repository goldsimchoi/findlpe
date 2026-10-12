package adapter

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestRenderPOSIXPreservesUntrustedArguments(t *testing.T) {
	args := []string{
		"apostrophe'kept",
		"line one\nline two",
		"$(printf injected)",
		"`printf injected`",
		"-leading-dash",
	}
	command := Command{
		Script: `for value do printf '<%s>\n' "$value"; done`,
		Args:   args,
	}

	rendered, err := RenderPOSIX(command)
	if err != nil {
		t.Fatalf("RenderPOSIX: %v", err)
	}
	output, err := exec.Command("sh", "-c", rendered).CombinedOutput()
	if err != nil {
		t.Fatalf("execute rendered command: %v (%s)", err, output)
	}
	var expected strings.Builder
	for _, arg := range args {
		expected.WriteString("<")
		expected.WriteString(arg)
		expected.WriteString(">\n")
	}
	if string(output) != expected.String() {
		t.Fatalf("rendered output = %q, want %q\ncommand: %s", output, expected.String(), rendered)
	}
}

func TestRenderPOSIXRejectsNUL(t *testing.T) {
	tests := []Command{
		{Script: "printf ok\x00bad"},
		{Script: "printf '%s' \"$1\"", Args: []string{"ok\x00bad"}},
	}
	for _, command := range tests {
		if _, err := RenderPOSIX(command); !errors.Is(err, ErrInvalidCommand) {
			t.Fatalf("RenderPOSIX(%#v) error = %v, want ErrInvalidCommand", command, err)
		}
	}
}
