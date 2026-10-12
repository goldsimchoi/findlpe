package binary

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"strings"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

type DelegationFact struct {
	Subject      string           `json:"subject"`
	Host         string           `json:"host,omitempty"`
	RunAs        string           `json:"run_as"`
	Command      string           `json:"command"`
	NoPassword   bool             `json:"no_password"`
	SourceKind   string           `json:"source_kind"`
	SourcePath   string           `json:"source_path,omitempty"`
	EvidenceIDs  []string         `json:"evidence_ids"`
	MissingFacts []string         `json:"missing_facts,omitempty"`
	Confidence   model.Confidence `json:"confidence"`
}

const sudoersScript = `printf 'LPECO_SUDOERS_V1\n'
_lpeco_hex_file() { od -An -v -tx1 "$1" 2>/dev/null | tr -d ' \n'; }
_lpeco_hex_text() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
for _lpeco_file in /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$_lpeco_file" ] || continue
  [ -r "$_lpeco_file" ] || continue
  printf 'FILE\t%s\t%s\n' "$(_lpeco_hex_text "$_lpeco_file")" "$(_lpeco_hex_file "$_lpeco_file")"
done`

const sudoListScript = `LC_ALL=C sudo -n -l`

func SudoersDefinition() probe.Definition {
	return probe.Definition{
		ID: "binary.sudoers", Collector: "binary", Parser: "sudoers-v1", RedactionPolicy: "command-values", SafetyClass: model.PassiveRead,
		Variants: []probe.Variant{{ID: "files", Command: adapter.Command{Script: sudoersScript}}},
		Timeout:  10 * time.Second, MaxOutput: 2 * 1024 * 1024, Produces: []string{"delegation"}, Idempotent: true,
	}
}

func SudoListDefinition() probe.Definition {
	return probe.Definition{
		ID: "binary.sudo-list", Collector: "binary", Parser: "sudo-list", RedactionPolicy: "command-values", SafetyClass: model.ObservableRead,
		Variants: []probe.Variant{{ID: "non-interactive", Command: adapter.Command{Script: sudoListScript}, Requirements: []probe.Requirement{probe.CommandRequirement("sudo")}}},
		Timeout:  10 * time.Second, MaxOutput: 2 * 1024 * 1024, Produces: []string{"delegation"}, Idempotent: true,
	}
}

func ParseSudoers(sourcePath string, input []byte, evidenceID string) []DelegationFact {
	lines := logicalSudoersLines(input)
	var facts []DelegationFact
	for _, line := range lines {
		line = strings.TrimSpace(stripSudoersComment(line))
		if line == "" || strings.HasPrefix(line, "#include") || strings.HasPrefix(line, "@include") || strings.Contains(line, "_Alias ") || strings.HasPrefix(line, "Defaults") {
			continue
		}
		left, right, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		leftFields := strings.Fields(left)
		if len(leftFields) < 2 {
			continue
		}
		subject := leftFields[0]
		host := strings.Join(leftFields[1:], " ")
		right = strings.TrimSpace(right)
		runAs := "root"
		if strings.HasPrefix(right, "(") {
			if close := strings.IndexByte(right, ')'); close >= 0 {
				runAs = strings.TrimSpace(strings.Split(right[1:close], ":")[0])
				right = strings.TrimSpace(right[close+1:])
			}
		}
		noPassword := false
		if before, after, found := strings.Cut(right, ":"); found && isSudoTagList(before) {
			noPassword = containsWord(before, "NOPASSWD")
			right = strings.TrimSpace(after)
		}
		for _, command := range splitSudoCommands(right) {
			facts = append(facts, DelegationFact{
				Subject: subject, Host: host, RunAs: runAs, Command: command, NoPassword: noPassword,
				SourceKind: "sudoers-file", SourcePath: sourcePath, EvidenceIDs: []string{evidenceID}, Confidence: model.ConfidenceHigh,
			})
		}
	}
	return facts
}

func ParseSudoList(input []byte, evidenceID string) []DelegationFact {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	var facts []DelegationFact
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "(") {
			continue
		}
		close := strings.IndexByte(line, ')')
		if close < 0 {
			continue
		}
		runAs := strings.TrimSpace(strings.Split(line[1:close], ":")[0])
		rest := strings.TrimSpace(line[close+1:])
		noPassword := false
		if before, after, found := strings.Cut(rest, ":"); found && isSudoTagList(before) {
			noPassword = containsWord(before, "NOPASSWD")
			rest = strings.TrimSpace(after)
		}
		for _, command := range splitSudoCommands(rest) {
			facts = append(facts, DelegationFact{
				RunAs: runAs, Command: command, NoPassword: noPassword, SourceKind: "sudo-list",
				EvidenceIDs: []string{evidenceID}, Confidence: model.ConfidenceHigh,
			})
		}
	}
	return facts
}

func ParseSudoersProbe(input []byte, evidenceID string) []DelegationFact {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	line := 0
	var facts []DelegationFact
	for scanner.Scan() {
		line++
		if line == 1 {
			if scanner.Text() != "LPECO_SUDOERS_V1" {
				return nil
			}
			continue
		}
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) != 3 || parts[0] != "FILE" {
			continue
		}
		path, pathErr := hex.DecodeString(parts[1])
		content, contentErr := hex.DecodeString(parts[2])
		if pathErr == nil && contentErr == nil {
			facts = append(facts, ParseSudoers(string(path), content, evidenceID)...)
		}
	}
	return facts
}

func logicalSudoersLines(input []byte) []string {
	physical := strings.Split(strings.ReplaceAll(string(input), "\r\n", "\n"), "\n")
	var logical []string
	var current string
	for _, line := range physical {
		trimmed := strings.TrimRight(line, " \t")
		continued := strings.HasSuffix(trimmed, "\\")
		if continued {
			trimmed = strings.TrimSuffix(trimmed, "\\")
		}
		current += trimmed
		if continued {
			current += " "
			continue
		}
		logical = append(logical, current)
		current = ""
	}
	if current != "" {
		logical = append(logical, current)
	}
	return logical
}

func stripSudoersComment(value string) string {
	escaped := false
	for index, character := range value {
		if character == '#' && !escaped {
			return value[:index]
		}
		escaped = character == '\\' && !escaped
		if character != '\\' {
			escaped = false
		}
	}
	return value
}

func isSudoTagList(value string) bool {
	upper := strings.ToUpper(strings.TrimSpace(value))
	return strings.Contains(upper, "PASSWD") || strings.Contains(upper, "EXEC") || strings.Contains(upper, "SETENV") || strings.Contains(upper, "FOLLOW") || strings.Contains(upper, "LOG_")
}

func containsWord(value, wanted string) bool {
	for _, field := range strings.FieldsFunc(strings.ToUpper(value), func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		if field == wanted {
			return true
		}
	}
	return false
}

func splitSudoCommands(value string) []string {
	var result []string
	for _, command := range strings.Split(value, ",") {
		command = strings.TrimSpace(command)
		if command != "" {
			result = append(result, command)
		}
	}
	return result
}
