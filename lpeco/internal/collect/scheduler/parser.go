package scheduler

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/normalone/lpeco/internal/model"
)

type Diagnostic struct {
	Code        string   `json:"code"`
	Message     string   `json:"message"`
	SourcePath  string   `json:"source_path,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type ScheduleFact struct {
	Kind         string           `json:"kind"`
	SourcePath   string           `json:"source_path"`
	User         string           `json:"user"`
	Schedule     string           `json:"schedule"`
	Command      string           `json:"command"`
	Interpreter  string           `json:"interpreter,omitempty"`
	Script       string           `json:"script,omitempty"`
	TriggerPath  string           `json:"trigger_path,omitempty"`
	Active       bool             `json:"active"`
	EvidenceIDs  []string         `json:"evidence_ids"`
	MissingFacts []string         `json:"missing_facts,omitempty"`
	Confidence   model.Confidence `json:"confidence"`
}

func ParseCron(sourcePath, owner string, system bool, input []byte, evidenceID string) []ScheduleFact {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var facts []ScheduleFact
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || isEnvironmentAssignment(line) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		var schedule, user, command string
		if strings.HasPrefix(fields[0], "@") {
			minimum := 2
			if system {
				minimum = 3
			}
			if len(fields) < minimum {
				continue
			}
			schedule = fields[0]
			if system {
				user = fields[1]
				command = strings.Join(fields[2:], " ")
			} else {
				user = owner
				command = strings.Join(fields[1:], " ")
			}
		} else {
			minimum := 6
			if system {
				minimum = 7
			}
			if len(fields) < minimum {
				continue
			}
			schedule = strings.Join(fields[:5], " ")
			if system {
				user = fields[5]
				command = strings.Join(fields[6:], " ")
			} else {
				user = owner
				command = strings.Join(fields[5:], " ")
			}
		}
		interpreter, script := commandChain(command)
		fact := ScheduleFact{
			Kind: "cron", SourcePath: sourcePath, User: user, Schedule: schedule, Command: command,
			Interpreter: interpreter, Script: script, Active: true, EvidenceIDs: []string{evidenceID}, Confidence: model.ConfidenceHigh,
		}
		if strings.Contains(command, "%") {
			fact.MissingFacts = append(fact.MissingFacts, "cron percent-input semantics not expanded")
			fact.Confidence = model.ConfidenceMedium
		}
		facts = append(facts, fact)
	}
	return facts
}

func ParsePeriodic(sourcePath, owner, schedule string, input []byte, evidenceID string) ScheduleFact {
	interpreter := shebangInterpreter(input)
	missing := []string{}
	confidence := model.ConfidenceHigh
	if interpreter == "" {
		missing = append(missing, "script interpreter unavailable")
		confidence = model.ConfidenceMedium
	}
	return ScheduleFact{
		Kind: "periodic", SourcePath: sourcePath, User: owner, Schedule: schedule, Command: sourcePath,
		Interpreter: interpreter, Script: sourcePath, Active: true, EvidenceIDs: []string{evidenceID}, MissingFacts: missing, Confidence: confidence,
	}
}

func ParseSysV(input []byte, evidenceID string) ([]ScheduleFact, []Diagnostic) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	lineNumber := 0
	var facts []ScheduleFact
	var diagnostics []Diagnostic
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if lineNumber == 1 {
			if line != "LPECO_SYSV_V1" {
				return nil, []Diagnostic{{Code: "unsupported-sysv-format", Message: "SysV framing header is missing", EvidenceIDs: []string{evidenceID}}}
			}
			continue
		}
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 4 || parts[0] != "LINK" {
			diagnostics = append(diagnostics, Diagnostic{Code: "malformed-sysv-link", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
			continue
		}
		trigger, err1 := decodeHex(parts[1])
		script, err2 := decodeHex(parts[2])
		shebang, err3 := decodeHex(parts[3])
		if err1 != nil || err2 != nil || err3 != nil {
			diagnostics = append(diagnostics, Diagnostic{Code: "invalid-sysv-encoding", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
			continue
		}
		interpreter := parseShebang(shebang)
		confidence := model.ConfidenceHigh
		missing := []string{}
		if interpreter == "" {
			confidence = model.ConfidenceMedium
			missing = append(missing, "init script interpreter unavailable")
		}
		facts = append(facts, ScheduleFact{
			Kind: "sysv", SourcePath: trigger, TriggerPath: trigger, User: "root", Schedule: "boot/runlevel", Command: script,
			Interpreter: interpreter, Script: script, Active: true, EvidenceIDs: []string{evidenceID}, MissingFacts: missing, Confidence: confidence,
		})
	}
	if err := scanner.Err(); err != nil {
		diagnostics = append(diagnostics, Diagnostic{Code: "sysv-read-error", Message: err.Error(), EvidenceIDs: []string{evidenceID}})
	}
	return facts, diagnostics
}

func ParseProbeOutput(input []byte, evidenceID string) ([]ScheduleFact, []Diagnostic) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	lineNumber := 0
	var facts []ScheduleFact
	var diagnostics []Diagnostic
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if lineNumber == 1 {
			if line != "LPECO_SCHEDULER_V1" {
				return nil, []Diagnostic{{Code: "unsupported-scheduler-format", Message: "scheduler framing header is missing", EvidenceIDs: []string{evidenceID}}}
			}
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) == 0 || line == "" {
			continue
		}
		switch parts[0] {
		case "CRON_SYSTEM", "CRON_USER":
			if len(parts) != 4 {
				diagnostics = append(diagnostics, Diagnostic{Code: "malformed-cron-source", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
				continue
			}
			path, err1 := decodeHex(parts[1])
			owner, err2 := decodeHex(parts[2])
			content, err3 := decodeHex(parts[3])
			if err1 != nil || err2 != nil || err3 != nil {
				diagnostics = append(diagnostics, Diagnostic{Code: "invalid-cron-encoding", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
				continue
			}
			facts = append(facts, ParseCron(path, owner, parts[0] == "CRON_SYSTEM", []byte(content), evidenceID)...)
		case "PERIODIC":
			if len(parts) != 5 {
				continue
			}
			path, err1 := decodeHex(parts[1])
			owner, err2 := decodeHex(parts[2])
			schedule, err3 := decodeHex(parts[3])
			content, err4 := decodeHex(parts[4])
			if err1 == nil && err2 == nil && err3 == nil && err4 == nil {
				facts = append(facts, ParsePeriodic(path, owner, schedule, []byte(content), evidenceID))
			}
		case "SYSV":
			if len(parts) != 4 {
				continue
			}
			encoded := []byte("LPECO_SYSV_V1\nLINK\t" + parts[1] + "\t" + parts[2] + "\t" + parts[3] + "\n")
			parsed, parsedDiagnostics := ParseSysV(encoded, evidenceID)
			facts = append(facts, parsed...)
			diagnostics = append(diagnostics, parsedDiagnostics...)
		}
	}
	return facts, diagnostics
}

func Facts(values []ScheduleFact) ([]model.Fact, error) {
	facts := make([]model.Fact, 0, len(values))
	for _, value := range values {
		data, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		id, err := model.StableID("fact", struct {
			Kind string
			Data json.RawMessage
		}{"schedule", data})
		if err != nil {
			return nil, err
		}
		facts = append(facts, model.Fact{ID: id, Kind: "schedule", SourceCollector: "scheduler", EvidenceIDs: value.EvidenceIDs, Confidence: value.Confidence, Data: data})
	}
	return facts, nil
}

func isEnvironmentAssignment(line string) bool {
	key, _, found := strings.Cut(line, "=")
	if !found || strings.ContainsAny(key, " \t") || key == "" {
		return false
	}
	for _, character := range key {
		if character != '_' && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func commandChain(command string) (string, string) {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "/bin/sh", ""
	}
	first := strings.Trim(fields[0], "'\"")
	base := filepath.Base(first)
	if isInterpreter(base) {
		for _, field := range fields[1:] {
			field = strings.Trim(field, "'\"")
			if strings.HasPrefix(field, "-") {
				continue
			}
			return first, field
		}
		return first, ""
	}
	if filepath.IsAbs(first) {
		return "/bin/sh", first
	}
	return "/bin/sh", ""
}

func isInterpreter(base string) bool {
	return base == "sh" || base == "bash" || base == "dash" || base == "zsh" || base == "perl" || base == "ruby" || base == "node" || base == "php" || strings.HasPrefix(base, "python")
}

func shebangInterpreter(input []byte) string {
	line, _, _ := strings.Cut(string(input), "\n")
	return parseShebang(line)
}

func parseShebang(line string) string {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "#!") {
		return ""
	}
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#!")))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func decodeHex(value string) (string, error) {
	decoded, err := hex.DecodeString(value)
	return string(decoded), err
}
