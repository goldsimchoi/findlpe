package binary

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/normalone/lpeco/internal/model"
)

type Diagnostic struct {
	Code        string   `json:"code"`
	Message     string   `json:"message"`
	Path        string   `json:"path,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type DependencyFact struct {
	ConsumerPath string           `json:"consumer_path"`
	Kind         string           `json:"kind"`
	Target       string           `json:"target"`
	Resolved     bool             `json:"resolved"`
	EvidenceIDs  []string         `json:"evidence_ids"`
	MissingFacts []string         `json:"missing_facts,omitempty"`
	Confidence   model.Confidence `json:"confidence"`
}

func ParseELF(path string, input []byte, evidenceID string) ([]DependencyFact, []Diagnostic) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 8*1024*1024)
	var facts []DependencyFact
	var diagnostics []Diagnostic
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "SHEBANG=") {
			decoded, err := hex.DecodeString(strings.TrimPrefix(line, "SHEBANG="))
			if err != nil {
				diagnostics = append(diagnostics, Diagnostic{Code: "invalid-shebang-encoding", Message: err.Error(), Path: path, EvidenceIDs: []string{evidenceID}})
				continue
			}
			if target := parseShebangTarget(string(decoded)); target != "" {
				facts = append(facts, dependency(path, "script", target, strings.HasPrefix(target, "/"), evidenceID))
			}
			continue
		}
		if marker := "Requesting program interpreter:"; strings.Contains(line, marker) {
			target := strings.TrimSpace(strings.TrimSuffix(strings.SplitN(line, marker, 2)[1], "]"))
			facts = append(facts, dependency(path, "interpreter", target, strings.HasPrefix(target, "/"), evidenceID))
			continue
		}
		if strings.Contains(line, "(NEEDED)") {
			if target, ok := bracketValue(line); ok {
				facts = append(facts, dependency(path, "needed", target, strings.HasPrefix(target, "/"), evidenceID))
			}
			continue
		}
		if strings.Contains(line, "(RPATH)") {
			if value, ok := bracketValue(line); ok {
				for _, target := range strings.Split(value, ":") {
					facts = append(facts, dependency(path, "rpath", target, strings.HasPrefix(target, "/"), evidenceID))
				}
			}
			continue
		}
		if strings.Contains(line, "(RUNPATH)") {
			if value, ok := bracketValue(line); ok {
				for _, target := range strings.Split(value, ":") {
					facts = append(facts, dependency(path, "runpath", target, strings.HasPrefix(target, "/") && !strings.Contains(target, "$"), evidenceID))
				}
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "NEEDED" {
			facts = append(facts, dependency(path, "needed", fields[1], strings.HasPrefix(fields[1], "/"), evidenceID))
		} else if len(fields) >= 2 && (fields[0] == "RPATH" || fields[0] == "RUNPATH") {
			kind := strings.ToLower(fields[0])
			for _, target := range strings.Split(fields[1], ":") {
				facts = append(facts, dependency(path, kind, target, strings.HasPrefix(target, "/") && !strings.Contains(target, "$"), evidenceID))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		diagnostics = append(diagnostics, Diagnostic{Code: "elf-output-read-error", Message: err.Error(), Path: path, EvidenceIDs: []string{evidenceID}})
	}
	return facts, diagnostics
}

func dependency(consumer, kind, target string, resolved bool, evidenceID string) DependencyFact {
	fact := DependencyFact{ConsumerPath: consumer, Kind: kind, Target: target, Resolved: resolved, EvidenceIDs: []string{evidenceID}, Confidence: model.ConfidenceHigh}
	if !resolved {
		fact.MissingFacts = append(fact.MissingFacts, fmt.Sprintf("%s target is not resolved to an absolute path", kind))
		fact.Confidence = model.ConfidenceMedium
	}
	return fact
}

func bracketValue(value string) (string, bool) {
	start := strings.IndexByte(value, '[')
	end := strings.LastIndexByte(value, ']')
	if start < 0 || end <= start {
		return "", false
	}
	return value[start+1 : end], true
}

func parseShebangTarget(value string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(value), "\n")
	line = strings.TrimSpace(strings.TrimPrefix(line, "#!"))
	if line == "" {
		return ""
	}
	return line
}
