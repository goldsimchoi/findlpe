package systemdunit

import (
	"strings"
)

type Source struct {
	Path       string
	EvidenceID string
	Content    []byte
}

type SourceRef struct {
	Path       string `json:"path"`
	Line       int    `json:"line"`
	EvidenceID string `json:"evidence_id"`
}

type Assignment struct {
	Section string    `json:"section"`
	Key     string    `json:"key"`
	Value   string    `json:"value"`
	Source  SourceRef `json:"source"`
	Line    int       `json:"line"`
}

type Diagnostic struct {
	Path    string `json:"path,omitempty"`
	Line    int    `json:"line,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Document struct {
	Source      Source       `json:"-"`
	Assignments []Assignment `json:"assignments"`
}

func Parse(source Source) (Document, []Diagnostic) {
	document := Document{Source: source}
	lines, diagnostics := lexLogicalLines(source.Content)
	for index := range diagnostics {
		diagnostics[index].Path = source.Path
	}
	section := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line.text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			if section == "" {
				diagnostics = append(diagnostics, Diagnostic{Path: source.Path, Line: line.line, Code: "empty-section", Message: "section name is empty"})
			}
			continue
		}
		key, value, found := strings.Cut(trimmed, "=")
		if !found {
			diagnostics = append(diagnostics, Diagnostic{Path: source.Path, Line: line.line, Code: "missing-equals", Message: "assignment lacks '='"})
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if section == "" {
			diagnostics = append(diagnostics, Diagnostic{Path: source.Path, Line: line.line, Code: "assignment-outside-section", Message: "assignment occurs before a section"})
			continue
		}
		if key == "" {
			diagnostics = append(diagnostics, Diagnostic{Path: source.Path, Line: line.line, Code: "empty-key", Message: "assignment key is empty"})
			continue
		}
		document.Assignments = append(document.Assignments, Assignment{
			Section: section, Key: key, Value: value, Line: line.line,
			Source: SourceRef{Path: source.Path, Line: line.line, EvidenceID: source.EvidenceID},
		})
	}
	return document, diagnostics
}
