package binary

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/normalone/lpeco/internal/model"
)

type PackageOwnershipFact struct {
	Path         string           `json:"path"`
	Manager      string           `json:"manager"`
	Package      string           `json:"package,omitempty"`
	Owned        bool             `json:"owned"`
	EvidenceIDs  []string         `json:"evidence_ids"`
	MissingFacts []string         `json:"missing_facts,omitempty"`
	Confidence   model.Confidence `json:"confidence"`
}

func ParsePackageProbe(path string, input []byte, evidenceID string) PackageOwnershipFact {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	manager := "unknown"
	var payload strings.Builder
	line := 0
	for scanner.Scan() {
		line++
		if line == 1 && scanner.Text() == "LPECO_PACKAGE_V1" {
			continue
		}
		if line == 2 && strings.HasPrefix(scanner.Text(), "MANAGER\t") {
			manager = strings.TrimPrefix(scanner.Text(), "MANAGER\t")
			continue
		}
		payload.WriteString(scanner.Text())
		payload.WriteByte('\n')
	}
	return ParsePackageOwnership(path, manager, []byte(payload.String()), evidenceID)
}

func ParsePackageOwnership(path, manager string, input []byte, evidenceID string) PackageOwnershipFact {
	value := strings.TrimSpace(string(input))
	fact := PackageOwnershipFact{Path: path, Manager: manager, EvidenceIDs: []string{evidenceID}, Confidence: model.ConfidenceHigh}
	switch manager {
	case "dpkg":
		if packageName, _, found := strings.Cut(value, ":"); found && packageName != "" {
			fact.Package = strings.TrimSpace(packageName)
			fact.Owned = true
		}
	case "rpm":
		if value != "" && !strings.Contains(strings.ToLower(value), "not owned") {
			fact.Package = strings.Fields(value)[0]
			fact.Owned = true
		}
	case "apk":
		if _, packageName, found := strings.Cut(value, " is owned by "); found {
			fact.Package = strings.Fields(packageName)[0]
			fact.Owned = true
		}
	default:
		fact.Confidence = model.ConfidenceLow
		fact.MissingFacts = append(fact.MissingFacts, "package manager unavailable")
	}
	if !fact.Owned && len(fact.MissingFacts) == 0 {
		fact.Confidence = model.ConfidenceMedium
		fact.MissingFacts = append(fact.MissingFacts, "package ownership not confirmed")
	}
	return fact
}
