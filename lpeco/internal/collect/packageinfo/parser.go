package packageinfo

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/normalone/lpeco/internal/model"
)

type ownershipRecord struct {
	fact     OwnershipFact
	observed map[string]bool
	resolved map[string]bool
}

func ParseOwnership(input []byte, evidenceID string) ([]OwnershipFact, []Diagnostic) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	lineNumber := 0
	header := false
	byPath := make(map[string]OwnershipFact)
	var order []string
	var current *ownershipRecord
	var diagnostics []Diagnostic

	finish := func(truncated bool) {
		if current == nil {
			return
		}
		if truncated {
			current.fact.MissingFacts = append(current.fact.MissingFacts, "ownership record is truncated")
			diagnostics = append(diagnostics, Diagnostic{Code: "truncated-ownership-record", Message: current.fact.Path, EvidenceIDs: []string{evidenceID}})
		}
		current.fact.ObservedPackages = sortedKeys(current.observed)
		current.fact.ResolvedPackages = sortedKeys(current.resolved)
		union := make(map[string]bool)
		for packageName := range current.observed {
			union[packageName] = true
		}
		for packageName := range current.resolved {
			union[packageName] = true
		}
		current.fact.Packages = sortedKeys(union)
		current.fact.Owned = len(current.fact.Packages) > 0
		if len(current.fact.Packages) > 1 {
			current.fact.Ambiguous = true
			current.fact.MissingFacts = append(current.fact.MissingFacts, "package ownership is ambiguous")
		}
		if len(current.observed) > 0 && len(current.resolved) > 0 && !equalSets(current.observed, current.resolved) {
			current.fact.Ambiguous = true
			current.fact.MissingFacts = append(current.fact.MissingFacts, "observed and resolved ownership conflict")
		}
		if current.fact.Manager != "dpkg" {
			if current.fact.Manager == "rpm" || current.fact.Manager == "apk" {
				current.fact.MissingFacts = append(current.fact.MissingFacts, "package manager "+current.fact.Manager+" is unsupported for Ubuntu matching")
			} else {
				current.fact.MissingFacts = append(current.fact.MissingFacts, "package manager is unavailable")
			}
		}
		if !current.fact.Owned {
			current.fact.MissingFacts = append(current.fact.MissingFacts, "package ownership not confirmed")
		}
		current.fact.MissingFacts = uniqueSorted(current.fact.MissingFacts)
		current.fact.Confidence = model.ConfidenceHigh
		if len(current.fact.MissingFacts) > 0 {
			current.fact.Confidence = model.ConfidenceMedium
		}
		if existing, exists := byPath[current.fact.Path]; exists {
			existing.Ambiguous = true
			existing.MissingFacts = uniqueSorted(append(existing.MissingFacts, "ownership record is duplicated"))
			existing.Confidence = model.ConfidenceMedium
			byPath[current.fact.Path] = existing
			diagnostics = append(diagnostics, Diagnostic{Code: "duplicate-ownership-record", Message: current.fact.Path, EvidenceIDs: []string{evidenceID}})
		} else {
			byPath[current.fact.Path] = current.fact
			order = append(order, current.fact.Path)
		}
		current = nil
	}

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if lineNumber == 1 {
			if line != "LPECO_PACKAGE_OWNERSHIP_V1" {
				return nil, []Diagnostic{{Code: "unsupported-ownership-format", Message: "header is missing", EvidenceIDs: []string{evidenceID}}}
			}
			header = true
			continue
		}
		parts := strings.Split(line, "\t")
		switch parts[0] {
		case "BEGIN":
			if current != nil {
				finish(true)
			}
			if len(parts) != 4 {
				diagnostics = append(diagnostics, Diagnostic{Code: "malformed-ownership-begin", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
				continue
			}
			path, pathErr := decodeHex(parts[1])
			resolved, resolvedErr := decodeHex(parts[2])
			if pathErr != nil || resolvedErr != nil || path == "" {
				diagnostics = append(diagnostics, Diagnostic{Code: "invalid-ownership-path", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
				continue
			}
			current = &ownershipRecord{
				fact:     OwnershipFact{Path: path, ResolvedPath: resolved, Manager: parts[3], EvidenceIDs: []string{evidenceID}},
				observed: make(map[string]bool), resolved: make(map[string]bool),
			}
		case "QUERY":
			if current == nil || len(parts) != 4 {
				diagnostics = append(diagnostics, Diagnostic{Code: "orphan-or-malformed-ownership-query", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
				continue
			}
			status, statusErr := strconv.Atoi(parts[2])
			output, outputErr := decodeHex(parts[3])
			if statusErr != nil || outputErr != nil || parts[1] != "observed" && parts[1] != "resolved" {
				current.fact.MissingFacts = append(current.fact.MissingFacts, "ownership query frame is malformed")
				diagnostics = append(diagnostics, Diagnostic{Code: "malformed-ownership-query", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
				continue
			}
			if status != 0 && status != 1 {
				current.fact.MissingFacts = append(current.fact.MissingFacts, fmt.Sprintf("package ownership query failed with exit %d", status))
				continue
			}
			if status == 1 {
				continue
			}
			packages := parseOwners(current.fact.Manager, output)
			target := current.observed
			if parts[1] == "resolved" {
				target = current.resolved
			}
			for _, packageName := range packages {
				target[packageName] = true
			}
		case "END":
			if len(parts) != 1 || current == nil {
				diagnostics = append(diagnostics, Diagnostic{Code: "orphan-or-malformed-ownership-end", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
				continue
			}
			finish(false)
		case "":
		default:
			diagnostics = append(diagnostics, Diagnostic{Code: "unknown-ownership-record", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
			if current != nil {
				current.fact.MissingFacts = append(current.fact.MissingFacts, "ownership record contains unknown data")
			}
		}
	}
	if scanner.Err() != nil {
		diagnostics = append(diagnostics, Diagnostic{Code: "ownership-read-error", Message: scanner.Err().Error(), EvidenceIDs: []string{evidenceID}})
	}
	if current != nil {
		finish(true)
	}
	if !header {
		return nil, diagnostics
	}
	result := make([]OwnershipFact, 0, len(order))
	for _, path := range order {
		result = append(result, byPath[path])
	}
	return result, diagnostics
}

func ParseMetadata(input []byte, evidenceID string) ([]InstalledPackageFact, []Diagnostic) {
	scanner := bufio.NewScanner(bytes.NewReader(input))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	lineNumber := 0
	byRequest := make(map[string]InstalledPackageFact)
	var order []string
	var diagnostics []Diagnostic
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if lineNumber == 1 {
			if line != "LPECO_PACKAGE_METADATA_V1" {
				return nil, []Diagnostic{{Code: "unsupported-metadata-format", Message: "header is missing", EvidenceIDs: []string{evidenceID}}}
			}
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) == 1 && parts[0] == "" {
			continue
		}
		if len(parts) != 5 || parts[0] != "RECORD" {
			diagnostics = append(diagnostics, Diagnostic{Code: "malformed-metadata-record", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
			continue
		}
		request, requestErr := decodeHex(parts[1])
		status, statusErr := strconv.Atoi(parts[3])
		payload, payloadErr := decodeHex(parts[4])
		if requestErr != nil || statusErr != nil || payloadErr != nil || request == "" {
			diagnostics = append(diagnostics, Diagnostic{Code: "invalid-metadata-record", Message: fmt.Sprintf("line %d", lineNumber), EvidenceIDs: []string{evidenceID}})
			continue
		}
		fact := InstalledPackageFact{RequestedPackage: request, Manager: parts[2], EvidenceIDs: []string{evidenceID}, Confidence: model.ConfidenceHigh}
		if status != 0 {
			fact.MissingFacts = []string{fmt.Sprintf("package metadata query failed with exit %d", status)}
			fact.Confidence = model.ConfidenceMedium
		} else if fact.Manager != "dpkg" {
			fact.MissingFacts = []string{"package manager " + fact.Manager + " metadata is unsupported for Ubuntu matching"}
			fact.Confidence = model.ConfidenceMedium
		} else {
			parseMetadataPayload(&fact, payload)
		}
		if existing, exists := byRequest[request]; exists {
			existing.MissingFacts = uniqueSorted(append(existing.MissingFacts, "package metadata record is duplicated"))
			existing.Confidence = model.ConfidenceMedium
			byRequest[request] = existing
			diagnostics = append(diagnostics, Diagnostic{Code: "duplicate-metadata-record", Message: request, EvidenceIDs: []string{evidenceID}})
			continue
		}
		byRequest[request] = fact
		order = append(order, request)
	}
	if scanner.Err() != nil {
		diagnostics = append(diagnostics, Diagnostic{Code: "metadata-read-error", Message: scanner.Err().Error(), EvidenceIDs: []string{evidenceID}})
	}
	if len(input) > 0 && !bytes.HasSuffix(input, []byte("\n")) {
		diagnostics = append(diagnostics, Diagnostic{Code: "truncated-metadata-frame", Message: "final record lacks newline", EvidenceIDs: []string{evidenceID}})
		if len(order) > 0 {
			last := order[len(order)-1]
			fact := byRequest[last]
			fact.MissingFacts = uniqueSorted(append(fact.MissingFacts, "metadata frame is truncated"))
			fact.Confidence = model.ConfidenceMedium
			byRequest[last] = fact
		}
	}
	result := make([]InstalledPackageFact, 0, len(order))
	for _, request := range order {
		result = append(result, byRequest[request])
	}
	return result, diagnostics
}

func parseMetadataPayload(fact *InstalledPackageFact, payload string) {
	payload = strings.TrimSuffix(payload, "\n")
	fields := strings.Split(payload, "\t")
	if len(fields) != 6 {
		fact.MissingFacts = []string{"package metadata payload is malformed"}
		fact.Confidence = model.ConfidenceMedium
		return
	}
	fact.Status = fields[0]
	binaryName := fields[1]
	fact.Architecture = fields[2]
	if separator := strings.LastIndexByte(binaryName, ':'); separator > 0 {
		binaryArchitecture := binaryName[separator+1:]
		fact.BinaryPackage = binaryName[:separator]
		if fact.Architecture == "" {
			fact.Architecture = binaryArchitecture
		} else if binaryArchitecture != fact.Architecture {
			fact.MissingFacts = append(fact.MissingFacts, "binary package architecture conflicts with metadata")
		}
	} else {
		fact.BinaryPackage = binaryName
	}
	fact.BinaryVersion = model.DebianVersion{Raw: fields[3]}
	fact.SourcePackage = fields[4]
	fact.SourceVersion = model.DebianVersion{Raw: fields[5]}
	if fact.BinaryPackage == "" || fact.Architecture == "" || fact.BinaryVersion.Raw == "" {
		fact.MissingFacts = append(fact.MissingFacts, "binary package metadata is missing")
	}
	if fact.SourcePackage == "" || fact.SourceVersion.Raw == "" {
		fact.MissingFacts = append(fact.MissingFacts, "source package metadata is missing")
	}
	if fact.RequestedPackage != fields[1] && fact.RequestedPackage != fact.BinaryPackage {
		fact.MissingFacts = append(fact.MissingFacts, "requested package does not match returned binary package")
	}
	fact.MissingFacts = uniqueSorted(fact.MissingFacts)
	if len(fact.MissingFacts) > 0 {
		fact.Confidence = model.ConfidenceMedium
	}
}

func parseOwners(manager, output string) []string {
	set := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		switch manager {
		case "dpkg":
			separator := strings.LastIndex(line, ": ")
			if separator > 0 {
				name := strings.TrimSpace(line[:separator])
				if name != "" && !strings.HasPrefix(name, "diversion by ") {
					set[name] = true
				}
			}
		case "rpm":
			if !strings.Contains(strings.ToLower(line), "not owned") {
				set[strings.Fields(line)[0]] = true
			}
		case "apk":
			if _, packageName, found := strings.Cut(line, " is owned by "); found {
				if fields := strings.Fields(packageName); len(fields) > 0 {
					set[fields[0]] = true
				}
			}
		}
	}
	return sortedKeys(set)
}

func marshalFacts(kind string, values any, evidenceID string) ([]model.Fact, error) {
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(encoded, &entries); err != nil {
		return nil, err
	}
	result := make([]model.Fact, 0, len(entries))
	for _, data := range entries {
		var envelope struct {
			EvidenceIDs  []string         `json:"evidence_ids"`
			MissingFacts []string         `json:"missing_facts"`
			Confidence   model.Confidence `json:"confidence"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			return nil, err
		}
		id, err := model.StableID("fact", struct {
			Kind string
			Data json.RawMessage
		}{kind, data})
		if err != nil {
			return nil, err
		}
		if len(envelope.EvidenceIDs) == 0 {
			envelope.EvidenceIDs = []string{evidenceID}
		}
		if envelope.Confidence == "" {
			envelope.Confidence = model.ConfidenceLow
		}
		result = append(result, model.Fact{
			ID: id, Kind: kind, SourceCollector: "packageinfo", Data: data,
			EvidenceIDs: envelope.EvidenceIDs, MissingFacts: envelope.MissingFacts, Confidence: envelope.Confidence,
		})
	}
	return result, nil
}

func decodeHex(value string) (string, error) {
	decoded, err := hex.DecodeString(value)
	return string(decoded), err
}

func sortedKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	if len(result) == 0 {
		return nil
	}
	sort.Strings(result)
	return result
}

func equalSets(left, right map[string]bool) bool {
	if len(left) != len(right) {
		return false
	}
	for value := range left {
		if !right[value] {
			return false
		}
	}
	return true
}

func uniqueSorted(values []string) []string {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = true
		}
	}
	return sortedKeys(set)
}
