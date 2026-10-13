package report

import (
	"encoding/json"
	"io"
	"net/url"
	"sort"
	"strings"

	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/redact"
	"github.com/normalone/lpeco/internal/vulnerability"
)

type Data struct {
	Session          model.Session           `json:"session"`
	Facts            []model.Fact            `json:"facts"`
	Candidates       []model.Candidate       `json:"candidates"`
	Evidence         []model.Evidence        `json:"evidence"`
	GraphDiagnostics []model.GraphDiagnostic `json:"graph_diagnostics"`
	RuleDiagnostics  []model.RuleDiagnostic  `json:"rule_diagnostics"`
	Limitations      []string                `json:"limitations"`
}

type Document struct {
	SchemaVersion        int                     `json:"schema_version"`
	Session              model.Session           `json:"session"`
	Facts                []model.Fact            `json:"facts"`
	Candidates           []model.Candidate       `json:"candidates"`
	Evidence             []model.Evidence        `json:"evidence"`
	Graph                json.RawMessage         `json:"graph"`
	GraphDiagnostics     []model.GraphDiagnostic `json:"graph_diagnostics"`
	RuleDiagnostics      []model.RuleDiagnostic  `json:"rule_diagnostics"`
	KnownVulnerabilities KnownVulnerabilities    `json:"known_vulnerabilities"`
	Limitations          []string                `json:"limitations"`
}

type KnownVulnerabilities struct {
	Coverage    model.VulnerabilityCoverage     `json:"coverage"`
	Matches     []model.VulnerabilityMatch      `json:"matches"`
	Diagnostics []model.VulnerabilityDiagnostic `json:"diagnostics"`
}

func WriteJSON(destination io.Writer, data Data) error {
	facts := sanitizedFacts(data.Facts)
	graph, _ := graphpkg.Build(facts)
	graphJSON, err := json.Marshal(graph)
	if err != nil {
		return err
	}
	document := Document{
		SchemaVersion:        2,
		Session:              sanitizedSession(data.Session),
		Facts:                facts,
		Candidates:           sanitizedCandidates(data.Candidates),
		Evidence:             sanitizedEvidence(data.Evidence),
		Graph:                graphJSON,
		GraphDiagnostics:     sanitizedGraphDiagnostics(data.GraphDiagnostics),
		RuleDiagnostics:      sanitizedRuleDiagnostics(data.RuleDiagnostics),
		KnownVulnerabilities: buildKnownVulnerabilities(data),
		Limitations:          sanitizedStrings(data.Limitations),
	}
	encoder := json.NewEncoder(destination)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
}

func sanitizedGraphDiagnostics(values []model.GraphDiagnostic) []model.GraphDiagnostic {
	result := append([]model.GraphDiagnostic(nil), values...)
	for index := range result {
		result[index].Message = redact.String(result[index].Message)
		result[index].EvidenceIDs = sortedStrings(result[index].EvidenceIDs)
	}
	sort.Slice(result, func(i, j int) bool {
		left := result[i].Code + "\x00" + result[i].FactID + "\x00" + result[i].Message
		right := result[j].Code + "\x00" + result[j].FactID + "\x00" + result[j].Message
		return left < right
	})
	if result == nil {
		return []model.GraphDiagnostic{}
	}
	return result
}

func sanitizedRuleDiagnostics(values []model.RuleDiagnostic) []model.RuleDiagnostic {
	result := append([]model.RuleDiagnostic(nil), values...)
	for index := range result {
		result[index].Message = redact.String(result[index].Message)
		result[index].EvidenceIDs = sortedStrings(result[index].EvidenceIDs)
	}
	sort.Slice(result, func(i, j int) bool {
		left := result[i].RuleID + "\x00" + result[i].Code + "\x00" + result[i].Node.ID + "\x00" + result[i].Message
		right := result[j].RuleID + "\x00" + result[j].Code + "\x00" + result[j].Node.ID + "\x00" + result[j].Message
		return left < right
	})
	if result == nil {
		return []model.RuleDiagnostic{}
	}
	return result
}

func sanitizedSession(value model.Session) model.Session {
	value.Target = redact.String(value.Target)
	if value.SchemaVersion == 1 {
		value.Vulnerability = model.VulnerabilityCoverage{Mode: model.VulnerabilityModeOff, Status: model.VulnerabilityCoverageLegacyNotRequested}
	} else {
		value.Vulnerability = sanitizedCoverage(value.Vulnerability)
	}
	return value
}

func sanitizedFacts(values []model.Fact) []model.Fact {
	result := make([]model.Fact, len(values))
	for index, value := range values {
		if value.Kind == vulnerability.VulnerabilityMatchFactKind {
			var match model.VulnerabilityMatch
			if err := json.Unmarshal(value.Data, &match); err == nil {
				matches := sanitizedVulnerabilityMatches([]model.VulnerabilityMatch{match})
				if len(matches) == 1 {
					value.Data, _ = json.Marshal(matches[0])
				} else {
					value.Data = json.RawMessage(`{"invalid":true}`)
				}
			} else {
				value.Data = json.RawMessage(`{"invalid":true}`)
			}
		} else {
			value.Data = redact.JSON(value.Data)
		}
		value.EvidenceIDs = sortedStrings(value.EvidenceIDs)
		result[index] = value
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].ID < result[j].ID
	})
	if result == nil {
		return []model.Fact{}
	}
	return result
}

func buildKnownVulnerabilities(data Data) KnownVulnerabilities {
	session := sanitizedSession(data.Session)
	matches, factDiagnostics := vulnerability.MatchesFromFacts(data.Facts)
	coverage := sanitizedCoverage(session.Vulnerability)
	diagnostics := append([]model.VulnerabilityDiagnostic(nil), coverage.Diagnostics...)
	diagnostics = append(diagnostics, factDiagnostics...)
	return KnownVulnerabilities{
		Coverage: coverage, Matches: sanitizedVulnerabilityMatches(matches), Diagnostics: sanitizedVulnerabilityDiagnostics(diagnostics),
	}
}

func sanitizedCoverage(value model.VulnerabilityCoverage) model.VulnerabilityCoverage {
	value.Provider = redact.String(value.Provider)
	value.SelectedRelease = redact.String(value.SelectedRelease)
	value.SelectedCodename = redact.String(value.SelectedCodename)
	value.SelectedChannel = redact.String(value.SelectedChannel)
	value.SelectedArchitecture = redact.String(value.SelectedArchitecture)
	value.Snapshot.Provider = redact.String(value.Snapshot.Provider)
	value.Snapshot.Digest = redact.String(value.Snapshot.Digest)
	value.Snapshot.ImpactCatalogDigest = redact.String(value.Snapshot.ImpactCatalogDigest)
	value.Snapshot.SupportedReleases = sanitizedStrings(value.Snapshot.SupportedReleases)
	value.Snapshot.SupportedChannels = sanitizedStrings(value.Snapshot.SupportedChannels)
	value.Diagnostics = sanitizedVulnerabilityDiagnostics(value.Diagnostics)
	return value
}

func sanitizedVulnerabilityMatches(values []model.VulnerabilityMatch) []model.VulnerabilityMatch {
	result := append([]model.VulnerabilityMatch(nil), values...)
	for index := range result {
		match := &result[index]
		match.ID = redact.String(match.ID)
		match.Provider = redact.String(match.Provider)
		match.SnapshotDigest = redact.String(match.SnapshotDigest)
		match.DistributionID = redact.String(match.DistributionID)
		match.Release = redact.String(match.Release)
		match.Codename = redact.String(match.Codename)
		match.Channel = redact.String(match.Channel)
		match.Architecture = redact.String(match.Architecture)
		match.BinaryPackage = redact.String(match.BinaryPackage)
		match.BinaryArchitecture = redact.String(match.BinaryArchitecture)
		match.SourcePackage = redact.String(match.SourcePackage)
		match.AdvisoryID = redact.String(match.AdvisoryID)
		match.RecordID = redact.String(match.RecordID)
		match.Reason = redact.String(match.Reason)
		match.BinaryVersion = sanitizedDebianVersion(match.BinaryVersion)
		match.SourceVersion = sanitizedDebianVersion(match.SourceVersion)
		match.CVEIDs = sanitizedStrings(match.CVEIDs)
		match.USNIDs = sanitizedStrings(match.USNIDs)
		match.OfficialReferences = sanitizedOfficialReferences(match.OfficialReferences)
		match.SeverityMetadata = sanitizedStrings(match.SeverityMetadata)
		match.ImpactAnnotationIDs = sanitizedStrings(match.ImpactAnnotationIDs)
		match.TargetEvidenceIDs = sanitizedStrings(match.TargetEvidenceIDs)
		match.MissingFacts = sanitizedStrings(match.MissingFacts)
		match.Comparisons = append([]model.VersionComparison(nil), match.Comparisons...)
		for comparisonIndex := range match.Comparisons {
			match.Comparisons[comparisonIndex].Installed = sanitizedDebianVersion(match.Comparisons[comparisonIndex].Installed)
			match.Comparisons[comparisonIndex].Boundary = sanitizedDebianVersion(match.Comparisons[comparisonIndex].Boundary)
			match.Comparisons[comparisonIndex].Operator = redact.String(match.Comparisons[comparisonIndex].Operator)
			match.Comparisons[comparisonIndex].Reason = redact.String(match.Comparisons[comparisonIndex].Reason)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ID != result[j].ID {
			return result[i].ID < result[j].ID
		}
		return result[i].RecordID < result[j].RecordID
	})
	if result == nil {
		return []model.VulnerabilityMatch{}
	}
	return result
}

func sanitizedDebianVersion(value model.DebianVersion) model.DebianVersion {
	value.Raw = redact.String(value.Raw)
	value.Upstream = redact.String(value.Upstream)
	value.Revision = redact.String(value.Revision)
	return value
}

func sanitizedVulnerabilityDiagnostics(values []model.VulnerabilityDiagnostic) []model.VulnerabilityDiagnostic {
	byKey := make(map[string]model.VulnerabilityDiagnostic, len(values))
	for _, value := range values {
		value.Code = redact.String(value.Code)
		value.Message = redact.String(value.Message)
		value.MatchID = redact.String(value.MatchID)
		value.EvidenceIDs = sanitizedStrings(value.EvidenceIDs)
		value.MissingFacts = sanitizedStrings(value.MissingFacts)
		key := value.Code + "\x00" + value.MatchID + "\x00" + value.Message + "\x00" + strings.Join(value.EvidenceIDs, "\x00") + "\x00" + strings.Join(value.MissingFacts, "\x00")
		byKey[key] = value
	}
	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]model.VulnerabilityDiagnostic, 0, len(keys))
	for _, key := range keys {
		result = append(result, byKey[key])
	}
	return result
}

func sanitizedOfficialReferences(values []string) []string {
	var result []string
	for _, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Host != "ubuntu.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/security/") {
			continue
		}
		result = append(result, redact.String(parsed.String()))
	}
	return sanitizedStrings(result)
}

func sanitizedCandidates(values []model.Candidate) []model.Candidate {
	result := make([]model.Candidate, len(values))
	for index, value := range values {
		value.Summary = redact.String(value.Summary)
		value.EvidenceIDs = sanitizedStrings(value.EvidenceIDs)
		value.RelatedMatchIDs = sanitizedStrings(value.RelatedMatchIDs)
		value.MissingFacts = sanitizedStrings(value.MissingFacts)
		value.PathNodes = append([]model.NodeRef(nil), value.PathNodes...)
		sort.Slice(value.PathNodes, func(i, j int) bool { return value.PathNodes[i].ID < value.PathNodes[j].ID })
		result[index] = value
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := priorityOrder(result[i].Priority), priorityOrder(result[j].Priority)
		if left != right {
			return left < right
		}
		if result[i].RuleID != result[j].RuleID {
			return result[i].RuleID < result[j].RuleID
		}
		return result[i].ID < result[j].ID
	})
	if result == nil {
		return []model.Candidate{}
	}
	return result
}

func sanitizedEvidence(values []model.Evidence) []model.Evidence {
	result := append([]model.Evidence(nil), values...)
	for index := range result {
		result[index].Adapter = redact.String(result[index].Adapter)
		result[index].VariantID = redact.String(result[index].VariantID)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	if result == nil {
		return []model.Evidence{}
	}
	return result
}

func sanitizedStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]bool)
	for _, value := range values {
		value = redact.String(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	if result == nil {
		return []string{}
	}
	return result
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	if result == nil {
		return []string{}
	}
	return result
}

func priorityOrder(value model.Priority) int {
	switch value {
	case model.PriorityP0:
		return 0
	case model.PriorityP1:
		return 1
	default:
		return 2
	}
}
