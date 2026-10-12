package report

import (
	"encoding/json"
	"io"
	"sort"

	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/redact"
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
	SchemaVersion    int                     `json:"schema_version"`
	Session          model.Session           `json:"session"`
	Facts            []model.Fact            `json:"facts"`
	Candidates       []model.Candidate       `json:"candidates"`
	Evidence         []model.Evidence        `json:"evidence"`
	Graph            json.RawMessage         `json:"graph"`
	GraphDiagnostics []model.GraphDiagnostic `json:"graph_diagnostics"`
	RuleDiagnostics  []model.RuleDiagnostic  `json:"rule_diagnostics"`
	Limitations      []string                `json:"limitations"`
}

func WriteJSON(destination io.Writer, data Data) error {
	facts := sanitizedFacts(data.Facts)
	graph, _ := graphpkg.Build(facts)
	graphJSON, err := json.Marshal(graph)
	if err != nil {
		return err
	}
	document := Document{
		SchemaVersion:    1,
		Session:          sanitizedSession(data.Session),
		Facts:            facts,
		Candidates:       sanitizedCandidates(data.Candidates),
		Evidence:         sanitizedEvidence(data.Evidence),
		Graph:            graphJSON,
		GraphDiagnostics: sanitizedGraphDiagnostics(data.GraphDiagnostics),
		RuleDiagnostics:  sanitizedRuleDiagnostics(data.RuleDiagnostics),
		Limitations:      sanitizedStrings(data.Limitations),
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
	return value
}

func sanitizedFacts(values []model.Fact) []model.Fact {
	result := make([]model.Fact, len(values))
	for index, value := range values {
		value.Data = redact.JSON(value.Data)
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

func sanitizedCandidates(values []model.Candidate) []model.Candidate {
	result := make([]model.Candidate, len(values))
	for index, value := range values {
		value.Summary = redact.String(value.Summary)
		value.EvidenceIDs = sortedStrings(value.EvidenceIDs)
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
