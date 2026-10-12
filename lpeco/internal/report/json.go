package report

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/redact"
)

type Data struct {
	Session     model.Session     `json:"session"`
	Facts       []model.Fact      `json:"facts"`
	Candidates  []model.Candidate `json:"candidates"`
	Evidence    []model.Evidence  `json:"evidence"`
	Limitations []string          `json:"limitations"`
}

type Document struct {
	SchemaVersion int               `json:"schema_version"`
	Session       model.Session     `json:"session"`
	Facts         []model.Fact      `json:"facts"`
	Candidates    []model.Candidate `json:"candidates"`
	Evidence      []model.Evidence  `json:"evidence"`
	Limitations   []string          `json:"limitations"`
}

func WriteJSON(destination io.Writer, data Data) error {
	document := Document{
		SchemaVersion: 1,
		Session:       sanitizedSession(data.Session),
		Facts:         sanitizedFacts(data.Facts),
		Candidates:    sanitizedCandidates(data.Candidates),
		Evidence:      sanitizedEvidence(data.Evidence),
		Limitations:   sanitizedStrings(data.Limitations),
	}
	encoder := json.NewEncoder(destination)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(document)
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
