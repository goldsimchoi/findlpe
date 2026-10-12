package rules

import (
	"context"
	"sort"

	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
)

type Metadata struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Description string `json:"description"`
}

type Diagnostic struct {
	Code        string        `json:"code"`
	RuleID      string        `json:"rule_id"`
	Message     string        `json:"message"`
	Node        model.NodeRef `json:"node"`
	EvidenceIDs []string      `json:"evidence_ids"`
}

type Evaluation struct {
	Candidates  []model.Candidate `json:"candidates"`
	Diagnostics []Diagnostic      `json:"diagnostics"`
}

type Rule interface {
	ID() string
	Metadata() Metadata
	Evaluate(context.Context, *graphpkg.Graph) []model.Candidate
}

func PrimaryRules() []Rule {
	return []Rule{
		writableUnitSourceRule{},
		writableExecChainRule{},
		controlledEnvironmentRule{},
		controlledSearchPathRule{},
		replaceableDependencyRule{},
	}
}

func AllRules() []Rule {
	return append(PrimaryRules(),
		writableScheduledCommandRule{},
		suidSGIDControlRule{},
		capabilityBoundaryRule{},
		loaderPathControlRule{},
		sudoPolicyRule{},
		adminSocketControlRule{},
	)
}

// EvaluateAll evaluates a rule set without allowing one malformed result to
// contaminate reports. Candidate IDs are de-duplicated and output order is
// deterministic.
func EvaluateAll(ctx context.Context, g *graphpkg.Graph, ruleSet []Rule) []model.Candidate {
	return Evaluate(ctx, g, ruleSet).Candidates
}

type diagnosticProvider interface {
	Diagnostics(context.Context, *graphpkg.Graph) []Diagnostic
}

func Evaluate(ctx context.Context, g *graphpkg.Graph, ruleSet []Rule) Evaluation {
	if ctx == nil {
		ctx = context.Background()
	}
	byID := make(map[string]model.Candidate)
	diagnosticByKey := make(map[string]Diagnostic)
	for _, rule := range ruleSet {
		if rule == nil || ctx.Err() != nil {
			break
		}
		for _, candidate := range rule.Evaluate(ctx, g) {
			if candidate.RuleID == "" {
				candidate.RuleID = rule.ID()
			}
			if candidate.Validate() != nil {
				continue
			}
			if existing, ok := byID[candidate.ID]; ok {
				candidate.EvidenceIDs = mergeStrings(existing.EvidenceIDs, candidate.EvidenceIDs)
				candidate.MissingFacts = mergeStrings(existing.MissingFacts, candidate.MissingFacts)
			}
			byID[candidate.ID] = candidate
		}
		if provider, ok := rule.(diagnosticProvider); ok {
			for _, diagnostic := range provider.Diagnostics(ctx, g) {
				diagnostic.EvidenceIDs = mergeStrings(nil, diagnostic.EvidenceIDs)
				key := diagnostic.Code + "\x00" + diagnostic.RuleID + "\x00" + diagnostic.Node.ID + "\x00" + diagnostic.Message
				diagnosticByKey[key] = diagnostic
			}
		}
	}
	result := make([]model.Candidate, 0, len(byID))
	for _, candidate := range byID {
		result = append(result, candidate)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := priorityRank(result[i].Priority), priorityRank(result[j].Priority)
		if left != right {
			return left < right
		}
		if result[i].RuleID != result[j].RuleID {
			return result[i].RuleID < result[j].RuleID
		}
		return result[i].ID < result[j].ID
	})
	diagnostics := make([]Diagnostic, 0, len(diagnosticByKey))
	for _, diagnostic := range diagnosticByKey {
		diagnostics = append(diagnostics, diagnostic)
	}
	sort.Slice(diagnostics, func(i, j int) bool {
		left := diagnostics[i].RuleID + "\x00" + diagnostics[i].Code + "\x00" + diagnostics[i].Node.ID + "\x00" + diagnostics[i].Message
		right := diagnostics[j].RuleID + "\x00" + diagnostics[j].Code + "\x00" + diagnostics[j].Node.ID + "\x00" + diagnostics[j].Message
		return left < right
	})
	return Evaluation{Candidates: result, Diagnostics: diagnostics}
}

func priorityRank(value model.Priority) int {
	switch value {
	case model.PriorityP0:
		return 0
	case model.PriorityP1:
		return 1
	default:
		return 2
	}
}
