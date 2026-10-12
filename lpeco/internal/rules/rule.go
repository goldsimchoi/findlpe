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

// EvaluateAll evaluates a rule set without allowing one malformed result to
// contaminate reports. Candidate IDs are de-duplicated and output order is
// deterministic.
func EvaluateAll(ctx context.Context, g *graphpkg.Graph, ruleSet []Rule) []model.Candidate {
	if ctx == nil {
		ctx = context.Background()
	}
	byID := make(map[string]model.Candidate)
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
	return result
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
