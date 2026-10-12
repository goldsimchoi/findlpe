package rules

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAllRulesHavePositiveAndTwoNegatives(t *testing.T) {
	files, err := filepath.Glob("../../testdata/rules/*/scenarios.json")
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]struct{ positive, negative int })
	for _, file := range files {
		fixture := loadRuleFixture(t, file)
		for _, scenario := range fixture.Cases {
			count := counts[scenario.RuleID]
			if scenario.WantCount > 0 {
				count.positive++
			} else {
				count.negative++
			}
			counts[scenario.RuleID] = count
		}
	}
	seen := make(map[string]bool)
	for _, rule := range AllRules() {
		if seen[rule.ID()] {
			t.Fatalf("duplicate rule ID %q", rule.ID())
		}
		seen[rule.ID()] = true
		count := counts[rule.ID()]
		if count.positive < 1 || count.negative < 2 {
			t.Errorf("rule %s has %d positives and %d negatives", rule.ID(), count.positive, count.negative)
		}
	}
	if len(seen) != 11 || len(counts) != 11 {
		t.Fatalf("registry/fixture rule counts = %d/%d, want 11/11", len(seen), len(counts))
	}
}

func TestEveryCandidateReferencesEvidenceAndMissingFacts(t *testing.T) {
	files, _ := filepath.Glob("../../testdata/rules/*/scenarios.json")
	rules := rulesByID(AllRules())
	for _, file := range files {
		fixture := loadRuleFixture(t, file)
		for _, scenario := range fixture.Cases {
			candidates := EvaluateAll(context.Background(), graphFromFixture(t, scenario), []Rule{rules[scenario.RuleID]})
			for _, candidate := range candidates {
				if len(candidate.EvidenceIDs) == 0 {
					t.Errorf("%s candidate has no evidence", scenario.Name)
				}
				if candidate.MissingFacts == nil {
					t.Errorf("%s candidate has nil missing facts", scenario.Name)
				}
			}
		}
	}
}
