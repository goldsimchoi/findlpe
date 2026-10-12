package rules

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/normalone/lpeco/internal/model"
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
	ranks := []struct {
		name  string
		input RankInput
		want  model.Priority
	}{
		{"P0 complete chain", RankInput{PrivilegeBoundary: true, ControlConfirmed: true, TriggerConfirmed: true, SemanticsResolved: true, Confidences: []model.Confidence{model.ConfidenceHigh}}, model.PriorityP0},
		{"P1 incomplete trigger", RankInput{PrivilegeBoundary: true, ControlConfirmed: true, SemanticsResolved: true, Confidences: []model.Confidence{model.ConfidenceHigh}, MissingFacts: []string{"trigger unavailable"}}, model.PriorityP1},
		{"P2 unconfirmed control", RankInput{PrivilegeBoundary: true, SemanticsResolved: true, Confidences: []model.Confidence{model.ConfidenceHigh}, MissingFacts: []string{"control unavailable"}}, model.PriorityP2},
	}
	for _, rank := range ranks {
		if got := Rank(rank.input).Priority; got != rank.want {
			t.Errorf("%s priority = %s, want %s", rank.name, got, rank.want)
		}
	}
}

func TestEveryCandidateReferencesEvidenceAndMissingFacts(t *testing.T) {
	files, _ := filepath.Glob("../../testdata/rules/*/scenarios.json")
	rules := rulesByID(AllRules())
	positiveByRule := make(map[string]int)
	for _, file := range files {
		fixture := loadRuleFixture(t, file)
		for _, scenario := range fixture.Cases {
			candidates := EvaluateAll(context.Background(), graphFromFixture(t, scenario), []Rule{rules[scenario.RuleID]})
			if len(candidates) != scenario.WantCount {
				t.Errorf("%s candidate count = %d, want %d", scenario.Name, len(candidates), scenario.WantCount)
			}
			if len(candidates) > 0 {
				positiveByRule[scenario.RuleID] += len(candidates)
			}
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
	for _, rule := range AllRules() {
		if positiveByRule[rule.ID()] == 0 {
			t.Errorf("rule %s produced zero evidence-backed candidates across its fixtures", rule.ID())
		}
	}
}
