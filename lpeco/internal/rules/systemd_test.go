package rules

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
)

func TestSystemdRuleFixtures(t *testing.T) {
	fixture := loadRuleFixture(t, "../../testdata/rules/systemd/scenarios.json")
	rules := rulesByID(PrimaryRules())
	for _, scenario := range fixture.Cases {
		if scenario.RuleID == "process.replaceable-dependency" {
			continue
		}
		t.Run(scenario.Name, func(t *testing.T) {
			rule, ok := rules[scenario.RuleID]
			if !ok {
				t.Fatalf("rule %q not registered", scenario.RuleID)
			}
			candidates := EvaluateAll(context.Background(), graphFromFixture(t, scenario), []Rule{rule})
			assertScenario(t, scenario, candidates)
		})
	}
}

func TestRankNeverReturnsP0ForLowConfidenceOrUnresolvedEvidence(t *testing.T) {
	for _, input := range []RankInput{
		{PrivilegeBoundary: true, ControlConfirmed: true, TriggerConfirmed: true, SemanticsResolved: true, Confidences: []model.Confidence{model.ConfidenceLow}},
		{PrivilegeBoundary: true, ControlConfirmed: true, TriggerConfirmed: true, SemanticsResolved: false, Confidences: []model.Confidence{model.ConfidenceHigh}},
		{PrivilegeBoundary: true, ControlConfirmed: true, TriggerConfirmed: true, SemanticsResolved: true, Confidences: []model.Confidence{model.ConfidenceHigh}, MissingFacts: []string{"one", "two"}},
	} {
		result := Rank(input)
		if result.Priority == model.PriorityP0 {
			t.Fatalf("unsafe P0 rank for %#v: %#v", input, result)
		}
	}
}

type ruleFixture struct {
	Cases []fixtureCase `json:"cases"`
}

type fixtureCase struct {
	Name           string         `json:"name"`
	RuleID         string         `json:"rule_id"`
	Current        string         `json:"current"`
	WantCount      int            `json:"want_count"`
	WantPriority   model.Priority `json:"want_priority,omitempty"`
	WantMissing    []string       `json:"want_missing,omitempty"`
	WantDiagnostic string         `json:"want_diagnostic,omitempty"`
	Nodes          []fixtureNode  `json:"nodes"`
	Edges          []fixtureEdge  `json:"edges"`
}

type fixtureNode struct {
	Key        string           `json:"key"`
	Kind       model.NodeKind   `json:"kind"`
	Label      string           `json:"label"`
	Attributes json.RawMessage  `json:"attributes,omitempty"`
	Confidence model.Confidence `json:"confidence,omitempty"`
}

type fixtureEdge struct {
	Kind       model.EdgeKind   `json:"kind"`
	From       string           `json:"from"`
	To         string           `json:"to"`
	Attributes json.RawMessage  `json:"attributes,omitempty"`
	Confidence model.Confidence `json:"confidence,omitempty"`
}

func loadRuleFixture(t *testing.T, path string) ruleFixture {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture ruleFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return fixture
}

func graphFromFixture(t *testing.T, scenario fixtureCase) *graphpkg.Graph {
	t.Helper()
	g := graphpkg.New()
	refs := make(map[string]model.NodeRef)
	for _, node := range scenario.Nodes {
		confidence := node.Confidence
		if confidence == "" {
			confidence = model.ConfidenceHigh
		}
		ref, _, err := g.AddNode(graphpkg.NodeSpec{
			Key: node.Key, Kind: node.Kind, Label: node.Label, SourceCollector: "fixture",
			EvidenceIDs: []string{"e-node-" + node.Key}, Confidence: confidence, Attributes: node.Attributes,
		})
		if err != nil {
			t.Fatalf("add node %s: %v", node.Key, err)
		}
		refs[node.Key] = ref
	}
	current, ok := refs[scenario.Current]
	if !ok {
		t.Fatalf("current fixture node %q missing", scenario.Current)
	}
	g.SetCurrentPrincipal(current)
	for index, edge := range scenario.Edges {
		confidence := edge.Confidence
		if confidence == "" {
			confidence = model.ConfidenceHigh
		}
		if err := g.AddEdge(graphpkg.EdgeSpec{
			Kind: edge.Kind, From: refs[edge.From], To: refs[edge.To], SourceCollector: "fixture",
			EvidenceIDs: []string{"e-edge-" + scenario.Name + "-" + string(rune('a'+index))}, Confidence: confidence, Attributes: edge.Attributes,
		}); err != nil {
			t.Fatalf("add edge %d: %v", index, err)
		}
	}
	return g
}

func rulesByID(values []Rule) map[string]Rule {
	result := make(map[string]Rule, len(values))
	for _, value := range values {
		result[value.ID()] = value
	}
	return result
}

func assertScenario(t *testing.T, scenario fixtureCase, candidates []model.Candidate) {
	t.Helper()
	if len(candidates) != scenario.WantCount {
		t.Fatalf("candidate count = %d, want %d: %#v", len(candidates), scenario.WantCount, candidates)
	}
	for _, candidate := range candidates {
		if candidate.RuleID != scenario.RuleID || len(candidate.EvidenceIDs) == 0 {
			t.Fatalf("candidate identity/evidence = %#v", candidate)
		}
		if err := candidate.Validate(); err != nil {
			t.Fatalf("invalid candidate: %v (%#v)", err, candidate)
		}
	}
	if scenario.WantCount > 0 && scenario.WantPriority != "" && candidates[0].Priority != scenario.WantPriority {
		t.Fatalf("priority = %s, want %s: %#v", candidates[0].Priority, scenario.WantPriority, candidates[0])
	}
	if scenario.WantCount > 0 {
		for _, wanted := range scenario.WantMissing {
			if !containsFragment(candidates[0].MissingFacts, wanted) {
				t.Fatalf("missing facts = %#v, want fragment %q", candidates[0].MissingFacts, wanted)
			}
		}
	}
}

func containsFragment(values []string, wanted string) bool {
	for _, value := range values {
		if strings.Contains(value, wanted) {
			return true
		}
	}
	return false
}
