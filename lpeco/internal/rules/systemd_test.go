package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/normalone/lpeco/internal/adapter"
	contextcollect "github.com/normalone/lpeco/internal/collect/context"
	pathcollect "github.com/normalone/lpeco/internal/collect/path"
	systemdcollect "github.com/normalone/lpeco/internal/collect/systemd"
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

func TestRankOnlyMarksCompleteHighConfidenceEvidenceReadOnlyValidated(t *testing.T) {
	tests := []struct {
		name        string
		confidences []model.Confidence
		missing     []string
		want        model.ValidationStatus
	}{
		{name: "high confidence", confidences: []model.Confidence{model.ConfidenceHigh}, want: model.ValidationReadOnly},
		{name: "medium confidence", confidences: []model.Confidence{model.ConfidenceMedium}, want: model.ValidationIncomplete},
		{name: "low confidence", confidences: []model.Confidence{model.ConfidenceLow}, want: model.ValidationIncomplete},
		{name: "missing fact", confidences: []model.Confidence{model.ConfidenceHigh}, missing: []string{"trigger timing unavailable"}, want: model.ValidationIncomplete},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Rank(RankInput{ControlConfirmed: true, SemanticsResolved: true, Confidences: tt.confidences, MissingFacts: tt.missing})
			if result.ValidationStatus != tt.want {
				t.Fatalf("ValidationStatus = %q, want %q (%#v)", result.ValidationStatus, tt.want, result)
			}
		})
	}
}

func TestIncompleteSystemdCatRemainsIncompleteThroughRuleEvaluation(t *testing.T) {
	const unitContent = "[Service]\nEnvironmentFile=/etc/default/demo\nExecStart=/usr/bin/demo $DEMO\n"
	catOutput := []byte(fmt.Sprintf(
		"LPECO_MANAGER\tsystem\t0\nLPECO_SYSTEMD_CAT_V2\nSOURCE\t%x\t%d\n%s",
		[]byte("/usr/lib/systemd/system/demo.service"), len(unitContent), unitContent,
	))
	catFacts, err := (systemdcollect.Collector{}).Parse(
		systemdcollect.CatDefinition("system", "demo.service"),
		adapter.ExecResult{Stdout: catOutput, Status: model.ProbeComplete},
		"e-cat-incomplete",
	)
	if err != nil {
		t.Fatalf("parse incomplete cat observation: %v", err)
	}

	runtimeUnit := systemdcollect.UnitFact{
		Name: "demo.service", Manager: "system", ManagerUID: 0,
		LoadState: "loaded", ActiveState: "active", User: "root", UID: 0, GID: 0,
		EnvironmentFiles: []string{"/etc/default/demo"}, RuntimeObserved: true,
		EvidenceIDs: []string{"e-runtime"}, Confidence: model.ConfidenceHigh,
	}
	systemdFacts, _ := systemdcollect.ReconcileFacts(append(
		[]model.Fact{semanticFact(t, "systemd_unit", "systemd", "e-runtime", model.ConfidenceHigh, runtimeUnit)},
		catFacts...,
	))
	var reconciledUnitFound bool
	for _, fact := range systemdFacts {
		if fact.Kind != "systemd_unit" {
			continue
		}
		var unit systemdcollect.UnitFact
		if json.Unmarshal(fact.Data, &unit) != nil || unit.Name != "demo.service" {
			continue
		}
		reconciledUnitFound = true
		if fact.Confidence == model.ConfidenceHigh || unit.Confidence == model.ConfidenceHigh ||
			!containsFragment(fact.MissingFacts, "unit file observation incomplete") ||
			!containsFragment(unit.MissingFacts, "unit file observation incomplete") {
			t.Fatalf("reconciled unit lost incomplete observation: fact=%#v unit=%#v", fact, unit)
		}
	}
	if !reconciledUnitFound {
		t.Fatal("reconciled demo.service unit fact missing")
	}

	facts := append([]model.Fact{
		semanticFact(t, "identity", "context", "e-identity", model.ConfidenceHigh, contextcollect.IdentityFact{
			UIDs: [4]int{1000, 1000, 1000, 1000}, GIDs: [4]int{1000, 1000, 1000, 1000},
		}),
		semanticFact(t, "systemd_activation", "systemd", "e-trigger", model.ConfidenceHigh, systemdcollect.ActivationFact{
			TriggerUnit: "demo.timer", TargetUnit: "demo.service", Manager: "system", ManagerUID: 0,
			Kind: "timer", Active: true, Automatic: true, EvidenceIDs: []string{"e-trigger"}, Confidence: model.ConfidenceHigh,
		}),
		semanticFact(t, "mount", "path", "e-mount", model.ConfidenceHigh, pathcollect.MountObservation{
			ID: 1, ParentID: 1, Root: "/", MountPoint: "/", FSType: "ext4", EvidenceIDs: []string{"e-mount"},
		}),
	}, systemdFacts...)
	paths := []pathcollect.StatObservation{
		{Path: "/", Device: 1, Inode: 1, Mode: 0o755, UID: 0, GID: 0, Kind: pathcollect.FileDirectory, Status: pathcollect.ObservationComplete},
		{Path: "/etc", Device: 1, Inode: 2, Mode: 0o755, UID: 0, GID: 0, Kind: pathcollect.FileDirectory, Status: pathcollect.ObservationComplete},
		{Path: "/etc/default", Device: 1, Inode: 3, Mode: 0o755, UID: 0, GID: 0, Kind: pathcollect.FileDirectory, Status: pathcollect.ObservationComplete},
		{Path: "/etc/default/demo", Device: 1, Inode: 4, Mode: 0o600, UID: 1000, GID: 1000, Kind: pathcollect.FileRegular, Status: pathcollect.ObservationComplete},
	}
	for index, observation := range paths {
		evidence := fmt.Sprintf("e-path-%d", index)
		observation.EvidenceIDs = []string{evidence}
		facts = append(facts,
			semanticFact(t, "path_stat", "path", evidence, model.ConfidenceHigh, observation),
			semanticFact(t, "path_acl", "path", evidence+"-acl", model.ConfidenceHigh, pathcollect.ACLObservation{
				Path: observation.Path, Status: pathcollect.ObservationComplete, EvidenceIDs: []string{evidence + "-acl"},
			}),
		)
	}

	built, diagnostics := graphpkg.Build(facts)
	for _, diagnostic := range diagnostics {
		if diagnostic.Code == "build-error" {
			t.Fatalf("graph build diagnostics: %#v", diagnostics)
		}
	}
	candidates := (controlledEnvironmentRule{}).Evaluate(context.Background(), built)
	if len(candidates) != 1 {
		t.Fatalf("candidate count = %d, want 1: %#v", len(candidates), candidates)
	}
	if candidates[0].Priority == model.PriorityP0 || candidates[0].ValidationStatus != model.ValidationIncomplete {
		t.Fatalf("incomplete unit observation was promoted: %#v", candidates[0])
	}
	if !containsFragment(candidates[0].MissingFacts, "unit file observation incomplete") {
		t.Fatalf("candidate missing facts = %#v", candidates[0].MissingFacts)
	}
}

func semanticFact(t *testing.T, kind, collector, evidence string, confidence model.Confidence, value any) model.Fact {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %s fact: %v", kind, err)
	}
	id, err := model.StableID("fact", struct {
		Kind string
		Data json.RawMessage
	}{kind, data})
	if err != nil {
		t.Fatalf("identify %s fact: %v", kind, err)
	}
	return model.Fact{
		ID: id, Kind: kind, SourceCollector: collector, EvidenceIDs: []string{evidence},
		Confidence: confidence, ObservationStatus: model.ProbeComplete, Data: data,
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
