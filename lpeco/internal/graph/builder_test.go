package graph

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/normalone/lpeco/internal/collect/context"
	"github.com/normalone/lpeco/internal/collect/systemd"
	"github.com/normalone/lpeco/internal/model"
)

func TestGraphStableNodeDedupAndDeterministicSerialization(t *testing.T) {
	identity := context.IdentityFact{UIDs: [4]int{1000, 1000, 1000, 1000}, GIDs: [4]int{1000, 1000, 1000, 1000}, Groups: []int{27, 1000}}
	factA := makeFact(t, "identity", "context", "e-identity-a", model.ConfidenceHigh, identity)
	factB := makeFact(t, "identity", "context", "e-identity-b", model.ConfidenceHigh, identity)
	unit := systemd.UnitFact{Name: "demo.service", Manager: "system", UID: 0, User: "root", ActiveState: "active", EvidenceIDs: []string{"e-unit"}, Confidence: model.ConfidenceHigh}
	unitFact := makeFact(t, "systemd_unit", "systemd", "e-unit", model.ConfidenceHigh, unit)

	left, diagnostics := Build([]model.Fact{factA, unitFact, factB})
	if hasDiagnosticCode(diagnostics, "build-error") {
		t.Fatalf("Build diagnostics = %#v", diagnostics)
	}
	right, _ := Build([]model.Fact{factB, factA, unitFact})
	if got := left.NodesByKind(model.NodePrincipal); len(got) != 2 {
		t.Fatalf("principal nodes = %#v", got)
	}
	current, ok := left.CurrentPrincipal()
	if !ok {
		t.Fatal("current principal missing")
	}
	node, _ := left.Node(current)
	if !reflect.DeepEqual(node.EvidenceIDs, []string{"e-identity-a", "e-identity-b"}) {
		t.Fatalf("deduplicated evidence = %#v", node.EvidenceIDs)
	}
	leftJSON, err := json.Marshal(left)
	if err != nil {
		t.Fatalf("marshal left: %v", err)
	}
	rightJSON, err := json.Marshal(right)
	if err != nil {
		t.Fatalf("marshal right: %v", err)
	}
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("serialization is nondeterministic:\n%s\n%s", leftJSON, rightJSON)
	}
}

func TestGraphRejectsEvidenceLessEdgesAndPreservesConflictingPartialFacts(t *testing.T) {
	unitHigh := systemd.UnitFact{Name: "demo.service", Manager: "system", UID: 0, User: "root", EvidenceIDs: []string{"e-runtime"}, Confidence: model.ConfidenceHigh}
	unitPartial := systemd.UnitFact{Name: "demo.service", Manager: "system", UID: 42, User: "service", MissingFacts: []string{"runtime properties unavailable"}, EvidenceIDs: []string{"e-files"}, Confidence: model.ConfidenceMedium}
	source := systemd.UnitSourceFact{UnitName: "demo.service", Path: "/etc/systemd/system/demo.service", Applied: true, Confidence: model.ConfidenceHigh}
	facts := []model.Fact{
		makeFact(t, "systemd_unit", "systemd", "e-runtime", model.ConfidenceHigh, unitHigh),
		makeFact(t, "systemd_unit", "systemd", "e-files", model.ConfidenceMedium, unitPartial),
		makeFact(t, "systemd_unit_source", "systemd", "", model.ConfidenceHigh, source),
	}
	built, diagnostics := Build(facts)
	if !hasDiagnosticCode(diagnostics, "node-conflict") {
		t.Fatalf("node conflict not preserved: %#v", diagnostics)
	}
	if !hasDiagnosticCode(diagnostics, "edge-without-evidence") {
		t.Fatalf("evidence-less edge was not rejected: %#v", diagnostics)
	}
	if len(built.Facts("systemd_unit")) != 2 {
		t.Fatalf("conflicting facts were dropped: %#v", built.Facts("systemd_unit"))
	}
	for _, edge := range built.Edges() {
		if len(edge.EvidenceIDs) == 0 {
			t.Fatalf("evidence-less edge retained: %#v", edge)
		}
	}
}

func makeFact(t *testing.T, kind, collector, evidence string, confidence model.Confidence, value any) model.Fact {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal fixture fact: %v", err)
	}
	id, err := model.StableID("fact", struct {
		Kind string
		Data json.RawMessage
	}{kind, data})
	if err != nil {
		t.Fatalf("fact ID: %v", err)
	}
	evidenceIDs := []string(nil)
	if evidence != "" {
		evidenceIDs = []string{evidence}
	}
	return model.Fact{ID: id, Kind: kind, SourceCollector: collector, EvidenceIDs: evidenceIDs, Confidence: confidence, Data: data}
}

func hasDiagnosticCode(values []Diagnostic, code string) bool {
	for _, value := range values {
		if value.Code == code {
			return true
		}
	}
	return false
}
