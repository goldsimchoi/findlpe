package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/model"
)

func TestTerminalReportGoldenAndPriorityOrder(t *testing.T) {
	data := fixtureData()
	var output bytes.Buffer
	if err := WriteTerminal(&output, data); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("../../testdata/report/terminal.golden")
	if err != nil {
		t.Fatal(err)
	}
	if output.String() != string(want) {
		t.Fatalf("terminal report mismatch\n--- got ---\n%s\n--- want ---\n%s", output.String(), want)
	}
	if strings.Contains(strings.ToLower(output.String()), "confirmed exploit") || strings.Contains(output.String(), "hunter2") {
		t.Fatalf("unsafe terminal wording/data: %s", output.String())
	}
}

func TestJSONReportIsDeterministicStableAndContainsNoRawSecrets(t *testing.T) {
	data := fixtureData()
	var first, second bytes.Buffer
	if err := WriteJSON(&first, data); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&second, data); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("JSON report is nondeterministic")
	}
	for _, forbidden := range []string{"hunter2", "raw-evidence-secret", "abc-token"} {
		if strings.Contains(first.String(), forbidden) {
			t.Fatalf("JSON report leaked %q: %s", forbidden, first.String())
		}
	}
	var document struct {
		SchemaVersion int               `json:"schema_version"`
		Candidates    []model.Candidate `json:"candidates"`
		Facts         []model.Fact      `json:"facts"`
	}
	if err := json.Unmarshal(first.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != 1 || len(document.Candidates) != 2 || document.Candidates[0].Priority != model.PriorityP0 {
		t.Fatalf("unexpected JSON schema/order: %#v", document)
	}
}

func fixtureData() Data {
	current := model.NodeRef{ID: "principal-user", Kind: model.NodePrincipal}
	root := model.NodeRef{ID: "principal-root", Kind: model.NodePrincipal}
	object := model.NodeRef{ID: "file-demo", Kind: model.NodeFile}
	candidate := func(id string, priority model.Priority, rule string, evidence []string, missing []string, summary string) model.Candidate {
		return model.Candidate{ID: id, RuleID: rule, Category: "systemd", Priority: priority, Confidence: model.ConfidenceHigh,
			CurrentPrincipal: current, TargetPrincipal: root, ControlledObject: &object, PathNodes: []model.NodeRef{object},
			EvidenceIDs: evidence, MissingFacts: missing, ValidationStatus: model.ValidationReadOnly, Summary: summary}
	}
	factData := json.RawMessage(`{"pid":42,"cmdline":["demo","--password","hunter2"],"environment":{"API_TOKEN":"abc-token","PATH":"/usr/bin"}}`)
	return Data{
		Session: model.Session{SchemaVersion: 1, ID: "session-report", CreatedAt: time.Unix(1700000000, 0).UTC(), UpdatedAt: time.Unix(1700000010, 0).UTC(), Status: model.SessionComplete, TransportKind: "ssh"},
		Facts:   []model.Fact{{ID: "fact-process", Kind: "process", SourceCollector: "process", EvidenceIDs: []string{"evidence-z"}, Confidence: model.ConfidenceHigh, Data: factData}},
		Candidates: []model.Candidate{
			candidate("candidate-p1", model.PriorityP1, "process.replaceable-dependency", []string{"evidence-z"}, []string{"repeatable process trigger not confirmed"}, "TOKEN=abc-token process lead"),
			candidate("candidate-p0", model.PriorityP0, "systemd.writable-unit-source", []string{"evidence-a"}, []string{}, "Applied unit source is writable"),
		},
		Evidence: []model.Evidence{
			{ID: "evidence-z", SessionID: "session-report", ProbeID: "process.snapshot", SHA256: "deadbeef", Status: model.ProbeComplete, RelativePath: "evidence/process.txt"},
			{ID: "evidence-a", SessionID: "session-report", ProbeID: "systemd.show", SHA256: "cafe", Status: model.ProbeComplete, RelativePath: "evidence/systemd.txt"},
		},
		Limitations: []string{"Read-only observations can be incomplete when permissions deny access.", "Candidate ranking does not prove successful privilege escalation."},
	}
}
