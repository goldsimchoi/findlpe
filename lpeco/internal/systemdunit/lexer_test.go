package systemdunit

import (
	"os"
	"testing"
)

func TestParseContinuationCommentsDuplicatesAndDiagnostics(t *testing.T) {
	content, err := os.ReadFile("../../testdata/systemd/unit/quoting/continued.service")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	document, diagnostics := Parse(Source{Path: "/etc/systemd/system/continued.service", EvidenceID: "evidence-unit", Content: content})
	if len(document.Assignments) != 5 {
		t.Fatalf("assignment count = %d, want 5: %#v", len(document.Assignments), document.Assignments)
	}
	if document.Assignments[0].Section != "Unit" || document.Assignments[0].Key != "Description" || document.Assignments[0].Value != "Demo service" || document.Assignments[0].Line != 3 {
		t.Fatalf("continued assignment = %#v", document.Assignments[0])
	}
	if document.Assignments[1].Value != `"ONE=hello world" TWO=plain` {
		t.Fatalf("quoted value was altered: %#v", document.Assignments[1])
	}
	if document.Assignments[2].Key != "Environment" || document.Assignments[3].Key != "Environment" {
		t.Fatalf("duplicate assignments not retained: %#v", document.Assignments)
	}
	if document.Assignments[4].Key != "ExecStart" || document.Assignments[4].Source.EvidenceID != "evidence-unit" {
		t.Fatalf("ExecStart provenance = %#v", document.Assignments[4])
	}
	if len(diagnostics) != 1 || diagnostics[0].Code != "missing-equals" || diagnostics[0].Line != 11 {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func TestParseRejectsAssignmentOutsideSectionButKeepsFollowingSection(t *testing.T) {
	document, diagnostics := Parse(Source{Path: "/tmp/demo.service", Content: []byte("User=root\n[Service]\nUser=daemon\n")})
	if len(diagnostics) != 1 || diagnostics[0].Code != "assignment-outside-section" {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	if len(document.Assignments) != 1 || document.Assignments[0].Value != "daemon" {
		t.Fatalf("document = %#v", document)
	}
}
