package report

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/vulnerability"
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

func TestReportsContainNoSecrets(t *testing.T) {
	data := fixtureData()
	var first, second, terminal bytes.Buffer
	if err := WriteJSON(&first, data); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&second, data); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("JSON report is nondeterministic")
	}
	if err := WriteTerminal(&terminal, data); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"hunter2", "raw-evidence-secret", "abc-token"} {
		if strings.Contains(first.String(), forbidden) {
			t.Fatalf("JSON report leaked %q: %s", forbidden, first.String())
		}
		if strings.Contains(terminal.String(), forbidden) {
			t.Fatalf("terminal report leaked %q: %s", forbidden, terminal.String())
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
	if document.SchemaVersion != 2 || len(document.Candidates) != 2 || document.Candidates[0].Priority != model.PriorityP0 {
		t.Fatalf("unexpected JSON schema/order: %#v", document)
	}
}

func TestKnownVulnerabilityJSONIsSeparatedDeterministicAndComplete(t *testing.T) {
	data := knownVulnerabilityFixtureData(t)
	var first, second bytes.Buffer
	if err := WriteJSON(&first, data); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&second, data); err != nil {
		t.Fatal(err)
	}
	if first.String() != second.String() {
		t.Fatal("known-vulnerability JSON is nondeterministic")
	}
	var document Document
	if err := json.Unmarshal(first.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.SchemaVersion != 2 {
		t.Fatalf("schema version = %d", document.SchemaVersion)
	}
	known := document.KnownVulnerabilities
	if known.Coverage.Status != model.VulnerabilityCoverageComplete || known.Coverage.Snapshot.Digest != strings.Repeat("a", 64) || known.Coverage.Snapshot.ImpactCatalogDigest != strings.Repeat("b", 64) {
		t.Fatalf("known coverage = %#v", known.Coverage)
	}
	if len(known.Matches) != 5 {
		t.Fatalf("matches = %#v", known.Matches)
	}
	wantStates := map[model.VulnerabilityState]bool{
		model.VulnerabilityStateAffected: true, model.VulnerabilityStateFixed: true,
		model.VulnerabilityStateNotAffected: true, model.VulnerabilityStateUnknown: true,
	}
	for _, match := range known.Matches {
		delete(wantStates, match.State)
		if !sort.StringsAreSorted(match.CVEIDs) || !sort.StringsAreSorted(match.USNIDs) || !sort.StringsAreSorted(match.OfficialReferences) || !sort.StringsAreSorted(match.TargetEvidenceIDs) || !sort.StringsAreSorted(match.MissingFacts) {
			t.Fatalf("unsorted match fields: %#v", match)
		}
		for _, reference := range match.OfficialReferences {
			if !strings.HasPrefix(reference, "https://ubuntu.com/security/") {
				t.Fatalf("unreviewed reference escaped report filter: %q", reference)
			}
		}
	}
	if len(wantStates) != 0 {
		t.Fatalf("missing states: %#v", wantStates)
	}
	if len(document.Candidates) != 2 || !reflect.DeepEqual(document.Candidates[1].RelatedMatchIDs, []string{"match-affected-path"}) {
		t.Fatalf("candidate relationship = %#v", document.Candidates)
	}
	assertKnownVulnerabilityGolden(t, document)
	if strings.Contains(first.String(), "exploit.example") || strings.Contains(first.String(), "RAW-ADVISORY-PROSE") || strings.Contains(first.String(), "raw-evidence-body") {
		t.Fatalf("unsafe provider/evidence data in JSON: %s", first.String())
	}
}

func assertKnownVulnerabilityGolden(t *testing.T, document Document) {
	t.Helper()
	body, err := os.ReadFile("../../testdata/report/known-vulnerabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	var want struct {
		SchemaVersion       int                 `json:"schema_version"`
		CoverageStatus      string              `json:"coverage_status"`
		SnapshotDigest      string              `json:"snapshot_digest"`
		OrderedMatchIDs     []string            `json:"ordered_match_ids"`
		RelatedCandidateIDs map[string][]string `json:"related_candidate_ids"`
	}
	if err := json.Unmarshal(body, &want); err != nil {
		t.Fatal(err)
	}
	gotIDs := make([]string, 0, len(document.KnownVulnerabilities.Matches))
	for _, match := range document.KnownVulnerabilities.Matches {
		gotIDs = append(gotIDs, match.ID)
	}
	related := make(map[string][]string)
	for _, candidate := range document.Candidates {
		for _, matchID := range candidate.RelatedMatchIDs {
			related[matchID] = append(related[matchID], candidate.ID)
		}
	}
	if document.SchemaVersion != want.SchemaVersion || string(document.KnownVulnerabilities.Coverage.Status) != want.CoverageStatus ||
		document.KnownVulnerabilities.Coverage.Snapshot.Digest != want.SnapshotDigest || !reflect.DeepEqual(gotIDs, want.OrderedMatchIDs) || !reflect.DeepEqual(related, want.RelatedCandidateIDs) {
		t.Fatalf("known-vulnerability golden mismatch\n got: schema=%d status=%s digest=%s matches=%#v related=%#v\nwant: %#v",
			document.SchemaVersion, document.KnownVulnerabilities.Coverage.Status, document.KnownVulnerabilities.Coverage.Snapshot.Digest, gotIDs, related, want)
	}
}

func TestKnownVulnerabilityTerminalSectionsAndMatchOnlyInventory(t *testing.T) {
	data := knownVulnerabilityFixtureData(t)
	var output bytes.Buffer
	if err := WriteTerminal(&output, data); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, heading := range []string{
		"Deterministic candidates:", "Known-vulnerability path candidates:",
		"Match-only known-vulnerability inventory:", "Known-vulnerability coverage:",
	} {
		if strings.Count(text, heading) != 1 {
			t.Fatalf("heading %q count != 1:\n%s", heading, text)
		}
	}
	for _, fragment := range []string{
		"match-affected-inventory", "match-unknown", "fixed: 1", "not affected: 1",
		"match-affected-path", "snapshot: " + strings.Repeat("a", 64), "status: complete", "stale: false",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("terminal output missing %q:\n%s", fragment, text)
		}
	}
	if strings.Contains(strings.ToLower(text), "no known vulnerabilities") || strings.Contains(text, "exploit.example") {
		t.Fatalf("prohibited terminal wording/link:\n%s", text)
	}
}

func TestKnownVulnerabilityEmptyCompleteStatementAndLegacyCoverage(t *testing.T) {
	complete := Data{Session: model.Session{SchemaVersion: model.SessionSchemaVersion, Vulnerability: model.VulnerabilityCoverage{
		Mode: model.VulnerabilityModeAuto, Status: model.VulnerabilityCoverageComplete,
		Snapshot: model.SnapshotReference{Digest: strings.Repeat("c", 64)},
	}}}
	var terminal bytes.Buffer
	if err := WriteTerminal(&terminal, complete); err != nil {
		t.Fatal(err)
	}
	want := "No affected records matched the selected privileged-component scope in snapshot " + strings.Repeat("c", 64) + "."
	if !strings.Contains(terminal.String(), want) {
		t.Fatalf("complete empty statement missing:\n%s", terminal.String())
	}

	legacy := fixtureData()
	var encoded bytes.Buffer
	if err := WriteJSON(&encoded, legacy); err != nil {
		t.Fatal(err)
	}
	var document Document
	if err := json.Unmarshal(encoded.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.KnownVulnerabilities.Coverage.Status != model.VulnerabilityCoverageLegacyNotRequested {
		t.Fatalf("legacy coverage = %#v", document.KnownVulnerabilities.Coverage)
	}
}

func TestKnownVulnerabilityTerminalEscapesHostileProviderStrings(t *testing.T) {
	data := knownVulnerabilityFixtureData(t)
	data.Session.Vulnerability.Provider = "ubuntu\x1b[31m\tline\r\nnext\u202eTOKEN=abc123"
	data.Session.Vulnerability.Diagnostics = append(data.Session.Vulnerability.Diagnostics, model.VulnerabilityDiagnostic{
		Code: "hostile", Message: "first\nsecond\x1b\u202e", MissingFacts: []string{"tab\tvalue"},
	})
	var output bytes.Buffer
	if err := WriteTerminal(&output, data); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, forbidden := range []string{"\x1b", "\r", "\t", "\u202e", "abc123"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("terminal output contains hostile sequence %q: %q", forbidden, text)
		}
	}
	for _, escaped := range []string{`\u001B`, `\u0009`, `\u000D`, `\u000A`, `\u202E`, "TOKEN=[REDACTED]"} {
		if !strings.Contains(text, escaped) {
			t.Fatalf("terminal output missing escape %q: %q", escaped, text)
		}
	}
	var encoded bytes.Buffer
	if err := WriteJSON(&encoded, data); err != nil || !json.Valid(encoded.Bytes()) {
		t.Fatalf("hostile JSON invalid: %v\n%s", err, encoded.String())
	}
}

func knownVulnerabilityFixtureData(t *testing.T) Data {
	t.Helper()
	version := model.DebianVersion{Raw: "1.0-1", Upstream: "1.0", Revision: "1", Valid: true}
	match := func(id string, state model.VulnerabilityState) model.VulnerabilityMatch {
		value := model.VulnerabilityMatch{
			ID: id, Provider: "ubuntu", SnapshotDigest: strings.Repeat("a", 64), DistributionID: "ubuntu", Release: "22.04", Codename: "jammy", Channel: "standard", Architecture: "amd64",
			BinaryPackage: "demo", BinaryArchitecture: "amd64", BinaryVersion: version, SourcePackage: "demo-source", SourceVersion: version,
			AdvisoryID: "CVE-2099-3001", RecordID: "record-" + id, CVEIDs: []string{"CVE-2099-3002", "CVE-2099-3001"}, USNIDs: []string{"USN-2", "USN-1"},
			OfficialReferences: []string{"https://exploit.example/poc", "https://ubuntu.com/security/notices/USN-1", "https://ubuntu.com/security/CVE-2099-3001"},
			State:              state, Reason: "provider reason", TargetEvidenceIDs: []string{"evidence-z", "evidence-a"}, Confidence: model.ConfidenceHigh,
		}
		if state == model.VulnerabilityStateUnknown {
			value.MissingFacts = []string{"under investigation", "architecture uncertain"}
			value.Confidence = model.ConfidenceMedium
		}
		return value
	}
	matches := []model.VulnerabilityMatch{
		match("match-unknown", model.VulnerabilityStateUnknown),
		match("match-fixed", model.VulnerabilityStateFixed),
		match("match-affected-inventory", model.VulnerabilityStateAffected),
		match("match-not-affected", model.VulnerabilityStateNotAffected),
		match("match-affected-path", model.VulnerabilityStateAffected),
	}
	facts, err := vulnerability.Facts(matches)
	if err != nil {
		t.Fatal(err)
	}
	current := model.NodeRef{ID: "principal-user", Kind: model.NodePrincipal}
	root := model.NodeRef{ID: "principal-root", Kind: model.NodePrincipal}
	consumer := model.NodeRef{ID: "process-root", Kind: model.NodeProcess}
	deterministic := model.Candidate{ID: "candidate-deterministic", RuleID: "systemd.writable-unit-source", Category: "systemd", Priority: model.PriorityP0, Confidence: model.ConfidenceHigh,
		CurrentPrincipal: current, TargetPrincipal: root, PrivilegedConsumer: &consumer, PathNodes: []model.NodeRef{consumer}, EvidenceIDs: []string{"evidence-b"}, MissingFacts: []string{}, ValidationStatus: model.ValidationReadOnly, Summary: "deterministic path"}
	known := model.Candidate{ID: "candidate-known", RuleID: "vulnerability.known-privilege-path", Category: "known-vulnerability", Priority: model.PriorityP1, Confidence: model.ConfidenceHigh,
		CurrentPrincipal: current, TargetPrincipal: root, PrivilegedConsumer: &consumer, PathNodes: []model.NodeRef{consumer}, EvidenceIDs: []string{"evidence-z", "evidence-a"}, RelatedMatchIDs: []string{"match-affected-path"}, MissingFacts: []string{}, ValidationStatus: model.ValidationReadOnly, Summary: "known path"}
	return Data{
		Session: model.Session{SchemaVersion: model.SessionSchemaVersion, ID: "known-report", Status: model.SessionComplete, TransportKind: "ssh", Vulnerability: model.VulnerabilityCoverage{
			Mode: model.VulnerabilityModeAuto, Status: model.VulnerabilityCoverageComplete, Provider: "ubuntu", SelectedRelease: "22.04", SelectedCodename: "jammy", SelectedChannel: "standard", SelectedArchitecture: "amd64",
			Snapshot: model.SnapshotReference{Provider: "ubuntu", SchemaVersion: 1, Digest: strings.Repeat("a", 64), RetrievedAt: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC), ProviderModifiedAt: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC), SupportedReleases: []string{"24.04", "22.04"}, SupportedChannels: []string{"standard"}, ImpactCatalogDigest: strings.Repeat("b", 64)},
		}},
		Facts: facts, Candidates: []model.Candidate{known, deterministic}, Evidence: []model.Evidence{{ID: "evidence-a", RelativePath: "evidence/body.txt"}},
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
	factData := json.RawMessage(`{"pid":42,"cmdline":["demo","--password","hunter2"],"values":{"PATH":{"value":"abc-token","sensitive":true},"DISPLAY":{"value":":0","sensitive":false}}}`)
	return Data{
		Session: model.Session{SchemaVersion: 1, ID: "session-report", CreatedAt: time.Unix(1700000000, 0).UTC(), UpdatedAt: time.Unix(1700000010, 0).UTC(), Status: model.SessionComplete, TransportKind: "ssh", Target: "ssh://alice:raw-evidence-secret@example.test"},
		Facts:   []model.Fact{{ID: "fact-process", Kind: "process", SourceCollector: "process", EvidenceIDs: []string{"evidence-z"}, Confidence: model.ConfidenceHigh, Data: factData}},
		Candidates: []model.Candidate{
			candidate("candidate-p1", model.PriorityP1, "process.replaceable-dependency", []string{"evidence-z"}, []string{"repeatable process trigger not confirmed"}, "TOKEN=abc-token process lead"),
			candidate("candidate-p0", model.PriorityP0, "systemd.writable-unit-source", []string{"evidence-a"}, []string{}, "Applied unit source is writable"),
		},
		Evidence: []model.Evidence{
			{ID: "evidence-z", SessionID: "session-report", ProbeID: "process.snapshot", SHA256: "deadbeef", Status: model.ProbeComplete, RelativePath: "evidence/process.txt"},
			{ID: "evidence-a", SessionID: "session-report", ProbeID: "systemd.show", SHA256: "cafe", Status: model.ProbeComplete, RelativePath: "evidence/systemd.txt"},
		},
		GraphDiagnostics: []model.GraphDiagnostic{{Code: "fixture-graph", Message: "graph TOKEN=abc-token", EvidenceIDs: []string{"evidence-z"}}},
		RuleDiagnostics:  []model.RuleDiagnostic{{Code: "fixture-rule", RuleID: "fixture", Message: "rule TOKEN=abc-token", EvidenceIDs: []string{"evidence-a"}}},
		Limitations:      []string{"Read-only observations can be incomplete when permissions deny access.", "Candidate ranking does not prove successful privilege escalation."},
	}
}
