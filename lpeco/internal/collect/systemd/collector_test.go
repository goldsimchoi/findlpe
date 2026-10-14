package systemd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

func TestPlanUsesSystemctlWhenAvailableAndReadOnlyFilesOtherwise(t *testing.T) {
	collector := Collector{}
	discovery := collect.Discovery{UnitNames: []string{"demo.service"}}
	withSystemctl := collector.Plan(model.HostProfile{SystemdRunning: true, AvailableCommands: map[string]bool{"systemctl": true}}, discovery)
	withoutSystemctl := collector.Plan(model.HostProfile{SystemdRunning: true, AvailableCommands: map[string]bool{"systemctl": false}}, discovery)
	if len(withSystemctl) != 4 || len(withoutSystemctl) != 4 {
		t.Fatalf("planned definitions = %d/%d, want system+user show and cat", len(withSystemctl), len(withoutSystemctl))
	}

	planner := probe.NewPlanner()
	capabilities := adapter.Capabilities{MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20}
	selected, err := planner.Select(withSystemctl[0], capabilities, model.HostProfile{SystemdRunning: true, AvailableCommands: map[string]bool{"systemctl": true}}, probe.Policy{})
	if err != nil || selected.ID != "systemctl" {
		t.Fatalf("systemctl selection = %#v, %v", selected, err)
	}
	selected, err = planner.Select(withoutSystemctl[0], capabilities, model.HostProfile{SystemdRunning: true, AvailableCommands: map[string]bool{"systemctl": false}}, probe.Policy{})
	if err != nil || selected.ID != "unit-files" {
		t.Fatalf("file fallback selection = %#v, %v", selected, err)
	}
	for _, definition := range withoutSystemctl {
		if definition.SafetyClass != model.PassiveRead {
			t.Fatalf("probe %s safety = %s", definition.ID, definition.SafetyClass)
		}
	}
}

func TestPlanTargetsUnitsOnlyInTheirDiscoveredManagerScope(t *testing.T) {
	definitions := (Collector{}).Plan(model.HostProfile{SystemdRunning: true}, collect.Discovery{
		Units: []collect.UnitIdentity{
			{Name: "demo.service", Manager: "system", ManagerUID: 0},
			{Name: "agent.service", Manager: "user", ManagerUID: 1000},
		},
	})
	ids := make([]string, 0, len(definitions))
	for _, definition := range definitions {
		ids = append(ids, definition.ID)
	}
	want := []string{
		"systemd.show.system",
		"systemd.show.user",
		"systemd.cat.system.demo.service",
		"systemd.cat.user.agent.service",
	}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("scoped systemd plan = %#v, want %#v", ids, want)
	}
}

func TestNormalizeCombinesRuntimeAuthorityWithFileProvenance(t *testing.T) {
	runtimeUnits, diagnostics := ParseShow(readSystemdFixture(t, "../../../testdata/systemd/show/full.txt"), "evidence-show")
	if len(diagnostics) != 0 {
		t.Fatalf("show diagnostics: %#v", diagnostics)
	}
	documents, catDiagnostics := ParseCat("demo.service", readSystemdFixture(t, "../../../testdata/systemd/cat/demo.cat"), "evidence-cat")
	if len(catDiagnostics) != 0 {
		t.Fatalf("cat diagnostics: %#v", catDiagnostics)
	}
	normalized := Normalize(runtimeUnits, map[string][]DocumentSet{"demo.service": {{Documents: documents, Complete: true}}}, 1000)
	demo := normalizedUnitByName(t, normalized.Units, "demo.service")
	if demo.User != "root" || demo.WorkingDirectory != "/opt/demo" || demo.RootDirectory != "" || demo.RootImage != "" {
		t.Fatalf("runtime-effective unit values = %#v", demo)
	}
	if !reflect.DeepEqual(demo.SourcePaths, []string{"/usr/lib/systemd/system/demo.service", "/etc/systemd/system/demo.service.d/20-local.conf"}) {
		t.Fatalf("source paths = %#v", demo.SourcePaths)
	}
	start := normalizedExec(t, normalized.Execs, "demo.service", "ExecStart")
	if start.Command.Executable != "/usr/bin/runtime-demo" || start.Source.EvidenceID != "evidence-cat" {
		t.Fatalf("normalized ExecStart = %#v", start)
	}
	if !hasDiagnostic(normalized.Diagnostics, "runtime-file-mismatch") {
		t.Fatalf("runtime/file mismatch diagnostic missing: %#v", normalized.Diagnostics)
	}
	for _, directive := range []string{"ExecStartPre", "ExecStart", "ExecReload"} {
		_ = normalizedExec(t, normalized.Execs, "demo.service", directive)
	}
	security := normalizedSecurity(t, normalized.Security, "demo.service")
	if !security.NoNewPrivileges || !reflect.DeepEqual(security.CapabilityBoundingSet, []string{"cap_chown", "cap_setuid"}) {
		t.Fatalf("unit security = %#v", security)
	}
}

func TestReconcileFactsCombinesSeparateRuntimeAndFileObservations(t *testing.T) {
	collector := Collector{}
	runtimeFacts, err := collector.Parse(ShowDefinition("system"), adapter.ExecResult{
		Stdout: readSystemdFixture(t, "../../../testdata/systemd/show/full.txt"), Status: model.ProbeComplete,
	}, "evidence-show")
	if err != nil {
		t.Fatal(err)
	}
	fileFacts, err := collector.Parse(CatDefinition("system", "demo.service"), adapter.ExecResult{
		Stdout: readSystemdFixture(t, "../../../testdata/systemd/cat/demo.cat"), Status: model.ProbeComplete,
	}, "evidence-cat")
	if err != nil {
		t.Fatal(err)
	}
	reconciled, diagnostics := ReconcileFacts(append(runtimeFacts, fileFacts...))
	if !hasDiagnostic(diagnostics, "runtime-file-mismatch") {
		t.Fatalf("runtime/file mismatch diagnostic missing: %#v", diagnostics)
	}
	var demo UnitFact
	var start ExecFact
	var security UnitSecurityFact
	var securityEnvelope model.Fact
	for _, fact := range reconciled {
		switch fact.Kind {
		case "systemd_unit":
			var value UnitFact
			_ = json.Unmarshal(fact.Data, &value)
			if value.Name == "demo.service" && value.Manager == "system" {
				demo = value
			}
		case "systemd_exec":
			var value ExecFact
			_ = json.Unmarshal(fact.Data, &value)
			if value.UnitName == "demo.service" && value.Directive == "ExecStart" && value.Manager == "system" {
				start = value
			}
		case "systemd_security":
			var value UnitSecurityFact
			_ = json.Unmarshal(fact.Data, &value)
			if value.UnitName == "demo.service" && value.Manager == "system" {
				security = value
				securityEnvelope = fact
			}
		}
	}
	if !demo.RuntimeObserved || !demo.FilesObserved || demo.Confidence != model.ConfidenceHigh {
		t.Fatalf("reconciled unit = %#v", demo)
	}
	if start.Command.Executable != "/usr/bin/runtime-demo" || start.Source.EvidenceID != "evidence-cat" || start.Confidence != model.ConfidenceHigh {
		t.Fatalf("reconciled ExecStart = %#v", start)
	}
	if security.Confidence != model.ConfidenceHigh || securityEnvelope.Confidence != model.ConfidenceHigh || len(securityEnvelope.MissingFacts) != 0 {
		t.Fatalf("reconciled security = %#v, envelope = %#v", security, securityEnvelope)
	}
}

func TestCatFactsCarryManagerScopeAndUserOwnership(t *testing.T) {
	input := append([]byte("LPECO_MANAGER\tuser\t1000\n"), readSystemdFixture(t, "../../../testdata/systemd/cat/file-only.cat")...)
	facts, err := (Collector{}).Parse(CatDefinition("user", "file-only.service"), adapter.ExecResult{Stdout: input, Status: model.ProbeComplete}, "evidence-user-file")
	if err != nil {
		t.Fatal(err)
	}
	for _, fact := range facts {
		switch fact.Kind {
		case "systemd_unit":
			var value UnitFact
			_ = json.Unmarshal(fact.Data, &value)
			if value.Manager != "user" || value.ManagerUID != 1000 || value.UID != 1000 || !value.InventoryOnly {
				t.Fatalf("user unit scope = %#v", value)
			}
		case "systemd_unit_source":
			var value UnitSourceFact
			_ = json.Unmarshal(fact.Data, &value)
			if value.Manager != "user" || value.ManagerUID != 1000 {
				t.Fatalf("user source scope = %#v", value)
			}
		case "systemd_exec":
			var value ExecFact
			_ = json.Unmarshal(fact.Data, &value)
			if value.Manager != "user" || value.ManagerUID != 1000 {
				t.Fatalf("user exec scope = %#v", value)
			}
		}
	}
}

func TestSystemctlHeaderOnlyObservationRequestsFileFallback(t *testing.T) {
	definition := ShowDefinition("system")
	assessment := (Collector{}).Assess(definition, definition.Variants[0], adapter.ExecResult{
		Stdout: []byte("LPECO_SYSTEMD_SHOW_V1\n"), Status: model.ProbeComplete,
	})
	if !assessment.Fallback || assessment.Status != model.ProbePartial {
		t.Fatalf("assessment = %#v, want partial fallback", assessment)
	}
	fileAssessment := (Collector{}).Assess(definition, definition.Variants[1], adapter.ExecResult{
		Stdout: []byte("LPECO_SYSTEMD_SHOW_V1\n"), Status: model.ProbeComplete,
	})
	if fileAssessment.Fallback {
		t.Fatalf("file variant recursively requested fallback: %#v", fileAssessment)
	}
}

func TestCatProbeReadsAuthoritativePathsIntoLengthDelimitedFrames(t *testing.T) {
	definition := CatDefinition("system", "demo.service")
	for _, variant := range definition.Variants {
		script := variant.Command.Script
		for _, required := range []string{"LPECO_SYSTEMD_CAT_V2", "SOURCE\\t%s\\t%s", "wc -c", "od -An -v -tx1"} {
			if !strings.Contains(script, required) {
				t.Errorf("%s cat variant lacks %q", variant.ID, required)
			}
		}
	}
	systemctlScript := definition.Variants[0].Command.Script
	for _, property := range []string{"--property=FragmentPath", "--property=DropInPaths"} {
		if !strings.Contains(systemctlScript, property) {
			t.Errorf("systemctl cat variant lacks authoritative %s lookup", property)
		}
	}
	if strings.Contains(systemctlScript, "systemctl $_lpeco_scope cat") {
		t.Fatal("systemctl cat output is ambiguous with legal unit comments")
	}
}

func TestCatParserRejectsLegacyCommentDelimitedOutput(t *testing.T) {
	documents, diagnostics := ParseCat("demo.service", []byte("# /etc/systemd/system/demo.service\n[Service]\nExecStart=/bin/true\n"), "evidence-legacy")
	if len(documents) != 0 || !hasDiagnostic(diagnostics, "cat-unsupported-format") {
		t.Fatalf("legacy ambiguous cat output = documents %#v, diagnostics %#v", documents, diagnostics)
	}
}

func TestCatFactsAcceptCanonicalFragmentForAlias(t *testing.T) {
	input := catFrameForTest("system", 0, catTestSource{
		Path:    "/usr/lib/systemd/system/rsyslog.service",
		Content: "[Service]\nExecStart=/usr/sbin/rsyslogd -n\n",
	})
	_, diagnostics := ParseCat("syslog.service", input, "evidence-alias")
	if len(diagnostics) != 0 {
		t.Fatalf("authoritative canonical alias source produced diagnostics: %#v", diagnostics)
	}
	facts, err := (Collector{}).Parse(CatDefinition("system", "syslog.service"), adapter.ExecResult{
		Stdout: input, Status: model.ProbeComplete,
	}, "evidence-alias")
	if err != nil {
		t.Fatalf("parse alias unit: %v", err)
	}
	for _, fact := range facts {
		if fact.Kind != "systemd_exec" {
			continue
		}
		var value ExecFact
		if json.Unmarshal(fact.Data, &value) == nil && value.UnitName == "syslog.service" && value.Command.Executable == "/usr/sbin/rsyslogd" {
			return
		}
	}
	t.Fatalf("canonical alias fragment did not produce an exec fact: %#v", facts)
}

func TestCatFramePreservesSourceLookingCommentsAsUnitContent(t *testing.T) {
	input := catFrameForTest("system", 0, catTestSource{
		Path: "/usr/lib/systemd/system/demo.service",
		Content: "[Service]\n" +
			"# /etc/systemd/system/demo.service\n" +
			"# /etc/systemd/system/demo.service.d/fake.conf\n" +
			"ExecStart=/usr/lib/demo/worker\n",
	})
	documents, diagnostics := ParseCat("demo.service", input, "evidence-comment")
	if len(diagnostics) != 0 {
		t.Fatalf("source-looking unit comments produced diagnostics: %#v", diagnostics)
	}
	if len(documents) != 1 || documents[0].Source.Path != "/usr/lib/systemd/system/demo.service" {
		t.Fatalf("source-looking comments changed document provenance: %#v", documents)
	}
	facts, err := (Collector{}).Parse(CatDefinition("system", "demo.service"), adapter.ExecResult{
		Stdout: input, Status: model.ProbeComplete,
	}, "evidence-comment")
	if err != nil {
		t.Fatalf("parse source-looking comments: %v", err)
	}
	for _, fact := range facts {
		if fact.Kind != "systemd_exec" {
			continue
		}
		var value ExecFact
		if json.Unmarshal(fact.Data, &value) == nil && value.Command.Executable == "/usr/lib/demo/worker" {
			return
		}
	}
	t.Fatalf("directive following source-looking comments was lost: %#v", facts)
}

func TestIncompleteCatFrameDowngradesFileDerivedSemantics(t *testing.T) {
	complete := catFrameForTest("system", 0, catTestSource{
		Path:    "/usr/lib/systemd/system/demo.service",
		Content: "[Service]\nExecStart=/usr/lib/demo/worker\n",
	})
	input := bytes.TrimSuffix(complete, []byte("END\n"))
	facts, err := (Collector{}).Parse(CatDefinition("system", "demo.service"), adapter.ExecResult{
		Stdout: input, Status: model.ProbeComplete,
	}, "evidence-truncated-frame")
	if err != nil {
		t.Fatalf("parse incomplete framed observation: %v", err)
	}
	var foundExec, foundSource, foundSecurity, foundDiagnostic bool
	for _, fact := range facts {
		switch fact.Kind {
		case "systemd_exec":
			var value ExecFact
			if json.Unmarshal(fact.Data, &value) == nil && value.Command.Executable == "/usr/lib/demo/worker" {
				foundExec = true
				if value.Confidence == model.ConfidenceHigh || !containsMissing(value.MissingFacts, "unit file observation incomplete") {
					t.Fatalf("incomplete frame left exec semantics authoritative: %#v", value)
				}
				if fact.Confidence == model.ConfidenceHigh || !containsMissing(fact.MissingFacts, "unit file observation incomplete") {
					t.Fatalf("incomplete frame was not reflected in fact envelope: %#v", fact)
				}
			}
		case "systemd_unit_source":
			var value UnitSourceFact
			if json.Unmarshal(fact.Data, &value) == nil && value.Path == "/usr/lib/systemd/system/demo.service" {
				foundSource = true
				if value.Confidence == model.ConfidenceHigh {
					t.Fatalf("incomplete frame left source confidence high: %#v", value)
				}
			}
		case "systemd_security":
			var value UnitSecurityFact
			if json.Unmarshal(fact.Data, &value) == nil && value.UnitName == "demo.service" {
				foundSecurity = true
				if value.Confidence == model.ConfidenceHigh || fact.Confidence == model.ConfidenceHigh ||
					!containsMissing(value.MissingFacts, "unit file observation incomplete") ||
					!containsMissing(fact.MissingFacts, "unit file observation incomplete") {
					t.Fatalf("incomplete frame left security semantics authoritative: value=%#v fact=%#v", value, fact)
				}
			}
		case "systemd_diagnostic":
			if strings.Contains(string(fact.Data), "cat-missing-end") {
				foundDiagnostic = true
			}
		}
	}
	if !foundExec || !foundSource || !foundSecurity || !foundDiagnostic {
		t.Fatalf("incomplete frame facts: exec=%v source=%v security=%v diagnostic=%v facts=%#v", foundExec, foundSource, foundSecurity, foundDiagnostic, facts)
	}
}

func TestNormalizeCreatesExplicitAndImplicitActivationEdges(t *testing.T) {
	runtimeUnits, _ := ParseShow(readSystemdFixture(t, "../../../testdata/systemd/show/full.txt"), "evidence-show")
	normalized := Normalize(runtimeUnits, nil, 1000)
	want := map[string]string{
		"demo.timer":   "demo.service",
		"agent.socket": "agent.service",
		"demo.path":    "demo.service",
	}
	for trigger, target := range want {
		found := false
		for _, activation := range normalized.Activations {
			if activation.TriggerUnit == trigger && activation.TargetUnit == target {
				found = true
				if activation.EvidenceIDs[0] != "evidence-show" {
					t.Fatalf("activation lacks show evidence: %#v", activation)
				}
			}
		}
		if !found {
			t.Fatalf("activation %s -> %s not found: %#v", trigger, target, normalized.Activations)
		}
	}
	user := normalizedUnitByName(t, normalized.Units, "user-demo.service")
	if !user.InventoryOnly {
		t.Fatalf("same-principal user unit was not inventory-only: %#v", user)
	}
}

func TestFileOnlyFallbackAndUnavailableRuntimeRemainPartial(t *testing.T) {
	documents, diagnostics := ParseCat("file-only.service", readSystemdFixture(t, "../../../testdata/systemd/cat/file-only.cat"), "evidence-file")
	if len(diagnostics) != 0 {
		t.Fatalf("ParseCat diagnostics: %#v", diagnostics)
	}
	normalized := Normalize(nil, map[string][]DocumentSet{"file-only.service": {{Documents: documents, Complete: true}}}, 1000)
	unit := normalizedUnitByName(t, normalized.Units, "file-only.service")
	if unit.Confidence != model.ConfidenceMedium || !containsMissing(unit.MissingFacts, "runtime properties unavailable") {
		t.Fatalf("file-only unit = %#v", unit)
	}
	exec := normalizedExec(t, normalized.Execs, "file-only.service", "ExecStart")
	if exec.Command.Executable != "/opt/file-only/run" || exec.Confidence != model.ConfidenceMedium {
		t.Fatalf("file-only exec = %#v", exec)
	}

	collector := Collector{}
	facts, err := collector.Parse(ShowDefinition("system"), adapter.ExecResult{
		Stderr: readSystemdFixture(t, "../../../testdata/systemd/show/dbus-denied.txt"), Status: model.ProbeUnavailable,
	}, "evidence-denied")
	if err != nil {
		t.Fatalf("collector unavailable parse: %v", err)
	}
	if len(facts) != 1 || facts[0].Kind != "systemd_collection_status" || facts[0].Confidence != model.ConfidenceLow {
		t.Fatalf("unavailable facts = %#v", facts)
	}
	if strings.Contains(string(facts[0].Data), "safe") {
		t.Fatalf("unavailable runtime was classified safe: %s", facts[0].Data)
	}
}

func TestNormalizedFactsAllCarryEvidence(t *testing.T) {
	runtimeUnits, _ := ParseShow(readSystemdFixture(t, "../../../testdata/systemd/show/full.txt"), "evidence-show")
	normalized := Normalize(runtimeUnits, nil, 1000)
	facts, err := Facts(normalized)
	if err != nil {
		t.Fatalf("Facts: %v", err)
	}
	if len(facts) == 0 {
		t.Fatal("Facts returned no systemd facts")
	}
	for _, fact := range facts {
		if len(fact.EvidenceIDs) == 0 {
			t.Fatalf("fact lacks evidence: %#v", fact)
		}
	}
}

func normalizedUnitByName(t *testing.T, units []UnitFact, name string) UnitFact {
	t.Helper()
	for _, unit := range units {
		if unit.Name == name {
			return unit
		}
	}
	t.Fatalf("normalized unit %q not found", name)
	return UnitFact{}
}

func normalizedExec(t *testing.T, values []ExecFact, unit, directive string) ExecFact {
	t.Helper()
	for _, value := range values {
		if value.UnitName == unit && value.Directive == directive {
			return value
		}
	}
	t.Fatalf("exec %s/%s not found", unit, directive)
	return ExecFact{}
}

func normalizedSecurity(t *testing.T, values []UnitSecurityFact, unit string) UnitSecurityFact {
	t.Helper()
	for _, value := range values {
		if value.UnitName == unit {
			return value
		}
	}
	t.Fatalf("security %s not found", unit)
	return UnitSecurityFact{}
}

func hasDiagnostic(values []CollectorDiagnostic, code string) bool {
	for _, value := range values {
		if value.Code == code {
			return true
		}
	}
	return false
}

func containsMissing(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}

type catTestSource struct {
	Path    string
	Content string
}

func catFrameForTest(manager string, managerUID int, sources ...catTestSource) []byte {
	var output bytes.Buffer
	if manager != "" {
		fmt.Fprintf(&output, "LPECO_MANAGER\t%s\t%d\n", manager, managerUID)
	}
	output.WriteString("LPECO_SYSTEMD_CAT_V2\n")
	for _, source := range sources {
		fmt.Fprintf(&output, "SOURCE\t%s\t%d\n", hex.EncodeToString([]byte(source.Path)), len(source.Content))
		output.WriteString(source.Content)
	}
	output.WriteString("END\n")
	return output.Bytes()
}
