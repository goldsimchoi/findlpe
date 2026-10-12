package systemd

import (
	"encoding/json"
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
		}
	}
	if !demo.RuntimeObserved || !demo.FilesObserved || demo.Confidence != model.ConfidenceHigh {
		t.Fatalf("reconciled unit = %#v", demo)
	}
	if start.Command.Executable != "/usr/bin/runtime-demo" || start.Source.EvidenceID != "evidence-cat" || start.Confidence != model.ConfidenceHigh {
		t.Fatalf("reconciled ExecStart = %#v", start)
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
