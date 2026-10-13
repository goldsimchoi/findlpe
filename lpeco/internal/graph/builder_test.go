package graph

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/normalone/lpeco/internal/collect/context"
	pathcollect "github.com/normalone/lpeco/internal/collect/path"
	"github.com/normalone/lpeco/internal/collect/process"
	"github.com/normalone/lpeco/internal/collect/systemd"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/systemdunit"
)

func TestGraphDoesNotGrantPathControlFromIncompleteMountInventory(t *testing.T) {
	facts := []model.Fact{
		makeFact(t, "identity", "context", "e-identity", model.ConfidenceHigh, context.IdentityFact{UIDs: [4]int{1000, 1000, 1000, 1000}, GIDs: [4]int{1000, 1000, 1000, 1000}}),
		makeFact(t, "process", "process", "e-process", model.ConfidenceHigh, process.ProcessFact{PID: 42, StartTime: 100, Name: "demo", Executable: "/srv/app/tool", UIDs: [4]int{1000, 1000, 1000, 1000}, GIDs: [4]int{1000, 1000, 1000, 1000}, EvidenceIDs: []string{"e-process"}, Confidence: model.ConfidenceHigh}),
	}
	for index, observation := range []pathcollect.StatObservation{
		{Path: "/", Device: 1, Inode: 1, Mode: 0o755, UID: 0, GID: 0, Kind: pathcollect.FileDirectory, Status: pathcollect.ObservationComplete, EvidenceIDs: []string{"e-stat"}},
		{Path: "/srv", Device: 1, Inode: 2, Mode: 0o755, UID: 0, GID: 0, Kind: pathcollect.FileDirectory, Status: pathcollect.ObservationComplete, EvidenceIDs: []string{"e-stat"}},
		{Path: "/srv/app", Device: 1, Inode: 3, Mode: 0o777, UID: 1000, GID: 1000, Kind: pathcollect.FileDirectory, Status: pathcollect.ObservationComplete, EvidenceIDs: []string{"e-stat"}},
		{Path: "/srv/app/tool", Device: 1, Inode: 4, Mode: 0o777, UID: 1000, GID: 1000, Kind: pathcollect.FileRegular, Status: pathcollect.ObservationComplete, EvidenceIDs: []string{"e-stat"}},
	} {
		facts = append(facts, makeFact(t, "path_stat", "path", "e-stat-"+string(rune('a'+index)), model.ConfidenceHigh, observation))
		facts = append(facts, makeFact(t, "path_acl", "path", "e-acl-"+string(rune('a'+index)), model.ConfidenceHigh, pathcollect.ACLObservation{Path: observation.Path, Status: pathcollect.ObservationComplete, EvidenceIDs: []string{"e-acl"}}))
	}
	mountFact := makeFact(t, "mount", "path", "e-mount", model.ConfidenceMedium, pathcollect.MountObservation{ID: 36, ParentID: 25, MountPoint: "/", EvidenceIDs: []string{"e-mount"}})
	mountFact.ObservationStatus = model.ProbePartial
	mountFact.MissingFacts = []string{"malformed child mount record"}
	facts = append(facts, mountFact)

	built, _ := Build(facts)
	current, ok := built.CurrentPrincipal()
	if !ok {
		t.Fatal("current principal missing")
	}
	if edges := built.Outgoing(current, model.EdgeCanWrite); len(edges) != 0 {
		t.Fatalf("incomplete mount inventory produced CAN_WRITE: %#v", edges)
	}
	mounts := built.NodesByKind(model.NodeMount)
	if len(mounts) != 1 || mounts[0].Confidence != model.ConfidenceMedium {
		t.Fatalf("mount fact confidence was not preserved: %#v", mounts)
	}
}

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

func TestGraphDoesNotGuessSystemdMainPIDAcrossPIDReuse(t *testing.T) {
	facts := []model.Fact{
		makeFact(t, "process", "process", "e-old", model.ConfidenceHigh, process.ProcessFact{PID: 42, StartTime: 100, Name: "old", UIDs: [4]int{0, 0, 0, 0}, GIDs: [4]int{0, 0, 0, 0}, EvidenceIDs: []string{"e-old"}, Confidence: model.ConfidenceHigh}),
		makeFact(t, "process", "process", "e-new", model.ConfidenceHigh, process.ProcessFact{PID: 42, StartTime: 200, Name: "new", UIDs: [4]int{0, 0, 0, 0}, GIDs: [4]int{0, 0, 0, 0}, EvidenceIDs: []string{"e-new"}, Confidence: model.ConfidenceHigh}),
		makeFact(t, "systemd_unit", "systemd", "e-unit", model.ConfidenceHigh, systemd.UnitFact{Name: "demo.service", Manager: "system", UID: 0, GID: 0, User: "root", MainPID: 42, EvidenceIDs: []string{"e-unit"}, Confidence: model.ConfidenceHigh}),
	}
	built, diagnostics := Build(facts)
	for _, processNode := range built.NodesByKind(model.NodeProcess) {
		if edges := built.Outgoing(processNode.NodeRef, model.EdgeManagedBy); len(edges) != 0 {
			t.Fatalf("ambiguous PID was linked to unit: %#v", edges)
		}
	}
	if !hasDiagnosticCode(diagnostics, "ambiguous-process") {
		t.Fatalf("PID reuse diagnostic missing: %#v", diagnostics)
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

func TestGraphScopesSameNamedSystemAndUserUnitsWithoutCrossAttachment(t *testing.T) {
	facts := []model.Fact{
		makeFact(t, "identity", "context", "e-identity", model.ConfidenceHigh, context.IdentityFact{UIDs: [4]int{1000, 1000, 1000, 1000}, GIDs: [4]int{1000, 1000, 1000, 1000}}),
		makeFact(t, "systemd_unit", "systemd", "e-system", model.ConfidenceHigh, systemd.UnitFact{Name: "demo.service", Manager: "system", ManagerUID: 0, UID: 0, User: "root", EvidenceIDs: []string{"e-system"}, Confidence: model.ConfidenceHigh}),
		makeFact(t, "systemd_unit", "systemd", "e-user", model.ConfidenceHigh, systemd.UnitFact{Name: "demo.service", Manager: "user", ManagerUID: 1000, UID: 1000, User: "user", InventoryOnly: true, EvidenceIDs: []string{"e-user"}, Confidence: model.ConfidenceHigh}),
		makeFact(t, "systemd_exec", "systemd", "e-system-exec", model.ConfidenceHigh, systemd.ExecFact{UnitName: "demo.service", Manager: "system", ManagerUID: 0, Directive: "ExecStart", Command: systemdunit.ExecCommand{Executable: "/opt/system", Valid: true}, EvidenceIDs: []string{"e-system-exec"}, Confidence: model.ConfidenceHigh}),
		makeFact(t, "systemd_exec", "systemd", "e-user-exec", model.ConfidenceHigh, systemd.ExecFact{UnitName: "demo.service", Manager: "user", ManagerUID: 1000, Directive: "ExecStart", Command: systemdunit.ExecCommand{Executable: "/opt/user", Valid: true}, EvidenceIDs: []string{"e-user-exec"}, Confidence: model.ConfidenceHigh}),
	}
	built, diagnostics := Build(facts)
	if hasDiagnosticCode(diagnostics, "ambiguous-unit") {
		t.Fatalf("scoped facts were treated as ambiguous: %#v", diagnostics)
	}
	for _, unit := range built.NodesByKind(model.NodeUnit) {
		manager := StringAttribute(unit.Attributes, "manager")
		execs := built.Outgoing(unit.NodeRef, model.EdgeExecutes)
		if len(execs) != 1 {
			t.Fatalf("unit %s exec edges = %#v", manager, execs)
		}
		target, _ := built.Node(execs[0].To)
		if manager == "system" && target.Label != "/opt/system" || manager == "user" && target.Label != "/opt/user" {
			t.Fatalf("cross-attached %s unit to %s", manager, target.Label)
		}
	}
}

func TestGraphRejectsTargetedFactsForReusedPID(t *testing.T) {
	facts := []model.Fact{
		makeFact(t, "process", "process", "e-process", model.ConfidenceHigh, process.ProcessFact{PID: 42, StartTime: 200, Name: "new", UIDs: [4]int{0, 0, 0, 0}, EvidenceIDs: []string{"e-process"}, Confidence: model.ConfidenceHigh}),
		makeFact(t, "process_dependency", "process", "e-deps", model.ConfidenceHigh, process.ProcessDependencyFact{PID: 42, StartTime: 100, OpenFiles: []string{"/tmp/stale"}, EvidenceIDs: []string{"e-deps"}}),
	}
	built, diagnostics := Build(facts)
	processes := built.NodesByKind(model.NodeProcess)
	if len(processes) != 1 || len(built.Outgoing(processes[0].NodeRef, model.EdgeLoads)) != 0 {
		t.Fatalf("stale dependency attached: %#v", built.Edges())
	}
	if !hasDiagnosticCode(diagnostics, "stale-process-identity") {
		t.Fatalf("stale identity diagnostic missing: %#v", diagnostics)
	}
}

func TestGraphMergesRepeatedSameIdentityProcessEvidence(t *testing.T) {
	first := process.ProcessFact{PID: 42, StartTime: 200, Name: "demo", UIDs: [4]int{0, 0, 0, 0}, EvidenceIDs: []string{"e-first"}, Confidence: model.ConfidenceHigh}
	second := first
	second.Executable = "/opt/demo"
	second.Cgroups = []process.CgroupFact{{Path: "/system.slice/demo.service"}}
	second.EvidenceIDs = []string{"e-second"}
	built, _ := Build([]model.Fact{
		makeFact(t, "process", "process", "e-first", model.ConfidenceHigh, first),
		makeFact(t, "process", "process", "e-second", model.ConfidenceHigh, second),
	})
	processes := built.NodesByKind(model.NodeProcess)
	if len(processes) != 1 || !reflect.DeepEqual(processes[0].EvidenceIDs, []string{"e-first", "e-second"}) {
		t.Fatalf("merged process = %#v", processes)
	}
}

func TestGraphRequiresCompatibleCgroupForSystemdMainPID(t *testing.T) {
	facts := []model.Fact{
		makeFact(t, "process", "process", "e-process", model.ConfidenceHigh, process.ProcessFact{PID: 42, StartTime: 200, Name: "other", UIDs: [4]int{0, 0, 0, 0}, Cgroups: []process.CgroupFact{{Path: "/user.slice/user-1000.slice/session.scope"}}, EvidenceIDs: []string{"e-process"}, Confidence: model.ConfidenceHigh}),
		makeFact(t, "systemd_unit", "systemd", "e-unit", model.ConfidenceHigh, systemd.UnitFact{Name: "demo.service", Manager: "system", MainPID: 42, ControlGroup: "/system.slice/demo.service", UID: 0, EvidenceIDs: []string{"e-unit"}, Confidence: model.ConfidenceHigh}),
	}
	built, diagnostics := Build(facts)
	if len(built.Outgoing(built.NodesByKind(model.NodeProcess)[0].NodeRef, model.EdgeManagedBy)) != 0 {
		t.Fatalf("incompatible cgroup produced MANAGED_BY: %#v", built.Edges())
	}
	if !hasDiagnosticCode(diagnostics, "cgroup-mismatch") {
		t.Fatalf("cgroup mismatch diagnostic missing: %#v", diagnostics)
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
