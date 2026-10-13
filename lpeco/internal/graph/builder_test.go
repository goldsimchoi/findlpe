package graph

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"

	"github.com/normalone/lpeco/internal/collect/context"
	"github.com/normalone/lpeco/internal/collect/packageinfo"
	pathcollect "github.com/normalone/lpeco/internal/collect/path"
	"github.com/normalone/lpeco/internal/collect/process"
	"github.com/normalone/lpeco/internal/collect/systemd"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/systemdunit"
)

func TestGraphMaterializesVulnerabilityPackageAndKernelRelationships(t *testing.T) {
	installed := packageinfo.InstalledPackageFact{
		RequestedPackage: "libc6:amd64", Manager: "dpkg", Status: "install ok installed", BinaryPackage: "libc6", Architecture: "amd64",
		BinaryVersion: model.DebianVersion{Raw: "2.35-0ubuntu3.3", Upstream: "2.35", Revision: "0ubuntu3.3", Valid: true},
		SourcePackage: "glibc", SourceVersion: model.DebianVersion{Raw: "2.35-0ubuntu3.3", Upstream: "2.35", Revision: "0ubuntu3.3", Valid: true},
		EvidenceIDs: []string{"e-metadata"}, Confidence: model.ConfidenceHigh,
	}
	ownership := packageinfo.OwnershipFact{
		Path: "/usr/lib/x86_64-linux-gnu/libc.so.6", ResolvedPath: "/usr/lib/x86_64-linux-gnu/libc.so.6", Manager: "dpkg",
		Packages: []string{"libc6:amd64"}, ObservedPackages: []string{"libc6:amd64"}, ResolvedPackages: []string{"libc6:amd64"},
		Owned: true, EvidenceIDs: []string{"e-owner"}, Confidence: model.ConfidenceHigh,
	}
	affected := graphMatchFixture("match-affected", "record-4911", model.VulnerabilityStateAffected, false)
	kernelAffected := graphMatchFixture("match-kernel", "record-4911", model.VulnerabilityStateAffected, true)
	fixed := graphMatchFixture("match-fixed", "record-fixed", model.VulnerabilityStateFixed, false)
	unknown := graphMatchFixture("match-unknown", "record-unknown", model.VulnerabilityStateUnknown, false)
	unknown.MissingFacts = []string{"provider status remains under investigation"}
	unknown.Confidence = model.ConfidenceMedium
	facts := []model.Fact{
		makeFact(t, "identity", "context", "e-identity", model.ConfidenceHigh, context.IdentityFact{UIDs: [4]int{1000, 1000, 1000, 1000}, GIDs: [4]int{1000, 1000, 1000, 1000}}),
		makeFact(t, "process", "process", "e-process", model.ConfidenceHigh, process.ProcessFact{PID: 7, StartTime: 1, Name: "root-consumer", UIDs: [4]int{0, 0, 0, 0}, GIDs: [4]int{0, 0, 0, 0}, EvidenceIDs: []string{"e-process"}, Confidence: model.ConfidenceHigh}),
		makeFact(t, "process_dependency", "process", "e-dependency", model.ConfidenceHigh, process.ProcessDependencyFact{PID: 7, StartTime: 1, MappedFiles: []string{ownership.Path}, EvidenceIDs: []string{"e-dependency"}}),
		makeFact(t, "package_ownership", "packageinfo", "e-owner", model.ConfidenceHigh, ownership),
		makeFact(t, "installed_package", "packageinfo", "e-metadata", model.ConfidenceHigh, installed),
		makeFact(t, "vulnerability_match", "vulnerability", "e-match", model.ConfidenceHigh, affected),
		makeFact(t, "vulnerability_match", "vulnerability", "e-kernel-match", model.ConfidenceHigh, kernelAffected),
		makeFact(t, "vulnerability_match", "vulnerability", "e-fixed", model.ConfidenceHigh, fixed),
		makeFact(t, "vulnerability_match", "vulnerability", "e-unknown", model.ConfidenceMedium, unknown),
	}

	left, diagnostics := Build(facts)
	if hasDiagnosticCode(diagnostics, "build-error") || hasDiagnosticCode(diagnostics, "vulnerability-package-missing") {
		t.Fatalf("unexpected vulnerability graph diagnostics: %#v", diagnostics)
	}
	rightFacts := slices.Clone(facts)
	slices.Reverse(rightFacts)
	right, _ := Build(rightFacts)
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	if string(leftJSON) != string(rightJSON) {
		t.Fatalf("vulnerability graph is not deterministic\nleft=%s\nright=%s", leftJSON, rightJSON)
	}
	if len(left.NodesByKind(model.NodePackage)) != 1 || len(left.NodesByKind(model.NodeVulnerability)) != 1 || len(left.NodesByKind(model.NodeKernel)) != 1 {
		t.Fatalf("materialized nodes: packages=%#v vulnerabilities=%#v kernels=%#v", left.NodesByKind(model.NodePackage), left.NodesByKind(model.NodeVulnerability), left.NodesByKind(model.NodeKernel))
	}
	provided, affectedEdges := edgesByKind(left, model.EdgeProvidedBy), edgesByKind(left, model.EdgeAffectedBy)
	if len(provided) != 2 || len(affectedEdges) != 2 {
		t.Fatalf("provided/affected edges = %d/%d: %#v", len(provided), len(affectedEdges), left.Edges())
	}
	for _, edge := range affectedEdges {
		if StringAttribute(edge.Attributes, "snapshot_digest") != affected.SnapshotDigest ||
			(StringAttribute(edge.Attributes, "match_id") != affected.ID && StringAttribute(edge.Attributes, "match_id") != kernelAffected.ID) {
			t.Fatalf("affected edge lost provenance: %#v", edge)
		}
		if len(edge.EvidenceIDs) == 0 {
			t.Fatalf("affected edge lost target evidence: %#v", edge)
		}
	}
	if len(left.Facts("vulnerability_match")) != 4 {
		t.Fatalf("non-affected match facts were discarded: %#v", left.Facts("vulnerability_match"))
	}
}

func TestGraphDiagnosesAmbiguousOwnershipAndMissingMatchPackage(t *testing.T) {
	ambiguous := packageinfo.OwnershipFact{
		Path: "/usr/lib/libambiguous.so", Manager: "dpkg", Packages: []string{"a:amd64", "b:amd64"}, Owned: true, Ambiguous: true,
		EvidenceIDs: []string{"e-owner"}, MissingFacts: []string{"package ownership is ambiguous"}, Confidence: model.ConfidenceMedium,
	}
	missingPackage := graphMatchFixture("match-missing", "record-missing", model.VulnerabilityStateAffected, false)
	missingPackage.BinaryPackage = "absent"
	missingPackage.SourcePackage = "absent-source"
	facts := []model.Fact{
		makeFact(t, "package_ownership", "packageinfo", "e-owner", model.ConfidenceMedium, ambiguous),
		makeFact(t, "vulnerability_match", "vulnerability", "e-match", model.ConfidenceHigh, missingPackage),
	}
	built, diagnostics := Build(facts)
	if len(edgesByKind(built, model.EdgeProvidedBy)) != 0 || len(edgesByKind(built, model.EdgeAffectedBy)) != 0 {
		t.Fatalf("ambiguous/missing inputs produced relationships: %#v", built.Edges())
	}
	if !hasDiagnosticCode(diagnostics, "package-ownership-ambiguous") || !hasDiagnosticCode(diagnostics, "vulnerability-package-missing") {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func graphMatchFixture(id, record string, state model.VulnerabilityState, kernel bool) model.VulnerabilityMatch {
	missing := []string{}
	confidence := model.ConfidenceHigh
	return model.VulnerabilityMatch{
		ID: id, Provider: "ubuntu", SnapshotDigest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		DistributionID: "ubuntu", Release: "22.04", Codename: "jammy", Channel: "standard", Architecture: "amd64",
		BinaryPackage: "libc6", BinaryArchitecture: "amd64", BinaryVersion: model.DebianVersion{Raw: "2.35-0ubuntu3.3", Valid: true},
		SourcePackage: "glibc", SourceVersion: model.DebianVersion{Raw: "2.35-0ubuntu3.3", Valid: true},
		AdvisoryID: "CVE-2023-4911", RecordID: record, CVEIDs: []string{"CVE-2023-4911"},
		State: state, Reason: "fixture comparison", Kernel: kernel, ImpactAnnotationIDs: []string{"ubuntu-cve-2023-4911-suid-loader-v1"},
		TargetEvidenceIDs: []string{"e-match"}, MissingFacts: missing, Confidence: confidence,
	}
}

func edgesByKind(g *Graph, kind model.EdgeKind) []model.Edge {
	var result []model.Edge
	for _, edge := range g.Edges() {
		if edge.Kind == kind {
			result = append(result, edge)
		}
	}
	return result
}

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
