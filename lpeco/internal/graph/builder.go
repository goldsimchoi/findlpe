package graph

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	contextcollect "github.com/normalone/lpeco/internal/collect/context"
	pathcollect "github.com/normalone/lpeco/internal/collect/path"
	processcollect "github.com/normalone/lpeco/internal/collect/process"
	systemdcollect "github.com/normalone/lpeco/internal/collect/systemd"
	"github.com/normalone/lpeco/internal/model"
)

type graphBuilder struct {
	graph            *Graph
	diagnostics      []Diagnostic
	unitByName       map[string][]model.NodeRef
	processByPID     map[int]model.NodeRef
	pathRefs         map[string][]model.NodeRef
	identity         *contextcollect.IdentityFact
	currentPrincipal model.Principal
	stats            map[string][]pathcollect.StatObservation
	acls             map[string]pathcollect.ACLObservation
	mounts           []pathcollect.MountObservation
	unitExecVars     map[string][]string
	unitSimpleExec   map[string]bool
}

// Build converts normalized collector facts into a queryable graph. Malformed
// or incomplete facts are diagnosed and retained instead of aborting the build.
func Build(facts []model.Fact) (*Graph, []Diagnostic) {
	ordered := append([]model.Fact(nil), facts...)
	sort.Slice(ordered, func(i, j int) bool { return factSortKey(ordered[i]) < factSortKey(ordered[j]) })
	b := &graphBuilder{
		graph: New(), unitByName: make(map[string][]model.NodeRef), processByPID: make(map[int]model.NodeRef),
		pathRefs: make(map[string][]model.NodeRef), stats: make(map[string][]pathcollect.StatObservation),
		acls: make(map[string]pathcollect.ACLObservation), unitExecVars: make(map[string][]string),
		unitSimpleExec: make(map[string]bool),
	}
	b.graph.setFacts(ordered)

	// Context and filesystem observations are prerequisites for control edges.
	for _, fact := range ordered {
		b.collectPrerequisite(fact)
	}
	// Materialize stable consumers before relationship facts are processed.
	for _, fact := range ordered {
		switch fact.Kind {
		case "identity":
			b.addIdentity(fact)
		case "process":
			b.addProcess(fact)
		case "systemd_unit":
			b.addSystemdUnit(fact)
		}
	}
	b.addProcessParents(ordered)
	// Exec facts first provide the environment-use context needed by unit facts.
	for _, fact := range ordered {
		if fact.Kind == "systemd_exec" {
			b.addSystemdExec(fact)
		}
	}
	for _, fact := range ordered {
		switch fact.Kind {
		case "process_dependency":
			b.addProcessDependencies(fact)
		case "systemd_unit_source":
			b.addSystemdSource(fact)
		case "systemd_activation":
			b.addSystemdActivation(fact)
		case "systemd_unit":
			b.addSystemdPaths(fact)
		}
	}
	b.addFilesystemRelationships()
	b.sortDiagnostics()
	return b.graph, b.diagnostics
}

func (b *graphBuilder) collectPrerequisite(fact model.Fact) {
	switch fact.Kind {
	case "identity":
		var value contextcollect.IdentityFact
		if b.decode(fact, &value) {
			copy := value
			b.identity = &copy
			b.currentPrincipal = principalFromIdentity(value)
		}
	case "path_stat":
		var value pathcollect.StatObservation
		if b.decode(fact, &value) && value.Path != "" {
			value.EvidenceIDs = mergeStrings(value.EvidenceIDs, fact.EvidenceIDs)
			value.Path = filepath.Clean(value.Path)
			b.stats[value.Path] = append(b.stats[value.Path], value)
		}
	case "path_acl":
		var value pathcollect.ACLObservation
		if b.decode(fact, &value) && value.Path != "" {
			value.EvidenceIDs = mergeStrings(value.EvidenceIDs, fact.EvidenceIDs)
			value.Path = filepath.Clean(value.Path)
			current, exists := b.acls[value.Path]
			if !exists || aclRank(value.Status) > aclRank(current.Status) || (aclRank(value.Status) == aclRank(current.Status) && rawSort(value) < rawSort(current)) {
				b.acls[value.Path] = value
			}
		}
	case "mount":
		var value pathcollect.MountObservation
		if b.decode(fact, &value) && value.MountPoint != "" {
			value.EvidenceIDs = mergeStrings(value.EvidenceIDs, fact.EvidenceIDs)
			b.mounts = append(b.mounts, value)
		}
	}
}

func (b *graphBuilder) addIdentity(fact model.Fact) {
	var value contextcollect.IdentityFact
	if !b.decode(fact, &value) {
		return
	}
	principal := principalFromIdentity(value)
	ref := b.addNode(fact, NodeSpec{
		Key: principalKey(principal.UID), Kind: model.NodePrincipal, Label: fmt.Sprintf("uid:%d", principal.UID),
		SourceCollector: fact.SourceCollector, EvidenceIDs: fact.EvidenceIDs, Confidence: fact.Confidence,
		Attributes: marshalAttributes(principal),
	})
	if ref.ID != "" {
		b.graph.SetCurrentPrincipal(ref)
	}
}

func (b *graphBuilder) addProcess(fact model.Fact) {
	var value processcollect.ProcessFact
	if !b.decode(fact, &value) || value.PID <= 0 {
		return
	}
	confidence := factConfidence(fact, value.Confidence)
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	key := fmt.Sprintf("pid:%d:start:%d", value.PID, value.StartTime)
	label := fmt.Sprintf("%s[%d]", value.Name, value.PID)
	ref := b.addNode(fact, NodeSpec{Key: key, Kind: model.NodeProcess, Label: label, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence, Attributes: marshalAttributes(value)})
	if ref.ID == "" {
		return
	}
	b.processByPID[value.PID] = ref
	principal := model.Principal{UID: effectiveID(value.UIDs), GID: effectiveID(value.GIDs)}
	target := b.ensurePrincipal(fact, principal, evidence, confidence)
	b.addEdge(fact, EdgeSpec{Kind: model.EdgeRunsAs, From: ref, To: target, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence})
	if value.Executable != "" {
		executable := b.ensurePathNode(fact, value.Executable, model.NodeExecutable, evidence, confidence)
		resolved := filepath.IsAbs(value.Executable)
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeExecutes, From: ref, To: executable, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
			Attributes: marshalAttributes(map[string]any{"resolved": resolved, "valid": resolved, "observed": true})})
	}
}

func (b *graphBuilder) addProcessParents(facts []model.Fact) {
	for _, fact := range facts {
		if fact.Kind != "process" {
			continue
		}
		var value processcollect.ProcessFact
		if !b.decode(fact, &value) || value.PPID <= 0 {
			continue
		}
		child, childOK := b.processByPID[value.PID]
		parent, parentOK := b.processByPID[value.PPID]
		if childOK && parentOK {
			b.addEdge(fact, EdgeSpec{Kind: model.EdgeSpawnedBy, From: child, To: parent, SourceCollector: fact.SourceCollector,
				EvidenceIDs: mergeStrings(fact.EvidenceIDs, value.EvidenceIDs), Confidence: factConfidence(fact, value.Confidence)})
		}
	}
}

func (b *graphBuilder) addProcessDependencies(fact model.Fact) {
	var value processcollect.ProcessDependencyFact
	if !b.decode(fact, &value) {
		return
	}
	process, ok := b.processByPID[value.PID]
	if !ok {
		b.diagnose("unresolved-consumer", fmt.Sprintf("process %d was not observed", value.PID), fact)
		return
	}
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	for _, target := range uniqueSorted(value.OpenFiles) {
		ref := b.ensurePathNode(fact, target, model.NodeFile, evidence, fact.Confidence)
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeLoads, From: process, To: ref, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: fact.Confidence,
			Attributes: marshalAttributes(map[string]any{"resolved": filepath.IsAbs(target), "observed": true, "dependency_kind": "open_file"})})
	}
	for _, target := range uniqueSorted(value.MappedFiles) {
		ref := b.ensurePathNode(fact, target, model.NodeLibrary, evidence, fact.Confidence)
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeLoads, From: process, To: ref, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: fact.Confidence,
			Attributes: marshalAttributes(map[string]any{"resolved": filepath.IsAbs(target), "observed": true, "dependency_kind": "mapped_file"})})
	}
}

func (b *graphBuilder) addSystemdUnit(fact model.Fact) {
	var value systemdcollect.UnitFact
	if !b.decode(fact, &value) || value.Name == "" {
		return
	}
	manager := value.Manager
	if manager == "" {
		manager = "system"
	}
	confidence := factConfidence(fact, value.Confidence)
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	key := fmt.Sprintf("%s:%d:%s", manager, value.ManagerUID, value.Name)
	ref := b.addNode(fact, NodeSpec{Key: key, Kind: model.NodeUnit, Label: value.Name, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence, Attributes: marshalAttributes(value)})
	if ref.ID == "" {
		return
	}
	b.unitByName[value.Name] = appendUniqueRefs(b.unitByName[value.Name], ref)
	principal := model.Principal{UID: value.UID, GID: value.GID}
	target := b.ensurePrincipal(fact, principal, evidence, confidence)
	b.addEdge(fact, EdgeSpec{Kind: model.EdgeRunsAs, From: ref, To: target, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
		Attributes: marshalAttributes(map[string]any{"dynamic_user": value.DynamicUser})})
}

func (b *graphBuilder) addSystemdExec(fact model.Fact) {
	var value systemdcollect.ExecFact
	if !b.decode(fact, &value) || value.Command.Executable == "" {
		return
	}
	unit, ok := b.unit(fact, value.UnitName)
	if !ok {
		return
	}
	confidence := factConfidence(fact, value.Confidence)
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	resolved := value.Command.Valid && !containsUnresolved(value.Command.Executable)
	executable := b.ensurePathNode(fact, value.Command.Executable, model.NodeExecutable, evidence, confidence)
	b.addEdge(fact, EdgeSpec{Kind: model.EdgeExecutes, From: unit, To: executable, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
		Attributes: marshalAttributes(map[string]any{"directive": value.Directive, "index": value.Index, "simple": value.Command.SimpleExecutable, "resolved": resolved, "valid": value.Command.Valid})})
	if value.Command.SimpleExecutable {
		b.unitSimpleExec[value.UnitName] = true
	}
	for _, reference := range value.Command.EnvironmentReferences {
		b.unitExecVars[value.UnitName] = append(b.unitExecVars[value.UnitName], reference.Name)
	}
}

func (b *graphBuilder) addSystemdSource(fact model.Fact) {
	var value systemdcollect.UnitSourceFact
	if !b.decode(fact, &value) || value.Path == "" {
		return
	}
	unit, ok := b.unit(fact, value.UnitName)
	if !ok {
		return
	}
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	confidence := factConfidence(fact, value.Confidence)
	source := b.ensurePathNode(fact, value.Path, model.NodeFile, evidence, confidence)
	b.addEdge(fact, EdgeSpec{Kind: model.EdgeReadsConfig, From: unit, To: source, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
		Attributes: marshalAttributes(map[string]any{"applied": value.Applied, "source_kind": value.Kind})})
}

func (b *graphBuilder) addSystemdActivation(fact model.Fact) {
	var value systemdcollect.ActivationFact
	if !b.decode(fact, &value) || value.TriggerUnit == "" || value.TargetUnit == "" {
		return
	}
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	confidence := factConfidence(fact, value.Confidence)
	target, ok := b.unit(fact, value.TargetUnit)
	if !ok {
		// A trigger may legitimately target a unit omitted from a partial
		// inventory. Preserve the relationship but lower confidence.
		target = b.addNode(fact, NodeSpec{Key: "system:0:" + value.TargetUnit, Kind: model.NodeUnit, Label: value.TargetUnit,
			SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: model.ConfidenceLow,
			Attributes: marshalAttributes(map[string]any{"name": value.TargetUnit, "inventory_missing": true})})
		b.unitByName[value.TargetUnit] = appendUniqueRefs(b.unitByName[value.TargetUnit], target)
	}
	trigger := b.addNode(fact, NodeSpec{Key: value.Kind + ":" + value.TriggerUnit, Kind: model.NodeTrigger, Label: value.TriggerUnit,
		SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
		Attributes: marshalAttributes(map[string]any{"kind": value.Kind, "schedule": value.Schedule})})
	b.addEdge(fact, EdgeSpec{Kind: model.EdgeActivates, From: trigger, To: target, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
		Attributes: marshalAttributes(map[string]any{"active": value.Active, "automatic": value.Automatic})})
}

func (b *graphBuilder) addSystemdPaths(fact model.Fact) {
	var value systemdcollect.UnitFact
	if !b.decode(fact, &value) || value.Name == "" {
		return
	}
	unit, ok := b.unit(fact, value.Name)
	if !ok {
		return
	}
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	confidence := factConfidence(fact, value.Confidence)
	variables := uniqueSorted(b.unitExecVars[value.Name])
	if b.unitSimpleExec[value.Name] {
		variables = mergeStrings(variables, []string{"PATH"})
	}
	for _, target := range uniqueSorted(value.EnvironmentFiles) {
		target = strings.TrimPrefix(target, "-")
		file := b.ensurePathNode(fact, target, model.NodeFile, evidence, confidence)
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeReadsEnvironment, From: unit, To: file, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
			Attributes: marshalAttributes(map[string]any{"used": len(variables) > 0, "variables": variables})})
	}
	for index, target := range value.ExecSearchPath {
		directory := b.ensurePathNode(fact, target, model.NodeDirectory, evidence, confidence)
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeResolvesThrough, From: unit, To: directory, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
			Attributes: marshalAttributes(map[string]any{"search_path": true, "index": index, "resolved": filepath.IsAbs(target) && !containsUnresolved(target)})})
	}
}

func (b *graphBuilder) addFilesystemRelationships() {
	sort.Slice(b.mounts, func(i, j int) bool {
		if b.mounts[i].MountPoint != b.mounts[j].MountPoint {
			return b.mounts[i].MountPoint < b.mounts[j].MountPoint
		}
		return b.mounts[i].ID < b.mounts[j].ID
	})
	mountRefs := make(map[int]model.NodeRef)
	for _, mount := range b.mounts {
		fact := model.Fact{Kind: "mount", SourceCollector: "path", EvidenceIDs: mount.EvidenceIDs, Confidence: model.ConfidenceHigh}
		mountRefs[mount.ID] = b.addNode(fact, NodeSpec{Key: fmt.Sprintf("%d:%s", mount.ID, mount.MountPoint), Kind: model.NodeMount, Label: mount.MountPoint,
			SourceCollector: "path", EvidenceIDs: mount.EvidenceIDs, Confidence: model.ConfidenceHigh, Attributes: marshalAttributes(mount)})
	}
	paths := make([]string, 0, len(b.pathRefs))
	for target := range b.pathRefs {
		paths = append(paths, target)
	}
	sort.Strings(paths)
	observations := pathcollect.ObservationSet{Stats: b.stats, ACLs: b.acls, Mounts: b.mounts}
	current, hasCurrent := b.graph.CurrentPrincipal()
	for _, target := range paths {
		refs := b.pathRefs[target]
		if mount, ok := pathcollect.MountForPath(target, b.mounts); ok {
			mountRef := mountRefs[mount.ID]
			for _, ref := range refs {
				fact := model.Fact{Kind: "mount", SourceCollector: "path", EvidenceIDs: mount.EvidenceIDs, Confidence: model.ConfidenceHigh}
				b.addEdge(fact, EdgeSpec{Kind: model.EdgeLocatedOn, From: ref, To: mountRef, SourceCollector: "path", EvidenceIDs: mount.EvidenceIDs, Confidence: model.ConfidenceHigh})
			}
		}
		if !hasCurrent || !filepath.IsAbs(target) {
			continue
		}
		resolution := pathcollect.Resolve(target, observations)
		assessment := pathcollect.EvaluateControl(b.currentPrincipal, resolution, pathcollect.UseWrite)
		if assessment.State != pathcollect.ControlAllowed || !assessment.Controlled {
			continue
		}
		for _, ref := range refs {
			fact := model.Fact{Kind: "path_control", SourceCollector: "path", EvidenceIDs: assessment.EvidenceIDs, Confidence: assessment.Confidence}
			b.addEdge(fact, EdgeSpec{Kind: model.EdgeCanWrite, From: current, To: ref, SourceCollector: "path", EvidenceIDs: assessment.EvidenceIDs,
				Confidence: assessment.Confidence, Attributes: marshalAttributes(assessment)})
		}
	}
}

func (b *graphBuilder) ensurePrincipal(fact model.Fact, principal model.Principal, evidence []string, confidence model.Confidence) model.NodeRef {
	return b.addNode(fact, NodeSpec{Key: principalKey(principal.UID), Kind: model.NodePrincipal, Label: fmt.Sprintf("uid:%d", principal.UID),
		SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence, Attributes: marshalAttributes(principal)})
}

func (b *graphBuilder) ensurePathNode(fact model.Fact, target string, kind model.NodeKind, evidence []string, confidence model.Confidence) model.NodeRef {
	key := target
	if filepath.IsAbs(target) {
		key = filepath.Clean(target)
	}
	ref := b.addNode(fact, NodeSpec{Key: key, Kind: kind, Label: target, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence,
		Confidence: confidence, Attributes: marshalAttributes(map[string]any{"path": target})})
	if filepath.IsAbs(target) && ref.ID != "" {
		b.pathRefs[filepath.Clean(target)] = appendUniqueRefs(b.pathRefs[filepath.Clean(target)], ref)
	}
	return ref
}

func (b *graphBuilder) unit(fact model.Fact, name string) (model.NodeRef, bool) {
	refs := append([]model.NodeRef(nil), b.unitByName[name]...)
	if len(refs) == 0 {
		b.diagnose("unresolved-consumer", "systemd unit was not observed: "+name, fact)
		return model.NodeRef{}, false
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
	if len(refs) > 1 {
		b.diagnose("ambiguous-unit", "multiple manager instances match "+name, fact)
	}
	return refs[0], true
}

func (b *graphBuilder) addNode(fact model.Fact, spec NodeSpec) model.NodeRef {
	ref, conflict, err := b.graph.AddNode(spec)
	if err != nil {
		b.diagnose("build-error", err.Error(), fact)
		return model.NodeRef{}
	}
	if conflict {
		b.diagnose("node-conflict", "conflicting observations retained for "+spec.Label, fact)
	}
	return ref
}

func (b *graphBuilder) addEdge(fact model.Fact, spec EdgeSpec) {
	if err := b.graph.AddEdge(spec); err != nil {
		code := "build-error"
		if strings.Contains(err.Error(), "evidence") {
			code = "edge-without-evidence"
		}
		b.diagnose(code, err.Error(), fact)
	}
}

func (b *graphBuilder) decode(fact model.Fact, target any) bool {
	if err := json.Unmarshal(fact.Data, target); err != nil {
		b.diagnose("build-error", fmt.Sprintf("decode %s fact: %v", fact.Kind, err), fact)
		return false
	}
	return true
}

func (b *graphBuilder) diagnose(code, message string, fact model.Fact) {
	b.diagnostics = append(b.diagnostics, Diagnostic{Code: code, Message: message, FactID: fact.ID, EvidenceIDs: uniqueSorted(fact.EvidenceIDs)})
}

func (b *graphBuilder) sortDiagnostics() {
	sort.Slice(b.diagnostics, func(i, j int) bool {
		left := b.diagnostics[i].Code + "\x00" + b.diagnostics[i].FactID + "\x00" + b.diagnostics[i].Message
		right := b.diagnostics[j].Code + "\x00" + b.diagnostics[j].FactID + "\x00" + b.diagnostics[j].Message
		return left < right
	})
}

func principalFromIdentity(value contextcollect.IdentityFact) model.Principal {
	return model.Principal{UID: effectiveID(value.UIDs), GID: effectiveID(value.GIDs), SupplementaryGIDs: append([]int(nil), value.Groups...), Capabilities: capabilityNames(value.Capabilities["effective"])}
}

func effectiveID(values [4]int) int { return values[1] }

func principalKey(uid int) string { return fmt.Sprintf("uid:%d", uid) }

func factConfidence(fact model.Fact, embedded model.Confidence) model.Confidence {
	if embedded == "" {
		return normalizeConfidence(fact.Confidence)
	}
	return weakerConfidence(fact.Confidence, embedded)
}

func containsUnresolved(value string) bool {
	return strings.ContainsAny(value, "%$")
}

func appendUniqueRefs(values []model.NodeRef, additions ...model.NodeRef) []model.NodeRef {
	for _, addition := range additions {
		if addition.ID == "" {
			continue
		}
		found := false
		for _, value := range values {
			if value.ID == addition.ID {
				found = true
				break
			}
		}
		if !found {
			values = append(values, addition)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values
}

func aclRank(value pathcollect.ObservationStatus) int {
	switch value {
	case pathcollect.ObservationComplete:
		return 3
	case pathcollect.ObservationPartial:
		return 2
	default:
		return 1
	}
}

func rawSort(value any) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func capabilityNames(bits uint64) []string {
	names := []string{
		"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID",
		"CAP_SETPCAP", "CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
		"CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
		"CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
		"CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
	}
	result := make([]string, 0)
	for index, name := range names {
		if bits&(uint64(1)<<index) != 0 {
			result = append(result, name)
		}
	}
	return result
}
