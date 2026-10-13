package graph

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	binarycollect "github.com/normalone/lpeco/internal/collect/binary"
	containercollect "github.com/normalone/lpeco/internal/collect/container"
	contextcollect "github.com/normalone/lpeco/internal/collect/context"
	pathcollect "github.com/normalone/lpeco/internal/collect/path"
	processcollect "github.com/normalone/lpeco/internal/collect/process"
	schedulercollect "github.com/normalone/lpeco/internal/collect/scheduler"
	systemdcollect "github.com/normalone/lpeco/internal/collect/systemd"
	"github.com/normalone/lpeco/internal/model"
)

type graphBuilder struct {
	graph            *Graph
	diagnostics      []Diagnostic
	unitByName       map[string][]model.NodeRef
	unitByKey        map[string]model.NodeRef
	processByPID     map[int][]model.NodeRef
	processByKey     map[string]model.NodeRef
	pathRefs         map[string][]model.NodeRef
	identity         *contextcollect.IdentityFact
	currentPrincipal model.Principal
	stats            map[string][]pathcollect.StatObservation
	acls             map[string]pathcollect.ACLObservation
	mounts           []mountPrerequisite
	unitExecVars     map[string][]string
	unitSimpleExec   map[string]bool
}

type mountPrerequisite struct {
	observation pathcollect.MountObservation
	fact        model.Fact
}

// Build converts normalized collector facts into a queryable graph. Malformed
// or incomplete facts are diagnosed and retained instead of aborting the build.
func Build(facts []model.Fact) (*Graph, []Diagnostic) {
	original := append([]model.Fact(nil), facts...)
	sort.Slice(original, func(i, j int) bool { return factSortKey(original[i]) < factSortKey(original[j]) })
	ordered, systemdDiagnostics := systemdcollect.ReconcileFacts(original)
	ordered = reconcileProcessFacts(ordered)
	b := &graphBuilder{
		graph: New(), unitByName: make(map[string][]model.NodeRef), unitByKey: make(map[string]model.NodeRef), processByPID: make(map[int][]model.NodeRef), processByKey: make(map[string]model.NodeRef),
		pathRefs: make(map[string][]model.NodeRef), stats: make(map[string][]pathcollect.StatObservation),
		acls: make(map[string]pathcollect.ACLObservation), unitExecVars: make(map[string][]string),
		unitSimpleExec: make(map[string]bool),
	}
	b.graph.setFacts(original)
	for _, diagnostic := range systemdDiagnostics {
		b.diagnostics = append(b.diagnostics, Diagnostic{Code: diagnostic.Code, Message: diagnostic.Message, EvidenceIDs: uniqueSorted(diagnostic.EvidenceIDs)})
	}

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
	b.addSystemdProcessManagement(ordered)
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
		case "schedule":
			b.addSchedule(fact)
		case "privileged_binary":
			b.addPrivilegedBinary(fact)
		case "binary_dependency":
			b.addBinaryDependency(fact)
		case "delegation":
			b.addDelegation(fact)
		case "admin_socket":
			b.addAdminSocket(fact)
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
			b.mounts = append(b.mounts, mountPrerequisite{observation: value, fact: fact})
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
	b.processByPID[value.PID] = appendUniqueRefs(b.processByPID[value.PID], ref)
	b.processByKey[processIdentityKey(value.PID, value.StartTime)] = ref
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
		child, childOK := b.uniqueProcess(value.PID)
		parent, parentOK := b.uniqueProcess(value.PPID)
		if childOK && parentOK {
			b.addEdge(fact, EdgeSpec{Kind: model.EdgeSpawnedBy, From: child, To: parent, SourceCollector: fact.SourceCollector,
				EvidenceIDs: mergeStrings(fact.EvidenceIDs, value.EvidenceIDs), Confidence: factConfidence(fact, value.Confidence)})
		}
	}
}

func (b *graphBuilder) addSystemdProcessManagement(facts []model.Fact) {
	for _, fact := range facts {
		if fact.Kind != "systemd_unit" {
			continue
		}
		var value systemdcollect.UnitFact
		if !b.decode(fact, &value) || value.Name == "" || value.MainPID <= 0 {
			continue
		}
		process, processOK := b.uniqueProcess(value.MainPID)
		unit, unitOK := b.unitByKey[systemdUnitKey(value)]
		if len(b.processByPID[value.MainPID]) > 1 {
			b.diagnose("ambiguous-process", fmt.Sprintf("PID %d refers to multiple observed process instances", value.MainPID), fact)
			continue
		}
		if !processOK || !unitOK {
			// A process may exit between the systemd and /proc snapshots. Preserve
			// the observed unit without guessing which process replaced it.
			continue
		}
		processNode, _ := b.graph.Node(process)
		var processValue processcollect.ProcessFact
		_ = json.Unmarshal(processNode.Attributes, &processValue)
		if value.ControlGroup != "" && len(processValue.Cgroups) > 0 && !compatibleControlGroup(value.ControlGroup, processValue.Cgroups) {
			b.diagnose("cgroup-mismatch", fmt.Sprintf("PID %d cgroup does not match unit %s", value.MainPID, value.Name), fact)
			continue
		}
		evidence := mergeStrings(mergeStrings(fact.EvidenceIDs, value.EvidenceIDs), processNode.EvidenceIDs)
		confidence := weakerConfidence(factConfidence(fact, value.Confidence), processNode.Confidence)
		b.addEdge(fact, EdgeSpec{
			Kind: model.EdgeManagedBy, From: process, To: unit,
			SourceCollector: mergeSources(fact.SourceCollector, processNode.SourceCollector),
			EvidenceIDs:     evidence, Confidence: confidence,
			Attributes: marshalAttributes(map[string]any{"main_pid": value.MainPID, "manager": systemdManager(value)}),
		})
	}
}

func (b *graphBuilder) addProcessDependencies(fact model.Fact) {
	var value processcollect.ProcessDependencyFact
	if !b.decode(fact, &value) {
		return
	}
	var process model.NodeRef
	var ok bool
	if value.StartTime > 0 {
		process, ok = b.processByKey[processIdentityKey(value.PID, value.StartTime)]
		if !ok && len(b.processByPID[value.PID]) > 0 {
			b.diagnose("stale-process-identity", fmt.Sprintf("process %d start time %d no longer matches", value.PID, value.StartTime), fact)
			return
		}
	} else {
		process, ok = b.uniqueProcess(value.PID)
	}
	if !ok {
		if len(b.processByPID[value.PID]) > 1 {
			b.diagnose("ambiguous-process", fmt.Sprintf("PID %d refers to multiple observed process instances", value.PID), fact)
		} else {
			b.diagnose("unresolved-consumer", fmt.Sprintf("process %d was not observed", value.PID), fact)
		}
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
	confidence := factConfidence(fact, value.Confidence)
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	key := systemdUnitKey(value)
	ref := b.addNode(fact, NodeSpec{Key: key, Kind: model.NodeUnit, Label: value.Name, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence, Attributes: marshalAttributes(value)})
	if ref.ID == "" {
		return
	}
	b.unitByName[value.Name] = appendUniqueRefs(b.unitByName[value.Name], ref)
	b.unitByKey[key] = ref
	var target model.NodeRef
	if value.User != "" && value.User != "root" && value.UID == 0 {
		target = b.namedPrincipal(fact, value.User, evidence, model.ConfidenceLow)
	} else {
		principal := model.Principal{UID: value.UID, GID: value.GID}
		target = b.ensurePrincipal(fact, principal, evidence, confidence)
	}
	b.addEdge(fact, EdgeSpec{Kind: model.EdgeRunsAs, From: ref, To: target, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
		Attributes: marshalAttributes(map[string]any{"dynamic_user": value.DynamicUser})})
}

func (b *graphBuilder) addSystemdExec(fact model.Fact) {
	var value systemdcollect.ExecFact
	if !b.decode(fact, &value) || value.Command.Executable == "" {
		return
	}
	unit, ok := b.unit(fact, value.Manager, value.ManagerUID, value.UnitName)
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
		b.unitSimpleExec[systemdFactKey(value.Manager, value.ManagerUID, value.UnitName)] = true
	}
	for _, reference := range value.Command.EnvironmentReferences {
		key := systemdFactKey(value.Manager, value.ManagerUID, value.UnitName)
		b.unitExecVars[key] = append(b.unitExecVars[key], reference.Name)
	}
}

func (b *graphBuilder) addSystemdSource(fact model.Fact) {
	var value systemdcollect.UnitSourceFact
	if !b.decode(fact, &value) || value.Path == "" {
		return
	}
	unit, ok := b.unit(fact, value.Manager, value.ManagerUID, value.UnitName)
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
	target, ok := b.unit(fact, value.Manager, value.ManagerUID, value.TargetUnit)
	if !ok {
		// A trigger may legitimately target a unit omitted from a partial
		// inventory. Preserve the relationship but lower confidence.
		target = b.addNode(fact, NodeSpec{Key: systemdFactKey(value.Manager, value.ManagerUID, value.TargetUnit), Kind: model.NodeUnit, Label: value.TargetUnit,
			SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: model.ConfidenceLow,
			Attributes: marshalAttributes(map[string]any{"name": value.TargetUnit, "manager": systemdFactManager(value.Manager), "manager_uid": value.ManagerUID, "inventory_missing": true})})
		b.unitByName[value.TargetUnit] = appendUniqueRefs(b.unitByName[value.TargetUnit], target)
		b.unitByKey[systemdFactKey(value.Manager, value.ManagerUID, value.TargetUnit)] = target
	}
	trigger := b.addNode(fact, NodeSpec{Key: systemdFactKey(value.Manager, value.ManagerUID, value.Kind+":"+value.TriggerUnit), Kind: model.NodeTrigger, Label: value.TriggerUnit,
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
	unit, ok := b.unit(fact, value.Manager, value.ManagerUID, value.Name)
	if !ok {
		return
	}
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	confidence := factConfidence(fact, value.Confidence)
	key := systemdFactKey(value.Manager, value.ManagerUID, value.Name)
	variables := uniqueSorted(b.unitExecVars[key])
	if b.unitSimpleExec[key] {
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

func (b *graphBuilder) addSchedule(fact model.Fact) {
	var value schedulercollect.ScheduleFact
	if !b.decode(fact, &value) || value.SourcePath == "" {
		return
	}
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	confidence := factConfidence(fact, value.Confidence)
	trigger := b.addNode(fact, NodeSpec{
		Key:  value.Kind + ":" + value.SourcePath + ":" + value.Schedule + ":" + value.Command,
		Kind: model.NodeTrigger, Label: value.SourcePath, SourceCollector: fact.SourceCollector,
		EvidenceIDs: evidence, Confidence: confidence,
		Attributes: marshalAttributes(map[string]any{"scheduler": true, "active": value.Active, "kind": value.Kind, "schedule": value.Schedule, "command": value.Command, "trigger_path": value.TriggerPath}),
	})
	target := b.namedPrincipal(fact, value.User, evidence, confidence)
	if target.ID != "" {
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeRunsAs, From: trigger, To: target, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence})
	}
	if value.Script != "" {
		script := b.ensurePathNode(fact, value.Script, model.NodeScript, evidence, confidence)
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeInterprets, From: trigger, To: script, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
			Attributes: marshalAttributes(map[string]any{"resolved": filepath.IsAbs(value.Script), "valid": filepath.IsAbs(value.Script), "chain": "script"})})
	}
	if value.Interpreter != "" {
		interpreter := b.ensurePathNode(fact, value.Interpreter, model.NodeExecutable, evidence, confidence)
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeExecutes, From: trigger, To: interpreter, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
			Attributes: marshalAttributes(map[string]any{"resolved": filepath.IsAbs(value.Interpreter), "valid": filepath.IsAbs(value.Interpreter), "chain": "interpreter"})})
	} else if command := firstCommand(value.Command); command != "" {
		executable := b.ensurePathNode(fact, command, model.NodeExecutable, evidence, confidence)
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeExecutes, From: trigger, To: executable, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
			Attributes: marshalAttributes(map[string]any{"resolved": filepath.IsAbs(command), "valid": filepath.IsAbs(command), "chain": "command"})})
	}
}

func (b *graphBuilder) addPrivilegedBinary(fact model.Fact) {
	var value binarycollect.PrivilegedBinaryFact
	if !b.decode(fact, &value) || value.Path == "" {
		return
	}
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	confidence := factConfidence(fact, value.Confidence)
	attributes := map[string]any{
		"path": value.Path, "mode": value.Mode, "owner_uid": value.UID, "owner_gid": value.GID,
		"suid": value.SUID, "sgid": value.SGID, "capabilities": value.Capabilities,
		"capability_boundary":        len(value.Capabilities) > 0,
		"bit_preservation_confirmed": false,
	}
	binary := b.addNode(fact, NodeSpec{Key: filepath.Clean(value.Path), Kind: model.NodeExecutable, Label: value.Path,
		SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence, Attributes: marshalAttributes(attributes)})
	b.registerPath(value.Path, binary)
	var target model.NodeRef
	switch {
	case value.SUID:
		target = b.ensurePrincipal(fact, model.Principal{UID: value.UID, GID: value.GID}, evidence, confidence)
	case value.SGID && b.identity != nil:
		principal := model.Principal{UID: b.currentPrincipal.UID, GID: value.GID}
		target = b.addNode(fact, NodeSpec{Key: fmt.Sprintf("uid:%d:gid:%d", principal.UID, principal.GID), Kind: model.NodePrincipal,
			Label: fmt.Sprintf("uid:%d gid:%d", principal.UID, principal.GID), SourceCollector: fact.SourceCollector,
			EvidenceIDs: evidence, Confidence: confidence, Attributes: marshalAttributes(principal)})
	case len(value.Capabilities) > 0:
		uid := -1
		gid := -1
		if b.identity != nil {
			uid, gid = b.currentPrincipal.UID, b.currentPrincipal.GID
		}
		target = b.addNode(fact, NodeSpec{Key: "capability:" + filepath.Clean(value.Path), Kind: model.NodePrincipal,
			Label: "file capabilities of " + value.Path, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
			Attributes: marshalAttributes(map[string]any{"uid": uid, "gid": gid, "capabilities": value.Capabilities, "capability_boundary": true})})
	}
	if target.ID != "" {
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeRunsAs, From: binary, To: target, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence})
	}
}

func (b *graphBuilder) addBinaryDependency(fact model.Fact) {
	var value binarycollect.DependencyFact
	if !b.decode(fact, &value) || value.ConsumerPath == "" || value.Target == "" {
		return
	}
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	confidence := factConfidence(fact, value.Confidence)
	consumer := b.ensurePathNode(fact, value.ConsumerPath, model.NodeExecutable, evidence, confidence)
	switch value.Kind {
	case "rpath", "runpath":
		target := b.ensurePathNode(fact, value.Target, model.NodeDirectory, evidence, confidence)
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeResolvesThrough, From: consumer, To: target, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
			Attributes: marshalAttributes(map[string]any{"loader_path": true, "dependency_kind": value.Kind, "resolved": value.Resolved})})
	case "interpreter", "script":
		target := b.ensurePathNode(fact, value.Target, model.NodeExecutable, evidence, confidence)
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeInterprets, From: consumer, To: target, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
			Attributes: marshalAttributes(map[string]any{"dependency_kind": value.Kind, "resolved": value.Resolved, "observed": true})})
	default:
		target := b.ensurePathNode(fact, value.Target, model.NodeLibrary, evidence, confidence)
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeLoads, From: consumer, To: target, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
			Attributes: marshalAttributes(map[string]any{"dependency_kind": value.Kind, "resolved": value.Resolved, "observed": true})})
	}
}

func (b *graphBuilder) addDelegation(fact model.Fact) {
	var value binarycollect.DelegationFact
	if !b.decode(fact, &value) || value.Command == "" {
		return
	}
	current, ok := b.graph.CurrentPrincipal()
	if !ok {
		b.diagnose("unresolved-principal", "delegation fact has no current principal", fact)
		return
	}
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	confidence := factConfidence(fact, value.Confidence)
	command := b.addNode(fact, NodeSpec{Key: "sudo:" + value.Command, Kind: model.NodeExecutable, Label: value.Command,
		SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
		Attributes: marshalAttributes(map[string]any{"delegated_command": true, "command": value.Command, "source_kind": value.SourceKind, "source_path": value.SourcePath, "negated": value.Negated, "semantics_resolved": value.SemanticsResolved})})
	target := b.namedPrincipal(fact, value.RunAs, evidence, confidence)
	if target.ID != "" {
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeRunsAs, From: command, To: target, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence})
	}
	policyConfirmed := value.SourceKind == "sudo-list"
	b.addEdge(fact, EdgeSpec{Kind: model.EdgeCanExecute, From: current, To: command, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
		Attributes: marshalAttributes(map[string]any{"delegation": true, "policy_confirmed": policyConfirmed, "no_password": value.NoPassword, "negated": value.Negated, "semantics_resolved": value.SemanticsResolved, "reachable": true, "subject": value.Subject})})
}

func (b *graphBuilder) addAdminSocket(fact model.Fact) {
	var value containercollect.AdminSocketFact
	if !b.decode(fact, &value) || value.Path == "" {
		return
	}
	evidence := mergeStrings(fact.EvidenceIDs, value.EvidenceIDs)
	confidence := factConfidence(fact, value.Confidence)
	socket := b.addNode(fact, NodeSpec{Key: filepath.Clean(value.Path), Kind: model.NodeSocket, Label: value.Path,
		SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
		Attributes: marshalAttributes(map[string]any{"path": value.Path, "daemon": value.Daemon, "daemon_uid": value.DaemonUID, "gid": value.GID, "mode": value.Mode, "direct_access": value.WriteAccess, "acl_summary": value.ACLSummary})})
	b.registerPath(value.Path, socket)
	target := b.ensurePrincipal(fact, model.Principal{UID: value.DaemonUID}, evidence, confidence)
	b.addEdge(fact, EdgeSpec{Kind: model.EdgeRunsAs, From: socket, To: target, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence})
	if current, ok := b.graph.CurrentPrincipal(); ok && value.WriteAccess {
		b.addEdge(fact, EdgeSpec{Kind: model.EdgeCanWrite, From: current, To: socket, SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: confidence,
			Attributes: marshalAttributes(map[string]any{"controlled": true, "direct_access": true, "access_check": true})})
	}
}

func (b *graphBuilder) addFilesystemRelationships() {
	sort.Slice(b.mounts, func(i, j int) bool {
		left, right := b.mounts[i], b.mounts[j]
		if left.observation.MountPoint != right.observation.MountPoint {
			return left.observation.MountPoint < right.observation.MountPoint
		}
		if left.observation.ID != right.observation.ID {
			return left.observation.ID < right.observation.ID
		}
		return factSortKey(left.fact) < factSortKey(right.fact)
	})
	mountValues := make([]pathcollect.MountObservation, 0, len(b.mounts))
	mountRefs := make(map[string]model.NodeRef)
	mountEvidence := make(map[string][]string)
	mountConfidence := make(map[string]model.Confidence)
	inventoryComplete := len(b.mounts) > 0
	var inventoryEvidence []string
	var inventoryMissing []string
	for _, prerequisite := range b.mounts {
		mount := prerequisite.observation
		fact := prerequisite.fact
		confidence := normalizeConfidence(fact.Confidence)
		key := fmt.Sprintf("%d:%s", mount.ID, mount.MountPoint)
		mountValues = append(mountValues, mount)
		mountRefs[key] = b.addNode(fact, NodeSpec{Key: key, Kind: model.NodeMount, Label: mount.MountPoint,
			SourceCollector: fact.SourceCollector, EvidenceIDs: mount.EvidenceIDs, Confidence: confidence, Attributes: marshalAttributes(mount)})
		mountEvidence[key] = mergeStrings(mountEvidence[key], mount.EvidenceIDs)
		if existing, ok := mountConfidence[key]; ok {
			mountConfidence[key] = weakerConfidence(existing, confidence)
		} else {
			mountConfidence[key] = confidence
		}
		inventoryEvidence = mergeStrings(inventoryEvidence, mount.EvidenceIDs)
		inventoryMissing = mergeStrings(inventoryMissing, fact.MissingFacts)
		if fact.ObservationStatus != model.ProbeComplete || confidence != model.ConfidenceHigh || len(fact.MissingFacts) > 0 {
			inventoryComplete = false
		}
	}
	if !inventoryComplete && len(inventoryMissing) == 0 {
		inventoryMissing = []string{"mount inventory incomplete"}
	}
	paths := make([]string, 0, len(b.pathRefs))
	for target := range b.pathRefs {
		paths = append(paths, target)
	}
	sort.Strings(paths)
	observations := pathcollect.ObservationSet{
		Stats: b.stats, ACLs: b.acls, Mounts: mountValues, MountInventoryComplete: inventoryComplete,
		MountInventoryEvidenceIDs: inventoryEvidence, MountInventoryMissing: inventoryMissing,
	}
	current, hasCurrent := b.graph.CurrentPrincipal()
	for _, target := range paths {
		refs := b.pathRefs[target]
		if mount, ok := pathcollect.MountForPath(target, mountValues); ok {
			key := fmt.Sprintf("%d:%s", mount.ID, mount.MountPoint)
			mountRef := mountRefs[key]
			for _, ref := range refs {
				fact := model.Fact{Kind: "mount", SourceCollector: "path", EvidenceIDs: mountEvidence[key], Confidence: mountConfidence[key]}
				b.addEdge(fact, EdgeSpec{Kind: model.EdgeLocatedOn, From: ref, To: mountRef, SourceCollector: "path", EvidenceIDs: mountEvidence[key], Confidence: mountConfidence[key]})
			}
		}
		if !hasCurrent || !filepath.IsAbs(target) {
			continue
		}
		resolution := pathcollect.Resolve(target, observations)
		assessment := pathcollect.EvaluateControl(b.currentPrincipal, resolution, pathcollect.UseWrite)
		if assessment.State == pathcollect.ControlAllowed && assessment.Controlled {
			for _, ref := range refs {
				fact := model.Fact{Kind: "path_control", SourceCollector: "path", EvidenceIDs: assessment.EvidenceIDs, Confidence: assessment.Confidence}
				b.addEdge(fact, EdgeSpec{Kind: model.EdgeCanWrite, From: current, To: ref, SourceCollector: "path", EvidenceIDs: assessment.EvidenceIDs,
					Confidence: assessment.Confidence, Attributes: marshalAttributes(assessment)})
			}
		}
		for _, ref := range refs {
			if ref.Kind != model.NodeExecutable && ref.Kind != model.NodeScript {
				continue
			}
			use := pathcollect.UseNativeExecute
			if ref.Kind == model.NodeScript {
				use = pathcollect.UseInterpretedScript
			}
			executable := pathcollect.EvaluateControl(b.currentPrincipal, resolution, use)
			if executable.State != pathcollect.ControlAllowed || !executable.Controlled {
				continue
			}
			attributes := map[string]any{"reachable": true, "controlled": true, "use_kind": executable.UseKind, "state": executable.State}
			fact := model.Fact{Kind: "path_control", SourceCollector: "path", EvidenceIDs: executable.EvidenceIDs, Confidence: executable.Confidence}
			b.addEdge(fact, EdgeSpec{Kind: model.EdgeCanExecute, From: current, To: ref, SourceCollector: "path", EvidenceIDs: executable.EvidenceIDs,
				Confidence: executable.Confidence, Attributes: marshalAttributes(attributes)})
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
	b.registerPath(target, ref)
	return ref
}

func (b *graphBuilder) registerPath(target string, ref model.NodeRef) {
	if filepath.IsAbs(target) && ref.ID != "" {
		clean := filepath.Clean(target)
		b.pathRefs[clean] = appendUniqueRefs(b.pathRefs[clean], ref)
	}
}

func (b *graphBuilder) namedPrincipal(fact model.Fact, name string, evidence []string, confidence model.Confidence) model.NodeRef {
	name = strings.TrimSpace(strings.TrimPrefix(name, "#"))
	if name == "root" {
		return b.ensurePrincipal(fact, model.Principal{UID: 0, GID: 0}, evidence, confidence)
	}
	if uid, err := strconv.Atoi(name); err == nil && uid >= 0 {
		return b.ensurePrincipal(fact, model.Principal{UID: uid}, evidence, confidence)
	}
	if name == "" {
		b.diagnose("unresolved-principal", "principal name is empty", fact)
		return model.NodeRef{}
	}
	return b.addNode(fact, NodeSpec{Key: "name:" + name, Kind: model.NodePrincipal, Label: name,
		SourceCollector: fact.SourceCollector, EvidenceIDs: evidence, Confidence: model.ConfidenceLow,
		Attributes: marshalAttributes(map[string]any{"name": name, "resolved": false})})
}

func (b *graphBuilder) unit(fact model.Fact, manager string, managerUID int, name string) (model.NodeRef, bool) {
	key := systemdFactKey(manager, managerUID, name)
	ref, ok := b.unitByKey[key]
	if !ok {
		b.diagnose("unresolved-consumer", "scoped systemd unit was not observed: "+key, fact)
		return model.NodeRef{}, false
	}
	return ref, true
}

func (b *graphBuilder) uniqueProcess(pid int) (model.NodeRef, bool) {
	refs := b.processByPID[pid]
	if len(refs) != 1 {
		return model.NodeRef{}, false
	}
	return refs[0], true
}

func processIdentityKey(pid int, startTime uint64) string {
	return fmt.Sprintf("%d:%d", pid, startTime)
}

func compatibleControlGroup(unit string, groups []processcollect.CgroupFact) bool {
	unit = filepath.Clean("/" + strings.TrimPrefix(unit, "/"))
	for _, group := range groups {
		path := filepath.Clean("/" + strings.TrimPrefix(group.Path, "/"))
		if path == unit || strings.HasPrefix(path, unit+"/") {
			return true
		}
	}
	return false
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

func systemdManager(value systemdcollect.UnitFact) string {
	if value.Manager == "" {
		return "system"
	}
	return value.Manager
}

func systemdUnitKey(value systemdcollect.UnitFact) string {
	return systemdFactKey(value.Manager, value.ManagerUID, value.Name)
}

func systemdFactManager(manager string) string {
	if manager == "" {
		return "system"
	}
	return manager
}

func systemdFactKey(manager string, managerUID int, name string) string {
	return fmt.Sprintf("%s:%d:%s", systemdFactManager(manager), managerUID, name)
}

func factConfidence(fact model.Fact, embedded model.Confidence) model.Confidence {
	if embedded == "" {
		return normalizeConfidence(fact.Confidence)
	}
	return weakerConfidence(fact.Confidence, embedded)
}

func containsUnresolved(value string) bool {
	return strings.ContainsAny(value, "%$")
}

func firstCommand(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return strings.Trim(fields[0], "'\"")
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
