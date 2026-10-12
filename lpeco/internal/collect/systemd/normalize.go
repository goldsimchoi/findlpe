package systemd

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/systemdunit"
)

type CollectorDiagnostic struct {
	Code        string   `json:"code"`
	Message     string   `json:"message"`
	UnitName    string   `json:"unit_name,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type UnitFact struct {
	Name             string           `json:"name"`
	Aliases          []string         `json:"aliases"`
	Manager          string           `json:"manager"`
	ManagerUID       int              `json:"manager_uid"`
	LoadState        string           `json:"load_state"`
	ActiveState      string           `json:"active_state"`
	SubState         string           `json:"sub_state"`
	Type             string           `json:"type"`
	User             string           `json:"user"`
	Group            string           `json:"group"`
	UID              int              `json:"uid"`
	GID              int              `json:"gid"`
	DynamicUser      bool             `json:"dynamic_user"`
	MainPID          int              `json:"main_pid"`
	ControlGroup     string           `json:"control_group"`
	Restart          string           `json:"restart"`
	EnvironmentFiles []string         `json:"environment_files"`
	ExecSearchPath   []string         `json:"exec_search_path"`
	WorkingDirectory string           `json:"working_directory"`
	RootDirectory    string           `json:"root_directory"`
	RootImage        string           `json:"root_image"`
	SourcePaths      []string         `json:"source_paths"`
	InventoryOnly    bool             `json:"inventory_only"`
	RuntimeObserved  bool             `json:"runtime_observed"`
	FilesObserved    bool             `json:"files_observed"`
	MissingFacts     []string         `json:"missing_facts"`
	EvidenceIDs      []string         `json:"evidence_ids"`
	Confidence       model.Confidence `json:"confidence"`
}

type UnitSourceFact struct {
	UnitName    string           `json:"unit_name"`
	Manager     string           `json:"manager"`
	ManagerUID  int              `json:"manager_uid"`
	Path        string           `json:"path"`
	Kind        string           `json:"kind"`
	Applied     bool             `json:"applied"`
	EvidenceIDs []string         `json:"evidence_ids"`
	Confidence  model.Confidence `json:"confidence"`
}

type ExecFact struct {
	UnitName        string                  `json:"unit_name"`
	Manager         string                  `json:"manager"`
	ManagerUID      int                     `json:"manager_uid"`
	Directive       string                  `json:"directive"`
	Index           int                     `json:"index"`
	Command         systemdunit.ExecCommand `json:"command"`
	Source          systemdunit.SourceRef   `json:"source"`
	MissingFacts    []string                `json:"missing_facts"`
	RuntimeObserved bool                    `json:"runtime_observed"`
	FileObserved    bool                    `json:"file_observed"`
	EvidenceIDs     []string                `json:"evidence_ids"`
	Confidence      model.Confidence        `json:"confidence"`
}

type ActivationFact struct {
	TriggerUnit string           `json:"trigger_unit"`
	TargetUnit  string           `json:"target_unit"`
	Manager     string           `json:"manager"`
	ManagerUID  int              `json:"manager_uid"`
	Kind        string           `json:"kind"`
	Active      bool             `json:"active"`
	Automatic   bool             `json:"automatic"`
	Schedule    string           `json:"schedule,omitempty"`
	EvidenceIDs []string         `json:"evidence_ids"`
	Confidence  model.Confidence `json:"confidence"`
}

type UnitSecurityFact struct {
	UnitName              string           `json:"unit_name"`
	Manager               string           `json:"manager"`
	ManagerUID            int              `json:"manager_uid"`
	DynamicUser           bool             `json:"dynamic_user"`
	NoNewPrivileges       bool             `json:"no_new_privileges"`
	CapabilityBoundingSet []string         `json:"capability_bounding_set"`
	AmbientCapabilities   []string         `json:"ambient_capabilities"`
	RuntimeObserved       bool             `json:"runtime_observed"`
	FilesObserved         bool             `json:"files_observed"`
	EvidenceIDs           []string         `json:"evidence_ids"`
	Confidence            model.Confidence `json:"confidence"`
}

type Normalized struct {
	Units       []UnitFact
	Sources     []UnitSourceFact
	Execs       []ExecFact
	Activations []ActivationFact
	Security    []UnitSecurityFact
	Diagnostics []CollectorDiagnostic
}

func Normalize(runtimeUnits []RuntimeUnit, documentSets map[string][]DocumentSet, currentUID int) Normalized {
	result := Normalized{}
	runtimeByName := make(map[string]RuntimeUnit, len(runtimeUnits))
	names := make(map[string]struct{})
	for _, runtime := range runtimeUnits {
		runtimeByName[runtime.Name] = runtime
		names[runtime.Name] = struct{}{}
	}
	for name := range documentSets {
		names[name] = struct{}{}
	}
	orderedNames := make([]string, 0, len(names))
	for name := range names {
		orderedNames = append(orderedNames, name)
	}
	sort.Strings(orderedNames)
	for _, name := range orderedNames {
		runtime, hasObservation := runtimeByName[name]
		hasRuntime := hasObservation && !runtime.FileInventory
		sets := documentSets[name]
		var documents []systemdunit.Document
		completeFiles := false
		for _, set := range sets {
			documents = append(documents, set.Documents...)
			completeFiles = completeFiles || set.Complete
		}
		context := systemdunit.LoadContext{UnitName: name, Aliases: aliasesWithoutName(runtime.Names, name)}
		effective := systemdunit.Merge(context, documents)
		unit := makeUnitFact(name, runtime, hasRuntime, effective, currentUID)
		if hasObservation && runtime.FileInventory {
			unit.Manager = runtime.Manager
			unit.ManagerUID = runtime.ManagerUID
			unit.FilesObserved = true
			unit.EvidenceIDs = appendUnique(unit.EvidenceIDs, runtime.EvidenceIDs...)
			if runtime.FragmentPath != "" {
				unit.SourcePaths = appendUnique(unit.SourcePaths, runtime.FragmentPath)
			}
			if unit.Manager == "user" && unit.ManagerUID >= 0 {
				unit.UID = unit.ManagerUID
				unit.InventoryOnly = true
			}
		}
		result.Units = append(result.Units, unit)
		appliedSources := make(map[string]bool, len(effective.Sources))
		for _, path := range effective.Sources {
			appliedSources[path] = true
		}
		for _, document := range documents {
			kind := "fragment"
			if strings.HasSuffix(filepath.Base(filepath.Dir(document.Source.Path)), ".d") {
				kind = "drop-in"
			}
			confidence := model.ConfidenceHigh
			if !completeFiles {
				confidence = model.ConfidenceMedium
			}
			result.Sources = append(result.Sources, UnitSourceFact{
				UnitName: name, Manager: unit.Manager, ManagerUID: unit.ManagerUID, Path: document.Source.Path, Kind: kind, Applied: appliedSources[document.Source.Path],
				EvidenceIDs: evidenceFromDocument(document), Confidence: confidence,
			})
		}
		execs, diagnostics := normalizeExecs(name, unit.Manager, unit.ManagerUID, runtime, hasRuntime, effective, unit.EvidenceIDs)
		result.Execs = append(result.Execs, execs...)
		result.Diagnostics = append(result.Diagnostics, diagnostics...)
		result.Security = append(result.Security, normalizeSecurity(name, unit.Manager, unit.ManagerUID, runtime, hasRuntime, effective, unit.EvidenceIDs))
	}
	for _, runtime := range runtimeUnits {
		if activation, ok := normalizeActivation(runtime); ok {
			result.Activations = append(result.Activations, activation)
		}
	}
	sort.Slice(result.Sources, func(i, j int) bool {
		if result.Sources[i].UnitName != result.Sources[j].UnitName {
			return result.Sources[i].UnitName < result.Sources[j].UnitName
		}
		return result.Sources[i].Path < result.Sources[j].Path
	})
	return result
}

func makeUnitFact(name string, runtime RuntimeUnit, hasRuntime bool, effective systemdunit.EffectiveUnit, currentUID int) UnitFact {
	unit := UnitFact{Name: name, Confidence: model.ConfidenceHigh, RuntimeObserved: hasRuntime, FilesObserved: len(effective.Sources) > 0}
	if hasRuntime {
		unit.Aliases = aliasesWithoutName(runtime.Names, name)
		unit.Manager = runtime.Manager
		unit.ManagerUID = runtime.ManagerUID
		unit.LoadState = runtime.LoadState
		unit.ActiveState = runtime.ActiveState
		unit.SubState = runtime.SubState
		unit.Type = runtime.Type
		unit.User = runtime.User
		unit.Group = runtime.Group
		unit.UID = runtime.UID
		unit.GID = runtime.GID
		unit.DynamicUser = runtime.DynamicUser
		unit.MainPID = runtime.MainPID
		unit.ControlGroup = runtime.ControlGroup
		unit.Restart = runtime.Restart
		unit.EnvironmentFiles = append([]string(nil), runtime.EnvironmentFiles...)
		unit.ExecSearchPath = append([]string(nil), runtime.ExecSearchPath...)
		unit.WorkingDirectory = runtime.WorkingDirectory
		unit.RootDirectory = runtime.RootDirectory
		unit.RootImage = runtime.RootImage
		unit.MissingFacts = append(unit.MissingFacts, runtime.MissingFacts...)
		unit.EvidenceIDs = append(unit.EvidenceIDs, runtime.EvidenceIDs...)
		unit.InventoryOnly = runtime.Manager == "user" && (runtime.ManagerUID == currentUID || runtime.UID == currentUID)
		if runtime.Manager == "user" && runtime.ManagerUID >= 0 {
			unit.UID = runtime.ManagerUID
			unit.InventoryOnly = true
		}
		if len(runtime.MissingFacts) > 0 {
			unit.Confidence = model.ConfidenceMedium
		}
	} else {
		unit.Manager = "system"
		unit.LoadState = "unknown"
		unit.ActiveState = "unknown"
		unit.MissingFacts = append(unit.MissingFacts, "runtime properties unavailable")
		unit.Confidence = model.ConfidenceMedium
		if value := effective.Scalar("Service", "User"); value != nil {
			unit.User = value.Value
		}
		if value := effective.Scalar("Service", "Group"); value != nil {
			unit.Group = value.Value
		}
		if value := effective.Scalar("Service", "Type"); value != nil {
			unit.Type = value.Value
		}
		if value := effective.Scalar("Service", "WorkingDirectory"); value != nil {
			unit.WorkingDirectory = value.Value
		}
		if value := effective.Scalar("Service", "RootDirectory"); value != nil {
			unit.RootDirectory = value.Value
		}
		if value := effective.Scalar("Service", "RootImage"); value != nil {
			unit.RootImage = value.Value
		}
		for _, value := range effective.Values("Service", "EnvironmentFile") {
			unit.EnvironmentFiles = append(unit.EnvironmentFiles, strings.TrimPrefix(value.Value, "-"))
		}
	}
	unit.SourcePaths = append([]string(nil), effective.Sources...)
	for _, path := range effective.Sources {
		for _, values := range effective.Properties {
			for _, value := range values {
				if value.Source.Path == path {
					unit.EvidenceIDs = appendUnique(unit.EvidenceIDs, value.Source.EvidenceID)
				}
			}
		}
	}
	unit.EvidenceIDs = compactNonEmpty(unit.EvidenceIDs)
	return unit
}

func normalizeExecs(name, manager string, managerUID int, runtime RuntimeUnit, hasRuntime bool, effective systemdunit.EffectiveUnit, unitEvidence []string) ([]ExecFact, []CollectorDiagnostic) {
	var facts []ExecFact
	var diagnostics []CollectorDiagnostic
	usedRuntime := make(map[string]bool)
	for _, directive := range []string{"ExecCondition", "ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost"} {
		values := effective.Values("Service", directive)
		for index, value := range values {
			command := systemdunit.ParseExec(value.Value)
			confidence := model.ConfidenceHigh
			missing := []string{}
			if !hasRuntime {
				confidence = model.ConfidenceMedium
				missing = append(missing, "runtime command unavailable")
			}
			runtimeObserved := false
			if runtimeCommand, ok := runtime.RuntimeExec[directive]; ok && index == 0 && hasRuntime {
				usedRuntime[directive] = true
				runtimeObserved = true
				if command.Executable != runtimeCommand.Executable || !equalStrings(command.Arguments, runtimeCommand.Arguments) {
					diagnostics = append(diagnostics, CollectorDiagnostic{Code: "runtime-file-mismatch", Message: directive + " differs between manager and files", UnitName: name, EvidenceIDs: appendUnique(runtime.EvidenceIDs, value.Source.EvidenceID)})
				}
				command = runtimeCommand
			}
			if !command.Valid {
				confidence = model.ConfidenceLow
				missing = append(missing, "command semantics incomplete")
			}
			facts = append(facts, ExecFact{
				UnitName: name, Manager: manager, ManagerUID: managerUID, Directive: directive, Index: index, Command: command, Source: value.Source,
				RuntimeObserved: runtimeObserved, FileObserved: true,
				MissingFacts: missing, EvidenceIDs: compactNonEmpty(appendUnique(runtime.EvidenceIDs, value.Source.EvidenceID)), Confidence: confidence,
			})
		}
	}
	for directive, runtimeCommand := range runtime.RuntimeExec {
		if usedRuntime[directive] {
			continue
		}
		facts = append(facts, ExecFact{
			UnitName: name, Manager: manager, ManagerUID: managerUID, Directive: directive, Command: runtimeCommand,
			RuntimeObserved: true,
			Source:          systemdunit.SourceRef{Path: runtime.FragmentPath, EvidenceID: first(runtime.EvidenceIDs)},
			MissingFacts:    []string{"file provenance unavailable"}, EvidenceIDs: append([]string(nil), unitEvidence...), Confidence: model.ConfidenceMedium,
		})
	}
	return facts, diagnostics
}

func normalizeSecurity(name, manager string, managerUID int, runtime RuntimeUnit, hasRuntime bool, effective systemdunit.EffectiveUnit, evidence []string) UnitSecurityFact {
	security := UnitSecurityFact{UnitName: name, Manager: manager, ManagerUID: managerUID, RuntimeObserved: hasRuntime, FilesObserved: len(effective.Sources) > 0, EvidenceIDs: append([]string(nil), evidence...), Confidence: model.ConfidenceHigh}
	if hasRuntime {
		security.DynamicUser = runtime.DynamicUser
		security.NoNewPrivileges = runtime.NoNewPrivileges
		security.CapabilityBoundingSet = append([]string(nil), runtime.CapabilityBoundingSet...)
		security.AmbientCapabilities = append([]string(nil), runtime.AmbientCapabilities...)
		if len(runtime.MissingFacts) > 0 {
			security.Confidence = model.ConfidenceMedium
		}
		return security
	}
	security.Confidence = model.ConfidenceMedium
	if value := effective.Scalar("Service", "DynamicUser"); value != nil {
		security.DynamicUser = parseSystemdBool(value.Value)
	}
	if value := effective.Scalar("Service", "NoNewPrivileges"); value != nil {
		security.NoNewPrivileges = parseSystemdBool(value.Value)
	}
	for _, value := range effective.Values("Service", "CapabilityBoundingSet") {
		security.CapabilityBoundingSet = append(security.CapabilityBoundingSet, strings.Fields(value.Value)...)
	}
	for _, value := range effective.Values("Service", "AmbientCapabilities") {
		security.AmbientCapabilities = append(security.AmbientCapabilities, strings.Fields(value.Value)...)
	}
	return security
}

func normalizeActivation(runtime RuntimeUnit) (ActivationFact, bool) {
	extension := filepath.Ext(runtime.Name)
	kind := strings.TrimPrefix(extension, ".")
	if kind != "timer" && kind != "socket" && kind != "path" {
		return ActivationFact{}, false
	}
	target := runtime.ActivationUnit
	if target == "" {
		target = strings.TrimSuffix(runtime.Name, extension) + ".service"
	}
	active := runtime.LoadState == "loaded" && runtime.ActiveState == "active"
	confidence := model.ConfidenceHigh
	if len(runtime.MissingFacts) > 0 {
		confidence = model.ConfidenceMedium
	}
	return ActivationFact{
		TriggerUnit: runtime.Name, TargetUnit: target, Manager: runtime.Manager, ManagerUID: runtime.ManagerUID, Kind: kind, Active: active, Automatic: active,
		Schedule: runtime.NextElapse, EvidenceIDs: append([]string(nil), runtime.EvidenceIDs...), Confidence: confidence,
	}, true
}

func Facts(normalized Normalized) ([]model.Fact, error) {
	var facts []model.Fact
	appendFacts := func(kind string, values any) error {
		encoded, err := json.Marshal(values)
		if err != nil {
			return err
		}
		var entries []json.RawMessage
		if err := json.Unmarshal(encoded, &entries); err != nil {
			return err
		}
		for index, entry := range entries {
			var envelope struct {
				EvidenceIDs []string         `json:"evidence_ids"`
				Confidence  model.Confidence `json:"confidence"`
			}
			if err := json.Unmarshal(entry, &envelope); err != nil {
				return err
			}
			if len(envelope.EvidenceIDs) == 0 {
				return fmt.Errorf("%s fact %d has no evidence", kind, index)
			}
			id, err := model.StableID("fact", struct {
				Kind string
				Data json.RawMessage
			}{kind, entry})
			if err != nil {
				return err
			}
			facts = append(facts, model.Fact{ID: id, Kind: kind, SourceCollector: "systemd", EvidenceIDs: envelope.EvidenceIDs, Confidence: envelope.Confidence, Data: entry})
		}
		return nil
	}
	for kind, values := range map[string]any{
		"systemd_unit": normalized.Units, "systemd_unit_source": normalized.Sources,
		"systemd_exec": normalized.Execs, "systemd_activation": normalized.Activations, "systemd_security": normalized.Security,
	} {
		if err := appendFacts(kind, values); err != nil {
			return nil, err
		}
	}
	for _, diagnostic := range normalized.Diagnostics {
		if len(diagnostic.EvidenceIDs) == 0 {
			continue
		}
		data, err := json.Marshal(diagnostic)
		if err != nil {
			return nil, err
		}
		id, err := model.StableID("fact", struct {
			Kind string
			Data json.RawMessage
		}{"systemd_diagnostic", data})
		if err != nil {
			return nil, err
		}
		facts = append(facts, model.Fact{ID: id, Kind: "systemd_diagnostic", SourceCollector: "systemd", EvidenceIDs: diagnostic.EvidenceIDs, Confidence: model.ConfidenceLow, Data: data})
	}
	sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
	return facts, nil
}

func aliasesWithoutName(values []string, name string) []string {
	var result []string
	for _, value := range values {
		if value != name {
			result = append(result, value)
		}
	}
	return result
}

func evidenceFromDocument(document systemdunit.Document) []string {
	if document.Source.EvidenceID != "" {
		return []string{document.Source.EvidenceID}
	}
	return nil
}

func appendUnique(values []string, additions ...string) []string {
	result := append([]string(nil), values...)
	for _, addition := range additions {
		if addition == "" || containsString(result, addition) {
			continue
		}
		result = append(result, addition)
	}
	return result
}

func compactNonEmpty(values []string) []string {
	var result []string
	for _, value := range values {
		if value != "" && !containsString(result, value) {
			result = append(result, value)
		}
	}
	return result
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
