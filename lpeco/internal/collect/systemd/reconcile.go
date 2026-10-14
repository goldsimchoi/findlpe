package systemd

import (
	"encoding/json"
	"reflect"
	"sort"

	"github.com/normalone/lpeco/internal/model"
)

// ReconcileFacts combines independently collected manager-authoritative and
// unit-file observations. Raw facts remain in the session store; the graph is
// built from this deterministic semantic view so runtime authority is never
// replaced by a lexical JSON variant.
func ReconcileFacts(facts []model.Fact) ([]model.Fact, []CollectorDiagnostic) {
	ordered := append([]model.Fact(nil), facts...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	result := make([]model.Fact, 0, len(ordered))
	unitGroups := make(map[string][]model.Fact)
	execGroups := make(map[string][]model.Fact)
	securityGroups := make(map[string][]model.Fact)
	var diagnostics []CollectorDiagnostic

	for _, fact := range ordered {
		switch fact.Kind {
		case "systemd_unit":
			var value UnitFact
			if json.Unmarshal(fact.Data, &value) != nil || value.Name == "" {
				result = append(result, fact)
				continue
			}
			unitGroups[scopeKey(value.Manager, value.ManagerUID, value.Name)] = append(unitGroups[scopeKey(value.Manager, value.ManagerUID, value.Name)], fact)
		case "systemd_exec":
			var value ExecFact
			if json.Unmarshal(fact.Data, &value) != nil || value.UnitName == "" {
				result = append(result, fact)
				continue
			}
			key := scopeKey(value.Manager, value.ManagerUID, value.UnitName) + "\x00" + value.Directive + "\x00" + itoa(value.Index)
			execGroups[key] = append(execGroups[key], fact)
		case "systemd_security":
			var value UnitSecurityFact
			if json.Unmarshal(fact.Data, &value) != nil || value.UnitName == "" {
				result = append(result, fact)
				continue
			}
			securityGroups[scopeKey(value.Manager, value.ManagerUID, value.UnitName)] = append(securityGroups[scopeKey(value.Manager, value.ManagerUID, value.UnitName)], fact)
		case "systemd_diagnostic":
			var value CollectorDiagnostic
			if json.Unmarshal(fact.Data, &value) == nil {
				diagnostics = append(diagnostics, value)
			}
			result = append(result, fact)
		default:
			result = append(result, fact)
		}
	}

	for _, key := range sortedKeys(unitGroups) {
		group := unitGroups[key]
		values := make([]UnitFact, len(group))
		marked := false
		for index := range group {
			_ = json.Unmarshal(group[index].Data, &values[index])
			marked = marked || values[index].RuntimeObserved || values[index].FilesObserved
		}
		if !marked || len(group) == 1 {
			result = append(result, group...)
			continue
		}
		merged := values[0]
		var runtime *UnitFact
		for index := range values {
			if values[index].RuntimeObserved {
				copy := values[index]
				runtime = &copy
				break
			}
		}
		if runtime != nil {
			merged = *runtime
		}
		for _, value := range values {
			merged.RuntimeObserved = merged.RuntimeObserved || value.RuntimeObserved
			merged.FilesObserved = merged.FilesObserved || value.FilesObserved
			merged.SourcePaths = appendUnique(merged.SourcePaths, value.SourcePaths...)
			merged.EvidenceIDs = appendUnique(merged.EvidenceIDs, value.EvidenceIDs...)
			merged.MissingFacts = appendUnique(merged.MissingFacts, value.MissingFacts...)
			if runtime != nil && value.FilesObserved {
				diagnostics = appendUnitMismatchDiagnostics(diagnostics, *runtime, value)
			}
		}
		if merged.RuntimeObserved {
			merged.MissingFacts = removeMissing(merged.MissingFacts, "runtime properties unavailable")
		}
		if merged.RuntimeObserved && merged.FilesObserved && len(merged.MissingFacts) == 0 {
			merged.Confidence = model.ConfidenceHigh
		} else if len(merged.MissingFacts) > 0 {
			merged.Confidence = atMostMedium(merged.Confidence)
		}
		resolved := []string{}
		if merged.RuntimeObserved {
			resolved = append(resolved, "runtime properties unavailable")
		}
		result = append(result, reconciledFact("systemd_unit", merged, group, resolved...))
	}

	for _, key := range sortedKeys(execGroups) {
		group := execGroups[key]
		values := make([]ExecFact, len(group))
		marked := false
		for index := range group {
			_ = json.Unmarshal(group[index].Data, &values[index])
			marked = marked || values[index].RuntimeObserved || values[index].FileObserved
		}
		if !marked || len(group) == 1 {
			result = append(result, group...)
			continue
		}
		merged := values[0]
		var runtime *ExecFact
		var file *ExecFact
		for index := range values {
			if values[index].RuntimeObserved && runtime == nil {
				copy := values[index]
				runtime = &copy
			}
			if values[index].FileObserved && file == nil {
				copy := values[index]
				file = &copy
			}
		}
		if runtime != nil {
			merged = *runtime
		}
		for _, value := range values {
			merged.RuntimeObserved = merged.RuntimeObserved || value.RuntimeObserved
			merged.FileObserved = merged.FileObserved || value.FileObserved
			merged.EvidenceIDs = appendUnique(merged.EvidenceIDs, value.EvidenceIDs...)
			merged.MissingFacts = appendUnique(merged.MissingFacts, value.MissingFacts...)
		}
		if file != nil {
			merged.Source = file.Source
			if runtime != nil && !reflect.DeepEqual(runtime.Command, file.Command) {
				diagnostics = append(diagnostics, CollectorDiagnostic{
					Code: "runtime-file-mismatch", Message: merged.Directive + " differs between manager and files",
					UnitName: merged.UnitName, EvidenceIDs: compactNonEmpty(appendUnique(runtime.EvidenceIDs, file.EvidenceIDs...)),
				})
			}
		}
		if merged.RuntimeObserved {
			merged.MissingFacts = removeMissing(merged.MissingFacts, "runtime command unavailable")
		}
		if merged.FileObserved {
			merged.MissingFacts = removeMissing(merged.MissingFacts, "file provenance unavailable")
		}
		if merged.RuntimeObserved && merged.FileObserved && merged.Command.Valid && len(merged.MissingFacts) == 0 {
			merged.Confidence = model.ConfidenceHigh
		} else if len(merged.MissingFacts) > 0 {
			merged.Confidence = atMostMedium(merged.Confidence)
		}
		resolved := []string{}
		if merged.RuntimeObserved {
			resolved = append(resolved, "runtime command unavailable")
		}
		if merged.FileObserved {
			resolved = append(resolved, "file provenance unavailable")
		}
		result = append(result, reconciledFact("systemd_exec", merged, group, resolved...))
	}

	for _, key := range sortedKeys(securityGroups) {
		group := securityGroups[key]
		values := make([]UnitSecurityFact, len(group))
		marked := false
		for index := range group {
			_ = json.Unmarshal(group[index].Data, &values[index])
			marked = marked || values[index].RuntimeObserved || values[index].FilesObserved
		}
		if !marked || len(group) == 1 {
			result = append(result, group...)
			continue
		}
		merged := values[0]
		for _, value := range values {
			if value.RuntimeObserved {
				merged = value
				break
			}
		}
		for _, value := range values {
			merged.RuntimeObserved = merged.RuntimeObserved || value.RuntimeObserved
			merged.FilesObserved = merged.FilesObserved || value.FilesObserved
			merged.EvidenceIDs = appendUnique(merged.EvidenceIDs, value.EvidenceIDs...)
			merged.MissingFacts = appendUnique(merged.MissingFacts, value.MissingFacts...)
		}
		if merged.RuntimeObserved {
			merged.MissingFacts = removeMissing(merged.MissingFacts, "runtime security properties unavailable")
		}
		if merged.RuntimeObserved && merged.FilesObserved && len(merged.MissingFacts) == 0 {
			merged.Confidence = model.ConfidenceHigh
		} else if len(merged.MissingFacts) > 0 {
			merged.Confidence = atMostMedium(merged.Confidence)
		}
		resolved := []string{}
		if merged.RuntimeObserved {
			resolved = append(resolved, "runtime security properties unavailable")
		}
		result = append(result, reconciledFact("systemd_security", merged, group, resolved...))
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].ID < result[j].ID
	})
	sort.Slice(diagnostics, func(i, j int) bool {
		left := diagnostics[i].Code + "\x00" + diagnostics[i].UnitName + "\x00" + diagnostics[i].Message
		right := diagnostics[j].Code + "\x00" + diagnostics[j].UnitName + "\x00" + diagnostics[j].Message
		return left < right
	})
	return result, diagnostics
}

func appendUnitMismatchDiagnostics(result []CollectorDiagnostic, runtime, file UnitFact) []CollectorDiagnostic {
	checks := []struct{ name, runtime, file string }{
		{"User", runtime.User, file.User}, {"Group", runtime.Group, file.Group},
		{"WorkingDirectory", runtime.WorkingDirectory, file.WorkingDirectory},
		{"RootDirectory", runtime.RootDirectory, file.RootDirectory}, {"RootImage", runtime.RootImage, file.RootImage},
	}
	for _, check := range checks {
		if check.runtime != "" && check.file != "" && check.runtime != check.file {
			result = append(result, CollectorDiagnostic{
				Code: "runtime-file-mismatch", Message: check.name + " differs between manager and files", UnitName: runtime.Name,
				EvidenceIDs: compactNonEmpty(appendUnique(runtime.EvidenceIDs, file.EvidenceIDs...)),
			})
		}
	}
	return result
}

func reconciledFact(kind string, value any, inputs []model.Fact, resolvedMissing ...string) model.Fact {
	data, _ := json.Marshal(value)
	var semantic struct {
		Confidence   model.Confidence `json:"confidence"`
		MissingFacts []string         `json:"missing_facts"`
	}
	_ = json.Unmarshal(data, &semantic)
	evidence := []string{}
	status := model.ProbeComplete
	confidence := semantic.Confidence
	if confidence == "" {
		confidence = model.ConfidenceHigh
	}
	missing := appendUnique(nil, semantic.MissingFacts...)
	for _, input := range inputs {
		evidence = appendUnique(evidence, input.EvidenceIDs...)
		unresolved := unresolvedMissingFacts(input.MissingFacts, resolvedMissing)
		missing = appendUnique(missing, unresolved...)
		// A source whose only limitation was supplied by another observation no
		// longer caps the reconciled result. Every other source confidence does.
		if len(input.MissingFacts) == 0 || len(unresolved) > 0 {
			confidence = weakerSystemdConfidence(confidence, input.Confidence)
		}
		if input.ObservationStatus != "" && input.ObservationStatus != model.ProbeComplete {
			status = input.ObservationStatus
			confidence = weakerSystemdConfidence(confidence, input.Confidence)
		}
	}
	missing = compactNonEmpty(missing)
	if len(missing) > 0 {
		confidence = atMostMedium(confidence)
	}
	var attributes map[string]any
	if json.Unmarshal(data, &attributes) == nil {
		attributes["confidence"] = confidence
		attributes["missing_facts"] = missing
		data, _ = json.Marshal(attributes)
	}
	id, _ := model.StableID("fact", struct {
		Kind string
		Data json.RawMessage
	}{kind, data})
	return model.Fact{ID: id, Kind: kind, SourceCollector: "systemd", EvidenceIDs: compactNonEmpty(evidence), Confidence: confidence, ObservationStatus: status, MissingFacts: missing, Data: data}
}

func unresolvedMissingFacts(values, resolved []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if containsString(resolved, value) {
			continue
		}
		result = appendUnique(result, value)
	}
	return result
}

func scopeKey(manager string, managerUID int, unit string) string {
	if manager == "" {
		manager = "system"
	}
	return manager + "\x00" + itoa(managerUID) + "\x00" + unit
}

func removeMissing(values []string, exact string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != exact {
			result = append(result, value)
		}
	}
	return compactNonEmpty(result)
}

func weakerSystemdConfidence(left, right model.Confidence) model.Confidence {
	rank := func(value model.Confidence) int {
		switch value {
		case model.ConfidenceHigh:
			return 3
		case model.ConfidenceMedium:
			return 2
		default:
			return 1
		}
	}
	if rank(right) < rank(left) {
		return right
	}
	return left
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	if negative {
		index--
		digits[index] = '-'
	}
	return string(digits[index:])
}
