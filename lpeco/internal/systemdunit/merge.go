package systemdunit

import (
	"path/filepath"
	"sort"
	"strings"
)

type LoadContext struct {
	UnitName string
	Aliases  []string
}

type EffectiveValue struct {
	Value  string    `json:"value"`
	Source SourceRef `json:"source"`
}

type EffectiveUnit struct {
	UnitName   string                      `json:"unit_name"`
	Properties map[string][]EffectiveValue `json:"properties"`
	Resets     []Assignment                `json:"resets"`
	Sources    []string                    `json:"sources"`
}

func Merge(context LoadContext, documents []Document) EffectiveUnit {
	effective := EffectiveUnit{UnitName: context.UnitName, Properties: make(map[string][]EffectiveValue)}
	var fragments []Document
	type dropIn struct {
		document    Document
		name        string
		specificity int
		rank        int
	}
	var dropIns []dropIn
	for _, document := range documents {
		if strings.HasSuffix(filepath.Base(filepath.Dir(document.Source.Path)), ".d") {
			applicable, specificity := DropInApplicability(context, document.Source.Path)
			if applicable {
				dropIns = append(dropIns, dropIn{document: document, name: filepath.Base(document.Source.Path), specificity: specificity, rank: LoadPathRank(document.Source.Path)})
			}
			continue
		}
		base := filepath.Base(document.Source.Path)
		if base == context.UnitName || contains(context.Aliases, base) || base == templateUnitName(context.UnitName) {
			fragments = append(fragments, document)
		}
	}
	if len(fragments) > 0 {
		sort.SliceStable(fragments, func(i, j int) bool {
			return LoadPathRank(fragments[i].Source.Path) > LoadPathRank(fragments[j].Source.Path)
		})
		applyDocument(&effective, fragments[0])
	}
	bestByName := make(map[string]dropIn)
	for _, candidate := range dropIns {
		current, exists := bestByName[candidate.name]
		if !exists || candidate.specificity > current.specificity || candidate.specificity == current.specificity && candidate.rank > current.rank {
			bestByName[candidate.name] = candidate
		}
	}
	selected := make([]dropIn, 0, len(bestByName))
	for _, candidate := range bestByName {
		selected = append(selected, candidate)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].name < selected[j].name })
	for _, candidate := range selected {
		applyDocument(&effective, candidate.document)
	}
	return effective
}

func (u EffectiveUnit) Values(section, key string) []EffectiveValue {
	return append([]EffectiveValue(nil), u.Properties[propertyKey(section, key)]...)
}

func (u EffectiveUnit) Scalar(section, key string) *EffectiveValue {
	values := u.Properties[propertyKey(section, key)]
	if len(values) == 0 {
		return nil
	}
	value := values[len(values)-1]
	return &value
}

func applyDocument(effective *EffectiveUnit, document Document) {
	effective.Sources = append(effective.Sources, document.Source.Path)
	for _, assignment := range document.Assignments {
		key := propertyKey(assignment.Section, assignment.Key)
		value := EffectiveValue{Value: assignment.Value, Source: assignment.Source}
		if isListDirective(assignment.Key) {
			if assignment.Value == "" {
				effective.Properties[key] = nil
				effective.Resets = append(effective.Resets, assignment)
				continue
			}
			effective.Properties[key] = append(effective.Properties[key], value)
			continue
		}
		effective.Properties[key] = []EffectiveValue{value}
	}
}

func propertyKey(section, key string) string { return section + "\x00" + key }

func isListDirective(key string) bool {
	if IsExecDirective(key) {
		return true
	}
	switch key {
	case "Environment", "EnvironmentFile", "PassEnvironment", "UnsetEnvironment", "ReadWritePaths", "ReadOnlyPaths", "InaccessiblePaths", "SupplementaryGroups", "CapabilityBoundingSet", "AmbientCapabilities", "Sockets", "Requires", "Wants", "After", "Before":
		return true
	default:
		return false
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
