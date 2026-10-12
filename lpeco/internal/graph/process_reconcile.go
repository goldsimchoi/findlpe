package graph

import (
	"bytes"
	"encoding/json"
	"sort"

	processcollect "github.com/normalone/lpeco/internal/collect/process"
	"github.com/normalone/lpeco/internal/model"
)

func reconcileProcessFacts(facts []model.Fact) []model.Fact {
	groups := make(map[string][]model.Fact)
	result := make([]model.Fact, 0, len(facts))
	for _, fact := range facts {
		if fact.Kind != "process" {
			result = append(result, fact)
			continue
		}
		var value processcollect.ProcessFact
		if json.Unmarshal(fact.Data, &value) != nil || value.PID <= 0 {
			result = append(result, fact)
			continue
		}
		key := processIdentityKey(value.PID, value.StartTime)
		groups[key] = append(groups[key], fact)
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		group := groups[key]
		if len(group) == 1 {
			result = append(result, group[0])
			continue
		}
		values := make([]processcollect.ProcessFact, len(group))
		best := 0
		for index := range group {
			_ = json.Unmarshal(group[index].Data, &values[index])
			if processCompleteness(values[index]) > processCompleteness(values[best]) || processCompleteness(values[index]) == processCompleteness(values[best]) && bytes.Compare(group[index].Data, group[best].Data) < 0 {
				best = index
			}
		}
		merged := values[best]
		confidence := group[best].Confidence
		status := group[best].ObservationStatus
		missing := append([]string(nil), group[best].MissingFacts...)
		for index, value := range values {
			merged.EvidenceIDs = mergeStrings(merged.EvidenceIDs, value.EvidenceIDs)
			merged.MissingFacts = mergeStrings(merged.MissingFacts, value.MissingFacts)
			for _, cgroup := range value.Cgroups {
				if !containsCgroup(merged.Cgroups, cgroup) {
					merged.Cgroups = append(merged.Cgroups, cgroup)
				}
			}
			missing = mergeStrings(missing, group[index].MissingFacts)
			confidence = weakerConfidence(confidence, group[index].Confidence)
			if group[index].ObservationStatus != "" && group[index].ObservationStatus != model.ProbeComplete {
				status = group[index].ObservationStatus
			}
		}
		sort.Slice(merged.Cgroups, func(i, j int) bool {
			return merged.Cgroups[i].Hierarchy+"\x00"+merged.Cgroups[i].Controllers+"\x00"+merged.Cgroups[i].Path < merged.Cgroups[j].Hierarchy+"\x00"+merged.Cgroups[j].Controllers+"\x00"+merged.Cgroups[j].Path
		})
		merged.Confidence = weakerConfidence(merged.Confidence, confidence)
		data, _ := json.Marshal(merged)
		id, _ := model.StableID("fact", struct {
			PID   int
			Start uint64
		}{merged.PID, merged.StartTime})
		result = append(result, model.Fact{ID: id, Kind: "process", SourceCollector: "process", EvidenceIDs: merged.EvidenceIDs, Confidence: confidence, ObservationStatus: status, MissingFacts: missing, Data: data})
	}
	sort.Slice(result, func(i, j int) bool { return factSortKey(result[i]) < factSortKey(result[j]) })
	return result
}

func processCompleteness(value processcollect.ProcessFact) int {
	score := 0
	for _, present := range []bool{value.Name != "", value.StartTime != 0, value.Executable != "", value.WorkingDirectory != "", value.Root != "", len(value.Cmdline) > 0, len(value.Cgroups) > 0} {
		if present {
			score++
		}
	}
	return score - len(value.MissingFacts)
}

func containsCgroup(values []processcollect.CgroupFact, target processcollect.CgroupFact) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
