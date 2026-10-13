package orchestrator

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/normalone/lpeco/internal/collect"
	binarycollect "github.com/normalone/lpeco/internal/collect/binary"
	containercollect "github.com/normalone/lpeco/internal/collect/container"
	contextcollect "github.com/normalone/lpeco/internal/collect/context"
	packagecollect "github.com/normalone/lpeco/internal/collect/packageinfo"
	pathcollect "github.com/normalone/lpeco/internal/collect/path"
	processcollect "github.com/normalone/lpeco/internal/collect/process"
	schedulercollect "github.com/normalone/lpeco/internal/collect/scheduler"
	systemdcollect "github.com/normalone/lpeco/internal/collect/systemd"
	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
)

type Phase string

const (
	PhaseProfile            Phase = "profile"
	PhaseContext            Phase = "context"
	PhasePrimary            Phase = "primary"
	PhaseTargetedValidation Phase = "targeted-validation"
	PhaseFallback           Phase = "fallback"
	PhaseFinalize           Phase = "finalize"
)

func defaultCollectors() []collect.Collector {
	return []collect.Collector{
		contextcollect.Collector{}, processcollect.Collector{}, systemdcollect.Collector{}, pathcollect.Collector{},
		schedulercollect.Collector{}, binarycollect.Collector{}, packagecollect.Collector{MaxItems: packagecollect.DefaultMaxItems}, containercollect.Collector{},
	}
}

func collectorsByID(values []collect.Collector) map[string]collect.Collector {
	result := make(map[string]collect.Collector, len(values))
	for _, value := range values {
		if value != nil && value.ID() != "" {
			result[value.ID()] = value
		}
	}
	return result
}

func selectCollectors(values map[string]collect.Collector, ids ...string) []collect.Collector {
	result := make([]collect.Collector, 0, len(ids))
	for _, id := range ids {
		if value, ok := values[id]; ok {
			result = append(result, value)
		}
	}
	return result
}

func discover(facts []model.Fact) collect.Discovery {
	g, _ := graphpkg.Build(facts)
	current, hasCurrent := g.CurrentPrincipal()
	pidSet := make(map[int]bool)
	processSet := make(map[string]collect.ProcessIdentity)
	unitSet := make(map[string]bool)
	pathSet := make(map[string]bool)
	var mounts []collect.Mount
	for _, fact := range facts {
		if fact.Kind != "mount" {
			continue
		}
		var mount collect.Mount
		if json.Unmarshal(fact.Data, &mount) == nil && mount.MountPoint != "" {
			mounts = append(mounts, mount)
		}
	}
	for _, node := range g.NodesByKind(model.NodeProcess) {
		privileged := !hasCurrent
		for _, edge := range g.Outgoing(node.NodeRef, model.EdgeRunsAs) {
			if !hasCurrent || edge.To.ID != current.ID {
				privileged = true
				break
			}
		}
		if privileged {
			if pid, ok := graphpkg.IntAttribute(node.Attributes, "pid"); ok && pid > 0 {
				pidSet[pid] = true
				if startTime, startOK := graphpkg.IntAttribute(node.Attributes, "start_time"); startOK && startTime > 0 {
					key := fmt.Sprintf("%d:%d", pid, startTime)
					processSet[key] = collect.ProcessIdentity{PID: pid, StartTime: uint64(startTime)}
				}
			}
		}
	}
	for _, node := range g.NodesByKind(model.NodeUnit) {
		if node.Label != "" {
			unitSet[node.Label] = true
		}
	}
	for _, kind := range []model.NodeKind{model.NodeFile, model.NodeDirectory, model.NodeExecutable, model.NodeScript, model.NodeLibrary, model.NodeSocket} {
		for _, node := range g.NodesByKind(kind) {
			path := graphpkg.StringAttribute(node.Attributes, "path")
			if path == "" {
				path = node.Label
			}
			if len(path) > 0 && path[0] == '/' {
				pathSet[path] = true
			}
		}
	}
	result := collect.Discovery{}
	for pid := range pidSet {
		result.HighValuePIDs = append(result.HighValuePIDs, pid)
	}
	for _, identity := range processSet {
		result.HighValueProcesses = append(result.HighValueProcesses, identity)
	}
	for unit := range unitSet {
		result.UnitNames = append(result.UnitNames, unit)
	}
	for path := range pathSet {
		result.ReferencedPaths = append(result.ReferencedPaths, path)
	}
	result.Mounts = mounts
	sort.Ints(result.HighValuePIDs)
	sort.Slice(result.HighValueProcesses, func(i, j int) bool {
		if result.HighValueProcesses[i].PID != result.HighValueProcesses[j].PID {
			return result.HighValueProcesses[i].PID < result.HighValueProcesses[j].PID
		}
		return result.HighValueProcesses[i].StartTime < result.HighValueProcesses[j].StartTime
	})
	sort.Strings(result.UnitNames)
	sort.Strings(result.ReferencedPaths)
	sort.Slice(result.Mounts, func(i, j int) bool {
		if result.Mounts[i].MountPoint != result.Mounts[j].MountPoint {
			return result.Mounts[i].MountPoint < result.Mounts[j].MountPoint
		}
		return result.Mounts[i].ID < result.Mounts[j].ID
	})
	return result
}

func pendingValidation(discovery collect.Discovery) []string {
	values := make([]string, 0, len(discovery.HighValuePIDs)+len(discovery.HighValueProcesses)+len(discovery.UnitNames)+len(discovery.ReferencedPaths))
	if len(discovery.HighValueProcesses) > 0 {
		for _, identity := range discovery.HighValueProcesses {
			values = append(values, fmt.Sprintf("pid:%d:start:%d", identity.PID, identity.StartTime))
		}
	} else {
		for _, pid := range discovery.HighValuePIDs {
			values = append(values, "pid:"+itoa(pid))
		}
	}
	for _, unit := range discovery.UnitNames {
		values = append(values, "unit:"+unit)
	}
	for _, path := range discovery.ReferencedPaths {
		values = append(values, "path:"+path)
	}
	sort.Strings(values)
	return uniqueStrings(values)
}
