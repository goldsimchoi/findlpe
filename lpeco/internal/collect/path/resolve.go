package path

import (
	"fmt"
	"path/filepath"
	"strings"
)

type ObservationSet struct {
	WorkingDirectory string                       `json:"working_directory,omitempty"`
	Stats            map[string][]StatObservation `json:"stats"`
	ACLs             map[string]ACLObservation    `json:"acls"`
	Mounts           []MountObservation           `json:"mounts"`
}

type SymlinkStep struct {
	Path        string   `json:"path"`
	Target      string   `json:"target"`
	ResolvedTo  string   `json:"resolved_to"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type Resolution struct {
	RequestedPath string            `json:"requested_path"`
	FinalPath     string            `json:"final_path"`
	Final         *StatObservation  `json:"final,omitempty"`
	Parents       []StatObservation `json:"parents"`
	Symlinks      []SymlinkStep     `json:"symlinks"`
	Complete      bool              `json:"complete"`
	Dangling      bool              `json:"dangling"`
	Loop          bool              `json:"loop"`
	RaceDetected  bool              `json:"race_detected"`
	MissingFacts  []string          `json:"missing_facts"`
	EvidenceIDs   []string          `json:"evidence_ids"`
	observations  ObservationSet
}

func Resolve(target string, observations ObservationSet) Resolution {
	resolution := Resolution{RequestedPath: target, Complete: true, observations: observations}
	if !filepath.IsAbs(target) {
		base := observations.WorkingDirectory
		if !filepath.IsAbs(base) {
			resolution.Complete = false
			resolution.MissingFacts = append(resolution.MissingFacts, "absolute working directory unavailable for relative path")
			return resolution
		}
		target = filepath.Join(base, target)
	}
	target = filepath.Clean(target)
	resolution.FinalPath = target
	pending := pathComponents(target)
	current := "/"
	visitedLinks := make(map[string]struct{})
	parentSeen := make(map[string]struct{})
	steps := 0

	root, ok, changed := selectStat(observations.Stats["/"])
	if !ok {
		resolution.Complete = false
		resolution.MissingFacts = append(resolution.MissingFacts, "stat missing for /")
		return resolution
	}
	resolution.EvidenceIDs = appendUniqueStrings(resolution.EvidenceIDs, root.EvidenceIDs...)
	if changed {
		resolution.RaceDetected = true
		resolution.Complete = false
		resolution.MissingFacts = append(resolution.MissingFacts, "path inode changed while observed: /")
	}
	if len(pending) == 0 {
		copy := root
		resolution.Final = &copy
		resolution.FinalPath = "/"
		return resolution
	}
	if len(pending) > 0 {
		resolution.Parents = append(resolution.Parents, root)
		parentSeen["/"] = struct{}{}
	}

	for len(pending) > 0 {
		steps++
		if steps > 256 {
			resolution.Loop = true
			resolution.Complete = false
			resolution.MissingFacts = append(resolution.MissingFacts, "symlink resolution step limit exceeded")
			return resolution
		}
		component := pending[0]
		pending = pending[1:]
		candidate := filepath.Join(current, component)
		stat, found, changed := selectStat(observations.Stats[candidate])
		if !found {
			resolution.FinalPath = filepath.Join(append([]string{candidate}, pending...)...)
			resolution.Dangling = true
			resolution.Complete = false
			resolution.MissingFacts = append(resolution.MissingFacts, "stat missing for "+candidate)
			return resolution
		}
		resolution.EvidenceIDs = appendUniqueStrings(resolution.EvidenceIDs, stat.EvidenceIDs...)
		if changed {
			resolution.RaceDetected = true
			resolution.Complete = false
			resolution.MissingFacts = append(resolution.MissingFacts, "path inode changed while observed: "+candidate)
		}
		if stat.Kind == FileSymlink {
			if _, seen := visitedLinks[candidate]; seen {
				resolution.Loop = true
				resolution.Complete = false
				resolution.MissingFacts = append(resolution.MissingFacts, "symlink loop at "+candidate)
				return resolution
			}
			visitedLinks[candidate] = struct{}{}
			if stat.LinkTarget == "" {
				resolution.Complete = false
				resolution.MissingFacts = append(resolution.MissingFacts, "symlink target unavailable for "+candidate)
				return resolution
			}
			resolvedTarget := stat.LinkTarget
			if !filepath.IsAbs(resolvedTarget) {
				resolvedTarget = filepath.Join(filepath.Dir(candidate), resolvedTarget)
			}
			resolvedTarget = filepath.Clean(resolvedTarget)
			resolution.Symlinks = append(resolution.Symlinks, SymlinkStep{Path: candidate, Target: stat.LinkTarget, ResolvedTo: resolvedTarget, EvidenceIDs: append([]string(nil), stat.EvidenceIDs...)})
			combined := append(pathComponents(resolvedTarget), pending...)
			pending = combined
			current = "/"
			continue
		}
		if len(pending) > 0 {
			if stat.Kind != FileDirectory {
				resolution.Complete = false
				resolution.MissingFacts = append(resolution.MissingFacts, candidate+" is not a directory")
				return resolution
			}
			if _, seen := parentSeen[candidate]; !seen {
				resolution.Parents = append(resolution.Parents, stat)
				parentSeen[candidate] = struct{}{}
			}
		}
		current = candidate
		if len(pending) == 0 {
			copy := stat
			resolution.Final = &copy
			resolution.FinalPath = candidate
		}
	}
	resolution.MissingFacts = uniqueStrings(resolution.MissingFacts)
	resolution.EvidenceIDs = uniqueStrings(resolution.EvidenceIDs)
	return resolution
}

func pathComponents(value string) []string {
	value = strings.TrimPrefix(filepath.Clean(value), "/")
	if value == "" || value == "." {
		return nil
	}
	return strings.Split(value, "/")
}

func selectStat(values []StatObservation) (StatObservation, bool, bool) {
	if len(values) == 0 {
		return StatObservation{}, false, false
	}
	selected := values[len(values)-1]
	changed := false
	for _, value := range values[:len(values)-1] {
		if value.Device != selected.Device || value.Inode != selected.Inode || value.Mode != selected.Mode || value.LinkTarget != selected.LinkTarget {
			changed = true
		}
	}
	return selected, true, changed
}

func appendUniqueStrings(values []string, additions ...string) []string {
	result := append([]string(nil), values...)
	for _, addition := range additions {
		if addition == "" || containsValue(result, addition) {
			continue
		}
		result = append(result, addition)
	}
	return result
}

func uniqueStrings(values []string) []string {
	return appendUniqueStrings(nil, values...)
}

func (resolution Resolution) String() string {
	return fmt.Sprintf("%s -> %s", resolution.RequestedPath, resolution.FinalPath)
}
