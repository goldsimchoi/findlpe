package integration

import (
	"encoding/json"
	"sort"

	contextcollect "github.com/normalone/lpeco/internal/collect/context"
	pathcollect "github.com/normalone/lpeco/internal/collect/path"
	processcollect "github.com/normalone/lpeco/internal/collect/process"
	schedulercollect "github.com/normalone/lpeco/internal/collect/scheduler"
	systemdcollect "github.com/normalone/lpeco/internal/collect/systemd"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/systemdunit"
)

func contextFixtureFacts(evidence string, systemdRunning bool) []model.Fact {
	return []model.Fact{
		fixtureFact("identity", "context", evidence, contextcollect.IdentityFact{UIDs: [4]int{1000, 1000, 1000, 1000}, GIDs: [4]int{1000, 1000, 1000, 1000}, Groups: []int{1000}}),
		fixtureFact("host", "context", evidence, contextcollect.HostFact{OS: "Linux", Architecture: "x86_64", InitSystem: map[bool]string{true: "systemd", false: "busybox"}[systemdRunning], SystemdRunning: systemdRunning, AvailableCommands: map[string]bool{"stat": true, "getfacl": true}}),
	}
}

func systemdFixtureFacts(evidence string) []model.Fact {
	process := processcollect.ProcessFact{PID: 42, PPID: 1, StartTime: 77, Name: "demo", UIDs: [4]int{0, 0, 0, 0}, GIDs: [4]int{0, 0, 0, 0}, Executable: "/opt/demo/bin", EvidenceIDs: []string{evidence}, Confidence: model.ConfidenceHigh}
	unit := systemdcollect.UnitFact{Name: "demo.service", Manager: "system", UID: 0, GID: 0, User: "root", MainPID: 42, ActiveState: "active", EvidenceIDs: []string{evidence}, Confidence: model.ConfidenceHigh}
	source := systemdcollect.UnitSourceFact{UnitName: "demo.service", Path: "/etc/systemd/system/demo.service", Kind: "fragment", Applied: true, EvidenceIDs: []string{evidence}, Confidence: model.ConfidenceHigh}
	exec := systemdcollect.ExecFact{UnitName: "demo.service", Directive: "ExecStart", Command: systemdunit.ExecCommand{Executable: "/opt/demo/bin", Valid: true}, EvidenceIDs: []string{evidence}, Confidence: model.ConfidenceHigh}
	activation := systemdcollect.ActivationFact{TriggerUnit: "demo.timer", TargetUnit: "demo.service", Kind: "timer", Active: true, Automatic: true, Schedule: "every minute", EvidenceIDs: []string{evidence}, Confidence: model.ConfidenceHigh}
	return []model.Fact{
		fixtureFact("process", "process", evidence, process),
		fixtureFact("systemd_unit", "systemd", evidence, unit),
		fixtureFact("systemd_unit_source", "systemd", evidence, source),
		fixtureFact("systemd_exec", "systemd", evidence, exec),
		fixtureFact("systemd_activation", "systemd", evidence, activation),
	}
}

func systemdPathFacts(evidence string) []model.Fact {
	return pathFacts(evidence, map[string]uint32{
		"/": 0o040755, "/etc": 0o040755, "/etc/systemd": 0o040755, "/etc/systemd/system": 0o040755,
		"/etc/systemd/system/demo.service": 0o100666,
	})
}

func schedulerFixtureFacts(evidence string) []model.Fact {
	value := schedulercollect.ScheduleFact{Kind: "cron", SourcePath: "/etc/cron.d/demo", User: "root", Schedule: "* * * * *", Command: "/bin/sh /opt/demo/job.sh", Interpreter: "/bin/sh", Script: "/opt/demo/job.sh", Active: true, EvidenceIDs: []string{evidence}, Confidence: model.ConfidenceHigh}
	return []model.Fact{fixtureFact("schedule", "scheduler", evidence, value)}
}

func schedulerPathFacts(evidence string) []model.Fact {
	return pathFacts(evidence, map[string]uint32{
		"/": 0o040755, "/opt": 0o040755, "/opt/demo": 0o040777, "/opt/demo/job.sh": 0o100755,
	})
}

func pathFacts(evidence string, modes map[string]uint32) []model.Fact {
	paths := make([]string, 0, len(modes))
	for path := range modes {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	result := []model.Fact{fixtureFact("mount", "path", evidence, pathcollect.MountObservation{ID: 1, ParentID: 0, MajorMinor: "8:1", Root: "/", MountPoint: "/", FSType: "ext4", Source: "/dev/vda1", EvidenceIDs: []string{evidence}})}
	for index, path := range paths {
		kind := pathcollect.FileDirectory
		uid := 0
		gid := 0
		if modes[path]&0o170000 == 0o100000 {
			kind = pathcollect.FileRegular
		}
		stat := pathcollect.StatObservation{Path: path, Device: 8, Inode: uint64(index + 10), Mode: modes[path], UID: uid, GID: gid, Kind: kind, Status: pathcollect.ObservationComplete, EvidenceIDs: []string{evidence}}
		acl := pathcollect.ACLObservation{Path: path, Status: pathcollect.ObservationComplete, Entries: []pathcollect.ACLEntry{}, EvidenceIDs: []string{evidence}}
		result = append(result, fixtureFact("path_stat", "path", evidence, stat), fixtureFact("path_acl", "path", evidence, acl))
	}
	return result
}

func fixtureFact(kind, collector, evidence string, value any) model.Fact {
	data, _ := json.Marshal(value)
	id, _ := model.StableID("fact", struct {
		Kind string
		Data json.RawMessage
	}{kind, data})
	return model.Fact{ID: id, Kind: kind, SourceCollector: collector, EvidenceIDs: []string{evidence}, Confidence: model.ConfidenceHigh, Data: data}
}
