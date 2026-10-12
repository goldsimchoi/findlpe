package path

import (
	"testing"

	"github.com/normalone/lpeco/internal/model"
)

func TestEvaluateControlDirectWriteReplacementStickyAndTraversal(t *testing.T) {
	principal := model.Principal{UID: 1000, GID: 1000, SupplementaryGIDs: []int{2000}}
	base := func() ObservationSet {
		return controlObservationSet(
			statDir("/", 1, 0, 0, 0o755),
			statDir("/opt", 2, 0, 0, 0o755),
			statDir("/opt/app", 3, 0, 2000, 0o775),
			statFile("/opt/app/run", 4, 0, 0, 0o644),
		)
	}
	resolution := Resolve("/opt/app/run", base())
	assessment := EvaluateControl(principal, resolution, UseWrite)
	if assessment.State != ControlAllowed || assessment.DirectWrite || !assessment.Replaceable {
		t.Fatalf("replacement assessment = %#v", assessment)
	}

	direct := base()
	direct.Stats["/opt/app/run"] = []StatObservation{statFile("/opt/app/run", 4, 1000, 1000, 0o600)}
	assessment = EvaluateControl(principal, Resolve("/opt/app/run", direct), UseWrite)
	if assessment.State != ControlAllowed || !assessment.DirectWrite {
		t.Fatalf("direct write assessment = %#v", assessment)
	}

	sticky := base()
	sticky.Stats["/opt/app"] = []StatObservation{statDir("/opt/app", 3, 0, 2000, 0o1777)}
	assessment = EvaluateControl(principal, Resolve("/opt/app/run", sticky), UseReplace)
	if assessment.State != ControlDenied || assessment.Replaceable {
		t.Fatalf("sticky replacement assessment = %#v", assessment)
	}

	blocked := base()
	blocked.Stats["/opt"] = []StatObservation{statDir("/opt", 2, 0, 0, 0o700)}
	assessment = EvaluateControl(principal, Resolve("/opt/app/run", blocked), UseWrite)
	if assessment.State != ControlDenied || !hasMissing(assessment.MissingFacts, "traverse") {
		t.Fatalf("non-traversable assessment = %#v", assessment)
	}
}

func TestEvaluateControlUnknownEvidenceIsNeverOptimisticallyWritable(t *testing.T) {
	principal := model.Principal{UID: 1000, GID: 1000}
	set := controlObservationSet(statDir("/", 1, 0, 0, 0o777), statFile("/tool", 2, 1000, 1000, 0o777))
	delete(set.ACLs, "/tool")
	assessment := EvaluateControl(principal, Resolve("/tool", set), UseWrite)
	if assessment.State != ControlUnknown || assessment.Controlled {
		t.Fatalf("missing ACL assessment = %#v", assessment)
	}

	set = controlObservationSet(statDir("/", 1, 0, 0, 0o777), statFile("/tool", 2, 1000, 1000, 0o777))
	set.Mounts = nil
	assessment = EvaluateControl(principal, Resolve("/tool", set), UseWrite)
	if assessment.State != ControlUnknown || assessment.Controlled {
		t.Fatalf("missing mount assessment = %#v", assessment)
	}
}

func TestEvaluateControlMountExecutionSemantics(t *testing.T) {
	principal := model.Principal{UID: 1000, GID: 1000}
	set := controlObservationSet(statDir("/", 1, 0, 0, 0o755), statFile("/tool", 2, 1000, 1000, 0o755))
	set.Mounts[0].NoExec = true
	if got := EvaluateControl(principal, Resolve("/tool", set), UseNativeExecute); got.State != ControlDenied || got.Executable {
		t.Fatalf("native noexec assessment = %#v", got)
	}
	if got := EvaluateControl(principal, Resolve("/tool", set), UseInterpretedScript); got.State != ControlAllowed || !got.Executable {
		t.Fatalf("interpreted noexec assessment = %#v", got)
	}
	set.Mounts[0].NoSUID = true
	if got := EvaluateControl(principal, Resolve("/tool", set), UseSetIDExecute); got.State != ControlDenied || got.SetIDEffective {
		t.Fatalf("nosuid assessment = %#v", got)
	}
	set.Mounts[0].ReadOnly = true
	if got := EvaluateControl(principal, Resolve("/tool", set), UseWrite); got.State != ControlDenied {
		t.Fatalf("read-only write assessment = %#v", got)
	}
}

func controlObservationSet(stats ...StatObservation) ObservationSet {
	set := ObservationSet{Stats: groupStats(stats), ACLs: make(map[string]ACLObservation), Mounts: []MountObservation{{MountPoint: "/", EvidenceIDs: []string{"e-mount"}}}}
	for _, stat := range stats {
		set.ACLs[stat.Path] = ACLObservation{Path: stat.Path, Status: ObservationComplete, EvidenceIDs: []string{"e-acl"}}
	}
	return set
}
