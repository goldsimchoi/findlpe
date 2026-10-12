package path

import (
	"fmt"

	"github.com/normalone/lpeco/internal/model"
)

type UseKind string

const (
	UseWrite             UseKind = "write"
	UseReplace           UseKind = "replace"
	UseNativeExecute     UseKind = "native_execute"
	UseInterpretedScript UseKind = "interpreted_script"
	UseSetIDExecute      UseKind = "setid_execute"

	UseFileWrite        = UseWrite
	UseFileReplace      = UseReplace
	UseNativeExecutable = UseNativeExecute
	UseSUIDExecutable   = UseSetIDExecute
)

type ControlState string

const (
	ControlAllowed ControlState = "allowed"
	ControlDenied  ControlState = "denied"
	ControlUnknown ControlState = "unknown"
)

type ControlAssessment struct {
	UseKind        UseKind           `json:"use_kind"`
	State          ControlState      `json:"state"`
	Controlled     bool              `json:"controlled"`
	DirectWrite    bool              `json:"direct_write"`
	Replaceable    bool              `json:"replaceable"`
	Executable     bool              `json:"executable"`
	SetIDEffective bool              `json:"setid_effective"`
	Mount          *MountObservation `json:"mount,omitempty"`
	EvidenceIDs    []string          `json:"evidence_ids"`
	MissingFacts   []string          `json:"missing_facts"`
	Confidence     model.Confidence  `json:"confidence"`
}

func EvaluateControl(principal model.Principal, resolution Resolution, use UseKind) ControlAssessment {
	assessment := ControlAssessment{UseKind: use, State: ControlUnknown, Confidence: model.ConfidenceLow, EvidenceIDs: append([]string(nil), resolution.EvidenceIDs...)}
	if !validUseKind(use) {
		assessment.MissingFacts = append(assessment.MissingFacts, "unknown use kind")
		return assessment
	}
	if !resolution.Complete || resolution.Final == nil {
		assessment.MissingFacts = append(assessment.MissingFacts, resolution.MissingFacts...)
		if len(assessment.MissingFacts) == 0 {
			assessment.MissingFacts = append(assessment.MissingFacts, "path resolution incomplete")
		}
		return assessment
	}

	mount, mountKnown := MountForPath(resolution.FinalPath, resolution.observations.Mounts)
	if !mountKnown {
		assessment.MissingFacts = append(assessment.MissingFacts, "mount evidence unavailable for "+resolution.FinalPath)
		return assessment
	}
	assessment.Mount = &mount
	assessment.EvidenceIDs = appendUniqueStrings(assessment.EvidenceIDs, mount.EvidenceIDs...)

	if use == UseWrite || use == UseReplace {
		if mount.ReadOnly {
			return deniedAssessment(assessment, "target is on a read-only mount")
		}
	}
	if use == UseNativeExecute && mount.NoExec {
		return deniedAssessment(assessment, "native execution is blocked by noexec")
	}
	if use == UseSetIDExecute && mount.NoSUID {
		return deniedAssessment(assessment, "set-ID transition is blocked by nosuid")
	}

	for _, parent := range resolution.Parents {
		parentMount, ok := MountForPath(parent.Path, resolution.observations.Mounts)
		if !ok {
			assessment.MissingFacts = append(assessment.MissingFacts, "mount evidence unavailable for parent "+parent.Path)
			return assessment
		}
		assessment.EvidenceIDs = appendUniqueStrings(assessment.EvidenceIDs, parentMount.EvidenceIDs...)
		acl, ok := resolution.observations.ACLs[parent.Path]
		if !ok {
			assessment.MissingFacts = append(assessment.MissingFacts, "ACL evidence unavailable for parent "+parent.Path)
			return assessment
		}
		assessment.EvidenceIDs = appendUniqueStrings(assessment.EvidenceIDs, acl.EvidenceIDs...)
		permissions, known := EffectivePermissions(principal, parent, acl)
		if !known {
			assessment.MissingFacts = append(assessment.MissingFacts, "ACL access unknown for parent "+parent.Path)
			return assessment
		}
		if !permissions.Execute {
			return deniedAssessment(assessment, "principal cannot traverse parent "+parent.Path)
		}
	}

	targetACL, ok := resolution.observations.ACLs[resolution.FinalPath]
	if !ok {
		assessment.MissingFacts = append(assessment.MissingFacts, "ACL evidence unavailable for target "+resolution.FinalPath)
		return assessment
	}
	assessment.EvidenceIDs = appendUniqueStrings(assessment.EvidenceIDs, targetACL.EvidenceIDs...)
	targetPermissions, known := EffectivePermissions(principal, *resolution.Final, targetACL)
	if !known {
		assessment.MissingFacts = append(assessment.MissingFacts, "ACL access unknown for target "+resolution.FinalPath)
		return assessment
	}

	assessment.Executable = targetPermissions.Execute
	if use == UseInterpretedScript {
		assessment.Executable = targetPermissions.Read
	}
	assessment.SetIDEffective = assessment.Executable && resolution.Final.Mode&(0o4000|0o2000) != 0 && !mount.NoSUID

	switch use {
	case UseWrite:
		assessment.DirectWrite = targetPermissions.Write
		assessment.Replaceable, known = replacementAllowed(principal, resolution, &assessment)
		if !known {
			return assessment
		}
		assessment.Controlled = assessment.DirectWrite || assessment.Replaceable
	case UseReplace:
		assessment.DirectWrite = targetPermissions.Write
		assessment.Replaceable, known = replacementAllowed(principal, resolution, &assessment)
		if !known {
			return assessment
		}
		assessment.Controlled = assessment.Replaceable
	case UseNativeExecute, UseInterpretedScript:
		assessment.Controlled = assessment.Executable
	case UseSetIDExecute:
		assessment.Controlled = assessment.SetIDEffective
	}
	if assessment.Controlled {
		assessment.State = ControlAllowed
	} else {
		assessment.State = ControlDenied
	}
	assessment.Confidence = model.ConfidenceHigh
	assessment.EvidenceIDs = uniqueStrings(assessment.EvidenceIDs)
	assessment.MissingFacts = uniqueStrings(assessment.MissingFacts)
	return assessment
}

func replacementAllowed(principal model.Principal, resolution Resolution, assessment *ControlAssessment) (bool, bool) {
	if len(resolution.Parents) == 0 {
		return false, true
	}
	parent := resolution.Parents[len(resolution.Parents)-1]
	parentMount, ok := MountForPath(parent.Path, resolution.observations.Mounts)
	if !ok {
		assessment.MissingFacts = append(assessment.MissingFacts, "mount evidence unavailable for containing directory "+parent.Path)
		return false, false
	}
	if parentMount.ReadOnly {
		return false, true
	}
	acl, ok := resolution.observations.ACLs[parent.Path]
	if !ok {
		assessment.MissingFacts = append(assessment.MissingFacts, "ACL evidence unavailable for containing directory "+parent.Path)
		return false, false
	}
	permissions, known := EffectivePermissions(principal, parent, acl)
	if !known {
		assessment.MissingFacts = append(assessment.MissingFacts, "ACL access unknown for containing directory "+parent.Path)
		return false, false
	}
	if !permissions.Write || !permissions.Execute {
		return false, true
	}
	if parent.Mode&0o1000 != 0 && principal.UID != 0 && principal.UID != parent.UID && principal.UID != resolution.Final.UID && !hasCapability(principal, "CAP_FOWNER") {
		assessment.MissingFacts = append(assessment.MissingFacts, "sticky directory prevents replacement by this principal")
		return false, true
	}
	return true, true
}

func deniedAssessment(assessment ControlAssessment, reason string) ControlAssessment {
	assessment.State = ControlDenied
	assessment.Controlled = false
	assessment.Confidence = model.ConfidenceHigh
	assessment.MissingFacts = append(assessment.MissingFacts, reason)
	assessment.EvidenceIDs = uniqueStrings(assessment.EvidenceIDs)
	return assessment
}

func validUseKind(use UseKind) bool {
	switch use {
	case UseWrite, UseReplace, UseNativeExecute, UseInterpretedScript, UseSetIDExecute:
		return true
	default:
		return false
	}
}

func (assessment ControlAssessment) String() string {
	return fmt.Sprintf("%s: %s", assessment.UseKind, assessment.State)
}
