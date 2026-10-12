package probe

import (
	"fmt"
	"sort"
	"strings"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/model"
)

const (
	ReasonAllowed      = "allowed"
	ReasonNeedsOptIn   = "observable-read-needs-opt-in"
	ReasonForbidden    = "forbidden-safety-class"
	ReasonCompleted    = "completed"
	ReasonRetryLimit   = "retry-limit"
	ReasonNotRetryable = "not-retryable"
)

type Policy struct {
	AllowObservable bool
}

type Decision struct {
	Run           bool
	RequiresOptIn bool
	Reason        string
	Err           error
}

type Planner interface {
	Select(Definition, adapter.Capabilities, model.HostProfile, Policy) (Variant, error)
	ShouldRun(Definition, model.Checkpoint, Policy) Decision
}

type planner struct{}

func NewPlanner() Planner {
	return planner{}
}

func (planner) Select(definition Definition, capabilities adapter.Capabilities, profile model.HostProfile, _ Policy) (Variant, error) {
	if err := definition.validate(); err != nil {
		return Variant{}, err
	}
	if !requirementsMet(definition.Requirements, capabilities, profile) {
		return Variant{}, fmt.Errorf("%w: requirements for probe %q", adapter.ErrUnsupported, definition.ID)
	}
	tooLarge := false
	for _, variant := range definition.Variants {
		if !requirementsMet(variant.Requirements, capabilities, profile) {
			continue
		}
		rendered, err := adapter.RenderPOSIX(variant.Command)
		if err != nil {
			return Variant{}, err
		}
		if capabilities.MaxCommandBytes > 0 && len(rendered) > capabilities.MaxCommandBytes {
			tooLarge = true
			continue
		}
		variant.MaxOutput = definition.MaxOutput
		if capabilities.MaxOutputBytes > 0 && variant.MaxOutput > capabilities.MaxOutputBytes {
			variant.MaxOutput = capabilities.MaxOutputBytes
		}
		return variant, nil
	}
	if tooLarge {
		return Variant{}, fmt.Errorf("%w: probe %q has no variant within limit", adapter.ErrCommandTooLarge, definition.ID)
	}
	return Variant{}, fmt.Errorf("%w: no supported variant for probe %q", adapter.ErrUnsupported, definition.ID)
}

func (planner) ShouldRun(definition Definition, checkpoint model.Checkpoint, policy Policy) Decision {
	switch definition.SafetyClass {
	case model.PassiveRead, model.ObservableRead:
	case model.TemporaryArtifact, model.StateChanging:
		return Decision{Reason: ReasonForbidden, Err: fmt.Errorf("%w: %s", ErrUnsafeProbe, definition.SafetyClass)}
	default:
		return Decision{Reason: ReasonForbidden, Err: fmt.Errorf("%w: unknown class %q", ErrUnsafeProbe, definition.SafetyClass)}
	}

	for _, completed := range checkpoint.Completed {
		if completed.ProbeID == definition.ID && completed.Status == model.ProbeComplete {
			return Decision{Reason: ReasonCompleted}
		}
	}
	retried := false
	for key, attempts := range checkpoint.RetryCounts {
		if (key == definition.ID || strings.HasPrefix(key, definition.ID+"|")) && attempts >= 1 {
			retried = true
			break
		}
	}
	if retried {
		if !definition.Idempotent {
			return Decision{Reason: ReasonNotRetryable}
		}
		return Decision{Reason: ReasonRetryLimit}
	}
	if definition.SafetyClass == model.ObservableRead && !policy.AllowObservable {
		return Decision{RequiresOptIn: true, Reason: ReasonNeedsOptIn}
	}
	return Decision{Run: true, Reason: ReasonAllowed}
}

func PreviewObservable(definitions []Definition, checkpoint model.Checkpoint) []string {
	ids := make([]string, 0)
	planner := planner{}
	for _, definition := range definitions {
		decision := planner.ShouldRun(definition, checkpoint, Policy{})
		if decision.RequiresOptIn {
			ids = append(ids, definition.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

func requirementsMet(requirements []Requirement, capabilities adapter.Capabilities, profile model.HostProfile) bool {
	for _, requirement := range requirements {
		var met bool
		switch requirement {
		case RequireInteractive:
			met = capabilities.Interactive
		case RequireTTY:
			met = capabilities.TTY
		case RequireReliableExitStatus:
			met = capabilities.ReliableExitStatus
		case RequireSeparateStderr:
			met = capabilities.SeparateStderr
		case RequireAsyncTasks:
			met = capabilities.AsyncTasks
		case RequireCancel:
			met = capabilities.Cancel
		case RequireSystemd:
			met = profile.SystemdRunning
		default:
			name, found := strings.CutPrefix(string(requirement), "command:")
			met = found && name != "" && profile.AvailableCommands[name]
		}
		if !met {
			return false
		}
	}
	return true
}

var _ Planner = planner{}
