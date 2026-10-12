package probe

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/model"
)

var (
	ErrUnsafeProbe    = errors.New("probe safety class is denied")
	ErrDuplicateProbe = errors.New("duplicate probe ID")
	ErrInvalidProbe   = errors.New("invalid probe definition")
)

type Requirement string

const (
	RequireInteractive        Requirement = "capability:interactive"
	RequireTTY                Requirement = "capability:tty"
	RequireReliableExitStatus Requirement = "capability:reliable-exit-status"
	RequireSeparateStderr     Requirement = "capability:separate-stderr"
	RequireAsyncTasks         Requirement = "capability:async-tasks"
	RequireCancel             Requirement = "capability:cancel"
	RequireSystemd            Requirement = "host:systemd"
)

func CommandRequirement(name string) Requirement {
	return Requirement("command:" + name)
}

type Variant struct {
	ID           string          `json:"id"`
	Command      adapter.Command `json:"command"`
	Requirements []Requirement   `json:"requirements,omitempty"`
	MaxOutput    int             `json:"max_output,omitempty"`
}

type Definition struct {
	ID              string            `json:"id"`
	Collector       string            `json:"collector"`
	Parser          string            `json:"parser"`
	RedactionPolicy string            `json:"redaction_policy"`
	SafetyClass     model.SafetyClass `json:"safety_class"`
	Requirements    []Requirement     `json:"requirements,omitempty"`
	Variants        []Variant         `json:"variants"`
	Timeout         time.Duration     `json:"timeout"`
	MaxOutput       int               `json:"max_output"`
	Produces        []string          `json:"produces"`
	Idempotent      bool              `json:"idempotent"`
}

func (d Definition) validate() error {
	if strings.TrimSpace(d.ID) == "" || strings.TrimSpace(d.Collector) == "" || strings.TrimSpace(d.Parser) == "" {
		return fmt.Errorf("%w: ID, collector and parser are required", ErrInvalidProbe)
	}
	switch d.SafetyClass {
	case model.PassiveRead, model.ObservableRead, model.TemporaryArtifact, model.StateChanging:
	default:
		return fmt.Errorf("%w: unknown safety class %q", ErrInvalidProbe, d.SafetyClass)
	}
	if d.Timeout <= 0 || d.MaxOutput <= 0 {
		return fmt.Errorf("%w: positive timeout and max output are required", ErrInvalidProbe)
	}
	if len(d.Variants) == 0 {
		return fmt.Errorf("%w: at least one variant is required", ErrInvalidProbe)
	}
	seen := make(map[string]struct{}, len(d.Variants))
	for _, variant := range d.Variants {
		if strings.TrimSpace(variant.ID) == "" {
			return fmt.Errorf("%w: variant ID is required", ErrInvalidProbe)
		}
		if _, ok := seen[variant.ID]; ok {
			return fmt.Errorf("%w: duplicate variant ID %q", ErrInvalidProbe, variant.ID)
		}
		seen[variant.ID] = struct{}{}
		if _, err := adapter.RenderPOSIX(variant.Command); err != nil {
			return fmt.Errorf("%w: variant %q: %v", ErrInvalidProbe, variant.ID, err)
		}
	}
	return nil
}
