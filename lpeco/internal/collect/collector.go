package collect

import (
	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

type Discovery struct {
	HighValuePIDs      []int
	HighValueProcesses []ProcessIdentity
	ReferencedPaths    []string
	UnitNames          []string
	Mounts             []Mount
}

type ProcessIdentity struct {
	PID       int    `json:"pid"`
	StartTime uint64 `json:"start_time"`
}

type Mount struct {
	ID         int    `json:"id"`
	MajorMinor string `json:"major_minor"`
	Root       string `json:"root"`
	MountPoint string `json:"mount_point"`
	Bind       bool   `json:"bind"`
	Remote     bool   `json:"remote"`
	Pseudo     bool   `json:"pseudo"`
}

type Collector interface {
	ID() string
	Plan(model.HostProfile, Discovery) []probe.Definition
	Parse(probe.Definition, adapter.ExecResult, string) ([]model.Fact, error)
}

// ObservationAssessment lets a collector conservatively reclassify a
// transport-successful observation and request the next passive variant.
// It is intentionally optional; the orchestrator remains the sole executor.
type ObservationAssessment struct {
	Status   model.ProbeStatus
	Fallback bool
}

type ObservationAssessor interface {
	Assess(probe.Definition, probe.Variant, adapter.ExecResult) ObservationAssessment
}
