package collect

import (
	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

type Discovery struct {
	HighValuePIDs   []int
	ReferencedPaths []string
	UnitNames       []string
}

type Collector interface {
	ID() string
	Plan(model.HostProfile, Discovery) []probe.Definition
	Parse(probe.Definition, adapter.ExecResult, string) ([]model.Fact, error)
}
