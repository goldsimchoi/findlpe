package packageinfo

import (
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

const DefaultMaxItems = 4096

type OwnershipFact struct {
	Path             string           `json:"path"`
	ResolvedPath     string           `json:"resolved_path,omitempty"`
	Manager          string           `json:"manager"`
	Packages         []string         `json:"packages"`
	ObservedPackages []string         `json:"observed_packages,omitempty"`
	ResolvedPackages []string         `json:"resolved_packages,omitempty"`
	Owned            bool             `json:"owned"`
	Ambiguous        bool             `json:"ambiguous"`
	EvidenceIDs      []string         `json:"evidence_ids"`
	MissingFacts     []string         `json:"missing_facts,omitempty"`
	Confidence       model.Confidence `json:"confidence"`
}

type InstalledPackageFact struct {
	RequestedPackage string              `json:"requested_package"`
	Manager          string              `json:"manager"`
	Status           string              `json:"status,omitempty"`
	BinaryPackage    string              `json:"binary_package,omitempty"`
	Architecture     string              `json:"architecture,omitempty"`
	BinaryVersion    model.DebianVersion `json:"binary_version"`
	SourcePackage    string              `json:"source_package,omitempty"`
	SourceVersion    model.DebianVersion `json:"source_version"`
	EvidenceIDs      []string            `json:"evidence_ids"`
	MissingFacts     []string            `json:"missing_facts,omitempty"`
	Confidence       model.Confidence    `json:"confidence"`
}

func (fact InstalledPackageFact) MatchEligible() bool {
	return fact.Manager == "dpkg" && fact.Status == "install ok installed" && len(fact.MissingFacts) == 0
}

type Request struct {
	Manager      string   `json:"manager"`
	Package      string   `json:"package"`
	Architecture string   `json:"architecture,omitempty"`
	Paths        []string `json:"paths,omitempty"`
	EvidenceIDs  []string `json:"evidence_ids,omitempty"`
}

type Plan struct {
	Definitions []probe.Definition `json:"definitions"`
	Requested   int                `json:"requested"`
	Omitted     int                `json:"omitted"`
}

type Diagnostic struct {
	Code        string   `json:"code"`
	Message     string   `json:"message"`
	EvidenceIDs []string `json:"evidence_ids"`
}
