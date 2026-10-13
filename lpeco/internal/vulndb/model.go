package vulndb

import (
	"time"

	"github.com/normalone/lpeco/internal/model"
)

// SnapshotSchemaVersion is the only immutable database layout understood by
// this release.
const SnapshotSchemaVersion = 1

// SnapshotStaleAfter is the age at which a validated snapshot is reported as
// stale. Staleness does not alter vulnerability state.
const SnapshotStaleAfter = 7 * 24 * time.Hour

const (
	ProviderStatusAffected           = "affected"
	ProviderStatusFixed              = "fixed"
	ProviderStatusNotAffected        = "not_affected"
	ProviderStatusUnderInvestigation = "under_investigation"
)

// Source records one official provider artifact used to build a snapshot.
type Source struct {
	Kind               string    `json:"kind"`
	URL                string    `json:"url"`
	ETag               string    `json:"etag,omitempty"`
	LastModified       string    `json:"last_modified,omitempty"`
	SHA256             string    `json:"sha256,omitempty"`
	ProviderModifiedAt time.Time `json:"provider_modified_at,omitempty"`
}

// UbuntuRelease is one reviewed standard Ubuntu release accepted by the v1
// normalizer.
type UbuntuRelease struct {
	VersionID string `json:"version_id"`
	Codename  string `json:"codename"`
	Channel   string `json:"channel"`
}

// ReleasePolicy is reviewed provider configuration, not advisory evidence.
type ReleasePolicy struct {
	SchemaVersion int             `json:"schema_version"`
	Provider      string          `json:"provider"`
	ReviewedAt    time.Time       `json:"reviewed_at"`
	Releases      []UbuntuRelease `json:"releases"`
}

// Manifest identifies and validates the semantic content of an immutable
// advisory snapshot.
type Manifest struct {
	SchemaVersion         int       `json:"schema_version"`
	Provider              string    `json:"provider"`
	Sources               []Source  `json:"sources"`
	RetrievedAt           time.Time `json:"retrieved_at"`
	MaxProviderModifiedAt time.Time `json:"max_provider_modified_at,omitempty"`
	NormalizerVersion     string    `json:"normalizer_version"`
	AdvisoryCount         int       `json:"advisory_count"`
	Digest                string    `json:"digest"`
	SupportedReleases     []string  `json:"supported_releases"`
	SupportedChannels     []string  `json:"supported_channels"`
	ImpactCatalogDigest   string    `json:"impact_catalog_digest"`
}

// AffectedPackage is the exact Ubuntu release and package scope supplied by
// official provider data. Empty boundaries remain explicit unknowns.
type AffectedPackage struct {
	SourcePackage       string            `json:"source_package"`
	BinaryPackages      []string          `json:"binary_packages"`
	Architectures       []string          `json:"architectures,omitempty"`
	IntroducedVersion   string            `json:"introduced_version,omitempty"`
	FixedVersion        string            `json:"fixed_version,omitempty"`
	BinaryFixedVersions map[string]string `json:"binary_fixed_versions,omitempty"`
}

// ProviderStatus is an exact official status supplement for the enclosing
// advisory record's release and package scope.
type ProviderStatus struct {
	Source       string `json:"source"`
	Status       string `json:"status"`
	FixedVersion string `json:"fixed_version,omitempty"`
}

// AdvisoryRecord is the normalized, prose-free unit used by matching.
type AdvisoryRecord struct {
	RecordID           string           `json:"record_id"`
	Provider           string           `json:"provider"`
	VulnerabilityID    string           `json:"vulnerability_id"`
	Release            string           `json:"release"`
	Codename           string           `json:"codename,omitempty"`
	Channel            string           `json:"channel"`
	Affected           AffectedPackage  `json:"affected"`
	ProviderStatuses   []ProviderStatus `json:"provider_statuses,omitempty"`
	CVEIDs             []string         `json:"cve_ids"`
	USNIDs             []string         `json:"usn_ids,omitempty"`
	OfficialReferences []string         `json:"official_references"`
	SeverityMetadata   []string         `json:"severity_metadata,omitempty"`
	ModifiedAt         time.Time        `json:"modified_at,omitempty"`
	Withdrawn          bool             `json:"withdrawn"`
	Diagnostics        []string         `json:"diagnostics,omitempty"`
}

// Snapshot is an in-memory validated immutable database. Directory and Stale
// are derived load metadata and are excluded from the content digest.
type Snapshot struct {
	Manifest          Manifest                 `json:"manifest"`
	Advisories        []AdvisoryRecord         `json:"advisories"`
	ImpactAnnotations []model.ImpactAnnotation `json:"impact_annotations"`
	Directory         string                   `json:"-"`
	Stale             bool                     `json:"-"`
}

// CurrentPointer is the only mutable file in the database root.
type CurrentPointer struct {
	SchemaVersion int    `json:"schema_version"`
	Digest        string `json:"digest"`
}
