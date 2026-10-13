package benchmark

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/normalone/lpeco/internal/collect/packageinfo"
	"github.com/normalone/lpeco/internal/model"
	reportpkg "github.com/normalone/lpeco/internal/report"
)

const maxImportBytes int64 = 64 << 20

func ImportLPECO(reader io.Reader, run RunIdentity) ([]Observation, error) {
	if err := validateImportRun(run); err != nil {
		return nil, err
	}
	if run.ToolID != "lpeco" {
		return nil, fmt.Errorf("LPECO importer requires tool ID lpeco, got %q", run.ToolID)
	}
	body, err := readImportArtifact(reader)
	if err != nil {
		return nil, err
	}
	if err := validateImportJSONHygiene(body); err != nil {
		return nil, err
	}
	var document reportpkg.Document
	if err := decodeStrictImportJSON(body, &document); err != nil {
		return nil, fmt.Errorf("decode LPECO report: %w", err)
	}
	if document.SchemaVersion != 2 || document.Session.SchemaVersion != model.SessionSchemaVersion {
		return nil, fmt.Errorf("LPECO report/session schema must both be 2")
	}
	if document.Session.Target != "" && document.Session.Target != "[REDACTED]" {
		return nil, errors.New("LPECO report contains a target host identifier")
	}
	if document.Session.TransportKind != run.Transport {
		return nil, fmt.Errorf("LPECO transport %q does not match run %q", document.Session.TransportKind, run.Transport)
	}
	distribution := document.Session.Profile.Distribution
	if distribution.ID != run.DistributionID || distribution.VersionID != run.Release {
		return nil, errors.New("LPECO distribution/release does not match run identity")
	}
	coverage := document.KnownVulnerabilities.Coverage
	if err := validateLPECOCoverage(coverage, run); err != nil {
		return nil, err
	}
	if err := compareCoverage(document.Session.Vulnerability, coverage); err != nil {
		return nil, err
	}

	switch coverage.Status {
	case model.VulnerabilityCoverageUnsupported:
		return []Observation{newLPECOObservation(run, coverage, "unsupported", "none", "none", "", "", []string{"coverage-unsupported"})}, nil
	case model.VulnerabilityCoverageIncomplete:
		return []Observation{newLPECOObservation(run, coverage, "unknown", "unknown", "none", "", "", append([]string{"coverage-incomplete"}, diagnosticCodes(coverage.Diagnostics)...))}, nil
	case model.VulnerabilityCoverageNotRun, model.VulnerabilityCoverageDisabled, model.VulnerabilityCoverageLegacyNotRequested:
		return []Observation{newLPECOObservation(run, coverage, "unknown", "unknown", "none", "", "", []string{"coverage-not-run"})}, nil
	case model.VulnerabilityCoverageComplete:
	default:
		return nil, fmt.Errorf("LPECO report has unsupported coverage status %q", coverage.Status)
	}

	evidenceIDs, nodeRefs, err := lpecoReportReferences(document)
	if err != nil {
		return nil, err
	}
	matches := document.KnownVulnerabilities.Matches
	matchIDs := make(map[string]model.VulnerabilityMatch, len(matches))
	var packageName, packageVersion string
	state := "none"
	for index, match := range matches {
		if match.ID == "" {
			return nil, fmt.Errorf("LPECO match %d has an empty ID", index)
		}
		if _, duplicate := matchIDs[match.ID]; duplicate {
			return nil, fmt.Errorf("duplicate LPECO match ID %q", match.ID)
		}
		if !sameDigest(match.SnapshotDigest, run.AdvisorySnapshotDigest) || match.DistributionID != run.DistributionID || match.Release != run.Release {
			return nil, fmt.Errorf("LPECO match %q does not match pinned snapshot/release identity", match.ID)
		}
		if match.BinaryPackage == "" || match.BinaryVersion.Raw == "" {
			return nil, fmt.Errorf("LPECO match %q lacks exact binary package/version context", match.ID)
		}
		if match.BinaryPackage != run.Package || match.BinaryVersion.Raw != run.PackageVersion {
			return nil, fmt.Errorf("LPECO match %q package/version does not match run identity", match.ID)
		}
		if packageName == "" {
			packageName, packageVersion = match.BinaryPackage, match.BinaryVersion.Raw
		} else if packageName != match.BinaryPackage || packageVersion != match.BinaryVersion.Raw {
			return nil, errors.New("LPECO report contains multiple package/version contexts for one benchmark run")
		}
		switch match.State {
		case model.VulnerabilityStateAffected:
			state = "affected"
		case model.VulnerabilityStateUnknown:
			if state != "affected" {
				state = "unknown"
			}
		case model.VulnerabilityStateFixed:
			if state == "none" || state == "not_affected" {
				state = "fixed"
			}
		case model.VulnerabilityStateNotAffected:
			if state == "none" {
				state = "not_affected"
			}
		default:
			return nil, fmt.Errorf("LPECO match %q has unsupported state %q", match.ID, match.State)
		}
		matchIDs[match.ID] = match
	}
	if state == "none" {
		packageName, packageVersion, err = lpecoInstalledPackageContext(document.Facts, evidenceIDs, run)
		if err != nil {
			return nil, err
		}
	}

	tier := "none"
	related := make(map[string]struct{})
	candidateIDs := make(map[string]struct{})
	for _, candidate := range document.Candidates {
		if candidate.RuleID != "vulnerability.known-privilege-path" {
			continue
		}
		if _, duplicate := candidateIDs[candidate.ID]; duplicate {
			return nil, fmt.Errorf("duplicate known-vulnerability candidate ID %q", candidate.ID)
		}
		candidateIDs[candidate.ID] = struct{}{}
		if candidate.Category != "known-vulnerability" {
			return nil, fmt.Errorf("known-vulnerability candidate %q has category %q", candidate.ID, candidate.Category)
		}
		if err := candidate.Validate(); err != nil {
			return nil, fmt.Errorf("validate known-vulnerability candidate %q: %w", candidate.ID, err)
		}
		if err := validateCandidateReferences(candidate, evidenceIDs, nodeRefs); err != nil {
			return nil, err
		}
		for _, id := range candidate.RelatedMatchIDs {
			match, exists := matchIDs[id]
			if !exists {
				return nil, fmt.Errorf("known-vulnerability candidate %q references missing match %q", candidate.ID, id)
			}
			if match.State != model.VulnerabilityStateAffected || match.Confidence != model.ConfidenceHigh || len(match.MissingFacts) != 0 {
				return nil, fmt.Errorf("known-vulnerability candidate %q references non-exact affected match %q", candidate.ID, id)
			}
			related[id] = struct{}{}
		}
		switch candidate.Priority {
		case model.PriorityP1:
			tier = "P1"
		case model.PriorityP2:
			if tier != "P1" {
				tier = "P2"
			}
		default:
			return nil, fmt.Errorf("known-vulnerability candidate %q has forbidden priority %q", candidate.ID, candidate.Priority)
		}
	}
	if state == "affected" && len(related) == 0 {
		tier = "match_only"
	}
	if state != "affected" && len(related) > 0 {
		return nil, errors.New("LPECO report joins a non-affected match to a privilege-path candidate")
	}
	outcome := "complete"
	if state == "unknown" {
		outcome = "unknown"
		tier = "none"
	}
	diagnostics := append(diagnosticCodes(coverage.Diagnostics), diagnosticCodes(document.KnownVulnerabilities.Diagnostics)...)
	return []Observation{newLPECOObservation(run, coverage, outcome, state, tier, packageName, packageVersion, diagnostics)}, nil
}

func newLPECOObservation(run RunIdentity, coverage model.VulnerabilityCoverage, outcome, state, tier, packageName, version string, diagnostics []string) Observation {
	observation := newObservation(run, outcome, state, tier, packageName, version, diagnostics)
	observation.CoverageStatus = string(coverage.Status)
	stale := coverage.Snapshot.Stale
	observation.SnapshotStale = &stale
	return observation
}

type lpecoGraphDocument struct {
	Current  *model.NodeRef `json:"current_principal,omitempty"`
	Nodes    []model.Node   `json:"nodes"`
	Edges    []model.Edge   `json:"edges"`
	Facts    []model.Fact   `json:"facts"`
	Variants []struct {
		NodeID     string            `json:"node_id"`
		Attributes []json.RawMessage `json:"attributes"`
	} `json:"conflicting_node_variants,omitempty"`
}

func lpecoReportReferences(document reportpkg.Document) (map[string]model.Evidence, map[string]model.NodeRef, error) {
	evidenceByID := make(map[string]model.Evidence, len(document.Evidence))
	for _, evidence := range document.Evidence {
		if evidence.ID == "" {
			return nil, nil, errors.New("LPECO report contains evidence with an empty ID")
		}
		if _, duplicate := evidenceByID[evidence.ID]; duplicate {
			return nil, nil, fmt.Errorf("duplicate LPECO evidence ID %q", evidence.ID)
		}
		evidenceByID[evidence.ID] = evidence
	}
	var graph lpecoGraphDocument
	if err := decodeStrictImportJSON(document.Graph, &graph); err != nil {
		return nil, nil, fmt.Errorf("decode LPECO report graph: %w", err)
	}
	nodeRefs := make(map[string]model.NodeRef, len(graph.Nodes))
	for _, node := range graph.Nodes {
		if node.ID == "" || node.Kind == "" {
			return nil, nil, errors.New("LPECO report graph contains an incomplete node reference")
		}
		if _, duplicate := nodeRefs[node.ID]; duplicate {
			return nil, nil, fmt.Errorf("duplicate LPECO graph node ID %q", node.ID)
		}
		nodeRefs[node.ID] = node.NodeRef
	}
	return evidenceByID, nodeRefs, nil
}

func validateCandidateReferences(candidate model.Candidate, evidenceByID map[string]model.Evidence, nodeRefs map[string]model.NodeRef) error {
	for _, id := range candidate.EvidenceIDs {
		if _, exists := evidenceByID[id]; !exists {
			return fmt.Errorf("known-vulnerability candidate %q references missing evidence %q", candidate.ID, id)
		}
	}
	references := []model.NodeRef{candidate.CurrentPrincipal, candidate.TargetPrincipal}
	for _, optional := range []*model.NodeRef{candidate.PrivilegedConsumer, candidate.ControlledObject, candidate.Trigger} {
		if optional != nil {
			references = append(references, *optional)
		}
	}
	references = append(references, candidate.PathNodes...)
	for _, reference := range references {
		actual, exists := nodeRefs[reference.ID]
		if !exists || actual.Kind != reference.Kind {
			return fmt.Errorf("known-vulnerability candidate %q references missing or mismatched graph node %q", candidate.ID, reference.ID)
		}
	}
	return nil
}

func lpecoInstalledPackageContext(facts []model.Fact, evidenceByID map[string]model.Evidence, run RunIdentity) (string, string, error) {
	var matched bool
	for _, fact := range facts {
		if fact.Kind != "installed_package" {
			continue
		}
		var installed packageinfo.InstalledPackageFact
		if err := decodeStrictImportJSON(fact.Data, &installed); err != nil {
			return "", "", fmt.Errorf("decode LPECO installed-package fact %q: %w", fact.ID, err)
		}
		if installed.BinaryPackage != run.Package || installed.BinaryVersion.Raw != run.PackageVersion {
			continue
		}
		if matched {
			return "", "", errors.New("LPECO report contains duplicate installed-package context for benchmark run")
		}
		matched = true
		if fact.ObservationStatus != model.ProbeComplete || fact.Confidence != model.ConfidenceHigh || len(fact.MissingFacts) != 0 || len(fact.EvidenceIDs) == 0 ||
			installed.Confidence != model.ConfidenceHigh || !installed.MatchEligible() || len(installed.EvidenceIDs) == 0 ||
			installed.Architecture == "" || installed.SourcePackage == "" || installed.SourceVersion.Raw == "" ||
			!installed.BinaryVersion.Valid || !installed.SourceVersion.Valid {
			return "", "", errors.New("LPECO installed-package context is incomplete or not high confidence")
		}
		for _, ids := range [][]string{fact.EvidenceIDs, installed.EvidenceIDs} {
			for _, id := range ids {
				evidence, exists := evidenceByID[id]
				if !exists {
					return "", "", fmt.Errorf("LPECO installed-package context references missing evidence %q", id)
				}
				if evidence.Status != model.ProbeComplete || evidence.Truncated {
					return "", "", fmt.Errorf("LPECO installed-package context references incomplete evidence %q", id)
				}
			}
		}
	}
	if !matched {
		return "", "", errors.New("complete LPECO zero-match result lacks exact installed-package context")
	}
	return run.Package, run.PackageVersion, nil
}

func validateLPECOCoverage(coverage model.VulnerabilityCoverage, run RunIdentity) error {
	if coverage.SelectedRelease != run.Release {
		return errors.New("LPECO coverage release does not match run identity")
	}
	hasSnapshot := coverage.Snapshot.Digest != "" || coverage.Snapshot.ImpactCatalogDigest != ""
	requiresSnapshot := coverage.Status == model.VulnerabilityCoverageComplete || coverage.Status == model.VulnerabilityCoverageUnsupported
	forbidsSnapshot := coverage.Status == model.VulnerabilityCoverageNotRun || coverage.Status == model.VulnerabilityCoverageDisabled || coverage.Status == model.VulnerabilityCoverageLegacyNotRequested
	if requiresSnapshot && !hasSnapshot {
		return errors.New("LPECO coverage status requires a pinned snapshot")
	}
	if forbidsSnapshot && hasSnapshot {
		return errors.New("LPECO non-run coverage unexpectedly claims a snapshot")
	}
	if hasSnapshot {
		if !sameDigest(coverage.Snapshot.Digest, run.AdvisorySnapshotDigest) {
			return errors.New("LPECO coverage snapshot digest does not match run identity")
		}
		if !sameDigest(coverage.Snapshot.ImpactCatalogDigest, run.ImpactCatalogDigest) {
			return errors.New("LPECO coverage impact-catalog digest does not match run identity")
		}
	}
	return nil
}

func compareCoverage(session, report model.VulnerabilityCoverage) error {
	if session.Status != report.Status || session.SelectedRelease != report.SelectedRelease ||
		!sameDigest(session.Snapshot.Digest, report.Snapshot.Digest) ||
		!sameDigest(session.Snapshot.ImpactCatalogDigest, report.Snapshot.ImpactCatalogDigest) ||
		session.Snapshot.Stale != report.Snapshot.Stale {
		return errors.New("LPECO session and report coverage identities disagree")
	}
	return nil
}

func diagnosticCodes(values []model.VulnerabilityDiagnostic) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, sanitizeDiagnosticCode(value.Code))
	}
	return canonicalStrings(result)
}

func readImportArtifact(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("import reader is required")
	}
	body, err := io.ReadAll(io.LimitReader(reader, maxImportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read import artifact: %w", err)
	}
	if int64(len(body)) > maxImportBytes {
		return nil, fmt.Errorf("import artifact exceeds %d-byte limit", maxImportBytes)
	}
	return body, nil
}

func validateImportJSONHygiene(body []byte) error {
	value, err := decodeGenericDocument(body)
	if err != nil {
		return err
	}
	return validateHygiene(value, nil)
}

func decodeStrictImportJSON(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func validateImportRun(run RunIdentity) error {
	for label, value := range map[string]string{
		"run ID": run.ID, "tool ID": run.ToolID, "scenario ID": run.ScenarioID,
	} {
		if err := validateIdentifier(label, value); err != nil {
			return err
		}
	}
	for label, value := range map[string]string{
		"tool name": run.ToolName, "tool version": run.ToolVersion, "transport": run.Transport,
		"distribution ID": run.DistributionID, "release": run.Release, "package class": run.PackageClass,
		"package": run.Package, "package version": run.PackageVersion,
		"scenario class": run.ScenarioClass, "acquisition": run.Acquisition,
	} {
		if err := validateExactValue(label, value); err != nil {
			return err
		}
		if err := validateHygieneString(value); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
	}
	for label, value := range map[string]string{
		"tool": run.ToolSHA256, "image": run.ImageDigest, "advisory snapshot": run.AdvisorySnapshotDigest,
		"impact catalog": run.ImpactCatalogDigest,
	} {
		if err := validateDigest(label, value); err != nil {
			return err
		}
	}
	if !oneOf(run.Transport, "ssh", "raw-listen", "stdio-raw", "c2-plugin", "offline", "manual") {
		return fmt.Errorf("unsupported import transport %q", run.Transport)
	}
	if !oneOf(run.Acquisition, "native", "preproduced", "manual") {
		return fmt.Errorf("unsupported import acquisition %q", run.Acquisition)
	}
	if run.PackageClass != "userspace" && run.PackageClass != "kernel" {
		return fmt.Errorf("unsupported import package class %q", run.PackageClass)
	}
	return nil
}

func newObservation(run RunIdentity, outcome, state, tier, packageName, version string, diagnostics []string) Observation {
	diagnostics = canonicalStrings(diagnostics)
	sum := sha256.Sum256([]byte(strings.Join([]string{
		run.ID, run.ToolID, run.ScenarioID, outcome, state, tier, packageName, version,
	}, "\x00")))
	return Observation{
		SchemaVersion: 1, ID: "observation-" + hex.EncodeToString(sum[:16]), RunID: run.ID, RunIdentitySHA256: RunIdentityDigest(run),
		ScenarioID: run.ScenarioID, ToolID: run.ToolID, Outcome: outcome, MatchState: state,
		PathTier: tier, Package: packageName, Version: version, Release: run.Release,
		CoverageStatus:      CoverageUnavailable,
		ResourceMeasurement: MeasurementUnavailable, SafetyMeasurement: MeasurementUnavailable,
		MeasurementProvenance: "import-contract-unavailable",
		DiagnosticCodes:       diagnostics,
	}
}

func sameDigest(first, second string) bool {
	return strings.TrimPrefix(first, "sha256:") == strings.TrimPrefix(second, "sha256:")
}

func sanitizeDiagnosticCode(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastDash := false
	for _, character := range value {
		valid := character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '_'
		if valid {
			builder.WriteRune(character)
			lastDash = false
			continue
		}
		if !lastDash && builder.Len() > 0 {
			builder.WriteByte('-')
			lastDash = true
		}
	}
	result := strings.Trim(builder.String(), "-")
	if result == "" {
		return "tool-diagnostic"
	}
	return result
}
