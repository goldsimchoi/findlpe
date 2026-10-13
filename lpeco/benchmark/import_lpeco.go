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
		return []Observation{newObservation(run, "unsupported", "none", "none", "", "", []string{"coverage-unsupported"})}, nil
	case model.VulnerabilityCoverageIncomplete:
		return []Observation{newObservation(run, "unknown", "unknown", "none", "", "", append([]string{"coverage-incomplete"}, diagnosticCodes(coverage.Diagnostics)...))}, nil
	case model.VulnerabilityCoverageNotRun, model.VulnerabilityCoverageDisabled, model.VulnerabilityCoverageLegacyNotRequested:
		return []Observation{newObservation(run, "unknown", "unknown", "none", "", "", []string{"coverage-not-run"})}, nil
	case model.VulnerabilityCoverageComplete:
	default:
		return nil, fmt.Errorf("LPECO report has unsupported coverage status %q", coverage.Status)
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

	tier := "none"
	related := make(map[string]struct{})
	for _, candidate := range document.Candidates {
		if candidate.RuleID != "vulnerability.known-privilege-path" {
			continue
		}
		if len(candidate.RelatedMatchIDs) == 0 {
			return nil, fmt.Errorf("known-vulnerability candidate %q has no related match IDs", candidate.ID)
		}
		for _, id := range candidate.RelatedMatchIDs {
			if _, exists := matchIDs[id]; !exists {
				return nil, fmt.Errorf("known-vulnerability candidate %q references missing match %q", candidate.ID, id)
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
	return []Observation{newObservation(run, outcome, state, tier, packageName, packageVersion, diagnostics)}, nil
}

func validateLPECOCoverage(coverage model.VulnerabilityCoverage, run RunIdentity) error {
	if coverage.SelectedRelease != run.Release {
		return errors.New("LPECO coverage release does not match run identity")
	}
	if !sameDigest(coverage.Snapshot.Digest, run.AdvisorySnapshotDigest) {
		return errors.New("LPECO coverage snapshot digest does not match run identity")
	}
	if !sameDigest(coverage.Snapshot.ImpactCatalogDigest, run.ImpactCatalogDigest) {
		return errors.New("LPECO coverage impact-catalog digest does not match run identity")
	}
	return nil
}

func compareCoverage(session, report model.VulnerabilityCoverage) error {
	if session.Status != report.Status || session.SelectedRelease != report.SelectedRelease ||
		!sameDigest(session.Snapshot.Digest, report.Snapshot.Digest) ||
		!sameDigest(session.Snapshot.ImpactCatalogDigest, report.Snapshot.ImpactCatalogDigest) {
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
		SchemaVersion: 1, ID: "observation-" + hex.EncodeToString(sum[:16]), RunID: run.ID,
		ScenarioID: run.ScenarioID, ToolID: run.ToolID, Outcome: outcome, MatchState: state,
		PathTier: tier, Package: packageName, Version: version, Release: run.Release,
		DiagnosticCodes: diagnostics,
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
