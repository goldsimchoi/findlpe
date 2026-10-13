package benchmark

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

type osvScannerDocument struct {
	SchemaVersion int                `json:"schema_version"`
	ScanStatus    string             `json:"scan_status"`
	ErrorCode     string             `json:"error_code,omitempty"`
	Results       []osvScannerResult `json:"results"`
}

type osvScannerResult struct {
	Source   osvScannerSource    `json:"source"`
	Packages []osvScannerPackage `json:"packages"`
}

type osvScannerSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvScannerPackage struct {
	Package         osvScannerPackageIdentity `json:"package"`
	BenchmarkState  string                    `json:"benchmark_state,omitempty"`
	Vulnerabilities []osvScannerVulnerability `json:"vulnerabilities"`
}

type osvScannerPackageIdentity struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvScannerVulnerability struct {
	ID       string               `json:"id"`
	Summary  string               `json:"summary,omitempty"`
	Severity []osvScannerSeverity `json:"severity,omitempty"`
}

type osvScannerSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// ImportOSVScanner converts the pinned benchmark interchange subset into one
// observation. It intentionally does not infer exploitability or a privilege
// path from vulnerability descriptions or severity metadata.
func ImportOSVScanner(reader io.Reader, run RunIdentity) ([]Observation, error) {
	if err := validateImportRun(run); err != nil {
		return nil, err
	}
	if run.ToolID != "osv-scanner" {
		return nil, fmt.Errorf("OSV-Scanner importer requires tool ID osv-scanner, got %q", run.ToolID)
	}
	body, err := readImportArtifact(reader)
	if err != nil {
		return nil, err
	}
	if err := validateImportJSONHygiene(body); err != nil {
		return nil, err
	}
	var document osvScannerDocument
	if err := decodeStrictImportJSON(body, &document); err != nil {
		return nil, fmt.Errorf("decode OSV-Scanner artifact: %w", err)
	}
	if document.SchemaVersion != 1 {
		return nil, fmt.Errorf("OSV-Scanner artifact has unsupported schema %d", document.SchemaVersion)
	}

	if document.ScanStatus != "complete" {
		if !oneOf(document.ScanStatus, "error", "timeout", "crash") {
			return nil, fmt.Errorf("OSV-Scanner artifact has unsupported scan status %q", document.ScanStatus)
		}
		if len(document.Results) != 0 {
			return nil, errors.New("failed OSV-Scanner artifact contains scored results")
		}
		code := sanitizeDiagnosticCode(document.ErrorCode)
		if document.ErrorCode == "" {
			code = "scanner-" + document.ScanStatus
		}
		return []Observation{newObservation(run, document.ScanStatus, "none", "none", "", "", []string{code})}, nil
	}
	if document.ErrorCode != "" {
		return nil, errors.New("complete OSV-Scanner artifact contains an error code")
	}

	var selected *osvScannerPackage
	for resultIndex := range document.Results {
		result := &document.Results[resultIndex]
		if err := validateExactValue("OSV source path", result.Source.Path); err != nil {
			return nil, fmt.Errorf("result %d: %w", resultIndex, err)
		}
		if err := validateExactValue("OSV source type", result.Source.Type); err != nil {
			return nil, fmt.Errorf("result %d: %w", resultIndex, err)
		}
		for packageIndex := range result.Packages {
			if selected != nil {
				return nil, errors.New("OSV-Scanner artifact contains multiple package contexts for one benchmark run")
			}
			selected = &result.Packages[packageIndex]
		}
	}
	if selected == nil {
		return nil, errors.New("complete OSV-Scanner artifact contains no package result")
	}

	identity := selected.Package
	if err := validateExactValue("OSV package name", identity.Name); err != nil {
		return nil, err
	}
	if err := validateExactValue("OSV package version", identity.Version); err != nil {
		return nil, err
	}
	if identity.Name != run.Package || identity.Version != run.PackageVersion {
		return nil, errors.New("OSV package/version does not match run identity")
	}
	wantEcosystem := run.DistributionID + ":" + run.Release
	if !strings.EqualFold(identity.Ecosystem, wantEcosystem) {
		return nil, fmt.Errorf("OSV ecosystem %q does not match run distribution/release %q", identity.Ecosystem, wantEcosystem)
	}

	state := selected.BenchmarkState
	if state == "" {
		if len(selected.Vulnerabilities) > 0 {
			state = "affected"
		} else {
			state = "none"
		}
	}
	if !oneOf(state, "affected", "fixed", "not_affected", "unknown", "none") {
		return nil, fmt.Errorf("OSV package has unsupported benchmark state %q", state)
	}
	if state == "affected" && len(selected.Vulnerabilities) == 0 {
		return nil, errors.New("affected OSV package has no vulnerability identifiers")
	}
	if state != "affected" && len(selected.Vulnerabilities) != 0 {
		return nil, fmt.Errorf("OSV package state %q conflicts with vulnerability results", state)
	}
	seenIDs := make(map[string]struct{}, len(selected.Vulnerabilities))
	for _, vulnerability := range selected.Vulnerabilities {
		if err := validateExactValue("OSV vulnerability ID", vulnerability.ID); err != nil {
			return nil, err
		}
		if _, duplicate := seenIDs[vulnerability.ID]; duplicate {
			return nil, fmt.Errorf("duplicate OSV vulnerability ID %q", vulnerability.ID)
		}
		seenIDs[vulnerability.ID] = struct{}{}
	}

	outcome := "complete"
	if state == "unknown" {
		outcome = "unknown"
	}
	return []Observation{newObservation(run, outcome, state, "none", identity.Name, identity.Version, nil)}, nil
}
