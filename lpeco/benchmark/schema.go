// Package benchmark defines an offline comparison format that is independent
// from LPECO's runtime matching and ranking packages.
package benchmark

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	ManifestSchemaVersion = 1
	CoreGroundTruthPath   = "testdata/known-vulnerability/scenarios.json"
	CoreGroundTruthSHA256 = "sha256:c1a53191b6bb536bc1cfc970c1e79eb0680465b2c2672756c5b1a48c2b35fae1"
	maxManifestBytes      = 8 << 20
)

var (
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	privateIPv4       = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	coreScenarioIDs   = map[string]struct{}{
		"annotated-reachable-p1": {}, "missing-annotation-p2": {}, "missing-reachability-p2": {},
		"affected-match-only": {}, "fixed-package": {}, "explicit-not-affected": {}, "epoch-backport": {},
		"ordinary-user-no-boundary": {}, "ambiguous-ownership-unknown": {}, "truncated-metadata-unknown": {},
		"under-investigation-unknown": {}, "running-kernel-p2": {}, "installed-newer-kernel-not-running": {},
		"unsupported-target": {}, "absent-database": {}, "corrupt-database": {}, "stale-database": {},
		"resume-snapshot-pinning": {},
	}
)

type Manifest struct {
	SchemaVersion          int                 `json:"schema_version"`
	GroundTruth            GroundTruthIdentity `json:"ground_truth"`
	AdvisorySnapshotDigest string              `json:"advisory_snapshot_digest"`
	ImpactCatalogDigest    string              `json:"impact_catalog_digest"`
	Tools                  []ToolIdentity      `json:"tools"`
	Scenarios              []Scenario          `json:"scenarios"`
	Runs                   []RunIdentity       `json:"runs"`
}

type GroundTruthIdentity struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type ToolIdentity struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	Role     string `json:"role"`
	Optional bool   `json:"optional,omitempty"`
	NotRun   bool   `json:"not_run,omitempty"`
}

type Distribution struct {
	ID           string `json:"id"`
	Release      string `json:"release"`
	Channel      string `json:"channel"`
	Architecture string `json:"architecture"`
}

type Scenario struct {
	ID            string         `json:"id"`
	GroundTruthID string         `json:"ground_truth_id"`
	ImageDigest   string         `json:"image_digest"`
	Distribution  Distribution   `json:"distribution"`
	PackageClass  string         `json:"package_class"`
	ScenarioClass string         `json:"scenario_class"`
	Expected      ExpectedResult `json:"expected"`
	DependsOn     []string       `json:"depends_on,omitempty"`
}

type ExpectedResult struct {
	MatchState     string `json:"match_state"`
	PathTier       string `json:"path_tier"`
	CoverageStatus string `json:"coverage_status"`
	Stale          bool   `json:"stale"`
}

// RunIdentity carries every value needed to reproduce one tool/scenario lane.
// Eligible and Diagnostics are derived by validation and are never accepted
// from an artifact.
type RunIdentity struct {
	ID                     string   `json:"id"`
	ToolID                 string   `json:"tool_id"`
	ToolName               string   `json:"tool_name,omitempty"`
	ToolVersion            string   `json:"tool_version,omitempty"`
	ToolSHA256             string   `json:"tool_sha256,omitempty"`
	ScenarioID             string   `json:"scenario_id"`
	ImageDigest            string   `json:"image_digest,omitempty"`
	AdvisorySnapshotDigest string   `json:"advisory_snapshot_digest,omitempty"`
	ImpactCatalogDigest    string   `json:"impact_catalog_digest,omitempty"`
	Transport              string   `json:"transport,omitempty"`
	DistributionID         string   `json:"distribution_id,omitempty"`
	Release                string   `json:"release,omitempty"`
	PackageClass           string   `json:"package_class,omitempty"`
	ScenarioClass          string   `json:"scenario_class,omitempty"`
	Acquisition            string   `json:"acquisition,omitempty"`
	DisposableCommand      []string `json:"disposable_command,omitempty"`
	Optional               bool     `json:"optional,omitempty"`
	Eligible               bool     `json:"-"`
	Diagnostics            []string `json:"-"`
}

// Observation is the deliberately small interchange record consumed by the
// evaluator. Importers populate it without retaining raw scanner evidence.
type Observation struct {
	SchemaVersion   int      `json:"schema_version"`
	ID              string   `json:"id"`
	RunID           string   `json:"run_id"`
	ScenarioID      string   `json:"scenario_id"`
	ToolID          string   `json:"tool_id"`
	Outcome         string   `json:"outcome"`
	MatchState      string   `json:"match_state"`
	PathTier        string   `json:"path_tier"`
	Package         string   `json:"package,omitempty"`
	Version         string   `json:"version,omitempty"`
	Release         string   `json:"release,omitempty"`
	RuntimeMillis   int64    `json:"runtime_millis"`
	RemoteCommands  int64    `json:"remote_commands"`
	OutputBytes     int64    `json:"output_bytes"`
	AdapterFailures int64    `json:"adapter_failures"`
	TargetWrites    int64    `json:"target_writes"`
	TargetEgress    int64    `json:"target_egress"`
	DiagnosticCodes []string `json:"diagnostic_codes,omitempty"`
}

func LoadManifest(reader io.Reader) (Manifest, error) {
	if reader == nil {
		return Manifest{}, errors.New("manifest reader is required")
	}
	body, err := io.ReadAll(io.LimitReader(reader, maxManifestBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	if len(body) > maxManifestBytes {
		return Manifest{}, fmt.Errorf("manifest exceeds %d-byte limit", maxManifestBytes)
	}
	generic, err := decodeGenericDocument(body)
	if err != nil {
		return Manifest{}, err
	}
	if err := validateHygiene(generic, nil); err != nil {
		return Manifest{}, err
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Manifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (manifest *Manifest) Validate() error {
	if manifest == nil {
		return errors.New("manifest is required")
	}
	if err := validateProgrammaticHygiene(*manifest); err != nil {
		return err
	}
	if manifest.SchemaVersion != ManifestSchemaVersion {
		return fmt.Errorf("unsupported manifest schema %d", manifest.SchemaVersion)
	}
	if manifest.GroundTruth.Path != CoreGroundTruthPath || filepath.IsAbs(manifest.GroundTruth.Path) || filepath.Clean(manifest.GroundTruth.Path) != manifest.GroundTruth.Path {
		return fmt.Errorf("ground-truth path %q is not the pinned repository path", manifest.GroundTruth.Path)
	}
	if strings.Contains(manifest.GroundTruth.Path, "..") {
		return fmt.Errorf("ground-truth path %q contains traversal", manifest.GroundTruth.Path)
	}
	if manifest.GroundTruth.SHA256 != CoreGroundTruthSHA256 {
		return fmt.Errorf("ground-truth digest %q does not match the reviewed corpus", manifest.GroundTruth.SHA256)
	}
	if err := validateDigest("advisory snapshot", manifest.AdvisorySnapshotDigest); err != nil {
		return err
	}
	if err := validateDigest("impact catalog", manifest.ImpactCatalogDigest); err != nil {
		return err
	}

	tools := make(map[string]ToolIdentity, len(manifest.Tools))
	for index, tool := range manifest.Tools {
		if err := validateIdentifier("tool ID", tool.ID); err != nil {
			return fmt.Errorf("tool %d: %w", index, err)
		}
		if _, duplicate := tools[tool.ID]; duplicate {
			return fmt.Errorf("duplicate tool ID %q", tool.ID)
		}
		if strings.TrimSpace(tool.Name) == "" {
			return fmt.Errorf("tool %q has an empty name", tool.ID)
		}
		if tool.Role != "product" && tool.Role != "baseline" {
			return fmt.Errorf("tool %q has unsupported role %q", tool.ID, tool.Role)
		}
		if tool.NotRun {
			if !tool.Optional || tool.Role != "baseline" || tool.Version != "" || tool.SHA256 != "" {
				return fmt.Errorf("not-run tool %q must be an unpinned optional baseline", tool.ID)
			}
		} else {
			if err := validateExactValue("tool version", tool.Version); err != nil {
				return fmt.Errorf("tool %q: %w", tool.ID, err)
			}
			if err := validateDigest("tool", tool.SHA256); err != nil {
				return fmt.Errorf("tool %q: %w", tool.ID, err)
			}
		}
		tools[tool.ID] = tool
	}
	if len(tools) == 0 {
		return errors.New("manifest contains no tools")
	}

	scenarios := make(map[string]Scenario, len(manifest.Scenarios))
	groundTruth := make(map[string]string, len(manifest.Scenarios))
	for index, scenario := range manifest.Scenarios {
		if err := validateScenario(index, scenario); err != nil {
			return err
		}
		if _, duplicate := scenarios[scenario.ID]; duplicate {
			return fmt.Errorf("duplicate scenario ID %q", scenario.ID)
		}
		if prior, duplicate := groundTruth[scenario.GroundTruthID]; duplicate {
			return fmt.Errorf("ground-truth scenario %q is referenced by both %q and %q", scenario.GroundTruthID, prior, scenario.ID)
		}
		scenarios[scenario.ID] = scenario
		groundTruth[scenario.GroundTruthID] = scenario.ID
	}
	if len(groundTruth) != len(coreScenarioIDs) {
		return fmt.Errorf("manifest covers %d of %d reviewed ground-truth scenarios", len(groundTruth), len(coreScenarioIDs))
	}
	for id := range coreScenarioIDs {
		if _, found := groundTruth[id]; !found {
			return fmt.Errorf("reviewed ground-truth scenario %q is missing", id)
		}
	}
	if err := validateScenarioDependencies(scenarios); err != nil {
		return err
	}

	runIDs := make(map[string]struct{}, len(manifest.Runs))
	for index := range manifest.Runs {
		run := &manifest.Runs[index]
		if err := validateIdentifier("run ID", run.ID); err != nil {
			return fmt.Errorf("run %d: %w", index, err)
		}
		if _, duplicate := runIDs[run.ID]; duplicate {
			return fmt.Errorf("duplicate run ID %q", run.ID)
		}
		runIDs[run.ID] = struct{}{}
		run.Diagnostics = runDiagnostics(*run, tools, scenarios, *manifest)
		run.Eligible = len(run.Diagnostics) == 0
		if !run.Optional && !run.Eligible {
			return fmt.Errorf("required run %q is not reproducible: %s", run.ID, strings.Join(run.Diagnostics, "; "))
		}
	}
	return nil
}

func validateScenario(index int, scenario Scenario) error {
	if err := validateIdentifier("scenario ID", scenario.ID); err != nil {
		return fmt.Errorf("scenario %d: %w", index, err)
	}
	if _, known := coreScenarioIDs[scenario.GroundTruthID]; !known {
		return fmt.Errorf("scenario %q references unknown ground-truth ID %q", scenario.ID, scenario.GroundTruthID)
	}
	if err := validateDigest("image", scenario.ImageDigest); err != nil {
		return fmt.Errorf("scenario %q: %w", scenario.ID, err)
	}
	for label, value := range map[string]string{
		"distribution ID": scenario.Distribution.ID, "release": scenario.Distribution.Release,
		"channel": scenario.Distribution.Channel, "architecture": scenario.Distribution.Architecture,
		"scenario class": scenario.ScenarioClass,
	} {
		if err := validateExactValue(label, value); err != nil {
			return fmt.Errorf("scenario %q: %w", scenario.ID, err)
		}
	}
	if scenario.PackageClass != "userspace" && scenario.PackageClass != "kernel" {
		return fmt.Errorf("scenario %q has unsupported package class %q", scenario.ID, scenario.PackageClass)
	}
	if !oneOf(scenario.Expected.MatchState, "affected", "fixed", "not_affected", "unknown", "none") {
		return fmt.Errorf("scenario %q has unsupported match state %q", scenario.ID, scenario.Expected.MatchState)
	}
	if !oneOf(scenario.Expected.PathTier, "P1", "P2", "match_only", "none") {
		return fmt.Errorf("scenario %q has unsupported path tier %q", scenario.ID, scenario.Expected.PathTier)
	}
	if !oneOf(scenario.Expected.CoverageStatus, "complete", "incomplete", "unsupported", "not_run") {
		return fmt.Errorf("scenario %q has unsupported coverage status %q", scenario.ID, scenario.Expected.CoverageStatus)
	}
	if scenario.Expected.PathTier == "P1" && scenario.Expected.MatchState != "affected" {
		return fmt.Errorf("scenario %q expects P1 without an affected match", scenario.ID)
	}
	return nil
}

func validateScenarioDependencies(scenarios map[string]Scenario) error {
	for id, scenario := range scenarios {
		seen := make(map[string]struct{}, len(scenario.DependsOn))
		for _, dependency := range scenario.DependsOn {
			if dependency == id {
				return fmt.Errorf("scenario %q depends on itself", id)
			}
			if _, exists := scenarios[dependency]; !exists {
				return fmt.Errorf("scenario %q references unknown dependency %q", id, dependency)
			}
			if _, duplicate := seen[dependency]; duplicate {
				return fmt.Errorf("scenario %q repeats dependency %q", id, dependency)
			}
			seen[dependency] = struct{}{}
		}
	}
	state := make(map[string]uint8, len(scenarios))
	var visit func(string) error
	visit = func(id string) error {
		switch state[id] {
		case 1:
			return fmt.Errorf("scenario dependency cycle includes %q", id)
		case 2:
			return nil
		}
		state[id] = 1
		for _, dependency := range scenarios[id].DependsOn {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	ids := make([]string, 0, len(scenarios))
	for id := range scenarios {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := visit(id); err != nil {
			return err
		}
	}
	return nil
}

func runDiagnostics(run RunIdentity, tools map[string]ToolIdentity, scenarios map[string]Scenario, manifest Manifest) []string {
	var result []string
	tool, toolFound := tools[run.ToolID]
	if !toolFound {
		result = append(result, "tool ID is absent from the manifest")
	} else {
		if tool.NotRun {
			result = append(result, "tool slot is explicitly not run")
		}
		if run.ToolName == "" || run.ToolName != tool.Name {
			result = append(result, "tool name is missing or mismatched")
		}
		if run.ToolVersion == "" || run.ToolVersion != tool.Version {
			result = append(result, "tool version is missing or mismatched")
		}
		if run.ToolSHA256 == "" || run.ToolSHA256 != tool.SHA256 || validateDigest("tool", run.ToolSHA256) != nil {
			result = append(result, "tool SHA-256 is missing, invalid, or mismatched")
		}
	}
	scenario, scenarioFound := scenarios[run.ScenarioID]
	if !scenarioFound {
		result = append(result, "scenario ID is absent from the manifest")
	} else {
		if run.ImageDigest != scenario.ImageDigest || validateDigest("image", run.ImageDigest) != nil {
			result = append(result, "image digest is missing, invalid, or mismatched")
		}
		if run.DistributionID != scenario.Distribution.ID {
			result = append(result, "distribution ID is missing or mismatched")
		}
		if run.Release != scenario.Distribution.Release {
			result = append(result, "release is missing or mismatched")
		}
		if run.PackageClass != scenario.PackageClass {
			result = append(result, "package class is missing or mismatched")
		}
		if run.ScenarioClass != scenario.ScenarioClass {
			result = append(result, "scenario class is missing or mismatched")
		}
	}
	if run.AdvisorySnapshotDigest != manifest.AdvisorySnapshotDigest || validateDigest("advisory snapshot", run.AdvisorySnapshotDigest) != nil {
		result = append(result, "advisory snapshot digest is missing, invalid, or mismatched")
	}
	if run.ImpactCatalogDigest != manifest.ImpactCatalogDigest || validateDigest("impact catalog", run.ImpactCatalogDigest) != nil {
		result = append(result, "impact catalog digest is missing, invalid, or mismatched")
	}
	if !oneOf(run.Transport, "ssh", "raw-listen", "stdio-raw", "c2-plugin", "offline", "manual") {
		result = append(result, "transport is missing or unsupported")
	}
	if !oneOf(run.Acquisition, "native", "preproduced", "manual") {
		result = append(result, "acquisition is missing or unsupported")
	}
	sort.Strings(result)
	return result
}

func validateProgrammaticHygiene(manifest Manifest) error {
	body, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode manifest for hygiene validation: %w", err)
	}
	generic, err := decodeGenericDocument(body)
	if err != nil {
		return err
	}
	return validateHygiene(generic, nil)
}

func decodeGenericDocument(body []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode manifest JSON: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	return value, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("manifest contains a trailing JSON value")
	}
	return fmt.Errorf("manifest contains trailing data: %w", err)
}

func validateHygiene(value any, path []string) error {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if reason := forbiddenManifestKey(key); reason != "" {
				return fmt.Errorf("manifest field %q is forbidden: %s", strings.Join(append(path, key), "."), reason)
			}
			if err := validateHygiene(typed[key], append(path, key)); err != nil {
				return err
			}
		}
	case []any:
		for index, item := range typed {
			if err := validateHygiene(item, append(path, fmt.Sprintf("[%d]", index))); err != nil {
				return err
			}
		}
	case string:
		if err := validateHygieneString(typed); err != nil {
			return fmt.Errorf("manifest field %q: %w", strings.Join(path, "."), err)
		}
	}
	return nil
}

func forbiddenManifestKey(key string) string {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, fragment := range []string{
		"raw_evidence", "evidence_body", "advisory_text", "advisory_prose", "hostname", "host_identifier",
		"ip_address", "password", "passwd", "access_token", "auth_token", "secret", "credential", "private_key",
	} {
		if strings.Contains(normalized, fragment) {
			return "raw evidence, advisory prose, credentials, and host identifiers are not benchmark metadata"
		}
	}
	if strings.Contains(normalized, "command") && normalized != "disposable_command" {
		return "commands are allowed only in disposable_command"
	}
	return ""
}

func validateHygieneString(value string) error {
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New("control characters are forbidden")
		}
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"begin private key", "password=", "token=", "secret=", "authorization: bearer", "bearer "} {
		if strings.Contains(lower, marker) {
			return errors.New("credential-shaped content is forbidden")
		}
	}
	if strings.Contains(lower, "localhost") || strings.Contains(lower, ".local") || strings.Contains(lower, ".internal") {
		return errors.New("private host identifiers are forbidden")
	}
	for _, candidate := range privateIPv4.FindAllString(value, -1) {
		address := net.ParseIP(candidate)
		if address != nil && (address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified()) {
			return errors.New("private IP identifiers are forbidden")
		}
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err == nil && parsed.User != nil {
			return errors.New("URL credentials are forbidden")
		}
	}
	return nil
}

func validateDigest(label, value string) error {
	if !digestPattern.MatchString(value) || value == "sha256:"+strings.Repeat("0", 64) {
		return fmt.Errorf("%s digest %q is not an exact SHA-256 identity", label, value)
	}
	return nil
}

func validateIdentifier(label, value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("%s %q is empty or malformed", label, value)
	}
	return nil
}

func validateExactValue(label, value string) error {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "*?") || strings.EqualFold(value, "latest") || strings.HasSuffix(strings.ToLower(value), ":latest") {
		return fmt.Errorf("%s %q is empty, wildcarded, or unpinned", label, value)
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}
