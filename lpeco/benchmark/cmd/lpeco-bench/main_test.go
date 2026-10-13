package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/normalone/lpeco/benchmark"
)

func TestCLIValidateProducesDeterministicJSONAndExitCodes(t *testing.T) {
	manifestPath := filepath.Join("..", "..", "manifests", "known-vulnerability.json")
	firstCode, firstOut, firstErr := invokeCLI([]string{"validate", "--manifest", manifestPath}, "")
	secondCode, secondOut, secondErr := invokeCLI([]string{"validate", "--manifest", manifestPath}, "")
	if firstCode != 0 || secondCode != 0 || firstErr != "" || secondErr != "" {
		t.Fatalf("validate = (%d, %q, %q) / (%d, %q, %q)", firstCode, firstOut, firstErr, secondCode, secondOut, secondErr)
	}
	if firstOut != secondOut {
		t.Fatalf("validate output is nondeterministic:\n%s\n%s", firstOut, secondOut)
	}
	var result struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		Scenarios     int    `json:"scenarios"`
		Runs          int    `json:"runs"`
	}
	if err := json.Unmarshal([]byte(firstOut), &result); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != 1 || result.Status != "valid" || result.Scenarios != 18 || result.Runs != 0 {
		t.Fatalf("validate result = %#v", result)
	}

	badPath := filepath.Join(t.TempDir(), "bad.json")
	writeTestFile(t, badPath, []byte(`{"schema_version":1}`), 0o600)
	code, stdout, stderr := invokeCLI([]string{"validate", "--manifest", badPath}, "")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "validate:") {
		t.Fatalf("invalid validate = (%d, %q, %q)", code, stdout, stderr)
	}

	code, _, stderr = invokeCLI([]string{"unknown"}, "")
	if code != 2 || !strings.Contains(stderr, "usage:") {
		t.Fatalf("usage failure = (%d, %q)", code, stderr)
	}
}

func TestCLIImportWritesPrivateArtifactAndRefusesOverwrite(t *testing.T) {
	temporary := t.TempDir()
	identityPath := filepath.Join(temporary, "identity.json")
	outputPath := filepath.Join(temporary, "observations.json")
	identity := testRunIdentity()
	identityBody, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, identityPath, identityBody, 0o600)
	inputPath := filepath.Join("..", "..", "testdata", "lpeco-valid.json")
	arguments := []string{
		"import", "--tool", "lpeco", "--identity", identityPath,
		"--input", inputPath, "--output", outputPath,
	}

	code, stdout, stderr := invokeCLI(arguments, "")
	if code != 0 || stderr != "" || stdout != "{\"schema_version\":1,\"status\":\"written\",\"observations\":1}\n" {
		t.Fatalf("import = (%d, %q, %q)", code, stdout, stderr)
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("observation mode = %04o", info.Mode().Perm())
	}
	body, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(body, []byte(`"path_tier": "P1"`)) || bytes.Contains(body, []byte("raw_evidence")) {
		t.Fatalf("normalized artifact = %s", body)
	}

	code, _, stderr = invokeCLI(arguments, "")
	if code != 1 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("overwrite refusal = (%d, %q)", code, stderr)
	}
	arguments = append(arguments, "--force")
	code, stdout, stderr = invokeCLI(arguments, "")
	if code != 0 || stderr != "" || !strings.Contains(stdout, `"status":"written"`) {
		t.Fatalf("forced overwrite = (%d, %q, %q)", code, stdout, stderr)
	}
	forcedBody, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, forcedBody) {
		t.Fatal("forced import changed deterministic output")
	}
}

func TestCLIScoreIsDeterministicAndRejectsIneligibleRuns(t *testing.T) {
	temporary := t.TempDir()
	manifest := loadTestManifest(t)
	runIdentity := testRunIdentity()
	manifest.Runs = []benchmark.RunIdentity{runIdentity}
	manifestPath := filepath.Join(temporary, "manifest.json")
	writeJSONFile(t, manifestPath, manifest)

	observationPath := filepath.Join(temporary, "observations.json")
	writeJSONFile(t, observationPath, map[string]any{
		"schema_version": 1,
		"observations": []benchmark.Observation{{
			SchemaVersion: 1, ID: "observation-test", RunID: runIdentity.ID,
			ScenarioID: runIdentity.ScenarioID, ToolID: runIdentity.ToolID,
			Outcome: "complete", MatchState: "affected", PathTier: "P1", Release: runIdentity.Release,
		}},
	})
	arguments := []string{"score", "--manifest", manifestPath, "--observations", observationPath}
	firstCode, firstOut, firstErr := invokeCLI(arguments, "")
	secondCode, secondOut, secondErr := invokeCLI(arguments, "")
	if firstCode != 0 || secondCode != 0 || firstErr != "" || secondErr != "" || firstOut != secondOut {
		t.Fatalf("score = (%d, %q) / (%d, %q), stderr %q / %q", firstCode, firstOut, secondCode, secondOut, firstErr, secondErr)
	}
	var report benchmark.Report
	if err := json.Unmarshal([]byte(firstOut), &report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || len(report.Tools) == 0 {
		t.Fatalf("score report = %#v", report)
	}

	manifest.Runs = append(manifest.Runs, benchmark.RunIdentity{
		ID: "unpinned-baseline", ToolID: "osv-scanner", ScenarioID: "annotated-reachable-p1",
		Optional: true, Acquisition: "preproduced",
	})
	writeJSONFile(t, manifestPath, manifest)
	code, stdout, stderr := invokeCLI(arguments, "")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "ineligible run") {
		t.Fatalf("ineligible score = (%d, %q, %q)", code, stdout, stderr)
	}
}

func TestCLIManualImportAcceptsOnlyReviewedNormalizedObservations(t *testing.T) {
	temporary := t.TempDir()
	runIdentity := testRunIdentity()
	runIdentity.ID = "import-linpeas"
	runIdentity.ToolID = "linpeas"
	runIdentity.ToolName = "LinPEAS reviewed output"
	runIdentity.ToolVersion = "v1.2.3"
	runIdentity.ToolSHA256 = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	runIdentity.Transport = "manual"
	runIdentity.Acquisition = "manual"
	identityPath := filepath.Join(temporary, "identity.json")
	writeJSONFile(t, identityPath, runIdentity)
	inputPath := filepath.Join(temporary, "reviewed.json")
	outputPath := filepath.Join(temporary, "normalized.json")
	observation := benchmark.Observation{
		SchemaVersion: 1, ID: "observation-reviewed", RunID: runIdentity.ID,
		ScenarioID: runIdentity.ScenarioID, ToolID: runIdentity.ToolID, Outcome: "complete",
		MatchState: "affected", PathTier: "none", Package: "demo", Version: "1.0-1", Release: "22.04",
	}
	writeJSONFile(t, inputPath, map[string]any{"schema_version": 1, "observations": []benchmark.Observation{observation}})
	arguments := []string{
		"import", "--tool", "manual", "--identity", identityPath,
		"--input", inputPath, "--output", outputPath,
	}
	code, _, stderr := invokeCLI(arguments, "")
	if code != 0 || stderr != "" {
		t.Fatalf("manual import = (%d, %q)", code, stderr)
	}

	observation.PathTier = "P1"
	writeJSONFile(t, inputPath, map[string]any{"schema_version": 1, "observations": []benchmark.Observation{observation}})
	arguments[len(arguments)-1] = filepath.Join(temporary, "rejected.json")
	code, _, stderr = invokeCLI(arguments, "")
	if code != 1 || !strings.Contains(stderr, "privilege-path") {
		t.Fatalf("manual path claim = (%d, %q)", code, stderr)
	}
}

func TestCLITreatsURLInputsAsLocalPaths(t *testing.T) {
	code, stdout, stderr := invokeCLI([]string{"validate", "--manifest", "http://127.0.0.1:1/manifest.json"}, "")
	if code != 1 || stdout != "" || !strings.Contains(stderr, "open") {
		t.Fatalf("URL input = (%d, %q, %q)", code, stdout, stderr)
	}
}

func invokeCLI(arguments []string, stdin string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(arguments, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func loadTestManifest(t *testing.T) benchmark.Manifest {
	t.Helper()
	file, err := os.Open(filepath.Join("..", "..", "manifests", "known-vulnerability.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	manifest, err := benchmark.LoadManifest(file)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func testRunIdentity() benchmark.RunIdentity {
	return benchmark.RunIdentity{
		ID: "import-lpeco", ToolID: "lpeco", ToolName: "LPECO schema-v2 fixture",
		ToolVersion: "fixture-contract-v1", ToolSHA256: "sha256:7193a60dd2e78f7d160657113564445cd545a5357ba24d4c38309ecad358cdb9",
		ScenarioID: "annotated-reachable-p1", ImageDigest: "sha256:11110aed7f9206e3a8b35eaa0726399ba5df15a0cd0f909a087f045d0d9cd9b3",
		AdvisorySnapshotDigest: "sha256:d610988e192438d45a99d151296eaad4a3c3e9cbb20729a7041d6d4bf4c8ba64",
		ImpactCatalogDigest:    "sha256:e989f283b88336525c314a4898ceaae909009d71fe459c0503ebde94a2fd72cf",
		Transport:              "ssh", DistributionID: "ubuntu", Release: "22.04", PackageClass: "userspace",
		ScenarioClass: "annotated_reachable_userspace", Acquisition: "native",
	}
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, '\n')
	writeTestFile(t, path, body, 0o600)
}

func writeTestFile(t *testing.T, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
}
