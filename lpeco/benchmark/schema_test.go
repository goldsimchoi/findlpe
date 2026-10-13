package benchmark

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestManifestCheckedInCoversPinnedGroundTruth(t *testing.T) {
	manifest := loadCheckedInManifest(t)
	if manifest.SchemaVersion != ManifestSchemaVersion {
		t.Fatalf("schema version = %d", manifest.SchemaVersion)
	}
	if manifest.GroundTruth.Path != CoreGroundTruthPath || manifest.GroundTruth.SHA256 != CoreGroundTruthSHA256 {
		t.Fatalf("ground truth identity = %#v", manifest.GroundTruth)
	}

	coreBody, err := os.ReadFile(filepath.Join("..", CoreGroundTruthPath))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(coreBody)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != manifest.GroundTruth.SHA256 {
		t.Fatalf("ground truth digest = %s, want %s", got, manifest.GroundTruth.SHA256)
	}
	var core struct {
		Scenarios []struct {
			ID string `json:"id"`
		} `json:"scenarios"`
	}
	if err := json.Unmarshal(coreBody, &core); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(manifest.Scenarios))
	for _, scenario := range manifest.Scenarios {
		got = append(got, scenario.GroundTruthID)
	}
	want := make([]string, 0, len(core.Scenarios))
	for _, scenario := range core.Scenarios {
		want = append(want, scenario.ID)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ground-truth references = %#v, want %#v", got, want)
	}

	optional := 0
	for _, tool := range manifest.Tools {
		if tool.NotRun {
			optional++
			if !tool.Optional || tool.Version != "" || tool.SHA256 != "" {
				t.Fatalf("not-run tool claims an execution identity: %#v", tool)
			}
		}
	}
	if optional < 4 {
		t.Fatalf("optional baseline slots = %d, want at least 4", optional)
	}
}

func TestManifestRejectsInvalidFixtures(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("testdata", "manifest-invalid-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 3 {
		t.Fatalf("invalid fixture count = %d", len(paths))
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if _, err := LoadManifest(file); err == nil {
				t.Fatal("invalid manifest was accepted")
			}
		})
	}
}

func TestManifestStrictLoadingAndHygiene(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("manifests", "known-vulnerability.json"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "unknown field", body: strings.Replace(string(body), `"schema_version": 1,`, `"schema_version": 1, "mystery": true,`, 1), want: "unknown field"},
		{name: "trailing value", body: string(body) + ` {}`, want: "trailing"},
		{name: "raw evidence key", body: strings.Replace(string(body), `"schema_version": 1,`, `"schema_version": 1, "raw_evidence": "blob",`, 1), want: "raw_evidence"},
		{name: "credential key", body: strings.Replace(string(body), `"schema_version": 1,`, `"schema_version": 1, "access_token": "fixture",`, 1), want: "access_token"},
		{name: "terminal control", body: strings.Replace(string(body), `"LPECO schema-v2 fixture"`, `"LPECO\u001b[31m fixture"`, 1), want: "control"},
		{name: "private host", body: strings.Replace(string(body), `"LPECO schema-v2 fixture"`, `"10.23.4.5"`, 1), want: "private"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadManifest(strings.NewReader(test.body))
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("LoadManifest error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestManifestValidationRules(t *testing.T) {
	base := loadCheckedInManifest(t)
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{name: "schema", mutate: func(value *Manifest) { value.SchemaVersion = 2 }},
		{name: "ground truth traversal", mutate: func(value *Manifest) { value.GroundTruth.Path = "../scenarios.json" }},
		{name: "ground truth digest", mutate: func(value *Manifest) { value.GroundTruth.SHA256 = digestOf('a') }},
		{name: "snapshot digest", mutate: func(value *Manifest) { value.AdvisorySnapshotDigest = "latest" }},
		{name: "catalog digest", mutate: func(value *Manifest) { value.ImpactCatalogDigest = "" }},
		{name: "duplicate tool", mutate: func(value *Manifest) { value.Tools = append(value.Tools, value.Tools[0]) }},
		{name: "latest tool", mutate: func(value *Manifest) { value.Tools[0].Version = "latest" }},
		{name: "tool digest", mutate: func(value *Manifest) { value.Tools[0].SHA256 = "sha256:short" }},
		{name: "duplicate scenario", mutate: func(value *Manifest) { value.Scenarios = append(value.Scenarios, value.Scenarios[0]) }},
		{name: "duplicate ground truth", mutate: func(value *Manifest) { value.Scenarios[1].GroundTruthID = value.Scenarios[0].GroundTruthID }},
		{name: "unknown ground truth", mutate: func(value *Manifest) { value.Scenarios[0].GroundTruthID = "not-in-core" }},
		{name: "image latest", mutate: func(value *Manifest) { value.Scenarios[0].ImageDigest = "ubuntu:latest" }},
		{name: "distribution wildcard", mutate: func(value *Manifest) { value.Scenarios[0].Distribution.Release = "*" }},
		{name: "package class", mutate: func(value *Manifest) { value.Scenarios[0].PackageClass = "all" }},
		{name: "scenario class", mutate: func(value *Manifest) { value.Scenarios[0].ScenarioClass = "" }},
		{name: "match state", mutate: func(value *Manifest) { value.Scenarios[0].Expected.MatchState = "maybe" }},
		{name: "path tier", mutate: func(value *Manifest) { value.Scenarios[0].Expected.PathTier = "P0" }},
		{name: "P1 without affected", mutate: func(value *Manifest) { value.Scenarios[0].Expected.MatchState = "fixed" }},
		{name: "missing core scenario", mutate: func(value *Manifest) { value.Scenarios = value.Scenarios[1:] }},
		{name: "unknown dependency", mutate: func(value *Manifest) { value.Scenarios[0].DependsOn = []string{"missing"} }},
		{name: "cycle", mutate: func(value *Manifest) {
			value.Scenarios[0].DependsOn = []string{value.Scenarios[1].ID}
			value.Scenarios[1].DependsOn = []string{value.Scenarios[0].ID}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := cloneManifest(t, base)
			test.mutate(&manifest)
			if err := manifest.Validate(); err == nil {
				t.Fatal("invalid manifest was accepted")
			}
		})
	}
}

func TestManifestRunEligibilityAndOrder(t *testing.T) {
	manifest := loadCheckedInManifest(t)
	first, second := manifest.Scenarios[0].ID, manifest.Scenarios[1].ID
	manifest.Scenarios[0], manifest.Scenarios[1] = manifest.Scenarios[1], manifest.Scenarios[0]
	manifest.Runs = append(manifest.Runs, RunIdentity{
		ID: "optional-osv-slot", ToolID: "osv-scanner", ScenarioID: first,
		Optional: true, Acquisition: "preproduced",
	})
	if err := manifest.Validate(); err != nil {
		t.Fatal(err)
	}
	if manifest.Scenarios[0].ID != second || manifest.Scenarios[1].ID != first {
		t.Fatal("validation reordered author-entered scenarios")
	}
	optional := manifest.Runs[len(manifest.Runs)-1]
	if optional.Eligible || len(optional.Diagnostics) == 0 {
		t.Fatalf("optional unpinned run eligibility = %#v", optional)
	}

	required := cloneManifest(t, manifest)
	required.Runs[len(required.Runs)-1].Optional = false
	if err := required.Validate(); err == nil {
		t.Fatal("required unpinned run was accepted")
	}

	eligible := cloneManifest(t, manifest)
	scenario := eligible.Scenarios[0]
	eligible.Runs = append(eligible.Runs, RunIdentity{
		ID: "lpeco-pinned", ToolID: "lpeco", ToolName: "LPECO schema-v2 fixture",
		ToolVersion: "fixture-contract-v1", ToolSHA256: digestOfRunTool(), ScenarioID: scenario.ID,
		ImageDigest: scenario.ImageDigest, AdvisorySnapshotDigest: eligible.AdvisorySnapshotDigest,
		ImpactCatalogDigest: eligible.ImpactCatalogDigest, Transport: "ssh",
		DistributionID: scenario.Distribution.ID, Release: scenario.Distribution.Release,
		PackageClass: scenario.PackageClass, ScenarioClass: scenario.ScenarioClass,
		Acquisition: "native", DisposableCommand: []string{"lpeco", "scan", "fixture"},
	})
	if err := eligible.Validate(); err != nil {
		t.Fatal(err)
	}
	if !eligible.Runs[len(eligible.Runs)-1].Eligible {
		t.Fatalf("fully pinned run is ineligible: %#v", eligible.Runs[len(eligible.Runs)-1].Diagnostics)
	}
}

func loadCheckedInManifest(t *testing.T) Manifest {
	t.Helper()
	file, err := os.Open(filepath.Join("manifests", "known-vulnerability.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	manifest, err := LoadManifest(file)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func cloneManifest(t *testing.T, value Manifest) Manifest {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result Manifest
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func digestOf(value byte) string {
	return "sha256:" + strings.Repeat(string(value), 64)
}

func digestOfRunTool() string {
	return "sha256:7193a60dd2e78f7d160657113564445cd545a5357ba24d4c38309ecad358cdb9"
}
