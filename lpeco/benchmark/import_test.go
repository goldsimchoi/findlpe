package benchmark

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportLPECORequiresSchemaIdentityAndStableJoins(t *testing.T) {
	run := importerRun("lpeco", "LPECO schema-v2 fixture", "fixture-contract-v1", digestOfRunTool(), "native", "ssh")
	observations, err := ImportLPECO(openImportFixture(t, "lpeco-valid.json"), run)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 {
		t.Fatalf("LPECO observations = %#v", observations)
	}
	observation := observations[0]
	if observation.Outcome != "complete" || observation.MatchState != "affected" || observation.PathTier != "P1" ||
		observation.Package != "demo" || observation.Version != "1.0-1" || observation.Release != "22.04" {
		t.Fatalf("LPECO observation = %#v", observation)
	}
	if len(observation.DiagnosticCodes) != 0 {
		t.Fatalf("unexpected LPECO diagnostics = %#v", observation.DiagnosticCodes)
	}

	mismatch := run
	mismatch.AdvisorySnapshotDigest = digestOf('9')
	if _, err := ImportLPECO(openImportFixture(t, "lpeco-valid.json"), mismatch); err == nil {
		t.Fatal("snapshot identity mismatch was accepted")
	}
	for _, name := range []string{"lpeco-schema-v1.json", "lpeco-raw-evidence.json", "lpeco-bad-join.json"} {
		t.Run(name, func(t *testing.T) {
			if _, err := ImportLPECO(openImportFixture(t, name), run); err == nil {
				t.Fatal("invalid LPECO report was accepted")
			}
		})
	}
}

func TestImportOSVScannerMapsOnlyExplicitPackageState(t *testing.T) {
	run := importerRun("osv-scanner", "OSV-Scanner", "fixture-v1", digestOf('5'), "preproduced", "offline")
	affected, err := ImportOSVScanner(openImportFixture(t, "osvscanner-affected.json"), run)
	if err != nil {
		t.Fatal(err)
	}
	if len(affected) != 1 || affected[0].Outcome != "complete" || affected[0].MatchState != "affected" ||
		affected[0].PathTier != "none" || affected[0].Package != "demo" || affected[0].Version != "1.0-1" {
		t.Fatalf("affected OSV observation = %#v", affected)
	}
	if len(affected[0].DiagnosticCodes) != 0 {
		t.Fatalf("OSV severity/prose leaked into diagnostics: %#v", affected[0])
	}

	fixed, err := ImportOSVScanner(openImportFixture(t, "osvscanner-fixed.json"), run)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixed) != 1 || fixed[0].MatchState != "fixed" || fixed[0].PathTier != "none" {
		t.Fatalf("fixed OSV observation = %#v", fixed)
	}

	failed, err := ImportOSVScanner(openImportFixture(t, "osvscanner-error.json"), run)
	if err != nil {
		t.Fatal(err)
	}
	if len(failed) != 1 || failed[0].Outcome != "error" || failed[0].MatchState != "none" || failed[0].PathTier != "none" {
		t.Fatalf("tool error was normalized as empty success: %#v", failed)
	}

	mismatch := run
	mismatch.Release = "24.04"
	if _, err := ImportOSVScanner(openImportFixture(t, "osvscanner-affected.json"), mismatch); err == nil {
		t.Fatal("OSV release mismatch was accepted")
	}
}

func TestImportOpenSCAPRejectsEntitiesAndNeverEmitsPrivilegeTier(t *testing.T) {
	run := importerRun("openscap", "OpenSCAP/Ubuntu OVAL", "fixture-v1", digestOf('6'), "preproduced", "offline")
	affected, err := ImportOpenSCAP(openImportFixture(t, "openscap-affected.xml"), run)
	if err != nil {
		t.Fatal(err)
	}
	if len(affected) != 1 || affected[0].MatchState != "affected" || affected[0].PathTier != "none" ||
		affected[0].Package != "demo" || affected[0].Version != "1.0-1" {
		t.Fatalf("affected OpenSCAP observation = %#v", affected)
	}
	fixed, err := ImportOpenSCAP(openImportFixture(t, "openscap-fixed.xml"), run)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixed) != 1 || fixed[0].MatchState != "fixed" || fixed[0].PathTier != "none" {
		t.Fatalf("fixed OpenSCAP observation = %#v", fixed)
	}
	if _, err := ImportOpenSCAP(openImportFixture(t, "openscap-xxe.xml"), run); err == nil {
		t.Fatal("XML external entity document was accepted")
	}
}

func TestImportMalformedHygieneAndSizeFailuresAreNeverEmptySuccess(t *testing.T) {
	run := importerRun("osv-scanner", "OSV-Scanner", "fixture-v1", digestOf('5'), "preproduced", "offline")
	for _, body := range []string{
		`{"schema_version":1,"scan_status":"complete"`,
		`{"schema_version":1,"scan_status":"complete","raw_evidence":"blob","results":[]}`,
		`{"schema_version":1,"scan_status":"complete","access_token":"fixture","results":[]}`,
		"{\"schema_version\":1,\"scan_status\":\"complete\",\"results\":[],\"note\":\"bad\\u001bcontrol\"}",
	} {
		if observations, err := ImportOSVScanner(strings.NewReader(body), run); err == nil || len(observations) != 0 {
			t.Fatalf("unsafe input = (%#v, %v), want rejection", observations, err)
		}
	}
	oversized := &repeatReader{remaining: maxImportBytes + 1, value: ' '}
	if observations, err := ImportOSVScanner(oversized, run); err == nil || len(observations) != 0 {
		t.Fatalf("oversized input = (%#v, %v), want rejection", observations, err)
	}
}

func TestImportIdentityAndOutputAreDeterministic(t *testing.T) {
	run := importerRun("lpeco", "LPECO schema-v2 fixture", "fixture-contract-v1", digestOfRunTool(), "native", "ssh")
	first, err := ImportLPECO(openImportFixture(t, "lpeco-valid.json"), run)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ImportLPECO(openImportFixture(t, "lpeco-valid.json"), run)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || len(second) != 1 || first[0].ID != second[0].ID {
		t.Fatalf("import IDs are not stable: %#v / %#v", first, second)
	}
	bad := run
	bad.ToolVersion = "latest"
	if _, err := ImportLPECO(openImportFixture(t, "lpeco-valid.json"), bad); err == nil {
		t.Fatal("unpinned importer identity was accepted")
	}
}

func importerRun(toolID, toolName, version, digest, acquisition, transport string) RunIdentity {
	return RunIdentity{
		ID: "import-" + toolID, ToolID: toolID, ToolName: toolName, ToolVersion: version, ToolSHA256: digest,
		ScenarioID: "annotated-reachable-p1", ImageDigest: "sha256:11110aed7f9206e3a8b35eaa0726399ba5df15a0cd0f909a087f045d0d9cd9b3",
		AdvisorySnapshotDigest: "sha256:d610988e192438d45a99d151296eaad4a3c3e9cbb20729a7041d6d4bf4c8ba64",
		ImpactCatalogDigest:    "sha256:e989f283b88336525c314a4898ceaae909009d71fe459c0503ebde94a2fd72cf",
		Transport:              transport, DistributionID: "ubuntu", Release: "22.04", PackageClass: "userspace",
		ScenarioClass: "annotated_reachable_userspace", Acquisition: acquisition,
	}
}

func openImportFixture(t *testing.T, name string) io.Reader {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(body)
}

type repeatReader struct {
	remaining int64
	value     byte
}

func (reader *repeatReader) Read(buffer []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, io.EOF
	}
	count := int64(len(buffer))
	if count > reader.remaining {
		count = reader.remaining
	}
	for index := int64(0); index < count; index++ {
		buffer[index] = reader.value
	}
	reader.remaining -= count
	return int(count), nil
}
