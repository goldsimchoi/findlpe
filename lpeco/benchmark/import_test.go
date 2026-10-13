package benchmark

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/normalone/lpeco/internal/collect/packageinfo"
	"github.com/normalone/lpeco/internal/model"
	reportpkg "github.com/normalone/lpeco/internal/report"
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
	wrongPackage := run
	wrongPackage.Package = "other"
	if _, err := ImportLPECO(openImportFixture(t, "lpeco-valid.json"), wrongPackage); err == nil {
		t.Fatal("package identity mismatch was accepted")
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

	fixedRun := run
	fixedRun.PackageVersion = "1.0-2"
	fixed, err := ImportOSVScanner(openImportFixture(t, "osvscanner-fixed.json"), fixedRun)
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
	wrongPackage := run
	wrongPackage.Package = "other"
	if _, err := ImportOSVScanner(openImportFixture(t, "osvscanner-affected.json"), wrongPackage); err == nil {
		t.Fatal("OSV package identity mismatch was accepted")
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
	fixedRun := run
	fixedRun.PackageVersion = "1.0-2"
	fixed, err := ImportOpenSCAP(openImportFixture(t, "openscap-fixed.xml"), fixedRun)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixed) != 1 || fixed[0].MatchState != "fixed" || fixed[0].PathTier != "none" {
		t.Fatalf("fixed OpenSCAP observation = %#v", fixed)
	}
	if _, err := ImportOpenSCAP(openImportFixture(t, "openscap-xxe.xml"), run); err == nil {
		t.Fatal("XML external entity document was accepted")
	}
	privateSchemaLocation := `<oval_results xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://10.23.4.5/private" schema_version="1" distribution="ubuntu" release="22.04" package="demo" version="1.0-1" scan_status="complete" result_semantics="affected-fixed"><results><system><definitions><definition definition_id="oval:fixture:def:1" result="true"/></definitions></system></results></oval_results>`
	if _, err := ImportOpenSCAP(strings.NewReader(privateSchemaLocation), run); err == nil {
		t.Fatal("unsafe OpenSCAP schema location was accepted")
	}
	wrongVersion := run
	wrongVersion.PackageVersion = "9.9-9"
	if _, err := ImportOpenSCAP(openImportFixture(t, "openscap-affected.xml"), wrongVersion); err == nil {
		t.Fatal("OpenSCAP package version mismatch was accepted")
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
	if observations, err := ImportOSVScanner(strings.NewReader(`{"schema_version":1,"scan_status":"complete","results":[]}`), run); err == nil || len(observations) != 0 {
		t.Fatalf("empty OSV result = (%#v, %v), want rejection", observations, err)
	}

	openSCAPRun := importerRun("openscap", "OpenSCAP/Ubuntu OVAL", "fixture-v1", digestOf('6'), "preproduced", "offline")
	emptyOpenSCAP := `<oval_results schema_version="1" distribution="ubuntu" release="22.04" package="demo" version="1.0-1" scan_status="complete" result_semantics="affected-fixed"><results><system><definitions/></system></results></oval_results>`
	if observations, err := ImportOpenSCAP(strings.NewReader(emptyOpenSCAP), openSCAPRun); err == nil || len(observations) != 0 {
		t.Fatalf("empty OpenSCAP result = (%#v, %v), want rejection", observations, err)
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

func TestImportLPECORejectsInvalidCandidateAndMixedStateJoin(t *testing.T) {
	run := importerRun("lpeco", "LPECO schema-v2 fixture", "fixture-contract-v1", digestOfRunTool(), "native", "ssh")

	invalid := loadLPECODocument(t)
	invalid.Candidates[0].CurrentPrincipal = model.NodeRef{}
	if observations, err := ImportLPECO(marshalLPECODocument(t, invalid), run); err == nil || len(observations) != 0 {
		t.Fatalf("invalid candidate = (%#v, %v), want rejection", observations, err)
	}

	mixed := loadLPECODocument(t)
	fixed := mixed.KnownVulnerabilities.Matches[0]
	fixed.ID = "match-fixed"
	fixed.State = model.VulnerabilityStateFixed
	mixed.KnownVulnerabilities.Matches = append(mixed.KnownVulnerabilities.Matches, fixed)
	mixed.Candidates[0].RelatedMatchIDs = []string{fixed.ID}
	if observations, err := ImportLPECO(marshalLPECODocument(t, mixed), run); err == nil || len(observations) != 0 {
		t.Fatalf("mixed-state join = (%#v, %v), want rejection", observations, err)
	}
}

func TestImportLPECORequiresInstalledPackageContextForZeroMatch(t *testing.T) {
	run := importerRun("lpeco", "LPECO schema-v2 fixture", "fixture-contract-v1", digestOfRunTool(), "native", "ssh")
	zeroMatch := loadLPECODocument(t)
	zeroMatch.KnownVulnerabilities.Matches = nil
	zeroMatch.Candidates = nil
	if observations, err := ImportLPECO(marshalLPECODocument(t, zeroMatch), run); err == nil || len(observations) != 0 {
		t.Fatalf("zero-match report without package fact = (%#v, %v), want rejection", observations, err)
	}

	installed := packageinfo.InstalledPackageFact{
		RequestedPackage: "demo", Manager: "dpkg", Status: "install ok installed",
		BinaryPackage: "demo", Architecture: "amd64",
		BinaryVersion: model.DebianVersion{Raw: "1.0-1", Valid: true},
		SourcePackage: "demo", SourceVersion: model.DebianVersion{Raw: "1.0-1", Valid: true},
		EvidenceIDs: []string{"evidence-fixture"}, Confidence: model.ConfidenceHigh,
	}
	data, err := json.Marshal(installed)
	if err != nil {
		t.Fatal(err)
	}
	zeroMatch.Facts = []model.Fact{{
		ID: "fact-installed-demo", Kind: "installed_package", SourceCollector: "packageinfo",
		EvidenceIDs: []string{"evidence-fixture"}, Confidence: model.ConfidenceHigh,
		ObservationStatus: model.ProbeTimeout, Data: data,
	}}
	if observations, err := ImportLPECO(marshalLPECODocument(t, zeroMatch), run); err == nil || len(observations) != 0 {
		t.Fatalf("zero-match report with timed-out package fact = (%#v, %v), want rejection", observations, err)
	}
	zeroMatch.Facts[0].ObservationStatus = model.ProbeComplete
	zeroMatch.Evidence[0].Status = model.ProbeTimeout
	if observations, err := ImportLPECO(marshalLPECODocument(t, zeroMatch), run); err == nil || len(observations) != 0 {
		t.Fatalf("zero-match report with timed-out evidence = (%#v, %v), want rejection", observations, err)
	}
	zeroMatch.Evidence[0].Status = model.ProbeComplete
	zeroMatch.Evidence[0].Truncated = true
	if observations, err := ImportLPECO(marshalLPECODocument(t, zeroMatch), run); err == nil || len(observations) != 0 {
		t.Fatalf("zero-match report with truncated evidence = (%#v, %v), want rejection", observations, err)
	}
	zeroMatch.Evidence[0].Truncated = false
	observations, err := ImportLPECO(marshalLPECODocument(t, zeroMatch), run)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].Outcome != "complete" || observations[0].MatchState != "none" ||
		observations[0].Package != run.Package || observations[0].Version != run.PackageVersion {
		t.Fatalf("zero-match observation = %#v", observations)
	}
}

func TestImportLPECOPreservesUnavailableAndStaleCoverage(t *testing.T) {
	run := importerRun("lpeco", "LPECO schema-v2 fixture", "fixture-contract-v1", digestOfRunTool(), "native", "ssh")

	notRun := loadLPECODocument(t)
	notRun.KnownVulnerabilities.Coverage.Status = model.VulnerabilityCoverageNotRun
	notRun.KnownVulnerabilities.Coverage.Snapshot = model.SnapshotReference{}
	notRun.Session.Vulnerability = notRun.KnownVulnerabilities.Coverage
	notRun.KnownVulnerabilities.Matches = nil
	notRun.Candidates = nil
	observations, err := ImportLPECO(marshalLPECODocument(t, notRun), run)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].Outcome != "unknown" || observations[0].CoverageStatus != "not_run" ||
		observations[0].SnapshotStale == nil || *observations[0].SnapshotStale {
		t.Fatalf("not-run coverage = %#v", observations)
	}

	stale := loadLPECODocument(t)
	stale.KnownVulnerabilities.Coverage.Snapshot.Stale = true
	stale.Session.Vulnerability = stale.KnownVulnerabilities.Coverage
	observations, err = ImportLPECO(marshalLPECODocument(t, stale), run)
	if err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].SnapshotStale == nil || !*observations[0].SnapshotStale {
		t.Fatalf("stale coverage = %#v", observations)
	}

	staleMismatch := loadLPECODocument(t)
	staleMismatch.KnownVulnerabilities.Coverage.Snapshot.Stale = true
	if observations, err := ImportLPECO(marshalLPECODocument(t, staleMismatch), run); err == nil || len(observations) != 0 {
		t.Fatalf("mismatched coverage staleness = (%#v, %v), want rejection", observations, err)
	}
}

func importerRun(toolID, toolName, version, digest, acquisition, transport string) RunIdentity {
	return RunIdentity{
		ID: "import-" + toolID, ToolID: toolID, ToolName: toolName, ToolVersion: version, ToolSHA256: digest,
		ScenarioID: "annotated-reachable-p1", ImageDigest: "sha256:11110aed7f9206e3a8b35eaa0726399ba5df15a0cd0f909a087f045d0d9cd9b3",
		AdvisorySnapshotDigest: "sha256:d610988e192438d45a99d151296eaad4a3c3e9cbb20729a7041d6d4bf4c8ba64",
		ImpactCatalogDigest:    "sha256:e989f283b88336525c314a4898ceaae909009d71fe459c0503ebde94a2fd72cf",
		Transport:              transport, DistributionID: "ubuntu", Release: "22.04", PackageClass: "userspace",
		Package: "demo", PackageVersion: "1.0-1",
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

func loadLPECODocument(t *testing.T) reportpkg.Document {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "lpeco-valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document reportpkg.Document
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func marshalLPECODocument(t *testing.T, document reportpkg.Document) io.Reader {
	t.Helper()
	body, err := json.Marshal(document)
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
