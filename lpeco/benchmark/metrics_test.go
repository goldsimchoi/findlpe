package benchmark

import (
	"encoding/json"
	"math"
	"reflect"
	"sort"
	"testing"
)

func TestEvaluateConfusionMatrixExcludesUnknownUnsupportedErrorsAndMissing(t *testing.T) {
	manifest := loadCheckedInManifest(t)
	manifest.Runs = nil
	cases := []struct {
		scenario string
		outcome  string
		match    string
		tier     string
	}{
		{"annotated-reachable-p1", "complete", "affected", "P1"},
		{"missing-annotation-p2", "complete", "fixed", "none"},
		{"missing-reachability-p2", "unknown", "unknown", "none"},
		{"fixed-package", "complete", "fixed", "none"},
		{"explicit-not-affected", "complete", "affected", "match_only"},
		{"unsupported-target", "unsupported", "none", "none"},
		{"absent-database", "missing", "none", "none"},
		{"corrupt-database", "crash", "none", "none"},
	}
	var observations []Observation
	for index, test := range cases {
		run := pinnedRun(t, manifest, "run-"+test.scenario, test.scenario, "ssh")
		manifest.Runs = append(manifest.Runs, run)
		if test.outcome == "missing" {
			continue
		}
		coverageStatus := "complete"
		if test.scenario == "unsupported-target" {
			coverageStatus = "unsupported"
		} else if test.scenario == "corrupt-database" {
			coverageStatus = "incomplete"
		}
		stale := false
		observations = append(observations, Observation{
			SchemaVersion: 1, ID: "observation-" + test.scenario, RunID: run.ID, RunIdentitySHA256: RunIdentityDigest(run),
			ScenarioID: run.ScenarioID, ToolID: run.ToolID, Outcome: test.outcome,
			MatchState: test.match, PathTier: test.tier, Package: "demo", Version: "1.0-1", Release: run.Release,
			CoverageStatus: coverageStatus, SnapshotStale: &stale,
			ResourceMeasurement: MeasurementMeasured, SafetyMeasurement: MeasurementMeasured,
			MeasurementProvenance: "fixture-monitor-v1",
			RuntimeMillis:         int64((index + 1) * 10),
			RemoteCommands:        int64(index + 1), OutputBytes: int64((index + 1) * 100),
			AdapterFailures: boolInt64(test.outcome == "crash"), TargetEgress: boolInt64(test.scenario == "explicit-not-affected"),
		})
	}

	report, err := Evaluate(manifest, observations)
	if err != nil {
		t.Fatal(err)
	}
	tool := findToolReport(t, report, "lpeco")
	assertMatrix(t, tool.Micro.Affected, ConfusionMatrix{TP: 1, FP: 1, TN: 1, FN: 1})
	assertRatio(t, tool.Micro.Affected.Precision, 1, 2, 0.5)
	assertRatio(t, tool.Micro.Affected.Recall, 1, 2, 0.5)
	assertRatio(t, tool.Micro.Affected.F1, 2, 4, 0.5)
	assertMatrix(t, tool.Micro.Fixed, ConfusionMatrix{TP: 1, FP: 1, TN: 2, FN: 0})
	assertRatio(t, tool.Micro.Fixed.Precision, 1, 2, 0.5)
	assertRatio(t, tool.Micro.Fixed.Recall, 1, 1, 1)
	assertRatio(t, tool.Micro.Fixed.F1, 2, 3, 2.0/3.0)

	assertRatio(t, tool.Micro.Path.Exact, 2, 4, 0.5)
	assertRatio(t, tool.Micro.Path.Adjacent, 3, 4, 0.75)
	assertRatio(t, tool.Micro.Path.P1, 1, 1, 1)
	assertRatio(t, tool.Micro.Path.P2, 0, 1, 0)
	assertRatio(t, tool.Micro.Path.None, 1, 2, 0.5)
	if tool.Micro.Path.MatchOnly.Available {
		t.Fatalf("empty match-only denominator was reported as available: %#v", tool.Micro.Path.MatchOnly)
	}

	assertRatio(t, tool.Micro.Outcomes.Complete, 4, 8, 0.5)
	assertRatio(t, tool.Micro.Outcomes.Unknown, 1, 8, 0.125)
	assertRatio(t, tool.Micro.Outcomes.Unsupported, 1, 8, 0.125)
	assertRatio(t, tool.Micro.Outcomes.Crash, 1, 8, 0.125)
	assertRatio(t, tool.Micro.Outcomes.ToolError, 1, 8, 0.125)
	assertRatio(t, tool.Micro.Outcomes.Missing, 1, 8, 0.125)
	if tool.Micro.Affected.TP+tool.Micro.Affected.FP+tool.Micro.Affected.TN+tool.Micro.Affected.FN != 4 {
		t.Fatal("non-complete rows leaked into the affected confusion matrix")
	}

	if tool.Resources.ObservedRuns != 7 || tool.Resources.ExpectedRuns != 8 || tool.Resources.RuntimeMillisTotal != 290 || tool.Resources.RuntimeMillisP50 != 40 || tool.Resources.RuntimeMillisP95 != 80 {
		t.Fatalf("runtime resources = %#v", tool.Resources)
	}
	if tool.Resources.OutputBytesTotal != 2900 || tool.Resources.OutputBytesP50 != 400 || tool.Resources.OutputBytesP95 != 800 || tool.Resources.RemoteCommands != 29 || tool.Resources.AdapterFailures != 1 {
		t.Fatalf("command/output resources = %#v", tool.Resources)
	}
	if tool.Safety.TargetWrites != 0 || tool.Safety.TargetEgress != 1 || tool.Safety.ZeroWrites || tool.Safety.ZeroEgress || tool.Safety.Passed {
		t.Fatalf("safety gates = %#v", tool.Safety)
	}
	if len(tool.Strata) == 0 || !sort.SliceIsSorted(tool.Strata, func(i, j int) bool {
		return tool.Strata[i].Dimension+"\x00"+tool.Strata[i].Value < tool.Strata[j].Dimension+"\x00"+tool.Strata[j].Value
	}) {
		t.Fatalf("strata are absent or nondeterministic: %#v", tool.Strata)
	}
	if !tool.Macro.AffectedF1.Available || !tool.Macro.PathExact.Available || tool.Macro.AffectedF1.Groups == 0 {
		t.Fatalf("macro view = %#v", tool.Macro)
	}
}

func TestEvaluateCrossTransportConsistencyAndSafety(t *testing.T) {
	manifest := loadCheckedInManifest(t)
	manifest.Runs = []RunIdentity{
		pinnedRun(t, manifest, "same-ssh", "annotated-reachable-p1", "ssh"),
		pinnedRun(t, manifest, "same-raw", "annotated-reachable-p1", "raw-listen"),
		pinnedRun(t, manifest, "same-c2", "annotated-reachable-p1", "c2-plugin"),
	}
	observations := []Observation{
		completeObservation(manifest.Runs[0], "affected", "P1", 10),
		completeObservation(manifest.Runs[1], "affected", "P1", 20),
		completeObservation(manifest.Runs[2], "affected", "P2", 30),
	}
	observations[1].TargetWrites = 1
	report, err := Evaluate(manifest, observations)
	if err != nil {
		t.Fatal(err)
	}
	tool := findToolReport(t, report, "lpeco")
	if tool.CrossTransport.ComparedGroups != 1 || tool.CrossTransport.MismatchedGroups != 1 {
		t.Fatalf("cross-transport consistency = %#v", tool.CrossTransport)
	}
	assertRatio(t, tool.CrossTransport.Consistent, 0, 1, 0)
	if tool.Safety.ZeroWrites || tool.Safety.Passed || tool.Safety.TargetWrites != 1 {
		t.Fatalf("write safety gate = %#v", tool.Safety)
	}
}

func TestEvaluateCrossTransportConsistencyIncludesCoverageStaleness(t *testing.T) {
	manifest := loadCheckedInManifest(t)
	manifest.Runs = []RunIdentity{
		pinnedRun(t, manifest, "stale-ssh", "annotated-reachable-p1", "ssh"),
		pinnedRun(t, manifest, "stale-raw", "annotated-reachable-p1", "raw-listen"),
	}
	first := completeObservation(manifest.Runs[0], "affected", "P1", 10)
	second := completeObservation(manifest.Runs[1], "affected", "P1", 10)
	second.SnapshotStale = boolPointer(true)
	report, err := Evaluate(manifest, []Observation{first, second})
	if err != nil {
		t.Fatal(err)
	}
	tool := findToolReport(t, report, "lpeco")
	if tool.CrossTransport.ComparedGroups != 1 || tool.CrossTransport.MismatchedGroups != 1 {
		t.Fatalf("cross-transport coverage consistency = %#v", tool.CrossTransport)
	}
	assertRatio(t, tool.CrossTransport.Consistent, 0, 1, 0)
}

func TestEvaluateDoesNotPassUnmeasuredSafety(t *testing.T) {
	manifest := loadCheckedInManifest(t)
	manifest.Runs = []RunIdentity{pinnedRun(t, manifest, "unmeasured", "annotated-reachable-p1", "ssh")}
	observation := completeObservation(manifest.Runs[0], "affected", "P1", 10)
	observation.ResourceMeasurement = MeasurementUnavailable
	observation.SafetyMeasurement = MeasurementUnavailable
	observation.MeasurementProvenance = "fixture-monitor-unavailable"
	observation.RuntimeMillis = 0
	observation.RemoteCommands = 0
	observation.OutputBytes = 0
	report, err := Evaluate(manifest, []Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	safety := findToolReport(t, report, "lpeco").Safety
	if safety.ObservedRuns != 0 || safety.ZeroWrites || safety.ZeroEgress || safety.Passed {
		t.Fatalf("unmeasured safety passed = %#v", safety)
	}
}

func TestEvaluateRejectsCounterOverflow(t *testing.T) {
	manifest := loadCheckedInManifest(t)
	manifest.Runs = []RunIdentity{
		pinnedRun(t, manifest, "overflow-a", "annotated-reachable-p1", "ssh"),
		pinnedRun(t, manifest, "overflow-b", "missing-annotation-p2", "ssh"),
		pinnedRun(t, manifest, "overflow-c", "missing-reachability-p2", "ssh"),
	}
	observations := make([]Observation, 0, len(manifest.Runs))
	for index, run := range manifest.Runs {
		observation := completeObservation(run, "affected", "P2", 10)
		if index < 2 {
			observation.TargetWrites = math.MaxInt64
			observation.TargetEgress = math.MaxInt64
		} else {
			observation.TargetWrites = 2
			observation.TargetEgress = 2
		}
		observations = append(observations, observation)
	}
	if _, err := Evaluate(manifest, observations); err == nil {
		t.Fatal("overflowing safety counters were accepted")
	}
}

func TestEvaluateCoverageFailureCannotBecomeTrueNegative(t *testing.T) {
	manifest := loadCheckedInManifest(t)
	manifest.Runs = []RunIdentity{pinnedRun(t, manifest, "wrong-complete", "unsupported-target", "ssh")}
	observation := completeObservation(manifest.Runs[0], "none", "none", 10)
	report, err := Evaluate(manifest, []Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	tool := findToolReport(t, report, "lpeco")
	matrix := tool.Micro.Affected.ConfusionMatrix
	if matrix.TP+matrix.FP+matrix.TN+matrix.FN != 0 || tool.Micro.Path.Exact.Available {
		t.Fatalf("coverage failure leaked into state/path metrics: %#v / %#v", matrix, tool.Micro.Path)
	}
	assertRatio(t, tool.Micro.Coverage.StatusExact, 0, 1, 0)
}

func TestEvaluateScoresCoverageAndStalenessSeparately(t *testing.T) {
	manifest := loadCheckedInManifest(t)
	manifest.Runs = []RunIdentity{pinnedRun(t, manifest, "stale-mismatch", "stale-database", "ssh")}
	observation := completeObservation(manifest.Runs[0], "affected", "P2", 10)
	report, err := Evaluate(manifest, []Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	coverage := findToolReport(t, report, "lpeco").Micro.Coverage
	assertRatio(t, coverage.StatusExact, 1, 1, 1)
	assertRatio(t, coverage.StaleExact, 0, 1, 0)
}

func TestEvaluateEmptyDenominatorsAndIneligibleRunsStayExplicit(t *testing.T) {
	manifest := loadCheckedInManifest(t)
	manifest.Runs = []RunIdentity{
		pinnedRun(t, manifest, "unknown-only", "ambiguous-ownership-unknown", "offline"),
		{ID: "optional-unpinned", ToolID: "osv-scanner", ScenarioID: "annotated-reachable-p1", Optional: true, Acquisition: "preproduced"},
	}
	observation := Observation{
		SchemaVersion: 1, ID: "unknown-only-observation", RunID: "unknown-only", RunIdentitySHA256: RunIdentityDigest(manifest.Runs[0]),
		ScenarioID: "ambiguous-ownership-unknown",
		ToolID:     "lpeco", Outcome: "unknown", MatchState: "unknown", PathTier: "none",
		Release: manifest.Runs[0].Release, CoverageStatus: "incomplete", SnapshotStale: boolPointer(false),
		ResourceMeasurement: MeasurementMeasured,
		SafetyMeasurement:   MeasurementMeasured, MeasurementProvenance: "fixture-monitor-v1",
	}
	report, err := Evaluate(manifest, []Observation{observation})
	if err != nil {
		t.Fatal(err)
	}
	tool := findToolReport(t, report, "lpeco")
	if tool.Micro.Affected.Precision.Available || tool.Micro.Affected.Recall.Available || tool.Micro.Path.Exact.Available {
		t.Fatalf("empty denominators became available: %#v", tool.Micro)
	}
	baseline := findToolReport(t, report, "osv-scanner")
	if baseline.EligibleRuns != 0 || baseline.IneligibleRuns != 1 || len(baseline.Diagnostics) == 0 {
		t.Fatalf("ineligible baseline run = %#v", baseline)
	}
}

func TestEvaluateRejectsBadJoinsDuplicatesAndIsDeterministic(t *testing.T) {
	manifest := loadCheckedInManifest(t)
	manifest.Runs = []RunIdentity{
		pinnedRun(t, manifest, "run-a", "annotated-reachable-p1", "ssh"),
		pinnedRun(t, manifest, "run-b", "fixed-package", "raw-listen"),
	}
	first := completeObservation(manifest.Runs[0], "affected", "P1", 10)
	second := completeObservation(manifest.Runs[1], "fixed", "none", 20)
	reportA, err := Evaluate(manifest, []Observation{first, second})
	if err != nil {
		t.Fatal(err)
	}
	reportB, err := Evaluate(manifest, []Observation{second, first})
	if err != nil {
		t.Fatal(err)
	}
	jsonA, _ := json.Marshal(reportA)
	jsonB, _ := json.Marshal(reportB)
	if !reflect.DeepEqual(jsonA, jsonB) {
		t.Fatalf("report depends on observation order\n%s\n%s", jsonA, jsonB)
	}

	tests := []struct {
		name         string
		observations []Observation
	}{
		{name: "duplicate run", observations: []Observation{first, first}},
		{name: "duplicate ID", observations: []Observation{first, func() Observation { value := second; value.ID = first.ID; return value }()}},
		{name: "unknown run", observations: []Observation{func() Observation { value := first; value.RunID = "missing"; return value }()}},
		{name: "scenario mismatch", observations: []Observation{func() Observation { value := first; value.ScenarioID = "fixed-package"; return value }()}},
		{name: "tool mismatch", observations: []Observation{func() Observation { value := first; value.ToolID = "openscap"; return value }()}},
		{name: "run identity mismatch", observations: []Observation{func() Observation { value := first; value.RunIdentitySHA256 = digestOf('9'); return value }()}},
		{name: "negative resources", observations: []Observation{func() Observation { value := first; value.OutputBytes = -1; return value }()}},
		{name: "bad outcome", observations: []Observation{func() Observation { value := first; value.Outcome = "success-ish"; return value }()}},
		{name: "release mismatch", observations: []Observation{func() Observation { value := first; value.Release = "99.99"; return value }()}},
		{name: "package mismatch", observations: []Observation{func() Observation { value := first; value.Package = "other"; return value }()}},
		{name: "complete without package context", observations: []Observation{func() Observation {
			value := first
			value.MatchState, value.PathTier, value.Package, value.Version = "none", "none", "", ""
			return value
		}()}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Evaluate(manifest, test.observations); err == nil {
				t.Fatal("invalid observations were accepted")
			}
		})
	}
}

func TestEvaluateRejectsBaselinePrivilegePathClaim(t *testing.T) {
	manifest := loadCheckedInManifest(t)
	for index := range manifest.Tools {
		if manifest.Tools[index].ID == "osv-scanner" {
			manifest.Tools[index].Version = "fixture-v1"
			manifest.Tools[index].SHA256 = digestOf('5')
			manifest.Tools[index].NotRun = false
		}
	}
	scenario := manifest.Scenarios[0]
	run := RunIdentity{
		ID: "osv-path-claim", ToolID: "osv-scanner", ToolName: "OSV-Scanner", ToolVersion: "fixture-v1",
		ToolSHA256: digestOf('5'), ScenarioID: scenario.ID, ImageDigest: scenario.ImageDigest,
		AdvisorySnapshotDigest: manifest.AdvisorySnapshotDigest, ImpactCatalogDigest: manifest.ImpactCatalogDigest,
		Transport: "offline", DistributionID: scenario.Distribution.ID, Release: scenario.Distribution.Release,
		PackageClass: scenario.PackageClass, Package: "demo", PackageVersion: "1.0-1",
		ScenarioClass: scenario.ScenarioClass, Acquisition: "preproduced", Optional: true,
	}
	manifest.Runs = []RunIdentity{run}
	observation := completeObservation(run, "affected", "P1", 10)
	observation.CoverageStatus = CoverageUnavailable
	observation.SnapshotStale = nil
	observation.Release = run.Release
	if _, err := Evaluate(manifest, []Observation{observation}); err == nil {
		t.Fatal("baseline privilege-path claim was accepted")
	}
}

func TestValidateObservationsDoesNotTrustMutableProductRole(t *testing.T) {
	manifest := loadCheckedInManifest(t)
	run := pinnedRun(t, manifest, "role-bypass", "annotated-reachable-p1", "offline")
	run.ToolID = "osv-scanner"
	run.ToolName = "OSV-Scanner"
	run.ToolVersion = "fixture-v1"
	run.ToolSHA256 = digestOf('5')
	run.Acquisition = "preproduced"
	observation := completeObservation(run, "affected", "P1", 10)
	if _, err := validateObservations(
		[]Observation{observation},
		map[string]RunIdentity{run.ID: run},
		map[string]ToolIdentity{run.ToolID: {ID: run.ToolID, Role: "product"}},
	); err == nil {
		t.Fatal("mutable product role allowed a baseline privilege-path claim")
	}
}

func pinnedRun(t *testing.T, manifest Manifest, id, scenarioID, transport string) RunIdentity {
	t.Helper()
	var scenario Scenario
	found := false
	for _, candidate := range manifest.Scenarios {
		if candidate.ID == scenarioID {
			scenario, found = candidate, true
			break
		}
	}
	if !found {
		t.Fatalf("scenario %q not found", scenarioID)
	}
	var tool ToolIdentity
	for _, candidate := range manifest.Tools {
		if candidate.ID == "lpeco" {
			tool = candidate
			break
		}
	}
	return RunIdentity{
		ID: id, ToolID: tool.ID, ToolName: tool.Name, ToolVersion: tool.Version, ToolSHA256: tool.SHA256,
		ScenarioID: scenario.ID, ImageDigest: scenario.ImageDigest, AdvisorySnapshotDigest: manifest.AdvisorySnapshotDigest,
		ImpactCatalogDigest: manifest.ImpactCatalogDigest, Transport: transport, DistributionID: scenario.Distribution.ID,
		Release: scenario.Distribution.Release, PackageClass: scenario.PackageClass, Package: "demo", PackageVersion: "1.0-1",
		ScenarioClass: scenario.ScenarioClass,
		Acquisition:   "native", DisposableCommand: []string{"lpeco", "scan", "fixture"},
	}
}

func completeObservation(run RunIdentity, match, tier string, runtime int64) Observation {
	return Observation{
		SchemaVersion: 1, ID: "observation-" + run.ID, RunID: run.ID, RunIdentitySHA256: RunIdentityDigest(run),
		ScenarioID: run.ScenarioID, ToolID: run.ToolID, Outcome: "complete", MatchState: match, PathTier: tier,
		Package: "demo", Version: "1.0-1", Release: run.Release, CoverageStatus: "complete", SnapshotStale: boolPointer(false),
		RuntimeMillis:       runtime,
		ResourceMeasurement: MeasurementMeasured, SafetyMeasurement: MeasurementMeasured,
		MeasurementProvenance: "fixture-monitor-v1",
		RemoteCommands:        1, OutputBytes: runtime * 10,
	}
}

func boolPointer(value bool) *bool {
	return &value
}

func findToolReport(t *testing.T, report Report, toolID string) ToolReport {
	t.Helper()
	for _, tool := range report.Tools {
		if tool.ToolID == toolID {
			return tool
		}
	}
	t.Fatalf("tool report %q not found: %#v", toolID, report.Tools)
	return ToolReport{}
}

func assertMatrix(t *testing.T, got ConfusionMetrics, want ConfusionMatrix) {
	t.Helper()
	if got.ConfusionMatrix != want {
		t.Fatalf("confusion matrix = %#v, want %#v", got.ConfusionMatrix, want)
	}
}

func assertRatio(t *testing.T, got Ratio, numerator, denominator int, value float64) {
	t.Helper()
	if !got.Available || got.Numerator != numerator || got.Denominator != denominator || got.Value != value {
		t.Fatalf("ratio = %#v, want %d/%d (%v)", got, numerator, denominator, value)
	}
}

func boolInt64(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
