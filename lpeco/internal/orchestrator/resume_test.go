package orchestrator

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
	"github.com/normalone/lpeco/internal/rules"
)

func TestResumeFromCompletedCheckpointWithoutDuplicates(t *testing.T) {
	collectors := []collect.Collector{
		testCollector{id: "context", plan: fixedPlan(testDefinition("context.current", "context", model.PassiveRead)), parse: contextFacts},
		testCollector{id: "process", plan: fixedPlan(testDefinition("process.snapshot", "process", model.PassiveRead)), parse: processFacts},
		testCollector{id: "path", plan: func(_ model.HostProfile, discovery collect.Discovery) []probe.Definition {
			if len(discovery.ReferencedPaths) == 0 {
				return nil
			}
			return []probe.Definition{testDefinition("path.validate", "path", model.PassiveRead)}
		}},
	}
	store := newTestStore(t, "resume")
	first := newFakeAdapter(adapter.Capabilities{TransportKind: "plugin", AsyncTasks: true, MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	first.errors["path.validate"] = []error{errors.New("plugin disconnected")}
	result, err := Run(context.Background(), first, store, Options{SessionID: "resume", Collectors: collectors, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{}})
	if err == nil || len(result.Checkpoint.PendingValidation) == 0 {
		t.Fatalf("first run = (%#v, %v), want resumable validation", result, err)
	}

	second := newFakeAdapter(adapter.Capabilities{TransportKind: "plugin", AsyncTasks: true, MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	resumed, err := Resume(context.Background(), second, store, Options{SessionID: "resume", Collectors: collectors, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{}})
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if second.callCount("context.current") != 0 || second.callCount("process.snapshot") != 0 || second.callCount("path.validate") != 1 {
		t.Fatalf("resume calls = %#v", second.probeCalls())
	}
	if len(resumed.Checkpoint.PendingValidation) != 0 {
		t.Fatalf("pending validation not cleared: %#v", resumed.Checkpoint.PendingValidation)
	}
	facts, loadErr := store.LoadFacts(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	ids := make(map[string]bool)
	for _, fact := range facts {
		if ids[fact.ID] {
			t.Fatalf("duplicate fact ID %q in %#v", fact.ID, facts)
		}
		ids[fact.ID] = true
	}
	evidence, loadErr := store.ListEvidence(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if got, want := len(evidence), 4; got != want {
		t.Fatalf("evidence count = %d, want %d: %#v", got, want, evidence)
	}
	if !reflect.DeepEqual(resumed.ObservablePreview, []string{}) {
		t.Fatalf("preview = %#v", resumed.ObservablePreview)
	}
}

func TestResumePinsVulnerabilitySnapshotAndDoesNotDuplicateFacts(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	pinned := testVulnerabilitySnapshot(t, "CVE-2099-1001", now)
	changed := testVulnerabilitySnapshot(t, "CVE-2099-1002", now.Add(time.Minute))
	store := newTestStore(t, "resume-vulnerability-pin")
	firstPackages := &testPackageCollector{}
	first, err := Run(context.Background(), newFakeAdapter(adapter.Capabilities{TransportKind: "raw", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20}), store, Options{
		SessionID: "resume-vulnerability-pin", Collectors: vulnerabilityTestCollectors(firstPackages, supportedDistribution()), PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{},
		Vulnerability: VulnerabilityInput{Mode: model.VulnerabilityModeAuto, Snapshot: &pinned}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(first.VulnerabilityMatches) != 1 {
		t.Fatalf("first matches = %#v", first.VulnerabilityMatches)
	}
	wantMatchID := first.VulnerabilityMatches[0].ID
	wantFactCount := countFactsOfKind(t, store, "vulnerability_match")

	exactPackages := &testPackageCollector{}
	exactTransport := newFakeAdapter(adapter.Capabilities{TransportKind: "raw", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	exact, err := Resume(context.Background(), exactTransport, store, Options{
		SessionID: "resume-vulnerability-pin", Collectors: vulnerabilityTestCollectors(exactPackages, supportedDistribution()), PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{},
		Vulnerability: VulnerabilityInput{Mode: model.VulnerabilityModeAuto, Snapshot: &pinned}, Now: func() time.Time { return now.Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("Resume exact: %v", err)
	}
	if len(exact.VulnerabilityMatches) != 1 || exact.VulnerabilityMatches[0].ID != wantMatchID {
		t.Fatalf("exact matches = %#v", exact.VulnerabilityMatches)
	}
	if exactTransport.callCount("package.ownership") != 0 || exactTransport.callCount("package.metadata") != 0 {
		t.Fatalf("exact resume repeated package probes: %#v", exactTransport.probeCalls())
	}
	if got := countFactsOfKind(t, store, "vulnerability_match"); got != wantFactCount {
		t.Fatalf("match fact count after exact resume = %d, want %d", got, wantFactCount)
	}

	mismatchTransport := newFakeAdapter(adapter.Capabilities{TransportKind: "raw", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	mismatched, err := Resume(context.Background(), mismatchTransport, store, Options{
		SessionID: "resume-vulnerability-pin", Collectors: vulnerabilityTestCollectors(&testPackageCollector{}, supportedDistribution()), PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{},
		Vulnerability: VulnerabilityInput{Mode: model.VulnerabilityModeAuto, Snapshot: &changed}, Now: func() time.Time { return now.Add(2 * time.Hour) },
	})
	if err == nil {
		t.Fatal("Resume with changed snapshot succeeded")
	}
	if mismatched.Vulnerability.Status != model.VulnerabilityCoverageIncomplete || mismatched.Vulnerability.Snapshot.Digest != pinned.Manifest.Digest {
		t.Fatalf("mismatched coverage = %#v", mismatched.Vulnerability)
	}
	if len(mismatched.VulnerabilityMatches) != 1 || mismatched.VulnerabilityMatches[0].ID != wantMatchID {
		t.Fatalf("mismatched resume changed persisted matches: %#v", mismatched.VulnerabilityMatches)
	}
	if mismatchTransport.callCount("package.ownership") != 0 || mismatchTransport.callCount("package.metadata") != 0 {
		t.Fatalf("mismatched resume ran package probes: %#v", mismatchTransport.probeCalls())
	}
	if got := countFactsOfKind(t, store, "vulnerability_match"); got != wantFactCount {
		t.Fatalf("match fact count after mismatch = %d, want %d", got, wantFactCount)
	}
}

func TestResumeMissingPinnedSnapshotIsPartial(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	snapshot := testVulnerabilitySnapshot(t, "CVE-2099-1003", now)
	store := newTestStore(t, "resume-vulnerability-missing")
	first, err := Run(context.Background(), newFakeAdapter(adapter.Capabilities{TransportKind: "raw", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20}), store, Options{
		SessionID: "resume-vulnerability-missing", Collectors: vulnerabilityTestCollectors(&testPackageCollector{}, supportedDistribution()), PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{},
		Vulnerability: VulnerabilityInput{Mode: model.VulnerabilityModeAuto, Snapshot: &snapshot}, Now: func() time.Time { return now },
	})
	if err != nil || len(first.VulnerabilityMatches) != 1 {
		t.Fatalf("Run = (%#v, %v)", first.VulnerabilityMatches, err)
	}
	resumed, err := Resume(context.Background(), newFakeAdapter(adapter.Capabilities{TransportKind: "raw", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20}), store, Options{
		SessionID: "resume-vulnerability-missing", Collectors: vulnerabilityTestCollectors(&testPackageCollector{}, supportedDistribution()), PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{},
		Vulnerability: VulnerabilityInput{Mode: model.VulnerabilityModeAuto}, Now: func() time.Time { return now.Add(time.Hour) },
	})
	if err == nil || resumed.Vulnerability.Status != model.VulnerabilityCoverageIncomplete {
		t.Fatalf("Resume missing = (%#v, %v)", resumed.Vulnerability, err)
	}
	if len(resumed.VulnerabilityMatches) != 1 || resumed.VulnerabilityMatches[0].ID != first.VulnerabilityMatches[0].ID {
		t.Fatalf("missing snapshot discarded matches: %#v", resumed.VulnerabilityMatches)
	}
}

func TestResumeSchemaOneKeepsLegacyVulnerabilityCoverage(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	snapshot := testVulnerabilitySnapshot(t, "CVE-2099-1004", now)
	store := newTestStore(t, "resume-schema-one")
	session := model.Session{
		SchemaVersion: 1, ID: "resume-schema-one", CreatedAt: now, UpdatedAt: now, Status: model.SessionInterrupted,
		Profile: model.HostProfile{Distribution: supportedDistribution()}, Checkpoint: newCheckpoint(now),
	}
	if err := store.Create(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	transport := newFakeAdapter(adapter.Capabilities{TransportKind: "raw", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	result, err := Resume(context.Background(), transport, store, Options{
		SessionID: "resume-schema-one", Collectors: []collect.Collector{}, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{},
		Vulnerability: VulnerabilityInput{Mode: model.VulnerabilityModeAuto, Snapshot: &snapshot}, Now: func() time.Time { return now.Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if result.Vulnerability.Status != model.VulnerabilityCoverageLegacyNotRequested || result.Vulnerability.Mode != model.VulnerabilityModeOff {
		t.Fatalf("legacy coverage = %#v", result.Vulnerability)
	}
	if containsPhase(result.Phases, PhaseKnownVulnerability) {
		t.Fatalf("schema-one phases = %#v", result.Phases)
	}
}

func countFactsOfKind(t *testing.T, store interface {
	LoadFacts(context.Context) ([]model.Fact, error)
}, kind string) int {
	t.Helper()
	facts, err := store.LoadFacts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, fact := range facts {
		if fact.Kind == kind {
			count++
		}
	}
	return count
}
