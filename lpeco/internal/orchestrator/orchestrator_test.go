package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	contextcollect "github.com/normalone/lpeco/internal/collect/context"
	pathcollect "github.com/normalone/lpeco/internal/collect/path"
	processcollect "github.com/normalone/lpeco/internal/collect/process"
	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
	"github.com/normalone/lpeco/internal/rules"
	storepkg "github.com/normalone/lpeco/internal/store"
)

func TestRunOrdersAdaptivePhasesAndExpandsOnlyReferencedPaths(t *testing.T) {
	var pathDiscovery collect.Discovery
	collectors := []collect.Collector{
		testCollector{id: "context", plan: fixedPlan(testDefinition("context.current", "context", model.PassiveRead)), parse: contextFacts},
		testCollector{id: "process", plan: func(_ model.HostProfile, discovery collect.Discovery) []probe.Definition {
			if len(discovery.HighValuePIDs) == 0 {
				return []probe.Definition{testDefinition("process.snapshot", "process", model.PassiveRead)}
			}
			if !reflect.DeepEqual(discovery.HighValuePIDs, []int{42}) {
				t.Fatalf("high-value PIDs = %#v", discovery.HighValuePIDs)
			}
			return []probe.Definition{testDefinition("process.dependencies.42", "process", model.PassiveRead)}
		}, parse: processFacts},
		testCollector{id: "path", plan: func(_ model.HostProfile, discovery collect.Discovery) []probe.Definition {
			pathDiscovery = discovery
			return []probe.Definition{testDefinition("path.validate./opt/demo/bin", "path", model.PassiveRead)}
		}},
		testCollector{id: "scheduler", plan: fixedPlan(testDefinition("scheduler.inventory", "scheduler", model.PassiveRead))},
	}
	transport := newFakeAdapter(adapter.Capabilities{TransportKind: "raw", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	result, err := Run(context.Background(), transport, newTestStore(t, "adaptive"), Options{SessionID: "adaptive", Collectors: collectors, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{}})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantPhases := []Phase{PhaseProfile, PhaseContext, PhasePrimary, PhaseTargetedValidation, PhaseFallback, PhaseFinalize}
	if !reflect.DeepEqual(result.Phases, wantPhases) {
		t.Fatalf("phases = %#v, want %#v", result.Phases, wantPhases)
	}
	if !reflect.DeepEqual(pathDiscovery.ReferencedPaths, []string{"/opt/demo/bin"}) {
		t.Fatalf("path discovery = %#v", pathDiscovery.ReferencedPaths)
	}
	wantCalls := []string{"context.current", "process.snapshot", "process.dependencies.42", "path.validate./opt/demo/bin", "scheduler.inventory"}
	if got := transport.probeCalls(); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("probe calls = %#v, want %#v", got, wantCalls)
	}
}

func TestDiscoverCarriesMountBoundariesIntoFallbackPlanning(t *testing.T) {
	mount := pathcollect.MountObservation{ID: 7, MajorMinor: "8:2", Root: "/", MountPoint: "/srv", Bind: true, EvidenceIDs: []string{"e-mount"}}
	discovery := discover([]model.Fact{testFact("mount", "path", "e-mount", mount)})
	want := []collect.Mount{{ID: 7, MajorMinor: "8:2", Root: "/", MountPoint: "/srv", Bind: true}}
	if !reflect.DeepEqual(discovery.Mounts, want) {
		t.Fatalf("discovered mounts = %#v, want %#v", discovery.Mounts, want)
	}
}

func TestRunRepeatsProcessSnapshotForObservationWindow(t *testing.T) {
	var waits []time.Duration
	collectors := []collect.Collector{
		testCollector{id: "context", plan: fixedPlan(testDefinition("context.current", "context", model.PassiveRead)), parse: contextFacts},
		testCollector{id: "process", plan: fixedPlan(testDefinition("process.snapshot", "process", model.PassiveRead)), parse: func(definition probe.Definition, _ adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
			if definition.Parser != "test" {
				t.Fatalf("observation parser = %q", definition.Parser)
			}
			value := processcollect.ProcessFact{PID: len(waits) + 40, StartTime: uint64(len(waits) + 1), Name: "observed", UIDs: [4]int{0, 0, 0, 0}, GIDs: [4]int{0, 0, 0, 0}, EvidenceIDs: []string{evidenceID}, Confidence: model.ConfidenceHigh}
			return []model.Fact{testFact("process", "process", evidenceID, value)}, nil
		}},
	}
	transport := newFakeAdapter(adapter.Capabilities{TransportKind: "raw", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	result, err := Run(context.Background(), transport, newTestStore(t, "observe"), Options{
		SessionID: "observe", Collectors: collectors, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{},
		ProcessObservation: 2500 * time.Millisecond, ObservationInterval: time.Second,
		Wait: func(_ context.Context, duration time.Duration) error {
			waits = append(waits, duration)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantCalls := []string{"context.current", "process.snapshot", "process.snapshot.observe.0001", "process.snapshot.observe.0002", "process.snapshot.observe.0003"}
	if got := transport.probeCalls(); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("probe calls = %#v, want %#v", got, wantCalls)
	}
	if !reflect.DeepEqual(waits, []time.Duration{time.Second, time.Second, 500 * time.Millisecond}) {
		t.Fatalf("waits = %#v", waits)
	}
	processCount := 0
	for _, fact := range result.Facts {
		if fact.Kind == "process" {
			processCount++
		}
	}
	if processCount != 4 {
		t.Fatalf("process facts = %d, want 4", processCount)
	}
}

func TestRunSkipsFallbackForStrongPrimaryUnlessFull(t *testing.T) {
	for _, test := range []struct {
		name         string
		full         bool
		wantFallback bool
	}{{"default", false, false}, {"full", true, true}} {
		t.Run(test.name, func(t *testing.T) {
			collectors := []collect.Collector{
				testCollector{id: "context", plan: fixedPlan(testDefinition("context.current", "context", model.PassiveRead)), parse: contextFacts},
				testCollector{id: "process", plan: fixedPlan(testDefinition("process.snapshot", "process", model.PassiveRead)), parse: processFacts},
				testCollector{id: "scheduler", plan: fixedPlan(testDefinition("scheduler.inventory", "scheduler", model.PassiveRead))},
			}
			transport := newFakeAdapter(adapter.Capabilities{TransportKind: "ssh", AsyncTasks: true, MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
			_, err := Run(context.Background(), transport, newTestStore(t, "fallback-"+test.name), Options{
				SessionID: "fallback-" + test.name, Collectors: collectors, Full: test.full,
				PrimaryRules: []rules.Rule{strongProcessRule{}}, Rules: []rules.Rule{strongProcessRule{}},
			})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			called := containsString(transport.probeCalls(), "scheduler.inventory")
			if called != test.wantFallback {
				t.Fatalf("fallback called = %v, want %v (%#v)", called, test.wantFallback, transport.probeCalls())
			}
		})
	}
}

func TestExecutionPolicyRetriesAndBoundsAsyncParallelism(t *testing.T) {
	definitions := []probe.Definition{
		testDefinition("a.retry", "process", model.PassiveRead),
		testDefinition("b.parallel", "process", model.PassiveRead),
		testDefinition("c.parallel", "process", model.PassiveRead),
		testDefinition("d.observable", "process", model.ObservableRead),
		testDefinition("e.forbidden", "process", model.StateChanging),
	}
	collectors := []collect.Collector{
		testCollector{id: "context", plan: fixedPlan(testDefinition("context.current", "context", model.PassiveRead)), parse: contextFacts},
		testCollector{id: "process", plan: func(model.HostProfile, collect.Discovery) []probe.Definition { return definitions }},
	}
	transport := newFakeAdapter(adapter.Capabilities{TransportKind: "plugin", AsyncTasks: true, MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	transport.delay = 25 * time.Millisecond
	transport.results["a.retry"] = []adapter.ExecResult{
		{Status: model.ProbeTimeout, Truncated: true},
		{Status: model.ProbeComplete},
	}
	result, err := Run(context.Background(), transport, newTestStore(t, "policy"), Options{
		SessionID: "policy", Collectors: collectors, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{}, MaxParallel: 2,
	})
	if err == nil || !errors.Is(err, probe.ErrUnsafeProbe) {
		t.Fatalf("Run error = %v, want unsafe probe aggregate", err)
	}
	if transport.callCount("a.retry") != 2 {
		t.Fatalf("retry calls = %d, want 2", transport.callCount("a.retry"))
	}
	if transport.callCount("d.observable") != 0 || transport.callCount("e.forbidden") != 0 {
		t.Fatalf("unsafe/preview probes executed: %#v", transport.probeCalls())
	}
	if !reflect.DeepEqual(result.ObservablePreview, []string{"d.observable"}) {
		t.Fatalf("observable preview = %#v", result.ObservablePreview)
	}
	if transport.maxConcurrency() != 2 {
		t.Fatalf("max concurrency = %d, want 2", transport.maxConcurrency())
	}
}

func TestObservableReadIsDisclosedBeforeExecution(t *testing.T) {
	definitions := []probe.Definition{testDefinition("process.observable", "process", model.ObservableRead)}
	collectors := []collect.Collector{
		testCollector{id: "context", plan: fixedPlan(testDefinition("context.current", "context", model.PassiveRead)), parse: contextFacts},
		testCollector{id: "process", plan: func(model.HostProfile, collect.Discovery) []probe.Definition { return definitions }},
	}
	transport := newFakeAdapter(adapter.Capabilities{TransportKind: "raw", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	var disclosed []string
	result, err := Run(context.Background(), transport, newTestStore(t, "observable-disclosure"), Options{
		SessionID: "observable-disclosure", Collectors: collectors, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{}, ObservableRead: true,
		BeforeObservable: func(probeIDs []string) error {
			if transport.callCount("process.observable") != 0 {
				t.Fatal("observable probe executed before disclosure")
			}
			disclosed = append(disclosed, probeIDs...)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !reflect.DeepEqual(disclosed, []string{"process.observable"}) {
		t.Fatalf("disclosed = %#v", disclosed)
	}
	if transport.callCount("process.observable") != 1 {
		t.Fatalf("observable calls = %d, want 1", transport.callCount("process.observable"))
	}
	if !reflect.DeepEqual(result.ObservablePreview, []string{"process.observable"}) {
		t.Fatalf("observable preview = %#v", result.ObservablePreview)
	}
}

func TestObservableReadFailsClosedWithoutDisclosureCallback(t *testing.T) {
	collectors := []collect.Collector{
		testCollector{id: "context", plan: fixedPlan(testDefinition("context.current", "context", model.PassiveRead)), parse: contextFacts},
		testCollector{id: "process", plan: fixedPlan(testDefinition("process.observable", "process", model.ObservableRead))},
	}
	transport := newFakeAdapter(adapter.Capabilities{TransportKind: "ssh", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	result, err := Run(context.Background(), transport, newTestStore(t, "observable-fail-closed"), Options{
		SessionID: "observable-fail-closed", Collectors: collectors, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{}, ObservableRead: true,
	})
	if err == nil || transport.callCount("process.observable") != 0 {
		t.Fatalf("Run = (%#v, %v), observable calls = %d; want fail-closed", result, err, transport.callCount("process.observable"))
	}
}

func TestIncompleteObservationCannotProduceP0AndInterruptsSession(t *testing.T) {
	collectors := []collect.Collector{
		testCollector{id: "context", plan: fixedPlan(testDefinition("context.current", "context", model.PassiveRead)), parse: contextFacts},
		testCollector{id: "process", plan: fixedPlan(testDefinition("process.snapshot", "process", model.PassiveRead)), parse: processFacts},
	}
	transport := newFakeAdapter(adapter.Capabilities{TransportKind: "ssh", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	transport.results["process.snapshot"] = []adapter.ExecResult{
		{Stdout: []byte("prefix"), Status: model.ProbePartial},
		{Stdout: []byte("prefix"), Status: model.ProbePartial},
	}
	sessionStore := newTestStore(t, "incomplete-bound")
	result, err := Run(context.Background(), transport, sessionStore, Options{
		SessionID: "incomplete-bound", Collectors: collectors,
		PrimaryRules: []rules.Rule{p0ProcessRule{}}, Rules: []rules.Rule{p0ProcessRule{}},
	})
	if err == nil {
		t.Fatal("Run succeeded with an unresolved partial observation")
	}
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates = %#v", result.Candidates)
	}
	candidate := result.Candidates[0]
	if candidate.Priority == model.PriorityP0 || candidate.Confidence == model.ConfidenceHigh || candidate.ValidationStatus != model.ValidationIncomplete {
		t.Fatalf("incomplete evidence produced an overconfident candidate: %#v", candidate)
	}
	if !containsTestFragment(candidate.MissingFacts, "observation") {
		t.Fatalf("candidate missing facts = %#v", candidate.MissingFacts)
	}
	for _, fact := range result.Facts {
		if fact.Kind == "process" && (fact.ObservationStatus != model.ProbePartial || fact.Confidence == model.ConfidenceHigh) {
			t.Fatalf("partial fact was not bounded: %#v", fact)
		}
	}
	session, loadErr := sessionStore.Load(context.Background(), "incomplete-bound")
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if session.Status != model.SessionInterrupted {
		t.Fatalf("session status = %s, want interrupted", session.Status)
	}
}

func TestNonZeroExitIsAnIncompleteObservation(t *testing.T) {
	definition := testDefinition("context.current", "context", model.PassiveRead)
	collector := testCollector{id: "context", plan: fixedPlan(definition), parse: contextFacts}
	transport := newFakeAdapter(adapter.Capabilities{TransportKind: "ssh", ReliableExitStatus: true, MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	exitCode := 1
	transport.results[definition.ID] = []adapter.ExecResult{
		{Stdout: []byte("prefix"), Status: model.ProbeComplete, ExitCode: &exitCode},
		{Stdout: []byte("prefix"), Status: model.ProbeComplete, ExitCode: &exitCode},
	}
	result, err := Run(context.Background(), transport, newTestStore(t, "nonzero-exit"), Options{
		SessionID: "nonzero-exit", Collectors: []collect.Collector{collector}, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{},
	})
	if err == nil {
		t.Fatalf("Run = (%#v, nil), want incomplete error", result)
	}
	for _, completed := range result.Checkpoint.Completed {
		if completed.ProbeID == definition.ID && completed.Status == model.ProbeComplete {
			t.Fatalf("non-zero exit recorded complete: %#v", completed)
		}
	}
}

func TestCollectorRequestedPassiveFallbackExecutesAlternateVariant(t *testing.T) {
	transport := &variantAdapter{}
	sessionStore := newTestStore(t, "variant-fallback")
	result, err := Run(context.Background(), transport, sessionStore, Options{
		SessionID: "variant-fallback", Collectors: []collect.Collector{fallbackCollector{}}, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !reflect.DeepEqual(transport.variants, []string{"manager", "files"}) {
		t.Fatalf("variants = %#v", transport.variants)
	}
	evidence, loadErr := sessionStore.ListEvidence(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	statuses := make([]model.ProbeStatus, 0, len(evidence))
	for _, item := range evidence {
		statuses = append(statuses, item.Status)
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i] < statuses[j] })
	if !reflect.DeepEqual(statuses, []model.ProbeStatus{model.ProbeComplete, model.ProbePartial}) {
		t.Fatalf("fallback evidence statuses = %#v", statuses)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("recovered fallback issues = %#v", result.Issues)
	}
}

func TestSSHStyleExecErrorRetriesOnceAndRecovers(t *testing.T) {
	collectors := []collect.Collector{
		testCollector{id: "context", plan: fixedPlan(testDefinition("context.current", "context", model.PassiveRead)), parse: contextFacts},
		testCollector{id: "process", plan: fixedPlan(testDefinition("process.retry", "process", model.PassiveRead))},
	}
	transport := newFakeAdapter(adapter.Capabilities{TransportKind: "ssh", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	transport.results["process.retry"] = []adapter.ExecResult{
		{Stdout: []byte("partial-before-timeout"), Status: model.ProbeTimeout},
		{Stdout: []byte("complete-after-retry"), Status: model.ProbeComplete},
	}
	transport.errors["process.retry"] = []error{adapter.MarkRetryable(context.DeadlineExceeded), nil}
	sessionStore := newTestStore(t, "exec-error-retry")
	_, err := Run(context.Background(), transport, sessionStore, Options{SessionID: "exec-error-retry", Collectors: collectors, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{}})
	if err != nil {
		t.Fatalf("Run after recovered retry: %v", err)
	}
	if transport.callCount("process.retry") != 2 {
		t.Fatalf("retry calls = %d, want 2", transport.callCount("process.retry"))
	}
	evidence, loadErr := sessionStore.ListEvidence(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	statuses := make([]model.ProbeStatus, 0, 2)
	for _, item := range evidence {
		if item.ProbeID == "process.retry" {
			statuses = append(statuses, item.Status)
		}
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i] < statuses[j] })
	if !reflect.DeepEqual(statuses, []model.ProbeStatus{model.ProbeComplete, model.ProbeTimeout}) {
		t.Fatalf("retry evidence statuses = %#v", statuses)
	}
}

func TestRecoveredRetryDiscardsSupersededPartialFacts(t *testing.T) {
	definition := testDefinition("process.retry-facts", "process", model.PassiveRead)
	collector := testCollector{
		id:   "process",
		plan: fixedPlan(definition),
		parse: func(_ probe.Definition, result adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
			value := struct {
				Value       string   `json:"value"`
				EvidenceIDs []string `json:"evidence_ids"`
			}{Value: string(result.Stdout), EvidenceIDs: []string{evidenceID}}
			return []model.Fact{testFact("retry_fact", "process", evidenceID, value)}, nil
		},
	}
	transport := newFakeAdapter(adapter.Capabilities{TransportKind: "ssh", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	transport.results[definition.ID] = []adapter.ExecResult{
		{Stdout: []byte("partial"), Status: model.ProbePartial},
		{Stdout: []byte("complete"), Status: model.ProbeComplete},
	}
	result, err := Run(context.Background(), transport, newTestStore(t, "retry-facts"), Options{
		SessionID: "retry-facts", Collectors: []collect.Collector{collector}, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var retryFacts []model.Fact
	for _, fact := range result.Facts {
		if fact.Kind == "retry_fact" {
			retryFacts = append(retryFacts, fact)
		}
	}
	if len(retryFacts) != 1 {
		t.Fatalf("retry facts = %#v, want only the successful retry", retryFacts)
	}
	if retryFacts[0].ObservationStatus != model.ProbeComplete || string(retryFacts[0].Data) == "" || !strings.Contains(string(retryFacts[0].Data), "complete") {
		t.Fatalf("retained retry fact = %#v", retryFacts[0])
	}
}

func TestRecoveredRetryDiscardsSupersededParseError(t *testing.T) {
	definition := testDefinition("process.retry-parse", "process", model.PassiveRead)
	collector := testCollector{
		id:   "process",
		plan: fixedPlan(definition),
		parse: func(_ probe.Definition, result adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
			if string(result.Stdout) == "bad" {
				return nil, errors.New("transient malformed output")
			}
			return []model.Fact{testFact("retry_parse_fact", "process", evidenceID, struct {
				Value string `json:"value"`
			}{Value: string(result.Stdout)})}, nil
		},
	}
	transport := newFakeAdapter(adapter.Capabilities{TransportKind: "ssh", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	transport.results[definition.ID] = []adapter.ExecResult{
		{Stdout: []byte("bad"), Status: model.ProbeComplete},
		{Stdout: []byte("good"), Status: model.ProbeComplete},
	}
	result, err := Run(context.Background(), transport, newTestStore(t, "retry-parse"), Options{
		SessionID: "retry-parse", Collectors: []collect.Collector{collector}, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{},
	})
	if err != nil || len(result.Issues) != 0 {
		t.Fatalf("recovered parse retry = (%#v, %v)", result.Issues, err)
	}
	if transport.callCount(definition.ID) != 2 {
		t.Fatalf("parse retry calls = %d, want 2", transport.callCount(definition.ID))
	}
	var facts []model.Fact
	for _, fact := range result.Facts {
		if fact.Kind == "retry_parse_fact" {
			facts = append(facts, fact)
		}
	}
	if len(facts) != 1 || !strings.Contains(string(facts[0].Data), "good") {
		t.Fatalf("parse retry facts = %#v", facts)
	}
}

func TestRawTransportExecutesSequentially(t *testing.T) {
	collectors := []collect.Collector{
		testCollector{id: "context", plan: fixedPlan(testDefinition("context.current", "context", model.PassiveRead)), parse: contextFacts},
		testCollector{id: "process", plan: func(model.HostProfile, collect.Discovery) []probe.Definition {
			return []probe.Definition{testDefinition("process.a", "process", model.PassiveRead), testDefinition("process.b", "process", model.PassiveRead)}
		}},
	}
	transport := newFakeAdapter(adapter.Capabilities{TransportKind: "raw", AsyncTasks: true, MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	transport.delay = 10 * time.Millisecond
	_, _ = Run(context.Background(), transport, newTestStore(t, "raw-sequential"), Options{SessionID: "raw-sequential", Collectors: collectors, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{}, MaxParallel: 4})
	if transport.maxConcurrency() != 1 {
		t.Fatalf("raw max concurrency = %d, want 1", transport.maxConcurrency())
	}
}

func TestParserErrorPersistsEvidenceAsParseError(t *testing.T) {
	bad := testCollector{id: "context", plan: fixedPlan(testDefinition("context.current", "context", model.PassiveRead)), parse: func(probe.Definition, adapter.ExecResult, string) ([]model.Fact, error) {
		return nil, errors.New("malformed context")
	}}
	store := newTestStore(t, "parse-error")
	_, err := Run(context.Background(), newFakeAdapter(adapter.Capabilities{TransportKind: "ssh", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20}), store, Options{SessionID: "parse-error", Collectors: []collect.Collector{bad}, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{}})
	if err == nil {
		t.Fatal("Run succeeded despite parse error")
	}
	evidence, loadErr := store.ListEvidence(context.Background())
	if loadErr != nil || len(evidence) == 0 || evidence[0].Status != model.ProbeParseError {
		t.Fatalf("evidence = %#v, err = %v", evidence, loadErr)
	}
}

func TestExecErrorPreservesPartialEvidenceStatusAndBody(t *testing.T) {
	collectors := []collect.Collector{
		testCollector{id: "context", plan: fixedPlan(testDefinition("context.current", "context", model.PassiveRead)), parse: contextFacts},
		testCollector{id: "process", plan: fixedPlan(testDefinition("process.partial", "process", model.PassiveRead))},
	}
	transport := newFakeAdapter(adapter.Capabilities{TransportKind: "raw", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20})
	partialBody := []byte("LPECO_PROC_V1\nPROCESS\t42\n")
	transport.results["process.partial"] = []adapter.ExecResult{{Stdout: partialBody, Status: model.ProbeTimeout}}
	transport.errors["process.partial"] = []error{context.DeadlineExceeded}
	sessionStore := newTestStore(t, "partial-evidence")
	result, err := Run(context.Background(), transport, sessionStore, Options{SessionID: "partial-evidence", Collectors: collectors, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{}})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run error = %v, want deadline exceeded", err)
	}
	evidence, loadErr := sessionStore.ListEvidence(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	var partial model.Evidence
	for _, item := range evidence {
		if item.ProbeID == "process.partial" {
			partial = item
			break
		}
	}
	if partial.ID == "" {
		t.Fatalf("partial evidence missing: %#v", evidence)
	}
	digest := sha256.Sum256(partialBody)
	if partial.Status != model.ProbeTimeout || partial.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("partial evidence = %#v", partial)
	}
	completed := result.Checkpoint.Completed["process.partial|"+partial.InputFingerprint]
	if completed.EvidenceID != partial.ID || completed.Status != model.ProbeTimeout {
		t.Fatalf("partial checkpoint = %#v", completed)
	}
}

func TestCancellationPersistsPartialEvidenceCheckpointAndSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport := &cancellingAdapter{cancel: cancel}
	collectors := []collect.Collector{
		testCollector{id: "context", plan: fixedPlan(testDefinition("context.current", "context", model.PassiveRead)), parse: contextFacts},
		testCollector{id: "process", plan: fixedPlan(testDefinition("process.cancelled", "process", model.PassiveRead)), parse: processFacts},
	}
	sessionStore := newTestStore(t, "cancel-persistence")
	result, err := Run(ctx, transport, sessionStore, Options{
		SessionID: "cancel-persistence", Collectors: collectors, PrimaryRules: []rules.Rule{}, Rules: []rules.Rule{},
	})
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want cancellation", err)
	}
	evidence, loadErr := sessionStore.ListEvidence(context.Background())
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	var partial model.Evidence
	for _, item := range evidence {
		if item.ProbeID == "process.cancelled" {
			partial = item
		}
	}
	if partial.ID == "" || partial.Status != model.ProbePartial {
		t.Fatalf("cancelled evidence = %#v", evidence)
	}
	completed := result.Checkpoint.Completed["process.cancelled|"+partial.InputFingerprint]
	if completed.EvidenceID != partial.ID || completed.Status != model.ProbePartial {
		t.Fatalf("cancelled checkpoint = %#v", completed)
	}
	session, loadErr := sessionStore.Load(context.Background(), "cancel-persistence")
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if session.Status != model.SessionInterrupted || session.Checkpoint.Completed["process.cancelled|"+partial.InputFingerprint].EvidenceID != partial.ID {
		t.Fatalf("cancelled session = %#v", session)
	}
}

type testCollector struct {
	id    string
	plan  func(model.HostProfile, collect.Discovery) []probe.Definition
	parse func(probe.Definition, adapter.ExecResult, string) ([]model.Fact, error)
}

func (c testCollector) ID() string { return c.id }
func (c testCollector) Plan(profile model.HostProfile, discovery collect.Discovery) []probe.Definition {
	if c.plan == nil {
		return nil
	}
	return c.plan(profile, discovery)
}
func (c testCollector) Parse(definition probe.Definition, result adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
	if c.parse == nil {
		return nil, nil
	}
	return c.parse(definition, result, evidenceID)
}

func fixedPlan(definitions ...probe.Definition) func(model.HostProfile, collect.Discovery) []probe.Definition {
	return func(model.HostProfile, collect.Discovery) []probe.Definition { return definitions }
}

func testDefinition(id, collector string, safety model.SafetyClass) probe.Definition {
	return probe.Definition{ID: id, Collector: collector, Parser: "test", RedactionPolicy: "default", SafetyClass: safety,
		Variants: []probe.Variant{{ID: "test", Command: adapter.Command{Script: "printf ok"}}}, Timeout: time.Second, MaxOutput: 4096, Produces: []string{"test"}, Idempotent: true}
}

func contextFacts(_ probe.Definition, _ adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
	identity := contextcollect.IdentityFact{UIDs: [4]int{1000, 1000, 1000, 1000}, GIDs: [4]int{1000, 1000, 1000, 1000}, Groups: []int{1000}}
	host := contextcollect.HostFact{OS: "Linux", Architecture: "x86_64", InitSystem: "systemd", SystemdRunning: true, AvailableCommands: map[string]bool{"stat": true}}
	return []model.Fact{testFact("identity", "context", evidenceID, identity), testFact("host", "context", evidenceID, host)}, nil
}

func processFacts(definition probe.Definition, _ adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
	if definition.ID != "process.snapshot" {
		return nil, nil
	}
	value := processcollect.ProcessFact{PID: 42, StartTime: 7, Name: "demo", UIDs: [4]int{0, 0, 0, 0}, GIDs: [4]int{0, 0, 0, 0}, Executable: "/opt/demo/bin", EvidenceIDs: []string{evidenceID}, Confidence: model.ConfidenceHigh}
	return []model.Fact{testFact("process", "process", evidenceID, value)}, nil
}

func testFact(kind, collector, evidence string, value any) model.Fact {
	data, _ := json.Marshal(value)
	id, _ := model.StableID("fact", struct {
		Kind string
		Data json.RawMessage
	}{kind, data})
	return model.Fact{ID: id, Kind: kind, SourceCollector: collector, EvidenceIDs: []string{evidence}, Confidence: model.ConfidenceHigh, Data: data}
}

type strongProcessRule struct{}

type p0ProcessRule struct{}

func (strongProcessRule) ID() string { return "test.strong-process" }
func (strongProcessRule) Metadata() rules.Metadata {
	return rules.Metadata{ID: "test.strong-process", Category: "test", Description: "test"}
}
func (strongProcessRule) Evaluate(_ context.Context, g *graphpkg.Graph) []model.Candidate {
	current, ok := g.CurrentPrincipal()
	if !ok || len(g.NodesByKind(model.NodeProcess)) == 0 {
		return nil
	}
	process := g.NodesByKind(model.NodeProcess)[0]
	var target model.NodeRef
	for _, edge := range g.Outgoing(process.NodeRef, model.EdgeRunsAs) {
		if edge.To.ID != current.ID {
			target = edge.To
			break
		}
	}
	if target.ID == "" {
		return nil
	}
	id, _ := model.StableID("candidate", process.ID)
	consumer := process.NodeRef
	return []model.Candidate{{ID: id, RuleID: "test.strong-process", Category: "test", Priority: model.PriorityP1, Confidence: model.ConfidenceHigh,
		CurrentPrincipal: current, TargetPrincipal: target, PrivilegedConsumer: &consumer, PathNodes: []model.NodeRef{consumer},
		EvidenceIDs: append([]string(nil), process.EvidenceIDs...), MissingFacts: []string{}, ValidationStatus: model.ValidationReadOnly, Summary: "strong test candidate"}}
}

func (p0ProcessRule) ID() string { return "test.p0-process" }
func (p0ProcessRule) Metadata() rules.Metadata {
	return rules.Metadata{ID: "test.p0-process", Category: "test", Description: "test"}
}
func (p0ProcessRule) Evaluate(_ context.Context, g *graphpkg.Graph) []model.Candidate {
	values := strongProcessRule{}.Evaluate(context.Background(), g)
	for index := range values {
		values[index].RuleID = "test.p0-process"
		values[index].Priority = model.PriorityP0
	}
	return values
}

func containsTestFragment(values []string, fragment string) bool {
	for _, value := range values {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}

type fakeAdapter struct {
	mu        sync.Mutex
	caps      adapter.Capabilities
	calls     []string
	results   map[string][]adapter.ExecResult
	errors    map[string][]error
	delay     time.Duration
	active    int
	maxActive int
}

type cancellingAdapter struct {
	cancel context.CancelFunc
}

type variantAdapter struct {
	variants []string
}

func (a *variantAdapter) Open(context.Context) (adapter.Capabilities, error) {
	return adapter.Capabilities{TransportKind: "ssh", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20}, nil
}
func (a *variantAdapter) Close(context.Context) error { return nil }
func (a *variantAdapter) Exec(_ context.Context, request adapter.ExecRequest) (adapter.ExecResult, error) {
	a.variants = append(a.variants, request.VariantID)
	if request.VariantID == "manager" {
		return adapter.ExecResult{Stdout: []byte("manager unavailable\n"), Status: model.ProbeComplete}, nil
	}
	return adapter.ExecResult{Stdout: []byte("files complete\n"), Status: model.ProbeComplete}, nil
}

type fallbackCollector struct{}

func (fallbackCollector) ID() string { return "context" }
func (fallbackCollector) Plan(model.HostProfile, collect.Discovery) []probe.Definition {
	return []probe.Definition{{
		ID: "context.fallback", Collector: "context", Parser: "test", RedactionPolicy: "default", SafetyClass: model.PassiveRead,
		Variants: []probe.Variant{
			{ID: "manager", Command: adapter.Command{Script: "printf manager"}},
			{ID: "files", Command: adapter.Command{Script: "printf files"}},
		},
		Timeout: time.Second, MaxOutput: 4096, Produces: []string{"test"}, Idempotent: true,
	}}
}
func (fallbackCollector) Parse(_ probe.Definition, _ adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
	return contextFacts(probe.Definition{}, adapter.ExecResult{}, evidenceID)
}
func (fallbackCollector) Assess(_ probe.Definition, variant probe.Variant, result adapter.ExecResult) collect.ObservationAssessment {
	if variant.ID == "manager" {
		return collect.ObservationAssessment{Status: model.ProbePartial, Fallback: true}
	}
	return collect.ObservationAssessment{Status: result.Status}
}

func (a *cancellingAdapter) Open(context.Context) (adapter.Capabilities, error) {
	return adapter.Capabilities{TransportKind: "ssh", MaxCommandBytes: 1 << 20, MaxOutputBytes: 1 << 20}, nil
}
func (a *cancellingAdapter) Close(context.Context) error { return nil }
func (a *cancellingAdapter) Exec(_ context.Context, request adapter.ExecRequest) (adapter.ExecResult, error) {
	if request.ProbeID == "process.cancelled" {
		a.cancel()
		return adapter.ExecResult{Stdout: []byte("partial-before-signal"), Status: model.ProbePartial}, context.Canceled
	}
	return adapter.ExecResult{Stdout: []byte("ok\n"), Status: model.ProbeComplete}, nil
}

func newFakeAdapter(caps adapter.Capabilities) *fakeAdapter {
	return &fakeAdapter{caps: caps, results: make(map[string][]adapter.ExecResult), errors: make(map[string][]error)}
}

func (a *fakeAdapter) Open(context.Context) (adapter.Capabilities, error) { return a.caps, nil }
func (a *fakeAdapter) Close(context.Context) error                        { return nil }
func (a *fakeAdapter) Exec(ctx context.Context, request adapter.ExecRequest) (adapter.ExecResult, error) {
	a.mu.Lock()
	a.calls = append(a.calls, request.ProbeID)
	index := 0
	for _, call := range a.calls[:len(a.calls)-1] {
		if call == request.ProbeID {
			index++
		}
	}
	a.active++
	if a.active > a.maxActive {
		a.maxActive = a.active
	}
	delay := a.delay
	a.mu.Unlock()
	if delay > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(delay):
		}
	}
	a.mu.Lock()
	a.active--
	var result adapter.ExecResult
	if values := a.results[request.ProbeID]; index < len(values) {
		result = values[index]
	}
	var err error
	if values := a.errors[request.ProbeID]; index < len(values) {
		err = values[index]
	}
	a.mu.Unlock()
	if result.Status == "" {
		result.Status = model.ProbeComplete
	}
	result.Stdout = append([]byte(nil), result.Stdout...)
	if len(result.Stdout) == 0 {
		result.Stdout = []byte("ok\n")
	}
	return result, err
}
func (a *fakeAdapter) probeCalls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}
func (a *fakeAdapter) callCount(id string) int {
	count := 0
	for _, call := range a.probeCalls() {
		if call == id {
			count++
		}
	}
	return count
}
func (a *fakeAdapter) maxConcurrency() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.maxActive
}

func newTestStore(t *testing.T, sessionID string) *storepkg.Store {
	t.Helper()
	value, err := storepkg.Open(t.TempDir(), sessionID)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func containsString(values []string, wanted string) bool {
	index := sort.SearchStrings(appendSorted(values), wanted)
	values = appendSorted(values)
	return index < len(values) && values[index] == wanted
}

func appendSorted(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
