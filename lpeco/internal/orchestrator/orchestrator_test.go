package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	contextcollect "github.com/normalone/lpeco/internal/collect/context"
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
