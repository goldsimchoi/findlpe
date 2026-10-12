package orchestrator

import (
	"context"
	"errors"
	"reflect"
	"testing"

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
