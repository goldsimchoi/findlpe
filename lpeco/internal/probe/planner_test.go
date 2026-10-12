package probe

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/model"
)

func TestPlannerSafetyMatrix(t *testing.T) {
	planner := NewPlanner()
	tests := []struct {
		name          string
		safety        model.SafetyClass
		policy        Policy
		wantRun       bool
		wantOptIn     bool
		wantUnsafeErr bool
	}{
		{name: "passive runs", safety: model.PassiveRead, wantRun: true},
		{name: "observable previews without opt-in", safety: model.ObservableRead, wantOptIn: true},
		{name: "observable runs with opt-in", safety: model.ObservableRead, policy: Policy{AllowObservable: true}, wantRun: true},
		{name: "temporary artifacts are always denied", safety: model.TemporaryArtifact, wantUnsafeErr: true},
		{name: "state changes are always denied", safety: model.StateChanging, wantUnsafeErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			definition := testDefinition("safety.test", tt.safety)
			decision := planner.ShouldRun(definition, model.Checkpoint{}, tt.policy)
			if decision.Run != tt.wantRun || decision.RequiresOptIn != tt.wantOptIn {
				t.Fatalf("decision = %#v", decision)
			}
			if errors.Is(decision.Err, ErrUnsafeProbe) != tt.wantUnsafeErr {
				t.Fatalf("decision error = %v, unsafe=%v", decision.Err, tt.wantUnsafeErr)
			}
		})
	}
}

func TestPlannerSelectsFirstSupportedVariantAndClampsOutput(t *testing.T) {
	definition := testDefinition("variant.test", model.PassiveRead)
	definition.MaxOutput = 4096
	definition.Variants = []Variant{
		{
			ID:           "separate-stderr",
			Command:      adapter.Command{Script: "printf first"},
			Requirements: []Requirement{RequireSeparateStderr},
		},
		{
			ID:      "portable",
			Command: adapter.Command{Script: "printf second"},
		},
	}
	capabilities := adapter.Capabilities{MaxCommandBytes: 1024, MaxOutputBytes: 512}

	selected, err := NewPlanner().Select(definition, capabilities, model.HostProfile{}, Policy{})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if selected.ID != "portable" || selected.MaxOutput != 512 {
		t.Fatalf("selected = %#v, want portable with 512-byte output cap", selected)
	}
}

func TestPlannerRejectsUnsupportedAndOversizedCommands(t *testing.T) {
	t.Run("unsupported requirement", func(t *testing.T) {
		definition := testDefinition("unsupported.test", model.PassiveRead)
		definition.Variants[0].Requirements = []Requirement{CommandRequirement("getfacl")}
		_, err := NewPlanner().Select(definition, adapter.Capabilities{}, model.HostProfile{}, Policy{})
		if !errors.Is(err, adapter.ErrUnsupported) {
			t.Fatalf("Select error = %v, want ErrUnsupported", err)
		}
	})

	t.Run("command limit", func(t *testing.T) {
		definition := testDefinition("large.test", model.PassiveRead)
		definition.Variants[0].Command = adapter.Command{Script: "printf '%s' 1234567890"}
		_, err := NewPlanner().Select(definition, adapter.Capabilities{MaxCommandBytes: 8}, model.HostProfile{}, Policy{})
		if !errors.Is(err, adapter.ErrCommandTooLarge) {
			t.Fatalf("Select error = %v, want ErrCommandTooLarge", err)
		}
	})
}

func TestPlannerSkipsCompletedProbeAndLimitsRetries(t *testing.T) {
	planner := NewPlanner()
	definition := testDefinition("process.snapshot", model.PassiveRead)

	completed := model.Checkpoint{Completed: map[string]model.CompletedProbe{
		"process.snapshot|abc": {
			ProbeID:          "process.snapshot",
			InputFingerprint: "abc",
			Status:           model.ProbeComplete,
		},
	}}
	decision := planner.ShouldRun(definition, completed, Policy{})
	if decision.Run || decision.Reason != ReasonCompleted {
		t.Fatalf("completed decision = %#v", decision)
	}

	retried := model.Checkpoint{RetryCounts: map[string]int{"process.snapshot|abc": 1}}
	decision = planner.ShouldRun(definition, retried, Policy{})
	if decision.Run || decision.Reason != ReasonRetryLimit {
		t.Fatalf("retry decision = %#v", decision)
	}

	definition.Idempotent = false
	decision = planner.ShouldRun(definition, model.Checkpoint{RetryCounts: map[string]int{"process.snapshot|abc": 0}}, Policy{})
	if !decision.Run {
		t.Fatalf("first non-idempotent execution denied: %#v", decision)
	}
	decision = planner.ShouldRun(definition, model.Checkpoint{RetryCounts: map[string]int{"process.snapshot|abc": 1}}, Policy{})
	if decision.Run || decision.Reason != ReasonNotRetryable {
		t.Fatalf("non-idempotent retry decision = %#v", decision)
	}
}

func TestRegistryRejectsDuplicateProbeAndReturnsCopies(t *testing.T) {
	definition := testDefinition("identity.current", model.PassiveRead)
	if _, err := NewRegistry([]Definition{definition, definition}); !errors.Is(err, ErrDuplicateProbe) {
		t.Fatalf("NewRegistry duplicate error = %v", err)
	}

	registry, err := NewRegistry([]Definition{definition})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	got, ok := registry.Get("identity.current")
	if !ok {
		t.Fatal("registered definition not found")
	}
	got.Variants[0].Command.Args = append(got.Variants[0].Command.Args, "mutated")
	again, _ := registry.Get("identity.current")
	if len(again.Variants[0].Command.Args) != 0 {
		t.Fatalf("registry exposed mutable command args: %#v", again)
	}
}

func TestPreviewObservableReturnsOnlyPendingProbeIDsInOrder(t *testing.T) {
	definitions := []Definition{
		testDefinition("z.observable", model.ObservableRead),
		testDefinition("passive", model.PassiveRead),
		testDefinition("a.observable", model.ObservableRead),
	}
	checkpoint := model.Checkpoint{Completed: map[string]model.CompletedProbe{
		"z.observable|abc": {ProbeID: "z.observable", Status: model.ProbeComplete},
	}}

	got := PreviewObservable(definitions, checkpoint)
	want := []string{"a.observable"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PreviewObservable() = %#v, want %#v", got, want)
	}
}

func testDefinition(id string, safety model.SafetyClass) Definition {
	return Definition{
		ID:              id,
		Collector:       "test",
		Parser:          "test",
		RedactionPolicy: "default",
		SafetyClass:     safety,
		Variants: []Variant{{
			ID:      "portable",
			Command: adapter.Command{Script: "printf ok"},
		}},
		Timeout:    time.Second,
		MaxOutput:  1024,
		Produces:   []string{"test.fact"},
		Idempotent: true,
	}
}
