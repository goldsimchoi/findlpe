package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	contextcollect "github.com/normalone/lpeco/internal/collect/context"
	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
	"github.com/normalone/lpeco/internal/rules"
	"github.com/normalone/lpeco/internal/store"
)

type Options struct {
	SessionID      string
	TransportKind  string
	Target         string
	Profile        model.HostProfile
	Collectors     []collect.Collector
	PrimaryRules   []rules.Rule
	Rules          []rules.Rule
	Planner        probe.Planner
	Full           bool
	ObservableRead bool
	MaxParallel    int
	Now            func() time.Time
}

type Issue struct {
	Phase   Phase  `json:"phase"`
	ProbeID string `json:"probe_id,omitempty"`
	Message string `json:"message"`
	Err     error  `json:"-"`
}

type Result struct {
	SessionID         string                `json:"session_id"`
	Profile           model.HostProfile     `json:"profile"`
	Checkpoint        model.Checkpoint      `json:"checkpoint"`
	Facts             []model.Fact          `json:"facts"`
	Candidates        []model.Candidate     `json:"candidates"`
	GraphDiagnostics  []graphpkg.Diagnostic `json:"graph_diagnostics"`
	RuleDiagnostics   []rules.Diagnostic    `json:"rule_diagnostics"`
	ObservablePreview []string              `json:"observable_preview"`
	Issues            []Issue               `json:"issues"`
	Phases            []Phase               `json:"phases"`
}

type RunError struct{ Issues []Issue }

func (e *RunError) Error() string {
	if e == nil || len(e.Issues) == 0 {
		return ""
	}
	return fmt.Sprintf("scan completed with %d resumable issue(s): %s", len(e.Issues), e.Issues[0].Message)
}

func (e *RunError) Unwrap() []error {
	values := make([]error, 0, len(e.Issues))
	for _, issue := range e.Issues {
		if issue.Err != nil {
			values = append(values, issue.Err)
		}
	}
	return values
}

type sessionSaver interface {
	SaveSession(context.Context, model.Session) error
}

type runner struct {
	transport  adapter.Adapter
	store      store.SessionStore
	options    Options
	planner    probe.Planner
	collectors map[string]collect.Collector
	caps       adapter.Capabilities
	session    model.Session
	facts      []model.Fact
	factIDs    map[string]bool
	checkpoint model.Checkpoint
	result     Result
	mu         sync.Mutex
}

func Run(ctx context.Context, transport adapter.Adapter, sessionStore store.SessionStore, options Options) (Result, error) {
	options = normalizeOptions(options)
	if options.SessionID == "" {
		return Result{}, errors.New("session ID is required")
	}
	now := options.Now()
	session := model.Session{SchemaVersion: 1, ID: options.SessionID, CreatedAt: now, UpdatedAt: now, Status: model.SessionRunning,
		TransportKind: options.TransportKind, Target: options.Target, Profile: cloneProfile(options.Profile), Checkpoint: newCheckpoint(now)}
	if err := sessionStore.Create(ctx, session); err != nil {
		return Result{}, fmt.Errorf("create session: %w", err)
	}
	return run(ctx, transport, sessionStore, options, session, nil)
}

func run(ctx context.Context, transport adapter.Adapter, sessionStore store.SessionStore, options Options, session model.Session, initialFacts []model.Fact) (Result, error) {
	r := &runner{
		transport: transport, store: sessionStore, options: options, planner: options.Planner,
		collectors: collectorsByID(options.Collectors), session: session, facts: append([]model.Fact(nil), initialFacts...),
		factIDs: make(map[string]bool), checkpoint: normalizeCheckpoint(session.Checkpoint),
		result: Result{SessionID: options.SessionID, Profile: cloneProfile(session.Profile), ObservablePreview: []string{}, Issues: []Issue{}, Phases: []Phase{}},
	}
	for _, fact := range r.facts {
		r.factIDs[fact.ID] = true
	}
	if r.result.Profile.AvailableCommands == nil {
		r.result.Profile = cloneProfile(options.Profile)
	}

	r.enterPhase(ctx, PhaseProfile)
	capabilities, err := transport.Open(ctx)
	if err != nil {
		r.addIssue(PhaseProfile, "", "open adapter: "+err.Error(), err)
		r.finish(ctx, false)
		return r.finalResult()
	}
	r.caps = capabilities
	if r.session.TransportKind == "" {
		r.session.TransportKind = capabilities.TransportKind
	}
	defer func() { _ = transport.Close(context.Background()) }()

	contextOutcome := r.runCollectorPhase(ctx, PhaseContext, selectCollectors(r.collectors, "context"), collect.Discovery{})
	r.updateProfileFromFacts()
	if contextOutcome.Interrupted || ctx.Err() != nil {
		r.finish(ctx, false)
		return r.finalResult()
	}

	primaryOutcome := r.runCollectorPhase(ctx, PhasePrimary, selectCollectors(r.collectors, "process", "systemd"), collect.Discovery{})
	if primaryOutcome.Interrupted || ctx.Err() != nil {
		r.finish(ctx, false)
		return r.finalResult()
	}

	discovery := discover(r.snapshotFacts())
	r.setPending(ctx, pendingValidation(discovery))
	r.enterPhase(ctx, PhaseTargetedValidation)
	validationOutcome := r.runDefinitions(ctx, PhaseTargetedValidation, planCollectors(selectCollectors(r.collectors, "process", "systemd"), r.result.Profile, discovery))
	if !validationOutcome.Interrupted {
		discovery = discover(r.snapshotFacts())
		r.setPending(ctx, pendingValidation(discovery))
		pathOutcome := r.runDefinitions(ctx, PhaseTargetedValidation, planCollectors(selectCollectors(r.collectors, "path"), r.result.Profile, discovery))
		validationOutcome.Interrupted = pathOutcome.Interrupted
		validationOutcome.Incomplete = validationOutcome.Incomplete || pathOutcome.Incomplete
	}
	if !validationOutcome.Interrupted && !validationOutcome.Incomplete {
		r.setPending(ctx, []string{})
	}
	if validationOutcome.Interrupted || ctx.Err() != nil {
		r.finish(ctx, false)
		return r.finalResult()
	}

	primaryCandidates := r.evaluate(options.PrimaryRules)
	if options.Full || !hasStrongCandidate(primaryCandidates.Candidates) {
		fallbackDiscovery := discover(r.snapshotFacts())
		fallbackOutcome := r.runCollectorPhase(ctx, PhaseFallback, selectCollectors(r.collectors, "scheduler", "binary", "container"), fallbackDiscovery)
		if fallbackOutcome.Interrupted || ctx.Err() != nil {
			r.finish(ctx, false)
			return r.finalResult()
		}
		// Expand only paths introduced by the fallback inventory. This is a
		// single bounded validation pass, not a fixed-point loop.
		fallbackDiscovery = discover(r.snapshotFacts())
		r.setPending(ctx, pendingValidation(fallbackDiscovery))
		expansion := r.runDefinitions(ctx, PhaseFallback, planCollectors(selectCollectors(r.collectors, "binary"), r.result.Profile, fallbackDiscovery))
		if !expansion.Interrupted {
			fallbackDiscovery = discover(r.snapshotFacts())
			r.setPending(ctx, pendingValidation(fallbackDiscovery))
			pathExpansion := r.runDefinitions(ctx, PhaseFallback, planCollectors(selectCollectors(r.collectors, "path"), r.result.Profile, fallbackDiscovery))
			expansion.Interrupted = pathExpansion.Interrupted
			expansion.Incomplete = expansion.Incomplete || pathExpansion.Incomplete
		}
		if !expansion.Interrupted && !expansion.Incomplete {
			r.setPending(ctx, []string{})
		}
		if expansion.Interrupted || ctx.Err() != nil {
			r.finish(ctx, false)
			return r.finalResult()
		}
	}

	r.enterPhase(ctx, PhaseFinalize)
	evaluation := r.evaluate(options.Rules)
	g, graphDiagnostics := graphpkg.Build(r.snapshotFacts())
	_ = g
	r.result.Candidates = evaluation.Candidates
	r.result.RuleDiagnostics = evaluation.Diagnostics
	r.result.GraphDiagnostics = graphDiagnostics
	if err := sessionStore.SaveCandidates(ctx, evaluation.Candidates); err != nil {
		r.addIssue(PhaseFinalize, "", "save candidates: "+err.Error(), err)
	}
	r.finish(ctx, len(r.result.Issues) == 0)
	return r.finalResult()
}

func (r *runner) runCollectorPhase(ctx context.Context, phase Phase, collectors []collect.Collector, discovery collect.Discovery) phaseOutcome {
	r.enterPhase(ctx, phase)
	return r.runDefinitions(ctx, phase, planCollectors(collectors, r.result.Profile, discovery))
}

func (r *runner) evaluate(ruleSet []rules.Rule) rules.Evaluation {
	g, _ := graphpkg.Build(r.snapshotFacts())
	return rules.Evaluate(context.Background(), g, ruleSet)
}

func (r *runner) enterPhase(ctx context.Context, phase Phase) {
	r.mu.Lock()
	r.result.Phases = append(r.result.Phases, phase)
	r.checkpoint.Phase = string(phase)
	r.checkpoint.UpdatedAt = r.options.Now()
	checkpoint := cloneCheckpoint(r.checkpoint)
	r.mu.Unlock()
	if err := r.store.SaveCheckpoint(ctx, checkpoint); err != nil {
		r.addIssue(phase, "", "save checkpoint: "+err.Error(), err)
	}
}

func (r *runner) setPending(ctx context.Context, values []string) {
	r.mu.Lock()
	r.checkpoint.PendingValidation = append([]string(nil), values...)
	r.checkpoint.UpdatedAt = r.options.Now()
	checkpoint := cloneCheckpoint(r.checkpoint)
	r.mu.Unlock()
	if err := r.store.SaveCheckpoint(ctx, checkpoint); err != nil {
		r.addIssue(PhaseTargetedValidation, "", "save pending validation: "+err.Error(), err)
	}
}

func (r *runner) updateProfileFromFacts() {
	profile := cloneProfile(r.result.Profile)
	for _, fact := range r.snapshotFacts() {
		switch fact.Kind {
		case "host":
			var value contextcollect.HostFact
			if json.Unmarshal(fact.Data, &value) == nil {
				profile.OS, profile.Architecture, profile.InitSystem = value.OS, value.Architecture, value.InitSystem
				profile.SystemdRunning = value.SystemdRunning
				profile.AvailableCommands = cloneBools(value.AvailableCommands)
				profile.MissingCapabilities = append([]string(nil), value.MissingFacts...)
			}
		case "namespace":
			var value contextcollect.NamespaceFact
			if json.Unmarshal(fact.Data, &value) == nil {
				profile.NamespaceIDs = cloneStrings(value.IDs)
			}
		}
	}
	r.result.Profile = profile
	r.session.Profile = cloneProfile(profile)
}

func (r *runner) finish(ctx context.Context, complete bool) {
	r.mu.Lock()
	r.session.Checkpoint = cloneCheckpoint(r.checkpoint)
	r.session.Profile = cloneProfile(r.result.Profile)
	r.session.UpdatedAt = r.options.Now()
	if complete {
		r.session.Status = model.SessionComplete
	} else {
		r.session.Status = model.SessionInterrupted
	}
	session := r.session
	r.mu.Unlock()
	if saver, ok := r.store.(sessionSaver); ok {
		if err := saver.SaveSession(ctx, session); err != nil {
			r.addIssue(PhaseFinalize, "", "save session: "+err.Error(), err)
		}
	} else if err := r.store.SaveCheckpoint(ctx, session.Checkpoint); err != nil {
		r.addIssue(PhaseFinalize, "", "save checkpoint: "+err.Error(), err)
	}
}

func (r *runner) finalResult() (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.result.Profile = cloneProfile(r.result.Profile)
	r.result.Checkpoint = cloneCheckpoint(r.checkpoint)
	r.result.Facts = append([]model.Fact(nil), r.facts...)
	sort.Slice(r.result.Facts, func(i, j int) bool { return r.result.Facts[i].ID < r.result.Facts[j].ID })
	r.result.ObservablePreview = uniqueStrings(r.result.ObservablePreview)
	r.result.Issues = append([]Issue(nil), r.result.Issues...)
	result := r.result
	if len(result.Issues) > 0 {
		return result, &RunError{Issues: result.Issues}
	}
	return result, nil
}

func (r *runner) addIssue(phase Phase, probeID, message string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.result.Issues = append(r.result.Issues, Issue{Phase: phase, ProbeID: probeID, Message: message, Err: err})
}

func (r *runner) snapshotFacts() []model.Fact {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]model.Fact(nil), r.facts...)
}

func planCollectors(collectors []collect.Collector, profile model.HostProfile, discovery collect.Discovery) []plannedDefinition {
	byID := make(map[string]plannedDefinition)
	for _, collector := range collectors {
		for _, definition := range collector.Plan(profile, discovery) {
			if _, exists := byID[definition.ID]; !exists {
				byID[definition.ID] = plannedDefinition{Definition: definition, Collector: collector}
			}
		}
	}
	result := make([]plannedDefinition, 0, len(byID))
	for _, value := range byID {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Definition.ID < result[j].Definition.ID })
	return result
}

func normalizeOptions(options Options) Options {
	if options.Now == nil {
		options.Now = func() time.Time { return time.Now().UTC() }
	}
	if options.MaxParallel <= 0 {
		options.MaxParallel = 4
	}
	if options.Planner == nil {
		options.Planner = probe.NewPlanner()
	}
	if options.Collectors == nil {
		options.Collectors = defaultCollectors()
	}
	if options.PrimaryRules == nil {
		options.PrimaryRules = rules.PrimaryRules()
	}
	if options.Rules == nil {
		options.Rules = rules.AllRules()
	}
	return options
}

func newCheckpoint(now time.Time) model.Checkpoint {
	return model.Checkpoint{Phase: string(PhaseProfile), Completed: map[string]model.CompletedProbe{}, RetryCounts: map[string]int{}, PendingValidation: []string{}, UpdatedAt: now}
}

func normalizeCheckpoint(value model.Checkpoint) model.Checkpoint {
	if value.Completed == nil {
		value.Completed = make(map[string]model.CompletedProbe)
	}
	if value.RetryCounts == nil {
		value.RetryCounts = make(map[string]int)
	}
	if value.PendingValidation == nil {
		value.PendingValidation = []string{}
	}
	return value
}

func cloneCheckpoint(value model.Checkpoint) model.Checkpoint {
	result := value
	result.Completed = make(map[string]model.CompletedProbe, len(value.Completed))
	for key, item := range value.Completed {
		result.Completed[key] = item
	}
	result.RetryCounts = make(map[string]int, len(value.RetryCounts))
	for key, item := range value.RetryCounts {
		result.RetryCounts[key] = item
	}
	result.PendingValidation = append([]string(nil), value.PendingValidation...)
	return result
}

func cloneProfile(value model.HostProfile) model.HostProfile {
	result := value
	result.AvailableCommands = cloneBools(value.AvailableCommands)
	result.NamespaceIDs = cloneStrings(value.NamespaceIDs)
	result.MissingCapabilities = append([]string(nil), value.MissingCapabilities...)
	return result
}

func cloneBools(values map[string]bool) map[string]bool {
	if values == nil {
		return nil
	}
	result := make(map[string]bool, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneStrings(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func hasStrongCandidate(values []model.Candidate) bool {
	for _, value := range values {
		if value.Priority == model.PriorityP0 || value.Priority == model.PriorityP1 {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	if result == nil {
		return []string{}
	}
	return result
}

func itoa(value int) string { return strconv.Itoa(value) }

func isRawTransport(kind string) bool { return strings.Contains(strings.ToLower(kind), "raw") }
