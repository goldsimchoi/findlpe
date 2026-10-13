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
	SessionID           string
	TransportKind       string
	Target              string
	Profile             model.HostProfile
	Collectors          []collect.Collector
	PrimaryRules        []rules.Rule
	Rules               []rules.Rule
	Planner             probe.Planner
	Full                bool
	ObservableRead      bool
	BeforeObservable    func([]string) error
	ProcessObservation  time.Duration
	ObservationInterval time.Duration
	MaxParallel         int
	Now                 func() time.Time
	Wait                func(context.Context, time.Duration) error
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
	persistMu  sync.Mutex
	evidence   map[string]model.ProbeStatus
}

func Run(ctx context.Context, transport adapter.Adapter, sessionStore store.SessionStore, options Options) (Result, error) {
	if options.ProcessObservation < 0 {
		return Result{}, errors.New("process observation duration cannot be negative")
	}
	options = normalizeOptions(options)
	if options.SessionID == "" {
		return Result{}, errors.New("session ID is required")
	}
	now := options.Now()
	session := model.Session{SchemaVersion: model.SessionSchemaVersion, ID: options.SessionID, CreatedAt: now, UpdatedAt: now, Status: model.SessionRunning,
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
		result:   Result{SessionID: options.SessionID, Profile: cloneProfile(session.Profile), ObservablePreview: []string{}, Issues: []Issue{}, Phases: []Phase{}},
		evidence: make(map[string]model.ProbeStatus),
	}
	if existingEvidence, evidenceErr := sessionStore.ListEvidence(context.Background()); evidenceErr == nil {
		for _, item := range existingEvidence {
			r.evidence[item.ID] = item.Status
		}
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
	defer func() {
		closeContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = transport.Close(closeContext)
	}()

	contextOutcome := r.runCollectorPhase(ctx, PhaseContext, selectCollectors(r.collectors, "context"), collect.Discovery{})
	r.updateProfileFromFacts()
	if contextOutcome.Interrupted || ctx.Err() != nil {
		r.finish(ctx, false)
		return r.finalResult()
	}

	primaryOutcome := r.runCollectorPhase(ctx, PhasePrimary, selectCollectors(r.collectors, "process", "systemd"), collect.Discovery{})
	if !primaryOutcome.Interrupted {
		observationOutcome := r.observeProcesses(ctx)
		primaryOutcome.Interrupted = observationOutcome.Interrupted
		primaryOutcome.Incomplete = primaryOutcome.Incomplete || observationOutcome.Incomplete
	}
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
	persistContext, cancelPersist := r.persistenceContext()
	if err := sessionStore.SaveCandidates(persistContext, evaluation.Candidates); err != nil {
		r.addIssue(PhaseFinalize, "", "save candidates: "+err.Error(), err)
	}
	cancelPersist()
	r.finish(ctx, len(r.result.Issues) == 0)
	return r.finalResult()
}

func (r *runner) runCollectorPhase(ctx context.Context, phase Phase, collectors []collect.Collector, discovery collect.Discovery) phaseOutcome {
	r.enterPhase(ctx, phase)
	return r.runDefinitions(ctx, phase, planCollectors(collectors, r.result.Profile, discovery))
}

func (r *runner) evaluate(ruleSet []rules.Rule) rules.Evaluation {
	g, _ := graphpkg.Build(r.snapshotFacts())
	evaluation := rules.Evaluate(context.Background(), g, ruleSet)
	for index := range evaluation.Candidates {
		evaluation.Candidates[index] = r.boundCandidateByEvidence(evaluation.Candidates[index])
	}
	return evaluation
}

func (r *runner) enterPhase(ctx context.Context, phase Phase) {
	r.mu.Lock()
	r.result.Phases = append(r.result.Phases, phase)
	r.checkpoint.Phase = string(phase)
	r.checkpoint.UpdatedAt = r.options.Now()
	r.mu.Unlock()
	if err := r.persistCheckpoint(); err != nil {
		r.addIssue(phase, "", "save checkpoint: "+err.Error(), err)
	}
}

func (r *runner) setPending(ctx context.Context, values []string) {
	r.mu.Lock()
	r.checkpoint.PendingValidation = append([]string(nil), values...)
	r.checkpoint.UpdatedAt = r.options.Now()
	r.mu.Unlock()
	if err := r.persistCheckpoint(); err != nil {
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
		case "distribution":
			var value model.DistributionProfile
			if json.Unmarshal(fact.Data, &value) == nil {
				profile.Distribution = cloneDistributionProfile(value)
			}
		case "kernel":
			var value model.KernelProfile
			if json.Unmarshal(fact.Data, &value) == nil {
				profile.Kernel = cloneKernelProfile(value)
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
	r.session.GraphDiagnostics = append([]model.GraphDiagnostic(nil), r.result.GraphDiagnostics...)
	r.session.RuleDiagnostics = append([]model.RuleDiagnostic(nil), r.result.RuleDiagnostics...)
	r.session.UpdatedAt = r.options.Now()
	if complete {
		r.session.Status = model.SessionComplete
	} else {
		r.session.Status = model.SessionInterrupted
	}
	session := r.session
	r.mu.Unlock()
	persistContext, cancelPersist := r.persistenceContext()
	defer cancelPersist()
	if saver, ok := r.store.(sessionSaver); ok {
		if err := saver.SaveSession(persistContext, session); err != nil {
			r.addIssue(PhaseFinalize, "", "save session: "+err.Error(), err)
		}
	} else if err := r.store.SaveCheckpoint(persistContext, session.Checkpoint); err != nil {
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
	if options.ObservationInterval <= 0 {
		options.ObservationInterval = time.Second
	}
	if options.Wait == nil {
		options.Wait = waitForContext
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

func (r *runner) observeProcesses(ctx context.Context) phaseOutcome {
	if r.options.ProcessObservation <= 0 {
		return phaseOutcome{}
	}
	collector, ok := r.collectors["process"]
	if !ok {
		return phaseOutcome{}
	}
	var snapshot probe.Definition
	for _, definition := range collector.Plan(r.result.Profile, collect.Discovery{}) {
		if definition.ID == "process.snapshot" {
			snapshot = definition
			break
		}
	}
	if snapshot.ID == "" {
		return phaseOutcome{}
	}

	outcome := phaseOutcome{}
	for elapsed, index := time.Duration(0), 1; elapsed < r.options.ProcessObservation; index++ {
		wait := r.options.ObservationInterval
		if remaining := r.options.ProcessObservation - elapsed; wait > remaining {
			wait = remaining
		}
		elapsed += wait
		definition := snapshot
		definition.ID = fmt.Sprintf("%s.observe.%04d", snapshot.ID, index)

		r.mu.Lock()
		checkpoint := cloneCheckpoint(r.checkpoint)
		r.mu.Unlock()
		decision := r.planner.ShouldRun(definition, checkpoint, probe.Policy{AllowObservable: r.options.ObservableRead})
		if !decision.Run {
			continue
		}
		if err := r.options.Wait(ctx, wait); err != nil {
			r.addIssue(PhasePrimary, definition.ID, "wait for process observation: "+err.Error(), err)
			outcome.Interrupted = true
			outcome.Incomplete = true
			return outcome
		}
		current := r.runDefinitions(ctx, PhasePrimary, []plannedDefinition{{Definition: definition, Collector: collector}})
		outcome.Interrupted = outcome.Interrupted || current.Interrupted
		outcome.Incomplete = outcome.Incomplete || current.Incomplete
		if current.Interrupted {
			return outcome
		}
	}
	return outcome
}

func waitForContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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
	result.Distribution = cloneDistributionProfile(value.Distribution)
	result.Kernel = cloneKernelProfile(value.Kernel)
	return result
}

func cloneDistributionProfile(value model.DistributionProfile) model.DistributionProfile {
	value.IDLike = append([]string(nil), value.IDLike...)
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	value.MissingFacts = append([]string(nil), value.MissingFacts...)
	return value
}

func cloneKernelProfile(value model.KernelProfile) model.KernelProfile {
	value.EvidenceIDs = append([]string(nil), value.EvidenceIDs...)
	value.MissingFacts = append([]string(nil), value.MissingFacts...)
	return value
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
		if (value.Priority == model.PriorityP0 || value.Priority == model.PriorityP1) && value.ValidationStatus != model.ValidationIncomplete {
			return true
		}
	}
	return false
}

func (r *runner) persistCheckpoint() error {
	r.persistMu.Lock()
	defer r.persistMu.Unlock()
	r.mu.Lock()
	checkpoint := cloneCheckpoint(r.checkpoint)
	r.mu.Unlock()
	persistContext, cancelPersist := r.persistenceContext()
	defer cancelPersist()
	return r.store.SaveCheckpoint(persistContext, checkpoint)
}

func (r *runner) persistenceContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

func (r *runner) boundCandidateByEvidence(candidate model.Candidate) model.Candidate {
	r.mu.Lock()
	statuses := make(map[string]model.ProbeStatus, len(candidate.EvidenceIDs))
	for _, evidenceID := range candidate.EvidenceIDs {
		if status, ok := r.evidence[evidenceID]; ok {
			statuses[evidenceID] = status
		}
	}
	r.mu.Unlock()
	severe := false
	for evidenceID, status := range statuses {
		if status == "" || status == model.ProbeComplete {
			continue
		}
		candidate.MissingFacts = append(candidate.MissingFacts, fmt.Sprintf("observation %s is %s", evidenceID, status))
		switch status {
		case model.ProbeUnavailable, model.ProbeTimeout, model.ProbeParseError:
			severe = true
		}
	}
	if len(candidate.MissingFacts) == 0 {
		return candidate
	}
	candidate.MissingFacts = uniqueStrings(candidate.MissingFacts)
	if candidate.Priority == model.PriorityP0 {
		candidate.Priority = model.PriorityP1
	}
	if severe {
		candidate.Confidence = model.ConfidenceLow
	} else if candidate.Confidence == model.ConfidenceHigh {
		candidate.Confidence = model.ConfidenceMedium
	}
	candidate.ValidationStatus = model.ValidationIncomplete
	return candidate
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
