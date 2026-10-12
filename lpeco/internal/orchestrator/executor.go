package orchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

type plannedDefinition struct {
	Definition probe.Definition
	Collector  collect.Collector
}

type phaseOutcome struct {
	Interrupted   bool
	Incomplete    bool
	ExecutionErr  error
	ParseErr      error
	Status        model.ProbeStatus
	NeedsFallback bool
	Facts         []model.Fact
}

type executionJob struct {
	planned    plannedDefinition
	variant    probe.Variant
	base       string
	attempt    int
	wasRetried bool
}

func (r *runner) runDefinitions(ctx context.Context, phase Phase, planned []plannedDefinition) phaseOutcome {
	definitions := make([]probe.Definition, 0, len(planned))
	for _, item := range planned {
		definitions = append(definitions, item.Definition)
	}
	registry, registryErr := probe.NewRegistry(definitions)
	if registryErr != nil {
		r.addIssue(phase, "", "build immutable probe registry: "+registryErr.Error(), registryErr)
		return phaseOutcome{Interrupted: true, Incomplete: true}
	}
	jobs := make([]executionJob, 0, len(planned))
	observableIDs := make([]string, 0)
	outcome := phaseOutcome{}
	policy := probe.Policy{AllowObservable: r.options.ObservableRead}
	for _, item := range planned {
		definition, registered := registry.Get(item.Definition.ID)
		if !registered {
			err := fmt.Errorf("probe %q is not registered", item.Definition.ID)
			r.addIssue(phase, item.Definition.ID, err.Error(), err)
			outcome.Incomplete = true
			continue
		}
		item.Definition = definition
		r.mu.Lock()
		checkpoint := cloneCheckpoint(r.checkpoint)
		r.mu.Unlock()
		decision := r.planner.ShouldRun(item.Definition, checkpoint, policy)
		switch {
		case decision.RequiresOptIn:
			r.mu.Lock()
			r.result.ObservablePreview = append(r.result.ObservablePreview, item.Definition.ID)
			r.mu.Unlock()
			continue
		case decision.Err != nil:
			r.addIssue(phase, item.Definition.ID, decision.Err.Error(), decision.Err)
			continue
		case !decision.Run:
			if (decision.Reason == probe.ReasonRetryLimit || decision.Reason == probe.ReasonNotRetryable) && hasIncompleteProbe(checkpoint, item.Definition.ID) {
				err := fmt.Errorf("probe remains incomplete after its retry budget was exhausted")
				r.addIssue(phase, item.Definition.ID, err.Error(), err)
				outcome.Incomplete = true
			}
			continue
		}
		variant, err := r.planner.Select(item.Definition, r.caps, r.result.Profile, policy)
		if err != nil {
			r.addIssue(phase, item.Definition.ID, "select probe variant: "+err.Error(), err)
			continue
		}
		base, err := inputFingerprint(item.Definition, variant)
		if err != nil {
			r.addIssue(phase, item.Definition.ID, "fingerprint probe: "+err.Error(), err)
			continue
		}
		attempt := 0
		r.mu.Lock()
		if hasIncompleteProbe(r.checkpoint, item.Definition.ID) {
			attempt = 1
			r.checkpoint.RetryCounts[item.Definition.ID+"|"+base] = 1
		}
		r.mu.Unlock()
		jobs = append(jobs, executionJob{planned: item, variant: variant, base: base, attempt: attempt, wasRetried: attempt > 0})
		if item.Definition.SafetyClass == model.ObservableRead {
			observableIDs = append(observableIDs, item.Definition.ID)
			r.mu.Lock()
			r.result.ObservablePreview = append(r.result.ObservablePreview, item.Definition.ID)
			r.mu.Unlock()
		}
	}
	if len(jobs) == 0 {
		return outcome
	}
	if len(observableIDs) > 0 {
		observableIDs = uniqueStrings(observableIDs)
		if r.options.BeforeObservable == nil {
			err := errors.New("observable-read probes require a pre-execution disclosure callback")
			r.addIssue(phase, "", err.Error(), err)
			outcome.Interrupted = true
			outcome.Incomplete = true
			return outcome
		}
		if err := r.options.BeforeObservable(append([]string(nil), observableIDs...)); err != nil {
			r.addIssue(phase, "", "disclose observable-read probes: "+err.Error(), err)
			outcome.Interrupted = true
			outcome.Incomplete = true
			return outcome
		}
	}
	parallel := r.options.MaxParallel
	if parallel > len(jobs) {
		parallel = len(jobs)
	}
	if parallel < 1 || !r.caps.AsyncTasks || isRawTransport(r.caps.TransportKind) {
		parallel = 1
	}
	jobChannel := make(chan executionJob)
	resultChannel := make(chan phaseOutcome, len(jobs))
	var workers sync.WaitGroup
	for index := 0; index < parallel; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobChannel {
				resultChannel <- r.executeJob(ctx, phase, job)
			}
		}()
	}
	go func() {
		for _, job := range jobs {
			jobChannel <- job
		}
		close(jobChannel)
		workers.Wait()
		close(resultChannel)
	}()
	for value := range resultChannel {
		outcome.Interrupted = outcome.Interrupted || value.Interrupted
		outcome.Incomplete = outcome.Incomplete || value.Incomplete
	}
	return outcome
}

func (r *runner) executeJob(ctx context.Context, phase Phase, job executionJob) phaseOutcome {
	outcome := r.executeAttempt(ctx, phase, job)
	if outcome.NeedsFallback && !outcome.Interrupted {
		fallback, err := r.fallbackJob(job)
		if err != nil {
			r.addIssue(phase, job.planned.Definition.ID, "select passive fallback: "+err.Error(), err)
			return r.reportFinalOutcome(phase, job.planned.Definition.ID, outcome)
		}
		fallbackOutcome := r.executeAttempt(ctx, phase, fallback)
		// A collector-requested fallback may provide a different half of the
		// observation (for example, systemd runtime authority followed by unit
		// file provenance). Keep both, but let complete fallback facts win ID
		// collisions over partial facts from the first variant.
		fallbackOutcome.Facts = append(fallbackOutcome.Facts, outcome.Facts...)
		return r.reportFinalOutcome(phase, job.planned.Definition.ID, fallbackOutcome)
	}
	if outcome.Interrupted || !outcome.Incomplete || job.attempt > 0 || !job.planned.Definition.Idempotent || job.planned.Definition.SafetyClass != model.PassiveRead {
		return r.reportFinalOutcome(phase, job.planned.Definition.ID, outcome)
	}
	r.mu.Lock()
	r.checkpoint.RetryCounts[job.planned.Definition.ID+"|"+job.base] = 1
	r.checkpoint.UpdatedAt = r.options.Now()
	r.mu.Unlock()
	if err := r.persistCheckpoint(); err != nil {
		r.addIssue(phase, job.planned.Definition.ID, "save retry checkpoint: "+err.Error(), err)
		outcome.Interrupted = true
		return r.reportFinalOutcome(phase, job.planned.Definition.ID, outcome)
	}
	job.attempt = 1
	job.wasRetried = true
	// A retry supersedes the first incomplete observation. Its raw evidence
	// remains stored, while only facts derived from the final attempt enter the
	// semantic graph.
	return r.reportFinalOutcome(phase, job.planned.Definition.ID, r.executeAttempt(ctx, phase, job))
}

func (r *runner) fallbackJob(job executionJob) (executionJob, error) {
	definition := job.planned.Definition
	selected := -1
	for index, variant := range definition.Variants {
		if variant.ID == job.variant.ID {
			selected = index
			break
		}
	}
	if selected < 0 || selected+1 >= len(definition.Variants) {
		return executionJob{}, fmt.Errorf("probe %q has no remaining variant", definition.ID)
	}
	definition.Variants = append([]probe.Variant(nil), definition.Variants[selected+1:]...)
	variant, err := r.planner.Select(definition, r.caps, r.result.Profile, probe.Policy{AllowObservable: r.options.ObservableRead})
	if err != nil {
		return executionJob{}, err
	}
	base, err := inputFingerprint(definition, variant)
	if err != nil {
		return executionJob{}, err
	}
	job.planned.Definition = definition
	job.variant = variant
	job.base = base
	job.attempt = 0
	job.wasRetried = false
	return job, nil
}

func (r *runner) reportFinalOutcome(phase Phase, probeID string, outcome phaseOutcome) phaseOutcome {
	reported := false
	persistContext, cancelPersist := r.persistenceContext()
	defer cancelPersist()
	if err := r.appendUniqueFacts(persistContext, outcome.Facts); err != nil {
		r.addIssue(phase, probeID, "store facts: "+err.Error(), err)
		outcome.Interrupted = true
		outcome.Incomplete = true
		reported = true
	}
	outcome.Facts = nil
	if outcome.ExecutionErr != nil {
		r.addIssue(phase, probeID, "execute probe: "+outcome.ExecutionErr.Error(), outcome.ExecutionErr)
		outcome.ExecutionErr = nil
		reported = true
	}
	if outcome.ParseErr != nil {
		r.addIssue(phase, probeID, "parse probe output: "+outcome.ParseErr.Error(), outcome.ParseErr)
		outcome.ParseErr = nil
		reported = true
	}
	if outcome.Incomplete && !reported {
		err := fmt.Errorf("probe observation is %s", outcome.Status)
		r.addIssue(phase, probeID, err.Error(), err)
	}
	return outcome
}

func (r *runner) executeAttempt(ctx context.Context, phase Phase, job executionJob) phaseOutcome {
	definition := job.planned.Definition
	fingerprint := fmt.Sprintf("%s-attempt-%d", job.base, job.attempt)
	request := adapter.ExecRequest{ProbeID: definition.ID, VariantID: job.variant.ID, Command: job.variant.Command, Timeout: definition.Timeout, MaxOutput: job.variant.MaxOutput}
	result, execErr := r.transport.Exec(ctx, request)
	if result.StartedAt.IsZero() {
		result.StartedAt = r.options.Now()
	}
	if result.FinishedAt.IsZero() {
		result.FinishedAt = r.options.Now()
	}
	if execErr != nil && (result.Status == "" || result.Status == model.ProbeComplete) {
		switch {
		case errors.Is(execErr, context.DeadlineExceeded):
			result.Status = model.ProbeTimeout
		case len(result.Stdout) > 0 || len(result.Stderr) > 0:
			result.Status = model.ProbePartial
		default:
			result.Status = model.ProbeUnavailable
		}
	} else if result.Status == "" {
		result.Status = model.ProbeComplete
	}
	if result.Truncated && result.Status == model.ProbeComplete {
		result.Status = model.ProbeTruncated
	}
	if result.ExitCode != nil && *result.ExitCode != 0 && result.Status == model.ProbeComplete {
		if len(result.Stdout) > 0 || len(result.Stderr) > 0 {
			result.Status = model.ProbePartial
		} else {
			result.Status = model.ProbeUnavailable
		}
	}
	needsFallback := false
	if assessor, ok := job.planned.Collector.(collect.ObservationAssessor); ok {
		assessment := assessor.Assess(definition, job.variant, result)
		if assessment.Status != "" {
			result.Status = assessment.Status
		}
		needsFallback = assessment.Fallback
	}
	body := evidenceBody(result)
	evidenceID, err := predictedEvidenceID(r.options.SessionID, definition.ID, fingerprint, body)
	if err != nil {
		r.addIssue(phase, definition.ID, "derive evidence ID: "+err.Error(), err)
		return phaseOutcome{Interrupted: true, Incomplete: true}
	}
	var facts []model.Fact
	var parseErr error
	if execErr == nil || len(result.Stdout) > 0 {
		facts, parseErr = job.planned.Collector.Parse(definition, result, evidenceID)
	}
	status := result.Status
	if parseErr != nil && status == model.ProbeComplete {
		status = model.ProbeParseError
	}
	facts = annotateObservation(facts, status, definition.ID)
	evidence := model.Evidence{
		SessionID: r.options.SessionID, ProbeID: definition.ID, VariantID: job.variant.ID, Adapter: r.caps.TransportKind,
		InputFingerprint: fingerprint, StartedAt: result.StartedAt, FinishedAt: result.FinishedAt,
		Status: status, ExitCode: result.ExitCode, MergedOutput: result.MergedOutput, Truncated: result.Truncated,
	}
	persistContext, cancelPersist := r.persistenceContext()
	defer cancelPersist()
	stored, _, storeErr := r.store.PutEvidence(persistContext, evidence, bytes.NewReader(body))
	if storeErr != nil {
		r.addIssue(phase, definition.ID, "store evidence: "+storeErr.Error(), storeErr)
		return phaseOutcome{Interrupted: true, Incomplete: true}
	}
	if stored.ID != evidenceID {
		err := fmt.Errorf("evidence ID mismatch: predicted %s, stored %s", evidenceID, stored.ID)
		r.addIssue(phase, definition.ID, err.Error(), err)
		return phaseOutcome{Interrupted: true, Incomplete: true}
	}
	r.mu.Lock()
	r.evidence[stored.ID] = status
	r.mu.Unlock()
	if parseErr != nil {
		facts = nil
	}
	r.recordCompletion(phase, definition.ID, fingerprint, status, stored.ID)
	incomplete := status != model.ProbeComplete || result.Truncated
	if execErr != nil {
		fatal := ctx.Err() != nil || isRawTransport(r.caps.TransportKind) || !adapter.IsRetryable(execErr)
		return phaseOutcome{Interrupted: fatal, Incomplete: true, ExecutionErr: execErr, ParseErr: parseErr, Status: status, NeedsFallback: needsFallback, Facts: facts}
	}
	return phaseOutcome{Incomplete: incomplete, ParseErr: parseErr, Status: status, NeedsFallback: needsFallback, Facts: facts}
}

func (r *runner) appendUniqueFacts(ctx context.Context, facts []model.Fact) error {
	if len(facts) == 0 {
		return nil
	}
	r.mu.Lock()
	unique := make([]model.Fact, 0, len(facts))
	for _, fact := range facts {
		if fact.ID == "" || r.factIDs[fact.ID] {
			continue
		}
		r.factIDs[fact.ID] = true
		unique = append(unique, fact)
	}
	r.mu.Unlock()
	if len(unique) == 0 {
		return nil
	}
	if err := r.store.AppendFacts(ctx, unique); err != nil {
		r.mu.Lock()
		for _, fact := range unique {
			delete(r.factIDs, fact.ID)
		}
		r.mu.Unlock()
		return err
	}
	r.mu.Lock()
	r.facts = append(r.facts, unique...)
	r.mu.Unlock()
	return nil
}

func (r *runner) recordCompletion(phase Phase, probeID, fingerprint string, status model.ProbeStatus, evidenceID string) {
	r.mu.Lock()
	key := probeID + "|" + fingerprint
	r.checkpoint.Completed[key] = model.CompletedProbe{ProbeID: probeID, InputFingerprint: fingerprint, Status: status, EvidenceID: evidenceID}
	r.checkpoint.UpdatedAt = r.options.Now()
	r.mu.Unlock()
	if err := r.persistCheckpoint(); err != nil {
		r.addIssue(phase, probeID, "save probe checkpoint: "+err.Error(), err)
	}
}

func annotateObservation(facts []model.Fact, status model.ProbeStatus, probeID string) []model.Fact {
	if status == "" {
		status = model.ProbeUnavailable
	}
	for index := range facts {
		facts[index].ObservationStatus = status
		if status == model.ProbeComplete {
			continue
		}
		facts[index].MissingFacts = uniqueStrings(append(facts[index].MissingFacts, fmt.Sprintf("probe %s observation is %s", probeID, status)))
		switch status {
		case model.ProbeUnavailable, model.ProbeTimeout, model.ProbeParseError:
			facts[index].Confidence = model.ConfidenceLow
		default:
			if facts[index].Confidence == model.ConfidenceHigh || facts[index].Confidence == "" {
				facts[index].Confidence = model.ConfidenceMedium
			}
		}
	}
	return facts
}

func inputFingerprint(definition probe.Definition, variant probe.Variant) (string, error) {
	rendered, err := adapter.RenderPOSIX(variant.Command)
	if err != nil {
		return "", err
	}
	return model.StableID("input", struct {
		ProbeID   string `json:"probe_id"`
		VariantID string `json:"variant_id"`
		Command   string `json:"command"`
		MaxOutput int    `json:"max_output"`
	}{definition.ID, variant.ID, rendered, variant.MaxOutput})
}

func evidenceBody(result adapter.ExecResult) []byte {
	if result.MergedOutput || len(result.Stderr) == 0 {
		return append([]byte(nil), result.Stdout...)
	}
	value := append([]byte(nil), result.Stdout...)
	value = append(value, []byte("\n--- STDERR ---\n")...)
	value = append(value, result.Stderr...)
	return value
}

func predictedEvidenceID(sessionID, probeID, fingerprint string, body []byte) (string, error) {
	digest := sha256.Sum256(body)
	return model.StableID("evidence", struct {
		SessionID, ProbeID, InputFingerprint, SHA256 string
	}{sessionID, probeID, fingerprint, hex.EncodeToString(digest[:])})
}

func hasIncompleteProbe(checkpoint model.Checkpoint, probeID string) bool {
	for _, completed := range checkpoint.Completed {
		if completed.ProbeID == probeID && completed.Status != model.ProbeComplete {
			return true
		}
	}
	return false
}
