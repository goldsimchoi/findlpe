package orchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	Interrupted bool
	Incomplete  bool
}

type executionJob struct {
	planned    plannedDefinition
	variant    probe.Variant
	base       string
	attempt    int
	wasRetried bool
}

func (r *runner) runDefinitions(ctx context.Context, phase Phase, planned []plannedDefinition) phaseOutcome {
	jobs := make([]executionJob, 0, len(planned))
	policy := probe.Policy{AllowObservable: r.options.ObservableRead}
	for _, item := range planned {
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
	}
	if len(jobs) == 0 {
		return phaseOutcome{}
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
	outcome := phaseOutcome{}
	for value := range resultChannel {
		outcome.Interrupted = outcome.Interrupted || value.Interrupted
		outcome.Incomplete = outcome.Incomplete || value.Incomplete
	}
	return outcome
}

func (r *runner) executeJob(ctx context.Context, phase Phase, job executionJob) phaseOutcome {
	outcome := r.executeAttempt(ctx, phase, job)
	if outcome.Interrupted || !outcome.Incomplete || job.attempt > 0 || !job.planned.Definition.Idempotent || job.planned.Definition.SafetyClass != model.PassiveRead {
		return outcome
	}
	r.mu.Lock()
	r.checkpoint.RetryCounts[job.planned.Definition.ID+"|"+job.base] = 1
	r.checkpoint.UpdatedAt = r.options.Now()
	checkpoint := cloneCheckpoint(r.checkpoint)
	r.mu.Unlock()
	if err := r.store.SaveCheckpoint(ctx, checkpoint); err != nil {
		r.addIssue(phase, job.planned.Definition.ID, "save retry checkpoint: "+err.Error(), err)
		return phaseOutcome{Interrupted: true, Incomplete: true}
	}
	job.attempt = 1
	job.wasRetried = true
	return r.executeAttempt(ctx, phase, job)
}

func (r *runner) executeAttempt(ctx context.Context, phase Phase, job executionJob) phaseOutcome {
	definition := job.planned.Definition
	fingerprint := fmt.Sprintf("%s-attempt-%d", job.base, job.attempt)
	request := adapter.ExecRequest{ProbeID: definition.ID, VariantID: job.variant.ID, Command: job.variant.Command, Timeout: definition.Timeout, MaxOutput: job.variant.MaxOutput}
	result, execErr := r.transport.Exec(ctx, request)
	if execErr != nil {
		r.recordCompletion(ctx, phase, definition.ID, fingerprint, model.ProbeUnavailable, "")
		r.addIssue(phase, definition.ID, "execute probe: "+execErr.Error(), execErr)
		return phaseOutcome{Interrupted: true, Incomplete: true}
	}
	if result.StartedAt.IsZero() {
		result.StartedAt = r.options.Now()
	}
	if result.FinishedAt.IsZero() {
		result.FinishedAt = r.options.Now()
	}
	if result.Status == "" {
		result.Status = model.ProbeComplete
	}
	if result.Truncated && result.Status == model.ProbeComplete {
		result.Status = model.ProbeTruncated
	}
	body := evidenceBody(result)
	evidenceID, err := predictedEvidenceID(r.options.SessionID, definition.ID, fingerprint, body)
	if err != nil {
		r.addIssue(phase, definition.ID, "derive evidence ID: "+err.Error(), err)
		return phaseOutcome{Interrupted: true, Incomplete: true}
	}
	facts, parseErr := job.planned.Collector.Parse(definition, result, evidenceID)
	status := result.Status
	if parseErr != nil {
		status = model.ProbeParseError
	}
	evidence := model.Evidence{
		SessionID: r.options.SessionID, ProbeID: definition.ID, VariantID: job.variant.ID, Adapter: r.caps.TransportKind,
		InputFingerprint: fingerprint, StartedAt: result.StartedAt, FinishedAt: result.FinishedAt,
		Status: status, ExitCode: result.ExitCode, MergedOutput: result.MergedOutput, Truncated: result.Truncated,
	}
	stored, _, storeErr := r.store.PutEvidence(ctx, evidence, bytes.NewReader(body))
	if storeErr != nil {
		r.addIssue(phase, definition.ID, "store evidence: "+storeErr.Error(), storeErr)
		return phaseOutcome{Interrupted: true, Incomplete: true}
	}
	if stored.ID != evidenceID {
		err := fmt.Errorf("evidence ID mismatch: predicted %s, stored %s", evidenceID, stored.ID)
		r.addIssue(phase, definition.ID, err.Error(), err)
		return phaseOutcome{Interrupted: true, Incomplete: true}
	}
	if parseErr != nil {
		r.addIssue(phase, definition.ID, "parse probe output: "+parseErr.Error(), parseErr)
		facts = nil
	}
	if err := r.appendUniqueFacts(ctx, facts); err != nil {
		r.addIssue(phase, definition.ID, "store facts: "+err.Error(), err)
		return phaseOutcome{Interrupted: true, Incomplete: true}
	}
	r.recordCompletion(ctx, phase, definition.ID, fingerprint, status, stored.ID)
	incomplete := status != model.ProbeComplete || result.Truncated
	return phaseOutcome{Incomplete: incomplete}
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

func (r *runner) recordCompletion(ctx context.Context, phase Phase, probeID, fingerprint string, status model.ProbeStatus, evidenceID string) {
	r.mu.Lock()
	key := probeID + "|" + fingerprint
	r.checkpoint.Completed[key] = model.CompletedProbe{ProbeID: probeID, InputFingerprint: fingerprint, Status: status, EvidenceID: evidenceID}
	r.checkpoint.UpdatedAt = r.options.Now()
	checkpoint := cloneCheckpoint(r.checkpoint)
	r.mu.Unlock()
	if err := r.store.SaveCheckpoint(ctx, checkpoint); err != nil {
		r.addIssue(phase, probeID, "save probe checkpoint: "+err.Error(), err)
	}
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
