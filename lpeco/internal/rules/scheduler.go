package rules

import (
	"context"
	"fmt"

	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
)

type writableScheduledCommandRule struct{}

func (writableScheduledCommandRule) ID() string { return "scheduler.writable-command" }
func (writableScheduledCommandRule) Metadata() Metadata {
	return Metadata{ID: "scheduler.writable-command", Category: "scheduler", Description: "Active scheduler command chain contains a controlled object"}
}

func (rule writableScheduledCommandRule) Evaluate(ctx context.Context, g *graphpkg.Graph) []model.Candidate {
	if g == nil {
		return nil
	}
	current, ok := g.CurrentPrincipal()
	if !ok {
		return nil
	}
	var result []model.Candidate
	for _, scheduler := range g.NodesByKind(model.NodeTrigger) {
		if ctx.Err() != nil {
			break
		}
		if !graphpkg.BoolAttribute(scheduler.Attributes, "scheduler", false) || !graphpkg.BoolAttribute(scheduler.Attributes, "active", false) {
			continue
		}
		for _, runsAs := range g.Outgoing(scheduler.NodeRef, model.EdgeRunsAs) {
			if !privilegeBoundary(g, current, runsAs.To) {
				continue
			}
			dependencies := append(g.Outgoing(scheduler.NodeRef, model.EdgeExecutes), g.Outgoing(scheduler.NodeRef, model.EdgeInterprets)...)
			for _, dependency := range dependencies {
				if !graphpkg.BoolAttribute(dependency.Attributes, "resolved", false) || !graphpkg.BoolAttribute(dependency.Attributes, "valid", false) || objectReadOnly(g, dependency.To) {
					continue
				}
				control, controlled := controlEdge(g, current, dependency.To)
				if !controlled {
					continue
				}
				trigger := scheduler.NodeRef
				rank := Rank(RankInput{PrivilegeBoundary: true, ControlConfirmed: true, TriggerConfirmed: true, SemanticsResolved: true,
					Confidences: []model.Confidence{scheduler.Confidence, runsAs.Confidence, dependency.Confidence, control.Confidence}})
				candidate := newCandidate(rule.Metadata(), rank, current, runsAs.To, scheduler.NodeRef, dependency.To, &trigger,
					[]model.NodeRef{scheduler.NodeRef, dependency.To}, evidenceFor(g, scheduler.NodeRef, runsAs.To, dependency.To, runsAs, dependency, control), nil,
					fmt.Sprintf("Active higher-privilege schedule %s consumes a controlled command object.", scheduler.Label))
				if candidate.ID != "" {
					result = append(result, candidate)
				}
			}
		}
	}
	return result
}

func (rule writableScheduledCommandRule) Diagnostics(ctx context.Context, g *graphpkg.Graph) []Diagnostic {
	return boundaryDiagnostics(ctx, g, rule.ID(), model.NodeTrigger, func(node model.Node) bool {
		return graphpkg.BoolAttribute(node.Attributes, "scheduler", false)
	})
}
