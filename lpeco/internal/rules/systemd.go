package rules

import (
	"context"
	"fmt"

	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
)

type writableUnitSourceRule struct{}
type writableExecChainRule struct{}
type controlledEnvironmentRule struct{}
type controlledSearchPathRule struct{}

func (writableUnitSourceRule) ID() string { return "systemd.writable-unit-source" }
func (writableUnitSourceRule) Metadata() Metadata {
	return Metadata{ID: "systemd.writable-unit-source", Category: "systemd", Description: "Applied unit source is controlled across a privilege boundary"}
}
func (writableExecChainRule) ID() string { return "systemd.writable-exec-chain" }
func (writableExecChainRule) Metadata() Metadata {
	return Metadata{ID: "systemd.writable-exec-chain", Category: "systemd", Description: "Unit executable chain is controlled across a privilege boundary"}
}
func (controlledEnvironmentRule) ID() string { return "systemd.controlled-environment" }
func (controlledEnvironmentRule) Metadata() Metadata {
	return Metadata{ID: "systemd.controlled-environment", Category: "systemd", Description: "A used unit environment file is controlled across a privilege boundary"}
}
func (controlledSearchPathRule) ID() string { return "systemd.controlled-search-path" }
func (controlledSearchPathRule) Metadata() Metadata {
	return Metadata{ID: "systemd.controlled-search-path", Category: "systemd", Description: "A simple executable resolves through a controlled search directory"}
}

func (rule writableUnitSourceRule) Evaluate(ctx context.Context, g *graphpkg.Graph) []model.Candidate {
	return evaluateSystemdObjectRule(ctx, g, rule.Metadata(), model.EdgeReadsConfig, func(edge model.Edge, _ *graphpkg.Graph, _ model.NodeRef) bool {
		return graphpkg.BoolAttribute(edge.Attributes, "applied", false)
	}, "applied unit source")
}

func (rule writableExecChainRule) Evaluate(ctx context.Context, g *graphpkg.Graph) []model.Candidate {
	return evaluateSystemdObjectRule(ctx, g, rule.Metadata(), model.EdgeExecutes, func(edge model.Edge, _ *graphpkg.Graph, _ model.NodeRef) bool {
		return graphpkg.BoolAttribute(edge.Attributes, "resolved", false) && graphpkg.BoolAttribute(edge.Attributes, "valid", false)
	}, "unit executable")
}

func (rule controlledEnvironmentRule) Evaluate(ctx context.Context, g *graphpkg.Graph) []model.Candidate {
	return evaluateSystemdObjectRule(ctx, g, rule.Metadata(), model.EdgeReadsEnvironment, func(edge model.Edge, _ *graphpkg.Graph, _ model.NodeRef) bool {
		return graphpkg.BoolAttribute(edge.Attributes, "used", false)
	}, "used environment file")
}

func (rule controlledSearchPathRule) Evaluate(ctx context.Context, g *graphpkg.Graph) []model.Candidate {
	return evaluateSystemdObjectRule(ctx, g, rule.Metadata(), model.EdgeResolvesThrough, func(edge model.Edge, graph *graphpkg.Graph, consumer model.NodeRef) bool {
		if !graphpkg.BoolAttribute(edge.Attributes, "search_path", false) || !graphpkg.BoolAttribute(edge.Attributes, "resolved", false) {
			return false
		}
		for _, executable := range graph.Outgoing(consumer, model.EdgeExecutes) {
			if graphpkg.BoolAttribute(executable.Attributes, "simple", false) && graphpkg.BoolAttribute(executable.Attributes, "resolved", false) && graphpkg.BoolAttribute(executable.Attributes, "valid", false) {
				return true
			}
		}
		return false
	}, "executable search directory")
}

type dependencyPredicate func(model.Edge, *graphpkg.Graph, model.NodeRef) bool

func evaluateSystemdObjectRule(ctx context.Context, g *graphpkg.Graph, metadata Metadata, relation model.EdgeKind, predicate dependencyPredicate, objectDescription string) []model.Candidate {
	if g == nil {
		return nil
	}
	current, ok := g.CurrentPrincipal()
	if !ok {
		return nil
	}
	var result []model.Candidate
	for _, unit := range g.NodesByKind(model.NodeUnit) {
		if ctx.Err() != nil {
			break
		}
		consumer := unit.NodeRef
		for _, runsAs := range g.Outgoing(consumer, model.EdgeRunsAs) {
			if !privilegeBoundary(g, current, runsAs.To) {
				continue
			}
			for _, dependency := range g.Outgoing(consumer, relation) {
				if !predicate(dependency, g, consumer) || objectReadOnly(g, dependency.To) {
					continue
				}
				control, controlled := controlEdge(g, current, dependency.To)
				if !controlled {
					continue
				}
				trigger, triggerEdge, triggerConfirmed := confirmedTrigger(g, consumer)
				missing := []string{}
				if !triggerConfirmed {
					missing = append(missing, "activation trigger not confirmed")
				}
				confidences := []model.Confidence{unit.Confidence, runsAs.Confidence, dependency.Confidence, control.Confidence}
				if triggerConfirmed {
					confidences = append(confidences, triggerEdge.Confidence)
				}
				rank := Rank(RankInput{PrivilegeBoundary: true, ControlConfirmed: true, TriggerConfirmed: triggerConfirmed, SemanticsResolved: true, Confidences: confidences, MissingFacts: missing})
				candidate := newCandidate(metadata, rank, current, runsAs.To, consumer, dependency.To, trigger,
					[]model.NodeRef{consumer, dependency.To}, evidenceFor(g, consumer, runsAs.To, dependency.To, trigger, runsAs, dependency, control, triggerEdge), missing,
					fmt.Sprintf("Higher-privilege unit %s consumes a controlled %s.", unit.Label, objectDescription))
				if candidate.ID != "" {
					result = append(result, candidate)
				}
			}
		}
	}
	return result
}
