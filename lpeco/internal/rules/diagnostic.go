package rules

import (
	"context"

	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
)

func boundaryDiagnostics(ctx context.Context, g *graphpkg.Graph, ruleID string, kind model.NodeKind, eligible func(model.Node) bool) []Diagnostic {
	if g == nil {
		return nil
	}
	current, ok := g.CurrentPrincipal()
	if !ok {
		return nil
	}
	return inventoryDiagnostics(ctx, g, ruleID, kind, func(node model.Node) bool {
		if !eligible(node) {
			return false
		}
		for _, edge := range g.Outgoing(node.NodeRef, model.EdgeRunsAs) {
			if privilegeBoundary(g, current, edge.To) {
				return false
			}
		}
		return true
	}, nil)
}

func inventoryDiagnostics(ctx context.Context, g *graphpkg.Graph, ruleID string, kind model.NodeKind, eligible func(model.Node) bool, candidates []model.Candidate) []Diagnostic {
	if g == nil {
		return nil
	}
	candidateConsumers := make(map[string]bool)
	for _, candidate := range candidates {
		if candidate.PrivilegedConsumer != nil {
			candidateConsumers[candidate.PrivilegedConsumer.ID] = true
		}
	}
	var result []Diagnostic
	for _, node := range g.NodesByKind(kind) {
		if ctx.Err() != nil {
			break
		}
		if !eligible(node) || candidateConsumers[node.ID] {
			continue
		}
		result = append(result, Diagnostic{
			Code: "inventory-only", RuleID: ruleID, Node: node.NodeRef,
			Message:     "Observed surface lacks a confirmed privilege boundary or controllable path and remains inventory only.",
			EvidenceIDs: node.EvidenceIDs,
		})
	}
	return result
}
