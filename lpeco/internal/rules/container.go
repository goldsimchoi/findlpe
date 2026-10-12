package rules

import (
	"context"
	"fmt"

	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
)

type adminSocketControlRule struct{}

func (adminSocketControlRule) ID() string { return "container.admin-socket-control" }
func (adminSocketControlRule) Metadata() Metadata {
	return Metadata{ID: "container.admin-socket-control", Category: "container", Description: "Current principal can write a higher-privilege daemon management socket"}
}

func (rule adminSocketControlRule) Evaluate(ctx context.Context, g *graphpkg.Graph) []model.Candidate {
	if g == nil {
		return nil
	}
	current, ok := g.CurrentPrincipal()
	if !ok {
		return nil
	}
	var result []model.Candidate
	for _, socket := range g.NodesByKind(model.NodeSocket) {
		if ctx.Err() != nil {
			break
		}
		if !graphpkg.BoolAttribute(socket.Attributes, "direct_access", false) {
			continue
		}
		for _, runsAs := range g.Outgoing(socket.NodeRef, model.EdgeRunsAs) {
			if !privilegeBoundary(g, current, runsAs.To) {
				continue
			}
			control, controlled := controlEdge(g, current, socket.NodeRef)
			if !controlled || !graphpkg.BoolAttribute(control.Attributes, "direct_access", false) || objectReadOnly(g, socket.NodeRef) {
				continue
			}
			rank := Rank(RankInput{PrivilegeBoundary: true, ControlConfirmed: true, TriggerConfirmed: true, SemanticsResolved: true,
				Confidences: []model.Confidence{socket.Confidence, runsAs.Confidence, control.Confidence}})
			candidate := newCandidate(rule.Metadata(), rank, current, runsAs.To, socket.NodeRef, socket.NodeRef, nil,
				[]model.NodeRef{socket.NodeRef}, evidenceFor(g, socket.NodeRef, runsAs.To, runsAs, control), nil,
				fmt.Sprintf("Current principal has confirmed write access to the higher-privilege %s management socket.", graphpkg.StringAttribute(socket.Attributes, "daemon")))
			if candidate.ID != "" {
				result = append(result, candidate)
			}
		}
	}
	return result
}

func (rule adminSocketControlRule) Diagnostics(ctx context.Context, g *graphpkg.Graph) []Diagnostic {
	return inventoryDiagnostics(ctx, g, rule.ID(), model.NodeSocket, func(model.Node) bool { return true }, rule.Evaluate(ctx, g))
}
