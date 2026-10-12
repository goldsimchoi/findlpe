package rules

import (
	"context"
	"fmt"
	"strings"

	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
)

type sudoPolicyRule struct{}

func (sudoPolicyRule) ID() string { return "delegation.sudo-policy" }
func (sudoPolicyRule) Metadata() Metadata {
	return Metadata{ID: "delegation.sudo-policy", Category: "delegation", Description: "Sudo policy permits a command across a principal boundary"}
}

func (rule sudoPolicyRule) Evaluate(ctx context.Context, g *graphpkg.Graph) []model.Candidate {
	if g == nil {
		return nil
	}
	current, ok := g.CurrentPrincipal()
	if !ok {
		return nil
	}
	var result []model.Candidate
	for _, allowed := range g.Outgoing(current, model.EdgeCanExecute) {
		if ctx.Err() != nil {
			break
		}
		if !graphpkg.BoolAttribute(allowed.Attributes, "delegation", false) || !graphpkg.BoolAttribute(allowed.Attributes, "policy_confirmed", false) {
			continue
		}
		command, ok := g.Node(allowed.To)
		if !ok || command.Kind != model.NodeExecutable {
			continue
		}
		resolvedDefault := strings.HasPrefix(strings.TrimSpace(command.Label), "/")
		if graphpkg.BoolAttribute(allowed.Attributes, "negated", false) || !graphpkg.BoolAttribute(allowed.Attributes, "semantics_resolved", resolvedDefault) {
			continue
		}
		for _, runsAs := range g.Outgoing(command.NodeRef, model.EdgeRunsAs) {
			if !privilegeBoundary(g, current, runsAs.To) {
				continue
			}
			noPassword := graphpkg.BoolAttribute(allowed.Attributes, "no_password", false)
			missing := []string{}
			if !noPassword {
				missing = append(missing, "non-interactive NOPASSWD permission not confirmed")
			}
			rank := Rank(RankInput{PrivilegeBoundary: true, ControlConfirmed: noPassword, TriggerConfirmed: noPassword, SemanticsResolved: true,
				Confidences: []model.Confidence{command.Confidence, allowed.Confidence, runsAs.Confidence}, MissingFacts: missing})
			candidate := newCandidate(rule.Metadata(), rank, current, runsAs.To, command.NodeRef, command.NodeRef, nil,
				[]model.NodeRef{command.NodeRef}, evidenceFor(g, current, command.NodeRef, runsAs.To, allowed, runsAs), missing,
				fmt.Sprintf("Confirmed sudo policy permits %s under a different principal.", command.Label))
			if candidate.ID != "" {
				result = append(result, candidate)
			}
		}
	}
	return result
}

func (rule sudoPolicyRule) Diagnostics(ctx context.Context, g *graphpkg.Graph) []Diagnostic {
	return boundaryDiagnostics(ctx, g, rule.ID(), model.NodeExecutable, func(node model.Node) bool {
		for _, edge := range g.Incoming(node.NodeRef, model.EdgeCanExecute) {
			if graphpkg.BoolAttribute(edge.Attributes, "delegation", false) {
				return true
			}
		}
		return false
	})
}
