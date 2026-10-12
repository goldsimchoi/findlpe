package rules

import (
	"context"
	"encoding/json"
	"fmt"

	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
)

type suidSGIDControlRule struct{}
type capabilityBoundaryRule struct{}
type loaderPathControlRule struct{}

func (suidSGIDControlRule) ID() string { return "binary.suid-sgid-control" }
func (suidSGIDControlRule) Metadata() Metadata {
	return Metadata{ID: "binary.suid-sgid-control", Category: "binary", Description: "Controlled set-ID binary crosses a principal boundary"}
}
func (capabilityBoundaryRule) ID() string { return "binary.capability-boundary" }
func (capabilityBoundaryRule) Metadata() Metadata {
	return Metadata{ID: "binary.capability-boundary", Category: "binary", Description: "Controlled file-capability binary crosses a security boundary"}
}
func (loaderPathControlRule) ID() string { return "binary.loader-path-control" }
func (loaderPathControlRule) Metadata() Metadata {
	return Metadata{ID: "binary.loader-path-control", Category: "binary", Description: "Privileged binary resolves dependencies through a controlled directory"}
}

func (rule suidSGIDControlRule) Evaluate(ctx context.Context, g *graphpkg.Graph) []model.Candidate {
	return evaluatePrivilegedBinary(ctx, g, rule.Metadata(), func(node model.Node) bool {
		return graphpkg.BoolAttribute(node.Attributes, "suid", false) || graphpkg.BoolAttribute(node.Attributes, "sgid", false)
	}, true)
}

func (rule capabilityBoundaryRule) Evaluate(ctx context.Context, g *graphpkg.Graph) []model.Candidate {
	eligible := func(node model.Node) bool {
		return graphpkg.BoolAttribute(node.Attributes, "capability_boundary", false) && nonEmptyStringArray(node.Attributes, "capabilities")
	}
	result := evaluatePrivilegedBinary(ctx, g, rule.Metadata(), eligible, false)
	if g == nil {
		return result
	}
	current, ok := g.CurrentPrincipal()
	if !ok {
		return result
	}
	covered := make(map[string]bool)
	for _, candidate := range result {
		if candidate.PrivilegedConsumer != nil {
			covered[candidate.PrivilegedConsumer.ID+"\x00"+candidate.TargetPrincipal.ID] = true
		}
	}
	for _, binary := range g.NodesByKind(model.NodeExecutable) {
		if ctx.Err() != nil {
			break
		}
		if !eligible(binary) || objectNoSUID(g, binary.NodeRef) {
			continue
		}
		for _, runsAs := range g.Outgoing(binary.NodeRef, model.EdgeRunsAs) {
			key := binary.ID + "\x00" + runsAs.To.ID
			if covered[key] || !privilegeBoundary(g, current, runsAs.To) {
				continue
			}
			if _, controlled := controlEdge(g, current, binary.NodeRef); controlled && !objectReadOnly(g, binary.NodeRef) {
				continue
			}
			missing := []string{"current-principal control of capability executable is unconfirmed"}
			rank := Rank(RankInput{PrivilegeBoundary: true, ControlConfirmed: false, SemanticsResolved: true,
				Confidences: []model.Confidence{binary.Confidence, runsAs.Confidence}, MissingFacts: missing})
			consumer := binary.NodeRef
			evidence := evidenceFor(g, binary.NodeRef, runsAs.To, runsAs)
			id, err := model.StableID("candidate", struct {
				Rule, Current, Target, Consumer, State string
			}{rule.ID(), current.ID, runsAs.To.ID, consumer.ID, "inventory"})
			if err != nil || len(evidence) == 0 {
				continue
			}
			result = append(result, model.Candidate{
				ID: id, RuleID: rule.ID(), Category: rule.Metadata().Category, Priority: rank.Priority, Confidence: rank.Confidence,
				CurrentPrincipal: current, TargetPrincipal: runsAs.To, PrivilegedConsumer: &consumer,
				PathNodes: []model.NodeRef{consumer}, EvidenceIDs: evidence, MissingFacts: missing,
				ValidationStatus: rank.ValidationStatus,
				Summary:          fmt.Sprintf("File-capability executable %s crosses a privilege boundary; current-principal control is unconfirmed.", binary.Label),
			})
		}
	}
	return result
}

func evaluatePrivilegedBinary(ctx context.Context, g *graphpkg.Graph, metadata Metadata, eligible func(model.Node) bool, requireBitPreservation bool) []model.Candidate {
	if g == nil {
		return nil
	}
	current, ok := g.CurrentPrincipal()
	if !ok {
		return nil
	}
	var result []model.Candidate
	for _, binary := range g.NodesByKind(model.NodeExecutable) {
		if ctx.Err() != nil {
			break
		}
		if !eligible(binary) || objectNoSUID(g, binary.NodeRef) || objectReadOnly(g, binary.NodeRef) {
			continue
		}
		for _, runsAs := range g.Outgoing(binary.NodeRef, model.EdgeRunsAs) {
			if !privilegeBoundary(g, current, runsAs.To) {
				continue
			}
			control, controlled := controlEdge(g, current, binary.NodeRef)
			if !controlled {
				continue
			}
			triggerEdge, triggerConfirmed := executableTrigger(g, current, binary.NodeRef)
			missing := []string{}
			semantics := true
			if requireBitPreservation && !graphpkg.BoolAttribute(binary.Attributes, "bit_preservation_confirmed", false) {
				missing = append(missing, "privilege bit preservation after replacement is unconfirmed")
				semantics = false
			}
			if !triggerConfirmed {
				missing = append(missing, "execution trigger not confirmed")
			}
			confidences := []model.Confidence{binary.Confidence, runsAs.Confidence, control.Confidence}
			if triggerConfirmed {
				confidences = append(confidences, triggerEdge.Confidence)
			}
			rank := Rank(RankInput{PrivilegeBoundary: true, ControlConfirmed: true, TriggerConfirmed: triggerConfirmed, SemanticsResolved: semantics, Confidences: confidences, MissingFacts: missing})
			candidate := newCandidate(metadata, rank, current, runsAs.To, binary.NodeRef, binary.NodeRef, nil,
				[]model.NodeRef{binary.NodeRef}, evidenceFor(g, binary.NodeRef, runsAs.To, runsAs, control, triggerEdge), missing,
				fmt.Sprintf("Higher-privilege executable %s is controlled by the current principal.", binary.Label))
			if candidate.ID != "" {
				result = append(result, candidate)
			}
		}
	}
	return result
}

func (rule loaderPathControlRule) Evaluate(ctx context.Context, g *graphpkg.Graph) []model.Candidate {
	if g == nil {
		return nil
	}
	current, ok := g.CurrentPrincipal()
	if !ok {
		return nil
	}
	var result []model.Candidate
	for _, binary := range g.NodesByKind(model.NodeExecutable) {
		if ctx.Err() != nil {
			break
		}
		for _, runsAs := range g.Outgoing(binary.NodeRef, model.EdgeRunsAs) {
			if !privilegeBoundary(g, current, runsAs.To) {
				continue
			}
			for _, pathEdge := range g.Outgoing(binary.NodeRef, model.EdgeResolvesThrough) {
				if !graphpkg.BoolAttribute(pathEdge.Attributes, "loader_path", false) || !graphpkg.BoolAttribute(pathEdge.Attributes, "resolved", false) || objectReadOnly(g, pathEdge.To) {
					continue
				}
				control, controlled := controlEdge(g, current, pathEdge.To)
				if !controlled {
					continue
				}
				triggerEdge, triggerConfirmed := executableTrigger(g, current, binary.NodeRef)
				missing := []string{}
				if !triggerConfirmed {
					missing = append(missing, "execution trigger not confirmed")
				}
				confidences := []model.Confidence{binary.Confidence, runsAs.Confidence, pathEdge.Confidence, control.Confidence}
				if triggerConfirmed {
					confidences = append(confidences, triggerEdge.Confidence)
				}
				rank := Rank(RankInput{PrivilegeBoundary: true, ControlConfirmed: true, TriggerConfirmed: triggerConfirmed, SemanticsResolved: true, Confidences: confidences, MissingFacts: missing})
				candidate := newCandidate(rule.Metadata(), rank, current, runsAs.To, binary.NodeRef, pathEdge.To, nil,
					[]model.NodeRef{binary.NodeRef, pathEdge.To}, evidenceFor(g, binary.NodeRef, runsAs.To, pathEdge.To, runsAs, pathEdge, control, triggerEdge), missing,
					fmt.Sprintf("Higher-privilege executable %s resolves dependencies through a controlled directory.", binary.Label))
				if candidate.ID != "" {
					result = append(result, candidate)
				}
			}
		}
	}
	return result
}

func (rule suidSGIDControlRule) Diagnostics(ctx context.Context, g *graphpkg.Graph) []Diagnostic {
	return boundaryDiagnostics(ctx, g, rule.ID(), model.NodeExecutable, func(node model.Node) bool {
		return graphpkg.BoolAttribute(node.Attributes, "suid", false) || graphpkg.BoolAttribute(node.Attributes, "sgid", false)
	})
}

func (rule capabilityBoundaryRule) Diagnostics(ctx context.Context, g *graphpkg.Graph) []Diagnostic {
	return inventoryDiagnostics(ctx, g, rule.ID(), model.NodeExecutable, func(node model.Node) bool {
		return nonEmptyStringArray(node.Attributes, "capabilities")
	}, rule.Evaluate(ctx, g))
}

func (rule loaderPathControlRule) Diagnostics(ctx context.Context, g *graphpkg.Graph) []Diagnostic {
	return boundaryDiagnostics(ctx, g, rule.ID(), model.NodeExecutable, func(node model.Node) bool {
		for _, edge := range g.Outgoing(node.NodeRef, model.EdgeResolvesThrough) {
			if graphpkg.BoolAttribute(edge.Attributes, "loader_path", false) {
				return true
			}
		}
		return false
	})
}

func executableTrigger(g *graphpkg.Graph, current, executable model.NodeRef) (model.Edge, bool) {
	for _, edge := range g.Outgoing(current, model.EdgeCanExecute) {
		if edge.To.ID == executable.ID && graphpkg.BoolAttribute(edge.Attributes, "reachable", false) {
			return edge, true
		}
	}
	return model.Edge{}, false
}

func objectNoSUID(g *graphpkg.Graph, object model.NodeRef) bool {
	for _, edge := range g.Outgoing(object, model.EdgeLocatedOn) {
		mount, ok := g.Node(edge.To)
		if ok && graphpkg.BoolAttribute(mount.Attributes, "nosuid", false) {
			return true
		}
	}
	return false
}

func nonEmptyStringArray(attributes json.RawMessage, name string) bool {
	value, ok := graphpkg.Attributes(attributes)[name].([]any)
	return ok && len(value) > 0
}
