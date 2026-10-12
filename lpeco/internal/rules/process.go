package rules

import (
	"context"
	"fmt"
	"sort"

	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
)

type replaceableDependencyRule struct{}

func (replaceableDependencyRule) ID() string { return "process.replaceable-dependency" }
func (replaceableDependencyRule) Metadata() Metadata {
	return Metadata{ID: "process.replaceable-dependency", Category: "process", Description: "Observed process dependency is replaceable across a privilege boundary"}
}

func (rule replaceableDependencyRule) Evaluate(ctx context.Context, g *graphpkg.Graph) []model.Candidate {
	if g == nil {
		return nil
	}
	current, ok := g.CurrentPrincipal()
	if !ok {
		return nil
	}
	var result []model.Candidate
	for _, process := range g.NodesByKind(model.NodeProcess) {
		if ctx.Err() != nil {
			break
		}
		consumer := process.NodeRef
		dependencies := append(g.Outgoing(consumer, model.EdgeLoads), g.Outgoing(consumer, model.EdgeExecutes)...)
		sort.Slice(dependencies, func(i, j int) bool { return dependencies[i].ID < dependencies[j].ID })
		for _, runsAs := range g.Outgoing(consumer, model.EdgeRunsAs) {
			if !privilegeBoundary(g, current, runsAs.To) {
				continue
			}
			for _, dependency := range dependencies {
				resolved := graphpkg.BoolAttribute(dependency.Attributes, "resolved", false)
				observed := graphpkg.BoolAttribute(dependency.Attributes, "observed", false)
				if !resolved || !observed || objectReadOnly(g, dependency.To) {
					continue
				}
				control, controlled := controlEdge(g, current, dependency.To)
				if !controlled {
					continue
				}
				trigger, triggerEdge, triggerConfirmed := confirmedTrigger(g, consumer)
				missing := []string{}
				if !triggerConfirmed {
					missing = append(missing, "repeatable process trigger not confirmed")
				}
				confidences := []model.Confidence{process.Confidence, runsAs.Confidence, dependency.Confidence, control.Confidence}
				if triggerConfirmed {
					confidences = append(confidences, triggerEdge.Confidence)
				}
				rank := Rank(RankInput{PrivilegeBoundary: true, ControlConfirmed: true, TriggerConfirmed: triggerConfirmed, SemanticsResolved: true, Confidences: confidences, MissingFacts: missing})
				candidate := newCandidate(rule.Metadata(), rank, current, runsAs.To, consumer, dependency.To, trigger,
					[]model.NodeRef{consumer, dependency.To}, evidenceFor(g, consumer, runsAs.To, dependency.To, trigger, runsAs, dependency, control, triggerEdge), missing,
					fmt.Sprintf("Higher-privilege process %s consumes a controlled observed dependency.", process.Label))
				if candidate.ID != "" {
					result = append(result, candidate)
				}
			}
		}
	}
	return result
}

func privilegeBoundary(g *graphpkg.Graph, current, target model.NodeRef) bool {
	if current.ID == "" || target.ID == "" || current.ID == target.ID {
		return false
	}
	currentNode, currentOK := g.Node(current)
	targetNode, targetOK := g.Node(target)
	if !currentOK || !targetOK {
		return false
	}
	currentUID, currentHasUID := graphpkg.IntAttribute(currentNode.Attributes, "uid")
	targetUID, targetHasUID := graphpkg.IntAttribute(targetNode.Attributes, "uid")
	return currentHasUID && targetHasUID && currentUID != targetUID
}

func controlEdge(g *graphpkg.Graph, current, object model.NodeRef) (model.Edge, bool) {
	for _, edge := range g.Outgoing(current, model.EdgeCanWrite) {
		if edge.To.ID == object.ID && graphpkg.BoolAttribute(edge.Attributes, "controlled", false) && len(edge.EvidenceIDs) > 0 {
			return edge, true
		}
	}
	return model.Edge{}, false
}

func objectReadOnly(g *graphpkg.Graph, object model.NodeRef) bool {
	for _, edge := range g.Outgoing(object, model.EdgeLocatedOn) {
		mount, ok := g.Node(edge.To)
		if ok && graphpkg.BoolAttribute(mount.Attributes, "read_only", false) {
			return true
		}
	}
	return false
}

func confirmedTrigger(g *graphpkg.Graph, consumer model.NodeRef) (*model.NodeRef, model.Edge, bool) {
	for _, edge := range g.Incoming(consumer, model.EdgeActivates) {
		if graphpkg.BoolAttribute(edge.Attributes, "active", false) {
			copy := edge.From
			return &copy, edge, true
		}
	}
	return nil, model.Edge{}, false
}

func newCandidate(metadata Metadata, rank RankResult, current, target, consumer, object model.NodeRef, trigger *model.NodeRef, path []model.NodeRef, evidence, missing []string, summary string) model.Candidate {
	evidence = mergeStrings(nil, evidence)
	missing = mergeStrings(nil, missing)
	objectCopy := object
	consumerCopy := consumer
	id, err := model.StableID("candidate", struct {
		Rule     string         `json:"rule"`
		Current  string         `json:"current"`
		Target   string         `json:"target"`
		Consumer string         `json:"consumer"`
		Object   string         `json:"object"`
		Trigger  *model.NodeRef `json:"trigger,omitempty"`
	}{metadata.ID, current.ID, target.ID, consumer.ID, object.ID, trigger})
	if err != nil || len(evidence) == 0 {
		return model.Candidate{}
	}
	return model.Candidate{
		ID: id, RuleID: metadata.ID, Category: metadata.Category, Priority: rank.Priority, Confidence: rank.Confidence,
		CurrentPrincipal: current, TargetPrincipal: target, PrivilegedConsumer: &consumerCopy, ControlledObject: &objectCopy,
		Trigger: trigger, PathNodes: append([]model.NodeRef(nil), path...), EvidenceIDs: evidence, MissingFacts: missing,
		ValidationStatus: rank.ValidationStatus, Summary: summary,
	}
}

func evidenceFor(g *graphpkg.Graph, refsAndEdges ...any) []string {
	var result []string
	for _, value := range refsAndEdges {
		switch typed := value.(type) {
		case model.NodeRef:
			if typed.ID == "" {
				continue
			}
			if node, ok := g.Node(typed); ok {
				result = append(result, node.EvidenceIDs...)
			}
		case *model.NodeRef:
			if typed != nil {
				result = append(result, evidenceFor(g, *typed)...)
			}
		case model.Edge:
			result = append(result, typed.EvidenceIDs...)
		}
	}
	return mergeStrings(nil, result)
}

func mergeStrings(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	result := make([]string, 0, len(left)+len(right))
	for _, value := range append(append([]string(nil), left...), right...) {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	if result == nil {
		return []string{}
	}
	return result
}
