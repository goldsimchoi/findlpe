package graph

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/normalone/lpeco/internal/model"
)

// Diagnostic describes graph input that could not be represented without
// guessing. Facts remain available through Facts even when an edge is rejected.
type Diagnostic = model.GraphDiagnostic

type NodeSpec struct {
	Key             string
	Kind            model.NodeKind
	Label           string
	SourceCollector string
	EvidenceIDs     []string
	Confidence      model.Confidence
	Attributes      json.RawMessage
}

type EdgeSpec struct {
	Kind            model.EdgeKind
	From            model.NodeRef
	To              model.NodeRef
	SourceCollector string
	EvidenceIDs     []string
	Confidence      model.Confidence
	Attributes      json.RawMessage
}

// Graph is an in-memory, evidence-backed privilege graph. Its custom JSON
// representation contains sorted arrays so identical inputs serialize to the
// same bytes regardless of collection order.
type Graph struct {
	nodes    map[string]model.Node
	edges    map[string]model.Edge
	facts    []model.Fact
	current  *model.NodeRef
	variants map[string][]json.RawMessage
	nodeKeys map[string]string
	outgoing map[string]map[string]struct{}
	incoming map[string]map[string]struct{}
}

func New() *Graph {
	return &Graph{
		nodes:    make(map[string]model.Node),
		edges:    make(map[string]model.Edge),
		variants: make(map[string][]json.RawMessage),
		nodeKeys: make(map[string]string),
		outgoing: make(map[string]map[string]struct{}),
		incoming: make(map[string]map[string]struct{}),
	}
}

func (g *Graph) AddNode(spec NodeSpec) (model.NodeRef, bool, error) {
	if g == nil {
		return model.NodeRef{}, false, errors.New("nil graph")
	}
	if strings.TrimSpace(spec.Key) == "" {
		return model.NodeRef{}, false, errors.New("node key is required")
	}
	if spec.Kind == "" {
		return model.NodeRef{}, false, errors.New("node kind is required")
	}
	attributes, err := canonicalJSON(spec.Attributes)
	if err != nil {
		return model.NodeRef{}, false, fmt.Errorf("canonicalize node attributes: %w", err)
	}
	id, err := model.StableID("node", struct {
		Kind model.NodeKind `json:"kind"`
		Key  string         `json:"key"`
	}{spec.Kind, spec.Key})
	if err != nil {
		return model.NodeRef{}, false, err
	}
	ref := model.NodeRef{ID: id, Kind: spec.Kind}
	confidence := normalizeConfidence(spec.Confidence)
	if existing, ok := g.nodes[id]; ok {
		conflict := false
		if len(attributes) > 0 && len(existing.Attributes) > 0 && !bytes.Equal(attributes, existing.Attributes) {
			conflict = true
			g.addVariant(id, existing.Attributes)
			g.addVariant(id, attributes)
			// Choosing the lexical minimum makes the retained representative
			// independent from input order while variants preserve both values.
			if bytes.Compare(attributes, existing.Attributes) < 0 {
				existing.Attributes = attributes
			}
		} else if len(existing.Attributes) == 0 && len(attributes) > 0 {
			existing.Attributes = attributes
		}
		if existing.Label == "" || (spec.Label != "" && spec.Label < existing.Label) {
			existing.Label = spec.Label
		}
		existing.SourceCollector = mergeSources(existing.SourceCollector, spec.SourceCollector)
		existing.EvidenceIDs = mergeStrings(existing.EvidenceIDs, spec.EvidenceIDs)
		existing.Confidence = weakerConfidence(existing.Confidence, confidence)
		g.nodes[id] = existing
		return ref, conflict, nil
	}
	g.nodes[id] = model.Node{
		NodeRef: ref, Label: spec.Label, SourceCollector: spec.SourceCollector,
		EvidenceIDs: uniqueSorted(spec.EvidenceIDs), Confidence: confidence, Attributes: attributes,
	}
	g.nodeKeys[id] = spec.Key
	return ref, false, nil
}

func (g *Graph) AddEdge(spec EdgeSpec) error {
	if g == nil {
		return errors.New("nil graph")
	}
	if spec.Kind == "" {
		return errors.New("edge kind is required")
	}
	if len(compactStrings(spec.EvidenceIDs)) == 0 {
		return errors.New("edge evidence is required")
	}
	if _, ok := g.nodes[spec.From.ID]; !ok || spec.From.ID == "" {
		return errors.New("edge source node does not exist")
	}
	if _, ok := g.nodes[spec.To.ID]; !ok || spec.To.ID == "" {
		return errors.New("edge target node does not exist")
	}
	attributes, err := canonicalJSON(spec.Attributes)
	if err != nil {
		return fmt.Errorf("canonicalize edge attributes: %w", err)
	}
	id, err := model.StableID("edge", struct {
		Kind       model.EdgeKind  `json:"kind"`
		From       string          `json:"from"`
		To         string          `json:"to"`
		Attributes json.RawMessage `json:"attributes,omitempty"`
	}{spec.Kind, spec.From.ID, spec.To.ID, attributes})
	if err != nil {
		return err
	}
	confidence := normalizeConfidence(spec.Confidence)
	if existing, ok := g.edges[id]; ok {
		existing.SourceCollector = mergeSources(existing.SourceCollector, spec.SourceCollector)
		existing.EvidenceIDs = mergeStrings(existing.EvidenceIDs, spec.EvidenceIDs)
		existing.Confidence = weakerConfidence(existing.Confidence, confidence)
		g.edges[id] = existing
		return nil
	}
	g.edges[id] = model.Edge{
		ID: id, Kind: spec.Kind, From: spec.From, To: spec.To,
		SourceCollector: spec.SourceCollector, EvidenceIDs: uniqueSorted(spec.EvidenceIDs),
		Confidence: confidence, Attributes: attributes,
	}
	if g.outgoing[spec.From.ID] == nil {
		g.outgoing[spec.From.ID] = make(map[string]struct{})
	}
	if g.incoming[spec.To.ID] == nil {
		g.incoming[spec.To.ID] = make(map[string]struct{})
	}
	g.outgoing[spec.From.ID][id] = struct{}{}
	g.incoming[spec.To.ID][id] = struct{}{}
	return nil
}

func (g *Graph) SetCurrentPrincipal(ref model.NodeRef) {
	if g == nil || ref.ID == "" || ref.Kind != model.NodePrincipal {
		return
	}
	copy := ref
	g.current = &copy
}

func (g *Graph) setFacts(facts []model.Fact) {
	g.facts = append([]model.Fact(nil), facts...)
	sort.Slice(g.facts, func(i, j int) bool { return factSortKey(g.facts[i]) < factSortKey(g.facts[j]) })
}

func (g *Graph) addVariant(nodeID string, value json.RawMessage) {
	if len(value) == 0 {
		return
	}
	for _, existing := range g.variants[nodeID] {
		if bytes.Equal(existing, value) {
			return
		}
	}
	g.variants[nodeID] = append(g.variants[nodeID], append(json.RawMessage(nil), value...))
	sort.Slice(g.variants[nodeID], func(i, j int) bool {
		return bytes.Compare(g.variants[nodeID][i], g.variants[nodeID][j]) < 0
	})
}

func (g *Graph) MarshalJSON() ([]byte, error) {
	type variant struct {
		NodeID     string            `json:"node_id"`
		Attributes []json.RawMessage `json:"attributes"`
	}
	var current *model.NodeRef
	if g.current != nil {
		copy := *g.current
		current = &copy
	}
	variants := make([]variant, 0, len(g.variants))
	for nodeID, attributes := range g.variants {
		values := append([]json.RawMessage(nil), attributes...)
		variants = append(variants, variant{NodeID: nodeID, Attributes: values})
	}
	sort.Slice(variants, func(i, j int) bool { return variants[i].NodeID < variants[j].NodeID })
	return json.Marshal(struct {
		Current  *model.NodeRef `json:"current_principal,omitempty"`
		Nodes    []model.Node   `json:"nodes"`
		Edges    []model.Edge   `json:"edges"`
		Facts    []model.Fact   `json:"facts"`
		Variants []variant      `json:"conflicting_node_variants,omitempty"`
	}{current, g.Nodes(), g.Edges(), append([]model.Fact(nil), g.facts...), variants})
}

func canonicalJSON(value json.RawMessage) (json.RawMessage, error) {
	if len(bytes.TrimSpace(value)) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return nil, nil
	}
	var decoded any
	if err := json.Unmarshal(value, &decoded); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(decoded)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func marshalAttributes(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return encoded
}

func normalizeConfidence(value model.Confidence) model.Confidence {
	switch value {
	case model.ConfidenceHigh, model.ConfidenceMedium, model.ConfidenceLow:
		return value
	default:
		return model.ConfidenceLow
	}
}

func weakerConfidence(left, right model.Confidence) model.Confidence {
	rank := map[model.Confidence]int{model.ConfidenceLow: 0, model.ConfidenceMedium: 1, model.ConfidenceHigh: 2}
	left = normalizeConfidence(left)
	right = normalizeConfidence(right)
	if rank[left] <= rank[right] {
		return left
	}
	return right
}

func mergeSources(left, right string) string {
	return strings.Join(uniqueSorted(append(strings.Split(left, ","), strings.Split(right, ",")...)), ",")
}

func mergeStrings(left, right []string) []string {
	return uniqueSorted(append(append([]string(nil), left...), right...))
}

func compactStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			result = append(result, value)
		}
	}
	return result
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
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

func factSortKey(fact model.Fact) string {
	copy := fact
	copy.EvidenceIDs = uniqueSorted(copy.EvidenceIDs)
	data, _ := json.Marshal(copy)
	return string(data)
}
