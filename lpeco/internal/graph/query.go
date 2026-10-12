package graph

import (
	"encoding/json"
	"sort"

	"github.com/normalone/lpeco/internal/model"
)

func (g *Graph) CurrentPrincipal() (model.NodeRef, bool) {
	if g == nil || g.current == nil {
		return model.NodeRef{}, false
	}
	return *g.current, true
}

func (g *Graph) Node(ref model.NodeRef) (model.Node, bool) {
	if g == nil {
		return model.Node{}, false
	}
	node, ok := g.nodes[ref.ID]
	return node, ok
}

func (g *Graph) Nodes() []model.Node {
	if g == nil {
		return []model.Node{}
	}
	values := make([]model.Node, 0, len(g.nodes))
	for _, node := range g.nodes {
		values = append(values, node)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values
}

func (g *Graph) NodesByKind(kind model.NodeKind) []model.Node {
	values := make([]model.Node, 0)
	for _, node := range g.Nodes() {
		if node.Kind == kind {
			values = append(values, node)
		}
	}
	return values
}

func (g *Graph) Edges() []model.Edge {
	if g == nil {
		return []model.Edge{}
	}
	values := make([]model.Edge, 0, len(g.edges))
	for _, edge := range g.edges {
		values = append(values, edge)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values
}

func (g *Graph) Outgoing(ref model.NodeRef, kinds ...model.EdgeKind) []model.Edge {
	if g == nil {
		return []model.Edge{}
	}
	wanted := edgeKindSet(kinds)
	values := make([]model.Edge, 0, len(g.outgoing[ref.ID]))
	for id := range g.outgoing[ref.ID] {
		edge := g.edges[id]
		if len(wanted) == 0 || wanted[edge.Kind] {
			values = append(values, edge)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values
}

func (g *Graph) Incoming(ref model.NodeRef, kinds ...model.EdgeKind) []model.Edge {
	if g == nil {
		return []model.Edge{}
	}
	wanted := edgeKindSet(kinds)
	values := make([]model.Edge, 0, len(g.incoming[ref.ID]))
	for id := range g.incoming[ref.ID] {
		edge := g.edges[id]
		if len(wanted) == 0 || wanted[edge.Kind] {
			values = append(values, edge)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
	return values
}

func (g *Graph) Facts(kind string) []model.Fact {
	if g == nil {
		return []model.Fact{}
	}
	values := make([]model.Fact, 0)
	for _, fact := range g.facts {
		if kind == "" || fact.Kind == kind {
			values = append(values, fact)
		}
	}
	return values
}

func (g *Graph) NodeKey(ref model.NodeRef) string {
	if g == nil {
		return ""
	}
	return g.nodeKeys[ref.ID]
}

func Attributes(value json.RawMessage) map[string]any {
	result := make(map[string]any)
	_ = json.Unmarshal(value, &result)
	return result
}

func BoolAttribute(value json.RawMessage, name string, fallback bool) bool {
	attributes := Attributes(value)
	entry, ok := attributes[name]
	if !ok {
		return fallback
	}
	parsed, ok := entry.(bool)
	if !ok {
		return fallback
	}
	return parsed
}

func StringAttribute(value json.RawMessage, name string) string {
	entry, _ := Attributes(value)[name].(string)
	return entry
}

func IntAttribute(value json.RawMessage, name string) (int, bool) {
	entry, ok := Attributes(value)[name].(float64)
	if !ok {
		return 0, false
	}
	return int(entry), true
}

func edgeKindSet(values []model.EdgeKind) map[model.EdgeKind]bool {
	result := make(map[model.EdgeKind]bool, len(values))
	for _, value := range values {
		result[value] = true
	}
	return result
}
