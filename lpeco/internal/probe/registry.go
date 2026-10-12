package probe

import (
	"fmt"
	"sort"
)

type Registry struct {
	definitions map[string]Definition
	order       []string
}

func NewRegistry(definitions []Definition) (*Registry, error) {
	registry := &Registry{definitions: make(map[string]Definition, len(definitions))}
	for _, definition := range definitions {
		if err := definition.validate(); err != nil {
			return nil, fmt.Errorf("probe %q: %w", definition.ID, err)
		}
		if _, exists := registry.definitions[definition.ID]; exists {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateProbe, definition.ID)
		}
		registry.definitions[definition.ID] = cloneDefinition(definition)
		registry.order = append(registry.order, definition.ID)
	}
	sort.Strings(registry.order)
	return registry, nil
}

func (r *Registry) Get(id string) (Definition, bool) {
	definition, ok := r.definitions[id]
	if !ok {
		return Definition{}, false
	}
	return cloneDefinition(definition), true
}

func (r *Registry) Definitions() []Definition {
	result := make([]Definition, 0, len(r.order))
	for _, id := range r.order {
		result = append(result, cloneDefinition(r.definitions[id]))
	}
	return result
}

func cloneDefinition(definition Definition) Definition {
	clone := definition
	clone.Requirements = append([]Requirement(nil), definition.Requirements...)
	clone.Produces = append([]string(nil), definition.Produces...)
	clone.Variants = make([]Variant, len(definition.Variants))
	for index, variant := range definition.Variants {
		clone.Variants[index] = variant
		clone.Variants[index].Requirements = append([]Requirement(nil), variant.Requirements...)
		clone.Variants[index].Command.Args = append([]string(nil), variant.Command.Args...)
	}
	return clone
}
