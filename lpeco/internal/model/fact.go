package model

import "encoding/json"

type Fact struct {
	ID                string          `json:"id"`
	Kind              string          `json:"kind"`
	SourceCollector   string          `json:"source_collector"`
	EvidenceIDs       []string        `json:"evidence_ids"`
	Confidence        Confidence      `json:"confidence"`
	ObservationStatus ProbeStatus     `json:"observation_status,omitempty"`
	MissingFacts      []string        `json:"missing_facts,omitempty"`
	Data              json.RawMessage `json:"data"`
}
