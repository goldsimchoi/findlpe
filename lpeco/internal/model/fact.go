package model

import "encoding/json"

type Fact struct {
	ID              string          `json:"id"`
	Kind            string          `json:"kind"`
	SourceCollector string          `json:"source_collector"`
	EvidenceIDs     []string        `json:"evidence_ids"`
	Confidence      Confidence      `json:"confidence"`
	Data            json.RawMessage `json:"data"`
}
