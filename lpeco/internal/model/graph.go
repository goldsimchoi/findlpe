package model

import "encoding/json"

type NodeRef struct {
	ID   string   `json:"id"`
	Kind NodeKind `json:"kind"`
}

type Node struct {
	NodeRef
	Label           string          `json:"label,omitempty"`
	SourceCollector string          `json:"source_collector"`
	EvidenceIDs     []string        `json:"evidence_ids"`
	Confidence      Confidence      `json:"confidence"`
	Attributes      json.RawMessage `json:"attributes,omitempty"`
}

type Edge struct {
	ID              string          `json:"id"`
	Kind            EdgeKind        `json:"kind"`
	From            NodeRef         `json:"from"`
	To              NodeRef         `json:"to"`
	SourceCollector string          `json:"source_collector"`
	EvidenceIDs     []string        `json:"evidence_ids"`
	Confidence      Confidence      `json:"confidence"`
	Attributes      json.RawMessage `json:"attributes,omitempty"`
}
