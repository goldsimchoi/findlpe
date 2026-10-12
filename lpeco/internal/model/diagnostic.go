package model

type GraphDiagnostic struct {
	Code        string   `json:"code"`
	Message     string   `json:"message"`
	FactID      string   `json:"fact_id,omitempty"`
	EvidenceIDs []string `json:"evidence_ids"`
}

type RuleDiagnostic struct {
	Code        string   `json:"code"`
	RuleID      string   `json:"rule_id"`
	Message     string   `json:"message"`
	Node        NodeRef  `json:"node"`
	EvidenceIDs []string `json:"evidence_ids"`
}
