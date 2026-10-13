package model

import "time"

type SessionStatus string

const (
	SessionReady       SessionStatus = "ready"
	SessionRunning     SessionStatus = "running"
	SessionInterrupted SessionStatus = "interrupted"
	SessionComplete    SessionStatus = "complete"
)

type HostProfile struct {
	OS                  string              `json:"os,omitempty"`
	Architecture        string              `json:"architecture,omitempty"`
	Shell               string              `json:"shell,omitempty"`
	InitSystem          string              `json:"init_system,omitempty"`
	SystemdRunning      bool                `json:"systemd_running"`
	AvailableCommands   map[string]bool     `json:"available_commands,omitempty"`
	NamespaceIDs        map[string]string   `json:"namespace_ids,omitempty"`
	MissingCapabilities []string            `json:"missing_capabilities,omitempty"`
	Distribution        DistributionProfile `json:"distribution,omitempty"`
	Kernel              KernelProfile       `json:"kernel,omitempty"`
}

type CompletedProbe struct {
	ProbeID          string      `json:"probe_id"`
	InputFingerprint string      `json:"input_fingerprint"`
	Status           ProbeStatus `json:"status"`
	EvidenceID       string      `json:"evidence_id"`
}

type Checkpoint struct {
	Phase             string                    `json:"phase"`
	Completed         map[string]CompletedProbe `json:"completed"`
	RetryCounts       map[string]int            `json:"retry_counts"`
	PendingValidation []string                  `json:"pending_validation"`
	UpdatedAt         time.Time                 `json:"updated_at"`
}

type Session struct {
	SchemaVersion    int                   `json:"schema_version"`
	ID               string                `json:"id"`
	CreatedAt        time.Time             `json:"created_at"`
	UpdatedAt        time.Time             `json:"updated_at"`
	Status           SessionStatus         `json:"status"`
	TransportKind    string                `json:"transport_kind"`
	Target           string                `json:"target,omitempty"`
	Profile          HostProfile           `json:"profile"`
	Checkpoint       Checkpoint            `json:"checkpoint"`
	GraphDiagnostics []GraphDiagnostic     `json:"graph_diagnostics,omitempty"`
	RuleDiagnostics  []RuleDiagnostic      `json:"rule_diagnostics,omitempty"`
	Vulnerability    VulnerabilityCoverage `json:"vulnerability"`
}
