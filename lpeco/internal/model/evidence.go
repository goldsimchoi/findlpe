package model

import "time"

type Evidence struct {
	ID               string      `json:"id"`
	SessionID        string      `json:"session_id"`
	ProbeID          string      `json:"probe_id"`
	VariantID        string      `json:"variant_id"`
	Adapter          string      `json:"adapter"`
	SHA256           string      `json:"sha256"`
	InputFingerprint string      `json:"input_fingerprint"`
	StartedAt        time.Time   `json:"started_at"`
	FinishedAt       time.Time   `json:"finished_at"`
	Status           ProbeStatus `json:"status"`
	ExitCode         *int        `json:"exit_code,omitempty"`
	MergedOutput     bool        `json:"merged_output"`
	Truncated        bool        `json:"truncated"`
	RelativePath     string      `json:"relative_path"`
}
