package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEnumJSONRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{name: "safety", in: PassiveRead, want: `"passive-read"`},
		{name: "probe status", in: ProbeTruncated, want: `"truncated"`},
		{name: "priority", in: PriorityP1, want: `"P1"`},
		{name: "confidence", in: ConfidenceMedium, want: `"medium"`},
		{name: "validation", in: ValidationIncomplete, want: `"incomplete"`},
		{name: "node kind", in: NodeExecutable, want: `"Executable"`},
		{name: "edge kind", in: EdgeExecutes, want: `"EXECUTES"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("marshal = %s, want %s", got, tt.want)
			}
		})
	}

	var status ProbeStatus
	if err := json.Unmarshal([]byte(`"partial"`), &status); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if status != ProbePartial {
		t.Fatalf("unmarshal = %q, want %q", status, ProbePartial)
	}
}

func TestCandidateValidation(t *testing.T) {
	valid := Candidate{
		ID:                 "candidate-1",
		RuleID:             "systemd.writable-exec-chain",
		Category:           "systemd",
		Priority:           PriorityP1,
		Confidence:         ConfidenceHigh,
		CurrentPrincipal:   NodeRef{ID: "principal:1000", Kind: NodePrincipal},
		TargetPrincipal:    NodeRef{ID: "principal:0", Kind: NodePrincipal},
		PrivilegedConsumer: &NodeRef{ID: "unit:demo.service", Kind: NodeUnit},
		ControlledObject:   &NodeRef{ID: "file:/opt/demo/run", Kind: NodeExecutable},
		EvidenceIDs:        []string{"evidence-1"},
		ValidationStatus:   ValidationReadOnly,
		Summary:            "a higher-privileged unit consumes a controlled executable",
	}

	if err := valid.Validate(); err != nil {
		t.Fatalf("valid candidate rejected: %v", err)
	}

	tests := []struct {
		name       string
		mutate     func(*Candidate)
		wantErrSub string
	}{
		{
			name: "P0 cannot have low confidence",
			mutate: func(c *Candidate) {
				c.Priority = PriorityP0
				c.Confidence = ConfidenceLow
			},
			wantErrSub: "P0",
		},
		{
			name: "evidence is required",
			mutate: func(c *Candidate) {
				c.EvidenceIDs = nil
			},
			wantErrSub: "evidence",
		},
		{
			name: "target principal is required",
			mutate: func(c *Candidate) {
				c.TargetPrincipal = NodeRef{}
			},
			wantErrSub: "target principal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := valid
			tt.mutate(&candidate)
			err := candidate.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErrSub)
			}
		})
	}
}

func TestStableIDIgnoresMapInsertionOrder(t *testing.T) {
	left := map[string]any{
		"path": "/opt/demo/run",
		"ids":  []any{float64(1000), float64(0)},
	}
	right := make(map[string]any)
	right["ids"] = []any{float64(1000), float64(0)}
	right["path"] = "/opt/demo/run"

	leftID, err := StableID("fact", left)
	if err != nil {
		t.Fatalf("left StableID: %v", err)
	}
	rightID, err := StableID("fact", right)
	if err != nil {
		t.Fatalf("right StableID: %v", err)
	}
	if leftID != rightID {
		t.Fatalf("IDs differ by insertion order: %q != %q", leftID, rightID)
	}
	if !strings.HasPrefix(leftID, "fact-") || len(leftID) != len("fact-")+64 {
		t.Fatalf("unexpected stable ID shape: %q", leftID)
	}
}
