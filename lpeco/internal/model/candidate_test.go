package model

import (
	"strings"
	"testing"
)

func TestKnownVulnerabilityCandidateValidation(t *testing.T) {
	valid := Candidate{
		ID:                 "candidate-known-1",
		RuleID:             "vulnerability.known-privilege-path",
		Category:           "known-vulnerability",
		Priority:           PriorityP1,
		Confidence:         ConfidenceHigh,
		CurrentPrincipal:   NodeRef{ID: "principal:1000", Kind: NodePrincipal},
		TargetPrincipal:    NodeRef{ID: "principal:0", Kind: NodePrincipal},
		PrivilegedConsumer: &NodeRef{ID: "process:42", Kind: NodeProcess},
		ControlledObject:   &NodeRef{ID: "package:libc6", Kind: NodePackage},
		EvidenceIDs:        []string{"evidence-1"},
		RelatedMatchIDs:    []string{"match-a", "match-b"},
		ValidationStatus:   ValidationReadOnly,
		Summary:            "an affected package is used across a privilege boundary",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid known-vulnerability candidate rejected: %v", err)
	}

	tests := []struct {
		name       string
		mutate     func(*Candidate)
		wantErrSub string
	}{
		{
			name: "P0 is forbidden",
			mutate: func(candidate *Candidate) {
				candidate.Priority = PriorityP0
			},
			wantErrSub: "P0",
		},
		{
			name: "related matches are required",
			mutate: func(candidate *Candidate) {
				candidate.RelatedMatchIDs = nil
			},
			wantErrSub: "related match",
		},
		{
			name: "related matches are sorted",
			mutate: func(candidate *Candidate) {
				candidate.RelatedMatchIDs = []string{"match-b", "match-a"}
			},
			wantErrSub: "sorted",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			err := candidate.Validate()
			if err == nil || !strings.Contains(err.Error(), test.wantErrSub) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.wantErrSub)
			}
		})
	}
}
