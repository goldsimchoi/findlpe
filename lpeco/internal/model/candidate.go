package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type Candidate struct {
	ID                 string           `json:"id"`
	RuleID             string           `json:"rule_id"`
	Category           string           `json:"category"`
	Priority           Priority         `json:"priority"`
	Confidence         Confidence       `json:"confidence"`
	CurrentPrincipal   NodeRef          `json:"current_principal"`
	TargetPrincipal    NodeRef          `json:"target_principal"`
	PrivilegedConsumer *NodeRef         `json:"privileged_consumer,omitempty"`
	ControlledObject   *NodeRef         `json:"controlled_object,omitempty"`
	Trigger            *NodeRef         `json:"trigger,omitempty"`
	PathNodes          []NodeRef        `json:"path_nodes"`
	EvidenceIDs        []string         `json:"evidence_ids"`
	MissingFacts       []string         `json:"missing_facts"`
	ValidationStatus   ValidationStatus `json:"validation_status"`
	Summary            string           `json:"summary"`
}

func (c Candidate) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return errors.New("candidate ID is required")
	}
	if strings.TrimSpace(c.RuleID) == "" {
		return errors.New("candidate rule ID is required")
	}
	if strings.TrimSpace(c.Category) == "" {
		return errors.New("candidate category is required")
	}
	if c.Priority != PriorityP0 && c.Priority != PriorityP1 && c.Priority != PriorityP2 {
		return fmt.Errorf("unknown candidate priority %q", c.Priority)
	}
	if c.Confidence != ConfidenceHigh && c.Confidence != ConfidenceMedium && c.Confidence != ConfidenceLow {
		return fmt.Errorf("unknown candidate confidence %q", c.Confidence)
	}
	if c.Priority == PriorityP0 && (c.Confidence != ConfidenceHigh || len(c.MissingFacts) > 0) {
		return errors.New("P0 candidate requires high confidence and no missing facts")
	}
	if c.CurrentPrincipal.ID == "" {
		return errors.New("current principal is required")
	}
	if c.TargetPrincipal.ID == "" {
		return errors.New("target principal is required")
	}
	if len(c.EvidenceIDs) == 0 {
		return errors.New("candidate evidence is required")
	}
	if c.ValidationStatus != ValidationUnvalidated && c.ValidationStatus != ValidationReadOnly && c.ValidationStatus != ValidationIncomplete {
		return fmt.Errorf("unknown validation status %q", c.ValidationStatus)
	}
	if c.ValidationStatus == ValidationReadOnly && (c.Confidence != ConfidenceHigh || len(c.MissingFacts) > 0) {
		return errors.New("read-only validation requires high confidence and no missing facts")
	}
	if strings.TrimSpace(c.Summary) == "" {
		return errors.New("candidate summary is required")
	}
	return nil
}

func StableID(prefix string, value any) (string, error) {
	if strings.TrimSpace(prefix) == "" {
		return "", errors.New("stable ID prefix is required")
	}

	var canonical bytes.Buffer
	encoder := json.NewEncoder(&canonical)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", fmt.Errorf("encode stable ID input: %w", err)
	}
	digest := sha256.Sum256(bytes.TrimSuffix(canonical.Bytes(), []byte{'\n'}))
	return prefix + "-" + hex.EncodeToString(digest[:]), nil
}
