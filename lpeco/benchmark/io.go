package benchmark

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// ObservationDocument is the normalized, evidence-free interchange format
// written by lpeco-bench import and consumed by lpeco-bench score.
type ObservationDocument struct {
	SchemaVersion int           `json:"schema_version"`
	Observations  []Observation `json:"observations"`
}

// LoadRunIdentity decodes one pinned benchmark run identity from JSON.
func LoadRunIdentity(reader io.Reader) (RunIdentity, error) {
	body, err := readImportArtifact(reader)
	if err != nil {
		return RunIdentity{}, err
	}
	if err := validateImportJSONHygiene(body); err != nil {
		return RunIdentity{}, err
	}
	var run RunIdentity
	if err := decodeStrictImportJSON(body, &run); err != nil {
		return RunIdentity{}, fmt.Errorf("decode run identity: %w", err)
	}
	if err := validateImportRun(run); err != nil {
		return RunIdentity{}, err
	}
	return run, nil
}

// LoadObservations decodes a normalized observation document. Joins and score
// semantics are validated later against a manifest by Evaluate.
func LoadObservations(reader io.Reader) ([]Observation, error) {
	body, err := readImportArtifact(reader)
	if err != nil {
		return nil, err
	}
	if err := validateImportJSONHygiene(body); err != nil {
		return nil, err
	}
	var document ObservationDocument
	if err := decodeStrictImportJSON(body, &document); err != nil {
		return nil, fmt.Errorf("decode observation document: %w", err)
	}
	if document.SchemaVersion != 1 {
		return nil, fmt.Errorf("observation document has unsupported schema %d", document.SchemaVersion)
	}
	if len(document.Observations) == 0 {
		return nil, errors.New("observation document contains no observations")
	}
	return document.Observations, nil
}

// EncodeObservations writes deterministic normalized JSON. Raw scanner input
// and advisory prose are never part of this format.
func EncodeObservations(writer io.Writer, observations []Observation) error {
	if writer == nil {
		return errors.New("observation writer is required")
	}
	if len(observations) == 0 {
		return errors.New("at least one observation is required")
	}
	ordered := append([]Observation(nil), observations...)
	sort.Slice(ordered, func(first, second int) bool {
		if ordered[first].RunID != ordered[second].RunID {
			return ordered[first].RunID < ordered[second].RunID
		}
		return ordered[first].ID < ordered[second].ID
	})
	body, err := json.Marshal(ObservationDocument{SchemaVersion: 1, Observations: ordered})
	if err != nil {
		return fmt.Errorf("encode observation document: %w", err)
	}
	generic, err := decodeGenericDocument(body)
	if err != nil {
		return err
	}
	if err := validateHygiene(generic, nil); err != nil {
		return err
	}
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, body, "", "  "); err != nil {
		return fmt.Errorf("format observation document: %w", err)
	}
	formatted.WriteByte('\n')
	if _, err := writer.Write(formatted.Bytes()); err != nil {
		return fmt.Errorf("write observation document: %w", err)
	}
	return nil
}

// ImportManual accepts only hand-reviewed normalized observations for tools
// without a stable structured interchange format. It never parses scanner
// prose, and a non-LPECO manual lane cannot claim a privilege-path tier.
func ImportManual(reader io.Reader, run RunIdentity) ([]Observation, error) {
	if err := validateImportRun(run); err != nil {
		return nil, err
	}
	if run.Acquisition != "manual" || run.Transport != "manual" {
		return nil, errors.New("manual import requires manual acquisition and transport")
	}
	if run.ToolID == "lpeco" {
		return nil, errors.New("LPECO reports must use the schema-v2 LPECO importer")
	}
	observations, err := LoadObservations(reader)
	if err != nil {
		return nil, err
	}
	if len(observations) != 1 {
		return nil, errors.New("manual import requires exactly one reviewed observation per run")
	}
	if _, err := validateObservations(observations, map[string]RunIdentity{run.ID: run}); err != nil {
		return nil, err
	}
	observation := observations[0]
	if observation.PathTier != "none" {
		return nil, errors.New("manual baseline import cannot claim a privilege-path tier")
	}
	if observation.Release != run.Release {
		return nil, errors.New("manual observation release does not match run identity")
	}
	if observation.Outcome == "complete" && observation.MatchState != "none" {
		if err := validateExactValue("manual package", observation.Package); err != nil {
			return nil, err
		}
		if err := validateExactValue("manual package version", observation.Version); err != nil {
			return nil, err
		}
	}
	return observations, nil
}
