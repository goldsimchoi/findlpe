package benchmark

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

type openSCAPMetadata struct {
	schemaVersion   string
	distribution    string
	release         string
	packageName     string
	packageVersion  string
	scanStatus      string
	resultSemantics string
}

// ImportOpenSCAP reads the deliberately small OVAL-results subset used by the
// benchmark. External entities and document type declarations are rejected
// before XML tokenization.
func ImportOpenSCAP(reader io.Reader, run RunIdentity) ([]Observation, error) {
	if err := validateImportRun(run); err != nil {
		return nil, err
	}
	if run.ToolID != "openscap" {
		return nil, fmt.Errorf("OpenSCAP importer requires tool ID openscap, got %q", run.ToolID)
	}
	body, err := readImportArtifact(reader)
	if err != nil {
		return nil, err
	}
	lower := bytes.ToLower(body)
	if bytes.Contains(lower, []byte("<!doctype")) || bytes.Contains(lower, []byte("<!entity")) {
		return nil, errors.New("OpenSCAP XML document types and entities are forbidden")
	}

	metadata, results, err := parseOpenSCAP(body)
	if err != nil {
		return nil, err
	}
	if metadata.schemaVersion != "1" {
		return nil, fmt.Errorf("OpenSCAP artifact has unsupported schema %q", metadata.schemaVersion)
	}
	if metadata.distribution != run.DistributionID || metadata.release != run.Release {
		return nil, errors.New("OpenSCAP distribution/release does not match run identity")
	}
	if metadata.resultSemantics != "affected-fixed" {
		return nil, fmt.Errorf("OpenSCAP result semantics %q are unsupported", metadata.resultSemantics)
	}
	if metadata.scanStatus != "complete" {
		if !oneOf(metadata.scanStatus, "error", "timeout", "crash") {
			return nil, fmt.Errorf("OpenSCAP artifact has unsupported scan status %q", metadata.scanStatus)
		}
		if len(results) != 0 {
			return nil, errors.New("failed OpenSCAP artifact contains scored definitions")
		}
		return []Observation{newObservation(run, metadata.scanStatus, "none", "none", "", "", []string{"scanner-" + metadata.scanStatus})}, nil
	}
	if err := validateExactValue("OpenSCAP package", metadata.packageName); err != nil {
		return nil, err
	}
	if err := validateExactValue("OpenSCAP package version", metadata.packageVersion); err != nil {
		return nil, err
	}

	hasTrue, hasFalse, hasUnknown, hasError := false, false, false, false
	for _, result := range results {
		switch result {
		case "true":
			hasTrue = true
		case "false":
			hasFalse = true
		case "unknown", "not evaluated", "not applicable":
			hasUnknown = true
		case "error":
			hasError = true
		default:
			return nil, fmt.Errorf("OpenSCAP definition has unsupported result %q", result)
		}
	}

	outcome, state := "complete", "none"
	switch {
	case hasTrue:
		state = "affected"
	case hasError:
		outcome = "error"
	case hasUnknown:
		outcome, state = "unknown", "unknown"
	case hasFalse:
		state = "fixed"
	}
	return []Observation{newObservation(run, outcome, state, "none", metadata.packageName, metadata.packageVersion, nil)}, nil
}

func parseOpenSCAP(body []byte) (openSCAPMetadata, []string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.Strict = true
	var metadata openSCAPMetadata
	var stack []string
	var results []string
	seenDefinitions := make(map[string]struct{})
	rootSeen := false

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return openSCAPMetadata{}, nil, fmt.Errorf("decode OpenSCAP XML: %w", err)
		}
		switch typed := token.(type) {
		case xml.StartElement:
			name := typed.Name.Local
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			if err := validateOpenSCAPElement(name, parent); err != nil {
				return openSCAPMetadata{}, nil, err
			}
			if name == "oval_results" {
				if rootSeen || parent != "" {
					return openSCAPMetadata{}, nil, errors.New("OpenSCAP artifact has multiple or nested roots")
				}
				rootSeen = true
				metadata, err = openSCAPRootMetadata(typed.Attr)
				if err != nil {
					return openSCAPMetadata{}, nil, err
				}
			} else if name == "definition" {
				id, result, err := openSCAPDefinition(typed.Attr)
				if err != nil {
					return openSCAPMetadata{}, nil, err
				}
				if _, duplicate := seenDefinitions[id]; duplicate {
					return openSCAPMetadata{}, nil, fmt.Errorf("duplicate OpenSCAP definition ID %q", id)
				}
				seenDefinitions[id] = struct{}{}
				results = append(results, result)
			} else if err := rejectOpenSCAPAttributes(typed.Attr); err != nil {
				return openSCAPMetadata{}, nil, fmt.Errorf("OpenSCAP element %q: %w", name, err)
			}
			stack = append(stack, name)
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1] != typed.Name.Local {
				return openSCAPMetadata{}, nil, errors.New("OpenSCAP XML element nesting is invalid")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if strings.TrimSpace(string(typed)) != "" {
				return openSCAPMetadata{}, nil, errors.New("OpenSCAP XML contains unexpected prose")
			}
		case xml.Directive:
			return openSCAPMetadata{}, nil, errors.New("OpenSCAP XML directives are forbidden")
		case xml.ProcInst:
			if !strings.EqualFold(typed.Target, "xml") {
				return openSCAPMetadata{}, nil, errors.New("OpenSCAP XML processing instructions are forbidden")
			}
		case xml.Comment:
			return openSCAPMetadata{}, nil, errors.New("OpenSCAP XML comments are forbidden")
		}
	}
	if !rootSeen || len(stack) != 0 {
		return openSCAPMetadata{}, nil, errors.New("OpenSCAP XML root is missing or incomplete")
	}
	return metadata, results, nil
}

func validateOpenSCAPElement(name, parent string) error {
	wantParent := map[string]string{
		"oval_results": "", "results": "oval_results", "system": "results",
		"definitions": "system", "definition": "definitions",
	}
	want, known := wantParent[name]
	if !known || parent != want {
		return fmt.Errorf("OpenSCAP element %q is not allowed beneath %q", name, parent)
	}
	return nil
}

func openSCAPRootMetadata(attributes []xml.Attr) (openSCAPMetadata, error) {
	values, err := openSCAPAttributes(attributes, map[string]bool{
		"schema_version": true, "distribution": true, "release": true, "package": true,
		"version": true, "scan_status": true, "result_semantics": true,
	})
	if err != nil {
		return openSCAPMetadata{}, err
	}
	for _, name := range []string{"schema_version", "distribution", "release", "scan_status", "result_semantics"} {
		if values[name] == "" {
			return openSCAPMetadata{}, fmt.Errorf("OpenSCAP root attribute %q is required", name)
		}
	}
	return openSCAPMetadata{
		schemaVersion: values["schema_version"], distribution: values["distribution"], release: values["release"],
		packageName: values["package"], packageVersion: values["version"], scanStatus: values["scan_status"],
		resultSemantics: values["result_semantics"],
	}, nil
}

func openSCAPDefinition(attributes []xml.Attr) (string, string, error) {
	values, err := openSCAPAttributes(attributes, map[string]bool{"definition_id": true, "result": true})
	if err != nil {
		return "", "", err
	}
	if err := validateExactValue("OpenSCAP definition ID", values["definition_id"]); err != nil {
		return "", "", err
	}
	if values["result"] == "" {
		return "", "", errors.New("OpenSCAP definition result is required")
	}
	return values["definition_id"], values["result"], nil
}

func rejectOpenSCAPAttributes(attributes []xml.Attr) error {
	_, err := openSCAPAttributes(attributes, map[string]bool{})
	return err
}

func openSCAPAttributes(attributes []xml.Attr, allowed map[string]bool) (map[string]string, error) {
	values := make(map[string]string, len(attributes))
	for _, attribute := range attributes {
		if attribute.Name.Space == "xmlns" || attribute.Name.Local == "xmlns" || attribute.Name.Local == "schemaLocation" {
			continue
		}
		if !allowed[attribute.Name.Local] {
			return nil, fmt.Errorf("OpenSCAP attribute %q is not allowed", attribute.Name.Local)
		}
		if _, duplicate := values[attribute.Name.Local]; duplicate {
			return nil, fmt.Errorf("duplicate OpenSCAP attribute %q", attribute.Name.Local)
		}
		if err := validateHygieneString(attribute.Value); err != nil {
			return nil, fmt.Errorf("OpenSCAP attribute %q: %w", attribute.Name.Local, err)
		}
		values[attribute.Name.Local] = attribute.Value
	}
	return values, nil
}
