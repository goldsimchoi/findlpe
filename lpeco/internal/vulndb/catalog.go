package vulndb

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/normalone/lpeco/internal/model"
)

//go:embed catalog/impact-annotations.json
var impactCatalogJSON []byte

//go:embed catalog/ubuntu-releases.json
var releasePolicyJSON []byte

// LoadImpactCatalog loads, validates, and canonically hashes the reviewed
// impact annotations embedded in this binary.
func LoadImpactCatalog() ([]model.ImpactAnnotation, string, error) {
	var annotations []model.ImpactAnnotation
	if err := decodeStrictJSON(impactCatalogJSON, &annotations); err != nil {
		return nil, "", fmt.Errorf("decode embedded impact catalog: %w", err)
	}
	canonical, err := canonicalImpactAnnotations(annotations)
	if err != nil {
		return nil, "", fmt.Errorf("validate embedded impact catalog: %w", err)
	}
	stream, err := marshalAnnotationJSONL(canonical)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(stream)
	return canonical, hex.EncodeToString(digest[:]), nil
}

// LoadUbuntuReleasePolicy loads the narrow reviewed standard-release policy
// embedded in this binary.
func LoadUbuntuReleasePolicy() (ReleasePolicy, error) {
	var policy ReleasePolicy
	if err := decodeStrictJSON(releasePolicyJSON, &policy); err != nil {
		return ReleasePolicy{}, fmt.Errorf("decode embedded Ubuntu release policy: %w", err)
	}
	if policy.SchemaVersion != 1 {
		return ReleasePolicy{}, fmt.Errorf("unsupported release policy schema %d", policy.SchemaVersion)
	}
	if policy.Provider != "ubuntu" {
		return ReleasePolicy{}, fmt.Errorf("unsupported release policy provider %q", policy.Provider)
	}
	if policy.ReviewedAt.IsZero() {
		return ReleasePolicy{}, errors.New("release policy review time is required")
	}
	seenVersion := make(map[string]bool)
	seenCodename := make(map[string]bool)
	for index, release := range policy.Releases {
		if release.VersionID == "" || release.Codename == "" || release.Channel != "standard" {
			return ReleasePolicy{}, fmt.Errorf("release policy entry %d is not a complete standard release", index)
		}
		if seenVersion[release.VersionID] || seenCodename[release.Codename] {
			return ReleasePolicy{}, fmt.Errorf("release policy entry %d is duplicated", index)
		}
		seenVersion[release.VersionID] = true
		seenCodename[release.Codename] = true
	}
	if len(policy.Releases) == 0 {
		return ReleasePolicy{}, errors.New("release policy contains no releases")
	}
	sort.Slice(policy.Releases, func(i, j int) bool { return policy.Releases[i].VersionID < policy.Releases[j].VersionID })
	policy.ReviewedAt = policy.ReviewedAt.UTC()
	return policy, nil
}

func canonicalImpactAnnotations(input []model.ImpactAnnotation) ([]model.ImpactAnnotation, error) {
	result := append([]model.ImpactAnnotation(nil), input...)
	seen := make(map[string]bool, len(result))
	for index := range result {
		annotation := &result[index]
		annotation.SourcePackages = canonicalStrings(annotation.SourcePackages)
		annotation.BinaryPackages = canonicalStrings(annotation.BinaryPackages)
		annotation.AffectedUse = canonicalEdgeKinds(annotation.AffectedUse)
		annotation.Reachability = canonicalEdgeKinds(annotation.Reachability)
		annotation.OfficialReferences = canonicalStrings(annotation.OfficialReferences)
		annotation.ReviewedAt = annotation.ReviewedAt.UTC()
		if annotation.ID == "" || seen[annotation.ID] {
			return nil, fmt.Errorf("annotation %d has an empty or duplicate ID", index)
		}
		seen[annotation.ID] = true
		if annotation.SchemaVersion != 1 || annotation.Provider != "ubuntu" {
			return nil, fmt.Errorf("annotation %q has unsupported schema or provider", annotation.ID)
		}
		if !strings.HasPrefix(annotation.VulnerabilityID, "CVE-") || len(annotation.SourcePackages) == 0 || len(annotation.BinaryPackages) == 0 {
			return nil, fmt.Errorf("annotation %q has incomplete vulnerability/package scope", annotation.ID)
		}
		if len(annotation.AffectedUse) == 0 || len(annotation.Reachability) == 0 || annotation.ImpactClass == "" || annotation.TargetConstraint == "" {
			return nil, fmt.Errorf("annotation %q has incomplete impact scope", annotation.ID)
		}
		for _, kind := range annotation.AffectedUse {
			if kind != model.EdgeExecutes && kind != model.EdgeInterprets && kind != model.EdgeLoads {
				return nil, fmt.Errorf("annotation %q has unsupported affected-use relation %q", annotation.ID, kind)
			}
		}
		for _, kind := range annotation.Reachability {
			if kind != model.EdgeCanExecute && kind != model.EdgeCanWrite && kind != model.EdgeActivates {
				return nil, fmt.Errorf("annotation %q has unsupported reachability relation %q", annotation.ID, kind)
			}
		}
		if annotation.TargetConstraint != "different-principal" {
			return nil, fmt.Errorf("annotation %q has unsupported target constraint %q", annotation.ID, annotation.TargetConstraint)
		}
		if annotation.ReviewedAt.IsZero() || len(annotation.OfficialReferences) == 0 {
			return nil, fmt.Errorf("annotation %q lacks review provenance", annotation.ID)
		}
		for _, reference := range annotation.OfficialReferences {
			parsed, err := url.Parse(reference)
			if err != nil || parsed.Scheme != "https" || parsed.Host != "ubuntu.com" || !strings.HasPrefix(parsed.Path, "/security/") || parsed.RawQuery != "" || parsed.Fragment != "" {
				return nil, fmt.Errorf("annotation %q has non-official reference %q", annotation.ID, reference)
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	if result == nil {
		result = []model.ImpactAnnotation{}
	}
	return result, nil
}

func marshalAnnotationJSONL(annotations []model.ImpactAnnotation) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for _, annotation := range annotations {
		if err := encoder.Encode(annotation); err != nil {
			return nil, fmt.Errorf("encode impact annotation %q: %w", annotation.ID, err)
		}
	}
	return output.Bytes(), nil
}

func decodeStrictJSON(input []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func canonicalStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	if result == nil {
		return []string{}
	}
	return result
}

func canonicalEdgeKinds(values []model.EdgeKind) []model.EdgeKind {
	seen := make(map[model.EdgeKind]bool, len(values))
	result := make([]model.EdgeKind, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	if result == nil {
		return []model.EdgeKind{}
	}
	return result
}
