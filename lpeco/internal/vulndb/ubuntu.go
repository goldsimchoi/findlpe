package vulndb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/normalone/lpeco/internal/model"
)

// MaxProviderRecordBytes is the hard per-entry limit shared by incremental
// Ubuntu normalization and bounded archive synchronization.
const MaxProviderRecordBytes = 32 * 1024 * 1024

const (
	ubuntuOSVSchema         = "1.7.0"
	openVEXContext          = "https://openvex.dev/ns/v0.2.0"
	ubuntuNormalizerVersion = "ubuntu-v1"
)

var (
	ubuntuCVEIDPattern   = regexp.MustCompile(`^UBUNTU-(CVE-[0-9]{4}-[0-9]+)$`)
	cveIDPattern         = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]+$`)
	usnIDPattern         = regexp.MustCompile(`^USN-[0-9]+-[0-9]+$`)
	ubuntuVersionPattern = regexp.MustCompile(`^[0-9]{2}\.[0-9]{2}$`)
	debianPackagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*$`)
)

// UbuntuNormalizer incrementally accepts bounded official OSV and VEX entries
// and seals them into one deterministic snapshot. It never infers an installed
// target's vulnerability state.
type UbuntuNormalizer struct {
	mu sync.Mutex

	policy        ReleasePolicy
	releases      map[string]UbuntuRelease
	codenames     map[string]UbuntuRelease
	annotations   []model.ImpactAnnotation
	catalogDigest string
	initErr       error

	records     map[string]AdvisoryRecord
	vexByRecord map[string][]ProviderStatus
	vexKeys     map[string]bool
	osvEntries  map[string]bool
	vexEntries  map[string]bool
	maxModified time.Time
}

// NewUbuntuNormalizer creates a stateful incremental normalizer. Invalid
// reviewed policy/catalog input is retained as an error returned by every
// operation because the constructor interface intentionally has no error.
func NewUbuntuNormalizer(policy ReleasePolicy, annotations []model.ImpactAnnotation) *UbuntuNormalizer {
	normalizer := &UbuntuNormalizer{
		policy: policy, releases: make(map[string]UbuntuRelease), codenames: make(map[string]UbuntuRelease),
		records: make(map[string]AdvisoryRecord), vexByRecord: make(map[string][]ProviderStatus),
		vexKeys: make(map[string]bool), osvEntries: make(map[string]bool), vexEntries: make(map[string]bool),
	}
	if err := normalizer.loadPolicy(policy); err != nil {
		normalizer.initErr = err
		return normalizer
	}
	canonical, err := canonicalImpactAnnotations(annotations)
	if err != nil {
		normalizer.initErr = fmt.Errorf("validate impact annotations: %w", err)
		return normalizer
	}
	stream, err := marshalAnnotationJSONL(canonical)
	if err != nil {
		normalizer.initErr = err
		return normalizer
	}
	digest := sha256.Sum256(stream)
	normalizer.annotations = canonical
	normalizer.catalogDigest = hex.EncodeToString(digest[:])
	return normalizer
}

// AddOSV validates and stages one Ubuntu CVE OSV entry. The normalizer is not
// mutated when the entry is malformed or duplicates a normalized record key.
func (normalizer *UbuntuNormalizer) AddOSV(entryName string, reader io.Reader) error {
	if normalizer == nil {
		return errors.New("Ubuntu normalizer is nil")
	}
	body, err := readProviderRecord(reader)
	if err != nil {
		return fmt.Errorf("read OSV entry %q: %w", entryName, err)
	}
	var document osvDocument
	if err := decodeProviderJSON(body, &document); err != nil {
		return fmt.Errorf("decode OSV entry %q: %w", entryName, err)
	}
	if document.SchemaVersion != ubuntuOSVSchema {
		return fmt.Errorf("OSV entry %q uses unsupported schema %q", entryName, document.SchemaVersion)
	}
	match := ubuntuCVEIDPattern.FindStringSubmatch(document.ID)
	if len(match) != 2 {
		return fmt.Errorf("OSV entry %q is not an Ubuntu CVE record", entryName)
	}
	if document.Modified.IsZero() {
		return fmt.Errorf("OSV entry %q has no valid modified timestamp", entryName)
	}
	vulnerabilityID := match[1]
	records := make(map[string]AdvisoryRecord)
	for index, affected := range document.Affected {
		record, key, err := normalizer.normalizeOSVAffected(entryName, index, vulnerabilityID, document, affected)
		if err != nil {
			return err
		}
		if _, exists := records[key]; exists {
			return fmt.Errorf("OSV entry %q duplicates normalized key %q", entryName, key)
		}
		records[key] = record
	}
	if len(records) == 0 {
		return fmt.Errorf("OSV entry %q contains no affected package records", entryName)
	}

	normalizer.mu.Lock()
	defer normalizer.mu.Unlock()
	if normalizer.initErr != nil {
		return normalizer.initErr
	}
	if normalizer.osvEntries[entryName] {
		return fmt.Errorf("OSV entry %q was already added", entryName)
	}
	for key := range records {
		if _, exists := normalizer.records[key]; exists {
			return fmt.Errorf("OSV entry %q duplicates normalized key %q", entryName, key)
		}
	}
	for key, record := range records {
		normalizer.records[key] = record
	}
	normalizer.osvEntries[entryName] = true
	if document.Modified.After(normalizer.maxModified) {
		normalizer.maxModified = document.Modified.UTC()
	}
	return nil
}

// AddVEX validates and stages one Ubuntu CVE OpenVEX document as an exact
// status supplement. Free-form descriptions and action text are discarded.
func (normalizer *UbuntuNormalizer) AddVEX(entryName string, reader io.Reader) error {
	if normalizer == nil {
		return errors.New("Ubuntu normalizer is nil")
	}
	body, err := readProviderRecord(reader)
	if err != nil {
		return fmt.Errorf("read VEX entry %q: %w", entryName, err)
	}
	var document vexDocument
	if err := decodeProviderJSON(body, &document); err != nil {
		return fmt.Errorf("decode VEX entry %q: %w", entryName, err)
	}
	if document.Context != openVEXContext {
		return fmt.Errorf("VEX entry %q uses unsupported context %q", entryName, document.Context)
	}
	if document.Author != "Canonical Ltd." || document.Version < 1 || document.Timestamp.IsZero() || len(document.Statements) == 0 {
		return fmt.Errorf("VEX entry %q has incomplete Canonical document metadata", entryName)
	}
	type stagedStatus struct {
		recordKey string
		uniqueKey string
		status    ProviderStatus
	}
	var staged []stagedStatus
	localKeys := make(map[string]bool)
	for statementIndex, statement := range document.Statements {
		if !cveIDPattern.MatchString(statement.Vulnerability.Name) {
			return fmt.Errorf("VEX entry %q statement %d is not a CVE statement", entryName, statementIndex)
		}
		switch statement.Status {
		case ProviderStatusAffected, ProviderStatusFixed, ProviderStatusNotAffected, ProviderStatusUnderInvestigation:
		default:
			return fmt.Errorf("VEX entry %q statement %d has unsupported status %q", entryName, statementIndex, statement.Status)
		}
		groups := make(map[string][]ubuntuPURL)
		for productIndex, product := range statement.Products {
			parsed, err := parseUbuntuPURL(product.ID)
			if err != nil {
				return fmt.Errorf("VEX entry %q statement %d product %d: %w", entryName, statementIndex, productIndex, err)
			}
			groups[parsed.Distro] = append(groups[parsed.Distro], parsed)
		}
		if len(groups) == 0 {
			return fmt.Errorf("VEX entry %q statement %d has no products", entryName, statementIndex)
		}
		for distro, products := range groups {
			scope, supported := normalizer.scopeFromDistro(distro)
			if !supported && scope.Release == "" {
				// The corresponding OSV record retains this unreviewed release as
				// unsupported coverage; do not guess a version from a codename.
				continue
			}
			sourceName := ""
			for _, product := range products {
				if product.Architecture != "source" {
					continue
				}
				if sourceName != "" && sourceName != product.Name {
					return fmt.Errorf("VEX entry %q statement %d has ambiguous source packages for %q", entryName, statementIndex, distro)
				}
				sourceName = product.Name
			}
			if sourceName == "" {
				return fmt.Errorf("VEX entry %q statement %d lacks a source-package PURL for %q", entryName, statementIndex, distro)
			}
			recordKey := ubuntuRecordKey(statement.Vulnerability.Name, scope.Release, scope.Channel, sourceName)
			for _, product := range products {
				status := ProviderStatus{
					Source: "vex", Status: statement.Status, SourcePackage: sourceName,
					Architecture: product.Architecture, Version: product.Version,
				}
				if product.Architecture != "source" {
					status.BinaryPackage = product.Name
				}
				if statement.Status == ProviderStatusFixed {
					status.FixedVersion = product.Version
				}
				uniqueKey := recordKey + "\x00" + providerStatusSortKey(status)
				if localKeys[uniqueKey] {
					return fmt.Errorf("VEX entry %q duplicates normalized status key", entryName)
				}
				localKeys[uniqueKey] = true
				staged = append(staged, stagedStatus{recordKey: recordKey, uniqueKey: uniqueKey, status: status})
			}
		}
	}

	normalizer.mu.Lock()
	defer normalizer.mu.Unlock()
	if normalizer.initErr != nil {
		return normalizer.initErr
	}
	if normalizer.vexEntries[entryName] {
		return fmt.Errorf("VEX entry %q was already added", entryName)
	}
	for _, value := range staged {
		if normalizer.vexKeys[value.uniqueKey] {
			return fmt.Errorf("VEX entry %q duplicates normalized status key", entryName)
		}
	}
	for _, value := range staged {
		normalizer.vexKeys[value.uniqueKey] = true
		normalizer.vexByRecord[value.recordKey] = append(normalizer.vexByRecord[value.recordKey], value.status)
	}
	normalizer.vexEntries[entryName] = true
	if document.Timestamp.After(normalizer.maxModified) {
		normalizer.maxModified = document.Timestamp.UTC()
	}
	return nil
}

// Snapshot seals the current normalized records and reviewed annotations into
// deterministic schema-v1 content. It performs no filesystem I/O.
func (normalizer *UbuntuNormalizer) Snapshot(retrievedAt time.Time, sources []Source) (Snapshot, error) {
	if normalizer == nil {
		return Snapshot{}, errors.New("Ubuntu normalizer is nil")
	}
	normalizer.mu.Lock()
	defer normalizer.mu.Unlock()
	if normalizer.initErr != nil {
		return Snapshot{}, normalizer.initErr
	}
	records := make([]AdvisoryRecord, 0, len(normalizer.records))
	for key, original := range normalizer.records {
		record := original
		record.ProviderStatuses = append([]ProviderStatus(nil), normalizer.vexByRecord[key]...)
		statuses := make(map[string]bool)
		for _, status := range record.ProviderStatuses {
			statuses[status.Status] = true
		}
		if len(statuses) > 1 {
			record.Diagnostics = append(record.Diagnostics, "provider-status-conflict")
		}
		records = append(records, record)
	}
	releases := make([]string, 0, len(normalizer.policy.Releases))
	for _, release := range normalizer.policy.Releases {
		releases = append(releases, release.VersionID)
	}
	maxModified := normalizer.maxModified
	for _, source := range sources {
		if source.ProviderModifiedAt.After(maxModified) {
			maxModified = source.ProviderModifiedAt.UTC()
		}
	}
	snapshot := Snapshot{
		Manifest: Manifest{
			SchemaVersion: SnapshotSchemaVersion, Provider: "ubuntu", Sources: append([]Source(nil), sources...),
			RetrievedAt: retrievedAt, MaxProviderModifiedAt: maxModified,
			NormalizerVersion: ubuntuNormalizerVersion, AdvisoryCount: len(records),
			SupportedReleases: releases, SupportedChannels: []string{"standard"},
			ImpactCatalogDigest: normalizer.catalogDigest,
		},
		Advisories: records, ImpactAnnotations: append([]model.ImpactAnnotation(nil), normalizer.annotations...),
	}
	prepared, err := prepareSnapshot(snapshot, false)
	if err != nil {
		return Snapshot{}, fmt.Errorf("seal Ubuntu snapshot: %w", err)
	}
	return prepared.snapshot, nil
}

func (normalizer *UbuntuNormalizer) normalizeOSVAffected(entryName string, index int, vulnerabilityID string, document osvDocument, affected osvAffected) (AdvisoryRecord, string, error) {
	scope, err := normalizer.scopeFromEcosystem(affected.Package.Ecosystem)
	if err != nil {
		return AdvisoryRecord{}, "", fmt.Errorf("OSV entry %q affected[%d]: %w", entryName, index, err)
	}
	purl, err := parseUbuntuPURL(affected.Package.PURL)
	if err != nil {
		return AdvisoryRecord{}, "", fmt.Errorf("OSV entry %q affected[%d]: %w", entryName, index, err)
	}
	if affected.Package.Name == "" || affected.Package.Name != purl.Name || purl.Architecture != "source" {
		return AdvisoryRecord{}, "", fmt.Errorf("OSV entry %q affected[%d] has inconsistent source package PURL", entryName, index)
	}
	if scope.Codename != "" && distroCodename(purl.Distro) != scope.Codename {
		return AdvisoryRecord{}, "", fmt.Errorf("OSV entry %q affected[%d] ecosystem and PURL distro disagree", entryName, index)
	}
	introduced, fixed, err := normalizeOSVRanges(affected.Ranges)
	if err != nil {
		return AdvisoryRecord{}, "", fmt.Errorf("OSV entry %q affected[%d]: %w", entryName, index, err)
	}
	for versionIndex, version := range affected.Versions {
		if _, err := ParseDebianVersion(version); err != nil {
			return AdvisoryRecord{}, "", fmt.Errorf("OSV entry %q affected[%d] version[%d]: %w", entryName, index, versionIndex, err)
		}
	}
	binaryVersions := make(map[string]string)
	for binaryIndex, binary := range affected.EcosystemSpecific.Binaries {
		if !debianPackagePattern.MatchString(binary.Name) {
			return AdvisoryRecord{}, "", fmt.Errorf("OSV entry %q affected[%d] binary[%d] has invalid name", entryName, index, binaryIndex)
		}
		if binary.Version != "" {
			if _, err := ParseDebianVersion(binary.Version); err != nil {
				return AdvisoryRecord{}, "", fmt.Errorf("OSV entry %q affected[%d] binary[%d] version: %w", entryName, index, binaryIndex, err)
			}
		}
		if existing, ok := binaryVersions[binary.Name]; ok && existing != binary.Version {
			return AdvisoryRecord{}, "", fmt.Errorf("OSV entry %q affected[%d] has conflicting binary versions for %q", entryName, index, binary.Name)
		}
		binaryVersions[binary.Name] = binary.Version
	}
	binaries := make([]string, 0, len(binaryVersions))
	for name := range binaryVersions {
		binaries = append(binaries, name)
	}
	diagnostics := append([]string(nil), scope.Diagnostics...)
	if len(binaries) == 0 {
		diagnostics = append(diagnostics, "binary-package-mapping-unavailable")
	}
	recordID, err := model.StableID("ubuntu-advisory-record", struct {
		VulnerabilityID string `json:"vulnerability_id"`
		Release         string `json:"release"`
		Channel         string `json:"channel"`
		SourcePackage   string `json:"source_package"`
	}{vulnerabilityID, scope.Release, scope.Channel, affected.Package.Name})
	if err != nil {
		return AdvisoryRecord{}, "", err
	}
	record := AdvisoryRecord{
		RecordID: recordID, Provider: "ubuntu", VulnerabilityID: vulnerabilityID,
		Release: scope.Release, Codename: scope.Codename, Channel: scope.Channel,
		Affected: AffectedPackage{
			SourcePackage: affected.Package.Name, BinaryPackages: binaries,
			IntroducedVersion: introduced, FixedVersion: fixed, BinaryFixedVersions: binaryVersions,
		},
		CVEIDs: collectCVEIDs(vulnerabilityID, document.Upstream, document.Aliases),
		USNIDs: collectUSNIDs(document.Related), OfficialReferences: officialUbuntuReferences(document.References),
		SeverityMetadata: normalizeSeverity(document.Severity), ModifiedAt: document.Modified.UTC(),
		Withdrawn: document.Withdrawn != nil, Diagnostics: diagnostics,
	}
	key := ubuntuRecordKey(vulnerabilityID, scope.Release, scope.Channel, affected.Package.Name)
	return record, key, nil
}

func (normalizer *UbuntuNormalizer) loadPolicy(policy ReleasePolicy) error {
	if policy.SchemaVersion != 1 || policy.Provider != "ubuntu" || policy.ReviewedAt.IsZero() || len(policy.Releases) == 0 {
		return errors.New("Ubuntu release policy is incomplete")
	}
	for index, release := range policy.Releases {
		if !ubuntuVersionPattern.MatchString(release.VersionID) || release.Codename == "" || release.Channel != "standard" {
			return fmt.Errorf("Ubuntu release policy entry %d is invalid", index)
		}
		if _, exists := normalizer.releases[release.VersionID]; exists {
			return fmt.Errorf("Ubuntu release policy version %q is duplicated", release.VersionID)
		}
		if _, exists := normalizer.codenames[release.Codename]; exists {
			return fmt.Errorf("Ubuntu release policy codename %q is duplicated", release.Codename)
		}
		normalizer.releases[release.VersionID] = release
		normalizer.codenames[release.Codename] = release
	}
	return nil
}

type ubuntuScope struct {
	Release     string
	Codename    string
	Channel     string
	Diagnostics []string
}

func (normalizer *UbuntuNormalizer) scopeFromEcosystem(ecosystem string) (ubuntuScope, error) {
	parts := strings.Split(ecosystem, ":")
	if len(parts) < 2 || parts[0] != "Ubuntu" {
		return ubuntuScope{}, fmt.Errorf("unsupported ecosystem %q", ecosystem)
	}
	if parts[1] == "Pro" {
		version := ""
		for _, part := range parts[2:] {
			if ubuntuVersionPattern.MatchString(part) {
				version = part
				break
			}
		}
		if version == "" {
			return ubuntuScope{}, fmt.Errorf("Pro ecosystem %q has no release", ecosystem)
		}
		release, ok := normalizer.releases[version]
		codename := ""
		if ok {
			codename = release.Codename
		}
		return ubuntuScope{Release: version, Codename: codename, Channel: "pro", Diagnostics: []string{"unsupported-channel: pro"}}, nil
	}
	if len(parts) != 2 && !(len(parts) == 3 && parts[2] == "LTS") {
		return ubuntuScope{}, fmt.Errorf("unsupported Ubuntu ecosystem shape %q", ecosystem)
	}
	version := parts[1]
	if !ubuntuVersionPattern.MatchString(version) {
		return ubuntuScope{}, fmt.Errorf("invalid Ubuntu release in ecosystem %q", ecosystem)
	}
	if release, ok := normalizer.releases[version]; ok {
		return ubuntuScope{Release: version, Codename: release.Codename, Channel: "standard"}, nil
	}
	return ubuntuScope{Release: version, Channel: "unsupported", Diagnostics: []string{"unsupported-release: " + version}}, nil
}

func (normalizer *UbuntuNormalizer) scopeFromDistro(distro string) (ubuntuScope, bool) {
	codename := distroCodename(distro)
	release, ok := normalizer.codenames[codename]
	if !ok {
		return ubuntuScope{Codename: codename, Channel: "unsupported"}, false
	}
	if strings.Contains(distro, "/") {
		return ubuntuScope{Release: release.VersionID, Codename: codename, Channel: "pro"}, false
	}
	return ubuntuScope{Release: release.VersionID, Codename: codename, Channel: "standard"}, true
}

func normalizeOSVRanges(ranges []osvRange) (string, string, error) {
	if len(ranges) == 0 {
		return "", "", errors.New("OSV affected package has no ranges")
	}
	introduced := ""
	fixed := ""
	for _, current := range ranges {
		if current.Type != "ECOSYSTEM" {
			return "", "", fmt.Errorf("unsupported OSV range type %q", current.Type)
		}
		for _, event := range current.Events {
			switch {
			case event.Introduced != "":
				if event.Introduced != "0" || introduced != "" {
					return "", "", errors.New("OSV introduced event must be the single value 0")
				}
				introduced = event.Introduced
			case event.Fixed != "":
				if fixed != "" {
					return "", "", errors.New("OSV range has multiple fixed boundaries")
				}
				if _, err := ParseDebianVersion(event.Fixed); err != nil {
					return "", "", fmt.Errorf("invalid OSV fixed boundary: %w", err)
				}
				fixed = event.Fixed
			default:
				return "", "", errors.New("OSV range has an unsupported empty event")
			}
		}
	}
	if introduced != "0" {
		return "", "", errors.New("OSV range does not begin at introduced version 0")
	}
	return introduced, fixed, nil
}

type ubuntuPURL struct {
	Name         string
	Version      string
	Architecture string
	Distro       string
}

func parseUbuntuPURL(raw string) (ubuntuPURL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "pkg" || parsed.Fragment != "" || !strings.HasPrefix(parsed.Opaque, "deb/ubuntu/") {
		return ubuntuPURL{}, fmt.Errorf("invalid Ubuntu deb PURL %q", raw)
	}
	identity := strings.TrimPrefix(parsed.Opaque, "deb/ubuntu/")
	separator := strings.LastIndexByte(identity, '@')
	if separator <= 0 || separator == len(identity)-1 {
		return ubuntuPURL{}, fmt.Errorf("Ubuntu deb PURL %q lacks package/version", raw)
	}
	name, err := url.PathUnescape(identity[:separator])
	if err != nil || !debianPackagePattern.MatchString(name) || strings.Contains(name, "/") {
		return ubuntuPURL{}, fmt.Errorf("Ubuntu deb PURL %q has invalid package name", raw)
	}
	version, err := url.PathUnescape(identity[separator+1:])
	if err != nil {
		return ubuntuPURL{}, fmt.Errorf("Ubuntu deb PURL %q has invalid version encoding", raw)
	}
	if _, err := ParseDebianVersion(version); err != nil {
		return ubuntuPURL{}, fmt.Errorf("Ubuntu deb PURL %q has invalid Debian version: %w", raw, err)
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return ubuntuPURL{}, fmt.Errorf("Ubuntu deb PURL %q has invalid qualifiers", raw)
	}
	for key, values := range query {
		if key != "arch" && key != "distro" || len(values) != 1 || values[0] == "" {
			return ubuntuPURL{}, fmt.Errorf("Ubuntu deb PURL %q has unsupported qualifiers", raw)
		}
	}
	architecture := query.Get("arch")
	distro := query.Get("distro")
	if architecture == "" || distro == "" || strings.ContainsAny(architecture, "/\x00") || strings.ContainsRune(distro, '\x00') {
		return ubuntuPURL{}, fmt.Errorf("Ubuntu deb PURL %q lacks architecture or distro", raw)
	}
	return ubuntuPURL{Name: name, Version: version, Architecture: architecture, Distro: distro}, nil
}

func readProviderRecord(reader io.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("provider record reader is nil")
	}
	body, err := io.ReadAll(io.LimitReader(reader, MaxProviderRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxProviderRecordBytes {
		return nil, fmt.Errorf("provider record exceeds %d-byte bound", MaxProviderRecordBytes)
	}
	return body, nil
}

func decodeProviderJSON(input []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
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

func collectCVEIDs(primary string, groups ...[]string) []string {
	values := []string{primary}
	for _, group := range groups {
		for _, value := range group {
			if cveIDPattern.MatchString(value) {
				values = append(values, value)
			}
		}
	}
	return canonicalStrings(values)
}

func collectUSNIDs(values []string) []string {
	result := make([]string, 0)
	for _, value := range values {
		if usnIDPattern.MatchString(value) {
			result = append(result, value)
		}
	}
	return canonicalStrings(result)
}

func officialUbuntuReferences(values []osvReference) []string {
	result := make([]string, 0)
	for _, reference := range values {
		parsed, err := url.Parse(reference.URL)
		if err == nil && parsed.Scheme == "https" && parsed.Host == "ubuntu.com" && strings.HasPrefix(parsed.Path, "/security/") && parsed.RawQuery == "" && parsed.Fragment == "" {
			result = append(result, reference.URL)
		}
	}
	return canonicalStrings(result)
}

func normalizeSeverity(values []osvSeverity) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value.Type != "" && value.Score != "" {
			result = append(result, value.Type+"="+value.Score)
		}
	}
	return canonicalStrings(result)
}

func ubuntuRecordKey(vulnerabilityID, release, channel, sourcePackage string) string {
	return vulnerabilityID + "\x00" + release + "\x00" + channel + "\x00" + sourcePackage
}

func distroCodename(distro string) string {
	return filepath.Base(strings.TrimSuffix(distro, "/"))
}

type osvDocument struct {
	SchemaVersion string         `json:"schema_version"`
	ID            string         `json:"id"`
	Details       string         `json:"details"`
	Aliases       []string       `json:"aliases"`
	Upstream      []string       `json:"upstream"`
	Related       []string       `json:"related"`
	Severity      []osvSeverity  `json:"severity"`
	Published     time.Time      `json:"published"`
	Modified      time.Time      `json:"modified"`
	Withdrawn     *time.Time     `json:"withdrawn"`
	Affected      []osvAffected  `json:"affected"`
	References    []osvReference `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		PURL      string `json:"purl"`
	} `json:"package"`
	Ranges            []osvRange `json:"ranges"`
	Versions          []string   `json:"versions"`
	EcosystemSpecific struct {
		Binaries []struct {
			Name    string `json:"binary_name"`
			Version string `json:"binary_version"`
		} `json:"binaries"`
		Availability   string `json:"availability"`
		PriorityReason string `json:"priority_reason"`
	} `json:"ecosystem_specific"`
}

type osvRange struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced string `json:"introduced"`
		Fixed      string `json:"fixed"`
	} `json:"events"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type vexDocument struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Timestamp  time.Time      `json:"timestamp"`
	Version    int            `json:"version"`
	Statements []vexStatement `json:"statements"`
}

type vexStatement struct {
	Vulnerability struct {
		ID          string   `json:"@id"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Aliases     []string `json:"aliases"`
	} `json:"vulnerability"`
	Timestamp time.Time `json:"timestamp"`
	Products  []struct {
		ID string `json:"@id"`
	} `json:"products"`
	Status          string `json:"status"`
	StatusNotes     string `json:"status_notes"`
	ActionStatement string `json:"action_statement"`
	ImpactStatement string `json:"impact_statement"`
	Justification   string `json:"justification"`
}
