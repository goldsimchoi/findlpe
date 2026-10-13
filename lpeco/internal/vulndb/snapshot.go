package vulndb

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/normalone/lpeco/internal/model"
)

const (
	manifestFilename    = "manifest.json"
	advisoriesFilename  = "advisories.jsonl.gz"
	annotationsFilename = "impact-annotations.jsonl.gz"
	currentFilename     = "current.json"

	maxManifestBytes            = 1 << 20
	maxCompressedSnapshotStream = 256 << 20
	maxAdvisoryStreamBytes      = 512 << 20
	maxAnnotationStreamBytes    = 32 << 20
	maxSnapshotRecords          = 250000
)

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type snapshotEncoding struct {
	snapshot        Snapshot
	manifest        []byte
	advisories      []byte
	annotations     []byte
	advisoriesGzip  []byte
	annotationsGzip []byte
}

// DefaultDir returns the platform user-cache location for immutable advisory
// snapshots. It does not create the directory.
func DefaultDir() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve user cache directory: %w", err)
	}
	if cache == "" || !filepath.IsAbs(cache) {
		return "", errors.New("resolve user cache directory: path is empty or not absolute")
	}
	return filepath.Join(cache, "lpeco", "vuln-db"), nil
}

// Validate verifies schema, counts, catalog content, and the semantic content
// digest of a snapshot without performing I/O.
func Validate(snapshot Snapshot) error {
	_, err := prepareSnapshot(snapshot, true)
	return err
}

// Publish validates and writes a content-addressed snapshot before atomically
// replacing the current pointer. Existing immutable snapshots are retained.
func Publish(ctx context.Context, root string, snapshot Snapshot) (model.SnapshotReference, error) {
	if err := ctx.Err(); err != nil {
		return model.SnapshotReference{}, err
	}
	prepared, err := prepareSnapshot(snapshot, snapshot.Manifest.Digest != "")
	if err != nil {
		return model.SnapshotReference{}, fmt.Errorf("prepare advisory snapshot: %w", err)
	}
	if err := ensurePrivateDirectory(root); err != nil {
		return model.SnapshotReference{}, fmt.Errorf("prepare vulnerability database root: %w", err)
	}
	finalDirectory := filepath.Join(root, "sha256-"+prepared.snapshot.Manifest.Digest)
	if info, statErr := os.Lstat(finalDirectory); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return model.SnapshotReference{}, fmt.Errorf("snapshot destination %q is not a private directory", filepath.Base(finalDirectory))
		}
		if _, err := LoadDirectory(ctx, finalDirectory, prepared.snapshot.Manifest.RetrievedAt); err != nil {
			return model.SnapshotReference{}, fmt.Errorf("validate existing immutable snapshot: %w", err)
		}
	} else if !os.IsNotExist(statErr) {
		return model.SnapshotReference{}, fmt.Errorf("inspect snapshot destination: %w", statErr)
	} else {
		if err := publishDirectory(ctx, root, finalDirectory, prepared); err != nil {
			return model.SnapshotReference{}, err
		}
	}

	loaded, err := LoadDirectory(ctx, finalDirectory, prepared.snapshot.Manifest.RetrievedAt)
	if err != nil {
		return model.SnapshotReference{}, fmt.Errorf("validate published snapshot: %w", err)
	}
	pointer := CurrentPointer{SchemaVersion: SnapshotSchemaVersion, Digest: loaded.Manifest.Digest}
	if err := writeCanonicalJSONAtomic(ctx, filepath.Join(root, currentFilename), pointer); err != nil {
		return model.SnapshotReference{}, fmt.Errorf("replace current snapshot pointer: %w", err)
	}
	if err := syncDirectory(root); err != nil {
		return model.SnapshotReference{}, fmt.Errorf("sync vulnerability database root: %w", err)
	}
	return snapshotReference(loaded, loaded.Manifest.RetrievedAt), nil
}

// LoadCurrent loads and validates the immutable snapshot named by current.json.
func LoadCurrent(ctx context.Context, root string, now time.Time) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if err := requirePrivateDirectory(root); err != nil {
		return Snapshot{}, fmt.Errorf("validate vulnerability database root: %w", err)
	}
	pointerBytes, err := readPrivateRegularFile(filepath.Join(root, currentFilename), maxManifestBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read current snapshot pointer: %w", err)
	}
	var pointer CurrentPointer
	if err := decodeStrictJSON(pointerBytes, &pointer); err != nil {
		return Snapshot{}, fmt.Errorf("decode current snapshot pointer: %w", err)
	}
	if pointer.SchemaVersion != SnapshotSchemaVersion {
		return Snapshot{}, fmt.Errorf("unsupported current pointer schema %d", pointer.SchemaVersion)
	}
	return LoadDigest(ctx, root, pointer.Digest, now)
}

// LoadDigest loads one exact content-addressed snapshot beneath root.
func LoadDigest(ctx context.Context, root, digest string, now time.Time) (Snapshot, error) {
	if !digestPattern.MatchString(digest) {
		return Snapshot{}, fmt.Errorf("invalid snapshot digest %q", digest)
	}
	if err := requirePrivateDirectory(root); err != nil {
		return Snapshot{}, fmt.Errorf("validate vulnerability database root: %w", err)
	}
	return LoadDirectory(ctx, filepath.Join(root, "sha256-"+digest), now)
}

// LoadDirectory loads only an exact sha256-<digest> immutable directory and
// rejects symlinks, extra entries, permissive modes, and non-canonical bytes.
func LoadDirectory(ctx context.Context, directory string, now time.Time) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	name := filepath.Base(filepath.Clean(directory))
	if !strings.HasPrefix(name, "sha256-") || !digestPattern.MatchString(strings.TrimPrefix(name, "sha256-")) {
		return Snapshot{}, fmt.Errorf("snapshot directory %q is not an exact content-addressed name", name)
	}
	if err := requirePrivateDirectory(directory); err != nil {
		return Snapshot{}, fmt.Errorf("validate snapshot directory: %w", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read snapshot directory: %w", err)
	}
	wanted := map[string]bool{manifestFilename: true, advisoriesFilename: true, annotationsFilename: true}
	if len(entries) != len(wanted) {
		return Snapshot{}, fmt.Errorf("snapshot directory has %d entries, want %d", len(entries), len(wanted))
	}
	for _, entry := range entries {
		if !wanted[entry.Name()] {
			return Snapshot{}, fmt.Errorf("snapshot directory contains unexpected entry %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return Snapshot{}, fmt.Errorf("inspect snapshot entry %q: %w", entry.Name(), err)
		}
		if entry.Type()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			return Snapshot{}, fmt.Errorf("snapshot entry %q is not a private regular file", entry.Name())
		}
	}

	manifestBytes, err := readPrivateRegularFile(filepath.Join(directory, manifestFilename), maxManifestBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read snapshot manifest: %w", err)
	}
	var manifest Manifest
	if err := decodeStrictJSON(manifestBytes, &manifest); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot manifest: %w", err)
	}
	advisoryBytes, err := readDeterministicGzip(filepath.Join(directory, advisoriesFilename), maxAdvisoryStreamBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read advisory stream: %w", err)
	}
	annotationBytes, err := readDeterministicGzip(filepath.Join(directory, annotationsFilename), maxAnnotationStreamBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("read impact annotation stream: %w", err)
	}
	advisories, err := decodeAdvisoryJSONL(advisoryBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("decode advisory stream: %w", err)
	}
	annotations, err := decodeAnnotationJSONL(annotationBytes)
	if err != nil {
		return Snapshot{}, fmt.Errorf("decode impact annotation stream: %w", err)
	}
	snapshot := Snapshot{Manifest: manifest, Advisories: advisories, ImpactAnnotations: annotations}
	prepared, err := prepareSnapshot(snapshot, true)
	if err != nil {
		return Snapshot{}, err
	}
	if !bytes.Equal(manifestBytes, prepared.manifest) || !bytes.Equal(advisoryBytes, prepared.advisories) || !bytes.Equal(annotationBytes, prepared.annotations) {
		return Snapshot{}, errors.New("snapshot files are not in canonical form")
	}
	wantDigest := strings.TrimPrefix(name, "sha256-")
	if prepared.snapshot.Manifest.Digest != wantDigest {
		return Snapshot{}, fmt.Errorf("snapshot directory digest %q does not match manifest %q", wantDigest, prepared.snapshot.Manifest.Digest)
	}
	prepared.snapshot.Directory = filepath.Clean(directory)
	prepared.snapshot.Stale = snapshotIsStale(prepared.snapshot.Manifest.RetrievedAt, now)
	return prepared.snapshot, nil
}

func prepareSnapshot(input Snapshot, requireDigest bool) (snapshotEncoding, error) {
	snapshot := canonicalSnapshot(input)
	if err := validateSnapshotFields(snapshot); err != nil {
		return snapshotEncoding{}, err
	}
	annotations, err := canonicalImpactAnnotations(snapshot.ImpactAnnotations)
	if err != nil {
		return snapshotEncoding{}, err
	}
	snapshot.ImpactAnnotations = annotations
	advisories, err := marshalAdvisoryJSONL(snapshot.Advisories)
	if err != nil {
		return snapshotEncoding{}, err
	}
	annotationStream, err := marshalAnnotationJSONL(snapshot.ImpactAnnotations)
	if err != nil {
		return snapshotEncoding{}, err
	}
	catalogSum := sha256.Sum256(annotationStream)
	catalogDigest := hex.EncodeToString(catalogSum[:])
	if snapshot.Manifest.ImpactCatalogDigest != catalogDigest {
		return snapshotEncoding{}, fmt.Errorf("impact catalog digest mismatch: manifest=%q content=%q", snapshot.Manifest.ImpactCatalogDigest, catalogDigest)
	}

	providedDigest := snapshot.Manifest.Digest
	snapshot.Manifest.Digest = ""
	manifestForDigest, err := canonicalJSONLine(snapshot.Manifest)
	if err != nil {
		return snapshotEncoding{}, fmt.Errorf("encode manifest for digest: %w", err)
	}
	hasher := sha256.New()
	_, _ = hasher.Write([]byte("LPECO_VULN_SNAPSHOT_V1\x00"))
	_, _ = hasher.Write(manifestForDigest)
	_, _ = hasher.Write([]byte("\x00ADVISORIES\x00"))
	_, _ = hasher.Write(advisories)
	_, _ = hasher.Write([]byte("\x00ANNOTATIONS\x00"))
	_, _ = hasher.Write(annotationStream)
	digest := hex.EncodeToString(hasher.Sum(nil))
	if requireDigest && providedDigest != digest {
		return snapshotEncoding{}, fmt.Errorf("snapshot content digest mismatch: manifest=%q content=%q", providedDigest, digest)
	}
	snapshot.Manifest.Digest = digest
	manifest, err := canonicalJSONLine(snapshot.Manifest)
	if err != nil {
		return snapshotEncoding{}, fmt.Errorf("encode snapshot manifest: %w", err)
	}
	advisoriesGzip, err := deterministicGzip(advisories)
	if err != nil {
		return snapshotEncoding{}, fmt.Errorf("compress advisory stream: %w", err)
	}
	annotationsGzip, err := deterministicGzip(annotationStream)
	if err != nil {
		return snapshotEncoding{}, fmt.Errorf("compress impact annotation stream: %w", err)
	}
	return snapshotEncoding{
		snapshot: snapshot, manifest: manifest, advisories: advisories, annotations: annotationStream,
		advisoriesGzip: advisoriesGzip, annotationsGzip: annotationsGzip,
	}, nil
}

func canonicalSnapshot(input Snapshot) Snapshot {
	result := input
	result.Directory = ""
	result.Stale = false
	result.Manifest.RetrievedAt = result.Manifest.RetrievedAt.UTC()
	result.Manifest.MaxProviderModifiedAt = result.Manifest.MaxProviderModifiedAt.UTC()
	result.Manifest.SupportedReleases = canonicalStrings(result.Manifest.SupportedReleases)
	result.Manifest.SupportedChannels = canonicalStrings(result.Manifest.SupportedChannels)
	result.Manifest.Sources = append([]Source(nil), result.Manifest.Sources...)
	for index := range result.Manifest.Sources {
		result.Manifest.Sources[index].ProviderModifiedAt = result.Manifest.Sources[index].ProviderModifiedAt.UTC()
	}
	sort.Slice(result.Manifest.Sources, func(i, j int) bool {
		return sourceSortKey(result.Manifest.Sources[i]) < sourceSortKey(result.Manifest.Sources[j])
	})
	result.Advisories = append([]AdvisoryRecord(nil), result.Advisories...)
	for index := range result.Advisories {
		record := &result.Advisories[index]
		record.ModifiedAt = record.ModifiedAt.UTC()
		record.Affected.BinaryPackages = canonicalStrings(record.Affected.BinaryPackages)
		record.Affected.Architectures = canonicalStrings(record.Affected.Architectures)
		if record.Affected.BinaryFixedVersions != nil {
			copy := make(map[string]string, len(record.Affected.BinaryFixedVersions))
			for name, version := range record.Affected.BinaryFixedVersions {
				copy[name] = version
			}
			record.Affected.BinaryFixedVersions = copy
		}
		record.ProviderStatuses = append([]ProviderStatus(nil), record.ProviderStatuses...)
		sort.Slice(record.ProviderStatuses, func(i, j int) bool {
			left, right := record.ProviderStatuses[i], record.ProviderStatuses[j]
			return providerStatusSortKey(left) < providerStatusSortKey(right)
		})
		record.CVEIDs = canonicalStrings(record.CVEIDs)
		record.USNIDs = canonicalStrings(record.USNIDs)
		record.OfficialReferences = canonicalStrings(record.OfficialReferences)
		record.SeverityMetadata = canonicalStrings(record.SeverityMetadata)
		record.Diagnostics = canonicalStrings(record.Diagnostics)
	}
	sort.Slice(result.Advisories, func(i, j int) bool {
		return advisorySortKey(result.Advisories[i]) < advisorySortKey(result.Advisories[j])
	})
	result.ImpactAnnotations = append([]model.ImpactAnnotation(nil), result.ImpactAnnotations...)
	return result
}

func validateSnapshotFields(snapshot Snapshot) error {
	manifest := snapshot.Manifest
	if manifest.SchemaVersion != SnapshotSchemaVersion {
		return fmt.Errorf("unsupported snapshot schema %d", manifest.SchemaVersion)
	}
	if manifest.Provider == "" || manifest.NormalizerVersion == "" || manifest.RetrievedAt.IsZero() {
		return errors.New("snapshot provider, normalizer version, and retrieval time are required")
	}
	if manifest.AdvisoryCount != len(snapshot.Advisories) {
		return fmt.Errorf("advisory count %d does not match %d records", manifest.AdvisoryCount, len(snapshot.Advisories))
	}
	if len(manifest.Sources) == 0 || len(manifest.SupportedReleases) == 0 || len(manifest.SupportedChannels) == 0 || !digestPattern.MatchString(manifest.ImpactCatalogDigest) {
		return errors.New("snapshot source, support scope, or impact catalog digest is incomplete")
	}
	seenSource := make(map[string]bool)
	for index, source := range manifest.Sources {
		parsed, err := url.Parse(source.URL)
		if source.Kind == "" || err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("source %d is incomplete", index)
		}
		key := source.Kind + "\x00" + source.URL
		if seenSource[key] {
			return fmt.Errorf("source %d is duplicated", index)
		}
		seenSource[key] = true
		if source.SHA256 != "" && !digestPattern.MatchString(source.SHA256) {
			return fmt.Errorf("source %d has an invalid checksum", index)
		}
	}
	seenRecord := make(map[string]bool)
	for index, record := range snapshot.Advisories {
		if record.RecordID == "" || record.Provider != manifest.Provider || !strings.HasPrefix(record.VulnerabilityID, "CVE-") ||
			record.Release == "" || record.Channel == "" || record.Affected.SourcePackage == "" {
			return fmt.Errorf("advisory record %d has incomplete identity or package scope", index)
		}
		key := advisorySortKey(record)
		if seenRecord[key] {
			return fmt.Errorf("advisory record %d duplicates normalized key", index)
		}
		seenRecord[key] = true
		for _, status := range record.ProviderStatuses {
			switch status.Status {
			case ProviderStatusAffected, ProviderStatusFixed, ProviderStatusNotAffected, ProviderStatusUnderInvestigation:
			default:
				return fmt.Errorf("advisory record %d has unsupported provider status %q", index, status.Status)
			}
			if status.Source == "" || status.SourcePackage != record.Affected.SourcePackage {
				return fmt.Errorf("advisory record %d has provider status without matching source scope", index)
			}
		}
	}
	return nil
}

func marshalAdvisoryJSONL(records []AdvisoryRecord) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for _, record := range records {
		if err := encoder.Encode(record); err != nil {
			return nil, fmt.Errorf("encode advisory %q: %w", record.RecordID, err)
		}
	}
	return output.Bytes(), nil
}

func canonicalJSONLine(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func deterministicGzip(input []byte) ([]byte, error) {
	var output bytes.Buffer
	writer, err := gzip.NewWriterLevel(&output, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	writer.Header.ModTime = time.Time{}
	writer.Header.Name = ""
	writer.Header.Comment = ""
	writer.Header.Extra = nil
	writer.Header.OS = 255
	if _, err := writer.Write(input); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func publishDirectory(ctx context.Context, root, finalDirectory string, prepared snapshotEncoding) error {
	temporary, err := os.MkdirTemp(root, ".snapshot.tmp-")
	if err != nil {
		return fmt.Errorf("create snapshot temporary directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return fmt.Errorf("restrict snapshot temporary directory: %w", err)
	}
	files := []struct {
		name string
		body []byte
	}{
		{manifestFilename, prepared.manifest},
		{advisoriesFilename, prepared.advisoriesGzip},
		{annotationsFilename, prepared.annotationsGzip},
	}
	for _, file := range files {
		if err := writePrivateFile(ctx, filepath.Join(temporary, file.name), file.body); err != nil {
			return err
		}
	}
	if err := syncDirectory(temporary); err != nil {
		return fmt.Errorf("sync snapshot temporary directory: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(temporary, finalDirectory); err != nil {
		return fmt.Errorf("commit immutable snapshot: %w", err)
	}
	committed = true
	if err := os.Chmod(finalDirectory, 0o700); err != nil {
		return fmt.Errorf("restrict immutable snapshot: %w", err)
	}
	if err := syncDirectory(root); err != nil {
		return fmt.Errorf("sync vulnerability database root: %w", err)
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("directory path is required")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("path is not a directory or is a symlink")
		}
	} else if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
	} else {
		return err
	}
	return os.Chmod(path, 0o700)
}

func requirePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path is not a directory or is a symlink")
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("directory mode is %#o, want 0700", info.Mode().Perm())
	}
	return nil
}

func writePrivateFile(ctx context.Context, path string, body []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict %s: %w", filepath.Base(path), err)
	}
	if _, err := io.Copy(file, &contextReader{ctx: ctx, reader: bytes.NewReader(body)}); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filepath.Base(path), err)
	}
	remove = false
	return nil
}

func writeCanonicalJSONAtomic(ctx context.Context, path string, value any) error {
	body, err := canonicalJSONLine(value)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := io.Copy(temporary, &contextReader{ctx: ctx, reader: bytes.NewReader(body)}); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	return os.Chmod(path, 0o600)
}

func readPrivateRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("path is not a private regular file")
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("file exceeds %d-byte bound", maximum)
	}
	return os.ReadFile(path)
}

func readDeterministicGzip(path string, maximum int64) ([]byte, error) {
	compressed, err := readPrivateRegularFile(path, maxCompressedSnapshotStream)
	if err != nil {
		return nil, err
	}
	readerBytes := bytes.NewReader(compressed)
	reader, err := gzip.NewReader(readerBytes)
	if err != nil {
		return nil, err
	}
	reader.Multistream(false)
	if !reader.Header.ModTime.IsZero() || reader.Header.Name != "" || reader.Header.Comment != "" || len(reader.Header.Extra) != 0 || reader.Header.OS != 255 {
		_ = reader.Close()
		return nil, errors.New("gzip header is not deterministic")
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		_ = reader.Close()
		return nil, err
	}
	if int64(len(decoded)) > maximum {
		_ = reader.Close()
		return nil, fmt.Errorf("uncompressed stream exceeds %d-byte bound", maximum)
	}
	if err := reader.Close(); err != nil {
		return nil, err
	}
	if readerBytes.Len() != 0 {
		return nil, errors.New("gzip stream has trailing or concatenated data")
	}
	return decoded, nil
}

func decodeAdvisoryJSONL(input []byte) ([]AdvisoryRecord, error) {
	if len(input) > 0 && input[len(input)-1] != '\n' {
		return nil, errors.New("advisory JSONL lacks final newline")
	}
	lines := bytes.Split(input, []byte{'\n'})
	if len(lines)-1 > maxSnapshotRecords {
		return nil, errors.New("advisory record count exceeds bound")
	}
	result := make([]AdvisoryRecord, 0, len(lines)-1)
	for index, line := range lines[:len(lines)-1] {
		if len(line) == 0 {
			return nil, fmt.Errorf("advisory JSONL line %d is empty", index+1)
		}
		var record AdvisoryRecord
		if err := decodeStrictJSON(line, &record); err != nil {
			return nil, fmt.Errorf("line %d: %w", index+1, err)
		}
		result = append(result, record)
	}
	if result == nil {
		result = []AdvisoryRecord{}
	}
	return result, nil
}

func decodeAnnotationJSONL(input []byte) ([]model.ImpactAnnotation, error) {
	if len(input) > 0 && input[len(input)-1] != '\n' {
		return nil, errors.New("impact annotation JSONL lacks final newline")
	}
	lines := bytes.Split(input, []byte{'\n'})
	if len(lines)-1 > maxSnapshotRecords {
		return nil, errors.New("impact annotation count exceeds bound")
	}
	result := make([]model.ImpactAnnotation, 0, len(lines)-1)
	for index, line := range lines[:len(lines)-1] {
		if len(line) == 0 {
			return nil, fmt.Errorf("impact annotation JSONL line %d is empty", index+1)
		}
		var annotation model.ImpactAnnotation
		if err := decodeStrictJSON(line, &annotation); err != nil {
			return nil, fmt.Errorf("line %d: %w", index+1, err)
		}
		result = append(result, annotation)
	}
	if result == nil {
		result = []model.ImpactAnnotation{}
	}
	return result, nil
}

func snapshotReference(snapshot Snapshot, now time.Time) model.SnapshotReference {
	return model.SnapshotReference{
		Provider: snapshot.Manifest.Provider, SchemaVersion: snapshot.Manifest.SchemaVersion,
		Digest: snapshot.Manifest.Digest, RetrievedAt: snapshot.Manifest.RetrievedAt,
		ProviderModifiedAt:  snapshot.Manifest.MaxProviderModifiedAt,
		Stale:               snapshotIsStale(snapshot.Manifest.RetrievedAt, now),
		SupportedReleases:   append([]string(nil), snapshot.Manifest.SupportedReleases...),
		SupportedChannels:   append([]string(nil), snapshot.Manifest.SupportedChannels...),
		ImpactCatalogDigest: snapshot.Manifest.ImpactCatalogDigest,
	}
}

func snapshotIsStale(retrievedAt, now time.Time) bool {
	if retrievedAt.IsZero() || now.IsZero() {
		return false
	}
	return !now.UTC().Before(retrievedAt.UTC().Add(SnapshotStaleAfter))
}

func sourceSortKey(source Source) string {
	return source.Kind + "\x00" + source.URL + "\x00" + source.ETag + "\x00" + source.LastModified + "\x00" + source.SHA256 + "\x00" + source.ProviderModifiedAt.Format(time.RFC3339Nano)
}

func advisorySortKey(record AdvisoryRecord) string {
	return record.Release + "\x00" + record.Affected.SourcePackage + "\x00" + record.VulnerabilityID + "\x00" + record.RecordID
}

func providerStatusSortKey(status ProviderStatus) string {
	return status.Source + "\x00" + status.SourcePackage + "\x00" + status.BinaryPackage + "\x00" + status.Architecture + "\x00" + status.Version + "\x00" + status.Status + "\x00" + status.FixedVersion
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
