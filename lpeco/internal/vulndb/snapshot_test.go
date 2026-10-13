package vulndb

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/model"
)

func TestSnapshotPublishIsCanonicalImmutableAndDeterministic(t *testing.T) {
	ctx := context.Background()
	snapshot := snapshotFixture(t)
	firstRoot := filepath.Join(t.TempDir(), "db")
	secondRoot := filepath.Join(t.TempDir(), "db")

	firstReference, err := Publish(ctx, firstRoot, snapshot)
	if err != nil {
		t.Fatalf("Publish(first): %v", err)
	}
	secondReference, err := Publish(ctx, secondRoot, snapshot)
	if err != nil {
		t.Fatalf("Publish(second): %v", err)
	}
	if firstReference.Digest == "" || firstReference.Digest != secondReference.Digest {
		t.Fatalf("non-deterministic digest: first=%q second=%q", firstReference.Digest, secondReference.Digest)
	}

	directoryName := "sha256-" + firstReference.Digest
	firstDirectory := filepath.Join(firstRoot, directoryName)
	secondDirectory := filepath.Join(secondRoot, directoryName)
	for _, directory := range []string{firstRoot, secondRoot, firstDirectory, secondDirectory} {
		assertMode(t, directory, 0o700)
	}
	for _, name := range []string{"manifest.json", "advisories.jsonl.gz", "impact-annotations.jsonl.gz"} {
		firstBytes, err := os.ReadFile(filepath.Join(firstDirectory, name))
		if err != nil {
			t.Fatal(err)
		}
		secondBytes, err := os.ReadFile(filepath.Join(secondDirectory, name))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(firstBytes, secondBytes) {
			t.Errorf("%s differs across publication directories", name)
		}
		assertMode(t, filepath.Join(firstDirectory, name), 0o600)
	}
	assertMode(t, filepath.Join(firstRoot, "current.json"), 0o600)

	loaded, err := LoadCurrent(ctx, firstRoot, snapshot.Manifest.RetrievedAt.Add(time.Hour))
	if err != nil {
		t.Fatalf("LoadCurrent: %v", err)
	}
	if loaded.Manifest.Digest != firstReference.Digest || loaded.Directory != firstDirectory {
		t.Fatalf("loaded snapshot identity = %#v", loaded)
	}
	if got := advisorySortKeys(loaded.Advisories); !reflect.DeepEqual(got, []string{
		"22.04\x00glibc\x00CVE-2023-4911\x00record-a",
		"24.04\x00xz-utils\x00CVE-2024-0001\x00record-b",
	}) {
		t.Fatalf("advisories are not canonical: %#v", got)
	}

	updated := snapshotFixture(t)
	updated.Advisories = append(updated.Advisories, AdvisoryRecord{
		RecordID: "record-c", Provider: "ubuntu", VulnerabilityID: "CVE-2025-0002", Release: "26.04", Codename: "resolute", Channel: "standard",
		Affected: AffectedPackage{SourcePackage: "demo", BinaryPackages: []string{"demo"}},
	})
	updated.Manifest.AdvisoryCount = len(updated.Advisories)
	updatedReference, err := Publish(ctx, firstRoot, updated)
	if err != nil {
		t.Fatalf("Publish(updated): %v", err)
	}
	if updatedReference.Digest == firstReference.Digest {
		t.Fatal("changed semantic content retained the old digest")
	}
	if _, err := os.Stat(firstDirectory); err != nil {
		t.Fatalf("old immutable snapshot was removed: %v", err)
	}
	current, err := LoadCurrent(ctx, firstRoot, updated.Manifest.RetrievedAt)
	if err != nil || current.Manifest.Digest != updatedReference.Digest {
		t.Fatalf("current pointer did not atomically advance: snapshot=%#v err=%v", current, err)
	}
	entries, err := os.ReadDir(firstRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("publication left temporary entry %q", entry.Name())
		}
	}
}

func TestSnapshotStaleAtSevenDayBoundary(t *testing.T) {
	ctx := context.Background()
	snapshot := snapshotFixture(t)
	root := filepath.Join(t.TempDir(), "db")
	reference, err := Publish(ctx, root, snapshot)
	if err != nil {
		t.Fatal(err)
	}

	fresh, err := LoadDigest(ctx, root, reference.Digest, snapshot.Manifest.RetrievedAt.Add(7*24*time.Hour-time.Nanosecond))
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Stale {
		t.Fatal("snapshot became stale before seven days")
	}
	stale, err := LoadDigest(ctx, root, reference.Digest, snapshot.Manifest.RetrievedAt.Add(7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !stale.Stale {
		t.Fatal("snapshot was not stale at exactly seven days")
	}
}

func TestSnapshotValidationRejectsTamperingAndFutureSchema(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "db")
	reference, err := Publish(ctx, root, snapshotFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDigest(ctx, root, reference.Digest, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	mutations := []struct {
		name   string
		mutate func(*Snapshot)
	}{
		{name: "future schema", mutate: func(value *Snapshot) { value.Manifest.SchemaVersion = SnapshotSchemaVersion + 1 }},
		{name: "count mismatch", mutate: func(value *Snapshot) { value.Manifest.AdvisoryCount++ }},
		{name: "content checksum", mutate: func(value *Snapshot) { value.Manifest.Digest = strings.Repeat("0", 64) }},
		{name: "catalog checksum", mutate: func(value *Snapshot) { value.Manifest.ImpactCatalogDigest = strings.Repeat("1", 64) }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			copy := cloneSnapshot(t, loaded)
			mutation.mutate(&copy)
			if err := Validate(copy); err == nil {
				t.Fatalf("Validate accepted %s", mutation.name)
			}
		})
	}

	directory := filepath.Join(root, "sha256-"+reference.Digest)
	advisoryPath := filepath.Join(directory, "advisories.jsonl.gz")
	body, err := os.ReadFile(advisoryPath)
	if err != nil {
		t.Fatal(err)
	}
	body[len(body)/2] ^= 0xff
	if err := os.WriteFile(advisoryPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDirectory(ctx, directory, time.Now().UTC()); err == nil {
		t.Fatal("LoadDirectory accepted corrupted gzip/checksum content")
	}
}

func TestSnapshotLoadRejectsSymlinksAndArbitraryDirectory(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "db")
	reference, err := Publish(ctx, root, snapshotFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	realDirectory := filepath.Join(root, "sha256-"+reference.Digest)
	linkRoot := filepath.Join(t.TempDir(), "links")
	if err := os.Mkdir(linkRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(linkRoot, "sha256-"+reference.Digest)
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDirectory(ctx, linkedDirectory, time.Now().UTC()); err == nil {
		t.Fatal("LoadDirectory followed a snapshot-directory symlink")
	}
	if _, err := LoadDirectory(ctx, root, time.Now().UTC()); err == nil {
		t.Fatal("LoadDirectory accepted an arbitrary database root")
	}
}

func TestSnapshotFailedPublicationPreservesCurrentPointer(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "db")
	if _, err := Publish(ctx, root, snapshotFixture(t)); err != nil {
		t.Fatal(err)
	}
	pointerPath := filepath.Join(root, "current.json")
	before, err := os.ReadFile(pointerPath)
	if err != nil {
		t.Fatal(err)
	}

	invalid := snapshotFixture(t)
	invalid.Manifest.SchemaVersion = SnapshotSchemaVersion + 1
	if _, err := Publish(ctx, root, invalid); err == nil {
		t.Fatal("Publish accepted a future-schema snapshot")
	}
	after, err := os.ReadFile(pointerPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed publication changed current.json")
	}
}

func snapshotFixture(t *testing.T) Snapshot {
	t.Helper()
	annotations, digest, err := LoadImpactCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return Snapshot{
		Manifest: Manifest{
			SchemaVersion: SnapshotSchemaVersion, Provider: "ubuntu",
			Sources: []Source{
				{Kind: "vex", URL: "https://security-metadata.canonical.com/vex/vex-all.tar.xz", ETag: "vex-tag"},
				{Kind: "osv", URL: "https://security-metadata.canonical.com/osv/osv-all.tar.xz", ETag: "osv-tag"},
			},
			RetrievedAt:           time.Date(2026, 10, 14, 2, 3, 4, 0, time.FixedZone("fixture", 9*60*60)),
			MaxProviderModifiedAt: time.Date(2026, 10, 13, 20, 0, 0, 0, time.UTC),
			NormalizerVersion:     "ubuntu-v1", AdvisoryCount: 2,
			SupportedReleases: []string{"24.04", "22.04", "26.04"},
			SupportedChannels: []string{"standard"}, ImpactCatalogDigest: digest,
		},
		Advisories: []AdvisoryRecord{
			{
				RecordID: "record-b", Provider: "ubuntu", VulnerabilityID: "CVE-2024-0001", Release: "24.04", Codename: "noble", Channel: "standard",
				Affected: AffectedPackage{SourcePackage: "xz-utils", BinaryPackages: []string{"xz-utils", "liblzma5"}, Architectures: []string{"amd64"}, FixedVersion: "5.6.1-1"},
				CVEIDs:   []string{"CVE-2024-0001"}, OfficialReferences: []string{"https://ubuntu.com/security/CVE-2024-0001"},
			},
			{
				RecordID: "record-a", Provider: "ubuntu", VulnerabilityID: "CVE-2023-4911", Release: "22.04", Codename: "jammy", Channel: "standard",
				Affected:         AffectedPackage{SourcePackage: "glibc", BinaryPackages: []string{"libc6"}, Architectures: []string{"amd64", "arm64"}, FixedVersion: "2.35-0ubuntu3.4"},
				ProviderStatuses: []ProviderStatus{{Source: "vex", Status: "fixed", SourcePackage: "glibc", FixedVersion: "2.35-0ubuntu3.4"}},
				CVEIDs:           []string{"CVE-2023-4911"}, USNIDs: []string{"USN-6409-1"},
				OfficialReferences: []string{"https://ubuntu.com/security/notices/USN-6409-1", "https://ubuntu.com/security/CVE-2023-4911"},
			},
		},
		ImpactAnnotations: annotations,
	}
}

func advisorySortKeys(values []AdvisoryRecord) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.Release+"\x00"+value.Affected.SourcePackage+"\x00"+value.VulnerabilityID+"\x00"+value.RecordID)
	}
	return result
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %#o, want %#o", path, got, want)
	}
}

func cloneSnapshot(t *testing.T, value Snapshot) Snapshot {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var copy Snapshot
	if err := json.Unmarshal(encoded, &copy); err != nil {
		t.Fatal(err)
	}
	copy.Directory = value.Directory
	copy.Stale = value.Stale
	return copy
}

func TestSnapshotReferenceCarriesPinnedMetadata(t *testing.T) {
	root := filepath.Join(t.TempDir(), "db")
	snapshot := snapshotFixture(t)
	reference, err := Publish(context.Background(), root, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	want := model.SnapshotReference{
		Provider: "ubuntu", SchemaVersion: SnapshotSchemaVersion, Digest: reference.Digest,
		RetrievedAt: snapshot.Manifest.RetrievedAt.UTC(), ProviderModifiedAt: snapshot.Manifest.MaxProviderModifiedAt.UTC(),
		SupportedReleases: []string{"22.04", "24.04", "26.04"}, SupportedChannels: []string{"standard"},
		ImpactCatalogDigest: snapshot.Manifest.ImpactCatalogDigest,
	}
	if !reflect.DeepEqual(reference, want) {
		t.Fatalf("reference = %#v, want %#v", reference, want)
	}
}
