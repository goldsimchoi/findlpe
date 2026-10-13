package vulndb

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestNormalizeUbuntuCVE4911Shape(t *testing.T) {
	normalizer := newTestUbuntuNormalizer(t)
	addOSVFixture(t, normalizer, "osv/cve/2023/UBUNTU-CVE-2023-4911.json", "cve-2023-4911.json")
	snapshot, err := normalizer.Snapshot(testRetrievedAt(), testSources())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Advisories) != 1 {
		t.Fatalf("advisories = %#v", snapshot.Advisories)
	}
	record := snapshot.Advisories[0]
	if record.Provider != "ubuntu" || record.VulnerabilityID != "CVE-2023-4911" || record.Release != "22.04" || record.Codename != "jammy" || record.Channel != "standard" {
		t.Fatalf("record identity = %#v", record)
	}
	if record.Affected.SourcePackage != "glibc" || record.Affected.IntroducedVersion != "0" || record.Affected.FixedVersion != "2.35-0ubuntu3.4" ||
		!reflect.DeepEqual(record.Affected.BinaryPackages, []string{"libc-bin", "libc6"}) || record.Affected.BinaryFixedVersions["libc6"] != "2.35-0ubuntu3.4" {
		t.Fatalf("affected package = %#v", record.Affected)
	}
	if !reflect.DeepEqual(record.CVEIDs, []string{"CVE-2023-4911"}) || !reflect.DeepEqual(record.USNIDs, []string{"USN-6409-1"}) ||
		!reflect.DeepEqual(record.OfficialReferences, []string{"https://ubuntu.com/security/CVE-2023-4911", "https://ubuntu.com/security/notices/USN-6409-1"}) {
		t.Fatalf("official identity/reference fields = %#v", record)
	}
	if !slices.Contains(record.SeverityMetadata, "Ubuntu=high") || len(record.ProviderStatuses) != 0 {
		t.Fatalf("severity/status = %#v / %#v", record.SeverityMetadata, record.ProviderStatuses)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("SANITIZED-PROSE-MUST-NOT-BE-NORMALIZED")) || bytes.Contains(encoded, []byte(`"state":"affected"`)) {
		t.Fatalf("normalizer copied prose or inferred installed state: %s", encoded)
	}
}

func TestNormalizeUbuntuStatusesUnsupportedScopeAndConflict(t *testing.T) {
	normalizer := newTestUbuntuNormalizer(t)
	addOSVFixture(t, normalizer, "osv/cve/2025/UBUNTU-CVE-2025-0001.json", "states-osv.json")
	addVEXFixture(t, normalizer, "vex/cve/2025/CVE-2025-0001.json", "states-vex.json")
	snapshot, err := normalizer.Snapshot(testRetrievedAt(), testSources())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Advisories) != 7 {
		t.Fatalf("advisory count = %d, records=%#v", len(snapshot.Advisories), snapshot.Advisories)
	}
	bySource := make(map[string]AdvisoryRecord)
	for _, record := range snapshot.Advisories {
		bySource[record.Affected.SourcePackage] = record
	}
	for source, status := range map[string]string{
		"open-aff": ProviderStatusAffected, "not-aff": ProviderStatusNotAffected,
		"investigate": ProviderStatusUnderInvestigation, "fixedpkg": ProviderStatusFixed,
	} {
		if !slices.Contains(providerStatusNames(bySource[source].ProviderStatuses), status) {
			t.Errorf("%s statuses = %#v, want %q", source, bySource[source].ProviderStatuses, status)
		}
	}
	openStatuses := bySource["open-aff"].ProviderStatuses
	if !hasProviderScope(openStatuses, "open-aff-bin", "amd64", "1.0-1") {
		t.Fatalf("binary architecture/version scope lost: %#v", openStatuses)
	}
	conflict := bySource["conflict"]
	if !slices.Contains(providerStatusNames(conflict.ProviderStatuses), ProviderStatusAffected) || !slices.Contains(providerStatusNames(conflict.ProviderStatuses), ProviderStatusFixed) || !slices.Contains(conflict.Diagnostics, "provider-status-conflict") {
		t.Fatalf("conflicting status not preserved explicitly: %#v", conflict)
	}
	if pro := bySource["pro-pkg"]; pro.Channel != "pro" || !slices.Contains(pro.Diagnostics, "unsupported-channel: pro") {
		t.Fatalf("Pro-only record was dropped or promoted: %#v", pro)
	}
	if eol := bySource["eol-pkg"]; eol.Channel != "unsupported" || !slices.Contains(eol.Diagnostics, "unsupported-release: 20.04") {
		t.Fatalf("unreviewed release was dropped or promoted: %#v", eol)
	}
	if !reflect.DeepEqual(snapshot.Manifest.SupportedChannels, []string{"standard"}) || !reflect.DeepEqual(snapshot.Manifest.SupportedReleases, []string{"22.04", "24.04", "26.04"}) {
		t.Fatalf("unsupported scope leaked into manifest coverage: %#v", snapshot.Manifest)
	}
	encoded, _ := json.Marshal(snapshot)
	if bytes.Contains(encoded, []byte("PROSE-MUST-NOT-BE-NORMALIZED")) || bytes.Contains(encoded, []byte("STATE-FIXTURE-PROSE")) || bytes.Contains(encoded, []byte("VEX-PROSE")) {
		t.Fatalf("normalized snapshot copied advisory prose: %s", encoded)
	}
}

func TestNormalizeUbuntuWithdrawnRecordIsRetained(t *testing.T) {
	body := strings.Replace(readUbuntuFixture(t, "order-osv.json"), `"modified": "2026-10-11T00:00:00Z",`, `"modified": "2026-10-11T00:00:00Z", "withdrawn": "2026-10-12T00:00:00Z",`, 1)
	normalizer := newTestUbuntuNormalizer(t)
	if err := normalizer.AddOSV("osv/cve/2025/withdrawn.json", strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := normalizer.Snapshot(testRetrievedAt(), testSources())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Advisories) != 1 || !snapshot.Advisories[0].Withdrawn {
		t.Fatalf("withdrawn record not retained: %#v", snapshot.Advisories)
	}
}

func TestNormalizeUbuntuRejectsMalformedDuplicateUnknownAndOversizedRecords(t *testing.T) {
	t.Run("malformed purl", func(t *testing.T) {
		normalizer := newTestUbuntuNormalizer(t)
		if err := normalizer.AddOSV("osv/cve/2025/malformed.json", strings.NewReader(readUbuntuFixture(t, "malformed-purl.json"))); err == nil {
			t.Fatal("malformed Ubuntu deb PURL was accepted")
		}
	})
	t.Run("duplicate normalized record", func(t *testing.T) {
		normalizer := newTestUbuntuNormalizer(t)
		body := readUbuntuFixture(t, "order-osv.json")
		if err := normalizer.AddOSV("osv/cve/2025/one.json", strings.NewReader(body)); err != nil {
			t.Fatal(err)
		}
		if err := normalizer.AddOSV("osv/cve/2025/two.json", strings.NewReader(body)); err == nil {
			t.Fatal("duplicate normalized key was accepted")
		}
	})
	t.Run("unknown OSV schema", func(t *testing.T) {
		normalizer := newTestUbuntuNormalizer(t)
		if err := normalizer.AddOSV("osv/cve/2025/future.json", strings.NewReader(`{"schema_version":"9.0.0","id":"UBUNTU-CVE-2025-0004"}`)); err == nil {
			t.Fatal("future OSV schema was accepted")
		}
	})
	t.Run("unknown VEX context", func(t *testing.T) {
		normalizer := newTestUbuntuNormalizer(t)
		if err := normalizer.AddVEX("vex/cve/2025/future.json", strings.NewReader(`{"@context":"https://openvex.dev/ns/v9.0.0","statements":[]}`)); err == nil {
			t.Fatal("future VEX context was accepted")
		}
	})
	t.Run("oversized record", func(t *testing.T) {
		normalizer := newTestUbuntuNormalizer(t)
		body := strings.NewReader(strings.Repeat("x", MaxProviderRecordBytes+1))
		if err := normalizer.AddOSV("osv/cve/2025/oversized.json", body); err == nil {
			t.Fatal("oversized provider record was accepted")
		}
	})
}

func TestNormalizeUbuntuOrderIsDeterministic(t *testing.T) {
	left := newTestUbuntuNormalizer(t)
	addOSVFixture(t, left, "osv/cve/2025/z.json", "order-osv.json")
	addOSVFixture(t, left, "osv/cve/2023/a.json", "cve-2023-4911.json")
	right := newTestUbuntuNormalizer(t)
	addOSVFixture(t, right, "osv/cve/2023/a.json", "cve-2023-4911.json")
	addOSVFixture(t, right, "osv/cve/2025/z.json", "order-osv.json")

	leftSnapshot, err := left.Snapshot(testRetrievedAt(), testSources())
	if err != nil {
		t.Fatal(err)
	}
	rightSnapshot, err := right.Snapshot(testRetrievedAt(), testSources())
	if err != nil {
		t.Fatal(err)
	}
	leftJSON, _ := json.Marshal(leftSnapshot)
	rightJSON, _ := json.Marshal(rightSnapshot)
	if !bytes.Equal(leftJSON, rightJSON) || leftSnapshot.Manifest.Digest != rightSnapshot.Manifest.Digest {
		t.Fatalf("input order changed normalized snapshot\nleft:  %s\nright: %s", leftJSON, rightJSON)
	}
	if got := advisorySortKeys(leftSnapshot.Advisories); !slices.IsSorted(got) {
		t.Fatalf("records are not sorted by normalized key: %#v", got)
	}
}

func newTestUbuntuNormalizer(t *testing.T) *UbuntuNormalizer {
	t.Helper()
	policy, err := LoadUbuntuReleasePolicy()
	if err != nil {
		t.Fatal(err)
	}
	annotations, _, err := LoadImpactCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return NewUbuntuNormalizer(policy, annotations)
}

func addOSVFixture(t *testing.T, normalizer *UbuntuNormalizer, entry, name string) {
	t.Helper()
	if err := normalizer.AddOSV(entry, strings.NewReader(readUbuntuFixture(t, name))); err != nil {
		t.Fatalf("AddOSV(%s): %v", name, err)
	}
}

func addVEXFixture(t *testing.T, normalizer *UbuntuNormalizer, entry, name string) {
	t.Helper()
	if err := normalizer.AddVEX(entry, strings.NewReader(readUbuntuFixture(t, name))); err != nil {
		t.Fatalf("AddVEX(%s): %v", name, err)
	}
}

func readUbuntuFixture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "ubuntu", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func testRetrievedAt() time.Time {
	return time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
}

func testSources() []Source {
	return []Source{
		{Kind: "osv", URL: "https://security-metadata.canonical.com/osv/osv-all.tar.xz"},
		{Kind: "vex", URL: "https://security-metadata.canonical.com/vex/vex-all.tar.xz"},
	}
}

func providerStatusNames(values []ProviderStatus) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !slices.Contains(result, value.Status) {
			result = append(result, value.Status)
		}
	}
	return result
}

func hasProviderScope(values []ProviderStatus, binary, architecture, version string) bool {
	for _, value := range values {
		if value.BinaryPackage == binary && value.Architecture == architecture && value.Version == version {
			return true
		}
	}
	return false
}
