package vulndb

import (
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/model"
)

func TestCatalogContainsOnlyReviewedImpactAnnotations(t *testing.T) {
	annotations, digest, err := LoadImpactCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(digest) {
		t.Fatalf("catalog digest = %q", digest)
	}
	if len(annotations) == 0 {
		t.Fatal("impact catalog is empty")
	}
	seen := make(map[string]bool)
	for _, annotation := range annotations {
		if seen[annotation.ID] {
			t.Fatalf("duplicate annotation ID %q", annotation.ID)
		}
		seen[annotation.ID] = true
		if annotation.SchemaVersion != 1 || annotation.Provider != "ubuntu" {
			t.Fatalf("unreviewed schema/provider in %#v", annotation)
		}
		for _, reference := range annotation.OfficialReferences {
			parsed, err := url.Parse(reference)
			if err != nil || parsed.Scheme != "https" || parsed.Host != "ubuntu.com" || !strings.HasPrefix(parsed.Path, "/security/") {
				t.Fatalf("non-official annotation reference %q", reference)
			}
		}
	}

	var loader *model.ImpactAnnotation
	for index := range annotations {
		if annotations[index].ID == "ubuntu-cve-2023-4911-suid-loader-v1" {
			loader = &annotations[index]
			break
		}
	}
	if loader == nil {
		t.Fatal("reviewed CVE-2023-4911 annotation is absent")
	}
	if loader.VulnerabilityID != "CVE-2023-4911" || !reflect.DeepEqual(loader.SourcePackages, []string{"glibc"}) || !reflect.DeepEqual(loader.BinaryPackages, []string{"libc6"}) ||
		!reflect.DeepEqual(loader.AffectedUse, []model.EdgeKind{model.EdgeLoads}) || !reflect.DeepEqual(loader.Reachability, []model.EdgeKind{model.EdgeCanExecute}) ||
		loader.TargetConstraint != "different-principal" {
		t.Fatalf("CVE-2023-4911 annotation scope = %#v", loader)
	}
	wantReferences := []string{
		"https://ubuntu.com/security/CVE-2023-4911",
		"https://ubuntu.com/security/notices/USN-6409-1",
	}
	if !reflect.DeepEqual(loader.OfficialReferences, wantReferences) {
		t.Fatalf("annotation references = %#v", loader.OfficialReferences)
	}

	lower := strings.ToLower(string(impactCatalogJSON))
	for _, forbidden := range []string{"\"command\"", "\"payload\"", "proof_of_concept", "\"poc\"", "qualys.com", "cisa.gov", "exploit-db", "github.com"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("catalog contains forbidden field/domain %q", forbidden)
		}
	}
}

func TestCatalogUbuntuReleasePolicyIsNarrowAndReviewed(t *testing.T) {
	policy, err := LoadUbuntuReleasePolicy()
	if err != nil {
		t.Fatal(err)
	}
	if policy.SchemaVersion != 1 || policy.Provider != "ubuntu" || !policy.ReviewedAt.Equal(time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("release policy metadata = %#v", policy)
	}
	want := []UbuntuRelease{
		{VersionID: "22.04", Codename: "jammy", Channel: "standard"},
		{VersionID: "24.04", Codename: "noble", Channel: "standard"},
		{VersionID: "26.04", Codename: "resolute", Channel: "standard"},
	}
	if !reflect.DeepEqual(policy.Releases, want) {
		t.Fatalf("reviewed releases = %#v, want %#v", policy.Releases, want)
	}
	encoded := strings.ToLower(string(releasePolicyJSON))
	for _, forbidden := range []string{"\"channel\":\"esm\"", "\"channel\":\"pro\"", "fips", "realtime", "livepatch", "26.10"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("release policy includes unsupported scope %q", forbidden)
		}
	}
}
