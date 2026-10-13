package packageinfo

import (
	"encoding/hex"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/normalone/lpeco/internal/model"
)

func TestParseOwnershipStates(t *testing.T) {
	tests := []struct {
		name          string
		frame         string
		wantManager   string
		wantPackages  []string
		wantOwned     bool
		wantAmbiguous bool
		wantMissing   string
	}{
		{
			name: "single dpkg owner across usr merge",
			frame: ownershipFrame("/bin/demo", "/usr/bin/demo", "dpkg",
				query("observed", 0, "demo:amd64: /bin/demo\n")+query("resolved", 0, "demo:amd64: /usr/bin/demo\n")),
			wantManager: "dpkg", wantPackages: []string{"demo:amd64"}, wantOwned: true,
		},
		{
			name: "multiple owners are ambiguous",
			frame: ownershipFrame("/opt/shared", "/opt/shared", "dpkg",
				query("observed", 0, "alpha: /opt/shared\nbeta:amd64: /opt/shared\n")),
			wantManager: "dpkg", wantPackages: []string{"alpha", "beta:amd64"}, wantOwned: true, wantAmbiguous: true,
			wantMissing: "package ownership is ambiguous",
		},
		{
			name: "observed and resolved owners conflict",
			frame: ownershipFrame("/lib/demo.so", "/usr/lib/demo.so", "dpkg",
				query("observed", 0, "old:amd64: /lib/demo.so\n")+query("resolved", 0, "new:amd64: /usr/lib/demo.so\n")),
			wantManager: "dpkg", wantPackages: []string{"new:amd64", "old:amd64"}, wantOwned: true, wantAmbiguous: true,
			wantMissing: "observed and resolved ownership conflict",
		},
		{
			name:        "no owner remains explicit",
			frame:       ownershipFrame("/opt/unowned", "/opt/unowned", "dpkg", query("observed", 1, "")),
			wantManager: "dpkg", wantMissing: "package ownership not confirmed",
		},
		{
			name:        "rpm ownership is retained but unsupported",
			frame:       ownershipFrame("/usr/bin/rpm-demo", "/usr/bin/rpm-demo", "rpm", query("observed", 0, "rpm-demo-1.0-1.x86_64\n")),
			wantManager: "rpm", wantPackages: []string{"rpm-demo-1.0-1.x86_64"}, wantOwned: true,
			wantMissing: "package manager rpm is unsupported for Ubuntu matching",
		},
		{
			name:        "apk ownership is retained but unsupported",
			frame:       ownershipFrame("/usr/bin/apk-demo", "/usr/bin/apk-demo", "apk", query("observed", 0, "/usr/bin/apk-demo is owned by apk-demo-1.0-r0\n")),
			wantManager: "apk", wantPackages: []string{"apk-demo-1.0-r0"}, wantOwned: true,
			wantMissing: "package manager apk is unsupported for Ubuntu matching",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts, diagnostics := ParseOwnership([]byte(test.frame), "e-owner")
			if len(diagnostics) != 0 {
				t.Fatalf("diagnostics = %#v", diagnostics)
			}
			if len(facts) != 1 {
				t.Fatalf("facts = %#v", facts)
			}
			got := facts[0]
			if got.Manager != test.wantManager || got.Owned != test.wantOwned || got.Ambiguous != test.wantAmbiguous || !reflect.DeepEqual(got.Packages, test.wantPackages) {
				t.Fatalf("ownership = %#v", got)
			}
			if test.wantMissing != "" && !slices.Contains(got.MissingFacts, test.wantMissing) {
				t.Fatalf("missing facts = %#v, want %q", got.MissingFacts, test.wantMissing)
			}
		})
	}
}

func TestParseOwnershipRejectsMalformedTruncatedAndDuplicateRecords(t *testing.T) {
	frames := []string{
		"not-a-package-frame\n",
		"LPECO_PACKAGE_OWNERSHIP_V1\nBEGIN\t" + hx("/opt/demo") + "\t" + hx("/opt/demo") + "\tdpkg\n" + query("observed", 0, "demo: /opt/demo\n"),
		ownershipFrame("/opt/demo", "/opt/demo", "dpkg", query("observed", 0, "demo: /opt/demo\n")) + strings.TrimPrefix(ownershipFrame("/opt/demo", "/opt/demo", "dpkg", query("observed", 0, "demo: /opt/demo\n")), "LPECO_PACKAGE_OWNERSHIP_V1\n"),
		"LPECO_PACKAGE_OWNERSHIP_V1\nBEGIN\tzz\t" + hx("/opt/demo") + "\tdpkg\nEND\n",
	}
	for index, frame := range frames {
		facts, diagnostics := ParseOwnership([]byte(frame), "e-malformed")
		if len(diagnostics) == 0 && !ownershipHasMissing(facts) {
			t.Fatalf("case %d accepted malformed frame: facts=%#v diagnostics=%#v", index, facts, diagnostics)
		}
	}
}

func TestParseInstalledPackageMetadata(t *testing.T) {
	installedPayload := "install ok installed\tlibc6:amd64\tamd64\t2.35-0ubuntu3.4\tglibc\t2.35-0ubuntu3.4"
	uninstalledPayload := "deinstall ok config-files\toldpkg:amd64\tamd64\t1:2.0-1\toldsrc\t1:2.0-1"
	missingSourcePayload := "install ok installed\tdemo:amd64\tamd64\t1.0-1\t\t"
	frame := "LPECO_PACKAGE_METADATA_V1\n" +
		metadataRecord("libc6:amd64", "dpkg", 0, installedPayload) +
		metadataRecord("oldpkg:amd64", "dpkg", 0, uninstalledPayload) +
		metadataRecord("demo:amd64", "dpkg", 0, missingSourcePayload)

	facts, diagnostics := ParseMetadata([]byte(frame), "e-metadata")
	if len(diagnostics) != 0 || len(facts) != 3 {
		t.Fatalf("metadata facts=%#v diagnostics=%#v", facts, diagnostics)
	}
	installed := facts[0]
	if installed.Status != "install ok installed" || installed.BinaryPackage != "libc6" || installed.Architecture != "amd64" || installed.BinaryVersion.Raw != "2.35-0ubuntu3.4" || installed.BinaryVersion.Valid || installed.SourcePackage != "glibc" || installed.SourceVersion.Raw != "2.35-0ubuntu3.4" {
		t.Fatalf("installed metadata = %#v", installed)
	}
	if facts[1].Status != "deinstall ok config-files" {
		t.Fatalf("uninstalled metadata = %#v", facts[1])
	}
	if !slices.Contains(facts[2].MissingFacts, "source package metadata is missing") {
		t.Fatalf("missing source metadata = %#v", facts[2])
	}
}

func TestParseMetadataKeepsFailuresAndDuplicatesIncomplete(t *testing.T) {
	good := "install ok installed\tdemo:amd64\tamd64\t1.0-1\tdemo\t1.0-1"
	frame := "LPECO_PACKAGE_METADATA_V1\n" +
		metadataRecord("denied:amd64", "dpkg", 13, "") +
		metadataRecord("demo:amd64", "dpkg", 0, good) +
		metadataRecord("demo:amd64", "dpkg", 0, good) +
		"RECORD\tzz\tdpkg\t0\t" + hx(good) + "\n"
	facts, diagnostics := ParseMetadata([]byte(frame), "e-metadata")
	if len(diagnostics) == 0 || len(facts) != 2 {
		t.Fatalf("facts=%#v diagnostics=%#v", facts, diagnostics)
	}
	for _, fact := range facts {
		if fact.Confidence == model.ConfidenceHigh || len(fact.MissingFacts) == 0 {
			t.Fatalf("failure/duplicate became complete: %#v", fact)
		}
	}
}

func ownershipHasMissing(values []OwnershipFact) bool {
	for _, value := range values {
		if len(value.MissingFacts) > 0 {
			return true
		}
	}
	return false
}

func ownershipFrame(observed, resolved, manager, queries string) string {
	return "LPECO_PACKAGE_OWNERSHIP_V1\nBEGIN\t" + hx(observed) + "\t" + hx(resolved) + "\t" + manager + "\n" + queries + "END\n"
}

func query(kind string, status int, output string) string {
	return "QUERY\t" + kind + "\t" + strconv.Itoa(status) + "\t" + hx(output) + "\n"
}

func metadataRecord(request, manager string, status int, payload string) string {
	return "RECORD\t" + hx(request) + "\t" + manager + "\t" + strconv.Itoa(status) + "\t" + hx(payload) + "\n"
}

func hx(value string) string { return hex.EncodeToString([]byte(value)) }
