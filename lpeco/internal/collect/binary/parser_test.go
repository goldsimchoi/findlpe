package binary

import (
	"os"
	"reflect"
	"strings"
	"testing"

	pathcollect "github.com/normalone/lpeco/internal/collect/path"
	"github.com/normalone/lpeco/internal/model"
)

func TestParseReadableSudoersAndNonInteractiveList(t *testing.T) {
	facts := ParseSudoers("/etc/sudoers", readBinaryFixture(t, "../../../testdata/fallback/sudo/sudoers"), "e-sudoers")
	if len(facts) != 2 || facts[0].Subject != "alice" || facts[0].RunAs != "root" || !facts[0].NoPassword || facts[0].Command != "/usr/bin/systemctl restart demo.service" {
		t.Fatalf("sudoers facts = %#v", facts)
	}
	if facts[1].Subject != "%ops" || facts[1].RunAs != "backup" || facts[1].NoPassword {
		t.Fatalf("group sudoers fact = %#v", facts[1])
	}
	listed := ParseSudoList(readBinaryFixture(t, "../../../testdata/fallback/sudo/list.txt"), "e-sudo-list")
	if len(listed) != 1 || listed[0].SourceKind != "sudo-list" || !listed[0].NoPassword {
		t.Fatalf("sudo list facts = %#v", listed)
	}

	definition := SudoListDefinition()
	if definition.SafetyClass != model.ObservableRead {
		t.Fatalf("sudo list safety = %s", definition.SafetyClass)
	}
	script := definition.Variants[0].Command.Script
	if !strings.Contains(script, "sudo -n -l") || strings.Contains(script, " -S") || strings.Contains(strings.ToLower(script), "password") {
		t.Fatalf("sudo list command can prompt or submit credentials: %q", script)
	}
	if SudoersDefinition().SafetyClass != model.PassiveRead {
		t.Fatal("readable sudoers probe is not passive")
	}
}

func TestParsePrivilegedFilesCapabilitiesAndELFDependencies(t *testing.T) {
	files, diagnostics := ParsePrivilegedInventory(readBinaryFixture(t, "../../../testdata/fallback/suid/inventory.txt"), "e-priv")
	if len(diagnostics) != 0 || len(files) != 3 {
		t.Fatalf("privileged inventory = %#v, %#v", files, diagnostics)
	}
	helper := privilegedByPath(t, files, "/usr/local/bin/helper")
	groupTool := privilegedByPath(t, files, "/usr/local/bin/grouptool")
	capped := privilegedByPath(t, files, "/usr/local/bin/capped")
	if !helper.SUID || helper.SGID {
		t.Fatalf("SUID fact = %#v", helper)
	}
	if !groupTool.SGID || !reflect.DeepEqual(capped.Capabilities, []string{"cap_setuid=ep", "cap_net_bind_service=eip"}) {
		t.Fatalf("SGID/capability facts = %#v", files)
	}

	dependencies, diagnostics := ParseELF("/usr/local/bin/helper", readBinaryFixture(t, "../../../testdata/fallback/elf/readelf.txt"), "e-elf")
	if len(diagnostics) != 0 {
		t.Fatalf("ELF diagnostics = %#v", diagnostics)
	}
	wantKinds := map[string]bool{"interpreter": false, "needed": false, "rpath": false, "runpath": false, "script": false}
	for _, dependency := range dependencies {
		wantKinds[dependency.Kind] = true
		if len(dependency.EvidenceIDs) == 0 {
			t.Fatalf("dependency lacks evidence: %#v", dependency)
		}
	}
	for kind, found := range wantKinds {
		if !found {
			t.Fatalf("dependency kind %q missing: %#v", kind, dependencies)
		}
	}
}

func privilegedByPath(t *testing.T, values []PrivilegedBinaryFact, path string) PrivilegedBinaryFact {
	t.Helper()
	for _, value := range values {
		if value.Path == path {
			return value
		}
	}
	t.Fatalf("privileged binary %q missing", path)
	return PrivilegedBinaryFact{}
}

func TestPackageOwnershipParsersAndUnknownManager(t *testing.T) {
	tests := []struct {
		manager string
		input   string
		owned   bool
		name    string
	}{
		{manager: "dpkg", input: "demo-tools: /usr/bin/demo\n", owned: true, name: "demo-tools"},
		{manager: "rpm", input: "demo-tools-1.0-1.x86_64\n", owned: true, name: "demo-tools-1.0-1.x86_64"},
		{manager: "apk", input: "/usr/bin/demo is owned by demo-tools-1.0-r0\n", owned: true, name: "demo-tools-1.0-r0"},
		{manager: "unknown", input: "", owned: false},
	}
	for _, tt := range tests {
		got := ParsePackageOwnership("/usr/bin/demo", tt.manager, []byte(tt.input), "e-pkg")
		if got.Owned != tt.owned || got.Package != tt.name || len(got.EvidenceIDs) == 0 {
			t.Fatalf("%s ownership = %#v", tt.manager, got)
		}
	}
	framed := ParsePackageProbe("/usr/bin/demo", []byte("LPECO_PACKAGE_V1\nMANAGER\trpm\ndemo-tools-1.0-1.x86_64\n"), "e-pkg")
	if !framed.Owned || framed.Manager != "rpm" || framed.Package != "demo-tools-1.0-1.x86_64" {
		t.Fatalf("framed package ownership = %#v", framed)
	}
}

func TestWalkPlanSkipsPseudoRemoteDuplicateBindAndExcludes(t *testing.T) {
	mounts := []pathcollect.MountObservation{
		{ID: 1, MajorMinor: "8:1", Root: "/", MountPoint: "/"},
		{ID: 2, MajorMinor: "0:1", Root: "/", MountPoint: "/proc", Pseudo: true},
		{ID: 3, MajorMinor: "0:2", Root: "/", MountPoint: "/net", Remote: true},
		{ID: 4, MajorMinor: "8:2", Root: "/", MountPoint: "/srv"},
		{ID: 5, MajorMinor: "8:2", Root: "/", MountPoint: "/mnt/srv", Bind: true},
		{ID: 6, MajorMinor: "8:3", Root: "/", MountPoint: "/secret"},
	}
	got := PlanWalk(mounts, WalkOptions{Excludes: []string{"/secret"}, Limit: 10})
	if !reflect.DeepEqual(got, []WalkTarget{{Root: "/", MajorMinor: "8:1", Limit: 10}, {Root: "/srv", MajorMinor: "8:2", Limit: 10}}) {
		t.Fatalf("walk plan = %#v", got)
	}
}

func readBinaryFixture(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return value
}
