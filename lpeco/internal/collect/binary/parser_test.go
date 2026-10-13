package binary

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/normalone/lpeco/internal/collect"
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

	ambiguous := ParseSudoList([]byte("(root) NOPASSWD: !/bin/sh, ALL\n"), "e-ambiguous")
	if len(ambiguous) != 2 || !ambiguous[0].Negated || ambiguous[0].SemanticsResolved || ambiguous[1].SemanticsResolved {
		t.Fatalf("ambiguous sudo semantics = %#v", ambiguous)
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

func TestPrivilegedWalkPrunesExcludedTreeBeforeCapabilityReads(t *testing.T) {
	root := t.TempDir()
	excluded := filepath.Join(root, "excluded")
	allowed := filepath.Join(root, "allowed")
	if err := os.MkdirAll(excluded, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(excluded, "secret"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(allowed, "visible"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "fake-bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	getcap := filepath.Join(bin, "getcap")
	if err := os.WriteFile(getcap, []byte("#!/bin/sh\nfor value do last=$value; done\nprintf '%s\\n' \"$last\" >>\"$LPECO_GETCAP_LOG\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "getcap.log")
	definition := PrivilegedDefinitionWithExcludes(root, []string{excluded}, 100)
	command := definition.Variants[0].Command
	process := exec.Command("sh", append([]string{"-c", command.Script, "lpeco"}, command.Args...)...)
	process.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "LPECO_GETCAP_LOG="+logPath)
	if output, err := process.CombinedOutput(); err != nil {
		t.Fatalf("walk: %v\n%s", err, output)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), filepath.Join(excluded, "secret")) {
		t.Fatalf("excluded tree was read by getcap: %s", log)
	}
	if !strings.Contains(string(log), filepath.Join(allowed, "visible")) {
		t.Fatalf("allowed tree was not inspected: %s", log)
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

func TestTargetedELFProbeTreatsExpectedNegativeResultAsComplete(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "script")
	if err := os.WriteFile(target, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(root, "bin")
	if err := os.Mkdir(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"readelf": "#!/bin/sh\nexit 1\n",
	} {
		if err := os.WriteFile(filepath.Join(fakeBin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	elfCommand := ELFDefinition(target).Variants[0].Command
	elfProcess := exec.Command("sh", append([]string{"-c", elfCommand.Script, "lpeco"}, elfCommand.Args...)...)
	elfProcess.Env = append(os.Environ(), "PATH="+fakeBin+":/usr/bin:/bin")
	elfOutput, err := elfProcess.CombinedOutput()
	if err != nil {
		t.Fatalf("non-ELF script probe should be complete: %v\n%s", err, elfOutput)
	}
	dependencies, diagnostics := ParseELF(target, elfOutput, "e-script")
	if len(diagnostics) != 0 || len(dependencies) != 1 || dependencies[0].Kind != "script" {
		t.Fatalf("script dependencies = %#v, diagnostics = %#v", dependencies, diagnostics)
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

func TestWalkPlanRestrictsContainingMountToRequestedRoot(t *testing.T) {
	mounts := []pathcollect.MountObservation{
		{ID: 1, MajorMinor: "8:1", Root: "/", MountPoint: "/"},
		{ID: 2, MajorMinor: "8:2", Root: "/", MountPoint: "/opt/data"},
		{ID: 3, MajorMinor: "8:3", Root: "/", MountPoint: "/home"},
	}
	got := PlanWalk(mounts, WalkOptions{Roots: []string{"/opt"}, Limit: 10})
	want := []WalkTarget{{Root: "/opt", MajorMinor: "8:1", Limit: 10}, {Root: "/opt/data", MajorMinor: "8:2", Limit: 10}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("restricted walk plan = %#v, want %#v", got, want)
	}
}

func TestCollectorPlansWalkFromDiscoveredMounts(t *testing.T) {
	discovery := collect.Discovery{Mounts: []collect.Mount{
		{MajorMinor: "8:1", Root: "/", MountPoint: "/"},
		{MajorMinor: "0:1", Root: "/", MountPoint: "/proc", Pseudo: true},
		{MajorMinor: "8:2", Root: "/", MountPoint: "/srv"},
		{MajorMinor: "8:2", Root: "/", MountPoint: "/mnt/srv", Bind: true},
	}}
	definitions := (Collector{WalkOptions: WalkOptions{Limit: 17}}).Plan(model.HostProfile{}, discovery)
	var roots []string
	for _, definition := range definitions {
		if definition.Parser == "privileged-v1" {
			roots = append(roots, definition.Variants[0].Command.Args[0])
		}
	}
	if !reflect.DeepEqual(roots, []string{"/", "/srv"}) {
		t.Fatalf("collector walk roots = %#v", roots)
	}
}

func TestCollectorLeavesPackageOwnershipToPackageInfoCollector(t *testing.T) {
	definitions := (Collector{WalkOptions: WalkOptions{Limit: 17}}).Plan(model.HostProfile{}, collect.Discovery{ReferencedPaths: []string{"/usr/bin/demo"}})
	foundELF := false
	for _, definition := range definitions {
		if definition.Parser == "package-ownership" {
			t.Fatalf("binary collector still planned package ownership: %#v", definition)
		}
		if definition.Parser == "elf-text" {
			foundELF = true
		}
	}
	if !foundELF {
		t.Fatal("binary collector stopped planning ELF inspection")
	}
}

func TestPrivilegedWalkKeepsCapabilitySearchOnFilesystemBoundary(t *testing.T) {
	script := PrivilegedDefinition("/", 10).Variants[0].Command.Script
	if strings.Contains(script, "getcap -r") {
		t.Fatalf("recursive getcap escapes find -xdev boundary: %s", script)
	}
	if strings.Count(script, `find "$_lpeco_root" -xdev`) < 2 {
		t.Fatalf("set-ID and capability searches must both enforce -xdev: %s", script)
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
