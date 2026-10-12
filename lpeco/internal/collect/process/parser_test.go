package process

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	"github.com/normalone/lpeco/internal/model"
)

func TestParseProcessSnapshotAcrossDistributionFixtures(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantPID   int
		wantExe   string
		wantGroup string
	}{
		{name: "debian", path: "../../../testdata/proc/debian/snapshot.txt", wantPID: 101, wantExe: "/usr/bin/demo", wantGroup: "/system.slice/demo.service"},
		{name: "rhel", path: "../../../testdata/proc/rhel/snapshot.txt", wantPID: 202, wantExe: "/usr/local/bin/worker", wantGroup: "/system.slice/rhel-worker.service"},
		{name: "alpine", path: "../../../testdata/proc/alpine/snapshot.txt", wantPID: 303, wantExe: "/usr/sbin/crond", wantGroup: "/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processes, err := ParseSnapshot(readProcessFixture(t, tt.path), "evidence-"+tt.name)
			if err != nil {
				t.Fatalf("ParseSnapshot: %v", err)
			}
			if len(processes) != 1 {
				t.Fatalf("process count = %d", len(processes))
			}
			process := processes[0]
			if process.PID != tt.wantPID || process.Executable != tt.wantExe || len(process.Cgroups) != 1 || process.Cgroups[0].Path != tt.wantGroup {
				t.Fatalf("process = %#v", process)
			}
			if len(process.Cmdline) == 0 || process.StartTime == 0 || !reflect.DeepEqual(process.EvidenceIDs, []string{"evidence-" + tt.name}) {
				t.Fatalf("process identity/evidence = %#v", process)
			}
		})
	}
}

func TestParseProcessSnapshotPreservesPermissionAndRaceFailures(t *testing.T) {
	busybox, err := ParseSnapshot(readProcessFixture(t, "../../../testdata/proc/busybox/snapshot.txt"), "evidence-busybox")
	if err != nil {
		t.Fatalf("ParseSnapshot busybox: %v", err)
	}
	if len(busybox) != 1 || !containsString(busybox[0].MissingFacts, "exe: permission denied") || busybox[0].Confidence != model.ConfidenceMedium {
		t.Fatalf("busybox partial process = %#v", busybox)
	}

	races, err := ParseSnapshot(readProcessFixture(t, "../../../testdata/proc/races/snapshot.txt"), "evidence-races")
	if err != nil {
		t.Fatalf("ParseSnapshot races: %v", err)
	}
	if len(races) != 2 || races[0].PID != 404 || !containsString(races[0].MissingFacts, "status: process vanished") {
		t.Fatalf("race processes = %#v", races)
	}
	if races[0].Confidence != model.ConfidenceLow || races[1].Confidence != model.ConfidenceMedium {
		t.Fatalf("race confidence = %q/%q", races[0].Confidence, races[1].Confidence)
	}
}

func TestParseEnvironmentMarksAllowlistedValuesSensitive(t *testing.T) {
	fact, err := ParseEnvironment(readProcessFixture(t, "../../../testdata/proc/debian/environment.txt"), 101, "evidence-env")
	if err != nil {
		t.Fatalf("ParseEnvironment: %v", err)
	}
	if len(fact.Values) != 2 || fact.Values["PATH"].Value != "/usr/local/sbin:/usr/bin" || !fact.Values["PATH"].Sensitive {
		t.Fatalf("environment fact = %#v", fact)
	}
	if _, exists := fact.Values["UNLISTED_SECRET"]; exists {
		t.Fatal("unallowlisted environment key was retained")
	}
}

func TestEnvironmentProbeEmitsOnlyAllowlistedKeys(t *testing.T) {
	command := exec.Command("/bin/sleep", "2")
	command.Env = []string{
		"PATH=/fixture/bin",
		"PYTHONPATH=/fixture/python",
		"UNLISTED_SECRET=must-not-appear",
	}
	if err := command.Start(); err != nil {
		t.Fatalf("start fixture process: %v", err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	definition := EnvironmentDefinition(strconv.Itoa(command.Process.Pid))
	rendered, err := adapter.RenderPOSIX(definition.Variants[0].Command)
	if err != nil {
		t.Fatalf("RenderPOSIX: %v", err)
	}
	output, err := exec.CommandContext(context.Background(), "sh", "-c", rendered).CombinedOutput()
	if err != nil {
		t.Fatalf("run environment probe: %v (%s)", err, output)
	}
	if bytes.Contains(output, []byte("must-not-appear")) || bytes.Contains(output, []byte("UNLISTED_SECRET")) {
		t.Fatalf("environment probe leaked unallowlisted value: %q", output)
	}
	parsed, err := ParseEnvironment(output, command.Process.Pid, "evidence-live-env")
	if err != nil {
		t.Fatalf("ParseEnvironment live output: %v (%q)", err, output)
	}
	if parsed.Values["PATH"].Value != "/fixture/bin" || parsed.Values["PYTHONPATH"].Value != "/fixture/python" {
		t.Fatalf("allowlisted environment = %#v", parsed.Values)
	}
}

func TestProcessFactsRetainEvidenceAndTypedPayload(t *testing.T) {
	processes, err := ParseSnapshot(readProcessFixture(t, "../../../testdata/proc/debian/snapshot.txt"), "evidence-process")
	if err != nil {
		t.Fatalf("ParseSnapshot: %v", err)
	}
	facts, err := Facts(processes)
	if err != nil {
		t.Fatalf("Facts: %v", err)
	}
	if len(facts) != 2 || facts[0].Kind != "process" || facts[1].Kind != "cgroup" {
		t.Fatalf("facts = %#v", facts)
	}
	for _, fact := range facts {
		if !reflect.DeepEqual(fact.EvidenceIDs, []string{"evidence-process"}) {
			t.Fatalf("fact evidence = %#v", fact)
		}
	}
}

func TestCollectorPlansEnvironmentAndDependenciesOnlyForHighValuePIDs(t *testing.T) {
	collector := Collector{}
	primary := collector.Plan(model.HostProfile{}, collect.Discovery{})
	if len(primary) != 1 || primary[0].ID != "process.snapshot" {
		t.Fatalf("primary process plan = %#v", primary)
	}
	targeted := collector.Plan(model.HostProfile{}, collect.Discovery{HighValuePIDs: []int{101, 202}})
	wantIDs := []string{
		"process.snapshot",
		"process.environment.101", "process.dependencies.101",
		"process.environment.202", "process.dependencies.202",
	}
	var gotIDs []string
	for _, definition := range targeted {
		gotIDs = append(gotIDs, definition.ID)
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("targeted process plan IDs = %#v, want %#v", gotIDs, wantIDs)
	}
}

func TestCollectorCarriesExpectedStartTimeIntoTargetedProbes(t *testing.T) {
	definitions := (Collector{}).Plan(model.HostProfile{}, collect.Discovery{HighValueProcesses: []collect.ProcessIdentity{{PID: 101, StartTime: 4242}}})
	wantIDs := []string{"process.snapshot", "process.environment.101.4242", "process.dependencies.101.4242"}
	var gotIDs []string
	for _, definition := range definitions {
		gotIDs = append(gotIDs, definition.ID)
		if definition.ID != "process.snapshot" && !reflect.DeepEqual(definition.Variants[0].Command.Args, []string{"101", "4242"}) {
			t.Fatalf("targeted args = %#v", definition.Variants[0].Command.Args)
		}
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatalf("targeted process plan IDs = %#v, want %#v", gotIDs, wantIDs)
	}
}

func TestTargetedParserRecordsVerifiedStartTime(t *testing.T) {
	input := []byte("LPECO_DEP_V1\nSTARTTIME\t4242\nMAP\t2f6f70742f64656d6f2e736f\nEND_STARTTIME\t4242\n")
	parsed, err := ParseDependenciesIdentity(input, 101, 4242, "evidence-deps")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.StartTime != 4242 || len(parsed.MappedFiles) != 1 {
		t.Fatalf("parsed dependency identity = %#v", parsed)
	}
}

func TestParseTargetedDependenciesAndEnvironmentFacts(t *testing.T) {
	dependencies, err := ParseDependencies(readProcessFixture(t, "../../../testdata/proc/debian/dependencies.txt"), 101, "evidence-deps")
	if err != nil {
		t.Fatalf("ParseDependencies: %v", err)
	}
	if !reflect.DeepEqual(dependencies.OpenFiles, []string{"/etc/demo.conf"}) || !reflect.DeepEqual(dependencies.MappedFiles, []string{"/opt/demo/plugin.so", "/usr/lib/libc.so.6"}) {
		t.Fatalf("dependencies = %#v", dependencies)
	}
	dependencyFacts, err := DependencyFacts(dependencies)
	if err != nil || len(dependencyFacts) != 1 || dependencyFacts[0].Kind != "process_dependency" {
		t.Fatalf("DependencyFacts = (%#v, %v)", dependencyFacts, err)
	}

	collector := Collector{}
	environmentFacts, err := collector.Parse(EnvironmentDefinition("101"), adapter.ExecResult{Stdout: readProcessFixture(t, "../../../testdata/proc/debian/environment.txt")}, "evidence-env")
	if err != nil || len(environmentFacts) != 1 || environmentFacts[0].Kind != "process_environment" {
		t.Fatalf("environment collector facts = (%#v, %v)", environmentFacts, err)
	}
}

func readProcessFixture(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return value
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}
