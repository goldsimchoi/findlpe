package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	binarycollect "github.com/normalone/lpeco/internal/collect/binary"
	contextcollect "github.com/normalone/lpeco/internal/collect/context"
	pathcollect "github.com/normalone/lpeco/internal/collect/path"
	processcollect "github.com/normalone/lpeco/internal/collect/process"
	schedulercollect "github.com/normalone/lpeco/internal/collect/scheduler"
	systemdcollect "github.com/normalone/lpeco/internal/collect/systemd"
	graphpkg "github.com/normalone/lpeco/internal/graph"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/orchestrator"
	"github.com/normalone/lpeco/internal/probe"
	"github.com/normalone/lpeco/internal/rules"
	"github.com/normalone/lpeco/internal/store"
)

func TestSystemdPrivilegeGraphIntegration(t *testing.T) {
	sessionStore, err := store.Open(t.TempDir(), "systemd-graph")
	if err != nil {
		t.Fatal(err)
	}
	result, err := orchestrator.Run(context.Background(), integrationTransport(t, "stdio-raw"), sessionStore, orchestrator.Options{
		SessionID: "systemd-graph", Collectors: cannedHostCollectors(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	g, diagnostics := graphBuild(t, result.Facts)
	if !hasGraphDiagnostic(diagnostics, "runtime-file-mismatch") {
		t.Fatalf("runtime/file diagnostic missing = %#v", diagnostics)
	}
	processes := g.NodesByKind(model.NodeProcess)
	if len(processes) != 1 || len(g.Outgoing(processes[0].NodeRef, model.EdgeManagedBy)) != 1 {
		t.Fatalf("process-to-unit management chain missing")
	}
	if !hasCandidate(result.Candidates, "systemd.writable-unit-source", model.PriorityP0) {
		t.Fatalf("systemd P0 candidate missing: %#v", result.Candidates)
	}
}

func TestNonSystemdFallbackIntegration(t *testing.T) {
	root := integrationRoot(t)
	read := func(relative string) []byte {
		value, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	contextFacts, err := (contextcollect.Collector{}).Parse(contextcollect.Definitions()[0], adapter.ExecResult{Stdout: read("testdata/context/minimal-busybox.txt"), Status: model.ProbeComplete}, "e-context")
	if err != nil {
		t.Fatal(err)
	}
	cronContent := read("testdata/fallback/cron/system.cron")
	sysvLines := strings.TrimPrefix(string(read("testdata/fallback/sysv/links.txt")), "LPECO_SYSV_V1\n")
	sysvLines = strings.ReplaceAll(sysvLines, "LINK\t", "SYSV\t")
	schedulerTranscript := fmt.Sprintf("LPECO_SCHEDULER_V1\nCRON_SYSTEM\t%s\t%s\t%s\n%s",
		hex.EncodeToString([]byte("/etc/cron.d/demo")), hex.EncodeToString([]byte("root")), hex.EncodeToString(cronContent), sysvLines)
	schedulerFacts, err := (schedulercollect.Collector{}).Parse(schedulercollect.Definition(), adapter.ExecResult{Stdout: []byte(schedulerTranscript), Status: model.ProbeComplete}, "e-scheduler")
	if err != nil {
		t.Fatal(err)
	}
	binaryFacts, err := (binarycollect.Collector{}).Parse(binarycollect.PrivilegedDefinition("/", 100), adapter.ExecResult{Stdout: read("testdata/fallback/suid/inventory.txt"), Status: model.ProbeComplete}, "e-binary")
	if err != nil {
		t.Fatal(err)
	}
	statTranscript, aclTranscript := cannedPathObservations(map[string]uint32{
		"/opt/jobs/root.py": 0o100666, "/opt/backup.sh": 0o100666,
		"/etc/init.d/legacy": 0o100777, "/etc/init.d/worker": 0o100777,
		"/usr/local/bin/capped": 0o100755,
	})
	pathCollector := pathcollect.Collector{}
	mountFacts, _ := pathCollector.Parse(pathcollect.MountInfoDefinition(), adapter.ExecResult{Stdout: []byte("36 25 0:32 / / rw,relatime - ext4 /dev/vda1 rw\n"), Status: model.ProbeComplete}, "e-mount")
	statFacts, _ := pathCollector.Parse(pathcollect.StatDefinition("/"), adapter.ExecResult{Stdout: statTranscript, Status: model.ProbeComplete}, "e-stat")
	aclFacts, _ := pathCollector.Parse(pathcollect.ACLDefinition("/"), adapter.ExecResult{Stdout: aclTranscript, Status: model.ProbeComplete}, "e-acl")
	facts := append([]model.Fact{}, contextFacts...)
	facts = append(facts, schedulerFacts...)
	facts = append(facts, binaryFacts...)
	facts = append(facts, mountFacts...)
	facts = append(facts, statFacts...)
	facts = append(facts, aclFacts...)
	g, diagnostics := graphBuild(t, facts)
	if len(diagnostics) != 0 {
		t.Fatalf("graph diagnostics = %#v", diagnostics)
	}
	candidates := rules.EvaluateAll(context.Background(), g, rules.AllRules())
	if !hasCandidate(candidates, "scheduler.writable-command", model.PriorityP0) {
		t.Fatalf("scheduler fallback candidate missing: %#v", candidates)
	}
	if !hasCandidate(candidates, "binary.capability-boundary", model.PriorityP2) {
		t.Fatalf("binary P2 inventory candidate missing: %#v", candidates)
	}
	kinds := map[string]bool{}
	for _, fact := range schedulerFacts {
		var value schedulercollect.ScheduleFact
		if json.Unmarshal(fact.Data, &value) == nil {
			kinds[value.Kind] = true
		}
	}
	if !kinds["cron"] || !kinds["sysv"] {
		t.Fatalf("fallback parsers did not cover cron and SysV: %#v", kinds)
	}
}

func TestCrossAdapterCandidateEquivalence(t *testing.T) {
	var baseline []candidateMeaning
	for _, transportKind := range []string{"ssh", "raw-listen", "stdio-raw", "c2-plugin"} {
		t.Run(transportKind, func(t *testing.T) {
			base := t.TempDir()
			sessionID := "cross-" + transportKind
			sessionStore, err := store.Open(base, sessionID)
			if err != nil {
				t.Fatal(err)
			}
			collectors := cannedHostCollectors(t)
			result, err := orchestrator.Run(context.Background(), integrationTransport(t, transportKind), sessionStore, orchestrator.Options{SessionID: sessionID, Collectors: collectors})
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			meaning := candidateMeanings(result.Candidates)
			if len(meaning) == 0 {
				t.Fatal("no candidates")
			}
			if !hasCandidate(result.Candidates, "systemd.writable-unit-source", model.PriorityP0) {
				t.Fatalf("real collector path did not produce expected P0: %#v", result.Candidates)
			}
			graph, diagnostics := graphpkg.Build(result.Facts)
			if len(graph.NodesByKind(model.NodeProcess)) == 0 || !hasManagedByEdge(graph) {
				t.Fatalf("real collector graph lacks MANAGED_BY; diagnostics=%#v", diagnostics)
			}
			probeIDs := make(map[string]bool)
			for _, evidence := range mustEvidence(t, sessionStore) {
				probeIDs[evidence.ProbeID] = true
			}
			for _, required := range []string{"context.current", "process.snapshot", "systemd.show.system", "systemd.cat.system.demo.service"} {
				if !probeIDs[required] {
					t.Fatalf("actual collector probe %s was not transported: %#v", required, probeIDs)
				}
			}
			if baseline == nil {
				baseline = meaning
			} else if !reflect.DeepEqual(meaning, baseline) {
				t.Fatalf("candidate meanings differ\ngot:  %#v\nwant: %#v", meaning, baseline)
			}
		})
	}
}

type candidateMeaning struct {
	RuleID, Current, Target, Consumer, Object string
	Priority                                  model.Priority
}

func candidateMeanings(values []model.Candidate) []candidateMeaning {
	result := make([]candidateMeaning, 0, len(values))
	for _, value := range values {
		meaning := candidateMeaning{RuleID: value.RuleID, Current: value.CurrentPrincipal.ID, Target: value.TargetPrincipal.ID, Priority: value.Priority}
		if value.PrivilegedConsumer != nil {
			meaning.Consumer = value.PrivilegedConsumer.ID
		}
		if value.ControlledObject != nil {
			meaning.Object = value.ControlledObject.ID
		}
		result = append(result, meaning)
	}
	return result
}

type transcriptCollector struct {
	delegate    collect.Collector
	plan        func(collect.Discovery) []probe.Definition
	transcripts map[string][]byte
}

func (collector transcriptCollector) ID() string { return collector.delegate.ID() }
func (collector transcriptCollector) Plan(_ model.HostProfile, discovery collect.Discovery) []probe.Definition {
	definitions := collector.plan(discovery)
	for index := range definitions {
		transcript := collector.transcripts[definitions[index].ID]
		definitions[index].Requirements = nil
		definitions[index].Variants = []probe.Variant{{ID: "canned-transcript", Command: adapter.Command{Script: "printf '%s' \"$1\"", Args: []string{string(transcript)}}}}
	}
	return definitions
}
func (collector transcriptCollector) Parse(definition probe.Definition, result adapter.ExecResult, evidence string) ([]model.Fact, error) {
	return collector.delegate.Parse(definition, result, evidence)
}

func cannedHostCollectors(t *testing.T) []collect.Collector {
	t.Helper()
	root := integrationRoot(t)
	read := func(relative string) []byte {
		value, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	contextDefinition := contextcollect.Definitions()[0]
	processDefinition := processcollect.SnapshotDefinition()
	showDefinition := systemdcollect.ShowDefinition("system")
	catDefinition := systemdcollect.CatDefinition("system", "demo.service")
	sourcePath := "/etc/systemd/system/demo.service.d/20-local.conf"
	mountDefinition := pathcollect.MountInfoDefinition()
	statDefinition := pathcollect.StatDefinition(sourcePath)
	aclDefinition := pathcollect.ACLDefinition(sourcePath)
	return []collect.Collector{
		transcriptCollector{delegate: contextcollect.Collector{}, plan: func(collect.Discovery) []probe.Definition { return []probe.Definition{contextDefinition} }, transcripts: map[string][]byte{contextDefinition.ID: read("testdata/context/full.txt")}},
		transcriptCollector{delegate: processcollect.Collector{}, plan: func(collect.Discovery) []probe.Definition { return []probe.Definition{processDefinition} }, transcripts: map[string][]byte{processDefinition.ID: read("testdata/proc/debian/snapshot.txt")}},
		transcriptCollector{delegate: systemdcollect.Collector{}, plan: func(discovery collect.Discovery) []probe.Definition {
			definitions := []probe.Definition{showDefinition}
			for _, unit := range discovery.UnitNames {
				if unit == "demo.service" {
					definitions = append(definitions, catDefinition)
					break
				}
			}
			return definitions
		}, transcripts: map[string][]byte{showDefinition.ID: read("testdata/systemd/show/full.txt"), catDefinition.ID: read("testdata/systemd/cat/demo.cat")}},
		transcriptCollector{delegate: pathcollect.Collector{}, plan: func(collect.Discovery) []probe.Definition {
			return []probe.Definition{mountDefinition, statDefinition, aclDefinition}
		}, transcripts: map[string][]byte{mountDefinition.ID: []byte("36 25 0:32 / / rw,relatime - ext4 /dev/vda1 rw\n"), statDefinition.ID: cannedWritableStat(sourcePath), aclDefinition.ID: cannedWritableACL(sourcePath)}},
	}
}

func cannedWritableStat(target string) []byte {
	paths := []string{target, filepath.Dir(target), "/etc/systemd/system", "/etc/systemd", "/etc", "/"}
	var output strings.Builder
	output.WriteString("LPECO_PATH_STAT_V1\n")
	for index, path := range paths {
		mode, kind := "41ed", "directory"
		if index == 0 {
			mode, kind = "81b6", "regular file"
		}
		fmt.Fprintf(&output, "STAT\t%s\t1\t%d\t%s\t0\t0\t%s\t\n", hex.EncodeToString([]byte(path)), index+10, mode, kind)
	}
	return []byte(output.String())
}

func cannedWritableACL(target string) []byte {
	paths := []string{target, filepath.Dir(target), "/etc/systemd/system", "/etc/systemd", "/etc", "/"}
	var output strings.Builder
	output.WriteString("LPECO_PATH_ACL_V1\n")
	for index, path := range paths {
		fmt.Fprintf(&output, "ACL\t%s\n", hex.EncodeToString([]byte(path)))
		if index == 0 {
			output.WriteString("user::rw-\ngroup::rw-\nother::rw-\n")
		} else {
			output.WriteString("user::rwx\ngroup::r-x\nother::r-x\n")
		}
		output.WriteString("END_ACL\n")
	}
	return []byte(output.String())
}

func cannedPathObservations(modes map[string]uint32) ([]byte, []byte) {
	allModes := make(map[string]uint32)
	for target, mode := range modes {
		for path := filepath.Clean(target); ; path = filepath.Dir(path) {
			if _, exists := allModes[path]; !exists {
				allModes[path] = 0o040755
			}
			if path == "/" {
				break
			}
		}
		allModes[filepath.Clean(target)] = mode
	}
	paths := make([]string, 0, len(allModes))
	for path := range allModes {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var stats, acls strings.Builder
	stats.WriteString("LPECO_PATH_STAT_V1\n")
	acls.WriteString("LPECO_PATH_ACL_V1\n")
	for index, path := range paths {
		mode := allModes[path]
		kind := "directory"
		if mode&0o170000 == 0o100000 {
			kind = "regular file"
		}
		fmt.Fprintf(&stats, "STAT\t%s\t1\t%d\t%x\t0\t0\t%s\t\n", hex.EncodeToString([]byte(path)), index+100, mode, kind)
		fmt.Fprintf(&acls, "ACL\t%s\n", hex.EncodeToString([]byte(path)))
		fmt.Fprintf(&acls, "user::%s\ngroup::%s\nother::%s\nEND_ACL\n", modePermissions(mode>>6), modePermissions(mode>>3), modePermissions(mode))
	}
	return []byte(stats.String()), []byte(acls.String())
}

func modePermissions(mode uint32) string {
	var value strings.Builder
	if mode&4 != 0 {
		value.WriteByte('r')
	} else {
		value.WriteByte('-')
	}
	if mode&2 != 0 {
		value.WriteByte('w')
	} else {
		value.WriteByte('-')
	}
	if mode&1 != 0 {
		value.WriteByte('x')
	} else {
		value.WriteByte('-')
	}
	return value.String()
}

func hasManagedByEdge(graph *graphpkg.Graph) bool {
	for _, process := range graph.NodesByKind(model.NodeProcess) {
		if len(graph.Outgoing(process.NodeRef, model.EdgeManagedBy)) > 0 {
			return true
		}
	}
	return false
}

func mustEvidence(t *testing.T, sessionStore *store.Store) []model.Evidence {
	t.Helper()
	values, err := sessionStore.ListEvidence(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].ProbeID < values[j].ProbeID })
	return values
}

func hasCandidate(values []model.Candidate, ruleID string, priority model.Priority) bool {
	for _, value := range values {
		if value.RuleID == ruleID && value.Priority == priority {
			return true
		}
	}
	return false
}

func graphBuild(t *testing.T, facts []model.Fact) (*graphpkg.Graph, []graphpkg.Diagnostic) {
	t.Helper()
	g, diagnostics := graphpkg.Build(facts)
	if g == nil {
		t.Fatal(fmt.Errorf("nil graph"))
	}
	return g, diagnostics
}

func hasGraphDiagnostic(values []graphpkg.Diagnostic, code string) bool {
	for _, value := range values {
		if value.Code == code {
			return true
		}
	}
	return false
}
