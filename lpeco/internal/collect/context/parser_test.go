package context

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/normalone/lpeco/internal/model"
)

func TestParseContextFullFixture(t *testing.T) {
	input := readContextFixture(t, "../../../testdata/context/full.txt")
	parsed, err := ParseOutput(input)
	if err != nil {
		t.Fatalf("ParseOutput: %v", err)
	}
	if parsed.Identity.UIDs != [4]int{1000, 1001, 1002, 1003} || parsed.Identity.GIDs != [4]int{100, 101, 102, 103} {
		t.Fatalf("identity IDs = %#v/%#v", parsed.Identity.UIDs, parsed.Identity.GIDs)
	}
	if !reflect.DeepEqual(parsed.Identity.Groups, []int{4, 24, 100, 998}) {
		t.Fatalf("groups = %#v", parsed.Identity.Groups)
	}
	if parsed.Identity.Capabilities["effective"] != 0x400 || !parsed.Identity.NoNewPrivileges || parsed.Identity.SeccompMode != 2 {
		t.Fatalf("security identity = %#v", parsed.Identity)
	}
	if parsed.Namespaces.IDs["pid"] != "pid:[4026533001]" || parsed.Security.LSM["apparmor"] != "enforce" {
		t.Fatalf("namespace/security = %#v / %#v", parsed.Namespaces, parsed.Security)
	}
	if parsed.Host.OS != "Linux" || parsed.Host.Architecture != "x86_64" || parsed.Host.InitSystem != "systemd" || !parsed.Host.SystemdRunning {
		t.Fatalf("host = %#v", parsed.Host)
	}
	if parsed.Host.AvailableCommands["systemctl"] != true || parsed.Host.AvailableCommands["getfacl"] != false {
		t.Fatalf("commands = %#v", parsed.Host.AvailableCommands)
	}
	if len(parsed.MissingFacts) != 0 {
		t.Fatalf("unexpected missing facts: %#v", parsed.MissingFacts)
	}

	facts, err := Facts(parsed, "evidence-context")
	if err != nil {
		t.Fatalf("Facts: %v", err)
	}
	if len(facts) != 4 {
		t.Fatalf("fact count = %d, want 4", len(facts))
	}
	for _, fact := range facts {
		if !reflect.DeepEqual(fact.EvidenceIDs, []string{"evidence-context"}) || fact.Confidence != model.ConfidenceHigh {
			t.Fatalf("fact lacks evidence/confidence: %#v", fact)
		}
	}
}

func TestParseContextMinimalFixturePreservesMissingFacts(t *testing.T) {
	parsed, err := ParseOutput(readContextFixture(t, "../../../testdata/context/minimal-busybox.txt"))
	if err != nil {
		t.Fatalf("ParseOutput: %v", err)
	}
	sort.Strings(parsed.MissingFacts)
	wantMissing := []string{"capabilities", "groups", "lsm", "namespaces", "no_new_privileges", "seccomp"}
	if !reflect.DeepEqual(parsed.MissingFacts, wantMissing) {
		t.Fatalf("missing facts = %#v, want %#v", parsed.MissingFacts, wantMissing)
	}
	if parsed.Host.InitSystem != "busybox" || parsed.Host.SystemdRunning {
		t.Fatalf("minimal host = %#v", parsed.Host)
	}
	facts, err := Facts(parsed, "evidence-minimal")
	if err != nil {
		t.Fatalf("Facts: %v", err)
	}
	for _, fact := range facts {
		if fact.Confidence != model.ConfidenceMedium {
			t.Fatalf("partial context fact confidence = %q, want medium", fact.Confidence)
		}
		var payload struct {
			MissingFacts []string `json:"missing_facts"`
		}
		if err := json.Unmarshal(fact.Data, &payload); err != nil {
			t.Fatalf("decode partial fact: %v", err)
		}
		if !reflect.DeepEqual(payload.MissingFacts, wantMissing) {
			t.Fatalf("fact missing_facts = %#v, want %#v", payload.MissingFacts, wantMissing)
		}
	}
}

func TestContextProbeDefinitionsArePassiveAndFixed(t *testing.T) {
	definitions := Definitions()
	if len(definitions) == 0 {
		t.Fatal("Definitions returned no context probes")
	}
	for _, definition := range definitions {
		if definition.SafetyClass != model.PassiveRead || !definition.Idempotent || len(definition.Variants) == 0 {
			t.Fatalf("unsafe or incomplete context probe: %#v", definition)
		}
	}
}

func readContextFixture(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return value
}
