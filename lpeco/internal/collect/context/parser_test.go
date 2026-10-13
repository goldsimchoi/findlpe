package context

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/model"
)

func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		want        model.DistributionProfile
		wantMissing []string
	}{
		{
			name:  "exact Ubuntu standard release",
			input: "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\nID_LIKE=\"debian ubuntu\"\n",
			want: model.DistributionProfile{
				ID: "ubuntu", VersionID: "24.04", VersionCodename: "noble", IDLike: []string{"debian", "ubuntu"}, Channel: "standard",
			},
		},
		{
			name:  "quoted values and supported escapes",
			input: "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=\"no\\\\ble\"\nID_LIKE='debian ubuntu'\n",
			want: model.DistributionProfile{
				ID: "ubuntu", VersionID: "24.04", VersionCodename: `no\ble`, IDLike: []string{"debian", "ubuntu"}, Channel: "standard",
			},
		},
		{
			name:        "ID_LIKE is not provider authority",
			input:       "VERSION_ID=24.04\nVERSION_CODENAME=noble\nID_LIKE=ubuntu\n",
			want:        model.DistributionProfile{VersionID: "24.04", VersionCodename: "noble", IDLike: []string{"ubuntu"}},
			wantMissing: []string{"os-release ID is missing"},
		},
		{
			name:        "duplicate mandatory ID invalidates provider",
			input:       "ID=ubuntu\nID=debian\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n",
			want:        model.DistributionProfile{VersionID: "24.04", VersionCodename: "noble"},
			wantMissing: []string{"os-release ID is duplicated"},
		},
		{
			name:        "duplicate mandatory VERSION_ID invalidates release",
			input:       "ID=ubuntu\nVERSION_ID=24.04\nVERSION_ID=22.04\nVERSION_CODENAME=noble\n",
			want:        model.DistributionProfile{ID: "ubuntu", VersionCodename: "noble"},
			wantMissing: []string{"os-release VERSION_ID is duplicated"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, missing := ParseOSRelease([]byte(test.input))
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ParseOSRelease() = %#v, want %#v", got, test.want)
			}
			for _, want := range test.wantMissing {
				if !slices.Contains(missing, want) {
					t.Fatalf("missing facts = %#v, want %q", missing, want)
				}
			}
		})
	}
}

func TestParseOSReleaseRejectsMalformedQuotingAndNUL(t *testing.T) {
	malformed := readContextFixture(t, "../../../testdata/context/malformed-os-release.txt")
	for _, input := range [][]byte{malformed, []byte("ID=ubuntu\x00\nVERSION_ID=24.04\n")} {
		profile, missing := ParseOSRelease(input)
		if profile.ID != "" || len(missing) == 0 {
			t.Fatalf("malformed profile = %#v, missing = %#v", profile, missing)
		}
	}
}

func TestParseContextV2UnreadableAndMissingKernelStayIncomplete(t *testing.T) {
	frame := "LPECO_CONTEXT_V2\nSTATUS\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nEND_STATUS\n" +
		"OS_RELEASE\tunreadable\t" + hex.EncodeToString([]byte("/etc/os-release")) + "\t\nKERNEL\t\t\n"
	parsed, err := ParseOutput([]byte(frame))
	if err != nil {
		t.Fatalf("ParseOutput: %v", err)
	}
	if parsed.Distribution.ID != "" || parsed.Kernel.Release != "" {
		t.Fatalf("unreadable context gained identity: %#v / %#v", parsed.Distribution, parsed.Kernel)
	}
	if parsed.Distribution.Confidence != model.ConfidenceMedium || parsed.Kernel.Confidence != model.ConfidenceMedium {
		t.Fatalf("incomplete confidence = %q/%q", parsed.Distribution.Confidence, parsed.Kernel.Confidence)
	}
	if !slices.Contains(parsed.Distribution.MissingFacts, "os-release is unreadable") || !slices.Contains(parsed.Kernel.MissingFacts, "running kernel release is missing") {
		t.Fatalf("missing facts = %#v / %#v", parsed.Distribution.MissingFacts, parsed.Kernel.MissingFacts)
	}
}

func TestParseContextLegacyV1MarksDistributionAndKernelUnavailable(t *testing.T) {
	frame := "LPECO_CONTEXT_V1\nSTATUS\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nEND_STATUS\nOS\tLinux\nARCH\tx86_64\n"
	parsed, err := ParseOutput([]byte(frame))
	if err != nil {
		t.Fatalf("ParseOutput legacy: %v", err)
	}
	if !slices.Contains(parsed.Distribution.MissingFacts, "distribution unavailable in legacy context frame") || !slices.Contains(parsed.Kernel.MissingFacts, "kernel unavailable in legacy context frame") {
		t.Fatalf("legacy missing facts = %#v / %#v", parsed.Distribution.MissingFacts, parsed.Kernel.MissingFacts)
	}
}

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
	if parsed.Distribution.ID != "ubuntu" || parsed.Distribution.VersionID != "24.04" || parsed.Distribution.VersionCodename != "noble" || parsed.Distribution.SourcePath != "/etc/os-release" {
		t.Fatalf("distribution = %#v", parsed.Distribution)
	}
	if parsed.Kernel.Release != "6.8.0-31-generic" || parsed.Kernel.Version != "#31-Ubuntu SMP PREEMPT_DYNAMIC" {
		t.Fatalf("kernel = %#v", parsed.Kernel)
	}
	if len(parsed.MissingFacts) != 0 {
		t.Fatalf("unexpected missing facts: %#v", parsed.MissingFacts)
	}

	facts, err := Facts(parsed, "evidence-context")
	if err != nil {
		t.Fatalf("Facts: %v", err)
	}
	if len(facts) != 6 {
		t.Fatalf("fact count = %d, want 6", len(facts))
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
		if fact.Kind == "distribution" {
			if fact.Confidence != model.ConfidenceHigh {
				t.Fatalf("valid distribution confidence = %q, want high", fact.Confidence)
			}
			continue
		}
		if fact.Kind == "kernel" {
			if fact.Confidence != model.ConfidenceMedium {
				t.Fatalf("missing kernel confidence = %q, want medium", fact.Confidence)
			}
			continue
		}
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
	if len(definitions) != 1 {
		t.Fatalf("Definitions count = %d, want 1", len(definitions))
	}
	for _, definition := range definitions {
		if definition.SafetyClass != model.PassiveRead || !definition.Idempotent || len(definition.Variants) == 0 {
			t.Fatalf("unsafe or incomplete context probe: %#v", definition)
		}
		if definition.Timeout != 10*time.Second || definition.MaxOutput != 512*1024 || definition.Parser != "context-v2" || len(definition.Variants) != 1 {
			t.Fatalf("unbounded or unstable context definition: %#v", definition)
		}
		script := strings.ToLower(definition.Variants[0].Command.Script)
		for _, forbidden := range []string{"source ", "eval ", "curl ", "wget ", "apt-get", "apt update", "dnf ", "yum ", "apk add"} {
			if strings.Contains(script, forbidden) {
				t.Fatalf("context script contains forbidden operation %q", forbidden)
			}
		}
		primary := strings.Index(script, "if [ -e /etc/os-release ]")
		fallback := strings.Index(script, "elif [ -e /usr/lib/os-release ]")
		if primary < 0 || fallback <= primary {
			t.Fatalf("context script does not select /etc/os-release before absent-only fallback")
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
