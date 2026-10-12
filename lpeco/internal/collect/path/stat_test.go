package path

import (
	"reflect"
	"strings"
	"testing"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/model"
)

func TestParseStatOutputAndResolveSymlinkChains(t *testing.T) {
	parsed, diagnostics := ParseStat([]byte("LPECO_PATH_STAT_V1\nSTAT\t2f6f7074\t8\t10\t41ed\t0\t0\tdirectory\t\nSTAT\t2f6f70742f617070\t8\t11\t41ed\t0\t0\tdirectory\t\nSTAT\t2f6f70742f6170702f63757272656e74\t8\t12\ta1ff\t0\t0\tsymlink\t2e2e2f72656c65617365732f7632\nSTAT\t2f6f70742f72656c6561736573\t8\t13\t41ed\t0\t0\tdirectory\t\nSTAT\t2f6f70742f72656c65617365732f7632\t8\t14\ta1ff\t0\t0\tsymlink\t2f7372762f617070\nSTAT\t2f737276\t8\t15\t41ed\t0\t0\tdirectory\t\nSTAT\t2f7372762f617070\t8\t16\t81ed\t0\t0\tregular\t\nSTAT\t2f\t8\t2\t41ed\t0\t0\tdirectory\t\n"), "e-stat")
	if len(diagnostics) != 0 {
		t.Fatalf("ParseStat diagnostics = %#v", diagnostics)
	}
	resolution := Resolve("/opt/app/current", ObservationSet{Stats: groupStats(parsed)})
	if resolution.FinalPath != "/srv/app" || !resolution.Complete || len(resolution.Symlinks) != 2 {
		t.Fatalf("resolution = %#v", resolution)
	}
	if got := statPaths(resolution.Parents); !reflect.DeepEqual(got, []string{"/", "/opt", "/opt/app", "/opt/releases", "/srv"}) {
		t.Fatalf("parent chain = %#v", got)
	}
}

func TestResolveReportsDanglingLoopRaceAndRelativeBase(t *testing.T) {
	base := []StatObservation{
		statDir("/", 1, 0, 0, 0o755), statDir("/work", 2, 1000, 1000, 0o755),
		statLink("/work/dangling", 3, "missing"),
		statLink("/work/a", 4, "b"), statLink("/work/b", 5, "a"),
		statFile("/work/racy", 6, 1000, 1000, 0o644), statFile("/work/racy", 7, 1000, 1000, 0o644),
		statFile("/work/relative", 8, 1000, 1000, 0o644),
	}
	set := ObservationSet{WorkingDirectory: "/work", Stats: groupStats(base)}

	if got := Resolve("dangling", set); !got.Dangling || got.Complete || !hasMissing(got.MissingFacts, "missing") {
		t.Fatalf("dangling resolution = %#v", got)
	}
	if got := Resolve("a", set); !got.Loop || got.Complete || !hasMissing(got.MissingFacts, "loop") {
		t.Fatalf("loop resolution = %#v", got)
	}
	if got := Resolve("racy", set); !got.RaceDetected || got.Complete || !hasMissing(got.MissingFacts, "changed") {
		t.Fatalf("race resolution = %#v", got)
	}
	if got := Resolve("relative", set); got.FinalPath != "/work/relative" || !got.Complete {
		t.Fatalf("relative resolution = %#v", got)
	}
}

func TestResolveRootAndProbeArgumentsRemainData(t *testing.T) {
	root := statDir("/", 1, 0, 0, 0o755)
	resolution := Resolve("/", ObservationSet{Stats: groupStats([]StatObservation{root})})
	if !resolution.Complete || resolution.Final == nil || resolution.Final.Path != "/" {
		t.Fatalf("root resolution = %#v", resolution)
	}

	target := "/tmp/a'; touch /tmp/not-allowed; printf '"
	definition := StatDefinition(target)
	if definition.SafetyClass != model.PassiveRead || strings.Contains(definition.Variants[0].Command.Script, target) {
		t.Fatalf("unsafe stat definition = %#v", definition)
	}
	if !reflect.DeepEqual(definition.Variants[0].Command.Args, []string{target}) {
		t.Fatalf("probe arguments = %#v", definition.Variants[0].Command.Args)
	}
	if _, err := adapter.RenderPOSIX(definition.Variants[0].Command); err != nil {
		t.Fatalf("RenderPOSIX: %v", err)
	}
}

func groupStats(values []StatObservation) map[string][]StatObservation {
	result := make(map[string][]StatObservation)
	for _, value := range values {
		result[value.Path] = append(result[value.Path], value)
	}
	return result
}

func statPaths(values []StatObservation) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.Path
	}
	return result
}

func statDir(path string, inode uint64, uid, gid int, permissions uint32) StatObservation {
	return StatObservation{Path: path, Device: 8, Inode: inode, Mode: 0o040000 | permissions, UID: uid, GID: gid, Kind: FileDirectory, EvidenceIDs: []string{"e-stat"}}
}

func statFile(path string, inode uint64, uid, gid int, permissions uint32) StatObservation {
	return StatObservation{Path: path, Device: 8, Inode: inode, Mode: 0o100000 | permissions, UID: uid, GID: gid, Kind: FileRegular, EvidenceIDs: []string{"e-stat"}}
}

func statLink(path string, inode uint64, target string) StatObservation {
	return StatObservation{Path: path, Device: 8, Inode: inode, Mode: 0o120777, UID: 0, GID: 0, Kind: FileSymlink, LinkTarget: target, EvidenceIDs: []string{"e-stat"}}
}

func hasMissing(values []string, fragment string) bool {
	for _, value := range values {
		if containsFold(value, fragment) {
			return true
		}
	}
	return false
}
