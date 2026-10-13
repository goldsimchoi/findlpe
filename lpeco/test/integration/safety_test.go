package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/normalone/lpeco/internal/adapter"
	binarycollect "github.com/normalone/lpeco/internal/collect/binary"
	containercollect "github.com/normalone/lpeco/internal/collect/container"
	contextcollect "github.com/normalone/lpeco/internal/collect/context"
	packagecollect "github.com/normalone/lpeco/internal/collect/packageinfo"
	"github.com/normalone/lpeco/internal/collect/path"
	processcollect "github.com/normalone/lpeco/internal/collect/process"
	schedulercollect "github.com/normalone/lpeco/internal/collect/scheduler"
	systemdcollect "github.com/normalone/lpeco/internal/collect/systemd"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

func TestContainerFixtureRequiresDisposableGuard(t *testing.T) {
	script := filepath.Join("container", "fixture.sh")
	command := exec.Command("sh", script, "setup")
	command.Env = append(os.Environ(), "LPECO_DISPOSABLE_FIXTURE=", "LPECO_FIXTURE_KIND=debian")
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 70 {
		t.Fatalf("unguarded fixture setup = (%v, %q), want exit 70", err, output)
	}
	if !strings.Contains(string(output), "refusing destructive fixture setup") {
		t.Fatalf("unguarded fixture output = %q", output)
	}
}

func TestContainerDockerfilesDeclareDisposableBuildMarker(t *testing.T) {
	for _, fixture := range []string{"debian", "alpine"} {
		t.Run(fixture, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join("container", "Dockerfile."+fixture))
			if err != nil {
				t.Fatal(err)
			}
			dockerfile := string(content)
			setupOffset := strings.Index(dockerfile, "/usr/local/libexec/lpeco-fixture setup")
			markerOffset := strings.Index(dockerfile, "&& : > /run/.containerenv")
			confirmationOffset := strings.Index(dockerfile, "LPECO_DISPOSABLE_FIXTURE=confirmed")
			if setupOffset < 0 {
				t.Fatal("Dockerfile does not run fixture setup")
			}
			if markerOffset < 0 || markerOffset > setupOffset {
				t.Fatal("Dockerfile must create /run/.containerenv before fixture setup")
			}
			if confirmationOffset < 0 || confirmationOffset > setupOffset {
				t.Fatal("Dockerfile must confirm the disposable fixture before setup")
			}
		})
	}
}

func TestTargetPersistentStateUnchanged(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "managed")
	if err := os.Mkdir(directory, 0o750); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "config.ini")
	if err := os.WriteFile(target, []byte("token=fixture-only\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	before := snapshotTree(t, root)
	processBefore := snapshotProcessIdentity(t, strconv.Itoa(os.Getpid()))
	managerBefore := snapshotProcessIdentity(t, "1")
	pid := strconv.Itoa(os.Getpid())
	definitions := append([]probe.Definition{}, contextcollect.Definitions()...)
	definitions = append(definitions,
		processcollect.EnvironmentDefinition(pid),
		processcollect.DependencyDefinition(pid),
		schedulercollect.Definition(),
		binarycollect.SudoersDefinition(),
		binarycollect.PrivilegedDefinition(root, 100),
		containercollect.SocketDefinition(),
		systemdcollect.ShowDefinition("system"),
		systemdcollect.ShowDefinition("user"),
		path.StatDefinition(target),
		path.ACLDefinition(target),
		path.MountInfoDefinition(),
	)
	packageCollector := packagecollect.Collector{MaxItems: packagecollect.DefaultMaxItems}
	ownershipPlan := packageCollector.PlanOwnership(model.HostProfile{}, []string{target}, adapter.Capabilities{MaxCommandBytes: 64 * 1024, MaxOutputBytes: 4 * 1024 * 1024})
	metadataPlan := packageCollector.PlanMetadata(model.HostProfile{}, []packagecollect.Request{{Manager: "dpkg", Package: "lpeco-fixture-nonexistent"}}, adapter.Capabilities{MaxCommandBytes: 64 * 1024, MaxOutputBytes: 4 * 1024 * 1024})
	definitions = append(definitions, ownershipPlan.Definitions...)
	definitions = append(definitions, metadataPlan.Definitions...)
	if _, err := exec.LookPath("objdump"); err == nil {
		definitions = append(definitions, binarycollect.ELFDefinition(target))
	}
	for _, definition := range definitions {
		if definition.SafetyClass != model.PassiveRead {
			t.Fatalf("probe %s safety = %s", definition.ID, definition.SafetyClass)
		}
		variant := definition.Variants[len(definition.Variants)-1]
		assertNoTargetEgressOrMutation(t, definition.ID, variant.Command.Script)
		command := exec.Command("sh", append([]string{"-c", variant.Command.Script, "lpeco"}, variant.Command.Args...)...)
		if _, err := command.CombinedOutput(); err != nil {
			t.Fatalf("probe %s failed: %v", definition.ID, err)
		}
		if current := snapshotTree(t, root); !reflect.DeepEqual(current, before) {
			t.Fatalf("probe %s changed persistent fixture state\nbefore: %#v\nafter:  %#v", definition.ID, before, current)
		}
		if current := snapshotProcessIdentity(t, strconv.Itoa(os.Getpid())); current != processBefore {
			t.Fatalf("probe %s changed test target process identity: before=%#v after=%#v", definition.ID, processBefore, current)
		}
		if current := snapshotProcessIdentity(t, "1"); current != managerBefore {
			t.Fatalf("probe %s changed service-manager process identity: before=%#v after=%#v", definition.ID, managerBefore, current)
		}
	}
	after := snapshotTree(t, root)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("persistent fixture state changed\nbefore: %#v\nafter:  %#v", before, after)
	}
}

type processIdentitySnapshot struct {
	PID        string
	StartTime  string
	Executable string
	UID        uint32
	GID        uint32
}

func snapshotProcessIdentity(t *testing.T, pid string) processIdentitySnapshot {
	t.Helper()
	statBody, err := os.ReadFile(filepath.Join("/proc", pid, "stat"))
	if err != nil {
		t.Fatal(err)
	}
	closing := strings.LastIndex(string(statBody), ") ")
	if closing < 0 {
		t.Fatalf("malformed /proc/%s/stat", pid)
	}
	fields := strings.Fields(string(statBody)[closing+2:])
	if len(fields) <= 19 {
		t.Fatalf("short /proc/%s/stat", pid)
	}
	executable, _ := os.Readlink(filepath.Join("/proc", pid, "exe"))
	info, err := os.Stat(filepath.Join("/proc", pid))
	if err != nil {
		t.Fatal(err)
	}
	value := processIdentitySnapshot{PID: pid, StartTime: fields[19], Executable: executable}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		value.UID, value.GID = stat.Uid, stat.Gid
	}
	return value
}

func assertNoTargetEgressOrMutation(t *testing.T, probeID, script string) {
	t.Helper()
	lower := strings.ToLower(script)
	for _, forbidden := range []string{
		"curl ", "wget ", "netcat ", "socat ", "ssh ", "ftp ", "/dev/tcp", "/dev/udp",
		"apt-get ", "apt update", "dnf ", "yum ", "apk add", "pip install",
		"systemctl start", "systemctl stop", "systemctl restart", "systemctl reload", "systemctl enable", "systemctl disable",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("probe %s contains target egress or mutation primitive %q", probeID, forbidden)
		}
	}
}

type fileSnapshot struct {
	Path       string
	Mode       fs.FileMode
	UID, GID   uint32
	Size       int64
	ContentSHA string
}

func snapshotTree(t *testing.T, root string) []fileSnapshot {
	t.Helper()
	var result []fileSnapshot
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := fileSnapshot{Path: path, Mode: info.Mode(), Size: info.Size()}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			value.UID, value.GID = stat.Uid, stat.Gid
		}
		if info.Mode().IsRegular() {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(content)
			value.ContentSHA = hex.EncodeToString(digest[:])
		}
		result = append(result, value)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result
}
