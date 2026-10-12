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

	binarycollect "github.com/normalone/lpeco/internal/collect/binary"
	containercollect "github.com/normalone/lpeco/internal/collect/container"
	contextcollect "github.com/normalone/lpeco/internal/collect/context"
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
	pid := strconv.Itoa(os.Getpid())
	definitions := append([]probe.Definition{}, contextcollect.Definitions()...)
	definitions = append(definitions,
		processcollect.EnvironmentDefinition(pid),
		processcollect.DependencyDefinition(pid),
		schedulercollect.Definition(),
		binarycollect.SudoersDefinition(),
		binarycollect.PrivilegedDefinition(root, 100),
		binarycollect.PackageDefinition(target),
		containercollect.SocketDefinition(),
		systemdcollect.ShowDefinition("system"),
		systemdcollect.ShowDefinition("user"),
		path.StatDefinition(target),
		path.ACLDefinition(target),
		path.MountInfoDefinition(),
	)
	if _, err := exec.LookPath("objdump"); err == nil {
		definitions = append(definitions, binarycollect.ELFDefinition(target))
	}
	for _, definition := range definitions {
		if definition.SafetyClass != model.PassiveRead {
			t.Fatalf("probe %s safety = %s", definition.ID, definition.SafetyClass)
		}
		variant := definition.Variants[len(definition.Variants)-1]
		command := exec.Command("sh", append([]string{"-c", variant.Command.Script, "lpeco"}, variant.Command.Args...)...)
		if _, err := command.CombinedOutput(); err != nil {
			t.Fatalf("probe %s failed: %v", definition.ID, err)
		}
	}
	after := snapshotTree(t, root)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("persistent fixture state changed\nbefore: %#v\nafter:  %#v", before, after)
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
