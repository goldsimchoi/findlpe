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

func TestVMPrepareRequiresDisposableGuard(t *testing.T) {
	script := filepath.Join("vm", "prepare.sh")
	command := exec.Command(script)
	command.Env = append(os.Environ(), "LPECO_VM_DISPOSABLE=")
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 64 {
		t.Fatalf("unguarded VM preparation = (%v, %q), want exit 64", err, output)
	}
	if !strings.Contains(string(output), "refusing VM preparation") {
		t.Fatalf("unguarded VM preparation output = %q", output)
	}
}

func TestVMPrepareRejectsBaseImageDigestMismatchWithoutArtifacts(t *testing.T) {
	root := t.TempDir()
	baseImage := filepath.Join(root, "base.img")
	if err := os.WriteFile(baseImage, []byte("not-a-cloud-image"), 0o600); err != nil {
		t.Fatal(err)
	}
	outputImage := filepath.Join(root, "prepared.qcow2")
	sshKey := filepath.Join(root, "id_ed25519")
	script := filepath.Join("vm", "prepare.sh")
	command := exec.Command(script)
	command.Env = append(os.Environ(),
		"LPECO_VM_DISPOSABLE=YES",
		"LPECO_VM_BASE_IMAGE="+baseImage,
		"LPECO_VM_BASE_SHA256="+strings.Repeat("0", 64),
		"LPECO_VM_IMAGE="+outputImage,
		"LPECO_VM_SSH_KEY="+sshKey,
		"LPECO_VM_SSH_USER=lpeco",
		"LPECO_VM_SSH_PORT=22222",
	)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 65 {
		t.Fatalf("mismatched VM base digest = (%v, %q), want exit 65", err, output)
	}
	if !strings.Contains(string(output), "base image checksum mismatch") {
		t.Fatalf("mismatched VM base digest output = %q", output)
	}
	for _, path := range []string{outputImage, sshKey, sshKey + ".pub"} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("failed preparation left artifact %s: %v", path, statErr)
		}
	}
}

func TestVMFixtureDocumentsVerifiedPreparation(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("vm", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"make prepare-vm",
		"LPECO_VM_BASE_IMAGE",
		"LPECO_VM_BASE_SHA256",
		"release-20260926",
	} {
		if !strings.Contains(string(readme), required) {
			t.Errorf("VM preparation documentation is missing %q", required)
		}
	}
	makefile, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(makefile), "prepare-vm:") {
		t.Error("Makefile is missing prepare-vm target")
	}
}

func TestVMPreparationDefersUserOwnedUnitSource(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("vm", "prepare.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(content)
	start := strings.Index(script, "path: /etc/systemd/system/lpeco-fixture.service.d/20-local.conf")
	if start < 0 {
		t.Fatal("VM preparation is missing the user-controlled unit drop-in")
	}
	entry := script[start:]
	if next := strings.Index(entry, "\n  - path:"); next >= 0 {
		entry = entry[:next]
	}
	if !strings.Contains(entry, "owner: ${LPECO_VM_SSH_USER}:${LPECO_VM_SSH_USER}") {
		t.Fatal("fixture unit drop-in is not owned by the scanning user")
	}
	if !strings.Contains(entry, "defer: true") {
		t.Fatal("new-user-owned write_files entry must be deferred until cloud-init final stage")
	}
}

func TestVMPreparationUsesNativeSocketActivationSemantics(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("vm", "prepare.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(content)
	start := strings.Index(script, "path: /etc/systemd/system/lpeco-fixture.socket")
	if start < 0 {
		t.Fatal("VM preparation is missing the socket activation unit")
	}
	entry := script[start:]
	if next := strings.Index(entry, "\n  - path:"); next >= 0 {
		entry = entry[:next]
	}
	if !strings.Contains(entry, "Service=lpeco-fixture.service") {
		t.Fatal("socket fixture must use systemd's Service= activation directive")
	}
	if strings.Contains(entry, "Unit=lpeco-fixture.service") {
		t.Fatal("socket fixture must not use the timer/path-only Unit= directive")
	}
	assertion, err := os.ReadFile(filepath.Join("vm", "assert.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(assertion), "--property=Triggers") {
		t.Fatal("VM assertion must verify the generic runtime activation relationship")
	}
}

func TestVMPreparationStartsActivationUnitsBeforeTheirService(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("vm", "prepare.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(content)
	start := strings.Index(script, "- [systemctl, start,")
	if start < 0 {
		t.Fatal("VM preparation is missing the activation start command")
	}
	line := script[start:]
	if end := strings.IndexByte(line, '\n'); end >= 0 {
		line = line[:end]
	}
	serviceOffset := strings.Index(line, "lpeco-fixture.service")
	if serviceOffset < 0 {
		t.Fatal("VM preparation does not start the target service")
	}
	for _, trigger := range []string{"lpeco-fixture.timer", "lpeco-fixture.socket", "lpeco-fixture.path"} {
		triggerOffset := strings.Index(line, trigger)
		if triggerOffset < 0 {
			t.Errorf("VM preparation does not start %s", trigger)
		} else if triggerOffset > serviceOffset {
			t.Errorf("VM preparation starts %s after its target service", trigger)
		}
	}
}

func TestVMFixtureGetfaclReportsBaseModeEntries(t *testing.T) {
	target := filepath.Join(t.TempDir(), "mode-fixture")
	if err := os.WriteFile(target, []byte("fixture\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(filepath.Join("vm", "fixture-getfacl"), "-cpn", "--", target)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture getfacl failed: %v: %s", err, output)
	}
	want := "user::rw-\ngroup::r--\nother::---\n"
	if string(output) != want {
		t.Fatalf("fixture getfacl output = %q, want %q", output, want)
	}
}

func TestVMPreparationInstallsAndChecksFixtureGetfacl(t *testing.T) {
	preparation, err := os.ReadFile(filepath.Join("vm", "prepare.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"fixture-getfacl", "path: /usr/local/bin/getfacl"} {
		if !strings.Contains(string(preparation), required) {
			t.Errorf("VM preparation does not install %q", required)
		}
	}
	assertion, err := os.ReadFile(filepath.Join("vm", "assert.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(assertion), "command -v getfacl") {
		t.Fatal("VM assertion does not verify the fixture ACL observer")
	}
}

func TestVMRunnerPinsAllAdvertisedHostKeysBeforeScanning(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("vm", "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(content)
	keyscanOffset := strings.Index(script, "ssh-keyscan")
	scanOffset := strings.Index(script, `"$LPECO_BINARY" scan ssh`)
	if keyscanOffset < 0 {
		t.Fatal("VM runner must collect every advertised SSH host key")
	}
	if scanOffset < 0 || keyscanOffset > scanOffset {
		t.Fatal("VM runner must pin host keys before launching LPECO")
	}
	strictOffset := strings.Index(script[keyscanOffset:scanOffset], "StrictHostKeyChecking=yes")
	if strictOffset < 0 {
		t.Fatal("VM runner must use strict host-key checking after key discovery")
	}
	if strings.Contains(script[keyscanOffset:scanOffset], "ssh_options+=( -o StrictHostKeyChecking=yes )") {
		t.Fatal("VM runner must replace accept-new options because OpenSSH keeps the first duplicate option value")
	}
	if !strings.Contains(script[keyscanOffset:scanOffset], "strict_ssh_options=(") {
		t.Fatal("VM runner must build a strict-only SSH option set after host-key discovery")
	}
}

func TestVMRunnerRejectsNonNumericSizingBeforeQEMU(t *testing.T) {
	for _, variable := range []string{"LPECO_VM_MEMORY_MB", "LPECO_VM_CPUS", "LPECO_VM_BOOT_TIMEOUT"} {
		t.Run(variable, func(t *testing.T) {
			root := t.TempDir()
			image := filepath.Join(root, "fixture.qcow2")
			key := filepath.Join(root, "id_ed25519")
			for _, path := range []string{image, key} {
				if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			stubDirectory := filepath.Join(root, "bin")
			if err := os.Mkdir(stubDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(root, "qemu-img-invoked")
			qemuImageStub := filepath.Join(stubDirectory, "qemu-img")
			if err := os.WriteFile(qemuImageStub, []byte("#!/bin/sh\n: > \"$LPECO_TEST_QEMU_MARKER\"\nexit 99\n"), 0o700); err != nil {
				t.Fatal(err)
			}

			command := exec.Command(filepath.Join("vm", "run.sh"))
			command.Env = []string{
				"PATH=" + stubDirectory + ":" + os.Getenv("PATH"),
				"LPECO_TEST_QEMU_MARKER=" + marker,
				"LPECO_VM_DISPOSABLE=YES",
				"LPECO_VM_IMAGE=" + image,
				"LPECO_VM_SSH_USER=lpeco",
				"LPECO_VM_SSH_KEY=" + key,
				"LPECO_VM_SSH_PORT=22222",
				"LPECO_BINARY=/bin/true",
				variable + "=1+1",
			}
			output, err := command.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 64 {
				t.Fatalf("invalid %s = (%v, %q), want exit 64", variable, err, output)
			}
			if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("invalid %s reached qemu-img: %v", variable, statErr)
			}
		})
	}
}

func TestVMCheckpointResolutionUsesLatestSuccessfulProbeState(t *testing.T) {
	checkpoint := `{
  "checkpoint": {
    "completed": {
      "recovered|attempt-0": {
        "probe_id": "systemd.cat.system.recovered.service",
        "status": "partial"
      },
      "recovered|attempt-1": {
        "probe_id": "systemd.cat.system.recovered.service",
        "status": "complete"
      },
      "unresolved|attempt-0": {
        "probe_id": "process.environment.1",
        "status": "unavailable"
      },
      "complete|attempt-0": {
        "probe_id": "context.current",
        "status": "complete"
      }
    }
  }
}`
	command := exec.Command("awk", "-f", filepath.Join("vm", "checkpoint-resolution.awk"))
	command.Stdin = strings.NewReader(checkpoint)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("checkpoint resolution failed: %v: %s", err, output)
	}
	lines := strings.FieldsFunc(strings.TrimSpace(string(output)), func(r rune) bool { return r == '\n' })
	sort.Strings(lines)
	want := []string{
		"recovered\tsystemd.cat.system.recovered.service",
		"unresolved\tprocess.environment.1",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Fatalf("checkpoint resolution = %#v, want %#v", lines, want)
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
