//go:build vm_integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestDisposableVMFixture(t *testing.T) {
	for _, variable := range []string{"LPECO_VM_DISPOSABLE", "LPECO_VM_IMAGE", "LPECO_VM_SSH_USER", "LPECO_VM_SSH_KEY", "LPECO_VM_SSH_PORT"} {
		if os.Getenv(variable) == "" {
			t.Fatalf("VM setup error: %s is required; see test/integration/vm/README.md", variable)
		}
	}
	if os.Getenv("LPECO_VM_DISPOSABLE") != "YES" {
		t.Fatal("VM setup error: LPECO_VM_DISPOSABLE must be exactly YES")
	}
	root := vmModuleRoot(t)
	binary := filepath.Join(t.TempDir(), "lpeco")
	build := exec.Command("go", "build", "-trimpath", "-o", binary, "./cmd/lpeco")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build VM fixture binary: %v\n%s", err, output)
	}
	runner := filepath.Join(root, "test", "integration", "vm", "run.sh")
	command := exec.Command(runner)
	command.Dir = root
	command.Env = append(os.Environ(), "LPECO_BINARY="+binary)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("run disposable VM fixture: %v\n%s", err, output)
	} else {
		t.Log(string(output))
	}
}

func vmModuleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve VM test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
