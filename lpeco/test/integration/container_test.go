//go:build integration

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestContainerFixtures(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("container integration prerequisite: docker: %v", err)
	}
	root := integrationModuleRoot(t)
	contextDirectory := t.TempDir()
	binary := filepath.Join(contextDirectory, "lpeco")
	build := exec.Command("go", "build", "-trimpath", "-o", binary, "./cmd/lpeco")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture binary: %v\n%s", err, output)
	}
	copyFixtureFile(t, filepath.Join(root, "test", "integration", "container", "fixture.sh"), filepath.Join(contextDirectory, "fixture.sh"), 0o755)

	for _, fixture := range []string{"debian", "alpine"} {
		t.Run(fixture, func(t *testing.T) {
			tag := fmt.Sprintf("lpeco-integration-%s-%d-%d", fixture, os.Getpid(), time.Now().UnixNano())
			dockerfile := filepath.Join(root, "test", "integration", "container", "Dockerfile."+fixture)
			buildImage := exec.Command("docker", "build", "--pull", "-f", dockerfile, "-t", tag, contextDirectory)
			if output, err := buildImage.CombinedOutput(); err != nil {
				t.Fatalf("build %s fixture image: %v\n%s", fixture, err, output)
			}
			t.Cleanup(func() {
				_ = exec.Command("docker", "image", "rm", "-f", tag).Run()
			})
			run := exec.Command("docker", "run", "--rm", "--network", "none", "--tmpfs", "/tmp:mode=1777", "--tmpfs", "/run:mode=755", tag, "verify")
			output, err := run.CombinedOutput()
			if err != nil {
				t.Fatalf("run %s fixture: %v\n%s", fixture, err, output)
			}
			if !strings.Contains(string(output), "persistent-state=unchanged") {
				t.Fatalf("fixture did not attest persistent state: %s", output)
			}
		})
	}
}

func integrationModuleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve integration test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func copyFixtureFile(t *testing.T, source, destination string, mode os.FileMode) {
	t.Helper()
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, content, mode); err != nil {
		t.Fatal(err)
	}
}
