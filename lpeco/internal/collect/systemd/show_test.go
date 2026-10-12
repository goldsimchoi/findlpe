package systemd

import (
	"os"
	"reflect"
	"testing"
)

func TestParseShowCoversRuntimeStatesManagersAndExecutionContext(t *testing.T) {
	units, diagnostics := ParseShow(readSystemdFixture(t, "../../../testdata/systemd/show/full.txt"), "evidence-show")
	if len(diagnostics) != 0 {
		t.Fatalf("ParseShow diagnostics: %#v", diagnostics)
	}
	if len(units) != 7 {
		t.Fatalf("unit count = %d, want 7", len(units))
	}
	demo := runtimeUnitByName(t, units, "demo.service")
	if demo.Manager != "system" || demo.LoadState != "loaded" || demo.ActiveState != "active" || demo.MainPID != 101 || demo.ControlGroup != "/system.slice/demo.service" {
		t.Fatalf("demo runtime = %#v", demo)
	}
	if demo.User != "root" || demo.UID != 0 || demo.Restart != "always" || !demo.NoNewPrivileges {
		t.Fatalf("demo execution/security = %#v", demo)
	}
	if !reflect.DeepEqual(demo.EnvironmentFiles, []string{"/etc/default/demo"}) || !reflect.DeepEqual(demo.ExecSearchPath, []string{"/opt/demo/bin", "/usr/bin"}) {
		t.Fatalf("demo paths = %#v/%#v", demo.EnvironmentFiles, demo.ExecSearchPath)
	}
	if demo.RuntimeExec["ExecStart"].Executable != "/usr/bin/runtime-demo" || demo.RuntimeExec["ExecStart"].Arguments[0] != "--serve" {
		t.Fatalf("runtime ExecStart = %#v", demo.RuntimeExec["ExecStart"])
	}
	if runtimeUnitByName(t, units, "failed.service").ActiveState != "failed" || runtimeUnitByName(t, units, "ones.service").Type != "oneshot" {
		t.Fatalf("failed/oneshot states were not retained")
	}
	user := runtimeUnitByName(t, units, "user-demo.service")
	if user.Manager != "user" || user.ManagerUID != 1000 || user.UID != 1000 {
		t.Fatalf("user manager runtime = %#v", user)
	}
}

func TestParseShowTruncationReturnsPartialUnitAndDiagnostic(t *testing.T) {
	units, diagnostics := ParseShow(readSystemdFixture(t, "../../../testdata/systemd/show/truncated.txt"), "evidence-truncated")
	if len(units) != 1 || units[0].Name != "partial.service" || len(units[0].MissingFacts) == 0 {
		t.Fatalf("partial units = %#v", units)
	}
	if len(diagnostics) == 0 || diagnostics[0].Code != "truncated-unit" {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
}

func runtimeUnitByName(t *testing.T, units []RuntimeUnit, name string) RuntimeUnit {
	t.Helper()
	for _, unit := range units {
		if unit.Name == name {
			return unit
		}
	}
	t.Fatalf("runtime unit %q not found", name)
	return RuntimeUnit{}
}

func readSystemdFixture(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return value
}
