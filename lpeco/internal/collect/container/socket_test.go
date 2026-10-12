package container

import (
	"os"
	"strings"
	"testing"

	"github.com/normalone/lpeco/internal/model"
)

func TestAdminSocketRequiresObservedWriteAccessNotGroupName(t *testing.T) {
	input, err := os.ReadFile("../../../testdata/fallback/sockets/inventory.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	facts, diagnostics := ParseSocketInventory(input, "e-socket")
	if len(diagnostics) != 0 || len(facts) != 1 {
		t.Fatalf("socket facts = %#v, %#v", facts, diagnostics)
	}
	if facts[0].Path != "/run/docker.sock" || facts[0].Daemon != "docker" || !facts[0].WriteAccess || facts[0].DaemonUID != 0 {
		t.Fatalf("admin socket = %#v", facts[0])
	}
	if len(facts[0].EvidenceIDs) == 0 || facts[0].Confidence != model.ConfidenceHigh {
		t.Fatalf("socket evidence = %#v", facts[0])
	}
	definition := SocketDefinition()
	if definition.SafetyClass != model.PassiveRead || strings.Contains(definition.Variants[0].Command.Script, "connect") {
		t.Fatalf("socket probe is not a passive access check: %#v", definition)
	}
}
