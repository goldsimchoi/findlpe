package graph

import (
	"testing"

	binarycollect "github.com/normalone/lpeco/internal/collect/binary"
	containercollect "github.com/normalone/lpeco/internal/collect/container"
	schedulercollect "github.com/normalone/lpeco/internal/collect/scheduler"
	"github.com/normalone/lpeco/internal/model"
)

func TestGraphBuildsFallbackConsumerRelationships(t *testing.T) {
	facts := []model.Fact{
		makeFact(t, "identity", "context", "e-identity", model.ConfidenceHigh, map[string]any{"uids": [4]int{1000, 1000, 1000, 1000}, "gids": [4]int{1000, 1000, 1000, 1000}, "groups": []int{1000}}),
		makeFact(t, "schedule", "scheduler", "e-schedule", model.ConfidenceHigh, schedulercollect.ScheduleFact{Kind: "cron", SourcePath: "/etc/cron.d/demo", User: "root", Schedule: "* * * * *", Command: "/opt/demo/job.sh", Interpreter: "/bin/sh", Script: "/opt/demo/job.sh", Active: true, EvidenceIDs: []string{"e-schedule"}, Confidence: model.ConfidenceHigh}),
		makeFact(t, "privileged_binary", "binary", "e-binary", model.ConfidenceHigh, binarycollect.PrivilegedBinaryFact{Path: "/opt/demo/helper", UID: 0, GID: 0, SUID: true, Capabilities: []string{"cap_setuid=ep"}, EvidenceIDs: []string{"e-binary"}, Confidence: model.ConfidenceHigh}),
		makeFact(t, "binary_dependency", "binary", "e-loader", model.ConfidenceHigh, binarycollect.DependencyFact{ConsumerPath: "/opt/demo/helper", Kind: "runpath", Target: "/opt/demo/lib", Resolved: true, EvidenceIDs: []string{"e-loader"}, Confidence: model.ConfidenceHigh}),
		makeFact(t, "delegation", "binary", "e-sudo", model.ConfidenceHigh, binarycollect.DelegationFact{RunAs: "root", Command: "/usr/bin/systemctl restart demo", SourceKind: "sudo-list", EvidenceIDs: []string{"e-sudo"}, Confidence: model.ConfidenceHigh}),
		makeFact(t, "admin_socket", "container", "e-socket", model.ConfidenceHigh, containercollect.AdminSocketFact{Path: "/run/docker.sock", Daemon: "docker", DaemonUID: 0, WriteAccess: true, EvidenceIDs: []string{"e-socket"}, Confidence: model.ConfidenceHigh}),
	}
	g, diagnostics := Build(facts)
	if hasDiagnosticCode(diagnostics, "build-error") {
		t.Fatalf("build diagnostics = %#v", diagnostics)
	}
	if len(g.NodesByKind(model.NodeTrigger)) != 1 || len(g.NodesByKind(model.NodeSocket)) != 1 {
		t.Fatalf("fallback nodes missing: triggers=%d sockets=%d", len(g.NodesByKind(model.NodeTrigger)), len(g.NodesByKind(model.NodeSocket)))
	}
	current, _ := g.CurrentPrincipal()
	assertEdgeKind(t, g, current, model.EdgeCanExecute)
	assertEdgeKind(t, g, current, model.EdgeCanWrite)
	foundLoader := false
	for _, executable := range g.NodesByKind(model.NodeExecutable) {
		if len(g.Outgoing(executable.NodeRef, model.EdgeResolvesThrough)) > 0 {
			foundLoader = true
		}
	}
	if !foundLoader {
		t.Fatal("resolved loader search path edge missing")
	}
}

func assertEdgeKind(t *testing.T, g *Graph, from model.NodeRef, kind model.EdgeKind) {
	t.Helper()
	if len(g.Outgoing(from, kind)) == 0 {
		t.Fatalf("%s edge from %s missing", kind, from.ID)
	}
}
