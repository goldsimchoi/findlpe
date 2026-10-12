package systemdunit

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadPathRankMatchesSystemdPrecedence(t *testing.T) {
	paths := []string{
		"/etc/systemd/system/demo.service",
		"/run/systemd/system/demo.service",
		"/usr/lib/systemd/system/demo.service",
		"/lib/systemd/system/demo.service",
	}
	var ranks []int
	for _, path := range paths {
		ranks = append(ranks, LoadPathRank(path))
	}
	if !(ranks[0] > ranks[1] && ranks[1] > ranks[2] && ranks[2] > ranks[3]) {
		t.Fatalf("load path ranks = %#v", ranks)
	}
}

func TestMergeAppliesDropInPrecedenceResetAndProvenance(t *testing.T) {
	documents := []Document{
		parseFixtureAt(t, "../../testdata/systemd/unit/debian/demo.service", "/usr/lib/systemd/system/demo.service", "ev-fragment"),
		parseFixtureAt(t, "../../testdata/systemd/unit/dropins/10-base-vendor.conf", "/usr/lib/systemd/system/demo.service.d/10-base.conf", "ev-vendor-dropin"),
		parseFixtureAt(t, "../../testdata/systemd/unit/dropins/10-base-run.conf", "/run/systemd/system/demo.service.d/10-base.conf", "ev-run-dropin"),
		parseFixtureAt(t, "../../testdata/systemd/unit/dropins/20-local.conf", "/etc/systemd/system/demo.service.d/20-local.conf", "ev-local-dropin"),
	}
	effective := Merge(LoadContext{UnitName: "demo.service"}, documents)
	if got := effective.Scalar("Service", "User"); got == nil || got.Value != "root" || got.Source.EvidenceID != "ev-local-dropin" {
		t.Fatalf("effective User = %#v", got)
	}
	execValues := effective.Values("Service", "ExecStart")
	if len(execValues) != 1 || execValues[0].Value != "/opt/demo/bin/run --foreground" || execValues[0].Source.Line != 4 {
		t.Fatalf("effective ExecStart = %#v", execValues)
	}
	environmentFiles := effective.Values("Service", "EnvironmentFile")
	wantEnvironmentFiles := []string{"/etc/default/demo", "/run/demo.env"}
	var gotEnvironmentFiles []string
	for _, value := range environmentFiles {
		gotEnvironmentFiles = append(gotEnvironmentFiles, value.Value)
	}
	if !reflect.DeepEqual(gotEnvironmentFiles, wantEnvironmentFiles) {
		t.Fatalf("EnvironmentFile = %#v, want %#v", gotEnvironmentFiles, wantEnvironmentFiles)
	}
	if len(effective.Resets) != 1 || effective.Resets[0].Key != "ExecStart" {
		t.Fatalf("reset provenance = %#v", effective.Resets)
	}
}

func TestDropInApplicabilityHandlesTypeTemplateInstanceAndAlias(t *testing.T) {
	context := LoadContext{UnitName: "demo@blue.service", Aliases: []string{"alias.service"}}
	tests := []struct {
		path            string
		wantApplicable  bool
		wantSpecificity int
	}{
		{path: "/etc/systemd/system/service.d/10.conf", wantApplicable: true, wantSpecificity: 0},
		{path: "/etc/systemd/system/demo@.service.d/10.conf", wantApplicable: true, wantSpecificity: 2},
		{path: "/etc/systemd/system/demo@blue.service.d/10.conf", wantApplicable: true, wantSpecificity: 3},
		{path: "/etc/systemd/system/alias.service.d/10.conf", wantApplicable: true, wantSpecificity: 3},
		{path: "/etc/systemd/system/other.service.d/10.conf", wantApplicable: false},
	}
	for _, tt := range tests {
		applicable, specificity := DropInApplicability(context, tt.path)
		if applicable != tt.wantApplicable || applicable && specificity != tt.wantSpecificity {
			t.Fatalf("DropInApplicability(%q) = %v/%d, want %v/%d", tt.path, applicable, specificity, tt.wantApplicable, tt.wantSpecificity)
		}
	}
}

func parseFixtureAt(t *testing.T, fixture, path, evidenceID string) Document {
	t.Helper()
	content, err := os.ReadFile(filepath.Clean(fixture))
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixture, err)
	}
	document, diagnostics := Parse(Source{Path: path, EvidenceID: evidenceID, Content: content})
	if len(diagnostics) != 0 {
		t.Fatalf("parse fixture %s diagnostics: %#v", fixture, diagnostics)
	}
	return document
}
