package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/normalone/lpeco/internal/adapter/raw"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/vulndb"
)

func TestConfiguredCollectorsRegisterBoundedPackageInfoAfterBinary(t *testing.T) {
	collectors := configuredCollectors(CommonOptions{})
	ids := make([]string, 0, len(collectors))
	for _, collector := range collectors {
		ids = append(ids, collector.ID())
	}
	want := []string{"context", "process", "systemd", "path", "scheduler", "binary", "packageinfo", "container"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("configured collector order = %#v, want %#v", ids, want)
	}
}

func TestParseRejectsPublicRawBindWithoutExplicitGate(t *testing.T) {
	_, err := Parse([]string{"listen", "raw", "--bind", "0.0.0.0:4444"})
	if !errors.Is(err, raw.ErrPublicBindDenied) {
		t.Fatalf("Parse error = %v, want ErrPublicBindDenied", err)
	}
	configuration, err := Parse([]string{"listen", "raw", "--bind", "0.0.0.0:4444", "--allow-public-bind"})
	if err != nil || !configuration.Raw.AllowPublicBind {
		t.Fatalf("explicit public bind = (%#v, %v)", configuration, err)
	}
}

func TestSSHDefaultsToHostKeyVerificationAndNeverStoresPassword(t *testing.T) {
	configuration, err := Parse([]string{"scan", "ssh", "server.test", "--user", "alice", "--ask-password"})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.SSH.InsecureIgnoreHostKey || !configuration.SSH.AskPassword {
		t.Fatalf("SSH configuration = %#v", configuration.SSH)
	}
	if _, err := Parse([]string{"scan", "ssh", "server.test", "--user", "alice", "--password", "hunter2"}); err == nil {
		t.Fatal("plaintext password flag was accepted")
	}
}

func TestObservableReadRequiresExplicitFlag(t *testing.T) {
	without, err := Parse([]string{"scan", "bridge", "--adapter", "agent --stdio"})
	if err != nil {
		t.Fatal(err)
	}
	with, err := Parse([]string{"scan", "bridge", "--adapter", "agent --stdio", "--observable-read"})
	if err != nil {
		t.Fatal(err)
	}
	if without.Common.ObservableRead || !with.Common.ObservableRead {
		t.Fatalf("observable flags = %v/%v", without.Common.ObservableRead, with.Common.ObservableRead)
	}
}

func TestParseRejectsInvalidDurationProtocolAndReportFormat(t *testing.T) {
	for _, arguments := range [][]string{
		{"listen", "raw", "--bind", "127.0.0.1:4444", "--accept-timeout", "later"},
		{"scan", "bridge", "--adapter", "agent", "--protocol", "telnet"},
		{"report", "session-one", "--format", "yaml"},
		{"scan", "ssh", "server.test", "--user", "alice", "--observe", "-1s"},
	} {
		if _, err := Parse(arguments); err == nil {
			t.Fatalf("Parse(%#v) succeeded", arguments)
		}
	}
}

func TestParseCommonScanControls(t *testing.T) {
	configuration, err := Parse([]string{"scan", "bridge", "--adapter", "agent --stdio", "--state-dir", "/tmp/state", "--observe", "5s", "--full", "--scan-root", "/opt", "--exclude", "/opt/cache", "--max-output", "8192"})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.Common.StateDir != "/tmp/state" || configuration.Common.Observe.String() != "5s" || !configuration.Common.Full || configuration.Common.MaxOutput != 8192 {
		t.Fatalf("common configuration = %#v", configuration.Common)
	}
	if got := scanOptions(configuration, "session").ProcessObservation; got != 5*time.Second {
		t.Fatalf("orchestrator observation = %s, want 5s", got)
	}
}

func TestParseVulnerabilityModesAndExplicitSnapshot(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		wantMode  model.VulnerabilityMode
		wantDB    string
		wantError bool
	}{
		{name: "default auto", arguments: []string{"scan", "bridge", "--adapter", "agent"}, wantMode: model.VulnerabilityModeAuto},
		{name: "explicit off", arguments: []string{"scan", "bridge", "--adapter", "agent", "--vuln-mode", "off"}, wantMode: model.VulnerabilityModeOff},
		{name: "explicit required", arguments: []string{"scan", "bridge", "--adapter", "agent", "--vuln-mode", "required"}, wantMode: model.VulnerabilityModeRequired},
		{name: "snapshot implies required", arguments: []string{"scan", "bridge", "--adapter", "agent", "--vuln-db", "/tmp/sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, wantMode: model.VulnerabilityModeRequired, wantDB: "/tmp/sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{name: "snapshot conflicts with off", arguments: []string{"scan", "bridge", "--adapter", "agent", "--vuln-mode", "off", "--vuln-db", "/tmp/snapshot"}, wantError: true},
		{name: "invalid mode", arguments: []string{"scan", "bridge", "--adapter", "agent", "--vuln-mode", "sometimes"}, wantError: true},
		{name: "resume parity", arguments: []string{"resume", "session-one", "--transport", "bridge", "--adapter", "agent", "--vuln-mode", "required", "--vuln-db", "/tmp/snapshot"}, wantMode: model.VulnerabilityModeRequired, wantDB: "/tmp/snapshot"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configuration, err := Parse(test.arguments)
			if (err != nil) != test.wantError {
				t.Fatalf("Parse(%#v) error = %v, wantError %v", test.arguments, err, test.wantError)
			}
			if test.wantError {
				return
			}
			if configuration.Vulnerability.Mode != test.wantMode || configuration.Vulnerability.SnapshotDir != test.wantDB {
				t.Fatalf("vulnerability options = %#v, want mode=%q db=%q", configuration.Vulnerability, test.wantMode, test.wantDB)
			}
		})
	}
}

func TestParseVulnerabilityDatabaseCommandsAndUsage(t *testing.T) {
	syncConfiguration, err := Parse([]string{"vuln-db", "sync", "--provider", "ubuntu", "--db-dir", "/tmp/lpeco-db"})
	if err != nil {
		t.Fatal(err)
	}
	if syncConfiguration.Mode != ModeVulnDBSync || syncConfiguration.Vulnerability.Provider != "ubuntu" || syncConfiguration.Vulnerability.DatabaseDir != "/tmp/lpeco-db" {
		t.Fatalf("sync configuration = %#v", syncConfiguration)
	}
	statusConfiguration, err := Parse([]string{"vuln-db", "status", "--db-dir", "/tmp/lpeco-db"})
	if err != nil {
		t.Fatal(err)
	}
	if statusConfiguration.Mode != ModeVulnDBStatus || statusConfiguration.Vulnerability.DatabaseDir != "/tmp/lpeco-db" {
		t.Fatalf("status configuration = %#v", statusConfiguration)
	}
	for _, arguments := range [][]string{
		{"vuln-db"},
		{"vuln-db", "sync", "--provider", "debian"},
		{"vuln-db", "sync", "extra"},
		{"vuln-db", "status", "extra"},
		{"vuln-db", "status", "--source-url", "https://example.invalid"},
	} {
		if _, err := Parse(arguments); err == nil {
			t.Fatalf("Parse(%#v) succeeded", arguments)
		}
	}
	usage := Usage()
	for _, fragment := range []string{"vuln-db sync", "vuln-db status", "--vuln-mode auto|off|required", "--vuln-db <snapshot-dir>"} {
		if !strings.Contains(usage, fragment) {
			t.Fatalf("usage missing %q:\n%s", fragment, usage)
		}
	}
}

func TestResolveVulnerabilityInputHonorsOffExplicitAndPinnedResume(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	first := cliTestSnapshot(t, "CVE-2099-2001", now)
	firstReference, err := vulndb.Publish(context.Background(), root, first)
	if err != nil {
		t.Fatal(err)
	}
	firstDirectory := root + "/sha256-" + firstReference.Digest

	off := resolveNewVulnerability(context.Background(), VulnerabilityOptions{Mode: model.VulnerabilityModeOff, SnapshotDir: "/does/not/exist"}, now)
	if off.Mode != model.VulnerabilityModeOff || off.Snapshot != nil || off.LoadError != nil {
		t.Fatalf("off input = %#v", off)
	}
	explicit := resolveNewVulnerability(context.Background(), VulnerabilityOptions{Mode: model.VulnerabilityModeRequired, SnapshotDir: firstDirectory}, now)
	if explicit.LoadError != nil || explicit.Snapshot == nil || explicit.Snapshot.Manifest.Digest != firstReference.Digest || !explicit.Explicit {
		t.Fatalf("explicit input = %#v", explicit)
	}

	second := cliTestSnapshot(t, "CVE-2099-2002", now.Add(time.Minute))
	secondReference, err := vulndb.Publish(context.Background(), root, second)
	if err != nil {
		t.Fatal(err)
	}
	if secondReference.Digest == firstReference.Digest {
		t.Fatal("test snapshots unexpectedly share a digest")
	}
	session := model.Session{SchemaVersion: model.SessionSchemaVersion, Vulnerability: model.VulnerabilityCoverage{
		Mode: model.VulnerabilityModeAuto, Snapshot: model.SnapshotReference{
			Provider: firstReference.Provider, SchemaVersion: firstReference.SchemaVersion, Digest: firstReference.Digest, ImpactCatalogDigest: firstReference.ImpactCatalogDigest,
		},
	}}
	pinned := resolveResumeVulnerability(context.Background(), VulnerabilityOptions{Mode: model.VulnerabilityModeAuto, DatabaseDir: root}, session, now.Add(time.Hour))
	if pinned.LoadError != nil || pinned.Snapshot == nil || pinned.Snapshot.Manifest.Digest != firstReference.Digest {
		t.Fatalf("pinned resume input = %#v", pinned)
	}
}

func TestVulnerabilityDatabaseStatusIsLocalAndComplete(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	root := t.TempDir()
	snapshot := cliTestSnapshot(t, "CVE-2099-2003", now.Add(-time.Hour))
	reference, err := vulndb.Publish(context.Background(), root, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := runVulnerabilityDatabaseStatus(context.Background(), VulnerabilityOptions{DatabaseDir: root}, &output, now); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, fragment := range []string{
		"integrity: valid", "provider: ubuntu", "schema: 1", "digest: " + reference.Digest,
		"stale: false", "supported_releases:", "advisory_count: 1", "impact_catalog_digest:", "sources:",
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("status missing %q:\n%s", fragment, text)
		}
	}
}

func TestVulnerabilityDatabaseExecuteExitCodes(t *testing.T) {
	original := syncVulnerabilityDatabase
	t.Cleanup(func() { syncVulnerabilityDatabase = original })
	syncVulnerabilityDatabase = func(context.Context, vulndb.SyncConfig) (model.SnapshotReference, error) {
		return model.SnapshotReference{}, errors.New("offline")
	}
	var stdout, stderr bytes.Buffer
	configuration := Config{Mode: ModeVulnDBSync, Vulnerability: VulnerabilityOptions{Provider: "ubuntu", DatabaseDir: t.TempDir()}}
	if code := executeVulnerabilityDatabase(context.Background(), configuration, &stdout, &stderr); code != ExitOperation {
		t.Fatalf("sync exit = %d, want %d", code, ExitOperation)
	}
	if !strings.Contains(stderr.String(), "offline") {
		t.Fatalf("sync stderr = %q", stderr.String())
	}
	if code := Execute(context.Background(), []string{"vuln-db", "sync", "--provider", "debian"}, nil, &stdout, &stderr); code != ExitUsage {
		t.Fatalf("parse exit = %d, want %d", code, ExitUsage)
	}
}

func cliTestSnapshot(t *testing.T, cve string, retrievedAt time.Time) vulndb.Snapshot {
	t.Helper()
	policy, err := vulndb.LoadUbuntuReleasePolicy()
	if err != nil {
		t.Fatal(err)
	}
	annotations, _, err := vulndb.LoadImpactCatalog()
	if err != nil {
		t.Fatal(err)
	}
	normalizer := vulndb.NewUbuntuNormalizer(policy, annotations)
	document := fmt.Sprintf(`{
		"schema_version":"1.7.0","id":"UBUNTU-%[1]s","upstream":["%[1]s"],"modified":"2026-10-13T20:00:00Z",
		"affected":[{"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"demo-source","purl":"pkg:deb/ubuntu/demo-source@1.0-2?arch=source&distro=jammy"},
		"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0-2"}]}],"versions":["1.0-1"],
		"ecosystem_specific":{"binaries":[{"binary_name":"demo","binary_version":"1.0-2"}],"availability":"No subscription required"}}],
		"references":[{"type":"REPORT","url":"https://ubuntu.com/security/%[1]s"}]}`, cve)
	if err := normalizer.AddOSV(cve+".json", strings.NewReader(document)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := normalizer.Snapshot(retrievedAt, []vulndb.Source{{Kind: "ubuntu-osv", URL: vulndb.UbuntuOSVURL, ProviderModifiedAt: retrievedAt.Add(-time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
