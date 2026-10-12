package cli

import (
	"errors"
	"testing"

	"github.com/normalone/lpeco/internal/adapter/raw"
)

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
}
