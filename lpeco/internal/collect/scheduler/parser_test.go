package scheduler

import (
	"os"
	"testing"

	"github.com/normalone/lpeco/internal/model"
)

func TestParseSystemAndUserCronWithExecutionChains(t *testing.T) {
	system := ParseCron("/etc/crontab", "root", true, readFixture(t, "../../../testdata/fallback/cron/system.cron"), "e-cron-system")
	if len(system) != 2 {
		t.Fatalf("system schedules = %#v", system)
	}
	if system[0].User != "root" || system[0].Interpreter != "/usr/bin/python3" || system[0].Script != "/opt/jobs/root.py" || !system[0].Active {
		t.Fatalf("system cron fact = %#v", system[0])
	}
	if system[1].Schedule != "@reboot" || system[1].User != "backup" || system[1].Script != "/opt/backup.sh" {
		t.Fatalf("macro cron fact = %#v", system[1])
	}

	user := ParseCron("/var/spool/cron/crontabs/alice", "alice", false, readFixture(t, "../../../testdata/fallback/cron/user.cron"), "e-cron-user")
	if len(user) != 1 || user[0].User != "alice" || user[0].Script != "/home/alice/bin/job.sh" {
		t.Fatalf("user cron facts = %#v", user)
	}
}

func TestPeriodicAndSysVProduceActiveInterpreterChains(t *testing.T) {
	periodic := ParsePeriodic("/etc/cron.daily/cleanup", "root", "@daily", readFixture(t, "../../../testdata/fallback/cron/periodic.sh"), "e-periodic")
	if periodic.Kind != "periodic" || periodic.Interpreter != "/bin/sh" || periodic.Script != "/etc/cron.daily/cleanup" || !periodic.Active {
		t.Fatalf("periodic fact = %#v", periodic)
	}
	links, diagnostics := ParseSysV(readFixture(t, "../../../testdata/fallback/sysv/links.txt"), "e-sysv")
	if len(diagnostics) != 0 || len(links) != 2 {
		t.Fatalf("sysv = %#v, %#v", links, diagnostics)
	}
	if links[0].Kind != "sysv" || links[0].Script != "/etc/init.d/legacy" || links[0].Interpreter != "/bin/sh" || !links[0].Active {
		t.Fatalf("sysv fact = %#v", links[0])
	}
	if len(links[0].EvidenceIDs) == 0 || links[0].Confidence != model.ConfidenceHigh {
		t.Fatalf("sysv evidence = %#v", links[0])
	}
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return value
}
