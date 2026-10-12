package scheduler

import (
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

const schedulerScript = `printf 'LPECO_SCHEDULER_V1\n'
_lpeco_hex() { od -An -v -tx1 "$1" 2>/dev/null | tr -d ' \n'; }
_lpeco_text_hex() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
for _lpeco_file in /etc/crontab /etc/cron.d/*; do
  [ -f "$_lpeco_file" ] || continue
  printf 'CRON_SYSTEM\t%s\t%s\t%s\n' "$(_lpeco_text_hex "$_lpeco_file")" "$(_lpeco_text_hex root)" "$(_lpeco_hex "$_lpeco_file")"
done
for _lpeco_file in /var/spool/cron/crontabs/* /var/spool/cron/*; do
  [ -f "$_lpeco_file" ] || continue
  _lpeco_user=${_lpeco_file##*/}
  printf 'CRON_USER\t%s\t%s\t%s\n' "$(_lpeco_text_hex "$_lpeco_file")" "$(_lpeco_text_hex "$_lpeco_user")" "$(_lpeco_hex "$_lpeco_file")"
done
for _lpeco_pair in hourly:/etc/cron.hourly daily:/etc/cron.daily weekly:/etc/cron.weekly monthly:/etc/cron.monthly; do
  _lpeco_schedule=@${_lpeco_pair%%:*}; _lpeco_dir=${_lpeco_pair#*:}
  for _lpeco_file in "$_lpeco_dir"/*; do
    [ -f "$_lpeco_file" ] || continue
    printf 'PERIODIC\t%s\t%s\t%s\t%s\n' "$(_lpeco_text_hex "$_lpeco_file")" "$(_lpeco_text_hex root)" "$(_lpeco_text_hex "$_lpeco_schedule")" "$(_lpeco_hex "$_lpeco_file")"
  done
done
for _lpeco_link in /etc/rc?.d/S*; do
  [ -L "$_lpeco_link" ] || continue
  _lpeco_target=$(readlink -f -- "$_lpeco_link" 2>/dev/null) || continue
  _lpeco_shebang=$(sed -n '1p' "$_lpeco_target" 2>/dev/null)
  printf 'SYSV\t%s\t%s\t%s\n' "$(_lpeco_text_hex "$_lpeco_link")" "$(_lpeco_text_hex "$_lpeco_target")" "$(_lpeco_text_hex "$_lpeco_shebang")"
done`

func Definition() probe.Definition {
	return probe.Definition{
		ID: "scheduler.inventory", Collector: "scheduler", Parser: "scheduler-v1", RedactionPolicy: "paths", SafetyClass: model.PassiveRead,
		Variants: []probe.Variant{{ID: "posix", Command: adapter.Command{Script: schedulerScript}}},
		Timeout:  20 * time.Second, MaxOutput: 8 * 1024 * 1024, Produces: []string{"schedule"}, Idempotent: true,
	}
}

type Collector struct{}

func (Collector) ID() string { return "scheduler" }

func (Collector) Plan(model.HostProfile, collect.Discovery) []probe.Definition {
	return []probe.Definition{Definition()}
}

func (Collector) Parse(_ probe.Definition, result adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
	values, _ := ParseProbeOutput(result.Stdout, evidenceID)
	return Facts(values)
}

var _ collect.Collector = Collector{}
