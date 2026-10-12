package process

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/normalone/lpeco/internal/adapter"
	"github.com/normalone/lpeco/internal/collect"
	"github.com/normalone/lpeco/internal/model"
	"github.com/normalone/lpeco/internal/probe"
)

const snapshotScript = `printf 'LPECO_PROC_V1\n'
_lpeco_hex_value() { printf '%s' "$1" | od -An -v -tx1 | tr -d ' \n'; }
for _lpeco_dir in /proc/[0-9]*; do
  _lpeco_pid=${_lpeco_dir#/proc/}
  printf 'PROCESS\t%s\n' "$_lpeco_pid"
  if [ -r "$_lpeco_dir/status" ]; then printf 'STATUS\n'; cat "$_lpeco_dir/status"; printf 'END_STATUS\n'; else printf 'ERROR\tstatus\tpermission denied or process vanished\n'; fi
  if [ -r "$_lpeco_dir/stat" ]; then _lpeco_stat=$(cat "$_lpeco_dir/stat" 2>/dev/null); _lpeco_rest=${_lpeco_stat##*) }; _lpeco_start=$(printf '%s\n' "$_lpeco_rest" | awk '{print $20}'); printf 'STARTTIME\t%s\n' "$_lpeco_start"; else printf 'ERROR\tstarttime\tpermission denied or process vanished\n'; fi
  if [ -r "$_lpeco_dir/cmdline" ]; then printf 'CMDLINE_HEX\t'; od -An -v -tx1 "$_lpeco_dir/cmdline" 2>/dev/null | tr -d ' \n'; printf '\n'; else printf 'ERROR\tcmdline\tpermission denied or process vanished\n'; fi
  for _lpeco_name in exe cwd root; do
    _lpeco_path=$(readlink "$_lpeco_dir/$_lpeco_name" 2>/dev/null) || { printf 'ERROR\t%s\tpermission denied or process vanished\n' "$_lpeco_name"; continue; }
    printf '%s_HEX\t%s\n' "$(printf '%s' "$_lpeco_name" | tr '[:lower:]' '[:upper:]')" "$(_lpeco_hex_value "$_lpeco_path")"
  done
  if [ -r "$_lpeco_dir/cgroup" ]; then while IFS= read -r _lpeco_group; do printf 'CGROUP\t%s\n' "$_lpeco_group"; done < "$_lpeco_dir/cgroup"; else printf 'ERROR\tcgroup\tpermission denied or process vanished\n'; fi
  printf 'END_PROCESS\n'
done`

const environmentScript = `printf 'LPECO_ENV_V1\n'
case "$1" in ''|*[!0-9]*) printf 'ERROR\tpid\tinvalid pid\n'; exit 64;; esac
_lpeco_file="/proc/$1/environ"
if [ ! -r "$_lpeco_file" ]; then printf 'ERROR\tenvironment\tpermission denied or process vanished\n'; exit 0; fi
tr '\000' '\n' < "$_lpeco_file" | while IFS= read -r _lpeco_entry; do
  case "$_lpeco_entry" in
    PATH=*|LD_LIBRARY_PATH=*|LD_PRELOAD=*|PYTHONPATH=*|PERL5LIB=*|RUBYLIB=*|GEM_PATH=*|NODE_PATH=*|CLASSPATH=*)
      _lpeco_key=${_lpeco_entry%%=*}; _lpeco_value=${_lpeco_entry#*=}
      _lpeco_key_hex=$(printf '%s' "$_lpeco_key" | od -An -v -tx1 | tr -d ' \n')
      _lpeco_value_hex=$(printf '%s' "$_lpeco_value" | od -An -v -tx1 | tr -d ' \n')
      printf 'ENV\t%s\t%s\n' "$_lpeco_key_hex" "$_lpeco_value_hex"
      ;;
  esac
done`

const dependencyScript = `printf 'LPECO_DEP_V1\n'
case "$1" in ''|*[!0-9]*) printf 'ERROR\tpid\tinvalid pid\n'; exit 64;; esac
_lpeco_dir="/proc/$1"
for _lpeco_fd in "$_lpeco_dir"/fd/*; do
  [ -e "$_lpeco_fd" ] || continue
  _lpeco_path=$(readlink "$_lpeco_fd" 2>/dev/null) || { printf 'ERROR\tfd\tpermission denied or process vanished\n'; break; }
  _lpeco_hex=$(printf '%s' "$_lpeco_path" | od -An -v -tx1 | tr -d ' \n')
  printf 'FD\t%s\t%s\n' "${_lpeco_fd##*/}" "$_lpeco_hex"
done
if [ -r "$_lpeco_dir/maps" ]; then
  awk '$NF ~ /^\// {print $NF}' "$_lpeco_dir/maps" 2>/dev/null | sort -u | while IFS= read -r _lpeco_path; do
    _lpeco_hex=$(printf '%s' "$_lpeco_path" | od -An -v -tx1 | tr -d ' \n')
    printf 'MAP\t%s\n' "$_lpeco_hex"
  done
else
  printf 'ERROR\tmaps\tpermission denied or process vanished\n'
fi`

func SnapshotDefinition() probe.Definition {
	return probe.Definition{
		ID: "process.snapshot", Collector: "process", Parser: "proc-v1", RedactionPolicy: "process-default",
		SafetyClass: model.PassiveRead,
		Variants:    []probe.Variant{{ID: "proc-posix", Command: adapter.Command{Script: snapshotScript}}},
		Timeout:     20 * time.Second, MaxOutput: 8 * 1024 * 1024, Produces: []string{"process", "cgroup"}, Idempotent: true,
	}
}

func EnvironmentDefinition(pid string) probe.Definition {
	return probe.Definition{
		ID: "process.environment." + pid, Collector: "process", Parser: "env-v1", RedactionPolicy: "environment-values",
		SafetyClass: model.PassiveRead,
		Variants:    []probe.Variant{{ID: "proc-posix", Command: adapter.Command{Script: environmentScript, Args: []string{pid}}}},
		Timeout:     5 * time.Second, MaxOutput: 256 * 1024, Produces: []string{"process_environment"}, Idempotent: true,
	}
}

func DependencyDefinition(pid string) probe.Definition {
	return probe.Definition{
		ID: "process.dependencies." + pid, Collector: "process", Parser: "dependency-v1", RedactionPolicy: "paths",
		SafetyClass: model.PassiveRead,
		Variants:    []probe.Variant{{ID: "proc-posix", Command: adapter.Command{Script: dependencyScript, Args: []string{pid}}}},
		Timeout:     10 * time.Second, MaxOutput: 2 * 1024 * 1024, Produces: []string{"process_dependency"}, Idempotent: true,
	}
}

type Collector struct{}

func (Collector) ID() string { return "process" }

func (Collector) Plan(_ model.HostProfile, discovery collect.Discovery) []probe.Definition {
	definitions := []probe.Definition{SnapshotDefinition()}
	for _, pid := range discovery.HighValuePIDs {
		value := strconv.Itoa(pid)
		definitions = append(definitions, EnvironmentDefinition(value), DependencyDefinition(value))
	}
	return definitions
}

func (Collector) Parse(definition probe.Definition, result adapter.ExecResult, evidenceID string) ([]model.Fact, error) {
	if definition.Parser == "proc-v1" {
		parsed, err := ParseSnapshot(result.Stdout, evidenceID)
		if err != nil {
			return nil, err
		}
		return Facts(parsed)
	}
	pidText := strings.TrimPrefix(definition.ID, "process.environment.")
	if definition.Parser == "env-v1" {
		pid, err := strconv.Atoi(pidText)
		if err != nil {
			return nil, err
		}
		parsed, err := ParseEnvironment(result.Stdout, pid, evidenceID)
		if err != nil {
			return nil, err
		}
		return EnvironmentFacts(parsed)
	}
	if definition.Parser == "dependency-v1" {
		pid, err := strconv.Atoi(strings.TrimPrefix(definition.ID, "process.dependencies."))
		if err != nil {
			return nil, err
		}
		parsed, err := ParseDependencies(result.Stdout, pid, evidenceID)
		if err != nil {
			return nil, err
		}
		return DependencyFacts(parsed)
	}
	return nil, fmt.Errorf("unsupported process parser %q", definition.Parser)
}

var _ collect.Collector = Collector{}
