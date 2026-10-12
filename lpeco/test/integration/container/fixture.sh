#!/bin/sh
set -eu

if [ "${LPECO_DISPOSABLE_FIXTURE:-}" != "confirmed" ]; then
  printf 'refusing destructive fixture setup outside an explicitly disposable container\n' >&2
  exit 70
fi
if [ ! -e /.dockerenv ] && [ ! -e /run/.containerenv ]; then
  printf 'refusing destructive fixture setup: container marker is absent\n' >&2
  exit 70
fi

fixture_kind=${LPECO_FIXTURE_KIND:?LPECO_FIXTURE_KIND must be debian or alpine}

write_executable() {
  destination=$1
  shift
  mkdir -p "$(dirname "$destination")"
  printf '%s\n' "$@" >"$destination"
  chmod 0755 "$destination"
}

setup_common() {
  mkdir -p /opt/lpeco-fixture/bin /opt/lpeco-fixture/jobs /etc/cron.d /etc/init.d /etc/rc2.d
  write_executable /opt/lpeco-fixture/bin/root-worker '#!/bin/sh' 'exec sleep 600'
  write_executable /opt/lpeco-fixture/bin/replaceable-worker '#!/bin/sh' 'exec sleep 600'
  chmod 0777 /opt/lpeco-fixture/bin/replaceable-worker
  write_executable /opt/lpeco-fixture/jobs/root-job '#!/bin/sh' 'exit 0'
  chmod 0777 /opt/lpeco-fixture/jobs/root-job
  printf '%s\n' '* * * * * root /bin/sh /opt/lpeco-fixture/jobs/root-job' >/etc/cron.d/lpeco-demo
  chmod 0644 /etc/cron.d/lpeco-demo
  write_executable /etc/init.d/lpeco-demo '#!/bin/sh' '/bin/sh /opt/lpeco-fixture/jobs/root-job'
	chmod 0777 /etc/init.d/lpeco-demo
  ln -sfn /etc/init.d/lpeco-demo /etc/rc2.d/S99lpeco-demo
  chown -R 0:0 /opt/lpeco-fixture /etc/cron.d/lpeco-demo /etc/init.d/lpeco-demo
	cp /bin/sleep /opt/lpeco-fixture/bin/capped
	chown 0:0 /opt/lpeco-fixture/bin/capped
	chmod 0755 /opt/lpeco-fixture/bin/capped
	setcap cap_setuid=ep /opt/lpeco-fixture/bin/capped
}

setup_debian() {
  mkdir -p /etc/systemd/system
  printf '%s\n' '[Unit]' 'Description=LPECO P0 fixture' '[Service]' 'User=root' 'ExecStart=/opt/lpeco-fixture/bin/root-worker' >/etc/systemd/system/lpeco-p0.service
  chmod 0666 /etc/systemd/system/lpeco-p0.service
  printf '%s\n' '[Unit]' 'Description=LPECO P1 fixture' '[Service]' 'User=root' 'ExecStart=/opt/lpeco-fixture/bin/replaceable-worker' >/etc/systemd/system/lpeco-p1.service
  chmod 0644 /etc/systemd/system/lpeco-p1.service
  printf '%s\n' '[Unit]' 'Description=LPECO incomplete fixture' '[Service]' 'User=root' 'EnvironmentFile=/opt/lpeco-fixture/p2.env' 'ExecStart=/opt/lpeco-fixture/bin/root-worker' >/etc/systemd/system/lpeco-p2.service
  printf '%s\n' 'FIXTURE_VALUE=not-a-secret' >/opt/lpeco-fixture/p2.env
  chmod 0666 /opt/lpeco-fixture/p2.env
  for kind in timer socket path; do
    printf '%s\n' '[Unit]' "Description=LPECO ${kind} activation" "[${kind}]" 'Unit=lpeco-p0.service' >"/etc/systemd/system/lpeco-p0.${kind}"
    chmod 0644 "/etc/systemd/system/lpeco-p0.${kind}"
  done

  write_executable /usr/local/bin/cat '#!/bin/sh' 'if [ "$#" -eq 1 ] && [ "$1" = /proc/1/comm ]; then printf "systemd\\n"; exit 0; fi' 'exec /bin/cat "$@"'
  write_executable /usr/local/bin/systemctl '#!/bin/sh' \
    'scope=system' \
    'if [ "${1:-}" = --user ]; then scope=user; shift; fi' \
    'operation=${1:-}' \
    'if [ "$operation" = list-units ]; then' \
    '  [ "$scope" = system ] || exit 0' \
    '  for unit in lpeco-p0.service lpeco-p1.service lpeco-p2.service lpeco-p0.timer lpeco-p0.socket lpeco-p0.path; do printf "%s loaded active running fixture\\n" "$unit"; done' \
    '  exit 0' \
    'fi' \
    'unit=' \
    'for argument do unit=$argument; done' \
    'if [ "$operation" = show ]; then' \
    '  worker_pid=$(/bin/cat /run/lpeco-fixture/worker.pid 2>/dev/null || printf 0)' \
    '  printf "Id=%s\\nNames=%s\\nLoadState=loaded\\nActiveState=active\\nSubState=running\\nUID=0\\nGID=0\\nUser=root\\nGroup=root\\n" "$unit" "$unit"' \
    '  case "$unit" in' \
    '    lpeco-p0.service) printf "Type=simple\\nMainPID=%s\\nFragmentPath=/etc/systemd/system/lpeco-p0.service\\nExecStart={ path=/opt/lpeco-fixture/bin/root-worker ; argv[]=/opt/lpeco-fixture/bin/root-worker ; ignore_errors=no ; }\\n" "$worker_pid" ;;' \
    '    lpeco-p1.service) printf "Type=simple\\nMainPID=0\\nFragmentPath=/etc/systemd/system/lpeco-p1.service\\nExecStart={ path=/opt/lpeco-fixture/bin/replaceable-worker ; argv[]=/opt/lpeco-fixture/bin/replaceable-worker ; ignore_errors=no ; }\\n" ;;' \
    '    lpeco-p2.service) printf "Type=simple\\nMainPID=0\\nFragmentPath=/etc/systemd/system/lpeco-p2.service\\nEnvironmentFiles=/opt/lpeco-fixture/p2.env\\nExecStart={ path=/opt/lpeco-fixture/bin/root-worker ; argv[]=/opt/lpeco-fixture/bin/root-worker ; ignore_errors=no ; }\\n" ;;' \
    '    lpeco-p0.timer) printf "Type=timer\\nUnit=lpeco-p0.service\\nNextElapseUSecRealtime=Mon 2030-01-01 00:00:00 UTC\\nFragmentPath=/etc/systemd/system/lpeco-p0.timer\\n" ;;' \
    '    lpeco-p0.socket) printf "Type=socket\\nUnit=lpeco-p0.service\\nFragmentPath=/etc/systemd/system/lpeco-p0.socket\\n" ;;' \
    '    lpeco-p0.path) printf "Type=path\\nUnit=lpeco-p0.service\\nFragmentPath=/etc/systemd/system/lpeco-p0.path\\n" ;;' \
    '  esac' \
    '  exit 0' \
    'fi' \
    'if [ "$operation" = cat ]; then' \
    '  path=/etc/systemd/system/$unit' \
    '  [ -f "$path" ] || exit 1' \
    '  printf "# %s\\n" "$path"' \
    '  exec /bin/cat "$path"' \
    'fi' \
    'exit 1'
}

setup_fixture() {
  setup_common
  case "$fixture_kind" in
    debian) setup_debian ;;
    alpine) ;;
    *) printf 'unknown fixture kind: %s\n' "$fixture_kind" >&2; exit 64 ;;
  esac
}

managed_paths() {
  printf '%s\n' /opt/lpeco-fixture /etc/cron.d/lpeco-demo /etc/init.d/lpeco-demo /etc/rc2.d/S99lpeco-demo
  if [ "$fixture_kind" = debian ]; then
    printf '%s\n' /etc/systemd/system/lpeco-p0.service /etc/systemd/system/lpeco-p1.service /etc/systemd/system/lpeco-p2.service /etc/systemd/system/lpeco-p0.timer /etc/systemd/system/lpeco-p0.socket /etc/systemd/system/lpeco-p0.path /usr/local/bin/cat /usr/local/bin/systemctl
  fi
}

snapshot() {
  managed_paths | while IFS= read -r root; do
    if [ -e "$root" ] || [ -L "$root" ]; then
      if [ -d "$root" ]; then find "$root" -xdev -print; else printf '%s\n' "$root"; fi
    fi
  done | sort -u | while IFS= read -r path; do
    metadata=$(stat -c '%a|%u|%g|%s|%F' -- "$path")
    digest=-
    target=-
    if [ -f "$path" ] && [ ! -L "$path" ]; then digest=$(sha256sum "$path" | awk '{print $1}'); fi
    if [ -L "$path" ]; then target=$(readlink -- "$path"); fi
	capability=$(getcap -n -- "$path" 2>/dev/null || true)
	printf '%s|%s|%s|%s|%s\n' "$path" "$metadata" "$digest" "$target" "$capability"
  done
}

runtime_snapshot() {
  worker_pid=$(/bin/cat /run/lpeco-fixture/worker.pid)
  kill -0 "$worker_pid"
  printf 'worker|pid=%s|owner=%s|exe=%s|cmd=' "$worker_pid" "$(stat -c '%u:%g' -- "/proc/$worker_pid")" "$(readlink -- "/proc/$worker_pid/exe")"
  tr '\000' ' ' <"/proc/$worker_pid/cmdline"
  printf '\n'
  if [ "$fixture_kind" = debian ]; then
    PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin systemctl list-units --all --no-legend --no-pager
    for unit in lpeco-p0.service lpeco-p1.service lpeco-p2.service lpeco-p0.timer lpeco-p0.socket lpeco-p0.path; do
      PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin systemctl show -- "$unit"
    done
  fi
}

persistent_file_list() {
  find /etc /opt /usr/local -xdev -print 2>/dev/null | sort
}

run_scan() {
  rm -rf /tmp/lpeco-state
  mkdir -p /run/lpeco-fixture /run/systemd/system
  /bin/sleep 600 &
  worker_pid=$!
  printf '%s\n' "$worker_pid" >/run/lpeco-fixture/worker.pid
  trap 'kill "$worker_pid" 2>/dev/null || true' EXIT HUP INT TERM

  before=$(mktemp)
  after=$(mktemp)
  before_runtime=$(mktemp)
  after_runtime=$(mktemp)
	before_files=$(mktemp)
	after_files=$(mktemp)
  snapshot >"$before"
  runtime_snapshot >"$before_runtime"
	persistent_file_list >"$before_files"

  scan_command='PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin HOME=/home/lpeco /usr/local/bin/lpeco scan bridge --adapter /bin/sh --protocol raw --session-id container-fixture --state-dir /tmp/lpeco-state --observe 0 --full --scan-root /opt/lpeco-fixture'
  scan_status=0
  su -s /bin/sh lpeco -c "$scan_command" >/tmp/lpeco-terminal.txt 2>/tmp/lpeco-stderr.txt || scan_status=$?
  if [ "$scan_status" -ne 3 ]; then
    printf 'expected an interrupted scan for protected root process data, got status %s\n' "$scan_status" >&2
    sed -n '1,160p' /tmp/lpeco-stderr.txt >&2
    exit 1
  fi
  grep -q 'scan interrupted' /tmp/lpeco-stderr.txt
  su -s /bin/sh lpeco -c 'PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin /usr/local/bin/lpeco report container-fixture --format json --state-dir /tmp/lpeco-state' >/tmp/lpeco-report.json

  incomplete_probes=$(awk -F'"' '
    /"probe_id":/ { probe=$4 }
    /"status":/ && probe != "" && $4 != "complete" { print probe; probe="" }
  ' /tmp/lpeco-state/container-fixture/session.json | sort -u)
  printf '%s\n' "$incomplete_probes" | while IFS= read -r probe_id; do
    case "$probe_id" in
      process.environment.*|systemd.show.user|systemd.cat.user.*) ;;
      '') ;;
      *) printf 'unexpected incomplete fixture probe: %s\n' "$probe_id" >&2; exit 1 ;;
    esac
  done
  printf '%s\n' "$incomplete_probes" | grep -q '^process\.environment\.'

  snapshot >"$after"
  runtime_snapshot >"$after_runtime"
	persistent_file_list >"$after_files"
  if ! diff -u "$before" "$after"; then
    printf 'managed target state changed during scan\n' >&2
    exit 1
  fi
  if ! diff -u "$before_runtime" "$after_runtime"; then
    printf 'managed process/service state changed during scan\n' >&2
    exit 1
  fi
	if ! diff -u "$before_files" "$after_files"; then
	  printf 'persistent filesystem gained or lost paths during scan\n' >&2
	  exit 1
	fi
  [ "$(stat -c %a /tmp/lpeco-state/container-fixture)" = 700 ]
  [ "$(stat -c %a /tmp/lpeco-state/container-fixture/evidence)" = 700 ]
  find /tmp/lpeco-state/container-fixture -type f -print | while IFS= read -r state_file; do
    [ "$(stat -c %a "$state_file")" = 600 ] || { printf 'non-private state file: %s\n' "$state_file" >&2; exit 1; }
  done

	assert_candidate() {
	  _lpeco_rule=$1 _lpeco_priority=$2
	  awk -v rule="$_lpeco_rule" -v priority="$_lpeco_priority" '
	    index($0, "\"rule_id\": \"" rule "\"") { candidate=1; next }
	    candidate && index($0, "\"priority\": \"" priority "\"") { found=1; exit }
	    candidate && index($0, "\"rule_id\":") { candidate=0 }
	    END { exit found ? 0 : 1 }
	  ' /tmp/lpeco-report.json
	}
	case "$fixture_kind" in
	  debian)
	    assert_candidate systemd.writable-unit-source P0
	    assert_candidate systemd.writable-exec-chain P1
	    grep -q '"kind": "MANAGED_BY"' /tmp/lpeco-report.json
	    grep -q '"kind": "ACTIVATES"' /tmp/lpeco-report.json
	    ;;
	  alpine)
	    assert_candidate scheduler.writable-command P0
	    grep -q '"kind": "sysv"' /tmp/lpeco-report.json
	    grep -q '"kind": "cron"' /tmp/lpeco-report.json
	    ;;
	esac
	assert_candidate binary.capability-boundary P2
	grep -q '"kind": "privileged_binary"' /tmp/lpeco-report.json
	grep -q '"kind": "CAN_WRITE"' /tmp/lpeco-report.json
  grep -q '"status": "interrupted"' /tmp/lpeco-state/container-fixture/session.json
  printf 'fixture=%s persistent-state=unchanged report=/tmp/lpeco-report.json\n' "$fixture_kind"
}

case ${1:-verify} in
  setup) setup_fixture ;;
  snapshot) snapshot ;;
  verify) run_scan ;;
  *) printf 'usage: %s setup|snapshot|verify\n' "$0" >&2; exit 64 ;;
esac
