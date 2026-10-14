#!/bin/sh
set -eu

action=${1:?check or snapshot is required}
fixture_root=${2:-/opt/lpeco-vm-fixture}

check_systemd() {
  [ "$(cat /proc/1/comm)" = systemd ] || { printf 'PID 1 is not systemd\n' >&2; exit 1; }
  command -v getfacl >/dev/null 2>&1 || { printf 'fixture getfacl observer is unavailable\n' >&2; exit 1; }
  for unit in lpeco-fixture.service lpeco-fixture.timer lpeco-fixture.socket lpeco-fixture.path lpeco-fixture-inactive.service lpeco-fixture-failed.service lpeco-fixture-oneshot.service; do
    load_state=$(systemctl show --property=LoadState --value -- "$unit")
    if [ "$load_state" != loaded ]; then
      printf 'unit is not loaded: %s (LoadState=%s)\n' "$unit" "$load_state" >&2
      systemctl show --property=LoadState,UnitFileState,FragmentPath -- "$unit" >&2 || true
      systemctl status --no-pager -- "$unit" >&2 || true
      find /etc/systemd/system -maxdepth 2 -name 'lpeco-fixture*' -printf 'fixture-file=%p owner=%u:%g mode=%m\n' >&2 || true
      tail -n 120 /var/log/cloud-init-output.log >&2 || true
      tail -n 120 /var/log/cloud-init.log >&2 || true
      exit 1
    fi
  done
  [ "$(systemctl show --property=MainPID --value -- lpeco-fixture.service)" -gt 0 ]
  [ "$(systemctl show --property=ActiveState --value -- lpeco-fixture-inactive.service)" = inactive ]
  [ "$(systemctl show --property=ActiveState --value -- lpeco-fixture-failed.service)" = failed ]
  [ "$(systemctl show --property=Type --value -- lpeco-fixture-oneshot.service)" = oneshot ]
  for trigger in lpeco-fixture.timer lpeco-fixture.socket lpeco-fixture.path; do
    active_state=$(systemctl show --property=ActiveState --value -- "$trigger")
    if [ "$active_state" != active ]; then
      printf 'activation unit is not active: %s (ActiveState=%s)\n' "$trigger" "$active_state" >&2
      systemctl show --property=LoadState,ActiveState,SubState,Result,Triggers -- "$trigger" >&2 || true
      systemctl status --no-pager -- "$trigger" >&2 || true
      exit 1
    fi
    activation_targets=$(systemctl show --property=Triggers --value -- "$trigger")
    case " $activation_targets " in
      *' lpeco-fixture.service '*) ;;
      *) printf 'activation target mismatch: %s (Triggers=%s)\n' "$trigger" "$activation_targets" >&2; exit 1 ;;
    esac
  done
}

snapshot() {
  {
    find "$fixture_root" -xdev -print
    for unit_root in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
      [ -d "$unit_root" ] && find "$unit_root" -maxdepth 2 -name 'lpeco-fixture*' -print
    done
  } | sort -u | while IFS= read -r path; do
    [ -e "$path" ] || [ -L "$path" ] || continue
    metadata=$(stat -c '%a|%u|%g|%s|%F' -- "$path")
    digest=-
    target=-
    if [ -f "$path" ] && [ ! -L "$path" ]; then digest=$(sha256sum "$path" | awk '{print $1}'); fi
    if [ -L "$path" ]; then target=$(readlink -- "$path"); fi
    printf '%s|%s|%s|%s\n' "$path" "$metadata" "$digest" "$target"
  done
}

state_snapshot() {
  check_systemd
  for unit in lpeco-fixture.service lpeco-fixture.timer lpeco-fixture.socket lpeco-fixture.path lpeco-fixture-inactive.service lpeco-fixture-failed.service lpeco-fixture-oneshot.service; do
    printf 'unit=%s\n' "$unit"
    systemctl show --property=LoadState,ActiveState,SubState,MainPID,Result -- "$unit"
  done
  main_pid=$(systemctl show --property=MainPID --value -- lpeco-fixture.service)
  printf 'main-process|pid=%s|owner=%s|exe=%s|cmd=' "$main_pid" "$(stat -c '%u:%g' -- "/proc/$main_pid")" "$(readlink -- "/proc/$main_pid/exe")"
  tr '\000' ' ' <"/proc/$main_pid/cmdline"
  printf '\n'
}

case "$action" in
  check) check_systemd ;;
  snapshot) snapshot ;;
  state) state_snapshot ;;
  *) printf 'usage: assert.sh check|snapshot|state [fixture-root]\n' >&2; exit 64 ;;
esac
