#!/usr/bin/env bash
set -euo pipefail

if [[ ${LPECO_VM_DISPOSABLE:-} != YES ]]; then
  printf 'refusing VM run: set LPECO_VM_DISPOSABLE=YES for a disposable fixture image\n' >&2
  exit 64
fi

required_variables=(LPECO_VM_IMAGE LPECO_VM_SSH_USER LPECO_VM_SSH_KEY LPECO_VM_SSH_PORT LPECO_BINARY)
for variable in "${required_variables[@]}"; do
  if [[ -z ${!variable:-} ]]; then
    printf 'VM setup error: %s is required\n' "$variable" >&2
    exit 64
  fi
done
if [[ ! -f $LPECO_VM_IMAGE ]]; then
  printf 'VM setup error: image not found: %s\n' "$LPECO_VM_IMAGE" >&2
  exit 66
fi
if [[ ! -f $LPECO_VM_SSH_KEY ]]; then
  printf 'VM setup error: SSH key not found: %s\n' "$LPECO_VM_SSH_KEY" >&2
  exit 66
fi
if [[ ! -x $LPECO_BINARY ]]; then
  printf 'VM setup error: lpeco binary not executable: %s\n' "$LPECO_BINARY" >&2
  exit 66
fi
if [[ $LPECO_VM_IMAGE != /* || $LPECO_VM_SSH_KEY != /* ]]; then
  printf 'VM setup error: LPECO_VM_IMAGE and LPECO_VM_SSH_KEY must be absolute paths\n' >&2
  exit 64
fi
if [[ ! $LPECO_VM_SSH_PORT =~ ^[0-9]+$ ]] || (( LPECO_VM_SSH_PORT < 1 || LPECO_VM_SSH_PORT > 65535 )); then
  printf 'VM setup error: LPECO_VM_SSH_PORT must be an integer from 1 to 65535\n' >&2
  exit 64
fi
if [[ ! $LPECO_VM_SSH_USER =~ ^[A-Za-z0-9_.-]+$ ]] || [[ $LPECO_VM_SSH_USER == -* ]]; then
  printf 'VM setup error: LPECO_VM_SSH_USER contains unsafe characters\n' >&2
  exit 64
fi
for command_name in qemu-system-x86_64 qemu-img ssh ssh-keyscan; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'VM setup error: command not found: %s\n' "$command_name" >&2
    exit 69
  fi
done

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
temporary_directory=$(mktemp -d)
overlay=$temporary_directory/fixture-overlay.qcow2
pid_file=$temporary_directory/qemu.pid
known_hosts=$temporary_directory/known_hosts
serial_log=$temporary_directory/serial.log
qemu_pid=

cleanup() {
  if [[ -n $qemu_pid ]] && kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid" 2>/dev/null || true
    for _ in {1..20}; do
      kill -0 "$qemu_pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$qemu_pid" 2>/dev/null; then
      kill -KILL "$qemu_pid" 2>/dev/null || true
    fi
  fi
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

image_format=${LPECO_VM_IMAGE_FORMAT:-qcow2}
memory=${LPECO_VM_MEMORY_MB:-1024}
cpus=${LPECO_VM_CPUS:-1}
accel=${LPECO_VM_ACCEL:-tcg}
boot_timeout=${LPECO_VM_BOOT_TIMEOUT:-180}
if [[ ! $memory =~ ^[0-9]+$ ]] || (( memory < 512 )); then
  printf 'VM setup error: LPECO_VM_MEMORY_MB must be an integer of at least 512\n' >&2
  exit 64
fi
if [[ ! $cpus =~ ^[0-9]+$ ]] || (( cpus < 1 )); then
  printf 'VM setup error: LPECO_VM_CPUS must be a positive integer\n' >&2
  exit 64
fi
if [[ ! $boot_timeout =~ ^[0-9]+$ ]] || (( boot_timeout < 30 )); then
  printf 'VM setup error: LPECO_VM_BOOT_TIMEOUT must be an integer of at least 30 seconds\n' >&2
  exit 64
fi

qemu-img create -q -f qcow2 -F "$image_format" -b "$LPECO_VM_IMAGE" "$overlay"
qemu-system-x86_64 \
  -name lpeco-disposable-fixture \
  -accel "$accel" \
  -m "$memory" -smp "$cpus" \
  -drive "file=$overlay,if=virtio,format=qcow2" \
  -netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:${LPECO_VM_SSH_PORT}-:22" \
  -device virtio-net-pci,netdev=net0 \
  -display none -serial "file:$serial_log" \
  -daemonize -pidfile "$pid_file"
qemu_pid=$(<"$pid_file")

ssh_options=(
  -i "$LPECO_VM_SSH_KEY"
  -p "$LPECO_VM_SSH_PORT"
  -o BatchMode=yes
  -o ConnectTimeout=3
  -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$known_hosts"
)
destination=${LPECO_VM_SSH_USER}@127.0.0.1

deadline=$((SECONDS + boot_timeout))
until ssh "${ssh_options[@]}" "$destination" true >/dev/null 2>&1; do
  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    printf 'VM exited before SSH became ready; serial log follows\n' >&2
    sed -n '1,240p' "$serial_log" >&2 || true
    exit 1
  fi
  if (( SECONDS >= deadline )); then
    printf 'VM setup error: SSH was not ready within %s seconds; serial log follows\n' "$boot_timeout" >&2
    sed -n '1,240p' "$serial_log" >&2 || true
    exit 1
  fi
  sleep 2
done

advertised_host_keys=$temporary_directory/advertised-host-keys
if ! ssh-keyscan -T 5 -p "$LPECO_VM_SSH_PORT" 127.0.0.1 >"$advertised_host_keys" 2>/dev/null || [[ ! -s $advertised_host_keys ]]; then
  printf 'VM setup error: could not collect the fixture SSH host keys\n' >&2
  exit 1
fi
if ! awk 'NF >= 3 && ($2 ~ /^ssh-/ || $2 ~ /^ecdsa-/) { found=1 } END { exit !found }' "$advertised_host_keys"; then
  printf 'VM setup error: fixture advertised no supported SSH host key\n' >&2
  exit 1
fi
sort -u "$advertised_host_keys" >"$known_hosts"
chmod 0600 "$known_hosts"
strict_ssh_options=(
  -i "$LPECO_VM_SSH_KEY"
  -p "$LPECO_VM_SSH_PORT"
  -o BatchMode=yes
  -o ConnectTimeout=3
  -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$known_hosts"
)
if ! ssh "${strict_ssh_options[@]}" "$destination" true >/dev/null 2>&1; then
  printf 'VM setup error: strict SSH host-key verification failed after key discovery\n' >&2
  exit 1
fi

fixture_root=${LPECO_VM_FIXTURE_ROOT:-/opt/lpeco-vm-fixture}
if [[ ! $fixture_root =~ ^/[A-Za-z0-9_./-]+$ ]] || [[ /$fixture_root/ == */../* ]]; then
  printf 'VM setup error: LPECO_VM_FIXTURE_ROOT must be a normalized absolute path\n' >&2
  exit 64
fi
before_snapshot=$temporary_directory/before.snapshot
after_snapshot=$temporary_directory/after.snapshot
before_state=$temporary_directory/before.state
after_state=$temporary_directory/after.state
state_directory=$temporary_directory/state
terminal_report=$temporary_directory/terminal.txt
scan_stderr=$temporary_directory/scan.stderr
json_report=$temporary_directory/report.json

ssh "${strict_ssh_options[@]}" "$destination" sh -s -- check "$fixture_root" <"$script_directory/assert.sh"
ssh "${strict_ssh_options[@]}" "$destination" sh -s -- snapshot "$fixture_root" <"$script_directory/assert.sh" >"$before_snapshot"
ssh "${strict_ssh_options[@]}" "$destination" sh -s -- state "$fixture_root" <"$script_directory/assert.sh" >"$before_state"

scan_status=0
SSH_AUTH_SOCK= "$LPECO_BINARY" scan ssh "127.0.0.1:${LPECO_VM_SSH_PORT}" \
  --user "$LPECO_VM_SSH_USER" --key "$LPECO_VM_SSH_KEY" --known-hosts "$known_hosts" \
  --session-id vm-fixture --state-dir "$state_directory" --observe 5s --full --scan-root "$fixture_root" \
  >"$terminal_report" 2>"$scan_stderr" || scan_status=$?
if [[ $scan_status -ne 3 ]]; then
  printf 'expected an interrupted scan for protected root process data, got status %s\n' "$scan_status" >&2
  sed -n '1,160p' "$scan_stderr" >&2
  exit 1
fi
grep -q 'scan interrupted' "$scan_stderr"

checkpoint_resolution=$temporary_directory/checkpoint-resolution
awk -f "$script_directory/checkpoint-resolution.awk" "$state_directory/vm-fixture/session.json" | sort >"$checkpoint_resolution"
mapfile -t incomplete_probes < <(awk -F'\t' '$1 == "unresolved" { print $2 }' "$checkpoint_resolution")
print_scan_diagnostics() {
  printf 'scan stderr follows:\n' >&2
  sed -n '1,200p' "$scan_stderr" >&2
  unresolved_count=$(awk -F'\t' '$1 == "unresolved" { count++ } END { print count+0 }' "$checkpoint_resolution")
  recovered_count=$(awk -F'\t' '$1 == "recovered" { count++ } END { print count+0 }' "$checkpoint_resolution")
  printf 'checkpoint resolution: unresolved=%s recovered-by-fallback-or-retry=%s\n' "$unresolved_count" "$recovered_count" >&2
  printf 'unresolved probe IDs (first 200):\n' >&2
  awk -F'\t' '$1 == "unresolved" { print $2 }' "$checkpoint_resolution" | sed -n '1,200p' >&2
  printf 'unresolved probe families:\n' >&2
  awk -F'\t' '$1 == "unresolved" { split($2, part, "."); print part[1] "." part[2] }' "$checkpoint_resolution" | sort | uniq -c >&2
}
found_protected_environment=false
for probe_id in "${incomplete_probes[@]}"; do
  case "$probe_id" in
    process.environment.*) found_protected_environment=true ;;
    systemd.show.user|systemd.cat.user.*) ;;
    *)
      printf 'unexpected incomplete VM probe: %s\n' "$probe_id" >&2
      print_scan_diagnostics
      exit 1
      ;;
  esac
done
if [[ $found_protected_environment != true ]]; then
  printf 'VM scan did not preserve the expected protected process observation\n' >&2
  printf 'incomplete probes observed:\n' >&2
  printf '  %s\n' "${incomplete_probes[@]:-<none>}" >&2
  print_scan_diagnostics
  exit 1
fi
"$LPECO_BINARY" report vm-fixture --format json --state-dir "$state_directory" >"$json_report"

ssh "${strict_ssh_options[@]}" "$destination" sh -s -- check "$fixture_root" <"$script_directory/assert.sh"
ssh "${strict_ssh_options[@]}" "$destination" sh -s -- snapshot "$fixture_root" <"$script_directory/assert.sh" >"$after_snapshot"
ssh "${strict_ssh_options[@]}" "$destination" sh -s -- state "$fixture_root" <"$script_directory/assert.sh" >"$after_state"
diff -u "$before_snapshot" "$after_snapshot"
diff -u "$before_state" "$after_state"
grep -q '"rule_id": "systemd.writable-unit-source"' "$json_report"
grep -q '"status": "interrupted"' "$state_directory/vm-fixture/session.json"
[ "$(stat -c %a "$state_directory/vm-fixture")" = 700 ]
[ "$(stat -c %a "$state_directory/vm-fixture/evidence")" = 700 ]
find "$state_directory/vm-fixture" -type f -print | while IFS= read -r state_file; do
  [[ $(stat -c %a "$state_file") == 600 ]] || { printf 'non-private state file: %s\n' "$state_file" >&2; exit 1; }
done

printf 'vm-fixture=passed real-systemd=verified persistent-state=unchanged source-image=unchanged overlay=discarded\n'
