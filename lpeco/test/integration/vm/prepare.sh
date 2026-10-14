#!/usr/bin/env bash
set -euo pipefail

if [[ ${LPECO_VM_DISPOSABLE:-} != YES ]]; then
  printf 'refusing VM preparation: set LPECO_VM_DISPOSABLE=YES for an isolated fixture image\n' >&2
  exit 64
fi

required_variables=(
  LPECO_VM_BASE_IMAGE
  LPECO_VM_BASE_SHA256
  LPECO_VM_IMAGE
  LPECO_VM_SSH_KEY
  LPECO_VM_SSH_USER
  LPECO_VM_SSH_PORT
)
for variable in "${required_variables[@]}"; do
  if [[ -z ${!variable:-} ]]; then
    printf 'VM setup error: %s is required\n' "$variable" >&2
    exit 64
  fi
done

for absolute_path in "$LPECO_VM_BASE_IMAGE" "$LPECO_VM_IMAGE" "$LPECO_VM_SSH_KEY"; do
  if [[ $absolute_path != /* ]]; then
    printf 'VM setup error: image and key paths must be absolute: %s\n' "$absolute_path" >&2
    exit 64
  fi
done
if [[ ! -f $LPECO_VM_BASE_IMAGE ]]; then
  printf 'VM setup error: base image not found: %s\n' "$LPECO_VM_BASE_IMAGE" >&2
  exit 66
fi
if [[ ! $LPECO_VM_BASE_SHA256 =~ ^[[:xdigit:]]{64}$ ]]; then
  printf 'VM setup error: LPECO_VM_BASE_SHA256 must contain 64 hexadecimal characters\n' >&2
  exit 64
fi

actual_digest=$(sha256sum -- "$LPECO_VM_BASE_IMAGE" | awk '{print $1}')
expected_digest=${LPECO_VM_BASE_SHA256,,}
if [[ $actual_digest != "$expected_digest" ]]; then
  printf 'base image checksum mismatch: got %s, want %s\n' "$actual_digest" "$expected_digest" >&2
  exit 65
fi

if [[ ! $LPECO_VM_SSH_PORT =~ ^[0-9]+$ ]] || (( LPECO_VM_SSH_PORT < 1 || LPECO_VM_SSH_PORT > 65535 )); then
  printf 'VM setup error: LPECO_VM_SSH_PORT must be an integer from 1 to 65535\n' >&2
  exit 64
fi
if [[ ! $LPECO_VM_SSH_USER =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]]; then
  printf 'VM setup error: LPECO_VM_SSH_USER contains unsafe characters\n' >&2
  exit 64
fi
if [[ $LPECO_VM_BASE_IMAGE == "$LPECO_VM_IMAGE" || $LPECO_VM_IMAGE == "$LPECO_VM_SSH_KEY" ]]; then
  printf 'VM setup error: base image, prepared image, and SSH key paths must be distinct\n' >&2
  exit 64
fi
for output_path in "$LPECO_VM_IMAGE" "$LPECO_VM_SSH_KEY" "$LPECO_VM_SSH_KEY.pub"; do
  if [[ -e $output_path || -L $output_path ]]; then
    printf 'VM setup error: refusing to overwrite existing path: %s\n' "$output_path" >&2
    exit 73
  fi
  output_parent=$(dirname -- "$output_path")
  if [[ ! -d $output_parent ]]; then
    printf 'VM setup error: output directory does not exist: %s\n' "$output_parent" >&2
    exit 73
  fi
done

for command_name in qemu-system-x86_64 qemu-img ssh ssh-keygen xorriso nc; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'VM setup error: command not found: %s\n' "$command_name" >&2
    exit 69
  fi
done

base_format=${LPECO_VM_BASE_FORMAT:-qcow2}
memory=${LPECO_VM_MEMORY_MB:-1024}
cpus=${LPECO_VM_CPUS:-1}
accel=${LPECO_VM_ACCEL:-tcg}
boot_timeout=${LPECO_VM_PREPARE_TIMEOUT:-300}
if [[ ! $memory =~ ^[0-9]+$ ]] || (( memory < 512 )); then
  printf 'VM setup error: LPECO_VM_MEMORY_MB must be an integer of at least 512\n' >&2
  exit 64
fi
if [[ ! $cpus =~ ^[0-9]+$ ]] || (( cpus < 1 )); then
  printf 'VM setup error: LPECO_VM_CPUS must be a positive integer\n' >&2
  exit 64
fi
if [[ ! $boot_timeout =~ ^[0-9]+$ ]] || (( boot_timeout < 30 )); then
  printf 'VM setup error: LPECO_VM_PREPARE_TIMEOUT must be an integer of at least 30 seconds\n' >&2
  exit 64
fi
if ! qemu-img info -f "$base_format" -- "$LPECO_VM_BASE_IMAGE" >/dev/null; then
  printf 'VM setup error: base image is not a readable %s image\n' "$base_format" >&2
  exit 65
fi

script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
fixture_getfacl_content=$(sed 's/^/      /' "$script_directory/fixture-getfacl")
temporary_directory=$(mktemp -d)
overlay=$temporary_directory/prepared-overlay.qcow2
seed_image=$temporary_directory/seed.iso
serial_log=$temporary_directory/serial.log
monitor_socket=$temporary_directory/monitor.sock
pid_file=$temporary_directory/qemu.pid
known_hosts=$temporary_directory/known_hosts
qemu_pid=
completed=false

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
  if [[ $completed != true ]]; then
    rm -f -- "$LPECO_VM_IMAGE" "$LPECO_VM_SSH_KEY" "$LPECO_VM_SSH_KEY.pub"
  fi
  rm -rf -- "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

ssh-keygen -q -t ed25519 -N '' -C lpeco-vm-fixture -f "$LPECO_VM_SSH_KEY"
public_key=$(awk 'NF >= 2 { print $1 " " $2; exit }' "$LPECO_VM_SSH_KEY.pub")
if [[ ! $public_key =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+$ ]]; then
  printf 'VM setup error: generated SSH public key has an unexpected format\n' >&2
  exit 65
fi

cat >"$temporary_directory/meta-data" <<EOF
instance-id: lpeco-vm-fixture
local-hostname: lpeco-vm-fixture
EOF

cat >"$temporary_directory/user-data" <<EOF
#cloud-config
hostname: lpeco-vm-fixture
manage_etc_hosts: true
ssh_pwauth: false
disable_root: true
package_update: false
package_upgrade: false
users:
  - name: ${LPECO_VM_SSH_USER}
    lock_passwd: true
    shell: /bin/bash
    ssh_authorized_keys:
      - ${public_key}
write_files:
  - path: /usr/local/bin/getfacl
    owner: root:root
    permissions: '0755'
    content: |
${fixture_getfacl_content}
  - path: /opt/lpeco-vm-fixture/bin/root-worker
    owner: root:root
    permissions: '0755'
    content: |
      #!/bin/sh
      while :; do sleep 3600; done
  - path: /opt/lpeco-vm-fixture/config.ini
    owner: root:root
    permissions: '0644'
    content: |
      fixture=true
  - path: /opt/lpeco-vm-fixture/trigger
    owner: root:root
    permissions: '0644'
    content: |
      stable
  - path: /etc/systemd/system/lpeco-fixture.service
    owner: root:root
    permissions: '0644'
    content: |
      [Unit]
      Description=LPECO active root fixture
      [Service]
      Type=simple
      ExecStart=/opt/lpeco-vm-fixture/bin/root-worker
      Restart=always
      [Install]
      WantedBy=multi-user.target
  - path: /etc/systemd/system/lpeco-fixture.service.d/20-local.conf
    owner: ${LPECO_VM_SSH_USER}:${LPECO_VM_SSH_USER}
    permissions: '0644'
    defer: true
    content: |
      [Service]
      Environment=LPECO_FIXTURE=1
  - path: /etc/systemd/system/lpeco-fixture.timer
    owner: root:root
    permissions: '0644'
    content: |
      [Unit]
      Description=LPECO timer activation fixture
      [Timer]
      Unit=lpeco-fixture.service
      OnCalendar=2099-01-01 00:00:00 UTC
      Persistent=false
      [Install]
      WantedBy=timers.target
  - path: /etc/systemd/system/lpeco-fixture.socket
    owner: root:root
    permissions: '0644'
    content: |
      [Unit]
      Description=LPECO socket activation fixture
      [Socket]
      Service=lpeco-fixture.service
      ListenStream=/run/lpeco-fixture.sock
      [Install]
      WantedBy=sockets.target
  - path: /etc/systemd/system/lpeco-fixture.path
    owner: root:root
    permissions: '0644'
    content: |
      [Unit]
      Description=LPECO path activation fixture
      [Path]
      Unit=lpeco-fixture.service
      PathChanged=/opt/lpeco-vm-fixture/trigger
      [Install]
      WantedBy=multi-user.target
  - path: /etc/systemd/system/lpeco-fixture-inactive.service
    owner: root:root
    permissions: '0644'
    content: |
      [Unit]
      Description=LPECO inactive fixture
      [Service]
      Type=oneshot
      ExecStart=/bin/true
  - path: /etc/systemd/system/lpeco-fixture-failed.service
    owner: root:root
    permissions: '0644'
    content: |
      [Unit]
      Description=LPECO failed fixture
      [Service]
      Type=oneshot
      ExecStart=/bin/false
      [Install]
      WantedBy=multi-user.target
  - path: /etc/systemd/system/lpeco-fixture-oneshot.service
    owner: root:root
    permissions: '0644'
    content: |
      [Unit]
      Description=LPECO oneshot fixture
      [Service]
      Type=oneshot
      ExecStart=/bin/true
      RemainAfterExit=yes
      [Install]
      WantedBy=multi-user.target
runcmd:
  - [systemctl, disable, --now, apt-daily.timer, apt-daily-upgrade.timer]
  - [systemctl, daemon-reload]
  - [systemctl, enable, lpeco-fixture.service, lpeco-fixture.timer, lpeco-fixture.socket, lpeco-fixture.path, lpeco-fixture-failed.service, lpeco-fixture-oneshot.service]
  - [systemctl, start, lpeco-fixture.timer, lpeco-fixture.socket, lpeco-fixture.path, lpeco-fixture-oneshot.service, lpeco-fixture.service]
  - [bash, -c, 'systemctl start lpeco-fixture-failed.service || true']
  - [systemctl, stop, lpeco-fixture-inactive.service]
  - [touch, /run/lpeco-fixture-ready]
EOF

(
  cd "$temporary_directory"
  xorriso -as mkisofs -quiet -output "$seed_image" -volid cidata -joliet -rock user-data meta-data
)
qemu-img create -q -f qcow2 -F "$base_format" -b "$LPECO_VM_BASE_IMAGE" "$overlay"
qemu-img resize -q "$overlay" +1G
qemu-system-x86_64 \
  -name lpeco-disposable-preparation \
  -accel "$accel" \
  -m "$memory" -smp "$cpus" \
  -drive "file=$overlay,if=virtio,format=qcow2" \
  -drive "file=$seed_image,if=virtio,format=raw,readonly=on" \
  -netdev "user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:${LPECO_VM_SSH_PORT}-:22" \
  -device virtio-net-pci,netdev=net0 \
  -display none -serial "file:$serial_log" \
  -monitor "unix:$monitor_socket,server=on,wait=off" \
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
until ssh "${ssh_options[@]}" "$destination" test -e /run/lpeco-fixture-ready >/dev/null 2>&1; do
  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    printf 'VM exited before fixture preparation completed; serial log follows\n' >&2
    sed -n '1,240p' "$serial_log" >&2 || true
    exit 1
  fi
  if (( SECONDS >= deadline )); then
    printf 'VM setup error: fixture preparation was not ready within %s seconds; serial log follows\n' "$boot_timeout" >&2
    sed -n '1,240p' "$serial_log" >&2 || true
    exit 1
  fi
  sleep 2
done

ssh "${ssh_options[@]}" "$destination" sh -s -- check /opt/lpeco-vm-fixture <"$script_directory/assert.sh"
printf 'system_powerdown\n' | nc -N -w 3 -U "$monitor_socket" >/dev/null 2>&1 || true
shutdown_deadline=$((SECONDS + 60))
while kill -0 "$qemu_pid" 2>/dev/null; do
  if (( SECONDS >= shutdown_deadline )); then
    printf 'VM setup error: fixture did not shut down cleanly\n' >&2
    exit 1
  fi
  sleep 1
done
qemu_pid=

qemu-img convert -q -f qcow2 -O qcow2 "$overlay" "$LPECO_VM_IMAGE"
chmod 0600 "$LPECO_VM_IMAGE" "$LPECO_VM_SSH_KEY"
chmod 0644 "$LPECO_VM_SSH_KEY.pub"
completed=true

prepared_digest=$(sha256sum -- "$LPECO_VM_IMAGE" | awk '{print $1}')
printf 'prepared VM image: %s\n' "$LPECO_VM_IMAGE"
printf 'prepared image sha256: %s\n' "$prepared_digest"
printf 'SSH key: %s\n' "$LPECO_VM_SSH_KEY"
printf 'run: LPECO_VM_DISPOSABLE=YES LPECO_VM_IMAGE=%q LPECO_VM_SSH_USER=%q LPECO_VM_SSH_KEY=%q LPECO_VM_SSH_PORT=%q make test-vm\n' \
  "$LPECO_VM_IMAGE" "$LPECO_VM_SSH_USER" "$LPECO_VM_SSH_KEY" "$LPECO_VM_SSH_PORT"
