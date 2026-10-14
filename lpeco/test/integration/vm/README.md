# Disposable systemd VM fixture

The VM gate validates the real systemd and cgroup path. Both preparation and
execution deliberately refuse to run unless `LPECO_VM_DISPOSABLE=YES` is set.
Neither the downloaded base image nor the prepared fixture image is booted
directly: both scripts create temporary qcow2 overlays and discard them after
use.

## Image contract

Prepare a Linux qcow2 image with SSH public-key authentication for an
unprivileged account and these units:

- `lpeco-fixture.service`: active root service with a non-zero `MainPID` and an
  applied unit fragment or drop-in writable by the SSH account.
- `lpeco-fixture.timer`, `.socket`, and `.path`: loaded and active, each
  triggering `lpeco-fixture.service` through the unit type's native directive
  (`Unit=` for timer/path and `Service=` for socket).
- `lpeco-fixture-inactive.service`: loaded and inactive.
- `lpeco-fixture-failed.service`: loaded and failed.
- `lpeco-fixture-oneshot.service`: `Type=oneshot`, loaded and active/exited with
  `RemainAfterExit=yes`.
- `/opt/lpeco-vm-fixture`: the fixture application/config tree, readable by the
  SSH account. Any deliberately controlled object must stay inside this
  disposable image.

The account must be able to run `systemctl show`, read the fixture unit files,
read `/proc`, and execute `/bin/sh`. Install `acl`, `binutils`, `findutils`, and
`libcap` tooling when building a custom image so all passive collectors are
available. The reproducible minimal image includes a fixture-only
`getfacl`-compatible observer that emits the base owner/group/other entries
from `stat`; the fixture creates no extended ACLs. This keeps the ACL-backed
permission edge testable while the guest remains offline. It is not a general
replacement for the `acl` package. Other unavailable optional utilities remain
explicit capability gaps. LPECO itself runs on the host through its verified
SSH transport; neither the binary nor evidence is copied into the guest. Do
not point this harness at a workstation, shared server, or production image.

The unprivileged account is expected to be denied access to root process
environments. The harness therefore requires CLI exit 3 and an `interrupted`
session, then verifies that every incomplete checkpoint belongs only to those
protected environment reads or the user-systemd passive fallback. It continues
all graph, service-state, and persistent-state assertions after that check.

If known-vulnerability assertions are added to this gate, supply the database
from a host-side immutable snapshot pinned by digest. The guest must remain
offline: do not copy the database or helper binaries into it, run package
updates, install packages, or permit target egress. Record the exact qcow2 image
digest, Ubuntu release/channel, package fixture versions, snapshot digest, and
impact-catalog digest with the result so it can be reproduced. Package probes
must remain passive `dpkg-query`/identity reads covered by the same before/after
file, process, and service snapshots.

## Prepare a pinned fixture image

The following released Ubuntu 24.04 image and digest are a reviewed baseline.
The dated URL is intentional: do not replace it with the mutable `current`
alias. Downloading happens on the host. The guest is booted with QEMU user
networking in `restrict=on` mode, so fixture preparation cannot reach external
networks. `prepare.sh` verifies the complete base-image digest before creating
an SSH key or output image, refuses to overwrite paths, and flattens the
temporary overlay into a standalone prepared image.

```sh
mkdir -p /absolute/path/to/lpeco-vm
curl --fail --location \
  --output /absolute/path/to/lpeco-vm/ubuntu-24.04-20260926.img \
  https://cloud-images.ubuntu.com/releases/noble/release-20260926/ubuntu-24.04-server-cloudimg-amd64.img

export LPECO_VM_DISPOSABLE=YES
export LPECO_VM_BASE_IMAGE=/absolute/path/to/lpeco-vm/ubuntu-24.04-20260926.img
export LPECO_VM_BASE_SHA256=6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2
export LPECO_VM_IMAGE=/absolute/path/to/lpeco-vm/prepared.qcow2
export LPECO_VM_SSH_USER=lpeco
export LPECO_VM_SSH_KEY=/absolute/path/to/lpeco-vm/id_ed25519
export LPECO_VM_SSH_PORT=22222
make prepare-vm
```

Preparation requires `qemu-system-x86_64`, `qemu-img`, `xorriso`, OpenSSH
client tools, and an OpenBSD-compatible `nc` with Unix-socket support. It uses
TCG by default; set `LPECO_VM_ACCEL=kvm` only when the current user has explicit
access to `/dev/kvm`. Optional sizing and timeout settings are
`LPECO_VM_MEMORY_MB`, `LPECO_VM_CPUS`, and `LPECO_VM_PREPARE_TIMEOUT`.

## Run the gate

```sh
export LPECO_VM_DISPOSABLE=YES
export LPECO_VM_IMAGE=/absolute/path/to/prepared.qcow2
export LPECO_VM_IMAGE_FORMAT=qcow2
export LPECO_VM_SSH_USER=lpeco
export LPECO_VM_SSH_KEY=/absolute/path/to/id_ed25519
export LPECO_VM_SSH_PORT=22222
make test-vm
```

Optional settings are `LPECO_VM_ACCEL` (default `tcg`), `LPECO_VM_MEMORY_MB`
(default `1024`), `LPECO_VM_CPUS` (default `1`), and
`LPECO_VM_BOOT_TIMEOUT` in seconds (default `180`). A missing image, key,
required variable, QEMU utility, or SSH utility is a setup error—not a skipped
test.
