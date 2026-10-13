# Disposable systemd VM fixture

The VM gate validates the real systemd and cgroup path. It deliberately refuses
to run unless `LPECO_VM_DISPOSABLE=YES` is set. The source image is never booted
directly: `run.sh` creates a temporary qcow2 overlay and deletes that overlay on
exit.

## Image contract

Prepare a Linux qcow2 image with SSH public-key authentication for an
unprivileged account and these units:

- `lpeco-fixture.service`: active root service with a non-zero `MainPID` and an
  applied unit fragment or drop-in writable by the SSH account.
- `lpeco-fixture.timer`, `.socket`, and `.path`: loaded and active, each with
  `Unit=lpeco-fixture.service`.
- `lpeco-fixture-inactive.service`: loaded and inactive.
- `lpeco-fixture-failed.service`: loaded and failed.
- `lpeco-fixture-oneshot.service`: `Type=oneshot`, loaded and active/exited with
  `RemainAfterExit=yes`.
- `/opt/lpeco-vm-fixture`: the fixture application/config tree, readable by the
  SSH account. Any deliberately controlled object must stay inside this
  disposable image.

The account must be able to run `systemctl show`, read the fixture unit files,
read `/proc`, and execute `/bin/sh`. Install `acl`, `binutils`, `findutils`, and
`libcap` tooling so all passive collectors are available. LPECO itself runs on
the host through its verified SSH transport; neither the binary nor evidence is
copied into the guest. Do not point this harness at a workstation, shared
server, or production image.

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

## Run

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
