# Test fixtures

## Fast acceptance tests

`go test ./...` uses canned context, `/proc`, systemd, path/ACL/mount, cron,
binary, and adapter transcripts. These tests are deterministic and require no
root privileges. The cross-adapter fixture sends real collector commands over
ephemeral SSH, raw listener, stdio raw, and a JSON-RPC plugin subprocess, then
parses them with the production collectors and compares candidate meaning rather
than transport metadata.

## Container gate

```sh
make test-integration
```

The tagged test builds a static local `lpeco` binary and two disposable images:

- Debian supplies deterministic systemd manager output linked to a real
  root-owned process plus timer/socket/path activation and P0/P1/incomplete
  evidence cases.
- Alpine exposes cron and SysV fallback relationships without systemd.

Both run LPECO as UID 1000 over the raw stdio bridge with container networking
disabled. The harness requires an explicit disposable sentinel plus a container
marker before setup, snapshots all managed fixture paths, a global persistent
path list, file capabilities, and managed process/service identity before and
after, verifies owner-only state permissions, and requires P0/P1/P2 candidates
and graph edges in the JSON report. Protected root process environments are
intentionally unreadable, so the scan must end `interrupted` (CLI exit 3); the
harness rejects any incomplete probe outside that expected allowlist. Docker
and registry access for the image build are prerequisites; missing prerequisites
fail the gate.

## Real systemd VM gate

```sh
make test-vm
```

This gate compares those service states and the main process identity before
and after the scan. It validates loaded, inactive, failed, and oneshot services;
a non-zero service `MainPID`; and live timer/socket/path activation under real
systemd and cgroups. As in the container gate, protected root process reads must
produce only the explicitly allowlisted incomplete observations. It requires
the prepared image and explicit environment variables in
[`test/integration/vm/README.md`](../test/integration/vm/README.md). The runner
uses a temporary qcow2 overlay, refuses to run without
`LPECO_VM_DISPOSABLE=YES`, and treats missing setup as an error rather than a
skip. The host binary connects with verified SSH and keeps all evidence in the
host-side temporary directory; no LPECO binary or evidence is copied into the
guest.

Container and VM images contain deliberately writable privileged-consumer
inputs. Never reuse them outside an isolated test network.
