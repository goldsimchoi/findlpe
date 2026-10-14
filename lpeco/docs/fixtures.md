# Test fixtures

## Fast acceptance tests

`go test ./...` uses canned context, `/proc`, systemd, path/ACL/mount, cron,
binary, and adapter transcripts. These tests are deterministic and require no
root privileges. The cross-adapter fixture sends real collector commands over
ephemeral SSH, raw listener, stdio raw, and a JSON-RPC plugin subprocess, then
parses them with the production collectors and compares candidate meaning rather
than transport metadata.

Known-vulnerability release ground truth lives in
`testdata/known-vulnerability/scenarios.json`. Its labels are hand-authored and
cover the release cases for P1/P2/match-only results, fixed and explicitly
not-affected packages, Debian epoch/backport ordering, unknown evidence,
running-kernel identity, database availability/integrity/staleness, unsupported
targets, and resume pinning. Tests validate those labels and the separate
benchmark harness consumes the scenario IDs; scanner output is never copied
back into expected labels.

The independent comparison harness in [`benchmark/`](../benchmark/README.md)
references this corpus by its reviewed file and semantic SHA-256 values. Its
manifest pins scenario images, tool builds, exact package/version identities,
the advisory snapshot, and the impact catalog. Benchmark results are normalized
observations bound to a canonical run-identity digest only: raw scanner output,
advisory prose, credentials, and target identifiers are rejected. Optional
baseline artifacts must be acquired separately in a disposable authorized
environment; the test suite and `lpeco-bench` do not execute those tools or use
the network.

The package-correlation cross-adapter fixture sends the same bounded package
ownership and metadata requests through ephemeral SSH, raw listener, stdio raw,
and JSON-RPC C2 transports. It compares semantic package facts, matches,
candidates, coverage, and missing facts while ignoring transport-specific
evidence IDs, then resumes against the exact pinned snapshot and asserts that
package evidence and match facts are not duplicated. Feed-sync tests use a
local deterministic HTTP server on the operator side. No integration fixture
permits target egress or package-repository refresh.

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
make prepare-vm
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

The fixture README provides a dated Ubuntu cloud-image URL and SHA-256 digest.
The preparation target verifies that digest before creating artifacts, boots
only an overlay with guest egress disabled, provisions the deliberately unsafe
units, shuts it down cleanly, and emits a standalone qcow2 image plus a fresh
SSH key. It also installs a fixture-only base-mode ACL observer so the pinned
minimal image can exercise permission edges without network package installs;
the fixture has no extended ACLs. It refuses to overwrite either output.

Container and VM images contain deliberately writable privileged-consumer
inputs. Never reuse them outside an isolated test network.

## Schema compatibility

New sessions use report/session schema 2 and can contain provider coverage,
known-vulnerability matches, and known-vulnerability path candidates as
separate collections. A schema-2 resume must resolve the exact saved provider,
snapshot schema/digest, and impact-catalog digest. Schema-1 fixtures remain
valid legacy input and are reported as `legacy_not_requested`; they are not
silently upgraded by consulting the current database.
