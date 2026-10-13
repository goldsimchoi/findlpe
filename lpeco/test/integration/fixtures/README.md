# Integration fixture inventory

These fixtures are intentionally vulnerable and must only be used in disposable
containers or virtual machines.

- `debian`: a deterministic `systemctl` transcript backed by a real root-owned
  process. It exposes active timer, socket, and path activation for a root
  service, an applied writable unit source, a writable executable, and an
  incomplete lower-confidence unit.
- `alpine`: a non-systemd host with root cron and SysV entries whose command
  objects are controlled by the unprivileged fixture user.
- `vm`: a prepared Linux image running real systemd. The required unit names and
  image contract are documented in `../vm/README.md`.

The container harness snapshots content hashes, modes, owners, sizes, symlink
targets, and the file list below the managed fixture roots. Access times and the
operator-owned session directory under `/tmp/lpeco-state` are intentionally not
part of that snapshot.

Known-vulnerability correlation uses the hand-authored release manifest at
`../../../testdata/known-vulnerability/scenarios.json`. Its expected match,
coverage, and path-tier labels are review inputs and must not be regenerated
from scanner output. The cross-adapter fixture supplies deterministic Ubuntu,
privileged-consumer, package-owner, and installed-version facts through the
normal passive `exec` contract. Its database snapshot is built and retained on
the test runner; it is never copied into a fixture target.

Safety assertions run before and after every registered definition. New fixture
probes must not contain target network clients, repository refresh/install
commands, upload/write redirections, or service/process mutation. Feed tests use
only a loopback `httptest` server on the operator side.
