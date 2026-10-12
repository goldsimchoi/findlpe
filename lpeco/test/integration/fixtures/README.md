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
