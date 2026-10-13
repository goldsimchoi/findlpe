# Changelog

All notable user-visible changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project plans
to use [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once releases
begin.

## Unreleased

### Added

- Read-only Linux inventory across processes, systemd system and user managers,
  cron and SysV schedulers, privileged binaries, sudo policy, path permissions,
  mounts, ACLs, and container-management sockets.
- Evidence graph correlation and deterministic P0, P1, and P2 candidates with
  explicit missing-fact and confidence semantics.
- Verified SSH, raw listener, raw stdio bridge, and asynchronous JSON-RPC C2
  adapter transports with bounded output and cancellation behavior.
- Resumable sessions, immutable raw evidence references, redacted terminal and
  JSON reports, and integration fixtures for cross-transport behavior.
- Contribution, security, development, and automated repository policy checks
  for long-term maintenance.

### Changed

- Incomplete or conflicting observations remain explicit diagnostics and cannot
  be promoted to fully validated high-confidence candidates.

### Deprecated

- No compatibility surface is deprecated before the first public release.

### Removed

- No compatibility surface has been removed before the first public release.

### Fixed

- Raw-shell framing, bounded retries, and resume semantics preserve partial
  evidence instead of treating an incomplete exchange as success.

### Security

- Probe registration enforces read-only safety classes, fixed scripts, bounded
  execution, target-value quoting, report redaction, and restrictive local
  evidence permissions.
