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
- Operator-synchronized, immutable Ubuntu OSV/VEX snapshots and offline exact
  package-version correlation for graph-selected privileged components, with
  separate coverage, match-only, and P1/P2 privilege-path reporting.
- Contribution, security, development, and automated repository policy checks
  for long-term maintenance.
- An offline, reproducible known-vulnerability benchmark with independently
  authored scenario labels, strict LPECO/OSV-Scanner/OpenSCAP normalization,
  manual baseline review, deterministic scoring, and explicit safety/resource
  accounting.

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
- Mount inventory parse failures and partial observations now fail closed
  instead of falling back to a less-specific writable mount.
- P0 and read-only-validated candidates now require complete, high-confidence
  evidence at both ranking and model-validation boundaries.
- Raw-shell exit-status parsing is bounded to the protocol's three-digit
  range and rejects malformed suffixes without draining unbounded input.

### Security

- Probe registration enforces read-only safety classes, fixed scripts, bounded
  execution, target-value quoting, report redaction, and restrictive local
  evidence permissions.
- Vulnerability databases stay on the operator side; targets receive only
  bounded passive package queries and never receive feeds, uploads, repository
  refreshes, or target-egress commands. Sync uses fixed Canonical HTTPS sources,
  bounded archive decoding, atomic content-addressed publication, exact resume
  pinning, official-reference allowlisting, and terminal control escaping.
- The minimum Go patch release is 1.26.9, which includes the standard-library
  fixes required by the repository vulnerability gate.
- Benchmark scoring binds normalized observations to immutable ground-truth
  semantics and complete run/package identities, rejects contradictory scanner
  joins and overflowing counters, and never treats unavailable safety
  measurement as a passing zero.
