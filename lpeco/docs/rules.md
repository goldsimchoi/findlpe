# Candidate rule catalog

Rules consume the typed evidence graph. They do not emit an exploit or execute
a candidate. Every emitted candidate crosses to a different principal or a
capability boundary, references evidence, and records unresolved facts.

| Rule ID | Required relationship | Important suppressions |
|---|---|---|
| `systemd.writable-unit-source` | Higher-privilege unit reads an applied unit fragment/drop-in controlled by the current principal. | Unapplied sources, cross-manager/name collisions, inventory-only user units, incomplete path control, read-only mounts, or no privilege boundary. |
| `systemd.writable-exec-chain` | Higher-privilege unit executes a resolved valid executable/script chain containing a controlled object. | Unresolved specifiers/commands, unknown ACLs, or read-only objects. |
| `systemd.controlled-environment` | A unit actually uses an environment file controlled by the current principal. | Merely present but unused files, unknown path control, or same-principal units. |
| `systemd.controlled-search-path` | A simple executable resolves through a controlled `ExecSearchPath`/PATH directory. | Absolute commands, unresolved search semantics, or read-only directories. |
| `process.replaceable-dependency` | An observed higher-privilege process loads/executes a controlled resolved dependency. | Guessed dependencies, vanished/unreadable process data, or no repeatable trigger; absent trigger lowers rank. |
| `scheduler.writable-command` | Active root/different-principal cron, periodic, or SysV trigger executes/interprets a controlled command object. | Disabled/incomplete schedules, unresolved command chains, or unknown permissions. |
| `binary.suid-sgid-control` | A controlled set-ID executable crosses UID/GID boundaries. | `nosuid`, read-only object, missing execution reachability, or unconfirmed privilege-bit preservation; uncertainty lowers rank. |
| `binary.capability-boundary` | A controlled file-capability executable provides a capability boundary. | No effective capability set, read-only object, or no executable reachability. |
| `binary.loader-path-control` | A privileged executable has a resolved loader search directory controlled by the current principal. | Guessed/unresolved loader paths, read-only directories, or no boundary. |
| `delegation.sudo-policy` | Confirmed `sudo -n -l` policy permits a resolved, non-negated command as a different principal. | Sudoers file text alone is inventory; negated, alias/digest/wildcard/`ALL`, or same-principal entries are rejected. Password-required entries remain P2 inventory, never P0. |
| `container.admin-socket-control` | Current principal has direct write access to a higher-privilege Docker/containerd/Podman management socket. | Group membership without effective write access, inaccessible socket, or read-only mount. |

## Rank and confidence

Priority is operational triage; confidence is evidence quality.

- P0 requires a confirmed boundary, confirmed control, resolved semantics, a
  confirmed trigger, high aggregate confidence, and no missing facts.
- P1 has confirmed boundary/control but lacks a trigger, complete semantics, or
  high-confidence evidence.
- P2 represents incomplete inventory/diagnostic state and is the safe default
  before the minimum candidate chain is established.

The rule engine never upgrades permission denial, truncation, missing tools, or
an unresolved systemd expansion into negative evidence. Candidate IDs and
ordering are deterministic for identical typed facts. Runtime systemd values and
file-derived directives are reconciled only in the same manager scope; a
disagreement is retained as a graph diagnostic.
