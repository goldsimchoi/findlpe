# Safety model

## Scope

LPECO assumes an operator has explicit authorization and already controls an
execution channel on the target. Its job is evidence collection and candidate
correlation. Exploitation, persistence, lateral movement, credential attacks,
payload delivery, and service manipulation are outside the trust boundary.

## Probe policy

Every probe is registered at build time with a safety class, fixed script,
separate arguments, timeout, output bound, parser, and expected fact types.

| Class | Default policy | Intended effect |
|---|---|---|
| `passive-read` | Allowed | Reads existing metadata or content available to the current principal. |
| `observable-read` | Explicit `--observable-read` opt-in | Read-only, but may be visible in audit/authentication logs. |
| `temporary-artifact` | Always denied | Would create a target-side file or other temporary state. |
| `state-changing` | Always denied | Would alter service, process, permission, policy, or persistent state. |

Probe scripts are immutable registry data. Target-derived values are passed as
POSIX-quoted positional arguments through one renderer; NUL is rejected. The
raw transport adds unpredictable record-separator markers and accepts a result
only after a valid end marker and exit status. A timeout closes that raw channel.

The core does not call adapter upload/download capabilities. It does not use
write-based permission checks, `systemctl start/restart`, `sudo` password
prompts, or authentication retries. `sudo -n -l` is the only current
observable-read operation.
Before an opted-in observable probe runs, the CLI discloses its registered probe
ID. If disclosure cannot be written, that observable batch does not execute.

## Evidence semantics

Raw stdout/stderr is stored before parsing, including failed, partial,
truncated, timed-out, and parse-error observations. A denied read or unavailable
tool means “unknown,” not “not vulnerable.” Graph edges require evidence IDs,
and candidate validation requires evidence plus explicit missing-fact fields.
Low-confidence candidates cannot be P0. Facts derived from non-complete
observations are annotated and confidence-bounded. Candidates referencing them
cannot remain P0, high confidence, or read-only validated. If a retry succeeds,
its semantic facts supersede those from the incomplete attempt; both raw
evidence records remain. Unresolved incomplete work leaves a resumable
`interrupted` session.

Systemd manager output is treated as runtime authority, while `systemctl cat` or
unit-file fallback supplies provenance. The graph reconciles them only within
the exact `(system|user, manager UID, unit name)` scope and reports conflicting
runtime/file values. A failed or header-only manager response activates the
next passive variant. User-manager inventory is not treated as a root boundary.

Targeted `/proc` reads bind a PID to its start time before and after collection;
PID reuse makes the observation incomplete. Process-to-unit association also
checks cgroup evidence instead of relying only on a unit name.

Path control is computed from the current UID/GID and supplementary groups,
every traversed parent, POSIX mode, ACL mask, sticky directories, symlink
resolution, inode changes, and the containing mount's `ro`, `noexec`, and
`nosuid` flags. `noexec` is not applied to a script read by an interpreter.
Filesystem exclusions are applied as `find` prune conditions before traversal;
the capability loop also rechecks them before calling `getcap`.

## Local data and secrets

Session directories and evidence directories are `0700`; all regular session
files are `0600`. Evidence bodies are content-hashed and not copied into terminal
or JSON reports. Environment values, authorization-like headers, passwords,
private keys, and common token forms are redacted from typed report data and
errors. A typed value carrying `"sensitive": true` is masked regardless of its
field name. SSH passwords are requested from `/dev/tty` through an ephemeral
callback and are never placed in configuration or session metadata.

The local state directory can still contain sensitive target output. Protect,
retain, and delete it according to the engagement data-handling plan.

## Network boundary

SSH verifies host keys unless the operator explicitly disables verification.
The raw listener binds exactly one connection and rejects wildcard bind
addresses by default. `--allow-public-bind` is a high-risk acknowledgement, not
authentication; use an isolated interface and firewall.

External JSONL adapters are trusted components. They receive fully rendered
read-only probe commands and may expose them to a C2 service. Run only reviewed
adapter binaries, keep stdout reserved for protocol frames, and send diagnostics
to bounded stderr. Core response lines are bounded to 8 MiB, and negotiated
command output is capped by the smaller of the adapter claim, `--max-output`,
and the inverse base64/envelope limit. Adapter shutdown has a deadline; a child
that ignores close is terminated.

## Verification

Unit tests fuzz command/frame redaction boundaries and exercise partial data.
Integration fixtures compare path lists, content hashes, modes, owners, sizes,
symlink targets, managed process identity, and service state before and after
scans. The systemd VM runner boots only a temporary overlay and requires an
explicit disposable-image guard. Destructive fixture setup additionally requires
an explicit disposable sentinel and a container marker before it can run.
