# LPECO

LPECO is a read-only Linux privilege-boundary candidate orchestrator for
authorized security assessments. After you already have an approved SSH,
reverse-shell/raw-shell, or C2 execution channel, it inventories processes,
systemd, scheduled jobs, privileged binaries, delegation policy, paths, mounts,
ACLs, and container-management sockets. It correlates those observations into
evidence-backed candidates. An optional offline Ubuntu database also correlates
exact installed package versions for graph-selected privileged components; it
does not exploit them or claim host-wide vulnerability coverage.

## Authorization and safety boundary

Use LPECO only on systems you own or are explicitly authorized to assess. The
core never generates payloads, exploits a candidate, changes a service, writes
to target configuration, uploads a helper, brute-forces credentials, or
recommends kernel exploits. A finding is a triage hypothesis, not proof that
privilege escalation will succeed.

All default probes are `passive-read`. The only current `observable-read` probe
is non-interactive sudo policy inspection; it may create audit or authentication
log entries and is skipped unless `--observable-read` is supplied. When enabled,
the exact observable probe IDs are printed before those probes execute. The
scheduler has no override for `temporary-artifact` or `state-changing` probes.

## Offline known-vulnerability correlation

Database synchronization is an explicit operator-side action. It contacts only
the fixed Canonical Ubuntu OSV and VEX endpoints, normalizes the bounded feeds,
and atomically publishes a content-addressed snapshot under the user cache:

```sh
./bin/lpeco vuln-db sync --provider ubuntu
./bin/lpeco vuln-db status
```

Use `--db-dir <path>` on either command to select another operator-side store.
`status` performs local integrity validation and reports the digest, age,
staleness, provider/source times, supported standard releases, record count,
and reviewed impact-catalog digest without making an HTTP request. There is no
feed-URL override flag.

New schema-v2 scans default to `--vuln-mode auto`:

- `auto` uses a valid current snapshot for a supported target. A missing DB is
  `not_run` and an unsupported target is `unsupported`; both leave an otherwise
  complete deterministic scan successful. Corruption or incomplete package
  work returns partial exit 3.
- `off` records `disabled`, performs no vulnerability DB I/O, and sends no
  package-correlation probes.
- `required` turns missing, unsupported, corrupt, or incomplete coverage into
  partial exit 3.

An exact immutable snapshot can be selected with
`--vuln-db <.../sha256-DIGEST>`. This implies `required` and cannot be combined
with `off`. Package queries are limited to components already connected to an
observed privilege boundary; LPECO never inventories every installed package.
It compares Debian versions exactly and emits affected, fixed, explicitly
not-affected, or unknown match records. An affected match is not proof that an
exploit exists or will succeed.

## Build

Go 1.26.9 or newer is expected.

```sh
make verify
./bin/lpeco help
```

`make verify` checks formatting without rewriting source, runs `go vet`, the
race-enabled test suite, both CLI builds, and Git diff hygiene. Use `make fmt`
explicitly when you want to rewrite Go files.

Run the additional gates independently when diagnosing a failure:

```sh
make test-integration
make test-benchmark
make vulncheck
```

The repository CI aggregate is `make verify-ci`; it combines `verify`, policy
and governance checks, workflow linting, integration tests, and the pinned
vulnerability scan. `make test-vm` remains a separate release gate: it requires
a prepared disposable image and its explicit guard, and ordinary hosted CI does
not treat missing VM evidence as success.

## Independent scanner benchmark

The repository includes an offline harness for measuring known-vulnerability
state and privilege-path results against the hand-authored 18-scenario corpus.
It can compare LPECO with optional OpenSCAP/Ubuntu OVAL, OSV-Scanner, LinPEAS,
and Linux Exploit Suggester lanes without passing their output into LPECO. The
harness never launches a scanner, shell, container, VM, or network client;
operators acquire pinned artifacts separately in disposable authorized labs.

Build `bin/lpeco-bench` with `make build`, then use its `validate`, `import`, and
`score` subcommands to validate a pinned manifest, normalize reviewed local
artifacts, and produce deterministic metrics. Unpinned or ineligible runs are
refused during aggregate scoring. See [the benchmark guide](benchmark/README.md)
for the artifact contracts, safety rules, and metric interpretation.

## Transports

Verified SSH (host-key checking is on by default):

```sh
./bin/lpeco scan ssh server.example:22 \
  --user analyst \
  --known-hosts "$HOME/.ssh/known_hosts" \
  --key "$HOME/.ssh/id_ed25519" \
  --session-id assessment-01
```

`--ask-password` reads from `/dev/tty` and never stores the password. Use
`--insecure-ignore-host-key` only when the assessment plan explicitly accepts
the interception risk.

Listen for one already-established raw shell:

```sh
./bin/lpeco listen raw \
  --bind 127.0.0.1:4444 \
  --session-id assessment-02
```

LPECO does not create or deliver a reverse-shell payload. The peer must already
be an authorized shell connected to the listener. Wildcard addresses such as
`0.0.0.0:4444` are rejected unless `--allow-public-bind` is explicit. That flag
exposes an unauthenticated command channel to the reachable network; firewall,
network isolation, and peer authentication remain the operator's responsibility.

Wrap an existing shell-producing program with raw framing:

```sh
./bin/lpeco scan bridge \
  --protocol raw \
  --adapter '/path/to/approved-shell-wrapper --profile lab' \
  --session-id assessment-03
```

Use a C2 integration through the JSONL plugin protocol:

```sh
./bin/lpeco scan bridge \
  --protocol jsonrpc \
  --adapter '/path/to/your-lpeco-c2-adapter --target agent-17' \
  --session-id assessment-04
```

`lpeco-c2-example` demonstrates async `exec`/`poll`/`cancel`; it returns fixture
data and is not a production C2 connector. See [the adapter protocol](docs/adapter-protocol.md).
The core bounds each plugin response line to 8 MiB and further caps negotiated
output by the JSON/base64 envelope and `--max-output` (4 MiB by default).

## Scope and fallback collection

By default, fallback filesystem discovery starts at `/`. Bound it on large
hosts and exclude assessment-external trees:

```sh
./bin/lpeco scan ssh server.example:22 --user analyst \
  --scan-root /usr/local --scan-root /opt \
  --exclude /opt/archive --full
```

`--full` runs cron/SysV, binary, sudo, and management-socket collectors even if
a strong process/systemd candidate already exists. Multiple `--scan-root` and
`--exclude` values are supported. Pseudo, remote, duplicate, and explicitly
excluded mounts are not recursively walked. Excluded directories are pruned
before descent, so their entries are not opened for capability inspection.

## Resume and reports

Every observation is recorded as `complete`, `partial`, `unavailable`,
`timeout`, `truncated`, or `parse_error`. Incomplete passive probes are
checkpointed and retried at most once. A successful retry supersedes facts from
the incomplete attempt while preserving its raw evidence. Collector-requested
fallbacks, such as systemd manager output followed by unit-file inventory, can
retain complementary facts from both variants. An unresolved incomplete probe
leaves the session `interrupted` and the CLI exits 3. A closed raw channel or
broken transport is left for resume with a newly established connection.
Re-supply any non-default `--observe`, `--scan-root`, `--exclude`, `--full`, and
`--observable-read` choices so a resumed plan has the same scope. Schema-v2
resume resolves the exact snapshot and impact-catalog digest pinned in the
session; a newer `current.json` cannot change prior results. A missing or
mismatched pin leaves the session partial without recomputing matches. Schema-v1
sessions remain `legacy_not_requested` and never gain the phase implicitly:

```sh
./bin/lpeco resume assessment-01 \
  --transport ssh --target server.example:22 --user analyst \
  --known-hosts "$HOME/.ssh/known_hosts" --key "$HOME/.ssh/id_ed25519"

./bin/lpeco report assessment-01 --format terminal
./bin/lpeco report assessment-01 --format json >assessment-01.json
```

The default state root is `$XDG_STATE_HOME/lpeco/sessions`, or
`$HOME/.local/state/lpeco/sessions` when `XDG_STATE_HOME` is not absolute. A
session directory and its `evidence/` directory are mode `0700`; evidence,
facts, checkpoint metadata, and candidate files are mode `0600`. Raw evidence
stays there and is referenced by ID and SHA-256. Reports contain redacted typed
facts, evidence metadata, the derived graph, and graph/rule diagnostics, not raw
evidence bodies. Schema-v2 output separates deterministic candidates,
known-vulnerability privilege-path candidates, match-only inventory, and
provider coverage. “No affected records matched the selected scope” is not a
claim that the host has no vulnerabilities.

## How to read a candidate

- `P0`: a complete, high-confidence privilege boundary, controlled object, and
  confirmed trigger.
- `P1`: control and a privilege boundary are supported, but a trigger,
  semantics, or confidence element is incomplete.
- `P2`: inventory/diagnostic priority where the control chain is not validated.

The known-vulnerability rule is capped at P1. P1 additionally requires an exact
complete affected match, a different-principal consumer, a reviewed impact
annotation, an observed affected-use edge, and an existing high-confidence
current-user interaction allowed by that annotation. Missing impact or
reachability remains P2; an exact affected running-kernel package is P2 only.

Confidence is separate from priority. Permission denial, truncation, a vanished
process, an unresolved systemd specifier, or a missing tool is retained as
missing evidence and never treated as proof that a path is safe. A candidate
referencing incomplete evidence cannot remain P0/high-confidence/read-only
validated.

## Known limits

- Process discovery repeats `/proc` snapshots every second for the configured
  `--observe` window (30 seconds by default, `0` to disable). Processes shorter
  than the interval can still be missed. Targeted environment/dependency reads
  bind PID to `/proc/<pid>/stat` start time before and after collection; cgroups
  are used when associating processes to systemd units, but consumers and paths
  can still change between observations.
- The MVP does not execute exploits, test writes, restart services, interpret
  arbitrary sudo command semantics, search for zero-days, or recommend kernel
  exploits. Running-kernel package correlation is exact, offline, and P2-only.
- Ubuntu coverage is limited to reviewed standard 22.04/jammy, 24.04/noble,
  and 26.04/resolute policy entries in the pinned snapshot. Pro/ESM and
  unreviewed releases are unsupported rather than guessed. A snapshot becomes
  stale after seven days but remains usable with an explicit warning.
- systemd runtime authority and unit-file provenance are collected separately,
  scoped by system/user manager plus manager UID, then reconciled. File fallback
  cannot supply every runtime property; mismatches are diagnostics rather than
  silently merged facts. User managers are inventory-only for escalation rules.
- Raw shells merge stdout/stderr and cannot recover after a timeout without a
  new connection. Missing framing markers are partial evidence, never success.

More detail is in [the safety model](docs/safety-model.md), [rule catalog](docs/rules.md),
and [fixture guide](docs/fixtures.md).

## Release checklist

| # | MVP condition | Evidence test |
|---|---|---|
| 1 | SSH, raw listener, and stdio raw bridge implement the adapter contract | `TestBuiltinAdaptersSatisfyContract` |
| 2 | Example C2 plugin supports async exec/poll/cancel | `TestExamplePluginAsyncLifecycle` |
| 3 | systemd process → unit → trigger → dependency → permission graph | `TestSystemdPrivilegeGraphIntegration` |
| 4 | Non-systemd cron/SysV/binary fallback | `TestNonSystemdFallbackIntegration` |
| 5 | Transport-independent candidate meaning | `TestCrossAdapterCandidateEquivalence` |
| 6 | Resume from a completed checkpoint without duplicates | `TestResumeFromCompletedCheckpointWithoutDuplicates` |
| 7 | Every candidate references evidence and missing facts | `TestEveryCandidateReferencesEvidenceAndMissingFacts` |
| 8 | Every rule has a positive and at least two negative cases; rank covers P0/P1/P2 | `TestAllRulesHavePositiveAndTwoNegatives` |
| 9 | Persistent target state is unchanged | `TestTargetPersistentStateUnchanged` |
| 10 | Terminal and JSON reports do not disclose secrets | `TestReportsContainNoSecrets` |
| 11 | Known-vulnerability phase runs after fallback or fallback skip | `TestRunVulnerabilityModesAndTwoPassCollection`, `TestRunSkipsFallbackForStrongPrimaryUnlessFull` |
| 12 | Resume accepts only the pinned snapshot/catalog and does not duplicate facts | `TestResumePinsVulnerabilitySnapshotAndDoesNotDuplicateFacts` |
| 13 | SSH/raw/C2 produce equivalent package, match, candidate, and coverage meaning | `TestKnownVulnerabilityCrossAdapterSemanticEquivalenceAndResume` |
| 14 | Hand-authored scenario ground truth covers state, tier, kernel, DB, and pinning cases | `TestKnownVulnerabilityGroundTruthManifestCoversReleaseCases` |
| 15 | Package probes preserve target files and process/service-manager identity and contain no egress primitive | `TestTargetPersistentStateUnchanged` |
| 16 | Schema-v2 reports separate matches, paths, and coverage and escape hostile terminal data | `TestKnownVulnerabilityJSONIsSeparatedDeterministicAndComplete`, `TestKnownVulnerabilityTerminalEscapesHostileProviderStrings` |

Run `make verify`, `make test-integration`, and—when the prepared disposable
image is configured—`make test-vm` before a release.
