# Known-vulnerability benchmark

This directory contains an offline comparison harness for LPECO's first-stage
known-vulnerability correlation. It measures package/advisory state and, where
the product actually emits one, an evidence-backed privilege-path tier. It does
not discover zero-days, execute an exploit, prove exploitability, or turn a
baseline scanner into an LPECO input.

The checked-in manifest is a reproducible template. Its OpenSCAP/Ubuntu OVAL,
OSV-Scanner, LinPEAS, and Linux Exploit Suggester lanes are optional and marked
`not_run`; a missing third-party tool is not represented as a zero-finding
success.

## Trust boundary

`lpeco-bench` only reads paths explicitly supplied by the operator (or one
selected stdin stream) and writes normalized local JSON. It has no scanner,
shell, container, VM, or network execution path. Artifact acquisition is an
operator-controlled step outside this command and must use systems you own or
are explicitly authorized to assess.

Use a disposable image or VM, isolate its network, and record the exact image
digest before running any comparison tool. Do not commit native scanner output,
target output, credentials, host identifiers, or local assessment state. The
import boundary caps artifacts at 64 MiB and rejects unknown schema fields,
raw-evidence/secret-shaped fields, control characters, identity mismatches, and
XML document type/entity declarations. Normalized files are created as `0600`
and are not overwritten unless `--force` is explicit.

## Ground truth and pinning

Expected labels are independently hand-authored in
`testdata/known-vulnerability/scenarios.json`. They cover affected, fixed,
explicitly not-affected and unknown states; P1, P2 and match-only paths; Debian
epoch/backport behavior; running-kernel identity; unsupported, absent, corrupt
and stale databases; and resume snapshot pinning. Tests require all 18 scenario
IDs and the reviewed corpus SHA-256. Scanner output must never be used to edit
those expected labels.

Before collecting results, copy `manifests/known-vulnerability.json` to a local
work area and add one `runs` entry per tool/scenario/transport lane. Every
eligible run pins:

- the exact tool name, version, and executable SHA-256;
- the immutable scenario image digest;
- the advisory-snapshot and impact-catalog SHA-256 values;
- distribution, release, package class, scenario class, transport, and
  acquisition mode.

Tags such as `latest`, wildcards, digest placeholders, mismatched scenario
metadata, and dependency cycles make a run ineligible. Required ineligible runs
invalidate the manifest; `score` also refuses optional ineligible runs so an
aggregate cannot silently mix pinned and unpinned evidence.

```sh
./bin/lpeco-bench validate --manifest /work/benchmark-manifest.json
```

Exit status is 0 for valid output, 1 for artifact/validation/scoring failures,
and 2 for command-line usage errors. Diagnostics go to stderr; successful JSON
goes to stdout.

## Acquire and normalize lanes

Run each pinned tool separately in the same disposable scenario. Preserve its
native artifact in the controlled work area long enough for review, then feed
only the reviewed local path to `import`. Neither CI nor `lpeco-bench` downloads
or launches a baseline.

Each run identity is a strict JSON encoding of `benchmark.RunIdentity`. For an
LPECO lane, import the schema-v2 report whose transport, distribution, release,
snapshot, catalog, match IDs, and candidate joins agree with that identity:

```sh
./bin/lpeco-bench import \
  --tool lpeco \
  --identity /work/lpeco-run.json \
  --input /work/lpeco-report.json \
  --output /work/lpeco-observations.json
```

The `osv-scanner` and `openscap` import modes consume the versioned, reviewed
machine-readable interchange contracts represented by `benchmark/testdata`.
They retain explicit package/version/release and affected/fixed/unknown status,
but discard summaries and severity. They always emit `path_tier: none`: an
external CVE or severity score is not evidence of a reachable privilege path.

```sh
./bin/lpeco-bench import --tool osv-scanner \
  --identity /work/osv-run.json --input /work/osv-v1.json \
  --output /work/osv-observations.json

./bin/lpeco-bench import --tool openscap \
  --identity /work/openscap-run.json --input /work/oval-v1.xml \
  --output /work/openscap-observations.json
```

LinPEAS and Linux Exploit Suggester do not have a stable result contract used
by this harness. Their results may be included only after human review as an
already normalized observation document, with both `acquisition` and
`transport` set to `manual` in the run identity. Manual baselines cannot claim
P1, P2, or match-only path tiers and are never parsed from colored prose:

```sh
./bin/lpeco-bench import --tool manual \
  --identity /work/linpeas-manual-run.json \
  --input /work/reviewed-observation.json \
  --output /work/linpeas-observations.json
```

Using `--input -` is supported. Run identities remain explicit local files, and
only one score input may consume stdin. No flag accepts a feed URL.

## Score

Pass every normalized document as a repeated flag:

```sh
./bin/lpeco-bench score \
  --manifest /work/benchmark-manifest.json \
  --observations /work/lpeco-observations.json \
  --observations /work/osv-observations.json \
  > /work/report.json
```

Scoring joins observations by exact run, tool, and scenario identity. Duplicate
IDs/runs, unknown joins, negative counters, and claimed states on failed runs
are errors. `unknown`, `unsupported`, `error`, `timeout`, `crash`, parse error,
and missing observations remain separate outcome rates and are excluded from
affected/fixed confusion matrices; they are never converted to negatives.

The report provides:

- affected and fixed precision, recall, F1, and integer confusion matrices;
- exact and adjacent path-tier accuracy, with unavailable denominators marked
  unavailable rather than reported as zero;
- micro totals, macro scenario-class aggregates, and distribution/release,
  userspace/kernel, and scenario-class strata;
- runtime, remote-command, output-byte and adapter-failure counters;
- target-write and target-egress safety gates;
- semantic consistency across SSH, raw-shell, stdio, and C2 transport lanes.

Only a complete LPECO schema-v2 observation may report P1/P2/match-only. A good
package-vulnerability baseline can therefore score package state without being
misrepresented as a privilege-path engine. Do not rank tools from one headline
number; inspect coverage/error rates, strata, safety gates, and confidence
interval limitations alongside precision and recall.

## Repository gate

```sh
make test-benchmark
```

The gate uses synthetic local fixtures only. It performs no download, network
access, container/VM launch, or third-party scanner execution and is included
in `make verify-ci`.
