# Development Guide

## Repository layout

The repository root contains governance and GitHub automation. The Go module is
intentionally located in `lpeco/`; do not move it or change its module path as
part of unrelated work.

Key module paths are:

- `cmd/`: the LPECO CLI and example C2 adapter entrypoints;
- `internal/`: transports, scheduling, collection, evidence, graph, rules,
  reports, and session behavior;
- `test/integration/`: container, fixture, cross-adapter, and guarded VM tests;
- `docs/`: the safety model, candidate rule catalog, fixture guide, and adapter
  protocol; and
- `testdata/`: synthetic input and expected output only.

Read `lpeco/README.md` and `lpeco/docs/safety-model.md` before changing runtime
behavior. Rule changes also require `lpeco/docs/rules.md`; adapter changes
require `lpeco/docs/adapter-protocol.md`.

## Prerequisites

- Go 1.26 or newer
- Git
- A Linux environment for the complete suite
- Docker for integration fixtures that exercise containers
- A separately prepared disposable VM image for the guarded VM test

Use only synthetic fixture data. Local session state and raw assessment
evidence must not enter the repository.

## Make targets

Run these commands from `lpeco/`:

| Command | Purpose | Mutates source |
|---|---|---|
| `make fmt` | Apply `gofmt` during development | Yes |
| `make fmt-check` | Fail on formatting differences | No |
| `make vet` | Run `go vet ./...` | No |
| `make test` | Run ordinary unit tests | No |
| `make test-race` | Run ordinary tests with the race detector | No |
| `make test-integration` | Run integration-tagged fixtures | No |
| `make build` | Build both CLIs under ignored `bin/` | Only ignored output |
| `make vulncheck` | Run the pinned Go vulnerability scanner | No source changes |
| `make verify` | Check format, vet, race tests, builds, and diff hygiene | No source changes |
| `make verify-ci` | Run `verify`, integration tests, and vulnerability checks | No source changes |
| `make test-vm` | Run the explicit disposable-VM fixture | Requires guard and image |

The complete local pre-push command is:

```sh
cd lpeco
make verify-ci
```

The VM suite is deliberately outside hosted CI. It fails unless its disposable
image guard is explicit; that failure must not be converted into a passing or
skipped release check.

## Test-first change flow

1. Update local `develop`, then create a branch allowed by
   `CONTRIBUTING.md`.
2. Read the nearest tests and safety documentation.
3. Add a focused test that fails for the missing behavior or regression.
4. Implement the smallest coherent change and run the focused test.
5. Run the package suite, then `make verify-ci` before opening a pull request.
6. Update `CHANGELOG.md` under `Unreleased` for user-visible behavior.

Probe tests must include incomplete and denied observations. Rule tests require
one positive and at least two meaningfully different negative scenarios.
Adapters require common contract coverage; report changes require redaction and
schema or golden coverage. Integration fixtures compare target state before and
after collection.

## Reproduce repository policy

Run governance checks from the repository root:

```sh
sh .github/scripts/check-governance.sh .
sh .github/scripts/check-pr-policy_test.sh
sh .github/scripts/check-pr-policy.sh \
  develop feat/systemd-rule 'feat(systemd): add unit rule'
```

The PR validator consumes exactly `BASE_REF`, `HEAD_REF`, and `PR_TITLE`; it does
not evaluate input. CI passes GitHub event values as quoted arguments.

Hosted CI exposes four required job names: `policy`, `quality`, `integration`,
and `vulnerability`. External actions and installed tools are fixed to reviewed
versions, workflow permissions are read-only, and pull request code receives no
write token or repository secret.

## Compatibility and releases

The CLI flags, JSON report schema, stored session schema, and adapter protocol
are public compatibility surfaces. During the planned 0.x series, an
incompatible change still needs a changelog entry, migration note, and version
decision.

Create a `release/vX.Y.Z` branch only after normal changes have landed on
`develop`. A release requires all of the following:

- a clean checkout passing `make verify-ci`;
- successful `make test-vm` output from the prepared disposable image;
- confirmation of the ten acceptance conditions in `lpeco/README.md`;
- supported Linux fixture results;
- updated changelog, version, migration notes, and security support range;
- CLI version metadata that reports both the version and source commit;
- an explicit project license selected by the owner; and
- repository visibility and security settings verified by API readback.

After validation, merge the release branch into `main`, create an annotated
`vX.Y.Z` tag, and merge that release commit back into `develop`. Hotfixes start
from `main`, return there first, and are reconciled into `develop` immediately.
No release should be represented as complete while the license, CLI metadata,
or disposable VM evidence remains open.

See [`maintainers/github-settings.md`](maintainers/github-settings.md) for the
remote repository controls.
