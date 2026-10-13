# Contributing to FindLPE

Thank you for improving LPECO. Safety and evidence integrity are product
requirements, not optional review preferences. Contributions must preserve the
read-only collection boundary and must be tested against incomplete and hostile
inputs.

Use the project only with explicit authorization. Do not put credentials,
private keys, access tokens, customer names, assessment identifiers, or raw
target evidence in an issue, fixture, commit, or pull request.

## Development branches

- `develop` is the integration branch for the next release.
- `main` contains release-ready history. Do not base ordinary development on it.
- Start ordinary work from current `develop` and use
  `feat/<kebab-slug>`, `fix/<kebab-slug>`, `docs/<kebab-slug>`,
  `refactor/<kebab-slug>`, `test/<kebab-slug>`, `ci/<kebab-slug>`, or
  `chore/<kebab-slug>`.
- Open ordinary pull requests into `develop` and delete the work branch after
  merge. Direct pushes, force-pushes, and deletion of either long-lived branch
  are prohibited.
- Create `release/vX.Y.Z` from `develop`, merge it into `main` after release
  validation, create the annotated version tag, and merge the same release
  commit back into `develop`.
- Create `hotfix/<kebab-slug>` from `main`, merge it into `main` first, and
  immediately reconcile the same change into `develop`.

Branch names are lowercase. Normal and hotfix slugs are kebab-case. The
repository policy script accepts Dependabot branches separately and permits a
`main` back-merge into `develop`.

## Commits and pull request titles

Use [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
Allowed types are `feat`, `fix`, `docs`, `refactor`, `test`, `ci`, `build`,
`chore`, `perf`, and `revert`. An optional scope is lowercase kebab-case. Mark a
breaking change with `!` and a `BREAKING CHANGE:` footer. Keep each commit an
independently understandable and reversible change.

The pull request title becomes the squash commit for ordinary work. Check the
same policy locally from the repository root:

```sh
sh .github/scripts/check-pr-policy.sh \
  develop feat/systemd-rule 'feat(systemd): add unit rule'
```

## Local workflow

Go 1.26 or newer is required. Run Go commands from `lpeco/`:

```sh
make fmt
make verify-ci
```

`make fmt` is the developer convenience target that updates formatting. The CI
aggregate `make verify-ci` is non-mutating and covers format checking, vet,
race-enabled tests, builds, integration tests, and the pinned vulnerability
scan. The guarded `make test-vm` is separate release evidence and requires a
prepared disposable image.

From the repository root, also run:

```sh
sh .github/scripts/check-governance.sh .
sh .github/scripts/check-pr-policy_test.sh
```

## Go review rules

- Keep every Go source file identical to `gofmt` output.
- Add meaningful doc comments to packages and exported names.
- Choose short, specific package names; do not create buckets named `util`,
  `common`, or `misc`.
- Add useful operation context to errors, but redact secrets, credentials, and
  raw target evidence.
- Define the smallest interface at the consuming package. Do not expose an
  interface merely to mirror a concrete implementation.
- For every new dependency, explain why the standard library and existing
  dependencies are insufficient and record security and maintenance impact in
  the pull request.
- Do not commit generated binaries, local session state, or evidence output.

## Safety-sensitive changes

Read [`lpeco/docs/safety-model.md`](lpeco/docs/safety-model.md) before modifying
collection, transport, evidence, graph, rule, or report behavior.

### Probes

A new or changed probe must include:

- a unique registry ID, timeout, output limit, parser, expected fact types, and
  an accurate `passive-read`, `observable-read`, `temporary-artifact`, or
  `state-changing` classification;
- an immutable script with target-derived values supplied only as separately
  quoted positional arguments;
- tests for success, permission denial, a missing tool, and truncated, partial,
  or malformed output as applicable; and
- integration evidence that persistent target state is unchanged.

The scheduler must continue to deny `temporary-artifact` and `state-changing`
probes. A new `observable-read` probe requires explicit operator opt-in and
pre-execution disclosure of its probe ID.

### Candidate rules

A new or changed rule must:

- distinguish the current principal from the higher principal or capability
  boundary;
- connect control, consumer, trigger, and resolved semantics to evidence IDs;
- add at least one positive case and two negative cases with different causes;
- treat denial, parse error, timeout, truncation, and missing tools as unknown,
  never as proof of safety;
- prevent incomplete evidence from becoming P0, high confidence, or
  `read_only_validated`; and
- avoid exploit steps, payloads, and abuse commands in findings.

Update [`lpeco/docs/rules.md`](lpeco/docs/rules.md) when rule semantics change.

### Adapters and reports

Adapters must pass the common contract tests and handle timeout, cancellation,
bounded output, malformed responses, and transport closure. Raw transport may
report success only after complete marker and frame validation. Do not add core
upload or download behavior.

Report or error changes require redaction tests and the relevant golden or JSON
tests. Raw evidence bodies stay out of default terminal and JSON reports.
Compatibility changes to CLI options, report or session schemas, or the adapter
protocol require a migration note and an explicit version decision.

## Pull request gate

A pull request must describe purpose and user-visible behavior, safety and data
exposure impact, compatibility impact, and commands run. Add automated tests for
new behavior and update affected README, safety, rule, adapter, and development
documentation. Every user-visible change updates the `Unreleased` section of
[`CHANGELOG.md`](CHANGELOG.md).

The `policy`, `quality`, `integration`, and `vulnerability` checks must pass,
and every review conversation must be resolved. Review the final diff for
secrets and real assessment data before requesting merge. Security reports do
not belong in public issues; follow [`SECURITY.md`](SECURITY.md).
