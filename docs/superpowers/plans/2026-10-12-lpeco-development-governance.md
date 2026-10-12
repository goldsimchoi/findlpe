# LPECO Development Governance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** LPECO를 장기 `develop` 브랜치로 운영하고, 기여·보안·리뷰·CI·의존성·릴리스 규칙을 문서와 자동 검사 및 GitHub 설정으로 강제한다.

**Architecture:** 저장소 수준 정책은 루트 문서와 `.github/`에 두고, Go module 전용 작업 규칙과 검증 명령은 `lpeco/`에 둔다. PR 정책은 입력만 검사하는 작은 POSIX shell 경계로 분리하고, GitHub Actions는 그 정책과 Make target을 호출한다. 기존 원격 `main` 이력은 force-push 없이 `develop`에 병합하며, 모든 로컬 검증과 원격 CI가 성공한 뒤 보호 규칙을 적용한다.

**Tech Stack:** Git, GitHub CLI/API, GitHub Actions, POSIX shell, GNU Make, Go 1.26.7, `govulncheck` v1.9.0, `actionlint` v1.7.12, Docker integration fixtures.

**Spec:** `docs/superpowers/specs/2026-10-12-lpeco-development-governance-design.md`

## Global Constraints

- 작업 원격은 `https://github.com/goldsimchoi/findlpe.git`이고 owner는 `@goldsimchoi`다.
- 원격 `main`의 기존 commit `106d3302d99ca641106279f505cca8806f5f5bb7`과 README를 force-push, reset 또는 삭제하지 않는다. 실행 시 원격 SHA가 달라졌으면 병합 전 새 상태를 다시 검토한다.
- 현재 `feature/lpeco-mvp`를 `develop`으로 이름 변경하고, 이후 일반 작업은 `develop`에서 직접 하지 않고 명세의 작업 브랜치 규칙을 따른다.
- 이 변경에서는 `lpeco/` module을 저장소 루트로 옮기거나 module path/API를 재구성하지 않는다.
- `/home/normalone/red` 기본 worktree의 untracked HTB 자료, VPN 파일, `harness/`, `dirsearch/` 및 다른 workspace 파일은 열거나 stage하거나 push하지 않는다.
- GitHub Actions의 외부 action은 full commit SHA로 고정한다: `actions/checkout` v7.0.1은 `3d3c42e5aac5ba805825da76410c181273ba90b1`, `actions/setup-go` v7.0.0은 `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e`다.
- workflow 권한은 `contents: read`이며 fork/PR 코드에 repository secret이나 write token을 제공하지 않는다.
- `govulncheck`는 v1.9.0, `actionlint`는 v1.7.12로 고정하고 `@latest`를 사용하지 않는다.
- LPECO의 read-only 안전 경계, evidence 보수성, redaction, probe safety class와 rule negative-test 조건은 완화하지 않는다.
- license는 소유자가 별도로 선택할 때까지 공개 릴리스 차단 항목으로 남긴다. 가짜 보안 이메일을 만들지 않는다.
- disposable VM image가 없으면 `make test-vm` 성공을 주장하지 않는다.
- 각 구현 commit은 검증 후 `origin/develop`에 push한다. `main`에는 이 작업 중 직접 push하지 않는다.
- 실행 방식은 사용자가 요청한 Native 방식이다. 현재 세션의 주 agent가 각 task를 순서대로 구현하고 마지막에 독립 branch review를 수행한다.

## Review Focus

1. 서로 무관한 local/remote root history를 합칠 때 원격 `main`이나 로컬 MVP commit을 잃지 않고 PR 가능한 공통 조상을 만드는가.
2. PR title과 branch 이름에 newline, shell metacharacter, uppercase 또는 예상 밖 slash가 있어도 command injection 없이 명확히 거부되는가.
3. workflow가 untrusted PR에서 최소 권한을 유지하고, 모든 action이 검증된 immutable SHA에 고정되는가.
4. `make verify`가 파일을 수정하지 않으며 vulnerability database/network/tool 실패를 성공으로 바꾸지 않는가.
5. 단일 maintainer가 self-review할 수 있으면서도 direct push, force-push, branch deletion과 실패한 required check 병합을 실제 GitHub 설정으로 막는가.

## File and Responsibility Map

```text
README.md                                  # 저장소 진입점과 module 링크
CONTRIBUTING.md                            # 사람용 기여·branch·review 규칙
SECURITY.md                                # 지원 범위와 비공개 신고 절차
CHANGELOG.md                               # Unreleased 및 SemVer 변경 이력
docs/development.md                        # 로컬 개발, fixture, CI, release 절차
docs/maintainers/github-settings.md        # 재현 가능한 GitHub 설정과 검증법
docs/superpowers/specs/...governance...md  # 확정된 원격/owner 사실 반영
lpeco/AGENTS.md                            # module-scoped agent 작업 규칙
lpeco/Makefile                             # 비변경 검증과 pinned security tools
.github/scripts/check-pr-policy.sh         # pure PR base/head/title validator
.github/scripts/check-pr-policy_test.sh    # validator table tests
.github/scripts/check-governance.sh        # 필수 정책 파일과 핵심 값 검사
.github/workflows/ci.yml                   # policy/quality/integration/vulnerability CI
.github/PULL_REQUEST_TEMPLATE.md           # 안전·호환성·검증 self-review
.github/ISSUE_TEMPLATE/*.yml               # redacted bug/feature intake와 routing
.github/CODEOWNERS                         # @goldsimchoi review routing
.github/dependabot.yml                     # monthly Go/Actions updates
```

---

### Task 1: Preserve the Remote History and Establish `develop`

**Files:**
- Modify: `docs/superpowers/specs/2026-10-12-lpeco-development-governance-design.md`
- Preserve from remote: `README.md`

**Interfaces:**
- Consumes: local clean branch `feature/lpeco-mvp`; remote `main` at the observed SHA.
- Produces: local and remote `develop`, upstream tracking `origin/develop`, a shared history with `origin/main`, and the approved spec updated with the actual repository identity.

- [ ] **Step 1: Revalidate local and remote identities without mutation**

Run from `/home/normalone/red/.worktrees/lpeco-mvp`:

```bash
git status --short --branch
git branch --show-current
git ls-remote --heads https://github.com/goldsimchoi/findlpe.git
```

Expected: clean `feature/lpeco-mvp`; remote `main` exists. If the remote SHA differs from `106d3302...`, inspect it before continuing rather than forcing the expected state.

- [ ] **Step 2: Rename the integration branch and connect the remote**

Run:

```bash
git branch -m develop
git remote add origin https://github.com/goldsimchoi/findlpe.git
git fetch origin --prune
```

Expected: `git branch --show-current` prints `develop`; `origin/main` exists. If `origin` already exists, verify its exact URL and use `git remote set-url origin ...` only when it is not the requested repository.

- [ ] **Step 3: Merge the one-commit remote history without rewriting either side**

Run:

```bash
git merge --no-ff --allow-unrelated-histories origin/main -m "chore: connect findlpe repository history"
```

Expected: a merge commit, remote `README.md` present, and all prior LPECO commits still reachable. Verify with `git merge-base develop origin/main` and `git log --graph --oneline --all -12`.

- [ ] **Step 4: Record the real remote and owner in the approved spec**

Change the current-state section to name `goldsimchoi/findlpe`, mark the design approved, replace the provisional `@normalone` CODEOWNER with `@goldsimchoi`, and state that the remote `main` stub is preserved while `develop` becomes the default integration branch.

- [ ] **Step 5: Verify and commit the factual spec update**

Run: `git diff --check && git diff -- docs/superpowers/specs/2026-10-12-lpeco-development-governance-design.md`

Expected: only factual repository-state changes and no whitespace errors.

Commit:

```bash
git add docs/superpowers/specs/2026-10-12-lpeco-development-governance-design.md README.md
git commit -m "docs: bind governance to findlpe repository"
```

- [ ] **Step 6: Publish `develop` without modifying remote `main`**

Run: `git push -u origin develop`

Expected: a new `origin/develop` at local HEAD; `origin/main` remains at its original remote commit.

### Task 2: Enforce Pull Request Naming and Flow as a Pure Policy Boundary

**Files:**
- Create: `.github/scripts/check-pr-policy_test.sh`
- Create: `.github/scripts/check-pr-policy.sh`

**Interfaces:**
- Consumes: `check-pr-policy.sh BASE_REF HEAD_REF PR_TITLE` as three positional strings.
- Produces: exit `0` with no mutation for a permitted flow; nonzero plus a concise stderr reason for invalid base/head/title.

- [ ] **Step 1: Write failing table tests for valid and invalid flows**

The test script must assert success for:

- `develop`, `feat/systemd-rule`, `feat(systemd): add unit rule`
- `develop`, `dependabot/go_modules/lpeco/golang.org/x/crypto-0.59.0`, `build(deps): bump x/crypto`
- `main`, `release/v0.1.0`, `chore(release): prepare v0.1.0`
- `main`, `hotfix/report-redaction`, `fix(report): redact token values`

It must assert failure for unknown base branches, `feat/*` into `main`, uppercase or empty slug, double slash, missing Conventional Commit type, unsupported type, newline in any input, and shell metacharacters that do not match the allowed grammar.

- [ ] **Step 2: Run the tests and verify the missing implementation fails**

Run: `sh .github/scripts/check-pr-policy_test.sh`

Expected: FAIL because `check-pr-policy.sh` does not exist.

- [ ] **Step 3: Implement the validator with anchored allowlists**

Use POSIX `case` and anchored `grep -E`; never evaluate input. `develop` accepts `feat|fix|docs|refactor|test|ci|chore/<kebab-slug>`, `release/vX.Y.Z`, `hotfix/<kebab-slug>`, `dependabot/*`, and the `main` back-merge. `main` accepts only release and hotfix branches. PR titles accept the documented Conventional Commit types with optional lowercase scope and optional `!`.

- [ ] **Step 4: Run policy tests**

Run: `sh .github/scripts/check-pr-policy_test.sh`

Expected: PASS with each case counted and no repository changes.

- [ ] **Step 5: Commit and push**

```bash
git add .github/scripts/check-pr-policy.sh .github/scripts/check-pr-policy_test.sh
git commit -m "ci: enforce pull request naming policy"
git push origin develop
```

### Task 3: Add Human and Agent Development Governance

**Files:**
- Modify: `README.md`
- Create: `CONTRIBUTING.md`
- Create: `SECURITY.md`
- Create: `CHANGELOG.md`
- Create: `docs/development.md`
- Create: `docs/maintainers/github-settings.md`
- Create: `lpeco/AGENTS.md`
- Create: `.github/scripts/check-governance.sh`

**Interfaces:**
- Consumes: approved governance spec and existing `lpeco/README.md`, `lpeco/docs/safety-model.md`, `lpeco/docs/rules.md`.
- Produces: stable human/agent policy documents; `check-governance.sh [REPO_ROOT]` defaults to the Git root and exits nonzero when a required policy file or pinned invariant is absent.

- [ ] **Step 1: Write the governance checker before the documents**

The checker must require each file in this task, executable policy scripts, exact branch names `main`/`develop`, `@goldsimchoi`, the private-reporting URL, `make verify-ci`, the read-only prohibition language, and the release blockers for license and disposable VM evidence. It must reject `TODO`, `TBD`, `example.com`, placeholder email addresses and `@latest` within the operational policy files.

- [ ] **Step 2: Run the checker and verify missing documents fail**

Run: `sh .github/scripts/check-governance.sh .`

Expected: FAIL listing `CONTRIBUTING.md` first, without stopping at a shell syntax error.

- [ ] **Step 3: Write the repository entrypoint and contribution rules**

`README.md` must explain that implementation lives under `lpeco/`, link build/use/safety docs, state the authorized-assessment boundary, and link CONTRIBUTING/SECURITY/CHANGELOG. `CONTRIBUTING.md` must pin branch flow, Conventional Commits, PR gates, probe/rule/adapter/report obligations and local commands from the spec. It must also carry the Go review rules for `gofmt`, package/exported-name comments, specific package names, contextual but redacted errors, consumer-owned minimal interfaces and justified dependencies.

- [ ] **Step 4: Write security, changelog, development and maintainer docs**

`SECURITY.md` must support `develop` until the first release, then the latest minor line, direct reporters to GitHub private vulnerability reporting, prohibit public disclosure of credentials/assessment evidence, and promise no response time not yet staffed. `CHANGELOG.md` starts with `Unreleased`, uses `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, and `Security`, and summarizes the implemented MVP without declaring a release. Contribution/release docs require every user-visible PR to update `Unreleased` and retain CLI version metadata as a first-public-release prerequisite. The development and maintainer docs must make every command and remote setting reproducible.

- [ ] **Step 5: Write the module-scoped agent contract**

`lpeco/AGENTS.md` must direct agents to read nearby safety/rule docs, use tests first, preserve fixed probe scripts and evidence semantics, avoid unrelated workspace files, run proportional verification, and never add exploit/payload/state-changing behavior.

- [ ] **Step 6: Run policy and link checks**

Run:

```bash
sh -n .github/scripts/check-governance.sh .github/scripts/check-pr-policy.sh .github/scripts/check-pr-policy_test.sh
sh .github/scripts/check-governance.sh .
rg -n 'CONTRIBUTING|SECURITY|CHANGELOG|development' README.md
```

Expected: PASS; each linked relative path exists.

- [ ] **Step 7: Commit and push**

```bash
git add README.md CONTRIBUTING.md SECURITY.md CHANGELOG.md docs/development.md docs/maintainers/github-settings.md lpeco/AGENTS.md .github/scripts/check-governance.sh
git commit -m "docs: establish contribution and security governance"
git push origin develop
```

### Task 4: Add GitHub Review, Issue and Dependency Metadata

**Files:**
- Create: `.github/PULL_REQUEST_TEMPLATE.md`
- Create: `.github/ISSUE_TEMPLATE/bug_report.yml`
- Create: `.github/ISSUE_TEMPLATE/feature_request.yml`
- Create: `.github/ISSUE_TEMPLATE/config.yml`
- Create: `.github/CODEOWNERS`
- Create: `.github/dependabot.yml`
- Modify: `.github/scripts/check-governance.sh`

**Interfaces:**
- Consumes: branch/safety rules in CONTRIBUTING and SECURITY.
- Produces: GitHub-native intake and ownership metadata, plus checker coverage for required keys and owner routing.

- [ ] **Step 1: Extend the checker first and confirm red state**

Require all six files, `@goldsimchoi`, `blank_issues_enabled: false`, Go module directory `/lpeco`, Actions directory `/`, monthly schedules, grouped minor/patch updates, and PR checklist entries for safety, tests, docs, compatibility and secret review.

Run: `sh .github/scripts/check-governance.sh .`

Expected: FAIL on the first absent `.github` metadata file.

- [ ] **Step 2: Add CODEOWNERS and the PR template**

Route the whole repository, `.github/`, probe/rule/adapter/report code and safety documentation to `@goldsimchoi`. The template must not ask contributors to paste raw target output; it asks for redacted evidence and exact local commands run.

- [ ] **Step 3: Add structured issue forms**

The bug form collects version/commit, Linux distribution, transport, redacted reproduction, expected/actual behavior and safety/data impact. The feature form collects authorized use case, proposed evidence, safety class, alternatives and compatibility. Config disables blank issues and links security reports to `https://github.com/goldsimchoi/findlpe/security`.

- [ ] **Step 4: Add monthly Dependabot configuration**

Configure `gomod` at `/lpeco` and `github-actions` at `/`. Group patch/minor updates per ecosystem and exclude major updates from those groups so they arrive as separate PRs.

- [ ] **Step 5: Validate YAML and governance requirements**

Run:

```bash
python3 - <<'PY'
from pathlib import Path
import yaml
for path in Path('.github').rglob('*.yml'):
    yaml.safe_load(path.read_text())
    print(path)
PY
sh .github/scripts/check-governance.sh .
```

Expected: every YAML file parses and the governance checker passes. This local PyYAML check is supplemental; GitHub's own parser after push is the authoritative remote check.

- [ ] **Step 6: Commit and push**

```bash
git add .github/PULL_REQUEST_TEMPLATE.md .github/ISSUE_TEMPLATE .github/CODEOWNERS .github/dependabot.yml .github/scripts/check-governance.sh
git commit -m "chore: add GitHub collaboration metadata"
git push origin develop
```

### Task 5: Make Local Verification Deterministic and Non-Mutating

**Files:**
- Modify: `lpeco/Makefile`
- Modify: `lpeco/README.md`

**Interfaces:**
- Consumes: existing Go package/test/build targets and repository policy scripts.
- Produces: `fmt-check`, `test-policy`, `test-governance`, `vulncheck`, and a non-mutating `verify`; tool variables `GOVULNCHECK_VERSION=v1.9.0` and `ACTIONLINT_VERSION=v1.7.12` for the next task.

- [ ] **Step 1: Exercise the missing targets and record the expected failure**

Run from `lpeco/`:

```bash
make fmt-check
make vulncheck
make test-policy
make test-governance
```

Expected: FAIL with “No rule to make target” before editing the Makefile.

- [ ] **Step 2: Add focused targets and change `verify` to use `fmt-check`**

`fmt-check` runs `gofmt -l` and prints every mismatched file before failing without modifying it. `vulncheck` runs `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...`. Policy targets call the scripts relative to the module directory. Preserve `fmt` as the explicit mutating local convenience command.

- [ ] **Step 3: Prove the verification path does not mutate tracked files**

Run:

```bash
before="$(git status --porcelain --untracked-files=no)"
make verify
after="$(git status --porcelain --untracked-files=no)"
test "$before" = "$after"
```

Expected: PASS and identical status snapshots.

- [ ] **Step 4: Run the new policy and vulnerability targets**

Run: `make test-policy && make test-governance && make vulncheck`

Expected: all pass; `govulncheck` reports no reachable known vulnerability. A database/network/tool failure is a test failure, not a skip.

- [ ] **Step 5: Update user-facing build verification commands**

Document `make verify`, `make test-integration`, `make vulncheck`, and the future `make verify-ci`; keep the disposable VM caveat explicit.

- [ ] **Step 6: Commit and push**

```bash
git add lpeco/Makefile lpeco/README.md
git commit -m "build: make local verification deterministic"
git push origin develop
```

### Task 6: Add Least-Privilege GitHub Actions CI

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `lpeco/Makefile`
- Modify: `.github/scripts/check-governance.sh`
- Modify: `docs/development.md`

**Interfaces:**
- Consumes: Make targets and PR policy scripts from Tasks 2–5.
- Produces: GitHub checks named exactly `policy`, `quality`, `integration`, and `vulnerability`; `make lint-actions`; aggregate `make verify-ci`.

- [ ] **Step 1: Add failing governance expectations for CI**

Extend the checker to require workflow-level `permissions: contents: read`, concurrency cancellation, job timeouts, the four exact job IDs, both pinned action SHAs, `working-directory: lpeco`, and absence of mutable `uses: ...@vN` references.

Run: `sh .github/scripts/check-governance.sh .`

Expected: FAIL because `.github/workflows/ci.yml` is absent.

- [ ] **Step 2: Create the workflow with four isolated jobs**

Trigger on pushes to and PRs targeting `main`/`develop`. The `policy` job checks out and runs the policy/governance scripts, passing PR metadata through quoted environment variables rather than interpolating expressions into shell source. `quality` runs `make verify`; `integration` runs `make test-integration`; `vulnerability` runs `make vulncheck`. Every job has a finite timeout and only read permission.

- [ ] **Step 3: Add `lint-actions` and `verify-ci` Make targets**

`lint-actions` runs `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 ../.github/workflows/*.yml`. `verify-ci` depends on `verify`, `test-policy`, `test-governance`, `lint-actions`, `test-integration`, and `vulncheck`.

- [ ] **Step 4: Validate workflow syntax and the complete local gate**

Run from `lpeco/`:

```bash
make lint-actions
make verify-ci
```

Expected: actionlint has no findings; format/vet/race/build/policy/governance/container integration/vulnerability checks all pass.

- [ ] **Step 5: Verify no generated change and update CI documentation**

Run: `git diff --check && git status --short`

Expected: only the four planned files are modified/untracked; no Go source or `go.mod`/`go.sum` drift from tool execution.

- [ ] **Step 6: Commit and push the workflow**

```bash
git add .github/workflows/ci.yml .github/scripts/check-governance.sh lpeco/Makefile docs/development.md
git commit -m "ci: verify lpeco changes on GitHub"
git push origin develop
```

### Task 7: Prove Local and Hosted Acceptance Gates

**Files:**
- Modify only if evidence exposes a defect: files owned by the failing task
- Update when verification commands change: `CHANGELOG.md`, `docs/development.md`

**Interfaces:**
- Consumes: all governance and CI artifacts.
- Produces: clean local acceptance evidence and one successful GitHub Actions run for `develop`.

- [ ] **Step 1: Run the complete local gate from a clean status**

Run:

```bash
git diff --check
cd lpeco
make verify-ci
```

Expected: PASS. If anything fails, use `superpowers:systematic-debugging`, fix the owning task, rerun its focused check, then rerun `make verify-ci`.

- [ ] **Step 2: Re-run the named MVP acceptance and safety suites explicitly**

Run from `lpeco/`:

```bash
go test -tags=integration ./test/integration -count=1 -v
go test ./internal/rules -run TestAllRulesHavePositiveAndTwoNegatives -count=1 -v
go test ./internal/report -run TestReportsContainNoSecrets -count=1 -v
```

Expected: all tests pass; this supplements rather than replaces `verify-ci`.

- [ ] **Step 3: Exercise the VM release gate without bypassing its guard**

Run: `make test-vm`

Expected in the current environment: a clear failure explaining that `LPECO_VM_DISPOSABLE` and an image are required. Record this as an outstanding release gate; do not weaken the guard or label it passed.

- [ ] **Step 4: Push any evidence-driven corrections and wait for hosted CI**

If Step 1 or 2 required corrections, commit them with the narrow Conventional Commit type and `git push origin develop`. Then run:

```bash
head_sha="$(git rev-parse HEAD)"
run_id="$(gh run list --repo goldsimchoi/findlpe --branch develop --workflow CI --limit 10 --json databaseId,headSha --jq ".[] | select(.headSha == \"$head_sha\") | .databaseId" | head -n 1)"
test -n "$run_id"
gh run watch "$run_id" --repo goldsimchoi/findlpe --exit-status
```

Expected: the latest run for the current `origin/develop` SHA completes successfully. Confirm all four job conclusions through `gh run view`.

- [ ] **Step 5: Verify GitHub parsed repository metadata**

Use `gh api` to read the workflow, default branch, repository contents and security endpoints. Expected: the workflow is active, issue-form/YAML files are retrievable, and remote `main` still contains its original history.

### Task 8: Apply and Audit GitHub Repository Protections

**Files:**
- Modify: `docs/maintainers/github-settings.md` only if actual API behavior differs from the documented commands

**Interfaces:**
- Consumes: green hosted checks `policy`, `quality`, `integration`, `vulnerability` and admin authentication for `goldsimchoi/findlpe`.
- Produces: default branch `develop`, read-only workflow token default, protected `main`/`develop`, private vulnerability reporting and dependency security features.

- [ ] **Step 1: Configure non-destructive repository defaults**

Use GitHub API to set `default_branch=develop`, delete merged branches, allow squash and merge commits, disable rebase merges, and set Actions `default_workflow_permissions=read` with PR approval disabled for workflows. Read back each value immediately.

- [ ] **Step 2: Enable security reporting and dependency alerts**

Enable private vulnerability reporting, vulnerability alerts and automated security fixes through their official repository API endpoints. If an endpoint is unavailable for the account/repository, retain the documented manual step and report the exact response rather than claiming success.

- [ ] **Step 3: Protect `main` and `develop`**

For both branches require PRs, strict up-to-date status, checks `policy`, `quality`, `integration`, `vulnerability`, conversation resolution, admin enforcement, and prohibit force-push/deletion. Set required approvals to zero while there is only one maintainer; do not require CODEOWNER approval yet. Preserve merge commits because release/hotfix reconciliation requires them.

- [ ] **Step 4: Read back and assert the protection contract**

Run `gh api repos/goldsimchoi/findlpe/branches/{main,develop}/protection` and inspect exact booleans and required contexts. Also verify `origin/main` was never force-updated and `origin/develop` equals local HEAD.

- [ ] **Step 5: Reconcile documentation only if the platform imposed a real difference**

If GitHub rejected an unsupported setting, update `docs/maintainers/github-settings.md` with the actual supported path, rerun governance checks, commit on a new `docs/github-settings` branch, open a PR to `develop`, wait for checks and merge through the newly protected workflow. Do not bypass protection.

### Task 9: Final Independent Review and Completion Audit

**Files:**
- Review: every file listed in the file map
- Review: remote branch/settings state

**Interfaces:**
- Consumes: the approved spec, this plan, local commits, hosted checks and GitHub API readbacks.
- Produces: requirement-by-requirement evidence that the governance system is complete, plus an explicit list of external release blockers that remain by design.

- [ ] **Step 1: Request a fresh whole-branch code review**

Use `superpowers:requesting-code-review` with base `origin/main` and head `origin/develop`, emphasizing shell injection, workflow supply-chain safety, branch topology, Make non-mutation and contradictions across documents. Resolve all important findings through feature/fix branches and protected PRs.

- [ ] **Step 2: Run final verification after review fixes**

Run from `lpeco/`: `make verify-ci`; from repository root: `git diff --check`, `sh .github/scripts/check-governance.sh .`, and `git status --short --branch`.

Expected: all executable checks pass and the worktree is clean.

- [ ] **Step 3: Audit every spec acceptance criterion against authoritative evidence**

Map each item in spec section 15 to a local file/command, GitHub Actions result or API response. Treat the disposable VM test and license as outstanding first-release blockers, not failures of this governance implementation.

- [ ] **Step 4: Verify final remote state**

Confirm `develop` is the current/default protected branch, `main` is protected and unchanged except its original README history, all implementation commits are on `origin/develop`, CI is green, private reporting state is known, and no tag/release was created.

- [ ] **Step 5: Hand off the result**

Report branch/commit URLs, files added, local/remote checks, repository settings applied, and the two intentionally outstanding release prerequisites (license selection and disposable VM evidence). Do not claim a public `v0.1.0` release.
