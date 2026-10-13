#!/bin/sh

set -eu

fail() {
	printf 'FAIL: %s\n' "$1" >&2
	exit 1
}

if [ "$#" -gt 1 ]; then
	fail 'usage: check-governance.sh [REPO_ROOT]'
fi

if [ "$#" -eq 1 ]; then
	root_input=$1
else
	root_input=$(git rev-parse --show-toplevel 2>/dev/null) ||
		fail 'not inside a Git repository'
fi

root=$(CDPATH= cd -- "$root_input" 2>/dev/null && pwd) ||
	fail 'repository root is not a readable directory'

require_file() {
	relative_path=$1
	[ -f "$root/$relative_path" ] || fail "missing required file: $relative_path"
}

require_executable() {
	relative_path=$1
	[ -x "$root/$relative_path" ] || fail "required script is not executable: $relative_path"
}

require_text() {
	relative_path=$1
	required_text=$2
	description=$3
	LC_ALL=C grep -Fq -- "$required_text" "$root/$relative_path" ||
		fail "$relative_path is missing $description"
}

# Keep this order stable so a fresh checkout reports the primary contributor
# entrypoint first.
for required_file in \
	CONTRIBUTING.md \
	SECURITY.md \
	CHANGELOG.md \
	docs/development.md \
	docs/maintainers/github-settings.md \
	lpeco/AGENTS.md \
	README.md \
	.github/scripts/check-governance.sh \
	.github/PULL_REQUEST_TEMPLATE.md \
	.github/ISSUE_TEMPLATE/bug_report.yml \
	.github/ISSUE_TEMPLATE/feature_request.yml \
	.github/ISSUE_TEMPLATE/config.yml \
	.github/CODEOWNERS \
	.github/dependabot.yml \
	.github/workflows/ci.yml; do
	require_file "$required_file"
done

for policy_script in \
	.github/scripts/check-governance.sh \
	.github/scripts/check-pr-policy.sh \
	.github/scripts/check-pr-policy_test.sh; do
	require_executable "$policy_script"
done

require_text README.md 'lpeco/' 'the implementation directory'
require_text README.md '(CONTRIBUTING.md)' 'the contribution guide link'
require_text README.md '(SECURITY.md)' 'the security policy link'
require_text README.md '(CHANGELOG.md)' 'the changelog link'
require_text README.md '(docs/development.md)' 'the development guide link'

require_text CONTRIBUTING.md '`develop`' 'the develop branch policy'
require_text CONTRIBUTING.md '`main`' 'the main branch policy'
require_text CONTRIBUTING.md 'Conventional Commits' 'the commit convention'
require_text CONTRIBUTING.md 'make verify-ci' 'the local CI command'
require_text CONTRIBUTING.md 'read-only' 'the read-only collection boundary'
require_text CONTRIBUTING.md 'Unreleased' 'the changelog update rule'

require_text SECURITY.md '`develop`' 'the pre-release support line'
require_text SECURITY.md 'latest minor' 'the released-version support rule'
require_text SECURITY.md \
	'https://github.com/goldsimchoi/findlpe/security/advisories/new' \
	'the private vulnerability reporting URL'

for changelog_section in Added Changed Deprecated Removed Fixed Security; do
	require_text CHANGELOG.md "### $changelog_section" "the $changelog_section section"
done
require_text CHANGELOG.md '## Unreleased' 'the Unreleased heading'

require_text docs/development.md 'make verify-ci' 'the full local verification command'
require_text docs/development.md 'check-pr-policy.sh' 'the PR policy reproduction command'

require_text docs/maintainers/github-settings.md '@goldsimchoi' 'the repository owner'
require_text docs/maintainers/github-settings.md '`develop`' 'the default branch'
require_text docs/maintainers/github-settings.md '`main`' 'the release branch'
require_text docs/maintainers/github-settings.md 'License selection' 'the license release blocker'
require_text docs/maintainers/github-settings.md 'Disposable VM evidence' 'the VM release blocker'

require_text lpeco/AGENTS.md 'docs/safety-model.md' 'the safety model instruction'
require_text lpeco/AGENTS.md 'docs/rules.md' 'the rule authoring instruction'
require_text lpeco/AGENTS.md 'read-only' 'the read-only agent boundary'
require_text lpeco/AGENTS.md 'state-changing' 'the state-changing behavior prohibition'

for checklist_item in Safety Tests Documentation Compatibility Secrets; do
	require_text .github/PULL_REQUEST_TEMPLATE.md \
		"- [ ] $checklist_item" "the $checklist_item checklist item"
done
require_text .github/PULL_REQUEST_TEMPLATE.md 'redacted evidence' 'redacted evidence guidance'
require_text .github/PULL_REQUEST_TEMPLATE.md 'Exact commands run' 'the command-results prompt'

for bug_field in version distribution transport reproduction expected actual safety_impact; do
	require_text .github/ISSUE_TEMPLATE/bug_report.yml \
		"id: $bug_field" "the $bug_field bug field"
done
for feature_field in use_case proposed_evidence safety_class alternatives compatibility; do
	require_text .github/ISSUE_TEMPLATE/feature_request.yml \
		"id: $feature_field" "the $feature_field feature field"
done
require_text .github/ISSUE_TEMPLATE/config.yml \
	'blank_issues_enabled: false' 'the disabled blank-issue setting'
require_text .github/ISSUE_TEMPLATE/config.yml \
	'https://github.com/goldsimchoi/findlpe/security' 'the security-report link'

require_text .github/CODEOWNERS '@goldsimchoi' 'the repository owner'
for owned_path in '/.github/' '/lpeco/internal/probe/' '/lpeco/internal/rules/' '/lpeco/internal/adapter/' '/lpeco/internal/report/' '/lpeco/docs/safety-model.md'; do
	require_text .github/CODEOWNERS "$owned_path" "the $owned_path ownership route"
done

require_text .github/dependabot.yml 'package-ecosystem: "gomod"' 'the Go module ecosystem'
require_text .github/dependabot.yml 'directory: "/lpeco"' 'the Go module directory'
require_text .github/dependabot.yml 'package-ecosystem: "github-actions"' 'the Actions ecosystem'
require_text .github/dependabot.yml 'directory: "/"' 'the Actions directory'
monthly_count=$(LC_ALL=C grep -Fc 'interval: "monthly"' "$root/.github/dependabot.yml" || :)
[ "$monthly_count" -eq 2 ] || fail '.github/dependabot.yml must contain two monthly schedules'
group_count=$(LC_ALL=C grep -Fc 'update-types: ["minor", "patch"]' "$root/.github/dependabot.yml" || :)
[ "$group_count" -eq 2 ] || fail '.github/dependabot.yml must group minor and patch updates in both ecosystems'
commit_prefix_count=$(LC_ALL=C grep -Ec '^[[:space:]]+prefix: "build"$' "$root/.github/dependabot.yml" || :)
[ "$commit_prefix_count" -eq 2 ] || fail '.github/dependabot.yml must use the build commit prefix in both ecosystems'
commit_scope_count=$(LC_ALL=C grep -Fc 'include: "scope"' "$root/.github/dependabot.yml" || :)
[ "$commit_scope_count" -eq 2 ] || fail '.github/dependabot.yml must include dependency scope in both ecosystems'

workflow=.github/workflows/ci.yml
require_text "$workflow" 'permissions:' 'workflow permissions'
require_text "$workflow" '  contents: read' 'read-only contents permission'
require_text "$workflow" 'cancel-in-progress: true' 'concurrency cancellation'
require_text "$workflow" 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' 'the pinned checkout action'
require_text "$workflow" 'actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e' 'the pinned setup-go action'
require_text "$workflow" 'working-directory: lpeco' 'the Go module working directory'
require_text "$workflow" 'BASE_REF: ${{ github.base_ref }}' 'the quoted PR base environment input'
require_text "$workflow" 'HEAD_REF: ${{ github.head_ref }}' 'the quoted PR head environment input'
require_text "$workflow" 'PR_TITLE: ${{ github.event.pull_request.title }}' 'the quoted PR title environment input'

for job_id in policy quality integration vulnerability; do
	if ! LC_ALL=C grep -Eq "^  $job_id:$" "$root/$workflow"; then
		fail "$workflow is missing the $job_id job ID"
	fi
	if ! LC_ALL=C grep -Eq "^    name: $job_id$" "$root/$workflow"; then
		fail "$workflow must expose the exact $job_id check name"
	fi
done
timeout_count=$(LC_ALL=C grep -Ec '^    timeout-minutes: [1-9][0-9]*$' "$root/$workflow" || :)
[ "$timeout_count" -eq 4 ] || fail "$workflow must set a finite timeout on all four jobs"
working_directory_count=$(LC_ALL=C grep -Fc 'working-directory: lpeco' "$root/$workflow" || :)
[ "$working_directory_count" -eq 3 ] || fail "$workflow must set the module directory on all three Go jobs"
branch_filter_count=$(LC_ALL=C grep -Fc 'branches: [main, develop]' "$root/$workflow" || :)
[ "$branch_filter_count" -eq 2 ] || fail "$workflow must cover pushes and pull requests for main and develop"

invalid_uses=$(LC_ALL=C grep -En '^[[:space:]]*- uses:' "$root/$workflow" |
	LC_ALL=C grep -Ev '@[0-9a-f]{40}([[:space:]]*#.*)?$' || :)
if [ -n "$invalid_uses" ]; then
	first_invalid_use=$(printf '%s\n' "$invalid_uses" | sed -n '1p')
	fail "$workflow contains an action not pinned to a full commit SHA: $first_invalid_use"
fi
if LC_ALL=C grep -Eq 'uses:[[:space:]]+[^[:space:]#]+@v[0-9]+([[:space:]#]|$)' "$root/$workflow"; then
	fail "$workflow contains a mutable major-version action reference"
fi

operational_files='README.md CONTRIBUTING.md SECURITY.md CHANGELOG.md docs/development.md docs/maintainers/github-settings.md lpeco/AGENTS.md'
for operational_file in $operational_files; do
	forbidden=$(LC_ALL=C grep -En \
		'(TODO|TBD|example\.com|placeholder@|your[-_ ]?email|@latest)' \
		"$root/$operational_file" || :)
	if [ -n "$forbidden" ]; then
		first_match=$(printf '%s\n' "$forbidden" | sed -n '1p')
		fail "$operational_file contains placeholder text: $first_match"
	fi
done

printf 'PASS: governance documents and pinned invariants are present\n'
