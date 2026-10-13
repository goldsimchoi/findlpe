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
	.github/scripts/check-governance.sh; do
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
