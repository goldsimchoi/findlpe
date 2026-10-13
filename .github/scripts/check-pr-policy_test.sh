#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
policy="$script_dir/check-pr-policy.sh"

if [ ! -x "$policy" ]; then
	printf 'FAIL: policy script is missing or not executable: %s\n' "$policy" >&2
	exit 1
fi

test_dir=$(mktemp -d "${TMPDIR:-/tmp}/findlpe-pr-policy.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM

passed=0
failed=0

expect_pass() {
	name=$1
	shift
	if "$policy" "$@" >"$test_dir/stdout" 2>"$test_dir/stderr"; then
		passed=$((passed + 1))
		printf 'ok %d - %s\n' "$passed" "$name"
	else
		status=$?
		failed=$((failed + 1))
		printf 'not ok - %s (exit %d)\n' "$name" "$status" >&2
		sed 's/^/  stderr: /' "$test_dir/stderr" >&2
	fi
}

expect_fail() {
	name=$1
	shift
	if "$policy" "$@" >"$test_dir/stdout" 2>"$test_dir/stderr"; then
		failed=$((failed + 1))
		printf 'not ok - %s (unexpected success)\n' "$name" >&2
	elif [ ! -s "$test_dir/stderr" ]; then
		failed=$((failed + 1))
		printf 'not ok - %s (missing stderr reason)\n' "$name" >&2
	else
		passed=$((passed + 1))
		printf 'ok %d - %s\n' "$passed" "$name"
	fi
}

expect_pass 'feature branch into develop' \
	develop feat/systemd-rule 'feat(systemd): add unit rule'
expect_pass 'Dependabot branch into develop' \
	develop dependabot/go_modules/lpeco/golang.org/x/crypto-0.59.0 \
	'build(deps): bump x/crypto'
expect_pass 'release branch into main' \
	main release/v0.1.0 'chore(release): prepare v0.1.0'
expect_pass 'hotfix branch into main' \
	main hotfix/report-redaction 'fix(report): redact token values'
expect_pass 'main back-merge into develop' \
	develop main 'chore: merge release back into develop'

expect_fail 'unknown base branch' \
	staging feat/systemd-rule 'feat(systemd): add unit rule'
expect_fail 'feature branch cannot target main' \
	main feat/systemd-rule 'feat(systemd): add unit rule'
expect_fail 'uppercase work-branch slug' \
	develop feat/Systemd-rule 'feat(systemd): add unit rule'
expect_fail 'empty work-branch slug' \
	develop feat/ 'feat(systemd): add unit rule'
expect_fail 'double slash in branch' \
	develop feat/systemd//rule 'feat(systemd): add unit rule'
expect_fail 'missing Conventional Commit type' \
	develop feat/systemd-rule 'add unit rule'
expect_fail 'unsupported Conventional Commit type' \
	develop feat/systemd-rule 'style(systemd): add unit rule'
expect_fail 'uppercase title scope' \
	develop feat/systemd-rule 'feat(Systemd): add unit rule'
expect_fail 'newline in base ref' \
	"$(printf 'develop\nmain')" feat/systemd-rule 'feat(systemd): add unit rule'
expect_fail 'newline in head ref' \
	develop "$(printf 'feat/systemd-rule\nmain')" 'feat(systemd): add unit rule'
expect_fail 'newline in PR title' \
	develop feat/systemd-rule "$(printf 'feat(systemd): add unit rule\ninjected')"
expect_fail 'shell metacharacter in branch' \
	develop 'feat/systemd-rule;touch-pwned' 'feat(systemd): add unit rule'

sentinel="$test_dir/injected"
expect_fail 'shell metacharacters in title' \
	develop feat/systemd-rule "feat(systemd): safe; touch $sentinel"
if [ -e "$sentinel" ]; then
	failed=$((failed + 1))
	printf 'not ok - policy evaluated untrusted input\n' >&2
fi

expect_fail 'missing argument' \
	develop feat/systemd-rule
expect_fail 'extra argument' \
	develop feat/systemd-rule 'feat(systemd): add unit rule' extra

if [ "$failed" -ne 0 ]; then
	printf 'FAIL: %d passed, %d failed\n' "$passed" "$failed" >&2
	exit 1
fi

printf 'PASS: %d policy cases\n' "$passed"
