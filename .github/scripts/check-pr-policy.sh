#!/bin/sh

set -eu

fail() {
	printf 'error: %s\n' "$1" >&2
	exit 1
}

matches() {
	value=$1
	pattern=$2
	printf '%s\n' "$value" | LC_ALL=C grep -Eq "$pattern"
}

contains_control_character() {
	case "$1" in
		*'
'*) return 0 ;;
	esac

	printf '%s' "$1" | LC_ALL=C grep -q '[[:cntrl:]]'
}

if [ "$#" -ne 3 ]; then
	fail 'expected BASE_REF HEAD_REF PR_TITLE'
fi

base_ref=$1
head_ref=$2
pr_title=$3

if contains_control_character "$base_ref" ||
	contains_control_character "$head_ref" ||
	contains_control_character "$pr_title"; then
	fail 'base, head, and title must not contain control characters'
fi

work_branch='^(feat|fix|docs|refactor|test|ci|chore)/[a-z0-9]+(-[a-z0-9]+)*$'
release_branch='^release/v[0-9]+\.[0-9]+\.[0-9]+$'
hotfix_branch='^hotfix/[a-z0-9]+(-[a-z0-9]+)*$'
dependabot_branch='^dependabot/[A-Za-z0-9._+@-]+(/[A-Za-z0-9._+@-]+)*$'

case "$base_ref" in
	develop)
		case "$head_ref" in
			main) ;;
			*)
				if ! matches "$head_ref" "$work_branch" &&
					! matches "$head_ref" "$release_branch" &&
					! matches "$head_ref" "$hotfix_branch" &&
					! matches "$head_ref" "$dependabot_branch"; then
					fail 'head branch is not permitted to target develop'
				fi
				;;
		esac
		;;
	main)
		if ! matches "$head_ref" "$release_branch" &&
			! matches "$head_ref" "$hotfix_branch"; then
			fail 'only release and hotfix branches may target main'
		fi
		;;
	*)
		fail 'base branch must be main or develop'
		;;
esac

title_pattern='^(feat|fix|docs|refactor|test|ci|build|chore|perf|revert)(\([a-z0-9]+(-[a-z0-9]+)*\))?!?: [A-Za-z0-9][A-Za-z0-9 .,_:/@+()-]*$'
if ! matches "$pr_title" "$title_pattern"; then
	fail 'title must use an allowed Conventional Commit type and safe description'
fi
