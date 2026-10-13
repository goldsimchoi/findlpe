# GitHub Repository Settings

This runbook applies to `goldsimchoi/findlpe`; the repository owner and default
CODEOWNER are `@goldsimchoi`. Treat command success as provisional until the
corresponding readback confirms the value. Do not bypass protection to repair a
setting.

Set the repository identifier once in the maintainer shell:

```sh
repo=goldsimchoi/findlpe
```

## Repository and merge policy

The default integration branch is `develop`. `main` remains the release branch
and its original bootstrap history must not be force-updated. Permit squash
merge for ordinary pull requests and merge commits for release/hotfix
reconciliation; disable rebase merge and remove merged work branches.

```sh
gh api --method PATCH "repos/$repo" \
  -f default_branch=develop \
  -F delete_branch_on_merge=true \
  -F allow_squash_merge=true \
  -F allow_merge_commit=true \
  -F allow_rebase_merge=false

gh api "repos/$repo" \
  --jq '{default_branch,delete_branch_on_merge,allow_squash_merge,allow_merge_commit,allow_rebase_merge}'
```

Set the default GitHub Actions token to read-only and prevent workflows from
approving pull requests:

```sh
gh api --method PUT "repos/$repo/actions/permissions/workflow" \
  -f default_workflow_permissions=read \
  -F can_approve_pull_request_reviews=false

gh api "repos/$repo/actions/permissions/workflow"
```

## Branch protection

Apply the same baseline to `main` and `develop`. It requires pull requests,
strictly up-to-date `policy`, `quality`, `integration`, and `vulnerability`
checks, resolved conversations, and admin enforcement. Force-push and branch
deletion remain disabled.

The project currently has one maintainer, so the required approval count is
zero and CODEOWNER approval is not required. When a second active maintainer is
added, change both branches to one required approval and require CODEOWNER
review.

```sh
for branch in main develop; do
  gh api --method PUT "repos/$repo/branches/$branch/protection" \
    --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["policy", "quality", "integration", "vulnerability"]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": false,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 0,
    "require_last_push_approval": false
  },
  "restrictions": null,
  "required_conversation_resolution": true,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "lock_branch": false,
  "allow_fork_syncing": false
}
JSON
done

for branch in main develop; do
  gh api "repos/$repo/branches/$branch/protection" \
    --jq '{required_status_checks,enforce_admins,required_pull_request_reviews,required_conversation_resolution,required_linear_history,allow_force_pushes,allow_deletions}'
done
```

Before applying required checks, confirm a successful CI run has created all
four check names on `develop`. If repository plan or API capability rejects a
field, record the supported setting here through a normal protected pull
request; do not silently weaken the documented policy.

## Security features

Enable dependency alerts, automated security fixes, and private vulnerability
reporting, then read each endpoint back. Enable secret scanning and push
protection too when the repository plan exposes those controls.

```sh
gh api --method PUT "repos/$repo/vulnerability-alerts"
gh api --method PUT "repos/$repo/automated-security-fixes"
gh api --method PUT "repos/$repo/private-vulnerability-reporting"

gh api -i "repos/$repo/vulnerability-alerts"
gh api "repos/$repo/automated-security-fixes"
gh api "repos/$repo/private-vulnerability-reporting"
```

The public reporting path in `SECURITY.md` is
`https://github.com/goldsimchoi/findlpe/security/advisories/new`. Never replace
it with an unmonitored email address.

## Readback record

For each settings change, retain the command output or API response in the
maintainer's release evidence outside the repository. Confirm:

- repository default branch is exactly `develop`;
- merge settings and default workflow permissions match this file;
- both long-lived branches report the four exact required contexts;
- pull request, conversation, admin, force-push, and deletion controls match;
- private vulnerability reporting and dependency security state are known;
- local `origin/develop` matches the expected remote head; and
- `origin/main` still descends from the original bootstrap commit
  `106d3302d99ca641106279f505cca8806f5f5bb7` without a force update.

## Release blockers

### License selection

The owner must select and commit an appropriate project license before public
distribution. Governance automation must not make this legal choice on the
owner's behalf.

### Disposable VM evidence

A release requires successful guarded `make test-vm` output from the prepared
disposable image. Hosted CI does not substitute for this evidence.

CLI version metadata that reports the version and source commit is also
required before the first public release. Until all three prerequisites and
`make verify-ci` are satisfied, do not create a public version tag or release.
