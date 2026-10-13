## Summary

Describe the problem, the user-visible behavior, and why this change belongs in
LPECO. Link a tracking issue when one exists.

## Safety and evidence impact

State whether this changes a probe, safety class, target command, transport,
evidence semantics, candidate ranking, report data, or redaction. Explain why
the read-only boundary and incomplete-evidence rules still hold.

Provide only synthetic or redacted evidence. Do not paste raw target output,
credentials, tokens, private keys, customer identifiers, or assessment data.

## Compatibility and documentation

Identify effects on CLI options, JSON reports, stored sessions, the adapter
protocol, and migration behavior. List the README, safety model, rule catalog,
adapter protocol, development guide, and `Unreleased` changelog entries updated.

## Verification

Exact commands run and their results:

```text
Command and concise result
```

## Review checklist

- [ ] Safety: The change preserves the authorized, read-only product boundary.
- [ ] Tests: New behavior or a regression has focused automated coverage.
- [ ] Documentation: Affected docs and `CHANGELOG.md` are current.
- [ ] Compatibility: Public surfaces and migration impact are documented.
- [ ] Secrets: The diff and test data contain no credentials or assessment data.
- [ ] Evidence: Denied, partial, malformed, and missing observations remain unknown.
