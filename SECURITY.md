# Security Policy

## Supported versions

Before the first public release, only the current `develop` branch receives
security fixes. After releases begin, the latest minor release line and current
`develop` are supported; older minor lines are not maintained unless a release
announcement explicitly says otherwise.

| Version or branch | Security support |
|---|---|
| Current `develop` | Yes |
| Latest released minor line | Yes, after the first release |
| Older minor lines | No |

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/goldsimchoi/findlpe/security/advisories/new).
Do not open a public issue for a vulnerability before coordinated disclosure.
No security email address is published until the maintainer has an actively
managed mailbox for this project.

Provide only what is reasonably necessary:

- the affected version or commit and platform;
- prerequisites, impact, and a minimal reproduction;
- whether LPECO crossed its read-only boundary, changed target state, or exposed
  a secret; and
- any constraints on disclosure timing.

Do not include live credentials, private keys, tokens, customer identifiers, or
raw assessment evidence. Replace them with synthetic values and redact target
output. If sensitive material was submitted accidentally, call that out in the
private report so its handling can be prioritized.

## What to expect

This project does not yet have staffed response-time guarantees. The maintainer
will acknowledge, investigate, coordinate a fix and disclosure, and credit the
reporter when capacity and the report permit. Absence of a promised service
level must not be interpreted as permission to publish secrets or assessment
data.

Issues of particular concern include command or frame injection, unintended
target writes, unsafe probe classification, loss of evidence integrity,
redaction bypass, credential exposure, adapter trust-boundary violations, and
workflow supply-chain compromise.

## Assessment boundary

LPECO is for explicitly authorized assessments. Reports about using it without
authorization, adding exploitation or persistence, delivering payloads,
attempting credentials, or mutating target services are outside the intended
product boundary. A security fix must not introduce those behaviors.
