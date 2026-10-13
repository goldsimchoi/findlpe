# FindLPE / LPECO

This repository contains LPECO, a read-only Linux privilege-boundary candidate
orchestrator for authorized security assessments. The implementation and Go
module live under [`lpeco/`](lpeco/).

LPECO starts after an operator has an approved SSH, raw/reverse-shell, or C2
execution channel. It inventories processes, systemd units, schedulers,
privileged binaries, delegation policy, paths, mounts, ACLs, and container
management sockets, then correlates evidence-backed review candidates. It does
not exploit a candidate, generate a payload, change target state, persist, or
attempt credential attacks.

Use this software only on systems you own or are explicitly authorized to
assess. A reported candidate is a triage hypothesis, not proof that privilege
escalation is possible.

## Start here

- [Build, usage, transports, and reports](lpeco/README.md)
- [Safety model](lpeco/docs/safety-model.md)
- [Candidate rule catalog](lpeco/docs/rules.md)
- [External adapter protocol](lpeco/docs/adapter-protocol.md)
- [Development and verification](docs/development.md)

## Project governance

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

The project is in pre-release development on `develop`. `main` is reserved for
release-ready history; no public release is implied by the current source tree.
