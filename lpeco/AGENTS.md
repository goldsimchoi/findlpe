# LPECO Agent Instructions

These instructions apply to all work under `lpeco/`.

1. Read `README.md` and `docs/safety-model.md` before changing runtime behavior.
   Read `docs/rules.md` for graph or candidate work and
   `docs/adapter-protocol.md` for transport or adapter work. Follow the root
   `CONTRIBUTING.md` as the human policy of record.
2. Inspect the nearest implementation and tests before editing. Add a focused
   failing test before a feature or bug fix, then make the smallest coherent
   change. Do not mix unrelated refactors or touch unrelated workspace files.
3. Preserve the read-only trust boundary. Never add exploitation steps,
   payload generation or delivery, persistence, credential attacks, service
   mutation, kernel-exploit recommendations, or any other state-changing
   behavior.
4. Keep probe scripts fixed in registry data and pass target-derived values as
   separately quoted positional arguments. Preserve safety classifications,
   timeouts, output bounds, parser contracts, and expected fact types. The
   scheduler must continue to deny `temporary-artifact` and `state-changing`
   probes.
5. Preserve evidence semantics. Permission denial, missing tools, parse errors,
   timeouts, truncation, transport loss, and unresolved values mean unknown,
   not safe. Retain raw evidence references and missing facts; never promote
   incomplete evidence to P0, high confidence, or `read_only_validated`.
6. Use synthetic fixtures. Never commit secrets, credentials, customer or
   assessment identifiers, raw target output, generated binaries, or local
   session state. Errors need useful operation context without sensitive data.
7. Keep Go source formatted, package names specific, exported names documented,
   interfaces consumer-owned and minimal, and dependencies justified.
8. Run verification proportional to the change. Start with the focused test,
   then the affected package. Before handoff, run `make verify`; run
   `make test-integration` for collector, graph, rule, transport, adapter,
   report, or fixture changes. Run `make verify-ci` for a complete pre-merge
   check. Use `make test-vm` only with the explicit disposable-image guard.

If a requested change conflicts with these safety or evidence rules, stop and
surface the conflict instead of weakening the guard.
