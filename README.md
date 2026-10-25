# Probator

A checklist-contract audit engine. An audit is declared as data — a
`contract.json` naming its domains, its deterministic stage-1 rules and its
tool surface, plus a `policy.md` holding the judgement text — and `probator`
executes it by running an agent inside a restricted tool sandbox and
validating the submission mechanically.

The coverage guarantee is structural, not aspirational: the submission's
`coverage` keys must set-equal the contract's `domains`, every entry needs a
`{status, reason}`, `pass` additionally requires every changed diff paged to
its end, no blocking findings and no `unknown` coverage, and the submission
is accepted exactly once. A reviewer that cannot complete the contract leaves
the gate blocked; it cannot produce a passing receipt without the evidence.

Probator is an independent project with its own policy, receipts and
release line.

## Layout

- `src/bin/probator.rs` + `src/bin/probator/*` — the audit engine
- `src/bin/probator-agent.rs` — the audit host that speaks a4aa.v1 to the
  serving runtime (Virtual-Agent / AwP), enforcing the contract's tool
  surface fail-closed. When the operator's Virtual-Agent registry carries a
  binding named after the checker (`clean-auditor`, `money-saver`, …), that
  binding owns the harness, model and fallback chain; otherwise the packaged
  `audit` binding built from the contract's runtime is used. A checker-named
  binding is admitted only when every candidate runs the audit-safe `pi`
  command (pinned tool surface, no extensions/skills/context files); an
  arbitrary agent command is refused before `va` starts.
- `tools/<checker>/` — audit sources: `contract.json`, `policy.md`,
  `SKILL.md` (plus `documents.json`, Money Saver's official-document
  catalog); `tools/registry.json` declares the agents/bindings/secrets
- `docs/review-contract.schema.json` — the contract's single source of truth,
  with `docs/review-contract-design.md` recording the design decisions
- `tests/review-parity/` — golden corpus pinning accept/refuse behaviour,
  the seal chain, sanitization and the deterministic stage byte-for-byte
  against the recorded reference implementation

## Agent profiles

`tools/registry.json` declares how a checker reaches an agent runtime:
`agents` name the runtimes and their launch command plus tool-surface
restrictions, `profiles` map a checker to an agent and model, `bindings`
pick the profile and its ordered fallbacks, and `secrets` name credentials
resolved from the environment or a file at run time — values never live in
the repository. `probator install` copies this document into the checker's
profile directory; `probator-agent` resolves it at run start.

## Commands

`probator` is the whole engine; the everyday surface is small:

- `probator run` — execute the checker gate over the repository's
  unpublished snapshots
- `probator gate-audit` — the orchestrator-facing surface: one JSON action
  on stdin, one findings array on stdout
- `probator inspect [--json|--html <file>]` — render the installed policy:
  registered checkers, their domains, stage-1 rules and profile bindings,
  always read from configuration, never hardcoded
- `probator eval` — score recorded runs into a checker x architecture matrix
- `probator install` / `update` / `pull` — manage installed checkers and
  their published profile documents
- `probator validate` / `manifest` / `stage1` / `snapshot` / `serve` /
  `sanitize` / `baseline` / `full-audit` — the contract and run machinery
  the gate is built from

## Build, verify, install

```sh
cargo fmt && cargo clippy --all-targets && cargo test
cargo install --path . --root ~/.local
```

Installs `probator` and `probator-agent` beside each other; the engine
locates the agent host as a sibling on PATH.

## Data roots

- `$XDG_DATA_HOME/probator/profiles/` (else `~/.local/share/probator/profiles`)
  — installed checkers and per-run directories (`<checker>-runs/`)
- `$XDG_CONFIG_HOME/probator/` (else `~/.config/probator/`) —
  `withheld-names.txt`, `repo-deps.txt`, `config.toml`
- `$PROBATOR_CONFIG`, `$PROBATOR_PROFILES_URL`, `$PROBATOR_REPO_DEPS`,
  `$PROBATOR_VA_BIN` override the corresponding resolutions
