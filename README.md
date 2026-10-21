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

Probator forks the review engine that lived inside GitVault. The two trees
now evolve independently.

## Layout

- `src/bin/probator.rs` + `src/bin/probator/*` — the audit engine
- `src/bin/probator-agent.rs` — the audit host that speaks a4aa.v1 to the
  serving runtime (Virtual-Agent / AwP), enforcing the contract's tool
  surface fail-closed
- `tools/<checker>/` — audit sources: `contract.json`, `policy.md`,
  `profile.json`; `tools/registry.json` declares the agents/bindings
- `docs/review-contract.schema.json` — the contract's single source of truth
- `tests/review-parity/` — golden corpus pinning accept/refuse behaviour,
  the seal chain, sanitization and the deterministic stage byte-for-byte
  against the recorded reference implementation

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
