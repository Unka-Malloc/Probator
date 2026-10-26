# Review contracts as data

Status: milestone landed in the working tree. This note records the design
decision and the migration shape; "Landed so far" lists what exists.

## Landed so far

The `probator` binary (`src/bin/probator.rs` + `src/bin/probator/`):

- `contract.rs` — the contract model and validation, the executable mirror of
  the schema. Every schema rule has exactly one named check; the two must
  agree exactly.
- `sanitize.rs` — the report and evidence sanitizers, byte-parity with the
  retired Python engine, pinned by goldens.
- `evidence.rs` — the sensitive-path contract and the gate-mode evidence verbs
  (inventory/list/diff/read/find) with the pagination state a verdict depends
  on.
- `stage1.rs` — the deterministic stage: the per-checker builtins
  (withheld-names-and-credentials, workspace-hygiene,
  static-checklist, dependency-direction) plus regex rules executed
  as data over a declared target. The builtins own one coupled scan pass each.
- `documents.rs` — the operator-curated official-document fetcher: catalog
  keys, listed URLs, and unlisted pages on a catalog host; query/fragment-free
  self-located URLs resolved only to public addresses; redirects pinned to the
  same authority; HTML text extraction, paged replies,
  a persisted per-run cache.
- `fullservice.rs` — the snapshot-backed review object (inventory /
  original_request / list / read / find), the snapshot builder with
  byte-identical reuse, and the full-service verdict rules.
- `manifest.rs` + `submit.rs` — the tool manifest derived from a contract and
  the verdict validation, both refusal-wording-exact.
- `serve.rs` — the bridge-facing JSONL tool server, wire-compatible with the
  retired `--serve-tools`, now also writing the receipt (`report.json`) with
  its engine marker.
- `credential.rs` — the one-shot verdict credential: the run issues
  `verdict.key`, `serve` signs the receipt's `receipt_mac` under it, the
  gate recomputes the signature before trusting the report and the key
  dies with the finalized verdict.
- `conceal.rs` — end-of-run session concealment by recorded id across the
  admitted agents' stores, plus the desktop `archivedSessions` list the
  sidebar filter consults; skips runs still marked live.
- `engine.rs` + `ranges.rs` — the gate: snapshot resolution for push/pr/release,
  the deterministic stage first, the per-checker coverage ledger
  (`<profiles>/cursors/<checker>.json`, sealed, scoped to the reviewer,
  checker-named binding and runtime tuple that produced the verdict, and
  advancing only on a complete pass or block), incremental `base..head`
  reviews, carried blocking findings cleared only when a hunk re-opens their
  own line, receipt reuse and resume keys, the retention window, the A4AA
  runner process, the full-audit lifecycle. Receipts carry
  `engine: probator <version>`; Python-era receipts are never reused.
- `install.rs` — `install` / `update` / `pull`: payload copy and pinning,
  registry-entry upsert, bundle verification. A checker installs as a
  contract, a policy and a registry entry - no code of its own.

The four checkers carry `tools/<checker>/contract.json` with their stage-1
rules filled in. The Python payload - engine, per-checker plugins, stage-one
modules, the sync library and the installer - is removed; the parity goldens
under `tests/review-parity/` recorded its behavior beforehand and remain as
the pinned fixtures the Rust tests run against.

Still open: publishing `contract.json` itself through the profile registry
(today it flows hash-pinned through the installer payload, which the signed
config already anchors), and anything the live acceptance run teaches.

## Decision

The per-checker review contract becomes a registry-published JSON document,
executed by a general Rust runtime. Three layers, separated by rate of change
and trust:

1. **Declaration** — `contract.json`: domains, finding keys, stage-1 rules,
   events, severity, tool surface, task template, runtime reference. Published
   through the profile registry, hash-pinned and versioned by git tag like
   `policy.md` today. Schema: [`review-contract.schema.json`](review-contract.schema.json).
2. **Judgment** — `policy.md`, unchanged. Natural language instructing the
   reviewer is not data and never enters the DSL.
3. **Execution** — one Rust verb set in the Probator binary: snapshot resolution,
   the stage-1 rule executor, the evidence server (inventory/diff/read/find
   with sanitization and pagination state), submit validation, receipts and
   resume keys, the model tool bridge.

## The runtime is general; the gate binding is pinned

`probator ./any-contract.json` executes any contract file for
development or one-off review; results from unpinned contracts are marked
non-authoritative and never join receipt reuse. A blocking gate binds a
contract by registry tag in the signed `config.toml`:

```toml
[[checkers]]
name = "codebase-maintainer"
contract = "profile/codebase-maintainer/v6"
on = ["pre-push", "pr"]
```

The runtime verifies the fetched contract's hash against the pinned version
before executing it. This is the same layering the system already has —
the engine runs any registered command, while the signed config decides which
commands are gates — extended so that the pinned surface covers the whole
contract, not only the prose documents.

## Why JSON, and why not the alternatives

The contract is parsed by the Rust runtime, validated and served by the Node
profile registry, and round-tripped through the dashboard web UI. JSON is the
only candidate all three already speak, it has one unambiguous grammar, and
`checks.json` is the precedent. TOML stays where the operator hand-writes:
`config.toml`. YAML fails the gate's cannot-drift property (dialect and
coercion ambiguity); KDL/RON/HCL/CUE fail the three-parser constraint.

## What each side keeps

- The four auditors are pure document packages: `policy.md`, `SKILL.md`,
  `contract.json`, plus `documents.json` for Money Saver. Adding a reviewer is
  adding registry documents, never editing the engine - today that sentence is
  true of the whole tool surface, not only configuration.
- The Python payload layer (`audit_engine.py` and friends) is retired: the
  parity goldens under `tests/review-parity/` recorded its behavior for the
  migration, and the Rust verb set is now the only execution substrate.
- Stage-1 rules execute as data (`regex`, `prompt`); deterministic checks
  that are genuinely code ship as named builtins the contract references,
  never as executable text inside the contract.

## Verification shape

The schema is the single contract source: the Node registry validates drafts
against it at publish, the Rust runtime validates contracts before execution,
and conformance fixtures (one per auditor) pin that the four published
contracts produce the exact tool manifests and submit validation the retired
Python engine produced. The fixtures live in `tests/review-parity/`:
`sanitize`/`safepath`/`manifest`/`submit` goldens generated by
`tests/dump_review_parity.py` from the Python engine before it was retired;
the Rust tests now assert them as the behavioral anchor, so the runtime
cannot drift from the recorded parity without a deliberate regeneration.
