# Codebase Maintainer

Agent execution uses the shared A4AA-backed `probator-agent` runner.
Build and install it as described in the [Probator runtime setup](../../README.md#agent-profiles)
before installing or updating this checker.

Codebase Maintainer is a blocking Probator checker that reviews what a push
or a pull request is about to publish, in two stages:

1. **Deterministic, entirely local** — a hygiene scan of the paths the
   operation introduces or modifies: conflict markers left in text, merge-tool
   artifacts (`*.orig`, `*.rej`, `*.LOCAL.*`), editor and OS junk
   (`.DS_Store`, `._*`, swap files). Nothing leaves the machine, nothing is
   written, and a refusal here costs no tokens.
2. **Semantic, isolated agent review** — only if stage one passes: a fresh,
   durable audit session over the same immutable range, on the provider/model
   the synced `profile.json` declares, judging structure / contracts / craft /
   duplication / tests / evolution, and returning advisory findings with
   architecture advice for long-term maintainability.

It only refuses. It never stages, edits, commits or fixes anything; the working
tree is byte-identical before and after a run. There is no skip flag and no
environment variable that widens the judgement.

## The gate and the advice

Two jobs, different weights. **The gate** refuses on confirmed, material norm
violations — the test is agreement, not severity: if reasonable engineers would
not argue about whether the norm is violated, it can block. **The advice** is
everything else worth saying: advisory findings that name the file and line,
the evidence, and the smallest effective next step. Advice never holds a
publication, and a finding that only says "consider refactoring" is a contract
violation, not a finding.

The norms enforced are the durable ones: one authority per piece of knowledge;
boundaries that keep change local; public contracts honoured or explicitly
versioned; tests that can actually fail; migrations that finish rather than
leave a second live implementation; documentation that describes the system
that exists. Design patterns are vocabulary, not decoration — a pattern earns
its structure when a real recurring constraint justifies it.

## Install

```sh
probator install --source tools/codebase-maintainer            # first install
probator update --source tools/codebase-maintainer   # refresh payload and skill links
```

The installer creates the checker's private home `~/.local/share/probator/profiles/codebase-maintainer`,
installs the contract payload and writes the checker's declared AwP registry.
Migrating from `sustainable-maintainer`: the renamed checker does not
inherit the old profile or ledger — remove the stale `sustainable-maintainer`
row from `~/.config/probator/checkers.toml` and delete
`~/.local/share/probator/profiles/sustainable-maintainer` plus
`~/.agents/skills/sustainable-maintainer` once the old name's records are no
longer needed, so a machine never runs both spellings.
document (the audit agent spec and binding the runner resolves), links the shared skill directory `~/.agents/skills/codebase-maintainer`
into every agent skill directory it finds, and registers (or replaces in place)
this entry in `$XDG_CONFIG_HOME/probator/checkers.toml` (or `~/.config/probator/checkers.toml`):

```toml
[[checkers]]
name = "codebase-maintainer"
on = ["pre-push", "pr"]
kind = "exec"
severity = "blocking"
timeout_secs = 0
```

The routing `config.toml` keeps only the `audit_policy = "checkers.toml"`
declaration binding this policy file's name; deleting the policy file
does not silence the audit, it refuses.

Hook files are owned by `~/.git-hooks/_dispatch`; the installer never writes
them.

## Explicit full-service review

`probator full-audit --contract <contract.json> --manifest <manifest.json>
--request <charter.json> --output <new-private-directory>` runs the same
reviewer over the whole current source
of explicitly selected projects, including nonignored unstaged/untracked
changes. The manifest maps project labels to local source roots under
`projects`; the charter carries the authorized conversation URL and the exact
original messages. Optional `reuse` maps a second selected project to its
primary copy so byte-identical files share evidence while distinct code
remains independently inspectable.

The reviewer must read the charter and account for every project and every
domain before submitting; findings must name an exact listed path and an
existing line the reviewer actually read this run. Unknown coverage cannot
pass. The report stays in the private output directory: it never blocks
publication and never approves a later commit. Resume a failed review with
`probator full-audit --resume <run-directory>`; a submitted report is
never re-audited.

## Boundaries an operator must know

- `git push --no-verify` skips the `pre-push` hook — git offers no counter to
  it. The boundary that cannot be bypassed is the one Probator itself
  controls: `pr create`, `pr merge`.
- Every event is scanned whole: the review object is the tree at the
  operation's head commit, so no later gate can widen what an earlier review
  passed.
- The semantic stage is not paid for twice: the deterministic stage runs on
  every operation, but a range that already passed the semantic review is
  reused — for as long as the judged items are the same ones. A receipt written
  under an earlier contract did not answer the current questions, so it is not
  reused and the range is reviewed again.

## Evidence and privacy

Credential containers (`.env`, `*.pem`, `*.key`, `secrets/`, `credentials*`,
`.ssh/**`, `*.db`) are outside the review's tool surface entirely: the shared
audit engine refuses to serve them to the model, because a maintainability
review never needs to read a key file. The deterministic stage itself judges
what hygiene never needs judgement — conflict markers, merge-tool artifacts
and editor/OS junk. Receipts are sanitized before they are written; reports
live under
`~/.local/share/probator/profiles/codebase-maintainer/codebase-maintainer-runs/` and
the run scope file is deleted when the run ends.

## Syncing a published profile

The prompt and skill this agent runs on are hosted in a profile registry (`PROBATOR_PROFILES_URL`,
which must be set explicitly; the local development registry is `http://127.0.0.1:8891`) and versioned by git tag. `probator install` seeds them once; after
that the registry is the source:

```sh
probator pull --source tools/codebase-maintainer                             # newest published version
probator pull --source tools/codebase-maintainer --tag profile/codebase-maintainer/v1   # a pinned version
```

The download is checked file by file (and as a whole, by manifest) before
anything is written. A local edit to a synced document makes the checker refuse
the operation until it is synced again: a prompt that this machine edited is not
the prompt that was reviewed.
