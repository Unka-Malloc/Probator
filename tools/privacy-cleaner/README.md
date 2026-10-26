# Privacy Cleaner

Agent execution uses the shared A4AA-backed `probator-agent` runner.
Build and install it as described in the [Probator runtime setup](../../README.md#agent-profiles)
before installing or updating this checker.

Privacy Cleaner is a blocking Probator checker that reviews what a push, a pull
request or a merge request is about to publish, in two stages:

1. **Deterministic, entirely local** — Probator's own scan of the outgoing
   revision: withheld names over the whole revision, and credential shapes by
   format. One `git grep` answers both, nothing leaves the machine, nothing is
   written, and a refusal here costs no tokens.
2. **Semantic, isolated agent review** — only if stage one passes: a fresh,
   durable audit session over the same immutable range, on the provider/model
   the synced `profile.json` declares, judging privacy / business_secret /
   operations_data / machine_path /
   personal_info / credentials, plus the three standing items below.

It only refuses. It never stages, edits, commits or fixes anything; the working
tree is byte-identical before and after a run. There is no skip flag and no
environment variable that widens the judgement.

## Install

```sh
probator install --source tools/privacy-cleaner            # first install
probator update --source tools/privacy-cleaner   # refresh payload and skill links
```

The installer creates the checker's private home `~/.local/share/probator/profiles/privacy-cleaner`,
installs the contract payload and writes the checker's declared AwP registry
document (the audit agent spec and binding the runner resolves), links the shared skill directory `~/.agents/skills/privacy-cleaner`
into every agent skill directory it finds, and registers (or replaces in place)
this entry in `$XDG_CONFIG_HOME/probator/checkers.toml` (or `~/.config/probator/checkers.toml`):

```toml
[[checkers]]
name = "privacy-cleaner"
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

## Withheld names, and the three standing items

Four checks sit outside the six domains.

**Withheld names** are decided by the deterministic stage, locally and for free.
The list is machine state — `$XDG_CONFIG_HOME/probator/withheld-names.txt`,
overridable with `PRIVACY_CLEANER_WITHHELD` — and never a repository file: the rule
is public, the names it withholds are not, and a list kept in a repository would
publish exactly what it protects. Why a list is needed at all: the existence of
an unpublished project, or of the internal operations plane behind an
open-source product, is itself the secret, so the check is a name check rather
than a shape.

Every name on the list is refused when it appears **anywhere in the outgoing
revision**, not only in the changed files — a name already in the tree is
already published — and one `git grep` answers it. Matching ignores case,
spaces, hyphens and underscores, so `Widget Go`, `widget-go` and `WidgetGO`
are one entry. A line may end with `except <owner[/repo]>` to skip it inside a
repository that carries the name as its own identity. The refusal reports the
file and line and never the name.

**The tooling item** is a coverage item of the semantic review, not a pattern
list. Which directories a project's tooling owns is a judgement about that
project, and a hardcoded list would either miss a tool or refuse a project that
tracks such a directory deliberately. The reviewer must establish which tools the
project uses — from manifests, scripts, CI and editor configuration, and from any
directory that looks like a tool's own state — and for each decide whether its
data directory lives inside the repository and whether `.gitignore` covers it. A
tool whose data directory is inside the repository and not ignored is a blocking
finding: it is published, or one `git add -A` away from being published. Coverage
`tooling` is required on every review, and `unknown` cannot pass.

**The hardcoding item** is the second coverage item, and it follows the same
shape: a judgement about the code around the value, not a pattern list — a
pattern that matched every literal would report arithmetic.

Parameters belong in configuration. A parameter is a value an operator, a
deployment or a different environment may need to change: endpoints, hosts,
ports, prices, quotas, model or provider names, thresholds, timeouts, retry and
page limits, sizes, feature switches, versions, identifiers, paths to something
outside the program. Two places are accepted, in this order — a configuration
file the program reads, or, where there is genuinely no configuration
mechanism, one dedicated place that holds the data (a settings or constants
module, one exported table, a singleton that owns the values).

Below that it is a finding: the same value repeated across files, an
environment's fact written into a function body, a tunable buried among
unrelated logic. What makes the two accepted forms work is that a value in one
named place can be found and changed, while a value in ten call sites cannot —
and the copy that is missed is the one that ships. A parameter a deployment must
change, one appearing in more than one place, or an environment fact hardcoded
into logic is blocking; a named local constant used once, next to the behaviour
it describes, is not. Overlap resolves to the specific domain — an absolute path
is `machine_path`, a credential is `credentials` — and this item judges where the
value lives, not whether it is secret. Coverage `hardcoding` is required on every
review, and `unknown` cannot pass.

**The repository-scope item** is the third coverage item: every file's
subject must be this repository. Material owned by a different repository,
project or tool workspace — another codebase's audit or inspection reports,
plans produced for another programme, a foreign tool's state or session
exports — is a finding wherever it sits, including an inherited file the
change carries forward. Coverage `repository_scope` is required on every
review, and `unknown` cannot pass.

## Boundaries an operator must know

- `git push --no-verify` skips the `pre-push` hook — git offers no counter to
  it. The boundaries that cannot be bypassed are the ones Probator itself
  controls: `pr create`, `pr merge`, `release create`.
- Every event is scanned whole: the review object is the tree at the
  operation's head commit, so no later gate can widen what an earlier review
  passed.
- The semantic stage is not paid for twice: the deterministic stage runs on
  every operation, but a range that already passed the semantic review is
  reused — for as long as the judged items are the same ones. A receipt written
  under an earlier contract did not answer the current questions, so it is not
  reused and the range is reviewed again.

## Evidence and privacy

The deterministic stage judges credential containers (`.env`, `*.pem`,
`*.key`, `secrets/`, `credentials*`, `.ssh/**`, `*.db`) — they are never handed
to the semantic stage, because sending a key file to a cloud model is itself a
leak. Receipts are sanitized before they are written; reports live under
`~/.local/share/probator/profiles/privacy-cleaner/privacy-cleaner-runs/` and the run scope file
is deleted when the run ends.

## Syncing a published profile

The prompt and skill this agent runs on are hosted in a profile registry (`PROBATOR_PROFILES_URL`,
which must be set explicitly; the local development registry is `http://127.0.0.1:8891`) and versioned by git tag. `probator install` seeds them once; after
that the registry is the source:

```sh
probator pull --source tools/privacy-cleaner                 # newest published version
probator pull --source tools/privacy-cleaner --tag profile/privacy-cleaner/v2   # a pinned version
```

The download is checked file by file (and as a whole, by manifest) before
anything is written. A local edit to a synced document makes the checker refuse
the operation until it is synced again: a prompt that this machine edited is not
the prompt that was reviewed.
