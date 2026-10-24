# Security Enhancer

Agent execution uses the shared A4AA-backed `probator-agent` runner.
Build and install it as described in the [Probator runtime setup](../../README.md#agent-profiles)
before installing or updating this checker.

Security Enhancer is a blocking Probator checker that reviews what a push, a
pull request, a merge or a release is about to publish, in two stages:

1. **Static checklist, entirely local** — rules evaluated on the immutable Git
   objects of the outgoing range. No repository code is executed and no
   repository script is parsed: a change never certifies itself. A regression
   refuses immediately and costs no tokens.
2. **Semantic, isolated agent review** — only if stage one finds no regression: a
   fresh, durable audit session over the same immutable range, on the
   provider/model the synced `profile.json` declares, judging
   dependency_supply_chain / ci_workflow_authority /
   secret_handling / transport_security / authz_defaults / container_runtime /
   release_artifacts.

It only refuses. It never stages, edits, commits or fixes anything; the working
tree is byte-identical before and after a run. There is no skip flag and no
environment variable that widens the judgement.

## The two classes of static finding

**Regressions refuse the operation** — the shape is wrong on its own and the
repair is in the change: a manifest that moves without the lockfile kept beside
it; `pull_request_target`, `permissions: write-all`, a `uses:` pinned to a
branch (or a `docker://…:latest`), `curl … | sh`, `NODE_TLS_REJECT_UNAUTHORIZED=0`
in CI; `USER root`, `--privileged`, `chmod 777`, a literal secret in
`ARG`/`ENV`, a `FROM` without a tag or with `:latest`; a removed `.gitignore`
rule that was protecting a key-shaped file, a removed `CODEOWNERS` line, a
changed registry source, a newly committed credential file; `verify=False` /
`InsecureSkipVerify` / `--insecure`, `DEBUG = True`, a CORS wildcard combined
with credentials.

**Surfaces are recorded, not refused** — a new install hook, a URL or git
dependency source, a private address, a plaintext endpoint. These are decisions
to be made rather than mistakes to be undone, and refusing them would block
ordinary work with no repair available. They are printed as `notice` lines,
listed in `security_context` inventory, and must be judged by the semantic
stage: an unjudged surface is an incomplete review, not a pass.

Neither class prints the matched text — a hit names the rule, the file and the
line, so an internal host name or a build-arg value never lands in a log.

## Install

```sh
probator install --source tools/security-enhancer            # first install
probator update --source tools/security-enhancer   # refresh payload and skill links
```

The installer creates the checker's private home
`~/.local/share/probator/profiles/security-enhancer`, installs the contract payload and writes the checker's declared AwP registry
document (the audit agent spec and binding the runner resolves), links the shared
skill directory `~/.agents/skills/security-enhancer` into every agent skill
directory it finds, and registers (or replaces in place) this entry in
`$XDG_CONFIG_HOME/probator/checkers.toml` (or `~/.config/probator/checkers.toml`):

```toml
[[checkers]]
name = "security-enhancer"
on = ["pre-push", "pr", "release"]
kind = "exec"
severity = "blocking"
timeout_secs = 0
```

The routing `config.toml` keeps only the `audit_policy = "checkers.toml"`
declaration binding this policy file's name; deleting the policy file
does not silence the audit, it refuses.

Hook files are owned by `~/.git-hooks/_dispatch`; the installer never writes
them.

## Ranges

Every event judges one object: the whole tree at the operation's head commit.
There is no narrower mirror to widen later — the snapshot a push review passed
is the same object the release gate judges.

- `pre-push`: the head of each pushed ref. A deletion publishes nothing; an
  already-published tip is skipped.
- `pr create` / `pr merge`: the branch or merge-request head, fetched into
  `FETCH_HEAD` when it is not available locally (no ref is created).
- `release create`: the whole tree at the release commit.

## Boundaries an operator must know

- `git push --no-verify` skips the `pre-push` hook — git offers no counter to
  it. The boundaries that cannot be bypassed are the ones Probator itself
  controls: `pr create`, `pr merge`, `release create`.
- `release delete` is not gated: destroying a release is a recovery action, not
  a publication.
- The semantic stage is not paid for twice: the static stage runs on every
  operation, but a range that already passed the semantic review is reused.

## Evidence and privacy

Credential containers (`.env`, `*.pem`, `*.key`, `secrets/`, `credentials*`,
`.ssh/**`, `.npmrc`, `*.db`) are judged by the static stage and never handed to
the semantic stage, because sending a key file to a cloud model is itself a
leak. Receipts are sanitized before they are written; reports live under
`~/.local/share/probator/profiles/security-enhancer/security-enhancer-runs/` and the run
scope file is deleted when the run ends.

## Syncing a published profile

The prompt and skill this agent runs on are hosted in a profile registry (`PROBATOR_PROFILES_URL`,
which must be set explicitly; the local development registry is `http://127.0.0.1:8891`) and versioned by git tag. `probator install` seeds them once; after
that the registry is the source:

```sh
probator pull --source tools/security-enhancer                 # newest published version
probator pull --source tools/security-enhancer --tag profile/security-enhancer/v2   # a pinned version
```

The download is checked file by file (and as a whole, by manifest) before
anything is written. A local edit to a synced document makes the checker refuse
the operation until it is synced again: a prompt that this machine edited is not
the prompt that was reviewed.
