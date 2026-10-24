---
name: security-enhancer
description: The hardening gate before publication. Use when changing anything that will be pushed, proposed, merged or released, and when a Security Enhancer refusal needs to be understood or repaired. Covers dependency supply chain, CI authority, secret handling, transport security, authorization defaults, container runtime and release artifacts.
---

# Security Enhancer

Publication happens at several boundaries, and Security Enhancer stands at all
of them: `pre-push`, `pr` (create and merge), and `release create`. It reviews
the outgoing range only, refuses when the change cannot ship as it stands, and
never modifies anything.

## What a refusal means

- **static refusal** (stage one): a shape that is wrong on its own — a disabled
  TLS check, a floating CI action, a world-writable install step, an ignore rule
  that was protecting a key file, a manifest that moves without its lockfile.
  The checklist runs locally and refuses at once; no token is spent.
- **semantic refusal** (stage two): the seven domains judged by an isolated
  agent session with a fresh context each run.

Repair the change, then publish again. Do not re-word a finding away and do not
look for a skip: the checker reads no environment variable and no file in the
repository that widens the judgement, and it never runs the repository's own
verifier.

## Recorded surfaces are not refusals

New execution or egress paths — an added install hook, a URL or git dependency
source, a private address, a plaintext endpoint — are reported as `notice` lines
and handed to the semantic stage, which must judge each one. They do not block
by themselves: they are decisions to be made, not mistakes to be undone.

## What it never sees

Credential containers (`.env`, `*.pem`, `*.key`, `*.p12`, `secrets/`,
`credentials*`, `.ssh/**`, `.npmrc`, `*.db`) are excluded from the semantic
stage by design. The static stage reads them locally instead, which is how a
registry change in `.npmrc` is still caught without a key ever reaching a cloud
model.

## Self-check before publication

Walk the outgoing diff once before pushing, proposing or releasing: every
dependency and CI action pinned, the lockfile moving with its manifest, CI
permissions at minimum, no TLS or signature check disabled, no secret in code
or in an unignored file, transport encrypted, authorization defaults closed,
containers non-root, release artifacts checksummed. Fix what the list catches,
then let the checker run anyway — self-check precedes the audit, it does not
replace it.

## Boundaries worth knowing

- `git push --no-verify` bypasses the `pre-push` hook; the unbypassable
  boundaries are Probator's own `pr` and `release` paths.
- A release is judged as "everything since the previous release"; a first
  release is scanned whole and the receipt records why.
- The semantic stage runs once per range; a range that already passed is reused
  rather than paid for twice.

Full operation notes: `tools/security-enhancer/README.md` in the Probator
repository.
