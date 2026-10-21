---
name: clean-auditor
description: The privacy and confidentiality gate before publication. Use when changing anything that will be pushed, proposed in a pull request, or released, and when a Clean Auditor refusal needs to be understood or repaired. Covers privacy, business secrets, operational data, machine paths, personal information, credentials and content belonging to other repositories.
---

# Clean Auditor

Publication happens at three boundaries, and Clean Auditor stands at two of
them: `pre-push` and `pr` (create and merge). `release create` is gated by
the Security Enhancer. It reviews the outgoing range only, refuses when the
change cannot be published, and never modifies anything.

## What a refusal means

A refusal is a verdict, not an obstacle:

- **deterministic refusal** (stage one): a shape it can prove — a credential,
  a machine path, an internal address, a structural policy violation. The scan
  runs locally, prints category counts and never prints the matched value.
- **semantic refusal** (stage two): the six domains and the three standing
  items — tooling hygiene, hardcoded parameters and repository scope — judged
  by an isolated OpenCode conversation with a fresh context each run.

Repair the change (remove or generalize the content), then publish again. Do
not re-word the finding away and do not add a skip: the checker reads no
environment variable that widens the judgement.

## What it never sees

Credential containers (`.env`, `*.pem`, `*.key`, `*.p12`, `secrets/`,
`credentials*`, `.ssh/**`, `*.db`) are excluded from the semantic stage by
design. If a key file is part of the outgoing change, stage one decides — not a
cloud model.

## Self-check before publication

Walk the outgoing diff once before pushing, proposing or releasing: no
credential shapes or credential containers, no withheld names, no personal
information, no machine paths, host names or private endpoints, no real
operational data; every tool's state directory ignored; every parameter in
configuration or its one named place; no material that belongs to a different
repository. Fix what the list catches, then let the checker run anyway —
self-check precedes the audit, it does not replace it.

## Boundaries worth knowing

- `git push --no-verify` bypasses the `pre-push` hook; the unbypassable
  boundaries are Probator's own `pr` and `release` paths.
- A branch with nothing published to compare against is scanned whole and the
  receipt records why.
- The semantic stage runs once per range; a range that already passed is reused
  rather than paid for twice — unless the judged items changed since, because a
  receipt written under an earlier contract did not answer the current
  questions.

Full operation notes: `tools/clean-auditor/README.md` in the Probator
repository.
