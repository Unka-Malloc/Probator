---
name: sustainable-maintainer
description: The long-term maintainability gate before publication. Use when changing anything that will be pushed or proposed in a pull request, and when a Sustainable Maintainer refusal needs to be understood or repaired. Covers module structure, contracts, craft, duplication, tests and evolution residue — and gives architectural advice for keeping the repository maintainable.
---

# Sustainable Maintainer

Sustainable Maintainer stands at two publication boundaries: `pre-push` and
`pr` (create and merge). It reviews the outgoing range only, refuses when the
change should not be published as it stands, and never modifies anything.
Beyond the gate it returns advisory findings: specific, evidence-based
recommendations for keeping the repository maintainable long-term — better
boundaries, simpler structure, the smallest effective next step.

## What a refusal means

A refusal is a verdict, not an obstacle:

- **deterministic refusal** (stage one): a shape it can prove — conflict
  markers left in text, merge-tool artifacts (`*.orig`, `*.rej`,
  `*.LOCAL.*`), editor or OS junk (`.DS_Store`, `._*`, swap files) committed
  to the tree. The scan runs locally and never costs a token.
- **semantic refusal** (stage two): the six domains judged by an isolated OpenCode
  conversation with a fresh context each run — structure, contracts, craft,
  duplication, tests, evolution.

Repair the change, then publish again. A blocking finding is a material norm
violation reasonable engineers would not argue about; everything softer is
advisory and cannot hold a push. Do not re-word the finding away and do not
add a skip: the checker reads no environment variable that widens the
judgement.

## What it never sees

Credential containers (`.env`, `*.pem`, `*.key`, `*.p12`, `secrets/`,
`credentials*`, `.ssh/**`, `*.db`) are excluded from the semantic stage by
design. A maintainability review never needs to read a key file.

## What it rewards

The norms it enforces are the durable ones: one authority per piece of
knowledge, boundaries that keep change local, contracts honoured or
explicitly versioned, tests that can actually fail, migrations that finish,
documentation that describes the system that exists. Design patterns are
vocabulary, not decoration — a pattern earns its structure when a real
constraint justifies it.

## Self-check before publication

Walk the outgoing diff once before pushing or opening a pull request: no
conflict markers, merge artifacts or editor/OS junk; no knowledge copied while
its original stands; contracts broken only with a version bump, a migration
path or a deprecation window; no dead code, debug scaffolding or swallowed
errors; behaviour the change adds or alters covered under the repository's
test conventions; every superseded path of an authorized replacement removed;
documentation updated to describe the system that exists. Fix what the list
catches, then let the checker run anyway — self-check precedes the audit, it
does not replace it.

## Full-service review

Beyond the gate, the operator can assign a repository-wide review with an
explicit manifest of projects plus a review charter. The same six domains and
the same gate/advice weights apply to the whole current source; coverage is
accounted per project as well as per domain, and a finding must name an exact
listed path and line the reviewer actually read. A full-service report is
private to the operator: it never blocks publication and never approves a
later commit. Full operation notes: `tools/sustainable-maintainer/README.md`
in the Probator repository.

## Boundaries worth knowing

- `git push --no-verify` bypasses the `pre-push` hook; the unbypassable
  boundary is Probator's own `pr` path.
- A branch with nothing published to compare against is scanned whole and the
  receipt records why.
- The semantic stage runs once per range; a range that already passed is
  reused rather than paid for twice — unless the judged items changed since,
  because a receipt written under an earlier contract did not answer the
  current questions.

Full operation notes: `tools/sustainable-maintainer/README.md` in the
Probator repository.
