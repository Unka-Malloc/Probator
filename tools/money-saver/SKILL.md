---
name: money-saver
description: Optimize operational cost and service continuity during software development, and require the Money Saver audit before every push or pull request. Covers cloud services and clients, SQL, storage, traffic, compute, duplicate work and premature internal cancellation.
---

# Money Saver

Every development Agent owns the cost and efficiency of its implementation. Apply
the analysis criteria in the [review policy](policy.md) while changing service or client behavior, and remove
demonstrably useless work in the authorized scope. Check official billing and
technical documentation before making cost claims. The [official reference
catalog](documents.json) is a starting point; use the actual deployment provider's
official sources when it is not listed.
The policy's read-only tool restrictions apply to the independent auditor; the
implementing Agent still makes and verifies authorized improvements.

Trace each service outcome through database access, file I/O, upstream requests,
computation and response. Quantify reads, writes, scanned rows, requests, bytes and
CPU/duration per useful result. Prefer deleting duplicate work before introducing
caches or new validation. Preserve required security, integrity and durability.

Healthy requests and Agent tasks must run to completion. Remove arbitrary internal
time, silence, turn, iteration and attempt limits that abort viable work or replay
already paid operations. Retry only after an unavoidable external failure, at one
owning layer, with safe resumption and reuse of completed results. User cancellation
and provider-enforced failure are distinct from internally manufactured failure.
Control spending through efficient work, admission and concurrency; do not spend
tokens or traffic and then throw the completed progress away.

Before every push and pull request, allow Probator's mandatory Money Saver checker
to finish. It audits the outgoing content at the publication boundary; local commits
never trigger it.
It runs on OpenCode under the provider, model and reasoning effort the synced profile declares.
Fix blocking findings within the approved scope, then audit the changed candidate.
An incomplete or failed audit does not pass. Do not disable hooks/checkers, use
alternate hooksPath/commit-tree, forge receipts or switch providers to evade review.
Do not add repeated manual audits of an unchanged candidate on top of the hook.

Full-service audits require an explicit scope. Account for every selected client
and service, follow actual call chains, and report unread areas honestly. Provide
relative file/line, trigger, present/improved resource units, official sources,
minimal remedy and focused validation. Without traffic data, report per-operation
savings and a formula; do not invent a monthly bill or claim zero financial risk.

Keep source evidence sanitized. Never transmit secrets, machine/person identifiers,
private endpoints or backend runtime data. Original user requests may be supplied
only for the assigned audit, with their source link and exact wording.

## Self-check before publication

Walk the outgoing diff once before pushing or opening a pull request: every
billed operation still earns its result — no request, query, transfer or
computation nobody consumes; no paid work replayed because progress was
discarded; no new internal limit that could abort a viable stream or task;
every spend-controlling tunable in configuration. Fix what the list catches,
then let the checker run anyway — self-check precedes the audit, it does not
replace it.
