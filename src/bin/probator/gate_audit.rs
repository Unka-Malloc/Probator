//! `probator gate-audit` — the orchestrator-facing audit surface.
//!
//! One JSON action arrives on stdin, one JSON array of gate findings leaves
//! on stdout. Any release orchestrator that can write the envelope can drive
//! the audit; the binary stays generic because the envelope uses probator's
//! own vocabulary rather than any caller's schema. Failure is always a
//! `high` finding, never a bare error: an audit that cannot answer refuses.
//!
//! Findings carry `{severity, message, path?, line?}` plus `source`. The
//! report's `evidence` and `validation` fields never cross this boundary —
//! locations are actionable, matched values are not.

use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn high(message: impl Into<String>) -> Value {
    json!({"source": "probator", "severity": "high", "message": message.into()})
}

/// The gate event name a checker row's `on` list binds to. Upstream
/// vocabularies differ — a registry publish and a store submission are the
/// release boundary for our contracts — so the aliases collapse here.
fn event_of(kind: &str) -> Option<&'static str> {
    match kind.trim().to_ascii_lowercase().as_str() {
        "push" | "pre-push" | "working-tree" => Some("pre-push"),
        "pr" | "pull-request" | "merge-request" => Some("pr"),
        "release" | "publish" | "submit" => Some("release"),
        _ => None,
    }
}

/// The policy rows bound to this event: `(name, argv)` pairs in file order.
/// A row without a command cannot run at all, which is a refusal — the
/// policy declared a check the executor cannot reach.
fn checkers_for(policy: &Path, event: &str) -> Result<Vec<(String, Vec<String>)>, String> {
    let raw = std::fs::read_to_string(policy)
        .map_err(|_| format!("audit policy {} is absent", policy.display()))?;
    let document: toml::Value =
        toml::from_str(&raw).map_err(|error| format!("audit policy does not parse: {error}"))?;
    let rows = document
        .get("checkers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut selected = Vec::new();
    for row in rows {
        let on = row
            .get("on")
            .and_then(|v| v.as_array())
            .map(|list| list.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
            .unwrap_or_default();
        if !on.contains(&event) {
            continue;
        }
        let name = row
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("checker")
            .to_string();
        let argv = row
            .get("command")
            .and_then(|v| v.as_array())
            .map(|list| {
                list.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if argv.is_empty() {
            return Err(format!("checker {name} declares no command"));
        }
        selected.push((name, argv));
    }
    Ok(selected)
}

/// The child's range environment. `detail` fields map onto the same
/// PROBATOR_* names the gate-side hooks already use; `range` names the
/// review object explicitly — `working-tree` for the uncommitted state, any
/// other value must resolve to a commit. No range at all falls back to the
/// event's own scope when it carries one, else the working tree.
fn range_env(event: &str, detail: &Map<String, Value>) -> Vec<(&'static str, String)> {
    let mut env = Vec::new();
    for (field, var) in [
        ("tag", "PROBATOR_RELEASE_TAG"),
        ("commit", "PROBATOR_RELEASE_COMMIT"),
        ("base", "PROBATOR_PR_BASE"),
        ("head", "PROBATOR_PR_HEAD"),
        ("number", "PROBATOR_PR_NUMBER"),
        ("push_refs", "PROBATOR_PUSH_REFS"),
    ] {
        if let Some(value) = detail.get(field).and_then(|v| v.as_str()) {
            let value = value.trim();
            if !value.is_empty() {
                env.push((var, value.to_string()));
            }
        }
    }
    match detail
        .get("range")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some("working-tree") => env.push(("PROBATOR_EVENT", "working-tree".to_string())),
        Some(range) => env.push(("PROBATOR_HEAD", range.to_string())),
        None => {
            let scoped = (event == "release"
                && env.iter().any(|(var, _)| *var == "PROBATOR_RELEASE_COMMIT"))
                || (event == "pr" && env.iter().any(|(var, _)| *var == "PROBATOR_PR_HEAD"))
                || (event == "pre-push" && env.iter().any(|(var, _)| *var == "PROBATOR_PUSH_REFS"));
            env.push((
                "PROBATOR_EVENT",
                if scoped { event } else { "working-tree" }.to_string(),
            ));
        }
    }
    env
}

/// The reports a checker invocation produced, located by the ` report: `
/// lines `probator run` prints — the declared interface between the run and
/// whoever consumes the sealed receipt.
fn report_paths(stdout: &str) -> Vec<PathBuf> {
    stdout
        .lines()
        .filter_map(|line| line.rsplit_once(" report: ").map(|(_, path)| path.trim()))
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// A line a checker emits while tearing down a conversation that has already
/// ended: killing a pid that exited on its own (or a probe it may not signal),
/// or archiving a session whose turn is over. These are housekeeping, never
/// audit evidence, and they must not turn a settled review into a refusal.
fn cleanup_noise(line: &str) -> bool {
    let line = line.trim().to_ascii_lowercase();
    (line.contains("kill")
        && (line.contains("no such process") || line.contains("operation not permitted")))
        || line.starts_with("conceal:")
        || (line.contains("session")
            && (line.contains("already ended")
                || line.contains("already closed")
                || line.contains("not running")))
}

const FAILURE_WORDS: [&str; 8] = [
    "fail", "error", "denied", "abort", "cancel", "timeout", "panic", "refus",
];

/// The exact settled-pass lines `probator run` prints. The gate does not
/// treat an arbitrary log substring as a verdict: a failed invocation that
/// merely mentions a report or a settled phrase is still a failure.
fn settled_line(line: &str) -> bool {
    let line = line.trim();
    if let Some(prefix) =
        line.strip_suffix(": nothing unpublished in this operation; no review needed")
    {
        return !prefix.trim().is_empty();
    }
    if line.ends_with("); reusing that verdict")
        && line.contains(" already passed its semantic review (")
        && line
            .split_once(": ")
            .is_some_and(|(title, _)| !title.trim().is_empty())
    {
        return true;
    }
    if let Some((prefix, rest)) = line.split_once(": outcome waived by signed operator ruling") {
        return !prefix.trim().is_empty()
            && (rest.is_empty() || rest.starts_with(" — waived findings: "));
    }
    false
}

/// Progress chatter: the agent announcing the skill or resource it is
/// reading, or the run announcing that it settled without a review. An abort
/// is still reported through the failure lines around it; these lines are not
/// a diagnosis.
fn progress_noise(line: &str) -> bool {
    let line = line.trim();
    let lower = line.to_ascii_lowercase();
    let failure = FAILURE_WORDS.iter().any(|word| lower.contains(word));
    // A settled announcement or report hand-off is housekeeping, but only
    // when the same line does not also report a failure. A diagnostic such
    // as "failed to write report: ..." must survive the filter.
    if !failure
        && (settled_line(line)
            || line
                .rsplit_once(" report: ")
                .is_some_and(|(before, path)| !before.trim().is_empty() && !path.trim().is_empty()))
    {
        return true;
    }
    let announcement = (line.starts_with("**") && line.ends_with("**") && line.len() > 4)
        || line.starts_with("Reading ");
    if !announcement {
        return false;
    }
    // A progress announcement that also reports a failure is a diagnosis:
    // only the plain "reading/checking ..." chatter is suppressed.
    !failure
}

/// The lines that actually explain a refused invocation, and whether any
/// cleanup-only line was present. Stderr is read first, matching the
/// diagnostic order a caller expects; duplicates are dropped.
fn failure_lines(stdout: &str, stderr: &str) -> (Vec<String>, bool) {
    let mut lines: Vec<String> = Vec::new();
    let mut cleanup = false;
    for line in stderr.lines().chain(stdout.lines()) {
        let line = line.trim();
        if line.is_empty() || progress_noise(line) {
            continue;
        }
        if cleanup_noise(line) {
            cleanup = true;
            continue;
        }
        if !lines.iter().any(|seen| seen == line) {
            lines.push(line.to_string());
        }
    }
    (lines, cleanup)
}

/// Whether the invocation printed one of the exact settled-pass lines
/// `probator run` emits when there is no report to hand back. A cleanup
/// failure after such a completion cannot manufacture an audit verdict; only
/// a real refusal without one can.
fn audit_completed(stdout: &str) -> bool {
    stdout.lines().any(settled_line)
}

fn severity_of(report_severity: &str) -> &'static str {
    match report_severity.to_ascii_lowercase().as_str() {
        "blocking" | "high" | "error" => "high",
        "warn" | "warning" => "warn",
        _ => "info",
    }
}

/// How strongly a receipt's own label refuses publication. Duplicates at one
/// location merge by the strongest label, so an advisory can never mask a
/// blocking finding.
fn severity_rank(report_severity: &str) -> u8 {
    match report_severity.to_ascii_lowercase().as_str() {
        "blocking" => 3,
        "high" | "error" => 2,
        "warn" | "warning" => 1,
        _ => 0,
    }
}

/// The receipt's standing view: fresh findings plus the carried blockers, in
/// the same order and form the review engine merges before matching operator
/// rulings. A waiver index therefore names the same location on both
/// surfaces.
fn standing(report: &Value) -> Value {
    let mut merged = report.clone();
    let mut findings = merged["findings"].as_array().cloned().unwrap_or_default();
    for finding in report["carried_findings"].as_array().into_iter().flatten() {
        let duplicate = findings.iter().any(|existing| {
            existing["file"] == finding["file"]
                && existing["line"] == finding["line"]
                && existing["evidence"] == finding["evidence"]
        });
        if !duplicate {
            findings.push(finding.clone());
        }
    }
    merged["findings"] = json!(findings);
    merged
}

/// One finding's identity inside a receipt: location plus the evidence text
/// its fingerprint is computed from. Two blockers may share a location; only
/// the one an operator ruling names may be suppressed.
type FindingIdentity = (String, u64, String);

fn finding_identity(finding: &Value) -> FindingIdentity {
    (
        finding["file"].as_str().unwrap_or("").to_string(),
        finding["line"].as_u64().unwrap_or(0),
        finding["evidence"].as_str().unwrap_or("").to_string(),
    )
}

/// The findings a signature-verified operator ledger waives for this report,
/// and whether a verdict-level ruling accepts the whole outcome. The gate
/// recomputes this from the configured ledger and anchor itself: an unsigned
/// `waivers.json` sidecar is a run-history note, never authority. Keeping the
/// per-finding identity is what stops a fingerprint ruling for one blocker
/// from suppressing an unrelated blocker at the same file and line.
fn signed_waivers(
    report: &Value,
    checker: &str,
    ledger: Option<&Path>,
    anchor: Option<&Path>,
) -> (HashSet<FindingIdentity>, bool) {
    let merged = standing(report);
    let repo = report["repo"].as_str().unwrap_or("");
    let slug = repo.strip_prefix("local:").map_or(repo, |_| "");
    let head = report["review_head"].as_str().unwrap_or("");
    let (indexes, verdict_waived) =
        crate::objection::waivers_from(ledger, anchor, &merged, checker, slug, head);
    let waived = indexes
        .iter()
        .map(|index| finding_identity(&merged["findings"][*index]))
        .collect();
    (waived, verdict_waived)
}

/// One sealed report → gate findings. Evidence and validation stay inside
/// the run directory; only locations and judgements cross.
fn findings_of(name: &str, report_path: &Path) -> Vec<Value> {
    let ledger = crate::objection::ledger_path();
    let anchor = crate::objection::anchor_path();
    findings_of_at(name, report_path, ledger.as_deref(), anchor.as_deref())
}

fn findings_of_at(
    name: &str,
    report_path: &Path,
    ledger: Option<&Path>,
    anchor: Option<&Path>,
) -> Vec<Value> {
    let report: Value = match std::fs::read_to_string(report_path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
    {
        Some(report) => report,
        None => {
            return vec![high(format!(
                "{name}: audit ended without a readable sealed report"
            ))];
        }
    };
    // A path printed by the checker only settles the audit when the document
    // behind it is the sealed receipt the engine writes. A hand-written pass
    // JSON must not become a gate pass merely because the path was printed.
    if !crate::seal::valid(&report) {
        return vec![high(format!(
            "{name}: audit ended without a readable sealed report"
        ))];
    }
    let verdict = report["verdict"].as_str().unwrap_or("");
    let carried: Vec<Value> = report["carried_findings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    // A pass verdict with carried blockers is a legitimate standing refusal:
    // the receipt's gate_status records it. A pass the receipt never
    // confirmed and that carries nothing is the suspicious shape.
    if verdict == "pass" && report["gate_status"] != "passed" && carried.is_empty() {
        return vec![high(format!(
            "{name}: report claims a pass the receipt never confirmed"
        ))];
    }
    let (waived_findings, verdict_waived) = signed_waivers(&report, name, ledger, anchor);
    if verdict_waived {
        return Vec::new();
    }
    // A gate finding carries a location, not evidence. Suppress a location
    // only when every blocking finding there is waived: a fingerprint ruling
    // for one blocker must leave its neighbour standing.
    let mut blocking_at: HashMap<(String, u64), (usize, usize)> = HashMap::new();
    for finding in report["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(carried.iter())
    {
        if finding["severity"].as_str() != Some("blocking") {
            continue;
        }
        let location = (
            finding["file"].as_str().unwrap_or("").to_string(),
            finding["line"].as_u64().unwrap_or(0),
        );
        let counts = blocking_at.entry(location).or_default();
        counts.0 += 1;
        if waived_findings.contains(&finding_identity(finding)) {
            counts.1 += 1;
        }
    }
    let waived_locations: HashSet<(String, u64)> = blocking_at
        .iter()
        .filter(|(_, (total, waived))| *total > 0 && total == waived)
        .map(|(location, _)| location.clone())
        .collect();
    let mut findings = Vec::new();
    // The gate reports locations, not evidence: one location surfaces once
    // even when the receipt carries the same finding twice. A later finding
    // with a stronger severity replaces the first — an advisory duplicate
    // must never mask a blocking finding on the same location.
    let mut merged: Vec<(&Value, bool)> = Vec::new();
    let mut positions: HashMap<(String, u64), usize> = HashMap::new();
    for (finding, inherited) in report["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|finding| (finding, false))
        .chain(carried.iter().map(|finding| (finding, true)))
    {
        let location = (
            finding["file"].as_str().unwrap_or("").to_string(),
            finding["line"].as_u64().unwrap_or(0),
        );
        if waived_locations.contains(&location)
            || (finding["severity"].as_str() == Some("blocking")
                && waived_findings.contains(&finding_identity(finding)))
        {
            continue;
        }
        if let Some(&index) = positions.get(&location) {
            let current = severity_rank(merged[index].0["severity"].as_str().unwrap_or(""));
            if severity_rank(finding["severity"].as_str().unwrap_or("")) > current {
                merged[index] = (finding, inherited);
            }
            continue;
        }
        positions.insert(location, merged.len());
        merged.push((finding, inherited));
    }
    for (finding, inherited) in merged {
        let impact = finding["impact"].as_str().unwrap_or("");
        let remedy = finding["remedy"].as_str().unwrap_or("");
        let message = match (impact.is_empty(), remedy.is_empty()) {
            (false, false) => format!("{name}: {impact} — {remedy}"),
            (false, true) => format!("{name}: {impact}"),
            _ => format!("{name}: finding"),
        };
        let message = if inherited {
            format!("{message} (carried from the previous covered head)")
        } else {
            message
        };
        let mut out = json!({
            "source": "probator",
            "severity": severity_of(finding["severity"].as_str().unwrap_or("")),
            "message": message,
        });
        if let Some(file) = finding["file"].as_str().filter(|f| !f.is_empty()) {
            out["path"] = json!(file);
        }
        if let Some(line) = finding["line"].as_u64().filter(|l| *l > 0) {
            out["line"] = json!(line);
        }
        findings.push(out);
    }
    // A non-pass verdict with no blocking finding to show is not clean: the
    // gate's consumers stop on high severity, so the refusal is synthesized
    // from the report's own summary rather than trusted to be remembered.
    if verdict != "pass"
        && waived_findings.is_empty()
        && !findings.iter().any(|finding| finding["severity"] == "high")
    {
        let summary = report["summary"].as_str().unwrap_or("no summary");
        findings.push(high(format!("{name}: verdict {verdict} — {summary}")));
    }
    findings
}

/// Whether this policy row runs the review engine rather than an arbitrary
/// script checker. Only the engine can produce a sealed receipt, so only it
/// is expected to settle through one of the exact completion lines.
fn review_runner(argv: &[String]) -> bool {
    argv.iter().skip(1).any(|arg| arg == "run") && argv.iter().any(|arg| arg == "--contract")
}

/// One policy row → findings: run the declared command, then translate
/// whatever sealed reports it produced. A command with no review run
/// subcommand is a script checker — its exit code is the whole verdict.
fn run_checker(name: &str, argv: &[String], repo: &str, env: &[(&str, String)]) -> Vec<Value> {
    let mut command = Command::new(&argv[0]);
    command.args(argv[1..].iter().map(|arg| arg.replace("{repo}", repo)));
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in env {
        command.env(key, value);
    }
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => return vec![high(format!("{name}: checker could not start: {error}"))],
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reports = report_paths(&stdout);
    if reports.is_empty() {
        if output.status.success() {
            // A review runner exits successfully only after printing a
            // settled pass, a reused verdict, a waiver, or a report path.
            // Silence is not a pass: without a sealed receipt the audit did
            // not finish, so the gate stays closed.
            if review_runner(argv) && !audit_completed(&stdout) {
                let (detail, _) = failure_lines(&stdout, &stderr);
                let tail = detail
                    .first()
                    .map(String::as_str)
                    .unwrap_or("no settled verdict was printed");
                return vec![high(format!(
                    "{name}: audit did not complete — no sealed report (exit 0): {tail}"
                ))];
            }
            return Vec::new();
        }
        let (detail, cleanup) = failure_lines(&stdout, &stderr);
        // A cleanup race after a completed audit (the report path or a
        // settled pass was already printed, then a dead pid was killed)
        // describes housekeeping, not the review. It cannot become a gate
        // finding on its own.
        if cleanup && detail.is_empty() && audit_completed(&stdout) {
            return Vec::new();
        }
        // No report and no completion: the audit did not finish. Say that —
        // never dress a session abort up as a checker verdict. It stays a
        // high refusal, so fail-closed behavior is unchanged.
        #[cfg(unix)]
        let signal = {
            use std::os::unix::process::ExitStatusExt as _;
            output.status.signal()
        };
        #[cfg(not(unix))]
        let signal = None;
        let message = if let Some(signal) = signal {
            let first = detail
                .first()
                .map(String::as_str)
                .unwrap_or("no diagnostics");
            format!(
                "{name}: audit did not complete — terminated by signal {signal}; no sealed report: {first}"
            )
        } else if detail.is_empty() {
            let tail = if cleanup {
                "only cleanup diagnostics were emitted"
            } else {
                "no diagnostic was emitted"
            };
            format!("{name}: audit did not complete — no sealed report was produced and {tail}")
        } else {
            format!(
                "{name}: audit did not complete — no sealed report (exit {:?}): {}",
                output.status.code(),
                detail[0]
            )
        };
        return vec![high(message)];
    }
    reports
        .iter()
        .flat_map(|path| findings_of(name, path))
        .collect()
}

/// Every checker bound to the event runs in its own thread: each reviewer
/// owns its run directory and the shared stage-1 evidence document is a
/// per-key store built for concurrent readers, so the only sequencing the
/// gate needs is joining the handles in policy order before the findings
/// print. A thread that dies before answering is a refusal, not a pass.
fn run_checkers(
    checkers: &[(String, Vec<String>)],
    repo: &str,
    env: &[(&str, String)],
) -> Vec<Value> {
    std::thread::scope(|scope| {
        checkers
            .iter()
            .map(|(name, argv)| {
                (
                    name,
                    scope.spawn(move || run_checker(name, argv, repo, env)),
                )
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flat_map(|(name, handle)| {
                handle
                    .join()
                    .unwrap_or_else(|_| vec![high(format!("{name}: the checker thread panicked"))])
            })
            .collect()
    })
}

/// Claim an exclusively owned 0700 directory under `base` and name the
/// shared stage-1 evidence document inside it. The orchestrator owns this
/// root; children never recreate a missing ancestor, so a failed claim just
/// leaves the cache off instead of trusting state outside the boundary.
fn claim_evidence_root(base: &Path) -> Option<PathBuf> {
    for attempt in 0..64u32 {
        let candidate = base.join(format!(
            "probator-stage1-{}-{attempt}-{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&candidate) {
            Ok(()) => return Some(candidate.join("evidence.json")),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => break,
        }
    }
    None
}

/// The per-gate-run evidence document every spawned checker shares: the
/// first resolution and scan are recorded once instead of re-bought by each
/// reviewer. A single process-wide claim keeps concurrent checks separate.
fn stage1_evidence_path() -> Option<PathBuf> {
    static PATH: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    PATH.get_or_init(|| claim_evidence_root(&std::env::temp_dir()))
        .clone()
}

pub fn run() -> i32 {
    let findings = (|| {
        let mut input = String::new();
        if std::io::stdin().read_to_string(&mut input).is_err() {
            return vec![high("the gate action could not be read")];
        }
        let action: Value = match serde_json::from_str(&input) {
            Ok(action) => action,
            Err(_) => return vec![high("the gate action is not valid JSON")],
        };
        let kind = action["kind"].as_str().unwrap_or("");
        let Some(event) = event_of(kind) else {
            return vec![high(format!("unknown gate event kind '{kind}'"))];
        };
        let target = action["target"].as_str().unwrap_or("").trim().to_string();
        if target.is_empty() {
            return vec![high("the gate action names no target")];
        }
        let detail = action["detail"].as_object().cloned().unwrap_or_default();
        let mut env = range_env(event, &detail);
        let policy = crate::install::policy_file();
        let checkers = match checkers_for(&policy, event) {
            Ok(checkers) => checkers,
            Err(message) => return vec![high(message)],
        };
        // One private evidence document for the whole operation: range
        // resolution and the withheld/credential sweep are shared by every
        // checker the event spawns.
        let evidence = stage1_evidence_path();
        if let Some(path) = &evidence {
            env.push(("PROBATOR_STAGE1_EVIDENCE", path.display().to_string()));
        }
        // The range is resolved once, here, before any checker starts: the
        // single fetch and snapshot scan land in the shared document under
        // the same key the children compute from these PROBATOR_* values, so
        // every spawned reviewer joins on a hit and no checker ever repeats
        // the remote work. A resolution error is left for the children to
        // report with their own context.
        if let Some(path) = evidence.as_deref() {
            let vars: serde_json::Map<String, Value> = env
                .iter()
                .map(|(name, value)| ((*name).to_string(), Value::String(value.clone())))
                .collect();
            let _ = crate::ranges::ranges_shared(&target, event, &vars, Some(path));
        }
        let findings = run_checkers(&checkers, &target, &env);
        if let Some(root) = evidence.as_deref().and_then(Path::parent) {
            let _ = std::fs::remove_dir_all(root);
        }
        findings
    })();
    match serde_json::to_string(&findings) {
        Ok(text) => {
            println!("{text}");
            0
        }
        Err(_) => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Write a report fixture the gate accepts as a sealed receipt. Tests
    /// that exercise the unsealed path write the file directly instead.
    fn write_sealed_report(path: &Path, mut report: Value) {
        report["seal"] = json!(crate::seal::seal("", &report));
        std::fs::write(path, serde_json::to_string(&report).unwrap()).unwrap();
    }

    #[test]
    fn event_aliases_collapse() {
        for (kind, event) in [
            ("Push", "pre-push"),
            ("pre-push", "pre-push"),
            ("working-tree", "pre-push"),
            ("pr", "pr"),
            ("Release", "release"),
            ("Publish", "release"),
            ("submit", "release"),
        ] {
            assert_eq!(event_of(kind), Some(event), "{kind}");
        }
        assert_eq!(event_of("commit"), None);
    }

    #[test]
    fn range_env_names_the_review_object() {
        let detail = json!({"range": "working-tree"})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            range_env("pre-push", &detail),
            vec![("PROBATOR_EVENT", "working-tree".to_string())]
        );
        let detail = json!({"range": "HEAD~3"}).as_object().unwrap().clone();
        assert_eq!(
            range_env("pre-push", &detail),
            vec![("PROBATOR_HEAD", "HEAD~3".to_string())]
        );
        let detail = json!({"tag": "v1", "commit": "abc"})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            range_env("release", &detail),
            vec![
                ("PROBATOR_RELEASE_TAG", "v1".to_string()),
                ("PROBATOR_RELEASE_COMMIT", "abc".to_string()),
                ("PROBATOR_EVENT", "release".to_string()),
            ]
        );
        // A pre-push carrying ref lines scopes to those refs; without them it
        // degrades to the working tree rather than pretending a range exists.
        let detail = json!({"push_refs": "refs/heads/main a1b2 refs/heads/main c3d4"})
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            range_env("pre-push", &detail),
            vec![
                (
                    "PROBATOR_PUSH_REFS",
                    "refs/heads/main a1b2 refs/heads/main c3d4".to_string()
                ),
                ("PROBATOR_EVENT", "pre-push".to_string()),
            ]
        );
        let detail = json!({}).as_object().unwrap().clone();
        assert_eq!(
            range_env("pre-push", &detail),
            vec![("PROBATOR_EVENT", "working-tree".to_string())]
        );
    }

    #[test]
    fn report_translation_never_carries_evidence() {
        let dir = std::env::temp_dir().join(format!(
            "probator-gate-report-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");
        write_sealed_report(
            &path,
            json!({
                "verdict": "block",
                "gate_status": "refused",
                "summary": "leaks",
                "findings": [{
                    "file": "a.txt",
                    "line": 7,
                    "severity": "blocking",
                    "evidence": "the actual secret text must never leave the run",
                    "impact": "a credential would publish",
                    "remedy": "remove it",
                    "validation": "more quoted secrets"
                }]
            }),
        );
        let findings = findings_of_at("privacy-cleaner", &path, None, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "high");
        assert_eq!(findings[0]["path"], "a.txt");
        assert_eq!(findings[0]["line"], 7);
        let text = serde_json::to_string(&findings).unwrap();
        assert!(!text.contains("secret text"));
        assert!(!text.contains("more quoted"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn carried_blockers_surface_until_a_recorded_waiver_clears_them() {
        let dir = std::env::temp_dir().join(format!(
            "probator-gate-carried-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");
        write_sealed_report(
            &path,
            json!({
                "verdict": "pass",
                "gate_status": "refused",
                "summary": "the fresh range is clean",
                "findings": [],
                "carried_findings": [{
                    "file": "b.txt",
                    "line": 2,
                    "severity": "blocking",
                    "evidence": "the sealed blocker still stands",
                    "impact": "the old defect remains",
                    "remedy": "re-open and fix it"
                }]
            }),
        );
        let findings = findings_of_at("privacy-cleaner", &path, None, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["severity"], "high");
        assert_eq!(findings[0]["path"], "b.txt");
        assert_eq!(findings[0]["line"], 2);
        assert!(
            findings[0]["message"].as_str().unwrap().contains("carried"),
            "{findings:?}"
        );
        let text = serde_json::to_string(&findings).unwrap();
        assert!(!text.contains("sealed blocker still stands"), "{text}");

        // The gate recomputes the waiver from the configured signed ledger;
        // the location-level ruling clears the carried blocker.
        let (ledger, anchor) = signed_waiver_ledger(
            &dir,
            "id = \"waive-carried\"\nchecker = \"privacy-cleaner\"\nkind = \"finding\"\n\
             file = \"b.txt\"\nline = 2\nverdict = \"overruled\"\n",
        );
        assert!(findings_of_at("privacy-cleaner", &path, Some(&ledger), Some(&anchor)).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_location_surfaces_once_across_fresh_and_carried_findings() {
        let dir = std::env::temp_dir().join(format!(
            "probator-gate-dedup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");
        write_sealed_report(
            &path,
            json!({
                "verdict": "block",
                "gate_status": "refused",
                "summary": "one defect",
                "findings": [{
                    "file": "a.txt", "line": 7, "severity": "blocking",
                    "evidence": "fresh evidence", "impact": "stale", "remedy": "fix"
                }],
                "carried_findings": [{
                    "file": "a.txt", "line": 7, "severity": "blocking",
                    "evidence": "carried evidence", "impact": "stale", "remedy": "fix"
                }]
            }),
        );
        let findings = findings_of_at("privacy-cleaner", &path, None, None);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0]["path"], "a.txt");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_advisory_duplicate_never_masks_a_blocking_finding() {
        let dir = std::env::temp_dir().join(format!(
            "probator-gate-dedup-rank-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");
        write_sealed_report(
            &path,
            json!({
                "verdict": "pass",
                "gate_status": "refused",
                "summary": "the increment is clean but the old blocker stands",
                "findings": [{
                    "file": "a.txt", "line": 7, "severity": "info",
                    "evidence": "fresh advisory", "impact": "advisory", "remedy": "note"
                }],
                "carried_findings": [{
                    "file": "a.txt", "line": 7, "severity": "blocking",
                    "evidence": "the old blocker still stands",
                    "impact": "the old defect remains",
                    "remedy": "re-open and fix it"
                }]
            }),
        );
        let findings = findings_of_at("privacy-cleaner", &path, None, None);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0]["severity"], "high");
        assert_eq!(findings[0]["path"], "a.txt");
        let message = findings[0]["message"].as_str().unwrap();
        assert!(message.contains("old defect remains"), "{message}");

        // The waiver still names the merged blocking finding.
        let (ledger, anchor) = signed_waiver_ledger(
            &dir,
            "id = \"waive-merged\"\nchecker = \"privacy-cleaner\"\nkind = \"finding\"\n\
             file = \"a.txt\"\nline = 7\nverdict = \"overruled\"\n",
        );
        assert!(findings_of_at("privacy-cleaner", &path, Some(&ledger), Some(&anchor)).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn refusal_without_findings_synthesizes_a_high() {
        let dir = std::env::temp_dir().join(format!(
            "probator-gate-report2-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");
        write_sealed_report(
            &path,
            json!({
                "verdict": "block",
                "gate_status": "refused",
                "summary": "coverage incomplete",
                "findings": []
            }),
        );
        let findings = findings_of_at("x", &path, None, None);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]["message"]
                .as_str()
                .unwrap()
                .contains("coverage incomplete")
        );
        // Advisory findings do not stand in for the refusal either: a
        // non-pass verdict with no high still synthesizes one.
        write_sealed_report(
            &path,
            json!({
                "verdict": "incomplete",
                "gate_status": "refused",
                "summary": "coverage incomplete",
                "findings": [{
                    "file": "a.txt", "line": 3, "severity": "advisory",
                    "evidence": "note", "impact": "minor note", "remedy": "none"
                }]
            }),
        );
        let findings = findings_of_at("x", &path, None, None);
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(
            findings.iter().any(|finding| finding["severity"] == "high"
                && finding["message"]
                    .as_str()
                    .unwrap()
                    .contains("coverage incomplete")),
            "{findings:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_shared_evidence_root_is_private_and_named_inside_it() {
        let base = std::env::temp_dir().join(format!(
            "probator-gate-evidence-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let evidence = claim_evidence_root(&base).expect("a private root is claimable");
        assert_eq!(evidence.file_name().unwrap(), "evidence.json");
        assert_eq!(evidence.parent().unwrap().parent().unwrap(), base);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(evidence.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o700);
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn report_lines_locate_the_receipt() {
        let stdout =
            "Synthetic Reviewer: pass — all good\nSynthetic Reviewer report: /tmp/x/report.json\n";
        assert_eq!(
            report_paths(stdout),
            vec![PathBuf::from("/tmp/x/report.json")]
        );
    }

    /// A sealed-report fixture: one blocking finding at `src/a.rs:12`, with
    /// the repository and head a verdict-level ruling binds to.
    fn waiver_fixture(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "probator-gate-waiver-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");
        write_sealed_report(
            &path,
            json!({
                "verdict": "block",
                "gate_status": "refused",
                "summary": "blocked",
                "repo": "synthetic/repo",
                "review_head": HEAD,
                "findings": [{
                    "file": "src/a.rs",
                    "line": 12,
                    "severity": "blocking",
                    "evidence": "the synthetic cost",
                    "impact": "a real cost",
                    "remedy": "fix it"
                }]
            }),
        );
        (path, dir)
    }

    const HEAD: &str = "0123456789012345678901234567890123456789";

    /// An operator-signed ruling ledger plus the allowed-signers anchor that
    /// verifies it. The signature namespace/principal match the config signer.
    fn signed_waiver_ledger(dir: &Path, body: &str) -> (PathBuf, PathBuf) {
        let key = dir.join("ruling-key");
        let keygen = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .output()
            .expect("ssh-keygen is required for the signature tests");
        assert!(
            keygen.status.success(),
            "ssh-keygen keygen failed: {}",
            String::from_utf8_lossy(&keygen.stderr)
        );
        let public = std::fs::read_to_string(dir.join("ruling-key.pub")).unwrap();
        let anchor = dir.join("ruling-anchor");
        std::fs::write(
            &anchor,
            format!("rulings {}", public.trim_end_matches('\n')),
        )
        .unwrap();
        let ledger = dir.join("objections.toml");
        std::fs::write(&ledger, format!("[[ruling]]\n{body}")).unwrap();
        let signature = Command::new("ssh-keygen")
            .args(["-Y", "sign", "-n", "test-rulings", "-f"])
            .arg(&key)
            .arg(&ledger)
            .output()
            .expect("ssh-keygen is required for the signature tests");
        assert!(
            signature.status.success(),
            "ssh-keygen sign failed: {}",
            String::from_utf8_lossy(&signature.stderr)
        );
        (ledger, anchor)
    }

    #[test]
    fn a_signed_finding_waiver_leaves_no_gate_finding() {
        let (path, dir) = waiver_fixture("finding");
        let (ledger, anchor) = signed_waiver_ledger(
            &dir,
            "id = \"waive-a\"\nchecker = \"money-saver\"\nkind = \"finding\"\n\
             file = \"src/a.rs\"\nline = 12\nverdict = \"overruled\"\n",
        );
        assert!(findings_of_at("money-saver", &path, Some(&ledger), Some(&anchor)).is_empty());
        // An unsigned sidecar claiming the same waiver carries no authority.
        std::fs::write(
            dir.join("waivers.json"),
            json!({"objection_waived": ["src/a.rs:12"], "verdict_waived": false}).to_string(),
        )
        .unwrap();
        let unverified = findings_of_at("money-saver", &path, None, None);
        assert_eq!(unverified.len(), 1, "{unverified:?}");
        assert_eq!(unverified[0]["path"], "src/a.rs");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_signed_verdict_waiver_accepts_the_whole_report() {
        let (path, dir) = waiver_fixture("verdict");
        let (ledger, anchor) = signed_waiver_ledger(
            &dir,
            &format!(
                "id = \"accept-head\"\nchecker = \"money-saver\"\nkind = \"verdict\"\n\
                 head = \"{HEAD}\"\nverdict = \"overruled\"\n"
            ),
        );
        assert!(findings_of_at("money-saver", &path, Some(&ledger), Some(&anchor)).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_waiver_naming_another_location_does_not_hide_the_finding() {
        let (path, dir) = waiver_fixture("unrelated");
        let (ledger, anchor) = signed_waiver_ledger(
            &dir,
            "id = \"waive-b\"\nchecker = \"money-saver\"\nkind = \"finding\"\n\
             file = \"src/b.rs\"\nline = 4\nverdict = \"overruled\"\n",
        );
        let findings = findings_of_at("money-saver", &path, Some(&ledger), Some(&anchor));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["path"], "src/a.rs");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_fingerprint_waiver_only_clears_the_blocker_it_names() {
        let dir = std::env::temp_dir().join(format!(
            "probator-gate-fingerprint-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.json");
        let waived_evidence = "the first defect";
        write_sealed_report(
            &path,
            json!({
                "verdict": "block",
                "gate_status": "refused",
                "summary": "two defects at one location",
                "repo": "synthetic/repo",
                "review_head": HEAD,
                "findings": [{
                    "file": "src/a.rs", "line": 12, "severity": "blocking",
                    "evidence": waived_evidence,
                    "impact": "the first defect remains",
                    "remedy": "fix the first"
                }, {
                    "file": "src/a.rs", "line": 12, "severity": "blocking",
                    "evidence": "the second defect",
                    "impact": "the second defect remains",
                    "remedy": "fix the second"
                }]
            }),
        );
        let fingerprint =
            crate::objection::fingerprint("money-saver", "src/a.rs", 12, waived_evidence);
        let (ledger, anchor) = signed_waiver_ledger(
            &dir,
            &format!(
                "id = \"waive-one-of-two\"\nchecker = \"money-saver\"\nkind = \"finding\"\n\
                 file = \"src/a.rs\"\nline = 12\nfingerprint = \"{fingerprint}\"\n\
                 verdict = \"overruled\"\n"
            ),
        );
        let findings = findings_of_at("money-saver", &path, Some(&ledger), Some(&anchor));
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0]["severity"], "high");
        assert_eq!(findings[0]["path"], "src/a.rs");
        let message = findings[0]["message"].as_str().unwrap();
        assert!(
            message.contains("second defect remains"),
            "an unrelated blocker at the same location must stay: {message}"
        );
        assert!(!message.contains("first defect remains"), "{message}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A throwaway checker script: `run_checker` invokes `/bin/sh <script>`,
    /// so both the stdout report protocol and stderr diagnostics are real.
    fn checker_script(tag: &str, body: &str) -> (PathBuf, Vec<String>) {
        let dir = std::env::temp_dir().join(format!(
            "probator-gate-checker-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("checker.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        (
            dir,
            vec!["/bin/sh".to_string(), path.to_string_lossy().into_owned()],
        )
    }

    /// A checker that had already settled its review and only failed while
    /// tearing down a conversation is not a refusal.
    #[test]
    fn a_cleanup_failure_after_a_settled_audit_produces_no_high() {
        let (dir, argv) = checker_script(
            "settled",
            "echo 'sample-gate: nothing unpublished in this operation; no review needed'\n\
             echo 'kill: 424242: No such process' >&2\n\
             exit 1",
        );
        let findings = run_checker("sample-gate", &argv, "/tmp/repo", &[]);
        assert!(findings.is_empty(), "{findings:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Concealment warnings describe teardown of sessions that already
    /// finished; after a settled audit they are housekeeping, not a refusal.
    #[test]
    fn a_conceal_warning_after_a_settled_audit_produces_no_high() {
        let (dir, argv) = checker_script(
            "conceal-warning",
            "echo 'sample-gate: nothing unpublished in this operation; no review needed'\n\
             echo 'conceal: /tmp/store.db refused: database is locked' >&2\n\
             exit 1",
        );
        let findings = run_checker("sample-gate", &argv, "/tmp/repo", &[]);
        assert!(findings.is_empty(), "{findings:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Archiving a conversation whose turn already ended is teardown too; it
    /// cannot override the settled verdict.
    #[test]
    fn a_finished_session_teardown_after_a_settled_audit_produces_no_high() {
        let (dir, argv) = checker_script(
            "session-ended",
            "echo 'sample-gate: nothing unpublished in this operation; no review needed'\n\
             echo 'error: session 7f already ended before archive' >&2\n\
             exit 1",
        );
        let findings = run_checker("sample-gate", &argv, "/tmp/repo", &[]);
        assert!(findings.is_empty(), "{findings:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A report on disk outranks the wrapper's exit status: the review was
    /// complete, so cleanup noise cannot turn it into a high finding.
    #[test]
    fn a_sealed_report_outranks_a_cleanup_failure() {
        let (dir, argv) = checker_script(
            "report",
            "echo 'sample-gate: pass — clean'\n\
             echo 'sample-gate report: REPLACE/report.json'\n\
             echo 'kill: 7: No such process' >&2\n\
             exit 1",
        );
        write_sealed_report(
            &dir.join("report.json"),
            json!({
                "verdict": "pass",
                "gate_status": "passed",
                "findings": []
            }),
        );
        let path = dir.join("report.json");
        let body = std::fs::read_to_string(dir.join("checker.sh"))
            .unwrap()
            .replace("REPLACE/report.json", &path.to_string_lossy());
        std::fs::write(dir.join("checker.sh"), body).unwrap();
        let findings = run_checker("sample-gate", &argv, "/tmp/repo", &[]);
        assert!(findings.is_empty(), "{findings:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A review runner that exits successfully without printing a settled
    /// pass has not produced a receipt. Silence is not a pass.
    #[test]
    fn a_review_runner_without_a_sealed_report_refuses() {
        let (dir, mut argv) = checker_script("silent-runner", "exit 0");
        argv.extend(["run", "--contract", "contract.json"].map(str::to_string));
        let findings = run_checker("sample-gate", &argv, "/tmp/repo", &[]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0]["severity"], "high");
        let message = findings[0]["message"].as_str().unwrap();
        assert!(message.contains("audit did not complete"), "{message}");
        assert!(message.contains("no sealed report"), "{message}");
        assert!(!message.contains("refused or failed"), "{message}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A review runner's settled pass needs no report file; the exact line
    /// it prints is the completion evidence.
    #[test]
    fn a_review_runner_with_a_settled_line_passes() {
        let (dir, mut argv) = checker_script(
            "settled-runner",
            "echo 'sample-gate: nothing unpublished in this operation; no review needed'",
        );
        argv.extend(["run", "--contract", "contract.json"].map(str::to_string));
        let findings = run_checker("sample-gate", &argv, "/tmp/repo", &[]);
        assert!(findings.is_empty(), "{findings:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A report path is not a verdict on its own: the file must be the
    /// sealed receipt the engine writes.
    #[test]
    fn an_unsealed_report_is_not_a_verdict() {
        let (dir, argv) =
            checker_script("unsealed", "echo 'sample-gate report: REPLACE/report.json'");
        std::fs::write(
            dir.join("report.json"),
            json!({"verdict": "pass", "gate_status": "passed", "findings": []}).to_string(),
        )
        .unwrap();
        let path = dir.join("report.json");
        let body = std::fs::read_to_string(dir.join("checker.sh"))
            .unwrap()
            .replace("REPLACE/report.json", &path.to_string_lossy());
        std::fs::write(dir.join("checker.sh"), body).unwrap();
        let findings = run_checker("sample-gate", &argv, "/tmp/repo", &[]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0]["severity"], "high");
        assert!(
            findings[0]["message"]
                .as_str()
                .unwrap()
                .contains("without a readable sealed report"),
            "{findings:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A failure diagnostic that mentions a report is still a diagnosis.
    #[test]
    fn a_failure_line_mentioning_a_report_is_not_suppressed() {
        let (dir, argv) = checker_script(
            "report-failure",
            "echo 'failed to write report: disk full' >&2\n\
             exit 1",
        );
        let findings = run_checker("sample-gate", &argv, "/tmp/repo", &[]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0]["severity"], "high");
        let message = findings[0]["message"].as_str().unwrap();
        assert!(message.contains("failed to write report"), "{message}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Cleanup noise must not hide the real reason a checker failed.
    #[test]
    fn cleanup_noise_never_masks_the_real_failure() {
        let (dir, argv) = checker_script(
            "masked",
            "echo 'kill: 9: No such process' >&2\n\
             echo 'fatal: the audit session could not read its skill' >&2\n\
             exit 1",
        );
        let findings = run_checker("sample-gate", &argv, "/tmp/repo", &[]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        let message = findings[0]["message"].as_str().unwrap();
        assert!(message.contains("did not complete"), "{message}");
        assert!(message.contains("could not read its skill"), "{message}");
        assert!(!message.contains("No such process"), "{message}");
        assert!(!message.contains("refused or failed"), "{message}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// An aborted session with no report stays a fail-closed high, but it is
    /// reported as an incomplete audit rather than as a checker verdict.
    #[test]
    fn an_aborted_session_is_an_incomplete_audit_not_a_verdict() {
        let (dir, argv) = checker_script(
            "aborted",
            "echo '**Reading privacy-cleaner skill**' >&2\n\
             echo 'session aborted before submit' >&2\n\
             exit 1",
        );
        let findings = run_checker("privacy-cleaner", &argv, "/tmp/repo", &[]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0]["severity"], "high");
        let message = findings[0]["message"].as_str().unwrap();
        assert!(message.contains("audit did not complete"), "{message}");
        assert!(
            message.contains("session aborted before submit"),
            "{message}"
        );
        assert!(!message.contains("Reading privacy-cleaner"), "{message}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The event's checkers dispatch concurrently: each script waits for
    /// the other's start marker, so a serial loop would leave the first
    /// one waiting out its bound and landing a refusal instead of a pass.
    #[test]
    fn checkers_bound_to_one_event_run_concurrently() {
        let shared = std::env::temp_dir().join(format!(
            "probator-gate-par-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&shared).unwrap();
        let body = |own: &str, other: &str| {
            format!(
                "echo started > \"{r}/{own}\"\n\
                 n=0\n\
                 while [ $n -lt 200 ]; do\n\
                 [ -f \"{r}/{other}\" ] && exit 0\n\
                 n=$((n + 1))\n\
                 sleep 0.05\n\
                 done\n\
                 echo \"partner {other} never appeared\" >&2\n\
                 exit 1",
                r = shared.display(),
            )
        };
        let (dir_a, argv_a) = checker_script("parallel-a", &body("one", "two"));
        let (dir_b, argv_b) = checker_script("parallel-b", &body("two", "one"));
        let checkers = vec![
            ("parallel-a".to_string(), argv_a),
            ("parallel-b".to_string(), argv_b),
        ];
        let findings = run_checkers(&checkers, "/tmp/repo", &[]);
        assert!(findings.is_empty(), "{findings:?}");
        let _ = std::fs::remove_dir_all(dir_a);
        let _ = std::fs::remove_dir_all(dir_b);
        let _ = std::fs::remove_dir_all(shared);
    }

    /// Progress chatter alone is not a diagnosis. With no report the audit
    /// did not finish, so it still refuses — but it is never reported as a
    /// checker verdict, and the progress line is not quoted as evidence.
    #[test]
    fn progress_only_output_is_an_incomplete_audit() {
        let (dir, argv) = checker_script(
            "progress",
            "echo '**Checking workspace listing**' >&2\n\
             exit 1",
        );
        let findings = run_checker("security-enhancer", &argv, "/tmp/repo", &[]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0]["severity"], "high");
        let message = findings[0]["message"].as_str().unwrap();
        assert!(message.contains("audit did not complete"), "{message}");
        assert!(message.contains("no diagnostic was emitted"), "{message}");
        assert!(!message.contains("Checking workspace listing"), "{message}");
        assert!(!message.contains("refused or failed"), "{message}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A cleanup probe the wrapper may not signal is housekeeping too. With
    /// no report it stays a fail-closed incomplete audit, never a verdict.
    #[test]
    fn a_permission_denied_cleanup_probe_is_not_a_verdict() {
        let (dir, argv) = checker_script(
            "eperm",
            "echo 'kill: 71385: Operation not permitted' >&2\n\
             exit 1",
        );
        let findings = run_checker("sample-gate", &argv, "/tmp/repo", &[]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0]["severity"], "high");
        let message = findings[0]["message"].as_str().unwrap();
        assert!(message.contains("audit did not complete"), "{message}");
        assert!(message.contains("only cleanup diagnostics"), "{message}");
        assert!(!message.contains("refused or failed"), "{message}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A progress line that reports its own failure is a diagnosis, not
    /// chatter: the conservative filter must not hide it.
    #[test]
    fn a_failing_progress_line_is_still_a_diagnosis() {
        let (dir, argv) = checker_script(
            "failed-progress",
            "echo '**Reading the required skill failed: permission denied**' >&2\n\
             exit 1",
        );
        let findings = run_checker("money-saver", &argv, "/tmp/repo", &[]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        let message = findings[0]["message"].as_str().unwrap();
        assert!(message.contains("audit did not complete"), "{message}");
        assert!(message.contains("permission denied"), "{message}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A checker killed by a signal without a report stays a high refusal and
    /// names the signal instead of inventing a verdict.
    #[cfg(unix)]
    #[test]
    fn a_signalled_checker_without_a_report_still_refuses() {
        let (dir, argv) = checker_script("signal", "kill -TERM $$");
        let findings = run_checker("sample-gate", &argv, "/tmp/repo", &[]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0]["severity"], "high");
        let message = findings[0]["message"].as_str().unwrap();
        assert!(message.contains("terminated by signal 15"), "{message}");
        assert!(message.contains("no sealed report"), "{message}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A crash with no report is still a high refusal: fail-closed is not
    /// weakened by the cleanup classification.
    #[test]
    fn a_crash_without_a_report_still_refuses() {
        let (dir, argv) = checker_script(
            "crash",
            "echo 'thread main panicked at src/bin/probator.rs:1' >&2\n\
             exit 1",
        );
        let findings = run_checker("sample-gate", &argv, "/tmp/repo", &[]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0]["severity"], "high");
        let message = findings[0]["message"].as_str().unwrap();
        assert!(message.contains("did not complete"), "{message}");
        assert!(message.contains("panicked"), "{message}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A printed report path whose file is absent is still a refusal: the
    /// gate never treats an unreadable receipt as a pass.
    #[test]
    fn a_report_path_without_a_readable_receipt_still_refuses() {
        let (dir, argv) = checker_script(
            "missing",
            "echo 'sample-gate report: MISSING/report.json'\n\
             exit 0",
        );
        let missing = dir.join("missing.json");
        let body = std::fs::read_to_string(dir.join("checker.sh"))
            .unwrap()
            .replace("MISSING/report.json", &missing.to_string_lossy());
        std::fs::write(dir.join("checker.sh"), body).unwrap();
        let findings = run_checker("sample-gate", &argv, "/tmp/repo", &[]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0]["severity"], "high");
        assert!(
            findings[0]["message"]
                .as_str()
                .unwrap()
                .contains("without a readable sealed report"),
            "{findings:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
