//! The orchestration layer: snapshot resolution in, one review per target,
//! receipts out. Ported from the retired Python engine's run machinery -
//! receipt reuse, the resume keys, the retention window, the audit-agent
//! review process and the full-audit lifecycle - so a review is never paid for twice
//! and an interrupted run continues instead of replaying.
//!
//! The receipt identity names the engine that produced it: receipts written
//! by the Python engine are not reused, because the deterministic stage and
//! the tool surface now live here.

use crate::contract::{self, Contract};
use crate::credential;
use crate::evidence;
use crate::fullservice;
use crate::sanitize::sanitize;
use crate::util::sha256;
use crate::{ranges, stage1};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The retention window for review-run directories, the same convention the
/// run-record store applies (src/records.rs): newest 200 survive, and nothing
/// older than 90 days. Unfinished reviews retain their paid progress until
/// finalized; only settled receipts and abandoned directories use the bounds.
pub const MAX_RUNS: usize = 200;
pub const MAX_AGE_SECS: u64 = 90 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
// the installed profile's settings and the sync contract
// ---------------------------------------------------------------------------

/// The checker installation record: paths and pins written by the installer.
pub struct Settings {
    pub agent_runner: Option<String>,
    pub profile: PathBuf,
    pub skill_dir: PathBuf,
    pub synced: Option<Value>,
    pub payload: Map<String, Value>,
    /// The review-visible identity of the operator's checker-named binding,
    /// or `null` when the packaged installation document is authoritative.
    /// A changed binding is a changed reviewer: no cursor, resume or receipt
    /// may cross it.
    pub checker_binding: Value,
}

pub fn load_settings(contract_dir: &Path, checker: &str) -> Result<Settings, String> {
    let raw = std::fs::read_to_string(contract_dir.join("installation.json"))
        .map_err(|error| format!("installation.json: {error}"))?;
    let value: Value =
        serde_json::from_str(&raw).map_err(|error| format!("installation.json: {error}"))?;
    let text = |key: &str| value[key].as_str().unwrap_or("").to_string();
    Ok(Settings {
        agent_runner: value["agent_runner"].as_str().map(str::to_string),
        profile: PathBuf::from(text("profile")),
        skill_dir: PathBuf::from(text("skill_dir")),
        synced: value.get("synced").cloned(),
        payload: value["payload"].as_object().cloned().unwrap_or_default(),
        checker_binding: checker_binding_identity(checker),
    })
}

/// The synced-document drift check: a local edit the registry never saw
/// refuses the operation, so "the registry is the only source" stays
/// executable. The payload pin does the same for the contract itself.
pub fn assert_synced(settings: &Settings, contract_dir: &Path) -> Result<(), String> {
    let mut changed = Vec::new();
    if let Some(synced) = &settings.synced
        && let Some(files) = synced["files"].as_object()
    {
        for (name, expected) in files {
            let path = settings.skill_dir.join(name);
            let matches = std::fs::read_to_string(&path)
                .map(|text| sha256(&text) == expected.as_str().unwrap_or(""))
                .unwrap_or(false);
            if !matches {
                changed.push(name.clone());
            }
        }
    }
    if !changed.is_empty() {
        return Err(format!(
            "the local prompt copy no longer matches what the registry published ({}); \
             run `probator install --source {}` to sync",
            changed.join(", "),
            contract_dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
        ));
    }
    let mut drifted = Vec::new();
    for (name, expected) in &settings.payload {
        let path = contract_dir.join(name);
        let matches = std::fs::read_to_string(&path)
            .map(|text| sha256(&text) == expected.as_str().unwrap_or(""))
            .unwrap_or(false);
        if !matches {
            drifted.push(name.clone());
        }
    }
    if !drifted.is_empty() {
        return Err(format!(
            "the installed payload no longer matches what the installer wrote ({})",
            drifted.join(", ")
        ));
    }
    Ok(())
}

/// The runtime this review runs on — the synced profile.json's declared
/// `runtime` block, held to inert labels and the declared provider's
/// namespace. A profile that declares no runtime refuses the audit: a
/// provider, model or effort is never invented, and which agent or catalog
/// the declaration names is the profile's business, not the engine's.
pub fn declared_runtime(settings: &Settings) -> Result<Map<String, Value>, String> {
    let declared = std::fs::read_to_string(settings.skill_dir.join("profile.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|profile| profile["runtime"].as_object().cloned())
        .ok_or_else(|| "The synced profile declares no audit runtime".to_string())?;
    let mut runtime = Map::new();
    for key in ["harness", "provider"] {
        let Some(value) = declared
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| contract::is_runtime_label(value))
        else {
            return Err(format!(
                "The audit runtime must declare {key} as an inert label"
            ));
        };
        runtime.insert(key.to_string(), json!(value));
    }
    // Every declared model must sit in the runtime's own provider
    // namespace — provider-relative, never a pinned vendor.
    let prefix = format!("{}/", runtime["provider"].as_str().unwrap_or(""));
    let model = declared["model"].as_str().unwrap_or("");
    if !contract::RUNTIME_VALUE.is_match(model) || !model.starts_with(&prefix) {
        return Err(format!(
            "The audit runtime's model must sit in its declared provider's namespace \
             ({prefix}…), not {model:?}"
        ));
    }
    runtime.insert("model".to_string(), json!(model));
    if let Some(effort) = declared.get("effort") {
        let Some(effort) = effort
            .as_str()
            .filter(|value| contract::RUNTIME_VALUE.is_match(value))
        else {
            return Err("runtime.effort must be an inert label".to_string());
        };
        runtime.insert("effort".to_string(), json!(effort));
    }
    if let Some(fallbacks) = declared.get("fallback_models") {
        let fallbacks = fallbacks
            .as_array()
            .ok_or_else(|| "runtime.fallback_models must be a list".to_string())?
            .iter()
            .map(|entry| entry.as_str().unwrap_or("").to_string())
            .collect::<Vec<_>>();
        if let Some(bad) = fallbacks.iter().find(|entry| !entry.starts_with(&prefix)) {
            return Err(format!(
                "runtime.fallback_models entry {bad:?} must sit in the declared provider's \
                 namespace ({prefix}…)"
            ));
        }
        runtime.insert("models".to_string(), json!(fallbacks));
    }
    if let Some(windows) = declared.get("windows") {
        let windows = windows
            .as_array()
            .ok_or_else(|| "runtime.windows must be a list".to_string())?;
        for (index, window) in windows.iter().enumerate() {
            let bounds = [window["from"].as_str(), window["to"].as_str()];
            if bounds
                .iter()
                .flatten()
                .any(|b| !contract::is_window_bound(b))
                || bounds.iter().any(Option::is_none)
            {
                return Err(format!("runtime.windows[{index}] bounds must be \"HH:MM\""));
            }
            let timezone = window["timezone"].as_str().unwrap_or("");
            if timezone.is_empty()
                || !timezone
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "/_-".contains(c))
            {
                return Err(format!(
                    "runtime.windows[{index}].timezone must be an IANA zone name"
                ));
            }
            let model_entries = window["model"].as_str().into_iter().chain(
                window["models"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str),
            );
            for entry in model_entries {
                if !entry.starts_with(&prefix) {
                    return Err(format!(
                        "runtime.windows[{index}] model {entry:?} must sit in the declared \
                         provider's namespace ({prefix}…)"
                    ));
                }
            }
        }
        runtime.insert("windows".to_string(), json!(windows));
    }
    if let Some(retry) = declared.get("retry") {
        let object = retry
            .as_object()
            .ok_or_else(|| "runtime.retry must be an object".to_string())?;
        // The contract's snake_case `reset_grace` projects into the
        // role's camelCase `resetGrace` — the AwP document shape.
        let mut projected = Map::new();
        for (key, value) in object {
            if !value.is_string() {
                return Err(format!(
                    "runtime.retry.{key} must be a duration string (\"30m\", \"PT3H1M\")"
                ));
            }
            let key = match key.as_str() {
                "interval" => "interval",
                "reset_grace" | "resetGrace" => "resetGrace",
                other => {
                    return Err(format!("runtime.retry.{other} is not a declared field"));
                }
            };
            projected.insert(key.to_string(), value.clone());
        }
        runtime.insert("retry".to_string(), Value::Object(projected));
    }
    Ok(runtime)
}

/// Stable role identity: the checker name and the registry's version tag.
fn role_identity(settings: &Settings, contract: &Contract) -> Value {
    json!({
        "id": contract.name,
        "revision": settings.synced.as_ref().and_then(|s| s["tag"].as_str()),
    })
}

/// The review-visible slice of one binding: its selected profile and fallback
/// chain, and each candidate's harness, model, session protocol and prompt
/// mapping. Secrets and command environments never enter this identity.
///
/// The bindings are normalized by the same resolver the audit host uses, so
/// the short string form and the object form name the same reviewer. An
/// absent (or explicitly null) binding is `null`, matching the packaged
/// installation path. A binding that is present but has no usable profile is
/// a distinct identity: it must never inherit the packaged reviewer's cursor
/// or sealed receipt.
fn checker_binding_identity_from(registry: &Value, checker: &str) -> Value {
    let Some(binding) = crate::checker_binding::checker_binding(registry, checker) else {
        return Value::Null;
    };
    if binding.is_null() {
        return Value::Null;
    }
    let (primary, fallbacks) = crate::checker_binding::binding_profiles(binding);
    let Some(primary) = primary else {
        // A malformed binding is not the packaged path. Keep a non-reversible
        // digest so two unusable bindings still name different identities
        // without copying arbitrary operator fields into a receipt.
        return json!({
            "unresolved": true,
            "binding_digest": sha256(&serde_json::to_string(binding).unwrap_or_default()),
        });
    };
    let profiles: Vec<Value> = std::iter::once(primary.as_str())
        .chain(fallbacks.iter().map(String::as_str))
        .map(|name| {
            let profile = &registry["profiles"][name];
            let agent = profile["agent"].as_str().unwrap_or("");
            let spec = &registry["agents"][agent];
            let alternates: Vec<Value> = spec["alternates"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|alternate| {
                    json!({
                        "id": alternate["id"],
                        "lane": alternate["lane"],
                        "prefer_load": alternate["prefer_load"],
                        "program": alternate["command"]["program"],
                        "args": alternate["command"]["args"],
                    })
                })
                .collect();
            json!({
                "profile": name,
                "agent": agent,
                "revision": profile["revision"],
                "model": profile["model"],
                "models": profile["models"],
                "windows": profile["windows"],
                "effort": profile["effort"],
                "permission": profile["permission"],
                "retry": profile["retry"],
                // Persona text and when it is composed are prompt behavior.
                "instructions": profile["instructions"],
                "instructionMode": profile["instructionMode"],
                "contextWindow": profile["contextWindow"],
                "requiredCapabilities": profile["requiredCapabilities"],
                "preferredCapabilities": profile["preferredCapabilities"],
                "stateKey": profile["stateKey"],
                "lane": spec["lane"],
                "clientName": spec["clientName"],
                "maxOutputBytes": spec["maxOutputBytes"],
                "program": spec["command"]["program"],
                "args": spec["command"]["args"],
                // The session protocol and prompt mapping are part of what
                // the reviewer actually does; an operator edit there is a
                // different reviewer, not a fresh cursor for the old one.
                "sessionOpen": spec["sessionOpen"],
                "sessionResume": spec["sessionResume"],
                "prompt": spec["prompt"],
                "passthrough": spec["passthrough"],
                "alternates": alternates,
            })
        })
        .collect();
    // Only the review-relevant authority: secrets and command environments
    // never enter a receipt or a cursor key.
    json!({
        "binding": {
            "profile": primary,
            "fallbacks": fallbacks,
            "prompt": binding["prompt"],
        },
        "profiles": profiles,
    })
}

fn checker_binding_identity(checker: &str) -> Value {
    crate::checker_binding::load_registry()
        .map(|(_, registry)| checker_binding_identity_from(&registry, checker))
        .unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------
// run directories: retention, resume keys, receipt reuse
// ---------------------------------------------------------------------------

fn unfinished_run(path: &Path) -> bool {
    // Submission is not completion: only a finalized receipt settles a run.
    if !path.join("resume.json").is_file() {
        return false;
    }
    match std::fs::read_to_string(path.join("report.json")) {
        Err(_) => true,
        Ok(raw) => serde_json::from_str::<Value>(&raw)
            .map(|report| report.get("review_head").is_none())
            .unwrap_or(false),
    }
}

pub fn prune_runs(runs_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(runs_dir) else {
        return;
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|p| p.is_dir())
        .collect();
    let mtime = |path: &Path| {
        std::fs::metadata(path)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH)
    };
    dirs.sort_by_key(|b| std::cmp::Reverse(mtime(b)));
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_sub(MAX_AGE_SECS);
    for (rank, path) in dirs.iter().enumerate() {
        if unfinished_run(path) {
            continue;
        }
        let expired = mtime(path)
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() < cutoff)
            .unwrap_or(false);
        if expired || rank >= MAX_RUNS {
            let _ = std::fs::remove_dir_all(path);
        }
    }
}

/// A previous passing review of exactly this target. The judged items are part
/// of the key: a receipt written under an earlier contract did not answer the
/// questions this run asks. Returns the receipt so the coverage ledger can
/// adopt the judgement it proves even when the ledger itself was lost.
fn audited(
    settings: &Settings,
    contract: &Contract,
    base: Option<&str>,
    head: &str,
    runtime: &Map<String, Value>,
) -> Option<Value> {
    let runs = settings.profile.join(format!("{}-runs", contract.name));
    let entries = std::fs::read_dir(&runs).ok()?;
    let identity = role_identity(settings, contract);
    for report_path in entries.flatten().map(|e| e.path().join("report.json")) {
        let Ok(raw) = std::fs::read_to_string(&report_path) else {
            continue;
        };
        let Ok(report) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let same_identity = ["id", "revision"]
            .iter()
            .all(|key| report["agent_profile"][key] == identity[key]);
        // A receipt written under another checker-named binding names a
        // reviewer that never judged this content; it is not reusable.
        let same_binding =
            report.get("checker_binding").unwrap_or(&Value::Null) == &settings.checker_binding;
        if report["review_base"].as_str().unwrap_or("") == base.unwrap_or("")
            && report["review_head"].as_str() == Some(head)
            && report["review_items"] == json!(contract.domains)
            && report["gate_status"] == "passed"
            && report["engine"] == concat!("probator ", env!("CARGO_PKG_VERSION"))
            && same_identity
            && same_binding
            && report["harness"] == runtime["harness"]
            && report["provider"] == runtime["provider"]
            && report["model"] == runtime["model"]
            && report["reasoning"] == runtime.get("effort").cloned().unwrap_or(Value::Null)
            && crate::seal::valid(&report)
        {
            return Some(report);
        }
    }
    None
}

/// `commit` is an ancestor of (or equal to) `head` in `repo`.
fn ancestor_of(repo: &str, commit: &str, head: &str) -> bool {
    if commit == head {
        return true;
    }
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["merge-base", "--is-ancestor", commit, head])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// The repository's review identity: its `owner/name` slug, or the canonical
/// checkout path when no usable remote names it. Two checkouts of one remote
/// share coverage; a path-identified local tree never shares it with another.
fn repo_identity(repo: &str) -> String {
    let slug = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            crate::git::slug_from_remote(String::from_utf8_lossy(&output.stdout).trim())
        });
    slug.or_else(|| {
        std::fs::canonicalize(repo)
            .ok()
            .map(|path| format!("local:{}", path.display()))
    })
    .unwrap_or_default()
}

/// A checker's coverage ledger entry: the newest head it finished judging
/// and the blocking findings still standing there. Reports are receipts;
/// this registry is the semantics — one lookup names everything the next
/// range must answer for.
struct Cursor {
    head: String,
    verdict: String,
    findings: Vec<Value>,
}

/// `profiles/cursors/<checker>.json`: the coverage ledger, one sealed entry
/// per repository-and-contract pair, kept beside the checker profiles in the
/// profiles root. Entries seal-chain the way receipts do — a hand-edited
/// position breaks its own seal and reads as no coverage.
fn cursor_file(profiles: &Path, checker: &str) -> PathBuf {
    profiles.join("cursors").join(format!("{checker}.json"))
}

/// The profiles root: the parent of the checker's own profile directory (the
/// same directory the conceal sweep walks). A relative profile with no parent
/// falls back to itself so the ledger still lands somewhere deterministic.
fn profiles_root(settings: &Settings) -> &Path {
    settings
        .profile
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(&settings.profile)
}

/// The reviewer identity a cursor entry belongs to: the same profile revision
/// and runtime tuple `audited` requires before it reuses a receipt. A changed
/// reviewer has not seen the covered content yet, so it must not inherit an
/// old verdict — its cursor simply does not exist.
fn runtime_identity(
    settings: &Settings,
    contract: &Contract,
    runtime: &Map<String, Value>,
) -> String {
    json!({
        "agent_profile": role_identity(settings, contract),
        "checker_binding": settings.checker_binding,
        "harness": runtime["harness"],
        "provider": runtime["provider"],
        "model": runtime["model"],
        "effort": runtime.get("effort").cloned().unwrap_or(Value::Null),
    })
    .to_string()
}

fn cursor_key(repo_id: &str, contract: &Contract, reviewer: &str) -> String {
    format!(
        "{repo_id}#{:.16}",
        sha256(&format!(
            "{}\n{reviewer}",
            serde_json::to_string(&contract.domains).unwrap_or_default()
        ))
    )
}

/// The ledger entry for this repository under this contract and reviewer —
/// only a signature-clean seal chain counts; anything else is no coverage.
fn cursor_entry(
    profiles: &Path,
    contract: &Contract,
    repo_id: &str,
    reviewer: &str,
) -> Option<Cursor> {
    let raw = std::fs::read_to_string(cursor_file(profiles, &contract.name)).ok()?;
    let store: Value = serde_json::from_str(&raw).ok()?;
    let entry = &store[cursor_key(repo_id, contract, reviewer)];
    if !crate::seal::valid(entry) {
        return None;
    }
    Some(Cursor {
        head: entry["head"].as_str()?.to_string(),
        verdict: entry["verdict"].as_str().unwrap_or("").to_string(),
        findings: entry["findings"].as_array().cloned().unwrap_or_default(),
    })
}

/// Record the position a settled verdict established. Only a complete
/// judgement moves the tape — pass is clean coverage and a block parks its
/// standing findings at the new head; an incomplete verdict judged nothing,
/// so neither the cursor nor the findings move.
fn cursor_advance(
    profiles: &Path,
    contract: &Contract,
    reviewer: &str,
    repo_id: &str,
    head: &str,
    verdict: &str,
    findings: Vec<Value>,
) {
    if verdict != "pass" && verdict != "block" {
        return;
    }
    let path = cursor_file(profiles, &contract.name);
    let mut store: Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_else(|| json!({}));
    let key = cursor_key(repo_id, contract, reviewer);
    let seal_prev = store[key.as_str()]["seal"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let mut entry = json!({
        "head": head,
        "verdict": verdict,
        "findings": findings,
        "seal_prev": seal_prev,
    });
    entry["seal"] = json!(crate::seal::seal(&seal_prev, &entry));
    store[key.as_str()] = entry;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // A cursor that cannot be written is not a verdict: the sealed receipt
    // still stands on its own, and the next run treats the range as
    // unreviewed rather than trusting a half-written ledger.
    let _ = evidence::write_json(&path, &store);
}

/// The commit this review may start from: the descendant of the target's own
/// base and the checker's coverage cursor — content at or below either was
/// already published or already reviewed, and is never reviewed twice. When
/// the two are unrelated (a rewritten history line) the target's own base
/// stands and the whole outgoing range is reviewed again.
fn effective_base(repo: &str, base: Option<&str>, cursor_head: Option<&str>) -> Option<String> {
    match (base, cursor_head) {
        (_, None) => base.map(str::to_string),
        (None, Some(cursor)) => Some(cursor.to_string()),
        (Some(base), Some(cursor)) => {
            if ancestor_of(repo, base, cursor) {
                Some(cursor.to_string())
            } else {
                Some(base.to_string())
            }
        }
    }
}

/// One `git diff --unified=0` hunk. The old-side range is the coordinate
/// space a carried finding was recorded in; the new-side count tells the
/// rebase how far surviving lines moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Hunk {
    old_start: u64,
    old_count: u64,
    new_start: u64,
    new_count: u64,
}

impl Hunk {
    fn old_end(&self) -> u64 {
        if self.old_count == 0 {
            self.old_start
        } else {
            self.old_start.saturating_add(self.old_count - 1)
        }
    }
}

/// The locations a review range rewrote. Findings were recorded against the
/// range's old side, so both `touches` and `rebase` compare their line
/// numbers there — not against the new-side ranges, where an insertion before
/// a blocker can overlap its old line number and clear a defect the range
/// never opened.
#[derive(Default, Clone)]
struct ChangedLines {
    hunks: HashMap<String, Vec<Hunk>>,
    /// Files whose whole content changed (or whose diff carries no line
    /// information, such as binaries).
    whole: HashSet<String>,
    /// Files the range removed; their evidence no longer exists.
    deleted: HashSet<String>,
}

impl ChangedLines {
    fn whole(paths: &[String]) -> Self {
        let mut changed = Self::default();
        changed.whole.extend(paths.iter().cloned());
        changed
    }

    /// Whether the range rewrote the finding's own line. A pure insertion
    /// (`old_count == 0`) sits between old lines and therefore removes none
    /// of them; a file-level finding (`line == 0`) is re-opened by any hunk.
    #[cfg(test)]
    fn touches(&self, file: &str, line: u64) -> bool {
        if self.deleted.contains(file) || self.whole.contains(file) {
            return true;
        }
        let Some(hunks) = self.hunks.get(file) else {
            return false;
        };
        line == 0
            || hunks
                .iter()
                .any(|hunk| hunk.old_count > 0 && (hunk.old_start..=hunk.old_end()).contains(&line))
    }

    /// The finding's line in the new revision when the range never rewrote
    /// it, or `None` when its evidence was modified or deleted. A finding
    /// that survives an insertion or a change before it moves with the
    /// content, so the ledger never parks a stale line number.
    fn rebase(&self, file: &str, line: u64) -> Option<u64> {
        if self.deleted.contains(file) || self.whole.contains(file) {
            return None;
        }
        let Some(hunks) = self.hunks.get(file) else {
            return Some(line);
        };
        if line == 0 {
            return None;
        }
        let mut shifted = i64::try_from(line).unwrap_or(i64::MAX);
        for hunk in hunks {
            if hunk.old_count == 0 {
                // `@@ -n,0 +m,k @@` inserts after old line n. A finding at
                // n or earlier does not move; everything after it does.
                if hunk.old_start < line {
                    shifted = shifted.saturating_add(i64::try_from(hunk.new_count).unwrap_or(0));
                }
                continue;
            }
            let old_end = hunk.old_end();
            if (hunk.old_start..=old_end).contains(&line) {
                return None;
            }
            if old_end < line {
                shifted = shifted
                    .saturating_add(i64::try_from(hunk.new_count).unwrap_or(0))
                    .saturating_sub(i64::try_from(hunk.old_count).unwrap_or(0));
            }
        }
        Some(u64::try_from(shifted.max(0)).unwrap_or(0))
    }
}

/// A hunk header range such as `-12,3` or `+4,0`. The count defaults to one,
/// matching Git's short form.
fn hunk_range(spec: &str) -> Option<(u64, u64)> {
    let body = spec.strip_prefix('-').or_else(|| spec.strip_prefix('+'))?;
    let (start, count) = body.split_once(',').unwrap_or((body, "1"));
    Some((start.parse().ok()?, count.parse().unwrap_or(1)))
}

/// Parse `git diff --unified=0` output into the old-side line ranges each path
/// rewrote. A hunk header is `@@ -old,count +new,count @@`; the blocker line
/// is live only when it falls inside `old..=old+count-1`.
fn parse_changed_lines(diff: &str) -> ChangedLines {
    let mut changed = ChangedLines::default();
    let mut previous: Option<String> = None;
    let mut new_file = false;
    let mut current: Option<String> = None;
    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            if let Some(path) = rest
                .split_whitespace()
                .nth(1)
                .and_then(|path| path.strip_prefix("b/"))
            {
                current = Some(path.to_string());
                changed.hunks.entry(path.to_string()).or_default();
            }
            continue;
        }
        if let Some(path) = line.strip_prefix("--- ") {
            let path = path.trim();
            new_file = path == "/dev/null";
            previous =
                (path != "/dev/null").then(|| path.strip_prefix("a/").unwrap_or(path).to_string());
            continue;
        }
        if let Some(path) = line.strip_prefix("+++ ") {
            let path = path.trim();
            if path == "/dev/null" {
                if let Some(old) = previous.take() {
                    changed.deleted.insert(old);
                }
                current = None;
            } else {
                let path = path.strip_prefix("b/").unwrap_or(path).to_string();
                // A whole file that did not exist in the old revision cannot
                // carry an old finding; it is re-opened rather than judged
                // by evidence from a same-named predecessor.
                if new_file {
                    changed.whole.insert(path.clone());
                }
                changed.hunks.entry(path.clone()).or_default();
                current = Some(path);
            }
            continue;
        }
        if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            if let Some(path) = current.clone() {
                changed.whole.insert(path);
            }
            continue;
        }
        let Some(header) = line.strip_prefix("@@ ") else {
            continue;
        };
        let Some(path) = current.clone() else {
            continue;
        };
        let mut parts = header.split_whitespace();
        let (Some(old), Some(new)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Some((old_start, old_count)), Some((new_start, new_count))) =
            (hunk_range(old), hunk_range(new))
        else {
            continue;
        };
        changed.hunks.entry(path).or_default().push(Hunk {
            old_start,
            old_count,
            new_start,
            new_count,
        });
    }
    changed
}

fn changed_lines_range(repo: &str, base: &str, head: &str) -> Result<ChangedLines, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args([
            "diff",
            "--unified=0",
            "--no-renames",
            "--no-color",
            "--no-ext-diff",
            base,
            head,
            "--",
        ])
        .output()
        .map_err(|error| format!("Git could not read the review diff: {error}"))?;
    if !output.status.success() {
        return Err("Git could not read the review diff".to_string());
    }
    Ok(parse_changed_lines(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// The blocking findings a ledger entry still stands on for a range that
/// never re-opened their evidence. A finding is cleared only when a hunk
/// touches its own line; a change elsewhere in the file leaves it standing,
/// because the increment never proved that defect fixed. A surviving finding
/// is rebased into the new head's coordinates, so the next increment compares
/// it against the revision that actually contains it.
fn carried_blockers(cursor: Option<&Cursor>, touched: &ChangedLines) -> Vec<Value> {
    let Some(cursor) = cursor else {
        return Vec::new();
    };
    cursor
        .findings
        .iter()
        .filter(|finding| finding["severity"].as_str() == Some("blocking"))
        .filter_map(|finding| {
            let Some(file) = finding["file"].as_str() else {
                return Some(finding.clone());
            };
            let line = finding["line"].as_u64().unwrap_or(0);
            let rebased = touched.rebase(file, line)?;
            let mut finding = finding.clone();
            if rebased != line {
                finding["line"] = json!(rebased);
            }
            Some(finding)
        })
        .collect()
}

/// The findings a receipt still stands on: the carried blockers plus every
/// fresh blocking finding, deduplicated by location and evidence. This is
/// the standing content the ledger parks at a new head.
fn standing_findings(report: &Value) -> Vec<Value> {
    let mut standing: Vec<Value> = report["carried_findings"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for finding in report["findings"].as_array().into_iter().flatten() {
        let blocking = finding["severity"].as_str() == Some("blocking");
        let duplicate = standing.iter().any(|existing| {
            existing["file"] == finding["file"]
                && existing["line"] == finding["line"]
                && existing["evidence"] == finding["evidence"]
        });
        if blocking && !duplicate {
            standing.push(finding.clone());
        }
    }
    standing
}

/// The receipt's standing view: fresh findings plus the carried blockers,
/// each carried finding labelled so the run history shows it was inherited.
fn standing_report(report: &Value) -> Value {
    let mut merged = report.clone();
    let mut findings = merged["findings"].as_array().cloned().unwrap_or_default();
    for finding in report["carried_findings"].as_array().into_iter().flatten() {
        let duplicate = findings.iter().any(|existing| {
            existing["file"] == finding["file"]
                && existing["line"] == finding["line"]
                && existing["evidence"] == finding["evidence"]
        });
        if !duplicate {
            let mut finding = finding.clone();
            finding["carried"] = json!(true);
            findings.push(finding);
        }
    }
    merged["findings"] = json!(findings);
    merged
}

/// The newest sealed receipt for this head under this checker: where a
/// replayed waiver record belongs. The cursor is the coverage semantics;
/// receipts keep the run history, attestation and waivers.
fn receipt_dir(runs: &Path, contract: &Contract, repo_id: &str, head: &str) -> Option<PathBuf> {
    let entries = std::fs::read_dir(runs).ok()?;
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in entries.flatten() {
        let report_path = entry.path().join("report.json");
        let Ok(raw) = std::fs::read_to_string(&report_path) else {
            continue;
        };
        let Ok(report) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if report["review_head"].as_str() != Some(head)
            || report["repo"].as_str() != Some(repo_id)
            || report["review_items"] != json!(contract.domains)
            || !crate::seal::valid(&report)
        {
            continue;
        }
        let mtime = std::fs::metadata(&report_path)
            .and_then(|metadata| metadata.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        if newest.as_ref().is_none_or(|(at, _)| mtime > *at) {
            newest = Some((mtime, entry.path()));
        }
    }
    newest.map(|(_, path)| path)
}

/// An unfinished run of exactly this target under this runtime, waiting to
/// continue. resume.json is the lookup key; scope.json cannot serve because
/// it is removed when a run ends.
fn resume_dir(runs: &Path, key: &Value) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(runs)
        .ok()?
        .flatten()
        .map(|entry| entry.path().join("resume.json"))
        .filter(|path| path.is_file())
        .collect();
    candidates.sort();
    for path in candidates {
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(candidate) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        if candidate == *key && unfinished_run(path.parent().unwrap()) {
            return Some(path.parent().unwrap().to_path_buf());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// the audit review process
// ---------------------------------------------------------------------------

/// Drive one review through the A4AA-backed audit runner: the agent owns
/// only the conversation, this runtime owns the tools, the evidence and the
/// receipt. Returns (usage, duration_ms, profile identity). No wall-clock
/// kill, no second reviewer.
fn agent_review(
    run_dir: &Path,
    settings: &Settings,
    runtime: &Map<String, Value>,
    contract: &Contract,
) -> Result<(Value, u128, Value), String> {
    let runner = settings
        .agent_runner
        .clone()
        .filter(|runner| !runner.is_empty())
        .or_else(|| {
            std::env::var_os("PATH").and_then(|path| {
                std::env::split_paths(&path)
                    .map(|dir| dir.join("probator-agent"))
                    .find(|candidate| candidate.is_file())
                    .map(|candidate| candidate.to_string_lossy().into_owned())
            })
        })
        .ok_or("The A4AA audit runner is not installed; update the checker installation")?;
    let completion_path = run_dir.join("completion.json");
    let saved: Option<Value> = std::fs::read_to_string(&completion_path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok());
    let cached = saved.as_ref().is_some_and(|saved| {
        saved["completed"] == true
            && saved["runtime"] == Value::Object(runtime.clone())
            && saved.get("checker_binding").unwrap_or(&Value::Null) == &settings.checker_binding
            && saved["outcome"].is_object()
    });
    let (outcome, returncode, duration_ms) = if let Some(saved) = saved.filter(|_| cached) {
        (
            saved["outcome"].clone(),
            0,
            saved["duration_ms"].as_u64().unwrap_or(0) as u128,
        )
    } else {
        // The runner owns the conversation: fire the task with the contract
        // and the run directory, inherit the operator's environment
        // verbatim, and read back the settled outcome on stdout.
        let started = std::time::Instant::now();
        let result = Command::new(&runner)
            .arg("--contract")
            .arg(contract.dir.join("contract.json"))
            .arg("--run")
            .arg(run_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .current_dir(run_dir)
            .output()
            .map_err(|error| format!("The A4AA audit runner could not start: {error}"))?;
        let duration_ms = started.elapsed().as_millis();
        let outcome = serde_json::from_str::<Value>(&String::from_utf8_lossy(&result.stdout))
            .unwrap_or(Value::Null);
        (outcome, result.status.code().unwrap_or(1), duration_ms)
    };
    let usage = &outcome["usage"];
    let valid_usage = [
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
    ]
    .iter()
    .all(|key| usage[key].as_u64().is_some());
    let identity = role_identity(settings, contract);
    let selected = &outcome["profile"];
    let valid_profile = ["id", "revision"]
        .iter()
        .all(|key| selected[key] == identity[key])
        && selected["principal"].is_string();
    let settled = outcome["completed"] == true && valid_usage && valid_profile;
    let has_report = run_dir.join("report.json").exists();
    evidence::write_json(
        &completion_path,
        &json!({
            "completed": settled && has_report && returncode == 0,
            "has_report": has_report,
            "runtime": runtime,
            "checker_binding": settings.checker_binding,
            "duration_ms": duration_ms as u64,
            "outcome": {
                "completed": outcome["completed"],
                "usage": outcome["usage"],
                "profile": outcome["profile"],
                "served": outcome["served"],
                "failure": outcome["failure"],
            },
            "failure_reason": if settled && has_report && returncode == 0 {
                Value::Null
            } else {
                json!("A4AA audit review did not complete")
            },
        }),
    )?;
    if returncode != 0 || !settled || !has_report {
        return Err(
            "The audit agent did not complete a valid review; publication refused".to_string(),
        );
    }
    Ok((outcome["usage"].clone(), duration_ms, selected.clone()))
}

// ---------------------------------------------------------------------------
// one target, then the gate
// ---------------------------------------------------------------------------

/// The per-hit detail lines under a refused stage-one report.
fn stage1_lines(contract: &Contract, summary: &stage1::Summary) -> Vec<String> {
    if contract
        .stage1
        .as_ref()
        .is_some_and(|stage1| stage1.surfaces)
    {
        let mut lines: Vec<String> = summary
            .hits
            .iter()
            .map(|hit| {
                format!(
                    "{}:{} {} → {}",
                    hit.path,
                    hit.line,
                    hit.rule,
                    hit.remedy.unwrap_or("")
                )
            })
            .collect();
        if let Some(surfaces) = &summary.surfaces {
            lines.extend(surfaces.iter().map(|surface| {
                format!("notice {}:{} {}", surface.path, surface.line, surface.rule)
            }));
        }
        return lines;
    }
    summary
        .hits
        .iter()
        .map(|hit| {
            let suffix = if hit.line > 0 {
                format!(":{}", hit.line)
            } else {
                String::new()
            };
            format!("{}{} {}", hit.path, suffix, hit.rule)
        })
        .collect()
}

/// The waiver note when certified rulings flip a non-pass outcome to a
/// pass, or None while any blocking finding still stands. A verdict-level
/// ruling accepts the whole outcome; finding-level rulings accept it only
/// once every blocking finding is covered. `waived` holds the indexes of
/// the findings the ledger overruled.
fn waiver_note(report: &Value, waived: &[usize], verdict_waived: bool) -> Option<Vec<String>> {
    let standing = report["findings"]
        .as_array()
        .map(|findings| {
            findings
                .iter()
                .enumerate()
                .filter(|(index, finding)| {
                    finding["severity"].as_str() == Some("blocking") && !waived.contains(index)
                })
                .count()
        })
        .unwrap_or(0);
    if !(verdict_waived || (standing == 0 && !waived.is_empty())) {
        return None;
    }
    Some(
        waived
            .iter()
            .map(|index| {
                let finding = &report["findings"][*index];
                format!(
                    "{}:{}",
                    finding["file"].as_str().unwrap_or(""),
                    finding["line"].as_u64().unwrap_or(0)
                )
            })
            .collect(),
    )
}

/// Whether the audit's outcome stands: a pass verdict carries no blocking
/// findings — fresh or inherited from the coverage ledger — or every
/// blocking finding is overruled by a signature-verified operator ruling.
/// The sealed report keeps the checker's own verdict; the waiver record
/// lands beside it so run history shows which operator decision stood in
/// for a fix. `run_dir` is None when the ledger replayed a settled receipt
/// that has not changed.
fn outcome(
    report: &Value,
    contract: &Contract,
    repo_id: &str,
    head: &str,
    run_dir: Option<&Path>,
) -> Result<i32, String> {
    let merged = standing_report(report);
    let blocking = merged["findings"]
        .as_array()
        .map(|findings| {
            findings
                .iter()
                .filter(|finding| finding["severity"].as_str() == Some("blocking"))
                .count()
        })
        .unwrap_or(0);
    if report["verdict"].as_str() == Some("pass") && blocking == 0 {
        return Ok(0);
    }
    // The repository slug a ruling binds to: the identity's remote slug, or
    // empty for a path-identified local tree (the same value the ledger
    // reader always used).
    let slug = repo_id.strip_prefix("local:").map_or(repo_id, |_| "");
    let (waived, verdict_waived) = crate::objection::waivers(&merged, &contract.name, slug, head);
    let Some(note) = waiver_note(&merged, &waived, verdict_waived) else {
        return Ok(1);
    };
    if let Some(dir) = run_dir {
        evidence::write_json(
            &dir.join("waivers.json"),
            &json!({
                "objection_waived": note,
                "verdict_waived": verdict_waived,
                "ledger": crate::objection::ledger_path(),
            }),
        )?;
    }
    println!(
        "{}: outcome waived by signed operator ruling{}",
        contract.title,
        if note.is_empty() {
            String::new()
        } else {
            format!(" — waived findings: {}", note.join(", "))
        }
    );
    Ok(0)
}

/// Run one review of one resolved target. Returns the exit code.
#[allow(clippy::too_many_arguments)]
fn review_target(
    repo: &str,
    settings: &Settings,
    target: &stage1::Target,
    base: Option<&str>,
    cursor: Option<&Cursor>,
    repo_id: &str,
    summary: Option<&stage1::Summary>,
    summaries: &[stage1::Summary],
    runtime: &Map<String, Value>,
    contract: &Contract,
) -> Result<i32, String> {
    let tree = {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["rev-parse", &format!("{}^{{tree}}", target.head)])
            .output()
            .map_err(|error| format!("Git could not read the review snapshot: {error}"))?;
        if !output.status.success() {
            return Err("Git could not read the review snapshot".to_string());
        }
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    };
    // With a review base the range's own diff is the whole review surface —
    // content at or below it was published or already covered by the cursor;
    // only a base-less target inventories the whole tree.
    let changed = match base {
        Some(base) => stage1::outgoing_paths_range(repo, Some(base), &target.head)?,
        None => stage1::outgoing_paths_snapshot(repo, &tree)?,
    };
    // A whole-tree target re-opens every path; a ranged target only re-opens
    // the lines its own hunks rewrote. The distinction keeps a blocker alive
    // when an unrelated line in the same file changed.
    let touched = match base {
        Some(base) => changed_lines_range(repo, base, &target.head)?,
        None => ChangedLines::whole(&changed),
    };
    // Carried findings were recorded against the cursor's head, which can be
    // older than this range's own base. Compare and rebase them against the
    // diff from that head so their coordinates and their re-open test agree.
    let carry = match cursor {
        Some(cursor) if base != Some(cursor.head.as_str()) => {
            changed_lines_range(repo, &cursor.head, &target.head)?
        }
        _ => touched.clone(),
    };
    // A path the tool surface refuses is a review that can never complete.
    // Refuse it before the review costs a token - naming the path, never its
    // content.
    for path in &changed {
        if evidence::safe_path(path).is_err() {
            return Err(format!(
                "The snapshot contains '{path}', a path the review contract excludes; \
                 no review could ever pass it, so the publication is refused locally"
            ));
        }
    }
    let runs = settings.profile.join(format!("{}-runs", contract.name));
    std::fs::create_dir_all(&runs).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&runs, std::fs::Permissions::from_mode(0o700));
    }
    let identity = role_identity(settings, contract);
    let resume_key = json!({
        "base": base,
        "head": target.head,
        "items": contract.domains,
        "agent_profile": identity,
        "checker_binding": settings.checker_binding,
        "harness": runtime["harness"],
        "provider": runtime["provider"],
        "model": runtime["model"],
        "effort": runtime.get("effort").cloned().unwrap_or(Value::Null),
    });
    let run_dir = match resume_dir(&runs, &resume_key) {
        Some(existing) => existing,
        None => {
            let created = runs.join(format!(
                "review-{}-{:04x}",
                std::process::id(),
                rand_suffix()
            ));
            std::fs::create_dir_all(&created).map_err(|error| error.to_string())?;
            evidence::write_json(&created.join("resume.json"), &resume_key)?;
            created
        }
    };
    // The conceal sweep skips directories whose `live` pid is still running;
    // a resumed directory gets its marker refreshed either way.
    let _ = std::fs::write(run_dir.join("live"), std::process::id().to_string());
    // The scope the evidence server reads; kind and surfaces ride along for
    // the checkers whose contracts carry them.
    let mut scope = json!({
        "repo": repo,
        "tree": tree,
        "base": base,
        "changed": changed.clone(),
        "runtime": runtime,
    });
    if let Some(cursor) = cursor {
        scope["coverage_cursor"] = json!(cursor.head);
    }
    if contract.stage1.is_some() {
        scope["kind"] = json!(target.kind);
        if contract
            .stage1
            .as_ref()
            .is_some_and(|stage1| stage1.surfaces)
        {
            let surfaces: Vec<Value> = summary
                .and_then(|summary| summary.surfaces.as_ref())
                .map(|surfaces| {
                    surfaces
                        .iter()
                        .map(|surface| {
                            json!({"path": surface.path, "line": surface.line, "rule": surface.rule})
                        })
                        .collect()
                })
                .unwrap_or_default();
            scope["surfaces"] = json!(surfaces);
        }
    }
    evidence::write_json(&run_dir.join("scope.json"), &scope)?;
    // The run's verdict credential: minted (or reused after an unfinished
    // attempt) before the reviewer starts, held here for the receipt check
    // and consumed once a verdict seals it.
    let key = credential::issue(&run_dir)?;
    let result = (|| -> Result<i32, String> {
        println!(
            "{}: reviewing {} with {}/{} ({})…",
            contract.title,
            target.label,
            runtime["provider"].as_str().unwrap_or(""),
            runtime["model"].as_str().unwrap_or(""),
            runtime
                .get("effort")
                .and_then(|v| v.as_str())
                .unwrap_or("default"),
        );
        let (usage, duration_ms, identity) = agent_review(&run_dir, settings, runtime, contract)?;
        let report_path = run_dir.join("report.json");
        let mut report: Value = serde_json::from_str(
            &std::fs::read_to_string(&report_path).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        // The verdict must carry this run's signature: a receipt that never
        // went through the review server's submit channel - hand-written,
        // replayed from another run, or left by a crashed attempt - is not a
        // review at all.
        if !credential::verify(&key, &report) {
            return Err(
                "the audit report carries no valid verdict credential; publication refused"
                    .to_string(),
            );
        }
        // The run record's optional signature marker participates in the
        // seal: an empty value is omitted before sealing, exactly as records
        // written before the field existed omit it. Normalizing after the
        // credential check keeps the credential's own bytes untouched.
        report = crate::records::normalize(report);
        if let Some(reference) = &target.ref_ {
            let moved = Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(["rev-parse", "--verify", &format!("{reference}^{{commit}}")])
                .output()
                .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
                .unwrap_or_default();
            if moved != target.head {
                return Err("The pushed ref moved during review; publication refused".to_string());
            }
        }
        // Blocking findings the coverage ledger holds on content this range
        // did not re-open keep standing — the evidence was never revisited,
        // so the recorded defect is still live. They join this receipt
        // before it seals, so the ledger and the receipt tell one story.
        let carried = carried_blockers(cursor, &carry);
        report["carried_findings"] = json!(carried);
        // The receipt's standing result, not the checker's bare verdict: a
        // pass that still stands on blocking findings — fresh or carried —
        // is a refusal, so the reuse path never waves it through and the
        // next cursor inherits the same blockers.
        let standing = report["findings"]
            .as_array()
            .map(|findings| {
                findings
                    .iter()
                    .filter(|finding| finding["severity"].as_str() == Some("blocking"))
                    .count()
            })
            .unwrap_or(0)
            + report["carried_findings"].as_array().map_or(0, Vec::len);
        report["gate_status"] = json!(if report["verdict"] == "pass" && standing == 0 {
            "passed"
        } else {
            "refused"
        });
        report["review_usage"] = json!({"tokens": usage, "duration_ms": duration_ms as u64});
        report["agent_profile"] = identity;
        report["checker_binding"] = settings.checker_binding.clone();
        report["review_base"] = json!(base);
        report["review_head"] = json!(target.head);
        report["repo"] = json!(repo_id);
        report["review_kind"] = json!(target.kind);
        // What this pass answered, so a later run under a wider contract does
        // not reuse it (see `audited`).
        report["review_items"] = json!(contract.domains);
        report["stage1"] =
            json!({"ranges": summaries.iter().map(stage1::Summary::to_json).collect::<Vec<_>>()});
        if !target.fallback.is_empty() {
            report["fallback"] = json!(target.fallback);
        }
        // Seal the receipt into the run history's chain: `audited` reuses a
        // receipt only when the seal recomputes, so a hand-written
        // `report.json` must at least join the chain honestly - and a receipt
        // deleted from the middle leaves a dangling `seal_prev` an operator
        // can see. Tamper-evidence, not tamper-proofing: the unforgeable
        // attestation is the `probator/audited` status the push hook posts.
        let seal_prev = crate::seal::latest(&runs, "report.json", Some(&run_dir));
        report["seal_prev"] = json!(seal_prev);
        report["seal"] = json!(crate::seal::seal(&seal_prev, &report));
        evidence::write_json(&report_path, &report)?;
        // The verdict is finalized on disk; its credential is spent. Doing
        // this only now keeps an unfinalized attempt resumable under the
        // same key.
        credential::consume(&run_dir);
        // The coverage ledger moves with the receipt it just sealed: a
        // complete judgement parks at this head with the blocking findings
        // still standing — fresh ones plus the ones the range never opened.
        let standing = standing_findings(&report);
        let reviewer = runtime_identity(settings, contract, runtime);
        cursor_advance(
            profiles_root(settings),
            contract,
            &reviewer,
            repo_id,
            &target.head,
            report["verdict"].as_str().unwrap_or(""),
            standing,
        );
        println!(
            "{}: {} — {}",
            contract.title,
            report["verdict"].as_str().unwrap_or(""),
            sanitize(report["summary"].as_str().unwrap_or(""))
        );
        if let Some(findings) = report["findings"].as_array() {
            for finding in findings {
                println!(
                    "  {}:{} [{}] {} → {}",
                    sanitize(finding["file"].as_str().unwrap_or("")),
                    finding["line"].as_i64().unwrap_or(0),
                    finding["severity"].as_str().unwrap_or(""),
                    sanitize(finding["impact"].as_str().unwrap_or("")),
                    sanitize(finding["remedy"].as_str().unwrap_or("")),
                );
            }
        }
        println!("{} report: {}", contract.title, report_path.display());
        let carried_count = report["carried_findings"].as_array().map_or(0, Vec::len);
        if carried_count > 0 {
            evidence::write_json(
                &run_dir.join("carried.json"),
                &json!({
                    "cursor": cursor.map(|entry| json!(entry.head)).unwrap_or(Value::Null),
                    "findings": report["carried_findings"],
                }),
            )?;
            println!(
                "{}: {} blocking finding(s) carried from the previous covered head",
                contract.title, carried_count
            );
        }
        // Operator-ruled objections: only rulings in a signature-verified
        // ledger waive anything. The sealed report keeps the checker's own
        // verdict; the waiver record lands beside it so the run history
        // shows exactly which operator decision stood in for a fix.
        outcome(&report, contract, repo_id, &target.head, Some(&run_dir))
    })();
    let _ = std::fs::remove_file(run_dir.join("scope.json"));
    // A run that never finalized its receipt is refused, never pending.
    // The reworded receipt is re-signed only when it was authentic to begin
    // with — re-signing an unverifiable receipt would launder a forged
    // report into a signature a resume would accept.
    if let Ok(raw) = std::fs::read_to_string(run_dir.join("report.json"))
        && let Ok(mut receipt) = serde_json::from_str::<Value>(&raw)
        && receipt["gate_status"] == "pending"
    {
        let authentic = credential::verify(&key, &receipt);
        receipt["gate_status"] = json!("refused");
        if authentic {
            receipt["receipt_mac"] = json!(credential::mac(&key, &receipt));
        }
        let _ = evidence::write_json(&run_dir.join("report.json"), &receipt);
    }
    result
}

fn rand_suffix() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos % 0xffff) as u16
}

/// The checker entry point. Refuses on the first stage that finds a problem;
/// a refused audit never touches the working tree.
pub fn run(repo: &str, contract_path: &Path) -> Result<i32, String> {
    let contract = contract::load(contract_path)?;
    let settings = load_settings(contract.dir.as_path(), &contract.name)?;
    assert_synced(&settings, contract.dir.as_path())?;
    let runtime = declared_runtime(&settings)?;
    let runs = settings.profile.join(format!("{}-runs", contract.name));
    let result = review_gate(repo, &contract, &settings, &runtime);
    for entry in std::fs::read_dir(&runs).into_iter().flatten().flatten() {
        let marker = entry.path().join("live");
        if std::fs::read_to_string(&marker)
            .ok()
            .and_then(|pid| pid.trim().parse::<u32>().ok())
            == Some(std::process::id())
        {
            let _ = std::fs::remove_file(&marker);
        }
    }
    // Housekeeping follows the audit, never precedes it: a recorded session
    // is concealed only once its run has finished — flagging a conversation
    // while its agent is still prompting breaks the turn. The sweep covers
    // every checker's runs root, since a checker skipped by an earlier
    // phase's refusal never reaches its own sweep. It must also precede
    // pruning, since a removed run directory takes its session id evidence
    // with it.
    if let Some(profiles) = settings.profile.parent() {
        crate::conceal::run_sessions(profiles);
    }
    prune_runs(&runs);
    result
}

fn review_gate(
    repo: &str,
    contract: &Contract,
    settings: &Settings,
    runtime: &Map<String, Value>,
) -> Result<i32, String> {
    let targets = ranges::ranges(repo)?;
    if targets.is_empty() {
        println!(
            "{}: nothing unpublished in this operation; no review needed",
            contract.title
        );
        return Ok(0);
    }
    let mut summaries = Vec::new();
    if let Some(stage1_contract) = &contract.stage1 {
        let opts = stage1::Opts {
            withheld_path: None,
        };
        let (ok, found) = stage1::audit_all(
            repo,
            &targets,
            &stage1_contract.rules,
            &opts,
            stage1_contract.surfaces,
        )?;
        let stage_label = stage1_contract.label.as_deref().unwrap_or("deterministic");
        for summary in &found {
            let state = if summary.refused.is_empty() {
                summary.status.clone()
            } else {
                format!("refused: {}", summary.refused)
            };
            let surfaces = summary
                .surfaces
                .as_ref()
                .map(|surfaces| format!(", surfaces={}", surfaces.len()))
                .unwrap_or_default();
            println!(
                "{}: {} {} — {} ({}, findings={}{})",
                contract.title,
                stage_label,
                state,
                summary.label,
                summary.scope,
                summary.hits.len(),
                surfaces,
            );
            for line in stage1_lines(contract, summary) {
                println!("  {line}");
            }
        }
        summaries = found;
        if !ok {
            return Err(stage1_contract.refusal.clone().unwrap_or_else(|| {
                "The deterministic audit refused this operation; nothing was published".to_string()
            }));
        }
    }
    let repo_id = repo_identity(repo);
    let reviewer = runtime_identity(settings, contract, runtime);
    let runs = settings.profile.join(format!("{}-runs", contract.name));
    for (index, target) in targets.iter().enumerate() {
        // The coverage ledger: this checker's newest complete judgement on
        // this head's ancestry line for this reviewer identity. Content at
        // or below it — or at or below the target's own base — is never
        // reviewed twice.
        let cursor = cursor_entry(profiles_root(settings), contract, &repo_id, &reviewer)
            .filter(|entry| ancestor_of(repo, &entry.head, &target.head));
        // The identical head already carries this checker's judgement; the
        // ledger's outcome stands as-is — a signed ruling may still waive it.
        if let Some(entry) = &cursor
            && entry.head == target.head
        {
            if entry.verdict == "pass" && entry.findings.is_empty() {
                println!(
                    "{}: {} already passed its semantic review ({}); reusing that verdict",
                    contract.title,
                    target.label,
                    &target.head[..12.min(target.head.len())],
                );
                continue;
            }
            println!(
                "{}: {} was already refused at {}; the sealed verdict stands",
                contract.title,
                target.label,
                &target.head[..12.min(target.head.len())],
            );
            let replay = json!({
                "verdict": entry.verdict,
                "findings": entry.findings,
            });
            // The waiver record belongs beside the receipt that established
            // the standing refusal, not in a fresh run.
            let dir = receipt_dir(&runs, contract, &repo_id, &target.head);
            return outcome(&replay, contract, &repo_id, &target.head, dir.as_deref());
        }
        let base = effective_base(
            repo,
            target.base.as_deref(),
            cursor.as_ref().map(|entry| entry.head.as_str()),
        );
        if cursor.is_some() && base.as_deref() != target.base.as_deref() {
            let head = cursor
                .as_ref()
                .map(|entry| entry.head.as_str())
                .unwrap_or_default();
            println!(
                "{}: {} reviews the increment since {} ({} paths)",
                contract.title,
                target.label,
                &head[..12.min(head.len())],
                stage1::outgoing_paths_range(repo, base.as_deref(), &target.head)
                    .map(|paths| paths.len())
                    .unwrap_or(0),
            );
        }
        if let Some(receipt) = audited(settings, contract, base.as_deref(), &target.head, runtime) {
            println!(
                "{}: {} already passed its semantic review ({}); reusing that verdict",
                contract.title,
                target.label,
                &target.head[..12.min(target.head.len())],
            );
            // The receipt proves a complete pass even when the ledger was
            // lost or tampered with: adopt the judgement so the next range
            // starts at this head instead of re-reading covered content.
            cursor_advance(
                profiles_root(settings),
                contract,
                &reviewer,
                &repo_id,
                &target.head,
                receipt["verdict"].as_str().unwrap_or("pass"),
                Vec::new(),
            );
            continue;
        }
        let summary = summaries.get(index);
        if review_target(
            repo,
            settings,
            target,
            base.as_deref(),
            cursor.as_ref(),
            &repo_id,
            summary,
            &summaries,
            runtime,
            contract,
        )? != 0
        {
            return Ok(1);
        }
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// the full-audit lifecycle
// ---------------------------------------------------------------------------

/// Build a full-service run directory: the sanitized snapshot, the original
/// request, the scope and the bare object store the evidence server reads.
pub fn build_snapshot_dir(
    contract: &Contract,
    manifest_path: &Path,
    request_path: &Path,
    output: &Path,
) -> Result<(), String> {
    let selected: Value = serde_json::from_str(
        &std::fs::read_to_string(manifest_path).map_err(|e| format!("manifest: {e}"))?,
    )
    .map_err(|e| format!("manifest: {e}"))?;
    let projects = selected["projects"]
        .as_object()
        .ok_or("manifest: expected a projects object")?;
    let reuse = selected["reuse"].as_object();
    let snapshot = fullservice::snapshot_projects(contract, projects, reuse)?;
    std::fs::create_dir_all(output).map_err(|e| format!("output: {e}"))?;
    evidence::write_json(&output.join("snapshot.json"), &snapshot)?;
    let request: Value = serde_json::from_str(
        &std::fs::read_to_string(request_path).map_err(|e| format!("request: {e}"))?,
    )
    .map_err(|e| format!("request: {e}"))?;
    evidence::write_json(&output.join("request.json"), &request)?;
    let objects = output.join("objects.git");
    let init = Command::new("git")
        .args(["init", "--bare", "-q"])
        .arg(&objects)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !init.status.success() {
        return Err("git: could not create the run's object store".to_string());
    }
    let tree = Command::new("git")
        .arg("-C")
        .arg(&objects)
        .args(["hash-object", "-t", "tree", "--stdin", "-w"])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("git: {e}"))?;
    let tree = String::from_utf8_lossy(&tree.stdout).trim().to_string();
    evidence::write_json(
        &output.join("scope.json"),
        &json!({
            "mode": "full-service",
            "repo": objects.to_string_lossy(),
            "tree": tree,
            "base": tree,
            "changed": [],
        }),
    )?;
    Ok(())
}

/// Snapshot the selected projects and run one full audit over them.
pub fn start_full_audit(
    contract_path: &Path,
    manifest_path: &Path,
    request_path: &Path,
    output: &Path,
) -> Result<i32, String> {
    let contract = contract::load(contract_path)?;
    if !contract.tools.full_service {
        return Err("This contract offers no full-service mode".to_string());
    }
    if output.exists() {
        return Err("The output directory must not already exist".to_string());
    }
    build_snapshot_dir(&contract, manifest_path, request_path, output)?;
    resume_full_audit(contract_path, output)
}

/// Continue or finalize an existing full-audit directory.
pub fn resume_full_audit(contract_path: &Path, output: &Path) -> Result<i32, String> {
    let contract = contract::load(contract_path)?;
    if !contract.tools.full_service {
        return Err("This contract offers no full-service mode".to_string());
    }
    let output = output
        .canonicalize()
        .map_err(|error| format!("output: {error}"))?;
    if output.join("report.json").exists() {
        return Err("An existing submitted report must not be re-audited".to_string());
    }
    let snapshot: Value = serde_json::from_str(
        &std::fs::read_to_string(output.join("snapshot.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let status_path = output.join("status.json");
    if let Ok(raw) = std::fs::read_to_string(&status_path) {
        let previous: Value = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        if previous["state"] == "running" {
            return Err(
                "Review is already marked running; inspect the owning process first".to_string(),
            );
        }
        let history_path = output.join("attempts.json");
        let mut attempts: Vec<Value> = std::fs::read_to_string(&history_path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();
        attempts.push(previous);
        evidence::write_json(&history_path, &json!(attempts))?;
    }
    let settings = load_settings(contract.dir.as_path(), &contract.name)?;
    assert_synced(&settings, contract.dir.as_path())?;
    let runtime = declared_runtime(&settings)?;
    // Keep the declared runtime in the scope so the receipt labels the engine
    // that actually produced the verdict, even on a resumed directory.
    let scope_path = output.join("scope.json");
    let mut scope: Value =
        serde_json::from_str(&std::fs::read_to_string(&scope_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    scope["runtime"] = Value::Object(runtime.clone());
    evidence::write_json(&scope_path, &scope)?;
    evidence::write_json(
        &status_path,
        &json!({
            "state": "running",
            "projects": snapshot["projects"].as_object().map(|p| p.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
            "files": snapshot["files"].as_object().map(|f| f.len()).unwrap_or_default(),
        }),
    )?;
    // Same one-shot credential the gate path issues: the full audit's
    // verdict is signed by the session that produced it and the key dies
    // with it.
    let key = credential::issue(&output)?;
    match agent_review(&output, &settings, &runtime, &contract) {
        Err(error) => {
            evidence::write_json(
                &status_path,
                &json!({"state": "failed", "report_exists": output.join("report.json").exists()}),
            )?;
            eprintln!("{} full audit failed: {}", contract.title, sanitize(&error));
            Ok(1)
        }
        Ok((usage, duration_ms, identity)) => {
            let report_path = output.join("report.json");
            let mut report: Value = serde_json::from_str(
                &std::fs::read_to_string(&report_path).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            if !credential::verify(&key, &report) {
                evidence::write_json(
                    &status_path,
                    &json!({"state": "failed", "report_exists": true}),
                )?;
                return Err("the audit report carries no valid verdict credential".to_string());
            }
            // Same record rule as the gate path: an empty policy signature is
            // absent, never written back as "". The credential was checked
            // against the bytes the server wrote, before this normalization.
            report = crate::records::normalize(report);
            report["gate_status"] = json!("full-audit-complete");
            report["review_usage"] = json!({"tokens": usage, "duration_ms": duration_ms as u64});
            report["agent_profile"] = identity;
            report["checker_binding"] = settings.checker_binding.clone();
            evidence::write_json(&report_path, &report)?;
            credential::consume(&output);
            evidence::write_json(
                &status_path,
                &json!({"state": "completed", "report_exists": true}),
            )?;
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ChangedLines, Cursor, Hunk, Settings, audited, carried_blockers,
        checker_binding_identity_from, cursor_advance, cursor_entry, cursor_file, cursor_key,
        parse_changed_lines, runtime_identity, standing_report, waiver_note,
    };
    use crate::contract::Contract;
    use serde_json::{Map, Value, json};
    use std::path::PathBuf;

    const REVIEWER: &str = "reviewer-a";

    fn report(findings: serde_json::Value) -> serde_json::Value {
        json!({"verdict": "fail", "findings": findings})
    }

    fn blocking(file: &str, line: u64) -> serde_json::Value {
        json!({"severity": "blocking", "file": file, "line": line, "evidence": "e"})
    }

    fn sample_contract() -> Contract {
        serde_json::from_value(json!({
            "name": "sample-gate",
            "title": "Sample Gate",
            "domains": ["structure"],
            "finding_keys": ["file", "line", "severity", "evidence"],
            "on": ["pre-push"],
            "tools": {
                "name_prefix": "sample",
                "context": ["inventory", "list", "diff", "read", "find"],
                "submit": true,
                "descriptions": {
                    "context": "Inspect the range.",
                    "submit": "Submit the verdict."
                }
            },
            "task": "Review the change and submit."
        }))
        .unwrap()
    }

    /// A scratch profile directory; the cursor ledger lives under it.
    fn scratch_profile(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "probator-engine-{tag}-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn settings_with_binding(profile: PathBuf, binding: Value) -> Settings {
        Settings {
            agent_runner: None,
            profile,
            skill_dir: PathBuf::from("/tmp/probator-skill"),
            synced: Some(json!({"tag": "profile/sample-gate/v1"})),
            payload: Map::new(),
            checker_binding: binding,
        }
    }

    fn sample_runtime() -> Map<String, Value> {
        serde_json::from_value(json!({
            "harness": "pi",
            "provider": "openai",
            "model": "openai/gpt-6-luna"
        }))
        .unwrap()
    }

    #[test]
    fn a_changed_checker_binding_is_a_changed_reviewer() {
        let registry = json!({
            "agents": {
                "pi": {"id": "pi", "lane": "rpc",
                       "command": {"program": "pi", "args": ["--mode", "rpc"]}}
            },
            "profiles": {
                "sample-gate": {"agent": "pi", "model": "openai/gpt-6-luna"}
            },
            "bindings": {
                "sample-gate": {"profile": "sample-gate"}
            }
        });
        let first = checker_binding_identity_from(&registry, "sample-gate");
        assert!(first.is_object(), "{first}");
        let mut other = registry.clone();
        other["profiles"]["sample-gate"]["model"] = json!("openai/gpt-6.1-sol");
        let second = checker_binding_identity_from(&other, "sample-gate");
        assert_ne!(
            first, second,
            "a different binding profile is a different reviewer"
        );
        assert_eq!(
            checker_binding_identity_from(&json!({}), "sample-gate"),
            Value::Null
        );

        let contract = sample_contract();
        let runtime = sample_runtime();
        let profile = scratch_profile("binding-id");
        let settings_a = settings_with_binding(profile.clone(), first);
        let settings_b = settings_with_binding(profile.clone(), second);
        assert_ne!(
            runtime_identity(&settings_a, &contract, &runtime),
            runtime_identity(&settings_b, &contract, &runtime)
        );
        let _ = std::fs::remove_dir_all(profile);
    }

    #[test]
    fn a_changed_session_protocol_is_a_changed_reviewer() {
        let mut registry = json!({
            "agents": {
                "pi": {
                    "id": "pi", "lane": "rpc",
                    "command": {"program": "pi", "args": ["--mode", "rpc"]},
                    "sessionOpen": {"method": "get_state", "params": {}},
                    "sessionResume": {
                        "method": "switch_session",
                        "params": {"sessionPath": "{sessionId}"}
                    },
                    "prompt": {
                        "method": "prompt",
                        "params": {"message": "{prompt}"}
                    },
                    "passthrough": ["get_state"]
                }
            },
            "profiles": {
                "sample-gate": {"agent": "pi", "model": "openai/gpt-6-luna"}
            },
            "bindings": {
                "sample-gate": {"profile": "sample-gate"}
            }
        });
        let first = checker_binding_identity_from(&registry, "sample-gate");
        assert!(first.is_object(), "{first}");
        let mut changed_open = registry.clone();
        changed_open["agents"]["pi"]["sessionOpen"]["method"] = json!("open_session");
        assert_ne!(
            first,
            checker_binding_identity_from(&changed_open, "sample-gate"),
            "a changed session-open protocol is a different reviewer"
        );
        let mut changed_prompt = registry.clone();
        changed_prompt["agents"]["pi"]["prompt"]["params"]["message"] = json!("{review}");
        assert_ne!(
            first,
            checker_binding_identity_from(&changed_prompt, "sample-gate"),
            "a changed prompt mapping is a different reviewer"
        );
        let mut changed_resume = registry.clone();
        changed_resume["agents"]["pi"]["sessionResume"]["method"] = json!("resume_session");
        assert_ne!(
            first,
            checker_binding_identity_from(&changed_resume, "sample-gate"),
            "a changed resume protocol is a different reviewer"
        );
        let mut changed_instructions = registry.clone();
        changed_instructions["profiles"]["sample-gate"]["instructions"] =
            json!("Review only the synthetic fixture.");
        assert_ne!(
            first,
            checker_binding_identity_from(&changed_instructions, "sample-gate"),
            "changed persona text is a different reviewer"
        );
        let mut changed_instruction_mode = registry.clone();
        changed_instruction_mode["profiles"]["sample-gate"]["instructionMode"] =
            json!("every-turn");
        assert_ne!(
            first,
            checker_binding_identity_from(&changed_instruction_mode, "sample-gate"),
            "a changed instruction schedule is a different reviewer"
        );
        // The binding's own prompt remains part of the identity too.
        registry["bindings"]["sample-gate"] = json!({
            "profile": "sample-gate",
            "prompt": "Binding context."
        });
        assert_ne!(
            first,
            checker_binding_identity_from(&registry, "sample-gate"),
            "a changed binding prompt is a different reviewer"
        );
    }

    #[test]
    fn the_short_binding_form_names_the_same_reviewer_as_the_object_form() {
        let mut registry = json!({
            "agents": {
                "pi": {"id": "pi", "lane": "rpc",
                       "command": {"program": "pi", "args": ["--mode", "rpc"]}}
            },
            "profiles": {
                "sample-gate": {"agent": "pi", "model": "openai/gpt-6-luna"},
                "sample-gate-deep": {"agent": "pi", "model": "openai/gpt-6.1-sol"},
                "other-gate": {"agent": "pi", "model": "openai/gpt-6-luna"}
            },
            "bindings": {"sample-gate": "sample-gate"}
        });
        let short = checker_binding_identity_from(&registry, "sample-gate");
        assert!(short.is_object(), "{short}");

        registry["bindings"]["sample-gate"] = json!({"profile": "sample-gate"});
        assert_eq!(
            short,
            checker_binding_identity_from(&registry, "sample-gate"),
            "the short and object binding forms normalize to one identity"
        );

        registry["bindings"]["sample-gate"] = json!({
            "profile": "sample-gate",
            "fallbacks": [{"profile": "sample-gate-deep"}]
        });
        let object_fallback = checker_binding_identity_from(&registry, "sample-gate");
        registry["bindings"]["sample-gate"] = json!({
            "profile": "sample-gate",
            "fallbacks": ["sample-gate-deep"]
        });
        assert_eq!(
            object_fallback,
            checker_binding_identity_from(&registry, "sample-gate"),
            "fallback entries normalize across their string and object forms"
        );

        registry["bindings"]["sample-gate"] = json!("sample-gate");
        registry["profiles"]["sample-gate"]["model"] = json!("openai/gpt-6.1-sol");
        let changed = checker_binding_identity_from(&registry, "sample-gate");
        assert_ne!(
            short, changed,
            "changing the short binding's profile changes the reviewer"
        );
        let contract = sample_contract();
        let runtime = sample_runtime();
        let profile = scratch_profile("short-binding-id");
        let settings_a = settings_with_binding(profile.clone(), short.clone());
        let settings_b = settings_with_binding(profile.clone(), changed);
        assert_ne!(
            runtime_identity(&settings_a, &contract, &runtime),
            runtime_identity(&settings_b, &contract, &runtime),
            "a changed short binding cannot reuse the old cursor or receipt"
        );
        let _ = std::fs::remove_dir_all(profile);
        registry["bindings"]["sample-gate"] = json!("other-gate");
        assert_ne!(
            short,
            checker_binding_identity_from(&registry, "sample-gate"),
            "two different short bindings are different reviewers"
        );
    }

    #[test]
    fn a_present_but_unusable_binding_is_not_the_packaged_identity() {
        let registry = json!({
            "agents": {},
            "profiles": {},
            "bindings": {"sample-gate": {"fallbacks": []}}
        });
        let identity = checker_binding_identity_from(&registry, "sample-gate");
        assert_ne!(identity, Value::Null);
        assert_eq!(identity["unresolved"], true, "{identity}");
        assert_eq!(
            checker_binding_identity_from(
                &json!({"bindings": {"sample-gate": Value::Null}}),
                "sample-gate"
            ),
            Value::Null,
            "an explicit null binding is the packaged path"
        );
        assert_eq!(
            checker_binding_identity_from(&json!({"bindings": {}}), "sample-gate"),
            Value::Null,
            "an absent binding is the packaged path"
        );
    }

    #[test]
    fn a_receipt_from_another_binding_is_not_reused() {
        let profile = scratch_profile("binding-receipt");
        let contract = sample_contract();
        let runtime = sample_runtime();
        let head = "a".repeat(40);
        let binding = json!({"binding": "first"});
        let settings = settings_with_binding(profile.clone(), binding.clone());
        let run = profile.join("sample-gate-runs").join("review-1");
        std::fs::create_dir_all(&run).unwrap();
        let mut receipt = json!({
            "review_base": head,
            "review_head": head,
            "review_items": contract.domains,
            "gate_status": "passed",
            "engine": concat!("probator ", env!("CARGO_PKG_VERSION")),
            "agent_profile": {"id": "sample-gate", "revision": "profile/sample-gate/v1"},
            "checker_binding": binding,
            "harness": "pi",
            "provider": "openai",
            "model": "openai/gpt-6-luna",
            "reasoning": Value::Null,
        });
        receipt["seal"] = json!(crate::seal::seal("", &receipt));
        std::fs::write(
            run.join("report.json"),
            serde_json::to_string(&receipt).unwrap(),
        )
        .unwrap();
        assert!(
            audited(&settings, &contract, Some(&head), &head, &runtime).is_some(),
            "the same binding reuses its sealed receipt"
        );
        let other = settings_with_binding(profile.clone(), json!({"binding": "second"}));
        assert!(
            audited(&other, &contract, Some(&head), &head, &runtime).is_none(),
            "a changed binding has not judged the covered content"
        );
        let _ = std::fs::remove_dir_all(profile);
    }

    #[test]
    fn only_a_complete_judgement_advances_the_cursor() {
        let profile = scratch_profile("cursor");
        let contract = sample_contract();
        let repo = "local:/synthetic/repo";

        let first = "a".repeat(40);
        cursor_advance(
            &profile,
            &contract,
            REVIEWER,
            repo,
            &first,
            "pass",
            Vec::new(),
        );
        let entry =
            cursor_entry(&profile, &contract, repo, REVIEWER).expect("a sealed pass is coverage");
        assert_eq!(entry.head, first);
        assert_eq!(entry.verdict, "pass");
        assert!(entry.findings.is_empty());

        // A complete block parks its standing findings at the new head.
        let second = "b".repeat(40);
        let parked = blocking("src/other.rs", 4);
        cursor_advance(
            &profile,
            &contract,
            REVIEWER,
            repo,
            &second,
            "block",
            vec![parked.clone()],
        );
        let entry =
            cursor_entry(&profile, &contract, repo, REVIEWER).expect("a sealed block is coverage");
        assert_eq!(entry.head, second);
        assert_eq!(entry.verdict, "block");
        assert_eq!(entry.findings, vec![parked]);

        // An incomplete verdict judged nothing: neither the tape nor the
        // findings move.
        let third = "c".repeat(40);
        cursor_advance(
            &profile,
            &contract,
            REVIEWER,
            repo,
            &third,
            "incomplete",
            Vec::new(),
        );
        let entry =
            cursor_entry(&profile, &contract, repo, REVIEWER).expect("the old entry still stands");
        assert_eq!(entry.head, second, "an incomplete verdict judged nothing");
        assert_eq!(entry.verdict, "block");
        assert_eq!(entry.findings.len(), 1);
        let _ = std::fs::remove_dir_all(&profile);
    }

    #[test]
    fn a_tampered_cursor_entry_reads_as_no_coverage() {
        let profile = scratch_profile("cursor-tamper");
        let contract = sample_contract();
        let repo = "local:/synthetic/repo";
        cursor_advance(
            &profile,
            &contract,
            REVIEWER,
            repo,
            &"a".repeat(40),
            "pass",
            Vec::new(),
        );
        let path = cursor_file(&profile, &contract.name);
        let mut store: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        store[cursor_key(repo, &contract, REVIEWER).as_str()]["head"] = json!("b");
        std::fs::write(&path, serde_json::to_string(&store).unwrap()).unwrap();
        assert!(
            cursor_entry(&profile, &contract, repo, REVIEWER).is_none(),
            "a hand-edited position must not read as coverage"
        );
        let _ = std::fs::remove_dir_all(&profile);
    }

    #[test]
    fn coverage_does_not_survive_a_reviewer_change() {
        let profile = scratch_profile("cursor-reviewer");
        let contract = sample_contract();
        let repo = "local:/synthetic/repo";
        let head = "a".repeat(40);
        cursor_advance(
            &profile,
            &contract,
            REVIEWER,
            repo,
            &head,
            "pass",
            Vec::new(),
        );
        assert!(
            cursor_entry(&profile, &contract, repo, REVIEWER).is_some(),
            "the reviewer that produced the verdict owns the coverage"
        );
        assert!(
            cursor_entry(&profile, &contract, repo, "reviewer-b").is_none(),
            "a newly selected reviewer has not reviewed the covered content"
        );
        let _ = std::fs::remove_dir_all(&profile);
    }

    #[test]
    fn blockers_carry_only_on_paths_the_increment_never_opened() {
        let cursor = Cursor {
            head: "a".repeat(40),
            verdict: "block".into(),
            findings: vec![blocking("src/a.rs", 1), blocking("src/b.rs", 2)],
        };
        let changed = ChangedLines::whole(&["src/a.rs".to_string()]);
        assert_eq!(
            carried_blockers(Some(&cursor), &changed),
            vec![blocking("src/b.rs", 2)],
            "the touched file is re-reviewed; the untouched blocker stays"
        );
        assert!(carried_blockers(None, &changed).is_empty());
    }

    #[test]
    fn a_blocker_survives_a_change_elsewhere_in_its_file() {
        let cursor = Cursor {
            head: "a".repeat(40),
            verdict: "block".into(),
            findings: vec![
                blocking("src/a.rs", 10),
                blocking("src/a.rs", 20),
                blocking("src/b.rs", 1),
            ],
        };
        let mut touched = ChangedLines::default();
        touched.hunks.insert(
            "src/a.rs".into(),
            vec![Hunk {
                old_start: 1,
                old_count: 5,
                new_start: 1,
                new_count: 5,
            }],
        );
        assert_eq!(
            carried_blockers(Some(&cursor), &touched),
            vec![
                blocking("src/a.rs", 10),
                blocking("src/a.rs", 20),
                blocking("src/b.rs", 1)
            ],
            "a hunk elsewhere in the file does not re-open the blocker"
        );
        touched.hunks.insert(
            "src/a.rs".into(),
            vec![Hunk {
                old_start: 10,
                old_count: 3,
                new_start: 10,
                new_count: 3,
            }],
        );
        assert_eq!(
            carried_blockers(Some(&cursor), &touched),
            vec![blocking("src/a.rs", 20), blocking("src/b.rs", 1)],
            "only the blocker whose line the hunk rewrote is cleared"
        );
        touched.deleted.insert("src/a.rs".into());
        assert_eq!(
            carried_blockers(Some(&cursor), &touched),
            vec![blocking("src/b.rs", 1)],
            "a deleted file can no longer carry its evidence"
        );
    }

    /// An insertion immediately before an unchanged blocker rewrites no old
    /// line. Comparing against new-side ranges used to overlap the blocker's
    /// old line and clear a defect the increment never opened.
    #[test]
    fn an_insertion_before_a_blocker_does_not_clear_it() {
        let diff = "\
diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -4,0 +5,1 @@
+inserted
";
        let touched = parse_changed_lines(diff);
        assert!(!touched.touches("src/a.rs", 5));
        assert_eq!(touched.rebase("src/a.rs", 5), Some(6));
        let cursor = Cursor {
            head: "a".repeat(40),
            verdict: "block".into(),
            findings: vec![blocking("src/a.rs", 5)],
        };
        assert_eq!(
            carried_blockers(Some(&cursor), &touched),
            vec![blocking("src/a.rs", 6)],
            "the unchanged blocker survives and moves with its content"
        );
    }

    /// Deleting the blocker's own line proves the evidence is gone; the
    /// deletion-only hunk has no new-side line to compare against.
    #[test]
    fn deleting_the_blocker_line_clears_it() {
        let diff = "\
diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -5,1 +4,0 @@
-removed
";
        let touched = parse_changed_lines(diff);
        assert!(touched.touches("src/a.rs", 5));
        assert_eq!(touched.rebase("src/a.rs", 5), None);
        let cursor = Cursor {
            head: "a".repeat(40),
            verdict: "block".into(),
            findings: vec![blocking("src/a.rs", 5)],
        };
        assert!(carried_blockers(Some(&cursor), &touched).is_empty());
    }

    /// A file that did not exist in the old revision cannot carry evidence
    /// from a same-named predecessor; the whole file is re-opened instead.
    #[test]
    fn a_new_file_reopens_a_same_named_predecessors_blocker() {
        let diff = "\
diff --git a/src/a.rs b/src/a.rs
--- /dev/null
+++ b/src/a.rs
@@ -0,0 +1,1 @@
+new
";
        let touched = parse_changed_lines(diff);
        assert!(touched.whole.contains("src/a.rs"));
        assert!(touched.touches("src/a.rs", 5));
        let cursor = Cursor {
            head: "a".repeat(40),
            verdict: "block".into(),
            findings: vec![blocking("src/a.rs", 5)],
        };
        assert!(carried_blockers(Some(&cursor), &touched).is_empty());
    }

    /// A multi-line deletion clears only blockers inside the removed range;
    /// a blocker after it survives and is rebased by the hunk's delta.
    #[test]
    fn a_multi_line_deletion_clears_only_the_removed_blocker() {
        let diff = "\
diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -5,3 +4,0 @@
-a
-b
-c
";
        let touched = parse_changed_lines(diff);
        assert!(touched.touches("src/a.rs", 6));
        assert!(!touched.touches("src/a.rs", 8));
        assert_eq!(touched.rebase("src/a.rs", 8), Some(5));
        let cursor = Cursor {
            head: "a".repeat(40),
            verdict: "block".into(),
            findings: vec![blocking("src/a.rs", 6), blocking("src/a.rs", 8)],
        };
        assert_eq!(
            carried_blockers(Some(&cursor), &touched),
            vec![blocking("src/a.rs", 5)],
            "the removed blocker is gone; the survivor keeps the right line"
        );
    }

    #[test]
    fn unified_diff_hunks_name_the_old_side_lines_they_rewrite() {
        let diff = "\
diff --git a/src/a.rs b/src/a.rs
--- a/src/a.rs
+++ b/src/a.rs
@@ -1,2 +1,3 @@
-old
+new
+added
@@ -9,0 +12,2 @@
+line
+line
";
        let touched = parse_changed_lines(diff);
        assert_eq!(
            touched.hunks["src/a.rs"],
            vec![
                Hunk {
                    old_start: 1,
                    old_count: 2,
                    new_start: 1,
                    new_count: 3,
                },
                Hunk {
                    old_start: 9,
                    old_count: 0,
                    new_start: 12,
                    new_count: 2,
                },
            ]
        );
        assert!(touched.touches("src/a.rs", 1));
        assert!(
            !touched.touches("src/a.rs", 3),
            "an inserted line is not an old-side line"
        );
        assert!(
            !touched.touches("src/a.rs", 9),
            "a pure insertion removes no old line"
        );
    }

    #[test]
    fn deleted_and_binary_files_are_fully_touched() {
        let deleted = "\
diff --git a/src/gone.rs b/src/gone.rs
--- a/src/gone.rs
+++ /dev/null
@@ -1,1 +0,0 @@
-removed
";
        let touched = parse_changed_lines(deleted);
        assert!(touched.deleted.contains("src/gone.rs"));
        assert!(touched.touches("src/gone.rs", 1));

        let binary = "\
diff --git a/logo.png b/logo.png
index 1111111..2222222 100644
Binary files a/logo.png and b/logo.png differ
";
        let touched = parse_changed_lines(binary);
        assert!(touched.whole.contains("logo.png"));
        assert!(touched.touches("logo.png", 42));
    }

    #[test]
    fn a_carried_blocker_keeps_a_pass_refused_until_waived() {
        let rep = json!({
            "verdict": "pass",
            "findings": [],
            "carried_findings": [blocking("src/b.rs", 2)],
        });
        let merged = standing_report(&rep);
        assert_eq!(merged["findings"].as_array().unwrap().len(), 1);
        assert_eq!(merged["findings"][0]["carried"], true);
        assert_eq!(
            waiver_note(&merged, &[], false),
            None,
            "a fresh pass with a carried blocker is still a refusal"
        );
        assert_eq!(
            waiver_note(&merged, &[0], false),
            Some(vec!["src/b.rs:2".into()]),
            "only the signed ruling clears the carried blocker"
        );
    }

    #[test]
    fn a_fully_waived_non_pass_outcome_flips_to_a_pass() {
        let rep = report(json!([blocking("src/a.rs", 12), blocking("src/b.rs", 3)]));
        assert_eq!(
            waiver_note(&rep, &[0, 1], false),
            Some(vec!["src/a.rs:12".into(), "src/b.rs:3".into()])
        );
    }

    #[test]
    fn a_standing_blocking_finding_keeps_the_outcome_refused() {
        let rep = report(json!([blocking("src/a.rs", 12), blocking("src/b.rs", 3)]));
        assert_eq!(waiver_note(&rep, &[0], false), None);
    }

    #[test]
    fn a_verdict_ruling_accepts_an_outcome_with_no_findings() {
        let rep = report(json!([]));
        assert_eq!(waiver_note(&rep, &[], true), Some(Vec::new()));
        // Without the verdict ruling an empty finding list is still a
        // non-pass (for example an incomplete) and nothing is waived.
        assert_eq!(waiver_note(&rep, &[], false), None);
    }

    #[test]
    fn no_ruling_leaves_every_outcome_unchanged() {
        let rep = report(json!([blocking("src/a.rs", 12)]));
        assert_eq!(waiver_note(&rep, &[], false), None);
        let clean = report(json!([{"severity": "advisory", "file": "src/a.rs", "line": 1}]));
        assert_eq!(waiver_note(&clean, &[], false), None);
    }
}
