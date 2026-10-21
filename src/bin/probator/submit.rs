//! The verdict contract: what a submission must contain to be accepted.
//! Ported from the retired Python engine's `Review.submit` - there is exactly
//! one place where a review can pass, and every checker passes the same way.
//! The goldens under `tests/review-parity/` pin the accept/refuse behavior
//! and the refusal wording recorded from it.

use crate::contract::Contract;
use crate::evidence::safe_path;
use serde_json::Value;
use std::collections::HashSet;

/// The run state a verdict is judged against.
pub struct ReviewState<'a> {
    /// Every path the operation carries.
    pub changed: &'a [String],
    /// The paths whose diff the reviewer paged to its end.
    pub reviewed: &'a HashSet<String>,
    /// The official-document URLs fetched this review.
    pub fetched: &'a HashSet<String>,
}

/// Python truthiness: the engine's `not finding.get(key)` rejects missing,
/// null, false, zero, empty string and empty container alike.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|v| v != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Validate a submission. The check order mirrors the Python engine exactly,
/// so a report refused for two reasons reads the same first reason on both
/// runtimes.
pub fn validate(contract: &Contract, state: &ReviewState, report: &Value) -> Result<(), String> {
    let verdict = report["verdict"].as_str().unwrap_or("");
    if !["pass", "block", "incomplete"].contains(&verdict) {
        return Err("Invalid verdict".to_string());
    }
    let summary_ok = report["summary"].as_str().is_some_and(|s| !s.is_empty());
    let Some(findings) = report["findings"].as_array() else {
        return Err("Summary and findings are required".to_string());
    };
    if !summary_ok {
        return Err("Summary and findings are required".to_string());
    }
    let coverage = report["coverage"].as_object();
    let covered: HashSet<&str> = coverage
        .map(|c| c.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let domains: HashSet<&str> = contract.domains.iter().map(String::as_str).collect();
    if covered != domains {
        return Err(format!(
            "Account for every domain: {}",
            contract.domains.join(", ")
        ));
    }
    if !report["unknowns"].is_array() {
        return Err("Unknowns must be an explicit list".to_string());
    }
    for (index, finding) in findings.iter().enumerate() {
        for key in &contract.finding_keys {
            if !truthy(&finding[key]) {
                return Err(format!(
                    "findings[{index}].{key} is required and must not be empty"
                ));
            }
        }
        // A non-string file is not a path the contract can judge; refuse it
        // with the path contract's own refusal.
        safe_path(finding["file"].as_str().unwrap_or(""))?;
        if !["blocking", "advisory"].contains(&finding["severity"].as_str().unwrap_or("")) {
            return Err("Invalid finding severity".to_string());
        }
        if finding["line"].as_i64().is_none_or(|line| line < 1) {
            return Err("A positive line is required".to_string());
        }
    }
    let blocking = findings.iter().any(|f| f["severity"] == "blocking");
    let changed: HashSet<&str> = state.changed.iter().map(String::as_str).collect();
    let reviewed: HashSet<&str> = state.reviewed.iter().map(String::as_str).collect();
    if verdict == "pass" && (blocking || changed != reviewed) {
        return Err(
            "Pass requires every changed diff reviewed and no blocking findings".to_string(),
        );
    }
    if verdict == "block" && !blocking {
        return Err(
            "Block requires a concrete blocking finding; otherwise use incomplete".to_string(),
        );
    }
    if let Some(coverage) = coverage {
        for (domain, entry) in coverage {
            let status = entry["status"].as_str().unwrap_or("");
            let reason_ok = entry["reason"].as_str().is_some_and(|r| !r.is_empty());
            if !entry.is_object()
                || !["reviewed", "not-applicable", "unknown"].contains(&status)
                || !reason_ok
            {
                return Err(format!("coverage.{domain} must be {{status, reason}}"));
            }
            if verdict == "pass" && status == "unknown" {
                return Err("Unknown applicable coverage cannot pass".to_string());
            }
        }
    }
    if contract.tools.official_documents {
        for (index, finding) in findings.iter().enumerate() {
            let valid = finding["sources"].as_array().is_some_and(|sources| {
                sources.iter().all(|source| {
                    source
                        .as_str()
                        .is_some_and(|url| state.fetched.contains(url))
                })
            });
            if !valid {
                let mut available: Vec<&str> = state.fetched.iter().map(String::as_str).collect();
                available.sort();
                return Err(format!(
                    "findings[{index}].sources must be a list of fetched official URL strings; available: {}",
                    available.join(", ")
                ));
            }
        }
        let any_reviewed = coverage
            .map(|c| c.values().any(|entry| entry["status"] == "reviewed"))
            .unwrap_or(false);
        if verdict == "pass" && any_reviewed && state.fetched.is_empty() {
            return Err("Applicable cost review requires official documentation".to_string());
        }
    }
    Ok(())
}

/// The full-service verdict rules, checked before the gate's own contract:
/// the charter must be read, every project accounted for, and every finding
/// located in source the reviewer actually read.
pub struct FullState<'a> {
    /// The snapshot's files: path to sanitized content.
    pub files: &'a serde_json::Map<String, Value>,
    /// Reuse aliases: path to the primary copy's path.
    pub aliases: &'a serde_json::Map<String, Value>,
    /// The snapshot's project labels, in snapshot order.
    pub projects: &'a [String],
    /// The paths the reviewer actually read (journal-replayed on resume).
    pub reads: &'a HashSet<String>,
    pub original_read: bool,
}

pub fn validate_full(state: &FullState, report: &Value) -> Result<(), String> {
    if !state.original_read {
        return Err("Read original_request before deciding".to_string());
    }
    let coverage = report["projects"].as_object();
    let covered: HashSet<&str> = coverage
        .map(|c| c.keys().map(String::as_str).collect())
        .unwrap_or_default();
    let expected: HashSet<&str> = state.projects.iter().map(String::as_str).collect();
    if covered != expected {
        return Err(format!(
            "projects must contain these exact keys: {}",
            state.projects.join(", ")
        ));
    }
    let verdict = report["verdict"].as_str().unwrap_or("");
    if let Some(coverage) = coverage {
        for (name, item) in coverage {
            let status = item["status"].as_str().unwrap_or("");
            let reason_ok = item["reason"].as_str().is_some_and(|r| !r.is_empty());
            if !item.is_object()
                || !["reviewed", "not-applicable", "unknown"].contains(&status)
                || !reason_ok
            {
                return Err(format!(
                    "projects.{name} must be {{status: reviewed|not-applicable|unknown, reason: nonempty string}}"
                ));
            }
            if status == "reviewed"
                && !state
                    .reads
                    .iter()
                    .any(|path| path.starts_with(&format!("{name}/")))
            {
                return Err("Read the project's actual source before marking reviewed".to_string());
            }
            if status == "unknown" && verdict == "pass" {
                return Err("Unknown project coverage cannot pass".to_string());
            }
        }
    }
    let empty = Vec::new();
    let findings = report["findings"].as_array().unwrap_or(&empty);
    for (index, finding) in findings.iter().enumerate() {
        let path = finding["file"].as_str().unwrap_or("");
        let actual = state
            .aliases
            .get(path)
            .and_then(Value::as_str)
            .unwrap_or(path);
        let content = state
            .files
            .get(actual)
            .and_then(Value::as_str)
            .unwrap_or("");
        let lines = if content.is_empty() && !state.files.contains_key(actual) {
            None
        } else {
            Some(content.lines().count())
        };
        let line = finding["line"].as_i64().unwrap_or(0);
        let located = lines.is_some_and(|total| line >= 1 && line as usize <= total);
        if !located {
            return Err(format!(
                "findings[{index}] must name one exact listed path and an existing positive integer line; use read to check its location"
            ));
        }
        if !state.reads.contains(path) {
            return Err(format!(
                "findings[{index}] source context has not been read; read that exact file before submission"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ReviewState, validate};
    use crate::contract;
    use serde_json::Value;
    use std::collections::HashSet;
    use std::path::Path;

    /// Every golden cell replays: one report, one state, one contract, and
    /// the Python engine's recorded verdict on exactly that input.
    #[test]
    fn submit_validation_matches_the_engine_goldens() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("review-parity");
        let raw = std::fs::read_to_string(dir.join("submit-expected.json")).unwrap();
        let expected: Value = serde_json::from_str(&raw).unwrap();
        let cells = expected.as_object().unwrap();
        assert!(!cells.is_empty(), "the corpus must not be empty");
        for (checker, cases) in cells {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tools")
                .join(checker)
                .join("contract.json");
            let contract = contract::load(&path).unwrap_or_else(|e| panic!("{checker}: {e}"));
            for (name, cell) in cases.as_object().unwrap() {
                let changed: Vec<String> = serde_json::from_value(cell["changed"].clone()).unwrap();
                let reviewed: HashSet<String> =
                    serde_json::from_value(cell["reviewed"].clone()).unwrap();
                let fetched: HashSet<String> =
                    serde_json::from_value(cell["fetched"].clone()).unwrap();
                let state = ReviewState {
                    changed: &changed,
                    reviewed: &reviewed,
                    fetched: &fetched,
                };
                let outcome = validate(&contract, &state, &cell["report"]);
                match (outcome, cell["expected"]["error"].as_str()) {
                    (Err(actual), Some(expected)) => {
                        assert_eq!(actual, expected, "{checker}/{name}")
                    }
                    (Ok(()), None) => {}
                    (actual, expected) => {
                        panic!("{checker}/{name}: expected error {expected:?}, got {actual:?}")
                    }
                }
            }
        }
    }

    /// Full-service verdicts: the charter, project-coverage and
    /// read-before-finding rules ahead of the gate contract, per checker.
    #[test]
    fn full_service_validation_matches_the_engine_goldens() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("review-parity");
        let raw = std::fs::read_to_string(dir.join("fullsubmit-expected.json")).unwrap();
        let expected: Value = serde_json::from_str(&raw).unwrap();
        for (key, cell) in expected.as_object().unwrap() {
            let (checker, _) = key.split_once("::").unwrap();
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tools")
                .join(checker)
                .join("contract.json");
            let contract = contract::load(&path).unwrap();
            let changed: Vec<String> =
                serde_json::from_value(cell["gate"]["changed"].clone()).unwrap();
            let reviewed: HashSet<String> =
                serde_json::from_value(cell["gate"]["reviewed"].clone()).unwrap();
            let fetched: HashSet<String> =
                serde_json::from_value(cell["gate"]["fetched"].clone()).unwrap();
            let gate = ReviewState {
                changed: &changed,
                reviewed: &reviewed,
                fetched: &fetched,
            };
            let full = cell["full"].as_object().unwrap();
            let projects: Vec<String> = serde_json::from_value(full["projects"].clone()).unwrap();
            let reads: HashSet<String> = serde_json::from_value(full["reads"].clone()).unwrap();
            let state = super::FullState {
                files: full["files"].as_object().unwrap(),
                aliases: full["aliases"].as_object().unwrap(),
                projects: &projects,
                reads: &reads,
                original_read: full["original_read"].as_bool().unwrap(),
            };
            let outcome = super::validate_full(&state, &cell["report"])
                .and_then(|()| validate(&contract, &gate, &cell["report"]));
            match (outcome, cell["expected"]["error"].as_str()) {
                (Err(actual), Some(expected)) => assert_eq!(actual, expected, "{key}"),
                (Ok(()), None) => {}
                (actual, expected) => {
                    panic!("{key}: expected error {expected:?}, got {actual:?}")
                }
            }
        }
    }
}
