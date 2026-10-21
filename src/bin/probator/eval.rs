//! Score recorded audit runs into a checker x architecture quality matrix.
//!
//! Three scored dimensions, all observable offline:
//!
//! * productive (45%): the run sealed a verdict - pass or block both count,
//!   because "no" is a usable judgment while a dead run is not;
//! * decisive (40%): coverage entries judged `reviewed` or `not-applicable`
//!   rather than `unknown` - an unanswered checklist item is the failure this
//!   engine exists to prevent;
//! * substance (15%): median coverage-reason length, saturating at 120
//!   characters - a crude proxy that separates reasoning from rubber-stamping.
//!
//! Not scored: verdict mix (strictness and correctness are indistinguishable
//! without ground truth) and cost (reported, never weighted). Correctness
//! needs canary fixtures with planted findings - this matrix is the
//! compliance layer that decides whether such a run is even worth grading.

use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::Path;

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn get<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut at = value;
    for key in path {
        at = at.get(*key)?;
    }
    Some(at)
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    get(value, path).and_then(Value::as_str)
}

/// The architecture that actually produced the verdict. `runtime.model` and
/// `report.model` record the *requested* profile model; the fallback chain
/// means the turn may have been served by another agent entirely - the truth
/// lives in `outcome.served`. Declared-only sources carry a `~` marker.
fn architecture(
    resume: Option<&Value>,
    completion: Option<&Value>,
    report: Option<&Value>,
) -> String {
    if let Some(model) = completion.and_then(|v| string_at(v, &["outcome", "served", "model"])) {
        let agent = completion
            .and_then(|v| string_at(v, &["outcome", "served", "agent"]))
            .unwrap_or("?");
        return format!("{agent}/{model}");
    }
    for (model, harness) in [
        (
            report.and_then(|v| string_at(v, &["model"])),
            report.and_then(|v| string_at(v, &["harness"])),
        ),
        (
            completion.and_then(|v| string_at(v, &["runtime", "model"])),
            completion.and_then(|v| string_at(v, &["runtime", "harness"])),
        ),
        (
            resume.and_then(|v| string_at(v, &["model"])),
            resume.and_then(|v| string_at(v, &["harness"])),
        ),
    ] {
        if let Some(model) = model {
            return format!("{}/{model}~", harness.unwrap_or("?"));
        }
    }
    "?".to_string()
}

struct Run {
    checker: String,
    arch: String,
    verdict: String,
    productive: bool,
    anomaly: bool,
    domains: usize,
    unknown: usize,
    unknown_rate: f64,
    reason_score: f64,
    reason_median: usize,
    findings: usize,
    duration_ms: u64,
    tokens: u64,
}

fn load_run(checker: &str, dir: &Path) -> Option<Run> {
    let resume = read_json(&dir.join("resume.json"));
    let completion = read_json(&dir.join("completion.json"));
    // The sealed report wins; an unsealed draft still shows coverage intent.
    let coverage_doc =
        read_json(&dir.join("report.json")).or_else(|| read_json(&dir.join("draft.json")));
    let report = read_json(&dir.join("report.json"));
    if resume.is_none() && coverage_doc.is_none() && completion.is_none() {
        return None;
    }

    let verdict = report
        .as_ref()
        .and_then(|v| string_at(v, &["verdict"]))
        .unwrap_or("none")
        .to_string();
    // A verdict is productive when it is a real judgment the gate accepted -
    // or plausibly one for records too old to say. An explicitly failed
    // completion means the report was refused (fail-closed synthesis or a
    // lost handshake), never a delivered audit.
    let completion_failed = completion
        .as_ref()
        .map(|c| get(c, &["completed"]).and_then(Value::as_bool) == Some(false))
        .unwrap_or(false);
    let productive = matches!(verdict.as_str(), "pass" | "block") && !completion_failed;
    // Sealed-but-lost only counts when the record says so explicitly - an
    // old record that never knew `outcome.completed` is silent, not anomalous.
    let anomaly = completion
        .as_ref()
        .map(|c| {
            get(c, &["has_report"]).and_then(Value::as_bool) == Some(true)
                && (get(c, &["completed"]).and_then(Value::as_bool) == Some(false)
                    || get(c, &["outcome", "failure"])
                        .map(|f| !f.is_null())
                        .unwrap_or(false))
        })
        .unwrap_or(false);

    let coverage = coverage_doc
        .as_ref()
        .and_then(|v| v.get("coverage"))
        .and_then(Value::as_object);
    let declared = resume
        .as_ref()
        .and_then(|v| v.get("items"))
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    let domains = declared.max(coverage.map(Map::len).unwrap_or(0));

    let (mut unknown, mut reason_lens) = (0usize, Vec::new());
    if let Some(map) = coverage {
        for entry in map.values() {
            let status = entry
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            if status == "unknown" {
                unknown += 1;
            }
            let reason = entry.get("reason").and_then(Value::as_str).unwrap_or("");
            reason_lens.push(reason.chars().count());
        }
    }
    // No coverage at all is a wholly unanswered checklist, not a free pass.
    let unknown_rate = if domains == 0 || coverage.is_none() {
        1.0
    } else {
        unknown as f64 / domains as f64
    };
    reason_lens.sort_unstable();
    let reason_median = reason_lens.get(reason_lens.len() / 2).copied().unwrap_or(0);
    let reason_score = (reason_median as f64 / 120.0).min(1.0);

    let findings = report
        .as_ref()
        .and_then(|v| v.get("findings"))
        .and_then(Value::as_array)
        .map(|a| a.len())
        .unwrap_or(0);
    let duration_ms = completion
        .as_ref()
        .and_then(|v| v.get("duration_ms"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let usage = completion
        .as_ref()
        .and_then(|v| v.get("outcome"))
        .and_then(|v| v.get("usage"));
    let tokens = ["input_tokens", "output_tokens"]
        .iter()
        .map(|key| {
            usage
                .and_then(|u| u.get(*key))
                .and_then(Value::as_u64)
                .unwrap_or(0)
        })
        .sum();

    Some(Run {
        checker: checker.to_string(),
        arch: architecture(resume.as_ref(), completion.as_ref(), report.as_ref()),
        verdict,
        productive,
        anomaly,
        domains,
        unknown,
        unknown_rate,
        reason_score,
        reason_median,
        findings,
        duration_ms,
        tokens,
    })
}

/// Every run under a profiles root: <profile>/<checker>-runs/review-*/.
fn scan(profiles: &Path) -> Vec<Run> {
    let mut runs = Vec::new();
    for profile in std::fs::read_dir(profiles).into_iter().flatten().flatten() {
        for holder in std::fs::read_dir(profile.path())
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = holder.file_name().to_string_lossy().to_string();
            let Some(checker) = name.strip_suffix("-runs") else {
                continue;
            };
            for run in std::fs::read_dir(holder.path())
                .into_iter()
                .flatten()
                .flatten()
            {
                if run.file_name().to_string_lossy().starts_with("review-")
                    && let Some(scored) = load_run(checker, &run.path())
                {
                    runs.push(scored);
                }
            }
        }
    }
    runs
}

fn median(values: &mut [u64]) -> u64 {
    values.sort_unstable();
    values.get(values.len() / 2).copied().unwrap_or(0)
}

struct Cell {
    n: usize,
    productive: usize,
    anomalies: usize,
    pass: usize,
    block: usize,
    unknown_rate: f64,
    reason_score: f64,
    reason_median: usize,
    findings: usize,
    durations: Vec<u64>,
    tokens: Vec<u64>,
}

impl Cell {
    fn score(&self) -> f64 {
        let productive = self.productive as f64 / self.n as f64;
        let decisive = 1.0 - self.unknown_rate / self.n as f64;
        100.0 * (0.45 * productive + 0.40 * decisive + 0.15 * (self.reason_score / self.n as f64))
    }
}

pub fn run(profiles: &Path, json: bool, min_runs: usize, verbose: bool) -> Result<i32, String> {
    let runs = scan(profiles);
    if runs.is_empty() {
        return Err(format!("no audit runs found under {}", profiles.display()));
    }
    let mut cells: BTreeMap<(String, String), Cell> = BTreeMap::new();
    for run in &runs {
        let cell = cells
            .entry((run.checker.clone(), run.arch.clone()))
            .or_insert_with(|| Cell {
                n: 0,
                productive: 0,
                anomalies: 0,
                pass: 0,
                block: 0,
                unknown_rate: 0.0,
                reason_score: 0.0,
                reason_median: 0,
                findings: 0,
                durations: Vec::new(),
                tokens: Vec::new(),
            });
        cell.n += 1;
        cell.productive += run.productive as usize;
        cell.anomalies += run.anomaly as usize;
        // Verdicts count only for delivered audits - a refused report is the
        // gate's own fail-closed synthesis, not the model's judgment.
        cell.pass += (run.productive && run.verdict == "pass") as usize;
        cell.block += (run.productive && run.verdict == "block") as usize;
        cell.unknown_rate += run.unknown_rate;
        cell.reason_score += run.reason_score;
        cell.reason_median += run.reason_median;
        cell.findings += run.findings;
        cell.durations.push(run.duration_ms);
        cell.tokens.push(run.tokens);
    }

    if json {
        let cells_json: Vec<Value> = cells
            .iter()
            .filter(|(_, c)| c.n >= min_runs)
            .map(|((checker, arch), c)| {
                serde_json::json!({
                    "checker": checker, "architecture": arch, "runs": c.n,
                    "productive_rate": c.productive as f64 / c.n as f64,
                    "verdicts": {"pass": c.pass, "block": c.block, "none": c.n - c.pass - c.block},
                    "mean_unknown_rate": c.unknown_rate / c.n as f64,
                    "reason_median_chars": c.reason_median / c.n,
                    "findings": c.findings, "anomalies": c.anomalies,
                    "median_duration_s": median(&mut c.durations.clone()) / 1000,
                    "median_tokens": median(&mut c.tokens.clone()),
                    "score": (c.score() * 10.0).round() / 10.0,
                })
            })
            .collect();
        let out = serde_json::json!({
            "profiles": profiles.display().to_string(),
            "runs": runs.len(),
            "formula": "score = 100 * (0.45*productive + 0.40*(1-unknown_rate) + 0.15*reason_substance); \
                        '~' marks a declared (unverified) model; anomaly = sealed report refused by a \
                        failed completion handshake",
            "cells": cells_json,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "{:<22} {:<38} {:>4} {:>6} {:>5} {:>5} {:>6} {:>5} {:>7} {:>7} {:>6} {:>6}",
            "CHECKER",
            "ARCHITECTURE",
            "N",
            "PROD%",
            "PASS",
            "BLOCK",
            "UNK%",
            "RSN",
            "TOK(K)",
            "DUR(s)",
            "ANOM",
            "SCORE"
        );
        let mut sorted: Vec<_> = cells.iter().filter(|(_, c)| c.n >= min_runs).collect();
        sorted.sort_by(|a, b| {
            b.1.score()
                .partial_cmp(&a.1.score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for ((checker, arch), c) in sorted {
            println!(
                "{:<22} {:<38} {:>4} {:>5.0}% {:>5} {:>5} {:>5.0}% {:>5} {:>7} {:>7} {:>6} {:>6.1}",
                checker,
                arch,
                c.n,
                100.0 * c.productive as f64 / c.n as f64,
                c.pass,
                c.block,
                100.0 * c.unknown_rate / c.n as f64,
                c.reason_median / c.n,
                median(&mut c.tokens.clone()) / 1000,
                median(&mut c.durations.clone()) / 1000,
                c.anomalies,
                c.score()
            );
        }
        println!(
            "\n{} runs | score = 45% productive + 40% decisive + 15% reason substance | \
             '~' = declared model (no served record) | ANOM = sealed report, failed handshake",
            runs.len()
        );
    }

    if verbose {
        for run in &runs {
            println!(
                "  {:<20} {:<38} {:>5} {:>4}/{:<3} unk={} rsn={} tok={} {}ms{}{}",
                run.checker,
                run.arch,
                run.verdict,
                run.domains - run.unknown,
                run.domains,
                run.unknown,
                run.reason_median,
                run.tokens,
                run.duration_ms,
                if run.productive { " sealed" } else { "" },
                if run.anomaly { " ANOMALY" } else { "" },
            );
        }
    }
    Ok(0)
}
