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
        if !on.iter().any(|candidate| *candidate == event) {
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
                || (event == "pr" && env.iter().any(|(var, _)| *var == "PROBATOR_PR_HEAD"));
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

fn severity_of(report_severity: &str) -> &'static str {
    match report_severity.to_ascii_lowercase().as_str() {
        "blocking" | "high" | "error" => "high",
        "warn" | "warning" => "warn",
        _ => "info",
    }
}

/// One sealed report → gate findings. Evidence and validation stay inside
/// the run directory; only locations and judgements cross.
fn findings_of(name: &str, report_path: &Path) -> Vec<Value> {
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
    let verdict = report["verdict"].as_str().unwrap_or("");
    if verdict == "pass" && report["gate_status"] != "passed" {
        return vec![high(format!(
            "{name}: report claims a pass the receipt never confirmed"
        ))];
    }
    let mut findings = Vec::new();
    for finding in report["findings"].as_array().into_iter().flatten() {
        let impact = finding["impact"].as_str().unwrap_or("");
        let remedy = finding["remedy"].as_str().unwrap_or("");
        let message = match (impact.is_empty(), remedy.is_empty()) {
            (false, false) => format!("{name}: {impact} — {remedy}"),
            (false, true) => format!("{name}: {impact}"),
            _ => format!("{name}: finding"),
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
    if findings.is_empty() && verdict != "pass" {
        let summary = report["summary"].as_str().unwrap_or("no summary");
        findings.push(high(format!("{name}: verdict {verdict} — {summary}")));
    }
    findings
}

/// One policy row → findings: run the declared command, then translate
/// whatever sealed reports it produced. A command with no contract flag is
/// a script checker — its exit code is the whole verdict.
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
    let reports = report_paths(&stdout);
    if reports.is_empty() {
        if output.status.success() {
            return Vec::new();
        }
        let detail = String::from_utf8_lossy(&output.stderr)
            .lines()
            .chain(stdout.lines())
            .find(|line| !line.trim().is_empty())
            .unwrap_or("no diagnostics")
            .to_string();
        return vec![high(format!(
            "{name}: audit refused or failed (exit {:?}): {detail}",
            output.status.code()
        ))];
    }
    reports
        .iter()
        .flat_map(|path| findings_of(name, path))
        .collect()
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
        let env = range_env(event, &detail);
        let policy = crate::install::policy_file();
        let checkers = match checkers_for(&policy, event) {
            Ok(checkers) => checkers,
            Err(message) => return vec![high(message)],
        };
        checkers
            .iter()
            .flat_map(|(name, argv)| run_checker(name, argv, &target, &env))
            .collect()
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
        std::fs::write(
            &path,
            serde_json::to_string(&json!({
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
            }))
            .unwrap(),
        )
        .unwrap();
        let findings = findings_of("clean-auditor", &path);
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
        std::fs::write(
            &path,
            serde_json::to_string(&json!({
                "verdict": "block",
                "gate_status": "refused",
                "summary": "coverage incomplete",
                "findings": []
            }))
            .unwrap(),
        )
        .unwrap();
        let findings = findings_of("x", &path);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]["message"]
                .as_str()
                .unwrap()
                .contains("coverage incomplete")
        );
        let _ = std::fs::remove_dir_all(&dir);
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
}
