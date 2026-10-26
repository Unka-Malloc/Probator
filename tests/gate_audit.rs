//! The orchestrator-facing `gate-audit` surface, exercised through the real
//! binary. These tests pin the two classifications the wrapper must never
//! confuse: a cleanup race after a completed audit is housekeeping, while a
//! checker that crashes without a sealed report is still a fail-closed high
//! refusal. No agent runtime is involved; the checker is a throwaway script.

#![cfg(unix)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
static PROBATOR: &str = env!("CARGO_BIN_EXE_probator");

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

impl Fixture {
    /// A private config directory: `gate-audit` reads `<config>/checkers.toml`
    /// beside the routing table it would normally use.
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "probator-gate-audit-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(path.join("config")).unwrap();
        std::fs::write(path.join("config/config.toml"), "# synthetic fixture\n").unwrap();
        Fixture(path)
    }

    /// Write a one-row policy whose command is `/bin/sh <body-script>`.
    fn checker(&self, body: &str) -> PathBuf {
        let script = self.0.join("checker.sh");
        std::fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let policy = format!(
            "[[checkers]]\nname = \"sample-gate\"\non = [\"pre-push\"]\n\
             command = [\"/bin/sh\", \"{}\"]\n",
            script.display()
        );
        std::fs::write(self.0.join("config/checkers.toml"), policy).unwrap();
        script
    }

    fn gate(&self) -> Output {
        let mut child = Command::new(PROBATOR)
            .arg("gate-audit")
            .env("PROBATOR_CONFIG", self.0.join("config/config.toml"))
            .env_remove("PROBATOR_RULINGS_LEDGER")
            .env_remove("PROBATOR_RULINGS_ANCHOR")
            .env_remove("PROBATOR_STAGE1_EVIDENCE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("gate-audit starts");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(br#"{"kind":"push","target":"/tmp/repo"}"#)
            .unwrap();
        child.wait_with_output().unwrap()
    }
}

fn gate_findings(output: &Output) -> Vec<serde_json::Value> {
    assert!(
        output.status.success(),
        "gate-audit must report findings as JSON, not fail: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "gate-audit stdout is not JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// The dead-pid kill that used to manufacture an `audit refused or failed`
/// high arrives after the audit already settled. It is teardown, not a
/// verdict, and must leave the gate clean.
#[test]
fn a_cleanup_race_after_a_settled_audit_is_not_a_gate_finding() {
    let fixture = Fixture::new("cleanup");
    fixture.checker(
        "echo 'sample-gate: nothing unpublished in this operation; no review needed'\n\
         echo 'kill: 424242: No such process' >&2\n\
         exit 1",
    );
    let output = fixture.gate();
    let findings = gate_findings(&output);
    assert!(
        findings.is_empty(),
        "cleanup noise must not refuse a settled audit: {findings:?}"
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        !text.contains("refused or failed"),
        "the wrapper must not report a cleanup race as a checker verdict: {text}"
    );
}

/// A checker that panics before producing a sealed report is a real failed
/// audit. The gate stays closed and says so instead of inventing a verdict.
#[test]
fn a_crash_without_a_report_is_still_a_high_refusal() {
    let fixture = Fixture::new("crash");
    fixture.checker(
        "echo 'thread main panicked at src/bin/probator.rs:1' >&2\n\
         exit 1",
    );
    let findings = gate_findings(&fixture.gate());
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["severity"], "high");
    let message = findings[0]["message"].as_str().unwrap();
    assert!(message.contains("audit did not complete"), "{message}");
    assert!(message.contains("panicked"), "{message}");
    assert!(!message.contains("refused or failed"), "{message}");
}

/// A skill-read abort is an incomplete audit, not an audit conclusion. It
/// must surface as such — and it must not be quoted as a checker finding.
#[test]
fn an_aborted_skill_read_is_an_incomplete_audit_not_a_verdict() {
    let fixture = Fixture::new("aborted");
    fixture.checker(
        "echo '**Reading privacy-cleaner skill failed: permission denied**' >&2\n\
         exit 1",
    );
    let findings = gate_findings(&fixture.gate());
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0]["severity"], "high");
    let message = findings[0]["message"].as_str().unwrap();
    assert!(message.contains("audit did not complete"), "{message}");
    assert!(message.contains("permission denied"), "{message}");
    assert!(!message.contains("refused or failed"), "{message}");
}
