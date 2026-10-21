//! The gate lifecycle, exercised black-box through the real binary: snapshot
//! resolution, the deterministic stage, the review process with a fixture
//! runner standing in for the audit agent, the receipt, and receipt reuse.
//! No model is involved; the runner speaks the MCP tool protocol directly.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
static REVIEW: &str = env!("CARGO_BIN_EXE_probator");

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_AUTHOR_DATE", "1700000000 +0000")
        .env("GIT_COMMITTER_DATE", "1700000000 +0000")
        .env("GIT_AUTHOR_NAME", "Synthetic")
        .env("GIT_AUTHOR_EMAIL", "synthetic@example.invalid")
        .env("GIT_COMMITTER_NAME", "Synthetic")
        .env("GIT_COMMITTER_EMAIL", "synthetic@example.invalid")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(output.status.success(), "git {args:?} failed");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// The fixture runner speaks the MCP wire protocol itself: one inventory
/// call, one full diff page per path the fixture snapshots carry, one
/// verdict. The tool server arrives on the role's `mcpServers`, exactly as a
/// real session would see it.
const RUNNER: &str = r#"#!/bin/bash
set -euo pipefail
contract="" run_dir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --contract) contract="$2"; shift 2 ;;
    --run) run_dir="$2"; shift 2 ;;
    *) shift ;;
  esac
done
exe="$(sed -n 's/.*"review": *"\([^"]*\)".*/\1/p' "$(dirname "$contract")/installation.json")"
touch "$(dirname "$0")/runner-was-here"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"inventory"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"diff","path":"src/main.rs"}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"diff","path":"src/lib.rs"}}}' \
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"sample_submit_review","arguments":{"verdict":"pass","summary":"clean","coverage":{"structure":{"status":"reviewed","reason":"looked"}},"findings":[],"unknowns":[]}}}' \
  | "$exe" serve --contract "$contract" --run "$run_dir" >/dev/null
printf '{"completed":true,"stop_reason":"completed","usage":{"input_tokens":1,"output_tokens":1,"cache_read_tokens":0,"cache_write_tokens":0},"profile":{"id":"sample-gate","revision":null,"principal":"synthetic"}}\n'
"#;

const CONTRACT: &str = r#"{
  "name": "sample-gate",
  "title": "Sample Gate",
  "domains": ["structure"],
  "finding_keys": ["file", "line", "severity", "evidence"],
  "on": ["pre-push"],
  "tools": {
    "name_prefix": "sample",
    "context": ["inventory", "list", "diff", "read", "find"],
    "submit": true,
    "descriptions": {"context": "Inspect the range.", "submit": "Submit the verdict."}
  },
  "task": "Review the change and submit."
}
"#;

/// A repository with one unpublished commit on top of a pushed base, and the
/// checker's installation: contract, policy, the fixture runner.
fn fixture() -> (Fixture, String, String) {
    let root = std::env::temp_dir().join(format!(
        "gv-gate-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let repo = root.join("repo");
    std::fs::create_dir_all(repo.join("src")).unwrap();
    git(&repo, &["init", "-q"]);
    git(&repo, &["config", "commit.gpgsign", "false"]);
    std::fs::write(repo.join("src/main.rs"), "fn main() {}\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "base"]);
    let base = git(&repo, &["rev-parse", "HEAD"]);
    std::fs::write(
        repo.join("src/main.rs"),
        "fn main() { println!(\"v2\"); }\n",
    )
    .unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "head"]);
    let head = git(&repo, &["rev-parse", "HEAD"]);
    // The pushed ref exists locally, as it does at a real pre-push.
    git(&repo, &["branch", "-f", "nightly", "HEAD"]);

    let profile = root.join("profile");
    let skills = root.join("skills/sample-gate");
    let plugin = root.join("plugin");
    std::fs::create_dir_all(&skills).unwrap();
    std::fs::create_dir_all(&plugin).unwrap();
    std::fs::write(plugin.join("contract.json"), CONTRACT).unwrap();
    std::fs::write(plugin.join("policy.md"), "Review policy.\n").unwrap();
    // The audit runtime is declared data, synced with the profile: the
    // engine refuses a profile without one. Neutral labels — the gate
    // pins no vendor.
    std::fs::write(
        skills.join("profile.json"),
        serde_json::json!({
            "runtime": {
                "harness": "stub-agent",
                "provider": "stub",
                "model": "stub/reviewer-1"
            }
        })
        .to_string(),
    )
    .unwrap();
    let runner = root.join("runner.sh");
    std::fs::write(&runner, RUNNER).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(
        plugin.join("installation.json"),
        serde_json::json!({
            "agent_runner": runner.to_string_lossy(),
            "profile": profile.to_string_lossy(),
            "skill_dir": skills.to_string_lossy(),
            "review": REVIEW,
        })
        .to_string(),
    )
    .unwrap();
    (Fixture(root), base, head)
}

fn run_gate(root: &Path, repo: &Path, base: &str, head: &str) -> Output {
    Command::new(REVIEW)
        .args([
            "run",
            "--contract",
            &root.join("plugin/contract.json").to_string_lossy(),
            "--repo",
            &repo.to_string_lossy(),
        ])
        .env(
            "PROBATOR_PUSH_REFS",
            format!("refs/heads/nightly {head} refs/heads/nightly {base}"),
        )
        .output()
        .unwrap()
}

#[test]
fn the_gate_reviews_once_then_reuses_the_receipt() {
    let (guard, base, head) = fixture();
    let (root, repo) = (guard.0.clone(), guard.0.join("repo"));
    let first = run_gate(&root, &repo, &base, &head);
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        stdout.contains(
            "Sample Gate: reviewing push refs/heads/nightly with stub/stub/reviewer-1 (default)…"
        ),
        "{stdout}"
    );
    assert!(stdout.contains("Sample Gate: pass — clean"), "{stdout}");

    // The receipt holds the full identity: snapshot, contract, runtime,
    // engine. A push resolves to the whole tree at its head, and the base is
    // the remote tip the push would move - the receipt binds both.
    let runs = root.join("profile/sample-gate-runs");
    let receipt_path = std::fs::read_dir(&runs)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("report.json");
    let receipt: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["gate_status"], "passed");
    assert_eq!(receipt["review_base"], base);
    assert_eq!(receipt["review_head"], head);
    assert_eq!(receipt["review_items"], serde_json::json!(["structure"]));
    assert_eq!(receipt["agent_profile"]["id"], "sample-gate");
    assert_eq!(receipt["harness"], "stub-agent");
    assert_eq!(receipt["model"], "stub/reviewer-1");
    assert!(receipt["engine"].as_str().unwrap().starts_with("probator "));

    // The second run of the same range reuses the receipt: the runner is not
    // paid twice.
    let marker = root.join("runner-was-here");
    assert!(marker.exists());
    std::fs::remove_file(&marker).unwrap();
    let second = run_gate(&root, &repo, &base, &head);
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        stdout.contains("already passed its semantic review"),
        "{stdout}"
    );
    assert!(!marker.exists(), "the runner must not run again");
}

#[test]
fn the_deterministic_stage_refuses_before_any_review() {
    let (guard, base, head) = fixture();
    let root = guard.0.clone();
    // Same contract plus a stage-1 rule the head violates.
    let mut contract: serde_json::Value = serde_json::from_str(CONTRACT).unwrap();
    contract["stage1"] = serde_json::json!({
        "label": "deterministic",
        "refusal": "The sample static stage refused this operation",
        "rules": [{
            "id": "no-v2",
            "title": "v2 is forbidden",
            "kind": "regex",
            "pattern": "v2",
            "target": "added-lines"
        }]
    });
    std::fs::write(
        root.join("plugin/contract.json"),
        serde_json::to_string_pretty(&contract).unwrap(),
    )
    .unwrap();
    let repo = root.join("repo");
    let result = run_gate(&root, &repo, &base, &head);
    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("The sample static stage refused this operation"),
        "{stderr}"
    );
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(stdout.contains("refused: no-v2"), "{stdout}");
    assert!(stdout.contains("src/main.rs:1 no-v2"), "{stdout}");
    assert!(
        !root.join("runner-was-here").exists(),
        "a refused range never pays for a review"
    );
}

/// A release and a pull request resolve to the whole tree at their head
/// commit, exactly like a push. All three judge snapshots through the same
/// fixture runner.
#[test]
fn release_and_pr_judge_the_whole_snapshot() {
    let (guard, base, head) = fixture();
    let root = guard.0.clone();
    let repo = root.join("repo");
    // A prior release at the base commit, the release being published at head.
    git(&repo, &["tag", "v1", &base]);
    git(&repo, &["tag", "v2", &head]);
    let release = Command::new(REVIEW)
        .args([
            "run",
            "--contract",
            &root.join("plugin/contract.json").to_string_lossy(),
            "--repo",
            &repo.to_string_lossy(),
        ])
        .env("PROBATOR_EVENT", "release")
        .env("PROBATOR_RELEASE_TAG", "v2")
        .env("PROBATOR_RELEASE_COMMIT", "")
        .output()
        .unwrap();
    assert!(
        release.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&release.stderr)
    );
    let stdout = String::from_utf8_lossy(&release.stdout);
    assert!(stdout.contains("reviewing release v2"), "{stdout}");
    assert!(stdout.contains("pass — clean"), "{stdout}");

    // The release receipt records the whole snapshot at the release commit:
    // no base, exactly like every other event.
    let runs = root.join("profile/sample-gate-runs");
    let receipt_path = std::fs::read_dir(&runs)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path()
        .join("report.json");
    let release_receipt: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&receipt_path).unwrap()).unwrap();
    assert_eq!(release_receipt["review_head"], head);
    assert!(release_receipt["review_base"].is_null());

    // A pull request from a local branch against the default branch.
    let default = git(&repo, &["rev-parse", "--abbrev-ref", "HEAD"]);
    git(&repo, &["checkout", "-q", "-b", "feature", &base]);
    std::fs::write(repo.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "feature"]);
    let feature = git(&repo, &["rev-parse", "HEAD"]);
    git(&repo, &["checkout", "-q", &default]);
    let pr = Command::new(REVIEW)
        .args([
            "run",
            "--contract",
            &root.join("plugin/contract.json").to_string_lossy(),
            "--repo",
            &repo.to_string_lossy(),
        ])
        .env("PROBATOR_EVENT", "pr")
        .env("PROBATOR_PR_HEAD", "feature")
        .env("PROBATOR_PR_BASE", &default)
        .output()
        .unwrap();
    assert!(
        pr.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&pr.stderr)
    );
    let stdout = String::from_utf8_lossy(&pr.stdout);
    assert!(
        stdout.contains(&format!("reviewing pull request feature → {default}")),
        "{stdout}"
    );
    assert!(stdout.contains("pass — clean"), "{stdout}");

    // The PR receipt judges the feature head as a whole snapshot too.
    let mut pr_receipt = None;
    for entry in std::fs::read_dir(&runs).unwrap() {
        let report_path = entry.unwrap().path().join("report.json");
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
        if report["review_head"] == serde_json::json!(feature) {
            pr_receipt = Some(report);
        }
    }
    let pr_receipt = pr_receipt.expect("the PR run must have written a receipt");
    assert!(pr_receipt["review_base"].is_null());
}
