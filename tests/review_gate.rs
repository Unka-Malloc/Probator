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
if [ -f "$(dirname "$0")/emit-finding" ]; then
  submit='{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"sample_submit_review","arguments":{"verdict":"block","summary":"planted blocker","coverage":{"structure":{"status":"reviewed","reason":"looked"}},"findings":[{"file":"src/other.rs","line":1,"severity":"blocking","evidence":"planted blocker","impact":"stays standing","remedy":"reopen the file"}],"unknowns":[]}}}'
else
  submit='{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"sample_submit_review","arguments":{"verdict":"pass","summary":"clean","coverage":{"structure":{"status":"reviewed","reason":"looked"}},"findings":[],"unknowns":[]}}}'
fi
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"inventory"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"diff","path":"src/main.rs"}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"diff","path":"src/lib.rs"}}}' \
  '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"diff","path":"src/other.rs"}}}' \
  "$submit" \
  | "$exe" serve --contract "$contract" --run "$run_dir" > "$(dirname "$0")/serve-out.jsonl"
if [ "${FIXTURE_NO_USAGE:-}" = 1 ]; then usage=null; else usage='{"input_tokens":1,"output_tokens":1,"cache_read_tokens":0,"cache_write_tokens":0}'; fi
printf '{"completed":true,"stop_reason":"completed","usage":%s,"profile":{"id":"sample-gate","revision":null,"principal":"synthetic"}}\n' "$usage"
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
    // A real pre-push resolves the pushed ref at the pushed head; the
    // review's ref-moved check refuses a ref left pointing anywhere else.
    git(repo, &["branch", "-f", "nightly", head]);
    run_gate_env(root, repo, base, head, &[])
}

/// The gate run with extra environment, for the operator-ruling channel.
fn run_gate_env(root: &Path, repo: &Path, base: &str, head: &str, env: &[(&str, &Path)]) -> Output {
    let mut command = Command::new(REVIEW);
    command
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
        );
    for (key, value) in env {
        command.env(key, value);
    }
    command.output().unwrap()
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

/// A sealed receipt is the review evidence. A harness whose prompt response
/// omits the optional token counters (DSH ACP does) must not turn a settled
/// verdict into a refused audit; the absence is recorded as null, never
/// fabricated as zero.
#[test]
fn a_sealed_review_without_token_usage_still_settles() {
    let (guard, base, head) = fixture();
    let (root, repo) = (guard.0.clone(), guard.0.join("repo"));
    let run = run_gate_env(
        &root,
        &repo,
        &base,
        &head,
        &[("FIXTURE_NO_USAGE", Path::new("1"))],
    );
    assert!(
        run.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let runs = root.join("profile/sample-gate-runs");
    let run_dir = std::fs::read_dir(&runs)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let completion: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run_dir.join("completion.json")).unwrap())
            .unwrap();
    assert_eq!(completion["completed"], true);
    assert_eq!(completion["has_report"], true);
    assert!(completion["outcome"]["usage"].is_null());
}

/// A session that settles without calling the submit tool: the run keeps its
/// resume state (it was paid for and can be continued) but produces no sealed
/// receipt.
const NO_REPORT_RUNNER: &str = r#"#!/bin/bash
set -euo pipefail
printf '{"completed":true,"stop_reason":"completed","usage":{"input_tokens":1,"output_tokens":1,"cache_read_tokens":0,"cache_write_tokens":0},"profile":{"id":"sample-gate","revision":null,"principal":"synthetic"}}\n'
"#;

/// Point the checker's installation at a different fixture runner.
fn install_runner(root: &Path, runner: &Path) {
    let path = root.join("plugin/installation.json");
    let mut settings: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    settings["agent_runner"] = serde_json::json!(runner.to_string_lossy());
    std::fs::write(&path, serde_json::to_string(&settings).unwrap()).unwrap();
}

fn run_dirs(runs: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(runs)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    dirs.sort();
    dirs
}

/// Resume state belongs to a repository, not just to a commit range and
/// reviewer. Two checkouts can carry identical commits and the same
/// checker/profile; a session that settled on one without sealing a receipt
/// must never be continued while reviewing the other.
#[test]
fn a_session_on_one_repository_is_never_resumed_for_another() {
    let (guard, base, head) = fixture();
    let (root, repo_a) = (guard.0.clone(), guard.0.join("repo"));
    // The second checkout replays the same commits, so a resume key that
    // ignores repository identity collides exactly.
    let repo_b = root.join("repo-b");
    let copied = Command::new("cp")
        .args(["-R", &repo_a.to_string_lossy(), &repo_b.to_string_lossy()])
        .status()
        .unwrap();
    assert!(copied.success(), "the second checkout must be created");
    assert_eq!(git(&repo_b, &["rev-parse", "HEAD"]), head);

    // Repo A's session settles without a report: the run directory stays
    // resumable, exactly as an interrupted review does.
    let incomplete = root.join("no-report-runner.sh");
    std::fs::write(&incomplete, NO_REPORT_RUNNER).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&incomplete, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    install_runner(&root, &incomplete);
    let first = run_gate(&root, &repo_a, &base, &head);
    assert!(
        !first.status.success(),
        "a session without a sealed report must refuse: {}",
        String::from_utf8_lossy(&first.stdout)
    );
    let runs = root.join("profile/sample-gate-runs");
    let first_dirs = run_dirs(&runs);
    assert_eq!(first_dirs.len(), 1, "repo A gets its own run directory");
    assert!(!first_dirs[0].join("report.json").exists());
    let repo_a_identity = format!(
        "local:{}",
        std::fs::canonicalize(&repo_a).unwrap().display()
    );
    let a_key: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(first_dirs[0].join("resume.json")).unwrap())
            .unwrap();
    assert_eq!(a_key["repo"], serde_json::json!(repo_a_identity));

    // The same checker/profile now reviews repo B at the same commits. It
    // must open a fresh run directory instead of continuing A's session.
    install_runner(&root, &root.join("runner.sh"));
    let second = run_gate(&root, &repo_b, &base, &head);
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let dirs = run_dirs(&runs);
    assert_eq!(
        dirs.len(),
        2,
        "repo B must not resume repo A's run directory"
    );
    let repo_b_identity = format!(
        "local:{}",
        std::fs::canonicalize(&repo_b).unwrap().display()
    );
    let b_dir = dirs
        .iter()
        .find(|dir| {
            std::fs::read_to_string(dir.join("resume.json"))
                .ok()
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
                .is_some_and(|key| key["repo"] == serde_json::json!(repo_b_identity))
        })
        .expect("repo B's run carries its own repository identity");
    let receipt: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(b_dir.join("report.json")).unwrap()).unwrap();
    assert_eq!(receipt["repo"], serde_json::json!(repo_b_identity));
    assert_eq!(receipt["review_head"], head);
    assert!(
        !first_dirs[0].join("report.json").exists(),
        "repo A's unfinished session stays untouched"
    );
}

/// A sealed pass is a receipt for the repository it judged, not for bare
/// commit ids. Two checkouts can carry identical commits and the same
/// checker/profile; the second must still pay for its own review.
#[test]
fn a_sealed_receipt_on_one_repository_is_never_reused_for_another() {
    let (guard, base, head) = fixture();
    let (root, repo_a) = (guard.0.clone(), guard.0.join("repo"));
    let repo_b = root.join("repo-b");
    let copied = Command::new("cp")
        .args(["-R", &repo_a.to_string_lossy(), &repo_b.to_string_lossy()])
        .status()
        .unwrap();
    assert!(copied.success(), "the second checkout must be created");
    assert_eq!(
        git(&repo_b, &["rev-parse", "HEAD"]),
        head,
        "the two checkouts carry identical commits"
    );

    let first = run_gate(&root, &repo_a, &base, &head);
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let runs = root.join("profile/sample-gate-runs");
    let repo_a_identity = format!(
        "local:{}",
        std::fs::canonicalize(&repo_a).unwrap().display()
    );
    let first_dirs = run_dirs(&runs);
    assert_eq!(first_dirs.len(), 1);
    let receipt_a: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(first_dirs[0].join("report.json")).unwrap())
            .unwrap();
    assert_eq!(receipt_a["repo"], serde_json::json!(repo_a_identity));
    assert_eq!(receipt_a["verdict"], "pass");

    let marker = root.join("runner-was-here");
    assert!(marker.exists());
    std::fs::remove_file(&marker).unwrap();
    let second = run_gate(&root, &repo_b, &base, &head);
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        !stdout.contains("already passed its semantic review"),
        "repo B must not inherit repo A's sealed pass: {stdout}"
    );
    assert!(
        marker.exists(),
        "the reviewer must run for repo B's own receipt"
    );

    let repo_b_identity = format!(
        "local:{}",
        std::fs::canonicalize(&repo_b).unwrap().display()
    );
    let dirs = run_dirs(&runs);
    assert_eq!(dirs.len(), 2, "repo B gets its own run directory");
    let receipt_b: serde_json::Value = dirs
        .iter()
        .filter_map(|dir| {
            let raw = std::fs::read_to_string(dir.join("report.json")).ok()?;
            serde_json::from_str::<serde_json::Value>(&raw).ok()
        })
        .find(|report| report["repo"] == serde_json::json!(repo_b_identity))
        .expect("repo B's run seals a receipt naming that repository");
    assert_eq!(receipt_b["verdict"], "pass");
    assert_eq!(receipt_b["review_head"], head);
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

/// A runner that submits one blocking finding instead of a pass, so the
/// operator-ruling boundary can be exercised black-box.
const FAILING_RUNNER: &str = r#"#!/bin/bash
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
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"inventory"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"diff","path":"src/main.rs"}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"diff","path":"src/lib.rs"}}}' \
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"sample_submit_review","arguments":{"verdict":"block","summary":"a cost regression","coverage":{"structure":{"status":"reviewed","reason":"looked"}},"findings":[{"file":"src/main.rs","line":1,"severity":"blocking","evidence":"the added println costs money","impact":"one extra call per request","remedy":"remove the println"}],"unknowns":[]}}}' \
  | "$exe" serve --contract "$contract" --run "$run_dir" >/dev/null
printf '{"completed":true,"stop_reason":"completed","usage":{"input_tokens":1,"output_tokens":1,"cache_read_tokens":0,"cache_write_tokens":0},"profile":{"id":"sample-gate","revision":null,"principal":"synthetic"}}\n'
"#;

fn ssh_keygen(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new("ssh-keygen")
        .args(args)
        .output()
        .expect("ssh-keygen is required for the signature tests")
}

/// A signed ledger overruling the failing runner's finding, with the
/// allowed-signers anchor that verifies it.
fn signed_ledger(root: &Path) -> (PathBuf, PathBuf) {
    signed_ledger_for(root, "src/main.rs", 1)
}

/// The same signed ruling for one finding location, so a carried blocked
/// finding can be adjudicated black-box as well.
fn signed_ledger_for(root: &Path, file: &str, line: u64) -> (PathBuf, PathBuf) {
    let key = root.join("ruling-key");
    let keygen = ssh_keygen(&[
        "-q".as_ref(),
        "-t".as_ref(),
        "ed25519".as_ref(),
        "-N".as_ref(),
        "".as_ref(),
        "-f".as_ref(),
        key.as_os_str(),
    ]);
    assert!(
        keygen.status.success(),
        "ssh-keygen keygen failed: {}",
        String::from_utf8_lossy(&keygen.stderr)
    );
    let public = std::fs::read_to_string(root.join("ruling-key.pub")).unwrap();
    let anchor = root.join("ruling-anchor");
    std::fs::write(
        &anchor,
        format!("rulings {}", public.trim_end_matches('\n')),
    )
    .unwrap();
    let ledger = root.join("objections.toml");
    std::fs::write(
        &ledger,
        format!(
            "[[ruling]]\nid = \"ob-test\"\nchecker = \"sample-gate\"\nkind = \"finding\"\nfile = \"{file}\"\nline = {line}\nverdict = \"overruled\"\n"
        ),
    )
    .unwrap();
    let signature = ssh_keygen(&[
        "-Y".as_ref(),
        "sign".as_ref(),
        "-n".as_ref(),
        "test-rulings".as_ref(),
        "-f".as_ref(),
        key.as_os_str(),
        ledger.as_os_str(),
    ]);
    assert!(
        signature.status.success(),
        "ssh-keygen sign failed: {}",
        String::from_utf8_lossy(&signature.stderr)
    );
    (ledger, anchor)
}

fn newest_report(root: &Path) -> serde_json::Value {
    let runs = root.join("profile/sample-gate-runs");
    let mut newest: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(runs).unwrap().flatten() {
        let path = entry.path().join("report.json");
        let Ok(modified) = path.metadata().map(|meta| meta.modified().unwrap()) else {
            continue;
        };
        if newest.as_ref().is_none_or(|(time, _)| modified > *time) {
            newest = Some((modified, path));
        }
    }
    let (_, path) = newest.expect("a run must have written a report");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn a_signed_operator_ruling_waives_the_gate_finding() {
    let (guard, base, head) = fixture();
    let root = guard.0.clone();
    let repo = root.join("repo");
    let runner = root.join("runner.sh");
    std::fs::write(&runner, FAILING_RUNNER).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    // Without a configured ledger the blocking finding stands.
    let refused = run_gate(&root, &repo, &base, &head);
    assert!(!refused.status.success());
    assert_eq!(newest_report(&root)["verdict"], "block");

    // A signature-verified ruling for this checker, file and line stands in
    // for the fix; the sealed report keeps the checker's own verdict and the
    // waiver record lands beside it.
    let (ledger, anchor) = signed_ledger(&root);
    let waived = run_gate_env(
        &root,
        &repo,
        &base,
        &head,
        &[
            ("PROBATOR_RULINGS_LEDGER", &ledger),
            ("PROBATOR_RULINGS_ANCHOR", &anchor),
        ],
    );
    assert!(
        waived.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&waived.stderr)
    );
    let stdout = String::from_utf8_lossy(&waived.stdout);
    assert!(
        stdout.contains("outcome waived by signed operator ruling"),
        "{stdout}"
    );
    let receipt = newest_report(&root);
    assert_eq!(receipt["verdict"], "block", "the report is not rewritten");
    let run_dir = std::fs::read_dir(root.join("profile/sample-gate-runs"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.join("waivers.json").is_file())
        .expect("the waiver record must land beside the sealed report");
    let waivers: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run_dir.join("waivers.json")).unwrap())
            .unwrap();
    assert_eq!(
        waivers["objection_waived"],
        serde_json::json!(["src/main.rs:1"])
    );

    // A ledger edited after signing no longer verifies: the finding stands
    // again and no waiver record is written.
    let mut tampered = std::fs::read_to_string(&ledger).unwrap();
    tampered.push_str("# edited after signing\n");
    std::fs::write(&ledger, tampered).unwrap();
    let forged = run_gate_env(
        &root,
        &repo,
        &base,
        &head,
        &[
            ("PROBATOR_RULINGS_LEDGER", &ledger),
            ("PROBATOR_RULINGS_ANCHOR", &anchor),
        ],
    );
    assert!(!forged.status.success(), "a forged ledger waives nothing");
    assert!(
        !String::from_utf8_lossy(&forged.stdout)
            .contains("outcome waived by signed operator ruling")
    );
}

/// The adjudication fixture runner: a probe session lists the inventory —
/// the adjudication item ids and the increment's changed paths come from it
/// rather than being guessed — then the answering session diffs every
/// changed path and submits. Flag files steer the verdict:
/// `adjudicate-allow` answers the suspect as a plain identifier,
/// `adjudicate-confirm` answers it as literal key material with the block
/// verdict an honest review gives it, and `probe-unanswered` first submits
/// without inspecting or answering to exercise the in-band refusal.
const ADJUDICATION_RUNNER: &str = r#"#!/bin/bash
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
here="$(dirname "$0")"
touch "$here/runner-was-here"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"inventory"}}}' \
  | "$exe" serve --contract "$contract" --run "$run_dir" > "$here/probe-out.jsonl"
item="$(sed -n 's/.*\\"item\\":\\"\([0-9a-f]\{64\}\)\\".*/\1/p' "$here/probe-out.jsonl" | head -n1)"
lines=(
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}'
  '{"jsonrpc":"2.0","method":"notifications/initialized"}'
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"inventory"}}}'
)
request=10
while IFS= read -r path; do
  if [ -n "$path" ]; then
    lines+=('{"jsonrpc":"2.0","id":'"$request"',"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"diff","path":"'"$path"'"}}}')
    request=$((request + 1))
  fi
done <<EOF
$(sed -n 's/.*\\"changed\\":\[\([^]]*\)\].*/\1/p' "$here/probe-out.jsonl" | head -n1 | tr ',' '\n' | sed 's/\\"//g')
EOF
if [ -f "$here/probe-unanswered" ]; then
  lines+=('{"jsonrpc":"2.0","id":'"$request"',"method":"tools/call","params":{"name":"sample_submit_review","arguments":{"verdict":"pass","summary":"clean","coverage":{"structure":{"status":"reviewed","reason":"looked"}},"findings":[],"unknowns":[]}}}')
  request=$((request + 1))
fi
verdict='pass' summary='clean' answer=''
if [ -n "$item" ] && [ -f "$here/adjudicate-confirm" ]; then
  answer=',"adjudications":[{"item":"'"$item"'","key":true,"reason":"the hex literal is reusable key material"}]'
  verdict='block' summary='literal test key confirmed'
elif [ -n "$item" ] && [ -f "$here/adjudicate-allow" ]; then
  answer=',"adjudications":[{"item":"'"$item"'","key":false,"reason":"identifier naming the sandbox endpoint, not credential material"}]'
fi
if [ -n "$item" ] && { [ -f "$here/adjudicate-allow" ] || [ -f "$here/adjudicate-confirm" ]; }; then
  lines+=('{"jsonrpc":"2.0","id":'"$request"',"method":"tools/call","params":{"name":"sample_context","arguments":{"operation":"adjudication","item":"'"$item"'"}}}')
  request=$((request + 1))
fi
if [ "$verdict" = "block" ]; then
  findings='[{"file":"tests/test_keys.py","line":1,"severity":"blocking","evidence":"the hex literal is reusable key material","impact":"a published default anyone can replay","remedy":"mint the key at run time"}]'
else
  findings='[]'
fi
lines+=('{"jsonrpc":"2.0","id":'"$request"',"method":"tools/call","params":{"name":"sample_submit_review","arguments":{"verdict":"'"$verdict"'","summary":"'"$summary"'","coverage":{"structure":{"status":"reviewed","reason":"looked"}},"findings":'"$findings"',"unknowns":[]'"$answer"'}}}')
printf '%s\n' "${lines[@]}" | "$exe" serve --contract "$contract" --run "$run_dir" > "$here/serve-out.jsonl"
printf '{"completed":true,"stop_reason":"completed","usage":{"input_tokens":1,"output_tokens":1,"cache_read_tokens":0,"cache_write_tokens":0},"profile":{"id":"sample-gate","revision":null,"principal":"synthetic"}}\n'
"#;

/// A signed verdict-level ruling for one head, so the deterministic
/// refusal's appeal boundary can be exercised black-box.
fn signed_verdict_ledger(root: &Path, head: &str) -> (PathBuf, PathBuf) {
    let key = root.join("verdict-key");
    let keygen = ssh_keygen(&[
        "-q".as_ref(),
        "-t".as_ref(),
        "ed25519".as_ref(),
        "-N".as_ref(),
        "".as_ref(),
        "-f".as_ref(),
        key.as_os_str(),
    ]);
    assert!(
        keygen.status.success(),
        "ssh-keygen keygen failed: {}",
        String::from_utf8_lossy(&keygen.stderr)
    );
    let public = std::fs::read_to_string(root.join("verdict-key.pub")).unwrap();
    let anchor = root.join("verdict-anchor");
    std::fs::write(
        &anchor,
        format!("rulings {}", public.trim_end_matches('\n')),
    )
    .unwrap();
    let ledger = root.join("verdict-objections.toml");
    std::fs::write(
        &ledger,
        format!(
            "[[ruling]]\nid = \"ob-verdict\"\nchecker = \"sample-gate\"\nkind = \"verdict\"\nhead = \"{head}\"\nverdict = \"overruled\"\n"
        ),
    )
    .unwrap();
    let signature = ssh_keygen(&[
        "-Y".as_ref(),
        "sign".as_ref(),
        "-n".as_ref(),
        "test-rulings".as_ref(),
        "-f".as_ref(),
        key.as_os_str(),
        ledger.as_os_str(),
    ]);
    assert!(
        signature.status.success(),
        "ssh-keygen sign failed: {}",
        String::from_utf8_lossy(&signature.stderr)
    );
    (ledger, anchor)
}

/// The test-key sweep reports a suspect rather than refusing outright: the
/// deterministic stage stays clean, but the review cannot seal until the
/// reviewer opens the item through the adjudication operation and answers
/// it in the verdict. An identifier answer lands in the sealed ledger under
/// the suspect's content fingerprint — the same head reuses its receipt,
/// and a new head carrying the identical line is never asked about it.
fn test_key_contract(root: &Path, repo: &Path, line: &str) -> String {
    std::fs::create_dir_all(repo.join("tests")).unwrap();
    std::fs::write(repo.join("tests/test_keys.py"), format!("{line}\n")).unwrap();
    git(repo, &["add", "-A"]);
    git(repo, &["commit", "-qm", "test keys"]);
    let head = git(repo, &["rev-parse", "HEAD"]);
    let mut contract: serde_json::Value = serde_json::from_str(CONTRACT).unwrap();
    contract["stage1"] = serde_json::json!({
        "label": "deterministic",
        "rules": [{
            "id": "test-key-generation",
            "title": "test keys are generated, never defaulted",
            "kind": "builtin",
            "builtin": "test-key-generation"
        }]
    });
    contract["tools"]["context"] =
        serde_json::json!(["inventory", "list", "diff", "read", "find", "adjudication"]);
    std::fs::write(
        root.join("plugin/contract.json"),
        serde_json::to_string_pretty(&contract).unwrap(),
    )
    .unwrap();
    head
}

#[test]
fn a_test_key_suspect_is_adjudicated_not_refused() {
    let (guard, base, _head) = fixture();
    let root = guard.0.clone();
    let repo = root.join("repo");
    let runner = root.join("runner.sh");
    std::fs::write(&runner, ADJUDICATION_RUNNER).unwrap();
    let head = test_key_contract(&root, &repo, "SCOPE_KEY = \"sandbox-scope-label\"");
    std::fs::write(root.join("probe-unanswered"), "").unwrap();
    std::fs::write(root.join("adjudicate-allow"), "").unwrap();

    let first = run_gate(&root, &repo, &base, &head);
    let stdout = String::from_utf8_lossy(&first.stdout);
    assert!(
        first.status.success(),
        "stderr: {}\nstdout: {stdout}",
        String::from_utf8_lossy(&first.stderr)
    );
    // The stage names the suspect instead of refusing it.
    assert!(stdout.contains("deterministic clean"), "{stdout}");
    assert!(
        stdout.contains("adjudication tests/test_keys.py"),
        "{stdout}"
    );
    assert!(!stdout.contains("refused: test-key-default"), "{stdout}");

    // The submission channel enforced the adjudication: the verdict sent
    // before the item was opened was refused in-band, and only the session
    // that inspected and answered sealed.
    let served = std::fs::read_to_string(root.join("serve-out.jsonl")).unwrap();
    assert!(served.contains("was not inspected"), "{served}");

    // The identifier answer is recorded in the sealed adjudication ledger
    // under the suspect's content fingerprint.
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("adjudications/sample-gate.json")).unwrap(),
    )
    .unwrap();
    assert!(
        ledger
            .as_object()
            .unwrap()
            .values()
            .any(|entry| entry["verdict"] == "identifier"),
        "{ledger}"
    );

    // The identical head reuses the sealed receipt: no new review, no
    // re-asked suspect.
    std::fs::remove_file(root.join("runner-was-here")).unwrap();
    let again = run_gate(&root, &repo, &base, &head);
    assert!(again.status.success());
    assert!(
        !root.join("runner-was-here").exists(),
        "a sealed receipt must not reopen the review"
    );

    // A new head carrying the identical suspect line inherits the answer:
    // the reviewer still pays for the increment, but the scope holds no
    // adjudication item, so a plain verdict seals.
    std::fs::remove_file(root.join("probe-unanswered")).unwrap();
    std::fs::remove_file(root.join("adjudicate-allow")).unwrap();
    std::fs::write(repo.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "lib"]);
    let head2 = git(&repo, &["rev-parse", "HEAD"]);
    let second = run_gate(&root, &repo, &base, &head2);
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        root.join("runner-was-here").exists(),
        "a new head still pays a review"
    );
}

/// A suspect confirmed as literal key material is a blocking finding like
/// any other: it stands across commits while the blob that carries it stays
/// inside the published range. Rewriting the line raises a fresh suspect
/// the reviewer answers anew — but the confirmed blob still publishes, so
/// the gate keeps refusing on the confirmed verdict.
#[test]
fn a_confirmed_test_key_stays_blocked_while_its_blob_publishes() {
    let (guard, base, _head) = fixture();
    let root = guard.0.clone();
    let repo = root.join("repo");
    let runner = root.join("runner.sh");
    std::fs::write(&runner, ADJUDICATION_RUNNER).unwrap();
    let material = ["cafe0123", "4567beef"].concat();
    let head = test_key_contract(&root, &repo, &format!("API_KEY = \"{material}\""));
    std::fs::write(root.join("adjudicate-confirm"), "").unwrap();

    let first = run_gate(&root, &repo, &base, &head);
    assert!(
        !first.status.success(),
        "a confirmed test key must refuse the gate"
    );
    let report = newest_report(&root);
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["file"] == "tests/test_keys.py"
                && finding["severity"] == "blocking"),
        "{report}"
    );

    // An unrelated commit keeps the same suspect line: the recorded verdict
    // confirms it again, no re-asked adjudication, still refused.
    std::fs::write(repo.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "lib"]);
    let head2 = git(&repo, &["rev-parse", "HEAD"]);
    let second = run_gate(&root, &repo, &base, &head2);
    assert!(
        !second.status.success(),
        "the confirmed suspect still stands on an unchanged line"
    );

    // Rewrite the suspect line: the new content is a fresh suspect the
    // reviewer answers as an identifier — but the removed blob still sits
    // inside the published range, so the recorded key-material verdict on
    // it keeps the gate refused.
    std::fs::remove_file(root.join("adjudicate-confirm")).unwrap();
    std::fs::write(root.join("adjudicate-allow"), "").unwrap();
    std::fs::write(
        repo.join("tests/test_keys.py"),
        "SCOPE_KEY = \"sandbox-scope-label\"\n",
    )
    .unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "rename the suspect"]);
    let head3 = git(&repo, &["rev-parse", "HEAD"]);
    let third = run_gate(&root, &repo, &base, &head3);
    assert!(
        !third.status.success(),
        "the confirmed blob still publishes; stderr: {}\nstdout: {}",
        String::from_utf8_lossy(&third.stderr),
        String::from_utf8_lossy(&third.stdout)
    );
    // The fresh suspect was answered — the refusal stands on the earlier
    // confirmation, not on an unanswered item.
    let report = newest_report(&root);
    assert!(
        report["adjudications"]
            .as_array()
            .is_some_and(|answers| answers.iter().any(|answer| answer["key"] == false)),
        "{report}"
    );
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["origin"] == "adjudication"
                && finding["file"] == "tests/test_keys.py"),
        "{report}"
    );
}

/// A confirmed test key is appealable like every other finding: a signed
/// verdict ruling on this head and checker waives the refused outcome.
#[test]
fn a_verdict_ruling_waives_the_adjudicated_refusal() {
    let (guard, base, _head) = fixture();
    let root = guard.0.clone();
    let repo = root.join("repo");
    let runner = root.join("runner.sh");
    std::fs::write(&runner, ADJUDICATION_RUNNER).unwrap();
    let material = ["cafe0123", "4567beef"].concat();
    let head = test_key_contract(&root, &repo, &format!("API_KEY = \"{material}\""));
    std::fs::write(root.join("adjudicate-confirm"), "").unwrap();

    let refused = run_gate(&root, &repo, &base, &head);
    assert!(!refused.status.success());

    let (ledger, anchor) = signed_verdict_ledger(&root, &head);
    git(&repo, &["branch", "-f", "nightly", &head]);
    let ruled = run_gate_env(
        &root,
        &repo,
        &base,
        &head,
        &[
            ("PROBATOR_RULINGS_LEDGER", &ledger),
            ("PROBATOR_RULINGS_ANCHOR", &anchor),
        ],
    );
    let stdout = String::from_utf8_lossy(&ruled.stdout);
    assert!(
        ruled.status.success(),
        "the adjudicated refusal yields to a signed verdict ruling; stderr: {}\nstdout: {stdout}",
        String::from_utf8_lossy(&ruled.stderr)
    );
    assert!(
        stdout.contains("outcome waived by signed operator ruling"),
        "{stdout}"
    );
}

/// The coverage cursor moves forward on the tape: a head the checker already
/// covered is never re-opened — the next run's whole review surface is the
/// increment since it, and the sealed receipt records that base.
#[test]
fn the_coverage_cursor_reviews_only_the_increment() {
    let (guard, base, _head) = fixture();
    let (root, repo) = (guard.0.clone(), guard.0.join("repo"));
    // lib.rs joins the tree before the first review, so a whole-tree
    // inventory would list two paths while the later increment lists one.
    std::fs::write(repo.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "lib"]);
    let head1 = git(&repo, &["rev-parse", "HEAD"]);
    let first = run_gate(&root, &repo, &base, &head1);
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    std::fs::write(
        repo.join("src/main.rs"),
        "fn main() { println!(\"v3\"); }\n",
    )
    .unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "bump"]);
    let head2 = git(&repo, &["rev-parse", "HEAD"]);
    std::fs::remove_file(root.join("runner-was-here")).unwrap();
    let second = run_gate(&root, &repo, &base, &head2);
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        stdout.contains(&format!("reviews the increment since {}", &head1[..12])),
        "{stdout}"
    );
    assert!(
        root.join("runner-was-here").exists(),
        "a new head still pays a review"
    );

    // The receipt seals the cursor as its base and names the repository —
    // coverage binds to this repository's identity, never to a bare commit.
    let runs = root.join("profile/sample-gate-runs");
    let mut receipt = None;
    for entry in std::fs::read_dir(&runs).unwrap() {
        let report: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(entry.unwrap().path().join("report.json")).unwrap(),
        )
        .unwrap();
        if report["review_head"] == serde_json::json!(head2) {
            receipt = Some(report);
        }
    }
    let receipt = receipt.expect("the increment run must seal a receipt");
    assert_eq!(receipt["review_base"], head1);
    assert!(
        receipt["repo"]
            .as_str()
            .unwrap_or_default()
            .starts_with("local:")
    );

    // The reviewer was shown only the increment: the serve log's inventory
    // response names src/main.rs and never src/lib.rs.
    let serve_log = std::fs::read_to_string(root.join("serve-out.jsonl")).unwrap();
    let inventory = serve_log
        .lines()
        .find(|line| line.contains("\"id\":2"))
        .expect("the inventory response must be logged");
    assert!(inventory.contains("src/main.rs"), "{inventory}");
    assert!(!inventory.contains("src/lib.rs"), "{inventory}");

    // The coverage ledger recorded the judgement: a small registry entry,
    // not an archaeological scan of reports, is what moves the tape forward.
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("cursors/sample-gate.json")).unwrap(),
    )
    .unwrap();
    let entry = ledger.as_object().unwrap().values().next().unwrap();
    assert_eq!(entry["head"], head2);
    assert_eq!(entry["verdict"], "pass");
    assert!(entry["findings"].as_array().unwrap().is_empty());
}

/// A refused verdict's blocking findings ride the cursor: while their files
/// stay outside the increment they keep refusing the gate, and they clear
/// only when a later range re-opens them.
#[test]
fn blocking_findings_carry_until_their_file_is_touched() {
    let (guard, base, _head) = fixture();
    let (root, repo) = (guard.0.clone(), guard.0.join("repo"));
    std::fs::write(repo.join("src/other.rs"), "pub fn o() {}\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "other"]);
    let head1 = git(&repo, &["rev-parse", "HEAD"]);

    let marker = root.join("emit-finding");
    std::fs::write(&marker, "").unwrap();
    let first = run_gate(&root, &repo, &base, &head1);
    assert!(
        !first.status.success(),
        "a blocking finding refuses the gate: {}",
        String::from_utf8_lossy(&first.stdout)
    );

    // The fix touches a different file: the blocker stays outside the
    // increment and keeps refusing even though the fresh verdict passes.
    std::fs::remove_file(&marker).unwrap();
    std::fs::write(
        repo.join("src/main.rs"),
        "fn main() { println!(\"v3\"); }\n",
    )
    .unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "bump"]);
    let head2 = git(&repo, &["rev-parse", "HEAD"]);
    let second = run_gate(&root, &repo, &base, &head2);
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(
        !second.status.success(),
        "the carried blocker still refuses the gate: {stdout} stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        stdout.contains("1 blocking finding(s) carried"),
        "{stdout} stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    // The fresh review passed; the standing refusal is recorded beside the
    // receipt as carried evidence, not inside the checker's own verdict.
    let runs = root.join("profile/sample-gate-runs");
    let mut carried = None;
    for entry in std::fs::read_dir(&runs).unwrap() {
        let path = entry.unwrap().path();
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path.join("report.json")).unwrap())
                .unwrap();
        if report["review_head"] == serde_json::json!(head2) {
            carried = std::fs::read_to_string(path.join("carried.json")).ok();
        }
    }
    let carried = carried.expect("the increment run must record its carried findings");
    assert!(carried.contains("src/other.rs"), "{carried}");

    // The ledger keeps the standing finding at the new head: the tape moved,
    // and the refusal it carries did not evaporate — re-pushing the same
    // head replays it without paying another review.
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("cursors/sample-gate.json")).unwrap(),
    )
    .unwrap();
    let entry = ledger.as_object().unwrap().values().next().unwrap();
    assert_eq!(entry["head"], head2);
    assert_eq!(entry["verdict"], "pass");
    assert_eq!(entry["findings"].as_array().unwrap().len(), 1);
    std::fs::remove_file(root.join("runner-was-here")).unwrap();
    let repeat = run_gate(&root, &repo, &base, &head2);
    assert!(
        !repeat.status.success(),
        "the standing blocker refuses the same head again"
    );
    assert!(
        !root.join("runner-was-here").exists(),
        "the same head never pays for a second review"
    );
    let stdout = String::from_utf8_lossy(&repeat.stdout);
    assert!(stdout.contains("was already refused"), "{stdout}");

    // A signature-verified operator ruling for the carried finding accepts
    // the standing refusal: the gate opens without paying for a second
    // review, and the waiver record lands beside the receipt that carries it.
    let (rulings, anchor) = signed_ledger_for(&root, "src/other.rs", 1);
    let waived = run_gate_env(
        &root,
        &repo,
        &base,
        &head2,
        &[
            ("PROBATOR_RULINGS_LEDGER", &rulings),
            ("PROBATOR_RULINGS_ANCHOR", &anchor),
        ],
    );
    assert!(
        waived.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&waived.stderr)
    );
    let stdout = String::from_utf8_lossy(&waived.stdout);
    assert!(
        stdout.contains("outcome waived by signed operator ruling"),
        "{stdout}"
    );
    assert!(
        !root.join("runner-was-here").exists(),
        "a waived carried blocker still never pays for a second review"
    );
    let mut waiver_record = None;
    for entry in std::fs::read_dir(root.join("profile/sample-gate-runs")).unwrap() {
        let path = entry.unwrap().path();
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path.join("report.json")).unwrap())
                .unwrap();
        if report["review_head"] == serde_json::json!(head2) {
            waiver_record = std::fs::read_to_string(path.join("waivers.json")).ok();
        }
    }
    let waiver_record = waiver_record.expect("the carried finding's waiver must be recorded");
    assert!(waiver_record.contains("src/other.rs:1"), "{waiver_record}");

    // Re-opening the finding's file lets the new verdict speak for it.
    std::fs::write(repo.join("src/other.rs"), "pub fn o() -> u8 { 1 }\n").unwrap();
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-qm", "fix other"]);
    let head3 = git(&repo, &["rev-parse", "HEAD"]);
    let third = run_gate(&root, &repo, &base, &head3);
    assert!(
        third.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&third.stderr)
    );
    let stdout = String::from_utf8_lossy(&third.stdout);
    assert!(stdout.contains("pass — clean"), "{stdout}");
}
