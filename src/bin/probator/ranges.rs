//! Resolve what a push, a pull request or a release is about to publish.
//!
//! Every event judges the whole tree at its head commit: the auditors hold the
//! same global view from the first review on, so no later event can widen the
//! review object after an earlier one passed. Three properties matter:
//!
//! * the review object is the immutable whole-tree snapshot at `head` - one
//!   target per distinct head commit, with no base to compare against;
//! * a merge request whose head is not local is fetched into FETCH_HEAD only;
//! * a release is judged as the whole tree it publishes, exactly like a push.

use crate::stage1::Target;
use std::process::Command;

fn git(repo: &str, args: &[&str]) -> Result<std::process::Output, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|error| format!("Git could not read the review snapshot: {error}"))?;
    if !output.status.success() {
        return Err("Git could not read the review snapshot".to_string());
    }
    Ok(output)
}

fn rev(repo: &str, spec: &str) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", spec])
        .output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        _ => String::new(),
    }
}

/// Whether a commit object is in this object store. The remote sha a push
/// reports is the remote's live tip: a checkout that has not fetched since
/// the remote moved cannot diff against it, and then the whole snapshot is
/// the review object - the same shape a first push takes.
fn commit_known(repo: &str, sha: &str) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "-e", &format!("{sha}^{{commit}}")])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn short_ref(name: &str) -> &str {
    name.strip_prefix("refs/heads/").unwrap_or(name)
}

/// True when a remote-tracking ref already contains the commit.
fn published_elsewhere(repo: &str, commit: &str) -> bool {
    crate::git::refs_containing(std::path::Path::new(repo), commit, &["refs/remotes"])
}

/// Fetch a merge request's head into FETCH_HEAD; creates no ref.
fn fetch_pull_head(repo: &str, number: &str) -> Result<(), String> {
    git(
        repo,
        &[
            "fetch",
            "--no-tags",
            "--quiet",
            "origin",
            &format!("refs/pull/{number}/head"),
        ],
    )
    .map(|_| ())
    .map_err(|_| "The merge request head could not be fetched for review".to_string())
}

/// One whole-snapshot target at the resolved head commit.
///
/// `base` is the published tip the operation builds on - the remote ref's own
/// sha for a push, the base branch head for a pull request. When set, two
/// consumers use it: stage-one scans the blobs the `base..head` range
/// introduces (so a credential committed and removed inside the range still
/// gets caught), and the evidence server's `diff` tool shows the real
/// `base..head` diff instead of a whole-tree one - unchanged files page to
/// empty, which keeps the coverage contract while dropping the paid review to
/// the actual increment. Stage-one's own scans stay whole-tree either way.
fn snapshot(
    kind: &str,
    label: String,
    base: Option<String>,
    head: String,
    ref_: Option<String>,
) -> Target {
    Target {
        kind: kind.to_string(),
        label,
        base,
        head,
        ref_,
        scope: "snapshot".to_string(),
        fallback: String::new(),
    }
}

/// The whole tree a release publishes, at its resolved commit.
fn release_target(repo: &str, tag: &str, commit: &str) -> Result<Target, String> {
    let mut head = if commit.is_empty() {
        String::new()
    } else {
        rev(repo, &format!("{commit}^{{commit}}"))
    };
    if head.is_empty() && !tag.is_empty() {
        head = rev(repo, &format!("{tag}^{{commit}}"));
    }
    if head.is_empty() {
        return Err("The release commit is not in this checkout; publish this release from the tagged working tree".to_string());
    }
    let label = format!(
        "release {}",
        if tag.is_empty() {
            &head[..12.min(head.len())]
        } else {
            tag
        }
    );
    Ok(snapshot("release", label, None, head, None))
}

/// The push refs, pull request or release to audit. `vars` carries the
/// PROBATOR_* environment, injected so tests never mutate process state.
pub fn ranges_from(
    repo: &str,
    event: &str,
    vars: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<Target>, String> {
    let var = |name: &str| {
        vars.get(name)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string()
    };
    if event == "release" {
        return Ok(vec![release_target(
            repo,
            &var("PROBATOR_RELEASE_TAG"),
            &var("PROBATOR_RELEASE_COMMIT"),
        )?]);
    }
    if event == "pr" {
        let head_ref = var("PROBATOR_PR_HEAD");
        let base_ref = var("PROBATOR_PR_BASE");
        let number = var("PROBATOR_PR_NUMBER");
        // The range the request proposes: the base branch's remote-tracking
        // head, or origin/HEAD when the base is left at the default.
        let base = if base_ref.is_empty() {
            rev(repo, "refs/remotes/origin/HEAD^{commit}")
        } else {
            rev(
                repo,
                &format!("refs/remotes/origin/{}^{{commit}}", short_ref(&base_ref)),
            )
        };
        let (head, label);
        if !number.is_empty() {
            fetch_pull_head(repo, &number)?;
            head = rev(repo, "FETCH_HEAD^{commit}");
            label = format!(
                "merge request #{number} → {}",
                if base_ref.is_empty() {
                    "default"
                } else {
                    &base_ref
                }
            );
        } else {
            let mut found = rev(repo, &format!("{head_ref}^{{commit}}"));
            if found.is_empty() {
                found = rev(
                    repo,
                    &format!("refs/remotes/origin/{}^{{commit}}", short_ref(&head_ref)),
                );
            }
            head = found;
            label = format!(
                "pull request {head_ref} → {}",
                if base_ref.is_empty() {
                    "default"
                } else {
                    &base_ref
                }
            );
        }
        if head.is_empty() {
            return Err("The pull request head is not available locally; push the branch through Probator first".to_string());
        }
        let base = if base.is_empty() { None } else { Some(base) };
        return Ok(vec![snapshot("pr", label, base, head, None)]);
    }
    let mut found = Vec::new();
    for line in var("PROBATOR_PUSH_REFS").lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 4 {
            continue;
        }
        let (local_ref, local_sha, remote_sha) = (fields[0], fields[1], fields[3]);
        if local_sha.trim_matches('0').is_empty() {
            continue; // a deletion publishes nothing
        }
        let head = rev(repo, &format!("{local_sha}^{{commit}}"));
        if head.is_empty() || published_elsewhere(repo, &head) {
            continue; // already-published tips add no unreviewed content
        }
        let base = if remote_sha.trim_matches('0').is_empty() || !commit_known(repo, remote_sha) {
            None
        } else {
            Some(remote_sha.to_string())
        };
        found.push(snapshot(
            "push",
            format!("push {local_ref}"),
            base,
            head,
            Some(local_ref.to_string()),
        ));
    }
    // One target per distinct head commit.
    let mut seen = std::collections::HashSet::new();
    found.retain(|target| seen.insert(target.head.clone()));
    Ok(found)
}

/// The live form: the PROBATOR_* environment, read once.
pub fn ranges(repo: &str) -> Result<Vec<Target>, String> {
    let mut vars = serde_json::Map::new();
    for name in [
        "PROBATOR_EVENT",
        "PROBATOR_RELEASE_TAG",
        "PROBATOR_RELEASE_COMMIT",
        "PROBATOR_PR_HEAD",
        "PROBATOR_PR_BASE",
        "PROBATOR_PR_NUMBER",
        "PROBATOR_PUSH_REFS",
    ] {
        if let Ok(value) = std::env::var(name) {
            vars.insert(name.to_string(), serde_json::Value::String(value));
        }
    }
    let event = vars
        .get("PROBATOR_EVENT")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    ranges_from(repo, &event, &vars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A scratch repository with one commit; the tree is deleted on drop.
    struct Repo(std::path::PathBuf);

    impl Repo {
        fn new() -> (Self, String) {
            let dir = std::env::temp_dir().join(format!(
                "gv-ranges-{}-{:04x}",
                std::process::id(),
                rand::random::<u16>()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let git = |args: &[&str]| {
                let out = Command::new("git")
                    .arg("-C")
                    .arg(&dir)
                    .args(args)
                    .env("GIT_AUTHOR_NAME", "Synthetic")
                    .env("GIT_AUTHOR_EMAIL", "synthetic@example.invalid")
                    .env("GIT_COMMITTER_NAME", "Synthetic")
                    .env("GIT_COMMITTER_EMAIL", "synthetic@example.invalid")
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .output()
                    .unwrap();
                assert!(out.status.success(), "git {args:?}");
                String::from_utf8_lossy(&out.stdout).trim().to_string()
            };
            git(&["init", "-b", "main"]);
            std::fs::write(dir.join("one.txt"), "one\n").unwrap();
            git(&["add", "one.txt"]);
            git(&["commit", "-m", "one"]);
            let head = git(&["rev-parse", "HEAD"]);
            (Self(dir), head)
        }
    }

    impl Drop for Repo {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn push_vars(refs: &str) -> serde_json::Map<String, serde_json::Value> {
        json!({"PROBATOR_EVENT": "pre-push", "PROBATOR_PUSH_REFS": refs})
            .as_object()
            .unwrap()
            .clone()
    }

    #[test]
    fn a_first_push_and_an_unfetched_tip_both_review_the_whole_snapshot() {
        let (repo, head) = Repo::new();
        let zero = "0".repeat(40);
        let refs = format!("refs/heads/main {head} refs/heads/main {zero}\n");
        let targets = ranges_from(repo.0.to_str().unwrap(), "pre-push", &push_vars(&refs))
            .expect("a first push resolves");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].base, None, "no base: the whole tree is reviewed");

        // The remote advertises a tip this object store has never fetched:
        // the range cannot diff against it, so the review object is again
        // the whole snapshot rather than an unreadable range.
        let missing = "1".repeat(40);
        let refs = format!("refs/heads/main {head} refs/heads/main {missing}\n");
        let targets = ranges_from(repo.0.to_str().unwrap(), "pre-push", &push_vars(&refs))
            .expect("an unfetched tip still resolves");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].base, None, "unfetched tip: whole snapshot");
    }
}
