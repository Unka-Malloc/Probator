//! Read-only git probing.
//!
//! Everything here shells out to `git` and parses its output. Nothing in this
//! module executes repository content: `git remote get-url` and
//! `git for-each-ref` read metadata only.
//!
//! Routing on the remote's owner (rather than on the local path) is deliberate:
//! it survives cloning the same repository to a different directory, and it
//! keeps working for a fresh clone that has never been configured locally.

use std::path::Path;
use std::process::Command;

/// `Owner/Repo` parsed out of a remote URL.
pub fn slug_from_remote(url: &str) -> Option<String> {
    let path = remote_path(url)?;
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 {
        return None;
    }
    Some(format!("{}/{}", parts[0], parts[1]))
}

/// The `<owner>/<repo>` portion of a remote across the forms that occur in
/// the wild: `scheme://[user@]host[:port]/owner/repo` and the scp-like
/// `user@host:owner/repo`.
fn remote_path(remote: &str) -> Option<&str> {
    let s = remote.trim();
    let s = s.strip_suffix(".git").unwrap_or(s);
    if s.is_empty() {
        return None;
    }
    if let Some((_, rest)) = s.split_once("://") {
        rest.split_once('/').map(|(_, p)| p)
    } else {
        s.split_once(':').map(|(_, rest)| rest)
    }
}

/// Whether any ref under `refs` reaches `commit` - the shared "already
/// published" probe. The audit range filter asks about every remote mirror
/// (`refs/remotes`); the attestation skip asks only about the remote the
/// push targets (`refs/remotes/<remote>`), since the status it would post
/// lives on that repository, not on an unrelated one.
pub fn refs_containing(dir: &Path, commit: &str, refs: &[&str]) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "for-each-ref",
            "--count=1",
            "--contains",
            commit,
            "--format=%(refname)",
        ])
        .args(refs)
        .output()
        .map(|out| !String::from_utf8_lossy(&out.stdout).trim().is_empty())
        .unwrap_or(false)
}
