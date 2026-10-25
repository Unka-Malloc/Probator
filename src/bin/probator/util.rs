//! Small pure helpers shared by the review crate's modules.

use sha2::Digest as _;
use std::path::PathBuf;

/// Hex SHA-256 of a text payload - the bundle-manifest and sync-contract
/// hashes. One implementation: a digest the installer writes and the engine
/// re-checks must come from the same code.
pub(crate) fn sha256(text: &str) -> String {
    sha2::Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `$XDG_CONFIG_HOME` or `~/.config` — the one answer for where machine-local
/// configuration lives, so withheld-names, repo-deps and the routing file can
/// never disagree about the directory.
pub(crate) fn config_dir() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".config")
        })
}
