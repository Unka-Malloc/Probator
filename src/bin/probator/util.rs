//! Small pure helpers shared by the review crate's modules.

use sha2::Digest as _;
use std::path::PathBuf;

/// Hex SHA-256 of a text payload - the bundle-manifest and sync-contract
/// hashes. One implementation: a digest the installer writes and the engine
/// re-checks must come from the same code.
pub(crate) fn sha256(text: &str) -> String {
    sha256_bytes(text.as_bytes())
}

/// Hex SHA-256 of a raw byte payload - the installed-binary hash reported
/// by `self-update` cannot round-trip through text.
pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The corpus's base64 escape: a fixture value marked `b64:` decodes to the
/// text the publication gate would refuse if it were stored as literal
/// text, so a case can pin behavior without the tree carrying the shape.
#[cfg(test)]
pub(crate) fn b64_decode(value: &str) -> String {
    use base64::Engine as _;
    match value.strip_prefix("b64:") {
        Some(encoded) => String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .expect("fixture value marked b64: must decode"),
        )
        .expect("fixture value must be UTF-8"),
        None => value.to_string(),
    }
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
