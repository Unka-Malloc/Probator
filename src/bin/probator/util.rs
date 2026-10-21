//! Small pure helpers shared by the review crate's modules.

use sha2::Digest as _;

/// Hex SHA-256 of a text payload - the bundle-manifest and sync-contract
/// hashes. One implementation: a digest the installer writes and the engine
/// re-checks must come from the same code.
pub(crate) fn sha256(text: &str) -> String {
    sha2::Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
