//! The sha256 chain shared by the review binary's run records (records.rs) and
//! its review receipts (engine.rs). Both sides must compute the same seal over
//! the same canonical content or one side's verification means nothing to the
//! other's writes - so there is one implementation.

use serde_json::Value;
use std::path::Path;

pub(crate) fn sha256_hex(text: &str) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `sha256(seal_prev + "\n" + canonical document)`: the canonical content is
/// the document itself minus the seal fields, serialized the way it is
/// written to disk.
pub fn seal(seal_prev: &str, document: &Value) -> String {
    let mut payload = document.clone();
    if let Some(object) = payload.as_object_mut() {
        object.remove("seal");
        object.remove("seal_prev");
    }
    sha256_hex(&format!(
        "{seal_prev}\n{}",
        serde_json::to_string(&payload).unwrap_or_default()
    ))
}

/// The stored seal still covers the stored content - a document that never
/// joined the chain does not settle anything. `seal_prev` is absent on
/// genesis records (records.rs omits empty strings) and reads as "".
pub fn valid(document: &Value) -> bool {
    let seal = document["seal"].as_str().unwrap_or("");
    if seal.is_empty() {
        return false;
    }
    let prev = document["seal_prev"].as_str().unwrap_or("");
    self::seal(prev, document) == seal
}

/// The newest sealed `dir/*/file`, ordered by the file's mtime: the chain
/// head a new document links to. `exclude` skips the in-flight run's own
/// directory. Unsealed documents are skipped rather than treated as broken.
pub fn latest(dir: &Path, file: &str, exclude: Option<&Path>) -> String {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return String::new();
    };
    let mut newest: Option<(std::time::SystemTime, String)> = None;
    for entry in entries.flatten() {
        if Some(entry.path().as_path()) == exclude {
            continue;
        }
        let path = entry.path().join(file);
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(document) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let Some(seal) = document["seal"].as_str().filter(|s| !s.is_empty()) else {
            continue;
        };
        let mtime = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        if newest.as_ref().is_none_or(|(at, _)| mtime >= *at) {
            newest = Some((mtime, seal.to_string()));
        }
    }
    newest.map(|(_, seal)| seal).unwrap_or_default()
}
