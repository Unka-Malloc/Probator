//! The run's one-shot verdict credential. `run` issues a random key into the
//! run directory before the reviewer starts; the review server signs its
//! submitted receipt with `HMAC-SHA256(key, canonical receipt)`; `run` keeps
//! the key in memory, verifies the signature when the review ends, and
//! deletes the file — the credential is consumed by the verdict it sealed.
//! A receipt without the signature, signed under a different run's key, or
//! replayed into a run whose key already died is refused: the signature is
//! what a hand-written `report.json` cannot produce. This authenticates the
//! channel, not the reviewer's diligence — `submit::validate` still judges
//! what was actually reviewed.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::path::Path;

/// The credential file inside each run directory.
const KEY_FILE: &str = "verdict.key";

/// The receipt field the signature rides in.
const MAC_FIELD: &str = "receipt_mac";

/// The run's credential: reuse the file a previous attempt left (the
/// reviewer never reached a verdict, so its key was never consumed), or
/// mint a fresh one. Written `0600` beside the run's other evidence.
pub fn issue(run_dir: &Path) -> Result<[u8; 32], String> {
    let path = run_dir.join(KEY_FILE);
    if let Ok(raw) = std::fs::read(&path) {
        return <[u8; 32]>::try_from(raw.as_slice())
            .map_err(|_| "verdict credential is corrupt".to_string());
    }
    let key: [u8; 32] = rand::random();
    // create_new + mode in one open: no window where the key sits on disk
    // under loose permissions, and a racing attempt cannot clobber it.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|error| format!("verdict credential: {error}"))?;
    use std::io::Write as _;
    file.write_all(&key)
        .map_err(|error| format!("verdict credential: {error}"))?;
    Ok(key)
}

/// The key the review server signs with, read at startup. Absent means this
/// run's credential was already consumed — no verdict may be submitted.
pub fn load(run_dir: &Path) -> Option<[u8; 32]> {
    std::fs::read(run_dir.join(KEY_FILE))
        .ok()
        .and_then(|raw| <[u8; 32]>::try_from(raw.as_slice()).ok())
}

/// The receipt minus its signature, serialized the way it is written.
fn payload(receipt: &Value) -> Vec<u8> {
    let mut payload = receipt.clone();
    if let Some(object) = payload.as_object_mut() {
        object.remove(MAC_FIELD);
    }
    serde_json::to_vec(&payload).unwrap_or_default()
}

fn hmac_for(key: &[u8; 32]) -> Hmac<Sha256> {
    <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac accepts a key of any length")
}

/// `hex(HMAC-SHA256(key, canonical receipt))`.
pub fn mac(key: &[u8; 32], receipt: &Value) -> String {
    let mut hmac = hmac_for(key);
    hmac.update(&payload(receipt));
    hmac.finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// A receipt is authentic only when its stored signature recomputes under
/// this run's key; the comparison runs in constant time.
pub fn verify(key: &[u8; 32], receipt: &Value) -> bool {
    let Some(stored) = receipt[MAC_FIELD].as_str().and_then(hex_decode) else {
        return false;
    };
    let mut hmac = hmac_for(key);
    hmac.update(&payload(receipt));
    hmac.verify_slice(&stored).is_ok()
}

/// The credential dies with the verdict that sealed it.
pub fn consume(run_dir: &Path) {
    let _ = std::fs::remove_file(run_dir.join(KEY_FILE));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_key_signs_verifies_and_consumes_once() {
        let dir = std::env::temp_dir().join(format!(
            "probator-credential-{}-{:x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let key = issue(&dir).unwrap();
        assert_eq!(load(&dir), Some(key));
        // Reissue keeps the pending attempt's key rather than revoking it.
        assert_eq!(issue(&dir).unwrap(), key);

        let receipt = serde_json::json!({"verdict": "pass", "summary": "ok"});
        let signed = {
            let mut receipt = receipt.clone();
            receipt[MAC_FIELD] = serde_json::json!(mac(&key, &receipt));
            receipt
        };
        assert!(verify(&key, &signed));
        assert!(!verify(&rand::random(), &signed));
        assert!(!verify(&key, &receipt));

        consume(&dir);
        assert_eq!(load(&dir), None);

        std::fs::remove_dir_all(&dir).ok();
    }
}
