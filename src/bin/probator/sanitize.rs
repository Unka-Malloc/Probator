//! The review-payload sanitizer, ported from the retired Python engine
//! (`audit_engine.py`). The goldens under `tests/review-parity/` recorded its
//! behavior and pin this port.
//!
//! Two variants, one order of operations, byte parity with the Python engine
//! pinned by the goldens under `tests/review-parity/`:
//!
//! * [`sanitize`] - receipts and reports: private keys, credential shapes,
//!   quoted secrets, bearer tokens, this machine's paths, e-mail addresses and
//!   private networks.
//! * [`sanitize_source`] - evidence served to the reviewer: everything above,
//!   plus endpoints, addresses and account identifiers. Kept separate from the
//!   report sanitizer so official citations survive.
//!
//! Credential containers and runtime stores never reach this code: the
//! sensitive-path contract refuses them before any content is read.

use regex::Regex;
use std::sync::LazyLock;

static PRIVATE_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----").unwrap()
});
static CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b")
        .unwrap()
});
static QUOTED_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)((?:api[_-]?key|password|secret|access[_-]?token|authorization)["']?\s*[=:]\s*)["'][^"'\n]+["']"#,
    )
    .unwrap()
});
static BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*").unwrap());
static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap());
static PRIVATE_IP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
    )
    .unwrap()
});
static URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)(https?|wss?)://[^\s"'<>`]+"#).unwrap());
static ANY_IP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
static ACCOUNT_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)((?:account_id|database_id|zone_id|tenant_id)["']?\s*[=:]\s*)["'][^"'\n]+["']"#,
    )
    .unwrap()
});
static ENV_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?im)^(\s*(?:[- ]*\s*)?(?:[A-Z_]*(?:TOKEN|SECRET|PASSWORD|API_KEY)[A-Z_]*)\s*[=:]\s*)([^\s#]+)")
        .unwrap()
});

/// The cross-platform home and temp prefixes a receipt or a review payload
/// must never spell out — the same on every macOS, Linux and Windows host,
/// so the list itself discloses nothing about the machine running it.
/// One convention the receipt store shares: this list and
/// `records.rs::redact`; the parity goldens pinned the pair against the
/// retired Python engine.
const LOCAL_PATH_MARKERS: [&str; 5] = [
    "/Users/",
    "/home/",
    "/var/_folders/",
    "C:\\Users\\",
    "C:/Users/",
];

fn local_path(text: &str) -> String {
    const STOPS: [char; 8] = [' ', '\t', '\n', '\r', '"', '\'', '`', '<'];
    // The EARLIEST match wins: a later marker inside a copied span would never
    // be looked at again. Runs end at the first stop character.
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let earliest = LOCAL_PATH_MARKERS
            .iter()
            .filter_map(|marker| rest.find(marker).map(|at| (at, at + marker.len())))
            .min();
        let Some((at, after)) = earliest else {
            out.push_str(rest);
            break;
        };
        let end = rest[after..]
            .find(|c| STOPS.contains(&c))
            .map(|i| after + i)
            .unwrap_or(rest.len());
        out.push_str(&rest[..at]);
        out.push_str("[LOCAL_PATH]");
        rest = &rest[end..];
    }
    out
}

/// The report sanitizer.
pub fn sanitize(text: &str) -> String {
    let text = PRIVATE_KEY.replace_all(text, |caps: &regex::Captures| {
        // Keep the line count: a finding's line numbers stay meaningful.
        format!(
            "[PRIVATE_KEY]{}",
            "\n".repeat(caps[0].matches('\n').count())
        )
    });
    let text = CREDENTIAL.replace_all(&text, "[CREDENTIAL]");
    let text = QUOTED_SECRET.replace_all(&text, r#"$1"[REDACTED]""#);
    let text = BEARER.replace_all(&text, "Bearer [REDACTED]");
    let text = local_path(&text);
    let text = EMAIL.replace_all(&text, "[EMAIL]");
    PRIVATE_IP.replace_all(&text, "[PRIVATE_IP]").into_owned()
}

/// The evidence sanitizer: endpoint and account identifiers are unnecessary
/// for the domains any checker judges.
pub fn sanitize_source(raw: &str) -> String {
    let text = sanitize(raw);
    let text = URL.replace_all(&text, "$1://[ENDPOINT]");
    let text = ANY_IP.replace_all(&text, "[IP_ADDRESS]");
    let text = ACCOUNT_ID.replace_all(&text, r#"$1"[IDENTIFIER]""#);
    ENV_LINE.replace_all(&text, "$1[REDACTED]").into_owned()
}

#[cfg(test)]
mod tests {
    use super::{sanitize, sanitize_source};
    use serde_json::Value;
    use std::path::Path;

    fn parity_file(name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("review-parity")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path:?}: {error}"))
    }

    #[test]
    fn both_variants_match_the_engine_goldens() {
        let cases: Vec<Value> = serde_json::from_str(&parity_file("sanitize-cases.json")).unwrap();
        let expected: Value = serde_json::from_str(&parity_file("sanitize-expected.json")).unwrap();
        assert!(!cases.is_empty(), "the corpus must not be empty");
        for case in &cases {
            let name = case["name"].as_str().unwrap();
            // `b64:` marks base64 payloads: shapes the gate itself refuses
            // (credential forms) live encoded in the corpus and decode back to
            // the real text the sanitizer must catch - the expected side
            // carries the same escape when its pinned output is the shape.
            let input = crate::util::b64_decode(case["input"].as_str().unwrap());
            let expected_sanitize =
                crate::util::b64_decode(expected[name]["sanitize"].as_str().unwrap());
            let expected_source =
                crate::util::b64_decode(expected[name]["sanitize_source"].as_str().unwrap());
            assert_eq!(sanitize(&input), expected_sanitize, "case {name}");
            assert_eq!(
                sanitize_source(&input),
                expected_source,
                "case {name} (source)"
            );
        }
    }

    #[test]
    fn local_paths_end_at_stop_characters() {
        assert_eq!(sanitize("see /Users/x/y\""), "see [LOCAL_PATH]\"");
        assert_eq!(sanitize("/Users/x/y"), "[LOCAL_PATH]");
        assert_eq!(sanitize("no paths here"), "no paths here");
        assert_eq!(
            sanitize("a /Users/x b /home/y c"),
            "a [LOCAL_PATH] b [LOCAL_PATH] c"
        );
    }
}
