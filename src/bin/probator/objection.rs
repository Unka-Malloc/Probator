//! Operator-ruled objections to checker findings.
//!
//! A blocking checker verdict is evidence, not law: the operator may rule
//! that a finding does not apply. The ruling channel is a signed ledger,
//! blessed by the same configuration signing key that certifies the audit
//! policy, so a waiver is as hard to forge as the policy itself. An unsigned,
//! tampered or mismatched ledger waives nothing.
//!
//! This binary only reads and verifies rulings. Filing an objection and
//! signing the ledger belongs to the gate that holds the operator's key
//! (its `objection` command); the ledger path and its verification anchor are
//! supplied through `PROBATOR_RULINGS_LEDGER` and `PROBATOR_RULINGS_ANCHOR`.
//! The signature namespace is read from the signature itself — an SSHSIG
//! blob embeds the namespace its signer declared — and the principal comes
//! from the anchor, so a ledger signed by any signer verifies here
//! unchanged and this public tree never names the signer.
//!
//! Two kinds of rulings:
//!
//! - `finding`: waives one blocking finding, matched by checker, repository
//!   and file, optionally narrowed by line or by the finding's fingerprint
//!   (a hash of its evidence text). A location-level ruling persists while
//!   the checker's wording drifts; a fingerprint ruling lapses as soon as
//!   the finding text changes.
//! - `verdict`: accepts a whole non-pass outcome — including an
//!   `incomplete` that produced no findings at all — for one candidate:
//!   the ruling binds the exact head sha and lapses when it moves.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// The principal written into a materialized allowed-signers file when the
/// anchor is a bare public key. Any value works — it is checked against the
/// file this binary writes, and the signature's own principal stays in the
/// signer's files rather than being named here.
const MATERIALIZED_PRINCIPAL: &str = "rulings";

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
}

/// `PROBATOR_RULINGS_LEDGER` — the signed rulings ledger.
pub fn ledger_path() -> Option<PathBuf> {
    env_path("PROBATOR_RULINGS_LEDGER")
}

/// `PROBATOR_RULINGS_ANCHOR` — the allowed-signers file the ledger's
/// signature is verified against.
pub fn anchor_path() -> Option<PathBuf> {
    env_path("PROBATOR_RULINGS_ANCHOR")
}

/// The signature sidecar beside a ledger.
fn sig_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_os_string();
    p.push(".sig");
    PathBuf::from(p)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ruling {
    pub id: String,
    /// Repository slug (`owner/name`) the ruling is scoped to; empty means
    /// the ruling holds for any repository the finding appears in.
    #[serde(default)]
    pub repo: String,
    /// Checker contract name, e.g. `money-saver`.
    pub checker: String,
    /// `finding` waives one finding; `verdict` accepts a whole non-pass
    /// outcome for the bound head.
    pub kind: String,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub line: Option<u64>,
    /// sha256 of the finding's normalized evidence text; set at filing so
    /// the ruling lapses if the finding is reworded.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// The candidate head a `verdict` ruling covers.
    #[serde(default)]
    pub head: String,
    /// `overruled` waives; `sustained` records that the finding stands.
    pub verdict: String,
    /// Why the objection was filed.
    #[serde(default)]
    pub objection: String,
    /// The operator's adjudication note.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub ruled_at: String,
}

/// A finding's stable identity for one checker report.
pub fn fingerprint(checker: &str, file: &str, line: u64, evidence: &str) -> String {
    let normalized = evidence.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut hasher = Sha256::new();
    for part in [checker, file, &line.to_string(), &normalized] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_key_type(token: &str) -> bool {
    token.starts_with("ssh-") || token.starts_with("ecdsa-") || token.starts_with("sk-")
}

/// Whether the anchor is a bare public key rather than an allowed-signers
/// file. Both are natural readings of "the verification key"; `ssh-keygen
/// -Y verify` accepts only the allowed-signers form, so the bare form is
/// materialized with the fixed principal below.
fn bare_public_key(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .and_then(|line| line.split_whitespace().next())
        .is_some_and(is_key_type)
}

/// A temporary allowed-signers file for a bare public-key anchor. It is
/// removed on every exit path.
struct TempAnchor(PathBuf);

impl Drop for TempAnchor {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn materialize_bare_anchor(text: &str) -> Result<TempAnchor, String> {
    let path = std::env::temp_dir().join(format!(
        "probator-rulings-anchor-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    let temporary = TempAnchor(path.clone());
    let mut file = options
        .open(&path)
        .map_err(|error| format!("cannot create a temporary anchor: {error}"))?;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        writeln!(file, "{MATERIALIZED_PRINCIPAL} {line}")
            .map_err(|error| format!("cannot write a temporary anchor: {error}"))?;
    }
    Ok(temporary)
}

/// One u32-length-prefixed string out of an SSH wire blob.
fn ssh_string<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let (len, rest) = cursor
        .split_at_checked(4)
        .ok_or_else(|| "truncated signature".to_string())?;
    let len = u32::from_be_bytes(len.try_into().unwrap()) as usize;
    let (value, rest) = rest
        .split_at_checked(len)
        .ok_or_else(|| "truncated signature".to_string())?;
    *cursor = rest;
    Ok(value)
}

/// The namespace an SSHSIG blob was signed under: the blob embeds it after
/// the magic and version as the third length-prefixed string. Reading it
/// from the signature keeps the signer's own namespace out of this tree —
/// `ssh-keygen -Y verify` still checks the blob against the same value.
fn signature_namespace(sig: &Path) -> Result<String, String> {
    let blob =
        std::fs::read(sig).map_err(|error| format!("cannot read {}: {error}", sig.display()))?;
    // PEM armor wraps the raw blob in base64 between the BEGIN/END lines.
    let body: String = blob
        .iter()
        .map(|byte| *byte as char)
        .collect::<String>()
        .lines()
        .filter(|line| !line.starts_with("-----") && !line.trim().is_empty())
        .collect();
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|error| format!("signature is not valid base64: {error}"))?;
    if raw.get(..6) != Some(b"SSHSIG") || raw.get(6..10) != Some(&1u32.to_be_bytes()[..]) {
        return Err("not an SSHSIG v1 blob".to_string());
    }
    // SSHSIG(6) + u32 version + string pubkey + string namespace.
    let mut cursor: &[u8] = raw
        .get(10..)
        .ok_or_else(|| "truncated signature".to_string())?;
    ssh_string(&mut cursor)?; // publickey
    let namespace = ssh_string(&mut cursor)?;
    String::from_utf8(namespace.to_vec()).map_err(|_| "invalid namespace".to_string())
}

/// The principal to check against the anchor: the first principal named in
/// an allowed-signers file, or the materialized one when the anchor is a
/// bare key and this binary writes the file itself.
fn anchor_principal(anchor_text: &str, bare: bool) -> Result<String, String> {
    if bare {
        return Ok(MATERIALIZED_PRINCIPAL.to_string());
    }
    anchor_text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .and_then(|line| line.split_whitespace().next())
        .and_then(|principals| principals.split(',').next())
        .map(str::to_string)
        .ok_or_else(|| "anchor names no principal".to_string())
}

/// Verify the ledger's sidecar signature against the anchor, feeding the
/// exact bytes that will be parsed to `ssh-keygen -Y verify` so the verified
/// document and the interpreted document cannot diverge.
fn verify_signed(data: &[u8], sig: &Path, anchor: &Path) -> Result<(), String> {
    if !anchor.is_file() {
        return Err(format!("no anchor at {}", anchor.display()));
    }
    if !sig.is_file() {
        return Err(format!("no signature sidecar at {}", sig.display()));
    }
    let namespace = signature_namespace(sig)?;
    let anchor_text = std::fs::read_to_string(anchor)
        .map_err(|error| format!("cannot read {}: {error}", anchor.display()))?;
    let bare = bare_public_key(&anchor_text);
    let principal = anchor_principal(&anchor_text, bare)?;
    let temporary = if bare {
        Some(materialize_bare_anchor(&anchor_text)?)
    } else {
        None
    };
    let verify_anchor = temporary
        .as_ref()
        .map_or(anchor, |temporary| temporary.0.as_path());
    let mut child = Command::new("ssh-keygen")
        .arg("-Y")
        .arg("verify")
        .arg("-f")
        .arg(verify_anchor)
        .arg("-I")
        .arg(principal)
        .arg("-n")
        .arg(namespace)
        .arg("-s")
        .arg(sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("failed to run ssh-keygen -Y verify: {error}"))?;
    {
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .expect("stdin was piped")
            .write_all(data)
            .map_err(|error| format!("could not feed the ledger to ssh-keygen: {error}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|error| format!("ssh-keygen -Y verify did not finish: {error}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}

/// The signed rulings at an explicit ledger and anchor, or empty when the
/// ledger does not exist, cannot be read, or fails signature verification.
/// Waivers only ever come from a certified ledger.
pub fn load_rulings_at(ledger: &Path, anchor: &Path) -> Vec<Ruling> {
    let raw = match std::fs::read(ledger) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            eprintln!("probator: objections ledger unreadable - {error}");
            return Vec::new();
        }
    };
    let signature = sig_path(ledger);
    if let Err(reason) = verify_signed(&raw, &signature, anchor) {
        eprintln!("probator: objections ledger is not signed - no ruling applies ({reason})");
        return Vec::new();
    }
    let Ok(text) = String::from_utf8(raw) else {
        eprintln!("probator: objections ledger is not UTF-8 - no ruling applies");
        return Vec::new();
    };
    let doc: toml::Value = match toml::from_str(&text) {
        Ok(doc) => doc,
        Err(error) => {
            eprintln!("probator: objections ledger unreadable - {error}");
            return Vec::new();
        }
    };
    doc.get("ruling")
        .and_then(|value| value.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|value| value.clone().try_into().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The signed rulings, or empty when either environment variable is absent:
/// the ledger is never read from a default path and no ruling applies.
#[allow(dead_code)]
pub fn load_rulings() -> Vec<Ruling> {
    let (Some(ledger), Some(anchor)) = (ledger_path(), anchor_path()) else {
        return Vec::new();
    };
    load_rulings_at(&ledger, &anchor)
}

/// Which blocking findings a certified ledger waives for this run, and
/// whether a verdict-level ruling accepts a non-pass outcome for `head`.
/// Returns `(waived_finding_indexes, verdict_waived)`.
pub fn waivers(
    report: &serde_json::Value,
    checker: &str,
    repo_slug: &str,
    head: &str,
) -> (Vec<usize>, bool) {
    waivers_from(
        ledger_path().as_deref(),
        anchor_path().as_deref(),
        report,
        checker,
        repo_slug,
        head,
    )
}

/// The configured ledger and anchor are both required; a missing either one
/// leaves every finding standing. Exposed to the orchestrator-facing gate so
/// it can verify the same signed ledger instead of trusting an unsigned
/// sidecar written beside a report.
pub(crate) fn waivers_from(
    ledger: Option<&Path>,
    anchor: Option<&Path>,
    report: &serde_json::Value,
    checker: &str,
    repo_slug: &str,
    head: &str,
) -> (Vec<usize>, bool) {
    let (Some(ledger), Some(anchor)) = (ledger, anchor) else {
        return (Vec::new(), false);
    };
    waivers_with(
        &load_rulings_at(ledger, anchor),
        report,
        checker,
        repo_slug,
        head,
    )
}

/// The pure matching half of `waivers`, separated so the ledger load and its
/// signature verification stay untestable-free while every match rule is
/// exercised directly.
fn waivers_with(
    rulings: &[Ruling],
    report: &serde_json::Value,
    checker: &str,
    repo_slug: &str,
    head: &str,
) -> (Vec<usize>, bool) {
    let mut waived = Vec::new();
    let mut verdict_waived = false;
    if rulings.is_empty() {
        return (waived, verdict_waived);
    }
    let findings = report["findings"].as_array();
    for ruling in rulings.iter().filter(|r| {
        r.checker == checker
            && r.verdict == "overruled"
            && (r.repo.is_empty() || r.repo == repo_slug)
    }) {
        match ruling.kind.as_str() {
            "verdict" => {
                if ruling.head == head {
                    verdict_waived = true;
                }
            }
            _ => {
                if let Some(findings) = findings {
                    for (index, finding) in findings.iter().enumerate() {
                        if finding["severity"].as_str() != Some("blocking") {
                            continue;
                        }
                        if finding["file"].as_str() != Some(ruling.file.as_str()) {
                            continue;
                        }
                        if let Some(line) = ruling.line
                            && finding["line"].as_u64() != Some(line)
                        {
                            continue;
                        }
                        if let Some(expected) = &ruling.fingerprint {
                            let actual = fingerprint(
                                checker,
                                ruling.file.as_str(),
                                finding["line"].as_u64().unwrap_or(0),
                                finding["evidence"].as_str().unwrap_or(""),
                            );
                            if &actual != expected {
                                continue;
                            }
                        }
                        if !waived.contains(&index) {
                            waived.push(index);
                        }
                    }
                }
            }
        }
    }
    (waived, verdict_waived)
}

/// Whether a certified verdict ruling accepts this checker's outcome for
/// `head`. The deterministic stage consults this before refusing: an armed
/// ruling lets the audit continue, so the sealed report still records the
/// deterministic hits and the gate names the ruling that waived them.
/// Findings-level rulings never apply here — a stage-one refusal carries
/// no report coordinates to bind.
pub fn verdict_waived(checker: &str, repo_slug: &str, head: &str) -> bool {
    let (Some(ledger), Some(anchor)) = (ledger_path(), anchor_path()) else {
        return false;
    };
    verdict_waived_with(&load_rulings_at(&ledger, &anchor), checker, repo_slug, head)
}

/// The pure matching half of `verdict_waived`, kept beside `waivers_with`
/// so both apply the identical binding rule: checker, overruled verdict,
/// head, and an empty or matching repository slug.
fn verdict_waived_with(rulings: &[Ruling], checker: &str, repo_slug: &str, head: &str) -> bool {
    rulings.iter().any(|ruling| {
        ruling.kind == "verdict"
            && ruling.verdict == "overruled"
            && ruling.checker == checker
            && ruling.head == head
            && (ruling.repo.is_empty() || ruling.repo == repo_slug)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(findings: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "verdict": "fail",
            "findings": findings,
        })
    }

    fn blocking(file: &str, line: u64, evidence: &str) -> serde_json::Value {
        serde_json::json!({
            "severity": "blocking",
            "file": file,
            "line": line,
            "evidence": evidence,
            "impact": "x",
            "remedy": "y",
        })
    }

    fn ruling(checker: &str, kind: &str) -> Ruling {
        Ruling {
            id: "ob-test".into(),
            repo: "owner/repo".into(),
            checker: checker.into(),
            kind: kind.into(),
            file: String::new(),
            line: None,
            fingerprint: None,
            head: String::new(),
            verdict: "overruled".into(),
            objection: "why".into(),
            reason: "because".into(),
            ruled_at: "now".into(),
        }
    }

    #[test]
    fn a_finding_ruling_waives_the_exact_finding() {
        let mut r = ruling("checker", "finding");
        r.file = "src/a.rs".into();
        r.line = Some(12);
        r.fingerprint = Some(fingerprint("checker", "src/a.rs", 12, "the evidence"));
        let rep = report(serde_json::json!([
            blocking("src/a.rs", 12, "the evidence"),
            blocking("src/b.rs", 3, "other"),
        ]));
        let (waived, _) = waivers_with(&[r], &rep, "checker", "owner/repo", "abc");
        assert_eq!(waived, vec![0]);
    }

    #[test]
    fn a_location_ruling_without_fingerprint_still_waives() {
        let mut r = ruling("checker", "finding");
        r.file = "src/a.rs".into();
        r.line = Some(12);
        let rep = report(serde_json::json!([blocking("src/a.rs", 12, "reworded")]));
        let (waived, _) = waivers_with(&[r], &rep, "checker", "owner/repo", "abc");
        assert_eq!(waived, vec![0]);
    }

    #[test]
    fn a_fingerprint_ruling_lapses_when_the_finding_is_reworded() {
        let mut r = ruling("checker", "finding");
        r.file = "src/a.rs".into();
        r.line = Some(12);
        r.fingerprint = Some(fingerprint("checker", "src/a.rs", 12, "old evidence"));
        let rep = report(serde_json::json!([blocking(
            "src/a.rs",
            12,
            "new evidence"
        )]));
        let (waived, _) = waivers_with(&[r], &rep, "checker", "owner/repo", "abc");
        assert!(waived.is_empty());
    }

    #[test]
    fn a_repo_scoped_ruling_does_not_cross_repositories() {
        let mut r = ruling("checker", "finding");
        r.file = "src/a.rs".into();
        let rep = report(serde_json::json!([blocking("src/a.rs", 1, "e")]));
        let (waived, _) = waivers_with(&[r], &rep, "checker", "other/repo", "abc");
        assert!(waived.is_empty());
    }

    #[test]
    fn a_ruling_for_another_checker_waives_nothing() {
        let mut r = ruling("other-checker", "finding");
        r.file = "src/a.rs".into();
        let rep = report(serde_json::json!([blocking("src/a.rs", 1, "e")]));
        let (waived, _) = waivers_with(&[r], &rep, "checker", "owner/repo", "abc");
        assert!(waived.is_empty());
    }

    #[test]
    fn a_sustained_ruling_never_waives() {
        let mut r = ruling("checker", "finding");
        r.file = "src/a.rs".into();
        r.verdict = "sustained".into();
        let rep = report(serde_json::json!([blocking("src/a.rs", 1, "e")]));
        let (waived, verdict_waived) = waivers_with(&[r], &rep, "checker", "owner/repo", "abc");
        assert!(waived.is_empty() && !verdict_waived);
    }

    #[test]
    fn an_advisory_finding_is_never_waived_by_matching() {
        let mut r = ruling("checker", "finding");
        r.file = "src/a.rs".into();
        let rep = report(serde_json::json!([serde_json::json!({
            "severity": "advisory", "file": "src/a.rs", "line": 1, "evidence": "e"
        })]));
        let (waived, _) = waivers_with(&[r], &rep, "checker", "owner/repo", "abc");
        assert!(waived.is_empty());
    }

    #[test]
    fn a_verdict_ruling_binds_the_filed_head() {
        let mut r = ruling("checker", "verdict");
        r.head = "deadbeef".into();
        let rep = report(serde_json::json!([]));
        let (_, waived) = waivers_with(&[r.clone()], &rep, "checker", "owner/repo", "deadbeef");
        assert!(waived);
        let (_, waived) = waivers_with(&[r], &rep, "checker", "owner/repo", "cafe");
        assert!(!waived);
    }

    #[test]
    fn fingerprints_normalize_evidence_whitespace() {
        assert_eq!(
            fingerprint("c", "f", 1, "a   b\n\tc"),
            fingerprint("c", "f", 1, "a b c")
        );
        assert_ne!(
            fingerprint("c", "f", 1, "a b c"),
            fingerprint("c", "f", 2, "a b c")
        );
    }

    #[test]
    fn an_unconfigured_ledger_waives_nothing() {
        let rep = report(serde_json::json!([blocking("src/a.rs", 1, "e")]));
        let (waived, verdict_waived) =
            waivers_from(None, None, &rep, "checker", "owner/repo", "abc");
        assert!(waived.is_empty() && !verdict_waived);
        // One half of the pair is not enough either.
        let ledger = Path::new("/nonexistent/ledger.toml");
        let (waived, verdict_waived) =
            waivers_from(Some(ledger), None, &rep, "checker", "owner/repo", "abc");
        assert!(waived.is_empty() && !verdict_waived);
    }

    // ------------------------------------------------- signed ledger tests

    /// A scratch directory removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "probator-objection-{tag}-{}-{:016x}",
                std::process::id(),
                rand::random::<u64>()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ssh_keygen(args: &[&std::ffi::OsStr]) -> std::process::Output {
        Command::new("ssh-keygen")
            .args(args)
            .output()
            .expect("ssh-keygen is required for the signature tests")
    }

    /// Create an ed25519 signing key and its allowed-signers anchor, write
    /// `body` as the ledger, and sign it with the configuration namespace.
    fn sign_ledger(scratch: &Scratch, name: &str, body: &str) -> (PathBuf, PathBuf) {
        let key = scratch.path(name);
        let key_status = ssh_keygen(&[
            "-q".as_ref(),
            "-t".as_ref(),
            "ed25519".as_ref(),
            "-N".as_ref(),
            "".as_ref(),
            "-f".as_ref(),
            key.as_os_str(),
        ]);
        assert!(
            key_status.status.success(),
            "ssh-keygen keygen failed: {}",
            String::from_utf8_lossy(&key_status.stderr)
        );
        let public = std::fs::read_to_string(scratch.path(&format!("{name}.pub"))).unwrap();
        let anchor = scratch.path(&format!("{name}.allowed"));
        std::fs::write(
            &anchor,
            format!("test-rulings {}", public.trim_end_matches('\n')),
        )
        .unwrap();
        let ledger = scratch.path(&format!("{name}.toml"));
        std::fs::write(&ledger, body).unwrap();
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

    fn signed_body(checker: &str, verdict: &str) -> String {
        format!(
            "[[ruling]]\nid = \"ob-signed\"\nrepo = \"owner/repo\"\nchecker = \"{checker}\"\nkind = \"finding\"\nfile = \"src/a.rs\"\nline = 12\nverdict = \"{verdict}\"\n"
        )
    }

    #[test]
    fn a_valid_signature_makes_the_ruling_effective() {
        let scratch = Scratch::new("valid");
        let (ledger, anchor) = sign_ledger(&scratch, "valid", &signed_body("checker", "overruled"));
        let rulings = load_rulings_at(&ledger, &anchor);
        assert_eq!(rulings.len(), 1, "the verifier accepts a signed ledger");
        let rep = report(serde_json::json!([blocking(
            "src/a.rs",
            12,
            "the evidence"
        )]));
        let (waived, verdict_waived) = waivers_from(
            Some(&ledger),
            Some(&anchor),
            &rep,
            "checker",
            "owner/repo",
            "abc",
        );
        assert_eq!(waived, vec![0]);
        assert!(!verdict_waived);
    }

    #[test]
    fn a_bare_public_key_anchor_also_verifies() {
        let scratch = Scratch::new("bare-anchor");
        let (ledger, _allowed) =
            sign_ledger(&scratch, "bare", &signed_body("checker", "overruled"));
        // The keygen `.pub` file is a bare public key, not an allowed-signers
        // file; the verifier materializes the fixed principal for it.
        let rulings = load_rulings_at(&ledger, &scratch.path("bare.pub"));
        assert_eq!(rulings.len(), 1);
    }

    #[test]
    fn a_forged_ledger_waives_nothing() {
        let scratch = Scratch::new("forged");
        let (ledger, anchor) =
            sign_ledger(&scratch, "forged", &signed_body("checker", "overruled"));
        // Change the ruling after signing: the signature no longer covers
        // these bytes, so no ruling may be trusted.
        std::fs::write(
            &ledger,
            signed_body("checker", "overruled").replace("src/a.rs", "src/b.rs"),
        )
        .unwrap();
        assert!(load_rulings_at(&ledger, &anchor).is_empty());
        let rep = report(serde_json::json!([blocking(
            "src/b.rs",
            12,
            "the evidence"
        )]));
        let (waived, verdict_waived) = waivers_from(
            Some(&ledger),
            Some(&anchor),
            &rep,
            "checker",
            "owner/repo",
            "abc",
        );
        assert!(waived.is_empty() && !verdict_waived);
    }

    #[test]
    fn a_missing_signature_waives_nothing() {
        let scratch = Scratch::new("missing");
        let (ledger, anchor) =
            sign_ledger(&scratch, "missing", &signed_body("checker", "overruled"));
        std::fs::remove_file(sig_path(&ledger)).unwrap();
        assert!(load_rulings_at(&ledger, &anchor).is_empty());
        let rep = report(serde_json::json!([blocking(
            "src/a.rs",
            12,
            "the evidence"
        )]));
        let (waived, _) = waivers_from(
            Some(&ledger),
            Some(&anchor),
            &rep,
            "checker",
            "owner/repo",
            "abc",
        );
        assert!(waived.is_empty());
    }

    #[test]
    fn an_unrelated_signed_ruling_waives_nothing() {
        let scratch = Scratch::new("unrelated");
        let (ledger, anchor) = sign_ledger(
            &scratch,
            "unrelated",
            &signed_body("another-checker", "overruled"),
        );
        assert_eq!(load_rulings_at(&ledger, &anchor).len(), 1);
        let rep = report(serde_json::json!([blocking(
            "src/a.rs",
            12,
            "the evidence"
        )]));
        let (waived, verdict_waived) = waivers_from(
            Some(&ledger),
            Some(&anchor),
            &rep,
            "checker",
            "owner/repo",
            "abc",
        );
        assert!(waived.is_empty() && !verdict_waived);
    }

    #[test]
    fn a_signed_sustained_ruling_waives_nothing() {
        let scratch = Scratch::new("sustained");
        let (ledger, anchor) =
            sign_ledger(&scratch, "sustained", &signed_body("checker", "sustained"));
        assert_eq!(load_rulings_at(&ledger, &anchor).len(), 1);
        let rep = report(serde_json::json!([blocking(
            "src/a.rs",
            12,
            "the evidence"
        )]));
        let (waived, verdict_waived) = waivers_from(
            Some(&ledger),
            Some(&anchor),
            &rep,
            "checker",
            "owner/repo",
            "abc",
        );
        assert!(waived.is_empty() && !verdict_waived);
    }

    #[test]
    fn a_verdict_ruling_waives_the_bound_head() {
        let mut r = ruling("checker", "verdict");
        r.head = "abc".into();
        assert!(verdict_waived_with(&[r], "checker", "owner/repo", "abc"));
    }

    #[test]
    fn a_verdict_ruling_ignores_another_head() {
        let mut r = ruling("checker", "verdict");
        r.head = "abc".into();
        assert!(!verdict_waived_with(&[r], "checker", "owner/repo", "def"));
    }

    #[test]
    fn a_verdict_ruling_ignores_another_checker_and_repo() {
        let mut r = ruling("checker", "verdict");
        r.head = "abc".into();
        assert!(!verdict_waived_with(
            &[r.clone()],
            "other",
            "owner/repo",
            "abc"
        ));
        assert!(!verdict_waived_with(&[r], "checker", "other/repo", "abc"));
    }

    #[test]
    fn an_unbound_verdict_ruling_covers_any_repo() {
        let mut r = ruling("checker", "verdict");
        r.head = "abc".into();
        r.repo = String::new();
        assert!(verdict_waived_with(&[r], "checker", "any/repo", "abc"));
    }

    #[test]
    fn a_sustained_or_finding_ruling_never_waives_the_verdict() {
        let mut sustained = ruling("checker", "verdict");
        sustained.head = "abc".into();
        sustained.verdict = "sustained".into();
        let mut finding = ruling("checker", "finding");
        finding.head = "abc".into();
        assert!(!verdict_waived_with(
            &[sustained, finding],
            "checker",
            "owner/repo",
            "abc"
        ));
    }
}
