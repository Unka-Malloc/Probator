//! The deterministic stage: what can be proven from the revision itself is
//! decided here, locally, before any of it is described to a model. What must
//! never reach a model at all - a credential, the existence of a withheld
//! name - is refused without being repeated.
//!
//! The builtins are faithful ports of the three Python stage-one modules and
//! each owns one coupled scan pass: the hit ordering and the refusal priority
//! inside a builtin are its semantics, not an accident of scheduling. Regex
//! rules execute as data over a declared target. One deliberate refinement:
//! every checker stops at the first refused range - the refusal ends the
//! operation, and paying for the remaining ranges' scans would only repeat
//! the verdict that is already known.

use crate::contract::{RULE_TARGETS, Rule};
use crate::evidence::{
    EMPTY_TREE, git, git_command, git_head_attr, git_ok, git_status_error, suffix_of,
};
use regex::Regex;
use regex::bytes::Regex as BytesRegex;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// One review target: the whole tree at an immutable head commit. The
/// resolution layer judges every event as a snapshot; the base and scope
/// fields remain for the deterministic stage's parity corpus.
pub struct Target {
    pub kind: String,
    pub label: String,
    /// The commit the range diffs against; None for a snapshot scan.
    pub base: Option<String>,
    /// The outgoing commit.
    pub head: String,
    /// The pushed ref this range publishes, when it has one.
    pub ref_: Option<String>,
    pub scope: String,
}

pub struct Hit {
    pub path: String,
    pub line: u64,
    pub rule: String,
    pub remedy: Option<&'static str>,
}

impl Hit {
    fn to_json(&self) -> Value {
        let mut hit = json!({"path": self.path, "line": self.line, "rule": self.rule});
        if let Some(remedy) = self.remedy {
            hit["remedy"] = json!(remedy);
        }
        hit
    }
}

impl Target {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "label": self.label,
            "base": self.base,
            "head": self.head,
            "ref": self.ref_,
            "scope": self.scope,
        })
    }

    pub(crate) fn from_json(value: &Value) -> Option<Self> {
        Some(Self {
            kind: value["kind"].as_str()?.to_string(),
            label: value["label"].as_str()?.to_string(),
            base: value["base"].as_str().map(str::to_string),
            head: value["head"].as_str()?.to_string(),
            ref_: value["ref"].as_str().map(str::to_string),
            scope: value["scope"].as_str()?.to_string(),
        })
    }
}

/// One target's outcome. `surfaces` is Some only for a checker whose contract
/// echoes them to the semantic stage.
pub struct Summary {
    pub label: String,
    pub scope: String,
    pub status: String,
    pub hits: Vec<Hit>,
    pub surfaces: Option<Vec<Hit>>,
    pub refused: String,
}

impl Summary {
    pub fn to_json(&self) -> Value {
        let mut summary = json!({
            "label": self.label,
            "scope": self.scope,
            "status": self.status,
            "findings": self.hits.len(),
            "hits": self.hits.iter().map(Hit::to_json).collect::<Vec<_>>(),
            "refused": self.refused,
        });
        if let Some(surfaces) = &self.surfaces {
            summary["surfaces"] = json!(surfaces.iter().map(Hit::to_json).collect::<Vec<_>>());
        }
        summary
    }
}

/// Machine-local inputs the builtins consult. The withheld-names list lives
/// outside every repository: the rule is public, the names it withholds are
/// not. `machine_roots` pins the local path/hostname roots the machine-path
/// sweep refuses; `None` derives them from the calling machine.
pub struct Opts {
    pub withheld_path: Option<PathBuf>,
    pub machine_roots: Option<Vec<String>>,
}

// --------------------------------------------------------- shared evidence

/// The per-run evidence file the orchestrating `check` hands every spawned
/// checker. Deterministic preflight results are recorded once and shared, so
/// a successful baseline is not re-bought by every reviewer that follows -
/// and a standalone run, which sees no file, resolves everything itself.
pub(crate) fn shared_evidence_path() -> Option<PathBuf> {
    std::env::var_os("PROBATOR_STAGE1_EVIDENCE")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
}

/// One cache entry per file under `<evidence>.d/`: concurrent checkers in the
/// same phase share the document, and a read-modify-write on a single JSON
/// object would lose keys. Entries write through their own temp name then
/// rename, so a cache miss is the only failure mode - never a torn document.
fn evidence_entry(path: &Path, key: &str) -> PathBuf {
    path.with_extension("d")
        .join(format!("{}.json", crate::util::sha256(key)))
}

pub(crate) fn evidence_get(path: &Path, key: &str) -> Option<Value> {
    std::fs::read_to_string(evidence_entry(path, key))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
}

pub(crate) fn evidence_store(path: &Path, key: &str, value: Value) {
    // The orchestrator owns the private evidence root; a missing ancestor
    // must not be recreated here - a recreated root would land with
    // permissive defaults outside the trusted 0700 boundary.
    let dir = path.with_extension("d");
    match std::fs::create_dir(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => {}
        Err(_) => return,
    }
    let entry = evidence_entry(path, key);
    let tmp = dir.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        crate::util::sha256(key)
    ));
    let body = serde_json::to_string(&value).unwrap_or_default();
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(&tmp, &entry);
    }
}

// ---------------------------------------------------------- single-flight

/// One shared cache key's fill duty, claimed across the concurrent
/// checkers a gate event spawns. Without it every reviewer that misses
/// the entry pays the same remote fetch and the same snapshot scan at
/// once: `evidence_begin` hands the stored value to a caller that finds
/// it, a `Fill` to the caller that must produce it, and has siblings wait
/// behind a lock file rather than repeat the work. A lock owner is probed
/// with the same `kill -0` the run custodian uses - a live owner is
/// waited on without a wall-clock bound, and only its death hands the
/// duty to the next claimant.
pub(crate) enum Evidence<'a> {
    Hit(Value),
    Fill(Fill<'a>),
}

pub(crate) struct Fill<'a> {
    path: &'a Path,
    key: String,
    /// Present only when this process created the lock; dropping removes
    /// it so a failed compute frees the duty for the next claimant.
    lock: Option<PathBuf>,
}

impl Fill<'_> {
    /// Store the computed entry, then release the claim.
    pub(crate) fn store(self, value: Value) {
        evidence_store(self.path, &self.key, value);
    }
}

impl Drop for Fill<'_> {
    fn drop(&mut self) {
        if let Some(lock) = &self.lock {
            let _ = std::fs::remove_file(lock);
        }
    }
}

/// A live-pid probe through the same `kill -0` the run custodian uses.
fn pid_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// The single-flight entry point: `Hit` when the entry already exists,
/// `Fill` when this process owns the compute-and-store duty. A lock the
/// caller cannot create at all degrades to an uncoordinated fill - the
/// same work the no-cache path always paid, never a wrong verdict.
pub(crate) fn evidence_begin<'a>(path: &'a Path, key: &str) -> Evidence<'a> {
    let dir = path.with_extension("d");
    // The entry dir is otherwise created on first store; a claim needs it
    // up front, under the same rule - the orchestrator's missing ancestor
    // is never recreated, so a cache that cannot open just fills plainly.
    match std::fs::create_dir(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && dir.is_dir() => {}
        Err(_) => {
            return Evidence::Fill(Fill {
                path,
                key: key.to_string(),
                lock: None,
            });
        }
    }
    let lock = dir.join(format!("{}.lock", crate::util::sha256(key)));
    // An unreadable or empty lock can be mid-create between open and pid
    // write; it earns a short grace before being treated as ownerless. Both
    // wait branches share one poll rhythm and one grace bound, defined here.
    const LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(50);
    const LOCK_GRACE_POLLS: u8 = 20;
    let mut grace = 0u8;
    loop {
        if let Some(hit) = evidence_get(path, key) {
            return Evidence::Hit(hit);
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
        {
            Ok(mut file) => {
                use std::io::Write as _;
                let _ = writeln!(file, "{}", std::process::id());
                // A sibling may have stored between our miss and our claim;
                // release the lock we just took before handing back its entry.
                if let Some(hit) = evidence_get(path, key) {
                    drop(file);
                    let _ = std::fs::remove_file(&lock);
                    return Evidence::Hit(hit);
                }
                return Evidence::Fill(Fill {
                    path,
                    key: key.to_string(),
                    lock: Some(lock),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let owner = std::fs::read_to_string(&lock)
                    .ok()
                    .and_then(|text| text.trim().parse::<u32>().ok());
                match owner {
                    Some(pid) if pid_alive(pid) => {
                        grace = 0;
                        std::thread::sleep(LOCK_POLL);
                    }
                    _ if grace < LOCK_GRACE_POLLS => {
                        grace += 1;
                        std::thread::sleep(LOCK_POLL);
                    }
                    _ => {
                        grace = 0;
                        let _ = std::fs::remove_file(&lock);
                    }
                }
            }
            Err(_) => {
                return Evidence::Fill(Fill {
                    path,
                    key: key.to_string(),
                    lock: None,
                });
            }
        }
    }
}

/// The paths an operation carries - one enumeration so the deterministic
/// stage and the paid stage can never judge different sets. A range diffs
/// NUL-delimited against its base; a snapshot lists the whole tree. Renames
/// count as delete+add, and paths with newlines or quotes cannot split
/// entries.
pub fn outgoing_paths_range(
    repo: &str,
    base: Option<&str>,
    head: &str,
) -> Result<Vec<String>, String> {
    let output = git(
        repo,
        &[
            "diff",
            "--name-only",
            "--no-renames",
            "-z",
            base.unwrap_or(EMPTY_TREE),
            head,
        ],
    )?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect())
}

/// The snapshot form of the same enumeration: the whole tree at `head`.
pub fn outgoing_paths_snapshot(repo: &str, head: &str) -> Result<Vec<String>, String> {
    let output = git(repo, &["ls-tree", "-rz", "--name-only", head])?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect())
}

pub fn outgoing_paths(repo: &str, target: &Target) -> Result<Vec<String>, String> {
    if target.scope == "range" {
        outgoing_paths_range(repo, target.base.as_deref(), &target.head)
    } else {
        outgoing_paths_snapshot(repo, &target.head)
    }
}

/// One `ls-tree -r -z` pass over `tree` yielding `(path, mode, oid)` per
/// entry. The records are NUL-delimited, so a newline inside a name cannot
/// split one record into two; callers filter on the mode they accept.
fn ls_tree_entries(repo: &str, tree: &str) -> Result<Vec<(String, String, String)>, String> {
    let mut entries = Vec::new();
    for record in git(repo, &["ls-tree", "-r", "-z", tree])?
        .stdout
        .split(|byte| *byte == 0)
    {
        if record.is_empty() {
            continue;
        }
        let record = String::from_utf8_lossy(record);
        let Some((metadata, path)) = record.split_once('\t') else {
            continue;
        };
        let mut fields = metadata.split_whitespace();
        let (mode, oid) = (
            fields.next().unwrap_or("").to_string(),
            fields.nth(1).unwrap_or("").to_string(),
        );
        entries.push((path.to_string(), mode, oid));
    }
    Ok(entries)
}

/// `owner/name` parsed from the origin remote. A remote that is a local path
/// is not a repository any name can identify.
fn origin_slug(repo: &str) -> String {
    let remote = git_command(repo, &["remote", "get-url", "origin"], None)
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_default();
    if remote.is_empty() {
        return "local/unknown".to_string();
    }
    let mut slug = remote.as_str();
    for prefix in ["git@", "https://", "http://", "ssh://"] {
        if let Some(rest) = slug.strip_prefix(prefix) {
            slug = rest;
            break;
        }
    }
    // scp-style and URL forms both end at the first path segment boundary:
    // host:owner/repo or host/owner/repo.
    if let Some(at) = slug.find([':', '/']) {
        slug = &slug[at + 1..];
    }
    let slug = slug.strip_suffix(".git").unwrap_or(slug);
    let valid = {
        let mut parts = slug.split('/');
        matches!(parts.next(), Some(o) if !o.is_empty() && o.chars().all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-')))
            && matches!(parts.next(), Some(n) if !n.is_empty() && n.chars().all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '-')))
            && parts.next().is_none()
    };
    if valid {
        slug.to_string()
    } else {
        "local/unknown".to_string()
    }
}

fn is_binary(raw: &[u8], window: usize) -> bool {
    raw[..raw.len().min(window)].contains(&0)
}

// ---------------------------------------------------------------------------
// withheld-names-and-credentials (Privacy Cleaner)
// ---------------------------------------------------------------------------

/// Shapes, not keywords, ordered most specific first: a label is the first
/// rule that matches the line. A token shape only counts at an identifier
/// edge; without the left boundary, `task-resource-…` reads as an `sk-…` key.
const EDGE: &str = r"(?:^|[^A-Za-z0-9_-])";
const CREDENTIAL_RULES: [(&str, &str); 9] = [
    (
        "private-key-block",
        r"-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----",
    ),
    ("aws-access-key", r"(AKIA|ASIA)[A-Z0-9]{16}"),
    (
        "github-token",
        r"(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})",
    ),
    ("anthropic-key", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    ("google-api-key", r"AIza[A-Za-z0-9_-]{35}"),
    ("openai-key", r"sk-[A-Za-z0-9_-]{20,}"),
    ("slack-token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("stripe-key", r"(sk|rk)_(live|test)_[A-Za-z0-9]{20,}"),
    (
        "json-web-token",
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    ),
];

/// One name, matched however it is spelled: case and separators are not a
/// difference, so `Widget Go`, `widget-go` and `WidgetGO` are one name.
fn name_pattern(name: &str) -> String {
    let parts: Vec<String> = name
        .split(|c: char| c.is_whitespace() || matches!(c, '.' | '_' | '-'))
        .filter(|part| !part.is_empty())
        .map(regex::escape)
        .collect();
    if parts.is_empty() {
        regex::escape(name)
    } else {
        parts.join("[ _.-]*")
    }
}

/// Whether a slug (`Owner/Repo`) is the repository a scope names: the
/// repository's own name, an owner, or a full slug.
fn in_scope(repo_slug: &str, scope: &str) -> bool {
    if scope.is_empty() {
        return false;
    }
    let (slug, scope) = (repo_slug.to_lowercase(), scope.to_lowercase());
    slug == scope || slug.starts_with(&format!("{scope}/")) || slug.ends_with(&format!("/{scope}"))
}

/// The withheld names for this repository, one per line, `#` for comments. A
/// line may end with `except <owner[/repo]>`: pushing an internal repository
/// whose own name appears throughout its content is not a leak.
fn withheld_names(path: Option<&PathBuf>, repo_slug: &str) -> Vec<String> {
    let path = match path {
        Some(path) => path.clone(),
        None => {
            // Deployments that pinned a private list under the previous checker
            // name keep their protection through the migration window: the new
            // variable wins, the old one still answers while it is the only
            // one set.
            if let Ok(overridden) = std::env::var("PRIVACY_CLEANER_WITHHELD")
                .or_else(|_| std::env::var("CLEAN_AUDITOR_WITHHELD"))
            {
                let overridden = overridden.trim();
                if !overridden.is_empty() {
                    PathBuf::from(overridden)
                } else {
                    default_withheld_path()
                }
            } else {
                default_withheld_path()
            }
        }
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for line in raw.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (name, marker, scope) = {
            let mut split = line.splitn(2, " except ");
            let name = split.next().unwrap_or("").trim().to_string();
            let scope = split.next().unwrap_or("").trim().to_string();
            let marker = if line.contains(" except ") {
                " except "
            } else {
                ""
            };
            (name, marker, scope)
        };
        if !marker.is_empty() && in_scope(repo_slug, &scope) {
            continue;
        }
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}

fn default_withheld_path() -> PathBuf {
    crate::util::config_dir()
        .join("probator")
        .join("withheld-names.txt")
}

/// The local roots whose presence in published content exposes this machine:
/// the caller's home directory, its basename under every platform spelling,
/// the macOS per-user temp root, and the machine hostname in both forms.
/// Each becomes a literal case-insensitive pattern; a basename under three
/// characters is dropped rather than matched inside ordinary words. Tests
/// pin the list through `Opts::machine_roots`.
fn machine_roots(overrides: Option<&Vec<String>>) -> Vec<String> {
    if let Some(roots) = overrides {
        return roots.iter().map(|r| r.trim().to_string()).collect();
    }
    let mut roots = Vec::new();
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let home = home.to_string_lossy().trim().to_string();
        if home.len() > 3 {
            roots.push(home.clone());
            if let Some(base) = Path::new(&home).file_name() {
                let base = base.to_string_lossy();
                if base.len() >= 3 {
                    roots.push(format!("/Users/{base}"));
                    roots.push(format!("/home/{base}"));
                    roots.push(format!("C:\\Users\\{base}"));
                }
            }
        }
    }
    roots.push("/var/_folders/".to_string());
    if let Some(host) = machine_hostname() {
        if host.len() >= 3 {
            roots.push(host.clone());
            if let Some((short, _)) = host.split_once('.') {
                if short.len() >= 3 {
                    roots.push(short.to_string());
                }
            }
        }
    }
    roots.sort();
    roots.dedup();
    roots
}

/// The machine's hostname: environment first, the `hostname` tool as the
/// fallback. Any failure simply yields no hostname rule - a missing signal
/// never errors the sweep.
fn machine_hostname() -> Option<String> {
    for var in ["HOSTNAME", "COMPUTERNAME"] {
        if let Some(value) = std::env::var_os(var) {
            let value = value.to_string_lossy().trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    std::process::Command::new("hostname")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|host| !host.is_empty())
}

/// Every finding in the revision, as path/line/rule. Neither check ever
/// returns the matched text: a refusal must be actionable without repeating
/// the secret, and the developer can read their own line. `git grep -I`
/// skips a blob when the first 8000 bytes hold a NUL; this scan does the same.
///
/// Two scans over two different objects:
///
/// * the head tree - what the publication looks like;
/// * the `base..head` object range - every blob the push *introduces to
///   history*. A credential committed in one commit and removed in a later
///   commit of the same push is absent from the head tree but ships in the
///   published history forever. Without this second scan the deterministic
///   stage could not see it at all.
///
/// The withheld/credential sweep, memoized across sibling checkers: when the
/// orchestrating run provided a shared evidence file, an identical completed
/// scan is reused instead of replayed. The key binds the scan inputs - the
/// target's immutable head/base plus the resolved withheld list - so
/// different content can never reuse a verdict. Cache failures are silent:
/// they cost a rescan, never a wrong verdict.
fn clean_audit(repo: &str, target: &Target, opts: &Opts) -> Result<(String, Vec<Hit>), String> {
    let names = withheld_names(opts.withheld_path.as_ref(), &origin_slug(repo));
    let roots = machine_roots(opts.machine_roots.as_ref());
    let Some(cache) = shared_evidence_path() else {
        return clean_audit_scan(repo, target, &names, &roots);
    };
    let key = {
        let mut parts = format!(
            "clean-audit\u{0}{}\u{0}{}\u{0}",
            target.base.as_deref().unwrap_or(""),
            target.head
        );
        for name in &names {
            parts.push_str(name);
            parts.push('\u{0}');
        }
        for root in &roots {
            parts.push_str(root);
            parts.push('\u{0}');
        }
        format!("scan/{}", crate::util::sha256(&parts))
    };
    // Single-flight: the first checker's sweep fills the shared key while
    // siblings run concurrently on their own entries rather than paying
    // the same immutable-snapshot scan again.
    match evidence_begin(&cache, &key) {
        Evidence::Hit(cached) => {
            let why = cached["why"].as_str().unwrap_or_default().to_string();
            let hits: Vec<Hit> = cached["hits"]
                .as_array()
                .map(|rows| {
                    rows.iter()
                        .filter_map(|row| {
                            Some(Hit {
                                path: row["path"].as_str()?.to_string(),
                                line: row["line"].as_u64()?,
                                rule: row["rule"].as_str()?.to_string(),
                                remedy: None,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            Ok((why, hits))
        }
        Evidence::Fill(fill) => {
            let (why, hits) = clean_audit_scan(repo, target, &names, &roots)?;
            fill.store(json!({
                "why": why,
                "hits": hits.iter().map(Hit::to_json).collect::<Vec<_>>(),
            }));
            Ok((why, hits))
        }
    }
}

/// Stage a batch spec file other local users cannot pre-plant: `create_new`
/// refuses an existing name - symlink, FIFO or regular file alike - the 0600
/// mode keeps the list private, and the returned handle means the child
/// reads the file this process created even if the path is later replaced.
/// Retries cover a random-name collision with a sibling run.
///
/// A caller may pin scratch space by descriptor and export it as
/// `TMPDIR=/dev/fd/N`: that spelling reaches this process but `/dev/fd/N/leaf`
/// joins do not resolve on platforms without fd-relative path lookup
/// (Darwin fdescfs), so a pinned parent is opened through `openat` on a
/// duplicated share of the descriptor and unlinked through `unlinkat`. The
/// returned [`SpecStage`] keeps that parent alive until cleanup runs.
struct SpecStage {
    parent: Option<std::os::fd::OwnedFd>,
    name: std::ffi::OsString,
    path: std::path::PathBuf,
}

impl SpecStage {
    /// Remove the staged list through the same spelling that created it:
    /// `unlinkat` under a pinned parent, `remove_file` under a path one.
    fn unlink(&self) {
        #[cfg(unix)]
        if let Some(parent) = &self.parent {
            use std::os::fd::AsRawFd as _;
            use std::os::unix::ffi::OsStrExt as _;
            let Ok(name) = std::ffi::CString::new(self.name.as_bytes()) else {
                return;
            };
            unsafe {
                libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0);
            }
            return;
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn spec_file() -> Result<(SpecStage, std::fs::File), String> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    // A descriptor-spelled TMPDIR (`/dev/fd/N`) pins the parent by fd, so the
    // leaf is created with openat; every other spelling keeps path ops.
    let pinned_parent = std::env::temp_dir()
        .to_str()
        .and_then(|dir| dir.strip_prefix("/dev/fd/"))
        .and_then(|fd| fd.parse::<i32>().ok())
        .and_then(|fd| {
            // Duplicate so the stage's cleanup owns a live descriptor even
            // if the caller's own share closes first.
            let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
            (dup >= 0).then(|| unsafe { OwnedFd::from_raw_fd(dup) })
        });
    for _ in 0..8 {
        let name = std::ffi::OsString::from(format!(
            "probator-oids-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        if let Some(parent) = &pinned_parent {
            let Ok(cname) = std::ffi::CString::new(name.as_bytes()) else {
                continue;
            };
            let fd = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    cname.as_ptr(),
                    libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
                    0o600,
                )
            };
            if fd >= 0 {
                let file = unsafe { std::fs::File::from_raw_fd(fd) };
                let stage = SpecStage {
                    parent: pinned_parent,
                    name,
                    path: std::path::PathBuf::new(),
                };
                return Ok((stage, file));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(format!("Git could not stage the batch list: {error}"));
        }
        let path = std::env::temp_dir().join(&name);
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        options.mode(0o600);
        match options.open(&path) {
            Ok(file) => {
                let stage = SpecStage {
                    parent: None,
                    name,
                    path,
                };
                return Ok((stage, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!("Git could not stage the batch list: {error}"));
            }
        }
    }
    Err("Git could not stage the batch list: name collision".into())
}

#[cfg(not(unix))]
fn spec_file() -> Result<(SpecStage, std::fs::File), String> {
    for _ in 0..8 {
        let name = std::ffi::OsString::from(format!(
            "probator-oids-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let path = std::env::temp_dir().join(&name);
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => {
                let stage = SpecStage {
                    parent: None,
                    name,
                    path,
                };
                return Ok((stage, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!("Git could not stage the batch list: {error}"));
            }
        }
    }
    Err("Git could not stage the batch list: name collision".into())
}

/// The shared `cat-file --batch` preamble: specs stage through a file
/// (spec_file's 0600/create_new contract - piped stdin plus a parent that
/// stalls reading deadlocks once the list outgrows the pipe buffer), and
/// the returned child streams `<oid> <type> <size>` headers plus blob
/// bodies on the BufReader. Specs must be plain object names (OIDs or
/// revisions) - a path carrying a newline would split one spec into two
/// input lines and desynchronize the header-to-index pairing. The caller
/// owns the child's lifecycle and the list file's cleanup.
fn batch_body_reader(
    repo: &str,
    specs: &[String],
) -> Result<
    Option<(
        std::process::Child,
        std::io::BufReader<std::process::ChildStdout>,
        SpecStage,
    )>,
    String,
> {
    use std::io::{BufReader, Seek as _, SeekFrom, Write as _};
    if specs.is_empty() {
        return Ok(None);
    }
    let (list, mut file) = spec_file()?;
    let spawned = (|| {
        for spec in specs {
            writeln!(file, "{spec}")
                .map_err(|e| format!("Git could not stage the batch list: {e}"))?;
        }
        file.flush()
            .and_then(|_| file.seek(SeekFrom::Start(0)))
            .map_err(|e| format!("Git could not stage the batch list: {e}"))?;
        git_command(repo, &["cat-file", "--batch"], None)
            .stdin(std::process::Stdio::from(file))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("Git could not read the review snapshot: {e}"))
    })();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            list.unlink();
            return Err(error);
        }
    };
    let stdout = BufReader::new(child.stdout.take().unwrap());
    Ok(Some((child, stdout, list)))
}

/// One `<oid> <type> <size>` header off the batch stream: Ok(None) for a
/// spec with no object ("<spec> missing"), Err on a truncated or
/// malformed reply.
fn batch_header(out: &mut impl std::io::BufRead) -> Result<Option<usize>, String> {
    let mut header = String::new();
    if out.read_line(&mut header).unwrap_or(0) == 0 {
        return Err("Git could not read the review snapshot: batch ended early".into());
    }
    if header.trim_end().ends_with(" missing") {
        return Ok(None);
    }
    header
        .trim_end()
        .rsplit_once(' ')
        .filter(|(meta, _)| meta.split_ascii_whitespace().count() == 2)
        .and_then(|(_, size)| size.parse::<usize>().ok())
        .map(Some)
        .ok_or_else(|| {
            format!("Git could not read the review snapshot: bad batch header {header:?}")
        })
}

/// Stream the objects named by `specs` through one `git cat-file --batch`
/// process, in input order: `f` receives the spec's index and the whole
/// blob. This is the unbounded form of `for_each_blob_prefix`.
fn for_each_blob(
    repo: &str,
    specs: &[String],
    f: impl FnMut(usize, &[u8]) -> Result<bool, String>,
) -> Result<(), String> {
    for_each_blob_prefix(repo, specs, usize::MAX, f)
}

/// `for_each_blob` with a bounded view: the callback sees at most `cap`
/// bytes of each blob and the remainder is drained without buffering, so
/// probing a giant blob costs O(cap) memory plus its transit. Early
/// `Ok(false)` or an error stops the walk; every path leaves the child
/// reaped and the spec list removed.
fn for_each_blob_prefix(
    repo: &str,
    specs: &[String],
    cap: usize,
    mut f: impl FnMut(usize, &[u8]) -> Result<bool, String>,
) -> Result<(), String> {
    use std::io::Read as _;
    let Some((mut child, mut out, list)) = batch_body_reader(repo, specs)? else {
        return Ok(());
    };
    let mut result = Ok(());
    let mut walked_all = true;
    'walk: for index in 0..specs.len() {
        let size = match batch_header(&mut out) {
            Err(error) => {
                result = Err(error);
                walked_all = false;
                break 'walk;
            }
            Ok(None) => continue 'walk,
            Ok(Some(size)) => size,
        };
        let need = size.min(cap);
        let mut body = vec![0u8; need];
        let drained = (size - need) as u64;
        let mut newline = [0u8; 1];
        let read = out
            .read_exact(&mut body)
            .and_then(|_| {
                std::io::copy(&mut out.by_ref().take(drained), &mut std::io::sink()).map(|_| ())
            })
            .and_then(|_| out.read_exact(&mut newline));
        if read.is_err() {
            result = Err("Git could not read the review snapshot: truncated batch".into());
            walked_all = false;
            break 'walk;
        }
        match f(index, &body) {
            Ok(true) => {}
            Ok(false) => {
                walked_all = false;
                break 'walk;
            }
            Err(error) => {
                result = Err(error);
                walked_all = false;
                break 'walk;
            }
        }
    }
    if walked_all {
        // Every reply was consumed, so the spec file's EOF retires the
        // child on its own - wait for an honest status rather than kill
        // a process that already finished.
        match child.wait() {
            Ok(status) if status.success() => {}
            Ok(status) => {
                result = Err(git_status_error(
                    "Git could not read the review snapshot",
                    &status,
                    &[],
                ));
            }
            Err(e) => {
                result = Err(format!("Git could not read the review snapshot: {e}"));
            }
        }
    } else {
        // An early exit can leave the child mid-write on output nobody
        // will read; kill it, then reap.
        let _ = child.kill();
        let _ = child.wait();
    }
    list.unlink();
    result
}

fn clean_audit_scan(
    repo: &str,
    target: &Target,
    names: &[String],
    roots: &[String],
) -> Result<(String, Vec<Hit>), String> {
    let mut patterns: Vec<(&str, Regex)> = Vec::new();
    for name in names.iter().filter(|n| !n.trim().is_empty()) {
        patterns.push((
            "withheld-name",
            Regex::new(&format!("(?i){}", name_pattern(name)))
                .map_err(|e| format!("invalid withheld name pattern: {e}"))?,
        ));
    }
    for root in roots.iter().filter(|r| !r.trim().is_empty()) {
        patterns.push((
            "machine-path",
            Regex::new(&format!("(?i){}", regex::escape(root.trim())))
                .map_err(|e| format!("invalid machine path pattern: {e}"))?,
        ));
    }
    for (rule, expression) in CREDENTIAL_RULES {
        patterns.push((
            rule,
            Regex::new(&format!("(?i){EDGE}{expression}"))
                .map_err(|e| format!("invalid credential pattern: {e}"))?,
        ));
    }
    let mut hits = Vec::new();
    let mut scanned: std::collections::HashSet<String> = Default::default();
    let mut files: Vec<(String, String)> = Vec::new();
    for (path, mode, oid) in ls_tree_entries(repo, &target.head)? {
        if mode != "100644" && mode != "100755" {
            continue;
        }
        scanned.insert(oid.clone());
        files.push((path, oid));
    }
    let oids: Vec<String> = files.iter().map(|(_, oid)| oid.clone()).collect();
    for_each_blob(repo, &oids, |index, blob| {
        if is_binary(blob, 8000) {
            return Ok(true);
        }
        for (number, line) in String::from_utf8_lossy(blob).lines().enumerate() {
            let Some((rule, _)) = patterns.iter().find(|(_, pattern)| pattern.is_match(line))
            else {
                continue;
            };
            hits.push(Hit {
                path: files[index].0.clone(),
                line: number as u64 + 1,
                rule: rule.to_string(),
                remedy: None,
            });
            if hits.len() >= MAX_HITS {
                return Ok(false);
            }
        }
        Ok(true)
    })?;
    // The history pass: blobs the range adds that the head-tree pass did not
    // already scan. `rev-list --objects` lists "<sha> <path>" for trees and
    // blobs reachable from head but not base; commits carry no path. A first
    // publication has no base, and then the head's whole history is the range
    // - a first push can orphan credentials exactly like a later one.
    {
        let range = target
            .base
            .as_deref()
            .filter(|b| !b.is_empty())
            .map(|base| format!("{base}..{}", target.head))
            .unwrap_or_else(|| target.head.clone());
        let objects = git(repo, &["rev-list", "--objects", &range])?;
        let mut blobs: Vec<(String, String)> = Vec::new();
        for line in String::from_utf8_lossy(&objects.stdout).lines() {
            let mut parts = line.splitn(2, ' ');
            let Some(oid) = parts.next() else { continue };
            let path = parts.next().unwrap_or("");
            if !oid.is_empty() && !scanned.contains(oid) {
                blobs.push((oid.to_string(), path.to_string()));
            }
        }
        // Blob-or-tree is settled by one batched cat-file query rather
        // than one probe per object.
        if !blobs.is_empty() {
            let specs: Vec<&str> = blobs.iter().map(|(oid, _)| oid.as_str()).collect();
            let checked = batch_check(repo, &specs, "%(objecttype)")?;
            // `--batch-check` prints one row per query, in order - align
            // the answers positionally rather than trusting an echoed
            // name, and a lost row is an error, not a silent drop.
            let rows: Vec<&str> = checked.lines().collect();
            if rows.len() != blobs.len() {
                return Err("Git could not type the review blobs: batch reply lost rows".into());
            }
            let objects: Vec<(String, String)> = blobs
                .into_iter()
                .zip(rows)
                .filter(|(_, row)| row.ends_with("blob"))
                .map(|((oid, path), _)| (oid, path))
                .collect();
            let specs: Vec<String> = objects.iter().map(|(oid, _)| oid.clone()).collect();
            for_each_blob(repo, &specs, |index, blob| {
                if is_binary(blob, 8000) {
                    return Ok(true);
                }
                let (oid, path) = &objects[index];
                let label = if path.is_empty() {
                    format!("history-blob {oid}")
                } else {
                    format!("{path} (range blob {oid})")
                };
                for (number, line) in String::from_utf8_lossy(blob).lines().enumerate() {
                    let Some((rule, _)) =
                        patterns.iter().find(|(_, pattern)| pattern.is_match(line))
                    else {
                        continue;
                    };
                    hits.push(Hit {
                        path: label.clone(),
                        line: number as u64 + 1,
                        rule: rule.to_string(),
                        remedy: None,
                    });
                    if hits.len() >= MAX_HITS {
                        return Ok(false);
                    }
                }
                Ok(true)
            })?;
        }
    }
    let refused = if hits.iter().any(|hit| hit.rule == "withheld-name") {
        "withheld-name"
    } else if hits.iter().any(|hit| hit.rule == "machine-path") {
        "machine-path"
    } else if !hits.is_empty() {
        "credential-shape"
    } else {
        ""
    };
    Ok((refused.to_string(), hits))
}

// ---------------------------------------------------------------------------
// commit-identity (Privacy Cleaner)
// ---------------------------------------------------------------------------

/// The catalogue mirrors cya's attribution policy in compact form: agent
/// display names, dedicated addresses, and the local-part tokens that mark an
/// agent behind a shared `users.noreply.github.com` mailbox. Kept as
/// constants so the deterministic pass has no filesystem dependency.
const AGENT_NAMES: &[&str] = &[
    "claude code",
    "codex",
    "cursor agent",
    "cursoragent",
    "devin ai",
    "commandcodebot",
    "command code bot",
    "github copilot",
    "copilot-swe-agent",
    "openhands",
    "sweep-ai",
    "codegen-sh",
    "jules",
    "aider",
    "crush",
    "gemini-code-assist",
    "factory droid",
    "amazon q",
    "amazonq",
    "windsurf",
    "tabnine",
    "codegeex",
    "junie",
    "kiro",
    "hermes",
    "trae",
    "kimi",
    "qwen",
    "glm",
    "lingma",
];
const AGENT_ADDRESSES: &[&str] = &[
    "noreply@anthropic.com",
    "cursoragent@cursor.com",
    "noreply@commandcode.ai",
    "crush@charm.land",
    "aider@aider.chat",
    "openhands@all-hands.dev",
    "copilot@github.com",
    "devin@cognition.ai",
    "devin@cognition-labs.com",
    "devin-ai-integration[bot]@users.noreply.github.com",
    "noreply@trae.ai",
    "noreply@z.ai",
    "continue@continue.dev",
    "cline@cline.ai",
];
const AGENT_NOREPLY_TOKENS: &[&str] = &[
    "codex", "copilot", "devin", "cursor", "claude", "jules", "sweep-ai",
    "codegen-sh", "openhands", "factory-droid", "factory_droid", "gemini", "kimi",
    "qwen", "glm", "lingma", "aider", "commandcode", "amazon-q",
];
/// Tokens checked inside "Generated with ..." and trailer prose, where no
/// structured address exists.
const AGENT_PROSE_TOKENS: &[&str] = &[
    "claude", "devin", "cursor", "codex", "commandcode", "command code",
    "copilot", "aider", "openhands", "crush", "jules", "gemini", "kimi", "trae",
    "windsurf", "qwen", "glm",
];
const IDENTITY_TRAILER_KEYS: &[&str] = &[
    "co-authored-by",
    "generated-by",
    "assisted-by",
    "claude-session",
    "generated with",
    "co-written-by",
];
const MISCONFIGURED_NAMES: &[&str] = &["user.email", "user.name", "developer", "unknown"];
const LOCAL_EMAIL_SUFFIXES: &[&str] = &[".local", ".lan", ".internal", ".corp", ".localhost"];

/// Whether an attribution position names an agent rather than a person: a
/// bot-shaped name, a known agent name or address, or an agent token in the
/// local part of a shared noreply mailbox.
fn identity_is_agent(name: &str, email: &str) -> bool {
    let name = name.trim().to_lowercase();
    let email = email.trim().to_lowercase();
    let local = email.split('@').next().unwrap_or("");
    name.contains("[bot]")
        || name.contains("agent")
        || name.contains("ai draft")
        || AGENT_NAMES.iter().any(|a| name == *a)
        || AGENT_ADDRESSES.iter().any(|a| email == *a)
        || (email.ends_with("@users.noreply.github.com")
            && AGENT_NOREPLY_TOKENS.iter().any(|t| local.contains(t)))
}

/// Whether an email domain names a machine rather than a routable mailbox:
/// an mDNS or internal suffix, `localhost`, or this machine's own hostname.
fn email_is_machine(email: &str, machine: &str) -> bool {
    let Some((_, domain)) = email.rsplit_once('@') else {
        return false;
    };
    let domain = domain.trim_end_matches('>').to_lowercase();
    domain == "localhost"
        || LOCAL_EMAIL_SUFFIXES.iter().any(|s| domain.ends_with(s))
        || (!machine.is_empty() && domain == machine.to_lowercase())
}

/// Every commit in the audited range, checked for three facts the published
/// record must not carry: an author or committer that names an agent, a
/// mailbox hosted on a machine or internal domain, or a name left at a
/// gitconfig placeholder; and attribution trailers in the message that do
/// the same. `git log` emits one NUL-free record per commit - \x1f between
/// fields, \x1e between commits - so trailers are read as structured lines,
/// not prose.
fn identity_audit(repo: &str, target: &Target) -> Result<Vec<Hit>, String> {
    let range = target
        .base
        .as_deref()
        .filter(|b| !b.is_empty())
        .map(|base| format!("{base}..{}", target.head))
        .unwrap_or_else(|| target.head.clone());
    let output = git(
        repo,
        &[
            "log",
            "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e",
            &range,
        ],
    )?;
    let machine = machine_hostname().unwrap_or_default();
    let mut hits = Vec::new();
    for record in String::from_utf8_lossy(&output.stdout).split('\x1e') {
        let mut fields = record.splitn(6, '\x1f');
        let (Some(sha), Some(an), Some(ae), Some(cn), Some(ce), Some(body)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let sha = sha.trim();
        if sha.is_empty() {
            continue;
        }
        let path = format!("commit {}", &sha[..sha.len().min(12)]);
        for (line, name, email) in [(1u64, an, ae), (2, cn, ce)] {
            if identity_is_agent(name, email) {
                hits.push(Hit {
                    path: path.clone(),
                    line,
                    rule: "identity/agent-attribution".into(),
                    remedy: None,
                });
            }
            if email_is_machine(email, &machine) {
                hits.push(Hit {
                    path: path.clone(),
                    line,
                    rule: "identity/local-hostname".into(),
                    remedy: None,
                });
            }
            if MISCONFIGURED_NAMES.contains(&name.trim().to_lowercase().as_str()) {
                hits.push(Hit {
                    path: path.clone(),
                    line,
                    rule: "identity/misconfigured-name".into(),
                    remedy: None,
                });
            }
        }
        for (number, raw) in body.lines().enumerate() {
            if raw.starts_with(char::is_whitespace) {
                continue;
            }
            let lower = raw.to_lowercase();
            let Some(key) = IDENTITY_TRAILER_KEYS
                .iter()
                .find(|key| lower.starts_with(**key))
            else {
                continue;
            };
            let value = lower[key.len()..].trim_start_matches(':').trim().to_string();
            let (vname, vemail) = match value.rsplit_once('<') {
                Some((n, rest)) => (n.trim().to_string(), rest.trim_end_matches('>').to_string()),
                None => (value.clone(), String::new()),
            };
            if identity_is_agent(&vname, &vemail)
                || AGENT_PROSE_TOKENS.iter().any(|t| value.contains(t))
                || value.contains("[bot]")
            {
                hits.push(Hit {
                    path: path.clone(),
                    line: number as u64 + 3,
                    rule: "identity/agent-attribution".into(),
                    remedy: None,
                });
            }
        }
        if hits.len() >= MAX_HITS {
            break;
        }
    }
    Ok(hits)
}

// ---------------------------------------------------------------------------
// dependency-direction (Privacy Cleaner)
// ---------------------------------------------------------------------------

/// The sibling-repository dependency map, machine-local like the withheld
/// names: one line per repository, `Name <- upstream, upstream, ...`,
/// `#` comments. A document may name this repository's upstreams; a document
/// in an upstream repository must never name one of its downstreams — an
/// upstream naming a downstream publishes that repository's product plan
/// before the downstream has shipped anything on its own.
fn default_deps_path() -> PathBuf {
    crate::util::config_dir()
        .join("probator")
        .join("repo-deps.txt")
}

/// One mapped repository: canonical name, the aliases documents actually
/// use (`Adapter-For-All-Agents|a4aa`), and the upstreams it depends on
/// (canonical names only - the graph never resolves an alias).
struct DepRepo {
    name: String,
    aliases: Vec<String>,
    upstreams: Vec<String>,
    /// Repositories whose public documents may name this entry — the same
    /// `except` escape the withheld-name list uses. A downstream that is
    /// itself public (or that shares its name with an upstream's own
    /// vocabulary) is declared here rather than deleted, so the dependency
    /// map stays truthful.
    except: String,
}

impl DepRepo {
    /// Every spelling this repository answers to, keyed for comparison.
    fn names(&self) -> impl Iterator<Item = String> + '_ {
        std::iter::once(self.name.as_str())
            .chain(self.aliases.iter().map(String::as_str))
            .map(dep_key)
    }

    /// Every spelling, as document-match patterns.
    fn patterns(&self) -> impl Iterator<Item = Result<Regex, String>> + '_ {
        std::iter::once(self.name.as_str())
            .chain(self.aliases.iter().map(String::as_str))
            .map(|spelling| {
                Regex::new(&format!("(?i){}", name_pattern(spelling)))
                    .map_err(|e| format!("invalid dependency name pattern: {e}"))
            })
    }
}

fn deps_map(path: &std::path::Path) -> Vec<DepRepo> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for line in raw.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((name, upstreams)) = line.split_once("<-") else {
            continue;
        };
        let (name, except) = {
            let mut split = name.splitn(2, " except ");
            let name = split.next().unwrap_or("").trim().to_string();
            let scope = split.next().unwrap_or("").trim().to_string();
            (name, scope)
        };
        let mut spellings = name.split('|').map(str::trim).filter(|s| !s.is_empty());
        let Some(canonical) = spellings.next() else {
            continue;
        };
        entries.push(DepRepo {
            name: canonical.to_string(),
            aliases: spellings.map(str::to_string).collect(),
            except,
            upstreams: upstreams
                .split(',')
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .map(str::to_string)
                .collect(),
        });
    }
    entries
}

/// The public-document surface this rule guards: prose a reader meets on
/// the repository page. Source files are out of scope — code and comments
/// legitimately spell sibling names in tests, examples and identifiers.
fn is_document(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, Some(ext)),
        _ => (name, None),
    };
    if let Some(ext) = ext {
        if matches!(
            ext.to_ascii_lowercase().as_str(),
            "md" | "markdown" | "mdown" | "rst" | "adoc" | "asciidoc" | "txt" | "org"
        ) {
            return true;
        }
        return false;
    }
    matches!(
        stem.to_ascii_lowercase().as_str(),
        "readme"
            | "changelog"
            | "changes"
            | "history"
            | "news"
            | "contributing"
            | "authors"
            | "notice"
            | "roadmap"
            | "security"
            | "support"
    )
}

/// The comparison form: case and separators erased, so `Repo-Name.42`,
/// `repo name 42` and `REPONAME42` are one repository.
fn dep_key(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Every repository `name` transitively depends on, keyed for comparison.
fn dep_closure(entries: &[DepRepo], name: &str) -> std::collections::HashSet<String> {
    let mut seen = std::collections::HashSet::new();
    let mut pending = vec![dep_key(name)];
    while let Some(current) = pending.pop() {
        for entry in entries {
            if !entry.names().any(|spelling| spelling == current) {
                continue;
            }
            for upstream in &entry.upstreams {
                let key = dep_key(upstream);
                if seen.insert(key.clone()) {
                    pending.push(key);
                }
            }
        }
    }
    seen
}

/// Public documents of this repository may name its upstreams, never its
/// downstreams. Only downstream names are compiled: a reference to an
/// upstream or an unrelated sibling needs no finding.
fn deps_audit(repo: &str, target: &Target, _opts: &Opts) -> Result<Vec<Hit>, String> {
    let path = std::env::var("PROBATOR_REPO_DEPS")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_deps_path);
    let entries = deps_map(&path);
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let me = dep_key(origin_slug(repo).rsplit('/').next().unwrap_or_default());
    let mut forbidden: Vec<(String, Regex)> = Vec::new();
    for entry in &entries {
        if entry.names().any(|spelling| spelling == me)
            || !dep_closure(&entries, &entry.name).contains(&me)
            || (!entry.except.is_empty() && in_scope(&origin_slug(repo), &entry.except))
        {
            continue;
        }
        for pattern in entry.patterns() {
            forbidden.push((entry.name.clone(), pattern?));
        }
    }
    if forbidden.is_empty() {
        return Ok(Vec::new());
    }
    let mut docs: Vec<(String, String)> = Vec::new();
    for (path, mode, oid) in ls_tree_entries(repo, &target.head)? {
        if mode != "100644" && mode != "100755" {
            continue;
        }
        if is_document(&path) {
            docs.push((path, oid));
        }
    }
    let mut hits = Vec::new();
    let oids: Vec<String> = docs.iter().map(|(_, oid)| oid.clone()).collect();
    for_each_blob(repo, &oids, |index, blob| {
        if is_binary(blob, 8000) {
            return Ok(true);
        }
        for (number, line) in String::from_utf8_lossy(blob).lines().enumerate() {
            let Some((name, _)) = forbidden.iter().find(|(_, pattern)| pattern.is_match(line))
            else {
                continue;
            };
            hits.push(Hit {
                path: format!("{} ({name})", docs[index].0),
                line: number as u64 + 1,
                rule: "dependency-direction".to_string(),
                remedy: Some(
                    "upstream documents must not name a downstream repository; \
                     drop the reference or move it into the downstream's own docs",
                ),
            });
            if hits.len() >= MAX_HITS {
                return Ok(false);
            }
        }
        Ok(true)
    })?;
    Ok(hits)
}

// ---------------------------------------------------------------------------
// workspace-hygiene
// ---------------------------------------------------------------------------

static MERGE_ARTIFACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\.(orig|rej)$|\.(BACKUP|BASE|LOCAL|REMOTE)\.[0-9a-f]{7,}").unwrap()
});
static OS_JUNK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(^|/)(\.DS_Store|Thumbs\.db|desktop\.ini)$|(^|/)\._[^/]+$|\.(swp|swo)$|~$|(^|/)\.idea/|(^|/)\.history/|(^|/)\.workspace-root$|\.code-workspace$|(^|/)[^/]*\.local$",
    )
    .unwrap()
});
static SIDE_MARKERS: LazyLock<BytesRegex> =
    LazyLock::new(|| BytesRegex::new(r"^(<{7}|>{7})( .*)?\r?$").unwrap());
static EQUALS_MARKER: LazyLock<BytesRegex> =
    LazyLock::new(|| BytesRegex::new(r"^={7}\r?$").unwrap());
static BINARY_HINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\.(png|jpe?g|gif|ico|icns|zip|gz|bz2|xz|7z|woff2?|ttf|otf|pdf|jar|war|so|dylib|dll|exe|a|o|wasm|mp[34]|mov|webm|psd|keystore|jks|db|sqlite)$",
    )
    .unwrap()
});

const MAX_FILE_BYTES: usize = 2 * 1024 * 1024;
/// Reported hits are capped so a flooded report stays readable; the cap is one
/// constant because the tree pass and the range-blob pass share the budget.
const MAX_HITS: usize = 20;

fn junk_name_hit(path: &str) -> &'static str {
    if MERGE_ARTIFACT.is_match(path) {
        return "merge-artifact";
    }
    if OS_JUNK.is_match(path) {
        return "os-junk";
    }
    ""
}

/// 1-based lines carrying a conflict marker; `=======` counts only beside a
/// `<` or `>` marker - under a heading it is legitimate prose.
fn marker_lines(content: &[u8]) -> Vec<u64> {
    let mut sides = Vec::new();
    let mut equals = Vec::new();
    for (index, line) in content.split(|byte| *byte == b'\n').enumerate() {
        let number = index as u64 + 1;
        if SIDE_MARKERS.is_match(line) {
            sides.push(number);
        } else if EQUALS_MARKER.is_match(line) {
            equals.push(number);
        }
    }
    sides.extend(if sides.is_empty() { Vec::new() } else { equals });
    sides.sort_unstable();
    sides
}

/// The paths the range actually touched - added, modified or deleted - or
/// None when the target carries no base to diff against, meaning everything
/// outgoing is new. Snapshot-scoped targets still carry a base when the
/// operation knows one, so this works under either scope.
fn changed_paths(
    repo: &str,
    target: &Target,
) -> Result<Option<std::collections::HashSet<String>>, String> {
    let Some(base) = target.base.as_deref().filter(|b| !b.is_empty()) else {
        return Ok(None);
    };
    let output = git(
        repo,
        &[
            "diff",
            "--name-only",
            "--no-renames",
            "-z",
            base,
            &target.head,
        ],
    )?;
    Ok(Some(
        String::from_utf8_lossy(&output.stdout)
            .split('\0')
            .filter(|path| !path.is_empty())
            .map(str::to_string)
            .collect(),
    ))
}

/// Paths matching `kind` that the range touched. With a base, the changed set
/// is authoritative - it also names deletions the head tree no longer lists;
/// without one, every outgoing path is new by definition.
fn range_touched(
    changed: &Option<std::collections::HashSet<String>>,
    paths: &[String],
    kind: fn(&str) -> bool,
) -> Vec<String> {
    let mut found: Vec<String> = match changed {
        Some(set) => set.iter().filter(|p| kind(p)).cloned().collect(),
        None => paths.iter().filter(|p| kind(p.as_str())).cloned().collect(),
    };
    found.sort();
    found
}

/// Files an agent host reads as standing instructions or wiring: in this
/// workflow repository text IS executable, so a change here is reviewed as an
/// injection surface, not as documentation.
fn is_instruction_channel(path: &str) -> bool {
    const DIRS: [&str; 9] = [
        ".agents/",
        ".claude/",
        ".codex/",
        ".continue/",
        ".cursor/",
        ".devin/",
        ".githooks/",
        ".opencode/",
        ".windsurf/",
    ];
    if DIRS
        .iter()
        .any(|d| path.starts_with(d) || path.contains(&format!("/{d}")))
    {
        return true;
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    name.eq_ignore_ascii_case("agents.md")
        || name.eq_ignore_ascii_case("claude.md")
        || name.eq_ignore_ascii_case("gemini.md")
        || name.eq_ignore_ascii_case("skill.md")
        || matches!(
            name,
            ".cursorrules" | ".windsurfrules" | ".mcp.json" | "mcp.json" | "mcp.toml"
        )
}

/// Files whose change IS a published-interface change: wire contracts,
/// schemas and migration histories. The semantic stage adjudicates them; the
/// static stage only guarantees they are never silently overlooked.
fn is_interface_surface(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_lowercase();
    name.ends_with(".proto")
        || name.ends_with(".graphql")
        || name.ends_with(".thrift")
        || name.ends_with(".avsc")
        || name.ends_with(".avdl")
        || name.ends_with(".d.ts")
        || name.ends_with(".schema.json")
        || name.starts_with("openapi")
        || name.starts_with("swagger")
        || path.split('/').any(|part| part == "migrations")
}

/// The paths the operation removes: a deletion is never a finding.
fn deleted_paths(repo: &str, target: &Target) -> Result<std::collections::HashSet<String>, String> {
    if target.scope != "range" {
        return Ok(Default::default());
    }
    let output = git(
        repo,
        &[
            "diff",
            "--name-only",
            "--no-renames",
            "-z",
            "--diff-filter=D",
            target.base.as_deref().unwrap_or(EMPTY_TREE),
            &target.head,
        ],
    )?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect())
}

fn hygiene_audit(
    repo: &str,
    target: &Target,
    with_surfaces: bool,
) -> Result<(Vec<Hit>, Vec<Hit>), String> {
    let mut hits = Vec::new();
    let deleted = deleted_paths(repo, target)?;
    let paths = outgoing_paths(repo, target)?;
    // Published-interface changes the range touches are surfaced for the
    // semantic stage to adjudicate: a migration, a schema or a versioned wire
    // contract that moved must be answered, not merely noticed. A contract
    // that does not echo surfaces has no consumer for the diff, so it is not
    // computed - an empty set, not None, since None means "all paths are new".
    let changed = if with_surfaces {
        changed_paths(repo, target)?
    } else {
        Some(Default::default())
    };
    let surfaces: Vec<Hit> = range_touched(&changed, &paths, is_interface_surface)
        .into_iter()
        .map(|path| Hit {
            path,
            line: 1,
            rule: "surface/interface-change".into(),
            remedy: remedy("surface/interface-change"),
        })
        .collect();
    let mut candidates = Vec::new();
    for path in paths {
        if deleted.contains(&path) {
            continue;
        }
        let rule = junk_name_hit(&path);
        if !rule.is_empty() {
            hits.push(Hit {
                path,
                line: 0,
                rule: rule.to_string(),
                remedy: None,
            });
            continue;
        }
        if BINARY_HINT.is_match(&path) {
            continue;
        }
        candidates.push(path);
    }
    let oids = head_blob_oids(repo, target, &candidates)?;
    let mut paths_kept = Vec::new();
    let mut specs = Vec::new();
    for (path, oid) in candidates.into_iter().zip(oids) {
        let Some(oid) = oid else { continue };
        specs.push(oid);
        paths_kept.push(path);
    }
    for_each_blob(repo, &specs, |index, blob| {
        if blob.len() > MAX_FILE_BYTES || is_binary(blob, 8192) {
            return Ok(true);
        }
        for line in marker_lines(blob) {
            hits.push(Hit {
                path: paths_kept[index].clone(),
                line,
                rule: "conflict-marker".into(),
                remedy: None,
            });
        }
        Ok(true)
    })?;
    Ok((hits, surfaces))
}

// ---------------------------------------------------------------------------
// static-checklist
// ---------------------------------------------------------------------------

const MAX_SCAN_BYTES: usize = 1024 * 1024;
const SKIPPED_DIRS: [&str; 11] = [
    "node_modules",
    "vendor",
    "third_party",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "target",
    ".git",
    "bower_components",
];
const PROSE_SUFFIXES: [&str; 3] = [".md", ".rst", ".adoc"];
const PROSE_NAMES: [&str; 6] = [
    "readme",
    "changelog",
    "license",
    "notice",
    "authors",
    "contributing",
];
const CREDENTIAL_FILES: [&str; 9] = [
    ".netrc",
    "_netrc",
    ".pypirc",
    ".htpasswd",
    ".git-credentials",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials.json",
];

fn remedy(rule: &str) -> Option<&'static str> {
    Some(match rule {
        "dependency/lockfile-not-updated" => "commit the lockfile with the manifest",
        "ci/pull-request-target" => {
            "use `pull_request` unless the workflow needs the base repository's secrets"
        }
        "ci/write-all-permissions" => "grant the specific permissions the job needs",
        "ci/floating-action-ref" => "pin the action to an immutable reference",
        "ci/remote-script-execution" => {
            "download, verify and run a pinned artifact instead of piping to a shell"
        }
        "ci/tls-verification-disabled" => "keep TLS verification enabled in CI",
        "container/root-user" => "run the image as a non-root user",
        "container/privileged" => {
            "drop the privileged flag and grant the specific capability needed"
        }
        "container/world-writable" => "use the narrowest mode the step needs",
        "container/secret-in-image" => "pass secrets at run time, never as an image build argument",
        "container/unpinned-base-image" => "pin the base image by tag and digest",
        "hardening/ignore-rule-removed" => "restore the ignore rule or untrack the file first",
        "hardening/codeowner-removed" => {
            "restore the owner or land the governance change on its own"
        }
        "hardening/registry-source-changed" => "keep the registry source unchanged in this change",
        "hardening/credential-file-added" => "keep credential files out of the repository",
        "runtime/tls-verification-disabled" => "verify certificates in the shipped code path",
        "runtime/debug-enabled" => "ship with debug mode disabled",
        "runtime/cors-wildcard-credentials" => "name the allowed origins when credentials are sent",
        "surface/dependency-url-source" => {
            "confirm this dependency source is intended -- the semantic review will judge it"
        }
        "surface/install-hook-added" => {
            "confirm this install hook is intended -- the semantic review will judge it"
        }
        "surface/private-address" => {
            "confirm this address is intended to ship -- the semantic review will judge it"
        }
        "surface/plaintext-endpoint" => {
            "confirm this plaintext endpoint is intended -- the semantic review will judge it"
        }
        "surface/instruction-channel" => {
            "this file is read as standing instructions by agent hosts -- confirm the change is intended and not an injected directive"
        }
        "surface/interface-change" => {
            "this change touches a published interface -- confirm a migration or version bump answers it"
        }
        "hardening/protection-unreadable" => {
            "a protection file's diff read as binary on every surviving side -- the deterministic stage could not check its removed lines; review the blobs directly"
        }
        "surface/suppressed-unreadable" => {
            "a suppressed diff read as binary on every surviving side - the deterministic stage could not check its lines; review the blobs directly"
        }
        _ => return None,
    })
}

/// Which protection file a path is - the set whose removed lines and
/// unreadable suppressions the hardening rules answer for. Every site
/// that classifies a path as protected goes through `protection_kind` so
/// the set can never narrow on one side alone.
#[derive(Clone, Copy)]
enum ProtectionKind {
    Ignore,
    Codeowners,
}

fn protection_kind(path: &str) -> Option<ProtectionKind> {
    let name = path.rsplit('/').next().unwrap_or(path);
    if name == ".gitignore" {
        Some(ProtectionKind::Ignore)
    } else if name.to_uppercase().starts_with("CODEOWNERS") {
        Some(ProtectionKind::Codeowners)
    } else {
        None
    }
}

fn is_protection_file(path: &str) -> bool {
    protection_kind(path).is_some()
}

fn is_prose(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_lowercase();
    if PROSE_NAMES.contains(&name.split('.').next().unwrap_or("")) {
        return true;
    }
    suffix_of(&name).is_some_and(|suffix| PROSE_SUFFIXES.contains(&suffix.as_str()))
}

fn is_skipped(path: &str) -> bool {
    path.split('/').any(|part| SKIPPED_DIRS.contains(&part))
}

fn is_workflow(path: &str) -> bool {
    path.starts_with(".github/workflows/") && (path.ends_with(".yml") || path.ends_with(".yaml"))
}

fn is_dockerfile(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_lowercase();
    name.starts_with("dockerfile") || name.ends_with(".dockerfile") || name == "containerfile"
}

fn is_compose(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_lowercase();
    (name.starts_with("docker-compose") || name.starts_with("compose"))
        && (name.ends_with(".yml") || name.ends_with(".yaml"))
}

/// Added and removed lines of one file's diff, each numbered.
type DiffLines = (Vec<(u64, String)>, Vec<(u64, String)>);

/// `git` quotes a diff-header path C-style only when it cannot print it
/// raw (control, non-ASCII, quotes). Undo exactly that quoting.
fn unquote_git_path(raw: &str) -> String {
    let raw = raw.trim();
    if !(raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2) {
        return raw.to_string();
    }
    let mut out = Vec::new();
    let mut chars = raw[1..raw.len() - 1].chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.extend_from_slice(c.to_string().as_bytes());
            continue;
        }
        match chars.next() {
            Some('n') => out.push(b'\n'),
            Some('t') => out.push(b'\t'),
            Some('r') => out.push(b'\r'),
            Some('a') => out.push(0x07),
            Some('b') => out.push(0x08),
            Some('f') => out.push(0x0c),
            Some('v') => out.push(0x0b),
            Some('\\') => out.push(b'\\'),
            Some('"') => out.push(b'"'),
            Some(d @ '0'..='7') => {
                let mut value = d.to_digit(8).unwrap_or(0);
                for _ in 0..2 {
                    match chars.next().and_then(|c| c.to_digit(8)) {
                        Some(digit) => value = value * 8 + digit,
                        None => break,
                    }
                }
                out.push(value as u8);
            }
            Some(other) => out.extend_from_slice(other.to_string().as_bytes()),
            None => {}
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The attribute-pinning floor: `GIT_ATTR_SOURCE` is honored by Git
/// 2.42+, so below it the variable would be silently ignored and an
/// ambient `.gitattributes` could suppress a path the head
/// classification calls plain text - a divergent authority. The floor
/// is a named constant so callers, docs and tests agree on one value.
const ATTR_SOURCE_FLOOR: (u64, u64) = (2, 42);

/// `(major, minor)` out of a `git version` line, or None when the output
/// is not a version string at all.
fn parse_git_version(text: &str) -> Option<(u64, u64)> {
    let version = text
        .trim()
        .strip_prefix("git version ")?
        .split_whitespace()
        .next()?;
    let mut parts = version.split('.').filter_map(|p| p.parse::<u64>().ok());
    Some((parts.next()?, parts.next()?))
}

/// Whether one `git version` line clears the attribute floor - the
/// whole capability decision, so tests exercise the same predicate the
/// gate consults rather than a reimplemented comparison.
fn attr_floor_met(version_line: &str) -> bool {
    parse_git_version(version_line).is_some_and(|version| version >= ATTR_SOURCE_FLOOR)
}

/// Whether this git honors `GIT_ATTR_SOURCE`: fetch the version line,
/// then apply `attr_floor_met` - the only wiring `require_attr_source`
/// adds is the call and the error.
fn attr_source_supported(repo: &str) -> Result<bool, String> {
    let output = git(repo, &["version"])?;
    Ok(attr_floor_met(&String::from_utf8_lossy(&output.stdout)))
}

/// Fail the range audit closed rather than audit on a divergent
/// attribute source.
fn require_attr_source(repo: &str) -> Result<(), String> {
    if attr_source_supported(repo)? {
        return Ok(());
    }
    Err("Git could not read the review snapshot: range audits need Git 2.42+ so attribute passes can pin the audited tree".into())
}

/// (added, removed) per path across the whole range, plus the suppressed
/// paths where no surviving side was readable - the caller surfaces those
/// so the semantic stage knows coverage stopped. One `git diff` parses
/// every file instead of one process per path; same numbering the
/// per-path reader used: added at head, removed at base.
///
/// A path the hunk pass skipped is classified by its raw oid pair and by
/// its `diff` attribute at the audited head - both the hunk pass (via
/// `GIT_ATTR_SOURCE`) and the classification pass (via `--source`) are
/// bound to the same tree, one authority. A same-oid record is a
/// mode-only change and is skipped without reading a blob; a path the
/// raw pass did not record is recovered with both sides eligible. A path
/// suppressed by git's own binary-content detection (`diff` unspecified
/// or set, non-protection) is an ordinary binary asset and drops
/// silently. Everything else - attribute-suppressed paths, protection
/// files, and paths the attribute pass did not answer - is probed per
/// side with a bounded prefix read: each surviving side disqualifies
/// only its own lines when it reads as binary, a path with one readable
/// side is recovered and the unreadable side's lines are dropped without
/// a surface, and a path with no readable side lands in the second
/// return value. Recovery is uncapped by size - an unsuppressed twin
/// emits the same patch bytes - and the forced diff streams through a
/// keep-filtered parser, so memory follows the kept delta rather than
/// the patch.
fn range_diff(
    repo: &str,
    target: &Target,
    paths: &[String],
) -> Result<(std::collections::HashMap<String, DiffLines>, Vec<String>), String> {
    let base = target.base.as_deref().unwrap_or(EMPTY_TREE);
    require_attr_source(repo)?;
    // The hunk pass evaluates attributes at the audited head, matching the
    // classification pass - GIT_ATTR_SOURCE pins both to the same tree.
    let output = git_head_attr(
        repo,
        &[
            "diff",
            "--no-color",
            "--no-renames",
            "--unified=0",
            base,
            &target.head,
        ],
        &target.head,
    )?;
    let mut diffs = parse_diff_hunks(&output.stdout);
    // Paths the hunk pass named keep their parsed hunks; the rest split
    // by their raw oid pair - a same-oid record is a mode-only change
    // skipped before any blob is read, a path the raw pass did not
    // record is recovered unconditionally rather than guessed at, and a
    // real oid pair goes on to the attribute split below.
    let mut candidates: Vec<String> = Vec::new();
    for path in paths {
        if !diffs.contains_key(path.as_str()) {
            candidates.push(path.clone());
        }
    }
    if candidates.is_empty() {
        return Ok((diffs, Vec::new()));
    }
    let oids = range_oids(repo, target)?;
    let is_zero = |oid: &str| oid.bytes().all(|byte| byte == b'0');
    // Each surviving side is judged on its own: the base blob owns the
    // removed lines, the head blob the added ones.
    let mut sides: Vec<(String, String, String)> = Vec::new();
    let mut recover: Vec<String> = Vec::new();
    let mut gating: std::collections::HashMap<String, (bool, bool)> = Default::default();
    for path in candidates {
        match oids.get(path.as_str()) {
            // Changed without a raw record: recover rather than guess.
            None => {
                gating.insert(path.clone(), (true, true));
                recover.push(path);
            }
            // A same-oid record is a mode-only change with nothing to
            // recover - it is skipped before any blob is read.
            Some((base_oid, head_oid)) if base_oid == head_oid => continue,
            Some((base_oid, head_oid)) => {
                sides.push((path, base_oid.clone(), head_oid.clone()));
            }
        }
    }
    // The attribute split decides which suppressed paths even merit a
    // probe: a path suppressed by git's own binary-content detection is an
    // ordinary binary asset and is dropped without a surface, while an
    // attribute-suppressed path - or one the attribute pass did not
    // answer - is probed for a readable side. Protection files are always
    // probed regardless of the attribute answer, so a binary-marked or
    // content-detected `.gitignore` cannot hide a dropped rule line.
    let candidates: Vec<String> = sides.iter().map(|(path, _, _)| path.clone()).collect();
    let attrs = diff_attrs(repo, &target.head, &candidates)?;
    let probed_path = |path: &String| -> bool {
        // `unset` (a `-diff`/`binary` attribute) or a named driver
        // suppressed the hunk; `unspecified`/`set` means git's binary
        // detection did. A missing answer is unknown, not a negative:
        // the path is probed rather than trusted away. A protection
        // file is probed regardless of the answer - its removed lines
        // are owed to the removal rules even when the blob reads binary.
        is_protection_file(path)
            || attrs
                .get(path)
                .is_none_or(|state| state != "unspecified" && state != "set")
    };
    // Probe each surviving side with a bounded prefix read - a suppressed
    // blob that is genuinely binary produces only mojibake lines, so that
    // side disqualifies only its own added or removed lines. Recovery
    // itself is uncapped: an unsuppressed twin emits the same patch
    // bytes, so no size gate applies to the recovery list.
    let probes: Vec<String> = sides
        .iter()
        .filter(|(path, ..)| probed_path(path))
        .flat_map(|(_, b, h)| [b, h].into_iter().filter(|oid| !is_zero(oid)).cloned())
        .collect();
    let mut binary: std::collections::HashSet<String> = Default::default();
    for_each_blob_prefix(repo, &probes, 8000, |index, prefix| {
        if is_binary(prefix, 8000) {
            binary.insert(probes[index].clone());
        }
        Ok(true)
    })?;
    let mut excluded: Vec<String> = Vec::new();
    for (path, base_oid, head_oid) in sides {
        if !probed_path(&path) {
            continue;
        }
        let base_ok = !is_zero(&base_oid) && !binary.contains(&base_oid);
        let head_ok = !is_zero(&head_oid) && !binary.contains(&head_oid);
        // Only a readable side earns the forced diff: a path binary on
        // every surviving side has no lines worth patching and is
        // reported as unreadable coverage instead of silently dropped.
        if base_ok || head_ok {
            gating.insert(path.clone(), (base_ok, head_ok));
            recover.push(path);
        } else {
            excluded.push(path);
        }
    }
    if recover.is_empty() {
        return Ok((diffs, excluded));
    }
    // The forced patch streams through the parser rather than landing
    // whole: the keep filter drops a disqualified side's lines as they
    // arrive, so memory follows the kept delta, never the raw patch.
    let mut args: Vec<&str> = vec![
        "--literal-pathspecs",
        "diff",
        "--text",
        "--no-color",
        "--no-renames",
        "--unified=0",
        base,
        &target.head,
        "--",
    ];
    args.extend(recover.iter().map(String::as_str));
    let mut child = git_command(repo, &args, Some(target.head.as_str()))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("Git could not read the review diff: {e}"))?;
    let mut parser = DiffParser::new(|path: &str, added: bool| {
        // A binary base has no readable removed lines, a binary head no
        // added ones - keep only the side the surviving blob can honestly
        // describe.
        gating
            .get(path)
            .map(|&(base_ok, head_ok)| if added { head_ok } else { base_ok })
            .unwrap_or(true)
    });
    {
        use std::io::{BufRead as _, BufReader};
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut raw: Vec<u8> = Vec::new();
        loop {
            raw.clear();
            match out.read_until(b'\n', &mut raw) {
                Ok(0) => break,
                Ok(_) => parser.feed_raw(&raw),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("Git could not read the review diff: {e}"));
                }
            }
        }
    }
    match child.wait() {
        Ok(status) if status.success() => {}
        Ok(status) => {
            return Err(git_status_error(
                "Git could not read the review diff",
                &status,
                &[],
            ));
        }
        Err(e) => return Err(format!("Git could not read the review diff: {e}")),
    }
    for (path, pair) in parser.finish() {
        if !(pair.0.is_empty() && pair.1.is_empty()) {
            diffs.entry(path).or_insert(pair);
        }
    }
    Ok((diffs, excluded))
}

/// One `cat-file --batch-check` pass over a spec list, returning stdout as
/// text. The spec list goes through a file: piped stdin plus unconsumed
/// stdout deadlocks once the list outgrows the pipe buffer - the child
/// stalls writing output nobody reads while the parent stalls writing
/// input nobody drains. spec_file carries the 0600/create_new file
/// contract.
fn batch_check(repo: &str, specs: &[&str], format: &str) -> Result<String, String> {
    use std::io::{Seek as _, SeekFrom, Write as _};
    if specs.is_empty() {
        return Ok(String::new());
    }
    let (list, mut file) = spec_file()?;
    let output = (|| {
        for spec in specs {
            writeln!(file, "{spec}")
                .map_err(|e| format!("Git could not stage the batch list: {e}"))?;
        }
        file.flush()
            .and_then(|_| file.seek(SeekFrom::Start(0)))
            .map_err(|e| format!("Git could not stage the batch list: {e}"))?;
        git_command(
            repo,
            &["cat-file", &format!("--batch-check={format}")],
            None,
        )
        .stdin(std::process::Stdio::from(file))
        .output()
        .map_err(|e| format!("Git could not read the review snapshot: {e}"))
    })();
    list.unlink();
    let output = output?;
    if !output.status.success() {
        return Err(git_status_error(
            "Git could not read the review snapshot",
            &output.status,
            &output.stderr,
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The `diff` attribute state per path at the audited head, in one
/// `check-attr --stdin -z` pass bound to the same tree the diff passes
/// evaluate through `GIT_ATTR_SOURCE` - one authority, so a verdict and
/// the suppression it explains can never diverge. `unset` or a named
/// driver is the attribute layer's doing; `unspecified` and `set` mean
/// git's own content detection decided the file is binary. The pass
/// fails loudly - a dead child, a non-zero exit, a truncated record, or
/// a short answer count all return an error rather than leave a
/// suppressed change unclassified.
fn diff_attrs(
    repo: &str,
    head: &str,
    paths: &[String],
) -> Result<std::collections::HashMap<String, String>, String> {
    use std::io::{BufRead as _, BufReader, Read as _, Seek as _, SeekFrom, Write as _};
    let mut attrs: std::collections::HashMap<String, String> = Default::default();
    if paths.is_empty() {
        return Ok(attrs);
    }
    let (list, mut file) = spec_file()?;
    let spawned = (|| {
        for path in paths {
            file.write_all(path.as_bytes())
                .and_then(|_| file.write_all(&[0]))
                .map_err(|e| format!("Git could not stage the batch list: {e}"))?;
        }
        file.flush()
            .and_then(|_| file.seek(SeekFrom::Start(0)))
            .map_err(|e| format!("Git could not stage the batch list: {e}"))?;
        git_command(
            repo,
            &["check-attr", "--source", head, "-z", "--stdin", "diff"],
            None,
        )
        .stdin(std::process::Stdio::from(file))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Git could not read the review diff attributes: {e}"))
    })();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            list.unlink();
            return Err(error);
        }
    };
    let mut out = BufReader::new(child.stdout.take().unwrap());
    // "<path>\0diff\0<state>\0" per query, in input order. A field that
    // did not end on its NUL terminator is a truncated record, not an
    // answer - it fails the pass rather than being counted.
    let mut record: Vec<u8> = Vec::new();
    let mut fields = Vec::new();
    let mut triples = 0usize;
    let mut parse_error: Option<String> = None;
    loop {
        record.clear();
        match out.read_until(0, &mut record) {
            Ok(0) => break,
            Ok(_) if record.last() == Some(&0) => {}
            Ok(_) => {
                parse_error =
                    Some("Git could not read the review diff attributes: truncated record".into());
                break;
            }
            Err(e) => {
                parse_error = Some(format!(
                    "Git could not read the review diff attributes: {e}"
                ));
                break;
            }
        }
        fields.push(String::from_utf8_lossy(&record[..record.len() - 1]).into_owned());
        if fields.len() == 3 {
            attrs.insert(fields[0].clone(), fields[2].clone());
            fields.clear();
            triples += 1;
        }
    }
    if parse_error.is_none() && !fields.is_empty() {
        parse_error =
            Some("Git could not read the review diff attributes: truncated record".into());
    }
    if parse_error.is_some() {
        let _ = child.kill();
    }
    // stdout is drained or abandoned by now, so reading stderr to EOF
    // cannot deadlock and unblocks a child still writing diagnostics
    // before it can exit; only then does `wait` reap an honest status.
    let mut stderr = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr);
    }
    let status = child.wait();
    list.unlink();
    if let Some(error) = parse_error {
        return Err(error);
    }
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => {
            return Err(git_status_error(
                "Git could not read the review diff attributes",
                &status,
                stderr.as_bytes(),
            ));
        }
        Err(e) => {
            return Err(format!(
                "Git could not read the review diff attributes: {e}"
            ));
        }
    }
    // `check-attr` prints one triple per queried path; a short count
    // means the stream desynchronized, so every answer is suspect.
    if triples != paths.len() {
        return Err(format!(
            "Git could not read the review diff attributes: {triples} answers for {} paths",
            paths.len()
        ));
    }
    Ok(attrs)
}

/// Path -> (base oid, head oid) across the range from one
/// `git diff --raw --no-renames -z` pass. The hunk stream cannot say
/// whether a path it skipped changed its blob or only its mode; the raw
/// record pair is the metadata-level answer and carries deleted
/// (all-zero head) and added (all-zero base) entries explicitly. NUL
/// delimiters keep quoted and newline-bearing names intact.
fn range_oids(
    repo: &str,
    target: &Target,
) -> Result<std::collections::HashMap<String, (String, String)>, String> {
    let output = git(
        repo,
        &[
            "diff",
            "--raw",
            "--no-abbrev",
            "--no-renames",
            "-z",
            target.base.as_deref().unwrap_or(EMPTY_TREE),
            &target.head,
        ],
    )?;
    let mut map: std::collections::HashMap<String, (String, String)> = Default::default();
    let mut fields = output.stdout.split(|byte| *byte == 0);
    while let Some(metadata) = fields.next() {
        if metadata.is_empty() {
            continue;
        }
        let Some(path) = fields.next() else { break };
        // ":<old-mode> <new-mode> <old-oid> <new-oid> <status>" - a record
        // that cannot be parsed cannot prove the pair unchanged, so it is
        // skipped rather than reported unchanged.
        let metadata = String::from_utf8_lossy(metadata);
        let parts: Vec<&str> = metadata.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        map.insert(
            String::from_utf8_lossy(path).into_owned(),
            (parts[2].to_string(), parts[3].to_string()),
        );
    }
    Ok(map)
}

/// Parse `git diff --unified=0 --no-renames` output into (added, removed)
/// per path.
/// Line-fed parser for `diff --unified=0` output: `feed` consumes one
/// output line at a time, so the forced `--text` pass can stream a giant
/// recovered delta without ever holding the patch whole. `keep` decides
/// per path and per side whether a hunk line is stored, so a
/// disqualified side's bytes are consumed but never held.
struct DiffParser<F: Fn(&str, bool) -> bool> {
    diffs: std::collections::HashMap<String, DiffLines>,
    path: Option<String>,
    deleted_from: Option<String>,
    in_hunk: bool,
    old_line: u64,
    new_line: u64,
    header: Regex,
    keep: F,
}

impl<F: Fn(&str, bool) -> bool> DiffParser<F> {
    fn new(keep: F) -> Self {
        Self {
            diffs: Default::default(),
            path: None,
            deleted_from: None,
            in_hunk: false,
            old_line: 0,
            new_line: 0,
            header: Regex::new(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@").unwrap(),
            keep,
        }
    }

    fn feed(&mut self, line: &str) {
        if line.starts_with("diff --git ") {
            self.in_hunk = false;
            self.path = None;
            self.deleted_from = None;
            return;
        }
        if !self.in_hunk {
            if let Some(rest) = line.strip_prefix("--- ") {
                if rest != "/dev/null" {
                    // Unquote before stripping the prefix: git C-quotes the
                    // whole header path, `a/` included.
                    let quoted = unquote_git_path(rest);
                    self.deleted_from = Some(
                        quoted
                            .strip_prefix("a/")
                            .map(str::to_string)
                            .unwrap_or(quoted),
                    );
                }
                return;
            }
            if let Some(rest) = line.strip_prefix("+++ ") {
                self.path = if rest == "/dev/null" {
                    self.deleted_from.take()
                } else {
                    let quoted = unquote_git_path(rest);
                    Some(
                        quoted
                            .strip_prefix("b/")
                            .map(str::to_string)
                            .unwrap_or(quoted),
                    )
                };
                if let Some(p) = &self.path {
                    self.diffs.entry(p.clone()).or_default();
                }
                return;
            }
        }
        if line.starts_with("@@ ") {
            self.in_hunk = true;
            if let Some(found) = self.header.captures(line) {
                self.old_line = found[1].parse().unwrap_or(0);
                self.new_line = found[2].parse().unwrap_or(0);
            }
            return;
        }
        let Some(p) = &self.path else { return };
        if let Some(text) = line.strip_prefix('+') {
            if (self.keep)(p, true) {
                self.diffs
                    .entry(p.clone())
                    .or_default()
                    .0
                    .push((self.new_line, text.to_string()));
            }
            self.new_line += 1;
        } else if let Some(text) = line.strip_prefix('-') {
            if (self.keep)(p, false) {
                self.diffs
                    .entry(p.clone())
                    .or_default()
                    .1
                    .push((self.old_line, text.to_string()));
            }
            self.old_line += 1;
        }
    }

    /// One raw output line: bytes decode lossily and the terminator
    /// comes off the way `str::lines` strips it - `\r` only when it
    /// preceded the `\n` - so hunk text reaching `keep` never carries a
    /// terminator and a recovered binary line cannot wedge the stream on
    /// invalid UTF-8.
    fn feed_raw(&mut self, raw: &[u8]) {
        let text = String::from_utf8_lossy(raw);
        let line = match text.strip_suffix('\n') {
            Some(line) => line.strip_suffix('\r').unwrap_or(line),
            None => &text,
        };
        self.feed(line);
    }

    fn finish(self) -> std::collections::HashMap<String, DiffLines> {
        self.diffs
    }
}

/// Parse `diff --unified=0` output into (added, removed) per path.
fn parse_diff_hunks(stdout: &[u8]) -> std::collections::HashMap<String, DiffLines> {
    let mut parser = DiffParser::new(|_: &str, _: bool| true);
    for raw in stdout.split_inclusive(|byte| *byte == b'\n') {
        parser.feed_raw(raw);
    }
    parser.finish()
}

/// Resolve each path to its blob OID at the head in one `ls-tree -r -z`
/// pass. A newline inside a name cannot split a NUL-delimited record, and
/// the specs this returns are bare OIDs - no path text ever reaches the
/// line-delimited batch input. A path absent from the head gets no entry.
fn head_blob_oids(
    repo: &str,
    target: &Target,
    paths: &[String],
) -> Result<Vec<Option<String>>, String> {
    // Every entry is admitted - no mode filter - so a submodule or symlink
    // the caller asked about resolves to whatever object it names.
    let mut map: std::collections::HashMap<String, String> = Default::default();
    for (path, _, oid) in ls_tree_entries(repo, &target.head)? {
        map.insert(path, oid);
    }
    Ok(paths.iter().map(|path| map.get(path).cloned()).collect())
}

/// Invoke `f` with each path's text at the outgoing revision - missing,
/// binary and oversized blobs are skipped. Texts stream through one batch
/// pass and drop at the callback's end, so nothing ever holds the whole
/// tree: peak memory stays O(largest scanned blob).
fn for_each_head_text(
    repo: &str,
    target: &Target,
    paths: &[String],
    mut f: impl FnMut(&str, &str),
) -> Result<(), String> {
    let oids = head_blob_oids(repo, target, paths)?;
    let mut kept: Vec<&str> = Vec::new();
    let mut specs: Vec<String> = Vec::new();
    for (path, oid) in paths.iter().zip(&oids) {
        if let Some(oid) = oid {
            kept.push(path);
            specs.push(oid.clone());
        }
    }
    for_each_blob(repo, &specs, |index, blob| {
        if !blob.is_empty() && !is_binary(blob, 8000) && blob.len() <= MAX_SCAN_BYTES {
            f(kept[index], &String::from_utf8_lossy(blob));
        }
        Ok(true)
    })
}

fn is_new_file(repo: &str, target: &Target, path: &str) -> bool {
    match target.scope.as_str() {
        // The whole tree is being judged; a credential file in it is a finding.
        "range" => match &target.base {
            Some(base) => !git_ok(repo, &["cat-file", "-e", &format!("{base}:{path}")]),
            None => !git_ok(repo, &["cat-file", "-e", &format!("{EMPTY_TREE}:{path}")]),
        },
        _ => true,
    }
}

fn in_tree(repo: &str, target: &Target, path: &str) -> bool {
    git_ok(
        repo,
        &["cat-file", "-e", &format!("{}:{path}", target.head)],
    )
}

#[derive(Clone, Copy, PartialEq)]
enum Where {
    Workflow,
    Dockerfile,
    Compose,
    RegistrySource,
    PackageJson,
    RequirementsTxt,
    CargoToml,
    GoMod,
    Anywhere,
}

impl Where {
    fn matches(&self, path: &str) -> bool {
        let name = path.rsplit('/').next().unwrap_or(path);
        match self {
            Where::Workflow => is_workflow(path),
            Where::Dockerfile => is_dockerfile(path),
            Where::Compose => is_compose(path),
            Where::RegistrySource => [
                ".npmrc",
                "pip.conf",
                "pip.ini",
                ".yarnrc.yml",
                "nuget.config",
            ]
            .contains(&name),
            Where::PackageJson => name == "package.json",
            Where::RequirementsTxt => name.starts_with("requirements") && path.ends_with(".txt"),
            Where::CargoToml => name == "Cargo.toml",
            Where::GoMod => name == "go.mod",
            Where::Anywhere => true,
        }
    }
}

struct LineRule {
    rule: &'static str,
    group: Group,
    location: Where,
    pattern: Regex,
}

/// The three passes over a file's added lines. Each pass records at most one
/// hit per line (first matching rule); the pass order is the Python module's
/// `apply` order, and prose files skip the latter two passes.
#[derive(Clone, Copy, PartialEq)]
enum Group {
    Path,
    Code,
    Surface,
}

impl Group {
    fn sink<'a>(
        self,
        regressions: &'a mut Vec<Hit>,
        surfaces: &'a mut Vec<Hit>,
    ) -> &'a mut Vec<Hit> {
        match self {
            Group::Path | Group::Code => regressions,
            Group::Surface => surfaces,
        }
    }
}

fn line_rules() -> Vec<LineRule> {
    use Group::{Code as C, Path as P, Surface as S};
    use Where::*;
    let compile = |pattern: &str| Regex::new(pattern).expect("static rule pattern");
    vec![
        LineRule {
            rule: "ci/pull-request-target",
            group: P,
            location: Workflow,
            pattern: compile(r#"^\s*["']?pull_request_target["']?\s*:"#),
        },
        LineRule {
            rule: "ci/write-all-permissions",
            group: P,
            location: Workflow,
            pattern: compile(r#"permissions\s*:\s*["']?write-all"#),
        },
        LineRule {
            rule: "ci/floating-action-ref",
            group: P,
            location: Workflow,
            pattern: compile(
                r"(?i)uses\s*:\s*[\w.\-/]+@(?:main|master|HEAD)\b|uses\s*:\s*docker://\S+:latest\b",
            ),
        },
        LineRule {
            rule: "ci/remote-script-execution",
            group: P,
            location: Workflow,
            pattern: compile(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b"),
        },
        LineRule {
            rule: "ci/tls-verification-disabled",
            group: P,
            location: Workflow,
            pattern: compile(r#"NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*["']?0"#),
        },
        LineRule {
            rule: "container/root-user",
            group: P,
            location: Dockerfile,
            pattern: compile(r"(?i)^\s*USER\s+(?:root|0)\s*$"),
        },
        LineRule {
            rule: "container/privileged",
            group: P,
            location: Dockerfile,
            pattern: compile(r"(?:^|\s)--privileged(?:\s|$)"),
        },
        LineRule {
            rule: "container/privileged",
            group: P,
            location: Compose,
            pattern: compile(r#"^\s*privileged\s*:\s*["']?true"#),
        },
        LineRule {
            rule: "container/world-writable",
            group: P,
            location: Dockerfile,
            pattern: compile(r"\bchmod\s+(?:-[A-Za-z]+\s+)*777\b"),
        },
        LineRule {
            rule: "hardening/registry-source-changed",
            group: P,
            location: RegistrySource,
            pattern: compile(
                r"(?i)^\s*(?:@[\w.\-]+:)?registry\s*=|^\s*index-url\s*=|npmRegistryServer\s*:",
            ),
        },
        // Runtime switches are judged on code, not on prose that merely names
        // them: these carry no path predicate. The lookbehind of the Python
        // original becomes a consumed edge - only detection matters here.
        LineRule {
            rule: "runtime/tls-verification-disabled",
            group: C,
            location: Anywhere,
            pattern: compile(
                r"(?i)verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|rejectUnauthorized\s*:\s*false|ssl_verify\s*=\s*false|(?:^|\s)--insecure(?:\s|$)",
            ),
        },
        LineRule {
            rule: "runtime/debug-enabled",
            group: C,
            location: Anywhere,
            pattern: compile(r"(?:^|[^A-Za-z_])DEBUG\s*=\s*True|\bdebug\s*=\s*True"),
        },
        LineRule {
            rule: "surface/dependency-url-source",
            group: S,
            location: PackageJson,
            pattern: compile(
                r#"["'][^"']+["']\s*:\s*["'](?:git\+|https?://|github:|gitlab:|bitbucket:|file:|link:)"#,
            ),
        },
        LineRule {
            rule: "surface/dependency-url-source",
            group: S,
            location: RequirementsTxt,
            pattern: compile(r"^\s*(?:-e\s+)?(?:git\+|https?://)\S"),
        },
        // Only a git dependency is a URL source; a `path =` entry is a local
        // directory, and flagging it invents a supply-chain surface.
        LineRule {
            rule: "surface/dependency-url-source",
            group: S,
            location: CargoToml,
            pattern: compile(r#"(?:^|[\{\s])git\s*=\s*["']"#),
        },
        LineRule {
            rule: "surface/dependency-url-source",
            group: S,
            location: GoMod,
            pattern: compile(r"^\s*replace\s+\S+\s+=>\s+\S*(?:\.\./|https?://|git@)"),
        },
        LineRule {
            rule: "surface/install-hook-added",
            group: S,
            location: PackageJson,
            pattern: compile(
                r#"["'](?:pre|post)?install["']\s*:\s*["']|["']prepare["']\s*:\s*["']"#,
            ),
        },
        LineRule {
            rule: "surface/install-hook-added",
            group: S,
            location: RegistrySource,
            pattern: compile(r"ignore-scripts\s*=\s*false"),
        },
        LineRule {
            rule: "surface/private-address",
            group: S,
            location: Anywhere,
            pattern: compile(
                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b|\b[\w.\-]+\.(?:internal|corp|lan|intranet)\b",
            ),
        },
        // The plaintext rule's host allowlist is applied in code: the regex
        // crate has no lookahead, and only detection matters.
        LineRule {
            rule: "surface/plaintext-endpoint",
            group: S,
            location: Anywhere,
            pattern: PLAINTEXT_HOST.clone(),
        },
    ]
}

static SECRET_ARG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\s*(?:ARG|ENV)\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*|\s+)(.+?)\s*$").unwrap()
});
static SECRET_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|CREDENTIAL|ACCESS_?KEY|CLIENT_?SECRET)")
        .unwrap()
});
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(your|example|placeholder|changeme|<|\$\{|\$[A-Z_]|\{\{|x{4,}|\*{3,})")
        .unwrap()
});
static PROTECTED_IGNORE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(\.env|\.pem|\.key|\.p12|\.pfx|secret|credential|token|password|passwd|\.netrc|\.npmrc|\.ssh|id_rsa|id_ed25519|\.db|\.sqlite|\.kdbx|\.tfstate|credential)")
        .unwrap()
});
static FROM_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*FROM\s+(\S+)(?:\s+AS\s+(\S+))?\s*$").unwrap());
static WILDCARD_ORIGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)allow_origins\s*=\s*\[\s*["']\*["']\s*\]|Access-Control-Allow-Origin\s*:\s*\*"#,
    )
    .unwrap()
});
static CREDENTIALS_ORIGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)allow_credentials\s*=\s*True|Access-Control-Allow-Credentials\s*:\s*true")
        .unwrap()
});
static PLAINTEXT_HOST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"http://([\w.\-]+)").unwrap());

/// Hosts a plaintext endpoint may name without surfacing: loopback and the
/// documentation schemas. The Python original expresses this as a lookahead;
/// only detection matters, so it is a prefix filter here.
const PLAINTEXT_EXEMPT: [&str; 10] = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    "example.",
    "www.w3.org",
    "xmlsoap.org",
    "json-schema.org",
    "schema.org",
    "ns.adobe.com",
];

/// The manifest -> lockfiles that must move with it when they exist in the tree.
fn lockfiles_for(manifest: &str) -> &'static [&'static str] {
    match manifest {
        "package.json" => &[
            "package-lock.json",
            "npm-shrinkwrap.json",
            "yarn.lock",
            "pnpm-lock.yaml",
        ],
        "Cargo.toml" => &["Cargo.lock"],
        "go.mod" => &["go.sum"],
        "Gemfile" => &["Gemfile.lock"],
        "composer.json" => &["composer.lock"],
        "Pipfile" => &["Pipfile.lock"],
        "pyproject.toml" => &["poetry.lock", "uv.lock", "pdm.lock"],
        _ => &[],
    }
}

fn checklist_audit(
    repo: &str,
    target: &Target,
    changed: &[String],
    diffs: &std::collections::HashMap<String, DiffLines>,
    unreadable: &[String],
    with_surfaces: bool,
) -> Result<(Vec<Hit>, Vec<Hit>), String> {
    let mut regressions = Vec::new();
    let mut surfaces = Vec::new();
    let paths: Vec<String> = changed
        .iter()
        .filter(|path| !is_skipped(path))
        .cloned()
        .collect();
    let rules = line_rules();
    // Surfaces describe what the range touched - including deletions. The
    // caller's changed list already is the base..head name set for a
    // range target; for a snapshot-with-base target the scan list is the
    // whole tree, so the touched set is enumerated separately. No base
    // means every head path is new, and a contract that does not echo
    // surfaces pays no enumeration at all.
    let touched = if !with_surfaces {
        Some(Default::default())
    } else if target.scope == "range" {
        Some(changed.iter().cloned().collect())
    } else {
        changed_paths(repo, target)?
    };
    // A suppressed diff whose surviving sides were all unreadable leaves
    // a hole in this stage's coverage. On a protection file the hole is
    // blocking - its removed lines may have dropped an ignore rule or an
    // owner line this stage is chartered to catch. Any other path is
    // surfaced so the semantic stage knows to look rather than
    // adjudicating silence.
    for path in unreadable {
        if is_protection_file(path) {
            regressions.push(Hit {
                path: path.clone(),
                line: 1,
                rule: "hardening/protection-unreadable".into(),
                remedy: remedy("hardening/protection-unreadable"),
            });
        } else if with_surfaces {
            surfaces.push(Hit {
                path: path.clone(),
                line: 1,
                rule: "surface/suppressed-unreadable".into(),
                remedy: remedy("surface/suppressed-unreadable"),
            });
        }
    }

    // Files whose mere presence or newness is the finding.
    for path in &paths {
        let name = path.rsplit('/').next().unwrap_or(path);
        if CREDENTIAL_FILES.contains(&name) && is_new_file(repo, target, path) {
            regressions.push(Hit {
                path: path.clone(),
                line: 1,
                rule: "hardening/credential-file-added".into(),
                remedy: remedy("hardening/credential-file-added"),
            });
        }
        if name == "build.rs" && is_new_file(repo, target, path) {
            surfaces.push(Hit {
                path: path.clone(),
                line: 1,
                rule: "surface/install-hook-added".into(),
                remedy: remedy("surface/install-hook-added"),
            });
        }
    }

    // Instruction-channel changes - agent-facing directives and harness
    // wiring - are adjudicated by the semantic stage, and deletions count.
    for path in range_touched(&touched, &paths, is_instruction_channel) {
        surfaces.push(Hit {
            path,
            line: 1,
            rule: "surface/instruction-channel".into(),
            remedy: remedy("surface/instruction-channel"),
        });
    }

    // A manifest that moves without the lockfile the repository keeps beside it.
    let present: std::collections::HashSet<&str> = paths.iter().map(String::as_str).collect();
    for path in &paths {
        let name = path.rsplit('/').next().unwrap_or(path);
        let locks = lockfiles_for(name);
        if locks.is_empty() {
            continue;
        }
        let directory = path.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("");
        for lock in locks {
            let candidate = if directory.is_empty() {
                lock.to_string()
            } else {
                format!("{directory}/{lock}")
            };
            if !present.contains(candidate.as_str()) && in_tree(repo, target, &candidate) {
                regressions.push(Hit {
                    path: path.clone(),
                    line: 1,
                    rule: "dependency/lockfile-not-updated".into(),
                    remedy: remedy("dependency/lockfile-not-updated"),
                });
                break;
            }
        }
    }

    // Removals that weaken protection: the line checks a deleted path's
    // recovered delta needs exactly this, and nothing else from the head
    // text pass.
    let removed_rules = |path: &str, removed: &[(u64, String)]| -> Vec<Hit> {
        let mut hits = Vec::new();
        for (number, line) in removed {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            match protection_kind(path) {
                Some(ProtectionKind::Ignore) if PROTECTED_IGNORE.is_match(line) => {
                    hits.push(Hit {
                        path: path.to_string(),
                        line: *number,
                        rule: "hardening/ignore-rule-removed".into(),
                        remedy: remedy("hardening/ignore-rule-removed"),
                    });
                }
                Some(ProtectionKind::Codeowners) => {
                    hits.push(Hit {
                        path: path.to_string(),
                        line: *number,
                        rule: "hardening/codeowner-removed".into(),
                        remedy: remedy("hardening/codeowner-removed"),
                    });
                }
                _ => {}
            }
        }
        hits
    };

    // The shared range diff the caller computed already covers every
    // changed blob; texts stream through the callback, so nothing holds a
    // whole-tree map.
    for_each_head_text(repo, target, &paths, |path, text| {
        // A range diff that names no hunk for the path - a same-oid
        // mode-only change - has no added or removed lines. Only a
        // snapshot treats every line of the head text as added.
        let none: DiffLines = Default::default();
        let whole: DiffLines;
        let (added, _) = match diffs.get(path) {
            Some(pair) => pair,
            None if target.scope == "range" => &none,
            None => {
                whole = (
                    text.lines()
                        .enumerate()
                        .map(|(i, l)| (i as u64 + 1, l.to_string()))
                        .collect(),
                    Vec::new(),
                );
                &whole
            }
        };
        let prose = is_prose(path);
        let dockerfile = is_dockerfile(path);
        // Three passes over the added lines, each first-match-per-line; prose
        // files skip the code and surface passes. The dockerfile checks run
        // as their own pass, after the rule passes.
        for group in [Group::Path, Group::Code, Group::Surface] {
            if prose && group != Group::Path {
                continue;
            }
            for (number, line) in added {
                for rule in rules.iter().filter(|rule| rule.group == group) {
                    if !rule.location.matches(path) {
                        continue;
                    }
                    if rule.rule == "surface/plaintext-endpoint" {
                        // The rule matches only when a host survives the
                        // allowlist - no surviving host, no first-match break.
                        let hit = PLAINTEXT_HOST.captures_iter(line).any(|found| {
                            !PLAINTEXT_EXEMPT
                                .iter()
                                .any(|exempt| found[1].starts_with(exempt))
                        });
                        if hit {
                            surfaces.push(Hit {
                                path: path.to_string(),
                                line: *number,
                                rule: rule.rule.into(),
                                remedy: remedy(rule.rule),
                            });
                            break;
                        }
                        continue;
                    }
                    if rule.pattern.is_match(line) {
                        // The reviewed tree carries no suppression token: a
                        // comment on the offending line must never soften a
                        // blocking rule. Exemptions live only in the signed
                        // rulings ledger, which candidates cannot write.
                        group.sink(&mut regressions, &mut surfaces).push(Hit {
                            path: path.to_string(),
                            line: *number,
                            rule: rule.rule.into(),
                            remedy: remedy(rule.rule),
                        });
                        break;
                    }
                }
            }
        }
        if dockerfile {
            // Stage aliases declared elsewhere in the file are local build
            // stages, not external images: `FROM deps AS build` has no base
            // image to pin.
            let stage_aliases: std::collections::HashSet<String> = added
                .iter()
                .filter_map(|(_, line)| FROM_LINE.captures(line))
                .filter_map(|capture| capture.get(2).map(|alias| alias.as_str().to_string()))
                .collect();
            for (number, line) in added {
                if let Some(arg) = SECRET_ARG.captures(line)
                    && SECRET_NAME.is_match(&arg[1])
                    && !PLACEHOLDER.is_match(&arg[2])
                {
                    regressions.push(Hit {
                        path: path.to_string(),
                        line: *number,
                        rule: "container/secret-in-image".into(),
                        remedy: remedy("container/secret-in-image"),
                    });
                    continue;
                }
                if let Some(image) = FROM_LINE.captures(line) {
                    let reference = &image[1];
                    if stage_aliases.contains(reference) {
                        continue;
                    }
                    let tail = reference.rsplit('/').next().unwrap_or(reference);
                    if !reference.contains("@sha256:")
                        && (!tail.contains(':') || reference.ends_with(":latest"))
                    {
                        regressions.push(Hit {
                            path: path.to_string(),
                            line: *number,
                            rule: "container/unpinned-base-image".into(),
                            remedy: remedy("container/unpinned-base-image"),
                        });
                    }
                }
            }
        }
        // A wildcard origin is only a regression together with credentials.
        if !prose {
            let wildcard: Vec<u64> = added
                .iter()
                .filter(|(_, line)| WILDCARD_ORIGIN.is_match(line))
                .map(|(number, _)| *number)
                .collect();
            let credentials: Vec<u64> = added
                .iter()
                .filter(|(_, line)| CREDENTIALS_ORIGIN.is_match(line))
                .map(|(number, _)| *number)
                .collect();
            if !wildcard.is_empty() && !credentials.is_empty() {
                regressions.push(Hit {
                    path: path.to_string(),
                    line: credentials.iter().max().copied().unwrap_or(1),
                    rule: "runtime/cors-wildcard-credentials".into(),
                    remedy: remedy("runtime/cors-wildcard-credentials"),
                });
            }
        }
    })?;
    // Removal rules are driven by the diff, not by which paths still have
    // a head blob to stream: a deleted, emptied or head-unreadable
    // protection file has removed lines in the map and must still answer
    // to them. `paths` is the non-skipped changed set, so vendor and
    // build trees stay out of scope.
    for path in &paths {
        if let Some((_, removed)) = diffs.get(path) {
            regressions.extend(removed_rules(path, removed));
        }
    }
    Ok((regressions, surfaces))
}

// ---------------------------------------------------------------------------
// the executor
// ---------------------------------------------------------------------------

/// A regex rule over its declared target: one hit per matching line or path.
fn regex_hits(
    repo: &str,
    target: &Target,
    rule: &Rule,
    paths: &[String],
    diffs: &std::collections::HashMap<String, DiffLines>,
) -> Result<Vec<Hit>, String> {
    let pattern = Regex::new(rule.pattern.as_deref().unwrap_or(""))
        .map_err(|error| format!("stage1 rule {:?}: invalid pattern: {error}", rule.id))?;
    let mut hits = Vec::new();
    let target_name = rule.target.as_deref().unwrap_or("");
    if !RULE_TARGETS.contains(&target_name) {
        return Err(format!(
            "stage1 rule {:?}: unknown target {target_name:?}",
            rule.id
        ));
    }
    match target_name {
        "changed-paths" => {
            for path in paths {
                if pattern.is_match(path) {
                    hits.push(Hit {
                        path: path.clone(),
                        line: 0,
                        rule: rule.id.clone(),
                        remedy: None,
                    });
                }
            }
        }
        "revision-lines" => {
            let mut files: Vec<(String, String)> = Vec::new();
            for (path, mode, oid) in ls_tree_entries(repo, &target.head)? {
                if mode != "100644" && mode != "100755" {
                    continue;
                }
                files.push((path, oid));
            }
            let oids: Vec<String> = files.iter().map(|(_, oid)| oid.clone()).collect();
            for_each_blob(repo, &oids, |index, blob| {
                if is_binary(blob, 8192) || blob.len() > MAX_FILE_BYTES {
                    return Ok(true);
                }
                for (number, line) in String::from_utf8_lossy(blob).lines().enumerate() {
                    if pattern.is_match(line) {
                        hits.push(Hit {
                            path: files[index].0.clone(),
                            line: number as u64 + 1,
                            rule: rule.id.clone(),
                            remedy: None,
                        });
                    }
                }
                Ok(true)
            })?;
        }
        _ => {
            // added-lines / removed-lines: the caller's shared range diff,
            // numbered at the end of the range the line belongs to.
            // `range_diff` already recovered the delta of
            // attribute-suppressed changed blobs, so a missing entry is a
            // same-oid mode-only change, a content-detected binary asset,
            // or a suppressed path with no readable side - no usable
            // lines either way.
            if target.scope == "range" {
                for path in paths {
                    if let Some((added, removed)) = diffs.get(path) {
                        let lines = if target_name == "added-lines" {
                            added
                        } else {
                            removed
                        };
                        for (number, line) in lines {
                            if pattern.is_match(line) {
                                hits.push(Hit {
                                    path: path.clone(),
                                    line: *number,
                                    rule: rule.id.clone(),
                                    remedy: None,
                                });
                            }
                        }
                    }
                }
            } else if target_name == "added-lines" {
                // A snapshot has no base: every line counts as added.
                for_each_head_text(repo, target, paths, |path, text| {
                    for (index, line) in text.lines().enumerate() {
                        if pattern.is_match(line) {
                            hits.push(Hit {
                                path: path.to_string(),
                                line: index as u64 + 1,
                                rule: rule.id.clone(),
                                remedy: None,
                            });
                        }
                    }
                })?;
            }
        }
    }
    Ok(hits)
}

/// One range under one contract's stage-1 rules, in contract order.
/// `with_surfaces` is the contract's own `surfaces` declaration: a checker
/// that did not opt into surface reporting does not emit the key, whatever
/// its builtins collected.
pub fn audit(
    repo: &str,
    target: &Target,
    rules: &[Rule],
    opts: &Opts,
    with_surfaces: bool,
) -> Result<Summary, String> {
    let mut hits = Vec::new();
    let mut surfaces: Option<Vec<Hit>> = None;
    let mut status = "clean".to_string();
    let mut refused = String::new();
    // Changed-path and diff inputs are paid for only when some rule
    // consumes them, then shared by every regex rule and the checklist
    // pass - a contract of prompts and non-line rules never spawns the
    // diff pipeline at all.
    let needs_paths = rules.iter().any(|rule| match rule.kind.as_str() {
        "builtin" => rule.builtin.as_deref() == Some("static-checklist"),
        "regex" => !matches!(rule.target.as_deref(), Some("revision-lines")),
        _ => false,
    });
    let paths = if needs_paths {
        outgoing_paths(repo, target)?
    } else {
        Vec::new()
    };
    let needs_diffs = target.scope == "range"
        && rules.iter().any(|rule| {
            rule.kind == "builtin" && rule.builtin.as_deref() == Some("static-checklist")
                || rule.kind == "regex"
                    && matches!(
                        rule.target.as_deref(),
                        Some("added-lines" | "removed-lines")
                    )
        });
    let (diffs, unreadable) = if needs_diffs {
        range_diff(repo, target, &paths)?
    } else {
        (Default::default(), Vec::new())
    };
    for rule in rules {
        match rule.kind.as_str() {
            // A prompt rule is a judgement the reviewer must make; the
            // orchestration surfaces it as a checklist item. It decides
            // nothing here.
            "prompt" => {}
            "regex" => {
                let found = regex_hits(repo, target, rule, &paths, &diffs)?;
                if !found.is_empty() {
                    status = "refused".into();
                    if refused.is_empty() {
                        refused = rule.id.clone();
                    }
                    hits.extend(found);
                }
            }
            "builtin" => match rule.builtin.as_deref().unwrap_or("") {
                "withheld-names-and-credentials" => {
                    let (why, found) = clean_audit(repo, target, opts)?;
                    if !found.is_empty() {
                        status = why.clone();
                        if refused.is_empty() {
                            refused = why;
                        }
                        hits.extend(found);
                    }
                }
                "dependency-direction" => {
                    let found = deps_audit(repo, target, opts)?;
                    if !found.is_empty() {
                        status = "refused".into();
                        if refused.is_empty() {
                            refused = "dependency-direction".to_string();
                        }
                        hits.extend(found);
                    }
                }
                "workspace-hygiene" => {
                    let (found, found_surfaces) = hygiene_audit(repo, target, with_surfaces)?;
                    surfaces.get_or_insert_with(Vec::new).extend(found_surfaces);
                    if !found.is_empty() {
                        status = "refused".into();
                        if refused.is_empty() {
                            refused = found[0].rule.clone();
                        }
                        hits.extend(found);
                    }
                }
                "static-checklist" => {
                    let (regressions, found_surfaces) =
                        checklist_audit(repo, target, &paths, &diffs, &unreadable, with_surfaces)?;
                    surfaces.get_or_insert_with(Vec::new).extend(found_surfaces);
                    if !regressions.is_empty() {
                        status = "regression".into();
                        if refused.is_empty() {
                            refused = "static-security-regression".to_string();
                        }
                        hits.extend(regressions);
                    }
                }
                "commit-identity" => {
                    let found = identity_audit(repo, target)?;
                    if !found.is_empty() {
                        status = "refused".into();
                        if refused.is_empty() {
                            refused = "commit-identity".to_string();
                        }
                        hits.extend(found);
                    }
                }
                other => {
                    return Err(format!(
                        "stage1 rule {:?}: unknown builtin {other:?}",
                        rule.id
                    ));
                }
            },
            other => return Err(format!("stage1 rule {:?}: unknown kind {other:?}", rule.id)),
        }
    }
    Ok(Summary {
        label: target.label.clone(),
        scope: target.scope.clone(),
        status,
        hits,
        surfaces: if with_surfaces { surfaces } else { None },
        refused,
    })
}

/// Every range; the first refusal stops the stage - the refusal ends the
/// operation, so nothing after it is paid for.
pub fn audit_all(
    repo: &str,
    targets: &[Target],
    rules: &[Rule],
    opts: &Opts,
    with_surfaces: bool,
) -> Result<(bool, Vec<Summary>), String> {
    let mut summaries = Vec::new();
    for target in targets {
        let summary = audit(repo, target, rules, opts, with_surfaces)?;
        let refused = !summary.refused.is_empty();
        summaries.push(summary);
        if refused {
            return Ok((false, summaries));
        }
    }
    Ok((true, summaries))
}

#[cfg(test)]
mod tests {
    use super::{
        Hit, attr_floor_met, checklist_audit, clean_audit, dep_closure, dep_key, deps_map,
        hygiene_audit, in_scope, is_instruction_channel, is_interface_surface, marker_lines,
        name_pattern, outgoing_paths, range_diff, regex_hits,
    };
    use crate::contract::Rule;
    use base64::Engine as _;

    fn checklist(repo: &str, target: &super::Target) -> (Vec<Hit>, Vec<Hit>) {
        let paths = outgoing_paths(repo, target).unwrap();
        let (diffs, unreadable) = if target.scope == "range" {
            range_diff(repo, target, &paths).unwrap()
        } else {
            (Default::default(), Vec::new())
        };
        checklist_audit(repo, target, &paths, &diffs, &unreadable, true).unwrap()
    }

    #[test]
    fn a_name_matches_however_it_is_spelled() {
        let pattern = regex::Regex::new(&format!("(?i){}", name_pattern("Widget Go"))).unwrap();
        assert!(pattern.is_match("widget-go"));
        assert!(pattern.is_match("WidgetGO"));
        assert!(pattern.is_match("WIDGET GO"));
        assert!(pattern.is_match("the Widget Go project"));
        assert!(!pattern.is_match("Widget"));
    }

    #[test]
    fn the_dependency_map_closes_transitively_in_both_directions() {
        let file = std::env::temp_dir().join(format!(
            "gv-deps-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        std::fs::write(
            &file,
            "# comment\nUp <-\nMid <- Up\nDown <- Mid\nOther <- Unrelated\n",
        )
        .unwrap();
        let entries = deps_map(&file);
        let _ = std::fs::remove_file(&file);
        // Up's closure is empty; Mid sees Up; Down reaches Up through Mid.
        assert!(dep_closure(&entries, "Up").is_empty());
        assert!(dep_closure(&entries, "Mid").contains(&dep_key("Up")));
        assert!(dep_closure(&entries, "Down").contains(&dep_key("Up")));
        // The forbidden direction: whose closure contains "Up" - Mid and
        // Down, not Up itself, not the unrelated sibling.
        let mine = dep_key("Up");
        let downstreams: Vec<&str> = entries
            .iter()
            .map(|entry| entry.name.as_str())
            .filter(|name| dep_key(name) != mine && dep_closure(&entries, name).contains(&mine))
            .collect();
        assert_eq!(downstreams, ["Mid", "Down"]);
    }

    #[test]
    fn a_nested_document_naming_a_downstream_is_refused() {
        use super::{Target, deps_audit};
        use std::process::Command;
        let tag = format!(
            "gv-deps-e2e-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        );
        let dir = std::env::temp_dir().join(&tag);
        let run = |args: &[&str]| {
            let out = Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "git {:?}: {:?}", args, out);
        };
        std::fs::create_dir_all(dir.join("docs")).unwrap();
        std::fs::write(dir.join("docs/guide.md"), "See the Down project.\n").unwrap();
        std::fs::write(dir.join("README"), "Upstream notes.\n").unwrap();
        run(&["init", "-q", "-b", "main"]);
        run(&[
            "remote",
            "add",
            "origin",
            "git@github.com:acme/Upstream.git",
        ]);
        run(&["add", "-A"]);
        run(&[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-qm",
            "x",
        ]);
        let deps = std::env::temp_dir().join(format!("{tag}.deps"));
        std::fs::write(&deps, "Upstream <-\nDown <- Upstream\n").unwrap();
        unsafe { std::env::set_var("PROBATOR_REPO_DEPS", &deps) };
        let target = Target {
            kind: "push".into(),
            label: "push".into(),
            base: None,
            head: "HEAD".into(),
            ref_: None,
            scope: String::new(),
        };
        let hits = deps_audit(
            dir.to_str().unwrap(),
            &target,
            &super::Opts {
                withheld_path: None,
                machine_roots: None,
            },
        )
        .unwrap();
        unsafe { std::env::remove_var("PROBATOR_REPO_DEPS") };
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&deps);
        assert_eq!(hits.len(), 1, "expected one hit, got {}", hits.len());
        assert!(
            hits[0].path.starts_with("docs/guide.md"),
            "{}",
            hits[0].path
        );
    }

    #[test]
    fn scope_matches_name_owner_or_slug() {
        assert!(in_scope("acme/widget", "widget"));
        assert!(in_scope("acme/widget", "acme"));
        assert!(in_scope("acme/widget", "acme/widget"));
        assert!(!in_scope("acme/widget", "widge"));
        assert!(!in_scope("acme/widget", ""));
    }

    #[test]
    fn equals_markers_count_only_beside_sides() {
        let content = b"prose\n=======\nmore\n";
        assert_eq!(marker_lines(content), Vec::<u64>::new());
        let conflict = b"<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> branch\n";
        assert_eq!(marker_lines(conflict), vec![1, 3, 5]);
        let crlf = b"<<<<<<< HEAD\r\n=======\r\n>>>>>>> b\r\n";
        assert_eq!(marker_lines(crlf), vec![1, 2, 3]);
    }

    // -- the engine-parity corpus ------------------------------------------

    use super::{Opts, Target, audit_all};
    use crate::contract;
    use serde_json::{Value, json};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct CaseDir(PathBuf);
    impl Drop for CaseDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn git(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
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

    /// Fixture values are plain strings, except where a case must carry a
    /// literal the publication gate itself would refuse (credential shapes,
    /// disabled-verification flags): a `b64:` prefix marks base64 content the
    /// case decodes back to the real bytes before it reaches the repository
    /// under test. The corpus stays reviewable while this repository's own
    /// tree never stores the shape as text.
    fn case_str(value: &Value) -> String {
        let raw = value.as_str().unwrap();
        let Some(encoded) = raw.strip_prefix("b64:") else {
            return raw.to_string();
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("fixture value marked b64: must decode");
        String::from_utf8(bytes).expect("fixture value must be UTF-8")
    }

    fn apply(root: &Path, files: &serde_json::Map<String, Value>) {
        for (path, content) in files {
            let file = root.join(path);
            if content.is_null() {
                let _ = std::fs::remove_file(&file);
            } else {
                std::fs::create_dir_all(file.parent().unwrap()).unwrap();
                std::fs::write(&file, case_str(content)).unwrap();
            }
        }
    }

    /// Build the case's repo exactly as the Python generator builds it:
    /// optional base commit, one head commit, an optional origin remote.
    fn build_case(case: &Value) -> (CaseDir, Target) {
        let root = std::env::temp_dir().join(format!(
            "gv-stage1-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q"]);
        git(&root, &["config", "commit.gpgsign", "false"]);
        if !case["origin"].is_null() {
            let origin = case_str(&case["origin"]);
            git(&root, &["remote", "add", "origin", &origin]);
        }
        let mut base = None;
        if let Some(files) = case["base"].as_object() {
            apply(&root, files);
            git(&root, &["add", "-A"]);
            git(&root, &["commit", "-qm", "base"]);
            base = Some(git(&root, &["rev-parse", "HEAD"]));
        }
        apply(&root, case["head"].as_object().unwrap());
        git(&root, &["add", "-A"]);
        git(&root, &["commit", "-qm", "head"]);
        let head = git(&root, &["rev-parse", "HEAD"]);
        let target = Target {
            kind: "push".to_string(),
            label: format!("case {}", case["name"].as_str().unwrap()),
            scope: if base.is_some() {
                "range".into()
            } else {
                "snapshot".into()
            },
            base,
            head,
            ref_: None,
        };
        (CaseDir(root), target)
    }

    #[test]
    fn stage1_matches_the_engine_goldens() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("review-parity");
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
        let cases: Vec<Value> = serde_json::from_str(&read("stage1-cases.json")).unwrap();
        let expected: Value = serde_json::from_str(&read("stage1-expected.json")).unwrap();
        assert!(!cases.is_empty(), "the corpus must not be empty");
        for case in &cases {
            let name = case["name"].as_str().unwrap();
            let (guard, target) = build_case(case);
            // The withheld-names list is always an explicit file here: the
            // machine's own list must never leak into a test verdict.
            let withheld = guard.0.join("withheld.txt");
            let lines: Vec<String> = case
                .get("withheld_lines")
                .and_then(Value::as_array)
                .map(|lines| lines.iter().map(case_str).collect())
                .unwrap_or_default();
            std::fs::write(&withheld, lines.join("\n") + "\n").unwrap();
            // Machine roots are pinned per case the same way: the host's own
            // home directory and hostname must not decide a golden verdict,
            // so an absent key means an empty list, not derivation.
            let opts = Opts {
                withheld_path: Some(withheld),
                machine_roots: Some(
                    case.get("machine_roots")
                        .and_then(Value::as_array)
                        .map(|roots| roots.iter().map(case_str).collect())
                        .unwrap_or_default(),
                ),
            };
            for checker in case["checkers"].as_array().unwrap() {
                let checker = checker.as_str().unwrap();
                let contract_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tools")
                    .join(checker)
                    .join("contract.json");
                let contract = contract::load(&contract_path).unwrap();
                let rules: &[crate::contract::Rule] =
                    contract.stage1.as_ref().map_or(&[], |s| &s.rules);
                let (ok, summaries) = audit_all(
                    guard.0.to_str().unwrap(),
                    std::slice::from_ref(&target),
                    rules,
                    &opts,
                    contract.stage1.as_ref().is_some_and(|s| s.surfaces),
                )
                .unwrap();
                let produced = json!({
                    "ok": ok,
                    "summaries": summaries.iter().map(|s| s.to_json()).collect::<Vec<_>>(),
                });
                assert_eq!(produced, expected[name][checker], "{name}/{checker}");
            }
        }
    }

    // -- the range-aware behaviors the corpus cannot express -----------------

    fn commit_all(root: &Path, message: &str) -> String {
        git(root, &["add", "-A"]);
        git(root, &["commit", "-qm", message]);
        git(root, &["rev-parse", "HEAD"])
    }

    fn range_target(base: String, head: String) -> Target {
        Target {
            kind: "push".to_string(),
            label: "range".to_string(),
            scope: "range".to_string(),
            base: Some(base),
            head,
            ref_: None,
        }
    }

    /// A credential committed inside the range and deleted again before the
    /// head is still published history: the head-tree pass cannot see it, so
    /// the range-blob pass is what must not miss it.
    #[test]
    fn a_secret_removed_inside_the_range_is_still_scanned() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-range-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join("app.py"), "x = 1\n").unwrap();
        let base = commit_all(root, "base");
        // AWS's own documentation example key, base64-carried so this file
        // never holds the shape the gate scans for.
        let secret = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode("YXdzID0gIkFLSUFJT1NGT0ROTjdFWEFNUExFIgo=")
                .unwrap(),
        )
        .unwrap();
        std::fs::write(root.join("leak.py"), secret).unwrap();
        commit_all(root, "middle");
        std::fs::remove_file(root.join("leak.py")).unwrap();
        let head = commit_all(root, "head");

        let target = range_target(base, head);
        let opts = Opts {
            withheld_path: None,
            machine_roots: Some(Vec::new()),
        };
        let (_, hits) = clean_audit(root.to_str().unwrap(), &target, &opts).unwrap();
        assert!(
            hits.iter()
                .any(|h| h.rule == "aws-access-key" && h.path.contains("range blob")),
            "the middle commit's blob is scanned: {}",
            hits.iter()
                .map(|h| format!("{}:{}", h.path, h.rule))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    /// A machine path committed inside the range and rewritten at the head
    /// is still published history: the machine-path rule rides the same
    /// range-blob pass as the credential sweep.
    #[test]
    fn a_machine_path_removed_inside_the_range_is_still_scanned() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-range-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join("notes.md"), "built at <workspace>\n").unwrap();
        let base = commit_all(root, "base");
        // The path lives on a commit inside the range; the head rewrites it,
        // so only the range-blob pass can still see it.
        std::fs::write(root.join("notes.md"), "built at /home/builder/ws\n").unwrap();
        commit_all(root, "middle");
        std::fs::write(root.join("notes.md"), "built at <workspace>\n").unwrap();
        let head = commit_all(root, "head");

        let target = range_target(base, head);
        let opts = Opts {
            withheld_path: None,
            machine_roots: Some(vec!["/home/builder".to_string()]),
        };
        let (refused, hits) = clean_audit(root.to_str().unwrap(), &target, &opts).unwrap();
        assert_eq!(refused, "machine-path");
        assert!(
            hits.iter()
                .any(|h| h.rule == "machine-path" && h.path.contains("range blob")),
            "the base blob is scanned: {}",
            hits.iter()
                .map(|h| format!("{}:{}", h.path, h.rule))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    /// A commit lands with whichever author and message the caller pins:
    /// attribution findings come from git metadata, so the fixture must be
    /// able to write identities the pinned helper cannot.
    fn commit_as(
        root: &Path,
        message: &str,
        author: (&str, &str),
        committer: (&str, &str),
    ) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["add", "-A"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["commit", "-qm", message])
            .env("GIT_AUTHOR_NAME", author.0)
            .env("GIT_AUTHOR_EMAIL", author.1)
            .env("GIT_COMMITTER_NAME", committer.0)
            .env("GIT_COMMITTER_EMAIL", committer.1)
            .output()
            .unwrap();
        assert!(output.status.success());
        git(root, &["rev-parse", "HEAD"])
    }

    /// The published record must not carry an agent author, a machine-hosted
    /// mailbox, a gitconfig placeholder name, or an agent attribution
    /// trailer - each in a separate commit so every position is exercised.
    #[test]
    fn dirty_commit_identities_are_refused() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-ident-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);

        std::fs::write(root.join("a.txt"), "a\n").unwrap();
        let base = commit_all(root, "base");
        std::fs::write(root.join("b.txt"), "b\n").unwrap();
        commit_as(
            root,
            "agent author",
            ("devin-ai-integration[bot]", "devin-ai-integration[bot]@users.noreply.github.com"),
            ("Synthetic", "synthetic@example.invalid"),
        );
        std::fs::write(root.join("c.txt"), "c\n").unwrap();
        commit_as(
            root,
            "local mailbox",
            ("t", "t@builder-machine.local"),
            ("Synthetic", "synthetic@example.invalid"),
        );
        std::fs::write(root.join("d.txt"), "d\n").unwrap();
        commit_as(
            root,
            "misconfigured",
            ("user.email", "whoever@example.invalid"),
            ("Synthetic", "synthetic@example.invalid"),
        );
        std::fs::write(root.join("e.txt"), "e\n").unwrap();
        commit_as(
            root,
            "work\n\nCo-authored-by: Claude <noreply@anthropic.com>",
            ("Synthetic", "synthetic@example.invalid"),
            ("Synthetic", "synthetic@example.invalid"),
        );
        let head = git(root, &["rev-parse", "HEAD"]);

        let target = range_target(base, head);
        let hits = super::identity_audit(root.to_str().unwrap(), &target).unwrap();
        let rules: Vec<&str> = hits.iter().map(|h| h.rule.as_str()).collect();
        assert!(rules.contains(&"identity/agent-attribution"), "{rules:?}");
        assert!(rules.contains(&"identity/local-hostname"), "{rules:?}");
        assert!(rules.contains(&"identity/misconfigured-name"), "{rules:?}");
        assert!(
            hits.iter()
                .filter(|h| h.rule == "identity/agent-attribution")
                .count()
                >= 2,
            "author and trailer both count: {rules:?}"
        );
    }

    /// A clean range produces no identity findings - the pinned fixture
    /// identity is the baseline every other test already relies on.
    #[test]
    fn clean_commit_identities_pass() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-ident-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join("a.txt"), "a\n").unwrap();
        let base = commit_all(root, "base");
        std::fs::write(root.join("b.txt"), "b\n").unwrap();
        let head = commit_all(root, "head");
        let target = range_target(base, head);
        let hits = super::identity_audit(root.to_str().unwrap(), &target).unwrap();
        assert!(
            hits.is_empty(),
            "{}",
            hits.iter()
                .map(|h| format!("{}:{} {}", h.path, h.line, h.rule))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    /// A suppression token on the offending line must never soften a
    /// blocking rule: both lines regress, token or not. Exemptions live
    /// only in the signed rulings ledger candidates cannot write.
    #[test]
    fn an_inline_suppression_token_does_not_demote_a_blocking_hit() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-allow-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join("app.py"), "x = 1\n").unwrap();
        let base = commit_all(root, "base");
        // The trigger lines ride base64-encoded, the corpus convention: this
        // repository's own tree must never hold the shape its gate scans for.
        let b64 = |s: &str| {
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
        };
        std::fs::write(
            root.join("suppressed.py"),
            b64("ciA9IGdldCh1cmwsIHZlcmlmeSA9IEZhbHNlKSAgIyBndi1hbGxvdzpydW50aW1lL3Rscy12ZXJpZmljYXRpb24tZGlzYWJsZWQK"),
        )
        .unwrap();
        std::fs::write(
            root.join("raw.py"),
            b64("ciA9IGdldCh1cmwsIHZlcmlmeSA9IEZhbHNlKQo="),
        )
        .unwrap();
        let head = commit_all(root, "head");

        let target = range_target(base, head);
        let (regressions, surfaces) = checklist(root.to_str().unwrap(), &target);
        let seen = |hits: &[Hit]| {
            hits.iter()
                .map(|h| format!("{}:{}", h.path, h.rule))
                .collect::<Vec<_>>()
                .join(", ")
        };
        assert_eq!(
            regressions
                .iter()
                .filter(|h| h.rule == "runtime/tls-verification-disabled")
                .map(|h| h.path.as_str())
                .collect::<Vec<_>>(),
            ["raw.py", "suppressed.py"],
            "the token line regresses exactly like the plain one: {}",
            seen(&regressions)
        );
        assert!(
            !surfaces.iter().any(|h| h.rule.starts_with("suppressed/")),
            "no suppressed surface may exist: {}",
            seen(&surfaces)
        );
    }

    /// A newline inside a path must never split the batched reads the
    /// checklist and hygiene passes build: `head:path` used to ride a
    /// line-delimited spec file, so a first-sorting name like `!x\n<oid>`
    /// desynchronized the header-to-path pairing and shifted every later
    /// blob onto the wrong path — silently skipping the path-scoped rules.
    /// The specs now carry bare OIDs resolved through `ls-tree -r -z`.
    #[test]
    fn a_newline_in_a_path_cannot_desynchronize_the_blob_map() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-newline-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        let b64 = |s: &str| {
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
        };
        // The trigger contents ride base64 so this tree never stores the
        // shapes its own gate scans for.
        let workflow = root.join(".github/workflows/ci.yml");
        std::fs::create_dir_all(workflow.parent().unwrap()).unwrap();
        std::fs::write(
            &workflow,
            b64("b246IHB1c2gKcGVybWlzc2lvbnM6IHdyaXRlLWFsbApqb2JzOgogIHQ6CiAgICBydW5zLW9uOiB1YnVudHUtbGF0ZXN0Cg=="),
        )
        .unwrap();
        std::fs::write(
            root.join("Dockerfile"),
            b64("RlJPTSBzY3JhdGNoClVTRVIgcm9vdAo="),
        )
        .unwrap();
        std::fs::write(
            root.join("conflicted.txt"),
            "a\n<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> branch\n",
        )
        .unwrap();
        // A first-sorting name carrying a newline: under the line-delimited
        // spec format this split into `head:!x` plus a bare OID spec.
        let planted = format!("!x\n{}", "0".repeat(40));
        std::fs::write(root.join(&planted), "decoy\n").unwrap();
        git(root, &["add", "-A"]);
        git(root, &["commit", "-qm", "head"]);
        let head = git(root, &["rev-parse", "HEAD"]);
        let target = Target {
            kind: "push".to_string(),
            label: "newline".to_string(),
            scope: "snapshot".to_string(),
            base: None,
            head,
            ref_: None,
        };
        let repo = root.to_str().unwrap();
        let (regressions, _) = checklist(repo, &target);
        for (path, rule) in [
            (".github/workflows/ci.yml", "ci/write-all-permissions"),
            ("Dockerfile", "container/root-user"),
        ] {
            assert!(
                regressions.iter().any(|h| h.rule == rule && h.path == path),
                "{rule} must still name {path}: {}",
                regressions
                    .iter()
                    .map(|h| format!("{}:{}", h.path, h.rule))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let (hits, _) = hygiene_audit(repo, &target, true).unwrap();
        assert!(
            hits.iter()
                .any(|h| h.rule == "conflict-marker" && h.path == "conflicted.txt"),
            "the marker hit must keep its own path: {}",
            hits.iter()
                .map(|h| format!("{}:{}", h.path, h.rule))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    /// Git C-quotes a diff header path that needs it — `a/` prefix included —
    /// so the prefix must come off after unquoting, never before. A
    /// `café.py` key must stay `café.py`, not `a/café.py`.
    #[test]
    fn a_quoted_path_keeps_its_key_in_the_range_diff() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-quoted-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join("café.py"), "x = 1\n").unwrap();
        std::fs::write(root.join("gone.py"), "x = 1\n").unwrap();
        let base = commit_all(root, "base");
        std::fs::write(root.join("café.py"), "x = 1\ny = 2\n").unwrap();
        std::fs::remove_file(root.join("gone.py")).unwrap();
        let head = commit_all(root, "head");
        let target = range_target(base, head);
        let paths = outgoing_paths(root.to_str().unwrap(), &target).unwrap();
        let (diffs, _) = range_diff(root.to_str().unwrap(), &target, &paths).unwrap();
        for (path, added) in [("café.py", 1usize), ("gone.py", 0)] {
            let Some((a, _)) = diffs.get(path) else {
                panic!("{path} must key the diff map: {diffs:?}");
            };
            assert_eq!(a.len(), added, "{path} added lines: {diffs:?}");
        }
        assert!(
            diffs.keys().all(|path| !path.starts_with("a/")),
            "no header prefix may survive unquoting: {:?}",
            diffs.keys().collect::<Vec<_>>()
        );
    }

    /// A range path with no hunk — a mode-only chmod — is not "the whole
    /// file added": the checklist must not rescan pre-existing content as
    /// new, while a sibling's real diff still reports its added lines.
    #[test]
    fn a_mode_only_change_is_not_a_whole_file_add() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-chmod-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        let b64 = |s: &str| {
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
        };
        // A trigger line committed at base: rescanning it as "added" would
        // be a false blocking finding.
        std::fs::write(
            root.join("mode.py"),
            b64("ciA9IGdldCh1cmwsIHZlcmlmeSA9IEZhbHNlKQo="),
        )
        .unwrap();
        std::fs::write(root.join("normal.py"), "x = 1\n").unwrap();
        let base = commit_all(root, "base");
        let metadata = std::fs::metadata(root.join("mode.py")).unwrap();
        let mut permissions = metadata.permissions();
        use std::os::unix::fs::PermissionsExt as _;
        permissions.set_mode(0o755);
        std::fs::set_permissions(root.join("mode.py"), permissions).unwrap();
        // A real trigger line added to a sibling: the same pass must report
        // exactly this hit and none of mode.py's pre-existing lines.
        std::fs::write(
            root.join("normal.py"),
            b64("eCA9IDEKciA9IGdldCh1cmwsIHZlcmlmeSA9IEZhbHNlKQo="),
        )
        .unwrap();
        let head = commit_all(root, "head");
        let target = range_target(base, head);
        let (regressions, _) = checklist(root.to_str().unwrap(), &target);
        let tls = |path: &str| {
            regressions
                .iter()
                .filter(|h| h.rule == "runtime/tls-verification-disabled" && h.path == path)
                .count()
        };
        assert_eq!(
            tls("mode.py"),
            0,
            "the pre-existing line was never added in this range"
        );
        assert_eq!(
            tls("normal.py"),
            1,
            "the sibling's added trigger line still reports exactly once"
        );
    }

    /// A `-diff` attribute suppresses the hunk stream, so the range pass
    /// recovers the real delta with a forced `--text` diff: the added line
    /// reports, the pre-existing trigger line does not, and a removed
    /// ignore rule still reaches its removal rule.
    #[test]
    fn a_diff_attributed_change_recovers_its_real_delta() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-nodiff-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        let b64 = |s: &str| {
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
        };
        std::fs::write(
            root.join(".gitattributes"),
            "secret.py -diff\n.gitignore -diff\n",
        )
        .unwrap();
        std::fs::write(root.join(".gitignore"), b64("Ki5wZW0Ka2VlcC50eHQK")).unwrap();
        std::fs::write(
            root.join("secret.py"),
            b64("eCA9IDEKYyA9IGdldCh1cmwsIHZlcmlmeSA9IEZhbHNlKQo="),
        )
        .unwrap();
        let base = commit_all(root, "base");
        std::fs::write(root.join(".gitignore"), "keep.txt\n").unwrap();
        std::fs::write(
            root.join("secret.py"),
            b64("eCA9IDEKYyA9IGdldCh1cmwsIHZlcmlmeSA9IEZhbHNlKQpyID0gZ2V0KHVybCwgdmVyaWZ5ID0gRmFsc2UpCg=="),
        )
        .unwrap();
        let head = commit_all(root, "head");
        let target = range_target(base, head);
        let (regressions, _) = checklist(root.to_str().unwrap(), &target);
        let tls_lines: Vec<u64> = regressions
            .iter()
            .filter(|h| h.rule == "runtime/tls-verification-disabled" && h.path == "secret.py")
            .map(|h| h.line)
            .collect();
        assert_eq!(
            tls_lines,
            vec![3],
            "only the newly added trigger line reports, not the pre-existing one"
        );
        assert_eq!(
            regressions
                .iter()
                .filter(|h| h.rule == "hardening/ignore-rule-removed" && h.path == ".gitignore")
                .count(),
            1,
            "the recovered removed lines still feed removal rules"
        );
        // The added-lines regex executor sees the same recovered delta.
        let rule = Rule {
            id: "test/trigger".into(),
            title: "trigger".into(),
            kind: "regex".into(),
            pattern: Some(b64("dmVyaWZ5ID0gRmFsc2U=")),
            target: Some("added-lines".into()),
            prompt: None,
            builtin: None,
        };
        let paths = outgoing_paths(root.to_str().unwrap(), &target).unwrap();
        let (diffs, _) = range_diff(root.to_str().unwrap(), &target, &paths).unwrap();
        let hits = regex_hits(root.to_str().unwrap(), &target, &rule, &paths, &diffs).unwrap();
        assert_eq!(
            hits.iter()
                .filter(|h| h.path == "secret.py")
                .map(|h| h.line)
                .collect::<Vec<_>>(),
            vec![3],
            "the regex path reports the same recovered line"
        );
    }

    /// Removing a protection file outright - or emptying it - has no head
    /// blob to stream, yet the removed lines still owe the removal rules
    /// an answer. Under `-diff` the suppression must not hide the
    /// deletion either.
    #[test]
    fn a_deleted_or_emptied_protection_file_still_reports_removed_rules() {
        let b64 = |s: &str| {
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
        };
        for (variant, suppressed) in [("delete", false), ("empty", false), ("delete", true)] {
            let guard = CaseDir(std::env::temp_dir().join(format!(
                "gv-noprotect-{variant}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            )));
            let root = &guard.0;
            std::fs::create_dir_all(root).unwrap();
            git(root, &["init", "-q"]);
            git(root, &["config", "commit.gpgsign", "false"]);
            if suppressed {
                std::fs::write(root.join(".gitattributes"), ".gitignore -diff\n").unwrap();
            }
            std::fs::write(root.join(".gitignore"), b64("Ki5wZW0Ka2VlcC50eHQK")).unwrap();
            let base = commit_all(root, "base");
            match variant {
                "delete" => std::fs::remove_file(root.join(".gitignore")).unwrap(),
                _ => std::fs::write(root.join(".gitignore"), "").unwrap(),
            }
            let head = commit_all(root, "head");
            let target = range_target(base, head);
            let (regressions, _) = checklist(root.to_str().unwrap(), &target);
            assert_eq!(
                regressions
                    .iter()
                    .filter(|h| {
                        h.rule == "hardening/ignore-rule-removed" && h.path == ".gitignore"
                    })
                    .count(),
                1,
                "{variant} suppressed={suppressed}: the removed rule line must still surface"
            );
        }
    }

    /// A `-diff` file whose head turned binary keeps its base side: the
    /// removed rule line is still recovered and reported, while the head
    /// side is gated so added-lines rules see no mojibake.
    #[test]
    fn a_suppressed_binary_head_loses_only_its_own_side() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-binside-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        let b64 = |s: &str| {
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
        };
        std::fs::write(root.join(".gitattributes"), ".gitignore -diff\n").unwrap();
        std::fs::write(root.join(".gitignore"), b64("Ki5wZW0Ka2VlcC50eHQK")).unwrap();
        let base = commit_all(root, "base");
        // Head goes binary: the added side can no longer describe lines.
        std::fs::write(root.join(".gitignore"), b"pack\x00\x01\x02binary\n").unwrap();
        let head = commit_all(root, "head");
        let target = range_target(base, head);
        let (regressions, _) = checklist(root.to_str().unwrap(), &target);
        assert_eq!(
            regressions
                .iter()
                .filter(|h| h.rule == "hardening/ignore-rule-removed" && h.path == ".gitignore")
                .count(),
            1,
            "the readable base side still feeds removal rules"
        );
        let rule = Rule {
            id: "test/anyline".into(),
            title: "any".into(),
            kind: "regex".into(),
            pattern: Some(".".into()),
            target: Some("added-lines".into()),
            prompt: None,
            builtin: None,
        };
        let paths = outgoing_paths(root.to_str().unwrap(), &target).unwrap();
        let (diffs, unreadable) = range_diff(root.to_str().unwrap(), &target, &paths).unwrap();
        let hits = regex_hits(root.to_str().unwrap(), &target, &rule, &paths, &diffs).unwrap();
        assert!(
            hits.iter().all(|h| h.path != ".gitignore"),
            "the gated head side must not feed added-lines rules"
        );
        assert!(
            unreadable.is_empty(),
            "one readable side keeps the path out of the unreadable set"
        );
    }

    /// A suppressed deletion is recovered at any size: the unsuppressed
    /// diff would emit the same bytes, so the recovery list carries no
    /// size gate - only real binary sides are dropped.
    #[test]
    fn a_suppressed_oversized_deletion_is_recovered() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-bigside-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join(".gitattributes"), ".gitignore -diff\n").unwrap();
        let mut content = b"*.pem\n".to_vec();
        content.resize(1024 * 1024 + 64, b'x');
        std::fs::write(root.join(".gitignore"), &content).unwrap();
        let base = commit_all(root, "base");
        std::fs::remove_file(root.join(".gitignore")).unwrap();
        let head = commit_all(root, "head");
        let target = range_target(base, head);
        let (regressions, surfaces) = checklist(root.to_str().unwrap(), &target);
        assert_eq!(
            regressions
                .iter()
                .filter(|h| h.rule == "hardening/ignore-rule-removed" && h.path == ".gitignore")
                .count(),
            1,
            "the oversized base side still feeds removal rules"
        );
        assert!(
            surfaces
                .iter()
                .all(|h| h.rule != "surface/suppressed-unreadable"),
            "a recovered deletion leaves no coverage hole"
        );
    }

    /// A protection file is probed even without a suppression attribute:
    /// a `.gitignore` that turned binary still has its readable base side
    /// recovered, so the dropped rule line reports; and a protection file
    /// binary on every surviving side blocks instead of passing silently.
    #[test]
    fn a_content_binary_protection_file_never_goes_silent() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-protbin-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        let b64 = |s: &str| {
            String::from_utf8(base64::engine::general_purpose::STANDARD.decode(s).unwrap()).unwrap()
        };
        // No .gitattributes at all - the suppression is git's own binary
        // detection once a blob carries a NUL.
        std::fs::write(root.join(".gitignore"), b64("Ki5wZW0Ka2VlcC50eHQK")).unwrap();
        std::fs::write(root.join("CODEOWNERS"), b"* @o\x00wner\n").unwrap();
        let base = commit_all(root, "base");
        // `.gitignore`'s head side turns binary: the base is still
        // readable and owes the removal rules its dropped `*.pem` line.
        // `CODEOWNERS` was already binary and is deleted outright - no
        // surviving side is readable, so the hole blocks.
        std::fs::write(root.join(".gitignore"), b"keep.txt\nx\x00\x01\n").unwrap();
        std::fs::remove_file(root.join("CODEOWNERS")).unwrap();
        let head = commit_all(root, "head");
        let target = range_target(base, head);
        let (regressions, _) = checklist(root.to_str().unwrap(), &target);
        assert_eq!(
            regressions
                .iter()
                .filter(|h| h.rule == "hardening/ignore-rule-removed" && h.path == ".gitignore")
                .count(),
            1,
            "a readable base side still feeds removal rules without any attribute"
        );
        assert_eq!(
            regressions
                .iter()
                .filter(|h| h.rule == "hardening/protection-unreadable" && h.path == "CODEOWNERS")
                .count(),
            1,
            "a deleted protection file with an unreadable base blocks"
        );
    }

    /// An ordinary binary asset's change is suppressed by git's own
    /// content detection, not by an attribute - it is dropped from
    /// recovery without a surface, the same silence the diff gives it.
    #[test]
    fn a_plain_binary_change_is_not_a_surface() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-plainbin-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join("logo.png"), b"a\x00\x01binary\n").unwrap();
        std::fs::write(root.join("main.py"), "print(1)\n").unwrap();
        let base = commit_all(root, "base");
        std::fs::write(root.join("logo.png"), b"b\x00\x02binary\n").unwrap();
        let head = commit_all(root, "head");
        let target = range_target(base, head);
        let paths = outgoing_paths(root.to_str().unwrap(), &target).unwrap();
        let (diffs, unreadable) = range_diff(root.to_str().unwrap(), &target, &paths).unwrap();
        assert!(
            !diffs.contains_key("logo.png"),
            "a binary blob has no lines"
        );
        assert!(
            unreadable.is_empty(),
            "content-detected binaries are not a coverage gap"
        );
    }

    /// A suppressed delta whose recovered lines are not valid UTF-8 must
    /// not abort the stage: the streaming reader decodes lossily, so the
    /// readable side's lines still reach the rules.
    #[test]
    fn a_non_utf8_suppressed_delta_still_audits() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-nonutf8-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join(".gitattributes"), "blob.dat -diff\n").unwrap();
        std::fs::write(root.join("blob.dat"), b"first\xff\xfesecond\n").unwrap();
        let base = commit_all(root, "base");
        std::fs::write(root.join("blob.dat"), b"first\xfethird\n").unwrap();
        let head = commit_all(root, "head");
        let target = range_target(base, head);
        let rule = Rule {
            id: "test/anyline".into(),
            title: "any".into(),
            kind: "regex".into(),
            pattern: Some("third".into()),
            target: Some("added-lines".into()),
            prompt: None,
            builtin: None,
        };
        let paths = outgoing_paths(root.to_str().unwrap(), &target).unwrap();
        let (diffs, _) = range_diff(root.to_str().unwrap(), &target, &paths).unwrap();
        let hits = regex_hits(root.to_str().unwrap(), &target, &rule, &paths, &diffs).unwrap();
        assert_eq!(
            hits.iter().filter(|h| h.path == "blob.dat").count(),
            1,
            "non-UTF-8 bytes in a suppressed delta decode lossily, not abort"
        );
    }

    /// An attribute-suppressed file binary on every surviving side is the
    /// real gap: a `binary` attribute on churned content says "review me
    /// as text" yet no readable lines exist. On a protection file the
    /// hole is blocking; anywhere else it is a surface.
    #[test]
    fn an_attr_suppressed_binary_reports_unreadable() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-attrbin-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(
            root.join(".gitattributes"),
            ".gitignore binary\ndump.dat binary\n",
        )
        .unwrap();
        std::fs::write(root.join(".gitignore"), b"x\x00\x01\n").unwrap();
        std::fs::write(root.join("dump.dat"), b"y\x00\x02\n").unwrap();
        let base = commit_all(root, "base");
        std::fs::write(root.join(".gitignore"), b"x\x00\x03\n").unwrap();
        std::fs::write(root.join("dump.dat"), b"y\x00\x04\n").unwrap();
        let head = commit_all(root, "head");
        let target = range_target(base, head);
        let (regressions, surfaces) = checklist(root.to_str().unwrap(), &target);
        assert_eq!(
            regressions
                .iter()
                .filter(|h| h.rule == "hardening/protection-unreadable" && h.path == ".gitignore")
                .count(),
            1,
            "an unreadable protected suppression is blocking"
        );
        assert_eq!(
            surfaces
                .iter()
                .filter(|h| h.rule == "surface/suppressed-unreadable" && h.path == "dump.dat")
                .count(),
            1,
            "an unreadable ordinary suppression is surfaced"
        );
    }

    /// The floor the range gate enforces is the same predicate
    /// `require_attr_source` consults: below 2.42 - or an answer that is
    /// not a version at all - the stage refuses, so a stale or fake
    /// `git` can never reach the audit.
    #[test]
    fn the_attribute_source_floor_fails_closed() {
        for stale in [
            "git version 2.39.3",
            "git version 1.9.0",
            "git version 2.41.9",
            "git version",
            "not a version",
            "git version next",
        ] {
            assert!(
                !attr_floor_met(stale),
                "{stale:?} must not satisfy the floor"
            );
        }
        for ok in [
            "git version 2.42.0",
            "git version 2.42.0 (Apple Git-147)",
            "git version 3.0",
        ] {
            assert!(attr_floor_met(ok), "{ok:?} must satisfy the floor");
        }
    }

    /// A `git` placed first on PATH really is the binary the gate talks
    /// to - and a stale answer from it fails the floor closed.
    #[cfg(unix)]
    #[test]
    fn a_stale_git_on_path_fails_the_floor() {
        use std::os::unix::fs::PermissionsExt as _;
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-fakegit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        std::fs::create_dir_all(&guard.0).unwrap();
        let fake = guard.0.join("git");
        std::fs::write(&fake, "#!/bin/sh\necho 'git version 2.39.3'\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let output = super::git_command(".", &["version"], None)
            .env("PATH", &guard.0)
            .output()
            .unwrap();
        let answered = String::from_utf8_lossy(&output.stdout);
        assert!(
            answered.contains("2.39.3"),
            "the fake git answered: {answered}"
        );
        assert!(!attr_floor_met(&answered));
    }

    /// Attribute authority is the audited tree, not the checkout: an
    /// uncommitted `.gitattributes` cannot suppress the audited delta,
    /// and a committed `-diff` deleted only in the worktree still
    /// suppresses - and is still recovered - at head.
    #[test]
    fn attribute_answers_come_from_the_audited_head() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-attrhead-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join("tracked.txt"), "alpha\n").unwrap();
        let base = commit_all(root, "base");
        // Head carries the text change but no attributes; a -diff that
        // exists only in the dirty worktree afterwards must not suppress
        // the audited delta.
        std::fs::write(root.join("tracked.txt"), "alpha\nbeta\n").unwrap();
        let head = commit_all(root, "head");
        std::fs::write(root.join(".gitattributes"), "tracked.txt -diff\n").unwrap();
        let target = range_target(base.clone(), head.clone());
        let paths = outgoing_paths(root.to_str().unwrap(), &target).unwrap();
        let (diffs, _) = range_diff(root.to_str().unwrap(), &target, &paths).unwrap();
        assert!(
            diffs
                .get("tracked.txt")
                .is_some_and(|pair| !pair.0.is_empty()),
            "an attribute the audited tree never committed cannot hide the delta"
        );
        // Inverse: commit the -diff at the new head, then delete it from
        // the worktree only - head still suppresses, and recovery still
        // answers with the real delta.
        let base2 = head;
        std::fs::write(root.join("tracked.txt"), "alpha\nbeta\ngamma\n").unwrap();
        let head2 = commit_all(root, "head2");
        std::fs::remove_file(root.join(".gitattributes")).unwrap();
        let target2 = range_target(base2, head2);
        let paths2 = outgoing_paths(root.to_str().unwrap(), &target2).unwrap();
        let (diffs2, _) = range_diff(root.to_str().unwrap(), &target2, &paths2).unwrap();
        assert!(
            diffs2
                .get("tracked.txt")
                .is_some_and(|pair| !pair.0.is_empty()),
            "head's committed -diff suppresses and is recovered even when the worktree deletes it"
        );
    }

    /// A snapshot-scoped target that still carries a base derives its
    /// instruction surfaces from the base..head name set - a deleted
    /// channel file reports, an untouched same-tree sibling does not.
    #[test]
    fn a_snapshot_with_base_scopes_surfaces_to_the_range() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-snapbase-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join("AGENTS.md"), "rules\n").unwrap();
        std::fs::write(root.join("docs/SKILL.md"), "skill\n").unwrap();
        let base = commit_all(root, "base");
        std::fs::remove_file(root.join("AGENTS.md")).unwrap();
        std::fs::write(root.join("src.rs"), "fn main() {}\n").unwrap();
        let head = commit_all(root, "head");
        let target = super::Target {
            kind: "push".to_string(),
            label: "snapshot-with-base".to_string(),
            scope: "snapshot".to_string(),
            base: Some(base),
            head,
            ref_: None,
        };
        let (_, surfaces) = checklist(root.to_str().unwrap(), &target);
        let surfaced: Vec<&str> = surfaces
            .iter()
            .filter(|h| h.rule == "surface/instruction-channel")
            .map(|h| h.path.as_str())
            .collect();
        assert!(
            surfaced.contains(&"AGENTS.md"),
            "the deleted channel file is a surface: {surfaced:?}"
        );
        assert!(
            !surfaced.contains(&"docs/SKILL.md"),
            "an untouched in-tree file is not re-surfaced: {surfaced:?}"
        );
    }

    /// A deleted file has no head blob — a spec like `head:Release Notes.md`
    /// used to echo `<spec> missing`, which the whitespace header parser
    /// misread as a size and failed the whole pass. The OID-resolved batch
    /// simply carries no entry for it.
    #[test]
    fn a_deleted_path_with_a_space_or_newline_name_is_clean() {
        let guard = CaseDir(std::env::temp_dir().join(format!(
            "gv-deleted-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let root = &guard.0;
        std::fs::create_dir_all(root).unwrap();
        git(root, &["init", "-q"]);
        git(root, &["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join("Release Notes.md"), "notes\n").unwrap();
        let planted = format!("!x\n{}", "0".repeat(40));
        std::fs::write(root.join(&planted), "decoy\n").unwrap();
        std::fs::write(root.join("kept.py"), "x = 1\n").unwrap();
        let base = commit_all(root, "base");
        std::fs::remove_file(root.join("Release Notes.md")).unwrap();
        std::fs::remove_file(root.join(&planted)).unwrap();
        let head = commit_all(root, "head");
        let target = range_target(base, head);
        let (regressions, _) = checklist(root.to_str().unwrap(), &target);
        assert!(
            regressions.is_empty(),
            "deletions carry no lines to scan: {}",
            regressions
                .iter()
                .map(|h| format!("{}:{}", h.path, h.rule))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let (hygiene, _) = hygiene_audit(root.to_str().unwrap(), &target, true).unwrap();
        assert!(
            hygiene.is_empty(),
            "a deletion is never a finding: {}",
            hygiene
                .iter()
                .map(|h| format!("{}:{}", h.path, h.rule))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    #[test]
    fn instruction_and_interface_surfaces_are_classified() {
        for path in [
            "AGENTS.md",
            "docs/claude.md",
            "tools/x/SKILL.md",
            ".claude/settings.json",
            ".devin/skills/x.md",
            "lib/.mcp.json",
            "mcp.toml",
        ] {
            assert!(is_instruction_channel(path), "instruction: {path}");
        }
        assert!(!is_instruction_channel("src/main.rs"));
        assert!(!is_instruction_channel("docs/agent-notes.txt"));

        for path in [
            "api/v2.proto",
            "web/schema.graphql",
            "include/types.d.ts",
            // The repository's own published contract schema is itself an
            // interface surface.
            "docs/review-contract.schema.json",
            "db/migrations/0042_init.sql",
            "openapi.yaml",
        ] {
            assert!(is_interface_surface(path), "interface: {path}");
        }
        assert!(!is_interface_surface("src/api.rs"));
        assert!(!is_interface_surface("docs/notes.json"));
    }

    /// Checkers in one phase write the shared evidence concurrently: each key
    /// lives in its own entry file, so interleaved writers lose nothing.
    #[test]
    fn concurrent_evidence_writes_lose_no_keys() {
        use super::{evidence_get, evidence_store};
        let path = std::env::temp_dir().join(format!(
            "probator-ev-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        let mut handles = Vec::new();
        for writer in 0..8u32 {
            let path = path.clone();
            handles.push(std::thread::spawn(move || {
                for entry in 0..10u32 {
                    evidence_store(
                        &path,
                        &format!("key-{writer}-{entry}"),
                        serde_json::json!({"writer": writer}),
                    );
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        for writer in 0..8u32 {
            for entry in 0..10u32 {
                let value = evidence_get(&path, &format!("key-{writer}-{entry}"));
                assert_eq!(
                    value.as_ref().and_then(|v| v["writer"].as_u64()),
                    Some(writer as u64)
                );
            }
        }
        let _ = std::fs::remove_dir_all(path.with_extension("d"));
    }

    /// A miss races for the fill duty: the claimant computes and stores
    /// while a sibling's `evidence_begin` waits out the lock and returns
    /// the stored entry instead of paying the compute again.
    #[test]
    fn a_sibling_waits_for_the_fill_rather_than_recomputing() {
        use super::{Evidence, evidence_begin};
        let path = std::env::temp_dir().join(format!(
            "probator-evf-{}-{:04x}",
            std::process::id(),
            rand::random::<u16>()
        ));
        let (claimed, claim_signal) = std::sync::mpsc::channel::<bool>();
        let filler = std::thread::spawn({
            let path = path.clone();
            move || match evidence_begin(&path, "shared-key") {
                Evidence::Fill(fill) => {
                    let _ = claimed.send(true);
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    fill.store(serde_json::json!({"paid": 1}));
                    true
                }
                Evidence::Hit(_) => {
                    let _ = claimed.send(false);
                    false
                }
            }
        });
        // The sibling's claim is proven before this one tries.
        assert!(
            claim_signal.recv().unwrap(),
            "the first claim owns the fill"
        );
        let waited = match evidence_begin(&path, "shared-key") {
            Evidence::Hit(value) => {
                assert_eq!(value["paid"].as_u64(), Some(1));
                true
            }
            Evidence::Fill(_) => false,
        };
        assert!(filler.join().unwrap(), "the first claim owns the fill");
        assert!(waited, "the second claim waits and reuses the entry");
        let _ = std::fs::remove_dir_all(path.with_extension("d"));
    }
}
