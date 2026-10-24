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
use crate::evidence::{EMPTY_TREE, git, git_ok, suffix_of};
use regex::Regex;
use regex::bytes::Regex as BytesRegex;
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
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
    pub fallback: String,
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
            "fallback": self.fallback,
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
            fallback: value["fallback"].as_str()?.to_string(),
        })
    }
}

/// One target's outcome. `surfaces` is Some only for a checker whose contract
/// echoes them to the semantic stage.
pub struct Summary {
    pub label: String,
    pub scope: String,
    pub fallback: String,
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
            "fallback": self.fallback,
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
/// not.
pub struct Opts {
    pub withheld_path: Option<PathBuf>,
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
        .join(format!("{}.json", crate::seal::sha256_hex(key)))
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
        crate::seal::sha256_hex(key)
    ));
    let body = serde_json::to_string(&value).unwrap_or_default();
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(&tmp, &entry);
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

/// `owner/name` parsed from the origin remote. A remote that is a local path
/// is not a repository any name can identify.
fn origin_slug(repo: &str) -> String {
    let remote = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["remote", "get-url", "origin"])
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
// withheld-names-and-credentials (Clean Auditor)
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
            if let Ok(overridden) = std::env::var("CLEAN_AUDITOR_WITHHELD") {
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
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".config")
        });
    base.join("probator").join("withheld-names.txt")
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
    let Some(cache) = shared_evidence_path() else {
        return clean_audit_scan(repo, target, &names);
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
        format!("scan/{}", crate::seal::sha256_hex(&parts))
    };
    if let Some(cached) = evidence_get(&cache, &key) {
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
        return Ok((why, hits));
    }
    let (why, hits) = clean_audit_scan(repo, target, &names)?;
    evidence_store(
        &cache,
        &key,
        json!({
            "why": why,
            "hits": hits.iter().map(Hit::to_json).collect::<Vec<_>>(),
        }),
    );
    Ok((why, hits))
}

fn clean_audit_scan(
    repo: &str,
    target: &Target,
    names: &[String],
) -> Result<(String, Vec<Hit>), String> {
    let mut patterns: Vec<(&str, Regex)> = Vec::new();
    for name in names.iter().filter(|n| !n.trim().is_empty()) {
        patterns.push((
            "withheld-name",
            Regex::new(&format!("(?i){}", name_pattern(name)))
                .map_err(|e| format!("invalid withheld name pattern: {e}"))?,
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
    for record in git(repo, &["ls-tree", "-rz", &target.head])?
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
        if !metadata.starts_with("100644 ") && !metadata.starts_with("100755 ") {
            continue;
        }
        if let Some(oid) = metadata.split_whitespace().nth(2) {
            scanned.insert(oid.to_string());
        }
        let blob = git(
            repo,
            &["cat-file", "blob", &format!("{}:{path}", target.head)],
        )?;
        if is_binary(&blob.stdout, 8000) {
            continue;
        }
        for (number, line) in String::from_utf8_lossy(&blob.stdout).lines().enumerate() {
            let Some((rule, _)) = patterns.iter().find(|(_, pattern)| pattern.is_match(line))
            else {
                continue;
            };
            hits.push(Hit {
                path: path.to_string(),
                line: number as u64 + 1,
                rule: rule.to_string(),
                remedy: None,
            });
            if hits.len() >= MAX_HITS {
                break;
            }
        }
        if hits.len() >= MAX_HITS {
            break;
        }
    }
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
        // Blob-or-tree is settled by cat-file --batch-check in one process
        // rather than one probe per object. The oid list goes through a file:
        // piped stdin plus wait_with_output deadlocks once the list outgrows
        // the pipe buffer - the child stalls writing stdout nobody reads
        // while the parent stalls writing stdin nobody drains.
        if !blobs.is_empty() {
            let list = std::env::temp_dir().join(format!(
                "gv-oids-{}-{:04x}",
                std::process::id(),
                rand::random::<u16>()
            ));
            {
                use std::io::Write as _;
                let mut file = std::fs::File::create(&list)
                    .map_err(|e| format!("Git could not read the review snapshot: {e}"))?;
                for (oid, _) in &blobs {
                    let _ = writeln!(file, "{oid}");
                }
            }
            let checked = std::fs::File::open(&list)
                .map_err(|e| format!("Git could not read the review snapshot: {e}"))
                .and_then(|input| {
                    Command::new("git")
                        .arg("-C")
                        .arg(repo)
                        .args(["cat-file", "--batch-check=%(objectname) %(objecttype)"])
                        .stdin(std::process::Stdio::from(input))
                        .output()
                        .map_err(|e| format!("Git could not read the review snapshot: {e}"))
                });
            let _ = std::fs::remove_file(&list);
            let checked = checked?;
            let is_blob: std::collections::HashSet<String> =
                String::from_utf8_lossy(&checked.stdout)
                    .lines()
                    .filter(|l| l.ends_with(" blob"))
                    .filter_map(|l| l.split(' ').next().map(str::to_string))
                    .collect();
            'objects: for (oid, path) in blobs {
                if !is_blob.contains(&oid) {
                    continue;
                }
                let blob = git(repo, &["cat-file", "blob", &oid])?;
                if is_binary(&blob.stdout, 8000) {
                    continue;
                }
                let label = if path.is_empty() {
                    format!("history-blob {oid}")
                } else {
                    format!("{path} (range blob {oid})")
                };
                for (number, line) in String::from_utf8_lossy(&blob.stdout).lines().enumerate() {
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
                        break 'objects;
                    }
                }
            }
        }
    }
    let refused = if hits.iter().any(|hit| hit.rule == "withheld-name") {
        "withheld-name"
    } else if !hits.is_empty() {
        "credential-shape"
    } else {
        ""
    };
    Ok((refused.to_string(), hits))
}

// ---------------------------------------------------------------------------
// dependency-direction (Clean Auditor)
// ---------------------------------------------------------------------------

/// The sibling-repository dependency map, machine-local like the withheld
/// names: one line per repository, `Name <- upstream, upstream, ...`,
/// `#` comments. A document may name this repository's upstreams; a document
/// in an upstream repository must never name one of its downstreams — an
/// upstream naming a downstream publishes that repository's product plan
/// before the downstream has shipped anything on its own.
fn default_deps_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".config")
        });
    base.join("probator").join("repo-deps.txt")
}

/// One mapped repository: canonical name, the aliases documents actually
/// use (`Adapter-For-All-Agents|a4aa`), and the upstreams it depends on
/// (canonical names only - the graph never resolves an alias).
struct DepRepo {
    name: String,
    aliases: Vec<String>,
    upstreams: Vec<String>,
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
        let mut spellings = name.split('|').map(str::trim).filter(|s| !s.is_empty());
        let Some(canonical) = spellings.next() else {
            continue;
        };
        entries.push(DepRepo {
            name: canonical.to_string(),
            aliases: spellings.map(str::to_string).collect(),
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
    let mut hits = Vec::new();
    for record in git(repo, &["ls-tree", "-r", "-z", &target.head])?
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
        if !metadata.starts_with("100644 ") && !metadata.starts_with("100755 ") {
            continue;
        }
        if !is_document(path) {
            continue;
        }
        let blob = git(
            repo,
            &["cat-file", "blob", &format!("{}:{path}", target.head)],
        )?;
        if is_binary(&blob.stdout, 8000) {
            continue;
        }
        for (number, line) in String::from_utf8_lossy(&blob.stdout).lines().enumerate() {
            let Some((name, _)) = forbidden.iter().find(|(_, pattern)| pattern.is_match(line))
            else {
                continue;
            };
            hits.push(Hit {
                path: format!("{path} ({name})"),
                line: number as u64 + 1,
                rule: "dependency-direction".to_string(),
                remedy: Some(
                    "upstream documents must not name a downstream repository; \
                     drop the reference or move it into the downstream's own docs",
                ),
            });
            if hits.len() >= MAX_HITS {
                break;
            }
        }
        if hits.len() >= MAX_HITS {
            break;
        }
    }
    Ok(hits)
}

// ---------------------------------------------------------------------------
// workspace-hygiene
// ---------------------------------------------------------------------------

static MERGE_ARTIFACT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\.(orig|rej)$|\.(BACKUP|BASE|LOCAL|REMOTE)\.[0-9a-f]{7,}").unwrap()
});
static OS_JUNK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|/)(\.DS_Store|Thumbs\.db|desktop\.ini)$|(^|/)\._[^/]+$|\.(swp|swo)$|~$")
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
        let blob = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["show", &format!("{}:{path}", target.head)])
            .output()
            .map_err(|e| format!("Git could not read the review snapshot: {e}"))?;
        if !blob.status.success()
            || blob.stdout.len() > MAX_FILE_BYTES
            || is_binary(&blob.stdout, 8192)
        {
            continue;
        }
        for line in marker_lines(&blob.stdout) {
            hits.push(Hit {
                path: path.clone(),
                line,
                rule: "conflict-marker".into(),
                remedy: None,
            });
        }
    }
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
        _ => return None,
    })
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

/// Text of the file at the outgoing revision, or None when it is binary,
/// oversized or not a regular file.
fn blob_text(repo: &str, target: &Target, path: &str) -> Result<Option<String>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["cat-file", "blob", &format!("{}:{path}", target.head)])
        .output()
        .map_err(|e| format!("Git could not read the review snapshot: {e}"))?;
    let raw = output.stdout;
    if raw.is_empty() || is_binary(&raw, 8000) || raw.len() > MAX_SCAN_BYTES {
        return Ok(None);
    }
    Ok(Some(String::from_utf8_lossy(&raw).into_owned()))
}

/// (added, removed) line lists for one path, numbered at head and base. A
/// snapshot scan has no base: the caller reads the blob instead.
/// Added and removed lines of one file's diff, each numbered.
type DiffLines = (Vec<(u64, String)>, Vec<(u64, String)>);

fn diff_lines(repo: &str, target: &Target, path: &str) -> Result<Option<DiffLines>, String> {
    if target.scope != "range" {
        return Ok(None);
    }
    let output = git(
        repo,
        &[
            "diff",
            "--no-color",
            "--no-renames",
            "--unified=0",
            target.base.as_deref().unwrap_or(EMPTY_TREE),
            &target.head,
            "--",
            path,
        ],
    )?;
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let (mut old_line, mut new_line) = (0u64, 0u64);
    let header = Regex::new(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@").unwrap();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.starts_with("@@ ") {
            if let Some(found) = header.captures(line) {
                old_line = found[1].parse().unwrap_or(0);
                new_line = found[2].parse().unwrap_or(0);
            }
            continue;
        }
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if let Some(text) = line.strip_prefix('+') {
            added.push((new_line, text.to_string()));
            new_line += 1;
        } else if let Some(text) = line.strip_prefix('-') {
            removed.push((old_line, text.to_string()));
            old_line += 1;
        }
    }
    Ok(Some((added, removed)))
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
static SUPPRESS_ALLOW: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"gv-allow:([A-Za-z0-9/_-]+)").unwrap());
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
    with_surfaces: bool,
) -> Result<(Vec<Hit>, Vec<Hit>), String> {
    let mut regressions = Vec::new();
    let mut surfaces = Vec::new();
    let paths: Vec<String> = outgoing_paths(repo, target)?
        .into_iter()
        .filter(|path| !is_skipped(path))
        .collect();
    let rules = line_rules();
    // The changed-set feeds only surface classification; a contract that
    // does not echo surfaces has no consumer for the diff. An empty set, not
    // None, since None means "all paths are new".
    let changed = if with_surfaces {
        changed_paths(repo, target)?
    } else {
        Some(Default::default())
    };

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
    for path in range_touched(&changed, &paths, is_instruction_channel) {
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

    for path in &paths {
        let Some(text) = blob_text(repo, target, path)? else {
            continue;
        };
        let (added, removed) = match diff_lines(repo, target, path)? {
            Some(pair) => pair,
            None => (
                text.lines()
                    .enumerate()
                    .map(|(i, l)| (i as u64 + 1, l.to_string()))
                    .collect(),
                Vec::new(),
            ),
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
            for (number, line) in &added {
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
                                path: path.clone(),
                                line: *number,
                                rule: rule.rule.into(),
                                remedy: remedy(rule.rule),
                            });
                            break;
                        }
                        continue;
                    }
                    if rule.pattern.is_match(line) {
                        // `gv-allow:<rule-id>` on the same line suppresses a
                        // blocking hit where a documented compensating control
                        // exists (e.g. SPKI pinning instead of CA rejection).
                        // Suppressed hits stay visible as notices, never hidden.
                        let suppressed = SUPPRESS_ALLOW
                            .captures_iter(line)
                            .any(|allow| &allow[1] == rule.rule);
                        if suppressed {
                            surfaces.push(Hit {
                                path: path.clone(),
                                line: *number,
                                rule: format!("suppressed/{}", rule.rule),
                                remedy: remedy(rule.rule),
                            });
                        } else {
                            group.sink(&mut regressions, &mut surfaces).push(Hit {
                                path: path.clone(),
                                line: *number,
                                rule: rule.rule.into(),
                                remedy: remedy(rule.rule),
                            });
                        }
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
            for (number, line) in &added {
                if let Some(arg) = SECRET_ARG.captures(line)
                    && SECRET_NAME.is_match(&arg[1])
                    && !PLACEHOLDER.is_match(&arg[2])
                {
                    regressions.push(Hit {
                        path: path.clone(),
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
                            path: path.clone(),
                            line: *number,
                            rule: "container/unpinned-base-image".into(),
                            remedy: remedy("container/unpinned-base-image"),
                        });
                    }
                }
            }
        }
        // Removals that weaken protection.
        for (number, line) in &removed {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let name = path.rsplit('/').next().unwrap_or(path);
            if name == ".gitignore" && PROTECTED_IGNORE.is_match(line) {
                regressions.push(Hit {
                    path: path.clone(),
                    line: *number,
                    rule: "hardening/ignore-rule-removed".into(),
                    remedy: remedy("hardening/ignore-rule-removed"),
                });
            } else if name.to_uppercase().starts_with("CODEOWNERS") {
                regressions.push(Hit {
                    path: path.clone(),
                    line: *number,
                    rule: "hardening/codeowner-removed".into(),
                    remedy: remedy("hardening/codeowner-removed"),
                });
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
                    path: path.clone(),
                    line: credentials.iter().max().copied().unwrap_or(1),
                    rule: "runtime/cors-wildcard-credentials".into(),
                    remedy: remedy("runtime/cors-wildcard-credentials"),
                });
            }
        }
    }
    Ok((regressions, surfaces))
}

// ---------------------------------------------------------------------------
// the executor
// ---------------------------------------------------------------------------

/// A regex rule over its declared target: one hit per matching line or path.
fn regex_hits(repo: &str, target: &Target, rule: &Rule) -> Result<Vec<Hit>, String> {
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
            for path in outgoing_paths(repo, target)? {
                if pattern.is_match(&path) {
                    hits.push(Hit {
                        path,
                        line: 0,
                        rule: rule.id.clone(),
                        remedy: None,
                    });
                }
            }
        }
        "revision-lines" => {
            for record in git(repo, &["ls-tree", "-rz", &target.head])?
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
                if !metadata.starts_with("100644 ") && !metadata.starts_with("100755 ") {
                    continue;
                }
                let blob = git(
                    repo,
                    &["cat-file", "blob", &format!("{}:{path}", target.head)],
                )?;
                if is_binary(&blob.stdout, 8192) || blob.stdout.len() > MAX_FILE_BYTES {
                    continue;
                }
                for (index, line) in String::from_utf8_lossy(&blob.stdout).lines().enumerate() {
                    if pattern.is_match(line) {
                        hits.push(Hit {
                            path: path.to_string(),
                            line: index as u64 + 1,
                            rule: rule.id.clone(),
                            remedy: None,
                        });
                    }
                }
            }
        }
        _ => {
            // added-lines / removed-lines: the per-path diff, numbered at the
            // end of the range the line belongs to.
            for path in outgoing_paths(repo, target)? {
                let Some((added, removed)) = diff_lines(repo, target, &path)? else {
                    // A snapshot has no base: every line counts as added.
                    if target_name == "added-lines"
                        && let Some(text) = blob_text(repo, target, &path)?
                    {
                        for (index, line) in text.lines().enumerate() {
                            if pattern.is_match(line) {
                                hits.push(Hit {
                                    path: path.clone(),
                                    line: index as u64 + 1,
                                    rule: rule.id.clone(),
                                    remedy: None,
                                });
                            }
                        }
                    }
                    continue;
                };
                let lines = if target_name == "added-lines" {
                    &added
                } else {
                    &removed
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
    for rule in rules {
        match rule.kind.as_str() {
            // A prompt rule is a judgement the reviewer must make; the
            // orchestration surfaces it as a checklist item. It decides
            // nothing here.
            "prompt" => {}
            "regex" => {
                let found = regex_hits(repo, target, rule)?;
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
                        checklist_audit(repo, target, with_surfaces)?;
                    surfaces.get_or_insert_with(Vec::new).extend(found_surfaces);
                    if !regressions.is_empty() {
                        status = "regression".into();
                        if refused.is_empty() {
                            refused = "static-security-regression".to_string();
                        }
                        hits.extend(regressions);
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
        fallback: target.fallback.clone(),
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
        Hit, checklist_audit, clean_audit, dep_closure, dep_key, deps_map, in_scope,
        is_instruction_channel, is_interface_surface, marker_lines, name_pattern,
    };
    use base64::Engine as _;

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
            fallback: String::new(),
        };
        let hits = deps_audit(
            dir.to_str().unwrap(),
            &target,
            &super::Opts {
                withheld_path: None,
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
            fallback: String::new(),
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
            let opts = Opts {
                withheld_path: Some(withheld),
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
            fallback: String::new(),
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

    /// `gv-allow:<rule>` demotes a blocking security hit into a surfaced
    /// notice - visible, never hidden - while the same line unsuppressed stays
    /// a regression.
    #[test]
    fn gv_allow_demotes_a_blocking_hit_to_a_visible_surface() {
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
        let (regressions, surfaces) =
            checklist_audit(root.to_str().unwrap(), &target, true).unwrap();
        let seen = |hits: &[Hit]| {
            hits.iter()
                .map(|h| format!("{}:{}", h.path, h.rule))
                .collect::<Vec<_>>()
                .join(", ")
        };
        assert!(
            surfaces.iter().any(|h| {
                h.rule == "suppressed/runtime/tls-verification-disabled"
                    && h.path == "suppressed.py"
            }),
            "the suppression is a visible surface: {}",
            seen(&surfaces)
        );
        assert_eq!(
            regressions
                .iter()
                .filter(|h| h.rule == "runtime/tls-verification-disabled")
                .map(|h| h.path.as_str())
                .collect::<Vec<_>>(),
            ["raw.py"],
            "only the unsuppressed line regresses: {}",
            seen(&regressions)
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
}
