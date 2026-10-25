//! The evidence verbs: what a reviewer may read of the immutable review
//! object, and nothing else. Ported from the retired Python engine's Review;
//! the pagination and sensitive-path constants are pinned by the goldens
//! under `tests/review-parity/`.
//!
//! One deliberate divergence: Python's `splitlines` also splits on lone `\r`
//! and a handful of Unicode boundaries, Rust's `lines` on `\n` and `\r\n`.
//! Source trees under review use `\n`/`\r\n`; the exotic boundaries are a
//! Python stdlib accident, not a contract.

use crate::contract::Contract;
use crate::sanitize::sanitize_source;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Command;

// The pagination contract the tools and their descriptions share. The
// goldens recorded it from the retired Python engine: a size change here must
// land in the contract descriptions' placeholders too, or a tool description
// would promise a page the code no longer serves.
pub const READ_PAGE_LINES: usize = 400; // lines per `read` page
pub const DIFF_PAGE_CHARS: usize = 20000; // characters per `diff` page
pub const FIND_PAGE: usize = 100; // matches per `find` reply

/// A snapshot review diffs against the empty tree.
pub const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

// Credential containers and runtime stores are never handed to the semantic
// layer: shipping a key file to a cloud model is itself the leak this gate
// exists to prevent. Templates stay reviewable: an example file is exactly
// where a reviewer must look for a real value someone forgot to placeholder.
pub const SENSITIVE_PARTS: [&str; 13] = [
    ".git",
    ".ssh",
    ".aws",
    ".env",
    ".dev.vars",
    "secrets",
    "credentials",
    "logs",
    "runtime-data",
    ".netrc",
    ".npmrc",
    "credentials.json",
    "secrets.json",
];
pub const SENSITIVE_SUFFIXES: [&str; 12] = [
    ".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3", ".log", ".jsonl", ".enc",
    ".tfstate", ".kdbx",
];
pub const SENSITIVE_PREFIXES: [&str; 2] = [".env", ".dev.vars"];
pub const TEMPLATE_NAMES: [&str; 5] = [
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".dev.vars.example",
];

const PATH_REFUSAL: &str = "Sensitive or invalid path; contents are unavailable to the reviewer";

/// `PurePosixPath.parts`: split on `/`, dropping empty and `.` segments.
fn parts_of(path: &str) -> (bool, Vec<&str>) {
    let absolute = path.starts_with('/');
    let parts = path
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    (absolute, parts)
}

/// `PurePosixPath.suffix`, lowercased: the final dot-suffix, empty for
/// dotfiles and trailing dots.
pub(crate) fn suffix_of(name: &str) -> Option<String> {
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    Some(format!(".{}", ext.to_lowercase()))
}

/// The sensitive-path contract. One enumeration, so the deterministic stage
/// and the paid stage can never judge different sets.
pub fn safe_path(path: &str) -> Result<&str, String> {
    let (absolute, parts) = parts_of(path);
    let lowered: Vec<String> = parts.iter().map(|part| part.to_lowercase()).collect();
    let sensitive_part = lowered.iter().any(|part| {
        SENSITIVE_PARTS.contains(&part.as_str())
            || (!TEMPLATE_NAMES.contains(&part.as_str())
                && SENSITIVE_PREFIXES
                    .iter()
                    .any(|prefix| part.starts_with(prefix)))
    });
    let sensitive_suffix = parts
        .last()
        .and_then(|name| suffix_of(name))
        .is_some_and(|suffix| SENSITIVE_SUFFIXES.contains(&suffix.as_str()));
    if path.is_empty() || absolute || parts.contains(&"..") || sensitive_part || sensitive_suffix {
        return Err(PATH_REFUSAL.to_string());
    }
    Ok(path)
}

/// `fnmatch.fnmatchcase`: `*` spans slashes, `?` is one character, `[...]` a
/// class. Translated to a regular expression, the same construction CPython
/// uses.
#[cfg(test)]
pub(crate) fn fnmatchcase(name: &str, pattern: &str) -> Result<bool, String> {
    Ok(fnmatch_regex(pattern)?.is_match(name))
}

/// The compiled form of one glob, for callers matching it against many
/// names: regex compilation is the expensive half and belongs outside the
/// loop.
pub(crate) fn fnmatch_regex(pattern: &str) -> Result<regex::Regex, String> {
    let chars: Vec<char> = pattern.chars().collect();
    // Anchored at both ends: is_match searches unanchored, fnmatch compares
    // the whole name.
    let mut translated = String::from(r"(?s:\A");
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => translated.push_str(".*"),
            '?' => translated.push('.'),
            '[' => {
                let mut j = i + 1;
                if j < chars.len() && chars[j] == '!' {
                    j += 1;
                }
                if j < chars.len() && chars[j] == ']' {
                    j += 1;
                }
                while j < chars.len() && chars[j] != ']' {
                    j += 1;
                }
                if j >= chars.len() {
                    translated.push_str(r"\[");
                } else {
                    let mut stuff: String = chars[i + 1..j].iter().collect();
                    if let Some(rest) = stuff.strip_prefix('!') {
                        stuff = format!("^{rest}");
                    } else if stuff.starts_with('^') {
                        stuff = format!(r"\{stuff}");
                    }
                    translated.push('[');
                    translated.push_str(&stuff);
                    translated.push(']');
                    i = j;
                }
            }
            c => translated.push_str(&regex::escape(&c.to_string())),
        }
        i += 1;
    }
    translated.push_str(r")\z");
    regex::Regex::new(&translated).map_err(|error| format!("invalid glob pattern: {error}"))
}
/// The one `Command::new("git")` in these modules: `attr` pins
/// `GIT_ATTR_SOURCE` when a pass must answer attributes from the audited
/// tree rather than the ambient index/worktree. Every git spawn in
/// stage1 and evidence - buffered output callers, streamed bodies and
/// streamed diffs alike - starts here, so working directory, env and
/// attribute authority share a single construction.
pub(crate) fn git_command(repo: &str, args: &[&str], attr: Option<&str>) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(repo).args(args);
    if let Some(head) = attr {
        command.env("GIT_ATTR_SOURCE", head);
    }
    command
}

pub(crate) fn git(repo: &str, args: &[&str]) -> Result<std::process::Output, String> {
    git_output(repo, args, None)
}

/// `git` with the attribute source pinned to the audited tree: the review
/// object is the head commit, so attribute answers come from
/// `GIT_ATTR_SOURCE` (honored by Git 2.42+) rather than whatever the
/// index and worktree happen to hold. On an older Git the variable is
/// ignored and the ambient state answers; `check-attr --source` needs
/// Git 2.40 and fails closed below that floor, so the pair diverges only
/// on 2.40-2.41 against a worktree whose attributes differ from head's.
pub(crate) fn git_head_attr(
    repo: &str,
    args: &[&str],
    head: &str,
) -> Result<std::process::Output, String> {
    git_output(repo, args, Some(head))
}

fn git_output(
    repo: &str,
    args: &[&str],
    attr: Option<&str>,
) -> Result<std::process::Output, String> {
    let output = git_command(repo, args, attr)
        .output()
        .map_err(|error| format!("Git could not read the review snapshot: {error}"))?;
    if !output.status.success() {
        return Err("Git could not read the review snapshot".to_string());
    }
    Ok(output)
}

pub(crate) fn git_ok(repo: &str, args: &[&str]) -> bool {
    git_command(repo, args, None)
        .output()
        .is_ok_and(|output| output.status.success())
}

/// One JSON document, readable by the operator only.
pub(crate) fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let text = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    std::fs::write(path, text + "\n").map_err(|error| format!("{}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// A read-only view of one review object: the ls-tree entries, the changed
/// paths, and the paging state a verdict depends on.
pub struct Evidence {
    repo: String,
    tree: String,
    base: Option<String>,
    changed: Vec<String>,
    kind: String,
    surfaces: Value,
    /// ls-tree output order, kept for `list`; the map indexes into it.
    order: Vec<String>,
    entries: HashMap<String, (String, String)>, // path -> (mode, oid)
    diffs: HashMap<String, String>,
    diff_progress: HashMap<String, usize>,
    reviewed: HashSet<String>,
}

impl Evidence {
    /// Load the run directory's scope and enumerate the review object's tree.
    pub fn load(run_dir: &Path) -> Result<Evidence, String> {
        let raw = std::fs::read_to_string(run_dir.join("scope.json"))
            .map_err(|error| format!("scope.json: {error}"))?;
        let scope: Value =
            serde_json::from_str(&raw).map_err(|error| format!("scope.json: {error}"))?;
        let text = |key: &str| scope[key].as_str().unwrap_or_default().to_string();
        let repo = text("repo");
        let tree = text("tree");
        let base = match scope["base"].as_str() {
            Some(base) if !base.is_empty() => Some(base.to_string()),
            _ => None,
        };
        let changed = scope["changed"]
            .as_array()
            .map(|paths| {
                paths
                    .iter()
                    .filter_map(|p| p.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let output = git(&repo, &["ls-tree", "-rz", &tree])?;
        let mut order = Vec::new();
        let mut entries = HashMap::new();
        for record in output.stdout.split(|byte| *byte == 0) {
            if record.is_empty() {
                continue;
            }
            let record = String::from_utf8_lossy(record);
            let Some((metadata, path)) = record.split_once('\t') else {
                continue;
            };
            let mut fields = metadata.split_whitespace();
            let (Some(mode), Some(_kind), Some(oid)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            order.push(path.to_string());
            entries.insert(path.to_string(), (mode.to_string(), oid.to_string()));
        }
        Ok(Evidence {
            repo,
            tree,
            base,
            changed,
            kind: text("kind"),
            surfaces: scope.get("surfaces").cloned().unwrap_or_else(|| json!([])),
            order,
            entries,
            diffs: HashMap::new(),
            diff_progress: HashMap::new(),
            reviewed: HashSet::new(),
        })
    }

    /// The paths this verdict must account for.
    pub fn changed(&self) -> &[String] {
        &self.changed
    }

    /// The paths whose diff the reviewer paged to its end.
    pub fn reviewed(&self) -> &HashSet<String> {
        &self.reviewed
    }

    /// `inventory`: the review's mode, its range, and the contract's domains.
    pub fn inventory(&self, contract: &Contract, catalog: Option<&Map<String, Value>>) -> Value {
        let mut reply = Map::new();
        reply.insert("changed".into(), json!(self.changed));
        reply.insert("kind".into(), json!(self.kind));
        reply.insert(contract.tools.domain_key.clone(), json!(contract.domains));
        if let Some(catalog) = catalog {
            reply.insert("documents".into(), json!(catalog));
        }
        if contract
            .stage1
            .as_ref()
            .is_some_and(|stage1| stage1.surfaces)
        {
            reply.insert("surfaces".into(), self.surfaces.clone());
        }
        Value::Object(reply)
    }

    /// `list`: the tree's paths matching a glob, in ls-tree order, paged in
    /// match order — the same `{matches, more}` shape `find` returns, since
    /// the manifest promises offset pagination on both.
    pub fn list(&self, pattern: Option<&str>, offset: Option<i64>) -> Result<Value, String> {
        let pattern = fnmatch_regex(pattern.unwrap_or("*"))?;
        let mut matches = Vec::new();
        for path in &self.order {
            if pattern.is_match(path) {
                matches.push(path.clone());
            }
        }
        Ok(page(&matches, offset))
    }

    /// `diff`: the change to one path, paged in character order. Pages must be
    /// read in sequence; the last page read marks the path reviewed.
    pub fn diff(&mut self, path: &str, offset: Option<i64>) -> Result<Value, String> {
        let path = safe_path(path)?;
        if !self.changed.iter().any(|changed| changed == path) {
            return Err("Path is not part of this review snapshot".to_string());
        }
        if !self.diffs.contains_key(path) {
            let base = self.base.as_deref().unwrap_or(EMPTY_TREE);
            let output = git(
                &self.repo,
                &[
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-renames",
                    "--no-color",
                    "--unified=5",
                    base,
                    &self.tree,
                    "--",
                    path,
                ],
            )?;
            let raw = String::from_utf8_lossy(&output.stdout);
            self.diffs.insert(path.to_string(), sanitize_source(&raw));
        }
        let diff = &self.diffs[path];
        let chars: Vec<char> = diff.chars().collect();
        let total = chars.len();
        let start = offset.unwrap_or(0).max(0) as usize;
        if start > self.diff_progress.get(path).copied().unwrap_or(0) {
            return Err("Read the preceding diff page before advancing".to_string());
        }
        let end = (start + DIFF_PAGE_CHARS).min(total);
        let content: String = chars[start.min(end)..end].iter().collect();
        let progress = self.diff_progress.entry(path.to_string()).or_insert(0);
        *progress = end.max(*progress);
        if *progress == total {
            self.reviewed.insert(path.to_string());
        }
        Ok(json!({
            "content": content,
            "offset": start,
            "total_characters": total,
            "next_offset": if end < total { Value::from(end) } else { Value::Null },
        }))
    }

    /// `read`: numbered source lines of one path at the reviewed revision or
    /// the base. Binary blobs are reported, never served.
    pub fn read(
        &self,
        path: &str,
        start: Option<i64>,
        revision: Option<&str>,
        revision_label: &str,
    ) -> Result<Value, String> {
        let path = safe_path(path)?;
        let revision = revision.unwrap_or(revision_label);
        if revision != revision_label && revision != "base" {
            return Err(format!("revision must be {revision_label} or base"));
        }
        let blob = if revision == revision_label {
            let Some((mode, oid)) = self.entries.get(path) else {
                return Err("Only regular tracked source files can be read".to_string());
            };
            if mode != "100644" && mode != "100755" {
                return Err("Only regular tracked source files can be read".to_string());
            }
            oid.clone()
        } else {
            let Some(base) = &self.base else {
                return Err("This snapshot has no base revision; every path is new".to_string());
            };
            let spec = format!("{base}:{path}");
            if !git_ok(&self.repo, &["cat-file", "-e", &spec]) {
                return Err(
                    "Path does not exist in the base revision; the change adds it".to_string(),
                );
            }
            spec
        };
        let output = git(&self.repo, &["cat-file", "blob", &blob])?;
        if output.stdout.contains(&0) {
            return Ok(json!({"binary": true, "bytes": output.stdout.len()}));
        }
        let raw = String::from_utf8_lossy(&output.stdout);
        let sanitized = sanitize_source(&raw);
        let lines: Vec<&str> = sanitized.lines().collect();
        let start = start.unwrap_or(1).max(1) as usize;
        let end = (start - 1 + READ_PAGE_LINES).min(lines.len());
        let content = lines[(start - 1).min(end)..end]
            .iter()
            .enumerate()
            .map(|(index, line)| format!("{}: {line}", (start - 1).min(end) + index + 1))
            .collect::<Vec<_>>()
            .join("\n");
        Ok(json!({"total_lines": lines.len(), "content": content}))
    }

    /// `find`: a literal search over the review object, sanitized, paged in
    /// match order. Matches in paths the contract excludes are dropped, not
    /// served.
    pub fn find(&self, text: &str, offset: Option<i64>) -> Result<Value, String> {
        if text.is_empty() {
            return Err("A literal search string is required".to_string());
        }
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repo)
            .args(["grep", "-I", "-n", "-F", "-e", text, &self.tree, "--"])
            .output()
            .map_err(|error| format!("Source search failed: {error}"))?;
        match output.status.code() {
            Some(0) | Some(1) => {}
            _ => return Err("Source search failed".to_string()),
        }
        let mut matches = Vec::new();
        for record in String::from_utf8_lossy(&output.stdout).lines() {
            // <tree>:<path>:<line>:<text>; a path containing ':' truncates the
            // same way the Python engine's partition does.
            let Some((_, rest)) = record.split_once(':') else {
                continue;
            };
            let Some((path, line)) = rest.split_once(':') else {
                continue;
            };
            if safe_path(path).is_err() {
                continue;
            }
            matches.push(sanitize_source(&format!("{path}:{line}")));
        }
        Ok(page(&matches, offset))
    }
}

/// One page of a paged reply: `FIND_PAGE` entries after `offset`, with
/// `more` telling the caller another page exists. A negative offset reads
/// as zero — the first page — the same way `diff` treats it.
fn page(matches: &[String], offset: Option<i64>) -> Value {
    let start = offset.unwrap_or(0).max(0) as usize;
    let tail = &matches[start.min(matches.len())..];
    json!({
        "matches": &tail[..tail.len().min(FIND_PAGE)],
        "more": tail.len() > FIND_PAGE,
    })
}

#[cfg(test)]
mod tests {
    use super::{Evidence, fnmatchcase, safe_path};
    use crate::contract::Contract;
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        run: PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn git(repo: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
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
        assert!(output.status.success(), "git {args:?}: {:?}", output.stderr);
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn write(root: &Path, path: &str, content: &[u8]) {
        let file = root.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, content).unwrap();
    }

    fn commit(root: &Path, message: &str) -> String {
        git(root, &["add", "-A"]);
        git(root, &["commit", "-qm", message]);
        git(root, &["rev-parse", "HEAD"])
    }

    /// One range: base commit, then a head commit that modifies main.rs,
    /// deletes lib.rs, adds unicode.rs, and leaves a binary and a template
    /// untouched.
    fn fixture() -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "gv-evidence-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        git(&root, &["init", "-q"]);
        git(&root, &["config", "commit.gpgsign", "false"]);
        write(
            &root,
            "src/main.rs",
            b"fn main() {\n    println!(\"v1\");\n}\n",
        );
        write(&root, "src/lib.rs", b"pub fn gone() {}\n");
        write(
            &root,
            "docs/guide.md",
            b"# Guide\n\nsee https://docs.example.com/x\n",
        );
        write(&root, ".env.example", b"API_KEY=placeholder\n");
        write(&root, "data.bin", b"bin\0ary");
        let base = commit(&root, "base");
        let big: String = (1..=900)
            .map(|n| format!("let value_{n:03} = compute({n});\n"))
            .collect();
        write(&root, "src/main.rs", big.as_bytes());
        write(
            &root,
            "src/unicode.rs",
            "fn café() {\n    // héllo wörld\n    let münchen = 1;\n}\n"
                .repeat(3)
                .as_bytes(),
        );
        std::fs::remove_file(root.join("src/lib.rs")).unwrap();
        write(
            &root,
            "hits.txt",
            (1..=150)
                .map(|n| format!("needle on line {n}\n"))
                .collect::<String>()
                .as_bytes(),
        );
        let _head = commit(&root, "head");
        let tree = git(&root, &["rev-parse", "HEAD^{tree}"]);
        let run = root.join("run");
        std::fs::create_dir_all(&run).unwrap();
        let changed = git(
            &root,
            &["diff", "--name-only", "--no-renames", &base, &tree],
        )
        .lines()
        .map(|line| json!(line))
        .collect::<Vec<_>>();
        let scope = json!({
            "repo": root, "tree": tree, "base": base, "changed": changed,
            "kind": "commit", "surfaces": [{"path": "src/main.rs", "line": 1, "rule": "notice"}],
        });
        std::fs::write(
            run.join("scope.json"),
            serde_json::to_string_pretty(&scope).unwrap(),
        )
        .unwrap();
        Fixture { root, run }
    }

    fn sample_contract() -> Contract {
        serde_json::from_value(json!({
            "name": "sample-checker",
            "title": "Sample Checker",
            "domains": ["structure", "tests"],
            "finding_keys": ["file", "line", "severity", "evidence"],
            "on": ["pre-push"],
            "tools": {
                "name_prefix": "sample",
                "context": ["inventory", "list", "diff", "read", "find"],
                "submit": true,
                "descriptions": {"context": "c", "submit": "s"}
            },
            "task": "Review."
        }))
        .unwrap()
    }

    #[test]
    fn the_path_contract_holds() {
        for accepted in [
            "src/main.rs",
            "a//b.txt",
            "./x.rs",
            ".env.example",
            ".gitignore",
            "a/b/",
            "normal.json",
        ] {
            assert!(safe_path(accepted).is_ok(), "{accepted} must be accepted");
        }
        for refused in [
            "",
            "/abs",
            "../x",
            ".env",
            "sub/.env.production",
            "x.pem",
            "x.PEM",
            "dir/db.sqlite3",
            "logs/x.txt",
            "x/logs",
            ".ssh/config",
            "credentials.json",
        ] {
            assert!(safe_path(refused).is_err(), "{refused} must be refused");
        }
    }

    #[test]
    fn safe_path_matches_the_engine_goldens() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("review-parity");
        let read = |name: &str| {
            std::fs::read_to_string(dir.join(name))
                .unwrap_or_else(|error| panic!("{name}: {error}"))
        };
        let cases: Vec<String> = serde_json::from_str(&read("safepath-cases.json")).unwrap();
        let expected: serde_json::Value =
            serde_json::from_str(&read("safepath-expected.json")).unwrap();
        assert!(!cases.is_empty(), "the corpus must not be empty");
        for path in cases {
            assert_eq!(
                safe_path(&path).is_ok(),
                expected[path.as_str()].as_bool().unwrap(),
                "path {path:?}"
            );
        }
    }

    #[test]
    fn glob_matching_spans_directories() {
        assert!(fnmatchcase("src/main.rs", "*.rs").unwrap());
        assert!(fnmatchcase("src/main.rs", "src/*").unwrap());
        assert!(!fnmatchcase("src/main.rs", "*.md").unwrap());
        assert!(fnmatchcase("src/main.rs", "src/????.rs").unwrap());
        assert!(fnmatchcase("a", "[!bc]").unwrap());
        assert!(!fnmatchcase("b", "[!bc]").unwrap());
        assert!(fnmatchcase("a[", "a[").unwrap());
        assert!(!fnmatchcase("a[b", "a[").unwrap());
    }

    #[test]
    fn inventory_projects_the_contract() {
        let fixture = fixture();
        let evidence = Evidence::load(&fixture.run).unwrap();
        let mut contract = sample_contract();
        contract.stage1 = serde_json::from_value(json!({"surfaces": true, "rules": []})).unwrap();
        let reply = evidence.inventory(&contract, None);
        assert_eq!(reply["kind"], "commit");
        assert!(
            reply["changed"]
                .as_array()
                .unwrap()
                .contains(&json!("src/main.rs"))
        );
        assert_eq!(reply["domains"], json!(["structure", "tests"]));
        assert_eq!(reply["surfaces"][0]["rule"], "notice");
        let without = evidence.inventory(&sample_contract(), None);
        assert!(without.get("surfaces").is_none());
    }

    #[test]
    fn list_globs_the_tree() {
        let fixture = fixture();
        let evidence = Evidence::load(&fixture.run).unwrap();
        let all = evidence.list(None, None).unwrap();
        let matches = all["matches"].as_array().unwrap();
        assert!(matches.contains(&json!("src/main.rs")));
        assert!(matches.contains(&json!("docs/guide.md")));
        assert_eq!(
            evidence.list(Some("*.rs"), None).unwrap()["matches"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(evidence.list(Some(""), None).unwrap()["matches"], json!([]));
        // `offset` pages the match list the contract promises: the second
        // page of the `*.rs` glob skips the first match.
        let paged = evidence.list(Some("*.rs"), Some(1)).unwrap();
        assert_eq!(paged["matches"].as_array().unwrap().len(), 1);
        assert_eq!(paged["more"], false);
        // `find` honors the same offset.
        let first = evidence.find("héllo", None).unwrap();
        let next = evidence.find("héllo", Some(1)).unwrap();
        assert_eq!(
            next["matches"].as_array().unwrap().len() + 1,
            first["matches"].as_array().unwrap().len()
        );
    }

    #[test]
    fn diff_pages_in_order_and_marks_reviewed() {
        let fixture = fixture();
        let mut evidence = Evidence::load(&fixture.run).unwrap();
        let first = evidence.diff("src/main.rs", None).unwrap();
        let total = first["total_characters"].as_u64().unwrap() as usize;
        assert!(
            total > super::DIFF_PAGE_CHARS,
            "the fixture diff must exceed one page"
        );
        assert_eq!(first["offset"], 0);
        assert_eq!(first["next_offset"], json!(super::DIFF_PAGE_CHARS));
        assert!(first["content"].as_str().unwrap().contains("index "));
        let refusal = evidence
            .diff("src/main.rs", Some(super::DIFF_PAGE_CHARS as i64 + 1))
            .unwrap_err();
        assert_eq!(refusal, "Read the preceding diff page before advancing");
        let mut offset = first["next_offset"].as_u64().unwrap() as i64;
        loop {
            let page = evidence.diff("src/main.rs", Some(offset)).unwrap();
            match page["next_offset"].as_u64() {
                Some(next) => offset = next as i64,
                None => break,
            }
        }
        assert!(evidence.reviewed().contains("src/main.rs"));
        assert!(!evidence.reviewed().contains("src/unicode.rs"));
        assert_eq!(
            evidence.diff("docs/guide.md", None).unwrap_err(),
            "Path is not part of this review snapshot"
        );
        // A template passes the path contract and fails on range membership;
        // a real credential container never gets that far.
        assert_eq!(
            evidence.diff(".env.example", None).unwrap_err(),
            "Path is not part of this review snapshot"
        );
        assert_eq!(
            evidence.diff(".env", None).unwrap_err(),
            super::PATH_REFUSAL
        );
    }

    #[test]
    fn read_serves_numbered_lines_at_both_revisions() {
        let fixture = fixture();
        let evidence = Evidence::load(&fixture.run).unwrap();
        let page = evidence
            .read("src/unicode.rs", None, None, "outgoing")
            .unwrap();
        assert_eq!(page["total_lines"], 12);
        assert!(
            page["content"]
                .as_str()
                .unwrap()
                .starts_with("1: fn café() {")
        );
        let paged = evidence
            .read("src/unicode.rs", Some(2), None, "outgoing")
            .unwrap();
        assert!(
            paged["content"]
                .as_str()
                .unwrap()
                .starts_with("2:     // héllo wörld")
        );
        let old = evidence
            .read("src/main.rs", None, Some("base"), "outgoing")
            .unwrap();
        assert!(
            old["content"]
                .as_str()
                .unwrap()
                .contains("println!(\"v1\")")
        );
        assert_eq!(
            evidence
                .read("src/unicode.rs", None, Some("base"), "outgoing")
                .unwrap_err(),
            "Path does not exist in the base revision; the change adds it"
        );
        assert_eq!(
            evidence
                .read("src/lib.rs", None, None, "outgoing")
                .unwrap_err(),
            "Only regular tracked source files can be read"
        );
        assert_eq!(
            evidence.read("data.bin", None, None, "outgoing").unwrap(),
            json!({"binary": true, "bytes": 7})
        );
        assert_eq!(
            evidence
                .read("src/main.rs", None, Some("elsewhere"), "outgoing")
                .unwrap_err(),
            "revision must be outgoing or base"
        );
    }

    #[test]
    fn find_is_literal_sanitized_and_paged() {
        let fixture = fixture();
        let evidence = Evidence::load(&fixture.run).unwrap();
        let hits = evidence.find("héllo", None).unwrap();
        assert_eq!(
            hits["matches"],
            json!([
                "src/unicode.rs:2:    // héllo wörld",
                "src/unicode.rs:6:    // héllo wörld",
                "src/unicode.rs:10:    // héllo wörld",
            ])
        );
        assert_eq!(hits["more"], false);
        let many = evidence.find("needle", None).unwrap();
        assert_eq!(many["matches"].as_array().unwrap().len(), super::FIND_PAGE);
        assert_eq!(many["more"], true);
        // The URL in the guide is sanitized out of the match text.
        let guide = evidence.find("docs.example.com", None).unwrap();
        assert_eq!(
            guide["matches"],
            json!(["docs/guide.md:3:see https://[ENDPOINT]"])
        );
        assert_eq!(
            evidence.find("", None).unwrap_err(),
            "A literal search string is required"
        );
    }
}
