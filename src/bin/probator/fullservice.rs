//! The full-service review object: an operator-assigned snapshot of selected
//! source trees, reviewed once, resumable after failure. Ported from the two
//! Python `full_audit.py` review objects - one implementation here, so the
//! two full-service checkers cannot drift apart.
//!
//! The snapshot's files arrive already sanitized; reads of them are evidence
//! the verdict must account for, so the run keeps a progress journal
//! (`progress.jsonl`) that a resumed run replays instead of repaying.

use crate::contract::Contract;
use crate::evidence::{READ_PAGE_LINES, fnmatch_regex};
use crate::sanitize::sanitize_source;
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Paths per `list` reply in full-service mode.
pub const LIST_PAGE: usize = 200;

/// The engine-owned hygiene every snapshot applies: vendored, generated and
/// runtime directories are not reviewable source. Per-contract data carries
/// only what genuinely varies: suffixes, manifests, extra excluded names.
const HYGIENE_EXCLUDE: [&str; 17] = [
    ".git",
    "node_modules",
    "target",
    "build",
    "dist",
    "vendor",
    ".dart_tool",
    ".venv",
    ".next",
    "__pycache__",
    "reports",
    "history-assets",
    "fixtures",
    "snapshots",
    "testdata",
    "tmp",
    "cache",
];
const GENERATED_SUFFIXES: [&str; 4] = [".min.js", ".generated.ts", ".g.dart", ".freezed.dart"];

const SNAPSHOT_SCOPE: &str = "Current first-party source, manifests and root product/readme \
     documents; includes unstaged and untracked nonignored code. Excludes generated/build/vendor/\
     runtime data, private containers, fixtures and reports.";

/// The file contract: which files a full-service review reads. The shared
/// hygiene always applies; the contract's snapshot section adds its own.
pub fn eligible(contract: &Contract, path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    if path.split('/').any(|part| HYGIENE_EXCLUDE.contains(&part)) {
        return false;
    }
    if GENERATED_SUFFIXES
        .iter()
        .any(|suffix| name.ends_with(suffix))
    {
        return false;
    }
    let Some(snapshot) = &contract.snapshot else {
        return false;
    };
    if snapshot
        .exclude_names
        .iter()
        .any(|excluded| excluded == name)
    {
        return false;
    }
    if crate::evidence::safe_path(path).is_err() {
        return false;
    }
    // Case-sensitive, like the Python `Path.suffix` membership test.
    let suffix = name
        .rsplit_once('.')
        .filter(|(stem, _)| !stem.is_empty())
        .map(|(_, ext)| format!(".{ext}"));
    if suffix.is_some_and(|suffix| snapshot.suffixes.contains(&suffix)) {
        return true;
    }
    if snapshot.manifests.iter().any(|manifest| manifest == name) {
        return true;
    }
    static SPECIAL: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^(wrangler\..+|(docker-)?compose\..+|Dockerfile\..+)$").unwrap()
    });
    SPECIAL.is_match(name)
}

fn valid_label(name: &str) -> bool {
    !name.is_empty()
        && name.split('/').all(|segment| {
            !segment.is_empty()
                && segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        })
}

/// A sanitized, read-only snapshot of explicitly selected source trees, with
/// byte-identical reuse between a project and its primary copy. Ported from
/// the Python engine's `snapshot_projects`.
pub fn snapshot_projects(
    contract: &Contract,
    projects: &Map<String, Value>,
    reuse: Option<&Map<String, Value>>,
) -> Result<Value, String> {
    let mut files = Map::new();
    let mut coverage = Map::new();
    let compared: HashSet<&str> = reuse
        .map(|reuse| {
            reuse
                .keys()
                .map(String::as_str)
                .chain(reuse.values().filter_map(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let mut comparison_bytes: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    for (name, location) in projects {
        if !valid_label(name) {
            return Err("Project label must be a relative identifier".to_string());
        }
        let location = location.as_str().unwrap_or("");
        let root = std::fs::canonicalize(location)
            .map_err(|error| format!("Could not enumerate selected project: {error}"))?;
        let output = Command::new("rg")
            .args([
                "--files",
                "--hidden",
                "-g",
                "!.git",
                "-g",
                "!node_modules",
                "-g",
                "!target",
                "-g",
                "!build",
                "-g",
                "!dist",
                "-g",
                "!.venv",
            ])
            .current_dir(&root)
            .output()
            .map_err(|error| format!("Could not enumerate selected project: {error}"))?;
        if !output.status.success() && output.status.code() != Some(1) {
            return Err("Could not enumerate selected project".to_string());
        }
        let mut count = 0u64;
        let mut listing: Vec<String> = String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_string)
            .collect();
        listing.sort();
        for path in listing {
            if !eligible(contract, &path) {
                continue;
            }
            let file = root.join(&path);
            let is_real_file = file.is_file()
                && !file.is_symlink()
                && std::fs::canonicalize(&file).is_ok_and(|real| real.starts_with(&root));
            if !is_real_file {
                continue;
            }
            let raw =
                std::fs::read(&file).map_err(|error| format!("Could not read {path}: {error}"))?;
            if raw.contains(&0) {
                continue;
            }
            let key = format!("{name}/{path}");
            files.insert(
                key.clone(),
                json!(sanitize_source(&String::from_utf8_lossy(&raw))),
            );
            if compared.contains(name.as_str()) {
                comparison_bytes.insert(key, raw);
            }
            count += 1;
        }
        coverage.insert(
            name.clone(),
            json!({"source_files": count, "scope": SNAPSHOT_SCOPE}),
        );
    }
    let mut aliases = Map::new();
    if let Some(reuse) = reuse {
        for (destination, origin) in reuse {
            let origin = origin.as_str().unwrap_or("");
            if !coverage.contains_key(destination) || !coverage.contains_key(origin) {
                return Err("Reuse must refer to selected projects".to_string());
            }
            let mut shared = 0u64;
            let keys: Vec<String> = files
                .keys()
                .filter(|key| key.starts_with(&format!("{destination}/")))
                .cloned()
                .collect();
            for key in keys {
                let base_path = format!("{origin}{}", &key[destination.len()..]);
                let identical = files.contains_key(&base_path)
                    && comparison_bytes.get(&key) == comparison_bytes.get(&base_path);
                if identical {
                    aliases.insert(key.clone(), json!(base_path));
                    files.remove(&key);
                    shared += 1;
                }
            }
            let entry = coverage.get_mut(destination).unwrap();
            let source_files = entry["source_files"].as_u64().unwrap_or(0);
            entry["identical_source_reused_from"] = json!(origin);
            entry["identical_files"] = json!(shared);
            entry["distinct_files"] = json!(source_files - shared);
        }
    }
    Ok(json!({"files": files, "projects": coverage, "aliases": aliases}))
}

fn now_iso8601() -> String {
    crate::date::timestamp_string(crate::date::epoch_secs())
}

/// A full-service run's view of the snapshot, with the journal state a
/// resumed run replays.
pub struct FullEvidence {
    run_dir: PathBuf,
    files: Map<String, Value>,
    aliases: Map<String, Value>,
    projects: Map<String, Value>,
    request: Value,
    reads: HashSet<String>,
    original_read: bool,
}

impl FullEvidence {
    /// Load the snapshot and replay the journal a previous attempt left.
    pub fn load(run_dir: &Path) -> Result<FullEvidence, String> {
        let read = |name: &str| {
            std::fs::read_to_string(run_dir.join(name)).map_err(|error| format!("{name}: {error}"))
        };
        let snapshot: Value = serde_json::from_str(&read("snapshot.json")?)
            .map_err(|e| format!("snapshot.json: {e}"))?;
        let request: Value = serde_json::from_str(&read("request.json")?)
            .map_err(|e| format!("request.json: {e}"))?;
        let files = snapshot["files"].as_object().cloned().unwrap_or_default();
        let aliases = snapshot["aliases"].as_object().cloned().unwrap_or_default();
        let projects = snapshot["projects"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        let mut reads = HashSet::new();
        let mut original_read = false;
        if let Ok(journal) = read("progress.jsonl") {
            for line in journal.lines() {
                let Ok(event) = serde_json::from_str::<Value>(line) else {
                    continue;
                };
                match event["operation"].as_str() {
                    Some("read") => {
                        if let Some(path) = event["path"].as_str()
                            && (files.contains_key(path) || aliases.contains_key(path))
                        {
                            reads.insert(path.to_string());
                        }
                    }
                    Some("original_request") => original_read = true,
                    _ => {}
                }
            }
        }
        Ok(FullEvidence {
            run_dir: run_dir.to_path_buf(),
            files,
            aliases,
            projects,
            request,
            reads,
            original_read,
        })
    }

    /// One journal line. The journal exists so a resumed run inherits what
    /// this attempt already paid to read.
    pub(crate) fn event(&self, operation: &str, path: Option<&str>) {
        let mut event = json!({"at": now_iso8601(), "operation": operation});
        if let Some(path) = path {
            event["path"] = json!(path);
        }
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.run_dir.join("progress.jsonl"))
        {
            let _ = writeln!(file, "{event}");
        }
    }

    pub fn reads(&self) -> &HashSet<String> {
        &self.reads
    }

    pub fn original_read(&self) -> bool {
        self.original_read
    }

    pub fn projects(&self) -> Vec<String> {
        self.projects.keys().cloned().collect()
    }

    pub fn files(&self) -> &Map<String, Value> {
        &self.files
    }

    pub fn aliases(&self) -> &Map<String, Value> {
        &self.aliases
    }

    pub fn run_dir(&self) -> &Path {
        &self.run_dir
    }

    pub fn request(&self) -> &Value {
        &self.request
    }

    /// A resumed run's persisted documents rejoin the cache, so nothing is
    /// refetched and the verdict can still cite them.
    pub fn reload_documents(
        &self,
        documents: &mut Option<crate::documents::Documents>,
    ) -> Result<(), String> {
        let Some(documents) = documents.as_mut() else {
            return Ok(());
        };
        let dir = self.run_dir.join("official-documents");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Ok(());
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let Some(key) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .map(str::to_string)
            else {
                continue;
            };
            let Ok(raw) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Ok(saved) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            let url = saved["url"].as_str().unwrap_or("").to_string();
            if !documents.restorable(&key, &url) {
                continue;
            }
            documents.restore(
                key,
                crate::documents::Doc {
                    url,
                    accessed: saved["accessed"].as_str().unwrap_or("").to_string(),
                    content: saved["content"].as_str().unwrap_or("").to_string(),
                },
            );
        }
        Ok(())
    }

    /// The full-service context surface: inventory, original_request, list,
    /// read, find. Everything else is answered with the mode's own refusal.
    pub fn context(
        &mut self,
        contract: &Contract,
        catalog: Option<&Map<String, Value>>,
        args: &Value,
    ) -> Result<Value, String> {
        let operation = args["operation"].as_str().unwrap_or("");
        if operation != "read" {
            self.event(operation, args["path"].as_str());
        }
        match operation {
            "inventory" => {
                let mut reply = Map::new();
                reply.insert("mode".into(), json!("full-service"));
                reply.insert("projects".into(), Value::Object(self.projects.clone()));
                if let Some(catalog) = catalog {
                    reply.insert("documents".into(), Value::Object(catalog.clone()));
                }
                reply.insert(contract.tools.domain_key.clone(), json!(contract.domains));
                reply.insert(
                    "instructions".into(),
                    json!(
                        contract
                            .tools
                            .descriptions
                            .inventory_full_service
                            .as_deref()
                            .unwrap_or("")
                    ),
                );
                Ok(Value::Object(reply))
            }
            "original_request" => {
                self.original_read = true;
                Ok(self.request.clone())
            }
            "list" => {
                let pattern = args["pattern"].as_str().unwrap_or("*");
                let glob = fnmatch_regex(pattern)?;
                let paths: Vec<&String> = self
                    .files
                    .keys()
                    .chain(self.aliases.keys())
                    .filter(|path| glob.is_match(path))
                    .collect();
                let offset = args["offset"].as_i64().unwrap_or(0).max(0) as usize;
                let page: Vec<&String> =
                    paths.iter().skip(offset).take(LIST_PAGE).copied().collect();
                Ok(json!({
                    "paths": page,
                    "total": paths.len(),
                    "next_offset": if offset + LIST_PAGE < paths.len() {
                        Value::from(offset + LIST_PAGE)
                    } else {
                        Value::Null
                    },
                }))
            }
            "read" => {
                let path = args["path"].as_str().unwrap_or("");
                let actual = self
                    .aliases
                    .get(path)
                    .and_then(Value::as_str)
                    .unwrap_or(path)
                    .to_string();
                let Some(content) = self.files.get(&actual).and_then(Value::as_str) else {
                    return Err("Path is outside the selected source snapshot".to_string());
                };
                let lines: Vec<&str> = content.lines().collect();
                let start = args["start"].as_i64().unwrap_or(1).max(1) as usize;
                let end = (start - 1 + READ_PAGE_LINES).min(lines.len());
                self.reads.insert(path.to_string());
                self.event("read", Some(path));
                let numbered = lines[(start - 1).min(end)..end]
                    .iter()
                    .enumerate()
                    .map(|(index, line)| format!("{}: {line}", (start - 1).min(end) + index + 1))
                    .collect::<Vec<_>>()
                    .join("\n");
                Ok(json!({
                    "source_reused_from": if actual == path { Value::Null } else { json!(actual) },
                    "total_lines": lines.len(),
                    "content": numbered,
                    "next_line": if end < lines.len() { Value::from(end + 1) } else { Value::Null },
                }))
            }
            "find" => {
                let text = args["text"].as_str().unwrap_or("");
                if text.is_empty() {
                    return Err("Search text is required".to_string());
                }
                let mut pattern = args["pattern"]
                    .as_str()
                    .or_else(|| args["path"].as_str())
                    .unwrap_or("*")
                    .to_string();
                // A path that is not a listed file is a directory prefix.
                if args.get("pattern").is_none()
                    && args.get("path").is_some()
                    && !self.files.contains_key(&pattern)
                    && !self.aliases.contains_key(&pattern)
                {
                    pattern = format!("{}/*", pattern.trim_end_matches('/'));
                }
                // Literal alternatives: one case-insensitive regex compiled
                // per call, so the line scan itself never allocates.
                let needles: Vec<String> = text.split('|').map(regex::escape).collect();
                let needle_re = regex::Regex::new(&format!("(?i:{})", needles.join("|")))
                    .map_err(|error| format!("invalid find text: {error}"))?;
                let glob = fnmatch_regex(&pattern)?;
                let mut selected: Vec<(&String, &str)> = Vec::new();
                for (path, content) in self.files.iter() {
                    if glob.is_match(path) {
                        selected.push((path, content.as_str().unwrap_or("")));
                    }
                }
                for (alias, origin) in self.aliases.iter() {
                    let origin = origin.as_str().unwrap_or("");
                    // An alias joins only when its origin was not itself
                    // selected - the evidence stays one copy.
                    if glob.is_match(alias)
                        && !selected.iter().any(|(path, _)| path.as_str() == origin)
                        && let Some(content) = self.files.get(origin).and_then(Value::as_str)
                    {
                        selected.push((alias, content));
                    }
                }
                let offset = args["offset"].as_i64().unwrap_or(0).max(0) as usize;
                // Only the returned page is materialized - a common word can
                // match hundreds of thousands of lines.
                let mut matches = Vec::new();
                let mut total = 0usize;
                for (path, content) in selected {
                    for (index, line) in content.lines().enumerate() {
                        if needle_re.is_match(line) {
                            if total >= offset && matches.len() < crate::evidence::FIND_PAGE {
                                matches.push(format!("{path}:{}: {line}", index + 1));
                            }
                            total += 1;
                        }
                    }
                }
                Ok(json!({
                    "matches": matches,
                    "total": total,
                    "next_offset": if offset + crate::evidence::FIND_PAGE < total {
                        Value::from(offset + crate::evidence::FIND_PAGE)
                    } else {
                        Value::Null
                    },
                }))
            }
            _ => Err("Full reviews use inventory/original_request/list/read/find".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    // The full-service behavior is pinned by the script goldens replayed in
    // the serve tests; this module keeps the pure eligibility checks inline.
    use super::eligible;
    use crate::contract;
    use std::path::Path;

    fn codebase_maintainer() -> contract::Contract {
        contract::load(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tools/codebase-maintainer/contract.json")
                .as_path(),
        )
        .unwrap()
    }

    #[test]
    fn eligibility_is_the_file_contract() {
        let contract = codebase_maintainer();
        assert!(eligible(&contract, "src/main.rs"));
        assert!(eligible(&contract, "docs/guide.md"));
        assert!(eligible(&contract, "AGENTS.md"));
        assert!(eligible(&contract, "wrangler.toml"));
        assert!(eligible(&contract, "docker-compose.yml"));
        assert!(!eligible(&contract, "Cargo.lock"));
        assert!(!eligible(&contract, "node_modules/x/index.js"));
        assert!(!eligible(&contract, "src/lib.min.js"));
        assert!(!eligible(&contract, "assets/logo.png"));
        assert!(!eligible(&contract, ".env"));
        assert!(!eligible(&contract, "src/lib.rs/"));
        assert!(!eligible(&contract, "UPPER.RS"));
    }

    /// The sanitized snapshot the Python engine builds, byte for byte.
    #[test]
    fn snapshots_match_the_engine_goldens() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("review-parity");
        let cases: Vec<serde_json::Value> = serde_json::from_str(
            &std::fs::read_to_string(dir.join("snapshot-cases.json")).unwrap(),
        )
        .unwrap();
        let expected: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("snapshot-expected.json")).unwrap(),
        )
        .unwrap();
        assert!(!cases.is_empty(), "the corpus must not be empty");
        for case in &cases {
            let name = case["name"].as_str().unwrap();
            let contract = contract::load(
                &Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tools")
                    .join(case["checker"].as_str().unwrap())
                    .join("contract.json"),
            )
            .unwrap();
            let root =
                std::env::temp_dir().join(format!("gv-snapshot-{}-{}", std::process::id(), name));
            let _ = std::fs::remove_dir_all(&root);
            let mut projects = serde_json::Map::new();
            for (label, files) in case["projects"].as_object().unwrap() {
                let location = root.join(label);
                for (path, content) in files.as_object().unwrap() {
                    let file = location.join(path);
                    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
                    std::fs::write(&file, content.as_str().unwrap()).unwrap();
                }
                projects.insert(
                    label.clone(),
                    serde_json::json!(std::fs::canonicalize(&location).unwrap().to_string_lossy()),
                );
            }
            let reuse = case.get("reuse").and_then(|reuse| reuse.as_object());
            let produced = super::snapshot_projects(&contract, &projects, reuse).unwrap();
            let _ = std::fs::remove_dir_all(&root);
            assert_eq!(produced, expected[name], "{name}");
        }
    }
}
