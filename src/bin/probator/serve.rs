//! The MCP-facing tool server: one long-lived stdio process per review,
//! keeping the run's paging state coherent for the whole verdict. The audit
//! agent session spawns it as the declared MCP server: `initialize` and
//! `tools/list` publish the contract's tool manifest, and every audit tool
//! call arrives as `tools/call`, answered with the call's JSON payload in
//! `content` (and `structuredContent`). Notifications earn no reply.

use crate::contract::{self, Contract};
use crate::documents::Documents;
use crate::evidence::Evidence;
use crate::fullservice::FullEvidence;
use crate::manifest::{self, Mode};
use crate::sanitize::sanitize;
use crate::submit::{self, ReviewState};
use serde_json::{Map, Value, json};
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

/// A checker's official-document catalog, from beside its contract file.
pub fn load_catalog(
    contract_path: &Path,
    contract: &Contract,
) -> Result<Option<Map<String, Value>>, String> {
    if !contract.tools.official_documents {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(contract_path.with_file_name("documents.json"))
        .map_err(|error| format!("documents.json: {error}"))?;
    let catalog = serde_json::from_str::<Value>(&raw)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| "documents.json: expected an object of catalog keys to URLs".to_string())?;
    Ok(Some(catalog))
}

pub struct Server {
    contract: Contract,
    evidence: Evidence,
    catalog: Option<Map<String, Value>>,
    /// The catalogued document fetcher, present when the contract declares it.
    /// Its cache is the fetched set the verdict validation cites.
    documents: Option<Documents>,
    /// Full-service mode: the snapshot-backed review object. None at the gate.
    full: Option<FullEvidence>,
    /// Project labels for the full-service submit coverage schema.
    projects: Vec<String>,
    run_dir: PathBuf,
    /// The run's scope: runtime labels and the review object's tree ride it.
    scope: Value,
    /// The official-document URLs fetched this review.
    fetched: HashSet<String>,
    /// The run's verdict credential. Absent once a verdict consumed it —
    /// without it no receipt can be signed and none may be submitted.
    key: Option<[u8; 32]>,
    submitted: bool,
}

impl Server {
    /// Load the contract, the run's evidence and, for a reviewer with the
    /// official-document verb, its catalog from beside the contract file. A
    /// run directory whose scope declares full-service mode also loads the
    /// snapshot-backed review object.
    pub fn load(contract_path: &Path, run_dir: &Path) -> Result<Server, String> {
        let contract = contract::load(contract_path)?;
        let evidence = Evidence::load(run_dir)?;
        let catalog = load_catalog(contract_path, &contract)?;
        let mut documents = catalog.clone().map(Documents::new).transpose()?;
        let scope: Value = serde_json::from_str(
            &std::fs::read_to_string(run_dir.join("scope.json"))
                .map_err(|error| format!("scope.json: {error}"))?,
        )
        .map_err(|error| format!("scope.json: {error}"))?;
        let full = if scope["mode"].as_str() == Some("full-service") {
            if !contract.tools.full_service {
                return Err("This contract offers no full-service mode".to_string());
            }
            let full = FullEvidence::load(run_dir)?;
            // A resumed run's persisted documents rejoin the fetched set.
            full.reload_documents(&mut documents)?;
            Some(full)
        } else {
            None
        };
        let projects = full
            .as_ref()
            .map(FullEvidence::projects)
            .unwrap_or_default();
        Ok(Server {
            contract,
            evidence,
            catalog,
            documents,
            full,
            projects,
            run_dir: run_dir.to_path_buf(),
            scope,
            fetched: HashSet::new(),
            key: crate::credential::load(run_dir),
            submitted: false,
        })
    }

    /// Dispatch one tool call. Tool failures never echo repository content:
    /// the reply carries the sanitized reason and the error type, exactly the
    /// string the Python engine's `_call` produces.
    pub fn call(&mut self, tool: &str, args: &Value) -> String {
        let payload = match self.dispatch(tool, args) {
            Ok(value) => value,
            Err(message) => json!({"error": sanitize(&message), "error_type": "ValueError"}),
        };
        serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string())
    }

    fn dispatch(&mut self, tool: &str, args: &Value) -> Result<Value, String> {
        let prefix = self.contract.tools.name_prefix.clone();
        if tool == format!("{prefix}_context") {
            // The declared verb list is the capability boundary: an operation
            // the contract does not offer refuses before it is served, so the
            // manifest and the runtime stay one authority.
            let verbs = if self.full.is_some() {
                self.contract
                    .tools
                    .context_full_service
                    .as_deref()
                    .unwrap_or(self.contract.tools.context.as_slice())
            } else {
                self.contract.tools.context.as_slice()
            };
            let operation = args["operation"].as_str().unwrap_or("");
            if !verbs.iter().any(|verb| verb == operation) {
                return Err(if self.full.is_some() {
                    format!("Full reviews use {}", verbs.join("/"))
                } else {
                    "Unknown context operation".to_string()
                });
            }
            if let Some(full) = &mut self.full {
                return full.context(&self.contract, self.catalog.as_ref(), args);
            }
            return self.context(args);
        }
        if tool == format!("{prefix}_official_doc") && self.contract.tools.official_documents {
            let name = args["name"].as_str().unwrap_or("");
            let full_mode = self.full.is_some();
            let documents = self
                .documents
                .as_mut()
                .ok_or_else(|| "unknown tool".to_string())?;
            let key = documents.resolve(name)?;
            let fresh = !documents.is_cached(&key);
            let reply = documents.get(&key, args["offset"].as_i64().unwrap_or(0))?;
            if full_mode && fresh {
                // The fetched document persists into the run directory: a
                // resumed run inherits it instead of refetching.
                if let (Some(full), Some(doc)) = (&self.full, documents.cached(&key)) {
                    let directory = full.run_dir().join("official-documents");
                    std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
                    let record = json!({
                        "url": doc.url,
                        "accessed": doc.accessed,
                        "content": doc.content,
                    });
                    let path = directory.join(format!("{key}.json"));
                    std::fs::write(
                        &path,
                        serde_json::to_string(&record).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ =
                            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
                    }
                    full.event("official_doc", Some(&key));
                }
            }
            if let Some(url) = reply["url"].as_str() {
                self.fetched.insert(url.to_string());
            }
            return Ok(reply);
        }
        if tool == format!("{prefix}_submit_review") {
            // The draft is preserved before validation: a correction resumes
            // from it instead of recreating the findings after a failure.
            let draft =
                crate::sanitize::sanitize(&serde_json::to_string(args).map_err(|e| e.to_string())?);
            let draft_path = self.run_dir.join("draft.json");
            std::fs::write(&draft_path, draft).map_err(|error| error.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&draft_path, std::fs::Permissions::from_mode(0o600));
            }
            if self.submitted || self.run_dir.join("report.json").exists() {
                return Err("A verdict has already been submitted".to_string());
            }
            if let Some(full) = &self.full {
                full.event("submit_attempt", None);
                let projects = full.projects();
                let state = submit::FullState {
                    files: full.files(),
                    aliases: full.aliases(),
                    projects: &projects,
                    reads: full.reads(),
                    original_read: full.original_read(),
                };
                submit::validate_full(&state, args)?;
            }
            // fetched = every document this review holds: freshly fetched and
            // journal-restored alike, as the Python engine computed it.
            let mut fetched = self.fetched.clone();
            if let Some(documents) = &self.documents {
                fetched.extend(documents.fetched());
            }
            let state = ReviewState {
                changed: self.evidence.changed(),
                reviewed: self.evidence.reviewed(),
                fetched: &fetched,
            };
            submit::validate(&self.contract, &state, args)?;
            self.submitted = true;
            // The receipt: the verdict plus the engine that produced it, the
            // review object's tree and the contract's extras - everything a
            // later gate needs to decide reuse without rerunning the review.
            let mut receipt = args.clone();
            let runtime = &self.scope["runtime"];
            receipt["harness"] = runtime["harness"].clone();
            receipt["provider"] = runtime["provider"].clone();
            receipt["model"] = runtime["model"].clone();
            receipt["reasoning"] = runtime["effort"].clone();
            receipt["tree"] = self.scope["tree"].clone();
            receipt["gate_status"] = json!("pending");
            receipt["engine"] = json!(concat!("probator ", env!("CARGO_PKG_VERSION")));
            if let Some(full) = &self.full {
                receipt["audit_mode"] = json!("full-service");
                receipt["original_request_read"] = json!(true);
                receipt["conversation_url"] = full.request()["conversation_url"].clone();
                let mut read_files: Vec<&String> = full.reads().iter().collect();
                read_files.sort();
                receipt["read_files"] = json!(read_files);
            }
            if self
                .contract
                .stage1
                .as_ref()
                .is_some_and(|stage1| stage1.surfaces)
            {
                receipt["surfaces"] = self.scope["surfaces"].clone();
            }
            if self.contract.tools.official_documents {
                let mut sources: Vec<Value> = self
                    .documents
                    .as_ref()
                    .map(|documents| {
                        documents
                            .cached_docs()
                            .map(|doc| json!({"url": doc.url, "accessed": doc.accessed}))
                            .collect()
                    })
                    .unwrap_or_default();
                sources.sort_by(|a, b| a["url"].as_str().cmp(&b["url"].as_str()));
                receipt["official_sources"] = json!(sources);
            }
            // The receipt never describes this machine.
            let sanitized = crate::sanitize::sanitize(
                &serde_json::to_string(&receipt).map_err(|e| e.to_string())?,
            );
            let mut receipt: Value = serde_json::from_str(&sanitized).map_err(|e| e.to_string())?;
            // The record rule applies before the credential is minted: an
            // empty policy signature is absent, never "", so the MAC covers
            // exactly the record that is written.
            receipt = crate::records::normalize(receipt);
            // Sign the verdict with the run's one-shot credential: only the
            // session holding this run's key can produce a receipt the gate
            // accepts, and submitting consumes it.
            let Some(key) = self.key else {
                return Err("the run's verdict credential is already spent".to_string());
            };
            receipt["receipt_mac"] = json!(crate::credential::mac(&key, &receipt));
            crate::evidence::write_json(&self.run_dir.join("report.json"), &receipt)?;
            if let Some(full) = &self.full {
                full.event("submitted", args["verdict"].as_str());
            }
            return Ok(json!({"accepted": true, "verdict": args["verdict"]}));
        }
        Err("unknown tool".to_string())
    }

    fn context(&mut self, args: &Value) -> Result<Value, String> {
        match args["operation"].as_str().unwrap_or("") {
            "inventory" => Ok(self
                .evidence
                .inventory(&self.contract, self.catalog.as_ref())),
            "list" => Ok(self
                .evidence
                .list(args["pattern"].as_str(), args["offset"].as_i64())?),
            "diff" => {
                let path = args["path"].as_str().unwrap_or("");
                if path.is_empty() {
                    return Err("operation \"diff\" requires a \"path\" argument".to_string());
                }
                self.evidence.diff(path, args["offset"].as_i64())
            }
            "read" => {
                let path = args["path"].as_str().unwrap_or("");
                if path.is_empty() {
                    return Err("operation \"read\" requires a \"path\" argument".to_string());
                }
                self.evidence.read(
                    path,
                    args["start"].as_i64(),
                    args["revision"].as_str(),
                    &self.contract.tools.revision_label,
                )
            }
            "find" => self
                .evidence
                .find(args["text"].as_str().unwrap_or(""), args["offset"].as_i64()),
            _ => Err("Unknown context operation".to_string()),
        }
    }

    /// The contract's tools in MCP `tools/list` shape: the same manifest the
    /// bridge advertised, with `parameters` renamed `inputSchema`.
    fn mcp_tools(&self) -> Vec<Value> {
        let mode = if self.full.is_some() {
            Mode::FullService
        } else {
            Mode::Gate
        };
        manifest::manifest(&self.contract, mode, &self.projects)
            .into_iter()
            .map(|tool| {
                json!({
                    "name": tool["name"],
                    "description": tool["description"],
                    "inputSchema": tool["parameters"],
                })
            })
            .collect()
    }

    /// The MCP stdio loop: one JSON-RPC object per line. Requests earn a
    /// `result`/`error` reply; notifications and malformed lines earn none.
    pub fn serve_mcp(mut self, input: impl BufRead, output: &mut impl Write) {
        for line in input.lines() {
            let Ok(line) = line else { break };
            let Ok(request) = serde_json::from_str::<Value>(&line) else {
                continue;
            };
            let method = request["method"].as_str().unwrap_or("");
            if method.starts_with("notifications/") {
                continue;
            }
            let Some(id) = request.get("id").cloned() else {
                continue;
            };
            let reply = match method {
                "initialize" => json!({"jsonrpc": "2.0", "id": id, "result": {
                    "protocolVersion": request["params"]["protocolVersion"]
                        .as_str()
                        .unwrap_or("2024-11-05"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "probator",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                }}),
                "ping" => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
                "tools/list" => {
                    json!({"jsonrpc": "2.0", "id": id, "result": {"tools": self.mcp_tools()}})
                }
                "tools/call" => {
                    let name = request["params"]["name"].as_str().unwrap_or("");
                    let result = self.call(name, &request["params"]["arguments"]);
                    let parsed: Value = serde_json::from_str(&result).unwrap_or(Value::Null);
                    let is_error = parsed.get("error").is_some();
                    // `structuredContent` must be a JSON object per MCP; array
                    // payloads ride `content` alone, which carries the same
                    // serialized result losslessly.
                    let mut payload = json!({
                        "content": [{"type": "text", "text": result}],
                        "isError": is_error,
                    });
                    if parsed.is_object() {
                        payload["structuredContent"] = parsed;
                    }
                    json!({"jsonrpc": "2.0", "id": id, "result": payload})
                }
                other => json!({"jsonrpc": "2.0", "id": id, "error": {
                    "code": -32601,
                    "message": format!("method not found: {other}"),
                }}),
            };
            if writeln!(output, "{reply}").is_err() {
                break;
            }
            let _ = output.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Server;
    use serde_json::{Value, json};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A snapshot review object: one commit, no base, a contract beside it.
    fn fixture() -> (Fixture, std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "gv-serve-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let git = |args: &[&str]| {
            let output = Command::new("git")
                .arg("-C")
                .arg(&root)
                .args(args)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap();
            assert!(output.status.success());
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        };
        git(&["init", "-q"]);
        git(&["config", "commit.gpgsign", "false"]);
        std::fs::write(root.join("one.txt"), "first\n").unwrap();
        git(&["add", "."]);
        git(&[
            "-c",
            "user.name=Synthetic",
            "-c",
            "user.email=synthetic@example.invalid",
            "commit",
            "-qm",
            "base",
        ]);
        let tree = git(&["rev-parse", "HEAD^{tree}"]);
        let run = root.join("run");
        std::fs::create_dir_all(&run).unwrap();
        let scope = json!({"repo": root, "tree": tree, "base": "", "changed": ["one.txt"]});
        std::fs::write(run.join("scope.json"), scope.to_string()).unwrap();
        let contract = root.join("contract.json");
        let text = json!({
            "name": "sample-checker",
            "title": "Sample Checker",
            "domains": ["structure"],
            "finding_keys": ["file", "line", "severity", "evidence"],
            "on": ["pre-push"],
            "tools": {
                "name_prefix": "sample",
                "context": ["inventory", "list", "diff", "read", "find"],
                "submit": true,
                "descriptions": {"context": "c", "submit": "s"}
            },
            "task": "Review."
        });
        std::fs::write(&contract, serde_json::to_string_pretty(&text).unwrap()).unwrap();
        (Fixture(root), contract, run)
    }

    #[test]
    fn the_mcp_protocol_round_trips() {
        let (_guard, contract, run) = fixture();
        let server = Server::load(&contract, &run).unwrap();
        let mut input = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\"}}\n",
            "not json\n",
            "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"method\":\"tools/call\",\"params\":{\"name\":\"sample_context\",\"arguments\":{\"operation\":\"inventory\"}}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"sample_context\",\"arguments\":{\"operation\":\"diff\"}}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"bogus\",\"arguments\":{}}}\n",
            "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"bogus/method\"}\n",
        ).as_bytes();
        let mut output = Vec::new();
        server.serve_mcp(&mut input, &mut output);
        let replies: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            replies.len(),
            6,
            "a malformed line and notifications earn no reply"
        );
        assert_eq!(replies[0]["id"], json!(1));
        assert_eq!(
            replies[0]["result"]["serverInfo"]["name"],
            json!("probator")
        );
        assert_eq!(replies[0]["result"]["protocolVersion"], json!("2025-03-26"));
        let tools = replies[1]["result"]["tools"].as_array().unwrap();
        assert_eq!(
            tools
                .iter()
                .map(|tool| tool["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["sample_context", "sample_submit_review"]
        );
        assert!(tools[0]["inputSchema"].is_object());
        let inventory: Value =
            serde_json::from_str(replies[2]["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(replies[2]["id"], json!("x"));
        assert_eq!(inventory["changed"], json!(["one.txt"]));
        assert_eq!(inventory["domains"], json!(["structure"]));
        assert_eq!(replies[2]["result"]["isError"], json!(false));
        let missing_path: Value =
            serde_json::from_str(replies[3]["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(
            missing_path["error"],
            "operation \"diff\" requires a \"path\" argument"
        );
        assert_eq!(replies[3]["result"]["isError"], json!(true));
        assert_eq!(replies[3]["id"], json!(4));
        let unknown: Value =
            serde_json::from_str(replies[4]["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        assert_eq!(unknown["error"], "unknown tool");
        assert_eq!(replies[5]["error"]["code"], json!(-32601));
    }

    /// A submitted record drops the run-record's empty policy signature
    /// before the credential is minted, so the MAC covers exactly what is
    /// written and an old record never gains a `""` field on the way out.
    #[test]
    fn a_submitted_record_omits_an_empty_policy_signature() {
        let (_guard, contract, run) = fixture();
        crate::credential::issue(&run).unwrap();
        let mut server = Server::load(&contract, &run).unwrap();
        let _ = server.call(
            "sample_context",
            &json!({"operation": "diff", "path": "one.txt"}),
        );
        let reply: Value = serde_json::from_str(&server.call(
            "sample_submit_review",
            &json!({
                "verdict": "pass",
                "summary": "clean",
                "coverage": {"structure": {"status": "reviewed", "reason": "looked"}},
                "findings": [],
                "unknowns": [],
                "policy_signature": ""
            }),
        ))
        .unwrap();
        assert_eq!(reply["accepted"], json!(true), "{reply}");
        let report: Value =
            serde_json::from_str(&std::fs::read_to_string(run.join("report.json")).unwrap())
                .unwrap();
        assert!(
            report.get("policy_signature").is_none(),
            "an empty policy signature must not be written: {report}"
        );
        assert!(report["receipt_mac"].is_string());
    }

    #[test]
    fn a_snapshot_diff_reads_against_the_empty_tree() {
        let (_guard, contract, run) = fixture();
        let mut server = Server::load(&contract, &run).unwrap();
        let result: Value = serde_json::from_str(&server.call(
            "sample_context",
            &json!({"operation": "diff", "path": "one.txt"}),
        ))
        .unwrap();
        assert!(result["content"].as_str().unwrap().contains("+first"));
        assert_eq!(result["next_offset"], Value::Null);
        // A snapshot has no base revision to read.
        let read: Value = serde_json::from_str(&server.call(
            "sample_context",
            &json!({"operation": "read", "path": "one.txt", "revision": "base"}),
        ))
        .unwrap();
        assert_eq!(
            read["error"],
            "This snapshot has no base revision; every path is new"
        );
    }

    /// A full-service run directory for a golden case: snapshot, request,
    /// scope, and the bare object store holding the empty tree.
    fn build_full_run(case: &Value) -> (Fixture, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "gv-fullserve-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let run = root.join("run");
        std::fs::create_dir_all(&run).unwrap();
        let repo = root.join("objects.git");
        assert!(
            Command::new("git")
                .args(["init", "--bare", "-q"])
                .arg(&repo)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap()
                .status
                .success()
        );
        let tree = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["hash-object", "-t", "tree", "--stdin", "-w"])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap()
            .stdout;
        let tree = String::from_utf8_lossy(&tree).trim().to_string();
        let materialize = |content: &Value| -> String {
            content.as_str().map(str::to_string).unwrap_or_else(|| {
                (1..=content["lines"].as_u64().unwrap() as usize)
                    .map(|i| format!("line {i}\n"))
                    .collect()
            })
        };
        let files: serde_json::Map<String, Value> = case["snapshot"]["files"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(path, content)| (path.clone(), json!(materialize(content))))
            .collect();
        std::fs::write(
            run.join("snapshot.json"),
            json!({"files": files, "aliases": case["snapshot"]["aliases"],
                   "projects": case["snapshot"]["projects"]})
            .to_string(),
        )
        .unwrap();
        std::fs::write(run.join("request.json"), case["request"].to_string()).unwrap();
        std::fs::write(
            run.join("scope.json"),
            json!({"mode": "full-service", "repo": repo.to_string_lossy(),
                   "tree": tree, "base": tree, "changed": []})
            .to_string(),
        )
        .unwrap();
        (Fixture(root), run)
    }

    /// The full-service transcripts the Python engine produced, replayed
    /// through the wire protocol.
    #[test]
    fn full_service_replays_the_engine_transcripts() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("review-parity");
        let cases: Vec<Value> = serde_json::from_str(
            &std::fs::read_to_string(dir.join("fullscript-cases.json")).unwrap(),
        )
        .unwrap();
        let expected: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join("fullscript-expected.json")).unwrap(),
        )
        .unwrap();
        assert!(!cases.is_empty(), "the corpus must not be empty");
        for case in &cases {
            let name = case["name"].as_str().unwrap();
            let checker = case["checker"].as_str().unwrap();
            let contract_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tools")
                .join(checker)
                .join("contract.json");
            let prefix = crate::contract::load(&contract_path)
                .unwrap()
                .tools
                .name_prefix
                .clone();
            let (_guard, run) = build_full_run(case);
            let mut server = Server::load(&contract_path, &run).unwrap();
            let mut transcript = Vec::new();
            for step in case["script"].as_array().unwrap() {
                let result: Value =
                    serde_json::from_str(&server.call(&format!("{prefix}_context"), &step["call"]))
                        .unwrap();
                if let Some(error) = result.get("error") {
                    transcript.push(json!({"error": error}));
                } else {
                    transcript.push(json!({"reply": result}));
                }
            }
            assert_eq!(json!(transcript), expected[name], "{name}");
        }
    }
}
