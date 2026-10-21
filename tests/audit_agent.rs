//! Exercise the audit host against a mocked `va serve` child. Failover is
//! Virtual-Agent's job: these tests prove the host opens `binding: "audit"`
//! once, passes the shared role patch, and admits the serving custody
//! profile VA reports — it does not walk fallback candidates itself.
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn va_stub() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/va_serve.py");
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
    path
}

struct Fixture {
    contract_dir: PathBuf,
    run_dir: PathBuf,
    stub_dir: PathBuf,
    mode: String,
    profile: String,
    agent: String,
    model: String,
    session: String,
}
impl Fixture {
    fn new(mode: &str) -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "probator-va-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        let contract_dir = root.join("contract");
        let run_dir = root.join("run");
        let stub_dir = root.join("stub");
        std::fs::create_dir_all(&contract_dir).unwrap();
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::create_dir_all(&stub_dir).unwrap();
        let document = json!({
            "agents": {
                "opencode": {"id": "opencode", "lane": "acp", "command": {"program": "opencode", "args": []}},
                "devin": {"id": "devin", "lane": "acp", "command": {"program": "devin", "args": []}},
                "pi": {"id": "pi", "lane": "rpc", "command": {"program": "pi", "args": []}}
            },
            "profiles": {
                "synthetic-reviewer": {"agent": "opencode"},
                "synthetic-reviewer-devin": {"agent": "devin", "model": "swe-2-max"},
                "synthetic-reviewer-pi": {"agent": "pi", "model": "openai/gpt-6.1-sol", "effort": "xhigh"}
            },
            "bindings": {
                "audit": {"profile": "synthetic-reviewer", "prompt": "Binding context.",
                          "fallbacks": ["synthetic-reviewer-devin", "synthetic-reviewer-pi"]}
            },
            "secrets": {
                "devin-api-key": [{"env": "DEVIN_API_KEY"}]
            }
        });
        std::fs::write(
            contract_dir.join("registry.json"),
            serde_json::to_string_pretty(&document).unwrap(),
        )
        .unwrap();
        std::fs::write(
            contract_dir.join("contract.json"),
            serde_json::to_string_pretty(&json!({
                "name": "synthetic-reviewer",
                "title": "Synthetic Reviewer",
                "task": "synthetic audit"
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            contract_dir.join("installation.json"),
            serde_json::to_string_pretty(&json!({
                "synced": {"tag": "profile/synthetic-reviewer/v1"},
                "review": "/bin/echo"
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            contract_dir.join("policy.md"),
            "Only inspect synthetic evidence.",
        )
        .unwrap();
        std::fs::write(
            run_dir.join("scope.json"),
            serde_json::to_string_pretty(&json!({
                "runtime": {
                    "harness": "opencode",
                    "provider": "opencode",
                    "model": "opencode/stub-free"
                }
            }))
            .unwrap(),
        )
        .unwrap();
        Self {
            contract_dir,
            run_dir,
            stub_dir,
            mode: mode.to_string(),
            profile: "synthetic-reviewer".into(),
            agent: "opencode".into(),
            model: "opencode/stub-free".into(),
            session: "acp-stub-session".into(),
        }
    }

    fn write_document(&self, document: &Value) {
        std::fs::write(
            self.contract_dir.join("registry.json"),
            serde_json::to_string(document).unwrap(),
        )
        .unwrap();
    }

    fn document(&self) -> Value {
        serde_json::from_str(
            &std::fs::read_to_string(self.contract_dir.join("registry.json")).unwrap(),
        )
        .unwrap()
    }

    fn records(&self, name: &str) -> Vec<Value> {
        std::fs::read_to_string(self.stub_dir.join(name))
            .unwrap_or_default()
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn spawned(&self) -> bool {
        self.stub_dir.join("va-spawned.jsonl").exists()
    }

    fn invoke(&self) -> (bool, Value) {
        let wrapper = self.stub_dir.join("va");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nexec \"${{PYTHON:-python3}}\" \"{}\" \"$@\"\n",
                va_stub().display()
            ),
        )
        .unwrap();
        let _ = std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755));
        let output = Command::new(env!("CARGO_BIN_EXE_probator-agent"))
            .args([
                "--contract",
                self.contract_dir.to_str().unwrap(),
                "--run",
                self.run_dir.to_str().unwrap(),
            ])
            .env("PROBATOR_VA_BIN", &wrapper)
            .env("PROBATOR_VA_STUB_DIR", &self.stub_dir)
            .env("PROBATOR_VA_STUB_MODE", &self.mode)
            .env("PROBATOR_VA_STUB_PROFILE", &self.profile)
            .env("PROBATOR_VA_STUB_AGENT", &self.agent)
            .env("PROBATOR_VA_STUB_MODEL", &self.model)
            .env("PROBATOR_VA_STUB_SESSION", &self.session)
            .env("PYTHONUNBUFFERED", "1")
            .current_dir(&self.run_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(output.stdout.len() < 1024);
        let text = String::from_utf8(output.stdout).unwrap();
        let root = self.contract_dir.parent().unwrap();
        assert!(!text.contains(root.to_str().unwrap()));
        (
            output.status.success(),
            serde_json::from_str(&text).unwrap(),
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(root) = self.contract_dir.parent() {
            let _ = std::fs::remove_dir_all(root);
        }
    }
}

#[test]
fn declared_document_completes_with_usage_and_role_patch() {
    let fixture = Fixture::new("complete");
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    assert_eq!(result["completed"], true);
    assert_eq!(
        result["profile"],
        json!({"id":"synthetic-reviewer",
        "revision":"profile/synthetic-reviewer/v1","principal":"profile:synthetic-reviewer"})
    );
    assert_eq!(
        result["usage"],
        json!({"input_tokens":9,"output_tokens":4,
        "cache_read_tokens":2,"cache_write_tokens":1})
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            &std::fs::read_to_string(fixture.run_dir.join("audit-session.json")).unwrap()
        )
        .unwrap()["session_id"],
        "acp-stub-session"
    );
    let opens = fixture.records("session-open.jsonl");
    assert_eq!(opens.len(), 1, "{opens:?}");
    assert_eq!(opens[0]["binding"], "audit");
    assert!(
        opens[0].get("profile").is_none(),
        "Probator must open the binding, not a profile"
    );
    assert_eq!(
        opens[0]["patch"]["instructions"],
        "Only inspect synthetic evidence."
    );
    assert!(opens[0].get("resume").is_none());
    assert!(opens[0]["patch"].get("model").is_none());
    assert!(opens[0]["patch"].get("agent").is_none());
    assert_eq!(
        opens[0]["patch"]["mcpServers"],
        json!([{"type":"stdio","name":"probator-audit","command":"/bin/echo","args":[
            "serve","--contract",
            fixture.contract_dir.join("contract.json").to_string_lossy(),
            "--run",
            fixture.run_dir.to_string_lossy(),
        ],"env":[]}])
    );
    let prompts = fixture.records("session-prompt.jsonl");
    assert_eq!(prompts.len(), 1);
    let text = prompts[0]["text"].as_str().unwrap();
    assert!(
        text.starts_with("Review date (UTC): ") && text.ends_with("synthetic audit"),
        "{text}"
    );
    let spawned = fixture.records("va-spawned.jsonl");
    assert_eq!(spawned[0]["argv"], json!(["serve"]));
    assert_eq!(
        spawned[0]["virtual_agent_home"],
        fixture.run_dir.join("va-home").to_string_lossy().as_ref()
    );
    let home: Value = serde_json::from_str(
        &std::fs::read_to_string(fixture.run_dir.join("va-home/registry.json")).unwrap(),
    )
    .unwrap();
    assert!(home["secrets"]["devin-api-key"].is_array());
}

#[test]
fn agent_failures_never_complete() {
    for mode in ["failed", "interrupted", "disconnect"] {
        let fixture = Fixture::new(mode);
        let (_ok, result) = fixture.invoke();
        assert_eq!(result["completed"], false, "{mode}");
    }
}

#[test]
fn each_auditor_has_its_own_awp_principal() {
    for id in [
        "money-saver",
        "clean-auditor",
        "security-enhancer",
        "sustainable-maintainer",
    ] {
        let mut fixture = Fixture::new("complete");
        let mut contract: Value = serde_json::from_str(
            &std::fs::read_to_string(fixture.contract_dir.join("contract.json")).unwrap(),
        )
        .unwrap();
        contract["name"] = json!(id);
        std::fs::write(
            fixture.contract_dir.join("contract.json"),
            serde_json::to_string(&contract).unwrap(),
        )
        .unwrap();
        let mut document = fixture.document();
        document["profiles"][id] = json!({"agent": "opencode"});
        document["bindings"]["audit"]["profile"] = json!(id);
        fixture.write_document(&document);
        fixture.profile = id.to_string();
        let (ok, result) = fixture.invoke();
        assert!(ok);
        assert_eq!(result["profile"]["id"], id);
        assert_eq!(result["profile"]["principal"], format!("profile:{id}"));
        assert_eq!(fixture.records("session-open.jsonl")[0]["binding"], "audit");
    }
}

#[test]
fn inadmissible_roles_and_bindings_never_spawn_va() {
    for (runtime, policy) in [
        (
            json!({"harness": "unknown-agent", "provider": "opencode", "model": "opencode/stub-free"}),
            Some("Only inspect synthetic evidence."),
        ),
        (
            json!({"harness": "opencode", "provider": "opencode"}),
            Some("Only inspect synthetic evidence."),
        ),
        (
            json!({"harness": "opencode", "provider": "opencode",
                   "model": "opencode/stub-free", "models": ["openai/gpt-5"]}),
            Some("Only inspect synthetic evidence."),
        ),
        (
            json!({"harness": "opencode", "provider": "opencode", "model": "opencode/stub-free"}),
            Some(""),
        ),
    ] {
        let fixture = Fixture::new("complete");
        let mut scope: Value = serde_json::from_str(
            &std::fs::read_to_string(fixture.run_dir.join("scope.json")).unwrap(),
        )
        .unwrap();
        scope["runtime"] = runtime;
        std::fs::write(
            fixture.run_dir.join("scope.json"),
            serde_json::to_string(&scope).unwrap(),
        )
        .unwrap();
        if let Some(policy) = policy {
            std::fs::write(fixture.contract_dir.join("policy.md"), policy).unwrap();
        }
        let (ok, result) = fixture.invoke();
        assert!(!ok, "{result}");
        assert!(!fixture.spawned(), "{result}");
    }
    let fixture = Fixture::new("complete");
    let mut contract: Value = serde_json::from_str(
        &std::fs::read_to_string(fixture.contract_dir.join("contract.json")).unwrap(),
    )
    .unwrap();
    contract["name"] = json!("other-reviewer");
    std::fs::write(
        fixture.contract_dir.join("contract.json"),
        serde_json::to_string(&contract).unwrap(),
    )
    .unwrap();
    let (ok, result) = fixture.invoke();
    assert!(!ok, "{result}");
    assert!(!fixture.spawned(), "{result}");
}

#[test]
fn same_agent_models_are_overlaid_for_va_not_stepped_by_probator() {
    let fixture = Fixture::new("complete");
    let mut scope: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture.run_dir.join("scope.json")).unwrap())
            .unwrap();
    scope["runtime"]["models"] = json!(["opencode/glm-stub-free"]);
    std::fs::write(
        fixture.run_dir.join("scope.json"),
        serde_json::to_string(&scope).unwrap(),
    )
    .unwrap();
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    assert_eq!(fixture.records("session-open.jsonl").len(), 1);
    assert_eq!(fixture.records("session-open.jsonl")[0]["binding"], "audit");
    assert!(
        fixture.records("session-open.jsonl")[0]["patch"]
            .get("models")
            .is_none()
    );
    let home: Value = serde_json::from_str(
        &std::fs::read_to_string(fixture.run_dir.join("va-home/registry.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        home["profiles"]["synthetic-reviewer"]["models"],
        json!(["opencode/glm-stub-free"])
    );
    assert_eq!(
        home["profiles"]["synthetic-reviewer"]["model"],
        "opencode/stub-free"
    );
    assert_eq!(
        home["profiles"]["synthetic-reviewer-devin"]["model"],
        "swe-2-max"
    );
}

#[test]
fn undeclared_runtime_fields_do_not_leak_registry_values() {
    let fixture = Fixture::new("complete");
    let mut document = fixture.document();
    // The registry profile's tier list and effort were written for another
    // harness; the declared runtime names none of them, so none may survive
    // the overlay onto the serving profile.
    document["profiles"]["synthetic-reviewer"]["effort"] = json!("xhigh");
    document["profiles"]["synthetic-reviewer"]["models"] = json!(["openai/gpt-6.1-sol"]);
    document["profiles"]["synthetic-reviewer"]["windows"] =
        json!([{"days": "mon-fri", "start": "00:00", "end": "23:59", "timezone": "UTC"}]);
    fixture.write_document(&document);
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    let home: Value = serde_json::from_str(
        &std::fs::read_to_string(fixture.run_dir.join("va-home/registry.json")).unwrap(),
    )
    .unwrap();
    let primary = &home["profiles"]["synthetic-reviewer"];
    for key in ["effort", "models", "windows", "retry"] {
        assert!(
            primary.get(key).is_none(),
            "{key} leaked onto the serving profile: {primary}"
        );
    }
    assert_eq!(primary["agent"], "opencode");
    assert_eq!(primary["model"], "opencode/stub-free");
}

#[test]
fn va_serving_a_fallback_profile_is_admitted_after_one_binding_open() {
    let mut fixture = Fixture::new("complete");
    fixture.profile = "synthetic-reviewer-devin".into();
    fixture.agent = "devin".into();
    fixture.model = "swe-2-max".into();
    fixture.session = "devin-stub-session".into();
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    assert_eq!(result["completed"], true);
    assert_eq!(result["served"]["profile"], "synthetic-reviewer-devin");
    assert_eq!(result["served"]["agent"], "devin");
    assert_eq!(result["served"]["model"], "swe-2-max");
    let opens = fixture.records("session-open.jsonl");
    assert_eq!(opens.len(), 1, "Probator must not walk fallback profiles");
    assert_eq!(opens[0]["binding"], "audit");
    assert!(opens[0].get("profile").is_none());
    assert_eq!(
        opens[0]["patch"]["instructions"],
        "Only inspect synthetic evidence."
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            &std::fs::read_to_string(fixture.run_dir.join("audit-session.json")).unwrap()
        )
        .unwrap()["session_id"],
        "devin-stub-session"
    );
}

#[test]
fn an_exhausted_va_chain_is_classified_without_local_details() {
    let fixture = Fixture::new("exhausted");
    let (ok, result) = fixture.invoke();
    assert!(!ok);
    assert_eq!(result["completed"], false);
    assert!(result["failure"]["code"].is_string());
    assert_eq!(fixture.records("session-open.jsonl").len(), 1);
}

#[test]
fn va_serving_the_rpc_fallback_is_admitted() {
    let mut fixture = Fixture::new("rpc");
    fixture.profile = "synthetic-reviewer-pi".into();
    fixture.agent = "pi".into();
    fixture.model = "openai/gpt-6.1-sol".into();
    fixture.session = "rpc-stub-session".into();
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    assert_eq!(result["completed"], true);
    assert_eq!(result["served"]["profile"], "synthetic-reviewer-pi");
    assert_eq!(result["served"]["agent"], "pi");
    assert_eq!(result["served"]["model"], "openai/gpt-6.1-sol");
    assert_eq!(
        result["usage"],
        json!({
            "input_tokens": 42,
            "output_tokens": 10,
            "cache_read_tokens": 5,
            "cache_write_tokens": 2
        })
    );
    assert_eq!(fixture.records("session-open.jsonl").len(), 1);
    assert_eq!(fixture.records("session-open.jsonl")[0]["binding"], "audit");
    assert!(fixture.run_dir.join(".pi/mcp.json").exists());
}

#[test]
fn a_stale_resume_retries_the_same_binding_open_once() {
    let fixture = Fixture::new("stale-resume");
    std::fs::write(
        fixture.run_dir.join("audit-session.json"),
        json!({"session_id":"stale","session_ids":["stale"]}).to_string(),
    )
    .unwrap();
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    let opens = fixture.records("session-open.jsonl");
    assert_eq!(
        opens.len(),
        2,
        "stale resume retries once, then a fresh open"
    );
    assert_eq!(opens[0]["binding"], "audit");
    assert_eq!(opens[0]["resume"], "stale");
    assert!(opens[0].get("profile").is_none());
    assert_eq!(opens[1]["binding"], "audit");
    assert!(opens[1].get("resume").is_none());
    assert!(opens[1].get("profile").is_none());
    assert_eq!(opens[0]["patch"], opens[1]["patch"]);
}

#[test]
fn an_unadmitted_serving_profile_fails_closed() {
    let mut fixture = Fixture::new("complete");
    fixture.profile = "stranger".into();
    fixture.agent = "opencode".into();
    let (ok, result) = fixture.invoke();
    assert!(!ok, "{result}");
    assert_eq!(result["failure"]["code"], "audit_served_not_admitted");
    assert!(fixture.records("session-prompt.jsonl").is_empty());
}
