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

/// A pinned, executable stand-in for the trusted Pi installation. The stub
/// `va` never spawns it; the host validates its provenance before `va` runs.
fn pi_stub() -> PathBuf {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pi");
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
    path
}

struct Fixture {
    contract_dir: PathBuf,
    run_dir: PathBuf,
    stub_dir: PathBuf,
    user_home: PathBuf,
    mode: String,
    profile: String,
    agent: String,
    model: String,
    session: String,
    pi_agent_dir: Option<PathBuf>,
    pi_bin: Option<PathBuf>,
    path_override: Option<std::ffi::OsString>,
    va_missing: bool,
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
        let user_home = root.join("user-home");
        std::fs::create_dir_all(&contract_dir).unwrap();
        std::fs::create_dir_all(&run_dir).unwrap();
        std::fs::create_dir_all(&stub_dir).unwrap();
        std::fs::create_dir_all(&user_home).unwrap();
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
            user_home,
            mode: mode.to_string(),
            profile: "synthetic-reviewer".into(),
            agent: "opencode".into(),
            model: "opencode/stub-free".into(),
            session: "acp-stub-session".into(),
            pi_agent_dir: None,
            pi_bin: None,
            path_override: None,
            va_missing: false,
        }
    }

    fn write_user_registry(&self, document: &Value) {
        std::fs::write(
            self.user_home.join("registry.json"),
            serde_json::to_string_pretty(document).unwrap(),
        )
        .unwrap();
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
        if self.va_missing {
            let _ = std::fs::remove_file(&wrapper);
        } else {
            std::fs::write(
                &wrapper,
                format!(
                    "#!/bin/sh\nexec \"${{PYTHON:-python3}}\" \"{}\" \"$@\"\n",
                    va_stub().display()
                ),
            )
            .unwrap();
            let _ = std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755));
        }
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_probator-agent"));
        cmd.args([
            "--contract",
            self.contract_dir.to_str().unwrap(),
            "--run",
            self.run_dir.to_str().unwrap(),
        ])
        .env("PROBATOR_VA_BIN", &wrapper)
        .env("VIRTUAL_AGENT_HOME", &self.user_home)
        .env("PROBATOR_VA_STUB_DIR", &self.stub_dir)
        .env("PROBATOR_VA_STUB_MODE", &self.mode)
        .env("PROBATOR_VA_STUB_PROFILE", &self.profile)
        .env("PROBATOR_VA_STUB_AGENT", &self.agent)
        .env("PROBATOR_VA_STUB_MODEL", &self.model)
        .env("PROBATOR_VA_STUB_SESSION", &self.session)
        .env(
            "PROBATOR_PI_BIN",
            self.pi_bin.clone().unwrap_or_else(pi_stub),
        )
        .env("PYTHONUNBUFFERED", "1")
        .current_dir(&self.run_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        if let Some(dir) = &self.pi_agent_dir {
            cmd.env("PI_CODING_AGENT_DIR", dir);
        }
        if let Some(path) = &self.path_override {
            cmd.env("PATH", path);
        }
        let output = cmd.output().unwrap();
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
    // The project config must carry the declared audit server - and silence
    // every server the user's global agent config would otherwise leak in.
    let pi_dir = fixture.stub_dir.join("pi-agent");
    std::fs::create_dir_all(&pi_dir).unwrap();
    std::fs::write(
        pi_dir.join("mcp.json"),
        json!({"mcpServers": {"foreign-corp": {"command": "evil"}}}).to_string(),
    )
    .unwrap();
    fixture.pi_agent_dir = Some(pi_dir);
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    let mcp: Value = serde_json::from_str(
        &std::fs::read_to_string(fixture.run_dir.join(".pi/mcp.json")).unwrap(),
    )
    .unwrap();
    let servers = &mcp["mcpServers"];
    assert_eq!(servers["foreign-corp"]["enabled"], false);
    assert!(
        servers["probator-audit"]["command"].is_string(),
        "declared audit server must keep its real definition: {servers}"
    );
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

/// An uncertain resume open may already have reached the agent: no fresh
/// open follows it, so the preserved conversation stays resumable and paid
/// review progress is never discarded by a blind restart.
#[test]
fn an_uncertain_resume_open_never_falls_through_to_fresh() {
    let fixture = Fixture::new("uncertain-resume");
    std::fs::write(
        fixture.run_dir.join("audit-session.json"),
        json!({"session_id":"stale","session_ids":["stale"]}).to_string(),
    )
    .unwrap();
    let (ok, result) = fixture.invoke();
    assert!(!ok, "uncertain resume must refuse, not restart: {result}");
    let opens = fixture.records("session-open.jsonl");
    assert_eq!(opens.len(), 1, "uncertain resume must not open fresh");
    assert_eq!(opens[0]["resume"], "stale");
    assert!(fixture.records("session-prompt.jsonl").is_empty());
}

/// A sealed report outranks a lost `session/prompt` response: the submit tool
/// writes report.json before the turn settles, so an uncertain transport
/// failure after that point carries the settled verdict, not a refusal. The
/// gate still verifies the receipt's credential before honoring it.
#[test]
fn a_sealed_report_survives_a_lost_prompt_response() {
    let fixture = Fixture::new("sealed-drop");
    std::fs::write(
        fixture.run_dir.join("report.json"),
        json!({"verdict":"pass","gate_status":"pending"}).to_string(),
    )
    .unwrap();
    let (ok, result) = fixture.invoke();
    assert!(ok, "sealed report must outrank the lost response: {result}");
    assert_eq!(result["completed"], true);
    assert_eq!(result["stop_reason"], "report_sealed");
    assert_eq!(result["usage"]["input_tokens"], 9);
    assert_eq!(fixture.records("session-prompt.jsonl").len(), 1);
}

/// A permanent resume refusal that is not about the session being gone -
/// authorization, quota, anything else - must not fall through to a fresh
/// open: the preserved conversation stays resumable instead of restarting
/// paid work.
#[test]
fn a_permanent_non_stale_resume_error_never_falls_through_to_fresh() {
    let fixture = Fixture::new("permanent-resume");
    std::fs::write(
        fixture.run_dir.join("audit-session.json"),
        json!({"session_id":"kept","session_ids":["kept"]}).to_string(),
    )
    .unwrap();
    let (ok, result) = fixture.invoke();
    assert!(
        !ok,
        "permanent non-stale resume must refuse, not restart: {result}"
    );
    let opens = fixture.records("session-open.jsonl");
    assert_eq!(opens.len(), 1, "non-stale refusal must not open fresh");
    assert_eq!(opens[0]["resume"], "kept");
    assert!(fixture.records("session-prompt.jsonl").is_empty());
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

fn audit_safe_pi_agent(id: &str) -> Value {
    json!({
        "id": id,
        "clientName": "pi",
        "lane": "rpc",
        "command": {
            "program": "pi",
            "args": [
                "--mode", "rpc", "--approve",
                "--tools", "codemode,mcp__probator_audit__*",
                "--no-extensions",
                "-e", "builtin:mcp",
                "-e", "builtin:codemode",
                "-e", "builtin:tool-search",
                "--no-skills", "--no-prompt-templates", "--no-context-files"
            ]
        }
    })
}

fn checker_named_user_registry() -> Value {
    json!({
        "agents": {
            "pi-audit": audit_safe_pi_agent("pi-audit")
        },
        "profiles": {
            "audit-fast": {"agent": "pi-audit", "model": ""},
            "audit-deep": {"agent": "pi-audit", "model": "openai/gpt-6.1-sol"}
        },
        "bindings": {
            "synthetic-reviewer": {
                "profile": "audit-fast",
                "fallbacks": ["audit-deep"]
            }
        }
    })
}

/// Point the stub `va` at a profile the checker-named `pi-audit` binding can
/// serve, so a test that expects admission does not fail on profile custody.
fn admit_pi_binding(fixture: &mut Fixture) {
    fixture.profile = "audit-fast".into();
    fixture.agent = "pi-audit".into();
    fixture.model = String::new();
    fixture.session = "pi-default-session".into();
}

/// The operator's Agents choice wins over the packaged runtime: the audit
/// opens the checker-named binding through `va serve`, and VA may hand the
/// session to any profile in its fallback chain. The host must not walk that
/// chain itself, and the contract's harness/model must not leak into the
/// operator's profile.
#[test]
fn a_checker_named_binding_owns_harness_and_fallback_chain() {
    let mut fixture = Fixture::new("complete");
    fixture.write_user_registry(&checker_named_user_registry());
    fixture.profile = "audit-deep".into();
    fixture.agent = "pi-audit".into();
    fixture.model = "openai/gpt-6.1-sol".into();
    fixture.session = "pi-user-session".into();
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    assert_eq!(result["completed"], true);
    assert_eq!(result["profile"]["id"], "synthetic-reviewer");
    assert_eq!(
        result["served"],
        json!({"profile": "audit-deep", "agent": "pi-audit", "model": "openai/gpt-6.1-sol"})
    );
    let opens = fixture.records("session-open.jsonl");
    assert_eq!(opens.len(), 1, "{opens:?}");
    assert_eq!(opens[0]["binding"], "synthetic-reviewer");
    assert!(
        opens[0].get("profile").is_none(),
        "the binding, not a fixed profile, must be named"
    );
    assert_eq!(
        opens[0]["patch"]["instructions"],
        "Only inspect synthetic evidence."
    );
    assert_eq!(opens[0]["patch"]["mcpServers"][0]["name"], "probator-audit");
    assert!(
        opens[0]["patch"].get("model").is_none(),
        "the operator's model choice must not be overlaid by the contract"
    );
    assert!(opens[0]["patch"].get("agent").is_none());
    assert!(
        opens[0]["patch"].get("permission").is_none(),
        "ACP lanes do not advertise a permission selector; forcing one would refuse the open"
    );
    assert_eq!(opens[0]["patch"]["env"], json!({}));
    assert_eq!(opens[0]["patch"]["mechanisms"], Value::Null);
    assert_eq!(opens[0]["patch"]["skillReferences"], json!([]));
    assert_eq!(opens[0]["patch"]["mode"], Value::Null);
    let spawned = fixture.records("va-spawned.jsonl");
    assert_eq!(
        spawned[0]["virtual_agent_home"],
        fixture.user_home.to_string_lossy().as_ref()
    );
    assert!(
        !fixture.run_dir.join("va-home/registry.json").exists(),
        "a configured checker binding must not be replaced by a packaged document"
    );
    assert_eq!(
        serde_json::from_str::<Value>(
            &std::fs::read_to_string(fixture.run_dir.join("audit-session.json")).unwrap()
        )
        .unwrap()["session_id"],
        "pi-user-session"
    );
}

/// A checker-named binding may not substitute an arbitrary harness command:
/// a serve/ACP agent whose native tool set is not the audit allowlist is
/// refused before `va` starts.
#[test]
fn a_serve_binding_without_an_audit_safe_command_is_refused() {
    let mut fixture = Fixture::new("complete");
    fixture.write_user_registry(&json!({
        "agents": {
            "opencode-default": {"id": "opencode-default", "clientName": "opencode", "lane": "serve"}
        },
        "profiles": {
            "audit-serve": {"agent": "opencode-default", "model": "opencode/stub-free"}
        },
        "bindings": {
            "synthetic-reviewer": {"profile": "audit-serve"}
        }
    }));
    fixture.profile = "audit-serve".into();
    fixture.agent = "opencode-default".into();
    fixture.model = "opencode/stub-free".into();
    fixture.session = "opencode-stub-session".into();
    let (ok, result) = fixture.invoke();
    assert!(!ok, "{result}");
    assert_eq!(result["failure"]["code"], "audit_candidate_not_admitted");
    assert!(
        !fixture.spawned(),
        "an unsafe custom agent never reaches va"
    );
}

/// A checker-named binding may not point the audit at an arbitrary
/// executable that happens to be called `pi`: the path must canonicalize to
/// the gate's trusted installation.
#[test]
fn a_counterfeit_absolute_pi_program_is_refused() {
    let fixture = Fixture::new("complete");
    let root = fixture.contract_dir.parent().unwrap();
    let counterfeit = root.join("pi");
    std::fs::write(&counterfeit, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&counterfeit, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut registry = checker_named_user_registry();
    registry["agents"]["pi-audit"]["command"]["program"] = json!(counterfeit.to_string_lossy());
    fixture.write_user_registry(&registry);
    let (ok, result) = fixture.invoke();
    assert!(!ok, "{result}");
    assert_eq!(result["failure"]["code"], "audit_candidate_not_admitted");
    assert!(
        !fixture.spawned(),
        "a counterfeit executable never reaches va"
    );
}

/// An absent path in a trusted installation directory is harmless only when
/// it is the Pi name itself; a differently named future binary is refused.
#[test]
fn a_differently_named_path_in_a_trusted_directory_is_refused() {
    let fixture = Fixture::new("complete");
    let trusted_dir = pi_stub().canonicalize().unwrap();
    let candidate = trusted_dir.parent().unwrap().join("not-pi");
    let mut registry = checker_named_user_registry();
    registry["agents"]["pi-audit"]["command"]["program"] = json!(candidate.to_string_lossy());
    fixture.write_user_registry(&registry);
    let (ok, result) = fixture.invoke();
    assert!(!ok, "{result}");
    assert_eq!(result["failure"]["code"], "audit_candidate_not_admitted");
    assert!(!fixture.spawned());
}

/// A pinned symlink may point within its installation directory but may not
/// escape to an arbitrary executable.
#[test]
fn a_symlinked_pin_outside_its_directory_is_refused() {
    let mut fixture = Fixture::new("complete");
    let root = fixture.contract_dir.parent().unwrap();
    let evil = root.join("evil-pi");
    std::fs::write(&evil, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&evil, std::fs::Permissions::from_mode(0o755)).unwrap();
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let link = bin.join("pi");
    std::os::unix::fs::symlink(&evil, &link).unwrap();
    fixture.pi_bin = Some(link);
    fixture.write_user_registry(&checker_named_user_registry());
    let (ok, result) = fixture.invoke();
    assert!(!ok, "{result}");
    assert_eq!(result["failure"]["code"], "audit_candidate_not_admitted");
    assert!(!fixture.spawned(), "an escaped symlink never reaches va");
}

/// A custom pin is accepted only when its canonical file is still named
/// `pi`: the child resolves the bare name through the pin's directory, so a
/// differently named executable would leave that lookup unbound.
#[test]
fn a_pinned_runner_with_another_name_is_refused() {
    let mut fixture = Fixture::new("complete");
    let root = fixture.contract_dir.parent().unwrap();
    let other = root.join("reviewer");
    std::fs::write(&other, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755)).unwrap();
    fixture.pi_bin = Some(other);
    fixture.write_user_registry(&checker_named_user_registry());
    let (ok, result) = fixture.invoke();
    assert!(!ok, "{result}");
    assert_eq!(result["failure"]["code"], "audit_candidate_not_admitted");
    assert!(
        !fixture.spawned(),
        "a differently named pin never reaches va"
    );
}

/// A `pi` symlink may not resolve to a differently named target: the PATH
/// prefix would then contain a `pi` the validation never saw.
#[test]
fn a_pi_symlink_to_a_differently_named_target_is_refused() {
    let mut fixture = Fixture::new("complete");
    let root = fixture.contract_dir.parent().unwrap();
    let target = root.join("reviewer");
    std::fs::write(&target, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let link = bin.join("pi");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    fixture.pi_bin = Some(link);
    fixture.write_user_registry(&checker_named_user_registry());
    let (ok, result) = fixture.invoke();
    assert!(!ok, "{result}");
    assert_eq!(result["failure"]["code"], "audit_candidate_not_admitted");
    assert!(!fixture.spawned(), "an aliased pin never reaches va");
}

/// The object `program.resolve` form must hold every candidate to the same
/// trusted installation; one counterfeit path refuses the whole binding.
#[test]
fn a_counterfeit_pi_inside_a_resolve_list_is_refused() {
    let fixture = Fixture::new("complete");
    let root = fixture.contract_dir.parent().unwrap();
    let counterfeit = root.join("pi");
    std::fs::write(&counterfeit, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&counterfeit, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut registry = checker_named_user_registry();
    registry["agents"]["pi-audit"]["command"]["program"] = json!({
        "resolve": ["pi", counterfeit.to_string_lossy()]
    });
    fixture.write_user_registry(&registry);
    let (ok, result) = fixture.invoke();
    assert!(!ok, "{result}");
    assert_eq!(result["failure"]["code"], "audit_candidate_not_admitted");
    assert!(!fixture.spawned());
}

/// The same resolve form is admitted when it names the pinned installation.
#[test]
fn a_resolve_list_naming_the_pinned_pi_is_admitted() {
    let mut fixture = Fixture::new("complete");
    let trusted = pi_stub().canonicalize().unwrap();
    let mut registry = checker_named_user_registry();
    registry["agents"]["pi-audit"]["command"]["program"] = json!({
        "resolve": ["pi", trusted.to_string_lossy()]
    });
    fixture.write_user_registry(&registry);
    admit_pi_binding(&mut fixture);
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
}

/// A shadow `pi` earlier on PATH is not the pinned installation: validation
/// ignores PATH, and the `va` child receives the trusted directory first.
#[test]
fn a_path_shadowed_pi_does_not_replace_the_pinned_executable() {
    let mut fixture = Fixture::new("complete");
    let shadow = fixture.contract_dir.parent().unwrap().join("shadow-bin");
    std::fs::create_dir_all(&shadow).unwrap();
    let shadow_pi = shadow.join("pi");
    std::fs::write(&shadow_pi, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&shadow_pi, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut registry = checker_named_user_registry();
    registry["agents"]["pi-audit"]["command"]["program"] = json!("pi");
    fixture.write_user_registry(&registry);
    admit_pi_binding(&mut fixture);
    let inherited = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![shadow];
    paths.extend(std::env::split_paths(&inherited));
    fixture.path_override = Some(std::env::join_paths(paths).unwrap());
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    let pinned = pi_stub().canonicalize().unwrap();
    let spawned = fixture.records("va-spawned.jsonl");
    let path = spawned[0]["path"].as_str().expect("the stub records PATH");
    assert_eq!(
        std::env::split_paths(path).next().as_deref(),
        pinned.parent(),
        "the trusted Pi directory must be first on the child's PATH"
    );
}

/// Without a checker-named binding the packaged installation document still
/// owns the run-local `audit` binding, exactly as before this change.
#[test]
fn no_checker_binding_keeps_the_packaged_audit_binding() {
    let fixture = Fixture::new("complete");
    fixture.write_user_registry(&json!({
        "agents": {
            "pi-default": {"id": "pi-default", "clientName": "pi", "lane": "acp"}
        },
        "profiles": {
            "some-other-role": {"agent": "pi-default", "model": ""}
        },
        "bindings": {
            "some-other-role": {"profile": "some-other-role"}
        }
    }));
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    assert_eq!(result["served"]["profile"], "synthetic-reviewer");
    let opens = fixture.records("session-open.jsonl");
    assert_eq!(opens[0]["binding"], "audit");
    let spawned = fixture.records("va-spawned.jsonl");
    assert_eq!(
        spawned[0]["virtual_agent_home"],
        fixture.run_dir.join("va-home").to_string_lossy().as_ref()
    );
    let home: Value = serde_json::from_str(
        &std::fs::read_to_string(fixture.run_dir.join("va-home/registry.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(home["bindings"]["audit"]["profile"], "synthetic-reviewer");
}

/// A binding under the checker's name is an operator decision, not a hint: a
/// malformed one refuses instead of silently running the packaged profile.
#[test]
fn a_malformed_checker_binding_is_refused_not_silently_packaged() {
    let fixture = Fixture::new("complete");
    fixture.write_user_registry(&json!({
        "agents": {},
        "profiles": {},
        "bindings": {
            "synthetic-reviewer": {"profile": "missing-profile"}
        }
    }));
    let (ok, result) = fixture.invoke();
    assert!(!ok, "{result}");
    assert_eq!(result["failure"]["code"], "audit_candidate_not_admitted");
    assert!(!fixture.spawned());
}

/// A checker-named profile chooses the harness and model, never a stronger
/// tool surface. A permission, environment, cwd, mechanism, MCP server,
/// skill or mode the gate did not project refuses before `va` starts.
#[test]
fn a_checker_binding_cannot_add_a_capability_the_gate_did_not_project() {
    for (field, value) in [
        ("permission", json!("full")),
        ("env", json!({"LD_PRELOAD": "/tmp/unsafe.so"})),
        ("cwd", json!("/tmp")),
        ("mechanisms", json!({"shell": true})),
        ("mcpServers", json!([{"name": "shell"}])),
        ("skillReferences", json!(["shell"])),
        ("mode", json!("auto-approve")),
    ] {
        let fixture = Fixture::new("complete");
        let mut registry = checker_named_user_registry();
        registry["profiles"]["audit-fast"][field] = value;
        fixture.write_user_registry(&registry);
        let (ok, result) = fixture.invoke();
        assert!(!ok, "{field} must refuse: {result}");
        assert_eq!(result["failure"]["code"], "audit_candidate_not_admitted");
        assert!(!fixture.spawned(), "{field} must refuse before spawning va");
    }
}

/// A fallback can serve the session too, so its capability surface is checked
/// with the primary's.
#[test]
fn an_unsafe_fallback_candidate_refuses_the_binding() {
    let fixture = Fixture::new("complete");
    let mut registry = checker_named_user_registry();
    registry["profiles"]["audit-deep"]["permission"] = json!("full");
    fixture.write_user_registry(&registry);
    let (ok, result) = fixture.invoke();
    assert!(!ok, "{result}");
    assert_eq!(result["failure"]["code"], "audit_candidate_not_admitted");
    assert!(!fixture.spawned());
}

/// No `va` at all keeps the pre-existing fail-closed behaviour: the host
/// refuses with `audit_va_unavailable` rather than inventing a session.
#[test]
fn a_missing_va_binary_keeps_the_existing_refusal() {
    let mut fixture = Fixture::new("complete");
    fixture.va_missing = true;
    let (ok, result) = fixture.invoke();
    assert!(!ok, "{result}");
    assert_eq!(result["completed"], false);
    assert_eq!(result["failure"]["code"], "audit_va_unavailable");
    assert!(fixture.records("session-prompt.jsonl").is_empty());
}

/// Agents may leave an audit profile's model to the agent's client default
/// (Agent Management writes `model: ""`). The checker binding admits that
/// choice instead of forcing the contract's packaged model onto it.
#[test]
fn a_client_default_model_is_admitted_for_a_checker_binding() {
    let mut fixture = Fixture::new("complete");
    fixture.write_user_registry(&checker_named_user_registry());
    fixture.profile = "audit-fast".into();
    fixture.agent = "pi-audit".into();
    fixture.model = String::new();
    fixture.session = "pi-default-session".into();
    let (ok, result) = fixture.invoke();
    assert!(ok, "{result}");
    assert_eq!(result["profile"]["id"], "synthetic-reviewer");
    assert_eq!(result["served"]["profile"], "audit-fast");
    assert_eq!(result["served"]["agent"], "pi-audit");
    assert_eq!(result["served"]["model"], "");
    assert_eq!(
        fixture.records("session-open.jsonl")[0]["binding"],
        "synthetic-reviewer"
    );
}

/// The four publication checkers resolve their own operator binding by the
/// contract name, not a shared `audit` key.
#[test]
fn each_auditor_resolves_its_own_checker_named_binding() {
    for id in [
        "clean-auditor",
        "money-saver",
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
        let mut registry = checker_named_user_registry();
        let binding = registry["bindings"]["synthetic-reviewer"].clone();
        registry["bindings"]
            .as_object_mut()
            .unwrap()
            .remove("synthetic-reviewer");
        registry["bindings"][id] = binding;
        fixture.write_user_registry(&registry);
        fixture.profile = "audit-fast".into();
        fixture.agent = "pi-audit".into();
        fixture.model = String::new();
        fixture.session = format!("{id}-session");
        let (ok, result) = fixture.invoke();
        assert!(ok, "{id}: {result}");
        assert_eq!(result["profile"]["id"], id);
        assert_eq!(fixture.records("session-open.jsonl")[0]["binding"], id);
        assert_eq!(result["served"]["profile"], "audit-fast");
    }
}
