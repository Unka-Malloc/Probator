//! Audit host. The checker declares its agents, binding and secret recipes
//! in an AwP registry document (`registry.json`, materialized by the
//! installer from `tools/registry.json`). This host fires as
//! `probator-agent --contract <contract.json> --run <dir>` and
//! derives the whole review surface from the installation itself: the
//! checker's role, its one MCP tool server, the run's scope and any resume
//! binding all live in the two directories it is pointed at.
//!
//! Provider/agent failover is Virtual-Agent's job: this host speaks
//! a4aa.v1 to `va serve` with `session/open` `{ binding: "audit", patch }`
//! and admits the serving result. It does not walk the binding's candidate
//! chain itself. Same-agent model fallbacks stay on the serving profile
//! for VA/AwP. This host contributes the gate's admission rules, the
//! fail-closed permission handler and the settled outcome the gate persists.
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use a4aa::proto::acp::{PermissionDecision, PermissionPrompt};
use a4aa::{
    AgentEvent, CallFailure, JsonRpcPeer, PermissionHandler, RpcDelegate, RpcErrorObject,
    TokenUsage,
};
use serde_json::{Map, Value, json};

/// Everything the run needs, derived from the two paths the gate hands over:
/// the installed contract directory and this run's working directory.
struct Request {
    /// <contract dir>/registry.json — the AwP document declaring the audit
    /// agent and the `audit` binding.
    document: PathBuf,
    prompt: String,
    /// The projected role: identity, policy, model and the review's one MCP
    /// tool server.
    role: awp::Profile,
    resume: Option<String>,
    session_file: PathBuf,
    run_dir: PathBuf,
}

fn read_json(path: &Path) -> Result<Value, a4aa::AdapterError> {
    let raw =
        std::fs::read_to_string(path).map_err(|_| failure("audit_input_unreadable", "run/load"))?;
    serde_json::from_str(&raw).map_err(|_| failure("audit_input_invalid", "run/load"))
}

/// The review date stamped into a fresh conversation: UTC civil date, the
/// same convention `documents::today` writes into request documents.
fn review_date() -> String {
    jiff::Zoned::now()
        .with_time_zone(jiff::tz::TimeZone::UTC)
        .date()
        .to_string()
}

/// Derive the request from `--contract <path> --run <dir>`: the checker's
/// payload carries contract, registry, policy and installation; the run
/// directory carries scope, session and verdict state.
fn request_from(args: &[String]) -> Result<Request, a4aa::AdapterError> {
    let flag = |name: &str| -> Result<PathBuf, a4aa::AdapterError> {
        args.windows(2)
            .find(|pair| pair[0] == name)
            .map(|pair| PathBuf::from(&pair[1]))
            .ok_or_else(|| failure("audit_args_invalid", "run/args"))
    };
    let contract_path = flag("--contract")?;
    let contract_dir = if contract_path.is_dir() {
        contract_path.clone()
    } else {
        contract_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    };
    let run_dir = flag("--run")?;
    let contract = read_json(&contract_dir.join("contract.json"))?;
    let installation = read_json(&contract_dir.join("installation.json"))?;
    let scope = read_json(&run_dir.join("scope.json"))?;
    let runtime = &scope["runtime"];
    let session_file = run_dir.join("audit-session.json");
    let resume = read_json(&session_file)
        .ok()
        .and_then(|saved| saved["session_id"].as_str().map(str::to_string));
    let has_report = run_dir.join("report.json").exists();
    let full = scope["mode"].as_str() == Some("full-service");
    let task = if resume.is_some() && has_report {
        "The final review verdict has already been submitted and is preserved. \
         Finish this resumed conversation without submitting another verdict or \
         repeating the review. The publication gate will validate the stored verdict."
            .to_string()
    } else if resume.is_some() {
        "Continue this same review from its preserved conversation and draft. \
         Correct the outstanding report fields; reuse evidence and do not restart the audit."
            .to_string()
    } else if full {
        contract["task_full_service"]
            .as_str()
            .unwrap_or_else(|| contract["task"].as_str().unwrap_or(""))
            .to_string()
    } else {
        contract["task"].as_str().unwrap_or("").to_string()
    };
    // The review date is fresh-conversation context; a resumed session
    // already carries it, so only the bare directive goes again.
    let prompt = if resume.is_some() {
        task
    } else {
        format!("Review date (UTC): {}\n\n{}", review_date(), task)
    };
    // The checker's one tool surface is the review server itself, fired
    // per run so it learns its contract and run directory from the gate.
    let review = installation["review"].as_str().unwrap_or("probator");
    let tool_server = json!({
        "type": "stdio",
        "name": "probator-audit",
        "command": review,
        "args": [
            "serve",
            "--contract",
            contract_dir.join("contract.json").to_string_lossy(),
            "--run",
            run_dir.to_string_lossy(),
        ],
        "env": [],
    });
    let policy = std::fs::read_to_string(contract_dir.join("policy.md"))
        .map_err(|_| failure("audit_input_unreadable", "run/load"))?;
    let role: awp::Profile = serde_json::from_value(json!({
        "id": contract["name"],
        "name": contract["title"],
        "revision": installation["synced"]["tag"].as_str(),
        "agent": runtime["harness"],
        "model": runtime["model"],
        "models": runtime.get("models").cloned().unwrap_or_else(|| json!([])),
        "windows": runtime.get("windows").cloned().unwrap_or_else(|| json!([])),
        "retry": runtime.get("retry").cloned().unwrap_or(Value::Null),
        "effort": runtime.get("effort").cloned().unwrap_or(Value::Null),
        "permission": "read-only",
        "instructions": policy,
        "mcpServers": [tool_server],
        "extensions": {"provider": runtime["provider"]},
    }))
    .map_err(|_| failure("audit_role_invalid", "profile/build"))?;
    Ok(Request {
        document: contract_dir.join("registry.json"),
        prompt,
        role,
        resume,
        session_file,
        run_dir,
    })
}

/// The audit is read-only: the only calls a permission prompt may approve
/// are the checker's own `probator-audit` evidence and verdict tools — the
/// tool surface the role itself declares. Every other prompt is cancelled,
/// never approved on the operator's behalf.
struct AuditPermissions;

#[async_trait::async_trait]
impl PermissionHandler for AuditPermissions {
    async fn decide(&self, prompt: PermissionPrompt) -> PermissionDecision {
        let audit_tool = prompt.title.contains("probator-audit")
            || prompt.raw.to_string().contains("probator-audit");
        if !audit_tool {
            return PermissionDecision::Cancelled;
        }
        prompt
            .options
            .iter()
            .find(|(_, _, kind)| kind.starts_with("allow"))
            .map(|(id, _, _)| PermissionDecision::Selected(id.clone()))
            .unwrap_or(PermissionDecision::Cancelled)
    }
}

/// `session_id` stays the resume pointer; `session_ids` accumulates every
/// conversation the run has opened so the gate can conceal them all once the
/// audit completes.
fn save_session(path: &Path, id: &str) -> io::Result<()> {
    let mut ids: Vec<String> = std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|saved| saved["session_ids"].as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|saved| saved.as_str().map(str::to_string))
        .collect();
    if !ids.iter().any(|saved| saved == id) {
        ids.push(id.to_string());
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    writeln!(file, "{}", json!({"session_id":id,"session_ids":ids}))
}

/// `^[A-Za-z0-9._-]+$` — a provider or agent label; the provider-relative
/// model check relies on a provider never containing '/'.
fn is_label(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// `^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,79}$` — an inert model label, the same
/// shape the review contract enforces.
fn is_model_label(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && value.chars().count() <= 80
        && chars
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '+' | '-'))
}

/// Locate `va`. Tests override with `PROBATOR_VA_BIN`; deployments may use
/// `VA_BIN`. PATH lookup is the production default.
fn va_binary() -> PathBuf {
    std::env::var_os("PROBATOR_VA_BIN")
        .or_else(|| std::env::var_os("VA_BIN"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("va"))
}

fn binding_profile_ids(binding: &Value) -> (Option<String>, Vec<String>) {
    let primary = binding["profile"].as_str().map(str::to_string);
    let fallbacks = binding["fallbacks"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .as_str()
                .map(str::to_string)
                .or_else(|| entry["profile"].as_str().map(str::to_string))
        })
        .collect();
    (primary, fallbacks)
}

fn overlay_primary(document: &mut Value, role: &awp::Profile) -> Result<(), a4aa::AdapterError> {
    let profiles = document
        .get_mut("profiles")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| failure("audit_document_invalid", "registry/load"))?;
    let entry = profiles
        .get_mut(&role.id)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| failure("audit_candidate_not_admitted", "registry/resolve"))?;
    entry.insert("name".into(), json!(role.name));
    if let Some(revision) = &role.revision {
        entry.insert("revision".into(), json!(revision));
    }
    // The declared runtime is authoritative for the serving configuration:
    // a field it does not declare must be removed, never left over from the
    // registry profile. A leftover value written for a different harness
    // (an effort tier another agent does not offer, a model outside the
    // runtime provider's namespace) fails admission on a candidate that was
    // meant to serve.
    let mut overlay = |key: &str, value: Option<Value>| {
        if let Some(value) = value {
            entry.insert(key.into(), value);
        } else {
            entry.remove(key);
        }
    };
    overlay("model", role.model.as_ref().map(|model| json!(model)));
    overlay(
        "models",
        (!role.models.is_empty()).then(|| json!(role.models)),
    );
    overlay(
        "windows",
        (!role.windows.is_empty())
            .then(|| serde_json::to_value(&role.windows).ok())
            .flatten(),
    );
    overlay(
        "retry",
        role.retry
            .as_ref()
            .and_then(|retry| serde_json::to_value(retry).ok()),
    );
    overlay("effort", role.effort.as_ref().map(|effort| json!(effort)));
    Ok(())
}

fn write_pi_mcp(run_dir: &Path, servers: &[Value]) -> std::io::Result<()> {
    let pi_dir = run_dir.join(".pi");
    std::fs::create_dir_all(&pi_dir)?;
    let mut mcp_servers_map = Map::new();
    for server in servers {
        if let Some(name) = server["name"].as_str() {
            let mut spec = Map::new();
            if let Some(cmd) = server["command"].as_str() {
                spec.insert("command".to_string(), json!(cmd));
            }
            if let Some(args) = server["args"].as_array() {
                spec.insert("args".to_string(), json!(args));
            }
            if let Some(env) = server["env"].as_object() {
                spec.insert("env".to_string(), json!(env));
            }
            mcp_servers_map.insert(name.to_string(), Value::Object(spec));
        }
    }
    // A project entry without command/url/type overrides the same-named
    // global server: silence every server in the user's agent mcp.json so
    // nothing outside the declared audit surface is discoverable in the
    // session. A declared audit server keeps its real definition.
    let agent_dir = std::env::var_os("PI_CODING_AGENT_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".pi").join("agent"))
        });
    if let Some(dir) = agent_dir
        && let Ok(raw) = std::fs::read_to_string(dir.join("mcp.json"))
        && let Ok(doc) = serde_json::from_str::<Value>(&raw)
        && let Some(global) = doc["mcpServers"].as_object()
    {
        for name in global.keys() {
            mcp_servers_map
                .entry(name.clone())
                .or_insert_with(|| json!({ "enabled": false }));
        }
    }
    std::fs::write(
        pi_dir.join("mcp.json"),
        serde_json::to_string_pretty(&json!({ "mcpServers": mcp_servers_map })).unwrap_or_default(),
    )
}

fn lane_admitted(document: &Value, agent: &str) -> bool {
    let entry = &document["agents"][agent];
    std::iter::once(entry["lane"].as_str())
        .chain(
            entry["alternates"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|alternate| alternate["lane"].as_str()),
        )
        .flatten()
        .any(|lane| matches!(lane, "acp" | "serve" | "rpc"))
}

fn serving_model(session_state: &Value, declared: &str) -> String {
    session_state
        .pointer("/models/currentModelId")
        .or_else(|| session_state.pointer("/models/current_model_id"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            session_state["configOptions"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|option| option["id"].as_str() == Some("model"))
                .and_then(|option| option["currentValue"].as_str().map(str::to_string))
        })
        .filter(|model| !model.is_empty())
        .unwrap_or_else(|| declared.to_string())
}

fn usage_value(usage: &TokenUsage) -> Value {
    json!({
        "input_tokens": usage.input.unwrap_or(0),
        "output_tokens": usage.output.unwrap_or(0),
        "cache_read_tokens": usage.cached_input.unwrap_or(0),
        "cache_write_tokens": usage.cached_write.unwrap_or(0),
    })
}

fn capture_raw_usage(raw: &Value) -> Option<Value> {
    let usage = raw
        .pointer("/params/message/usage")
        .or_else(|| raw.pointer("/params/usage"))
        .or_else(|| raw.pointer("/data/message/usage"))
        .or_else(|| raw.pointer("/data/usage"))?;
    let input = usage["input"]
        .as_u64()
        .or_else(|| usage["input_tokens"].as_u64())?;
    let output = usage["output"]
        .as_u64()
        .or_else(|| usage["output_tokens"].as_u64())?;
    Some(json!({
        "input_tokens": input,
        "output_tokens": output,
        "cache_read_tokens": usage["cacheRead"].as_u64()
            .or_else(|| usage["cache_read_tokens"].as_u64())
            .unwrap_or(0),
        "cache_write_tokens": usage["cacheWrite"].as_u64()
            .or_else(|| usage["cache_write_tokens"].as_u64())
            .unwrap_or(0),
    }))
}

fn permission_prompt(params: &Value) -> PermissionPrompt {
    let options = params["options"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|option| {
            if let Some(fields) = option.as_array() {
                Some((
                    fields.first()?.as_str()?.to_string(),
                    fields.get(1)?.as_str()?.to_string(),
                    fields.get(2)?.as_str()?.to_string(),
                ))
            } else {
                Some((
                    option["optionId"]
                        .as_str()
                        .or_else(|| option["option_id"].as_str())?
                        .to_string(),
                    option["name"].as_str().unwrap_or("").to_string(),
                    option["kind"].as_str().unwrap_or("").to_string(),
                ))
            }
        })
        .collect();
    let content_texts = params["contentTexts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    PermissionPrompt {
        session_id: params["sessionId"].as_str().unwrap_or("").to_string(),
        tool_call_id: params["toolCallId"].as_str().unwrap_or("").to_string(),
        title: params["title"].as_str().unwrap_or("").to_string(),
        kind: params["kind"].as_str().map(str::to_string),
        content_texts,
        options,
        raw: params.get("raw").cloned().unwrap_or(Value::Null),
    }
}

/// Relays `va serve` events to the operator and records usage. Permission
/// prompts use the same fail-closed audit tool rule as the previous host.
struct HostDelegate {
    usage: Arc<std::sync::Mutex<Option<Value>>>,
}

#[async_trait::async_trait]
impl RpcDelegate for HostDelegate {
    async fn on_request(&self, method: &str, params: Value) -> Result<Value, RpcErrorObject> {
        if method != "permission/request" {
            return Err(RpcErrorObject::method_not_found(method));
        }
        match AuditPermissions.decide(permission_prompt(&params)).await {
            PermissionDecision::Selected(option) => Ok(json!({"selected": option})),
            PermissionDecision::Cancelled => Ok(json!({"cancelled": true})),
        }
    }

    async fn on_notification(&self, method: &str, params: Value) {
        if method != "session/event" {
            return;
        }
        let event = params.get("event").cloned().unwrap_or(Value::Null);
        match serde_json::from_value::<AgentEvent>(event.clone()) {
            Ok(AgentEvent::MessageChunk { text }) => eprint!("{text}"),
            Ok(AgentEvent::Usage { usage, .. }) => {
                *self.usage.lock().unwrap() = Some(usage_value(&usage));
            }
            Ok(AgentEvent::Raw { raw }) => {
                if let Some(usage) = capture_raw_usage(&raw) {
                    *self.usage.lock().unwrap() = Some(usage);
                }
            }
            _ => {
                if let Some(usage) = capture_raw_usage(&event) {
                    *self.usage.lock().unwrap() = Some(usage);
                }
            }
        }
    }
}

fn remote_error(stage: &'static str, error: RpcErrorObject) -> a4aa::AdapterError {
    let retryable = error
        .data
        .as_ref()
        .and_then(|data| data["retryable"].as_bool())
        .unwrap_or(false);
    let uncertain = error
        .data
        .as_ref()
        .and_then(|data| data["uncertainEffect"].as_bool())
        .unwrap_or(false);
    let code = if uncertain {
        "audit_va_recovery_required"
    } else if retryable {
        "audit_va_retryable"
    } else {
        "audit_va_call_failed"
    };
    let mut failure = if uncertain {
        a4aa::AdapterError::uncertain(code, stage)
    } else if retryable {
        a4aa::AdapterError::retryable(code, stage)
    } else {
        a4aa::AdapterError::permanent(code, stage)
    };
    failure.detail = Some(
        json!({
            "remoteCode": error.data.as_ref().and_then(|data| data.get("code").cloned()),
            "remoteStage": error.data.as_ref().and_then(|data| data.get("stage").cloned()),
            "attempts": error.data.as_ref().and_then(|data| data.get("attempts").cloned()),
            "message": error.message,
        })
        .to_string(),
    );
    failure
}

fn call_error(stage: &'static str, failure: CallFailure) -> a4aa::AdapterError {
    match failure {
        CallFailure::Remote(error) => remote_error(stage, error),
        CallFailure::Transport(_) => a4aa::AdapterError::uncertain("audit_va_transport", stage),
    }
}

struct Opened {
    sidecar_id: String,
    native_id: String,
    served: Value,
}

/// Whether a resume refusal proves the stored session is gone: the adapter's
/// own capability refusal, or a remote code that names the session as stale,
/// unsupported or unknown. Any other permanent error keeps the preserved
/// conversation for the next run rather than restarting paid work.
fn is_stale_resume(error: &a4aa::AdapterError) -> bool {
    if error.retryable || error.uncertain_effect {
        return false;
    }
    if error.code == "agent_session_resume_unsupported" {
        return true;
    }
    let remote = error
        .detail
        .as_deref()
        .and_then(|detail| serde_json::from_str::<Value>(detail).ok())
        .and_then(|detail| detail["remoteCode"].as_str().map(str::to_string))
        .unwrap_or_default();
    let remote = remote.as_str();
    remote.contains("resume_unsupported")
        || remote.contains("session_not_found")
        || remote.contains("unknown_session")
        || remote.contains("stale")
}

async fn open_once(peer: &JsonRpcPeer, params: Value) -> Result<Value, a4aa::AdapterError> {
    peer.call("session/open", params)
        .await
        .map_err(|error| call_error("session/open", error))
}

fn opened_from(
    result: &Value,
    document: &Value,
    role: &awp::Profile,
    admitted: &[String],
    primary: &str,
) -> Result<Opened, a4aa::AdapterError> {
    let sidecar_id = result["sessionId"].as_str().unwrap_or("").to_string();
    let native_id = result["nativeSessionId"]
        .as_str()
        .filter(|id| !id.is_empty())
        .unwrap_or(sidecar_id.as_str())
        .to_string();
    if sidecar_id.is_empty() || native_id.is_empty() {
        return Err(failure("audit_session_id_missing", "audit/open"));
    }
    let served_profile = result["custody"]["profile"]
        .as_str()
        .unwrap_or("")
        .to_string();
    if served_profile.is_empty() || !admitted.iter().any(|id| id == &served_profile) {
        return Err(failure("audit_served_not_admitted", "audit/open"));
    }
    let profile = &document["profiles"][&served_profile];
    let agent = profile["agent"].as_str().unwrap_or("");
    if !is_label(agent) || !lane_admitted(document, agent) {
        return Err(failure("audit_served_not_admitted", "audit/open"));
    }
    let declared_model = profile["model"].as_str().unwrap_or("");
    let model = serving_model(&result["sessionState"], declared_model);
    let provider = role
        .extensions
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("");
    let prefix = format!("{provider}/");
    let primary_served = served_profile == primary;
    if !is_model_label(&model) || (primary_served && !model.starts_with(&prefix)) {
        return Err(failure("audit_served_not_admitted", "audit/open"));
    }
    Ok(Opened {
        sidecar_id,
        native_id,
        served: json!({
            "profile": served_profile,
            "agent": agent,
            "model": model,
        }),
    })
}

async fn run(request: Request) -> a4aa::Result<Value> {
    let role = &request.role;
    // AwP models general virtual agents. This publication gate admits only
    // audit roles: executable, environment and tool surface stay gate-owned —
    // the single MCP server the role carries is the one the engine projected.
    // The agent itself is whatever the binding declared.
    let provider = role
        .extensions
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !is_label(role.agent.as_str())
        || role.permission.as_deref() != Some("read-only")
        || !is_label(provider)
        || !role.env.is_empty()
        || role.cwd.is_some()
        || role.mechanisms.is_some()
        || !role
            .mcp_servers
            .iter()
            .all(|server| server["name"] == "probator-audit")
    {
        return Err(failure("audit_role_not_admitted", "profile/resolve"));
    }
    // The role's model chain — primary, same-agent fallbacks and window
    // heads — stays inside the declared provider's namespace. Probator
    // overlays this onto the primary profile for VA; it does not step it.
    let prefix = format!("{provider}/");
    let chain_models = std::iter::once(role.model.as_deref().unwrap_or(""))
        .chain(role.models.iter().map(String::as_str))
        .chain(role.windows.iter().flat_map(|window| {
            window
                .model
                .iter()
                .chain(window.models.iter())
                .map(String::as_str)
        }))
        .collect::<Vec<_>>();
    if chain_models
        .iter()
        .any(|model| !is_model_label(model) || !model.starts_with(&prefix))
    {
        return Err(failure("audit_role_model_mismatch", "profile/resolve"));
    }
    if role
        .instructions
        .as_deref()
        .is_none_or(|text| text.trim().is_empty())
    {
        return Err(failure(
            "audit_role_instructions_missing",
            "profile/resolve",
        ));
    }
    let raw = std::fs::read_to_string(&request.document)
        .map_err(|_| failure("audit_document_unreadable", "registry/load"))?;
    let mut document: Value = serde_json::from_str(&raw)
        .map_err(|_| failure("audit_document_invalid", "registry/load"))?;
    let (primary, fallbacks) = binding_profile_ids(&document["bindings"]["audit"]);
    let Some(primary) = primary else {
        return Err(failure("audit_candidate_not_admitted", "registry/resolve"));
    };
    if primary != role.id {
        return Err(failure("audit_candidate_not_admitted", "registry/resolve"));
    }
    if document["profiles"][&primary]["agent"].as_str() != Some(role.agent.as_str()) {
        return Err(failure("audit_candidate_not_admitted", "registry/resolve"));
    }
    let mut admitted = vec![primary.clone()];
    admitted.extend(fallbacks);
    overlay_primary(&mut document, role)?;
    let va_home = request.run_dir.join("va-home");
    std::fs::create_dir_all(&va_home)
        .map_err(|_| failure("audit_va_home_unwritable", "registry/load"))?;
    std::fs::write(
        va_home.join("registry.json"),
        serde_json::to_string_pretty(&document).unwrap_or_default(),
    )
    .map_err(|_| failure("audit_va_home_unwritable", "registry/load"))?;
    // For RPC agents like pi that discover project-local MCP servers from
    // .pi/mcp.json, materialize the tool server definition into the run
    // directory. The session/open patch carries the same servers for VA. An
    // unwritable config must refuse here - a run that cannot arm its declared
    // evidence tools has no verdict worth recording.
    write_pi_mcp(&request.run_dir, &role.mcp_servers)
        .map_err(|_| failure("audit_mcp_config_unwritable", "run/start"))?;
    let identity = json!({"id":role.id,"revision":role.revision,
                          "principal":role.principal_id()});
    let captured_usage = Arc::new(std::sync::Mutex::new(None));
    let delegate = Arc::new(HostDelegate {
        usage: captured_usage.clone(),
    });
    let mut child = tokio::process::Command::new(va_binary())
        .arg("serve")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .env("VIRTUAL_AGENT_HOME", &va_home)
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| failure("audit_va_unavailable", "run/start"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| failure("audit_va_unavailable", "run/start"))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| failure("audit_va_unavailable", "run/start"))?;
    let peer = JsonRpcPeer::spawn(
        stdout,
        stdin,
        delegate,
        a4aa::observe::none(),
        a4aa::framing::DEFAULT_MAX_MESSAGE_BYTES,
    );
    let patch = json!({
        "name": role.name,
        "instructions": role.instructions,
        "mcpServers": role.mcp_servers,
    });
    let open_params = |resume: Option<&str>| {
        let mut params = json!({
            "binding": "audit",
            "cwd": request.run_dir,
            "patch": patch,
        });
        if let Some(resume) = resume {
            params["resume"] = json!(resume);
        }
        params
    };
    // One VA open owns binding failover. A stale resume is retried once
    // fresh — that is not a Probator walk of fallback profiles.
    let mut last_error = None;
    let mut opened = None;
    let attempts: Vec<Option<String>> = match &request.resume {
        Some(resume) => vec![Some(resume.clone()), None],
        None => vec![None],
    };
    for resume in attempts {
        match open_once(&peer, open_params(resume.as_deref())).await {
            Ok(result) => match opened_from(&result, &document, role, &admitted, &primary) {
                Ok(session) => {
                    opened = Some(session);
                    break;
                }
                Err(error) => {
                    if let Some(id) = result["sessionId"].as_str() {
                        let _ = peer.call("session/close", json!({"sessionId": id})).await;
                    }
                    last_error = Some(error);
                    break;
                }
            },
            Err(error) => {
                // Only an explicit stale/unsupported-session refusal may fall
                // through to a fresh open: a transport or uncertain outcome
                // may already have reached the agent, and a permanent error
                // that is not about the session must not orphan the preserved
                // conversation into a paid restart either.
                let definite_stale = is_stale_resume(&error);
                last_error = Some(error);
                if !definite_stale {
                    break;
                }
            }
        }
    }
    let Some(opened) = opened else {
        peer.close().await;
        let _ = child.wait().await;
        let retry_at = role.retry.as_ref().and_then(|policy| {
            policy
                .wakeup(&jiff::Zoned::now(), None)
                .map(|when| when.to_string())
        });
        return Err(last_error
            .map(|error| {
                let cause = error.detail.clone();
                error.with_detail(
                    json!({
                        "admitted": admitted,
                        "retryAt": retry_at,
                        "cause": cause
                    })
                    .to_string(),
                )
            })
            .unwrap_or_else(|| failure("audit_chain_empty", "registry/resolve")));
    };
    save_session(&request.session_file, &opened.native_id)
        .map_err(|_| failure("audit_session_save_failed", "audit/open"))?;
    let pending = peer
        .start_call(
            "session/prompt",
            json!({
                "sessionId": opened.sidecar_id,
                "text": request.prompt,
            }),
        )
        .map_err(|error| call_error("session/prompt", error))?;
    let wait = pending.wait();
    tokio::pin!(wait);
    let outcome = tokio::select! {
        result = &mut wait => result,
        _ = cancelled() => {
            let _ = peer
                .call("session/cancel", json!({"sessionId": opened.sidecar_id}))
                .await;
            wait.await
        }
    };
    let _ = peer
        .call("session/close", json!({"sessionId": opened.sidecar_id}))
        .await;
    peer.close().await;
    let _ = child.wait().await;
    match outcome {
        Ok(outcome) => {
            let stop_reason = outcome["stopReason"].as_str().unwrap_or("").to_string();
            let usage = outcome
                .get("usage")
                .cloned()
                .filter(|value| !value.is_null())
                .and_then(|value| serde_json::from_value::<TokenUsage>(value).ok())
                .map(|usage| usage_value(&usage))
                .or_else(|| captured_usage.lock().unwrap().clone());
            Ok(json!({"completed": stop_reason == "end_turn",
                      "stop_reason": stop_reason, "usage": usage,
                      "profile": identity, "served": opened.served}))
        }
        Err(error) => {
            // A sealed verdict on disk outranks a lost prompt response: the
            // submit tool writes report.json before the turn settles, so an
            // uncertain transport error after that point did not lose the
            // review. The gate verifies the receipt's credential itself;
            // reporting the settled report here keeps one flaky handshake
            // from discarding paid work.
            let error = call_error("session/prompt", error);
            if error.uncertain_effect && request.run_dir.join("report.json").exists() {
                let usage = captured_usage.lock().unwrap().clone();
                Ok(json!({"completed": true, "stop_reason": "report_sealed",
                          "usage": usage, "profile": identity, "served": opened.served}))
            } else {
                Err(error)
            }
        }
    }
}

fn failure(code: &'static str, stage: &'static str) -> a4aa::AdapterError {
    a4aa::AdapterError::permanent(code, stage)
}

async fn cancelled() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install termination handler");
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let request = match request_from(&args) {
        Ok(request) => request,
        Err(error) => {
            eprintln!(
                "invalid audit-agent request: {} {}",
                error.code,
                error.detail.as_deref().unwrap_or("")
            );
            std::process::exit(2);
        }
    };
    match run(request).await {
        Ok(result) => println!("{result}"),
        Err(error) => {
            println!(
                "{}",
                json!({"completed":false,"failure":{
                "code":error.code,"stage":error.stage,"retryable":error.retryable,
                "uncertain_effect":error.uncertain_effect,"detail":error.detail}})
            );
            std::process::exit(1);
        }
    }
}
