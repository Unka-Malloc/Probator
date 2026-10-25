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

#[path = "../checker_binding.rs"]
mod checker_binding;

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
/// tool surface the role itself declares. Approval reads the tool call's
/// identity fields, never prose a model can shape: a call that names the
/// audit namespace may proceed, a call that names anything else refuses,
/// and a call with no tool identity is cancelled.
struct AuditPermissions;

/// A tool identity names the audit surface when it is the canonical MCP
/// tool name (`mcp__probator_audit__…`) or the bare server name followed by
/// a separator rather than a longer identifier (`probator-audit: read`).
fn is_audit_name(name: &str) -> bool {
    name.starts_with("mcp__probator_audit__")
        || name == "probator-audit"
        || name
            .strip_prefix("probator-audit")
            .is_some_and(|rest| !rest.starts_with(|c: char| c.is_alphanumeric() || c == '-'))
}

/// The identities the call itself claims: the schema's `name` field, the
/// raw input's function name, and the title only when it is itself a tool
/// identifier - a prose title is display text, not an identity.
fn tool_identities(prompt: &PermissionPrompt) -> Vec<String> {
    let call = &prompt.raw["toolCall"];
    let mut names: Vec<String> = [
        call["name"].as_str(),
        call["rawInput"]["name"].as_str(),
        call["raw_input"]["name"].as_str(),
    ]
    .into_iter()
    .flatten()
    .map(str::to_string)
    .collect();
    if prompt.title.starts_with("mcp__") || is_audit_name(&prompt.title) {
        names.push(prompt.title.clone());
    }
    names
}

#[async_trait::async_trait]
impl PermissionHandler for AuditPermissions {
    async fn decide(&self, prompt: PermissionPrompt) -> PermissionDecision {
        let mut audit = false;
        for name in tool_identities(&prompt) {
            if is_audit_name(&name) {
                audit = true;
            } else {
                // A call that names any non-audit tool refuses outright.
                return PermissionDecision::Cancelled;
            }
        }
        if !audit {
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

/// The checker-named binding from the user's registry, when the operator has
/// adopted one in Agents. A binding that exists but carries no usable profile
/// is a configuration error: it must not silently fall back to the packaged
/// document, because that would run an Agent the operator did not choose.
fn user_binding(checker: &str) -> Option<(PathBuf, Value)> {
    let (home, document) = crate::checker_binding::load_registry()?;
    let binding = crate::checker_binding::checker_binding(&document, checker)?;
    if binding.is_null() {
        return None;
    }
    Some((home, document))
}

/// A checker-named binding may choose the harness, model and fallback chain,
/// but it may not add a capability the gate did not project. A profile is
/// admissible only when it is read-only and carries no extra environment,
/// working directory, mechanisms, MCP servers, skills or agent mode. The open
/// patch below forces the same fields; this check also refuses a fallback
/// that would violate them before `va` spends a turn on it.
///
/// `selector` is whether the open patch can project `permission` onto this
/// candidate's lane. Where it cannot, the profile must declare `read-only`
/// itself — a lane with no permission surface is not made read-only by
/// silence.
fn restricted_profile(profile: &Value, stamped_mcp: Option<&Value>, selector: bool) -> bool {
    if !profile.is_object() {
        return false;
    }
    let read_only = match profile.get("permission") {
        None | Some(Value::Null) => selector,
        Some(Value::String(permission)) => permission == "read-only",
        Some(_) => false,
    };
    let empty_map = |key: &str| match profile.get(key) {
        None | Some(Value::Null) => true,
        Some(Value::Object(map)) => map.is_empty(),
        Some(_) => false,
    };
    let absent = |key: &str| profile.get(key).is_none_or(Value::is_null);
    let empty_list = |key: &str| match profile.get(key) {
        None | Some(Value::Null) => true,
        Some(Value::Array(list)) => list.is_empty(),
        Some(_) => false,
    };
    read_only
        && empty_map("env")
        && absent("cwd")
        && absent("mechanisms")
        && absent("mode")
        && (empty_list("mcpServers")
            || stamped_mcp.is_some_and(|stamped| profile.get("mcpServers") == Some(stamped)))
        && empty_list("skillReferences")
}

/// The audit server list in the shape ACP and serve lanes accept: the role's
/// gate-built entries minus the stdio marker field the custody schema does
/// not know.
fn lane_mcp_list(role: &awp::Profile) -> Value {
    Value::Array(
        role.mcp_servers
            .iter()
            .map(|server| {
                let mut entry = server.clone();
                if let Some(object) = entry.as_object_mut() {
                    object.remove("type");
                }
                entry
            })
            .collect(),
    )
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
    //
    // A harness may also require a model id whose wire spelling the
    // provider/model label cannot carry: DSH ACP selects models as a JSON
    // pair (`["provider","model"]`). When the registry profile already
    // carries that native spelling, keep it — the declared runtime label and
    // the native value name the same model, and flattening the pair to a
    // slash label would hand the agent a value it does not advertise.
    let declared_model = role.model.as_deref().map(normalize_model_label);
    let native_model = entry
        .get("model")
        .and_then(Value::as_str)
        .map(normalize_model_label);
    if role.model.is_none() {
        entry.remove("model");
    } else if native_model != declared_model {
        entry.insert("model".into(), json!(role.model));
    }
    let mut overlay = |key: &str, value: Option<Value>| {
        if let Some(value) = value {
            entry.insert(key.into(), value);
        } else {
            entry.remove(key);
        }
    };
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

/// Whether every candidate a binding can serve runs on a lane that advertises
/// a per-session permission selector. RPC and ACP lanes reject a preset
/// outright (`agent_permission_unsupported`), so forcing one there would make
/// a healthy audit fail at `session/open`. The role itself still declares
/// read-only, and the host's permission handler cancels every non-audit
/// prompt; only lanes that can enforce the selector receive it.
fn permission_selector_supported(document: &Value, binding: &str) -> bool {
    let entry = &document["bindings"][binding];
    let mut profiles: Vec<&str> = Vec::new();
    if let Some(primary) = entry["profile"].as_str() {
        profiles.push(primary);
    }
    profiles.extend(
        entry["fallbacks"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str),
    );
    !profiles.is_empty()
        && profiles.iter().all(|profile| {
            let agent = document["profiles"][*profile]["agent"]
                .as_str()
                .unwrap_or("");
            document["agents"][agent]["lane"].as_str() == Some("serve")
        })
}

/// The fixed directories a Pi installation may live in. These are the roots
/// the gate trusts for both the executable and an operator binding's path
/// candidates; the ambient PATH is never one of them.
fn installation_roots() -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(home) = crate::checker_binding::user_home() {
        roots.push(home.join(".pi/agent/bin"));
        roots.push(home.join(".local/bin"));
    }
    roots.extend([
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
        PathBuf::from("/usr/bin"),
    ]);
    roots
}

fn under_root(path: &Path, roots: &[PathBuf]) -> bool {
    path.parent()
        .is_some_and(|parent| roots.iter().any(|root| root == parent))
}

/// The gate-owned Pi executable. `PROBATOR_PI_BIN` pins it explicitly; the
/// default search covers the known Pi installation locations and never the
/// ambient PATH, so a shadow `pi` cannot become the audit runner. The pinned
/// file must itself be named `pi`: the child resolves the bare name through
/// the PATH prefix below, so a differently named pin would leave that
/// resolution pointing at whatever `pi` happens to share its directory.
fn trusted_pi() -> Option<PathBuf> {
    let roots = installation_roots();
    if let Some(explicit) = std::env::var_os("PROBATOR_PI_BIN") {
        let path = Path::new(&explicit);
        // A relative pin would resolve against the run directory, which is
        // repository-controlled; the pin must be an absolute installation.
        if !path.is_absolute() || !is_pi_name(path) {
            return None;
        }
        let canonical = executable_file(path)?;
        // The pin may name a custom installation directory, but its symlink
        // target must stay in that same directory rather than escaping to an
        // arbitrary executable — and it must still be the `pi` the child's
        // PATH lookup will find.
        if canonical.parent() != path.parent() || !is_pi_name(&canonical) {
            return None;
        }
        return Some(canonical);
    }
    roots.iter().find_map(|root| {
        let canonical = executable_file(&root.join("pi"))?;
        (under_root(&canonical, &roots) && is_pi_name(&canonical)).then_some(canonical)
    })
}

fn is_pi_name(path: &Path) -> bool {
    path.file_name().and_then(|name| name.to_str()) == Some("pi")
}

/// Canonicalize a regular, executable file. A directory, a broken symlink or
/// a non-executable placeholder is not a usable audit runner.
fn executable_file(path: &Path) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(path).ok()?;
    let metadata = std::fs::metadata(&canonical).ok()?;
    if !metadata.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return None;
        }
    }
    Some(canonical)
}

/// The directories an operator binding may name as a Pi installation. The
/// pinned executable's own directory is included so a deployment that pins a
/// custom install root still works; `/tmp` and other arbitrary paths are not.
fn trusted_roots(trusted: &Path) -> Vec<PathBuf> {
    let mut roots = installation_roots();
    if let Some(parent) = trusted.parent()
        && !roots.iter().any(|root| root == parent)
    {
        roots.push(parent.to_path_buf());
    }
    roots
}

/// One declared program candidate. The bare `pi` name is resolved by the
/// gate-owned PATH prefix below. A path form must either canonicalize to the
/// trusted executable or be absent inside one of its installation roots; an
/// arbitrary existing path such as `/tmp/pi` is refused even when its basename
/// is right.
fn trusted_program_string(
    candidate: &str,
    trusted: &Path,
    home: Option<&Path>,
    roots: &[PathBuf],
) -> bool {
    if candidate == "pi" {
        return is_pi_name(trusted);
    }
    let expanded = home
        .map(|home| candidate.replace("{home}", home.to_string_lossy().as_ref()))
        .unwrap_or_else(|| candidate.to_string());
    let path = Path::new(&expanded);
    if !path.is_absolute() {
        return false;
    }
    if !is_pi_name(path) {
        return false;
    }
    if std::fs::symlink_metadata(path).is_ok() {
        return std::fs::canonicalize(path)
            .ok()
            .as_deref()
            .is_some_and(|path| path == trusted);
    }
    // An absent candidate cannot execute. It is harmless only in a known Pi
    // installation directory; a later substitution there stays bounded by
    // the same trusted root.
    roots
        .iter()
        .any(|root| path.parent() == Some(root.as_path()))
}

/// A checker-named agent's `command.program` may be the short `"pi"` name or
/// an AwP `{ "resolve": [...] }` object. Every candidate must be trusted; a
/// basename that merely looks like Pi is not enough.
fn trusted_program(
    program: &Value,
    trusted: &Path,
    home: Option<&Path>,
    roots: &[PathBuf],
) -> bool {
    match program {
        Value::String(candidate) => trusted_program_string(candidate, trusted, home, roots),
        Value::Object(map) => {
            if map.len() != 1 {
                return false;
            }
            let Some(resolve) = map.get("resolve").and_then(Value::as_array) else {
                return false;
            };
            !resolve.is_empty()
                && resolve.iter().all(|candidate| {
                    candidate.as_str().is_some_and(|candidate| {
                        trusted_program_string(candidate, trusted, home, roots)
                    })
                })
        }
        _ => false,
    }
}

/// The only harness shape a checker-named operator binding may run: the
/// packaged `pi` RPC command with the audit tool surface and no extension,
/// skill, prompt-template or context-file loading. Profile fields alone cannot
/// prove the agent's native tools are read-only; a custom command could expose
/// shell or extra tools, so it is refused before `va` starts.
fn audit_safe_agent(spec: &Value) -> bool {
    const SAFE_ARGS: [&str; 15] = [
        "--mode",
        "rpc",
        "--approve",
        "--tools",
        "codemode,mcp__probator_audit__*",
        "--no-extensions",
        "-e",
        "builtin:mcp",
        "-e",
        "builtin:codemode",
        "-e",
        "builtin:tool-search",
        "--no-skills",
        "--no-prompt-templates",
        "--no-context-files",
    ];
    let alternates_clear = spec["alternates"].is_null()
        || spec["alternates"]
            .as_array()
            .is_some_and(|alternates| alternates.is_empty());
    let env_clear = spec["command"]["env"].is_null()
        || spec["command"]["env"]
            .as_object()
            .is_some_and(|env| env.is_empty());
    if spec["lane"].as_str() != Some("rpc")
        || !alternates_clear
        || !env_clear
        || !spec["command"]["cwd"].is_null()
    {
        return false;
    }
    let Some(trusted) = trusted_pi() else {
        return false;
    };
    let home = crate::checker_binding::user_home();
    let roots = trusted_roots(&trusted);
    if !trusted_program(
        &spec["command"]["program"],
        &trusted,
        home.as_deref(),
        &roots,
    ) {
        return false;
    }
    let Some(args) = spec["command"]["args"].as_array() else {
        return false;
    };
    args.len() == SAFE_ARGS.len()
        && args
            .iter()
            .zip(SAFE_ARGS)
            .all(|(arg, expected)| arg.as_str() == Some(expected))
}

fn serving_model(session_state: &Value, declared: &str) -> String {
    let reported = session_state
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
        .filter(|model| !model.is_empty());
    normalize_model_label(&reported.unwrap_or_else(|| declared.to_string()))
}

/// A harness may report its model selector as a JSON pair
/// (`["provider","model"]`); fold that wire shape back into the
/// provider/model label the admission check and receipts use.
fn normalize_model_label(model: &str) -> String {
    let raw = model.trim();
    if let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(raw)
        && let Some(parts) = parts.iter().map(Value::as_str).collect::<Option<Vec<_>>>()
        && !parts.is_empty()
    {
        return parts.join("/");
    }
    raw.to_string()
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
    let remote_code = error.data.as_ref().and_then(|data| data["code"].as_str());
    // A provider quota refusal is a definitive environment answer: the
    // provider did not run the turn, so retrying cannot change it. It must
    // not be reported as an uncertain effect that invites another paid
    // attempt; the gate names it once and refuses.
    let quota = remote_code == Some("agent_quota_exhausted");
    let code = if quota {
        "audit_quota_exhausted"
    } else if uncertain {
        "audit_va_recovery_required"
    } else if retryable {
        "audit_va_retryable"
    } else {
        "audit_va_call_failed"
    };
    let mut failure = if quota {
        a4aa::AdapterError::permanent(code, stage)
    } else if uncertain {
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

struct Opened {
    sidecar_id: String,
    native_id: String,
    served: Value,
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
    binding: &str,
    enforce_provider: bool,
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
    // A profile that served an operator binding is still the reviewer's
    // sandbox: it may not declare a stronger permission, extra environment
    // or working directory, mechanisms, MCP servers or skills. The packaged
    // document's tool surface is the gate's own stamped server list — the
    // exact value this run wrote — so identical entries admit.
    let stamped = enforce_provider.then(|| lane_mcp_list(role));
    let agent = profile["agent"].as_str().unwrap_or("");
    // The open patch reaches only serve-lane candidates; every other lane
    // must carry its own read-only declaration.
    let selector = document["agents"][agent]["lane"].as_str() == Some("serve")
        && permission_selector_supported(document, binding);
    if !restricted_profile(profile, stamped.as_ref(), selector) {
        return Err(failure("audit_served_not_admitted", "audit/open"));
    }
    if !is_label(agent) || !lane_admitted(document, agent) {
        return Err(failure("audit_served_not_admitted", "audit/open"));
    }
    // A checker-named binding may only serve the audit-safe harness command;
    // the packaged installation document keeps its own fallback chain.
    if !enforce_provider && !audit_safe_agent(&document["agents"][agent]) {
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
    // The packaged document is bounded by the contract's runtime provider:
    // the primary candidate must serve a model in that provider's namespace.
    // A checker-named binding is owned by Agents instead; its profile may
    // legitimately leave the model to the agent's client default, so only a
    // malformed non-empty label is refused there.
    let model_admitted = if enforce_provider {
        is_model_label(&model) && (!primary_served || model.starts_with(&prefix))
    } else {
        model.is_empty() || is_model_label(&model)
    };
    if !model_admitted {
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
    if role.permission.as_deref() != Some("read-only")
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
    // The checker's binding is the one named after the checker in the user's
    // Virtual-Agent registry. The installer document is the packaged fallback:
    // it owns the run-local `audit` binding and the role overlay until the
    // operator adopts a checker-named chain in Agents.
    let checker = role.id.clone();
    let configured = if is_label(&checker) {
        user_binding(&checker)
    } else {
        None
    };
    let (document, binding, admitted, primary, va_home, enforce_provider) = match configured {
        Some((home, user)) => {
            let (primary, fallbacks) =
                crate::checker_binding::binding_profiles(&user["bindings"][&checker]);
            let Some(primary) = primary else {
                return Err(failure("audit_candidate_not_admitted", "registry/resolve"));
            };
            if !user["profiles"][&primary].is_object() {
                return Err(failure("audit_candidate_not_admitted", "registry/resolve"));
            }
            let mut admitted = vec![primary.clone()];
            admitted.extend(fallbacks);
            // The user's binding owns harness, model and fallback chain, but
            // every candidate it can serve must still be the gate's
            // read-only, single-tool shape. Refuse the binding before `va`
            // starts if any candidate declares a stronger capability or a
            // command whose native tools are not the audit allowlist.
            if admitted.iter().any(|id| {
                let profile = &user["profiles"][id];
                if !profile.is_object() || !restricted_profile(profile, None, false) {
                    return true;
                }
                let agent = profile["agent"].as_str().unwrap_or("");
                !audit_safe_agent(&user["agents"][agent])
            }) {
                return Err(failure("audit_candidate_not_admitted", "registry/resolve"));
            }
            // The user's binding owns harness, model and fallback chain; the
            // contract's runtime block only supplied the role text and the
            // audit tool surface. VA resolves and admits the candidates.
            (user, checker, admitted, primary, home, false)
        }
        None => {
            // The packaged document is bounded by the contract's declared
            // runtime: its agent and every model in the chain stay inside the
            // provider namespace Probator was configured for.
            let provider = role
                .extensions
                .get("provider")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !is_label(role.agent.as_str()) || !is_label(provider) {
                return Err(failure("audit_role_not_admitted", "profile/resolve"));
            }
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
            let raw = std::fs::read_to_string(&request.document)
                .map_err(|_| failure("audit_document_unreadable", "registry/load"))?;
            let mut document: Value = serde_json::from_str(&raw)
                .map_err(|_| failure("audit_document_invalid", "registry/load"))?;
            let (primary, fallbacks) =
                crate::checker_binding::binding_profiles(&document["bindings"]["audit"]);
            let Some(primary) = primary else {
                return Err(failure("audit_candidate_not_admitted", "registry/resolve"));
            };
            if primary != role.id {
                return Err(failure("audit_candidate_not_admitted", "registry/resolve"));
            }
            let profile_agent = document["profiles"][&primary]["agent"]
                .as_str()
                .unwrap_or("<missing>");
            if profile_agent != role.agent.as_str() {
                return Err(
                    failure("audit_profile_agent_mismatch", "registry/resolve").with_detail(format!(
                        "packaged profile '{primary}' declares agent '{profile_agent}', but the contract runtime harness is '{}'",
                        role.agent
                    )),
                );
            }
            let mut admitted = vec![primary.clone()];
            admitted.extend(fallbacks);
            overlay_primary(&mut document, role)?;
            // ACP and serve candidates arm the audit server through their
            // profile's `mcpServers`; the registry can only declare a static
            // shape there, so stamp the gate-built server — carrying this
            // run's own directory — onto every admitted candidate that
            // declares the surface. RPC candidates such as pi register
            // through the project file instead and keep no list.
            for id in &admitted {
                if let Some(profile) = document["profiles"][id].as_object_mut()
                    && profile
                        .get("mcpServers")
                        .and_then(Value::as_array)
                        .is_some_and(|servers| {
                            servers
                                .iter()
                                .any(|server| server["name"] == "probator-audit")
                        })
                {
                    profile.insert("mcpServers".into(), lane_mcp_list(role));
                }
            }
            let va_home = request.run_dir.join("va-home");
            std::fs::create_dir_all(&va_home)
                .map_err(|_| failure("audit_va_home_unwritable", "registry/load"))?;
            std::fs::write(
                va_home.join("registry.json"),
                serde_json::to_string_pretty(&document).unwrap_or_default(),
            )
            .map_err(|_| failure("audit_va_home_unwritable", "registry/load"))?;
            (
                document,
                "audit".to_string(),
                admitted,
                primary,
                va_home,
                true,
            )
        }
    };
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
    // A checker-named binding may declare the bare `pi` name. `va` resolves
    // that name through PATH, so put the gate-validated installation first:
    // a shadow `pi` earlier in the operator's PATH must not run the audit.
    let pinned_pi = (!enforce_provider).then(trusted_pi).flatten();
    let mut va = tokio::process::Command::new(va_binary());
    va.arg("serve")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .env("VIRTUAL_AGENT_HOME", &va_home)
        .kill_on_drop(true);
    if let Some(pi) = &pinned_pi {
        let dir = pi
            .parent()
            .ok_or_else(|| failure("audit_agent_untrusted", "run/start"))?;
        // The child resolves the bare name through this prefix. Refuse unless
        // that lookup lands on the exact canonical file validated above; a
        // directory-wide prefix alone is not a binding.
        if executable_file(&dir.join("pi")).as_deref() != Some(pi.as_path()) {
            return Err(failure("audit_agent_untrusted", "run/start"));
        }
        let path = std::env::var_os("PATH").unwrap_or_default();
        let pinned = std::env::join_paths(
            std::iter::once(dir.to_path_buf()).chain(std::env::split_paths(&path)),
        )
        .map_err(|_| failure("audit_agent_untrusted", "run/start"))?;
        va.env("PATH", pinned);
    }
    let mut child = va
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
    // The patch carries the gate's whole skill: a read-only posture and no
    // operator-supplied environment, working directory, mechanisms, skills
    // or mode. `va` layers the binding's harness/model choice underneath
    // these fields.
    //
    // The audit tool server is deliberately not repeated here. ACP and serve
    // candidates already carry it on their profile's `mcpServers` (stamped
    // with the run directory above), and pi RPC candidates discover the same
    // server from the project file written by `write_pi_mcp`. A session/open
    // `mcpServers` list would be refused by the custody layer for lanes with
    // no `mcpConfig` argv surface instead of arming the audit.
    let mut patch = json!({
        "name": role.name,
        "instructions": role.instructions,
        "env": {},
        "mechanisms": null,
        "skillReferences": [],
        "mode": null,
    });
    // Only a lane that advertises the selector may receive it; an RPC or ACP
    // candidate would otherwise refuse the whole open before the reviewer
    // ever starts.
    if permission_selector_supported(&document, &binding) {
        patch["permission"] = json!("read-only");
    }
    let open_params = |resume: Option<&str>| {
        let mut params = json!({
            "binding": binding,
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
            Ok(result) => {
                match opened_from(
                    &result,
                    &document,
                    role,
                    &admitted,
                    &primary,
                    &binding,
                    enforce_provider,
                ) {
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
                }
            }
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
