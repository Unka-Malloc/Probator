//! The installer: a checker lands on a machine as a contract, a policy, and a
//! registry entry - no code of its own. Ported from the retired Python
//! installer: one implementation, so the behavior that must never drift
//! (registry replacement, symlink conflict handling, bundle verification) has
//! exactly one home.

use crate::contract::{self, Contract};
use crate::util::sha256;
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

/// The two well-known roots every checker lives under. The profile root is
/// Probator's own data home — checkers are independent of any other agent
/// system's profile namespace.
pub(crate) fn profile_root() -> PathBuf {
    let base = std::env::var("XDG_DATA_HOME")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
                .join(".local")
                .join("share")
        });
    base.join("probator").join("profiles")
}

fn skill_root() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
        .join(".agents")
        .join("skills")
}

/// The registry file the gate binary actually reads: the same precedence
/// config.rs applies - $PROBATOR_CONFIG, then $XDG_CONFIG_HOME/probator, then
/// ~/.config/probator.
fn config_file() -> PathBuf {
    if let Ok(explicit) = std::env::var("PROBATOR_CONFIG")
        && !explicit.trim().is_empty()
    {
        return PathBuf::from(explicit);
    }
    crate::util::config_dir()
        .join("probator")
        .join("config.toml")
}

/// The audit policy lives in its own signed file beside the routing table, so
/// audits can run before the routing table is asked for a blessing. The
/// sibling convention matches `Policy::path_for` in the main binary.
pub(crate) fn policy_file() -> PathBuf {
    config_file()
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("checkers.toml")
}

/// The payload a checker installs: its contract, plus the document catalog
/// when the contract declares one.
fn payload_of(contract: &Contract) -> Vec<&'static str> {
    let mut payload = vec!["contract.json"];
    if contract.tools.official_documents {
        payload.push("documents.json");
    }
    payload
}

/// The declarative AwP registry template every checker materializes —
/// `tools/registry.json` in the source tree, baked into the binary so the
/// installer cannot drift from the document it validates. Beyond plain AwP
/// shape the template carries install-time conventions, resolved before
/// validation and never reaching disk:
///
/// - `{checker}` in any string or key: the contract name.
/// - `{"resolve": [candidates]}` as a `command.program`: a bare name looks
///   up `PATH`, a `{home}`-relative or absolute path checks existence; the
///   first reachable candidate wins. An unreachable declaration keeps its
///   first candidate as a bare name — a program that cannot spawn simply
///   yields to the next chain entry. Only the `audit` binding's primary
///   agent is required to resolve.
/// - `{"$json": <value>}` inside `env.set`: the value's compact JSON text
///   as a string literal.
///
/// The top-level `secrets` section is host data the audit runner resolves
/// — each reference names an ordered recipe list. It sits outside AwP's
/// document shape, so it is stripped for validation, not from the written
/// file.
const REGISTRY_TEMPLATE: &str = include_str!("../../../tools/registry.json");

/// Replace `{"$json": <value>}` with the value's compact JSON text — the
/// template's way of declaring an env entry whose literal is itself JSON.
fn embed_json_literals(value: &mut Value) {
    match value {
        Value::Array(items) => items.iter_mut().for_each(embed_json_literals),
        Value::Object(map) => {
            if map.len() == 1
                && let Some(inner) = map.remove("$json")
            {
                *value = Value::String(inner.to_string());
                return;
            }
            map.values_mut().for_each(embed_json_literals);
        }
        _ => {}
    }
}

/// One declared program candidate: a bare name resolves through `PATH`, a
/// path (`{home}` expands first) through an existence check.
fn probe_program(candidate: &str) -> Option<String> {
    if !candidate.contains('/') && !candidate.contains('{') {
        return which(candidate);
    }
    let expanded = if candidate.contains("{home}") {
        candidate.replace("{home}", std::env::var("HOME").ok()?.as_str())
    } else {
        candidate.to_string()
    };
    Path::new(&expanded).is_file().then_some(expanded)
}

/// Resolve one `command.program` declaration in place; returns the
/// reachable path a candidate resolved to, `None` when the declaration
/// kept its first candidate as an unreachable bare name.
fn resolve_program(program: &mut Value) -> Option<String> {
    let Some(candidates) = program.get("resolve").and_then(Value::as_array) else {
        // A plain string names the program already.
        return program.as_str().map(str::to_string);
    };
    for candidate in candidates.iter().filter_map(Value::as_str) {
        if let Some(found) = probe_program(candidate) {
            *program = json!(found);
            return Some(found);
        }
    }
    *program = json!(candidates.first().and_then(Value::as_str).unwrap_or(""));
    None
}

/// Resolve the `command.program` of one agent spec and each of its
/// declared lane alternates; returns the primary spec's resolution.
fn resolve_spec_programs(spec: &mut Value) -> Option<String> {
    let found = spec
        .pointer_mut("/command/program")
        .and_then(resolve_program);
    if let Some(alternates) = spec.get_mut("alternates").and_then(Value::as_array_mut) {
        for alternate in alternates {
            resolve_spec_programs(alternate);
        }
    }
    found
}

/// The host-side secret recipes a document may declare: each reference
/// names an ordered recipe list — `{"env": "NAME"}` reads a host variable,
/// `{"toml": {"path", "key"}}` a `key = "value"` assignment. Anything else
/// refuses the install rather than dying inside the audit run.
fn check_secrets(secrets: &Value) -> Result<(), String> {
    if secrets.is_null() {
        return Ok(());
    }
    let Some(object) = secrets.as_object() else {
        return Err("registry template: secrets must be an object".to_string());
    };
    for (reference, recipes) in object {
        let Some(recipes) = recipes.as_array() else {
            return Err(format!(
                "registry template: secrets.{reference} must be a recipe list"
            ));
        };
        for recipe in recipes {
            let declared = recipe["env"].is_string()
                || (recipe["toml"]["path"].is_string() && recipe["toml"]["key"].is_string());
            if !declared {
                return Err(format!(
                    "registry template: secrets.{reference} recipes are \
                     {{\"env\": \"NAME\"}} or {{\"toml\": {{\"path\", \"key\"}}}}"
                ));
            }
        }
    }
    Ok(())
}

/// The materialization product: the validated document to write plus what
/// the `audit` binding's primary program resolved to — `None` (with the
/// tried candidates) when no candidate exists on this machine.
struct Materialized {
    document: Value,
    primary: Option<String>,
    primary_candidates: Vec<String>,
}

/// Materialize the checker's registry document from the shared template:
/// substitute the contract name, embed declared env literals, resolve
/// declared program candidates and validate the AwP document — a template
/// that cannot materialize a registry fails the install, not the audit.
fn registry_document(contract: &Contract) -> Result<Materialized, String> {
    let mut document: Value =
        serde_json::from_str(&REGISTRY_TEMPLATE.replace("{checker}", &contract.name))
            .map_err(|error| format!("registry template: {error}"))?;
    embed_json_literals(&mut document);
    let primary_agent = document["bindings"]["audit"]["profile"]
        .as_str()
        .map(|profile| {
            document["profiles"][profile]["agent"]
                .as_str()
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_default();
    if primary_agent.is_empty() {
        return Err("registry template: the audit binding resolves to no agent".to_string());
    }
    let agents = document["agents"]
        .as_object_mut()
        .ok_or("registry template: agents must be an object")?;
    let primary_candidates = agents
        .get(primary_agent.as_str())
        .and_then(|entry| entry.pointer("/command/program/resolve"))
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut primary = None;
    for (id, entry) in agents.iter_mut() {
        let found = resolve_spec_programs(entry);
        if *id == primary_agent {
            primary = Some(found);
        }
    }
    check_secrets(&document["secrets"])?;
    // Validation runs on the AwP document alone: `secrets` is host data
    // the audit runner resolves, not a registry field.
    let mut awp_document = document.clone();
    if let Some(object) = awp_document.as_object_mut() {
        object.remove("secrets");
    }
    let document_model: awp::RegistryDocument = serde_json::from_value(awp_document)
        .map_err(|error| format!("registry template: {error}"))?;
    awp::Registry::from_document(document_model).map_err(|error| error.to_string())?;
    Ok(Materialized {
        document,
        primary: primary.flatten(),
        primary_candidates,
    })
}

/// Write the checker's materialized AwP registry document. The runner
/// resolves this file through AwP's standard registry and overlays the
/// runtime-projected role — nothing about a specific agent is wired into
/// the runner or the installer.
fn write_registry_document(target: &Path, document: &Value) -> Result<(), String> {
    let path = target.join("registry.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(document).map_err(|e| e.to_string())? + "\n",
    )
    .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Materialize the checker's registry document, requiring the `audit`
/// binding's primary agent program to exist on this machine — the audit
/// has no primary without it. Fallback programs may stay bare names.
fn materialized_registry(contract: &Contract) -> Result<(Value, String), String> {
    let materialized = registry_document(contract)?;
    let Some(program) = materialized.primary else {
        return Err(format!(
            "the audit binding's primary agent is not installed; \
             the registry template tried: {}",
            materialized.primary_candidates.join(", ")
        ));
    };
    Ok((materialized.document, program))
}

/// The files the drift check covers: the copied payload plus the generated
/// registry document, so a hand-edited agent declaration refuses the run.
fn installed_files(contract: &Contract) -> Vec<&'static str> {
    let mut names = payload_of(contract);
    names.push("registry.json");
    names
}

fn which(name: &str) -> Option<String> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file())
            .map(|candidate| candidate.to_string_lossy().into_owned())
    })
}

/// The engine the registry rows name. The fixed `~/.local/bin` install is
/// the trusted helper the publication gate invokes, so a registry written
/// from a development build must still point there — never at whatever
/// binary happened to run `install`.
fn installed_tool(name: &str) -> Option<String> {
    let canonical = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
        .join(".local")
        .join("bin")
        .join(name);
    if canonical.is_file() {
        return Some(canonical.to_string_lossy().into_owned());
    }
    which(name)
}

/// Add or replace this checker's registry entry. Replacing rather than
/// refusing keeps an installed checker updatable: the command embeds absolute
/// paths, so a machine that refused to touch an existing entry would be
/// stranded on whatever was written first.
fn register(policy: &Path, name: &str, block: &str) -> Result<&'static str, String> {
    let text = std::fs::read_to_string(policy).unwrap_or_default();
    let mut segments: Vec<String> = Vec::new();
    let mut current = String::new();
    for line in text.split_inclusive('\n') {
        if line.trim_start().starts_with('[') && !current.is_empty() {
            segments.push(std::mem::take(&mut current));
        }
        current.push_str(line);
    }
    if !current.is_empty() {
        segments.push(current);
    }
    let needle = format!("name = \"{name}\"");
    let mut action = "added";
    let mut replaced = false;
    for (index, segment) in segments.iter().enumerate() {
        if segment.trim_start().starts_with("[[checkers]]") && segment.contains(&needle) {
            segments[index] = block.to_string();
            action = "replaced";
            replaced = true;
            break;
        }
    }
    if !replaced {
        let separator = if text.ends_with("\n\n") || text.is_empty() {
            ""
        } else {
            "\n"
        };
        segments.push(format!("{separator}{block}"));
    }
    let updated = segments.concat();
    toml::from_str::<toml::Value>(&updated).map_err(|error| format!("checkers.toml: {error}"))?;
    std::fs::write(policy, updated).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(policy, std::fs::Permissions::from_mode(0o600));
    }
    Ok(action)
}

/// Bind the policy file into the routing table: `audit_policy` is a top-level
/// key, so it must be inserted ahead of the first table header. The signed
/// declaration is what stops an audit from being skipped by deleting the
/// policy file - an absent declared policy refuses to run.
fn declare_policy(config: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(config).unwrap_or_default();
    // A top-level key before the first table header is already a declaration.
    let already = text
        .lines()
        .take_while(|l| !l.trim_start().starts_with('['))
        .any(|l| l.trim_start().starts_with("audit_policy"));
    if already {
        return Ok(());
    }
    let declaration = "audit_policy = \"checkers.toml\"\n\n";
    // Insert before the first line that opens a table - a top-level key found
    // under a table header would silently belong to that table.
    let offset = text
        .char_indices()
        .scan(true, |bol, (i, c)| {
            let at_bol = *bol;
            *bol = c == '\n';
            Some((i, at_bol))
        })
        .find(|(i, at_bol)| *at_bol && text[*i..].trim_start().starts_with('['))
        .map(|(i, _)| i)
        .unwrap_or(text.len());
    let mut updated = String::with_capacity(text.len() + declaration.len());
    updated.push_str(&text[..offset]);
    updated.push_str(declaration);
    updated.push_str(&text[offset..]);
    toml::from_str::<toml::Value>(&updated).map_err(|e| format!("config.toml: {e}"))?;
    std::fs::write(config, updated).map_err(|e| e.to_string())?;
    Ok(())
}

fn read_installation(target: &Path) -> Option<Map<String, Value>> {
    std::fs::read_to_string(target.join("installation.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|value| value.as_object().cloned())
}

/// The payload's hashes, recorded so a later startup can tell an edited
/// payload apart from the one the installer wrote.
fn payload_hashes(target: &Path, payload: &[&str]) -> Result<Map<String, Value>, String> {
    let mut hashes = Map::new();
    for name in payload {
        let text =
            std::fs::read_to_string(target.join(name)).map_err(|e| format!("{name}: {e}"))?;
        hashes.insert(name.to_string(), json!(sha256(&text)));
    }
    Ok(hashes)
}

/// Copy the checker's documents and payload into place. Documents are the
/// registry's to publish: the source tree's copies seed a machine that has
/// never pulled; once a version is synced, `--pull` is the only thing that
/// overwrites them.
fn install_payload(source: &Path, target: &Path, contract: &Contract) -> Result<(), String> {
    let agent = &contract.name;
    let shared = skill_root().join(agent);
    std::fs::create_dir_all(&shared).map_err(|e| e.to_string())?;
    let synced = read_installation(target).is_some_and(|settings| settings.contains_key("synced"));
    if !synced {
        for name in ["SKILL.md", "policy.md"] {
            std::fs::copy(source.join(name), shared.join(name))
                .map_err(|e| format!("{name}: {e}"))?;
        }
    }
    // Every agent host's skills directory links the one shared copy:
    // home.glob(".*/skills"), home.glob(".config/*/skills") and
    // PROFILE_ROOT.glob("*/skills").
    let home = PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&home) {
        roots.extend(
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .filter(|p| {
                    p.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .starts_with('.')
                })
                .map(|p| p.join("skills")),
        );
    }
    if let Ok(entries) = std::fs::read_dir(home.join(".config")) {
        roots.extend(
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .map(|p| p.join("skills")),
        );
    }
    if let Ok(entries) = std::fs::read_dir(profile_root()) {
        roots.extend(
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .map(|p| p.join("skills")),
        );
    }
    let shared_real = std::fs::canonicalize(&shared).unwrap_or_else(|_| shared.clone());
    let shared_parent = shared
        .parent()
        .and_then(|p| p.canonicalize().ok())
        .unwrap_or_else(|| shared.clone());
    for directory in roots {
        if !directory.is_dir() {
            continue;
        }
        let directory_real = directory
            .canonicalize()
            .unwrap_or_else(|_| directory.clone());
        if directory_real == shared_parent {
            continue;
        }
        let link = directory.join(agent);
        if link.is_symlink()
            && std::fs::canonicalize(&link).ok().as_deref() == Some(shared_real.as_path())
        {
            continue;
        }
        if link.exists() || link.is_symlink() {
            return Err(format!(
                "Conflicting {agent} skill entry requires inspection: {}",
                link.display()
            ));
        }
        std::os::unix::fs::symlink(&shared, &link).map_err(|e| e.to_string())?;
    }
    for name in payload_of(contract) {
        std::fs::copy(source.join(name), target.join(name)).map_err(|e| format!("{name}: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(target.join(name), std::fs::Permissions::from_mode(0o600));
        }
    }
    // The policy rides the payload directory as a link into the shared skill
    // copy, so the registry's version is the only version in play.
    let destination = target.join("policy.md");
    if destination.exists() || destination.is_symlink() {
        let _ = std::fs::remove_file(&destination);
    }
    std::os::unix::fs::symlink(shared.join("policy.md"), &destination)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// The registry block for one checker, in the signed config's own shape.
fn checker_block(contract: &Contract, target: &Path) -> Result<String, String> {
    let events = serde_json::to_string(&contract.on).map_err(|e| e.to_string())?;
    let runner = installed_tool("probator")
        .ok_or_else(|| "the installed probator engine is required".to_string())?;
    let command = json!([
        runner,
        "run",
        "--contract",
        target.join("contract.json").to_string_lossy(),
        "--repo",
        "{repo}",
    ]);
    Ok(format!(
        "[[checkers]]\nname = \"{}\"\non = {}\nkind = \"exec\"\nseverity = \"blocking\"\ntimeout_secs = 0\ncommand = {}\n",
        contract.name,
        events,
        serde_json::to_string(&command).map_err(|e| e.to_string())?,
    ))
}

/// Install a checker from its source directory (`tools/<checker>/`).
pub fn install(source: &Path) -> Result<String, String> {
    let contract = contract::load(&source.join("contract.json"))?;
    let (Some(runner), Some(review)) =
        (installed_tool("probator-agent"), installed_tool("probator"))
    else {
        return Err("probator and probator-agent (the A4AA runner) are required".to_string());
    };
    let (document, program) = materialized_registry(&contract)?;
    let profile = profile_root().join(&contract.name);
    let target = profile.join("plugins").join(&contract.name);
    if !profile.exists() {
        std::fs::create_dir_all(&profile).map_err(|e| e.to_string())?;
    } else if !target.join("installation.json").is_file() {
        return Err(format!(
            "Existing {} profile requires inspection before installation",
            contract.name
        ));
    }
    std::fs::create_dir_all(&target).map_err(|e| e.to_string())?;
    install_payload(source, &target, &contract)?;
    write_registry_document(&target, &document)?;
    let previous = read_installation(&target).unwrap_or_default();
    let mut settings = json!({
        "program": program,
        "review": review,
        "agent_runner": runner,
        "profile": profile.to_string_lossy(),
        "skill_dir": skill_root().join(&contract.name).to_string_lossy(),
        "payload": payload_hashes(&target, &installed_files(&contract))?,
    });
    // Installing again does not un-sync anything.
    if let Some(synced) = previous.get("synced") {
        settings["synced"] = synced.clone();
    }
    write_settings(&target, &settings)?;
    let registry = config_file();
    if let Some(parent) = registry.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if !registry.exists() {
        std::fs::write(&registry, "").map_err(|e| e.to_string())?;
    }
    // The policy file is declared in the routing table so its absence refuses
    // an audit rather than silently running none; rows left in config.toml
    // migrate out at `probator config sign`, which certifies both files.
    declare_policy(&registry)?;
    let policy = policy_file();
    if !policy.exists() {
        std::fs::write(&policy, "").map_err(|e| e.to_string())?;
    }
    let action = register(&policy, &contract.name, &checker_block(&contract, &target)?)?;
    Ok(format!(
        "{} installed: blocking {}; registry entry {action} in {}",
        contract.title,
        contract.on.join(", "),
        policy.display()
    ))
}

/// The payload file names the Python implementation installed - removed on
/// update, so the contract is the only thing left.
const RETIRED_PAYLOAD: [&str; 10] = [
    "__init__.py",
    "clean_stage1.py",
    "security_stage1.py",
    "maintainer_stage1.py",
    "full_audit.py",
    "audit.py",
    "plugin.yaml",
    "profile_sync.py",
    "codex_config.py",
    "audit_runtime.py",
];

/// Refresh an installed checker's payload from its source directory and
/// re-register its entry; the retired Python payload files leave with it.
pub fn update(source: &Path) -> Result<String, String> {
    let contract = contract::load(&source.join("contract.json"))?;
    let (Some(runner), Some(review)) =
        (installed_tool("probator-agent"), installed_tool("probator"))
    else {
        return Err("probator and probator-agent (the A4AA runner) are required".to_string());
    };
    let (document, program) = materialized_registry(&contract)?;
    let profile = profile_root().join(&contract.name);
    let target = profile.join("plugins").join(&contract.name);
    let Some(mut settings) = read_installation(&target) else {
        return Err(format!("{} is not installed", contract.title));
    };
    // Legacy records predate the declared-agent runtime; the record
    // migrates in place so the checker never consults a removed harness
    // or home.
    settings.remove("hermes");
    settings.remove("pi");
    settings.remove("credential_file");
    settings.remove("python");
    settings.remove("codex");
    settings.remove("codex_home");
    settings.remove("agent_home");
    settings.insert("program".into(), json!(program));
    settings.insert("review".into(), json!(review));
    settings.insert("agent_runner".into(), json!(runner));
    settings.insert("profile".into(), json!(profile.to_string_lossy()));
    for retired in RETIRED_PAYLOAD {
        let _ = std::fs::remove_file(target.join(retired));
    }
    let _ = std::fs::remove_file(target.join("review_ranges.py"));
    let _ = std::fs::remove_file(target.join("audit_engine.py"));
    install_payload(source, &target, &contract)?;
    write_registry_document(&target, &document)?;
    settings.insert(
        "payload".into(),
        Value::Object(payload_hashes(&target, &installed_files(&contract))?),
    );
    write_settings(&target, &Value::Object(settings))?;
    let registry = config_file();
    declare_policy(&registry)?;
    let policy = policy_file();
    if !policy.exists() {
        std::fs::write(&policy, "").map_err(|e| e.to_string())?;
    }
    let action = register(&policy, &contract.name, &checker_block(&contract, &target)?)?;
    Ok(format!(
        "Updated {} payload and registry entry ({action})",
        contract.title
    ))
}

fn write_settings(target: &Path, settings: &Value) -> Result<(), String> {
    let path = target.join("installation.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(settings).map_err(|e| e.to_string())? + "\n",
    )
    .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// The bundle decides what the agent runs, so the channel must be
/// authenticated anywhere it can be intercepted: loopback http is the local
/// development registry, anything else is https or refused.
fn check_url(url: &str) -> Result<(), String> {
    let parts = url.split_once("://");
    let loopback = ["127.0.0.1", "::1", "localhost"].iter().any(|host| {
        parts.is_some_and(|(_, rest)| rest.split(['/', ':', '?']).next() == Some(host))
    });
    if parts.is_some_and(|(scheme, _)| scheme == "https") || loopback {
        return Ok(());
    }
    Err(format!(
        "profile registry outside loopback must be reached over https: {url}"
    ))
}

/// The whole version as one value: one line per file, sorted — the registry's
/// own shape (`lines.join("\n") + "\n"`), byte-identical so a bundle's
/// published manifest verifies.
fn bundle_manifest(files: &Map<String, Value>) -> String {
    let mut lines: Vec<String> = files
        .keys()
        .map(|name| format!("{name}\t{}", sha256(files[name].as_str().unwrap_or(""))))
        .collect();
    lines.sort();
    sha256(&(lines.join("\n") + "\n"))
}

/// Fetch one published profile version and install its documents. Every hash
/// is checked before the first byte is written.
pub fn pull(source: &Path, tag: Option<&str>) -> Result<String, String> {
    let contract = contract::load(&source.join("contract.json"))?;
    let target = profile_root()
        .join(&contract.name)
        .join("plugins")
        .join(&contract.name);
    // The registry decides which prompt and runtime the checker runs on, so
    // the channel is a choice the operator made - never whatever happens to
    // be listening on the port.
    let url = std::env::var("PROBATOR_PROFILES_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            "PROBATOR_PROFILES_URL is not set; the profile registry is an explicit choice"
                .to_string()
        })?;
    pull_with(&contract, &target, &url, tag)
}

fn pull_with(
    contract: &Contract,
    target: &Path,
    url: &str,
    tag: Option<&str>,
) -> Result<String, String> {
    let Some(settings) = read_installation(target) else {
        return Err(format!("{} is not installed", contract.title));
    };
    check_url(url)?;
    let mut endpoint = format!(
        "{}/api/probator/profiles/{}/bundle",
        url.trim_end_matches('/'),
        contract.name
    );
    if let Some(tag) = tag {
        endpoint += &format!("?tag={tag}");
    }
    let body = ureq::get(&endpoint)
        .header("accept", "application/json")
        .call()
        .map_err(|error| format!("the profile bundle could not be fetched: {error}"))?
        .into_body()
        .read_to_string()
        .map_err(|error| format!("the profile bundle could not be read: {error}"))?;
    let bundle: Value =
        serde_json::from_str(&body).map_err(|e| format!("the profile bundle: {e}"))?;
    let files = bundle["files"].as_object().cloned().unwrap_or_default();
    let hashes = bundle["hashes"].as_object().cloned().unwrap_or_default();
    let mut file_names: Vec<&String> = files.keys().collect();
    let mut hash_names: Vec<&String> = hashes.keys().collect();
    file_names.sort();
    hash_names.sort();
    if file_names != hash_names {
        return Err("The published profile listing is inconsistent; nothing was written".into());
    }
    if bundle_manifest(&files) != bundle["manifest"].as_str().unwrap_or("") {
        return Err(
            "The published profile manifest does not match its files; nothing was written".into(),
        );
    }
    for (name, text) in &files {
        if sha256(text.as_str().unwrap_or("")) != hashes[name].as_str().unwrap_or("") {
            return Err(format!(
                "The published copy of {name} does not match its hash; nothing was written"
            ));
        }
    }
    const SYNCED: [&str; 4] = ["policy.md", "SKILL.md", "documents.json", "profile.json"];
    let skill_dir = settings
        .get("skill_dir")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| skill_root().join(&contract.name));
    std::fs::create_dir_all(&skill_dir).map_err(|e| e.to_string())?;
    let mut kept = Map::new();
    for name in SYNCED {
        if let Some(text) = files.get(name) {
            std::fs::write(skill_dir.join(name), text.as_str().unwrap_or(""))
                .map_err(|e| format!("{name}: {e}"))?;
            kept.insert(name.to_string(), hashes[name].clone());
        }
    }
    let stale = skill_dir.join("documents.json");
    if !kept.contains_key("documents.json") && stale.exists() {
        let _ = std::fs::remove_file(&stale);
    }
    let bundle_tag = bundle["tag"].as_str().unwrap_or("").to_string();
    let version = bundle_tag
        .rsplit_once("/v")
        .and_then(|(_, v)| v.parse::<u64>().ok())
        .unwrap_or(0);
    let mut updated = settings;
    updated.insert("skill_dir".into(), json!(skill_dir.to_string_lossy()));
    updated.insert(
        "synced".into(),
        json!({"tag": bundle_tag, "version": version, "manifest": bundle["manifest"], "files": kept}),
    );
    write_settings(target, &Value::Object(updated))?;
    Ok(format!(
        "{} profile synced to {} ({} documents)",
        contract.name,
        bundle["tag"].as_str().unwrap_or(""),
        kept.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        bundle_manifest, check_url, declare_policy, payload_of, pull_with, register,
        registry_document, write_registry_document,
    };
    use crate::contract;
    use serde_json::{Value, json};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn contract_at(dir: &Path, official_documents: bool) -> contract::Contract {
        let mut text = json!({
            "name": "sample-checker",
            "title": "Sample Checker",
            "domains": ["structure"],
            "finding_keys": ["file", "line", "severity", "evidence"],
            "on": ["pre-push", "pr"],
            "tools": {
                "name_prefix": "sample",
                "context": ["inventory", "list", "diff", "read", "find"],
                "submit": true,
                "official_documents": official_documents,
                "descriptions": {"context": "c", "submit": "s"}
            },
            "task": "Review."
        });
        if official_documents {
            text["tools"]["descriptions"]["official_doc"] = json!("Fetch by key.");
        }
        std::fs::write(
            dir.join("contract.json"),
            serde_json::to_string_pretty(&text).unwrap(),
        )
        .unwrap();
        contract::load(&dir.join("contract.json")).unwrap()
    }

    static NEXT: AtomicU64 = AtomicU64::new(0);
    fn tempdir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gv-install-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn registry_blocks_replace_by_name_and_validate_as_toml() {
        let dir = tempdir();
        let policy = dir.join("checkers.toml");
        std::fs::write(&policy, "# audit policy\n").unwrap();
        let block_a =
            "[[checkers]]\nname = \"one\"\non = [\"pre-push\"]\ncommand = [\"/bin/true\"]\n";
        assert_eq!(register(&policy, "one", block_a).unwrap(), "added");
        let block_b = "[[checkers]]\nname = \"two\"\non = [\"pr\"]\ncommand = [\"/bin/false\"]\n";
        assert_eq!(register(&policy, "two", block_b).unwrap(), "added");
        let block_new = "[[checkers]]\nname = \"one\"\non = [\"pr\"]\ncommand = [\"/bin/sh\"]\n";
        assert_eq!(register(&policy, "one", block_new).unwrap(), "replaced");
        let text = std::fs::read_to_string(&policy).unwrap();
        assert!(
            text.contains("# audit policy"),
            "the file's own header survives"
        );
        assert!(text.contains("/bin/sh"), "the replacement landed");
        assert!(!text.contains("/bin/true\""), "the old block is gone");
        assert!(
            text.contains("name = \"two\""),
            "the other checker survives"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn declare_policy_places_the_key_before_any_table() {
        let dir = tempdir();
        let config = dir.join("config.toml");
        std::fs::write(&config, "# heading\n\n[identities.a]\nname = 'A'\n").unwrap();
        declare_policy(&config).unwrap();
        let text = std::fs::read_to_string(&config).unwrap();
        let declaration = text.find("audit_policy").unwrap();
        let first_table = text.find("[identities.a]").unwrap();
        assert!(
            declaration < first_table,
            "a top-level key under a table header would silently belong to it: {text}"
        );
        toml::from_str::<toml::Value>(&text).expect("the declaration keeps the file parseable");
        // Idempotent: a second declaration must not appear.
        declare_policy(&config).unwrap();
        let twice = std::fs::read_to_string(&config).unwrap();
        assert_eq!(twice.matches("audit_policy").count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_registry_template_materializes_a_valid_document() {
        let dir = tempdir();
        let contract = contract_at(&dir, false);
        let materialized = registry_document(&contract).unwrap();
        let document = &materialized.document;
        // The contract name filled the profile and binding placeholders.
        assert_eq!(
            document["bindings"]["audit"]["profile"],
            json!("sample-checker")
        );
        let fallbacks = document["bindings"]["audit"]["fallbacks"]
            .as_array()
            .expect("the audit binding declares fallbacks");
        let fallback_profiles: Vec<&str> = fallbacks
            .iter()
            .map(|fallback| {
                fallback
                    .as_str()
                    .or_else(|| fallback["profile"].as_str())
                    .unwrap_or("")
            })
            .collect();
        assert_eq!(
            fallback_profiles,
            ["sample-checker-pi", "sample-checker-codex",]
        );
        // Every packaged profile declares the read-only posture its lane
        // either enforces natively or receives through the audit projection.
        for (id, profile) in document["profiles"].as_object().unwrap() {
            assert_eq!(
                profile["permission"],
                json!("read-only"),
                "packaged profile {id} must declare read-only"
            );
        }
        // The primary checker profile arms the engine's audit tool surface.
        assert_eq!(
            document["profiles"]["sample-checker"]["mcpServers"][0]["name"],
            json!("probator-audit")
        );
        // Every program declaration resolved to a concrete string.
        for (id, entry) in document["agents"].as_object().unwrap() {
            assert!(
                entry["command"]["program"].is_string(),
                "agent {id} kept an unresolved program declaration"
            );
            for alternate in entry["alternates"].as_array().into_iter().flatten() {
                assert!(
                    alternate["command"]["program"].is_string(),
                    "agent {id} alternate kept an unresolved program declaration"
                );
            }
        }
        // The env config embedded as a literal string, not a template form.
        let env_set = &document["agents"]["opencode"]["command"]["env"]["inheritAll"]["set"];
        let config = env_set["OPENCODE_CONFIG_CONTENT"].as_str().unwrap();
        assert!(config.starts_with('{'), "the config embeds as JSON text");
        // The template embeds no credential recipe; a fallback may not carry
        // a secret reference the gate cannot resolve.
        assert_eq!(document["secrets"], json!({}));
        assert!(document["agents"].get("devin").is_none());
        // …and the AwP document validates once they are stripped.
        let mut stripped = document.clone();
        stripped.as_object_mut().unwrap().remove("secrets");
        let parsed: awp::RegistryDocument = serde_json::from_value(stripped).unwrap();
        let registry = awp::Registry::from_document(parsed).unwrap();
        let binding = registry.binding("audit").unwrap();
        assert_eq!(binding.profile(), "sample-checker");
        assert_eq!(
            binding
                .fallbacks()
                .iter()
                .map(|f| f.profile())
                .collect::<Vec<_>>(),
            ["sample-checker-pi", "sample-checker-codex"]
        );
        // The written file round-trips through the same path the runner uses.
        let target = dir.join("target");
        std::fs::create_dir_all(&target).unwrap();
        write_registry_document(&target, document).unwrap();
        let written = std::fs::read_to_string(target.join("registry.json")).unwrap();
        let mut on_disk: Value = serde_json::from_str(&written).unwrap();
        on_disk.as_object_mut().unwrap().remove("secrets");
        let reparsed: awp::RegistryDocument = serde_json::from_value(on_disk).unwrap();
        awp::Registry::from_document(reparsed).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_payload_is_the_contract_and_maybe_a_catalog() {
        let dir = tempdir();
        assert_eq!(payload_of(&contract_at(&dir, false)), vec!["contract.json"]);
        assert_eq!(
            payload_of(&contract_at(&dir, true)),
            vec!["contract.json", "documents.json"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn registry_urls_are_https_or_loopback() {
        assert!(check_url("http://127.0.0.1:8891").is_ok());
        assert!(check_url("http://localhost:8891").is_ok());
        assert!(check_url("https://registry.example.com").is_ok());
        assert!(check_url("http://registry.example.com").is_err());
    }

    /// Serve one canned registry bundle.
    fn serve_bundle(body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let mut sink = String::new();
                while reader.read_line(&mut sink).is_ok_and(|n| n > 2) {}
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
        });
        url
    }

    #[test]
    fn pull_verifies_the_bundle_before_writing() {
        let dir = tempdir();
        let source = dir.join("source");
        let target = dir.join("target");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        let contract = contract_at(&source, false);
        let skill_dir = dir.join("skill");
        std::fs::write(
            target.join("installation.json"),
            json!({"skill_dir": skill_dir.to_string_lossy()}).to_string(),
        )
        .unwrap();
        let files = json!({"policy.md": "the policy\n", "SKILL.md": "the skill\n"});
        let hashes = json!({
            "policy.md": crate::util::sha256("the policy\n"),
            "SKILL.md": crate::util::sha256("the skill\n"),
        });
        let bundle = json!({
            "tag": "profile/sample-checker/v3",
            "manifest": bundle_manifest(files.as_object().unwrap()),
            "files": files,
            "hashes": hashes,
        });
        let url = serve_bundle(bundle.to_string());
        let message = pull_with(&contract, &target, &url, None).unwrap();
        assert!(message.contains("v3"), "{message}");
        assert_eq!(
            std::fs::read_to_string(skill_dir.join("policy.md")).unwrap(),
            "the policy\n"
        );
        let settings: Value = serde_json::from_str(
            &std::fs::read_to_string(target.join("installation.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(settings["synced"]["tag"], "profile/sample-checker/v3");

        // A tampered file hash refuses the bundle and writes nothing.
        let target2 = dir.join("target2");
        let skill2 = dir.join("skill2");
        std::fs::create_dir_all(&target2).unwrap();
        std::fs::write(
            target2.join("installation.json"),
            json!({"skill_dir": skill2.to_string_lossy()}).to_string(),
        )
        .unwrap();
        let mut bad = bundle.clone();
        bad["files"]["policy.md"] = json!("edited\n");
        let url = serve_bundle(bad.to_string());
        assert!(pull_with(&contract, &target2, &url, None).is_err());
        assert!(!skill2.join("policy.md").exists(), "nothing was written");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
