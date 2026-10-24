//! One resolver for the operator's checker-named Virtual-Agent binding.
//!
//! The audit host and the review engine must agree on which binding they
//! mean: the engine keys cursor and receipt reuse on the resolved profile
//! chain, while the host opens that chain through `va serve`. Reading the
//! registry in two places with different home-directory precedence or
//! binding-shape support would let one reviewer inherit another's pass.

use std::path::PathBuf;

use serde_json::Value;

/// The user's home directory, with the same precedence `va` uses.
pub fn user_home() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// The Virtual-Agent home: an explicit override, else the user's
/// `.virtual-agent` directory.
pub fn registry_home() -> Option<PathBuf> {
    std::env::var_os("VIRTUAL_AGENT_HOME")
        .map(PathBuf::from)
        .or_else(|| user_home().map(|home| home.join(".virtual-agent")))
}

/// Load the operator registry. Absent or unreadable is not an error: the
/// packaged installation document remains authoritative.
pub fn load_registry() -> Option<(PathBuf, Value)> {
    let home = registry_home()?;
    let raw = std::fs::read_to_string(home.join("registry.json")).ok()?;
    let document = serde_json::from_str(&raw).ok()?;
    Some((home, document))
}

/// The binding under the checker's name, when the operator declared one.
pub fn checker_binding<'a>(document: &'a Value, checker: &str) -> Option<&'a Value> {
    document.get("bindings")?.get(checker)
}

/// The selected profile and fallback chain of a binding. AwP accepts both
/// the short `"binding": "profile"` form and the object
/// `{ "profile": ..., "fallbacks": [...] }` form; fallback entries may be
/// strings or `{ "profile": ... }` objects. The engine and the audit host
/// normalize both shapes here so the same binding always names the same
/// reviewer.
pub fn binding_profiles(binding: &Value) -> (Option<String>, Vec<String>) {
    let primary = binding.as_str().map(str::to_string).or_else(|| {
        binding
            .get("profile")
            .and_then(Value::as_str)
            .map(str::to_string)
    });
    let fallbacks = binding
        .get("fallbacks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry.as_str().map(str::to_string).or_else(|| {
                entry
                    .get("profile")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
        })
        .collect();
    (primary, fallbacks)
}
