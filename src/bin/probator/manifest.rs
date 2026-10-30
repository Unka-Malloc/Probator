//! The tool manifest a contract generates: the model-facing surface of a
//! review, derived from the contract - never hand-maintained per checker, so
//! four manifests cannot drift into four dialects. Byte-faithful to the
//! Python engine's `tool_plan` output, pinned by the goldens under
//! `tests/review-parity/`.

use crate::contract::Contract;
use crate::evidence::{DIFF_PAGE_CHARS, FIND_PAGE, READ_PAGE_LINES};
use serde_json::{Map, Value, json};

/// The review mode: the gate, or an operator-assigned full-service audit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Gate,
    FullService,
}

/// The runtime fills the page constants, so a size change cannot leave a
/// description promising a page the code no longer serves.
fn fill(template: &str) -> String {
    template
        .replace("{read_page_lines}", &READ_PAGE_LINES.to_string())
        .replace("{diff_page_chars}", &DIFF_PAGE_CHARS.to_string())
        .replace("{find_page}", &FIND_PAGE.to_string())
}

/// The coverage object every submit contract carries: one literal, generated
/// per domain set.
fn coverage_schema(domains: &[String]) -> Value {
    let entry = json!({
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["reviewed", "not-applicable", "unknown"]},
            "reason": {"type": "string"},
        },
        "required": ["status", "reason"],
        "additionalProperties": false,
    });
    let mut properties = Map::new();
    for domain in domains {
        properties.insert(domain.clone(), entry.clone());
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": domains,
        "additionalProperties": false,
    })
}

/// The context tool's parameter surface. One builder so a new key cannot land
/// on three checkers while the fourth tells the model a different contract.
fn context_schema(operations: &[String], revision_label: &str) -> Value {
    json!({
        "operation": {"type": "string", "enum": operations},
        "path": {"type": "string"},
        "pattern": {"type": "string"},
        "text": {"type": "string"},
        "start": {"type": "integer"},
        "offset": {"type": "integer"},
        "item": {"type": "string"},
        "revision": {"type": "string", "enum": [revision_label, "base"]},
    })
}

/// The findings-entry contract, generated from the same key list the
/// validator enforces so the tool manifest and the check cannot tell the
/// model different contracts. Sources stay free-form here: the verdict check
/// already requires every cited URL to have been fetched this review, whether
/// it came from the catalog or was located by the reviewer.
fn finding_schema(contract: &Contract) -> Value {
    let mut properties = Map::new();
    for key in &contract.finding_keys {
        let schema = match key.as_str() {
            "line" => json!({"type": "integer", "minimum": 1}),
            "severity" => json!({"type": "string", "enum": ["blocking", "advisory"]}),
            "sources" if contract.tools.official_documents => {
                json!({"type": "array", "items": {"type": "string"}})
            }
            _ => json!({"type": "string"}),
        };
        properties.insert(key.clone(), schema);
    }
    for key in &contract.finding_optional_keys {
        properties.insert(key.clone(), json!({"type": "string"}));
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": contract.finding_keys,
        "additionalProperties": false,
    })
}

/// The exact manifest the bridge extension receives, in tool order: context,
/// the official-document fetcher where contracted, submit.
pub fn manifest(contract: &Contract, mode: Mode, projects: &[String]) -> Vec<Value> {
    let prefix = &contract.tools.name_prefix;
    let full = mode == Mode::FullService && contract.tools.full_service;
    let operations = if full {
        contract
            .tools
            .context_full_service
            .as_ref()
            .unwrap_or(&contract.tools.context)
            .clone()
    } else {
        contract.tools.context.clone()
    };
    let context_description = if full {
        contract
            .tools
            .descriptions
            .context_full_service
            .as_deref()
            .unwrap_or(&contract.tools.descriptions.context)
    } else {
        &contract.tools.descriptions.context
    };
    let mut tools = vec![json!({
        "name": format!("{prefix}_context"),
        "description": fill(context_description),
        "parameters": {
            "type": "object",
            "properties": context_schema(&operations, &contract.tools.revision_label),
            "required": ["operation"],
        },
    })];
    if contract.tools.official_documents {
        tools.push(json!({
            "name": format!("{prefix}_official_doc"),
            "description": fill(contract.tools.descriptions.official_doc.as_deref().unwrap_or("")),
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "offset": {"type": "integer"},
                },
                "required": ["name"],
            },
        }));
    }
    let mut submit_properties = Map::new();
    submit_properties.insert(
        "verdict".into(),
        json!({"type": "string", "enum": ["pass", "block", "incomplete"]}),
    );
    submit_properties.insert("summary".into(), json!({"type": "string"}));
    submit_properties.insert("coverage".into(), coverage_schema(&contract.domains));
    submit_properties.insert(
        "findings".into(),
        json!({"type": "array", "items": finding_schema(contract)}),
    );
    submit_properties.insert(
        "unknowns".into(),
        json!({"type": "array", "items": {"type": "string"}}),
    );
    let mut required = vec!["verdict", "summary", "coverage", "findings", "unknowns"];
    // Money Saver advertises the per-project coverage whenever full-service is
    // offered - one submit schema shape in both modes, empty at the gate.
    // Others declare it only when a full-service review actually runs.
    let always = contract.tools.projects_coverage.as_deref() == Some("always");
    if contract.tools.full_service && (full || always) {
        let labels: &[String] = if full { projects } else { &[] };
        submit_properties.insert("projects".into(), coverage_schema(labels));
    }
    if full {
        required.push("projects");
    }
    tools.push(json!({
        "name": format!("{prefix}_submit_review"),
        "description": fill(&contract.tools.descriptions.submit),
        "parameters": {
            "type": "object",
            "properties": Value::Object(submit_properties),
            "required": required,
        },
    }));
    tools
}

#[cfg(test)]
mod tests {
    use super::{Mode, manifest};
    use crate::contract;
    use serde_json::{Value, json};
    use std::path::Path;

    fn parity_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("review-parity")
    }

    fn load_checker(name: &str) -> contract::Contract {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tools")
            .join(name);
        contract::load(&dir.join("contract.json")).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    fn golden(name: &str) -> Value {
        let raw = std::fs::read_to_string(parity_dir().join(name)).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    /// The four published contracts reproduce the Python engine's manifests
    /// exactly - the conformance property this milestone exists to pin.
    #[test]
    fn manifests_match_the_engine_goldens() {
        for checker in [
            "privacy-cleaner",
            "money-saver",
            "security-enhancer",
            "codebase-maintainer",
        ] {
            let contract = load_checker(checker);
            let produced = manifest(&contract, Mode::Gate, &[]);
            assert_eq!(
                json!(produced),
                golden(&format!("manifest-{checker}.json")),
                "{checker} gate manifest"
            );
        }
    }

    #[test]
    fn full_service_manifests_match_the_engine_goldens() {
        let projects = vec!["demo-app".to_string()];
        for checker in ["money-saver", "codebase-maintainer"] {
            let contract = load_checker(checker);
            let produced = manifest(&contract, Mode::FullService, &projects);
            assert_eq!(
                json!(produced),
                golden(&format!("manifest-{checker}-full.json")),
                "{checker} full-service manifest"
            );
        }
    }
}
