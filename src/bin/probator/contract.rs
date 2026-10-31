//! The review contract: the declarative half of an audit checker, as data.
//!
//! `docs/review-contract.schema.json` is the single contract source; this
//! module is its executable mirror. The registry validates a draft against the
//! schema at publish time, and this runtime validates the same rules before
//! executing a contract - the two must agree exactly, so every schema rule has
//! exactly one check here and the module tests pin the behaviour.

use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The evidence verbs a context tool may offer, mirrored from the schema enum.
pub const VERBS: [&str; 7] = [
    "inventory",
    "original_request",
    "list",
    "diff",
    "read",
    "find",
    "adjudication",
];
/// The git hook and forge events a checker may bind to.
pub const EVENTS: [&str; 7] = [
    "pre-commit",
    "pre-push",
    "commit-msg",
    "prepare-commit-msg",
    "pre-applypatch",
    "pr",
    "release",
];
/// The deterministic checks the runtime ships as code. A contract names them;
/// it never carries executable text. Each builtin owns one coupled scan pass
/// whose internal hit ordering and refusal priority are its semantics.
pub const BUILTINS: [&str; 6] = [
    "withheld-names-and-credentials",
    "dependency-direction",
    "workspace-hygiene",
    "static-checklist",
    "commit-identity",
    "test-key-generation",
];
/// What a regex rule's pattern applies to.
pub const RULE_TARGETS: [&str; 4] = [
    "revision-lines",
    "added-lines",
    "removed-lines",
    "changed-paths",
];
/// A checker is a blocking gate or an adviser.
pub const SEVERITIES: [&str; 2] = ["blocking", "advisory"];
/// Stage-1 labels: how the deterministic stage is announced.
pub const STAGE_LABELS: [&str; 2] = ["deterministic", "static"];

/// The declared runtime's value shape; a published profile.json is the only
/// place a provider, model or effort may come from.
pub static RUNTIME_VALUE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,79}$").unwrap()
});

/// Placeholders the runtime fills inside tool descriptions. Any other braced
/// token is a typo that would otherwise reach the model verbatim.
pub const DESCRIPTION_PLACEHOLDERS: [&str; 3] = ["read_page_lines", "diff_page_chars", "find_page"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    /// The directory the contract was loaded from: policy.md and
    /// documents.json live beside it. Not contract data.
    #[serde(skip)]
    pub dir: std::path::PathBuf,
    pub name: String,
    pub title: String,
    #[serde(default)]
    pub summary: Option<String>,
    pub domains: Vec<String>,
    pub finding_keys: Vec<String>,
    #[serde(default)]
    pub finding_optional_keys: Vec<String>,
    #[serde(default)]
    pub stage1: Option<Stage1>,
    pub on: Vec<String>,
    #[serde(default = "default_severity")]
    pub severity: String,
    pub tools: Tools,
    pub task: String,
    #[serde(default)]
    pub task_full_service: Option<String>,
    #[serde(default)]
    pub snapshot: Option<Snapshot>,
    #[serde(default)]
    pub runtime: Option<Runtime>,
}

fn default_severity() -> String {
    "blocking".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage1 {
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub surfaces: bool,
    #[serde(default)]
    pub refusal: Option<String>,
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub kind: String,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub builtin: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tools {
    pub name_prefix: String,
    pub context: Vec<String>,
    #[serde(default)]
    pub context_full_service: Option<Vec<String>>,
    pub submit: bool,
    #[serde(default)]
    pub official_documents: bool,
    #[serde(default)]
    pub full_service: bool,
    #[serde(default)]
    pub projects_coverage: Option<String>,
    #[serde(default = "default_domain_key")]
    pub domain_key: String,
    #[serde(default = "default_revision_label")]
    pub revision_label: String,
    pub descriptions: Descriptions,
}

fn default_domain_key() -> String {
    "domains".into()
}

fn default_revision_label() -> String {
    "outgoing".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptions {
    pub context: String,
    #[serde(default)]
    pub context_full_service: Option<String>,
    pub submit: String,
    #[serde(default)]
    pub official_doc: Option<String>,
    #[serde(default)]
    pub inventory_full_service: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub suffixes: Vec<String>,
    pub manifests: Vec<String>,
    #[serde(default)]
    pub exclude_names: Vec<String>,
}

/// Inert labels only - never a command, path or endpoint.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runtime {
    pub harness: String,
    pub provider: String,
    pub model: String,
    /// Ordered same-agent model fallbacks behind `model`: the session steps
    /// down the list when the active model cannot serve the turn.
    #[serde(default)]
    pub fallback_models: Vec<String>,
    /// Ordered peak/off-peak windows: the first window covering now leads
    /// the effective model chain; the declared chain trails.
    #[serde(default)]
    pub windows: Vec<RuntimeWindow>,
    /// Quota-recovery schedule handed to the orchestrator: an optional
    /// poll interval and a reset grace, each a duration string.
    #[serde(default)]
    pub retry: Option<RuntimeRetry>,
    /// Declarative reasoning-effort label passed through to the lane;
    /// what the agent does with it is the agent's business.
    #[serde(default)]
    pub effort: Option<String>,
}

/// The runtime's quota-recovery declaration: how the orchestrator should
/// schedule a retry after a fully exhausted attempt.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRetry {
    /// Poll interval for an unknown reset window — `"30m"`, `"PT1H"`.
    pub interval: Option<String>,
    /// Grace added to a known reset instant — the "3h01m" wake offset.
    pub reset_grace: Option<String>,
}

/// One peak/off-peak window: an IANA timezone name, `"HH:MM"` bounds that
/// may wrap midnight, and the model chain that leads while covered.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWindow {
    pub timezone: String,
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub models: Vec<String>,
}

// The schema's string patterns, hand-rolled: they are small ASCII classes, and
// pulling in a regex engine for five of them would be needless weight.

fn lower_digit(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit()
}

fn matches(value: &str, max: usize, first: fn(char) -> bool, rest: fn(char) -> bool) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(c) if first(c) => {}
        _ => return false,
    }
    value.chars().count() <= max && chars.all(rest)
}

/// `^[a-z0-9][a-z0-9-]{0,63}$` - the contract name.
fn is_name(value: &str) -> bool {
    matches(value, 64, lower_digit, |c| lower_digit(c) || c == '-')
}

/// `^[a-z0-9][a-z0-9_]{0,63}$` - domains and finding keys.
fn is_key(value: &str) -> bool {
    matches(value, 64, lower_digit, |c| lower_digit(c) || c == '_')
}

/// `^[a-z0-9][a-z0-9._/-]{0,63}$` - stage-1 rule ids.
fn is_rule_id(value: &str) -> bool {
    matches(value, 64, lower_digit, |c| {
        lower_digit(c) || matches!(c, '.' | '_' | '/' | '-')
    })
}

/// `^[a-z][a-z0-9_]{0,31}$` - the tool-name prefix, the revision label; with a
/// wider bound, the domain key.
fn is_label(value: &str, max: usize) -> bool {
    matches(
        value,
        max,
        |c| c.is_ascii_lowercase(),
        |c| lower_digit(c) || c == '_',
    )
}

/// `^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,79}$` - the runtime's model label.
fn is_model(value: &str) -> bool {
    matches(
        value,
        80,
        |c| c.is_ascii_alphanumeric(),
        |c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '+' | '-'),
    )
}

/// `HH:MM` with a 24-hour clock — a window bound, inert otherwise.
pub(crate) fn is_window_bound(value: &str) -> bool {
    let Some((h, m)) = value.split_once(':') else {
        return false;
    };
    let digit = |s: &str| s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit());
    digit(h)
        && digit(m)
        && h.parse::<u8>().is_ok_and(|h| h < 24)
        && m.parse::<u8>().is_ok_and(|m| m < 60)
}

/// `^\.[a-z0-9]+$` - a snapshot source suffix.
fn is_suffix(value: &str) -> bool {
    matches!(value.strip_prefix('.'), Some(rest) if !rest.is_empty() && rest.chars().all(lower_digit))
}

/// `^[A-Za-z0-9_.-]+$` - an exact file name in a snapshot contract.
fn is_file_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// `^[A-Za-z0-9._-]+$` — the runtime's harness and provider labels. The
/// provider-relative model check relies on a provider never containing '/'.
pub(crate) fn is_runtime_label(value: &str) -> bool {
    is_file_name(value)
}

/// The duplicate entries of a list, each named once.
fn duplicates(values: &[String]) -> Vec<&str> {
    let mut seen = HashSet::new();
    let mut dupes = Vec::new();
    for value in values {
        if !seen.insert(value.as_str()) && !dupes.contains(&value.as_str()) {
            dupes.push(value.as_str());
        }
    }
    dupes
}

fn check_list(
    field: &str,
    values: &[String],
    allow_empty: bool,
    shape: fn(&str) -> bool,
    issues: &mut Vec<String>,
) {
    if values.is_empty() && !allow_empty {
        issues.push(format!("{field} must name at least one entry"));
    }
    for value in values {
        if !shape(value) {
            issues.push(format!("{field} entry {value:?} has an invalid shape"));
        }
    }
    for dupe in duplicates(values) {
        issues.push(format!("{field} lists {dupe:?} twice"));
    }
}

/// Every braced token must name a placeholder the runtime fills; an unclosed
/// brace ends the scan. Anything else would reach the model verbatim.
fn check_placeholders(field: &str, text: &str, issues: &mut Vec<String>) {
    let mut rest = text;
    while let Some(at) = rest.find('{') {
        let Some(end) = rest[at..].find('}') else {
            issues.push(format!("{field} contains an unclosed {{placeholder}}"));
            return;
        };
        let token = &rest[at + 1..at + end];
        if !DESCRIPTION_PLACEHOLDERS.contains(&token) {
            issues.push(format!(
                "{field} uses unknown placeholder {{{token}}}; the runtime fills: {}",
                DESCRIPTION_PLACEHOLDERS.join(", ")
            ));
        }
        rest = &rest[at + end + 1..];
    }
}

/// A model must be an inert label inside the declared provider's namespace —
/// provider-relative (`{provider}/`), so the contract pins no vendor but a
/// chain cannot point across providers.
fn check_provider_model(field: &str, model: &str, prefix: &str, issues: &mut Vec<String>) {
    if !is_model(model) || !model.starts_with(prefix) {
        issues.push(format!(
            "{field} {model:?} must be a model in the declared provider's namespace ({prefix}…)"
        ));
    }
}

fn check_length(field: &str, value: &str, min: usize, max: usize, issues: &mut Vec<String>) {
    let length = value.chars().count();
    if length < min || length > max {
        issues.push(format!(
            "{field} must be {min}..={max} characters, is {length}"
        ));
    }
}

impl Rule {
    fn violations(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if !is_rule_id(&self.id) {
            issues.push(format!(
                "stage1 rule id {:?} must match ^[a-z0-9][a-z0-9._/-]{{0,63}}$",
                self.id
            ));
        }
        check_length(
            &format!("stage1 rule {:?} title", self.id),
            &self.title,
            1,
            160,
            &mut issues,
        );
        let absent = |issues: &mut Vec<String>, field: &str, value: &Option<String>| {
            if value.is_some() {
                issues.push(format!(
                    "stage1 rule {:?}: kind={} forbids {field}",
                    self.id, self.kind
                ));
            }
        };
        let require =
            |issues: &mut Vec<String>, field: &str, value: &Option<String>, max: usize| match value
            {
                None => issues.push(format!(
                    "stage1 rule {:?}: kind={} requires {field}",
                    self.id, self.kind
                )),
                Some(text) => check_length(
                    &format!("stage1 rule {:?} {field}", self.id),
                    text,
                    1,
                    max,
                    issues,
                ),
            };
        match self.kind.as_str() {
            "regex" => {
                require(&mut issues, "pattern", &self.pattern, 800);
                require(&mut issues, "target", &self.target, 600);
                if let Some(target) = &self.target
                    && !crate::contract::RULE_TARGETS.contains(&target.as_str())
                {
                    issues.push(format!(
                        "stage1 rule {:?}: unknown target {target:?}; the executor applies to: {}",
                        self.id,
                        crate::contract::RULE_TARGETS.join(", ")
                    ));
                }
                absent(&mut issues, "prompt", &self.prompt);
                absent(&mut issues, "builtin", &self.builtin);
            }
            "prompt" => {
                require(&mut issues, "prompt", &self.prompt, 4000);
                absent(&mut issues, "pattern", &self.pattern);
                absent(&mut issues, "target", &self.target);
                absent(&mut issues, "builtin", &self.builtin);
            }
            "builtin" => match &self.builtin {
                None => issues.push(format!(
                    "stage1 rule {:?}: kind=builtin requires a builtin name",
                    self.id
                )),
                Some(name) => {
                    if !BUILTINS.contains(&name.as_str()) {
                        issues.push(format!(
                            "stage1 rule {:?}: unknown builtin {name:?}; the runtime ships: {}",
                            self.id,
                            BUILTINS.join(", ")
                        ));
                    }
                    absent(&mut issues, "pattern", &self.pattern);
                    absent(&mut issues, "target", &self.target);
                    absent(&mut issues, "prompt", &self.prompt);
                }
            },
            other => issues.push(format!(
                "stage1 rule {:?}: unknown kind {other:?}; expected regex, prompt or builtin",
                self.id
            )),
        }
        issues
    }
}

impl Tools {
    fn violations(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if !is_label(&self.name_prefix, 32) {
            issues.push(format!(
                "tools.name_prefix {:?} must match ^[a-z][a-z0-9_]{{0,31}}$",
                self.name_prefix
            ));
        }
        check_verbs("tools.context", &self.context, &mut issues);
        if let Some(full) = &self.context_full_service {
            check_verbs("tools.context_full_service", full, &mut issues);
            if !self.full_service {
                issues.push(
                    "tools.context_full_service requires tools.full_service=true".to_string(),
                );
            }
        }
        if !self.submit {
            issues.push(
                "tools.submit must be true: a reviewer that cannot submit is not a checker".into(),
            );
        }
        if !is_label(&self.domain_key, 64) {
            issues.push(format!(
                "tools.domain_key {:?} must match ^[a-z][a-z0-9_]{{0,63}}$",
                self.domain_key
            ));
        }
        if !is_label(&self.revision_label, 32) {
            issues.push(format!(
                "tools.revision_label {:?} must match ^[a-z][a-z0-9_]{{0,31}}$",
                self.revision_label
            ));
        }
        if let Some(when) = &self.projects_coverage {
            if !["full-service", "always"].contains(&when.as_str()) {
                issues.push(format!(
                    "tools.projects_coverage {when:?} must be one of: full-service, always"
                ));
            }
            if !self.full_service {
                issues.push("tools.projects_coverage requires tools.full_service=true".to_string());
            }
        }
        let descriptions = &self.descriptions;
        check_length(
            "tools.descriptions.context",
            &descriptions.context,
            1,
            1200,
            &mut issues,
        );
        check_placeholders(
            "tools.descriptions.context",
            &descriptions.context,
            &mut issues,
        );
        check_length(
            "tools.descriptions.submit",
            &descriptions.submit,
            1,
            600,
            &mut issues,
        );
        check_placeholders(
            "tools.descriptions.submit",
            &descriptions.submit,
            &mut issues,
        );
        if let Some(full) = &descriptions.context_full_service {
            if !self.full_service {
                issues.push(
                    "tools.descriptions.context_full_service requires tools.full_service=true"
                        .into(),
                );
            }
            check_length(
                "tools.descriptions.context_full_service",
                full,
                1,
                1200,
                &mut issues,
            );
            check_placeholders("tools.descriptions.context_full_service", full, &mut issues);
        }
        match (&self.official_doc_description(), self.official_documents) {
            (None, true) => issues.push(
                "tools.descriptions.official_doc is required when official_documents=true".into(),
            ),
            (Some(_), false) => issues.push(
                "tools.descriptions.official_doc requires tools.official_documents=true".into(),
            ),
            (Some(text), true) => {
                check_length("tools.descriptions.official_doc", text, 1, 600, &mut issues);
                check_placeholders("tools.descriptions.official_doc", text, &mut issues);
            }
            (None, false) => {}
        }
        if let Some(inventory) = &self.descriptions.inventory_full_service {
            if !self.full_service {
                issues.push(
                    "tools.descriptions.inventory_full_service requires tools.full_service=true"
                        .into(),
                );
            }
            check_length(
                "tools.descriptions.inventory_full_service",
                inventory,
                1,
                1200,
                &mut issues,
            );
        }
        issues
    }

    fn official_doc_description(&self) -> Option<&String> {
        self.descriptions.official_doc.as_ref()
    }
}

fn check_verbs(field: &str, verbs: &[String], issues: &mut Vec<String>) {
    if verbs.is_empty() {
        issues.push(format!("{field} must offer at least one verb"));
    }
    for verb in verbs {
        if !VERBS.contains(&verb.as_str()) {
            issues.push(format!(
                "{field} names unknown verb {verb:?}; expected one of: {}",
                VERBS.join(", ")
            ));
        }
    }
    for dupe in duplicates(verbs) {
        issues.push(format!("{field} lists {dupe:?} twice"));
    }
}

impl Runtime {
    fn violations(&self) -> Vec<String> {
        let mut issues = Vec::new();
        for (field, value) in [("harness", &self.harness), ("provider", &self.provider)] {
            if !is_runtime_label(value) {
                issues.push(format!(
                    "runtime.{field} {value:?} must match ^[A-Za-z0-9._-]+$"
                ));
            }
        }
        // Every model the runtime names must sit in the declared provider's
        // namespace — provider-relative, so no vendor is pinned by the
        // contract but a chain cannot point across providers.
        let prefix = format!("{}/", self.provider);
        check_provider_model("runtime.model", &self.model, &prefix, &mut issues);
        for fallback in &self.fallback_models {
            check_provider_model(
                "runtime.fallback_models entry",
                fallback,
                &prefix,
                &mut issues,
            );
        }
        if let Some(retry) = &self.retry {
            for (field, duration) in [
                ("interval", &retry.interval),
                ("reset_grace", &retry.reset_grace),
            ] {
                if let Some(duration) = duration
                    && duration.parse::<jiff::SignedDuration>().is_err()
                {
                    issues.push(format!(
                        "runtime.retry.{field} {duration:?} must be a duration (\"30m\", \"PT3H1M\")"
                    ));
                }
            }
        }
        for window in &self.windows {
            if !is_window_bound(&window.from) || !is_window_bound(&window.to) {
                issues.push(format!(
                    "runtime.windows bounds {:?}..{:?} must be \"HH:MM\"",
                    window.from, window.to
                ));
            }
            if window.timezone.is_empty()
                || !window
                    .timezone
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "/_-".contains(c))
            {
                issues.push(format!(
                    "runtime.windows timezone {:?} must be an IANA zone name",
                    window.timezone
                ));
            }
            for model in window.model.iter().chain(window.models.iter()) {
                check_provider_model("runtime.windows model", model, &prefix, &mut issues);
            }
        }
        if let Some(effort) = &self.effort
            && !RUNTIME_VALUE.is_match(effort)
        {
            issues.push(format!("runtime.effort {effort:?} must be an inert label"));
        }
        issues
    }
}

impl Contract {
    /// Every schema violation, collected in one pass so a contract author sees
    /// the whole list rather than fixing one rule at a time.
    pub fn violations(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if !is_name(&self.name) {
            issues.push(format!(
                "name {:?} must match ^[a-z0-9][a-z0-9-]{{0,63}}$",
                self.name
            ));
        }
        check_length("title", &self.title, 1, 120, &mut issues);
        if let Some(summary) = &self.summary {
            check_length("summary", summary, 0, 2000, &mut issues);
        }
        check_list("domains", &self.domains, false, is_key, &mut issues);
        check_list(
            "finding_keys",
            &self.finding_keys,
            false,
            is_key,
            &mut issues,
        );
        // The runtime validates every finding's path, positive line and
        // severity enum, so a contract without these keys could never accept a
        // verdict.
        for required in ["file", "line", "severity"] {
            if !self.finding_keys.iter().any(|key| key == required) {
                issues.push(format!("finding_keys must contain {required:?}"));
            }
        }
        check_list(
            "finding_optional_keys",
            &self.finding_optional_keys,
            true,
            is_key,
            &mut issues,
        );
        for key in &self.finding_optional_keys {
            if self.finding_keys.contains(key) {
                issues.push(format!(
                    "finding_optional_keys entry {key:?} is already required by finding_keys"
                ));
            }
        }
        if let Some(stage1) = &self.stage1 {
            if let Some(label) = &stage1.label
                && !STAGE_LABELS.contains(&label.as_str())
            {
                issues.push(format!(
                    "stage1.label {label:?} must be one of: {}",
                    STAGE_LABELS.join(", ")
                ));
            }
            if let Some(refusal) = &stage1.refusal {
                check_length("stage1.refusal", refusal, 1, 300, &mut issues);
            }
            if stage1.rules.len() > 64 {
                issues.push(format!(
                    "stage1 carries {} rules; the limit is 64",
                    stage1.rules.len()
                ));
            }
            for rule in &stage1.rules {
                issues.extend(rule.violations());
            }
        }
        if self.on.is_empty() {
            issues.push("on must bind at least one event".to_string());
        }
        for event in &self.on {
            if !EVENTS.contains(&event.as_str()) {
                issues.push(format!(
                    "on names unknown event {event:?}; expected one of: {}",
                    EVENTS.join(", ")
                ));
            }
        }
        for dupe in duplicates(&self.on) {
            issues.push(format!("on lists {dupe:?} twice"));
        }
        if !SEVERITIES.contains(&self.severity.as_str()) {
            issues.push(format!(
                "severity {:?} must be one of: {}",
                self.severity,
                SEVERITIES.join(", ")
            ));
        }
        issues.extend(self.tools.violations());
        check_length("task", &self.task, 1, 4000, &mut issues);
        if let Some(task) = &self.task_full_service {
            if !self.tools.full_service {
                issues.push("task_full_service requires tools.full_service=true".to_string());
            }
            check_length("task_full_service", task, 1, 4000, &mut issues);
        }
        // The snapshot section is the full-service file contract: present
        // exactly when the mode is offered.
        match (&self.snapshot, self.tools.full_service) {
            (Some(_), false) => {
                issues.push("snapshot requires tools.full_service=true".to_string())
            }
            (None, true) => {
                issues.push("tools.full_service=true requires a snapshot file contract".to_string())
            }
            _ => {}
        }
        if let Some(snapshot) = &self.snapshot {
            for (field, values, shape) in [
                (
                    "snapshot.suffixes",
                    &snapshot.suffixes,
                    is_suffix as fn(&str) -> bool,
                ),
                (
                    "snapshot.manifests",
                    &snapshot.manifests,
                    is_file_name as fn(&str) -> bool,
                ),
                (
                    "snapshot.exclude_names",
                    &snapshot.exclude_names,
                    is_file_name as fn(&str) -> bool,
                ),
            ] {
                if values.is_empty() && field != "snapshot.exclude_names" {
                    issues.push(format!("{field} must name at least one entry"));
                }
                for value in values {
                    if !shape(value) {
                        issues.push(format!("{field} entry {value:?} has an invalid shape"));
                    }
                }
                for dupe in duplicates(values) {
                    issues.push(format!("{field} lists {dupe:?} twice"));
                }
            }
        }
        if let Some(runtime) = &self.runtime {
            issues.extend(runtime.violations());
        }
        issues
    }
}

/// Read, parse and validate a contract file. Every failure is one message:
/// unreadable file, malformed JSON, unknown field, or the violation list.
pub fn load(path: &Path) -> Result<Contract, String> {
    let raw = std::fs::read_to_string(path).map_err(|error| format!("unreadable: {error}"))?;
    let mut contract: Contract =
        serde_json::from_str(&raw).map_err(|error| format!("not a review contract: {error}"))?;
    let issues = contract.violations();
    if !issues.is_empty() {
        return Err(format!(
            "invalid review contract:\n  - {}",
            issues.join("\n  - ")
        ));
    }
    contract.dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    Ok(contract)
}

#[cfg(test)]
mod tests {
    use super::{BUILTINS, Contract, load};
    use serde_json::{Value, json};

    fn minimal() -> Value {
        json!({
            "name": "sample-checker",
            "title": "Sample Checker",
            "domains": ["structure"],
            "finding_keys": ["file", "line", "severity", "evidence"],
            "on": ["pre-push"],
            "tools": {
                "name_prefix": "sample",
                "context": ["inventory", "list", "diff", "read", "find"],
                "submit": true,
                "descriptions": {
                    "context": "Inspect the range; read is {read_page_lines} lines with start.",
                    "submit": "Submit the verdict once."
                }
            },
            "task": "Review the outgoing changes and submit one final verdict."
        })
    }

    fn parse(contract: Value) -> Contract {
        serde_json::from_value(contract).unwrap()
    }

    fn issues(contract: Value) -> Vec<String> {
        parse(contract).violations()
    }

    #[test]
    fn a_minimal_contract_is_valid() {
        assert_eq!(issues(minimal()), Vec::<String>::new());
    }

    #[test]
    fn a_full_contract_is_valid() {
        let mut contract = minimal();
        contract["summary"] = json!("A contract exercising every field.");
        contract["finding_optional_keys"] = json!(["title"]);
        contract["stage1"] = json!({
            "label": "static",
            "surfaces": true,
            "rules": [
                {"id": "no-conflict-markers", "title": "Conflict markers", "kind": "regex",
                 "pattern": "^(<{7}|={7}|>{7})", "target": "added-lines"},
                {"id": "intent", "title": "Stated intent", "kind": "prompt",
                 "prompt": "Does the change state its intent?"},
                {"id": "hygiene", "title": "Hygiene", "kind": "builtin", "builtin": "workspace-hygiene"}
            ]
        });
        contract["on"] = json!(["pre-push", "pr"]);
        contract["severity"] = json!("advisory");
        contract["tools"]["official_documents"] = json!(true);
        contract["tools"]["full_service"] = json!(true);
        contract["tools"]["context_full_service"] =
            json!(["inventory", "original_request", "list", "read", "find"]);
        contract["tools"]["domain_key"] = json!("cost_domains");
        contract["tools"]["revision_label"] = json!("staged");
        contract["tools"]["descriptions"]["context_full_service"] = json!("Inspect the snapshot.");
        contract["tools"]["descriptions"]["official_doc"] =
            json!("Fetch an official reference by key.");
        contract["tools"]["descriptions"]["inventory_full_service"] =
            json!("Read the charter first.");
        contract["snapshot"] = json!({"suffixes": [".rs"], "manifests": ["Cargo.toml"]});
        contract["task_full_service"] = json!("Perform the assigned full-service audit.");
        contract["runtime"] = json!({
            "harness": "agent-host", "provider": "acme",
            "model": "acme/reviewer-2", "effort": "high",
            "fallback_models": ["acme/reviewer-1"],
            "windows": [{"timezone": "Asia/Shanghai", "from": "09:00", "to": "18:00",
                         "model": "acme/reviewer-peak"}],
            "retry": {"interval": "30m", "reset_grace": "3h01m"}
        });
        assert_eq!(issues(contract), Vec::<String>::new());
    }

    #[test]
    fn names_domains_and_keys_keep_their_shapes() {
        let mut contract = minimal();
        contract["name"] = json!("Bad_Name");
        contract["domains"] = json!(["-bad", "structure", "structure"]);
        contract["finding_keys"] = json!(["file", "line", "severity", "Bad Key"]);
        let found = issues(contract);
        assert!(found.iter().any(|i| i.contains("name \"Bad_Name\"")));
        assert!(found.iter().any(|i| i.contains("domains entry \"-bad\"")));
        assert!(
            found
                .iter()
                .any(|i| i.contains("lists \"structure\" twice"))
        );
        assert!(
            found
                .iter()
                .any(|i| i.contains("finding_keys entry \"Bad Key\""))
        );
    }

    #[test]
    fn the_engine_finding_invariants_are_required() {
        let mut contract = minimal();
        contract["finding_keys"] = json!(["file", "evidence"]);
        let found = issues(contract);
        assert!(found.iter().any(|i| i.contains("must contain \"line\"")));
        assert!(
            found
                .iter()
                .any(|i| i.contains("must contain \"severity\""))
        );
    }

    #[test]
    fn optional_keys_must_not_duplicate_required_ones() {
        let mut contract = minimal();
        contract["finding_optional_keys"] = json!(["file", "title"]);
        let found = issues(contract);
        assert_eq!(
            found,
            vec![
                "finding_optional_keys entry \"file\" is already required by finding_keys"
                    .to_string()
            ]
        );
    }

    #[test]
    fn stage1_rules_enforce_the_kind_contract() {
        let mut contract = minimal();
        contract["stage1"] = json!({
            "label": "elaborate",
            "rules": [
                {"id": "Bad Id", "title": "x", "kind": "regex", "pattern": "a"},
                {"id": "ok-prompt", "title": "x", "kind": "prompt", "prompt": "Judge?", "target": "added lines"},
                {"id": "bad-builtin", "title": "x", "kind": "builtin", "builtin": "time-travel"},
                {"id": "mystery", "title": "x", "kind": "vibes"}
            ]
        });
        let found = issues(contract);
        assert!(found.iter().any(|i| i.contains("stage1.label")));
        assert!(found.iter().any(|i| i.contains("rule id \"Bad Id\"")));
        assert!(
            found
                .iter()
                .any(|i| i.contains("kind=regex requires target"))
        );
        assert!(
            found
                .iter()
                .any(|i| i.contains("kind=prompt forbids target"))
        );
        assert!(
            found
                .iter()
                .any(|i| i.contains("unknown builtin \"time-travel\""))
        );
        assert!(found.iter().any(|i| i.contains("unknown kind \"vibes\"")));
    }

    #[test]
    fn events_and_severity_are_closed_vocabularies() {
        let mut contract = minimal();
        contract["on"] = json!(["pre-push", "pre-push", "whenever"]);
        contract["severity"] = json!("grumpy");
        let found = issues(contract);
        assert!(
            found
                .iter()
                .any(|i| i.contains("on lists \"pre-push\" twice"))
        );
        assert!(
            found
                .iter()
                .any(|i| i.contains("unknown event \"whenever\""))
        );
        assert!(found.iter().any(|i| i.contains("severity \"grumpy\"")));
    }

    #[test]
    fn tool_surface_rules_hold() {
        let mut contract = minimal();
        contract["tools"]["name_prefix"] = json!("has-dash-");
        contract["tools"]["context"] = json!(["inventory", "inventory", "execute"]);
        contract["tools"]["context_full_service"] = json!(["inventory"]);
        contract["tools"]["revision_label"] = json!("Staged");
        contract["tools"]["projects_coverage"] = json!("always");
        let found = issues(contract);
        assert!(
            found
                .iter()
                .any(|i| i.contains("name_prefix \"has-dash-\""))
        );
        assert!(
            found
                .iter()
                .any(|i| i.contains("lists \"inventory\" twice"))
        );
        assert!(found.iter().any(|i| i.contains("unknown verb \"execute\"")));
        assert!(
            found
                .iter()
                .any(|i| i.contains("context_full_service requires tools.full_service"))
        );
        assert!(
            found
                .iter()
                .any(|i| i.contains("revision_label \"Staged\""))
        );
        assert!(
            found
                .iter()
                .any(|i| i.contains("projects_coverage requires tools.full_service"))
        );
    }

    #[test]
    fn official_document_description_is_conditional() {
        let mut without_flag = minimal();
        without_flag["tools"]["descriptions"]["official_doc"] = json!("Fetch a reference.");
        assert!(
            issues(without_flag)
                .iter()
                .any(|i| i.contains("official_doc requires tools.official_documents=true"))
        );
        let mut with_flag = minimal();
        with_flag["tools"]["official_documents"] = json!(true);
        assert!(
            issues(with_flag)
                .iter()
                .any(|i| i.contains("official_doc is required when official_documents=true"))
        );
    }

    #[test]
    fn description_placeholders_are_a_known_set() {
        let mut contract = minimal();
        contract["tools"]["descriptions"]["context"] =
            json!("read is {read_page_line} lines, diff is {diff_page_chars} chars, brace {oops");
        let found = issues(contract);
        assert!(
            found
                .iter()
                .any(|i| i.contains("unknown placeholder {read_page_line}"))
        );
        assert!(
            found
                .iter()
                .any(|i| i.contains("an unclosed {placeholder}"))
        );
        assert!(
            !found
                .iter()
                .any(|i| i.contains("unknown placeholder {diff_page_chars}"))
        );
    }

    #[test]
    fn lengths_are_bounded() {
        let mut contract = minimal();
        contract["title"] = json!("x".repeat(121));
        contract["summary"] = json!("x".repeat(2001));
        contract["task"] = json!("");
        let found = issues(contract);
        assert!(found.iter().any(|i| i.contains("title must be 1..=120")));
        assert!(found.iter().any(|i| i.contains("summary must be 0..=2000")));
        assert!(found.iter().any(|i| i.contains("task must be 1..=4000")));
    }

    #[test]
    fn the_runtime_is_inert_labels_only() {
        let mut contract = minimal();
        contract["runtime"] = json!({
            "harness": "bad harness", "provider": "acme",
            "model": "acme/ok-model", "effort": "not a label"
        });
        let found = issues(contract);
        assert!(found.iter().any(|i| i.contains("runtime.harness")));
        assert!(found.iter().any(|i| i.contains("runtime.effort")));
        assert!(!found.iter().any(|i| i.contains("runtime.provider")));
        assert!(!found.iter().any(|i| i.contains("runtime.model")));
    }

    #[test]
    fn runtime_models_stay_in_the_declared_provider() {
        let mut contract = minimal();
        contract["runtime"] = json!({
            "harness": "agent", "provider": "acme",
            "model": "other/model",
            "fallback_models": ["acme/ok", "other/fallback"],
            "windows": [{"timezone": "UTC", "from": "09:00", "to": "18:00",
                         "model": "other/peak"}]
        });
        let found = issues(contract);
        assert!(found.iter().any(|i| i.contains("runtime.model")));
        assert!(found.iter().any(|i| i.contains("runtime.fallback_models")));
        assert!(found.iter().any(|i| i.contains("runtime.windows model")));
        // Only the cross-provider entries are refused, not the whole chain.
        assert_eq!(
            found
                .iter()
                .filter(|i| i.contains("fallback_models"))
                .count(),
            1
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut contract = minimal();
        contract["surprise"] = json!(true);
        assert!(serde_json::from_value::<Contract>(contract).is_err());
    }

    #[test]
    fn load_reads_validates_and_reports() {
        let dir = std::env::temp_dir().join(format!("gv-contract-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let valid = dir.join("contract.json");
        std::fs::write(&valid, serde_json::to_string_pretty(&minimal()).unwrap()).unwrap();
        assert_eq!(load(&valid).unwrap().name, "sample-checker");
        let broken = dir.join("broken.json");
        std::fs::write(&broken, "{\"name\": ").unwrap();
        let message = load(&broken).unwrap_err();
        assert!(message.contains("not a review contract"), "{message}");
        let invalid = dir.join("invalid.json");
        let mut bad = minimal();
        bad["on"] = json!([]);
        std::fs::write(&invalid, serde_json::to_string(&bad).unwrap()).unwrap();
        let message = load(&invalid).unwrap_err();
        assert!(message.contains("invalid review contract"), "{message}");
        assert!(
            message.contains("on must bind at least one event"),
            "{message}"
        );
        assert!(
            load(&dir.join("missing.json"))
                .unwrap_err()
                .contains("unreadable")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The published schema and the runtime's builtin registry must declare
    /// the same deterministic checks: a contract naming a builtin the schema
    /// omits is rejected by consumers validating against it. Every shipped
    /// contract is loaded and its stage-1 builtins checked against the
    /// schema's enum.
    #[test]
    fn shipped_contracts_follow_the_published_schema() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let schema: Value = serde_json::from_str(
            &std::fs::read_to_string(root.join("docs/review-contract.schema.json")).unwrap(),
        )
        .unwrap();

        fn find_builtin_enum(node: &Value) -> Option<Vec<String>> {
            match node {
                Value::Object(map) => {
                    if let Some(variants) = map.get("enum").and_then(Value::as_array)
                        && variants
                            .iter()
                            .any(|v| v.as_str() == Some("commit-identity"))
                    {
                        return Some(
                            variants
                                .iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .collect(),
                        );
                    }
                    map.values().find_map(find_builtin_enum)
                }
                Value::Array(items) => items.iter().find_map(find_builtin_enum),
                _ => None,
            }
        }
        let schema_builtins: std::collections::BTreeSet<_> = find_builtin_enum(&schema)
            .expect("schema declares no builtin enum")
            .into_iter()
            .collect();
        let runtime_builtins: std::collections::BTreeSet<_> =
            BUILTINS.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            schema_builtins, runtime_builtins,
            "schema builtin enum and runtime registry disagree"
        );

        let tools = root.join("tools");
        let mut shipped = 0;
        for entry in std::fs::read_dir(&tools).unwrap() {
            let contract_path = entry.unwrap().path().join("contract.json");
            if !contract_path.is_file() {
                continue;
            }
            shipped += 1;
            let contract = load(&contract_path).unwrap();
            if let Some(stage1) = &contract.stage1 {
                for rule in &stage1.rules {
                    if let Some(builtin) = &rule.builtin {
                        assert!(
                            schema_builtins.contains(builtin),
                            "{}: builtin {builtin:?} is not in the published schema",
                            contract.name
                        );
                    }
                }
            }
        }
        assert!(shipped > 0, "no shipped contracts under tools/");
    }
}
