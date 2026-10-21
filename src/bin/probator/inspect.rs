//! Self-inspection: render the policy Probator actually enforces.
//!
//! Everything shown is read from the installed configuration - the signed
//! checkers.toml rows, each installed contract.json, its sibling policy.md
//! and registry.json. Nothing about the checks is hardcoded here; if a
//! contract changes, this output changes with it. The domain descriptions
//! come from policy.md prose, and bullets that name no registered domain are
//! surfaced as orphans - a checklist/policy divergence the contract cannot
//! enforce on its own.

use serde_json::Value;
use std::path::{Path, PathBuf};

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn toml_strings(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// A policy bullet's head token, normalized for matching: `**privacy**` ->
/// `privacy`, `Storage/files` -> `storage`, `VPS` -> `vps`.
fn bullet_key(head: &str) -> String {
    head.trim_matches(|c: char| "*_` ".contains(c))
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .next()
        .unwrap_or("")
        .to_lowercase()
}

/// A heading's candidate domain key: `## Repository scope` normalizes to
/// `repository_scope`, `## Tooling hygiene` to `tooling`. The last resort is
/// a long shared prefix (`hardcoded` vs `hardcoding`).
fn heading_key(heading: &str, domains: &[String]) -> Option<usize> {
    let lowered: Vec<String> = domains.iter().map(|d| d.to_lowercase()).collect();
    let whole: String = heading
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let whole = whole.trim_matches('_');
    if let Some(at) = lowered.iter().position(|d| d == whole) {
        return Some(at);
    }
    let first = heading
        .split_whitespace()
        .next()
        .map(|w| {
            w.trim_matches(|c: char| !c.is_ascii_alphanumeric())
                .to_lowercase()
        })
        .unwrap_or_default();
    lowered.iter().position(|d| {
        d == &first
            || (first.len() >= 6
                && d.len() >= 6
                && first
                    .chars()
                    .zip(d.chars())
                    .take_while(|(a, b)| a == b)
                    .count()
                    >= 6)
    })
}

/// Pair contract domains with the prose that defines them. Definitions come
/// from `**key**:`/`Key:` bullets first, then from section headings whose
/// title names a domain - some policies define their standing items as
/// sections rather than bullets. Bullets whose label matches nothing are
/// orphans: checks the policy describes but submit cannot require.
fn flush_bullet(
    bullet: Option<String>,
    lowered: &[String],
    defs: &mut [Option<String>],
    orphans: &mut Vec<(String, String)>,
) {
    let Some(text) = bullet else { return };
    let Some(colon) = text.find(':') else { return };
    let (head, rest) = text.split_at(colon);
    let head = head.trim_matches(|c: char| "*_` ".contains(c));
    // A label is a short single token; a sentence containing a colon is
    // prose, not a definition.
    if head.is_empty() || head.len() > 40 || head.contains(char::is_whitespace) {
        return;
    }
    let key = bullet_key(head);
    let body = rest[1..].trim().replace('\n', " ");
    if let Some(at) = lowered.iter().position(|d| d == &key) {
        if defs[at].is_none() {
            defs[at] = Some(body);
        }
    } else {
        orphans.push((key, body));
    }
}

fn flush_section(heading: &str, section: &str, domains: &[String], defs: &mut [Option<String>]) {
    let Some(at) = heading_key(heading, domains) else {
        return;
    };
    if defs[at].is_some() {
        return;
    }
    // The section's first paragraph is the definition.
    let lead: String = section
        .trim()
        .split("\n\n")
        .next()
        .unwrap_or("")
        .split('\n')
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('-'))
        .collect::<Vec<_>>()
        .join(" ");
    if !lead.is_empty() {
        defs[at] = Some(lead.chars().take(400).collect());
    }
}

fn extract_definitions(
    policy: &str,
    domains: &[String],
) -> (Vec<Option<String>>, Vec<(String, String)>) {
    let mut defs: Vec<Option<String>> = vec![None; domains.len()];
    let mut orphans = Vec::new();
    let lowered: Vec<String> = domains.iter().map(|d| d.to_lowercase()).collect();
    let mut bullet: Option<String> = None;
    let mut heading = String::new();
    let mut section = String::new();
    for line in policy.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            flush_bullet(bullet.take(), &lowered, &mut defs, &mut orphans);
            flush_section(&heading, &section, domains, &mut defs);
            heading = trimmed.trim_start_matches('#').trim().to_string();
            section.clear();
            continue;
        }
        if trimmed.starts_with("- ") || trimmed.starts_with("* ") {
            flush_bullet(bullet.take(), &lowered, &mut defs, &mut orphans);
            bullet = Some(trimmed[2..].to_string());
        } else if let Some(b) = &mut bullet {
            if trimmed.is_empty() {
                flush_bullet(bullet.take(), &lowered, &mut defs, &mut orphans);
            } else {
                b.push(' ');
                b.push_str(trimmed);
            }
        }
        section.push_str(trimmed);
        section.push('\n');
    }
    flush_bullet(bullet.take(), &lowered, &mut defs, &mut orphans);
    flush_section(&heading, &section, domains, &mut defs);
    (defs, orphans)
}

struct Checker {
    name: String,
    title: String,
    summary: String,
    on: Vec<String>,
    severity: String,
    command: Vec<String>,
    profiles: Vec<(String, String, String)>,
    domains: Vec<(String, Option<String>)>,
    stage1: Vec<(String, String, String)>,
    finding_keys: Vec<String>,
    task: String,
    orphans: Vec<(String, String)>,
    policy_md: Option<String>,
    contract: PathBuf,
}

fn load_checker(row: &toml::Value, profiles: &Path) -> Checker {
    let name = row
        .get("name")
        .and_then(toml::Value::as_str)
        .unwrap_or("?")
        .to_string();
    let on = toml_strings(row.get("on"));
    let severity = row
        .get("severity")
        .and_then(toml::Value::as_str)
        .unwrap_or("?")
        .to_string();
    let command: Vec<String> = row
        .get("command")
        .and_then(toml::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    // The contract path is read out of the registered command, not guessed -
    // the row is what actually runs.
    let declared = command
        .iter()
        .position(|a| a == "--contract")
        .and_then(|i| command.get(i + 1))
        .map(PathBuf::from);
    let contract = declared.unwrap_or_else(|| {
        profiles
            .join(&name)
            .join("plugins")
            .join(&name)
            .join("contract.json")
    });
    let dir = contract.parent().map(Path::to_path_buf).unwrap_or_default();
    let doc = read_json(&contract);

    let domains: Vec<String> = doc
        .as_ref()
        .map(|c| strings(c.get("domains")))
        .unwrap_or_default();
    let policy_md = std::fs::read_to_string(dir.join("policy.md")).ok();
    let (defs, orphans) = policy_md
        .as_deref()
        .map(|p| extract_definitions(p, &domains))
        .unwrap_or_else(|| (vec![None; domains.len()], Vec::new()));

    let registry = read_json(&dir.join("registry.json"));
    let mut profiles_list = Vec::new();
    if let Some(map) = registry
        .as_ref()
        .and_then(|r| r.get("profiles"))
        .and_then(Value::as_object)
    {
        for (profile, spec) in map {
            profiles_list.push((
                profile.clone(),
                spec.get("agent")
                    .and_then(Value::as_str)
                    .unwrap_or("?")
                    .to_string(),
                spec.get("model")
                    .and_then(Value::as_str)
                    .unwrap_or("(default)")
                    .to_string(),
            ));
        }
    }

    let stage1 = doc
        .as_ref()
        .and_then(|c| c.get("stage1"))
        .and_then(|s| s.get("rules"))
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .map(|r| {
                    (
                        r.get("id")
                            .and_then(Value::as_str)
                            .unwrap_or("?")
                            .to_string(),
                        r.get("title")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        r.get("kind")
                            .and_then(Value::as_str)
                            .unwrap_or("builtin")
                            .to_string(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    Checker {
        name: name.clone(),
        title: doc
            .as_ref()
            .and_then(|c| c.get("title"))
            .and_then(Value::as_str)
            .unwrap_or(&name)
            .to_string(),
        summary: doc
            .as_ref()
            .and_then(|c| c.get("summary"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        on,
        severity,
        command,
        profiles: profiles_list,
        domains: domains.into_iter().zip(defs).collect(),
        stage1,
        finding_keys: doc
            .as_ref()
            .map(|c| strings(c.get("finding_keys")))
            .unwrap_or_default(),
        task: doc
            .as_ref()
            .and_then(|c| c.get("task"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        orphans,
        policy_md,
        contract,
    }
}

fn load_all(policy_file: &Path, profiles: &Path) -> Result<Vec<Checker>, String> {
    let raw = std::fs::read_to_string(policy_file)
        .map_err(|e| format!("cannot read {}: {e}", policy_file.display()))?;
    let doc: toml::Value =
        toml::from_str(&raw).map_err(|e| format!("bad {}: {e}", policy_file.display()))?;
    let rows = doc
        .get("checkers")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if rows.is_empty() {
        return Err(format!("{} registers no checkers", policy_file.display()));
    }
    Ok(rows.iter().map(|row| load_checker(row, profiles)).collect())
}

fn esc(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn html(checkers: &[Checker], policy_file: &Path) -> String {
    let mut out = String::from(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>Probator policy</title><style>
body{font:14px/1.55 -apple-system,"SF Pro Text",sans-serif;max-width:960px;margin:2em auto;padding:0 1.5em;color:#1d1d1f}
h1{font-size:1.6em;border-bottom:2px solid #333;padding-bottom:.3em}
.checker{border:1px solid #d2d2d7;border-radius:10px;margin:1.4em 0;padding:1em 1.4em}
.checker h2{margin:.1em 0;font-size:1.25em}
.meta{color:#6e6e73;font-size:.86em;margin:.3em 0 1em}
.badge{display:inline-block;background:#f5f5f7;border:1px solid #d2d2d7;border-radius:6px;padding:1px 8px;margin:1px 3px 1px 0;font-size:.8em;font-family:ui-monospace,monospace}
table{border-collapse:collapse;width:100%;margin:.5em 0}
td,th{border-bottom:1px solid #e8e8ed;padding:5px 8px;text-align:left;vertical-align:top}
td.k{font-family:ui-monospace,monospace;white-space:nowrap;font-weight:600}
.undef{color:#b0b0b8;font-style:italic}
.orphan{background:#fff4e5;border-left:3px solid #e08000;padding:.5em .8em;margin:.6em 0}
summary{cursor:pointer;color:#0066cc;font-weight:600}
pre{background:#f5f5f7;padding:.7em;border-radius:8px;overflow-x:auto;font-size:.85em}
.policy{font-size:.9em}
.policy h1,.policy h2,.policy h3{margin:.8em 0 .3em}
.policy code{background:#f5f5f7;padding:0 4px;border-radius:4px}
footer{color:#aeaeb2;font-size:.8em;margin-top:2em;border-top:1px solid #e8e8ed;padding-top:.6em}
</style></head><body>"#,
    );
    out.push_str(&format!(
        "<h1>Probator policy — {} checkers</h1><p class=\"meta\">read from {} · every domain below is enforced at submit time (coverage keys must equal the registered set)</p>",
        checkers.len(),
        esc(&policy_file.display().to_string())
    ));
    for c in checkers {
        out.push_str(&format!(
            "<div class=\"checker\"><h2>{}</h2><p class=\"meta\"><span class=\"badge\">{}</span>{} · {} domain(s) · contract: {}</p>",
            esc(&c.title),
            esc(&c.severity),
            c.on.iter().map(|e| format!("<span class=\"badge\">{}</span>", esc(e))).collect::<String>(),
            c.domains.len(),
            esc(&c.contract.display().to_string())
        ));
        if !c.summary.is_empty() {
            out.push_str(&format!("<p>{}</p>", esc(&c.summary)));
        }
        if !c.profiles.is_empty() {
            out.push_str("<p class=\"meta\">profiles: ");
            for (p, agent, model) in &c.profiles {
                out.push_str(&format!(
                    "<span class=\"badge\">{p}: {agent}/{model}</span>"
                ));
            }
            out.push_str("</p>");
        }
        if !c.stage1.is_empty() {
            out.push_str("<h3>Stage 1 — deterministic (refuses before the model runs)</h3><table>");
            for (id, title, kind) in &c.stage1 {
                out.push_str(&format!(
                    "<tr><td class=\"k\">{}</td><td>{}</td><td>{}</td></tr>",
                    esc(id),
                    esc(title),
                    esc(kind)
                ));
            }
            out.push_str("</table>");
        }
        out.push_str("<h3>Domains — every one requires a coverage verdict</h3><table><tr><th>domain</th><th>definition (policy.md)</th></tr>");
        for (key, def) in &c.domains {
            let body = def.as_deref().map(esc).unwrap_or_else(|| {
                "<span class=\"undef\">no matching bullet in policy.md</span>".into()
            });
            out.push_str(&format!(
                "<tr><td class=\"k\">{}</td><td>{}</td></tr>",
                esc(key),
                body
            ));
        }
        out.push_str("</table>");
        if !c.orphans.is_empty() {
            out.push_str(&format!(
                "<div class=\"orphan\"><b>{} policy bullet(s) name no registered domain</b> — submit does not require a verdict for these:<ul>",
                c.orphans.len()
            ));
            for (key, body) in &c.orphans {
                out.push_str(&format!(
                    "<li><code>{}</code>: {}</li>",
                    esc(key),
                    esc(body)
                ));
            }
            out.push_str("</ul></div>");
        }
        if !c.finding_keys.is_empty() {
            out.push_str(&format!(
                "<p class=\"meta\">required finding fields: {}</p>",
                c.finding_keys
                    .iter()
                    .map(|k| format!("<span class=\"badge\">{}</span>", esc(k)))
                    .collect::<String>()
            ));
        }
        if !c.task.is_empty() {
            out.push_str(&format!("<h3>Task prompt</h3><pre>{}</pre>", esc(&c.task)));
        }
        if let Some(policy) = &c.policy_md {
            let mut rendered = String::new();
            pulldown_cmark::html::push_html(&mut rendered, pulldown_cmark::Parser::new(policy));
            out.push_str(&format!("<details><summary>policy.md (verbatim)</summary><div class=\"policy\">{rendered}</div></details>"));
        }
        out.push_str("</div>");
    }
    out.push_str(
        "<footer>generated by <code>probator inspect --html</code></footer></body></html>",
    );
    out
}

pub fn run(
    policy_file: &Path,
    profiles: &Path,
    json: bool,
    html_out: Option<&Path>,
) -> Result<i32, String> {
    let checkers = load_all(policy_file, profiles)?;
    if let Some(path) = html_out {
        std::fs::write(path, html(&checkers, policy_file))
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        println!("wrote {}", path.display());
        return Ok(0);
    }
    if json {
        let out: Vec<Value> = checkers
            .iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.name, "title": c.title, "summary": c.summary,
                    "on": c.on, "severity": c.severity, "command": c.command,
                    "contract": c.contract.display().to_string(),
                    "profiles": c.profiles.iter().map(|(p,a,m)| serde_json::json!({"profile":p,"agent":a,"model":m})).collect::<Vec<_>>(),
                    "stage1": c.stage1.iter().map(|(i,t,k)| serde_json::json!({"id":i,"title":t,"kind":k})).collect::<Vec<_>>(),
                    "domains": c.domains.iter().map(|(k,d)| serde_json::json!({"key":k,"definition":d})).collect::<Vec<_>>(),
                    "finding_keys": c.finding_keys, "task": c.task,
                    "orphan_bullets": c.orphans.iter().map(|(k,b)| serde_json::json!({"key":k,"text":b})).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
        );
        return Ok(0);
    }
    println!(
        "{} — {} checkers registered\n",
        policy_file.display(),
        checkers.len()
    );
    for c in &checkers {
        println!(
            "{}  [{} · {} · {} domain(s)]",
            c.title,
            c.severity,
            c.on.join(","),
            c.domains.len()
        );
        if !c.profiles.is_empty() {
            println!(
                "  profiles: {}",
                c.profiles
                    .iter()
                    .map(|(p, a, m)| format!("{p}:{a}/{m}"))
                    .collect::<Vec<_>>()
                    .join("  ")
            );
        }
        for (id, title, _) in &c.stage1 {
            println!("  stage1  {id}: {title}");
        }
        for (key, def) in &c.domains {
            let short = def
                .as_deref()
                .map(|d| d.chars().take(90).collect::<String>())
                .unwrap_or_else(|| "(no policy bullet)".into());
            println!("  domain  {key:<26} {short}");
        }
        for (key, body) in &c.orphans {
            println!(
                "  orphan  {key:<26} {} (no domain key)",
                body.chars().take(70).collect::<String>()
            );
        }
        println!();
    }
    Ok(0)
}
