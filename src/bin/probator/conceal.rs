//! Session concealment by recorded ID. Every audit run keeps an
//! `audit-session.json` — `session_id` for resume, `session_ids` for every
//! conversation the run ever opened (stale-resume retries and fallback lanes
//! included). Once the run is done, those sessions have served their turn:
//! the sweep marks them archived in each admitted agent's store so they leave
//! the operator's session list while staying resumable. Neither admitted
//! agent exposes an archive verb over its lane (`devin rm` deletes,
//! opencode's serve update ignores `time.archived`), so the sweep flips each
//! store's native list flag directly: `hidden` on devin's sessions.db,
//! `time_archived` on opencode's session_v2, and
//! `info._meta."cognition.ai/isArchived"` plus membership in the
//! `archivedSessions` list on the Devin desktop's globalStorage index — the
//! sidebar renders that index, not the CLI database, and its Archived filter
//! consults the list. Concealment is best-effort housekeeping: a missing store or a
//! refused write warns on stderr and never fails the gate.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

/// The desktop session-index record name for a devin-cli conversation.
const VSCDB_KEY: &str = "windsurf.acp.sessioninfo.session.acp/devin-cli/";

/// The desktop database and the archive-list key the sidebar filter actually
/// consults: session rows render unless their `acp/devin-cli/<id>` appears in
/// this JSON array. The per-row `isArchived` flag alone does not hide them.
const VSCDB_DB: &str = "Library/Application Support/Devin/User/globalStorage/state.vscdb";
const ARCHIVED_KEY: &str = "windsurf.acp.session/archivedSessions";

/// One harness session store: the database path under `$HOME`, the table
/// holding sessions, and the SQL boolean selecting recorded sessions.
struct Store {
    db: &'static str,
    table: &'static str,
    /// Row predicate over the recorded ids, e.g. `id IN ('a','b')`.
    match_: fn(ids: &BTreeSet<String>) -> String,
    /// The archive flag assignment for a concealed row.
    set: fn(now_ms: i64) -> String,
    /// The predicate keeping already-concealed rows untouched.
    pending: &'static str,
}

fn ids_in(ids: &BTreeSet<String>) -> String {
    format!("id IN ({})", quote_all(ids.iter()))
}

fn keys_in(ids: &BTreeSet<String>) -> String {
    let keys = ids.iter().map(|id| format!("{VSCDB_KEY}{id}"));
    format!("key IN ({})", quote_all(keys))
}

fn quote_all<'a>(values: impl Iterator<Item = impl AsRef<str> + 'a>) -> String {
    values
        .map(|value| format!("'{}'", value.as_ref().replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",")
}

const STORES: &[Store] = &[
    Store {
        db: ".local/share/opencode/opencode.db",
        table: "session_v2",
        match_: ids_in,
        set: |now_ms| format!("time_archived = {now_ms}"),
        pending: "time_archived IS NULL",
    },
    Store {
        db: ".local/share/devin/cli/sessions.db",
        table: "sessions",
        match_: ids_in,
        set: |_| "hidden = 1".to_string(),
        pending: "hidden IS NOT 1",
    },
    Store {
        db: VSCDB_DB,
        table: "ItemTable",
        match_: keys_in,
        set: |_| {
            "value = json_set(value, '$.info._meta.\"cognition.ai/isArchived\"', json('true'))"
                .to_string()
        },
        pending: "json_extract(value, '$.info._meta.\"cognition.ai/isArchived\"') IS NOT 1",
    },
];

/// Archive every finished run's recorded sessions in each admitted agent's
/// store: one UPDATE per store over the collected id list. `profiles_root`
/// is `~/.local/share/probator/profiles`; every `*-runs` directory beneath
/// it contributes, so a checker skipped by an earlier phase's refusal still
/// gets its backlog swept by whichever checker does run. Run directories
/// holding a `live` marker whose recorded pid is still running are in
/// flight — their sessions stay untouched until the run really ends.
pub fn run_sessions(profiles_root: &Path) {
    let ids = recorded_ids(profiles_root);
    if ids.is_empty() {
        return;
    }
    let Some(home) = std::env::var_os("HOME") else {
        return;
    };
    let now_ms = jiff::Zoned::now().timestamp().as_millisecond();
    for store in STORES {
        let db = Path::new(&home).join(store.db);
        if !db.is_file() {
            continue;
        }
        // The desktop and the harnesses hold their stores open; wait out a
        // transient writer instead of refusing on `database is locked`.
        let sql = format!(
            "PRAGMA busy_timeout = 15000; UPDATE {} SET {} WHERE {} AND {};",
            store.table,
            (store.set)(now_ms),
            (store.match_)(&ids),
            store.pending
        );
        if let Err(error) = run_sql(&db, &sql) {
            eprintln!("conceal: {} refused: {error}", db.display());
        }
    }
    archive_list(&Path::new(&home).join(VSCDB_DB), &ids);
}

/// One sqlite3 invocation, best-effort: the harnesses hold their stores
/// open so a refused write only earns a stderr note, never a gate failure.
fn run_sql(db: &Path, sql: &str) -> Result<String, String> {
    match Command::new("sqlite3").arg(db).arg(sql).output() {
        Ok(out) if out.status.success() => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
        Ok(out) => Err(String::from_utf8_lossy(&out.stderr).trim().to_string()),
        Err(error) => Err(error.to_string()),
    }
}

/// Merge the recorded ids into the desktop's `archivedSessions` list — the
/// single source the session list's Archived filter subtracts. One row, one
/// array: insert it when absent, union it otherwise.
fn archive_list(db: &Path, ids: &BTreeSet<String>) {
    if !db.is_file() {
        return;
    }
    // Only devin-cli lane ids belong under the `acp/devin-cli/` key shape —
    // intersect the recorded ids with the session-index keys actually
    // present so another lane's ids never become dead list entries.
    let known_out = run_sql(
        db,
        &format!(
            "PRAGMA busy_timeout = 15000; SELECT key FROM ItemTable WHERE {};",
            keys_in(ids)
        ),
    )
    .unwrap_or_default();
    let known: BTreeSet<&str> = known_out.lines().map(str::trim).collect();
    // The lane prefix is the tail of the sessioninfo key: one source.
    let lane = VSCDB_KEY.trim_start_matches("windsurf.acp.sessioninfo.session.");
    let members: Vec<String> = ids
        .iter()
        .filter(|id| known.contains(format!("{VSCDB_KEY}{id}").as_str()))
        .map(|id| format!("{lane}{id}"))
        .collect();
    if members.is_empty() {
        return;
    }
    let new_ids = serde_json::to_string(&members)
        .unwrap_or_default()
        .replace('\'', "''");
    let sql = format!(
        "PRAGMA busy_timeout = 15000;
         INSERT INTO ItemTable (key, value)
             SELECT '{ARCHIVED_KEY}', '{new_ids}'
             WHERE NOT EXISTS (SELECT 1 FROM ItemTable WHERE key = '{ARCHIVED_KEY}');
         UPDATE ItemTable SET value = (
             SELECT json_group_array(value) FROM (
                 SELECT value FROM json_each(ItemTable.value)
                 UNION SELECT value FROM json_each('{new_ids}')))
         WHERE key = '{ARCHIVED_KEY}';"
    );
    if let Err(error) = run_sql(db, &sql) {
        eprintln!("conceal: {} refused: {error}", db.display());
    }
}

/// Every session id recorded under `profiles_root`: walk each checker's
/// `*-runs` directory, skip runs still in flight, and read each finished
/// run's `audit-session.json` — `session_ids` (all conversations the run
/// opened) plus the scalar `session_id` for files written before the list
/// field existed.
fn recorded_ids(profiles_root: &Path) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let Ok(profiles) = std::fs::read_dir(profiles_root) else {
        return ids;
    };
    for profile in profiles.flatten() {
        let Ok(members) = std::fs::read_dir(profile.path()) else {
            continue;
        };
        for member in members.flatten() {
            let runs_dir = member.path();
            if !runs_dir.is_dir()
                || member
                    .file_name()
                    .to_str()
                    .is_none_or(|n| !n.ends_with("-runs"))
            {
                continue;
            }
            let Ok(runs) = std::fs::read_dir(&runs_dir) else {
                continue;
            };
            for run in runs.flatten() {
                let dir = run.path();
                if in_flight(&dir) {
                    continue;
                }
                let Ok(raw) = std::fs::read_to_string(dir.join("audit-session.json")) else {
                    continue;
                };
                let Ok(saved) = serde_json::from_str::<serde_json::Value>(&raw) else {
                    continue;
                };
                if let Some(id) = saved["session_id"].as_str() {
                    ids.insert(id.to_string());
                }
                if let Some(list) = saved["session_ids"].as_array() {
                    ids.extend(list.iter().filter_map(|id| id.as_str().map(str::to_string)));
                }
            }
        }
    }
    ids
}

/// A run is in flight while its `live` marker names a pid still running.
/// A stale marker (dead pid, unreadable pid) means the run died — its
/// sessions are finished and safe to archive.
fn in_flight(run_dir: &Path) -> bool {
    let Ok(pid) = std::fs::read_to_string(run_dir.join("live")) else {
        return false;
    };
    let Ok(pid) = pid.trim().parse::<u32>() else {
        return false;
    };
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}
