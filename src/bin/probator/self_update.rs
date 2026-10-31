//! Replace the installed engine binaries and refresh every installed
//! checker in one command. The binaries carry the system immutable flag
//! (`schg`) so the audit host can trust the helper it invokes; replacing
//! them is an operator action and this command performs the whole
//! sequence: build, unlock, atomic swap, relock, checker reinstall.

use super::install;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()))
}

fn bin_dir(root: &Path) -> PathBuf {
    root.join("bin")
}

fn sha256(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(crate::util::sha256_bytes(&bytes))
}

fn quoted(value: &Path) -> String {
    format!("'{}'", value.to_string_lossy().replace('\'', "'\\''"))
}

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| format!("{program}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} exited with {status}"))
    }
}

/// Enumerate installed checkers that still ship in `<source>/tools/`.
/// A checker counts as installed when its profile keeps an
/// `installation.json`; directories without one are left alone.
fn installed_checkers(source: &Path, profiles: &Path) -> Vec<PathBuf> {
    let tools = source.join("tools");
    let Ok(entries) = std::fs::read_dir(&tools) else {
        return Vec::new();
    };
    let mut sources = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|dir| dir.join("contract.json").is_file())
        .filter(|dir| {
            let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
                return false;
            };
            profiles
                .join(name)
                .join("plugins")
                .join(name)
                .join("installation.json")
                .is_file()
        })
        .collect::<Vec<_>>();
    sources.sort();
    sources
}

/// Swap the installed binaries for freshly built ones. The destination
/// files may carry `schg`, so one sudo session unlocks, installs and
/// relocks; the trap restores the flag if the sequence aborts. On hosts
/// without `chflags` the lock steps are skipped.
fn replace_binaries(new_probator: &Path, new_agent: &Path, dst_dir: &Path) -> Result<(), String> {
    let dst = dst_dir.join("probator");
    let dst_agent = dst_dir.join("probator-agent");
    if !dst.is_file() && !dst_agent.is_file() {
        return Err(format!(
            "no installed engine under {} to update",
            dst_dir.display()
        ));
    }
    let (dst, dst_agent) = (quoted(&dst), quoted(&dst_agent));
    let owner = "$SUDO_UID:$SUDO_GID";
    let script = if which_exists("chflags") {
        format!(
            "set -e\n\
             trap 'chflags schg {dst} {dst_agent} 2>/dev/null || true' EXIT\n\
             chflags noschg {dst} {dst_agent} 2>/dev/null || true\n\
             cp {new_p} {dst}.new && chown {owner} {dst}.new && chmod 755 {dst}.new && mv {dst}.new {dst}\n\
             cp {new_a} {dst_agent}.new && chown {owner} {dst_agent}.new && chmod 755 {dst_agent}.new && mv {dst_agent}.new {dst_agent}\n\
             chflags schg {dst} {dst_agent}\n\
             trap - EXIT",
            new_p = quoted(new_probator),
            new_a = quoted(new_agent),
        )
    } else {
        format!(
            "set -e\n\
             cp {new_p} {dst}.new && chown {owner} {dst}.new && chmod 755 {dst}.new && mv {dst}.new {dst}\n\
             cp {new_a} {dst_agent}.new && chown {owner} {dst_agent}.new && chmod 755 {dst_agent}.new && mv {dst_agent}.new {dst_agent}",
            new_p = quoted(new_probator),
            new_a = quoted(new_agent),
        )
    };
    eprintln!("engine replacement requires the operator password (sudo)");
    run("sudo", &["/bin/sh", "-c", &script])
}

fn which_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
        .unwrap_or(false)
}

/// Build the release binaries in `<source>`, swap them into
/// `<root>/bin` under the immutable-flag lock, then reinstall every
/// checker that has an installation record and still ships in
/// `<source>/tools/`.
pub fn self_update(source: &Path, root: &Path) -> Result<Vec<String>, String> {
    let source = if source.as_os_str().is_empty() {
        std::env::current_dir().map_err(|e| e.to_string())?
    } else {
        source.to_path_buf()
    };
    if !source.join("Cargo.toml").is_file() || !source.join("tools").is_dir() {
        return Err(format!(
            "{} does not look like a Probator source checkout",
            source.display()
        ));
    }
    let dst_dir = bin_dir(root);
    if !dst_dir.join("probator").is_file() && !dst_dir.join("probator-agent").is_file() {
        return Err(format!(
            "no installed engine under {} to update",
            dst_dir.display()
        ));
    }

    run(
        "cargo",
        &[
            "build",
            "--release",
            "--manifest-path",
            &source.join("Cargo.toml").to_string_lossy(),
            "--bins",
        ],
    )?;
    let built = source.join("target").join("release");
    let (new_probator, new_agent) = (built.join("probator"), built.join("probator-agent"));
    if !new_probator.is_file() || !new_agent.is_file() {
        return Err("release build did not produce probator and probator-agent".to_string());
    }
    replace_binaries(&new_probator, &new_agent, &dst_dir)?;

    let profiles = install::profile_root();
    let mut lines = Vec::new();
    for checker in installed_checkers(&source, &profiles) {
        match install::install(&checker) {
            Ok(message) => lines.push(message),
            Err(message) => {
                lines.push(format!("{}: {message}", checker.display()));
            }
        }
    }

    let dst = dst_dir.join("probator");
    let dst_agent = dst_dir.join("probator-agent");
    lines.push(format!(
        "installed probator {} sha256 {}",
        dst.display(),
        sha256(&dst)?
    ));
    lines.push(format!(
        "installed probator-agent {} sha256 {}",
        dst_agent.display(),
        sha256(&dst_agent)?
    ));
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tree(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    #[test]
    fn installed_checkers_keeps_only_installed_names() {
        let root = std::env::temp_dir().join(format!("self-update-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for name in ["privacy-cleaner", "money-saver", "unpublished"] {
            tree(&root, &format!("tools/{name}/contract.json"), "{}");
        }
        for name in ["privacy-cleaner", "money-saver"] {
            tree(
                &root,
                &format!("profiles/{name}/plugins/{name}/installation.json"),
                "{}",
            );
        }
        let found = installed_checkers(&root, &root.join("profiles"));
        assert_eq!(
            found,
            vec![
                root.join("tools/money-saver"),
                root.join("tools/privacy-cleaner")
            ]
        );
        let _ = fs::remove_dir_all(&root);
    }
}
