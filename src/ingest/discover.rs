//! Locate Claude artifacts in an extracted tree and group them into user profiles.
//!
//! A forensic collection may hold several users (e.g. `C/Users/alice`, `home/bob`)
//! or just the raw content of a single `~/.claude` directory. A "profile" is the
//! directory assumed to be the user's home.

use crate::util::rel_string;
use anyhow::Result;
use rusqlite::{Connection, params};
use std::collections::BTreeMap;
use std::path::Path;
use walkdir::WalkDir;

pub struct Item {
    pub profile_id: i64,
    pub rel: String,
}

#[derive(Default)]
pub struct Found {
    pub claude_dirs: Vec<Item>,
    pub claude_jsons: Vec<Item>,
    pub desktop_dirs: Vec<Item>,
    /// Project-level artifacts: `.claude/` without profile markers, `.mcp.json`, `CLAUDE.md`.
    pub loose: Vec<Item>,
}

const CLAUDE_MARKERS: &[&str] = &[
    "projects", "history.jsonl", ".credentials.json", "todos", "statsig", "file-history",
    "shell-snapshots", "session-env",
];
const DESKTOP_MARKERS: &[&str] = &[
    "claude_desktop_config.json", "Cookies", "Network", "Local Storage", "Local State",
    "IndexedDB",
];

fn has_any(dir: &Path, names: &[&str]) -> bool {
    names.iter().any(|n| dir.join(n).exists())
}

fn is_claude_profile_dir(dir: &Path, name: &str) -> bool {
    if name == ".claude" {
        has_any(dir, CLAUDE_MARKERS)
    } else {
        // Raw copy of ~/.claude under another name (or at the archive root).
        dir.join("projects").is_dir()
            && has_any(dir, &["history.jsonl", ".credentials.json", "settings.json", "todos", "statsig"])
    }
}

fn is_desktop_dir(dir: &Path, name: &str) -> bool {
    name.eq_ignore_ascii_case("claude") && has_any(dir, DESKTOP_MARKERS)
}

fn parent_rel(rel: &str) -> String {
    rel.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_default()
}

/// Strip the per-OS application-data suffix to get the home directory.
fn desktop_home(rel: &str) -> String {
    let parts: Vec<&str> = rel.split('/').collect();
    for marker in ["AppData", ".config", "Library"] {
        if let Some(i) = parts.iter().rposition(|p| p.eq_ignore_ascii_case(marker)) {
            return parts[..i].join("/");
        }
    }
    parent_rel(rel)
}

pub fn discover(conn: &Connection, root: &Path) -> Result<Found> {
    let mut claude_dirs = Vec::new();
    let mut claude_jsons = Vec::new();
    let mut desktop_dirs = Vec::new();
    let mut loose = Vec::new();
    // profile root -> claude dir / desktop dir
    let mut homes: BTreeMap<String, (Option<String>, Option<String>)> = BTreeMap::new();

    let mut walker = WalkDir::new(root).follow_links(false).into_iter();
    while let Some(entry) = walker.next() {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let rel = rel_string(root, path);
        let name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().is_dir() {
            if is_claude_profile_dir(path, &name) {
                let home = parent_rel(&rel);
                homes.entry(home.clone()).or_default().0 = Some(rel.clone());
                claude_dirs.push((home, rel));
                walker.skip_current_dir();
            } else if is_desktop_dir(path, &name) {
                let home = desktop_home(&rel);
                homes.entry(home.clone()).or_default().1 = Some(rel.clone());
                desktop_dirs.push((home, rel));
                walker.skip_current_dir();
            } else if name == ".claude" {
                loose.push(rel);
                walker.skip_current_dir();
            }
        } else if name == ".claude.json" || name.starts_with(".claude.json.backup") {
            let home = parent_rel(&rel);
            homes.entry(home.clone()).or_default();
            claude_jsons.push((home, rel));
        } else if matches!(name.as_str(), ".mcp.json" | "CLAUDE.md" | "CLAUDE.local.md") {
            loose.push(rel);
        }
    }

    // Loose items need a profile; fall back to an archive-root profile.
    if !loose.is_empty() && homes.is_empty() {
        homes.entry(String::new()).or_default();
    }

    let mut ids: BTreeMap<String, i64> = BTreeMap::new();
    for (home, (cdir, ddir)) in &homes {
        let label = if home.is_empty() {
            "(archive root)".to_string()
        } else {
            home.rsplit('/').next().unwrap_or(home).to_string()
        };
        conn.execute(
            "INSERT INTO profiles(root, label, claude_dir, desktop_dir) VALUES(?1,?2,?3,?4)",
            params![home, label, cdir, ddir],
        )?;
        ids.insert(home.clone(), conn.last_insert_rowid());
    }

    let profile_for = |rel: &str| -> i64 {
        ids.iter()
            .filter(|(h, _)| h.is_empty() || rel == h.as_str() || rel.starts_with(&format!("{h}/")))
            .max_by_key(|(h, _)| h.len())
            .map(|(_, id)| *id)
            .unwrap_or(0)
    };

    // Attribute every extracted file to a profile and a category.
    {
        let mut stmt = conn.prepare("SELECT id, rel_path FROM files")?;
        let rows: Vec<(i64, String)> =
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
        let mut upd = conn.prepare("UPDATE files SET profile_id=?1, category=?2 WHERE id=?3")?;
        conn.execute_batch("BEGIN")?;
        for (id, rel) in rows {
            let pid = profile_for(&rel);
            upd.execute(params![if pid == 0 { None } else { Some(pid) }, categorize(&rel), id])?;
        }
        conn.execute_batch("COMMIT")?;
    }

    // OS guess per profile from what lies beneath it.
    for (home, id) in &ids {
        let prefix = if home.is_empty() { String::new() } else { format!("{home}/") };
        let has = |needle: &str| -> bool {
            conn.query_row(
                "SELECT 1 FROM files WHERE rel_path LIKE ?1 || '%' AND rel_path LIKE '%' || ?2 || '%' LIMIT 1",
                params![prefix, needle],
                |_| Ok(()),
            )
            .is_ok()
        };
        let os = if has("/AppData/") || home.contains("Users/") && has("AppData") {
            "Windows"
        } else if has("/Library/Application Support/") {
            "macOS"
        } else if home.starts_with("home/") || home.contains("/home/") || has("/.config/") {
            "Linux"
        } else {
            "unknown"
        };
        conn.execute("UPDATE profiles SET os_guess=?1 WHERE id=?2", params![os, id])?;
    }

    let mk = |v: Vec<(String, String)>| -> Vec<Item> {
        v.into_iter().map(|(h, rel)| Item { profile_id: ids[&h], rel }).collect()
    };
    Ok(Found {
        claude_dirs: mk(claude_dirs),
        claude_jsons: mk(claude_jsons),
        desktop_dirs: mk(desktop_dirs),
        loose: loose.into_iter().map(|rel| Item { profile_id: profile_for(&rel), rel }).collect(),
    })
}

pub fn categorize(rel: &str) -> &'static str {
    let lower = rel.to_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    if lower.contains("/projects/") && name.ends_with(".jsonl") {
        "session-transcript"
    } else if lower.contains("/tool-results/") {
        "tool-result"
    } else if name == "history.jsonl" {
        "prompt-history"
    } else if name == ".credentials.json" {
        "credentials"
    } else if name.starts_with(".claude.json") {
        "claude-json"
    } else if lower.contains("/file-history/") {
        "file-history"
    } else if lower.contains("/todos/") {
        "todos"
    } else if lower.contains("/shell-snapshots/") {
        "shell-snapshot"
    } else if lower.contains("/session-env/") {
        "session-env"
    } else if lower.contains("/projects/") && lower.contains("/memory/") {
        "memory"
    } else if name == "cookies" || name == "cookies-journal" {
        "desktop-cookies"
    } else if lower.contains("/local storage/") {
        "desktop-local-storage"
    } else if lower.contains("/indexeddb/") {
        "desktop-indexeddb"
    } else if lower.contains("/session storage/") {
        "desktop-session-storage"
    } else if name.ends_with(".log") {
        "log"
    } else if name == "claude_desktop_config.json" || name == ".mcp.json" {
        "mcp-config"
    } else if name.starts_with("settings") && name.ends_with(".json") {
        "settings"
    } else if name == "claude.md" || name == "claude.local.md" {
        "instructions"
    } else if lower.contains("/plugins/") {
        "plugin"
    } else if lower.contains("/skills/") || lower.contains("/agents/") || lower.contains("/commands/") {
        "customization"
    } else if lower.contains("/cache/") || lower.contains("/code cache/") || lower.contains("/gpucache/") {
        "cache"
    } else if lower.contains("/telemetry/") || lower.contains("/statsig/") {
        "telemetry"
    } else {
        "other"
    }
}
