//! Parser for the Claude Desktop (Electron) profile directory:
//! `%APPDATA%\Claude`, `~/.config/Claude`, `~/Library/Application Support/Claude`.

use super::Ctx;
use crate::util::{self, truncate, webkit_to_iso};
use anyhow::Result;
use rusqlite::{Connection, OpenFlags, params};
use serde_json::Value;
use walkdir::WalkDir;

pub fn parse_dir(ctx: &Ctx, pid: i64, dir: &str) -> Result<()> {
    let base = ctx.abs(dir);
    let files: Vec<String> = WalkDir::new(&base)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(|e| util::rel_string(&ctx.root, e.path()))
        .collect();

    for rel in &files {
        let inner = rel.strip_prefix(dir).unwrap_or(rel).trim_start_matches('/');
        let lower = inner.to_lowercase();
        let name = lower.rsplit('/').next().unwrap_or("");
        let depth = inner.matches('/').count();
        match name {
            "cookies" => parse_cookies(ctx, pid, rel),
            "claude_desktop_config.json" => {
                if let Some(v) = ctx.read_json(rel) {
                    ctx.add_mcp_servers(pid, rel, "desktop", None, v.get("mcpServers").unwrap_or(&Value::Null));
                    let n = v.get("mcpServers").and_then(Value::as_object).map_or(0, |m| m.len());
                    ctx.add_config(pid, rel, "desktop-mcp-config", &format!("{n} MCP servers"));
                }
            }
            "local state" if depth == 0 => {
                let mut summary = String::new();
                if let Some(v) = ctx.read_json(rel) {
                    if let Some(k) = v.pointer("/os_crypt/encrypted_key").and_then(Value::as_str) {
                        ctx.add_secret(
                            Some(pid), rel, "config", "os_crypt encrypted_key (DPAPI/keychain protected)",
                            "os_crypt.encrypted_key", k, None,
                            "Wraps the AES key protecting Cookies/Local Storage. Needs the user's DPAPI master key (Windows) or keyring secret (Linux/macOS).",
                        );
                        summary.push_str("os_crypt.encrypted_key present");
                    }
                    if v.pointer("/os_crypt/app_bound_encrypted_key").is_some() {
                        summary.push_str(" | app_bound_encrypted_key present (v20 cookies)");
                    }
                }
                ctx.add_config(pid, rel, "desktop-local-state", &summary);
            }
            "config.json" | "preferences" | "extensions-installations.json" | "window-state.json" if depth == 0 => {
                ctx.add_config(pid, rel, "desktop-config", "");
            }
            "manifest.json" if lower.contains("extensions") => ctx.add_config(pid, rel, "desktop-extension", ""),
            // LevelDB journals (*.log) under storage dirs are databases, not logs.
            _ if lower.starts_with("logs/")
                || (name.ends_with(".log") && !lower.contains("leveldb") && !lower.contains("indexeddb") && !lower.contains("storage/")) =>
            {
                ctx.add_config(pid, rel, "desktop-log", "")
            }
            _ => {}
        }
    }

    // Local Storage is a LevelDB database; open a scratch copy, never the evidence.
    let ls = base.join("Local Storage").join("leveldb");
    if ls.is_dir() {
        let rel = util::rel_string(&ctx.root, &ls);
        if let Err(e) = parse_local_storage(ctx, pid, &ls, &rel) {
            crate::db::warn(ctx.conn, &rel, &format!("Local Storage: {e:#}"));
        }
    }
    Ok(())
}

fn parse_cookies(ctx: &Ctx, pid: i64, rel: &str) {
    if let Err(e) = parse_cookies_inner(ctx, pid, rel) {
        crate::db::warn(ctx.conn, rel, &format!("Cookies: {e:#}"));
    }
}

fn parse_cookies_inner(ctx: &Ctx, pid: i64, rel: &str) -> Result<()> {
    // Work on a copy: SQLite may want to touch -wal/-journal files next to the DB.
    let tmp = ctx.work.join(format!("cookies-{}.db", util::random_token(8)));
    std::fs::create_dir_all(&ctx.work)?;
    std::fs::copy(ctx.abs(rel), &tmp)?;
    for ext in ["-wal", "-journal"] {
        let side = ctx.abs(&format!("{rel}{ext}"));
        if side.exists() {
            std::fs::copy(&side, tmp.with_file_name(format!("{}{ext}", tmp.file_name().unwrap().to_string_lossy())))?;
        }
    }
    let src = Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_WRITE)?;

    let cols: Vec<String> = src
        .prepare("PRAGMA table_info(cookies)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<Result<_, _>>()?;
    let pick = |cands: &[&str]| -> String {
        cands.iter().find(|c| cols.iter().any(|x| x == *c)).map(|c| c.to_string()).unwrap_or_else(|| "NULL".into())
    };
    let sql = format!(
        "SELECT {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {} FROM cookies",
        pick(&["host_key"]),
        pick(&["name"]),
        pick(&["path"]),
        pick(&["creation_utc"]),
        pick(&["expires_utc"]),
        pick(&["last_access_utc"]),
        pick(&["last_update_utc"]),
        pick(&["is_secure", "secure"]),
        pick(&["is_httponly", "httponly"]),
        pick(&["samesite"]),
        pick(&["is_persistent", "persistent"]),
        pick(&["value"]),
        pick(&["encrypted_value"]),
    );
    let mut stmt = src.prepare(&sql)?;
    let mut rows = stmt.query([])?;
    while let Some(r) = rows.next()? {
        let host: Option<String> = r.get(0)?;
        let name: Option<String> = r.get(1)?;
        let ts = |i: usize| -> Option<String> { r.get::<_, Option<i64>>(i).ok().flatten().and_then(webkit_to_iso) };
        let samesite = match r.get::<_, Option<i64>>(9).ok().flatten() {
            Some(-1) => "unspecified",
            Some(0) => "none",
            Some(1) => "lax",
            Some(2) => "strict",
            _ => "",
        };
        let value: String = r.get::<_, Option<String>>(11).ok().flatten().unwrap_or_default();
        let enc: Vec<u8> = r.get::<_, Option<Vec<u8>>>(12).ok().flatten().unwrap_or_default();
        let encryption = if enc.is_empty() {
            if value.is_empty() { "empty" } else { "plaintext" }.to_string()
        } else if enc.starts_with(b"v10") || enc.starts_with(b"v11") || enc.starts_with(b"v20") {
            String::from_utf8_lossy(&enc[..3]).into_owned()
        } else if enc.starts_with(&[0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf]) {
            "DPAPI blob".to_string()
        } else {
            "unknown".to_string()
        };
        ctx.conn.execute(
            "INSERT INTO cookies(profile_id, file_rel, host, name, path, created, expires, last_access, last_update, secure, httponly,
                samesite, persistent, encryption, value, value_masked, encrypted_len)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                pid, rel, host, name, r.get::<_, Option<String>>(2)?, ts(3), ts(4), ts(5), ts(6),
                r.get::<_, Option<i64>>(7).ok().flatten(), r.get::<_, Option<i64>>(8).ok().flatten(), samesite,
                r.get::<_, Option<i64>>(10).ok().flatten(), encryption,
                (!value.is_empty()).then_some(&value), util::mask(&value), enc.len() as i64
            ],
        )?;
    }
    drop(rows);
    drop(stmt);
    drop(src);
    let _ = std::fs::remove_file(&tmp);
    Ok(())
}

fn parse_local_storage(ctx: &Ctx, pid: i64, dir: &std::path::Path, rel: &str) -> Result<()> {
    let tmp = ctx.work.join(format!("leveldb-{}", util::random_token(8)));
    std::fs::create_dir_all(&tmp)?;
    for e in std::fs::read_dir(dir)?.flatten() {
        if e.path().is_file() && e.file_name() != "LOCK" {
            std::fs::copy(e.path(), tmp.join(e.file_name()))?;
        }
    }
    let opts = rusty_leveldb::Options { create_if_missing: false, ..Default::default() };
    let mut db = rusty_leveldb::DB::open(&tmp, opts).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut it = db.new_iter().map_err(|e| anyhow::anyhow!("{e}"))?;
    use rusty_leveldb::LdbIterator;
    let mut stmt = ctx.conn.prepare_cached(
        "INSERT INTO local_storage(profile_id, file_rel, origin, key, value, value_len) VALUES(?1,?2,?3,?4,?5,?6)",
    )?;
    while it.advance() {
        let Some((k, v)) = it.current().map(|(k, v)| (k.to_vec(), v.to_vec())) else { continue };
        // Chromium layout: "_" + origin + 0x00 + <encoded key>; "META:<origin>" for bookkeeping.
        let (origin, key) = if k.first() == Some(&b'_') {
            match k.iter().position(|b| *b == 0) {
                Some(i) => (String::from_utf8_lossy(&k[1..i]).into_owned(), decode_chromium_string(&k[i + 1..])),
                None => (String::new(), String::from_utf8_lossy(&k).into_owned()),
            }
        } else {
            ("(meta)".to_string(), String::from_utf8_lossy(&k).into_owned())
        };
        let value = if origin == "(meta)" { hex::encode(&v[..v.len().min(256)]) } else { decode_chromium_string(&v) };
        stmt.execute(params![pid, rel, origin, key, truncate(&value, 1024 * 1024), v.len() as i64])?;
    }
    drop(it);
    drop(db);
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(())
}

/// Chromium Local Storage strings: first byte 0 = UTF-16LE, 1 = Latin-1.
fn decode_chromium_string(b: &[u8]) -> String {
    match b.first() {
        Some(0) => {
            let u: Vec<u16> = b[1..].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&u)
        }
        Some(1) => b[1..].iter().map(|&c| c as char).collect(),
        _ => String::from_utf8_lossy(b).into_owned(),
    }
}
