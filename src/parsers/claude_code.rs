//! Parser for a Claude Code configuration directory (`~/.claude`).

use super::{Ctx, looks_secret_key};
use crate::util::{self, json_ts, str_field, truncate};
use anyhow::Result;
use rusqlite::{OptionalExtension, params};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{BufRead, BufReader};
use walkdir::WalkDir;

const MAX_RAW: usize = 2 * 1024 * 1024;
const MAX_TEXT: usize = 256 * 1024;

pub fn parse_dir(ctx: &Ctx, pid: i64, dir: &str) -> Result<()> {
    let base = ctx.abs(dir);

    // Sessions, grouped per encoded project directory.
    let projects_dir = base.join("projects");
    if let Ok(rd) = std::fs::read_dir(&projects_dir) {
        let mut encs: Vec<_> = rd.flatten().filter(|e| e.path().is_dir()).collect();
        encs.sort_by_key(|e| e.file_name());
        for e in encs {
            let enc = e.file_name().to_string_lossy().into_owned();
            parse_project_dir(ctx, pid, dir, &enc)?;
        }
    }

    parse_history(ctx, pid, &Ctx::join(dir, "history.jsonl"));
    parse_todos(ctx, pid, dir);
    link_file_history(ctx, pid, dir)?;
    parse_registry(ctx, pid, dir);
    parse_credentials_file(ctx, pid, &Ctx::join(dir, ".credentials.json"));
    collect_config(ctx, pid, dir);
    Ok(())
}

fn rel_files(ctx: &Ctx, dir: &str) -> Vec<String> {
    let base = ctx.abs(dir);
    let mut v: Vec<String> = WalkDir::new(&base)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(|e| util::rel_string(&ctx.root, e.path()))
        .collect();
    v.sort();
    v
}

fn parse_project_dir(ctx: &Ctx, pid: i64, dir: &str, enc: &str) -> Result<()> {
    let pdir = Ctx::join(dir, &format!("projects/{enc}"));
    let mut cwd_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut rowids = Vec::new();
    for rel in rel_files(ctx, &pdir) {
        let lower = rel.to_lowercase();
        if lower.contains("/tool-results/") {
            continue;
        }
        if lower.ends_with(".jsonl") {
            match parse_session(ctx, pid, &rel, &pdir) {
                Ok((rowid, cwds, is_sub)) => {
                    rowids.push(rowid);
                    if !is_sub {
                        for (c, n) in cwds {
                            *cwd_counts.entry(c).or_default() += n;
                        }
                    }
                }
                Err(e) => crate::db::warn(ctx.conn, &rel, &format!("{e:#}")),
            }
        } else if lower.contains("/memory/") {
            ctx.add_config(pid, &rel, "memory", "auto-memory note");
        }
    }

    // Real path: the most frequent cwd whose encoding matches the directory name.
    let path = cwd_counts
        .iter()
        .filter(|(c, _)| util::encode_project_path(c) == enc)
        .max_by_key(|(_, n)| **n)
        .or_else(|| cwd_counts.iter().max_by_key(|(_, n)| **n))
        .map(|(c, _)| c.clone())
        .unwrap_or_else(|| format!("(decoded) {}", enc.replace('-', "/")));
    let project_id = upsert_project(ctx, pid, &path, Some(enc), "projects-dir")?;
    for r in rowids {
        ctx.conn.execute("UPDATE sessions SET project_id=?1 WHERE id=?2", params![project_id, r])?;
    }
    Ok(())
}

pub fn upsert_project(ctx: &Ctx, pid: i64, path: &str, enc: Option<&str>, source: &str) -> Result<i64> {
    let existing: Option<(i64, String)> = ctx
        .conn
        .query_row(
            "SELECT id, coalesce(sources,'') FROM projects WHERE profile_id=?1 AND (path=?2 OR (?3 IS NOT NULL AND encoded_dir=?3))",
            params![pid, path, enc],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((id, sources)) = existing {
        if !sources.split(", ").any(|s| s == source) {
            let s = if sources.is_empty() { source.to_string() } else { format!("{sources}, {source}") };
            ctx.conn.execute("UPDATE projects SET sources=?1 WHERE id=?2", params![s, id])?;
        }
        if let Some(enc) = enc {
            ctx.conn.execute("UPDATE projects SET encoded_dir=coalesce(encoded_dir, ?1) WHERE id=?2", params![enc, id])?;
        }
        if !path.starts_with("(decoded)") {
            ctx.conn.execute("UPDATE projects SET path=?1 WHERE id=?2 AND path LIKE '(decoded)%'", params![path, id])?;
        }
        return Ok(id);
    }
    ctx.conn.execute(
        "INSERT INTO projects(profile_id, path, encoded_dir, sources) VALUES(?1,?2,?3,?4)",
        params![pid, path, enc, source],
    )?;
    Ok(ctx.conn.last_insert_rowid())
}

#[derive(Default)]
struct Stats {
    session_ids: BTreeMap<String, usize>,
    title: Option<String>,
    summary: Option<String>,
    first_prompt: Option<String>,
    first_ts: Option<String>,
    last_ts: Option<String>,
    records: i64,
    user: i64,
    assistant: i64,
    tools: i64,
    models: BTreeSet<String>,
    versions: BTreeSet<String>,
    cwds: BTreeMap<String, usize>,
    branches: BTreeSet<String>,
    entrypoints: BTreeSet<String>,
    modes: BTreeSet<String>,
    usage_seen: HashSet<String>,
    input: i64,
    output: i64,
    cache_read: i64,
    cache_create: i64,
    cost: Option<f64>,
    errors: i64,
}

fn join_set(s: &BTreeSet<String>) -> String {
    s.iter().cloned().collect::<Vec<_>>().join(", ")
}

/// Returns (session rowid, cwd counts, is_subagent).
fn parse_session(ctx: &Ctx, pid: i64, rel: &str, pdir: &str) -> Result<(i64, BTreeMap<String, usize>, bool)> {
    let file = std::fs::File::open(ctx.abs(rel))?;
    let inner = rel.strip_prefix(pdir).unwrap_or(rel).trim_start_matches('/');
    let stem = inner.rsplit('/').next().unwrap_or(inner).trim_end_matches(".jsonl").to_string();
    // <sid>.jsonl | <sid>/subagents/agent-<id>.jsonl | agent-<id>.jsonl (legacy)
    let (is_sub, parent, agent_id) = if stem.starts_with("agent-") {
        let parent = inner.split('/').next().filter(|_| inner.contains('/')).map(str::to_string);
        (true, parent, Some(stem.trim_start_matches("agent-").to_string()))
    } else {
        (false, None, None)
    };

    ctx.conn.execute(
        "INSERT INTO sessions(profile_id, session_id, file_rel, is_subagent, parent_session, agent_id) VALUES(?1,?2,?3,?4,?5,?6)",
        params![pid, stem, rel, is_sub as i64, parent, agent_id],
    )?;
    let rowid = ctx.conn.last_insert_rowid();

    let mut st = Stats::default();
    let mut ins_msg = ctx.conn.prepare_cached(
        "INSERT INTO messages(session_rowid, line_no, type, subtype, uuid, parent_uuid, ts, role, model, is_sidechain, is_meta, text, raw)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
    )?;
    let mut ins_tool = ctx.conn.prepare_cached(
        "INSERT INTO tool_calls(session_rowid, message_uuid, ts, tool_name, tool_use_id, summary, input_json) VALUES(?1,?2,?3,?4,?5,?6,?7)",
    )?;
    let mut upd_tool = ctx.conn.prepare_cached(
        "UPDATE tool_calls SET is_error=?1, result_excerpt=?2, result_ts=?3 WHERE session_rowid=?4 AND tool_use_id=?5",
    )?;
    let mut ins_fh = ctx.conn.prepare_cached(
        "INSERT OR IGNORE INTO file_history(profile_id, session_id, original_path, backup_file, version, backup_ts) VALUES(?1,?2,?3,?4,?5,?6)",
    )?;

    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();
    let mut line_no = 0i64;
    let mut snapshot_session: Option<String> = None;
    loop {
        buf.clear();
        if reader.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        line_no += 1;
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        st.records += 1;
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => {
                st.errors += 1;
                ins_msg.execute(params![rowid, line_no, "parse-error", None::<String>, None::<String>, None::<String>, None::<String>, None::<String>, None::<String>, 0, 1, "", truncate(line, MAX_RAW)])?;
                continue;
            }
        };
        let t = str_field(&v, "type").unwrap_or("").to_string();
        let ts = json_ts(v.get("timestamp"));
        if let Some(ts) = &ts {
            if st.first_ts.as_ref().is_none_or(|f| ts < f) {
                st.first_ts = Some(ts.clone());
            }
            if st.last_ts.as_ref().is_none_or(|l| ts > l) {
                st.last_ts = Some(ts.clone());
            }
        }
        if let Some(s) = str_field(&v, "sessionId") {
            *st.session_ids.entry(s.to_string()).or_default() += 1;
            snapshot_session.get_or_insert_with(|| s.to_string());
        }
        if let Some(c) = str_field(&v, "cwd") {
            *st.cwds.entry(c.to_string()).or_default() += 1;
        }
        for (k, set) in [("version", &mut st.versions), ("gitBranch", &mut st.branches), ("entrypoint", &mut st.entrypoints), ("permissionMode", &mut st.modes)] {
            if let Some(x) = str_field(&v, k).filter(|x| !x.is_empty()) {
                set.insert(x.to_string());
            }
        }
        let uuid = str_field(&v, "uuid");
        let msg = v.get("message");
        let role = msg.and_then(|m| str_field(m, "role"));
        let model = msg.and_then(|m| str_field(m, "model"));
        let is_meta = v.get("isMeta").and_then(Value::as_bool).unwrap_or(false);
        let mut text = String::new();

        match t.as_str() {
            "user" => {
                st.user += 1;
                if let Some(content) = msg.and_then(|m| m.get("content")) {
                    match content {
                        Value::String(s) => {
                            text = s.clone();
                            if !is_meta && st.first_prompt.is_none() && !s.starts_with('<') {
                                st.first_prompt = Some(truncate(s, 500));
                            }
                        }
                        Value::Array(blocks) => {
                            for b in blocks {
                                match str_field(b, "type") {
                                    Some("text") => {
                                        let s = str_field(b, "text").unwrap_or("");
                                        if !is_meta && st.first_prompt.is_none() && !s.starts_with('<') {
                                            st.first_prompt = Some(truncate(s, 500));
                                        }
                                        push_line(&mut text, s);
                                    }
                                    Some("tool_result") => {
                                        let id = str_field(b, "tool_use_id").unwrap_or("");
                                        let err = b.get("is_error").and_then(Value::as_bool).unwrap_or(false);
                                        let body = block_text(b.get("content"));
                                        push_line(&mut text, &format!("[tool_result {id}{}] {}", if err { " ERROR" } else { "" }, truncate(&body, 8192)));
                                        upd_tool.execute(params![err as i64, truncate(&body, 4000), ts, rowid, id])?;
                                    }
                                    Some(other) => push_line(&mut text, &format!("[{other}]")),
                                    None => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            "assistant" => {
                st.assistant += 1;
                if let Some(m) = model.filter(|m| !m.starts_with('<')) {
                    st.models.insert(m.to_string());
                }
                let mid = msg.and_then(|m| str_field(m, "id")).unwrap_or("").to_string();
                if let Some(u) = msg.and_then(|m| m.get("usage")) {
                    // Claude Code writes one record per content block, all sharing usage.
                    if mid.is_empty() || st.usage_seen.insert(mid) {
                        let g = |k: &str| u.get(k).and_then(Value::as_i64).unwrap_or(0);
                        st.input += g("input_tokens");
                        st.output += g("output_tokens");
                        st.cache_read += g("cache_read_input_tokens");
                        st.cache_create += g("cache_creation_input_tokens");
                    }
                }
                if let Some(blocks) = msg.and_then(|m| m.get("content")).and_then(Value::as_array) {
                    for b in blocks {
                        match str_field(b, "type") {
                            Some("text") => push_line(&mut text, str_field(b, "text").unwrap_or("")),
                            Some("thinking") => push_line(&mut text, &format!("[thinking] {}", str_field(b, "thinking").unwrap_or(""))),
                            Some("redacted_thinking") => push_line(&mut text, "[redacted_thinking]"),
                            Some("tool_use") | Some("server_tool_use") => {
                                st.tools += 1;
                                let name = str_field(b, "name").unwrap_or("?");
                                let input = b.get("input").cloned().unwrap_or(Value::Null);
                                let summary = tool_summary(name, &input);
                                push_line(&mut text, &format!("[tool_use {name}] {summary}"));
                                ins_tool.execute(params![rowid, uuid, ts, name, str_field(b, "id"), summary, truncate(&input.to_string(), MAX_TEXT)])?;
                            }
                            Some(other) => push_line(&mut text, &format!("[{other}]")),
                            None => {}
                        }
                    }
                } else if let Some(s) = msg.and_then(|m| m.get("content")).and_then(Value::as_str) {
                    text = s.to_string();
                }
            }
            "system" => {
                text = v.get("content").map(|c| block_text(Some(c))).unwrap_or_default();
            }
            "summary" => {
                let s = str_field(&v, "summary").unwrap_or("").to_string();
                st.summary.get_or_insert_with(|| s.clone());
                text = s;
            }
            "ai-title" | "custom-title" => {
                let s = str_field(&v, "customTitle").or(str_field(&v, "aiTitle")).or(str_field(&v, "title")).unwrap_or("");
                if !s.is_empty() && (t == "custom-title" || st.title.is_none()) {
                    st.title = Some(s.to_string());
                }
                text = s.to_string();
            }
            "last-prompt" => text = str_field(&v, "lastPrompt").unwrap_or("").to_string(),
            "attachment" => {
                if let Some(a) = v.get("attachment") {
                    let kind = str_field(a, "type").unwrap_or("?");
                    let detail = str_field(a, "filename").or(str_field(a, "path")).or(str_field(a, "content")).unwrap_or("");
                    text = format!("[attachment {kind}] {}", truncate(detail, 2000));
                }
            }
            "cost-state" => {
                st.cost = v.get("totalCostUSD").and_then(Value::as_f64);
                text = format!("total cost USD {}", st.cost.unwrap_or(0.0));
            }
            "file-history-snapshot" => {
                if let Some(map) = v.pointer("/snapshot/trackedFileBackups").and_then(Value::as_object) {
                    let sid = snapshot_session.clone().unwrap_or_else(|| stem.clone());
                    for (path, info) in map {
                        let backup = str_field(info, "backupFileName").unwrap_or("(none: file created in session)");
                        ins_fh.execute(params![pid, sid, path, backup, info.get("version").and_then(Value::as_i64), json_ts(info.get("backupTime"))])?;
                    }
                    text = format!("[file-history-snapshot] {} tracked files", map.len());
                }
            }
            _ => {}
        }

        ins_msg.execute(params![
            rowid,
            line_no,
            t,
            str_field(&v, "subtype"),
            uuid,
            str_field(&v, "parentUuid"),
            ts,
            role,
            model,
            v.get("isSidechain").and_then(Value::as_bool).unwrap_or(false) as i64,
            is_meta as i64,
            truncate(&text, MAX_TEXT),
            truncate(line, MAX_RAW)
        ])?;
    }

    let sid = st.session_ids.iter().max_by_key(|(_, n)| **n).map(|(s, _)| s.clone());
    let (sid, parent) = match (is_sub, sid) {
        // Sub-agent records carry the parent session id.
        (true, Some(s)) => (format!("{s}/agent-{}", agent_id.clone().unwrap_or_default()), Some(s)),
        (_, Some(s)) => (s, parent),
        (_, None) => (stem.clone(), parent),
    };
    let duration = match (&st.first_ts, &st.last_ts) {
        (Some(a), Some(b)) => chrono::DateTime::parse_from_rfc3339(b)
            .ok()
            .zip(chrono::DateTime::parse_from_rfc3339(a).ok())
            .map(|(b, a)| (b - a).num_seconds()),
        _ => None,
    };
    let cwds_str = st.cwds.keys().cloned().collect::<Vec<_>>().join(", ");
    ctx.conn.execute(
        "UPDATE sessions SET session_id=?1, parent_session=?2, title=?3, first_prompt=?4, first_ts=?5, last_ts=?6, duration_s=?7,
            records=?8, user_msgs=?9, assistant_msgs=?10, tool_calls=?11, models=?12, versions=?13, cwds=?14, git_branches=?15,
            entrypoints=?16, permission_modes=?17, input_tokens=?18, output_tokens=?19, cache_read_tokens=?20,
            cache_creation_tokens=?21, cost_usd=?22, parse_errors=?23 WHERE id=?24",
        params![
            sid, parent, st.title.or(st.summary), st.first_prompt, st.first_ts, st.last_ts, duration,
            st.records, st.user, st.assistant, st.tools, join_set(&st.models), join_set(&st.versions), cwds_str,
            join_set(&st.branches), join_set(&st.entrypoints), join_set(&st.modes), st.input, st.output, st.cache_read,
            st.cache_create, st.cost, st.errors, rowid
        ],
    )?;
    Ok((rowid, st.cwds, is_sub))
}

fn push_line(text: &mut String, s: &str) {
    if !text.is_empty() {
        text.push('\n');
    }
    text.push_str(s);
}

/// Flatten a content field (string or list of blocks) to text.
fn block_text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|b| match str_field(b, "type") {
                Some("text") => str_field(b, "text").unwrap_or("").to_string(),
                Some(other) => format!("[{other}]"),
                None => b.as_str().map(str::to_string).unwrap_or_default(),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

/// Human-readable one-liner for a tool invocation (what an analyst wants to see).
pub fn tool_summary(name: &str, input: &Value) -> String {
    let s = |k: &str| str_field(input, k).unwrap_or("").to_string();
    let out = match name {
        "Bash" | "PowerShell" | "BashOutput" => {
            let d = s("description");
            if d.is_empty() { s("command") } else { format!("{}  # {d}", s("command")) }
        }
        "Read" | "Write" | "Edit" | "MultiEdit" | "NotebookEdit" | "NotebookRead" => {
            let p = s("file_path");
            if p.is_empty() { s("notebook_path") } else { p }
        }
        "Grep" => format!("/{}/ in {}", s("pattern"), s("path")),
        "Glob" => format!("{} in {}", s("pattern"), s("path")),
        "LS" => s("path"),
        "WebFetch" => s("url"),
        "WebSearch" => s("query"),
        "Task" | "Agent" => format!("[{}] {}", s("subagent_type"), s("description")),
        "TodoWrite" => format!("{} todos", input.get("todos").and_then(Value::as_array).map_or(0, Vec::len)),
        "Skill" => s("skill"),
        _ => String::new(),
    };
    let out = if out.trim().is_empty() { input.to_string() } else { out };
    truncate(&out, 2000)
}

fn parse_history(ctx: &Ctx, pid: i64, rel: &str) {
    let Ok(f) = std::fs::File::open(ctx.abs(rel)) else { return };
    let Ok(mut stmt) = ctx.conn.prepare_cached(
        "INSERT INTO history(profile_id, ts, project, session_id, display, pasted) VALUES(?1,?2,?3,?4,?5,?6)",
    ) else {
        return;
    };
    for line in BufReader::new(f).split(b'\n').map_while(Result::ok) {
        let Ok(v) = serde_json::from_slice::<Value>(&line) else { continue };
        let pasted = v.get("pastedContents").filter(|p| p.as_object().is_some_and(|o| !o.is_empty())).map(|p| truncate(&p.to_string(), MAX_TEXT));
        let _ = stmt.execute(params![
            pid,
            json_ts(v.get("timestamp")),
            str_field(&v, "project"),
            str_field(&v, "sessionId"),
            str_field(&v, "display"),
            pasted
        ]);
    }
}

fn parse_todos(ctx: &Ctx, pid: i64, dir: &str) {
    let tdir = Ctx::join(dir, "todos");
    for rel in rel_files(ctx, &tdir) {
        let Some(v) = ctx.read_json(&rel) else { continue };
        let name = rel.rsplit('/').next().unwrap_or("").trim_end_matches(".json");
        // <session>-agent-<agent>.json
        let sid = name.split("-agent-").next().unwrap_or(name);
        let items = v.as_array().cloned().or_else(|| v.get("todos").and_then(Value::as_array).cloned()).unwrap_or_default();
        for t in items {
            let _ = ctx.conn.execute(
                "INSERT INTO todos(profile_id, session_id, file_rel, content, status, active_form) VALUES(?1,?2,?3,?4,?5,?6)",
                params![pid, sid, rel, str_field(&t, "content"), str_field(&t, "status"), str_field(&t, "activeForm")],
            );
        }
    }
}

/// Map backups in file-history/<session>/<hash>@vN to the paths recorded in transcripts.
fn link_file_history(ctx: &Ctx, pid: i64, dir: &str) -> Result<()> {
    let fdir = Ctx::join(dir, "file-history");
    let known: HashMap<(String, String), i64> = {
        let mut stmt = ctx.conn.prepare("SELECT id, session_id, backup_file FROM file_history WHERE profile_id=?1")?;
        stmt.query_map([pid], |r| Ok(((r.get::<_, String>(1)?, r.get::<_, String>(2)?), r.get(0)?)))?
            .flatten()
            .collect()
    };
    for rel in rel_files(ctx, &fdir) {
        let inner = rel.strip_prefix(&fdir).unwrap_or(&rel).trim_start_matches('/');
        let Some((sid, file)) = inner.split_once('/') else { continue };
        match known.get(&(sid.to_string(), file.to_string())) {
            Some(id) => {
                ctx.conn.execute("UPDATE file_history SET backup_rel=?1 WHERE id=?2", params![rel, id])?;
            }
            None => {
                let version = file.rsplit_once("@v").and_then(|(_, v)| v.parse::<i64>().ok());
                ctx.conn.execute(
                    "INSERT OR IGNORE INTO file_history(profile_id, session_id, original_path, backup_file, version, backup_rel) VALUES(?1,?2,NULL,?3,?4,?5)",
                    params![pid, sid, file, version, rel],
                )?;
            }
        }
    }
    Ok(())
}

/// `~/.claude/sessions/<pid>.json`: live process registry at collection time.
fn parse_registry(ctx: &Ctx, pid: i64, dir: &str) {
    for rel in rel_files(ctx, &Ctx::join(dir, "sessions")) {
        if !rel.ends_with(".json") {
            continue;
        }
        let Some(v) = ctx.read_json(&rel) else { continue };
        let _ = ctx.conn.execute(
            "INSERT INTO session_registry(profile_id, file_rel, pid, session_id, cwd, name, status, kind, entrypoint, version, started_ts, updated_ts, raw)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                pid, rel, v.get("pid").and_then(Value::as_i64), str_field(&v, "sessionId"), str_field(&v, "cwd"),
                str_field(&v, "name"), str_field(&v, "status"), str_field(&v, "kind"), str_field(&v, "entrypoint"),
                str_field(&v, "version"), json_ts(v.get("startedAt")), json_ts(v.get("updatedAt")), v.to_string()
            ],
        );
    }
}

pub fn parse_credentials_file(ctx: &Ctx, pid: i64, rel: &str) {
    let Some(v) = ctx.read_json(rel) else { return };
    walk_secrets(ctx, pid, rel, "credentials-file", "", &v, None);
}

/// Record every string leaf of a credentials document; non-secret leaves
/// (scopes, tiers) are kept as context so the analyst sees the full picture.
fn walk_secrets(ctx: &Ctx, pid: i64, rel: &str, origin: &str, path: &str, v: &Value, expires: Option<String>) {
    match v {
        Value::Object(map) => {
            let exp = map.get("expiresAt").or(map.get("expires_at")).and_then(|e| json_ts(Some(e))).or(expires);
            let ctx_str = map
                .iter()
                .filter(|(k, v)| !looks_secret_key(k) && !v.is_object())
                .map(|(k, v)| format!("{k}={}", v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string())))
                .collect::<Vec<_>>()
                .join("; ");
            for (k, child) in map {
                let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                if let Value::String(s) = child {
                    if looks_secret_key(k) {
                        let kind = if path.is_empty() { k.clone() } else { format!("{path} {k}") };
                        ctx.add_secret(Some(pid), rel, origin, &kind, &p, s, exp.clone(), &truncate(&ctx_str, 1000));
                    }
                } else {
                    walk_secrets(ctx, pid, rel, origin, &p, child, exp.clone());
                }
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                walk_secrets(ctx, pid, rel, origin, &format!("{path}[{i}]"), child, expires.clone());
            }
        }
        _ => {}
    }
}

fn collect_config(ctx: &Ctx, pid: i64, dir: &str) {
    for rel in rel_files(ctx, dir) {
        let inner = rel.strip_prefix(dir).unwrap_or(&rel).trim_start_matches('/');
        let lower = inner.to_lowercase();
        let top = lower.split('/').next().unwrap_or("");
        let name = lower.rsplit('/').next().unwrap_or("");
        let kind = match top {
            "projects" | "todos" | "file-history" | "sessions" | "cache" | "statsig" => None,
            "shell-snapshots" => Some("shell-snapshot"),
            "session-env" => Some("session-env"),
            "backups" if name.starts_with(".claude.json") => {
                super::claude_json::parse(ctx, pid, &rel).ok();
                None
            }
            "agents" => Some("agent"),
            "commands" => Some("slash-command"),
            "skills" if name == "skill.md" => Some("skill"),
            "output-styles" => Some("output-style"),
            "plugins" if inner.matches('/').count() <= 1 && name.ends_with(".json") => Some("plugin-registry"),
            "plugins" if name == "plugin.json" => Some("plugin"),
            "telemetry" => Some("telemetry"),
            "ide" => Some("ide-lock"),
            _ if name == ".credentials.json" => Some("credentials"),
            _ if name.starts_with("settings") && name.ends_with(".json") => Some("settings"),
            _ if name == "claude.md" => Some("instructions"),
            _ if !inner.contains('/') && (name.ends_with(".json") || name.ends_with(".md") || name.ends_with(".sh")) => Some("config"),
            _ => None,
        };
        let Some(kind) = kind else { continue };
        let summary = if kind == "settings" { settings_summary(ctx, pid, &rel) } else { String::new() };
        ctx.add_config(pid, &rel, kind, &summary);
    }
}

/// Settings matter for DFIR: hooks and allowed tools can be abused for persistence.
pub fn settings_summary(ctx: &Ctx, pid: i64, rel: &str) -> String {
    let Some(v) = ctx.read_json(rel) else { return String::new() };
    let mut parts = Vec::new();
    if let Some(h) = v.get("hooks").and_then(Value::as_object) {
        let n: usize = h.values().filter_map(Value::as_array).map(Vec::len).sum();
        parts.push(format!("hooks: {} events / {n} matchers ({})", h.len(), h.keys().cloned().collect::<Vec<_>>().join(", ")));
        // Hook commands run automatically: surface them, they are a persistence vector.
        let cmds: Vec<String> = h
            .iter()
            .flat_map(|(event, matchers)| {
                matchers.as_array().into_iter().flatten().flat_map(move |m| {
                    m.get("hooks").and_then(Value::as_array).into_iter().flatten().filter_map(move |hk| {
                        str_field(hk, "command").map(|c| format!("{event}[{}]: {}", str_field(m, "matcher").unwrap_or("*"), truncate(c, 300)))
                    })
                })
            })
            .collect();
        if !cmds.is_empty() {
            parts.push(format!("hook commands: {}", cmds.join(" ; ")));
        }
    }
    if let Some(p) = v.get("permissions") {
        for k in ["allow", "deny", "ask"] {
            if let Some(a) = p.get(k).and_then(Value::as_array) {
                parts.push(format!("permissions.{k}: {}", a.len()));
            }
        }
        if let Some(m) = str_field(p, "defaultMode") {
            parts.push(format!("defaultMode: {m}"));
        }
    }
    if let Some(env) = v.get("env").and_then(Value::as_object) {
        parts.push(format!("env: {}", env.keys().cloned().collect::<Vec<_>>().join(", ")));
        for (k, val) in env {
            if let Some(s) = val.as_str().filter(|_| looks_secret_key(k)) {
                ctx.add_secret(Some(pid), rel, "config", "settings-env", &format!("env.{k}"), s, None, "");
            }
        }
    }
    for k in ["apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "statusLine", "model", "forceLoginMethod"] {
        if let Some(x) = v.get(k) {
            parts.push(format!("{k}: {}", truncate(&x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string()), 200)));
        }
    }
    if let Some(m) = v.get("mcpServers") {
        ctx.add_mcp_servers(pid, rel, "settings", None, m);
    }
    if let Some(p) = v.get("enabledPlugins").and_then(Value::as_object) {
        parts.push(format!("enabledPlugins: {}", p.keys().cloned().collect::<Vec<_>>().join(", ")));
    }
    parts.join(" | ")
}

/// Project-level artifacts found outside the profile directory.
pub fn parse_loose(ctx: &Ctx, pid: i64, rel: &str) -> Result<()> {
    let pid_opt = pid;
    let parent = rel.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
    let name = rel.rsplit('/').next().unwrap_or(rel);
    if ctx.abs(rel).is_dir() {
        for f in rel_files(ctx, rel) {
            let lname = f.rsplit('/').next().unwrap_or("").to_lowercase();
            let (kind, summary) = if lname.starts_with("settings") && lname.ends_with(".json") {
                ("project-settings", settings_summary(ctx, pid_opt, &f))
            } else if f.contains("/commands/") {
                ("project-slash-command", String::new())
            } else if f.contains("/agents/") {
                ("project-agent", String::new())
            } else if f.contains("/skills/") {
                ("project-skill", String::new())
            } else {
                ("project-config", String::new())
            };
            ctx.add_config(pid_opt, &f, kind, &format!("project {parent}{}{summary}", if summary.is_empty() { "" } else { " | " }));
        }
    } else if name == ".mcp.json" {
        if let Some(v) = ctx.read_json(rel) {
            ctx.add_mcp_servers(pid_opt, rel, "project (.mcp.json)", Some(parent), v.get("mcpServers").unwrap_or(&Value::Null));
        }
        ctx.add_config(pid_opt, rel, "mcp-config", &format!("project {parent}"));
    } else {
        ctx.add_config(pid_opt, rel, "instructions", &format!("project {parent}"));
    }
    Ok(())
}

/// Aggregate per-project statistics once all sources are parsed.
pub fn finalize_projects(ctx: &Ctx) -> Result<()> {
    ctx.conn.execute_batch(
        "INSERT INTO projects(profile_id, path, sources)
            SELECT DISTINCT h.profile_id, h.project, 'history' FROM history h
            WHERE h.project IS NOT NULL
              AND NOT EXISTS (SELECT 1 FROM projects p WHERE p.profile_id = h.profile_id AND p.path = h.project);
         UPDATE projects SET
            session_count = (SELECT count(*) FROM sessions s WHERE s.project_id = projects.id AND s.is_subagent = 0),
            first_ts = (SELECT min(first_ts) FROM sessions s WHERE s.project_id = projects.id),
            last_ts = (SELECT max(last_ts) FROM sessions s WHERE s.project_id = projects.id);
         UPDATE projects SET
            first_ts = coalesce(first_ts, (SELECT min(ts) FROM history h WHERE h.profile_id = projects.profile_id AND h.project = projects.path)),
            last_ts = coalesce(last_ts, (SELECT max(ts) FROM history h WHERE h.profile_id = projects.profile_id AND h.project = projects.path));",
    )?;
    Ok(())
}
