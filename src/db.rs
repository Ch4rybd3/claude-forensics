use anyhow::Result;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::path::Path;

pub const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY, ts TEXT, user TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS warnings (
    id INTEGER PRIMARY KEY, source TEXT, message TEXT
);
-- Every file extracted from the evidence archive.
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY,
    archive_path TEXT,      -- path as stored in the archive (original spelling)
    rel_path TEXT UNIQUE,   -- sanitised path inside extracted/
    size INTEGER,
    sha256 TEXT,
    mtime TEXT,             -- modification time recorded in the archive
    mtime_note TEXT,        -- 'utc' or 'local (DOS time, no tz)'
    ctime TEXT,
    atime TEXT,
    encrypted INTEGER,
    profile_id INTEGER,
    category TEXT
);
CREATE TABLE IF NOT EXISTS profiles (
    id INTEGER PRIMARY KEY,
    root TEXT UNIQUE,         -- relative directory assumed to be the user home
    label TEXT,
    os_guess TEXT,
    claude_dir TEXT,
    desktop_dir TEXT
);
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER,
    path TEXT,                -- real working directory
    encoded_dir TEXT,         -- ~/.claude/projects/<encoded_dir>
    sources TEXT,
    session_count INTEGER DEFAULT 0,
    first_ts TEXT,
    last_ts TEXT,
    config_json TEXT,         -- entry from .claude.json "projects"
    UNIQUE(profile_id, path)
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER,
    project_id INTEGER,
    session_id TEXT,
    file_rel TEXT,
    is_subagent INTEGER,
    parent_session TEXT,
    agent_id TEXT,
    title TEXT,
    first_prompt TEXT,
    first_ts TEXT,
    last_ts TEXT,
    duration_s INTEGER,
    records INTEGER,
    user_msgs INTEGER,
    assistant_msgs INTEGER,
    tool_calls INTEGER,
    models TEXT,
    versions TEXT,
    cwds TEXT,
    git_branches TEXT,
    entrypoints TEXT,
    permission_modes TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    cache_read_tokens INTEGER,
    cache_creation_tokens INTEGER,
    cost_usd REAL,
    parse_errors INTEGER
);
CREATE INDEX IF NOT EXISTS sessions_sid ON sessions(session_id);
-- One row per JSONL record of a session transcript.
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    session_rowid INTEGER,
    line_no INTEGER,
    type TEXT,
    subtype TEXT,
    uuid TEXT,
    parent_uuid TEXT,
    ts TEXT,
    role TEXT,
    model TEXT,
    is_sidechain INTEGER,
    is_meta INTEGER,
    text TEXT,
    raw TEXT
);
CREATE INDEX IF NOT EXISTS messages_session ON messages(session_rowid, line_no);
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(text, content='messages', content_rowid='id');
CREATE TABLE IF NOT EXISTS tool_calls (
    id INTEGER PRIMARY KEY,
    session_rowid INTEGER,
    message_uuid TEXT,
    ts TEXT,
    tool_name TEXT,
    tool_use_id TEXT,
    summary TEXT,
    input_json TEXT,
    is_error INTEGER,
    result_ts TEXT,
    result_excerpt TEXT
);
CREATE INDEX IF NOT EXISTS tool_calls_session ON tool_calls(session_rowid);
CREATE INDEX IF NOT EXISTS tool_calls_tuid ON tool_calls(tool_use_id);
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER,
    ts TEXT,
    project TEXT,
    session_id TEXT,
    display TEXT,
    pasted TEXT
);
CREATE TABLE IF NOT EXISTS todos (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER,
    session_id TEXT,
    file_rel TEXT,
    content TEXT,
    status TEXT,
    active_form TEXT
);
CREATE TABLE IF NOT EXISTS file_history (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER,
    session_id TEXT,
    original_path TEXT,
    backup_file TEXT,
    version INTEGER,
    backup_ts TEXT,
    backup_rel TEXT,     -- extracted file, if present
    UNIQUE(profile_id, session_id, backup_file)
);
CREATE TABLE IF NOT EXISTS session_registry (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER,
    file_rel TEXT,
    pid INTEGER,
    session_id TEXT,
    cwd TEXT,
    name TEXT,
    status TEXT,
    kind TEXT,
    entrypoint TEXT,
    version TEXT,
    started_ts TEXT,
    updated_ts TEXT,
    raw TEXT
);
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER,
    source TEXT,
    email TEXT,
    display_name TEXT,
    full_name TEXT,
    account_uuid TEXT,
    org_uuid TEXT,
    org_name TEXT,
    org_role TEXT,
    billing_type TEXT,
    account_created TEXT,
    subscription_created TEXT,
    user_id TEXT,
    machine_id TEXT,
    first_start TEXT,
    raw TEXT
);
-- Secrets: credential files, config keys, and regex hits anywhere in the evidence.
CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER,
    file_rel TEXT,
    origin TEXT,          -- credentials-file / config / scan
    kind TEXT,
    key_path TEXT,
    value TEXT,
    value_masked TEXT,
    expires TEXT,
    context TEXT,
    UNIQUE(file_rel, key_path, value)
);
CREATE TABLE IF NOT EXISTS mcp_servers (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER,
    file_rel TEXT,
    scope TEXT,
    project TEXT,
    name TEXT,
    transport TEXT,
    command TEXT,
    args TEXT,
    url TEXT,
    env_keys TEXT,
    raw TEXT
);
CREATE TABLE IF NOT EXISTS cookies (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER,
    file_rel TEXT,
    host TEXT,
    name TEXT,
    path TEXT,
    created TEXT,
    expires TEXT,
    last_access TEXT,
    last_update TEXT,
    secure INTEGER,
    httponly INTEGER,
    samesite TEXT,
    persistent INTEGER,
    encryption TEXT,
    value TEXT,
    value_masked TEXT,
    encrypted_len INTEGER
);
CREATE TABLE IF NOT EXISTS local_storage (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER,
    file_rel TEXT,
    origin TEXT,
    key TEXT,
    value TEXT,
    value_len INTEGER
);
-- Configuration-like documents shown verbatim (settings, CLAUDE.md, agents...).
CREATE TABLE IF NOT EXISTS config_files (
    id INTEGER PRIMARY KEY,
    profile_id INTEGER,
    file_rel TEXT UNIQUE,
    kind TEXT,
    summary TEXT
);
CREATE TABLE IF NOT EXISTS timeline (
    id INTEGER PRIMARY KEY,
    ts TEXT,
    profile_id INTEGER,
    source TEXT,
    kind TEXT,
    session_id TEXT,
    summary TEXT,
    ref TEXT
);
CREATE INDEX IF NOT EXISTS timeline_ts ON timeline(ts);
"#;

pub fn create(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch(SCHEMA)?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(conn)
}

pub fn open_rw(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    Ok(conn)
}

pub fn open_ro(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    Ok(conn)
}

pub fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}

pub fn get_meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM meta WHERE key=?1", [key], |r| r.get(0))
        .optional()?)
}

pub fn audit(conn: &Connection, user: &str, action: &str, detail: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO audit(ts, user, action, detail) VALUES(?1, ?2, ?3, ?4)",
        params![crate::util::now_iso(), user, action, detail],
    )?;
    Ok(())
}

pub fn warn(conn: &Connection, source: &str, message: &str) {
    tracing::warn!("{source}: {message}");
    let _ = conn.execute(
        "INSERT INTO warnings(source, message) VALUES(?1, ?2)",
        params![source, message],
    );
}
