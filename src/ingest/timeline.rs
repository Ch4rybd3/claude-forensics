//! Materialised super-timeline built from every parsed source.

use anyhow::Result;
use rusqlite::Connection;

const SOURCES: &[&str] = &[
    // Prompts typed by the user (history.jsonl)
    "INSERT INTO timeline(ts, profile_id, source, kind, session_id, summary, ref)
     SELECT ts, profile_id, 'history', 'prompt', session_id, project || ' » ' || substr(display, 1, 400), 'history:' || id
     FROM history WHERE ts IS NOT NULL",
    // Session boundaries
    "INSERT INTO timeline(ts, profile_id, source, kind, session_id, summary, ref)
     SELECT s.first_ts, s.profile_id, 'session', CASE s.is_subagent WHEN 1 THEN 'subagent-start' ELSE 'session-start' END,
            s.session_id, coalesce(p.path, '') || ' » ' || coalesce(s.title, s.first_prompt, ''), 'session:' || s.id
     FROM sessions s LEFT JOIN projects p ON p.id = s.project_id WHERE s.first_ts IS NOT NULL",
    "INSERT INTO timeline(ts, profile_id, source, kind, session_id, summary, ref)
     SELECT s.last_ts, s.profile_id, 'session', CASE s.is_subagent WHEN 1 THEN 'subagent-end' ELSE 'session-end' END,
            s.session_id, coalesce(s.title, ''), 'session:' || s.id
     FROM sessions s WHERE s.last_ts IS NOT NULL AND s.last_ts != s.first_ts",
    // User messages in transcripts (excluding tool results and meta records)
    "INSERT INTO timeline(ts, profile_id, source, kind, session_id, summary, ref)
     SELECT m.ts, s.profile_id, 'transcript', 'user-message', s.session_id, substr(m.text, 1, 400), 'session:' || s.id || '#' || m.line_no
     FROM messages m JOIN sessions s ON s.id = m.session_rowid
     WHERE m.type = 'user' AND m.is_meta = 0 AND m.ts IS NOT NULL AND m.text NOT LIKE '[tool_result%'",
    // Tool invocations
    "INSERT INTO timeline(ts, profile_id, source, kind, session_id, summary, ref)
     SELECT t.ts, s.profile_id, 'tool', t.tool_name, s.session_id,
            CASE t.is_error WHEN 1 THEN '[ERROR] ' ELSE '' END || substr(coalesce(t.summary, ''), 1, 400), 'session:' || s.id
     FROM tool_calls t JOIN sessions s ON s.id = t.session_rowid WHERE t.ts IS NOT NULL",
    "INSERT INTO timeline(ts, profile_id, source, kind, session_id, summary, ref)
     SELECT backup_ts, profile_id, 'file-history', 'file-backup', session_id, original_path || ' (v' || version || ')', 'file:' || coalesce(backup_rel, '')
     FROM file_history WHERE backup_ts IS NOT NULL",
    "INSERT INTO timeline(ts, profile_id, source, kind, session_id, summary, ref)
     SELECT started_ts, profile_id, 'registry', 'process-start', session_id, 'pid ' || pid || ' ' || coalesce(cwd, '') || ' [' || coalesce(status, '') || ']', 'file:' || file_rel
     FROM session_registry WHERE started_ts IS NOT NULL",
    "INSERT INTO timeline(ts, profile_id, source, kind, session_id, summary, ref)
     SELECT updated_ts, profile_id, 'registry', 'process-update', session_id, 'pid ' || pid || ' ' || coalesce(status, ''), 'file:' || file_rel
     FROM session_registry WHERE updated_ts IS NOT NULL",
    "INSERT INTO timeline(ts, profile_id, source, kind, summary, ref)
     SELECT created, profile_id, 'cookie', 'cookie-created', host || ' ' || name, 'file:' || file_rel FROM cookies WHERE created IS NOT NULL",
    "INSERT INTO timeline(ts, profile_id, source, kind, summary, ref)
     SELECT last_access, profile_id, 'cookie', 'cookie-last-access', host || ' ' || name, 'file:' || file_rel FROM cookies WHERE last_access IS NOT NULL",
    "INSERT INTO timeline(ts, profile_id, source, kind, summary, ref)
     SELECT expires, profile_id, 'cookie', 'cookie-expires', host || ' ' || name, 'file:' || file_rel FROM cookies WHERE expires IS NOT NULL",
    "INSERT INTO timeline(ts, profile_id, source, kind, summary, ref)
     SELECT account_created, profile_id, 'account', 'account-created', coalesce(email, '') || ' (' || source || ')', 'file:' || source FROM accounts WHERE account_created IS NOT NULL",
    "INSERT INTO timeline(ts, profile_id, source, kind, summary, ref)
     SELECT subscription_created, profile_id, 'account', 'subscription-created', coalesce(email, '') || ' ' || coalesce(billing_type, ''), 'file:' || source FROM accounts WHERE subscription_created IS NOT NULL",
    "INSERT INTO timeline(ts, profile_id, source, kind, summary, ref)
     SELECT first_start, profile_id, 'account', 'claude-code-first-start', coalesce(email, '') || ' machine ' || coalesce(machine_id, ''), 'file:' || source FROM accounts WHERE first_start IS NOT NULL",
    "INSERT INTO timeline(ts, profile_id, source, kind, summary, ref)
     SELECT expires, profile_id, 'credential', 'credential-expires', kind || ' ' || key_path, 'file:' || file_rel FROM credentials WHERE expires IS NOT NULL",
    // File system times recorded in the archive (UTC only)
    "INSERT INTO timeline(ts, profile_id, source, kind, summary, ref)
     SELECT mtime, profile_id, 'filesystem', 'file-modified', rel_path, 'file:' || rel_path FROM files WHERE mtime IS NOT NULL AND mtime_note = 'utc'",
    "INSERT INTO timeline(ts, profile_id, source, kind, summary, ref)
     SELECT ctime, profile_id, 'filesystem', 'file-created', rel_path, 'file:' || rel_path FROM files WHERE ctime IS NOT NULL",
];

pub fn build(conn: &Connection) -> Result<()> {
    conn.execute("DELETE FROM timeline", [])?;
    for sql in SOURCES {
        if let Err(e) = conn.execute(sql, []) {
            crate::db::warn(conn, "timeline", &format!("{e}"));
        }
    }
    Ok(())
}
