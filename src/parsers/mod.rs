pub mod claude_code;
pub mod claude_json;
pub mod desktop;
pub mod secrets;

use rusqlite::{Connection, params};
use serde_json::Value;
use std::path::PathBuf;

pub struct Ctx<'a> {
    pub conn: &'a Connection,
    /// Root of the extracted evidence.
    pub root: PathBuf,
    /// Scratch directory for temporary copies (e.g. LevelDB needs a writable dir).
    pub work: PathBuf,
}

impl Ctx<'_> {
    pub fn abs(&self, rel: &str) -> PathBuf {
        crate::util::join_rel(&self.root, rel)
    }

    pub fn join(dir: &str, name: &str) -> String {
        if dir.is_empty() { name.to_string() } else { format!("{dir}/{name}") }
    }

    pub fn read_json(&self, rel: &str) -> Option<Value> {
        let raw = std::fs::read(self.abs(rel)).ok()?;
        match serde_json::from_slice(&raw) {
            Ok(v) => Some(v),
            Err(e) => {
                crate::db::warn(self.conn, rel, &format!("invalid JSON: {e}"));
                None
            }
        }
    }

    pub fn add_config(&self, profile_id: i64, rel: &str, kind: &str, summary: &str) {
        let _ = self.conn.execute(
            "INSERT OR IGNORE INTO config_files(profile_id, file_rel, kind, summary) VALUES(?1,?2,?3,?4)",
            params![profile_id, rel, kind, summary],
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_secret(
        &self,
        profile_id: Option<i64>,
        rel: &str,
        origin: &str,
        kind: &str,
        key_path: &str,
        value: &str,
        expires: Option<String>,
        context: &str,
    ) {
        if value.is_empty() {
            return;
        }
        let _ = self.conn.execute(
            "INSERT OR IGNORE INTO credentials(profile_id, file_rel, origin, kind, key_path, value, value_masked, expires, context)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![profile_id, rel, origin, kind, key_path, value, crate::util::mask(value), expires, context],
        );
    }

    /// Register MCP servers from a `{ "name": { command/args/url/env... } }` object.
    pub fn add_mcp_servers(&self, profile_id: i64, rel: &str, scope: &str, project: Option<&str>, servers: &Value) {
        let Some(map) = servers.as_object() else { return };
        for (name, s) in map {
            let transport = s
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or(if s.get("url").is_some() { "http" } else { "stdio" });
            let args = s.get("args").map(|a| a.to_string());
            let env_keys = s.get("env").and_then(Value::as_object).map(|e| {
                e.keys().cloned().collect::<Vec<_>>().join(", ")
            });
            let _ = self.conn.execute(
                "INSERT INTO mcp_servers(profile_id, file_rel, scope, project, name, transport, command, args, url, env_keys, raw)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    profile_id,
                    rel,
                    scope,
                    project,
                    name,
                    transport,
                    s.get("command").and_then(Value::as_str),
                    args,
                    s.get("url").and_then(Value::as_str),
                    env_keys,
                    s.to_string()
                ],
            );
            for section in ["env", "headers"] {
                if let Some(env) = s.get(section).and_then(Value::as_object) {
                    for (k, v) in env {
                        if let Some(v) = v.as_str()
                            && looks_secret_key(k) {
                                self.add_secret(Some(profile_id), rel, "config", "mcp-env", &format!("mcpServers.{name}.{section}.{k}"), v, None, scope);
                            }
                    }
                }
            }
        }
    }
}

pub fn looks_secret_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    ["key", "token", "secret", "password", "passwd", "auth", "credential", "cookie", "session"]
        .iter()
        .any(|w| k.contains(w))
}
