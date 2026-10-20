//! Parser for `~/.claude.json` (global Claude Code state) and its backups.

use super::Ctx;
use super::claude_code::upsert_project;
use crate::util::{json_ts, str_field, truncate};
use anyhow::Result;
use rusqlite::params;
use serde_json::Value;

pub fn parse(ctx: &Ctx, pid: i64, rel: &str) -> Result<()> {
    let Some(v) = ctx.read_json(rel) else { return Ok(()) };
    let is_backup = rel.rsplit('/').next().is_some_and(|n| n != ".claude.json");

    let acct = v.get("oauthAccount");
    let g = |k: &str| acct.and_then(|a| str_field(a, k));
    let mut summary = Vec::new();
    if acct.is_some() || v.get("userID").is_some() {
        ctx.conn.execute(
            "INSERT INTO accounts(profile_id, source, email, display_name, full_name, account_uuid, org_uuid, org_name, org_role,
                billing_type, account_created, subscription_created, user_id, machine_id, first_start, raw)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
            params![
                pid, rel, g("emailAddress"), g("displayName"), g("fullName"), g("accountUuid"), g("organizationUuid"),
                g("organizationName"), g("organizationRole"), g("billingType"),
                json_ts(acct.and_then(|a| a.get("accountCreatedAt"))),
                json_ts(acct.and_then(|a| a.get("subscriptionCreatedAt"))),
                str_field(&v, "userID"), str_field(&v, "machineID"), json_ts(v.get("firstStartTime")),
                acct.map(|a| a.to_string())
            ],
        )?;
        if let Some(e) = g("emailAddress") {
            summary.push(format!("account {e}"));
        }
    }

    // API keys: primaryApiKey, plus approved/rejected custom key suffixes.
    if let Some(k) = str_field(&v, "primaryApiKey") {
        ctx.add_secret(Some(pid), rel, "config", "primaryApiKey", "primaryApiKey", k, None, "");
    }
    if let Some(c) = v.get("customApiKeyResponses") {
        for state in ["approved", "rejected"] {
            for k in c.get(state).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                ctx.add_secret(Some(pid), rel, "config", "custom API key (last 20 chars)", &format!("customApiKeyResponses.{state}"), k, None, state);
            }
        }
    }

    if let Some(m) = v.get("mcpServers") {
        ctx.add_mcp_servers(pid, rel, "user", None, m);
    }

    if let Some(projects) = v.get("projects").and_then(Value::as_object) {
        summary.push(format!("{} projects", projects.len()));
        for (path, cfg) in projects {
            let enc = crate::util::encode_project_path(path);
            let source = if is_backup { "claude.json backup" } else { "claude.json" };
            let id = upsert_project(ctx, pid, path, Some(&enc), source)?;
            // Prefer the live file over backups for the stored config.
            let sql = if is_backup {
                "UPDATE projects SET config_json=coalesce(config_json, ?1), encoded_dir=coalesce(encoded_dir, ?2) WHERE id=?3"
            } else {
                "UPDATE projects SET config_json=?1, encoded_dir=coalesce(encoded_dir, ?2) WHERE id=?3"
            };
            ctx.conn.execute(sql, params![truncate(&cfg.to_string(), 1024 * 1024), enc, id])?;
            if !is_backup
                && let Some(m) = cfg.get("mcpServers") {
                    ctx.add_mcp_servers(pid, rel, "local (project)", Some(path), m);
                }
        }
    }

    for k in ["numStartups", "firstStartTime", "installMethod", "autoUpdates", "lastOnboardingVersion", "lastReleaseNotesSeen"] {
        if let Some(x) = v.get(k) {
            summary.push(format!("{k}: {}", x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())));
        }
    }
    ctx.add_config(pid, rel, if is_backup { "claude-json-backup" } else { "claude-json" }, &summary.join(" | "));
    Ok(())
}
