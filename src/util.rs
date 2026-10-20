use chrono::{DateTime, TimeZone, Utc};
use rand::RngExt;
use serde_json::Value;

pub fn random_token(len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..len).map(|_| CHARS[rng.random_range(0..CHARS.len())] as char).collect()
}

pub fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

pub fn fmt_ts(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Epoch milliseconds -> ISO-8601 UTC.
pub fn ms_to_iso(ms: i64) -> Option<String> {
    Utc.timestamp_millis_opt(ms).single().map(fmt_ts)
}

/// Epoch seconds -> ISO-8601 UTC.
pub fn secs_to_iso(s: i64) -> Option<String> {
    Utc.timestamp_opt(s, 0).single().map(fmt_ts)
}

/// Chromium/WebKit timestamp (microseconds since 1601-01-01 UTC) -> ISO-8601.
pub fn webkit_to_iso(us: i64) -> Option<String> {
    if us <= 0 {
        return None;
    }
    let unix_us = us - 11_644_473_600_000_000;
    Utc.timestamp_micros(unix_us).single().map(fmt_ts)
}

/// Normalise any timestamp-ish JSON value (ISO string, epoch ms or s) to ISO-8601 UTC.
pub fn json_ts(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => {
            if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
                Some(fmt_ts(dt.with_timezone(&Utc)))
            } else if let Ok(n) = s.parse::<i64>() {
                num_ts(n)
            } else {
                Some(s.clone())
            }
        }
        Value::Number(n) => num_ts(n.as_i64().or_else(|| n.as_f64().map(|f| f as i64))?),
        _ => None,
    }
}

/// Heuristic: values above 1e11 are milliseconds.
pub fn num_ts(n: i64) -> Option<String> {
    if n <= 0 {
        None
    } else if n > 100_000_000_000 {
        ms_to_iso(n)
    } else {
        secs_to_iso(n)
    }
}

/// Mask a secret for display: keep a short prefix, show the length.
pub fn mask(s: &str) -> String {
    let n = s.chars().count();
    if n == 0 {
        return String::new();
    }
    let keep = if n > 24 { 12 } else if n > 8 { 4 } else { 0 };
    let prefix: String = s.chars().take(keep).collect();
    format!("{prefix}…[{n} chars masked]")
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [truncated, {} bytes total]", &s[..end], s.len())
}

pub fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// Claude Code encodes project paths as directory names by replacing every
/// non-alphanumeric character with '-'.
pub fn encode_project_path(p: &str) -> String {
    p.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect()
}

/// Join a forward-slash relative path onto a native base, component by component
/// (keeps paths well-formed on Windows, including long `\\?\` paths).
pub fn join_rel(base: &std::path::Path, rel: &str) -> std::path::PathBuf {
    let mut p = base.to_path_buf();
    for c in rel.split('/').filter(|c| !c.is_empty()) {
        p.push(c);
    }
    p
}

/// Forward-slash relative path, used everywhere in the DB.
pub fn rel_string(base: &std::path::Path, p: &std::path::Path) -> String {
    let r = p.strip_prefix(base).unwrap_or(p);
    r.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_keeps_short_prefix_only() {
        let secret = format!("sk-ant-api03-{}", "x".repeat(90));
        let m = mask(&secret);
        assert!(m.starts_with("sk-ant-api03…"));
        assert!(!m.contains("xxxx"));
        assert_eq!(mask("short"), "…[5 chars masked]");
        assert_eq!(mask(""), "");
    }

    #[test]
    fn rel_paths_round_trip() {
        let base = std::path::Path::new("base");
        let p = join_rel(base, "a/b/c.json");
        assert_eq!(rel_string(base, &p), "a/b/c.json");
    }
}
