use crate::auth::{self, Sessions, User};
use crate::case::CaseStore;
use crate::config::Config;
use crate::{db, ingest};
use anyhow::{Context, anyhow};
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router, middleware};
use md5::Md5;
use rusqlite::types::ValueRef;
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub store: CaseStore,
    pub sessions: Arc<Sessions>,
}

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    std::fs::create_dir_all(&cfg.data_dir)
        .with_context(|| format!("creating data dir {}", cfg.data_dir.display()))?;
    let store = CaseStore::new(&cfg.data_dir)?;
    store.mark_interrupted();
    let addr = format!("{}:{}", cfg.bind, cfg.port);
    let state = AppState { cfg: Arc::new(cfg), store, sessions: Arc::new(Sessions::new()) };

    let api = Router::new()
        .route("/me", get(me))
        .route("/logout", post(logout))
        .route("/cases", get(list_cases).post(upload_case))
        .route("/cases/{id}", get(case_overview).delete(delete_case))
        .route("/cases/{id}/table/{view}", get(table))
        .route("/cases/{id}/export/{view}", get(export))
        .route("/cases/{id}/sessions/{rowid}", get(session_detail))
        .route("/cases/{id}/messages/{msgid}/raw", get(message_raw))
        .route("/cases/{id}/search", get(search))
        .route("/cases/{id}/file", get(file_content))
        .route("/cases/{id}/reveal/{table}/{rowid}", post(reveal))
        .layer(middleware::from_fn_with_state(state.clone(), auth::require_auth))
        .route("/login", post(login))
        .layer(DefaultBodyLimit::disable());

    let app = Router::new()
        .route("/", get(|| async { static_file("text/html; charset=utf-8", include_str!("../static/index.html")) }))
        .route("/app.js", get(|| async { static_file("text/javascript; charset=utf-8", include_str!("../static/app.js")) }))
        .route("/style.css", get(|| async { static_file("text/css; charset=utf-8", include_str!("../static/style.css")) }))
        .nest("/api", api)
        .layer(middleware::from_fn(security_headers))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!("claude-forensics listening on http://{addr}  (data: {})", state.cfg.data_dir.display());
    if state.cfg.bind == "0.0.0.0" || state.cfg.bind == "::" {
        tracing::warn!("listening on ALL interfaces over plain HTTP: restrict access with a firewall or a TLS reverse proxy");
    }
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
    Ok(())
}

fn static_file(ct: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, "no-cache")], body).into_response()
}

async fn security_headers(req: axum::extract::Request, next: middleware::Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    h.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    h.insert("Referrer-Policy", HeaderValue::from_static("no-referrer"));
    h.insert(
        "Content-Security-Policy",
        HeaderValue::from_static("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'"),
    );
    res
}

// ---------------------------------------------------------------- errors

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        let msg = format!("{e:#}");
        let code = if msg.contains("not found") { StatusCode::NOT_FOUND } else { StatusCode::BAD_REQUEST };
        ApiError(code, msg)
    }
}

type ApiResult<T> = Result<T, ApiError>;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> anyhow::Result<T> + Send + 'static) -> ApiResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| ApiError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .map_err(ApiError::from)
}

// ---------------------------------------------------------------- auth

#[derive(Deserialize)]
struct LoginReq {
    username: String,
    password: String,
}

async fn login(
    State(st): State<AppState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(req): Json<LoginReq>,
) -> Response {
    let cfg = st.cfg.clone();
    let ok = tokio::task::spawn_blocking(move || auth::check_credentials(&cfg, &req.username, &req.password))
        .await
        .unwrap_or(false);
    if !ok {
        tracing::warn!("failed login from {peer}");
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        return ApiError(StatusCode::UNAUTHORIZED, "invalid credentials".into()).into_response();
    }
    tracing::info!("login '{}' from {peer}", st.cfg.username);
    let token = st.sessions.create(&st.cfg.username);
    let cookie = format!("{}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200", auth::COOKIE);
    ([(header::SET_COOKIE, cookie)], Json(json!({ "user": st.cfg.username }))).into_response()
}

async fn logout(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(t) = auth::token_from_headers(&headers) {
        st.sessions.remove(&t);
    }
    let cookie = format!("{}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0", auth::COOKIE);
    ([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response()
}

async fn me(Extension(User(u)): Extension<User>) -> Json<Value> {
    Json(json!({ "user": u, "version": env!("CARGO_PKG_VERSION") }))
}

// ---------------------------------------------------------------- cases

async fn list_cases(State(st): State<AppState>) -> ApiResult<Json<Value>> {
    let store = st.store.clone();
    let list = blocking(move || Ok(store.list())).await?;
    Ok(Json(json!(list)))
}

fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("evidence");
    let s: String = base
        .chars()
        .map(|c| if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .collect();
    let s = s.trim_start_matches('.').to_string();
    if s.is_empty() { "evidence.bin".into() } else { s }
}

/// Multipart upload: text fields (name, examiner, notes, password) then `file`.
/// The archive is streamed to disk while computing MD5/SHA-1/SHA-256.
async fn upload_case(
    State(st): State<AppState>,
    Extension(User(user)): Extension<User>,
    mut mp: Multipart,
) -> ApiResult<Json<Value>> {
    let id = CaseStore::new_id();
    let dir = st.store.dir(&id)?;
    let evidence_dir = dir.join("evidence");
    tokio::fs::create_dir_all(&evidence_dir).await.map_err(anyhow::Error::from)?;

    let mut fields: HashMap<String, String> = HashMap::new();
    let mut saved: Option<(String, std::path::PathBuf, u64, String, String, String)> = None;
    let result: anyhow::Result<()> = async {
        while let Some(mut field) = mp.next_field().await? {
            let name = field.name().unwrap_or("").to_string();
            if name == "file" {
                let orig = field.file_name().unwrap_or("evidence").to_string();
                let path = evidence_dir.join(sanitize_filename(&orig));
                let mut out = tokio::fs::File::create(&path).await?;
                let (mut sha256, mut sha1, mut md5) = (Sha256::new(), Sha1::new(), Md5::new());
                let mut size = 0u64;
                while let Some(chunk) = field.chunk().await? {
                    sha256.update(&chunk);
                    sha1.update(&chunk);
                    md5.update(&chunk);
                    size += chunk.len() as u64;
                    out.write_all(&chunk).await?;
                }
                out.flush().await?;
                out.sync_all().await?;
                saved = Some((
                    orig,
                    path,
                    size,
                    hex::encode(sha256.finalize()),
                    hex::encode(sha1.finalize()),
                    hex::encode(md5.finalize()),
                ));
            } else {
                fields.insert(name, field.text().await?);
            }
        }
        Ok(())
    }
    .await;
    let cleanup = |e: anyhow::Error| {
        let _ = std::fs::remove_dir_all(&dir);
        ApiError::from(e)
    };
    result.map_err(cleanup)?;
    let (orig, path, size, sha256, sha1, md5) = saved.ok_or_else(|| cleanup(anyhow!("no file uploaded")))?;
    if size == 0 {
        return Err(cleanup(anyhow!("uploaded file is empty")));
    }
    if let Err(e) = ingest::archive::detect(&path) {
        return Err(cleanup(e));
    }

    let db_path = dir.join("case.db");
    let password = fields.get("password").filter(|p| !p.is_empty()).cloned();
    let id2 = id.clone();
    let name = fields.get("name").filter(|s| !s.trim().is_empty()).cloned().unwrap_or_else(|| orig.clone());
    let meta = vec![
        ("id", id.clone()),
        ("name", name),
        ("examiner", fields.get("examiner").cloned().unwrap_or_default()),
        ("notes", fields.get("notes").cloned().unwrap_or_default()),
        ("created", crate::util::now_iso()),
        ("created_by", user.clone()),
        ("status", "ingesting".into()),
        ("stage", "queued".into()),
        ("archive_name", orig.clone()),
        ("archive_stored_as", crate::util::rel_string(&dir, &path)),
        ("archive_size", size.to_string()),
        ("archive_sha256", sha256.clone()),
        ("archive_sha1", sha1),
        ("archive_md5", md5),
        ("archive_password_used", if password.is_some() { "yes" } else { "no" }.into()),
        ("tool_version", env!("CARGO_PKG_VERSION").into()),
    ];
    let dir2 = dir.clone();
    blocking(move || {
        let conn = db::create(&db_path)?;
        for (k, v) in &meta {
            db::set_meta(&conn, k, v)?;
        }
        db::audit(&conn, &user, "ingest", &format!("uploaded {orig} ({size} bytes, sha256 {sha256})"))?;
        drop(conn);
        let job = ingest::Job {
            db_path,
            evidence: path,
            extracted: dir2.join("extracted"),
            work: dir2.join("tmp"),
            password,
        };
        std::thread::Builder::new().name(format!("ingest-{id2}")).spawn(move || ingest::run(job))?;
        Ok(())
    })
    .await
    .inspect_err(|_e| {
        let _ = std::fs::remove_dir_all(&dir);
    })?;
    Ok(Json(json!({ "id": id })))
}

async fn delete_case(
    State(st): State<AppState>,
    Extension(User(user)): Extension<User>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let store = st.store.clone();
    blocking(move || {
        tracing::warn!("case {id} deleted by {user}");
        store.delete(&id)
    })
    .await?;
    Ok(Json(json!({ "ok": true })))
}

fn open_case(st: &AppState, id: &str) -> anyhow::Result<rusqlite::Connection> {
    db::open_ro(&st.store.db_path(id)?)
}

fn count(conn: &rusqlite::Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |r| r.get(0)).unwrap_or(0)
}

async fn case_overview(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    blocking(move || {
        let conn = open_case(&st, &id)?;
        let meta: serde_json::Map<String, Value> = conn
            .prepare("SELECT key, value FROM meta")?
            .query_map([], |r| Ok((r.get::<_, String>(0)?, Value::String(r.get::<_, String>(1)?))))?
            .collect::<Result<_, _>>()?;
        let counts: serde_json::Map<String, Value> = [
            ("files", "SELECT count(*) FROM files"),
            ("profiles", "SELECT count(*) FROM profiles"),
            ("projects", "SELECT count(*) FROM projects"),
            ("sessions", "SELECT count(*) FROM sessions WHERE is_subagent=0"),
            ("subagents", "SELECT count(*) FROM sessions WHERE is_subagent=1"),
            ("messages", "SELECT count(*) FROM messages WHERE type IN ('user','assistant')"),
            ("tool_calls", "SELECT count(*) FROM tool_calls"),
            ("history", "SELECT count(*) FROM history"),
            ("accounts", "SELECT count(DISTINCT coalesce(account_uuid, email, user_id)) FROM accounts"),
            ("credentials", "SELECT count(*) FROM credentials"),
            ("mcp_servers", "SELECT count(*) FROM mcp_servers"),
            ("cookies", "SELECT count(*) FROM cookies"),
            ("local_storage", "SELECT count(*) FROM local_storage"),
            ("config_files", "SELECT count(*) FROM config_files"),
            ("file_history", "SELECT count(*) FROM file_history"),
            ("todos", "SELECT count(*) FROM todos"),
            ("timeline", "SELECT count(*) FROM timeline"),
            ("warnings", "SELECT count(*) FROM warnings"),
        ]
        .into_iter()
        .map(|(k, sql)| (k.to_string(), json!(count(&conn, sql))))
        .collect();
        let profiles = rows_json(&conn, &format!("SELECT * FROM ({}) LIMIT 200", view_sql("profiles").unwrap()), &[])?;
        let accounts = rows_json(
            &conn,
            "SELECT pf.label AS profile, a.email, a.display_name, a.org_name, a.org_role, a.billing_type, a.account_created,
                    a.first_start, a.machine_id, a.source
             FROM accounts a LEFT JOIN profiles pf ON pf.id = a.profile_id
             GROUP BY coalesce(a.account_uuid, a.email, a.user_id), a.profile_id ORDER BY a.profile_id",
            &[],
        )?;
        let range = rows_json(&conn, "SELECT min(ts) AS first, max(ts) AS last FROM timeline WHERE source NOT IN ('filesystem','cookie','credential','account')", &[])?;
        let tools = rows_json(&conn, "SELECT tool_name, count(*) AS n FROM tool_calls GROUP BY tool_name ORDER BY n DESC LIMIT 15", &[])?;
        Ok(Json(json!({
            "meta": meta, "counts": counts, "profiles": profiles, "accounts": accounts,
            "activity_range": range, "top_tools": tools
        })))
    })
    .await
}

// ---------------------------------------------------------------- generic tabular views

/// Whitelisted views. Each is wrapped as a subquery so filters/sort can be
/// applied generically against validated column names.
fn view_sql(name: &str) -> Option<&'static str> {
    Some(match name {
        "profiles" => "SELECT p.id, p.label, p.root, p.os_guess, p.claude_dir, p.desktop_dir,
                (SELECT count(*) FROM sessions s WHERE s.profile_id = p.id AND s.is_subagent = 0) AS sessions,
                (SELECT count(*) FROM projects x WHERE x.profile_id = p.id) AS projects,
                (SELECT group_concat(DISTINCT email) FROM accounts a WHERE a.profile_id = p.id) AS accounts
            FROM profiles p",
        "projects" => "SELECT pr.id, pf.label AS profile, pr.path, pr.session_count AS sessions, pr.first_ts, pr.last_ts,
                pr.sources, pr.encoded_dir,
                json_extract(pr.config_json, '$.hasTrustDialogAccepted') AS trust_accepted,
                json_extract(pr.config_json, '$.allowedTools') AS allowed_tools,
                json_extract(pr.config_json, '$.lastCost') AS last_cost,
                json_extract(pr.config_json, '$.lastSessionId') AS last_session_id
            FROM projects pr LEFT JOIN profiles pf ON pf.id = pr.profile_id",
        "sessions" => "SELECT s.id, pf.label AS profile, pr.path AS project, s.session_id, s.title, s.first_prompt,
                s.first_ts, s.last_ts, s.duration_s, s.user_msgs, s.assistant_msgs, s.tool_calls, s.models, s.versions,
                s.git_branches, s.entrypoints, s.permission_modes, s.input_tokens, s.output_tokens, s.cache_read_tokens,
                s.cost_usd, s.is_subagent, s.parent_session, s.parse_errors, s.file_rel
            FROM sessions s LEFT JOIN profiles pf ON pf.id = s.profile_id LEFT JOIN projects pr ON pr.id = s.project_id",
        "tool_calls" => "SELECT t.id, t.ts, pf.label AS profile, pr.path AS project, s.session_id, t.session_rowid,
                t.tool_name, t.summary, t.is_error, t.result_excerpt, t.tool_use_id
            FROM tool_calls t JOIN sessions s ON s.id = t.session_rowid
            LEFT JOIN profiles pf ON pf.id = s.profile_id LEFT JOIN projects pr ON pr.id = s.project_id",
        "history" => "SELECT h.id, h.ts, pf.label AS profile, h.project, h.session_id, h.display, h.pasted
            FROM history h LEFT JOIN profiles pf ON pf.id = h.profile_id",
        "todos" => "SELECT t.id, pf.label AS profile, t.session_id, t.status, t.content, t.active_form, t.file_rel
            FROM todos t LEFT JOIN profiles pf ON pf.id = t.profile_id",
        "file_history" => "SELECT f.id, f.backup_ts, pf.label AS profile, f.session_id, f.original_path, f.version,
                f.backup_file, f.backup_rel
            FROM file_history f LEFT JOIN profiles pf ON pf.id = f.profile_id",
        "registry" => "SELECT r.id, pf.label AS profile, r.pid, r.session_id, r.name, r.status, r.kind, r.cwd,
                r.entrypoint, r.version, r.started_ts, r.updated_ts, r.file_rel
            FROM session_registry r LEFT JOIN profiles pf ON pf.id = r.profile_id",
        "accounts" => "SELECT a.id, pf.label AS profile, a.email, a.display_name, a.full_name, a.account_uuid,
                a.org_uuid, a.org_name, a.org_role, a.billing_type, a.account_created, a.subscription_created,
                a.user_id, a.machine_id, a.first_start, a.source
            FROM accounts a LEFT JOIN profiles pf ON pf.id = a.profile_id",
        "credentials" => "SELECT c.id, pf.label AS profile, c.origin, c.kind, c.key_path, c.value_masked, c.expires,
                c.file_rel, c.context
            FROM credentials c LEFT JOIN profiles pf ON pf.id = c.profile_id",
        "mcp" => "SELECT m.id, pf.label AS profile, m.scope, m.project, m.name, m.transport, m.command, m.args,
                m.url, m.env_keys, m.file_rel
            FROM mcp_servers m LEFT JOIN profiles pf ON pf.id = m.profile_id",
        "cookies" => "SELECT c.id, pf.label AS profile, c.host, c.name, c.path, c.created, c.expires, c.last_access,
                c.last_update, c.secure, c.httponly, c.samesite, c.persistent, c.encryption, c.encrypted_len,
                c.value_masked, c.file_rel
            FROM cookies c LEFT JOIN profiles pf ON pf.id = c.profile_id",
        "local_storage" => "SELECT l.id, pf.label AS profile, l.origin, l.key, substr(l.value, 1, 2000) AS value,
                l.value_len, l.file_rel
            FROM local_storage l LEFT JOIN profiles pf ON pf.id = l.profile_id",
        "config" => "SELECT c.id, pf.label AS profile, c.kind, c.file_rel, c.summary, f.size, f.mtime
            FROM config_files c LEFT JOIN profiles pf ON pf.id = c.profile_id LEFT JOIN files f ON f.rel_path = c.file_rel",
        "files" => "SELECT f.id, pf.label AS profile, f.category, f.rel_path, f.size, f.sha256, f.mtime, f.mtime_note,
                f.ctime, f.atime, f.encrypted, f.archive_path
            FROM files f LEFT JOIN profiles pf ON pf.id = f.profile_id",
        "timeline" => "SELECT t.id, t.ts, pf.label AS profile, t.source, t.kind, t.session_id, t.summary, t.ref
            FROM timeline t LEFT JOIN profiles pf ON pf.id = t.profile_id",
        "warnings" => "SELECT id, source, message FROM warnings",
        "audit" => "SELECT id, ts, user, action, detail FROM audit",
        _ => return None,
    })
}

fn time_column(view: &str) -> &'static str {
    match view {
        "sessions" | "projects" => "first_ts",
        "file_history" => "backup_ts",
        "registry" => "started_ts",
        "cookies" => "created",
        "accounts" => "account_created",
        "files" => "mtime",
        _ => "ts",
    }
}

fn value_json(v: ValueRef<'_>) -> Value {
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => json!(i),
        ValueRef::Real(f) => json!(f),
        ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Value::String(format!("<blob {} bytes>", b.len())),
    }
}

fn rows_json(conn: &rusqlite::Connection, sql: &str, params: &[rusqlite::types::Value]) -> anyhow::Result<Vec<Value>> {
    let mut stmt = conn.prepare(sql)?;
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let mut rows = stmt.query(rusqlite::params_from_iter(params.iter()))?;
    let mut out = Vec::new();
    while let Some(r) = rows.next()? {
        let mut obj = serde_json::Map::new();
        for (i, c) in cols.iter().enumerate() {
            obj.insert(c.clone(), value_json(r.get_ref(i)?));
        }
        out.push(Value::Object(obj));
    }
    Ok(out)
}

struct Filtered {
    sql: String,
    params: Vec<rusqlite::types::Value>,
    columns: Vec<String>,
}

/// Build `SELECT * FROM (<view>) WHERE ... ORDER BY ...` from query parameters.
/// Column names are validated against the view, values are bound.
fn build_query(conn: &rusqlite::Connection, view: &str, q: &HashMap<String, String>) -> anyhow::Result<Filtered> {
    let base = view_sql(view).ok_or_else(|| anyhow!("unknown view '{view}'"))?;
    let columns: Vec<String> = conn
        .prepare(&format!("SELECT * FROM ({base}) LIMIT 0"))?
        .column_names()
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut wh: Vec<String> = Vec::new();
    let mut params: Vec<rusqlite::types::Value> = Vec::new();
    if let Some(s) = q.get("q").map(|s| s.trim()).filter(|s| !s.is_empty()) {
        // Every whitespace-separated term must match somewhere in the row.
        for term in s.split_whitespace() {
            let ors: Vec<String> = columns.iter().map(|c| format!("CAST(\"{c}\" AS TEXT) LIKE ?")).collect();
            wh.push(format!("({})", ors.join(" OR ")));
            for _ in &columns {
                params.push(format!("%{term}%").into());
            }
        }
    }
    for (k, v) in q {
        if let Some(col) = k.strip_prefix("f_")
            && columns.iter().any(|c| c == col) {
                if v == "__null" {
                    wh.push(format!("\"{col}\" IS NULL"));
                } else {
                    wh.push(format!("CAST(\"{col}\" AS TEXT) = ?"));
                    params.push(v.clone().into());
                }
            }
    }
    let tcol = time_column(view);
    if columns.iter().any(|c| c == tcol) {
        if let Some(from) = q.get("from").filter(|s| !s.is_empty()) {
            wh.push(format!("\"{tcol}\" >= ?"));
            params.push(from.clone().into());
        }
        if let Some(to) = q.get("to").filter(|s| !s.is_empty()) {
            wh.push(format!("\"{tcol}\" <= ?"));
            params.push(format!("{to}\u{10FFFF}").into());
        }
    }
    let mut sql = format!("SELECT * FROM ({base}) AS v");
    if !wh.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&wh.join(" AND "));
    }
    let default_sort = if columns.iter().any(|c| c == tcol) { tcol } else { "id" };
    let sort = q.get("sort").filter(|s| columns.iter().any(|c| c == *s)).map(String::as_str).unwrap_or(default_sort);
    let dir = match q.get("dir").map(String::as_str) {
        Some("desc") => "DESC",
        Some("asc") => "ASC",
        _ => "ASC",
    };
    let tiebreak = if columns.iter().any(|c| c == "id") { ", \"id\"" } else { "" };
    sql.push_str(&format!(" ORDER BY \"{sort}\" {dir} NULLS LAST{tiebreak}"));
    Ok(Filtered { sql, params, columns })
}

async fn table(
    State(st): State<AppState>,
    Path((id, view)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    blocking(move || {
        let conn = open_case(&st, &id)?;
        let f = build_query(&conn, &view, &q)?;
        let total: i64 = conn.query_row(
            &format!("SELECT count(*) FROM ({})", f.sql),
            rusqlite::params_from_iter(f.params.iter()),
            |r| r.get(0),
        )?;
        let limit: i64 = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(100).clamp(1, 5000);
        let offset: i64 = q.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0).max(0);
        let mut stmt = conn.prepare(&format!("{} LIMIT {limit} OFFSET {offset}", f.sql))?;
        let mut rows = stmt.query(rusqlite::params_from_iter(f.params.iter()))?;
        let mut out = Vec::new();
        while let Some(r) = rows.next()? {
            let row: Vec<Value> = (0..f.columns.len()).map(|i| r.get_ref(i).map(value_json).unwrap_or(Value::Null)).collect();
            out.push(Value::Array(row));
        }
        Ok(Json(json!({ "columns": f.columns, "rows": out, "total": total, "limit": limit, "offset": offset })))
    })
    .await
}

/// Neutralise spreadsheet formula injection when CSV exports are opened in Excel.
fn csv_cell(v: &Value) -> String {
    let s = match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{s}") } else { s };
    if s.contains([',', '"', '\n', '\r']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s }
}

async fn export(
    State(st): State<AppState>,
    Extension(User(user)): Extension<User>,
    Path((id, view)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Response> {
    let format = q.get("format").cloned().unwrap_or_else(|| "csv".into());
    let id2 = id.clone();
    let view2 = view.clone();
    let body = blocking(move || {
        let conn = open_case(&st, &id)?;
        let f = build_query(&conn, &view, &q)?;
        let rows = rows_json(&conn, &f.sql, &f.params)?;
        let n = rows.len();
        let out = if format == "json" {
            serde_json::to_string_pretty(&rows)?
        } else {
            let mut s = f.columns.iter().map(|c| csv_cell(&json!(c))).collect::<Vec<_>>().join(",");
            s.push_str("\r\n");
            for r in &rows {
                let line: Vec<String> = f.columns.iter().map(|c| csv_cell(r.get(c).unwrap_or(&Value::Null))).collect();
                s.push_str(&line.join(","));
                s.push_str("\r\n");
            }
            s
        };
        let wconn = db::open_rw(&st.store.db_path(&id)?)?;
        db::audit(&wconn, &user, "export", &format!("{view} as {format}: {n} rows, filters {q:?}"))?;
        Ok((out, format))
    })
    .await?;
    let (out, format) = body;
    let (ct, ext) = if format == "json" { ("application/json", "json") } else { ("text/csv; charset=utf-8", "csv") };
    let disp = format!("attachment; filename=\"{id2}-{view2}.{ext}\"");
    Ok(([(header::CONTENT_TYPE, ct.to_string()), (header::CONTENT_DISPOSITION, disp)], out).into_response())
}

// ---------------------------------------------------------------- sessions & search

async fn session_detail(State(st): State<AppState>, Path((id, rowid)): Path<(String, i64)>) -> ApiResult<Json<Value>> {
    blocking(move || {
        let conn = open_case(&st, &id)?;
        let p = [rusqlite::types::Value::Integer(rowid)];
        let session = rows_json(&conn, &format!("SELECT * FROM ({}) WHERE id = ?", view_sql("sessions").unwrap()), &p)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("session not found"))?;
        let messages = rows_json(
            &conn,
            "SELECT id, line_no, type, subtype, uuid, parent_uuid, ts, role, model, is_sidechain, is_meta, text, length(raw) AS raw_len
             FROM messages WHERE session_rowid = ? ORDER BY line_no",
            &p,
        )?;
        let tools = rows_json(
            &conn,
            "SELECT id, ts, tool_name, tool_use_id, summary, is_error, result_excerpt, message_uuid FROM tool_calls WHERE session_rowid = ? ORDER BY id",
            &p,
        )?;
        let sid = session.get("session_id").and_then(Value::as_str).unwrap_or("").to_string();
        let parent = sid.split('/').next().unwrap_or("").to_string();
        let sp = [rusqlite::types::Value::Text(parent.clone())];
        let todos = rows_json(&conn, "SELECT status, content, active_form, file_rel FROM todos WHERE session_id = ?", &sp)?;
        let files = rows_json(
            &conn,
            "SELECT original_path, version, backup_ts, backup_file, backup_rel FROM file_history WHERE session_id = ? ORDER BY original_path, version",
            &sp,
        )?;
        let subagents = rows_json(
            &conn,
            "SELECT id, session_id, title, first_prompt, first_ts, tool_calls FROM sessions WHERE is_subagent = 1 AND parent_session = ? ORDER BY first_ts",
            &sp,
        )?;
        let prompts = rows_json(&conn, "SELECT ts, display FROM history WHERE session_id = ? ORDER BY ts", &sp)?;
        Ok(Json(json!({
            "session": session, "messages": messages, "tool_calls": tools, "todos": todos,
            "file_history": files, "subagents": subagents, "history": prompts
        })))
    })
    .await
}

async fn message_raw(State(st): State<AppState>, Path((id, msgid)): Path<(String, i64)>) -> ApiResult<Json<Value>> {
    blocking(move || {
        let conn = open_case(&st, &id)?;
        let raw: String = conn.query_row("SELECT raw FROM messages WHERE id = ?", [msgid], |r| r.get(0))?;
        let parsed: Value = serde_json::from_str(&raw).unwrap_or(Value::String(raw));
        Ok(Json(parsed))
    })
    .await
}

async fn search(
    State(st): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Json<Value>> {
    blocking(move || {
        let conn = open_case(&st, &id)?;
        let query = q.get("q").cloned().unwrap_or_default();
        if query.trim().is_empty() {
            return Ok(Json(json!({ "rows": [], "total": 0 })));
        }
        // Raw FTS5 syntax when requested, otherwise quote each term (prefix match on the last).
        let fts = if q.get("raw").map(String::as_str) == Some("1") {
            query.clone()
        } else {
            query
                .split_whitespace()
                .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let limit: i64 = q.get("limit").and_then(|s| s.parse().ok()).unwrap_or(200).clamp(1, 2000);
        let mut where_extra = String::new();
        let mut params: Vec<rusqlite::types::Value> = vec![fts.clone().into()];
        if let Some(t) = q.get("type").filter(|s| !s.is_empty()) {
            where_extra.push_str(" AND m.type = ?");
            params.push(t.clone().into());
        } else {
            // These records repeat the last prompt / title after every turn: pure noise.
            where_extra.push_str(" AND m.type NOT IN ('last-prompt', 'ai-title', 'custom-title')");
        }
        let total: i64 = conn.query_row(
            &format!("SELECT count(*) FROM messages_fts f JOIN messages m ON m.id = f.rowid WHERE messages_fts MATCH ?{where_extra}"),
            rusqlite::params_from_iter(params.iter()),
            |r| r.get(0),
        )?;
        let rows = rows_json(
            &conn,
            &format!(
                "SELECT m.id, m.ts, m.type, m.line_no, s.id AS session_rowid, s.session_id, s.title, pr.path AS project, pf.label AS profile,
                        snippet(messages_fts, 0, '\u{1}', '\u{2}', ' … ', 24) AS snippet
                 FROM messages_fts f JOIN messages m ON m.id = f.rowid
                 JOIN sessions s ON s.id = m.session_rowid
                 LEFT JOIN projects pr ON pr.id = s.project_id LEFT JOIN profiles pf ON pf.id = s.profile_id
                 WHERE messages_fts MATCH ?{where_extra} ORDER BY m.ts LIMIT {limit}"
            ),
            &params,
        )?;
        Ok(Json(json!({ "rows": rows, "total": total, "fts": fts })))
    })
    .await
}

const MAX_VIEW: u64 = 4 * 1024 * 1024;

async fn file_content(
    State(st): State<AppState>,
    Extension(User(user)): Extension<User>,
    Path(id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> ApiResult<Response> {
    let rel = q.get("path").cloned().ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, "missing path".into()))?;
    let download = q.get("download").is_some_and(|v| v == "1");
    blocking(move || {
        let conn = open_case(&st, &id)?;
        // Only files recorded in the case can be served (no path traversal).
        let meta = rows_json(&conn, "SELECT * FROM files WHERE rel_path = ?", &[rel.clone().into()])?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("file not found in case"))?;
        let path = crate::util::join_rel(&st.store.dir(&id)?.join("extracted"), &rel);
        if download {
            let data = std::fs::read(&path)?;
            let wconn = db::open_rw(&st.store.db_path(&id)?)?;
            db::audit(&wconn, &user, "download", &rel)?;
            let name = rel.rsplit('/').next().unwrap_or("file").replace('"', "_");
            return Ok((
                [
                    (header::CONTENT_TYPE, "application/octet-stream".to_string()),
                    (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
                ],
                data,
            )
                .into_response());
        }
        let size = std::fs::metadata(&path)?.len();
        let mut data = Vec::new();
        use std::io::Read;
        std::fs::File::open(&path)?.take(MAX_VIEW).read_to_end(&mut data)?;
        let sample = &data[..data.len().min(8192)];
        let binary = sample.contains(&0) && !looks_utf16(sample);
        let content = if binary {
            hexdump(&data[..data.len().min(64 * 1024)])
        } else if looks_utf16(sample) {
            let u: Vec<u16> = data.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&u)
        } else {
            String::from_utf8_lossy(&data).into_owned()
        };
        Ok(Json(json!({
            "meta": meta, "binary": binary, "truncated": size > MAX_VIEW || (binary && data.len() > 64 * 1024),
            "content": content
        }))
        .into_response())
    })
    .await
}

fn looks_utf16(b: &[u8]) -> bool {
    b.len() >= 4 && b.iter().skip(1).step_by(2).take(64).filter(|x| **x == 0).count() > 24
}

fn hexdump(b: &[u8]) -> String {
    let mut s = String::new();
    for (i, chunk) in b.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|x| format!("{x:02x}")).collect();
        let ascii: String = chunk.iter().map(|&x| if (0x20..0x7f).contains(&x) { x as char } else { '.' }).collect();
        s.push_str(&format!("{:08x}  {:<48}  {}\n", i * 16, hex.join(" "), ascii));
    }
    s
}

async fn reveal(
    State(st): State<AppState>,
    Extension(User(user)): Extension<User>,
    Path((id, table, rowid)): Path<(String, String, i64)>,
) -> ApiResult<Json<Value>> {
    blocking(move || {
        let (sql, label) = match table.as_str() {
            "credentials" => ("SELECT value, kind || ' ' || key_path || ' @ ' || file_rel FROM credentials WHERE id = ?", "credential"),
            "cookies" => ("SELECT value, host || ' ' || name FROM cookies WHERE id = ?", "cookie"),
            _ => return Err(anyhow!("cannot reveal from '{table}'")),
        };
        let conn = db::open_rw(&st.store.db_path(&id)?)?;
        let (value, what): (Option<String>, String) = conn.query_row(sql, [rowid], |r| Ok((r.get(0)?, r.get(1)?)))?;
        db::audit(&conn, &user, "reveal-secret", &format!("{label} #{rowid}: {what}"))?;
        tracing::warn!("secret revealed by {user}: case {id} {label} #{rowid}");
        Ok(Json(json!({ "value": value })))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_cells_resist_formula_injection() {
        assert_eq!(csv_cell(&json!("=HYPERLINK(\"x\")")), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_cell(&json!("+1")), "'+1");
        assert_eq!(csv_cell(&json!("@cmd")), "'@cmd");
        assert_eq!(csv_cell(&json!("a,b")), "\"a,b\"");
        assert_eq!(csv_cell(&json!(42)), "42");
        assert_eq!(csv_cell(&Value::Null), "");
    }

    #[test]
    fn upload_names_are_flattened() {
        assert_eq!(sanitize_filename("../../evil.zip"), "evil.zip");
        assert_eq!(sanitize_filename("C:\\x\\.hidden"), "hidden");
        assert_eq!(sanitize_filename("a b;c.7z"), "a_b_c.7z");
        assert_eq!(sanitize_filename(""), "evidence.bin");
    }
}
