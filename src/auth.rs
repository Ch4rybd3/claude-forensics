use crate::config::{Config, Secret};
use anyhow::{Result, anyhow};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

pub const COOKIE: &str = "cf_session";
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);

pub fn hash_password(pw: &str) -> Result<String> {
    Argon2::default()
        .hash_password(pw.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| anyhow!("argon2: {e}"))
}

pub struct Sessions {
    inner: Mutex<HashMap<String, (String, Instant)>>,
}

impl Sessions {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    pub fn create(&self, user: &str) -> String {
        let token = crate::util::random_token(32);
        let mut m = self.inner.lock().unwrap();
        let now = Instant::now();
        m.retain(|_, (_, exp)| *exp > now);
        m.insert(token.clone(), (user.to_string(), now + SESSION_TTL));
        token
    }

    pub fn user(&self, token: &str) -> Option<String> {
        let m = self.inner.lock().unwrap();
        m.get(token).filter(|(_, exp)| *exp > Instant::now()).map(|(u, _)| u.clone())
    }

    pub fn remove(&self, token: &str) {
        self.inner.lock().unwrap().remove(token);
    }
}

pub fn check_credentials(cfg: &Config, user: &str, pw: &str) -> bool {
    let user_ok: bool = user.as_bytes().ct_eq(cfg.username.as_bytes()).into();
    let pw_ok = match &cfg.password {
        Secret::Plain(p) => pw.as_bytes().ct_eq(p.as_bytes()).into(),
        Secret::Argon2(h) => PasswordHash::new(h)
            .map(|parsed| Argon2::default().verify_password(pw.as_bytes(), &parsed).is_ok())
            .unwrap_or(false),
    };
    user_ok & pw_ok
}

pub fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v.to_string())
}

/// Logged-in user, inserted as a request extension by the middleware.
#[derive(Clone)]
pub struct User(pub String);

pub async fn require_auth(
    State(state): State<crate::server::AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let user = token_from_headers(req.headers()).and_then(|t| state.sessions.user(&t));
    match user {
        Some(u) => {
            req.extensions_mut().insert(User(u));
            next.run(req).await
        }
        None => (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"error": "unauthorized"})))
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(password: Secret) -> Config {
        Config { bind: "127.0.0.1".into(), port: 0, data_dir: ".".into(), username: "analyst".into(), password }
    }

    #[test]
    fn plain_and_argon2_passwords() {
        let plain = cfg(Secret::Plain("s3cret".into()));
        assert!(check_credentials(&plain, "analyst", "s3cret"));
        assert!(!check_credentials(&plain, "analyst", "wrong"));
        assert!(!check_credentials(&plain, "root", "s3cret"));

        let hashed = cfg(Secret::parse(hash_password("s3cret").unwrap()));
        assert!(matches!(hashed.password, Secret::Argon2(_)));
        assert!(check_credentials(&hashed, "analyst", "s3cret"));
        assert!(!check_credentials(&hashed, "analyst", "s3cre"));
    }

    #[test]
    fn session_cookie_lookup() {
        let sessions = Sessions::new();
        let token = sessions.create("analyst");
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, format!("theme=dark; {COOKIE}={token}").parse().unwrap());
        let found = token_from_headers(&h).unwrap();
        assert_eq!(sessions.user(&found).as_deref(), Some("analyst"));
        sessions.remove(&found);
        assert_eq!(sessions.user(&found), None);
    }
}
