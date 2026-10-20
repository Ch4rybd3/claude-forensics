use crate::db;
use anyhow::{Result, bail};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// Layout of a case on disk:
///   <data_dir>/cases/<id>/case.db        SQLite database
///   <data_dir>/cases/<id>/evidence/      untouched copy of the uploaded archive
///   <data_dir>/cases/<id>/extracted/     extracted working copy
#[derive(Clone)]
pub struct CaseStore {
    pub root: PathBuf,
}

#[derive(Serialize)]
pub struct CaseSummary {
    pub id: String,
    pub name: Option<String>,
    pub examiner: Option<String>,
    pub created: Option<String>,
    pub status: Option<String>,
    pub stage: Option<String>,
    pub archive_name: Option<String>,
    pub archive_size: Option<String>,
    pub sha256: Option<String>,
}

impl CaseStore {
    pub fn new(data_dir: &Path) -> Result<Self> {
        let root = data_dir.join("cases");
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    pub fn new_id() -> String {
        format!(
            "{}-{}",
            chrono::Utc::now().format("%Y%m%d-%H%M%S"),
            crate::util::random_token(6).to_lowercase()
        )
    }

    pub fn valid_id(id: &str) -> bool {
        !id.is_empty() && id.len() < 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    }

    pub fn dir(&self, id: &str) -> Result<PathBuf> {
        if !Self::valid_id(id) {
            bail!("invalid case id");
        }
        Ok(self.root.join(id))
    }

    pub fn db_path(&self, id: &str) -> Result<PathBuf> {
        let p = self.dir(id)?.join("case.db");
        if !p.exists() {
            bail!("case not found");
        }
        Ok(p)
    }

    pub fn list(&self) -> Vec<CaseSummary> {
        let mut out = Vec::new();
        let Ok(rd) = std::fs::read_dir(&self.root) else { return out };
        for e in rd.flatten() {
            let id = e.file_name().to_string_lossy().into_owned();
            let Ok(path) = self.db_path(&id) else { continue };
            let Ok(conn) = db::open_ro(&path) else { continue };
            let g = |k: &str| db::get_meta(&conn, k).ok().flatten();
            out.push(CaseSummary {
                name: g("name"),
                examiner: g("examiner"),
                created: g("created"),
                status: g("status"),
                stage: g("stage"),
                archive_name: g("archive_name"),
                archive_size: g("archive_size"),
                sha256: g("archive_sha256"),
                id,
            });
        }
        out.sort_by(|a, b| b.created.cmp(&a.created));
        out
    }

    /// Cases left in "ingesting" state by a previous run can never finish.
    pub fn mark_interrupted(&self) {
        for c in self.list() {
            if c.status.as_deref() == Some("ingesting")
                && let Ok(p) = self.db_path(&c.id)
                    && let Ok(conn) = db::open_rw(&p) {
                        let _ = db::set_meta(&conn, "status", "error");
                        let _ = db::set_meta(&conn, "error", "ingestion interrupted (server restarted)");
                    }
        }
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        let dir = self.dir(id)?;
        if dir.exists() {
            std::fs::remove_dir_all(dir)?;
        }
        Ok(())
    }
}
