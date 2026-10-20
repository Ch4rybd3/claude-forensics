//! Ingestion pipeline: extract -> discover profiles -> parse -> scan -> timeline.

pub mod archive;
mod discover;
mod timeline;

use crate::db;
use crate::parsers::{self, Ctx};
use anyhow::Result;
use rusqlite::Connection;
use std::path::PathBuf;

pub struct Job {
    pub db_path: PathBuf,
    pub evidence: PathBuf,
    pub extracted: PathBuf,
    pub work: PathBuf,
    pub password: Option<String>,
}

fn stage(conn: &Connection, s: &str) {
    tracing::info!("ingest: {s}");
    let _ = db::set_meta(conn, "stage", s);
}

/// Runs on a blocking thread. Status is reported through the case `meta` table.
pub fn run(job: Job) {
    let conn = match db::open_rw(&job.db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("cannot open case db: {e:#}");
            return;
        }
    };
    let started = std::time::Instant::now();
    match run_inner(&conn, &job) {
        Ok(()) => {
            let _ = db::set_meta(&conn, "status", "ready");
            stage(&conn, "done");
        }
        Err(e) => {
            tracing::error!("ingestion failed: {e:#}");
            let _ = db::set_meta(&conn, "status", "error");
            let _ = db::set_meta(&conn, "error", &format!("{e:#}"));
        }
    }
    let _ = db::set_meta(&conn, "ingest_seconds", &started.elapsed().as_secs().to_string());
    let _ = db::set_meta(&conn, "ingest_finished", &crate::util::now_iso());
    let _ = std::fs::remove_dir_all(&job.work);
}

fn run_inner(conn: &Connection, job: &Job) -> Result<()> {
    stage(conn, "detecting archive format");
    let format = archive::detect(&job.evidence)?;
    db::set_meta(conn, "archive_format", &format!("{format:?}"))?;

    stage(conn, "extracting and hashing files");
    conn.execute_batch("BEGIN")?;
    let mut ex = archive::Extractor::new(conn, job.extracted.clone());
    let res = ex.extract(&job.evidence, format, job.password.as_deref());
    let (count, bytes) = (ex.count, ex.bytes);
    conn.execute_batch("COMMIT")?;
    res?;
    db::set_meta(conn, "extracted_files", &count.to_string())?;
    db::set_meta(conn, "extracted_bytes", &bytes.to_string())?;

    stage(conn, "discovering profiles");
    let found = discover::discover(conn, &job.extracted)?;

    let ctx = Ctx { conn, root: job.extracted.clone(), work: job.work.clone() };

    conn.execute_batch("BEGIN")?;
    for (i, d) in found.claude_dirs.iter().enumerate() {
        stage(conn, &format!("parsing Claude Code dir {}/{}: {}", i + 1, found.claude_dirs.len(), d.rel));
        parsers::claude_code::parse_dir(&ctx, d.profile_id, &d.rel)?;
    }
    for d in &found.claude_jsons {
        stage(conn, &format!("parsing {}", d.rel));
        parsers::claude_json::parse(&ctx, d.profile_id, &d.rel)?;
    }
    for d in &found.desktop_dirs {
        stage(conn, &format!("parsing Claude Desktop dir {}", d.rel));
        parsers::desktop::parse_dir(&ctx, d.profile_id, &d.rel)?;
    }
    for d in &found.loose {
        parsers::claude_code::parse_loose(&ctx, d.profile_id, &d.rel)?;
    }
    parsers::claude_code::finalize_projects(&ctx)?;
    conn.execute_batch("COMMIT")?;

    stage(conn, "scanning for secrets");
    conn.execute_batch("BEGIN")?;
    parsers::secrets::scan(&ctx)?;
    conn.execute_batch("COMMIT")?;

    stage(conn, "building timeline and search index");
    conn.execute_batch("BEGIN")?;
    timeline::build(conn)?;
    conn.execute("INSERT INTO messages_fts(messages_fts) VALUES('rebuild')", [])?;
    conn.execute_batch("COMMIT")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::SimpleFileOptions;

    /// Builds a small zipped home directory with a Claude Code profile, ingests it
    /// end to end and checks what lands in the case database.
    #[test]
    fn ingests_zipped_claude_profile() {
        let dir = std::env::temp_dir().join(format!("cf-test-{}", crate::util::random_token(8)));
        std::fs::create_dir_all(&dir).unwrap();
        let evidence = dir.join("evidence.zip");

        let session = "0b6f1c2e-0000-4000-8000-000000000001";
        let key = format!("sk-ant-api03-{}", "Q".repeat(90));
        let user = serde_json::json!({"type": "user", "sessionId": session, "uuid": "u1",
            "timestamp": "2026-10-13T10:00:00.000Z", "cwd": "/home/alice/proj", "version": "2.1.0",
            "message": {"role": "user", "content": format!("deploy with {key}")}});
        let assistant = serde_json::json!({"type": "assistant", "sessionId": session, "uuid": "a1",
            "parentUuid": "u1", "timestamp": "2026-10-13T10:00:05.000Z", "cwd": "/home/alice/proj",
            "message": {"role": "assistant", "model": "claude-test", "content": [
                {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}}],
                "usage": {"input_tokens": 10, "output_tokens": 5}}});
        let history = serde_json::json!({"display": "deploy it", "timestamp": 1_791_712_800_000_i64,
            "project": "/home/alice/proj", "sessionId": session});

        let mut zw = zip::ZipWriter::new(std::fs::File::create(&evidence).unwrap());
        let opts = SimpleFileOptions::default();
        let mut add = |name: &str, body: String| {
            zw.start_file(name, opts).unwrap();
            zw.write_all(body.as_bytes()).unwrap();
        };
        add(&format!("home/alice/.claude/projects/-home-alice-proj/{session}.jsonl"), format!("{user}\n{assistant}\n"));
        add("home/alice/.claude/history.jsonl", format!("{history}\n"));
        add("home/alice/../../escape.txt", "zip-slip".into());
        zw.finish().unwrap();

        let db_path = dir.join("case.db");
        drop(db::create(&db_path).unwrap());
        run(Job {
            db_path: db_path.clone(),
            evidence,
            extracted: dir.join("extracted"),
            work: dir.join("work"),
            password: None,
        });

        let conn = db::open_ro(&db_path).unwrap();
        let one = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(db::get_meta(&conn, "status").unwrap().as_deref(), Some("ready"), "{:?}", db::get_meta(&conn, "error"));
        assert_eq!(one("SELECT count(*) FROM profiles"), 1);
        assert_eq!(one(&format!("SELECT count(*) FROM sessions WHERE session_id = '{session}'")), 1);
        assert_eq!(one("SELECT count(*) FROM tool_calls WHERE tool_name = 'Bash'"), 1);
        assert_eq!(one("SELECT count(*) FROM history WHERE display = 'deploy it'"), 1);
        assert!(one("SELECT count(*) FROM credentials WHERE kind = 'Anthropic API key' AND value_masked NOT LIKE '%QQQQ%'") >= 1);
        // The traversal entry stays inside extracted/.
        assert!(!dir.join("escape.txt").exists() && !std::env::temp_dir().join("escape.txt").exists());

        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
