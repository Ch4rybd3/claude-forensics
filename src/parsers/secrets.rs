//! Regex sweep of every text file for credentials that leaked into transcripts,
//! pasted content, shell snapshots, logs, etc.

use super::Ctx;
use anyhow::Result;
use regex::bytes::Regex;
use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

const MAX_FILE: u64 = 200 * 1024 * 1024;

fn patterns() -> &'static [(&'static str, Regex)] {
    static P: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    P.get_or_init(|| {
        [
            ("Anthropic API key", r"sk-ant-api\d\d-[A-Za-z0-9_\-]{80,}"),
            ("Anthropic OAuth access token", r"sk-ant-oat\d\d-[A-Za-z0-9_\-]{60,}"),
            ("Anthropic OAuth refresh token", r"sk-ant-ort\d\d-[A-Za-z0-9_\-]{60,}"),
            ("claude.ai session key", r"sk-ant-sid\d\d-[A-Za-z0-9_\-]{60,}"),
            ("Anthropic admin key", r"sk-ant-admin\d\d-[A-Za-z0-9_\-]{60,}"),
            ("OpenAI API key", r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}"),
            ("AWS access key id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            ("GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
            ("GitHub fine-grained PAT", r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
            ("GitLab PAT", r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
            ("Slack token", r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b"),
            ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
            ("Stripe key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b"),
            ("Private key", r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
            ("JWT", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
        ]
        .into_iter()
        .map(|(n, p)| (n, Regex::new(p).expect("valid regex")))
        .collect()
    })
}

pub fn scan(ctx: &Ctx) -> Result<()> {
    let files: Vec<(String, Option<i64>, i64)> = {
        let mut stmt = ctx.conn.prepare("SELECT rel_path, profile_id, size FROM files ORDER BY rel_path")?;
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect::<Result<_, _>>()?
    };
    for (rel, pid, size) in files {
        if size as u64 > MAX_FILE || size == 0 {
            continue;
        }
        let mut data = Vec::with_capacity(size as usize);
        if std::fs::File::open(ctx.abs(&rel)).and_then(|mut f| f.read_to_end(&mut data)).is_err() {
            continue;
        }
        // (kind, value) -> (first line, occurrences, context)
        let mut hits: HashMap<(&str, Vec<u8>), (usize, usize, String)> = HashMap::new();
        for (kind, re) in patterns() {
            for m in re.find_iter(&data) {
                let entry = hits.entry((kind, m.as_bytes().to_vec())).or_insert_with(|| {
                    let line = data[..m.start()].iter().filter(|b| **b == b'\n').count() + 1;
                    let a = m.start().saturating_sub(80);
                    let b = (m.end() + 80).min(data.len());
                    let before = String::from_utf8_lossy(&data[a..m.start()]).into_owned();
                    let after = String::from_utf8_lossy(&data[m.end()..b]).into_owned();
                    let masked = crate::util::mask(&String::from_utf8_lossy(m.as_bytes()));
                    (line, 0, format!("…{before}{masked}{after}…"))
                });
                entry.1 += 1;
            }
        }
        for ((kind, value), (line, count, context)) in hits {
            let value = String::from_utf8_lossy(&value).into_owned();
            let context = format!("line {line}, {count} occurrence(s): {}", context.replace(['\n', '\r'], " "));
            ctx.add_secret(pid, &rel, "scan", kind, &format!("line {line}"), &value, None, &context);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::patterns;

    fn kinds(text: &str) -> Vec<&'static str> {
        patterns().iter().filter(|(_, re)| re.is_match(text.as_bytes())).map(|(k, _)| *k).collect()
    }

    // Test tokens are built at runtime so no realistic-looking secret sits in the source.
    #[test]
    fn detects_known_formats() {
        let api = format!("key=sk-ant-api03-{}", "A".repeat(90));
        assert_eq!(kinds(&api), ["Anthropic API key"]);
        let oat = format!("sk-ant-oat01-{}", "b".repeat(70));
        assert_eq!(kinds(&oat), ["Anthropic OAuth access token"]);
        let gh = format!("token {}_{}", "ghp", "a1".repeat(18));
        assert_eq!(kinds(&gh), ["GitHub token"]);
        let aws = format!("{}{}", "AKIA", "Z".repeat(16));
        assert_eq!(kinds(&aws), ["AWS access key id"]);
        assert_eq!(kinds("-----BEGIN OPENSSH PRIVATE KEY-----"), ["Private key"]);
    }

    #[test]
    fn ignores_ordinary_text() {
        assert!(kinds("sk-ant-api03-short and ghp_tooshort, AKIA lowercase").is_empty());
    }
}
