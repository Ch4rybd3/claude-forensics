//! Archive detection and safe extraction (ZIP, 7z) with per-file hashing.

use crate::util;
use anyhow::{Context, Result, bail};
use rusqlite::{Connection, params};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Format {
    Zip,
    SevenZ,
}

pub fn detect(path: &Path) -> Result<Format> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 6];
    let n = f.read(&mut magic)?;
    if n >= 4 && &magic[..4] == b"PK\x03\x04" || n >= 4 && &magic[..4] == b"PK\x05\x06" {
        return Ok(Format::Zip);
    }
    if n == 6 && magic == [b'7', b'z', 0xBC, 0xAF, 0x27, 0x1C] {
        return Ok(Format::SevenZ);
    }
    bail!("unsupported archive format (expected ZIP or 7z)")
}

/// Metadata for one extracted entry, as recorded in the archive.
#[derive(Default)]
struct EntryMeta {
    mtime: Option<String>,
    mtime_note: &'static str,
    ctime: Option<String>,
    atime: Option<String>,
    encrypted: bool,
}

pub struct Extractor<'a> {
    pub conn: &'a Connection,
    pub out: PathBuf,
    used: HashSet<String>,
    pub count: u64,
    pub bytes: u64,
}

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Turn an archive entry name into safe relative path components that are valid
/// on both Linux and Windows. The original name is kept in `files.archive_path`.
pub fn sanitize(name: &str) -> Vec<String> {
    name.split(['/', '\\'])
        .filter(|c| !c.is_empty() && *c != "." && *c != "..")
        .map(|c| {
            let mut s: String = c
                .chars()
                .map(|ch| match ch {
                    '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
                    c if (c as u32) < 0x20 => '_',
                    c => c,
                })
                .collect();
            while s.ends_with('.') || s.ends_with(' ') {
                s.pop();
                s.push('_');
            }
            let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
            if WINDOWS_RESERVED.contains(&stem.as_str()) {
                s.insert(0, '_');
            }
            if s.len() > 200 {
                let mut end = 200;
                while !s.is_char_boundary(end) {
                    end -= 1;
                }
                s.truncate(end);
            }
            s
        })
        .collect()
}

impl<'a> Extractor<'a> {
    pub fn new(conn: &'a Connection, out: PathBuf) -> Self {
        Self { conn, out, used: HashSet::new(), count: 0, bytes: 0 }
    }

    fn unique_rel(&mut self, parts: Vec<String>) -> String {
        let base = parts.join("/");
        // Case-insensitive uniqueness keeps Windows (NTFS) from silently merging files.
        let mut rel = base.clone();
        let mut n = 1;
        while !self.used.insert(rel.to_lowercase()) {
            rel = format!("{base}~{n}");
            n += 1;
        }
        rel
    }

    fn write_entry(&mut self, archive_name: &str, reader: &mut dyn Read, meta: EntryMeta) -> Result<()> {
        let parts = sanitize(archive_name);
        if parts.is_empty() {
            return Ok(());
        }
        let rel = self.unique_rel(parts);
        let dest = util::join_rel(&self.out, &rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut f = File::create(&dest).with_context(|| format!("creating {}", dest.display()))?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 256 * 1024];
        let mut size = 0u64;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            f.write_all(&buf[..n])?;
            size += n as u64;
        }
        self.count += 1;
        self.bytes += size;
        self.conn.execute(
            "INSERT INTO files(archive_path, rel_path, size, sha256, mtime, mtime_note, ctime, atime, encrypted)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                archive_name,
                rel,
                size as i64,
                hex::encode(hasher.finalize()),
                meta.mtime,
                meta.mtime_note,
                meta.ctime,
                meta.atime,
                meta.encrypted as i64
            ],
        )?;
        Ok(())
    }

    pub fn extract(&mut self, path: &Path, format: Format, password: Option<&str>) -> Result<()> {
        std::fs::create_dir_all(&self.out)?;
        match format {
            Format::Zip => self.extract_zip(path, password),
            Format::SevenZ => self.extract_7z(path, password),
        }
    }

    fn extract_zip(&mut self, path: &Path, password: Option<&str>) -> Result<()> {
        let mut archive = zip::ZipArchive::new(BufReader::new(File::open(path)?))?;
        for i in 0..archive.len() {
            let entry = match password {
                Some(pw) if !pw.is_empty() => archive.by_index_decrypt(i, pw.as_bytes()),
                _ => archive.by_index(i),
            };
            let mut entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    crate::db::warn(self.conn, "zip", &format!("entry #{i}: {e}"));
                    continue;
                }
            };
            if entry.is_dir() || entry.is_symlink() {
                continue;
            }
            let name = String::from_utf8_lossy(entry.name_raw()).into_owned();
            let name = entry.name().map(|n| n.into_owned()).unwrap_or(name);
            let mut meta = EntryMeta { encrypted: entry.encrypted(), ..Default::default() };
            for field in entry.extra_data_fields() {
                match field {
                    zip::extra_fields::ExtraField::ExtendedTimestamp(ts) => {
                        if let Some(m) = ts.mod_time() {
                            meta.mtime = util::secs_to_iso(m as i64);
                            meta.mtime_note = "utc";
                        }
                        meta.atime = ts.ac_time().and_then(|t| util::secs_to_iso(t as i64));
                        meta.ctime = ts.cr_time().and_then(|t| util::secs_to_iso(t as i64));
                    }
                    zip::extra_fields::ExtraField::Ntfs(n) => {
                        meta.mtime = util::webkit_to_iso((n.mtime() / 10) as i64);
                        meta.mtime_note = "utc";
                        meta.atime = util::webkit_to_iso((n.atime() / 10) as i64);
                        meta.ctime = util::webkit_to_iso((n.ctime() / 10) as i64);
                    }
                    _ => {}
                }
            }
            if meta.mtime.is_none()
                && let Some(dt) = entry.last_modified() {
                    meta.mtime = Some(format!(
                        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
                        dt.year(),
                        dt.month(),
                        dt.day(),
                        dt.hour(),
                        dt.minute(),
                        dt.second()
                    ));
                    meta.mtime_note = "local (DOS time, no tz)";
                }
            if let Err(e) = self.write_entry(&name, &mut entry, meta) {
                crate::db::warn(self.conn, "zip", &format!("{name}: {e:#}"));
            }
        }
        Ok(())
    }

    fn extract_7z(&mut self, path: &Path, password: Option<&str>) -> Result<()> {
        let pw = match password {
            Some(p) if !p.is_empty() => sevenz_rust2::Password::new(p),
            _ => sevenz_rust2::Password::empty(),
        };
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(0))?;
        let mut reader = sevenz_rust2::ArchiveReader::new(file, pw).context("opening 7z archive")?;
        let nt = |t: sevenz_rust2::NtTime| util::webkit_to_iso((u64::from(t) / 10) as i64);
        let mut errors: Vec<String> = Vec::new();
        reader
            .for_each_entries(|entry, rd| {
                if entry.is_directory || entry.is_anti_item {
                    return Ok(true);
                }
                let meta = EntryMeta {
                    mtime: entry.has_last_modified_date.then(|| nt(entry.last_modified_date)).flatten(),
                    mtime_note: "utc",
                    ctime: entry.has_creation_date.then(|| nt(entry.creation_date)).flatten(),
                    atime: entry.has_access_date.then(|| nt(entry.access_date)).flatten(),
                    encrypted: password.is_some_and(|p| !p.is_empty()),
                };
                if let Err(e) = self.write_entry(&entry.name, rd, meta) {
                    errors.push(format!("{}: {e:#}", entry.name));
                    // Keep the (possibly solid) stream aligned for the next entry.
                    let _ = std::io::copy(rd, &mut std::io::sink());
                }
                Ok(true)
            })
            .context("reading 7z archive (wrong password?)")?;
        for e in errors {
            crate::db::warn(self.conn, "7z", &e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn drops_traversal_components() {
        assert_eq!(sanitize("../../etc/passwd"), ["etc", "passwd"]);
        assert_eq!(sanitize("/abs/./path"), ["abs", "path"]);
        assert_eq!(sanitize("..\\..\\Windows\\win.ini"), ["Windows", "win.ini"]);
    }

    #[test]
    fn neutralises_windows_names() {
        assert_eq!(sanitize("a/CON.txt"), ["a", "_CON.txt"]);
        assert_eq!(sanitize("a/lpt1"), ["a", "_lpt1"]);
        assert_eq!(sanitize("x:y*z?.txt"), ["x_y_z_.txt"]);
        assert_eq!(sanitize("trailing. "), ["trailing._"]);
        assert_eq!(sanitize("dots..."), ["dots.._"]);
    }

    #[test]
    fn truncates_long_names_on_char_boundary() {
        let long = "é".repeat(150);
        let out = sanitize(&long);
        assert!(out[0].len() <= 200);
        assert!(out[0].chars().all(|c| c == 'é'));
    }
}
