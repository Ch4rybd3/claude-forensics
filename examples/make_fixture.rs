//! Dev helper: turn a directory into a test collection.
//!   cargo run --example make_fixture -- leveldb <dir>          write Chromium-style Local Storage entries
//!   cargo run --example make_fixture -- 7z <src_dir> <out.7z> [password]

fn utf16(s: &str) -> Vec<u8> {
    let mut v = vec![0u8];
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("leveldb") => {
            let opts = rusty_leveldb::Options { create_if_missing: true, ..Default::default() };
            let mut db = rusty_leveldb::DB::open(&args[2], opts).expect("open leveldb");
            db.put(b"VERSION", b"1").unwrap();
            db.put(b"META:https://claude.ai", b"\x08\x80\x80\x80\x80\x10").unwrap();
            let mut k = b"_https://claude.ai\x00\x01".to_vec();
            k.extend_from_slice(b"lastActiveOrg");
            db.put(&k, &[b"\x01".as_slice(), b"8f4e2c1a-org-uuid"].concat()).unwrap();
            let mut k = b"_https://claude.ai\x00\x01".to_vec();
            k.extend_from_slice(b"recentConversations");
            db.put(&k, &utf16(r#"[{"uuid":"c0ffee","name":"Exfil plan ü"}]"#)).unwrap();
            db.flush().unwrap();
            db.close().unwrap();
        }
        Some("7z") => {
            let res = match args.get(4) {
                Some(pw) => sevenz_rust2::compress_to_path_encrypted(&args[2], &args[3], sevenz_rust2::Password::new(pw)),
                None => sevenz_rust2::compress_to_path(&args[2], &args[3]),
            };
            res.expect("7z compress");
        }
        _ => eprintln!("usage: make_fixture leveldb <dir> | 7z <src> <out.7z> [password]"),
    }
}
