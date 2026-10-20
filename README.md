# claude-forensics

[![CI](https://github.com/Ch4rybd3/claude-forensics/actions/workflows/ci.yml/badge.svg)](https://github.com/Ch4rybd3/claude-forensics/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

DFIR web interface to ingest and analyze **Claude Code** and **Claude Desktop** artifacts
collected from a workstation (Linux, Windows, macOS). Single static binary, embedded web UI,
one SQLite database per case.

## Download

Ready-to-run binaries of the latest release, no install needed:

- **Windows:** [claude-forensics-windows-x86_64.exe](https://github.com/Ch4rybd3/claude-forensics/releases/latest/download/claude-forensics-windows-x86_64.exe)
- **Linux:** [claude-forensics-linux-x86_64](https://github.com/Ch4rybd3/claude-forensics/releases/latest/download/claude-forensics-linux-x86_64), then `chmod +x claude-forensics-linux-x86_64`

Checksums and older versions are on the [Releases](https://github.com/Ch4rybd3/claude-forensics/releases) page.
The binaries are not code-signed, so Windows SmartScreen may warn on first launch.

## Build

Requires a recent stable Rust toolchain (edition 2024, Rust 1.85+).

```sh
git clone https://github.com/Ch4rybd3/claude-forensics.git && cd claude-forensics
cargo build --release            # target/release/claude-forensics
```

Windows: build natively with the MSVC toolchain (`cargo build --release` gives
`claude-forensics.exe`), or cross-compile with `--target x86_64-pc-windows-gnu`, which needs
`mingw-w64-gcc` for the bundled SQLite.

## Run

```sh
claude-forensics example-config > claude-forensics.toml   # then edit username/password
claude-forensics                                          # http://0.0.0.0:8080
```

| Option | Config key | Default |
|---|---|---|
| `-c, --config` | — | `./claude-forensics.toml` if present |
| `-b, --bind` | `server.bind` | `0.0.0.0` (all interfaces) |
| `-p, --port` | `server.port` | `8080` |
| `-d, --data-dir` | `server.data_dir` | `./cf-data` |
| `-u, --username` / `CF_USERNAME` | `auth.username` | required |
| `--password` / `CF_PASSWORD` | `auth.password` | required |

CLI options override the config file. The password may be plain text or an argon2 hash
produced by `claude-forensics hash-password` (reads stdin if no argument). Prefer the config
file or `CF_PASSWORD`: CLI arguments are visible in the process list.

The server speaks plain HTTP. When it listens on a network interface, put it behind a TLS
reverse proxy or restrict access with a firewall.

## Workflow

1. Drag and drop a **ZIP or 7z** collection (optionally password-protected, e.g. `infected`).
   It can be a zipped `~/.claude`, a whole user profile, or a KAPE/UAC triage archive
   containing several users.
2. The archive is streamed to disk and hashed (MD5, SHA-1, SHA-256). It is kept untouched in
   `cases/<id>/evidence/`.
3. Every entry is extracted to `cases/<id>/extracted/` with path sanitisation (zip-slip,
   Windows-reserved names and characters), hashed (SHA-256), and its archive timestamps are
   recorded.
4. Profiles are discovered and parsed, secrets are scanned, and a super-timeline and a
   full-text index are built.

## What is extracted

| Source | Artifacts |
|---|---|
| `~/.claude/projects/<dir>/*.jsonl` | Sessions, every transcript record, tool calls with their results, tokens, cost, models, versions, git branches, permission modes, sub-agent transcripts |
| `~/.claude/history.jsonl` | Prompts typed by the user, including those whose transcript was deleted |
| `~/.claude/file-history/` | Pre-edit backups, mapped to original paths through the transcript snapshots |
| `~/.claude/todos/`, `sessions/<pid>.json` | Agent todo lists, running-process registry at collection time |
| `~/.claude/.credentials.json` | OAuth access and refresh tokens, expiry, scopes |
| `~/.claude/settings*.json` | Hooks with their commands (persistence), permissions, env vars, `apiKeyHelper` |
| `~/.claude.json` and `backups/` | Account (email, org, UUIDs), user ID, machine ID, first start, projects with their config, MCP servers, API keys |
| Project `.claude/`, `.mcp.json`, `CLAUDE.md` | Project settings, commands, agents, MCP servers, instructions |
| Claude Desktop (`%APPDATA%\Claude`, `~/.config/Claude`, `~/Library/Application Support/Claude`) | Cookies (metadata and encryption scheme, values stay encrypted), Local Storage (LevelDB, decoded), `claude_desktop_config.json` MCP servers, `Local State` `os_crypt` key, logs |
| All files | Regex scan for Anthropic, OpenAI, AWS, GitHub, GitLab, Slack, Google and Stripe keys, private keys and JWTs |

Secrets are masked in the UI. Revealing one, exporting a table or downloading a file is
recorded in the case audit log. CSV exports are protected against formula injection.

## Layout

```
src/main.rs              CLI and config merge
src/server.rs            HTTP API, upload, generic tabular views, exports
src/auth.rs              login, sessions (HttpOnly cookie), argon2
src/ingest/archive.rs    ZIP/7z detection, safe extraction and hashing
src/ingest/discover.rs   profile discovery and file categorisation
src/ingest/timeline.rs   super-timeline
src/parsers/             claude_code, claude_json, desktop, secrets
static/                  embedded UI (vanilla HTML/CSS/JS)
examples/make_fixture.rs dev helper: LevelDB fixtures and 7z archives
```

`cargo test` covers path sanitisation, secret detection and masking, CSV export, login, and
a full ingestion of a zipped Claude Code profile.

## Responsible use

claude-forensics reveals credentials, prompts and transcripts. Use it only on evidence you are
authorised to examine, keep case data on protected storage, and do not expose the server to
untrusted networks.

## License

[MIT](LICENSE).

claude-forensics is an independent project. It is not affiliated with or endorsed by Anthropic;
Claude, Claude Code and Claude Desktop are Anthropic's products and are named only to describe
the artifacts this tool analyses.
