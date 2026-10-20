mod auth;
mod case;
mod config;
mod db;
mod ingest;
mod parsers;
mod server;
mod util;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "claude-forensics", version, about = "DFIR web interface for Claude Code / Claude Desktop artifacts")]
struct Cli {
    /// Path to a TOML config file (default: ./claude-forensics.toml if present)
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// Address to bind (default 0.0.0.0, i.e. all interfaces)
    #[arg(short, long)]
    bind: Option<String>,

    /// TCP port (default 8080)
    #[arg(short, long)]
    port: Option<u16>,

    /// Directory holding cases, evidence copies and databases (default ./cf-data)
    #[arg(short, long)]
    data_dir: Option<PathBuf>,

    /// Login username
    #[arg(short, long, env = "CF_USERNAME")]
    username: Option<String>,

    /// Login password (plain or argon2 hash). Prefer the config file or CF_PASSWORD
    /// env var: CLI arguments are visible in the process list.
    #[arg(long, env = "CF_PASSWORD", hide_env_values = true)]
    password: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Hash a password with argon2id for use in the config file
    HashPassword {
        /// Password to hash (read from stdin if omitted)
        password: Option<String>,
    },
    /// Print an example configuration file
    ExampleConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Command::HashPassword { password }) => {
            let pw = match password {
                Some(p) => p,
                None => {
                    let mut s = String::new();
                    std::io::stdin().read_line(&mut s)?;
                    s.trim_end_matches(['\r', '\n']).to_string()
                }
            };
            if pw.is_empty() {
                bail!("empty password");
            }
            println!("{}", auth::hash_password(&pw)?);
            return Ok(());
        }
        Some(Command::ExampleConfig) => {
            print!("{}", config::EXAMPLE_CONFIG);
            return Ok(());
        }
        None => {}
    }

    let file = config::load_file(cli.config.as_deref())?;
    let username = cli.username.or(file.auth.username);
    let password = cli.password.or(file.auth.password);
    let (username, password) = match (username, password) {
        (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => (u, p),
        _ => bail!(
            "credentials required: set [auth] username/password in the config file \
             or use --username/--password (or CF_USERNAME/CF_PASSWORD).\n\
             Run `claude-forensics example-config` for a template."
        ),
    };

    let cfg = config::Config {
        bind: cli.bind.or(file.server.bind).unwrap_or_else(|| "0.0.0.0".into()),
        port: cli.port.or(file.server.port).unwrap_or(8080),
        data_dir: cli.data_dir.or(file.server.data_dir).unwrap_or_else(|| PathBuf::from("cf-data")),
        username,
        password: config::Secret::parse(password),
    };

    server::run(cfg).await
}
