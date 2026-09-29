use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

use aegis::audit::{self, AuditLog};
use aegis::config::Config;
use aegis::policy::Action;
use aegis::proxy::Proxy;
use aegis::replay;
use aegis::upstream::Upstream;

#[derive(Parser)]
#[command(version, about = "Information-flow firewall for AI agent tool calls")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as an MCP server on stdio, proxying to the configured servers.
    Run {
        #[arg(short, long, default_value = "aegis.toml")]
        config: PathBuf,
    },
    /// Validate a configuration file.
    Check {
        #[arg(short, long, default_value = "aegis.toml")]
        config: PathBuf,
    },
    /// Verify the hash chain of an audit log.
    Verify { log: PathBuf },
    /// Show which recorded tool calls a policy would decide differently.
    Replay {
        log: PathBuf,
        /// Configuration whose sources and rules to replay against.
        #[arg(short, long, default_value = "aegis.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("aegis: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    match cli.command {
        Command::Run { config } => {
            let config = Config::load(&config)?;
            let audit = AuditLog::open(&config.audit.path)?;
            let mut upstreams = Vec::new();
            for server in &config.servers {
                upstreams.push(Upstream::spawn(server).await?);
            }
            let proxy = Proxy::new(upstreams, config.policy(), Some(audit))?;
            proxy.serve(tokio::io::stdin(), tokio::io::stdout()).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Check { config } => {
            let config = Config::load(&config)?;
            println!(
                "ok: {} servers, {} sources, {} rules",
                config.servers.len(),
                config.sources.len(),
                config.rules.len()
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Verify { log } => {
            let entries = audit::read(&log)?;
            audit::verify(&entries)?;
            println!("ok: {} entries, chain intact", entries.len());
            Ok(ExitCode::SUCCESS)
        }
        Command::Replay { log, config } => {
            let config = Config::load(&config)?;
            let entries = audit::read(&log)?;
            if let Err(e) = audit::verify(&entries) {
                eprintln!("warning: audit log fails verification: {e}");
            }
            let report = replay::replay(&entries, &config.policy());
            for change in &report.changes {
                let verb = match change.replayed.action {
                    Action::Allow => "now ALLOWED",
                    Action::Deny => "now DENIED ",
                };
                let rule = change
                    .replayed
                    .rule
                    .map_or("default".into(), |r| format!("rule #{r}"));
                println!("#{:<6} {verb} {} ({rule})", change.seq, change.tool);
            }
            println!(
                "{} calls replayed, {} decisions changed",
                report.calls,
                report.changes.len()
            );
            Ok(if report.changes.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
    }
}
