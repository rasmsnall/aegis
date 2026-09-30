use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};

use aegis::audit::{self, AuditKey, AuditLog};
use aegis::config::Config;
use aegis::policy::{Action, Policy};
use aegis::proxy::{self, Proxy};
use aegis::replay;
use aegis::resources::ResourceStore;
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
    /// Validate a configuration file without starting any server.
    Check {
        #[arg(short, long, default_value = "aegis.toml")]
        config: PathBuf,
    },
    /// Start the configured servers and show every tool with the labels its
    /// output gets and the rules that apply to it. Warns about sources and
    /// rules that match no tool, which usually means a typo.
    Tools {
        #[arg(short, long, default_value = "aegis.toml")]
        config: PathBuf,
        /// Exit with status 1 if there are any warnings.
        #[arg(long)]
        strict: bool,
    },
    /// Verify an audit log's chain (and signatures, given the key).
    Verify {
        log: PathBuf,
        /// Key the log was signed with; defaults to AEGIS_AUDIT_KEY.
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
    /// Show which recorded tool calls a policy would decide differently.
    Replay {
        log: PathBuf,
        /// Configuration whose sources and rules to replay against.
        #[arg(short, long, default_value = "aegis.toml")]
        config: PathBuf,
        /// Key the log was signed with; defaults to AEGIS_AUDIT_KEY.
        #[arg(long)]
        key_file: Option<PathBuf>,
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
            let key = AuditKey::load(config.audit.key_file.as_deref())?;
            let audit = AuditLog::open(&config.audit.path, key)?;
            let resources = ResourceStore::open(&config.state.path, config.resources.clone())?;
            let mut upstreams = Vec::new();
            for server in &config.servers {
                upstreams.push(Upstream::spawn(server, config.limits.max_message_bytes).await?);
            }
            let options = proxy::Options {
                audit: Some(audit),
                arguments: config.audit.arguments,
                redact_keys: config.audit.redact_keys.clone(),
                resources: Some(resources),
                approval_timeout: Duration::from_secs(config.approval.timeout_secs),
                max_message_bytes: config.limits.max_message_bytes,
            };
            let proxy = Proxy::new(upstreams, config.policy(), options)?;
            proxy
                .clone()
                .serve(tokio::io::stdin(), tokio::io::stdout())
                .await?;
            proxy.finish().await?;
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
        Command::Tools { config, strict } => tools(&Config::load(&config)?, strict).await,
        Command::Verify { log, key_file } => {
            let key = AuditKey::load(key_file.as_deref())?;
            let report = audit::verify(&audit::read(&log)?, key.as_ref())?;
            println!(
                "ok: {} in {}, chain intact{}",
                plural(report.entries, "entry", "entries"),
                plural(report.sessions, "session", "sessions"),
                if report.signed {
                    ", signatures valid"
                } else {
                    " (unsigned: detects accidental damage only, not deliberate rewrites)"
                }
            );
            for seq in &report.unfinished {
                println!(
                    "warning: session starting at entry {seq} has no session_end: aegis is still running, crashed, or the log was cut short"
                );
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Replay {
            log,
            config,
            key_file,
        } => {
            let config = Config::load(&config)?;
            let entries = audit::read(&log)?;
            let key = AuditKey::load(key_file.as_deref())?;
            if let Err(e) = audit::verify(&entries, key.as_ref()) {
                eprintln!("warning: audit log fails verification: {e}");
            }
            let report = replay::replay(&entries, &config.policy());
            for change in &report.changes {
                let verb = match change.replayed.action {
                    Action::Allow => "now ALLOWED",
                    Action::Deny => "now DENIED ",
                    Action::Ask => "now ASKS   ",
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

async fn tools(config: &Config, strict: bool) -> Result<ExitCode> {
    let mut warnings = Vec::new();
    let mut upstreams = Vec::new();
    for server in &config.servers {
        match Upstream::spawn(server, config.limits.max_message_bytes).await {
            Ok(u) => upstreams.push(u),
            Err(e) => warnings.push(format!("server {:?} did not start: {e:#}", server.name)),
        }
    }
    let listing = proxy::list_tools(&upstreams).await;
    for (server, e) in &listing.failures {
        warnings.push(format!("server {server:?} did not list its tools: {e:#}"));
    }
    let names: Vec<&str> = listing
        .tools
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();

    let policy = config.policy();
    let width = names.iter().map(|n| n.len()).max().unwrap_or(4).max(4);
    println!("{:width$}  {:28}  RULES", "TOOL", "OUTPUT LABELS");
    for name in &names {
        println!(
            "{name:width$}  {:28}  {}",
            describe_labels(&policy, name),
            describe_rules(&policy, name)
        );
    }

    for (i, source) in policy.sources.iter().enumerate() {
        if !names
            .iter()
            .any(|n| aegis::labels::glob_match(&source.tool, n))
        {
            warnings.push(format!(
                "source #{} ({:?}) matches no tool",
                i + 1,
                source.tool
            ));
        }
    }
    for (i, rule) in policy.rules.iter().enumerate() {
        if !names
            .iter()
            .any(|n| aegis::labels::glob_match(&rule.tool, n))
        {
            warnings.push(format!("rule #{} ({:?}) matches no tool", i + 1, rule.tool));
        }
    }
    println!();
    for w in &warnings {
        println!("warning: {w}");
    }
    println!(
        "{}, {}",
        plural(names.len(), "tool", "tools"),
        plural(warnings.len(), "warning", "warnings")
    );
    Ok(if strict && !warnings.is_empty() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn describe_labels(policy: &Policy, tool: &str) -> String {
    let labels: Vec<String> = policy.labels_for_result(tool).into_iter().collect();
    let text = if labels.is_empty() {
        "trusted".to_string()
    } else {
        labels.join(", ")
    };
    if policy.has_source_for(tool) {
        text
    } else {
        format!("{text} (default)")
    }
}

fn describe_rules(policy: &Policy, tool: &str) -> String {
    let rules = policy.rules_for(tool);
    if rules.is_empty() {
        let default = policy.default.as_str();
        return format!("- (default: {default})");
    }
    rules
        .iter()
        .map(|&r| {
            let rule = &policy.rules[r - 1];
            let action = rule.action.as_str();
            if rule.when_context_has.is_empty() {
                format!("#{r} {action}")
            } else {
                format!("#{r} {action} if {}", rule.when_context_has.join("|"))
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}
