use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use aegis::audit::{self, AuditKey, AuditLog};
use aegis::config::Config;
use aegis::labels::glob_match;
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
    /// Write a starting aegis.toml from an agent's MCP config (Claude Code's
    /// .mcp.json, Claude Desktop, Cursor) and show how to switch the agent
    /// over to aegis.
    Init {
        /// The agent's MCP config to read.
        #[arg(long, default_value = ".mcp.json")]
        from: PathBuf,
        /// Where to write the aegis config.
        #[arg(short, long, default_value = "aegis.toml")]
        config: PathBuf,
        /// Overwrite an existing aegis config (and backup).
        #[arg(long)]
        force: bool,
        /// Also rewrite the agent's MCP config to run aegis instead of the
        /// servers, keeping the original as <file>.aegis-backup.
        #[arg(long)]
        replace: bool,
        /// Don't start the servers to see their tools; write generic rules.
        #[arg(long)]
        no_probe: bool,
    },
    /// Render an audit log as an HTML report.
    Report {
        log: PathBuf,
        /// Where to write the report.
        #[arg(short, long, default_value = "aegis-report.html")]
        output: PathBuf,
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
                upstreams.push(Upstream::open(server, config.limits.max_message_bytes).await?);
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
        Command::Init {
            from,
            config,
            force,
            replace,
            no_probe,
        } => init(&from, &config, force, replace, !no_probe).await,
        Command::Report {
            log,
            output,
            key_file,
        } => {
            let entries = audit::read(&log)?;
            let key = AuditKey::load(key_file.as_deref())?;
            let verified = audit::verify(&entries, key.as_ref()).map_err(|e| format!("{e:#}"));
            let name = log.file_name().map_or_else(
                || log.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            std::fs::write(&output, aegis::report::render(&name, &entries, &verified))
                .with_context(|| format!("writing {}", output.display()))?;
            match &verified {
                Ok(v) => println!(
                    "wrote {}: {} in {}{}",
                    output.display(),
                    plural(v.entries, "entry", "entries"),
                    plural(v.sessions, "session", "sessions"),
                    if v.signed {
                        ", signatures valid"
                    } else {
                        ", unsigned"
                    }
                ),
                Err(e) => println!(
                    "wrote {}, but the log FAILED verification: {e}",
                    output.display()
                ),
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
        match Upstream::open(server, config.limits.max_message_bytes).await {
            Ok(u) => upstreams.push(u),
            Err(e) => warnings.push(format!("server {:?} did not start: {e:#}", server.name)),
        }
    }
    let listing = proxy::list_tools(&upstreams).await;
    for (server, e) in &listing.failures {
        warnings.push(format!("server {server:?} did not list its tools: {e:#}"));
    }
    let mut names: Vec<String> = listing
        .tools
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_string))
        .collect();
    // Resource reads and prompts are checked like tool calls, under these names.
    for upstream in &upstreams {
        for (capability, pseudo) in [
            ("resources", proxy::READ_RESOURCE),
            ("prompts", proxy::GET_PROMPT),
        ] {
            if upstream.supports(capability) {
                names.push(format!(
                    "{}{}{pseudo}",
                    upstream.name,
                    aegis::config::NAMESPACE_SEP
                ));
            }
        }
    }
    let names: Vec<&str> = names.iter().map(String::as_str).collect();

    let policy = config.policy();
    let rows: Vec<(&str, String, String)> = names
        .iter()
        .map(|n| (*n, describe_labels(&policy, n), describe_rules(&policy, n)))
        .collect();
    let width = rows.iter().map(|r| r.0.len()).max().unwrap_or(0).max(4);
    let labels_width = rows.iter().map(|r| r.1.len()).max().unwrap_or(0).max(13);
    println!(
        "{:width$}  {:labels_width$}  RULES",
        "TOOL", "OUTPUT LABELS"
    );
    for (name, labels, rules) in &rows {
        println!("{name:width$}  {labels:labels_width$}  {rules}");
    }

    for (i, source) in policy.sources.iter().enumerate() {
        if !names.iter().any(|n| glob_match(&source.tool, n)) {
            warnings.push(format!(
                "source #{} ({:?}) matches no tool",
                i + 1,
                source.tool
            ));
        }
    }
    for (i, rule) in policy.rules.iter().enumerate() {
        if !names.iter().any(|n| glob_match(&rule.tool, n)) {
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

/// The labels `tool`'s output gets: those of the first unconditional source
/// that names it (or the default), plus any argument-dependent sources
/// checked before it, e.g. `untrusted; trusted if url host docs.rs`.
fn describe_labels(policy: &Policy, tool: &str) -> String {
    let names = |labels: &[String]| {
        if labels.is_empty() {
            "trusted".to_string()
        } else {
            labels.join(", ")
        }
    };
    let mut conditional = Vec::new();
    let mut base = None;
    for source in policy.sources.iter().filter(|s| glob_match(&s.tool, tool)) {
        if !source.is_conditional() {
            base = Some(names(&source.labels));
            break;
        }
        let mut conditions = Vec::new();
        if !source.hosts.is_empty() {
            conditions.push(format!(
                "{} host {}",
                source.url_arg,
                source.hosts.join("|")
            ));
        }
        if !source.paths.is_empty() {
            conditions.push(format!("{} {}", source.path_arg, source.paths.join("|")));
        }
        for (key, patterns) in &source.args {
            conditions.push(format!("{key}={}", patterns.join("|")));
        }
        conditional.push(format!(
            "{} if {}",
            names(&source.labels),
            conditions.join(" and ")
        ));
    }
    let base = base.unwrap_or_else(|| format!("{} (default)", names(&policy.default_labels)));
    std::iter::once(base)
        .chain(conditional)
        .collect::<Vec<_>>()
        .join("; ")
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

/// Starts each server briefly and lists its tools, by original name. Servers
/// that don't start or answer are left out (and reported).
async fn probe_tools(
    servers: &[(String, aegis::init::McpServer)],
) -> BTreeMap<String, Vec<String>> {
    let mut found = BTreeMap::new();
    for (original, server) in servers {
        let command = server.command.clone().filter(|c| !c.is_empty());
        let url = server.url.clone().filter(|_| command.is_none());
        if command.is_none() && url.is_none() {
            continue;
        }
        let config = aegis::config::ServerConfig {
            name: aegis::init::sanitize_name(original),
            command: command.unwrap_or_default(),
            args: server.args.clone(),
            env: server.env.clone(),
            headers: if url.is_some() {
                server.headers.clone()
            } else {
                BTreeMap::new()
            },
            url,
            sandbox: None,
            startup_timeout_secs: 10,
            call_timeout_secs: 10,
        };
        let listed = match Upstream::open(&config, aegis::upstream::DEFAULT_MAX_MESSAGE_BYTES).await
        {
            Ok(upstream) => {
                let listing = proxy::list_tools(&[upstream]).await;
                match listing.failures.into_iter().next() {
                    Some((_, e)) => Err(e),
                    None => Ok(listing.tools),
                }
            }
            Err(e) => Err(e),
        };
        match listed {
            Ok(tools) => {
                let prefix = format!("{}{}", config.name, aegis::config::NAMESPACE_SEP);
                let names = tools
                    .iter()
                    .filter_map(|t| {
                        t["name"]
                            .as_str()?
                            .strip_prefix(&prefix)
                            .map(str::to_string)
                    })
                    .collect();
                found.insert(original.clone(), names);
            }
            Err(e) => println!(
                "  couldn't list the tools of \"{original}\" ({e:#}); using generic rules for it"
            ),
        }
    }
    found
}

async fn init(
    from: &Path,
    config: &Path,
    force: bool,
    replace: bool,
    probe: bool,
) -> Result<ExitCode> {
    use aegis::init;
    let text = std::fs::read_to_string(from).with_context(|| {
        format!(
            "reading {} (point --from at your agent's MCP config, e.g. .mcp.json for Claude Code)",
            from.display()
        )
    })?;
    let servers =
        init::parse_client_config(&text).with_context(|| format!("reading {}", from.display()))?;
    if config.exists() && !force {
        bail!(
            "{} already exists; pass --force to overwrite it",
            config.display()
        );
    }
    let tools = if probe {
        println!("starting each server briefly to see its tools…");
        probe_tools(&servers).await
    } else {
        BTreeMap::new()
    };
    let generated = init::generate(&servers, &tools);
    if generated.servers.is_empty() {
        bail!(
            "{} has no servers aegis can run (only stdio servers with a command are supported)",
            from.display()
        );
    }
    std::fs::write(config, &generated.toml)
        .with_context(|| format!("writing {}", config.display()))?;

    println!(
        "wrote {} for {}:",
        config.display(),
        plural(generated.servers.len(), "server", "servers")
    );
    for (name, kind) in &generated.servers {
        println!("  {name:20} {}", init::describe(*kind));
    }
    for (original, name) in &generated.renamed {
        println!(
            "  (\"{original}\" is called \"{name}\": aegis server names use letters, digits and -)"
        );
    }
    for (name, why) in &generated.skipped {
        println!("  skipped \"{name}\": {why}");
    }
    if servers.iter().any(|(_, s)| !s.env.is_empty()) {
        println!(
            "\nnote: {} contains environment values copied from {}. If they are secrets, keep it out of version control.",
            config.display(),
            from.display()
        );
    }

    let config_path = std::fs::canonicalize(config)?.display().to_string();
    if replace {
        let backup = PathBuf::from(format!("{}.aegis-backup", from.display()));
        if backup.exists() && !force {
            bail!(
                "{} already exists; pass --force to overwrite it",
                backup.display()
            );
        }
        std::fs::copy(from, &backup).with_context(|| format!("backing up {}", from.display()))?;
        let replaced = init::replace_servers(&text, &config_path, &generated.skipped)?;
        std::fs::write(from, replaced).with_context(|| format!("writing {}", from.display()))?;
        println!(
            "\nrewrote {} to run aegis instead (original saved as {}).",
            from.display(),
            backup.display()
        );
    } else {
        let entry =
            serde_json::json!({ "mcpServers": { "aegis": init::client_entry(&config_path) } });
        println!(
            "\nTo put aegis in front of these servers, replace them in {} with:\n\n{}\n\n(or run again with --replace to do it for you, keeping a backup)",
            from.display(),
            serde_json::to_string_pretty(&entry)?
        );
    }
    println!(
        "\nNext: `aegis tools -c {}` to check what each tool's output is labelled.",
        config.display()
    );
    Ok(ExitCode::SUCCESS)
}
