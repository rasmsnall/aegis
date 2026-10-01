//! `aegis init`: a starting `aegis.toml` from an agent's existing MCP config.
//!
//! Claude Code (`.mcp.json`, `~/.claude.json`), Claude Desktop and Cursor all
//! describe servers the same way:
//!
//! ```json
//! { "mcpServers": { "fetch": { "command": "uvx", "args": ["mcp-server-fetch"], "env": {} } } }
//! ```
//!
//! The generated policy is a reasoned starting point, not a final answer:
//! servers are classified by their name and command, and every source and
//! rule carries a comment saying why it is there. `aegis tools` shows what
//! it amounts to once the servers are running.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

/// One server from an MCP client config.
#[derive(Debug, Clone, Deserialize)]
pub struct McpServer {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub url: Option<String>,
}

/// Reads `mcpServers` from a client config. Server order is kept.
pub fn parse_client_config(text: &str) -> Result<Vec<(String, McpServer)>> {
    let value: Value = serde_json::from_str(text).context("not valid JSON")?;
    let Some(servers) = value.get("mcpServers").and_then(Value::as_object) else {
        bail!("no \"mcpServers\" object found");
    };
    servers
        .iter()
        .map(|(name, v)| {
            let server = serde_json::from_value(v.clone())
                .with_context(|| format!("server {name:?} is not in the usual format"))?;
            Ok((name.clone(), server))
        })
        .collect()
}

/// What a server most likely does, judged from its name and command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Fetches pages or searches the web: anyone can write what it returns.
    Web,
    /// Reads and writes local files.
    Files,
    /// Runs commands.
    Shell,
    /// GitHub, GitLab, issue trackers, chat, mail: mostly text other people wrote.
    Collaboration,
    /// Anything else.
    Other,
}

const WEB: &[&str] = &[
    "fetch",
    "web",
    "browser",
    "puppeteer",
    "playwright",
    "search",
    "brave",
    "tavily",
    "exa",
    "firecrawl",
    "scrape",
    "crawl",
    "http",
];
const FILES: &[&str] = &["filesystem", "files", "file-system", "fs"];
const SHELL: &[&str] = &[
    "shell",
    "terminal",
    "exec",
    "bash",
    "zsh",
    "desktop-commander",
];
const COLLABORATION: &[&str] = &[
    "github",
    "gitlab",
    "bitbucket",
    "jira",
    "linear",
    "slack",
    "discord",
    "gmail",
    "mail",
    "notion",
    "confluence",
    "teams",
];

/// Words in `texts`, split on anything but letters, digits and `-`, with
/// hyphenated words also split (`server-filesystem` gives all three).
fn words(texts: impl IntoIterator<Item = String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for text in texts {
        for word in text
            .to_ascii_lowercase()
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        {
            if word.is_empty() {
                continue;
            }
            out.insert(word.to_string());
            out.extend(
                word.split('-')
                    .filter(|w| !w.is_empty())
                    .map(str::to_string),
            );
        }
    }
    out
}

fn kind_of(words: &BTreeSet<String>) -> Kind {
    let has = |list: &[&str]| list.iter().any(|k| words.contains(*k));
    if has(SHELL) {
        Kind::Shell
    } else if has(FILES) {
        Kind::Files
    } else if has(COLLABORATION) {
        Kind::Collaboration
    } else if has(WEB) {
        Kind::Web
    } else {
        Kind::Other
    }
}

/// Words in tool names that say what a server does, when its name doesn't.
const TOOL_HINTS: &[(&str, Kind)] = &[
    ("execute", Kind::Shell),
    ("exec", Kind::Shell),
    ("command", Kind::Shell),
    ("shell", Kind::Shell),
    ("terminal", Kind::Shell),
    ("file", Kind::Files),
    ("directory", Kind::Files),
    ("issue", Kind::Collaboration),
    ("pull", Kind::Collaboration),
    ("comment", Kind::Collaboration),
    ("message", Kind::Collaboration),
    ("fetch", Kind::Web),
    ("search", Kind::Web),
    ("navigate", Kind::Web),
    ("browse", Kind::Web),
    ("scrape", Kind::Web),
];

/// Guesses what a server does: from its name first, then from its tool
/// names (when known), then from its command and arguments.
pub fn classify(name: &str, server: &McpServer, tools: &[String]) -> Kind {
    let by_name = kind_of(&words([name.to_string()]));
    if by_name != Kind::Other {
        return by_name;
    }
    let tool_words = words(tools.iter().map(|t| t.replace('_', " ")));
    for (hint, kind) in TOOL_HINTS {
        if tool_words
            .iter()
            .any(|w| w == hint || w.strip_suffix('s') == Some(hint))
        {
            return *kind;
        }
    }
    let command = server.command.iter().chain(&server.args).cloned();
    kind_of(&words(command))
}

/// A server name aegis accepts: letters, digits and `-`.
pub fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    let mut collapsed = String::new();
    for c in trimmed.chars() {
        if !(c == '-' && collapsed.ends_with('-')) {
            collapsed.push(c);
        }
    }
    if collapsed.is_empty() {
        "server".into()
    } else {
        collapsed
    }
}

pub struct Generated {
    pub toml: String,
    /// Servers kept, by their name in aegis.toml, and what they look like.
    pub servers: Vec<(String, Kind)>,
    /// Servers left out, and why (aegis only launches stdio servers).
    pub skipped: Vec<(String, String)>,
    /// Original name → name in aegis.toml.
    pub renamed: Vec<(String, String)>,
}

fn quote(s: &str) -> String {
    // TOML basic strings use the same escapes as JSON for what can occur here.
    serde_json::to_string(s).expect("strings serialize")
}

fn list(items: &[String]) -> String {
    format!(
        "[{}]",
        items
            .iter()
            .map(|s| quote(s))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Builds `aegis.toml` for `servers`. `tools` maps a server's original name
/// to its tool names, for the servers that could be started and listed; with
/// it, rules and resources are only written for tools that exist.
pub fn generate(
    servers: &[(String, McpServer)],
    tools: &BTreeMap<String, Vec<String>>,
) -> Generated {
    let mut skipped = Vec::new();
    let mut renamed = Vec::new();
    let mut used = BTreeSet::new();
    let mut kept: Vec<(String, &McpServer, Kind)> = Vec::new();
    for (original, server) in servers {
        let Some(_) = server.command.as_deref().filter(|c| !c.is_empty()) else {
            let why = if server.url.is_some() {
                "remote (HTTP) servers are not supported by aegis yet"
            } else {
                "no command to launch"
            };
            skipped.push((original.clone(), why.to_string()));
            continue;
        };
        let mut name = sanitize_name(original);
        let base = name.clone();
        let mut n = 2;
        while !used.insert(name.clone()) {
            name = format!("{base}-{n}");
            n += 1;
        }
        if &name != original {
            renamed.push((original.clone(), name.clone()));
        }
        let server_tools = tools.get(original).map(Vec::as_slice).unwrap_or_default();
        kept.push((name, server, classify(original, server, server_tools)));
    }
    // Every exposed tool name, if every kept server could be listed.
    let known: Option<Vec<String>> = servers
        .iter()
        .filter(|(n, s)| s.command.is_some() && !skipped.iter().any(|(k, _)| k == n))
        .zip(&kept)
        .map(|((original, _), (name, _, _))| {
            tools.get(original).map(|ts| {
                ts.iter()
                    .map(|t| format!("{name}{}{t}", crate::config::NAMESPACE_SEP))
                    .collect::<Vec<_>>()
            })
        })
        .collect::<Option<Vec<_>>>()
        .map(|v| v.concat());
    // Whether a pattern is worth writing: it matches a known tool, or the
    // tools aren't known.
    let useful = |pattern: &str| {
        known
            .as_ref()
            .is_none_or(|names| names.iter().any(|n| crate::labels::glob_match(pattern, n)))
    };

    let mut out = String::new();
    let w = &mut out;
    let _ = writeln!(
        w,
        "# Generated by `aegis init`. A starting point: read it, then run"
    );
    let _ = writeln!(
        w,
        "# `aegis tools` to see what each tool's output is labelled and which"
    );
    let _ = writeln!(w, "# rules apply to it.\n");
    let _ = writeln!(
        w,
        "[audit]\npath = \"aegis-audit.jsonl\"\narguments = \"redacted\"\n"
    );
    let _ = writeln!(
        w,
        "[policy]\n# Calls no rule matches go ahead.\ndefault = \"allow\""
    );
    let _ = writeln!(
        w,
        "# Output of tools no [[source]] matches is untrusted, so a tool you haven't\n# thought about is never trusted by accident.\ndefault_labels = [\"untrusted\"]\n"
    );

    let _ = writeln!(
        w,
        "# --- Servers -------------------------------------------------------------\n"
    );
    for (name, server, kind) in &kept {
        let _ = writeln!(w, "# Looks like: {}", describe(*kind));
        let _ = writeln!(w, "[[server]]\nname = {}", quote(name));
        let _ = writeln!(
            w,
            "command = {}",
            quote(server.command.as_deref().unwrap_or_default())
        );
        if !server.args.is_empty() {
            let _ = writeln!(w, "args = {}", list(&server.args));
        }
        if !server.env.is_empty() {
            let env: Vec<String> = server
                .env
                .iter()
                .map(|(k, v)| format!("{} = {}", quote(k), quote(v)))
                .collect();
            let _ = writeln!(w, "env = {{ {} }}", env.join(", "));
        }
        let _ = writeln!(w);
    }

    let _ = writeln!(
        w,
        "# --- Sources: labels on tool output, first match wins --------------------\n"
    );
    for (name, _, kind) in &kept {
        match kind {
            Kind::Web => {
                let _ = writeln!(
                    w,
                    "# Pages from hosts you trust stay trusted. Edit the list, or remove this.\n[[source]]\ntool = \"{name}__*\"\nlabels = []\nhosts = [\"docs.rs\", \"*.rust-lang.org\", \"developer.mozilla.org\"]\n"
                );
                let _ = writeln!(
                    w,
                    "# Everything else from the web: anyone can write it.\n[[source]]\ntool = \"{name}__*\"\nlabels = [\"untrusted\", \"external\"]\n"
                );
            }
            Kind::Files => {
                let _ = writeln!(
                    w,
                    "# Your own files are trusted. [[resource]] below keeps files written\n# while untrusted data was in play untrusted, even in later sessions.\n[[source]]\ntool = \"{name}__*\"\nlabels = []\n"
                );
            }
            Kind::Collaboration => {
                let _ = writeln!(
                    w,
                    "# Issues, pull requests, comments and messages are written by other\n# people. Unlisted, so untrusted by default. To trust parts of it, add a\n# source, e.g. tool = \"{name}__get_file_contents\", labels = [].\n"
                );
            }
            Kind::Shell => {
                let _ = writeln!(
                    w,
                    "# Command output is trusted; otherwise every command would block the\n# next one. Anything a command downloads is invisible to aegis, so keep\n# network access out of the shell where you can.\n[[source]]\ntool = \"{name}__*\"\nlabels = []\n"
                );
            }
            Kind::Other => {}
        }
    }

    let _ = writeln!(
        w,
        "# --- Rules: checked in order, first match decides -------------------------\n"
    );
    for (name, _, kind) in &kept {
        if *kind == Kind::Shell {
            let _ = writeln!(
                w,
                "[[rule]]\ntool = \"{name}__*\"\nwhen_context_has = [\"untrusted\"]\naction = \"deny\"\nreason = \"running commands is disabled once untrusted content is in context\"\n"
            );
        }
    }
    let asks = [
        (
            "*__*push*",
            true,
            "pushing after reading untrusted content needs a person's OK",
        ),
        (
            "*__*merge*",
            true,
            "merging after reading untrusted content needs a person's OK",
        ),
        ("*__*delete*", false, "deleting needs a person's OK"),
    ];
    let asks: Vec<_> = asks.into_iter().filter(|(p, _, _)| useful(p)).collect();
    if !asks.is_empty() {
        let _ = writeln!(
            w,
            "# Changes that are hard to undo need a person's OK. They see an approval\n# prompt the model can't answer.\n"
        );
    }
    for (pattern, when_untrusted, reason) in asks {
        let condition = if when_untrusted {
            "when_context_has = [\"untrusted\"]\n"
        } else {
            ""
        };
        let _ = writeln!(
            w,
            "[[rule]]\ntool = {}\n{condition}action = \"ask\"\nreason = {}\n",
            quote(pattern),
            quote(reason)
        );
    }

    for (name, _, kind) in &kept {
        let (write, read) = (format!("{name}__*write*"), format!("{name}__read*"));
        if *kind == Kind::Files && useful(&write) && useful(&read) {
            let _ = writeln!(
                w,
                "# --- Labels that outlive a session ----------------------------------------\n\n[[resource]]\nwrite = {}\nread = {}\nkey = \"path\"\n",
                quote(&write),
                quote(&read)
            );
        }
    }

    Generated {
        toml: out,
        servers: kept.iter().map(|(n, _, k)| (n.clone(), *k)).collect(),
        skipped,
        renamed,
    }
}

pub fn describe(kind: Kind) -> &'static str {
    match kind {
        Kind::Web => "web access (output untrusted, except trusted hosts)",
        Kind::Files => "local files (trusted, tracked across sessions)",
        Kind::Shell => "runs commands (output trusted; blocked once untrusted data is in context)",
        Kind::Collaboration => "content written by other people (untrusted)",
        Kind::Other => "unknown (output untrusted by default)",
    }
}

/// The client config entry that runs aegis instead of the servers.
pub fn client_entry(config_path: &str) -> Value {
    json!({ "command": "aegis", "args": ["run", "-c", config_path] })
}

/// `original` with its `mcpServers` replaced by a single `aegis` entry,
/// keeping servers aegis can't front (remote ones) as they were.
pub fn replace_servers(
    original: &str,
    config_path: &str,
    skipped: &[(String, String)],
) -> Result<String> {
    let mut value: Value = serde_json::from_str(original)?;
    let servers = value
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .context("no \"mcpServers\" object found")?;
    let keep: BTreeSet<&str> = skipped.iter().map(|(n, _)| n.as_str()).collect();
    servers.retain(|name, _| keep.contains(name.as_str()));
    servers.insert("aegis".into(), client_entry(config_path));
    Ok(serde_json::to_string_pretty(&value)? + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    const CLIENT: &str = r#"{
      "mcpServers": {
        "fetch": { "command": "uvx", "args": ["mcp-server-fetch"] },
        "filesystem": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/repo"] },
        "github_api": { "command": "github-mcp-server", "args": ["stdio"], "env": { "GITHUB_TOKEN": "x" } },
        "desktop-commander": { "command": "npx", "args": ["@wonderwhy-er/desktop-commander"] },
        "notes": { "command": "my-notes-server" },
        "remote": { "url": "https://mcp.example.com/sse" }
      },
      "theme": "dark"
    }"#;

    #[test]
    fn classifies_common_servers() {
        let servers = parse_client_config(CLIENT).unwrap();
        let kinds: Vec<Kind> = servers.iter().map(|(n, s)| classify(n, s, &[])).collect();
        assert_eq!(
            kinds,
            [
                Kind::Web,
                Kind::Files,
                Kind::Collaboration,
                Kind::Shell,
                Kind::Other,
                Kind::Other
            ]
        );
    }

    #[test]
    fn generated_config_is_valid_and_reasoned() {
        let servers = parse_client_config(CLIENT).unwrap();
        let generated = generate(&servers, &BTreeMap::new());
        let config: Config = toml::from_str(&generated.toml).unwrap();
        config.validate().unwrap();

        let names: Vec<&str> = config.servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "fetch",
                "filesystem",
                "github-api",
                "desktop-commander",
                "notes"
            ]
        );
        assert_eq!(
            generated.renamed,
            [("github_api".to_string(), "github-api".to_string())]
        );
        assert_eq!(generated.skipped.len(), 1);
        assert!(generated.skipped[0].1.contains("remote"));
        assert_eq!(config.servers[2].env["GITHUB_TOKEN"], "x");

        let policy = config.policy();
        let labels = |tool: &str, args: Value| policy.labels_for_result(tool, &args);
        assert!(labels("fetch__fetch", json!({ "url": "https://docs.rs/x" })).is_empty());
        assert!(
            labels("fetch__fetch", json!({ "url": "https://evil.example" })).contains("untrusted")
        );
        assert!(labels("filesystem__read_file", json!({})).is_empty());
        assert!(labels("github-api__get_issue", json!({})).contains("untrusted"));

        let mut session = crate::policy::Session::default();
        session.observe_result(
            &policy,
            "fetch__fetch",
            &json!({ "url": "https://evil.example" }),
        );
        let check = |tool: &str| session.check_call(&policy, tool).action;
        use crate::policy::Action;
        assert_eq!(check("desktop-commander__execute_command"), Action::Deny);

        // Running a command doesn't by itself block the next one.
        let mut clean = crate::policy::Session::default();
        clean.observe_result(
            &policy,
            "desktop-commander__execute_command",
            &json!({ "command": "ls" }),
        );
        assert_eq!(
            clean
                .check_call(&policy, "desktop-commander__execute_command")
                .action,
            Action::Allow
        );
        assert_eq!(check("github-api__push_files"), Action::Ask);
        assert_eq!(check("github-api__merge_pull_request"), Action::Ask);
        assert_eq!(check("filesystem__read_file"), Action::Allow);
        assert_eq!(config.resources.len(), 1);
    }

    #[test]
    fn name_wins_over_arguments_and_tools_refine_unknown_servers() {
        let server = |args: &[&str]| McpServer {
            command: Some("python3".into()),
            args: args.iter().map(|a| a.to_string()).collect(),
            env: Default::default(),
            url: None,
        };
        // "files" in the arguments doesn't make a GitHub server a file server.
        assert_eq!(
            classify("github_api", &server(&["--allowed-files"]), &[]),
            Kind::Collaboration
        );
        // An unhelpful name is classified by its tools.
        let tools = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        assert_eq!(
            classify("tools", &server(&[]), &tools(&["run_command"])),
            Kind::Shell
        );
        assert_eq!(
            classify("helper", &server(&[]), &tools(&["read_file", "write_file"])),
            Kind::Files
        );
        assert_eq!(
            classify("helper", &server(&[]), &tools(&["web_search"])),
            Kind::Web
        );
        assert_eq!(
            classify("helper", &server(&[]), &tools(&["get_issues"])),
            Kind::Collaboration
        );
    }

    #[test]
    fn known_tools_drop_rules_that_would_match_nothing() {
        let servers = parse_client_config(CLIENT).unwrap();
        let tools: BTreeMap<String, Vec<String>> = [
            ("fetch", vec!["fetch"]),
            ("filesystem", vec!["read_file", "write_file"]),
            ("github_api", vec!["get_issue", "push_files"]),
            ("desktop-commander", vec!["execute_command"]),
            ("notes", vec!["list_notes"]),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.into_iter().map(String::from).collect()))
        .collect();
        let config: Config = toml::from_str(&generate(&servers, &tools).toml).unwrap();
        config.validate().unwrap();
        let rule_tools: Vec<&str> = config.rules.iter().map(|r| r.tool.as_str()).collect();
        assert_eq!(rule_tools, ["desktop-commander__*", "*__*push*"]);
        assert_eq!(config.resources.len(), 1);
    }

    #[test]
    fn sanitizes_names() {
        assert_eq!(sanitize_name("github_api"), "github-api");
        assert_eq!(sanitize_name("My Server!"), "my-server");
        assert_eq!(sanitize_name("__"), "server");
        let servers = vec![
            (
                "a_b".to_string(),
                McpServer {
                    command: Some("x".into()),
                    args: vec![],
                    env: Default::default(),
                    url: None,
                },
            ),
            (
                "a-b".to_string(),
                McpServer {
                    command: Some("y".into()),
                    args: vec![],
                    env: Default::default(),
                    url: None,
                },
            ),
        ];
        let config: Config = toml::from_str(&generate(&servers, &BTreeMap::new()).toml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.servers[1].name, "a-b-2");
    }

    #[test]
    fn replacing_keeps_other_settings_and_remote_servers() {
        let servers = parse_client_config(CLIENT).unwrap();
        let generated = generate(&servers, &BTreeMap::new());
        let replaced = replace_servers(CLIENT, "/repo/aegis.toml", &generated.skipped).unwrap();
        let value: Value = serde_json::from_str(&replaced).unwrap();
        let names: Vec<&String> = value["mcpServers"].as_object().unwrap().keys().collect();
        assert_eq!(names, ["remote", "aegis"]);
        assert_eq!(
            value["mcpServers"]["aegis"]["args"],
            json!(["run", "-c", "/repo/aegis.toml"])
        );
        assert_eq!(value["theme"], "dark");
    }
}
