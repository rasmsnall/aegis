//! `aegis.toml` configuration.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::policy::{Action, Rule, Source};

/// Separator between a server name and its tool name in the tool names aegis
/// exposes to the agent: tool `exec` on server `shell` becomes `shell__exec`.
pub const NAMESPACE_SEP: &str = "__";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default, rename = "server")]
    pub servers: Vec<ServerConfig>,
    #[serde(default, rename = "source")]
    pub sources: Vec<Source>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// JSONL file the hash-chained audit log is appended to.
    #[serde(default = "default_audit_path")]
    pub path: PathBuf,
    /// File holding the key the log is signed with. If unset, the key is read
    /// from `AEGIS_AUDIT_KEY`; with neither, the log is an unsigned chain.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            path: default_audit_path(),
            key_file: None,
        }
    }
}

fn default_audit_path() -> PathBuf {
    PathBuf::from("aegis-audit.jsonl")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Action taken for a tool call that no rule matches.
    #[serde(default = "default_action")]
    pub default: Action,
    /// Labels for the output of tools that no `[[source]]` matches. Defaults
    /// to `["untrusted"]` so an unlisted tool is never trusted by accident;
    /// set `[]` to trust unlisted tools instead.
    #[serde(default = "default_labels")]
    pub default_labels: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default: default_action(),
            default_labels: default_labels(),
        }
    }
}

fn default_labels() -> Vec<String> {
    vec!["untrusted".into()]
}

fn default_action() -> Action {
    Action::Allow
}

/// An upstream MCP server launched over stdio.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// How long the server may take to start and answer `initialize`.
    #[serde(default = "default_startup_timeout")]
    pub startup_timeout_secs: u64,
    /// How long a single request (a tool call, a tool listing) may take.
    #[serde(default = "default_call_timeout")]
    pub call_timeout_secs: u64,
}

fn default_startup_timeout() -> u64 {
    30
}

fn default_call_timeout() -> u64 {
    300
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let config: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for server in &self.servers {
            // Without underscores in server names, the first `__` in an
            // exposed tool name always ends the server name, so two servers
            // can never expose the same name (`shell_` + `exec` would
            // otherwise collide with `shell` + `_exec`).
            let valid = server.name.starts_with(|c: char| c.is_ascii_alphanumeric())
                && server
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-');
            if !valid {
                bail!(
                    "server name {:?} must start with a letter or digit and contain only letters, digits and '-'",
                    server.name
                );
            }
            if server.startup_timeout_secs == 0 || server.call_timeout_secs == 0 {
                bail!(
                    "server {:?}: timeouts must be at least 1 second",
                    server.name
                );
            }
            if !seen.insert(server.name.as_str()) {
                bail!("duplicate server name {:?}", server.name);
            }
        }
        Ok(())
    }

    pub fn policy(&self) -> crate::policy::Policy {
        crate::policy::Policy {
            sources: self.sources.clone(),
            rules: self.rules.clone(),
            default: self.policy.default,
            default_labels: self.policy.default_labels.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_config() {
        let text = include_str!("../examples/aegis.toml");
        let config: Config = toml::from_str(text).unwrap();
        config.validate().unwrap();
        assert!(!config.servers.is_empty());
        assert!(!config.rules.is_empty());
    }

    fn server_named(name: &str) -> Config {
        toml::from_str(&format!("[[server]]\nname = {name:?}\ncommand = \"x\"")).unwrap()
    }

    #[test]
    fn server_names_cannot_collide() {
        for bad in ["a__b", "shell_", "_shell", "sh ell", "", "-x"] {
            assert!(server_named(bad).validate().is_err(), "{bad:?} accepted");
        }
        for good in ["shell", "web-2", "GitHub"] {
            server_named(good).validate().unwrap();
        }
    }

    #[test]
    fn unlisted_tools_are_untrusted_by_default() {
        let config: Config = toml::from_str("").unwrap();
        let policy = config.policy();
        assert!(policy.labels_for_result("any__tool").contains("untrusted"));

        let config: Config = toml::from_str("[policy]\ndefault_labels = []").unwrap();
        assert!(config.policy().labels_for_result("any__tool").is_empty());
    }
}
