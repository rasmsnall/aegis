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
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            path: default_audit_path(),
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
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default: default_action(),
        }
    }
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
            if server.name.is_empty() || server.name.contains(NAMESPACE_SEP) {
                bail!(
                    "server name {:?} must be non-empty and must not contain {NAMESPACE_SEP:?}",
                    server.name
                );
            }
            if !seen.insert(server.name.as_str()) {
                bail!("duplicate server name {:?}", server.name);
            }
        }
        for (i, source) in self.sources.iter().enumerate() {
            if source.labels.is_empty() {
                bail!("source #{} ({:?}) assigns no labels", i + 1, source.tool);
            }
        }
        Ok(())
    }

    pub fn policy(&self) -> crate::policy::Policy {
        crate::policy::Policy {
            sources: self.sources.clone(),
            rules: self.rules.clone(),
            default: self.policy.default,
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

    #[test]
    fn rejects_namespaced_server_name() {
        let config: Config = toml::from_str(
            r#"
            [[server]]
            name = "a__b"
            command = "x"
            "#,
        )
        .unwrap();
        assert!(config.validate().is_err());
    }
}
