//! `aegis.toml` configuration.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::audit::ArgumentLogging;
use crate::policy::{Action, Rule, Source};
use crate::resources::ResourceRule;

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
    #[serde(default, rename = "resource")]
    pub resources: Vec<ResourceRule>,
    #[serde(default)]
    pub state: StateConfig,
    #[serde(default)]
    pub approval: ApprovalConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    /// The organization's policy this config is layered on, if any. Not part
    /// of `aegis.toml`: see [`Config::load_with_org`].
    #[serde(skip)]
    pub org: Option<OrgPolicy>,
}

/// Where an organization installs the policy every aegis on the machine
/// runs under. Only an administrator should be able to write it.
pub fn system_org_policy_path() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into());
        PathBuf::from(base).join("aegis").join("org.toml")
    } else {
        PathBuf::from("/etc/aegis/org.toml")
    }
}

/// An organization's policy: `[policy]`, `[[source]]` and `[[rule]]`, as in
/// `aegis.toml`. A project's config is layered on top and can only make it
/// stricter (see [`crate::policy::Policy::org`]).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgPolicy {
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default, rename = "source")]
    pub sources: Vec<Source>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
    /// Where it was read from.
    #[serde(skip)]
    pub path: PathBuf,
    /// SHA-256 of the file, recorded in the audit log at session start.
    #[serde(skip)]
    pub sha256: String,
}

impl OrgPolicy {
    pub fn load(path: &Path) -> Result<Self> {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading organization policy {}", path.display()))?;
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("organization policy {} is not UTF-8", path.display()))?;
        let mut org: OrgPolicy = toml::from_str(text)
            .with_context(|| format!("parsing organization policy {}", path.display()))?;
        validate_conditions(&org.sources, &org.rules)
            .with_context(|| format!("organization policy {}", path.display()))?;
        org.path = path.to_path_buf();
        org.sha256 = hex::encode(Sha256::digest(&bytes));
        Ok(org)
    }

    pub fn policy(&self) -> crate::policy::Policy {
        crate::policy::Policy {
            sources: self.sources.clone(),
            rules: self.rules.clone(),
            default: self.policy.default,
            default_labels: self.policy.default_labels.clone(),
            org: None,
        }
    }
}

/// Which organization policy applies: the one installed at `system`, if
/// there is one, else `requested` (from `--org-policy`), else none.
/// Requesting a different file than the installed one is an error, so the
/// installed policy can't be swapped for a looser one.
pub fn resolve_org_policy(requested: Option<&Path>, system: &Path) -> Result<Option<PathBuf>> {
    if !system.exists() {
        return Ok(requested.map(Path::to_path_buf));
    }
    if let Some(requested) = requested {
        let same = match (requested.canonicalize(), system.canonicalize()) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
        if !same {
            bail!(
                "an organization policy is installed at {}; --org-policy can't replace it",
                system.display()
            );
        }
    }
    Ok(Some(system.to_path_buf()))
}

/// Where labels that outlive a session (see `[[resource]]`) are kept.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateConfig {
    #[serde(default = "default_state_path")]
    pub path: PathBuf,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            path: default_state_path(),
        }
    }
}

fn default_state_path() -> PathBuf {
    PathBuf::from("aegis-state.json")
}

/// How `action = "ask"` asks a person.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalConfig {
    /// How long to wait for an answer before denying the call.
    #[serde(default = "default_approval_timeout")]
    pub timeout_secs: u64,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_approval_timeout(),
        }
    }
}

fn default_approval_timeout() -> u64 {
    300
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Largest single JSON-RPC message accepted from the agent or a server.
    #[serde(default = "default_max_message_bytes")]
    pub max_message_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_message_bytes: default_max_message_bytes(),
        }
    }
}

fn default_max_message_bytes() -> usize {
    16 * 1024 * 1024
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
    /// How tool call arguments are logged: `redacted` (default) replaces
    /// values that look like secrets, `hash` keeps only a SHA-256 of them,
    /// `omit` drops them, `full` keeps them as sent.
    #[serde(default)]
    pub arguments: ArgumentLogging,
    /// Extra argument names to redact, on top of the built-in list.
    #[serde(default)]
    pub redact_keys: Vec<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            path: default_audit_path(),
            key_file: None,
            arguments: ArgumentLogging::default(),
            redact_keys: Vec::new(),
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

/// An upstream MCP server: launched over stdio (`command`) or reached over
/// MCP's Streamable HTTP transport (`url`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub name: String,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// The endpoint of a remote server, instead of `command`.
    #[serde(default)]
    pub url: Option<String>,
    /// HTTP headers sent to a remote server. `${VAR}` is replaced with the
    /// environment variable `VAR`, so tokens stay out of the file.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Confines a launched server's file and network access (Linux).
    #[serde(default)]
    pub sandbox: Option<crate::sandbox::SandboxConfig>,
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
    /// Loads `path` on top of the organization policy, if one applies (see
    /// [`resolve_org_policy`]). An organization policy that exists but can't
    /// be read or parsed is an error: aegis doesn't run without it.
    pub fn load_with_org(path: &Path, org: Option<&Path>) -> Result<Self> {
        let mut config = Self::load(path)?;
        if let Some(org) = resolve_org_policy(org, &system_org_policy_path())? {
            config.org = Some(OrgPolicy::load(&org)?);
        }
        Ok(config)
    }

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
            match (&server.url, server.command.is_empty()) {
                (Some(_), false) => bail!(
                    "server {:?}: set either command or url, not both",
                    server.name
                ),
                (None, true) => bail!("server {:?}: set command or url", server.name),
                (Some(url), true) => {
                    let parsed = url::Url::parse(url)
                        .with_context(|| format!("server {:?}: url {url:?}", server.name))?;
                    if !matches!(parsed.scheme(), "http" | "https") {
                        bail!(
                            "server {:?}: url must start with http:// or https://",
                            server.name
                        );
                    }
                    if !server.args.is_empty() || !server.env.is_empty() || server.sandbox.is_some()
                    {
                        bail!(
                            "server {:?}: args, env and sandbox apply to launched servers, not to a url",
                            server.name
                        );
                    }
                }
                (None, false) => {
                    if !server.headers.is_empty() {
                        bail!(
                            "server {:?}: headers apply to url servers only",
                            server.name
                        );
                    }
                }
            }
            if !seen.insert(server.name.as_str()) {
                bail!("duplicate server name {:?}", server.name);
            }
        }
        if self.approval.timeout_secs == 0 {
            bail!("[approval] timeout_secs must be at least 1 second");
        }
        if self.limits.max_message_bytes < 1024 {
            bail!("[limits] max_message_bytes must be at least 1024");
        }
        validate_conditions(&self.sources, &self.rules)?;
        for (i, r) in self.resources.iter().enumerate() {
            if r.key.is_empty() || r.key.split('.').any(str::is_empty) {
                bail!(
                    "resource #{}: key {:?} is not a valid argument name",
                    i + 1,
                    r.key
                );
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
            org: self.org.as_ref().map(|o| Box::new(o.policy())),
        }
    }
}

fn validate_conditions(sources: &[Source], rules: &[Rule]) -> Result<()> {
    let hosts = sources
        .iter()
        .enumerate()
        .flat_map(|(i, s)| {
            s.hosts
                .iter()
                .map(move |h| (format!("source #{}", i + 1), h))
        })
        .chain(
            rules
                .iter()
                .enumerate()
                .flat_map(|(i, r)| r.hosts.iter().map(move |h| (format!("rule #{}", i + 1), h))),
        );
    for (what, host) in hosts {
        let bare = host.strip_prefix("*.").unwrap_or(host);
        if bare.is_empty() || bare.contains(['/', ':', '*', '@', ' ']) {
            bail!(
                "{what} host {host:?} must be a host name like \"docs.rs\" or \"*.rust-lang.org\", without scheme, port or path"
            );
        }
    }
    Ok(())
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
    fn servers_have_command_or_url() {
        let parse = |body: &str| {
            toml::from_str::<Config>(&format!("[[server]]\nname = \"s\"\n{body}")).unwrap()
        };
        parse("url = \"https://mcp.example.com/mcp\"")
            .validate()
            .unwrap();
        parse("url = \"https://x.dev/mcp\"\nheaders = { Authorization = \"Bearer ${T}\" }")
            .validate()
            .unwrap();
        for bad in [
            "",
            "command = \"x\"\nurl = \"https://x.dev\"",
            "url = \"ftp://x.dev\"",
            "url = \"not a url\"",
            "command = \"x\"\nheaders = { A = \"b\" }",
            "url = \"https://x.dev\"\nargs = [\"a\"]",
        ] {
            assert!(parse(bad).validate().is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn host_patterns_are_validated() {
        let source = |host: &str| {
            toml::from_str::<Config>(&format!(
                "[[source]]\ntool = \"web__*\"\nlabels = []\nhosts = [{host:?}]"
            ))
            .unwrap()
        };
        for bad in [
            "https://docs.rs",
            "docs.rs/x",
            "docs.rs:443",
            "*",
            "*.",
            "a*.b",
            "",
        ] {
            assert!(source(bad).validate().is_err(), "{bad:?} accepted");
        }
        for good in ["docs.rs", "*.rust-lang.org", "localhost"] {
            source(good).validate().unwrap();
        }
    }

    #[test]
    fn rule_hosts_are_validated() {
        let rule = |host: &str| {
            toml::from_str::<Config>(&format!(
                "[[rule]]\ntool = \"web__*\"\naction = \"allow\"\nhosts = [{host:?}]"
            ))
            .unwrap()
        };
        assert!(rule("https://docs.rs").validate().is_err());
        rule("docs.rs").validate().unwrap();
    }

    #[test]
    fn installed_org_policy_cannot_be_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let system = dir.path().join("org.toml");
        let other = dir.path().join("loose.toml");
        std::fs::write(&other, "").unwrap();

        // Nothing installed: --org-policy is used if given.
        assert_eq!(resolve_org_policy(None, &system).unwrap(), None);
        assert_eq!(
            resolve_org_policy(Some(&other), &system).unwrap(),
            Some(other.clone())
        );

        std::fs::write(&system, "").unwrap();
        assert_eq!(
            resolve_org_policy(None, &system).unwrap(),
            Some(system.clone())
        );
        assert_eq!(
            resolve_org_policy(Some(&system), &system).unwrap(),
            Some(system.clone())
        );
        assert!(resolve_org_policy(Some(&other), &system).is_err());
    }

    #[test]
    fn org_policy_files_hold_only_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("org.toml");
        std::fs::write(
            &path,
            "[policy]\ndefault_labels = []\n[[rule]]\ntool = \"*__delete_*\"\naction = \"deny\"",
        )
        .unwrap();
        let org = OrgPolicy::load(&path).unwrap();
        assert_eq!(org.rules.len(), 1);
        assert_eq!(org.sha256.len(), 64);

        std::fs::write(&path, "[[server]]\nname = \"x\"\ncommand = \"x\"").unwrap();
        assert!(OrgPolicy::load(&path).is_err());
        std::fs::write(&path, "not toml [").unwrap();
        assert!(OrgPolicy::load(&path).is_err());
    }

    #[test]
    fn unlisted_tools_are_untrusted_by_default() {
        let config: Config = toml::from_str("").unwrap();
        let policy = config.policy();
        assert!(
            policy
                .labels_for_result("any__tool", &serde_json::Value::Null)
                .contains("untrusted")
        );

        let config: Config = toml::from_str("[policy]\ndefault_labels = []").unwrap();
        assert!(
            config
                .policy()
                .labels_for_result("any__tool", &serde_json::Value::Null)
                .is_empty()
        );
    }
}
