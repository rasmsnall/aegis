//! Source labelling and sink rules.
//!
//! The model is deliberately simple: every tool result carries the labels of
//! the sources it matches, those labels flow into the session context and stay
//! there (the context only ever grows), and every tool call is checked against
//! the rules given the labels the context has accumulated so far.
//!
//! This is coarse — it assumes anything the agent has read may influence
//! anything it does next — but that assumption is exactly what makes it sound
//! against prompt injection: the model cannot be talked out of it.
//!
//! Labelling fails closed: output of a tool no source matches gets the
//! policy's `default_labels` (`untrusted` unless configured otherwise), so a
//! newly added or renamed tool is never trusted by accident. A source with
//! `labels = []` marks a tool's output as trusted.
//!
//! Sources, like rules, are checked in order and the first one that matches
//! decides. A source can depend on the call's arguments (`hosts`, `paths`,
//! `args`), so "pages from docs.rs are trusted" goes before "everything else
//! from the web is untrusted". A condition that cannot be checked (the
//! argument is missing, or isn't a web URL) does not match, so the call
//! falls through to the next source, and in the end to `default_labels`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::labels::{LabelSet, glob_match, host_matches, normalize_path, url_host};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
    /// Run the call only if a person approves it.
    Ask,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Ask => "ask",
        }
    }
}

/// Labels attached to the output of every tool matching `tool`. Empty
/// `labels` marks the output as trusted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub tool: String,
    pub labels: Vec<String>,
    /// Only match when the URL in `url_arg` is on one of these hosts
    /// (`docs.rs`, or `*.rust-lang.org` for its subdomains).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default = "default_url_arg")]
    pub url_arg: String,
    /// Only match when the path in `path_arg`, normalized, matches one of
    /// these patterns (`*` also matches across `/`, so `src/*` covers `src/a/b`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default = "default_path_arg")]
    pub path_arg: String,
    /// Only match when each named argument (`a.b` looks inside objects) is a
    /// string matching one of its patterns.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, Vec<String>>,
}

fn default_url_arg() -> String {
    "url".into()
}

fn default_path_arg() -> String {
    "path".into()
}

/// The string at `key` (dotted for nested objects) in `arguments`.
fn arg_str<'a>(arguments: &'a Value, key: &str) -> Option<&'a str> {
    key.split('.')
        .try_fold(arguments, |v, part| v.get(part))?
        .as_str()
}

impl Source {
    /// A source with no argument conditions.
    pub fn new(tool: impl Into<String>, labels: &[&str]) -> Self {
        Self {
            tool: tool.into(),
            labels: labels.iter().map(|l| l.to_string()).collect(),
            hosts: Vec::new(),
            url_arg: default_url_arg(),
            paths: Vec::new(),
            path_arg: default_path_arg(),
            args: BTreeMap::new(),
        }
    }

    /// Whether this source depends on the call's arguments.
    pub fn is_conditional(&self) -> bool {
        !self.hosts.is_empty() || !self.paths.is_empty() || !self.args.is_empty()
    }

    /// Whether this source applies to a call of `tool` with `arguments`.
    pub fn matches(&self, tool: &str, arguments: &Value) -> bool {
        if !glob_match(&self.tool, tool) {
            return false;
        }
        if !self.hosts.is_empty() {
            let Some(host) = arg_str(arguments, &self.url_arg).and_then(url_host) else {
                return false;
            };
            if !self.hosts.iter().any(|p| host_matches(p, &host)) {
                return false;
            }
        }
        if !self.paths.is_empty() {
            let Some(path) = arg_str(arguments, &self.path_arg).map(normalize_path) else {
                return false;
            };
            if !self
                .paths
                .iter()
                .any(|p| glob_match(&normalize_path(p), &path))
            {
                return false;
            }
        }
        self.args.iter().all(|(key, patterns)| {
            arg_str(arguments, key).is_some_and(|v| patterns.iter().any(|p| glob_match(p, v)))
        })
    }
}

/// A rule over tool calls. The first rule that matches a call decides it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Tool name pattern (`*` wildcards), e.g. `shell__*`.
    pub tool: String,
    /// The rule only matches if the session context carries at least one of
    /// these labels. Empty means the rule matches unconditionally.
    #[serde(default)]
    pub when_context_has: Vec<String>,
    pub action: Action,
    /// Shown to the agent (and logged) when the rule denies a call.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub sources: Vec<Source>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    pub default: Action,
    /// Labels for the output of tools that no source matches.
    pub default_labels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub action: Action,
    /// 1-based index of the deciding rule; `None` means the default applied.
    pub rule: Option<usize>,
    /// Context labels that triggered the rule.
    pub matched_labels: Vec<String>,
    pub reason: Option<String>,
    /// For `ask`: whether a person approved the call. `None` until answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<bool>,
}

impl Decision {
    /// Whether the call goes ahead: allowed outright, or asked and approved.
    pub fn runs(&self) -> bool {
        match self.action {
            Action::Allow => true,
            Action::Deny => false,
            Action::Ask => self.approved == Some(true),
        }
    }

    /// The tool error shown to the agent when the call does not run.
    pub fn message(&self, tool: &str) -> String {
        let rule = self
            .rule
            .map_or("the default policy".to_string(), |r| format!("rule #{r}"));
        let because = if self.matched_labels.is_empty() {
            String::new()
        } else {
            format!(
                " because this session has read data labelled {}",
                self.matched_labels.join(", ")
            )
        };
        let mut text = match self.action {
            Action::Ask => format!(
                "aegis did not run this call to {tool}: {rule} requires a person's approval{because}, and it was not approved"
            ),
            _ => format!("aegis blocked this call to {tool} ({rule}){because}"),
        };
        if let Some(reason) = &self.reason {
            text += &format!(": {reason}");
        }
        text
    }
}

impl Policy {
    /// Labels carried by the output of a call to `tool` with `arguments`:
    /// those of the first matching source, else `default_labels`.
    pub fn labels_for_result(&self, tool: &str, arguments: &Value) -> LabelSet {
        match self.sources.iter().find(|s| s.matches(tool, arguments)) {
            Some(source) => source.labels.iter().cloned().collect(),
            None => self.default_labels.iter().cloned().collect(),
        }
    }

    /// Whether any source names `tool` explicitly (whatever its conditions).
    pub fn has_source_for(&self, tool: &str) -> bool {
        self.sources.iter().any(|s| glob_match(&s.tool, tool))
    }

    /// 1-based indexes of the rules whose tool pattern matches `tool`,
    /// whatever their label conditions.
    pub fn rules_for(&self, tool: &str) -> Vec<usize> {
        (0..self.rules.len())
            .filter(|&i| glob_match(&self.rules[i].tool, tool))
            .map(|i| i + 1)
            .collect()
    }

    pub fn decide(&self, tool: &str, context: &LabelSet) -> Decision {
        for (i, rule) in self.rules.iter().enumerate() {
            if !glob_match(&rule.tool, tool) {
                continue;
            }
            let matched_labels: Vec<String> = rule
                .when_context_has
                .iter()
                .filter(|l| context.contains(*l))
                .cloned()
                .collect();
            if !rule.when_context_has.is_empty() && matched_labels.is_empty() {
                continue;
            }
            return Decision {
                action: rule.action,
                rule: Some(i + 1),
                matched_labels,
                reason: rule.reason.clone(),
                approved: None,
            };
        }
        Decision {
            action: self.default,
            rule: None,
            matched_labels: Vec::new(),
            reason: None,
            approved: None,
        }
    }
}

/// Taint state for one agent session.
#[derive(Debug, Default, Clone)]
pub struct Session {
    context: LabelSet,
}

impl Session {
    pub fn context(&self) -> &LabelSet {
        &self.context
    }

    /// Records that the agent has seen the output of `tool`. Returns the labels
    /// that were newly added to the context.
    pub fn observe_result(&mut self, policy: &Policy, tool: &str, arguments: &Value) -> LabelSet {
        policy
            .labels_for_result(tool, arguments)
            .into_iter()
            .filter(|l| self.context.insert(l.clone()))
            .collect()
    }

    /// Adds labels from elsewhere (e.g. a file written in an earlier session).
    /// Returns the ones that were new.
    pub fn add_labels(&mut self, labels: impl IntoIterator<Item = String>) -> LabelSet {
        labels
            .into_iter()
            .filter(|l| self.context.insert(l.clone()))
            .collect()
    }

    pub fn check_call(&self, policy: &Policy, tool: &str) -> Decision {
        policy.decide(tool, &self.context)
    }
}

/// One call in a [`simulate`]d session.
#[derive(Debug, Clone, Deserialize)]
pub struct SimCall {
    pub tool: String,
    #[serde(default)]
    pub arguments: Value,
    /// The person's answer if the policy asks about this call.
    #[serde(default)]
    pub approved: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimEntry {
    pub tool: String,
    pub decision: Decision,
    /// Whether the call went ahead.
    pub runs: bool,
    /// Labels its output added to the context.
    pub added: Vec<String>,
    /// The tool error the agent saw, if the call did not run.
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Simulation {
    pub entries: Vec<SimEntry>,
    pub context: Vec<String>,
}

/// Runs a sequence of calls through `policy` from a clean session, exactly as
/// the proxy would decide them. This is what the website's playground runs,
/// compiled to WebAssembly.
pub fn simulate(policy: &Policy, calls: &[SimCall]) -> Simulation {
    let mut session = Session::default();
    let entries = calls
        .iter()
        .map(|call| {
            let mut decision = session.check_call(policy, &call.tool);
            if decision.action == Action::Ask {
                decision.approved = call.approved;
            }
            let runs = decision.runs();
            let added = if runs {
                session
                    .observe_result(policy, &call.tool, &call.arguments)
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            };
            let message = (!runs).then(|| decision.message(&call.tool));
            SimEntry {
                tool: call.tool.clone(),
                decision,
                runs,
                added,
                message,
            }
        })
        .collect();
    Simulation {
        entries,
        context: session.context().iter().cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            sources: vec![
                Source::new("web__*", &["untrusted"]),
                Source::new("files__*", &[]),
                Source::new("shell__*", &[]),
            ],
            rules: vec![
                Rule {
                    tool: "shell__*".into(),
                    when_context_has: vec!["untrusted".into()],
                    action: Action::Deny,
                    reason: Some("no shell after reading the web".into()),
                },
                Rule {
                    tool: "danger__*".into(),
                    when_context_has: vec![],
                    action: Action::Deny,
                    reason: None,
                },
            ],
            default: Action::Allow,
            default_labels: vec!["untrusted".into()],
        }
    }

    #[test]
    fn unlisted_tools_get_default_labels() {
        let mut policy = policy();
        assert!(
            policy
                .labels_for_result("files__read", &serde_json::Value::Null)
                .is_empty()
        );
        assert!(
            policy
                .labels_for_result("mail__read", &serde_json::Value::Null)
                .contains("untrusted")
        );
        assert!(!policy.has_source_for("mail__read"));

        let mut session = Session::default();
        session.observe_result(&policy, "mail__read", &serde_json::Value::Null);
        assert_eq!(
            session.check_call(&policy, "shell__exec").action,
            Action::Deny
        );

        policy.default_labels.clear();
        assert!(
            policy
                .labels_for_result("mail__read", &serde_json::Value::Null)
                .is_empty()
        );
    }

    #[test]
    fn ask_runs_only_when_approved() {
        let mut policy = policy();
        policy.rules[0].action = Action::Ask;
        let mut session = Session::default();
        session.observe_result(&policy, "web__fetch", &serde_json::Value::Null);
        let mut d = session.check_call(&policy, "shell__exec");
        assert_eq!(d.action, Action::Ask);
        assert!(!d.runs());
        assert!(d.message("shell__exec").contains("not approved"));
        d.approved = Some(false);
        assert!(!d.runs());
        d.approved = Some(true);
        assert!(d.runs());
        assert!(!session.check_call(&policy, "danger__rm").runs());
    }

    #[test]
    fn block_message_explains_itself() {
        let policy = policy();
        let mut session = Session::default();
        session.observe_result(&policy, "web__fetch", &serde_json::Value::Null);
        let text = session
            .check_call(&policy, "shell__exec")
            .message("shell__exec");
        assert_eq!(
            text,
            "aegis blocked this call to shell__exec (rule #1) because this session has read data labelled untrusted: no shell after reading the web"
        );
    }

    #[test]
    fn simulate_matches_the_session_model() {
        let mut policy = policy();
        policy.rules[0].action = Action::Ask;
        let calls = |approved| {
            vec![
                SimCall {
                    tool: "web__fetch".into(),
                    arguments: Value::Null,
                    approved: None,
                },
                SimCall {
                    tool: "shell__exec".into(),
                    arguments: Value::Null,
                    approved,
                },
            ]
        };
        let sim = simulate(&policy, &calls(Some(true)));
        assert_eq!(sim.context, ["untrusted"]);
        assert_eq!(sim.entries[0].added, ["untrusted"]);
        assert!(sim.entries[1].runs && sim.entries[1].message.is_none());

        let sim = simulate(&policy, &calls(None));
        assert!(!sim.entries[1].runs);
        assert!(
            sim.entries[1]
                .message
                .as_deref()
                .unwrap()
                .contains("not approved")
        );
    }

    #[test]
    fn first_matching_source_decides_and_can_trust_by_host() {
        use serde_json::json;
        let mut docs = Source::new("web__fetch", &[]);
        docs.hosts = vec!["docs.rs".into(), "*.rust-lang.org".into()];
        let mut src = Source::new("files__read*", &[]);
        src.paths = vec!["src/*".into()];
        let mut issue = Source::new("github__get_issue", &[]);
        issue.args = [("owner".to_string(), vec!["rasmsnall".to_string()])].into();
        let policy = Policy {
            sources: vec![docs, Source::new("web__*", &["untrusted"]), src, issue],
            rules: vec![],
            default: Action::Allow,
            default_labels: vec!["untrusted".into()],
        };
        let labels = |tool: &str, args: serde_json::Value| policy.labels_for_result(tool, &args);

        assert!(labels("web__fetch", json!({ "url": "https://docs.rs/serde" })).is_empty());
        assert!(
            labels(
                "web__fetch",
                json!({ "url": "https://doc.rust-lang.org/std" })
            )
            .is_empty()
        );
        for bad in [
            json!({ "url": "https://docs.rs@evil.com/" }),
            json!({ "url": "https://docs.rs.evil.com/" }),
            json!({ "url": "https://evil.com/?next=https://docs.rs" }),
            json!({ "url": "file:///etc/passwd" }),
            json!({ "uri": "https://docs.rs/" }), // wrong argument name
            json!({}),
        ] {
            assert!(
                labels("web__fetch", bad.clone()).contains("untrusted"),
                "{bad}"
            );
        }

        assert!(labels("files__read", json!({ "path": "src/a/b.rs" })).is_empty());
        assert!(labels("files__read", json!({ "path": "./src/x/../main.rs" })).is_empty());
        // Escaping src/ falls through to the default.
        assert!(labels("files__read", json!({ "path": "src/../.env" })).contains("untrusted"));

        assert!(labels("github__get_issue", json!({ "owner": "rasmsnall" })).is_empty());
        assert!(labels("github__get_issue", json!({ "owner": "someone" })).contains("untrusted"));
    }

    #[test]
    fn rules_for_ignores_label_conditions() {
        let policy = policy();
        assert_eq!(policy.rules_for("shell__exec"), vec![1]);
        assert_eq!(policy.rules_for("danger__rm"), vec![2]);
        assert!(policy.rules_for("files__read").is_empty());
    }

    #[test]
    fn shell_allowed_until_untrusted_data_is_seen() {
        let policy = policy();
        let mut session = Session::default();

        assert_eq!(
            session.check_call(&policy, "shell__exec").action,
            Action::Allow
        );

        let added = session.observe_result(&policy, "web__fetch", &serde_json::Value::Null);
        assert!(added.contains("untrusted"));

        let d = session.check_call(&policy, "shell__exec");
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.rule, Some(1));
        assert_eq!(d.matched_labels, vec!["untrusted".to_string()]);

        // Other tools are unaffected.
        assert_eq!(
            session.check_call(&policy, "files__read").action,
            Action::Allow
        );
    }

    #[test]
    fn taint_is_sticky() {
        let policy = policy();
        let mut session = Session::default();
        session.observe_result(&policy, "web__fetch", &serde_json::Value::Null);
        assert!(
            session
                .observe_result(&policy, "web__fetch", &serde_json::Value::Null)
                .is_empty()
        );
        session.observe_result(&policy, "files__read", &serde_json::Value::Null);
        assert_eq!(
            session.check_call(&policy, "shell__exec").action,
            Action::Deny
        );
    }

    #[test]
    fn unconditional_rule_and_default() {
        let mut policy = policy();
        let session = Session::default();
        assert_eq!(session.check_call(&policy, "danger__rm").rule, Some(2));
        policy.default = Action::Deny;
        let d = session.check_call(&policy, "files__read");
        assert_eq!((d.action, d.rule), (Action::Deny, None));
    }
}
