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
//!
//! Rules take the same conditions, so "`web__fetch` to docs.rs is fine even
//! with secrets in context" can go before "no `web__fetch` once the context
//! has secrets". A rule whose condition can't be checked doesn't match and
//! the next rule decides, so conditions belong on `allow` rules followed by
//! a broader `deny`: a `deny` limited to some hosts is a denylist, and any
//! host it doesn't name gets through.
//!
//! An organization can add sources and rules of its own (`org`) that every
//! project's policy runs under. Output gets the labels of the first matching
//! org source as well, and a call gets the stricter of the first matching
//! org rule's decision and the project's (deny, then ask, then allow), so a
//! project can tighten the org's policy but never loosen it.

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
    /// Deny is stricter than ask, which is stricter than allow.
    fn strictness(self) -> u8 {
        match self {
            Action::Allow => 0,
            Action::Ask => 1,
            Action::Deny => 2,
        }
    }

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

/// Conditions on a call's arguments, shared by sources and rules. All must
/// hold; none means the call's arguments don't matter.
#[derive(Debug, Clone, Copy)]
pub struct Conditions<'a> {
    pub hosts: &'a [String],
    pub url_arg: &'a str,
    pub paths: &'a [String],
    pub path_arg: &'a str,
    pub args: &'a BTreeMap<String, Vec<String>>,
}

impl Conditions<'_> {
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty() && self.paths.is_empty() && self.args.is_empty()
    }

    /// Whether `arguments` satisfy every condition. One that can't be checked
    /// (a missing argument, a URL that isn't http or https) doesn't hold.
    pub fn hold(&self, arguments: &Value) -> bool {
        if !self.hosts.is_empty() {
            let Some(host) = arg_str(arguments, self.url_arg).and_then(url_host) else {
                return false;
            };
            if !self.hosts.iter().any(|p| host_matches(p, &host)) {
                return false;
            }
        }
        if !self.paths.is_empty() {
            let Some(path) = arg_str(arguments, self.path_arg).map(normalize_path) else {
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

    /// Each condition in words, e.g. `url host docs.rs|*.rust-lang.org`.
    pub fn describe(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.hosts.is_empty() {
            out.push(format!("{} host {}", self.url_arg, self.hosts.join("|")));
        }
        if !self.paths.is_empty() {
            out.push(format!("{} {}", self.path_arg, self.paths.join("|")));
        }
        for (key, patterns) in self.args {
            out.push(format!("{key}={}", patterns.join("|")));
        }
        out
    }
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

    pub fn conditions(&self) -> Conditions<'_> {
        Conditions {
            hosts: &self.hosts,
            url_arg: &self.url_arg,
            paths: &self.paths,
            path_arg: &self.path_arg,
            args: &self.args,
        }
    }

    /// Whether this source depends on the call's arguments.
    pub fn is_conditional(&self) -> bool {
        !self.conditions().is_empty()
    }

    /// Whether this source applies to a call of `tool` with `arguments`.
    pub fn matches(&self, tool: &str, arguments: &Value) -> bool {
        glob_match(&self.tool, tool) && self.conditions().hold(arguments)
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
    /// Only match when the URL in `url_arg` is on one of these hosts, as for
    /// sources.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default = "default_url_arg")]
    pub url_arg: String,
    /// Only match when the path in `path_arg`, normalized, matches one of
    /// these patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default = "default_path_arg")]
    pub path_arg: String,
    /// Only match when each named argument is a string matching one of its
    /// patterns.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, Vec<String>>,
}

impl Rule {
    /// A rule with no label or argument conditions.
    pub fn new(tool: impl Into<String>, action: Action) -> Self {
        Self {
            tool: tool.into(),
            when_context_has: Vec::new(),
            action,
            reason: None,
            hosts: Vec::new(),
            url_arg: default_url_arg(),
            paths: Vec::new(),
            path_arg: default_path_arg(),
            args: BTreeMap::new(),
        }
    }

    pub fn conditions(&self) -> Conditions<'_> {
        Conditions {
            hosts: &self.hosts,
            url_arg: &self.url_arg,
            paths: &self.paths,
            path_arg: &self.path_arg,
            args: &self.args,
        }
    }
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
    /// The organization's sources and rules, applied on top of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<Org>,
}

/// An organization's sources and rules. They only add: labels on output,
/// and stricter decisions. Where none matches, the org has no say.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Org {
    #[serde(default, rename = "source")]
    pub sources: Vec<Source>,
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
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
    /// Whether the org policy decided (so `rule` numbers an org rule).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub org: bool,
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

    /// The deciding rule in words: `rule #2`, `org rule #1` or `default`.
    pub fn rule_label(&self) -> String {
        match (self.rule, self.org) {
            (Some(r), true) => format!("org rule #{r}"),
            (Some(r), false) => format!("rule #{r}"),
            (None, _) => "default".to_string(),
        }
    }

    /// The tool error shown to the agent when the call does not run.
    pub fn message(&self, tool: &str) -> String {
        let rule = match self.rule {
            Some(_) => self.rule_label(),
            None => "the default policy".to_string(),
        };
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
    /// those of the first matching source, else `default_labels`, plus those
    /// of the first matching org source.
    pub fn labels_for_result(&self, tool: &str, arguments: &Value) -> LabelSet {
        let mut labels: LabelSet = match self.sources.iter().find(|s| s.matches(tool, arguments)) {
            Some(source) => source.labels.iter().cloned().collect(),
            None => self.default_labels.iter().cloned().collect(),
        };
        let org = self.org.iter().flat_map(|o| &o.sources);
        if let Some(source) = org.into_iter().find(|s| s.matches(tool, arguments)) {
            labels.extend(source.labels.iter().cloned());
        }
        labels
    }

    /// Whether any source names `tool` explicitly (whatever its conditions).
    pub fn has_source_for(&self, tool: &str) -> bool {
        self.sources.iter().any(|s| glob_match(&s.tool, tool))
    }

    /// 1-based indexes of the rules whose tool pattern matches `tool`,
    /// whatever their label and argument conditions.
    pub fn rules_for(&self, tool: &str) -> Vec<usize> {
        (0..self.rules.len())
            .filter(|&i| glob_match(&self.rules[i].tool, tool))
            .map(|i| i + 1)
            .collect()
    }

    /// The first rule matching a call of `tool` with `arguments`, given the
    /// session's `context`, decides it; else the policy's default. If an org
    /// rule matches too, the stricter decision wins (the org's on a tie).
    pub fn decide(&self, tool: &str, arguments: &Value, context: &LabelSet) -> Decision {
        let own = first_match(&self.rules, tool, arguments, context).unwrap_or(Decision {
            action: self.default,
            rule: None,
            matched_labels: Vec::new(),
            reason: None,
            approved: None,
            org: false,
        });
        let org = self
            .org
            .as_ref()
            .and_then(|o| first_match(&o.rules, tool, arguments, context));
        match org {
            Some(org) if org.action.strictness() >= own.action.strictness() => {
                Decision { org: true, ..org }
            }
            _ => own,
        }
    }
}

/// The decision of the first of `rules` that matches the call, if any.
fn first_match(
    rules: &[Rule],
    tool: &str,
    arguments: &Value,
    context: &LabelSet,
) -> Option<Decision> {
    for (i, rule) in rules.iter().enumerate() {
        if !glob_match(&rule.tool, tool) || !rule.conditions().hold(arguments) {
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
        return Some(Decision {
            action: rule.action,
            rule: Some(i + 1),
            matched_labels,
            reason: rule.reason.clone(),
            approved: None,
            org: false,
        });
    }
    None
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

    pub fn check_call(&self, policy: &Policy, tool: &str, arguments: &Value) -> Decision {
        policy.decide(tool, arguments, &self.context)
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
            let mut decision = session.check_call(policy, &call.tool, &call.arguments);
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
                    when_context_has: vec!["untrusted".into()],
                    reason: Some("no shell after reading the web".into()),
                    ..Rule::new("shell__*", Action::Deny)
                },
                Rule::new("danger__*", Action::Deny),
            ],
            default: Action::Allow,
            default_labels: vec!["untrusted".into()],
            org: None,
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
            session
                .check_call(&policy, "shell__exec", &Value::Null)
                .action,
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
        let mut d = session.check_call(&policy, "shell__exec", &Value::Null);
        assert_eq!(d.action, Action::Ask);
        assert!(!d.runs());
        assert!(d.message("shell__exec").contains("not approved"));
        d.approved = Some(false);
        assert!(!d.runs());
        d.approved = Some(true);
        assert!(d.runs());
        assert!(
            !session
                .check_call(&policy, "danger__rm", &Value::Null)
                .runs()
        );
    }

    #[test]
    fn block_message_explains_itself() {
        let policy = policy();
        let mut session = Session::default();
        session.observe_result(&policy, "web__fetch", &serde_json::Value::Null);
        let text = session
            .check_call(&policy, "shell__exec", &Value::Null)
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
            org: None,
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
    fn rules_can_depend_on_arguments() {
        use serde_json::json;
        let mut docs = Rule {
            when_context_has: vec!["secret".into()],
            ..Rule::new("web__fetch", Action::Allow)
        };
        docs.hosts = vec!["docs.rs".into()];
        let mut ours = Rule::new("github__push_files", Action::Allow);
        ours.args = [("owner".to_string(), vec!["rasmsnall".to_string()])].into();
        let policy = Policy {
            sources: vec![],
            rules: vec![
                docs,
                Rule {
                    when_context_has: vec!["secret".into()],
                    ..Rule::new("web__fetch", Action::Deny)
                },
                ours,
                Rule::new("github__push_files", Action::Ask),
            ],
            default: Action::Allow,
            default_labels: vec![],
            org: None,
        };
        let mut session = Session::default();
        let fetch = |session: &Session, url: &str| {
            session
                .check_call(&policy, "web__fetch", &json!({ "url": url }))
                .rule
        };
        // Without the label, neither fetch rule applies.
        assert_eq!(fetch(&session, "https://evil.example/"), None);
        session.add_labels(["secret".to_string()]);
        assert_eq!(fetch(&session, "https://docs.rs/serde"), Some(1));
        for bad in [
            "https://docs.rs@evil.example/",
            "https://docs.rs.evil.example/",
            "file:///etc/passwd",
        ] {
            assert_eq!(fetch(&session, bad), Some(2), "{bad}");
        }
        // A missing argument doesn't satisfy the condition either.
        assert_eq!(
            session.check_call(&policy, "web__fetch", &json!({})).action,
            Action::Deny
        );

        let push = |owner: &str| {
            session
                .check_call(&policy, "github__push_files", &json!({ "owner": owner }))
                .action
        };
        assert_eq!(push("rasmsnall"), Action::Allow);
        assert_eq!(push("someone"), Action::Ask);
        assert_eq!(policy.rules_for("web__fetch"), vec![1, 2]);
    }

    fn org() -> Org {
        Org {
            sources: vec![Source::new("web__*", &["untrusted"])],
            rules: vec![
                Rule {
                    when_context_has: vec!["untrusted".into()],
                    reason: Some("org: no shell after the web".into()),
                    ..Rule::new("shell__*", Action::Deny)
                },
                Rule::new("*__delete_*", Action::Deny),
                Rule::new("github__push_files", Action::Ask),
            ],
        }
    }

    #[test]
    fn org_rules_win_over_looser_project_rules() {
        use serde_json::json;
        let project = Policy {
            sources: vec![
                Source::new("web__*", &[]),
                Source::new("mail__*", &["mail"]),
            ],
            rules: vec![
                Rule::new("shell__*", Action::Allow),
                Rule::new("github__delete_file", Action::Allow),
                Rule {
                    when_context_has: vec!["mail".into()],
                    ..Rule::new("files__write", Action::Deny)
                },
            ],
            default: Action::Allow,
            default_labels: vec![],
            org: Some(org()),
        };
        let mut session = Session::default();
        let check = |s: &Session, tool: &str| s.check_call(&project, tool, &json!({}));

        // The project trusts the web; the org doesn't, so pages still taint.
        let page = json!({ "url": "https://evil.example/" });
        session.observe_result(&project, "web__fetch", &page);
        assert!(session.context().contains("untrusted"));
        let d = check(&session, "shell__exec");
        assert_eq!((d.action, d.rule, d.org), (Action::Deny, Some(1), true));
        assert_eq!(
            d.message("shell__exec"),
            "aegis blocked this call to shell__exec (org rule #1) because this session has read data labelled untrusted: org: no shell after the web"
        );
        assert_eq!(check(&session, "github__delete_file").action, Action::Deny);
        assert_eq!(check(&session, "github__push_files").action, Action::Ask);

        // The project can add labels and rules of its own.
        session.observe_result(&project, "mail__read", &json!({}));
        assert!(session.context().contains("mail"));
        let d = check(&session, "files__write");
        assert_eq!((d.action, d.rule, d.org), (Action::Deny, Some(3), false));
        // Allowed by both: the project's rule is reported.
        let d = check(&Session::default(), "shell__exec");
        assert_eq!((d.action, d.rule, d.org), (Action::Allow, Some(1), false));
    }

    /// Whatever a project policy says, no call is decided more loosely than
    /// the org policy alone would decide it, and no output carries fewer
    /// labels.
    #[test]
    fn a_project_policy_never_loosens_the_org_policy() {
        use serde_json::json;
        // The org's sources and rules under a project that adds nothing.
        let alone = Policy {
            sources: vec![],
            rules: vec![],
            default: Action::Allow,
            default_labels: vec![],
            org: Some(org()),
        };
        let tools = [
            "shell__exec",
            "web__fetch",
            "github__delete_file",
            "github__push_files",
            "files__read",
        ];
        let args = [
            json!({}),
            json!({ "url": "https://docs.rs/x" }),
            json!({ "url": "https://evil.example/" }),
        ];
        let actions = [Action::Allow, Action::Ask, Action::Deny];
        let labelings: [&[&str]; 3] = [&[], &["untrusted"], &["other"]];
        let contexts: Vec<LabelSet> = vec![
            LabelSet::new(),
            ["untrusted".to_string()].into(),
            ["other".to_string()].into(),
        ];
        for &tool_pattern in &["*", "shell__*", "web__fetch", "github__*"] {
            for &action in &actions {
                for labels in labelings {
                    for &default in &actions {
                        let project = Policy {
                            sources: vec![Source::new(tool_pattern, labels)],
                            rules: vec![Rule::new(tool_pattern, action)],
                            default,
                            default_labels: vec![],
                            org: Some(org()),
                        };
                        for tool in tools {
                            for a in &args {
                                let layered = project.labels_for_result(tool, a);
                                assert!(layered.is_superset(&alone.labels_for_result(tool, a)));
                                for context in &contexts {
                                    let layered = project.decide(tool, a, context).action;
                                    let floor = alone.decide(tool, a, context).action;
                                    assert!(
                                        layered.strictness() >= floor.strictness(),
                                        "{tool} {a} {context:?}: {layered:?} < {floor:?}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
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
            session
                .check_call(&policy, "shell__exec", &Value::Null)
                .action,
            Action::Allow
        );

        let added = session.observe_result(&policy, "web__fetch", &serde_json::Value::Null);
        assert!(added.contains("untrusted"));

        let d = session.check_call(&policy, "shell__exec", &Value::Null);
        assert_eq!(d.action, Action::Deny);
        assert_eq!(d.rule, Some(1));
        assert_eq!(d.matched_labels, vec!["untrusted".to_string()]);

        // Other tools are unaffected.
        assert_eq!(
            session
                .check_call(&policy, "files__read", &Value::Null)
                .action,
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
            session
                .check_call(&policy, "shell__exec", &Value::Null)
                .action,
            Action::Deny
        );
    }

    #[test]
    fn unconditional_rule_and_default() {
        let mut policy = policy();
        let session = Session::default();
        assert_eq!(
            session.check_call(&policy, "danger__rm", &Value::Null).rule,
            Some(2)
        );
        policy.default = Action::Deny;
        let d = session.check_call(&policy, "files__read", &Value::Null);
        assert_eq!((d.action, d.rule), (Action::Deny, None));
    }
}
