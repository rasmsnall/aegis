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

use serde::{Deserialize, Serialize};

use crate::labels::{LabelSet, glob_match};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Deny,
}

/// Labels attached to the output of every tool matching `tool`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub tool: String,
    pub labels: Vec<String>,
}

/// A rule over tool calls. The first rule that matches a call decides it.
#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone)]
pub struct Policy {
    pub sources: Vec<Source>,
    pub rules: Vec<Rule>,
    pub default: Action,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub action: Action,
    /// 1-based index of the deciding rule; `None` means the default applied.
    pub rule: Option<usize>,
    /// Context labels that triggered the rule.
    pub matched_labels: Vec<String>,
    pub reason: Option<String>,
}

impl Policy {
    /// Labels carried by the output of `tool`.
    pub fn labels_for_result(&self, tool: &str) -> LabelSet {
        self.sources
            .iter()
            .filter(|s| glob_match(&s.tool, tool))
            .flat_map(|s| s.labels.iter().cloned())
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
            };
        }
        Decision {
            action: self.default,
            rule: None,
            matched_labels: Vec::new(),
            reason: None,
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
    pub fn observe_result(&mut self, policy: &Policy, tool: &str) -> LabelSet {
        policy
            .labels_for_result(tool)
            .into_iter()
            .filter(|l| self.context.insert(l.clone()))
            .collect()
    }

    pub fn check_call(&self, policy: &Policy, tool: &str) -> Decision {
        policy.decide(tool, &self.context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            sources: vec![Source {
                tool: "web__*".into(),
                labels: vec!["untrusted".into()],
            }],
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
        }
    }

    #[test]
    fn shell_allowed_until_untrusted_data_is_seen() {
        let policy = policy();
        let mut session = Session::default();

        assert_eq!(
            session.check_call(&policy, "shell__exec").action,
            Action::Allow
        );

        let added = session.observe_result(&policy, "web__fetch");
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
        session.observe_result(&policy, "web__fetch");
        assert!(session.observe_result(&policy, "web__fetch").is_empty());
        session.observe_result(&policy, "files__read");
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
