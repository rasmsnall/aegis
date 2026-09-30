//! Re-evaluates a recorded session under a different policy, to answer "what
//! would this policy have changed?" before rolling it out.

use std::collections::HashMap;

use crate::audit::{Entry, Event};
use crate::policy::{Action, Decision, Policy, Session};

#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    pub seq: u64,
    pub tool: String,
    pub recorded: Action,
    pub replayed: Decision,
}

#[derive(Debug, Default)]
pub struct Report {
    pub calls: usize,
    pub changes: Vec<Change>,
}

/// Replays `entries` against `policy`.
///
/// Labels depend only on which tools returned output (plus any labels
/// recalled from earlier sessions' files, which the log records), so taint can
/// be recomputed exactly, with two approximations: a call the recording did
/// not run but `policy` would is assumed to have returned output, and a call
/// the recording ran but `policy` would not has its result ignored. A call
/// `policy` would `ask` about is assumed to be approved, which can only add
/// taint, never hide it.
pub fn replay(entries: &[Entry], policy: &Policy) -> Report {
    let mut report = Report::default();
    let mut session = Session::default();
    // Results to ignore, per tool, because the replayed policy denied the call.
    let mut suppressed: HashMap<&str, usize> = HashMap::new();

    for entry in entries {
        match &entry.event {
            Event::SessionStart { .. } => {
                session = Session::default();
                suppressed.clear();
            }
            Event::ToolCall {
                tool,
                decision: recorded,
                ..
            } => {
                report.calls += 1;
                let replayed = session.check_call(policy, tool);
                let would_run = replayed.action != Action::Deny;
                match (recorded.runs(), would_run) {
                    (true, false) => {
                        *suppressed.entry(tool).or_default() += 1;
                    }
                    (false, true) => {
                        session.observe_result(policy, tool);
                    }
                    _ => {}
                }
                if recorded.action != replayed.action {
                    report.changes.push(Change {
                        seq: entry.seq,
                        tool: tool.clone(),
                        recorded: recorded.action,
                        replayed,
                    });
                }
            }
            Event::SessionEnd => {}
            Event::ToolResult { tool, recalled, .. } => {
                if let Some(n) = suppressed.get_mut(tool.as_str()).filter(|n| **n > 0) {
                    *n -= 1;
                } else {
                    session.observe_result(policy, tool);
                    session.add_labels(recalled.iter().cloned());
                }
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Rule, Source};

    fn entry(seq: u64, event: Event) -> Entry {
        Entry {
            seq,
            ts: 0,
            event,
            prev: String::new(),
            signed: false,
            hash: String::new(),
        }
    }

    fn call(seq: u64, tool: &str, action: Action) -> Entry {
        entry(
            seq,
            Event::ToolCall {
                tool: tool.into(),
                arguments: serde_json::Value::Null,
                context: vec![],
                decision: Decision {
                    action,
                    rule: None,
                    matched_labels: vec![],
                    reason: None,
                    approved: None,
                },
            },
        )
    }

    fn result(seq: u64, tool: &str) -> Entry {
        entry(
            seq,
            Event::ToolResult {
                tool: tool.into(),
                is_error: false,
                added: vec![],
                recalled: vec![],
            },
        )
    }

    #[test]
    fn stricter_policy_reports_newly_blocked_calls() {
        // Recorded under allow-everything.
        let log = vec![
            entry(0, Event::SessionStart { servers: vec![] }),
            call(1, "shell__exec", Action::Allow),
            result(2, "shell__exec"),
            call(3, "web__fetch", Action::Allow),
            result(4, "web__fetch"),
            call(5, "shell__exec", Action::Allow),
            result(6, "shell__exec"),
        ];
        let strict = Policy {
            sources: vec![Source {
                tool: "web__*".into(),
                labels: vec!["untrusted".into()],
            }],
            rules: vec![Rule {
                tool: "shell__*".into(),
                when_context_has: vec!["untrusted".into()],
                action: Action::Deny,
                reason: None,
            }],
            default: Action::Allow,
            default_labels: vec![],
        };
        let report = replay(&log, &strict);
        assert_eq!(report.calls, 3);
        assert_eq!(report.changes.len(), 1);
        assert_eq!(report.changes[0].seq, 5);
        assert_eq!(report.changes[0].replayed.action, Action::Deny);
    }

    #[test]
    fn looser_policy_assumes_unblocked_calls_return() {
        let log = vec![
            call(0, "web__fetch", Action::Deny),
            call(1, "shell__exec", Action::Allow),
        ];
        let policy = Policy {
            sources: vec![Source {
                tool: "web__*".into(),
                labels: vec!["untrusted".into()],
            }],
            rules: vec![Rule {
                tool: "shell__*".into(),
                when_context_has: vec!["untrusted".into()],
                action: Action::Deny,
                reason: None,
            }],
            default: Action::Allow,
            default_labels: vec![],
        };
        let report = replay(&log, &policy);
        // web__fetch is now allowed, so its output taints the later shell call.
        let tools: Vec<_> = report.changes.iter().map(|c| c.tool.as_str()).collect();
        assert_eq!(tools, ["web__fetch", "shell__exec"]);
    }
}
