//! `aegis watch`: follows an audit log and prints each call as it happens.

use std::io::{IsTerminal, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

use crate::audit::{Entry, Event};
use crate::report::{format_time, verdict};

/// How often the log is checked for new entries.
const POLL: Duration = Duration::from_millis(250);

/// Terminal styling, or none when output isn't a terminal or `NO_COLOR` is set.
#[derive(Clone, Copy)]
pub struct Style {
    color: bool,
}

impl Style {
    pub fn detect() -> Self {
        Self {
            color: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        }
    }

    pub fn plain() -> Self {
        Self { color: false }
    }

    fn paint(self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}

/// Tracks the hash chain so a gap or edit shows up while watching.
#[derive(Default)]
pub struct Watcher {
    last_hash: Option<String>,
}

impl Watcher {
    /// The lines to print for one entry.
    pub fn render(&mut self, entry: &Entry, style: Style) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(last) = &self.last_hash
            && *last != entry.prev
        {
            out.push(style.paint(
                "1;31",
                &format!(
                    "!! entry #{} does not follow the previous one: the log was edited or cut",
                    entry.seq
                ),
            ));
        }
        self.last_hash = Some(entry.hash.clone());

        let time = format_time(entry.ts);
        let time = style.paint("2", time.get(11..).unwrap_or(&time));
        match &entry.event {
            Event::SessionStart { servers } => out.push(format!(
                "{time}  {} {}",
                style.paint("1", "── session started"),
                style.paint("2", &format!("({})", servers.join(", ")))
            )),
            Event::SessionEnd => {
                out.push(format!("{time}  {}", style.paint("1", "── session ended")))
            }
            Event::ToolCall {
                tool,
                context,
                decision,
                ..
            } => {
                let (word, kind) = verdict(decision);
                let mark = if kind == "ok" { "✓" } else { "✗" };
                let code = if kind == "ok" { "32" } else { "1;31" };
                let mut line = format!(
                    "{time}  {} {}",
                    style.paint(code, &format!("{mark} {word:<12}")),
                    style.paint("1", tool)
                );
                if kind != "ok" {
                    let rule = decision
                        .rule
                        .map_or("default".into(), |r| format!("rule #{r}"));
                    let why = if decision.matched_labels.is_empty() {
                        rule
                    } else {
                        format!("{rule}, context has {}", decision.matched_labels.join(", "))
                    };
                    line += &style.paint("2", &format!("  ({why})"));
                } else if !context.is_empty() {
                    line += &style.paint("2", &format!("  context: {}", context.join(", ")));
                }
                out.push(line);
            }
            Event::ToolResult {
                tool,
                is_error,
                added,
                recalled,
            } => {
                let mut notes = Vec::new();
                if *is_error {
                    notes.push(style.paint("33", "returned an error"));
                }
                if !added.is_empty() {
                    notes.push(style.paint("1;35", &format!("+{}", added.join(" +"))));
                }
                if !recalled.is_empty() {
                    notes.push(style.paint("35", &format!("recalled {}", recalled.join(", "))));
                }
                if !notes.is_empty() {
                    out.push(format!(
                        "{time}    {} {}  {}",
                        style.paint("2", "↳"),
                        style.paint("2", tool),
                        notes.join("  ")
                    ));
                }
            }
        }
        out
    }
}

/// Prints the last `backlog` entries of `path`, then follows it. Waits for
/// the file to appear, and starts over if it is replaced or truncated.
pub async fn follow(path: &Path, backlog: usize, style: Style) -> Result<()> {
    let mut announced = false;
    let mut file = loop {
        match std::fs::File::open(path) {
            Ok(file) => break file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !announced {
                    eprintln!("waiting for {} to appear...", path.display());
                    announced = true;
                }
                tokio::time::sleep(POLL).await;
            }
            Err(e) => return Err(e).with_context(|| format!("opening {}", path.display())),
        }
    };
    let mut watcher = Watcher::default();
    let mut pending = String::new();
    let mut offset = 0u64;
    let mut first = true;
    loop {
        let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if len < offset {
            // Rotated or truncated: read the new file from the start.
            println!("{}", style.paint("2", "── log was replaced; starting over"));
            file =
                std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
            offset = 0;
            pending.clear();
            watcher = Watcher::default();
        }
        if len > offset {
            file.seek(SeekFrom::Start(offset))?;
            let mut chunk = Vec::new();
            (&mut file).take(len - offset).read_to_end(&mut chunk)?;
            offset += chunk.len() as u64;
            pending.push_str(&String::from_utf8_lossy(&chunk));
            let complete = pending.rfind('\n').map_or(0, |i| i + 1);
            let lines: Vec<String> = pending[..complete].lines().map(str::to_string).collect();
            pending.drain(..complete);
            let skip = if first {
                lines.len().saturating_sub(backlog)
            } else {
                0
            };
            for (i, line) in lines.iter().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<Entry>(line) {
                    Ok(entry) => {
                        let rendered = watcher.render(&entry, style);
                        if i >= skip {
                            for l in rendered {
                                println!("{l}");
                            }
                        }
                    }
                    Err(e) => println!("{}", style.paint("33", &format!("unreadable entry: {e}"))),
                }
            }
        }
        first = false;
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;
    use crate::policy::{Action, Decision};

    fn decision(action: Action, rule: Option<usize>, labels: &[&str]) -> Decision {
        Decision {
            action,
            rule,
            matched_labels: labels.iter().map(|l| l.to_string()).collect(),
            reason: None,
            approved: None,
        }
    }

    #[test]
    fn renders_a_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        let mut log = AuditLog::open(&path, None).unwrap();
        log.record(Event::SessionStart {
            servers: vec!["web".into(), "shell".into()],
        })
        .unwrap();
        log.record(Event::ToolCall {
            tool: "web__fetch".into(),
            arguments: serde_json::Value::Null,
            context: vec![],
            decision: decision(Action::Allow, None, &[]),
        })
        .unwrap();
        log.record(Event::ToolResult {
            tool: "web__fetch".into(),
            is_error: false,
            added: vec!["untrusted".into()],
            recalled: vec![],
        })
        .unwrap();
        log.record(Event::ToolCall {
            tool: "shell__exec".into(),
            arguments: serde_json::Value::Null,
            context: vec!["untrusted".into()],
            decision: decision(Action::Deny, Some(1), &["untrusted"]),
        })
        .unwrap();
        drop(log);

        let mut watcher = Watcher::default();
        let lines: Vec<String> = crate::audit::read(&path)
            .unwrap()
            .iter()
            .flat_map(|e| watcher.render(e, Style::plain()))
            .map(|l| l[10..].to_string()) // drop the time
            .collect();
        assert_eq!(
            lines,
            [
                "── session started (web, shell)",
                "✓ allowed      web__fetch",
                "  ↳ web__fetch  +untrusted",
                "✗ blocked      shell__exec  (rule #1, context has untrusted)",
            ]
        );
    }

    #[test]
    fn flags_a_broken_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        let mut log = AuditLog::open(&path, None).unwrap();
        log.record(Event::SessionStart { servers: vec![] }).unwrap();
        log.record(Event::SessionEnd).unwrap();
        log.record(Event::SessionEnd).unwrap();
        drop(log);
        let mut entries = crate::audit::read(&path).unwrap();
        entries.remove(1);
        let mut watcher = Watcher::default();
        let lines: Vec<String> = entries
            .iter()
            .flat_map(|e| watcher.render(e, Style::plain()))
            .collect();
        assert!(lines[1].contains("does not follow"), "{lines:?}");
    }
}
