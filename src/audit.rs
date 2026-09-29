//! Tamper-evident audit log.
//!
//! Each line is a JSON [`Entry`] whose `hash` is the SHA-256 of the previous
//! entry's hash concatenated with this entry's canonical JSON (without the
//! `hash` field). Editing, dropping or reordering any line breaks the chain,
//! which `aegis verify` detects.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::policy::Decision;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    SessionStart {
        servers: Vec<String>,
    },
    /// A tool call and the decision taken on it.
    ToolCall {
        tool: String,
        arguments: serde_json::Value,
        context: Vec<String>,
        decision: Decision,
    },
    /// A tool returned output; `added` are labels newly added to the context.
    ToolResult {
        tool: String,
        is_error: bool,
        added: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    /// Milliseconds since the Unix epoch.
    pub ts: u64,
    #[serde(flatten)]
    pub event: Event,
    pub prev: String,
    pub hash: String,
}

fn entry_hash(prev: &str, seq: u64, ts: u64, event: &Event) -> Result<String> {
    // Hash the entry as it is serialized, minus the `hash` field itself.
    let body = serde_json::to_string(&(seq, ts, event, prev))?;
    let mut h = Sha256::new();
    h.update(prev.as_bytes());
    h.update(body.as_bytes());
    Ok(hex::encode(h.finalize()))
}

pub struct AuditLog {
    file: File,
    seq: u64,
    prev: String,
}

impl AuditLog {
    /// Opens `path` for appending, continuing the hash chain of any entries
    /// already in it.
    pub fn open(path: &Path) -> Result<Self> {
        let (seq, prev) = if path.exists() {
            let entries = read(path)?;
            verify(&entries)?;
            entries
                .last()
                .map_or((0, GENESIS.to_string()), |e| (e.seq + 1, e.hash.clone()))
        } else {
            (0, GENESIS.to_string())
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening audit log {}", path.display()))?;
        Ok(Self { file, seq, prev })
    }

    pub fn record(&mut self, event: Event) -> Result<()> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let hash = entry_hash(&self.prev, self.seq, ts, &event)?;
        let entry = Entry {
            seq: self.seq,
            ts,
            event,
            prev: self.prev.clone(),
            hash,
        };
        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        self.seq += 1;
        self.prev = entry.hash;
        Ok(())
    }
}

pub fn read(path: &Path) -> Result<Vec<Entry>> {
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    BufReader::new(file)
        .lines()
        .enumerate()
        .filter(|(_, l)| l.as_ref().map_or(true, |l| !l.trim().is_empty()))
        .map(|(i, line)| {
            serde_json::from_str(&line?).with_context(|| format!("line {}: malformed entry", i + 1))
        })
        .collect()
}

/// Checks the hash chain. Returns an error naming the first bad entry.
pub fn verify(entries: &[Entry]) -> Result<()> {
    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 {
            bail!(
                "entry {i}: sequence number is {} (entry missing or reordered)",
                e.seq
            );
        }
        if e.prev != prev {
            bail!("entry {i}: does not follow the previous entry");
        }
        if entry_hash(&e.prev, e.seq, e.ts, &e.event)? != e.hash {
            bail!("entry {i}: contents do not match its hash (entry was modified)");
        }
        prev = e.hash.clone();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_log(path: &Path) {
        let mut log = AuditLog::open(path).unwrap();
        log.record(Event::SessionStart {
            servers: vec!["web".into()],
        })
        .unwrap();
        log.record(Event::ToolResult {
            tool: "web__fetch".into(),
            is_error: false,
            added: vec!["untrusted".into()],
        })
        .unwrap();
    }

    #[test]
    fn chain_verifies_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_log(&path);
        write_log(&path); // reopening continues the chain
        let entries = read(&path).unwrap();
        assert_eq!(entries.len(), 4);
        verify(&entries).unwrap();
    }

    #[test]
    fn detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_log(&path);

        let mut entries = read(&path).unwrap();
        if let Event::ToolResult { added, .. } = &mut entries[1].event {
            added.clear();
        }
        assert!(
            verify(&entries)
                .unwrap_err()
                .to_string()
                .contains("modified")
        );

        let entries = read(&path).unwrap();
        assert!(verify(&entries[1..]).is_err());
    }
}
