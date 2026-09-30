//! Audit log.
//!
//! Each line is a JSON [`Entry`] chained to the one before it: its `hash`
//! covers the previous entry's hash and this entry's contents. Editing,
//! dropping or reordering entries in the middle breaks the chain.
//!
//! A plain SHA-256 chain only catches accidental damage: anyone who can write
//! the file can rewrite it and recompute every hash. With an audit key, each
//! hash is an HMAC-SHA256 under that key, so rewriting the log requires the
//! key. aegis also closes every session with a signed `session_end` entry, so
//! a log whose tail was cut off shows up as an unfinished session.
//!
//! The key only helps while the agent's tools cannot read it: aegis strips
//! `AEGIS_AUDIT_KEY` from the environment of the servers it launches, but a
//! key file readable by those servers (same user, same filesystem) gives no
//! protection.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::policy::Decision;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Environment variable holding the audit key (alternative to a key file).
pub const KEY_ENV: &str = "AEGIS_AUDIT_KEY";

/// How tool call arguments are written to the log.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArgumentLogging {
    /// As sent.
    Full,
    /// With values that look like secrets replaced by `"[redacted]"`.
    #[default]
    Redacted,
    /// Only a SHA-256 of the arguments, enough to tell calls apart.
    Hash,
    /// Not at all.
    Omit,
}

/// Argument names redacted wherever they appear (matched case-insensitively,
/// as substrings: `github_token` and `X-Api-Key` both match).
const SECRET_KEYS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "api_key",
    "apikey",
    "api-key",
    "authorization",
    "cookie",
    "credential",
    "private_key",
    "privatekey",
    "signature",
];

/// Value prefixes of well-known credential formats.
const SECRET_PREFIXES: &[&str] = &[
    "Bearer ",
    "Basic ",
    "ghp_",
    "gho_",
    "ghs_",
    "github_pat_",
    "sk-",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "-----BEGIN",
];

/// Renders `arguments` for the log according to `mode`.
pub fn log_arguments(
    mode: ArgumentLogging,
    arguments: &serde_json::Value,
    extra_keys: &[String],
) -> serde_json::Value {
    use serde_json::Value;
    fn redact(v: &Value, extra: &[String]) -> Value {
        match v {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, v)| {
                        let lower = k.to_ascii_lowercase();
                        let secret = SECRET_KEYS.iter().any(|s| lower.contains(s))
                            || extra.iter().any(|e| e.eq_ignore_ascii_case(k));
                        let v = if secret {
                            Value::String("[redacted]".into())
                        } else {
                            redact(v, extra)
                        };
                        (k.clone(), v)
                    })
                    .collect(),
            ),
            Value::Array(items) => Value::Array(items.iter().map(|v| redact(v, extra)).collect()),
            Value::String(s) if SECRET_PREFIXES.iter().any(|p| s.starts_with(p)) => {
                Value::String("[redacted]".into())
            }
            other => other.clone(),
        }
    }
    match mode {
        ArgumentLogging::Full => arguments.clone(),
        ArgumentLogging::Redacted => redact(arguments, extra_keys),
        ArgumentLogging::Hash => {
            let digest = Sha256::digest(arguments.to_string().as_bytes());
            serde_json::json!({ "sha256": hex::encode(digest) })
        }
        ArgumentLogging::Omit => Value::Null,
    }
}

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
        /// Labels recalled for the resource the tool read (a file written
        /// while an earlier session held those labels).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        recalled: Vec<String>,
    },
    /// aegis shut down cleanly.
    SessionEnd,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    /// Milliseconds since the Unix epoch.
    pub ts: u64,
    #[serde(flatten)]
    pub event: Event,
    pub prev: String,
    /// Whether `hash` is an HMAC under the audit key.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub signed: bool,
    pub hash: String,
}

/// Secret key for signing the audit log.
#[derive(Clone)]
pub struct AuditKey(Vec<u8>);

impl AuditKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        if bytes.len() < 16 {
            bail!("audit key must be at least 16 bytes");
        }
        Ok(Self(bytes))
    }

    /// Reads a key from `key_file` if given, else from `AEGIS_AUDIT_KEY`.
    /// Surrounding whitespace is ignored.
    pub fn load(key_file: Option<&Path>) -> Result<Option<Self>> {
        let raw = match key_file {
            Some(path) => std::fs::read(path)
                .with_context(|| format!("reading audit key {}", path.display()))?,
            None => match std::env::var(KEY_ENV) {
                Ok(v) => v.into_bytes(),
                Err(_) => return Ok(None),
            },
        };
        let text = String::from_utf8_lossy(&raw);
        Self::new(text.trim().as_bytes().to_vec()).map(Some)
    }
}

fn entry_hash(
    key: Option<&AuditKey>,
    prev: &str,
    seq: u64,
    ts: u64,
    event: &Event,
) -> Result<String> {
    // Hash the entry as it is serialized, minus the `hash` field itself.
    let body = serde_json::to_string(&(seq, ts, event, prev))?;
    Ok(match key {
        Some(key) => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&key.0).expect("HMAC takes any key length");
            mac.update(prev.as_bytes());
            mac.update(body.as_bytes());
            hex::encode(mac.finalize().into_bytes())
        }
        None => {
            let mut h = Sha256::new();
            h.update(prev.as_bytes());
            h.update(body.as_bytes());
            hex::encode(h.finalize())
        }
    })
}

pub struct AuditLog {
    file: File,
    seq: u64,
    prev: String,
    key: Option<AuditKey>,
}

impl AuditLog {
    /// Opens `path` for appending, continuing the chain of any entries already
    /// in it. An existing log must verify under the same key.
    pub fn open(path: &Path, key: Option<AuditKey>) -> Result<Self> {
        let (seq, prev) = if path.exists() {
            let entries = read(path)?;
            verify(&entries, key.as_ref()).with_context(|| {
                format!("existing audit log {} does not verify", path.display())
            })?;
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
        Ok(Self {
            file,
            seq,
            prev,
            key,
        })
    }

    pub fn record(&mut self, event: Event) -> Result<()> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let hash = entry_hash(self.key.as_ref(), &self.prev, self.seq, ts, &event)?;
        let entry = Entry {
            seq: self.seq,
            ts,
            event,
            prev: self.prev.clone(),
            signed: self.key.is_some(),
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

/// What a successful verification found.
#[derive(Debug, Default, PartialEq)]
pub struct Verified {
    pub entries: usize,
    pub signed: bool,
    pub sessions: usize,
    /// Sequence numbers of `session_start` entries with no matching
    /// `session_end`: aegis is still running, crashed, or the log was cut
    /// short after that point.
    pub unfinished: Vec<u64>,
}

/// Checks the chain. With a key, every entry must be signed under it; without
/// one, a signed log is rejected rather than half-checked. Returns an error
/// naming the first bad entry.
pub fn verify(entries: &[Entry], key: Option<&AuditKey>) -> Result<Verified> {
    let mut report = Verified {
        entries: entries.len(),
        signed: key.is_some(),
        ..Verified::default()
    };
    let mut open_session: Option<u64> = None;
    let mut prev = GENESIS.to_string();
    for (i, e) in entries.iter().enumerate() {
        if e.seq != i as u64 {
            bail!(
                "entry {i}: sequence number is {} (entry missing or reordered)",
                e.seq
            );
        }
        match (key.is_some(), e.signed) {
            (true, false) => bail!(
                "entry {i}: not signed, but the log is expected to be (entry forged or log replaced)"
            ),
            (false, true) => bail!("entry {i}: signed; pass the audit key to verify it"),
            _ => {}
        }
        if e.prev != prev {
            bail!("entry {i}: does not follow the previous entry");
        }
        if entry_hash(key, &e.prev, e.seq, e.ts, &e.event)? != e.hash {
            bail!(
                "entry {i}: contents do not match its hash (entry was modified, or the key is wrong)"
            );
        }
        match e.event {
            Event::SessionStart { .. } => {
                report.unfinished.extend(open_session.replace(e.seq));
                report.sessions += 1;
            }
            Event::SessionEnd => open_session = None,
            _ => {}
        }
        prev = e.hash.clone();
    }
    report.unfinished.extend(open_session);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> AuditKey {
        AuditKey::new(*b"0123456789abcdef-test-key").unwrap()
    }

    fn write_session(path: &Path, key: Option<AuditKey>) {
        let mut log = AuditLog::open(path, key).unwrap();
        log.record(Event::SessionStart {
            servers: vec!["web".into()],
        })
        .unwrap();
        log.record(Event::ToolResult {
            tool: "web__fetch".into(),
            is_error: false,
            added: vec!["untrusted".into()],
            recalled: vec![],
        })
        .unwrap();
        log.record(Event::SessionEnd).unwrap();
    }

    /// Rewrites `entries` into a chain that verifies without a key, the way
    /// anyone with write access to the file could.
    fn forge(mut entries: Vec<Entry>) -> Vec<Entry> {
        let mut prev = GENESIS.to_string();
        for (i, e) in entries.iter_mut().enumerate() {
            e.seq = i as u64;
            e.prev = prev.clone();
            e.signed = false;
            e.hash = entry_hash(None, &e.prev, e.seq, e.ts, &e.event).unwrap();
            prev = e.hash.clone();
        }
        entries
    }

    #[test]
    fn chain_verifies_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_session(&path, None);
        write_session(&path, None); // reopening continues the chain
        let report = verify(&read(&path).unwrap(), None).unwrap();
        assert_eq!((report.entries, report.sessions), (6, 2));
        assert!(report.unfinished.is_empty());
    }

    #[test]
    fn detects_modification_and_gaps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_session(&path, None);

        let mut entries = read(&path).unwrap();
        if let Event::ToolResult { added, .. } = &mut entries[1].event {
            added.clear();
        }
        let err = verify(&entries, None).unwrap_err().to_string();
        assert!(err.contains("modified"), "{err}");

        let entries = read(&path).unwrap();
        assert!(verify(&entries[1..], None).is_err());
    }

    #[test]
    fn unsigned_chain_can_be_forged() {
        // Documents the limit of an unkeyed log.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_session(&path, None);
        let mut entries = read(&path).unwrap();
        entries.remove(1);
        verify(&forge(entries), None).unwrap();
    }

    #[test]
    fn signed_log_rejects_forgery_and_wrong_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_session(&path, Some(key()));
        let entries = read(&path).unwrap();
        assert!(entries.iter().all(|e| e.signed));
        verify(&entries, Some(&key())).unwrap();

        // A recomputed unkeyed chain is rejected.
        let mut forged = entries.clone();
        forged.remove(1);
        let err = verify(&forge(forged), Some(&key()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("not signed"), "{err}");

        // So is the wrong key, and verifying without any key.
        let other = AuditKey::new(*b"another-key-of-16-bytes").unwrap();
        assert!(verify(&entries, Some(&other)).is_err());
        assert!(
            verify(&entries, None)
                .unwrap_err()
                .to_string()
                .contains("pass the audit key")
        );

        // And an existing signed log cannot be reopened without its key.
        assert!(AuditLog::open(&path, None).is_err());
    }

    #[test]
    fn cut_off_tail_shows_as_unfinished_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        write_session(&path, Some(key()));
        write_session(&path, Some(key()));
        let entries = read(&path).unwrap();

        // Dropping the tail keeps the chain valid, but the last session no
        // longer has its signed end marker.
        let report = verify(&entries[..4], Some(&key())).unwrap();
        assert_eq!(report.unfinished, vec![3]);
        assert!(
            verify(&entries, Some(&key()))
                .unwrap()
                .unfinished
                .is_empty()
        );
    }

    #[test]
    fn redacts_secrets_in_arguments() {
        let args = serde_json::json!({
            "url": "https://example.com",
            "headers": { "Authorization": "x", "X-Api-Key": "y", "Accept": "text/html" },
            "github_token": "abc",
            "note": "ghp_0123456789",
            "items": [{ "password": "p" }, "Bearer abc"],
            "customer_id": "c-1",
            "author": "Ada",
        });
        let logged = log_arguments(ArgumentLogging::Redacted, &args, &["customer_id".into()]);
        assert_eq!(
            logged,
            serde_json::json!({
                "url": "https://example.com",
                "headers": { "Authorization": "[redacted]", "X-Api-Key": "[redacted]", "Accept": "text/html" },
                "github_token": "[redacted]",
                "note": "[redacted]",
                "items": [{ "password": "[redacted]" }, "[redacted]"],
                "customer_id": "[redacted]",
                "author": "Ada",
            })
        );
        assert_eq!(log_arguments(ArgumentLogging::Full, &args, &[]), args);
        assert_eq!(
            log_arguments(ArgumentLogging::Omit, &args, &[]),
            serde_json::Value::Null
        );
        let hashed = log_arguments(ArgumentLogging::Hash, &args, &[]);
        assert_eq!(hashed["sha256"].as_str().unwrap().len(), 64);
        assert!(!hashed.to_string().contains("abc"));
    }

    #[test]
    fn short_keys_are_rejected() {
        assert!(AuditKey::new(*b"short").is_err());
    }
}
