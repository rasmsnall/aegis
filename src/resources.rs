//! Labels that outlive a session.
//!
//! Session labels vanish when aegis restarts, which leaves a gap: a session
//! that has read untrusted data can write it to a file, and a later, clean
//! session can read that file through a trusted tool. `[[resource]]` entries
//! close it. They name the tools that write and read a kind of resource and
//! the argument that identifies it:
//!
//! ```toml
//! [[resource]]
//! write = "files__write_file"
//! read = "files__read_file"
//! key = "path"
//! ```
//!
//! When a write runs while the session holds labels, those labels are stored
//! against the resource in `[state].path`. When any later session reads that
//! resource, its output carries them again. Labels on a resource only
//! accumulate; delete the state file to reset them.
//!
//! Paths are compared after lexical normalization (`src/./a/../b` is `src/b`),
//! so trivial spellings cannot dodge the store. Symlinks, hard links and
//! case-insensitive filesystems can still give one file two names, and writes
//! made through tools not listed here (a shell, say) are not seen at all.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

use crate::labels::{LabelSet, glob_match};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyKind {
    /// Compare as filesystem paths, after lexical normalization.
    #[default]
    Path,
    /// Compare the argument value exactly.
    Exact,
}

/// Tools that write and read one kind of resource.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRule {
    /// Tool name pattern for calls that write the resource.
    pub write: String,
    /// Tool name pattern for calls that read it.
    pub read: String,
    /// Argument naming the resource; `a.b` looks inside nested objects.
    pub key: String,
    #[serde(default)]
    pub kind: KeyKind,
}

impl ResourceRule {
    fn resource_id(&self, arguments: &Value) -> Option<String> {
        let value = self
            .key
            .split('.')
            .try_fold(arguments, |v, part| v.get(part))?
            .as_str()?;
        Some(match self.kind {
            KeyKind::Path => normalize_path(value),
            KeyKind::Exact => value.to_string(),
        })
    }
}

pub use crate::labels::normalize_path;

/// Labels of resources written while a session held them, kept on disk.
pub struct ResourceStore {
    path: PathBuf,
    rules: Vec<ResourceRule>,
    labels: BTreeMap<String, BTreeSet<String>>,
}

impl ResourceStore {
    pub fn open(path: &Path, rules: Vec<ResourceRule>) -> Result<Self> {
        let labels = if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path: path.to_path_buf(),
            rules,
            labels,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Records that `tool` ran with `arguments` while the session held
    /// `context`. Saves the store if anything changed.
    pub fn on_write(&mut self, tool: &str, arguments: &Value, context: &LabelSet) -> Result<()> {
        if context.is_empty() {
            return Ok(());
        }
        let mut changed = false;
        for rule in self.rules.iter().filter(|r| glob_match(&r.write, tool)) {
            let Some(id) = rule.resource_id(arguments) else {
                eprintln!(
                    "aegis: {tool} matches a [[resource]] write rule but has no {:?} argument; the write is not tracked",
                    rule.key
                );
                continue;
            };
            let entry = self.labels.entry(id).or_default();
            for label in context {
                changed |= entry.insert(label.clone());
            }
        }
        if changed {
            self.save()?;
        }
        Ok(())
    }

    /// Labels stored for the resource that `tool` reads with `arguments`.
    pub fn on_read(&self, tool: &str, arguments: &Value) -> LabelSet {
        self.rules
            .iter()
            .filter(|r| glob_match(&r.read, tool))
            .filter_map(|r| self.labels.get(&r.resource_id(arguments)?))
            .flatten()
            .cloned()
            .collect()
    }

    fn save(&self) -> Result<()> {
        // Write a sibling file and rename it over the old one, so a crash
        // never leaves a half-written store.
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.labels)?)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("replacing {}", self.path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rules() -> Vec<ResourceRule> {
        vec![ResourceRule {
            write: "files__write*".into(),
            read: "files__read*".into(),
            key: "path".into(),
            kind: KeyKind::Path,
        }]
    }

    fn untrusted() -> LabelSet {
        ["untrusted".to_string()].into()
    }

    #[test]
    fn tainted_write_is_recalled_by_a_later_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        let mut store = ResourceStore::open(&path, rules()).unwrap();
        store
            .on_write(
                "files__write_file",
                &json!({ "path": "src/login.tsx" }),
                &untrusted(),
            )
            .unwrap();
        // A clean write adds nothing, and does not clear earlier labels.
        store
            .on_write(
                "files__write_file",
                &json!({ "path": "src/login.tsx" }),
                &LabelSet::new(),
            )
            .unwrap();

        // A new aegis process (a later session) reads the store back.
        let store = ResourceStore::open(&path, rules()).unwrap();
        let recalled = store.on_read(
            "files__read_file",
            &json!({ "path": "src/./x/../login.tsx" }),
        );
        assert_eq!(recalled, untrusted());
        assert!(
            store
                .on_read("files__read_file", &json!({ "path": "src/other.tsx" }))
                .is_empty()
        );
        assert!(
            store
                .on_read("web__fetch", &json!({ "path": "src/login.tsx" }))
                .is_empty()
        );
    }

    #[test]
    fn nested_keys_and_exact_ids() {
        let rule = ResourceRule {
            write: "db__put".into(),
            read: "db__get".into(),
            key: "record.id".into(),
            kind: KeyKind::Exact,
        };
        assert_eq!(
            rule.resource_id(&json!({ "record": { "id": "./a" } }))
                .as_deref(),
            Some("./a")
        );
        assert_eq!(rule.resource_id(&json!({ "record": {} })), None);
    }
}
