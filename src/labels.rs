//! Provenance labels and the wildcard matching used to attach them.

use std::collections::BTreeSet;

/// A set of provenance labels, e.g. `{"untrusted", "web"}`.
///
/// Ordered so audit logs and error messages are deterministic.
pub type LabelSet = BTreeSet<String>;

/// Matches `name` against a pattern where `*` matches any run of characters
/// (including none). All other characters match literally.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0, 0);
    // Position of the last `*` seen and the name index it was tried at, for backtracking.
    let mut star: Option<(usize, usize)> = None;

    while ni < n.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
        } else if pi < p.len() && p[pi] == n[ni] {
            pi += 1;
            ni += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == '*')
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn literal_and_wildcards() {
        assert!(glob_match("shell__exec", "shell__exec"));
        assert!(!glob_match("shell__exec", "shell__exec2"));
        assert!(glob_match("shell__*", "shell__exec"));
        assert!(glob_match("*", ""));
        assert!(glob_match("*__fetch*", "web__fetch_url"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxbyy"));
        assert!(!glob_match("git__*", "github__push"));
    }
}
