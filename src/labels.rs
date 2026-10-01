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

/// Resolves `.`, `..` and repeated separators without touching the disk.
pub fn normalize_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if matches!(parts.last(), Some(p) if *p != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            p => parts.push(p),
        }
    }
    let joined = parts.join("/");
    match (absolute, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

/// The host of an `http` or `https` URL, lowercased and without a trailing
/// dot. Parsed properly, so `https://docs.rs@evil.com/` has host `evil.com`.
/// Anything else (other schemes, relative URLs, junk) has no host.
pub fn url_host(value: &str) -> Option<String> {
    let url = url::Url::parse(value.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// `docs.rs` matches exactly that host; `*.rust-lang.org` matches any
/// subdomain of it (but not `rust-lang.org` itself).
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .strip_suffix(suffix)
            .is_some_and(|rest| rest.len() > 1 && rest.ends_with('.')),
        None => host == pattern,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn normalizes_paths() {
        for (input, want) in [
            ("src/./a/../login.tsx", "src/login.tsx"),
            ("src//login.tsx", "src/login.tsx"),
            ("./src/login.tsx", "src/login.tsx"),
            ("/a/../../etc/passwd", "/etc/passwd"),
            ("../x/../y", "../y"),
            ("src\\login.tsx", "src/login.tsx"),
            ("./", "."),
        ] {
            assert_eq!(normalize_path(input), want, "{input}");
        }
    }

    #[test]
    fn url_hosts_are_parsed_not_pattern_matched() {
        assert_eq!(
            url_host("https://docs.rs/serde").as_deref(),
            Some("docs.rs")
        );
        assert_eq!(url_host("HTTPS://Docs.RS./x").as_deref(), Some("docs.rs"));
        assert_eq!(
            url_host("https://docs.rs:443/x").as_deref(),
            Some("docs.rs")
        );
        // Lookalikes resolve to the host that is actually contacted.
        assert_eq!(
            url_host("https://docs.rs@evil.com/").as_deref(),
            Some("evil.com")
        );
        assert_eq!(
            url_host("https://docs.rs.evil.com/").as_deref(),
            Some("docs.rs.evil.com")
        );
        assert_eq!(
            url_host("https://evil.com/?u=https://docs.rs").as_deref(),
            Some("evil.com")
        );
        // No host: not a web URL at all.
        for bad in [
            "file:///etc/passwd",
            "docs.rs/serde",
            "javascript:alert(1)",
            "",
        ] {
            assert_eq!(url_host(bad), None, "{bad}");
        }
    }

    #[test]
    fn host_patterns() {
        assert!(host_matches("docs.rs", "docs.rs"));
        assert!(host_matches("DOCS.rs.", "docs.rs"));
        assert!(!host_matches("docs.rs", "docs.rs.evil.com"));
        assert!(!host_matches("docs.rs", "evildocs.rs"));
        assert!(host_matches("*.rust-lang.org", "doc.rust-lang.org"));
        assert!(host_matches("*.rust-lang.org", "a.b.rust-lang.org"));
        assert!(!host_matches("*.rust-lang.org", "rust-lang.org"));
        assert!(!host_matches("*.rust-lang.org", "evilrust-lang.org"));
    }
}
