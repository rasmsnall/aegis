# Changelog

## 0.3.0

- **`aegis init`** writes a starting `aegis.toml` from an agent's MCP config
  (Claude Code, Claude Desktop, Cursor). It starts each server briefly to see
  its tools, classifies servers by name, tools and command, writes a
  commented policy, and prints the entry that puts aegis in front of them, or
  rewrites the agent's config with `--replace` (keeping a backup).
- **`aegis report`** renders an audit log as a self-contained HTML page:
  verification status, per-session summary, the first moment the session
  held labelled data, and every call with its decision and reason.
- JSON objects keep their order, so `--replace` leaves the rest of the
  agent's config as it was.

## 0.2.0

- **Trust by host, path or argument.** A `[[source]]` can depend on the
  call's arguments: `hosts` (the host of a URL argument, parsed properly, so
  lookalikes like `https://docs.rs@evil.com/` don't count), `paths`
  (normalized, so `src/../.env` is not under `src/*`) and `args` (patterns on
  any string argument). Trusting documentation sites no longer means trusting
  the whole web.
- **Sources are now first-match**, like rules: the first source that matches
  a call decides its labels. Previously the labels of every matching source
  were combined. Put specific sources (trusted hosts) before general ones.
- `aegis tools` shows argument-dependent labels, and `aegis replay` checks
  them against the logged arguments (treating redacted, hashed or omitted
  arguments as not matching).
- The website's playground trusts docs.rs and the Rust docs, and has a
  "Read the Rust docs" call to show it.

## 0.1.0

First release of aegis, an information-flow firewall for AI agent tool calls.

- **Proxy:** one MCP server in front of all of an agent's servers, with tools
  exposed as `<server>__<tool>` so a single session context covers them all.
- **Labels and rules:** tool output is labelled by source (unlisted tools are
  untrusted by default), labels stay on the session, and every call is
  checked against first-match rules that `allow`, `deny` or `ask` a person.
- **Asking a person:** `ask` rules show an approval prompt through the MCP
  client's elicitation support; the model can't see or answer it.
- **Labels across sessions:** `[[resource]]` entries remember files written
  while untrusted data was in play and bring the label back when they are
  read later.
- **Audit log:** every call, result and decision, chained and optionally
  signed with HMAC-SHA256; secrets in arguments are redacted by default.
  `aegis verify` checks it and `aegis replay` shows what a new policy would
  decide differently.
- **Robustness:** startup and call timeouts, message size limits, and a
  failing server is left out instead of breaking the rest.
- **CLI:** `aegis run`, `check`, `tools`, `verify` and `replay`.
