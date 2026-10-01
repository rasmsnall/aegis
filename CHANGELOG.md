# Changelog

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
