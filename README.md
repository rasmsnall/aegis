# aegis

**An information-flow firewall for AI agent tool calls.**

Prompt injection works because an agent reads untrusted text (a web page, an
issue body, an email) and then acts with real privileges (a shell, `git push`,
an HTTP POST). Most defenses try to *spot* malicious text, and attackers get
around them.

aegis tracks **where data came from** instead. It sits between the agent and
its MCP servers and:

1. **Labels** every tool result by source (`web__*` output → `untrusted`).
   Tools you haven't listed are untrusted by default.
2. **Tracks** those labels through the session. Once the agent has read
   untrusted data, the session stays labelled for the rest of the session.
3. **Enforces** rules on every tool call given what the session has read, for
   example "no `shell__*` once the context has `untrusted`". A blocked call
   returns a tool error that tells the model why.
4. **Records** every call, result and decision in an audit log that you can
   verify (signed, when you give it a key) and replay against a different
   policy.

The agent can't be talked out of a rule, because the rule doesn't depend on
anything the model says.

```
agent ──MCP──▶ aegis ──▶ web server     (tools exposed as web__fetch, ...)
                 │  ├──▶ github server  (github__push_files, ...)
                 │  └──▶ shell server   (shell__exec, ...)
                 └──▶ aegis-audit.jsonl
```

aegis combines all servers behind one endpoint, so a single session context
covers all of them. Data read through `web` can then block a call on `shell`.
That wouldn't work if each server had its own proxy.

## Usage

```sh
cargo install mcp-aegis                    # installs the `aegis` command
aegis check  -c aegis.toml                 # validate config (offline)
aegis tools  -c aegis.toml                 # list tools with their labels and rules
aegis run    -c aegis.toml                 # serve MCP on stdio
aegis verify aegis-audit.jsonl             # check the log's chain and signatures
aegis replay aegis-audit.jsonl -c new.toml # what would new.toml decide differently?
```

Configure your agent to launch `aegis run -c aegis.toml` as its only MCP
server. Run `aegis tools` after changing the config: it starts the servers,
shows what each tool's output is labelled and which rules apply, and warns
about sources or rules that match no tool (usually a typo). With `--strict`
it exits 1 on warnings. `aegis replay` exits with status 2 when decisions
change, so both can gate policy changes in CI.

## Configuration

See [`examples/aegis.toml`](examples/aegis.toml).

```toml
[[server]]                 # upstream MCP servers (stdio)
name = "web"
command = "uvx"
args = ["mcp-server-fetch"]

[[source]]                 # labels attached to tool output
tool = "web__*"
labels = ["untrusted"]

[[source]]                 # labels = [] marks output as trusted
tool = "files__*"
labels = []

[[rule]]                   # first matching rule decides; else [policy].default
tool = "shell__*"
when_context_has = ["untrusted"]
action = "deny"
reason = "shell commands are disabled once untrusted content is in context"
```

Server names may contain only letters, digits and `-`, so the first `__` in an
exposed tool name always ends the server name. Each server takes
`startup_timeout_secs` (default 30) and `call_timeout_secs` (default 300); a
server that doesn't answer in time fails that request instead of hanging the
agent, and one that can't list its tools is left out of the listing.

## Audit log

Every call, result and decision is appended to `[audit].path` as JSON lines,
each chained to the one before it. Without a key, that chain only catches
accidental damage: anyone who can write the file can rewrite it and
recompute the chain.

To make rewrites detectable, give aegis a key of at least 16 bytes, through
`[audit].key_file` or the `AEGIS_AUDIT_KEY` environment variable. Each entry
is then signed with HMAC-SHA256, and `aegis verify --key-file ...` rejects
edited, reordered or forged entries. Every session ends with a signed
`session_end` entry, so a log whose tail was cut off shows up as an
unfinished session. aegis doesn't pass `AEGIS_AUDIT_KEY` on to the servers it
launches, but a key file those servers can read (same user, same filesystem)
gives no protection. Deleting the whole log is still possible; ship it off
the machine if you need to rule that out.

## Semantics and limits

- **Session-level taint.** Labels apply to the whole session, not to
  individual values. This is coarse but sound: aegis can't see what the model
  does with the text it reads, so it assumes everything it read can influence
  everything it does next.
- **Concurrent calls.** A call is checked against the labels present when it
  arrives. A call sent before an earlier call's result came back can't have
  been influenced by that result, so that result doesn't block it.
- **Labels follow tools, not data.** If one session writes untrusted text to
  a file and a later session reads that file through a trusted tool, the
  second session doesn't know. Keep file-writing tools behind a rule, or
  label file reads untrusted.
- **Replay** recomputes labels from the log. A call the recording blocked but
  the new policy allows is assumed to have returned output.
- **Not yet supported:** resources and prompts (only tools are proxied),
  server-to-client requests (sampling and elicitation are refused), HTTP
  transport, human approval as a third action, labels based on arguments
  (e.g. trust by URL domain), and OS-level enforcement so tools can't
  get around the proxy.

## Website

`site/` is a TypeScript/React (Vite) site with an in-browser playground that
runs the same policy rules. Run it with `cd site && npm install && npm run dev`.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
