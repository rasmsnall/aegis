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

![The website's playground replaying a prompt injection: the hidden instruction reaches the agent, and aegis blocks the shell command and holds the push for a person](https://raw.githubusercontent.com/rasmsnall/aegis/main/docs/playground.gif)

Try it at https://rasmsnall.github.io/aegis/#playground, or read
[the write-up](docs/writeup.md) on why this approach works.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/rasmsnall/aegis/main/install.sh | sh
```

installs a prebuilt binary (Linux x86_64/arm64, static; macOS Intel/Apple
silicon) to `~/.local/bin`, after checking its SHA-256. Windows binaries are
on the [releases page](https://github.com/rasmsnall/aegis/releases). Or
build it: `cargo install mcp-aegis`.

## Usage

```sh
aegis init   --from .mcp.json              # starting config from your agent's MCP servers
aegis check  -c aegis.toml                 # validate config (offline)
aegis tools  -c aegis.toml                 # list tools with their labels and rules
aegis run    -c aegis.toml                 # serve MCP on stdio
aegis watch  aegis-audit.jsonl             # follow calls and decisions live
aegis verify aegis-audit.jsonl             # check the log's chain and signatures
aegis replay aegis-audit.jsonl -c new.toml # what would new.toml decide differently?
aegis report aegis-audit.jsonl             # the log as an HTML page
```

`aegis init` reads your agent's MCP config (Claude Code's `.mcp.json`,
`~/.claude.json`, Claude Desktop or Cursor; anything with an `mcpServers`
object), starts each server briefly to see its tools, and writes an
`aegis.toml` with a commented starting policy: web servers untrusted except
well-known documentation hosts, file servers trusted and tracked across
sessions, shell servers blocked once untrusted data is in play, and pushes,
merges and deletes asking a person. It then prints the one entry that
replaces your servers in the agent's config, or with `--replace` rewrites the
config for you and keeps the original as `<file>.aegis-backup`. Remote
servers (`"type": "http"`) are fronted too; only servers on the old SSE
transport are left in place.

Configure your agent to launch `aegis run -c aegis.toml` as its only MCP
server. Run `aegis tools` after changing the config: it starts the servers,
shows what each tool's output is labelled and which rules apply, and warns
about sources or rules that match no tool (usually a typo). With `--strict`
it exits 1 on warnings. `aegis replay` exits with status 2 when decisions
change, so both can gate policy changes in CI (see
[the GitHub Action](#policy-changes-in-pull-requests)).

`aegis watch` follows the audit log while the agent works: each call as it
happens, allowed or blocked and why, and the labels each result adds. It
flags entries that don't follow on from the one before.

## Configuration

See [`examples/aegis.toml`](examples/aegis.toml).

```toml
[[server]]                 # upstream MCP servers, launched over stdio...
name = "web"
command = "uvx"
args = ["mcp-server-fetch"]

[[server]]                 # ...or reached over HTTP
name = "linear"
url = "https://mcp.linear.app/mcp"
headers = { Authorization = "Bearer ${LINEAR_TOKEN}" }   # read from the environment

[[source]]                 # labels attached to tool output
tool = "web__*"
labels = ["untrusted"]

[[source]]                 # labels = [] marks output as trusted
tool = "files__*"
labels = []
```

Sources are checked in order and the first one that matches decides. A source
can depend on the call's arguments, so specific trust goes before general
distrust:

```toml
[[source]]                 # pages from these hosts are trusted
tool = "web__fetch"
labels = []
hosts = ["docs.rs", "*.rust-lang.org"]   # host of the `url` argument

[[source]]                 # every other page is not
tool = "web__*"
labels = ["untrusted"]

[[rule]]                   # first matching rule decides; else [policy].default
tool = "shell__*"
when_context_has = ["untrusted"]
action = "deny"             # or "allow", or "ask" a person
reason = "shell commands are disabled once untrusted content is in context"
```

Conditions a source can have (all must hold):

- `hosts`: the URL in the `url` argument (or `url_arg`) is on one of these
  hosts. `*.rust-lang.org` means its subdomains. URLs are parsed, not pattern
  matched, so `https://docs.rs@evil.com/` and `https://docs.rs.evil.com/` are
  not docs.rs, and only `http` and `https` URLs count.
- `paths`: the path in the `path` argument (or `path_arg`), normalized,
  matches one of these patterns. `*` also matches across `/`, so `src/*`
  covers everything under `src/`, and `src/../.env` is not under it.
- `args`: each named argument (`a.b` for nested) is a string matching one of
  its patterns, e.g. `args = { owner = ["rasmsnall"] }`.

If a condition can't be checked (the argument is missing, or isn't a web
URL) the source doesn't match, and the next one decides, down to
`default_labels`.

### Remote servers

A server with `url` instead of `command` is reached over MCP's Streamable
HTTP transport: answers come back as JSON or as an event stream, and the
session id and protocol version the server hands out are sent back on every
request. `${VAR}` in `headers` is replaced by the environment variable, and
a missing variable stops aegis rather than sending an empty token. Remote
tools are labelled and checked like any others.

### Resources and prompts

Servers' resources and prompts pass through aegis too, under the same
policy. Reading a resource from server `web` is checked and labelled as the
call `web__resources/read` with arguments `{"uri": ...}`, and getting a
prompt as `web__prompts/get` with `{"name": ..., "arguments": ...}`. So
`tool = "web__*"` covers them, and `url_arg = "uri"` lets a source trust
resources by host. `aegis tools` lists both entries for servers that have
them.

### Sandboxing servers

The policy decides which calls run. A sandbox limits what a server can do
once it runs, so a compromised server can't read your SSH keys or send them
anywhere:

```toml
[[server]]
name = "files"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "/home/me/project"]

[server.sandbox]
read = ["/home/me/.npm"]              # read-only
write = ["/home/me/project", "/tmp"]  # read-write
connect_ports = [443]                 # outgoing TCP allowed only to these ports
# network = true                      # allow all TCP instead
# system = false                      # don't add /usr, /etc, /proc, ... read-only
```

On Linux this uses Landlock (kernel 5.13+, network rules 6.7+), which needs
no root and also covers everything the server starts. Paths not listed
can't be read or written at all, and the server can't listen for
connections. Where Landlock isn't available, or on other systems, a server
with a sandbox refuses to start rather than run unconfined.

### Asking a person

`action = "ask"` pauses the call and asks the person using the agent, through
the MCP client's elicitation support (the host shows an approval prompt). The
model never sees the prompt and cannot answer it. The prompt shows the call
with secrets redacted and the rule that asked. If the client can't show
prompts, or nobody answers within `[approval].timeout_secs` (default 300), the
call is denied. Either way the answer is recorded in the audit log.

### Labels that outlive a session

Session labels are gone once aegis restarts. That leaves a gap: a session that
read untrusted data could write it into a file, and a later, clean session
could read the file back through a trusted tool. `[[resource]]` entries close
it:

```toml
[[resource]]
write = "files__write_file"  # tools that write the resource
read = "files__read_file"    # tools that read it
key = "path"                 # the argument naming it (a.b for nested)
```

A write that runs while the session holds labels stores them against that
path in `[state].path` (default `aegis-state.json`). Any later read of the path
brings them back, so the shell stays blocked in the next session too. Paths are
compared after normalization (`src/./x/../a` is `src/a`); use `kind = "exact"`
for identifiers that aren't paths. Symlinks, hard links and case-insensitive
filesystems can still give one file two names, and writes through tools not
listed (a shell, say) aren't seen, so keep those behind a rule as well.

Server names may contain only letters, digits and `-`, so the first `__` in an
exposed tool name always ends the server name. Each server takes
`startup_timeout_secs` (default 30) and `call_timeout_secs` (default 300); a
server that doesn't answer in time fails that request instead of hanging the
agent, and one that can't list its tools is left out of the listing.
`[limits].max_message_bytes` (default 16 MiB) caps every message: an oversized
message from the agent gets an error, and a server that sends one is
disconnected.

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

Tool arguments are logged according to `[audit].arguments`. The default,
`redacted`, replaces values whose argument names look like secrets (`token`,
`password`, `api_key`, `Authorization`, ...) or whose values look like
credentials (`Bearer ...`, `ghp_...`, `sk-...`, private keys) with
`"[redacted]"`. Add names with `redact_keys`. `hash` keeps only a SHA-256 of
the arguments, `omit` drops them, and `full` keeps them as sent.

`aegis report` turns a log into a self-contained HTML page: whether it
verifies, then per session what ran, what was blocked or approved and why,
and the entry from which the session held labelled data. Everything from the
log is escaped, so text an attacker planted in a tool's output shows up as
text.

## Policy changes in pull requests

`action.yml` is a GitHub Action that replays recorded sessions against the
policy in a pull request and comments with every call it would decide
differently, so reviewers see what a rule change does to real traffic:

```yaml
on:
  pull_request:
    paths: [aegis.toml, audit/*.jsonl]
permissions:
  contents: read
  pull-requests: write
jobs:
  replay:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: rasmsnall/aegis@v0.4.0
        with:
          config: aegis.toml
          logs: audit/*.jsonl       # logs you've committed as test cases
          # fail-on-change: true
```

It installs aegis, runs `aegis check`, replays each log with
`aegis replay --markdown`, writes the result to the job summary and keeps
one pull request comment up to date. Outputs: `changed` and `report`. This
repository runs it on [`examples/session.jsonl`](examples/session.jsonl).

## Semantics and limits

- **Session-level taint.** Labels apply to the whole session, not to
  individual values. This is coarse but sound: aegis can't see what the model
  does with the text it reads, so it assumes everything it read can influence
  everything it does next.
- **Concurrent calls.** A call is checked against the labels present when it
  arrives. A call sent before an earlier call's result came back can't have
  been influenced by that result, so that result doesn't block it.
- **Across sessions, labels follow declared resources.** Files written through
  the tools in `[[resource]]` keep their labels; writes by other means (a
  shell, another program) are invisible to aegis.
- **Replay** recomputes labels from the log. A call the recording blocked but
  the new policy allows is assumed to have returned output, and a call the new
  policy would `ask` about is assumed approved (which can only add taint).
- **Not yet supported:** server-to-client requests from upstream servers
  (their sampling and elicitation requests are refused), resource
  subscriptions, the old SSE transport, and sandboxing outside Linux.

## Website

`site/` is a TypeScript/React (Vite) site. Its playground decides calls with
aegis's own policy engine (`src/policy.rs`), compiled to WebAssembly by
`npm run wasm`, so what you see there is what the proxy does. Building it needs
Rust with the `wasm32-unknown-unknown` target
(`rustup target add wasm32-unknown-unknown`); then run
`cd site && npm install && npm run dev`.

The site is published at https://rasmsnall.github.io/aegis/. Every push to
`main` that touches it rebuilds the `gh-pages` branch, which GitHub Pages
serves.

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
