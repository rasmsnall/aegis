import { useState } from "react";

import { Playground } from "./Playground.tsx";

const REPO = "https://github.com/rasmsnall/aegis";
const INSTALL = "cargo install mcp-aegis";

const CONFIG = `[[server]]
name = "web"
command = "uvx"
args = ["mcp-server-fetch"]

[[source]]            # label tool output by where it came from
tool = "web__*"
labels = ["untrusted"]

[[rule]]              # first matching rule decides
tool = "shell__*"
when_context_has = ["untrusted"]
action = "deny"
reason = "no shell once untrusted content is in context"`;

const CLI = `aegis check  -c aegis.toml                  # validate config
aegis run    -c aegis.toml                  # serve MCP on stdio
aegis verify aegis-audit.jsonl              # check the log's hash chain
aegis replay aegis-audit.jsonl -c new.toml  # what would change?`;

const STEPS = [
  ["Label", "Every tool result is labelled by where it came from. Web pages and issue bodies are untrusted."],
  ["Track", "Labels stay on the session. Once the agent has read untrusted text, it stays marked."],
  ["Enforce", "Each tool call is checked against rules. The model gets a clear error when one is blocked."],
  ["Record", "Every call and decision goes into a hash-chained audit log you can verify and replay."],
];

function CopyCommand({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="install"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      <code>$ {text}</code>
      <span className="muted small">{copied ? "copied" : "copy"}</span>
    </button>
  );
}

export function App() {
  return (
    <>
      <header className="nav wrap">
        <a className="logo" href="#">
          <svg viewBox="0 0 32 32" width="22" height="22" aria-hidden>
            <path d="M16 2 4 7v8c0 7.5 5.1 13.2 12 15 6.9-1.8 12-7.5 12-15V7z" fill="currentColor" />
          </svg>
          aegis
        </a>
        <nav>
          <a href="#how">How it works</a>
          <a href="#playground">Playground</a>
          <a href="#start">Get started</a>
          <a href={REPO}>GitHub</a>
        </nav>
      </header>

      <main>
        <section className="hero wrap">
          <p className="eyebrow">An information-flow firewall for AI agents</p>
          <h1>Your agent read a web page. Should it still be allowed to run shell commands?</h1>
          <p className="lede">
            aegis sits between an agent and its MCP servers. It tracks where every piece of data came from,
            and blocks tool calls your policy forbids given what the agent has already read. Prompt
            injection can't talk its way past a rule that never asks the model.
          </p>
          <div className="hero-actions">
            <CopyCommand text={INSTALL} />
            <a className="btn btn-primary" href="#playground">
              Try the playground
            </a>
          </div>
        </section>

        <section id="how" className="wrap">
          <h2>How it works</h2>
          <div className="diagram" aria-label="Agent connects to aegis, which fronts web, github and shell servers">
            <span className="node">agent</span>
            <span className="arrow">→</span>
            <span className="node node-accent">aegis</span>
            <span className="arrow">→</span>
            <span className="stack">
              <span className="node">web__*</span>
              <span className="node">github__*</span>
              <span className="node">shell__*</span>
            </span>
          </div>
          <ol className="steps">
            {STEPS.map(([title, body], i) => (
              <li key={title}>
                <span className="step-num">{i + 1}</span>
                <h3>{title}</h3>
                <p className="muted">{body}</p>
              </li>
            ))}
          </ol>
        </section>

        <section id="playground" className="wrap">
          <h2>Playground</h2>
          <p className="muted">
            This runs the same rules as the real aegis, in your browser. Turn aegis off to see what happens
            without it.
          </p>
          <Playground />
        </section>

        <section id="start" className="wrap">
          <h2>Get started</h2>
          <div className="code-grid">
            <div>
              <h3>aegis.toml</h3>
              <pre>
                <code>{CONFIG}</code>
              </pre>
            </div>
            <div>
              <h3>Commands</h3>
              <pre>
                <code>{CLI}</code>
              </pre>
              <p className="muted small">
                Point your agent at <code>aegis run</code> as its only MCP server. Tools appear as{" "}
                <code>&lt;server&gt;__&lt;tool&gt;</code>, so one session covers every server.
              </p>
            </div>
          </div>
        </section>
      </main>

      <footer className="wrap muted small">
        aegis is open source under MIT or Apache-2.0. <a href={REPO}>Source on GitHub</a>.
      </footer>
    </>
  );
}
