import { useState } from "react";

import { Playground } from "./Playground.tsx";
import { Steps } from "./Steps.tsx";
import { TickField } from "./TickField.tsx";

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

const CLI = `aegis check  -c aegis.toml
aegis run    -c aegis.toml
aegis verify aegis-audit.jsonl
aegis replay aegis-audit.jsonl -c new.toml`;

function Shield({ size = 22 }: { size?: number }) {
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} aria-hidden>
      <path d="M16 2 4 7v8c0 7.5 5.1 13.2 12 15 6.9-1.8 12-7.5 12-15V7z" fill="currentColor" />
    </svg>
  );
}

function InstallButton() {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="btn btn-white"
      onClick={() => {
        navigator.clipboard
          ?.writeText(INSTALL)
          .then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          })
          .catch(() => {
            // Clipboard refused: select the command so it can be copied by hand.
            const text = document.querySelector(".btn-white .mono");
            if (text) window.getSelection()?.selectAllChildren(text);
          });
      }}
    >
      <span className="mono">{copied ? "Copied" : INSTALL}</span>
    </button>
  );
}

export function App() {
  return (
    <>
      <header className="nav">
        <a className="logo" href="#top">
          <Shield />
          aegis
        </a>
        <nav>
          <a href="#how">How it works</a>
          <a href="#playground">Playground</a>
          <a href="#start">Get started</a>
        </nav>
        <a className="btn btn-blue nav-cta" href={REPO}>
          GitHub
        </a>
      </header>

      <main id="top">
        <section className="hero">
          <TickField />
          <div className="hero-content">
            <h1>Where agent security starts</h1>
            <p className="hero-sub">Label. Track. Enforce. Record. One firewall between your agent and its tools.</p>
            <div className="hero-actions">
              <a className="btn btn-blue" href="#playground">
                Try the playground
              </a>
              <InstallButton />
            </div>
          </div>
        </section>

        <section className="intro wrap">
          <p className="mono eyebrow">The problem</p>
          <p className="statement">
            Your agent read a web page. <span className="dim">Should it still be allowed to run shell commands?</span>{" "}
            aegis tracks where every piece of data came from and blocks the calls your policy forbids.{" "}
            <span className="dim">Prompt injection can't talk its way past a rule that never asks the model.</span>
          </p>
        </section>

        <section id="how" className="wrap">
          <Steps />
        </section>

        <section id="playground" className="wrap">
          <div className="section-head">
            <p className="mono eyebrow">Playground</p>
            <h2>Replay a prompt injection.</h2>
            <p className="dim">
              The same rules as the real aegis, running in your browser. Turn aegis off to see what happens without it.
            </p>
          </div>
          <Playground />
        </section>

        <section id="start" className="wrap">
          <div className="section-head">
            <p className="mono eyebrow">Get started</p>
            <h2>One config. One proxy.</h2>
            <p className="dim">
              Point your agent at <code>aegis run</code> as its only MCP server. Tools appear as{" "}
              <code>&lt;server&gt;__&lt;tool&gt;</code>, so one session covers every server.
            </p>
          </div>
          <div className="code-grid">
            <figure className="code">
              <figcaption className="mono">aegis.toml</figcaption>
              <pre>
                <code>{CONFIG}</code>
              </pre>
            </figure>
            <figure className="code">
              <figcaption className="mono">terminal</figcaption>
              <pre>
                <code>{CLI}</code>
              </pre>
            </figure>
          </div>
        </section>
      </main>

      <footer className="wrap">
        <a className="logo" href="#top">
          <Shield size={18} />
          aegis
        </a>
        <p className="mono dim">MIT or Apache-2.0 · <a href={REPO}>Source on GitHub</a></p>
      </footer>
    </>
  );
}
