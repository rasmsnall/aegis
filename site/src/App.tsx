import { useCallback, useRef, useState } from "react";

import { FlowField, type FlowEvent } from "./FlowField.tsx";
import { Playground } from "./Playground.tsx";
import { Steps } from "./Steps.tsx";

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

const CLI = `aegis init   --from .mcp.json --replace
aegis tools  -c aegis.toml
aegis run    -c aegis.toml
aegis report aegis-audit.jsonl
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
      className="btn btn-outline btn-install"
      onClick={() => {
        navigator.clipboard
          ?.writeText(INSTALL)
          .then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          })
          .catch(() => {
            // Clipboard refused: select the command so it can be copied by hand.
            const text = document.querySelector(".btn-install .mono");
            if (text) window.getSelection()?.selectAllChildren(text);
          });
      }}
    >
      <span className="mono">{copied ? "Copied" : INSTALL}</span>
    </button>
  );
}

export function App() {
  const lineRef = useRef<HTMLDivElement>(null);
  const heroRef = useRef<HTMLElement>(null);
  const stoppedRef = useRef<HTMLElement>(null);
  const leakedRef = useRef<HTMLElement>(null);
  const counts = useRef({ stopped: 0, leaked: 0 });
  const [guarded, setGuarded] = useState(true);

  // Counters update on every packet, so write to the DOM instead of re-rendering.
  const onFlow = useCallback((e: FlowEvent) => {
    counts.current[e] += 1;
    const el = e === "stopped" ? stoppedRef.current : leakedRef.current;
    if (el) el.textContent = String(counts.current[e]);
  }, []);

  return (
    <>
      <header className="nav">
        <div className="nav-inner wrap">
          <a className="logo" href="#top">
            <Shield />
            aegis
          </a>
          <nav>
            <a href="#how">How it works</a>
            <a href="#playground">Playground</a>
            <a href="#start">Get started</a>
          </nav>
          <a className="btn btn-outline nav-cta" href={REPO}>
            GitHub
          </a>
        </div>
      </header>

      <main id="top">
        <section className="hero" ref={heroRef}>
          <FlowField lineRef={lineRef} hostRef={heroRef} guarded={guarded} onEvent={onFlow} />
          <p className="hero-hint mono">Click anywhere up here to inject untrusted data</p>
          <div className="hero-content wrap">
            <div className={`policy-line ${guarded ? "" : "off"}`} ref={lineRef}>
              <span className="mono">
                {guarded ? (
                  <>
                    rule #1 · deny <b>shell__*</b> when context has <b className="taint">untrusted</b>
                  </>
                ) : (
                  "policy off · untrusted data passes"
                )}
              </span>
            </div>
            <h1>
              Untrusted data
              <br />
              {guarded ? "stops here." : "gets through."}
            </h1>
            <div className="hero-foot">
              <p className="hero-sub">
                aegis is a firewall between your AI agent and its tools. It labels everything the agent reads, and
                blocks the calls your policy forbids once untrusted data is in play.
              </p>
              <div className="hero-actions">
                <a className="btn btn-scarlet" href="#playground">
                  Try the playground
                </a>
                <InstallButton />
              </div>
            </div>
            <div className="hero-meta">
              <label className="switch switch-small mono" htmlFor="hero-guard">
                <input id="hero-guard" type="checkbox" checked={guarded} onChange={(e) => setGuarded(e.target.checked)} />
                <span className="switch-track" aria-hidden />
                policy line {guarded ? "on" : "off"}
              </label>
              <ul className="legend mono" aria-label="Legend">
                <li>
                  <i className="swatch swatch-trusted" /> trusted
                </li>
                <li>
                  <i className="swatch swatch-checked" /> passed the policy
                </li>
                <li>
                  <i className="swatch swatch-taint" /> untrusted
                </li>
              </ul>
              <p className="counters mono" aria-live="off">
                <span>
                  stopped <b ref={stoppedRef}>0</b>
                </span>
                <span className="leaked">
                  leaked <b ref={leakedRef}>0</b>
                </span>
              </p>
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
          <div className="section-head">
            <p className="mono eyebrow">How it works</p>
            <h2>Four steps on every call.</h2>
          </div>
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
              <code>aegis init</code> reads your agent's MCP config, writes a commented starting policy and
              puts aegis in front of your servers. Tools appear as <code>&lt;server&gt;__&lt;tool&gt;</code>, so
              one session covers every server.
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
