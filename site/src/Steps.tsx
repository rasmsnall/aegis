import { useEffect, useState, type ReactNode } from "react";

const STEPS = [
  {
    title: "Label",
    body: "Every tool result is labelled by where it came from.",
    caption: "A web page comes back through aegis and is stamped untrusted.",
  },
  {
    title: "Track",
    body: "Labels stay on the session. What the agent read, it keeps.",
    caption: "The label lands in the session context. Trusted data later can't wash it out.",
  },
  {
    title: "Enforce",
    body: "Each call is checked against your rules before it runs.",
    caption: "The agent tries to run a shell command. Rule #1 matches the context, and aegis stops the call.",
  },
  {
    title: "Record",
    body: "Every decision lands in a signed, hash-chained audit log.",
    caption: "Each call, result and decision is appended to the log, chained to the entry before it.",
  },
];

const INTERVAL = 5200;
const SCENE_MS = 4200;

type Point = readonly [number, number];

// Scene geometry (viewBox 720 × 340).
const AGENT = { x: 40, y: 140, w: 120, h: 56 };
const AEGIS = { x: 300, y: 118, w: 140, h: 100 };
const SERVERS = [
  { name: "web", y: 40 },
  { name: "github", y: 144 },
  { name: "shell", y: 248 },
] as const;
const SERVER_X = 580;
const SERVER_W = 120;
const SERVER_H = 52;
const TRAY = { x: 300, y: 252, w: 140, h: 40 };

const AGENT_OUT: Point = [AGENT.x + AGENT.w, 168];
const AEGIS_IN: Point = [AEGIS.x, 168];
const AEGIS_OUT: Point = [AEGIS.x + AEGIS.w, 168];
const AEGIS_BOTTOM: Point = [370, AEGIS.y + AEGIS.h];
const serverIn = (i: number): Point => [SERVER_X, SERVERS[i].y + SERVER_H / 2];

const clamp = (v: number) => Math.min(Math.max(v, 0), 1);
const ease = (v: number) => (v < 0.5 ? 2 * v * v : 1 - (-2 * v + 2) ** 2 / 2);
/** Progress of `t` through the window [from, to], eased. */
const span = (t: number, from: number, to: number) => ease(clamp((t - from) / (to - from)));

function along(points: readonly Point[], p: number): Point {
  const lengths = points.slice(1).map((pt, i) => Math.hypot(pt[0] - points[i][0], pt[1] - points[i][1]));
  let d = p * lengths.reduce((a, b) => a + b, 0);
  for (let i = 0; i < lengths.length; i++) {
    if (d <= lengths[i] || i === lengths.length - 1) {
      const k = lengths[i] ? d / lengths[i] : 0;
      return [points[i][0] + (points[i + 1][0] - points[i][0]) * k, points[i][1] + (points[i + 1][1] - points[i][1]) * k];
    }
    d -= lengths[i];
  }
  return points[points.length - 1];
}

/** 0 → 1 over `duration` ms, restarting whenever `key` changes. */
function useTimeline(key: number, duration: number) {
  const [t, setT] = useState(0);
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setT(1);
      return;
    }
    setT(0);
    const start = performance.now();
    let frame = 0;
    const tick = (now: number) => {
      const v = Math.min((now - start) / duration, 1);
      setT(v);
      if (v < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [key, duration]);
  return t;
}

/** The four stages as a row of progress bars over an animated scene of the current one. */
export function Steps() {
  const [step, setStep] = useState(0);
  const [paused, setPaused] = useState(false);
  const t = useTimeline(step, SCENE_MS);

  useEffect(() => {
    if (paused || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const id = setTimeout(() => setStep((s) => (s + 1) % STEPS.length), INTERVAL);
    return () => clearTimeout(id);
  }, [step, paused]);

  return (
    <div className="steps" onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)}>
      <div className="step-tabs" role="tablist" aria-label="How aegis works">
        {STEPS.map((s, i) => (
          <button
            key={s.title}
            role="tab"
            aria-selected={i === step}
            className={`step-tab ${i === step ? "active" : ""} ${i < step ? "done" : ""}`}
            onClick={() => setStep(i)}
          >
            <span className="step-bar" aria-hidden>
              {i === step && <span key={`${step}-${paused}`} className={`step-fill ${paused ? "held" : ""}`} />}
            </span>
            <span className="mono step-num">0{i + 1}</span>
            <span className="step-name">{s.title}</span>
            <span className="step-body">{s.body}</span>
          </button>
        ))}
      </div>
      <div className="step-stage">
        <Scene step={step} t={t} />
        <p key={step} className="step-caption" aria-live="polite">
          <span className="mono">0{step + 1}</span> {STEPS[step].caption}
        </p>
      </div>
    </div>
  );
}

function Packet({ at, tone, label }: { at: Point; tone: "plain" | "taint" | "block"; label?: string }) {
  return (
    <g transform={`translate(${at[0]} ${at[1]})`} className="d-packet">
      <rect x="-11" y="-6" width="22" height="12" className={`d-pk d-pk-${tone}`} />
      {label && (
        <text y="-13" textAnchor="middle" className={`d-mono d-pk-label d-pk-label-${tone}`}>
          {label}
        </text>
      )}
    </g>
  );
}

/** Shows children with a pop-in once `t` passes `from`. */
function After({ t, from, children }: { t: number; from: number; children: ReactNode }) {
  return t >= from ? <g className="d-pop">{children}</g> : null;
}

function Scene({ step, t }: { step: number; t: number }) {
  const tainted = step >= 1 || (step === 0 && t >= 0.62);
  const blocked = step === 2 && t >= 0.5;
  const trayShown = step >= 1 && step <= 2;
  const trayFill = step === 1 ? span(t, 0.36, 0.5) : step === 2 ? 1 : 0;

  // Moving pieces for the current step.
  const packets: ReactNode[] = [];
  const show = (p: number, points: readonly Point[], tone: "plain" | "taint" | "block", label?: string, key = packets.length) => {
    if (p > 0 && p < 1) packets.push(<Packet key={key} at={along(points, p)} tone={tone} label={label} />);
  };

  if (step === 0) {
    show(span(t, 0.02, 0.18), [AGENT_OUT, AEGIS_IN], "plain", "web__fetch");
    show(span(t, 0.18, 0.36), [AEGIS_OUT, serverIn(0)], "plain");
    const back = span(t, 0.42, 0.62);
    show(back, [serverIn(0), AEGIS_OUT], "plain", "page");
    show(span(t, 0.66, 0.9), [AEGIS_IN, AGENT_OUT], "taint", "untrusted");
  }
  if (step === 1) {
    show(span(t, 0.04, 0.2), [serverIn(0), AEGIS_OUT], "taint", "untrusted");
    show(span(t, 0.2, 0.36), [[370, 168], AEGIS_BOTTOM, [370, TRAY.y + 20]], "taint");
    show(span(t, 0.56, 0.72), [serverIn(1), AEGIS_OUT], "plain", "trusted");
    show(span(t, 0.72, 0.86), [[370, 168], AEGIS_BOTTOM, [370, TRAY.y + 20]], "plain");
  }
  if (step === 2) {
    show(span(t, 0.04, 0.24), [AGENT_OUT, AEGIS_IN], "plain", "shell__exec");
    const toShell = span(t, 0.38, 0.5);
    const stop = along([AEGIS_OUT, serverIn(2)], 0.42);
    show(toShell, [AEGIS_OUT, stop], "plain", "shell__exec");
    show(span(t, 0.62, 0.86), [AEGIS_IN, AGENT_OUT], "block", "blocked");
  }

  const burst = step === 2 ? span(t, 0.5, 0.75) : 0;
  const stop = along([AEGIS_OUT, serverIn(2)], 0.42);
  const pulse = step === 2 ? Math.sin(Math.PI * span(t, 0.24, 0.5)) : step === 0 ? Math.sin(Math.PI * span(t, 0.58, 0.7)) : 0;

  const logLines = [
    { at: 0.08, text: "tool_call    web__fetch   allow", hash: "9f3a" },
    { at: 0.28, text: "tool_result  web__fetch   +untrusted", hash: "c41e" },
    { at: 0.48, text: "tool_call    shell__exec  deny #1", hash: "07bd" },
    { at: 0.68, text: "session_end", hash: "e25c" },
  ];

  return (
    <svg viewBox="0 0 720 340" role="img" aria-label={`Diagram: ${STEPS[step].title}`} className="diagram">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
          <path d="M0 0 10 5 0 10z" className="d-arrow" />
        </marker>
      </defs>

      {/* Edges, with a slow flow running along them. */}
      <line x1={AGENT_OUT[0]} y1={168} x2={AEGIS_IN[0] - 2} y2={168} className="d-edge" markerEnd="url(#arrow)" />
      <line x1={AGENT_OUT[0]} y1={168} x2={AEGIS_IN[0] - 2} y2={168} className="d-flow" />
      {SERVERS.map((s, i) => {
        const [x2, y2] = serverIn(i);
        const cut = s.name === "shell" && blocked;
        return (
          <g key={s.name}>
            <line x1={AEGIS_OUT[0]} y1={168} x2={x2 - 2} y2={y2} className={cut ? "d-edge d-edge-cut" : "d-edge"} markerEnd="url(#arrow)" />
            {!cut && <line x1={AEGIS_OUT[0]} y1={168} x2={x2 - 2} y2={y2} className="d-flow" />}
          </g>
        );
      })}
      {trayShown && <line x1={370} y1={AEGIS.y + AEGIS.h} x2={370} y2={TRAY.y} className="d-edge d-pop" />}
      {step === 3 && <path d={`M370 ${AEGIS.y + AEGIS.h} V236 H150 V244`} className="d-edge d-pop" />}

      {/* Nodes. */}
      <rect {...AGENT} width={AGENT.w} height={AGENT.h} className={`d-box ${step === 2 && t >= 0.84 ? "d-box-hit" : ""}`} />
      <text x={AGENT.x + AGENT.w / 2} y={174} textAnchor="middle" className="d-label">
        agent
      </text>
      {SERVERS.map((s) => (
        <g key={s.name}>
          <rect x={SERVER_X} y={s.y} width={SERVER_W} height={SERVER_H} className="d-box" />
          <text x={SERVER_X + SERVER_W / 2} y={s.y + 32} textAnchor="middle" className="d-label">
            {s.name}
          </text>
        </g>
      ))}
      <g style={{ transform: `scale(${1 + pulse * 0.05})`, transformOrigin: "370px 168px" }}>
        <rect x={AEGIS.x} y={AEGIS.y} width={AEGIS.w} height={AEGIS.h} className="d-aegis" />
        <rect
          x={AEGIS.x}
          y={AEGIS.y}
          width={AEGIS.w}
          height={AEGIS.h}
          className="d-aegis-glow"
          style={{ opacity: pulse }}
        />
        <path d="M370 134l-13 5.5v9c0 8.2 5.5 14.4 13 16.4 7.5-2 13-8.2 13-16.4v-9z" className="d-shield" />
        <text x={370} y={200} textAnchor="middle" className="d-label d-ink">
          aegis
        </text>
      </g>

      {/* Step 0: the stamp. */}
      {step === 0 && (
        <After t={t} from={0.62}>
          <g transform="translate(324 86) rotate(-5)">
            <rect x="0" y="0" width="92" height="24" className="d-taint" />
            <text x="46" y="16" textAnchor="middle" className="d-mono d-ink">
              untrusted
            </text>
          </g>
        </After>
      )}

      {/* Steps 1–2: the session context tray. */}
      {trayShown && (
        <g className="d-pop">
          <rect x={TRAY.x} y={TRAY.y} width={TRAY.w} height={TRAY.h} className="d-box" />
          <rect x={TRAY.x} y={TRAY.y} width={TRAY.w * trayFill} height={TRAY.h} className="d-tray-fill" />
          <text x={370} y={TRAY.y + 25} textAnchor="middle" className="d-mono">
            {tainted && trayFill > 0.5 ? "context: untrusted" : "context: clean"}
          </text>
          {step === 1 && t >= 0.86 && (
            <text x={370} y={TRAY.y + 62} textAnchor="middle" className="d-mono d-note d-pop">
              labels only accumulate
            </text>
          )}
        </g>
      )}

      {/* Step 2: the rule that matches, and the stop. */}
      {step === 2 && (
        <After t={t} from={0.24}>
          <g className="d-slide">
            <rect x={265} y={24} width={210} height={62} className="d-rule" />
            <text x={279} y={46} className="d-mono d-muted">
              rule #1
            </text>
            <text x={279} y={70} className="d-mono">
              deny shell__* if untrusted
            </text>
          </g>
        </After>
      )}
      {burst > 0 && (
        <g transform={`translate(${stop[0]} ${stop[1]})`}>
          <circle r={8 + burst * 30} className="d-burst" style={{ opacity: 1 - burst }} />
          <rect x="-13" y="-13" width="26" height="26" className="d-block" />
          <path d="M-5-5 5 5M5-5-5 5" className="d-x" />
        </g>
      )}
      {step === 2 && t >= 0.86 && (
        <g className="d-pop">
          <rect x={AGENT.x} y={AGENT.y + AGENT.h + 10} width={AGENT.w} height={22} className="d-block" />
          <text x={AGENT.x + AGENT.w / 2} y={AGENT.y + AGENT.h + 25} textAnchor="middle" className="d-mono d-ink">
            tool error
          </text>
        </g>
      )}

      {/* Step 3: the log fills in, entry by entry. */}
      {step === 3 && (
        <g className="d-pop">
          <rect x={20} y={244} width={340} height={90} className="d-box" />
          {logLines.map((line, i) =>
            t >= line.at ? (
              <g key={line.text} className="d-log-line">
                <text x={34} y={264 + i * 19} className="d-mono">
                  <tspan className="d-muted">{String(i + 1).padStart(2, "0")} </tspan>
                  {line.text.slice(0, Math.ceil(line.text.length * span(t, line.at, line.at + 0.12)))}
                </text>
                {t >= line.at + 0.12 && (
                  <text x={348} y={264 + i * 19} textAnchor="end" className="d-mono d-hash">
                    {line.hash}
                  </text>
                )}
                {i > 0 && <path d={`M28 ${250 + i * 19}v8`} className="d-chain" />}
              </g>
            ) : null,
          )}
        </g>
      )}
      {step === 3 &&
        logLines.map((line, i) => {
          const p = span(t, line.at - 0.08, line.at);
          return p > 0 && p < 1 ? <Packet key={i} at={along([AEGIS_BOTTOM, [370, 236], [150, 236], [150, 244]], p)} tone="plain" /> : null;
        })}

      {packets}
    </svg>
  );
}
