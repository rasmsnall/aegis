import { useEffect, useState } from "react";

const STEPS = [
  { title: "Label", body: "Every tool result is labelled by where it came from." },
  { title: "Track", body: "Labels stay on the session. What the agent read, it keeps." },
  { title: "Enforce", body: "Each call is checked against your rules before it runs." },
  { title: "Record", body: "Every decision lands in a hash-chained audit log." },
];

const INTERVAL = 4500;

/** The four stages as a row of progress bars above a diagram of the current one. */
export function Steps() {
  const [step, setStep] = useState(0);
  const [paused, setPaused] = useState(false);

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
        <Diagram step={step} />
      </div>
    </div>
  );
}

function Diagram({ step }: { step: number }) {
  const servers = ["web", "github", "shell"];
  return (
    <svg viewBox="0 0 640 300" role="img" aria-label={`Diagram: ${STEPS[step].title}`} className="diagram">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
          <path d="M0 0 10 5 0 10z" className="d-arrow" />
        </marker>
      </defs>

      <rect x="40" y="118" width="120" height="48" className="d-box" />
      <text x="100" y="147" textAnchor="middle" className="d-label">
        agent
      </text>
      <line x1="160" y1="142" x2="244" y2="142" className="d-edge" markerEnd="url(#arrow)" />

      <rect x="246" y="96" width="132" height="92" className="d-aegis" />
      <path d="M312 110l-13 5.5v9c0 8.2 5.5 14.4 13 16.4 7.5-2 13-8.2 13-16.4v-9z" className="d-shield" />
      <text x="312" y="174" textAnchor="middle" className="d-label d-ink">
        aegis
      </text>

      {servers.map((name, i) => {
        const y = 38 + i * 94;
        const blocked = step === 2 && name === "shell";
        return (
          <g key={name}>
            <line
              x1="378"
              y1="142"
              x2="476"
              y2={y + 24}
              className={blocked ? "d-edge d-edge-cut" : "d-edge"}
              markerEnd="url(#arrow)"
            />
            <rect x="478" y={y} width="122" height="48" className="d-box" />
            <text x="539" y={y + 29} textAnchor="middle" className="d-label">
              {name}
            </text>
            {blocked && (
              <g transform={`translate(427 ${(142 + y + 24) / 2})`}>
                <rect x="-13" y="-13" width="26" height="26" className="d-block" />
                <path d="M-5-5 5 5M5-5-5 5" className="d-x" />
              </g>
            )}
          </g>
        );
      })}

      {step === 0 && <Tag x={478} y={8} text="untrusted" tone="taint" />}
      {step === 1 && <Tag x={246} y={204} text="context: untrusted" tone="taint" />}
      {step === 2 && <Tag x={246} y={204} text="shell__exec: blocked" tone="block" />}
      {step === 3 && (
        <g>
          {[0, 1, 2].map((i) => (
            <rect key={i} x={262 + i * 5} y={214 + i * 9} width="100" height="44" className="d-box" />
          ))}
          <text x="322" y="256" textAnchor="middle" className="d-mono">
            audit.jsonl
          </text>
          <line x1="312" y1="188" x2="312" y2="212" className="d-edge" markerEnd="url(#arrow)" />
        </g>
      )}
    </svg>
  );
}

function Tag({ x, y, text, tone }: { x: number; y: number; text: string; tone: "taint" | "block" }) {
  const width = text.length * 8 + 20;
  return (
    <g>
      <rect x={x} y={y} width={width} height="24" className={`d-${tone}`} />
      <text x={x + width / 2} y={y + 16} textAnchor="middle" className="d-mono d-ink">
        {text}
      </text>
    </g>
  );
}
