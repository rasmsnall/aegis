import { useEffect, useState } from "react";

const STEPS = [
  { title: "Label", body: "Every tool result is labelled by where it came from." },
  { title: "Track", body: "Labels stay on the session. What the agent read, it keeps." },
  { title: "Enforce", body: "Each call is checked against your rules before it runs." },
  { title: "Record", body: "Every decision lands in a hash-chained audit log." },
];

const INTERVAL = 4000;

/** Blue step carousel beside a dotted panel holding a diagram of the current step. */
export function Steps() {
  const [step, setStep] = useState(0);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    if (paused || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const id = setTimeout(() => setStep((s) => (s + 1) % STEPS.length), INTERVAL);
    return () => clearTimeout(id);
  }, [step, paused]);

  return (
    <div className="split" onMouseEnter={() => setPaused(true)} onMouseLeave={() => setPaused(false)}>
      <div className="split-blue">
        <Corners />
        <p className="split-kicker">How aegis works</p>
        <div className="split-body" aria-live="polite">
          <p className="mono split-count">
            0{step + 1} / 0{STEPS.length}
          </p>
          <h2 className="split-title">{STEPS[step].title}.</h2>
          <p className="split-text">{STEPS[step].body}</p>
        </div>
        <div className="progress" role="tablist" aria-label="Steps">
          {STEPS.map((s, i) => (
            <button
              key={s.title}
              role="tab"
              aria-selected={i === step}
              aria-label={s.title}
              className={i === step ? "active" : ""}
              onClick={() => setStep(i)}
            >
              {i === step && !paused && <span key={step} className="progress-fill" />}
            </button>
          ))}
        </div>
      </div>
      <div className="split-dark dots">
        <div className="card">
          <Diagram step={step} />
        </div>
      </div>
    </div>
  );
}

function Corners() {
  return (
    <>
      {["tl", "tr", "bl", "br"].map((c) => (
        <span key={c} className={`corner corner-${c}`} aria-hidden>
          +
        </span>
      ))}
    </>
  );
}

function Diagram({ step }: { step: number }) {
  const servers = ["web", "github", "shell"];
  return (
    <svg viewBox="0 0 400 300" role="img" aria-label={`Diagram: ${STEPS[step].title}`} className="diagram">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">
          <path d="M0 0 10 5 0 10z" fill="#000" />
        </marker>
      </defs>

      {/* agent */}
      <rect x="16" y="120" width="80" height="44" rx="3" fill="#fff" stroke="#000" strokeWidth="1.5" />
      <text x="56" y="147" textAnchor="middle" className="d-label">
        agent
      </text>
      <line x1="96" y1="142" x2="146" y2="142" stroke="#000" strokeWidth="1.5" markerEnd="url(#arrow)" />

      {/* aegis */}
      <rect x="148" y="104" width="96" height="76" rx="3" fill="#1e6ef3" stroke="#000" strokeWidth="1.5" />
      <path d="M196 116l-12 5v8c0 7.5 5.1 13.2 12 15 6.9-1.8 12-7.5 12-15v-8z" fill="#fff" />
      <text x="196" y="166" textAnchor="middle" className="d-label d-invert">
        aegis
      </text>

      {/* servers */}
      {servers.map((name, i) => {
        const y = 50 + i * 80;
        const blocked = step === 2 && name === "shell";
        return (
          <g key={name}>
            <line
              x1="244"
              y1="142"
              x2="300"
              y2={y + 22}
              stroke="#000"
              strokeWidth="1.5"
              strokeDasharray={blocked ? "4 4" : undefined}
              markerEnd="url(#arrow)"
            />
            <rect x="302" y={y} width="84" height="44" rx="3" fill="#fff" stroke="#000" strokeWidth="1.5" />
            <text x="344" y={y + 27} textAnchor="middle" className="d-label">
              {name}
            </text>
            {blocked && (
              <g transform={`translate(272 ${(142 + y + 22) / 2})`}>
                <circle r="11" fill="#ff4d4d" stroke="#000" strokeWidth="1.5" />
                <path d="M-4-4 4 4M4-4-4 4" stroke="#fff" strokeWidth="2" />
              </g>
            )}
          </g>
        );
      })}

      {step === 0 && <Tag x={302} y={22} text="untrusted" />}
      {step === 1 && <Tag x={148} y={196} text="context: untrusted" />}
      {step === 2 && <Tag x={148} y={196} text="shell__exec: blocked" danger />}
      {step === 3 && (
        <g>
          {[0, 1, 2].map((i) => (
            <rect key={i} x={160 + i * 4} y={200 + i * 8} width="72" height="40" rx="2" fill="#fff" stroke="#000" strokeWidth="1.5" />
          ))}
          <text x="204" y="236" textAnchor="middle" className="d-mono">
            audit.jsonl
          </text>
          <line x1="196" y1="180" x2="196" y2="198" stroke="#000" strokeWidth="1.5" markerEnd="url(#arrow)" />
        </g>
      )}
    </svg>
  );
}

function Tag({ x, y, text, danger = false }: { x: number; y: number; text: string; danger?: boolean }) {
  const width = text.length * 7.4 + 16;
  return (
    <g>
      <rect x={x} y={y} width={width} height="22" rx="2" fill={danger ? "#ff4d4d" : "#000"} />
      <text x={x + width / 2} y={y + 15} textAnchor="middle" className="d-mono d-invert">
        {text}
      </text>
    </g>
  );
}
