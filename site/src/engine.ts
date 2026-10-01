// The real aegis policy engine (src/policy.rs), compiled to WebAssembly.
// `npm run wasm` builds public/aegis.wasm from the Rust crate; the site and
// its tests both load that file, so the playground decides calls with
// exactly the code the proxy runs.

import type { Action, Policy } from "./policy.ts";

export interface Call {
  tool: string;
  arguments?: Record<string, unknown>;
  /** The person's answer, if the policy asks about this call. */
  approved?: boolean;
}

export interface Decision {
  action: Action;
  rule: number | null;
  matchedLabels: string[];
  reason: string | null;
  approved: boolean | null;
}

export interface SimEntry {
  tool: string;
  decision: Decision;
  runs: boolean;
  added: string[];
  message: string | null;
}

export interface Simulation {
  entries: SimEntry[];
  context: string[];
}

interface Exports {
  memory: WebAssembly.Memory;
  alloc(len: number): number;
  simulate(ptr: number, len: number): number;
  output_len(): number;
}

let engine: Exports | null = null;

/** Loads the engine from the given bytes, or fetches it next to the page. */
export async function initEngine(bytes?: BufferSource): Promise<void> {
  const source = bytes ?? (await (await fetch(new URL("aegis.wasm", document.baseURI))).arrayBuffer());
  const { instance } = await WebAssembly.instantiate(source, {});
  engine = instance.exports as unknown as Exports;
}

function toRust(policy: Policy) {
  return {
    default: policy.default,
    default_labels: policy.defaultLabels,
    sources: policy.sources,
    rules: policy.rules.map((r) => ({
      tool: r.tool,
      when_context_has: r.whenContextHas,
      action: r.action,
      reason: r.reason ?? null,
    })),
  };
}

export const engineLoaded = () => engine !== null;

/** Runs `calls` through `policy` from a clean session, in the Rust engine. */
export function simulate(policy: Policy, calls: Call[]): Simulation {
  if (!engine) throw new Error("policy engine not loaded");
  const input = new TextEncoder().encode(JSON.stringify({ policy: toRust(policy), calls }));
  const ptr = engine.alloc(input.length);
  new Uint8Array(engine.memory.buffer, ptr, input.length).set(input);
  const out = engine.simulate(ptr, input.length);
  const json = new TextDecoder().decode(new Uint8Array(engine.memory.buffer, out, engine.output_len()));
  const raw = JSON.parse(json);
  if (raw.error) throw new Error(`policy engine: ${raw.error}`);
  return {
    context: raw.context,
    entries: raw.entries.map((e: any) => ({
      tool: e.tool,
      runs: e.runs,
      added: e.added,
      message: e.message,
      decision: {
        action: e.decision.action,
        rule: e.decision.rule,
        matchedLabels: e.decision.matched_labels,
        reason: e.decision.reason,
        approved: e.decision.approved ?? null,
      },
    })),
  };
}
