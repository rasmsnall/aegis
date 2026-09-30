// TypeScript port of the aegis policy engine (src/policy.rs), used by the
// playground. Semantics match the Rust implementation: labels from tool output
// stay on the session for good, and the first matching rule decides a call.

export type Action = "allow" | "deny";

export interface Source {
  tool: string;
  labels: string[];
}

export interface Rule {
  tool: string;
  whenContextHas: string[];
  action: Action;
  reason?: string;
}

export interface Policy {
  sources: Source[];
  rules: Rule[];
  default: Action;
}

export interface Decision {
  action: Action;
  /** 1-based index of the deciding rule; null means the default applied. */
  rule: number | null;
  matchedLabels: string[];
  reason?: string;
}

/** `*` matches any run of characters; everything else matches literally. */
export function globMatch(pattern: string, name: string): boolean {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`, "s").test(name);
}

export function labelsForResult(policy: Policy, tool: string): string[] {
  const labels = new Set<string>();
  for (const source of policy.sources) {
    if (globMatch(source.tool, tool)) source.labels.forEach((l) => labels.add(l));
  }
  return [...labels].sort();
}

export function decide(policy: Policy, tool: string, context: ReadonlySet<string>): Decision {
  for (const [i, rule] of policy.rules.entries()) {
    if (!globMatch(rule.tool, tool)) continue;
    const matchedLabels = rule.whenContextHas.filter((l) => context.has(l));
    if (rule.whenContextHas.length > 0 && matchedLabels.length === 0) continue;
    return { action: rule.action, rule: i + 1, matchedLabels, reason: rule.reason };
  }
  return { action: policy.default, rule: null, matchedLabels: [] };
}

/** Mirrors the text aegis returns to the model when it blocks a call. */
export function blockMessage(tool: string, d: Decision): string {
  let text = `aegis blocked this call to ${tool} (${d.rule === null ? "default policy" : `rule #${d.rule}`})`;
  if (d.matchedLabels.length > 0) {
    text += ` because this session has read data labelled ${d.matchedLabels.join(", ")}`;
  }
  if (d.reason) text += `: ${d.reason}`;
  return text;
}

/** Renders a policy as the `aegis.toml` sections that define it. */
export function toToml(policy: Policy): string {
  const q = (s: string) => JSON.stringify(s);
  const list = (xs: string[]) => `[${xs.map(q).join(", ")}]`;
  const parts = [`[policy]\ndefault = ${q(policy.default)}`];
  for (const s of policy.sources) {
    parts.push(`[[source]]\ntool = ${q(s.tool)}\nlabels = ${list(s.labels)}`);
  }
  for (const r of policy.rules) {
    let rule = `[[rule]]\ntool = ${q(r.tool)}\n`;
    if (r.whenContextHas.length > 0) rule += `when_context_has = ${list(r.whenContextHas)}\n`;
    rule += `action = ${q(r.action)}`;
    if (r.reason) rule += `\nreason = ${q(r.reason)}`;
    parts.push(rule);
  }
  return parts.join("\n\n");
}

export const examplePolicy: Policy = {
  default: "allow",
  sources: [
    { tool: "web__*", labels: ["untrusted", "external"] },
    { tool: "github__get_issue*", labels: ["untrusted"] },
  ],
  rules: [
    {
      tool: "shell__*",
      whenContextHas: ["untrusted"],
      action: "deny",
      reason: "shell commands are disabled once untrusted content is in context",
    },
    {
      tool: "github__push_files",
      whenContextHas: ["untrusted"],
      action: "deny",
      reason: "pushing is disabled once untrusted content is in context",
    },
    {
      tool: "github__delete_*",
      whenContextHas: [],
      action: "deny",
      reason: "deletion is never allowed through this agent",
    },
  ],
};
