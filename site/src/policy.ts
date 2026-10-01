// Policy types for the playground, and the aegis.toml they render to. The
// decisions themselves come from the Rust engine (see engine.ts).

export type Action = "allow" | "deny" | "ask";

export interface Source {
  tool: string;
  labels: string[];
  /** Only when the `url` argument's host is one of these. */
  hosts?: string[];
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
  /** Labels for output of tools no source matches (untrusted by default). */
  defaultLabels: string[];
}

/** Renders a policy as the `aegis.toml` sections that define it. */
export function toToml(policy: Policy): string {
  const q = (s: string) => JSON.stringify(s);
  const list = (xs: string[]) => `[${xs.map(q).join(", ")}]`;
  const parts = [`[policy]\ndefault = ${q(policy.default)}\ndefault_labels = ${list(policy.defaultLabels)}`];
  for (const s of policy.sources) {
    let source = `[[source]]\ntool = ${q(s.tool)}\nlabels = ${list(s.labels)}`;
    if (s.hosts?.length) source += `\nhosts = ${list(s.hosts)}`;
    parts.push(source);
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
  defaultLabels: ["untrusted"],
  sources: [
    { tool: "web__fetch", labels: [], hosts: ["docs.rs", "*.rust-lang.org"] },
    { tool: "web__*", labels: ["untrusted", "external"] },
    { tool: "github__get_issue*", labels: ["untrusted"] },
    { tool: "files__*", labels: [] },
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
      action: "ask",
      reason: "pushing after reading untrusted content needs a person's OK",
    },
    {
      tool: "github__delete_*",
      whenContextHas: [],
      action: "deny",
      reason: "deletion is never allowed through this agent",
    },
  ],
};
