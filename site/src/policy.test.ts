import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { before, test } from "node:test";

import { initEngine, simulate } from "./engine.ts";
import { examplePolicy, toToml } from "./policy.ts";

before(async () => {
  // Built from the Rust crate by `npm run wasm`.
  await initEngine(readFileSync(new URL("../public/aegis.wasm", import.meta.url)));
});

const calls = (...tools: string[]) => tools.map((tool) => ({ tool }));

test("the engine blocks shell once untrusted data is read", () => {
  const sim = simulate(examplePolicy, calls("files__read", "web__fetch", "shell__exec"));
  assert.deepEqual(
    sim.entries.map((e) => e.runs),
    [true, true, false],
  );
  assert.deepEqual(sim.context, ["external", "untrusted"]);
  const blocked = sim.entries[2];
  assert.equal(blocked.decision.action, "deny");
  assert.equal(blocked.decision.rule, 1);
  assert.deepEqual(blocked.decision.matchedLabels, ["untrusted"]);
  assert.match(blocked.message!, /^aegis blocked this call to shell__exec \(rule #1\) because this session has read data labelled untrusted/);
});

test("pages from trusted hosts stay clean; everything else from the web doesn't", () => {
  const fetch = (url: string) => simulate(examplePolicy, [{ tool: "web__fetch", arguments: { url } }]).context;
  assert.deepEqual(fetch("https://docs.rs/serde"), []);
  assert.deepEqual(fetch("https://doc.rust-lang.org/std/"), []);
  assert.deepEqual(fetch("https://docs.rs@evil.example/"), ["external", "untrusted"]);
  assert.deepEqual(fetch("https://example.com/fix"), ["external", "untrusted"]);
});

test("files are trusted, unlisted tools are not", () => {
  assert.deepEqual(simulate(examplePolicy, calls("files__read")).context, []);
  assert.deepEqual(simulate(examplePolicy, calls("mail__read")).context, ["untrusted"]);
  const trusting = { ...examplePolicy, defaultLabels: [] };
  assert.deepEqual(simulate(trusting, calls("mail__read")).context, []);
});

test("ask runs only with a person's approval", () => {
  const push = (approved?: boolean) =>
    simulate(examplePolicy, [{ tool: "github__get_issue" }, { tool: "github__push_files", approved }]).entries[1];
  assert.equal(push(undefined).decision.action, "ask");
  assert.equal(push(undefined).runs, false);
  assert.match(push(undefined).message!, /not approved/);
  assert.equal(push(false).runs, false);
  assert.equal(push(true).runs, true);
  assert.equal(push(true).decision.approved, true);
});

test("unconditional rules and the default action", () => {
  assert.equal(simulate(examplePolicy, calls("github__delete_file")).entries[0].decision.rule, 3);
  const strict = { ...examplePolicy, default: "deny" as const };
  const d = simulate(strict, calls("files__read")).entries[0].decision;
  assert.equal(d.action, "deny");
  assert.equal(d.rule, null);
});

test("toToml emits the config format aegis reads", () => {
  const toml = toToml({
    default: "deny",
    defaultLabels: ["untrusted"],
    sources: [
      { tool: "web__fetch", labels: [], hosts: ["docs.rs"] },
      { tool: "web__*", labels: ["untrusted"] },
    ],
    rules: [{ tool: "shell__*", whenContextHas: ["untrusted"], action: "ask", reason: 'no "shell"' }],
  });
  assert.equal(
    toml,
    [
      '[policy]\ndefault = "deny"\ndefault_labels = ["untrusted"]',
      '[[source]]\ntool = "web__fetch"\nlabels = []\nhosts = ["docs.rs"]',
      '[[source]]\ntool = "web__*"\nlabels = ["untrusted"]',
      '[[rule]]\ntool = "shell__*"\nwhen_context_has = ["untrusted"]\naction = "ask"\nreason = "no \\"shell\\""',
    ].join("\n\n"),
  );
});
