import assert from "node:assert/strict";
import { test } from "node:test";

import { decide, examplePolicy, globMatch, labelsForResult } from "./policy.ts";

test("glob matching matches the Rust implementation's cases", () => {
  assert.ok(globMatch("shell__exec", "shell__exec"));
  assert.ok(!globMatch("shell__exec", "shell__exec2"));
  assert.ok(globMatch("shell__*", "shell__exec"));
  assert.ok(globMatch("*", ""));
  assert.ok(globMatch("a*b*c", "axxbyyc"));
  assert.ok(!globMatch("a*b*c", "axxbyy"));
  assert.ok(!globMatch("git__*", "github__push"));
  assert.ok(globMatch("a.b", "a.b") && !globMatch("a.b", "axb"));
});

test("shell is allowed until untrusted data is read", () => {
  const context = new Set<string>();
  assert.equal(decide(examplePolicy, "shell__exec", context).action, "allow");
  labelsForResult(examplePolicy, "web__fetch").forEach((l) => context.add(l));
  const d = decide(examplePolicy, "shell__exec", context);
  assert.equal(d.action, "deny");
  assert.equal(d.rule, 1);
  assert.deepEqual(d.matchedLabels, ["untrusted"]);
  assert.equal(decide(examplePolicy, "files__read", context).action, "allow");
});

test("unconditional rule applies on a clean context", () => {
  assert.equal(decide(examplePolicy, "github__delete_file", new Set()).rule, 3);
});
