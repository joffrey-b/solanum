// The automatic update check: once per launch, however often the profile
// picker comes back.
import { test } from "node:test";
import assert from "node:assert/strict";
import { onceUntilReload } from "./updateCheck.mjs";

test("runs once across repeated calls and hands everyone the same answer", async () => {
  let calls = 0;
  const check = onceUntilReload(async () => { calls += 1; return { latest: "1.2.3" }; });
  const first = await check();
  const second = await check();
  assert.equal(calls, 1);
  assert.deepEqual(first, { latest: "1.2.3" });
  assert.equal(first, second);
});

test("two calls made before the first finishes still run once", async () => {
  let calls = 0;
  let finish;
  const check = onceUntilReload(() => { calls += 1; return new Promise((r) => { finish = r; }); });
  const both = Promise.all([check(), check()]);
  finish("done");
  assert.deepEqual(await both, ["done", "done"]);
  assert.equal(calls, 1);
});

test("a failed check is not repeated, and every caller sees the failure", async () => {
  let calls = 0;
  const check = onceUntilReload(async () => { calls += 1; throw new Error("offline"); });
  await assert.rejects(check(), /offline/);
  await assert.rejects(check(), /offline/);
  assert.equal(calls, 1);
});

test("a function that throws at once counts as a failed check", async () => {
  let calls = 0;
  const check = onceUntilReload(() => { calls += 1; throw new Error("no bridge"); });
  await assert.rejects(check(), /no bridge/);
  await assert.rejects(check(), /no bridge/);
  assert.equal(calls, 1);
});

test("each wrapped function keeps its own state", async () => {
  let calls = 0;
  const run = async () => { calls += 1; };
  await onceUntilReload(run)();
  await onceUntilReload(run)();
  assert.equal(calls, 2);
});
