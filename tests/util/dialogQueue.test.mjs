import test from "node:test";
import assert from "node:assert/strict";
import { DialogQueue } from "./dialogQueue.mjs";

test("a second request waits for the first instead of replacing it (F-048)", async () => {
  let changes = 0;
  const q = new DialogQueue(() => { changes++; });
  const first = q.push({ name: "delete A" });
  const second = q.push({ name: "delete B" });
  assert.equal(q.size, 2);
  assert.equal(q.head().entry.name, "delete A");
  q.settle(q.head().id, true);
  assert.equal(await first, true);
  assert.equal(q.head().entry.name, "delete B");
  q.settle(q.head().id, false);
  assert.equal(await second, false);
  assert.equal(q.head(), null);
  assert.equal(changes, 4);
});

test("answering a request twice, or one that is gone, changes nothing", async () => {
  const q = new DialogQueue(() => {});
  const a = q.push("a");
  const b = q.push("b");
  const idA = q.head().id;
  q.settle(idA, "yes");
  q.settle(idA, "again");
  assert.equal(await a, "yes");
  assert.equal(q.size, 1);
  assert.equal(q.head().entry, "b");
  q.settle(999, "nothing");
  assert.equal(q.size, 1);
  q.settle(q.head().id, "no");
  assert.equal(await b, "no");
});

test("a request further back can be answered without disturbing the one shown", async () => {
  const q = new DialogQueue(() => {});
  q.push("shown");
  const later = q.push("later");
  const laterId = q.head().id + 1;
  q.settle(laterId, 7);
  assert.equal(await later, 7);
  assert.equal(q.head().entry, "shown");
});
