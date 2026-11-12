import test from "node:test";
import assert from "node:assert/strict";
import { subscribe, unlistenWhenReady } from "./tauriEvents.mjs";

// A listen() whose registrations resolve only when the test says so, like an
// IPC round trip that has not come back yet.
export const fakeBus = () => {
  const handlers = new Map();
  const pending = [];
  const listen = (name, handler) => new Promise((resolve) => {
    pending.push(() => {
      handlers.set(name, (handlers.get(name) || new Set()).add(handler));
      resolve(() => handlers.get(name).delete(handler));
    });
  });
  return {
    listen,
    registerAll: async () => { while (pending.length) pending.shift()(); await new Promise((r) => setTimeout(r, 0)); },
    count: (name) => handlers.get(name)?.size ?? 0,
    emit: (name, payload) => { for (const h of handlers.get(name) || []) h({ payload }); },
  };
};

test("a cleanup that runs before the registration resolves still unlistens (F-052)", async () => {
  const bus = fakeBus();
  const seen = [];
  const cleanup = subscribe(bus.listen, "sftp-transfer-session-3", (e) => seen.push(e.payload));
  cleanup();
  await bus.registerAll();
  assert.equal(bus.count("sftp-transfer-session-3"), 0);
  bus.emit("sftp-transfer-session-3", "stale");
  assert.deepEqual(seen, []);
});

test("after the registration the handler gets events until the cleanup", async () => {
  const bus = fakeBus();
  const seen = [];
  const cleanup = subscribe(bus.listen, "x", (e) => seen.push(e.payload));
  await bus.registerAll();
  bus.emit("x", 1);
  cleanup();
  bus.emit("x", 2);
  assert.deepEqual(seen, [1]);
  assert.equal(bus.count("x"), 0);
  cleanup();
});

test("an event between the cleanup and a late unlisten is not delivered", async () => {
  let deliver;
  const listen = (_name, handler) => { deliver = handler; return new Promise(() => {}); };
  const seen = [];
  const cleanup = subscribe(listen, "x", (e) => seen.push(e));
  cleanup();
  deliver("late");
  assert.deepEqual(seen, []);
});

test("unlistenWhenReady: a failed registration is ignored; a resolved one is removed once", async () => {
  const failed = unlistenWhenReady(Promise.reject(new Error("no window")));
  failed();
  let removed = 0;
  const stop = unlistenWhenReady(Promise.resolve(() => { removed++; }));
  await new Promise((r) => setTimeout(r, 0));
  stop();
  stop();
  assert.equal(removed, 1);
});
