import test from "node:test";
import assert from "node:assert/strict";
import { startLiveStream } from "./liveStream.mjs";

const tick = () => new Promise((r) => setTimeout(r, 0));

// A fake backend: listeners, a stream that exists once start() resolves, and
// start/stop calls the test can hold back.
const backend = () => {
  const handlers = new Map();
  const streams = new Set();
  const gates = { listen: null, start: null };
  const log = [];
  const hold = (name) => { let open; gates[name] = new Promise((r) => { open = r; }); return () => { gates[name] = null; open(); }; };
  return {
    log, streams, hold,
    count: () => [...handlers.values()].reduce((n, s) => n + s.size, 0),
    emit: (name, payload) => { for (const h of handlers.get(name) || []) h(payload); },
    opts: (extra = {}) => ({
      dataEvent: "docker-logs-s1",
      closedEvent: "docker-logs-closed-s1",
      listen: async (name, h) => {
        if (gates.listen) await gates.listen;
        handlers.set(name, (handlers.get(name) || new Set()).add(h));
        return () => handlers.get(name).delete(h);
      },
      start: async () => { log.push("start"); if (gates.start) await gates.start; streams.add("s1"); },
      stop: async () => { log.push("stop"); streams.delete("s1"); },
      onData: () => {},
      onEnd: () => {},
      ...extra,
    }),
  };
};

test("Stop while the listeners are being registered: no stream is started and no listener is left (F-051)", async () => {
  const b = backend();
  const release = b.hold("listen");
  let ended = 0;
  const run = startLiveStream(b.opts({ onEnd: () => ended++ }));
  await tick();
  run.stop();
  release();
  await tick(); await tick();
  assert.deepEqual(b.log, []);
  assert.equal(b.streams.size, 0);
  assert.equal(b.count(), 0);
  assert.equal(ended, 1);
});

test("Stop while the start is on its way: the stream is stopped once it exists", async () => {
  const b = backend();
  const release = b.hold("start");
  const run = startLiveStream(b.opts());
  await tick(); await tick();
  assert.deepEqual(b.log, ["start"]);
  run.stop();
  release();
  await tick(); await tick();
  assert.equal(b.streams.size, 0, "stream left running on the server");
  assert.equal(b.count(), 0);
});

test("Stop during the initial tail fetch: nothing else happens", async () => {
  const b = backend();
  let finishFetch;
  const run = startLiveStream(b.opts({ before: () => new Promise((r) => { finishFetch = r; }) }));
  run.stop();
  finishFetch();
  await tick(); await tick();
  assert.deepEqual(b.log, []);
  assert.equal(b.count(), 0);
});

test("the server closing the stream removes both listeners and ends the run once", async () => {
  const b = backend();
  const seen = [];
  let ends = 0;
  const run = startLiveStream(b.opts({ onData: (p) => seen.push(p), onEnd: () => ends++ }));
  await tick(); await tick();
  b.emit("docker-logs-s1", "line 1\n");
  b.emit("docker-logs-closed-s1", null);
  assert.equal(b.count(), 0, "listeners still registered after the stream closed");
  assert.equal(run.ended, true);
  run.stop();
  assert.equal(ends, 1);
  assert.deepEqual(b.log, ["start"], "no stop sent for a stream the server already ended");
  assert.deepEqual(seen, ["line 1\n"]);
});

test("a normal stop: stream stopped, listeners gone, later data ignored", async () => {
  const b = backend();
  const seen = [];
  const run = startLiveStream(b.opts({ onData: (p) => seen.push(p) }));
  await tick(); await tick();
  assert.equal(b.streams.size, 1);
  run.stop();
  await tick();
  assert.deepEqual(b.log, ["start", "stop"]);
  assert.equal(b.streams.size, 0);
  assert.equal(b.count(), 0);
  b.emit("docker-logs-s1", "late");
  assert.deepEqual(seen, []);
});

test("a failed start ends the run with its error and leaves no listener", async () => {
  const b = backend();
  let error;
  startLiveStream(b.opts({ start: async () => { throw "no such container"; }, onEnd: (e) => { error = e; } }));
  await tick(); await tick();
  assert.equal(error, "no such container");
  assert.equal(b.count(), 0);
});

test("the initial tail fetch failing ends the run with its error, nothing started", async () => {
  const b = backend();
  let error;
  startLiveStream(b.opts({ before: async () => { throw "logs failed"; }, onEnd: (e) => { error = e; } }));
  await tick(); await tick();
  assert.equal(error, "logs failed");
  assert.deepEqual(b.log, []);
  assert.equal(b.count(), 0);
});

test("the server closing the stream before the start answered: one end, no listener left", async () => {
  const b = backend();
  const release = b.hold("start");
  let ends = 0;
  const run = startLiveStream(b.opts({ onEnd: () => ends++ }));
  await tick(); await tick();
  b.emit("docker-logs-closed-s1", null);
  release();
  await tick(); await tick();
  assert.equal(run.ended, true);
  assert.equal(ends, 1);
  assert.equal(b.count(), 0);
  assert.equal(b.streams.size, 0, "a stream that registered after the close is stopped");
});
