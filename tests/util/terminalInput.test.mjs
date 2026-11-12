import test from "node:test";
import assert from "node:assert/strict";
import { LineTracker, echoedAt, isTerminalReply } from "./terminalInput.mjs";

const make = () => {
  let n = 0;
  const released = [];
  const t = new LineTracker(() => ++n, (s) => released.push(s));
  return { t, released };
};
// One key per onData call, as typed.
const type = (t, s) => Array.from(s).flatMap((k) => t.feed(k));

test("typed line with Backspace is consistent and starts where typed", () => {
  const { t } = make();
  assert.deepEqual(type(t, "lss\x7f -la\r"), [{ text: "ls -la", consistent: true, start: 1 }]);
});

test("a cursor key, Tab completion or another control key makes the line inconsistent", () => {
  for (const keys of [["l", "s", "\x1b[D", "x", "\r"], ["g", "i", "\t", "\r"], ["l", "s", "\x01", "\r"], ["\x1b[A", "\r"]]) {
    const { t } = make();
    const out = keys.flatMap((k) => t.feed(k));
    assert.equal(out.length, 1);
    assert.equal(out[0].consistent, false, JSON.stringify(keys));
  }
});

test("a paste of several lines is never typed input, the next typed line is", () => {
  const { t } = make();
  const out = t.feed("rm -rf /tmp/x\recho done\r");
  assert.equal(out.length, 2);
  assert.ok(out.every((l) => !l.consistent));
  assert.deepEqual(type(t, "pwd\r").map((l) => l.consistent), [true]);
  const { t: t2 } = make();
  t2.feed("a\rb");
  assert.deepEqual(type(t2, "c\r").map((l) => [l.text, l.consistent]), [["bc", false]]);
});

test("a one-line bracketed paste stays typed text", () => {
  const { t } = make();
  t.feed("\x1b[200~echo hi\x1b[201~");
  assert.deepEqual(t.feed("\r").map((l) => [l.text, l.consistent]), [["echo hi", true]]);
});

test("terminal replies and focus events are not typing", () => {
  for (const r of ["\x1b[?1;2c", "\x1b[>0;276;0c", "\x1b[0n", "\x1b[12;40R", "\x1b[?2004;1$y", "\x1bP1$r0m\x1b\\", "\x1b]11;rgb:0a0a/0a0a/0c0c\x1b\\", "\x1b[I", "\x1b[O"]) {
    assert.ok(isTerminalReply(r), JSON.stringify(r));
    const { t } = make();
    type(t, "ls");
    t.feed(r);
    assert.deepEqual(type(t, " -l\r").map((l) => [l.text, l.consistent]), [["ls -l", true]], JSON.stringify(r));
  }
  for (const k of ["\x1b[A", "a", "\x1b[1;5D", "\x1b[200~"]) assert.ok(!isTerminalReply(k), JSON.stringify(k));
});

test("code points, not UTF-16 units; non-ASCII is kept", () => {
  const { t } = make();
  type(t, "echo caf\u00e9 \ud83d\ude00");
  assert.equal(t.currentWord(), "\ud83d\ude00");
  t.feed("\x7f");
  assert.deepEqual(t.feed("\r").map((l) => [l.text, l.consistent]), [["echo caf\u00e9 ", true]]);
});

test("Ctrl+C starts over consistent, Ctrl+U releases the start", () => {
  const { t, released } = make();
  type(t, "ab\x1b[Dc");
  assert.equal(t.consistent, false);
  t.feed("\x03");
  assert.equal(t.consistent, true);
  assert.deepEqual(released, [1]);
  type(t, "xy");
  t.feed("\x15");
  assert.deepEqual(released, [1, 2]);
  assert.deepEqual(type(t, "pwd\r"), [{ text: "pwd", consistent: true, start: 3 }]);
});

test("replacing the last word (snippet) keeps it consistent unless the text has line breaks", () => {
  const { t } = make();
  type(t, "sudo gst");
  t.replaceWord("gst", "git status");
  assert.equal(t.text, "sudo git status");
  assert.equal(t.consistent, true);
  t.replaceWord("status", "a\nb");
  assert.equal(t.consistent, false);
});

// A fake xterm buffer: rows of text, wrapped rows marked.
const screen = (rows) => ({
  getLine: (y) => rows[y] === undefined ? undefined : {
    isWrapped: rows[y].wrapped ?? false,
    translateToString: (trim, start = 0) => { const s = rows[y].text.slice(start); return trim ? s.replace(/ +$/, "") : s; },
  },
});

test("echo check: what was typed is on screen where it was typed", () => {
  const prompt = "user@host:~$ ";
  assert.ok(echoedAt(screen([{ text: prompt + "ls -la" }]), 0, prompt.length, "ls -la"));
  assert.ok(echoedAt(screen([{ text: prompt + "ls -la       [main]" }]), 0, prompt.length, "ls -la"), "right prompt");
  const long = "echo " + "a".repeat(80);
  const row0 = (prompt + long).slice(0, 80), row1 = (prompt + long).slice(80);
  assert.ok(echoedAt(screen([{ text: row0 }, { text: row1, wrapped: true }]), 0, prompt.length, long), "wrapped");
  const p = "[sudo] password for u: ";
  assert.ok(!echoedAt(screen([{ text: p }]), 0, p.length, "hunter22"), "no echo");
  assert.ok(!echoedAt(screen([{ text: p + "********" }]), 0, p.length, "hunter22"), "asterisks");
  assert.ok(!echoedAt(screen([{ text: "Passwort: " }]), 0, 10, "geheim123"), "any language");
  assert.ok(!echoedAt(screen([{ text: prompt + "ls" }]), 0, prompt.length, "   "), "blank");
});

