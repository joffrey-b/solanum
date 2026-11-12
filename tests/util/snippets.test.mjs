import test from "node:test";
import assert from "node:assert/strict";
import { snippetKeys, echoedSoFar, asPaste, withoutPasteMarkers } from "./terminalInput.mjs";

export const SNIPPET_CASES = [
  // trigger, expansion, delimiter, bracketed, expected
  ["gst", "git status", " ", false, "\x7f\x7f\x7fgit status "],
  ["\ud83d\ude80", "deploy", " ", false, "\x7fdeploy "],
  ["caf\u00e9", "coffee", "\t", false, "\x7f\x7f\x7f\x7fcoffee\t"],
  ["gst", "git status", "\r", false, "\x7f\x7f\x7fgit status"],
  ["dep", "make\nmake install", "\r", true, "\x7f\x7f\x7f\x1b[200~make\rmake install\x1b[201~"],
];

test("snippet keys: one Backspace per code point, Enter never replayed, line breaks pasted", () => {
  for (const [trigger, expansion, delim, bracketed, want] of SNIPPET_CASES) {
    assert.equal(snippetKeys(trigger, expansion, delim, bracketed), want, JSON.stringify([trigger, delim]));
  }
});

const screen = (text) => ({ getLine: (y) => y === 0 ? { isWrapped: false, translateToString: (trim, start = 0) => { const s = text.slice(start); return trim ? s.replace(/ +$/, "") : s; } } : undefined });

test("snippet echo check allows the last keys' echo to be on its way, nothing more", () => {
  const p = "$ ";
  assert.ok(echoedSoFar(screen(p + "sudo gst"), 0, 2, "sudo gst"));
  assert.ok(echoedSoFar(screen(p + "sudo g"), 0, 2, "sudo gst"), "two keys still on their way");
  assert.ok(!echoedSoFar(screen(p + "su"), 0, 2, "sudo gst"), "too far behind");
  assert.ok(!echoedSoFar(screen("Password: "), 0, 10, "gst"), "no echo");
  assert.ok(!echoedSoFar(screen("Password: ***"), 0, 10, "gst"), "asterisks");
});

test("a paste never carries bracketed-paste markers of its own", () => {
  assert.equal(withoutPasteMarkers("a\x1b[201~rm -rf ~\r"), "arm -rf ~\r");
  assert.equal(asPaste("one\r\ntwo\nthree", false), "one\rtwo\rthree");
  assert.equal(asPaste("x\x1b[201~y", true), "\x1b[200~xy\x1b[201~");
});
