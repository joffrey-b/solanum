import test from "node:test";
import assert from "node:assert/strict";
import { assessPaste, asPaste, withoutPasteMarkers } from "./terminalInput.mjs";

// [clipboard, bracketed paste on, what the program must receive]
export const PASTE_CASES = [
  ["ls -la", false, "ls -la"],
  ["echo a\r\necho b\n", true, "\x1b[200~echo a\recho b\r\x1b[201~"],
  ["x\x1b[201~rm -rf ~\n", true, "\x1b[200~xrm -rf ~\r\x1b[201~"],
];

test("a paste reaches the program bracketed when asked, without markers of its own", () => {
  for (const [text, bracketed, want] of PASTE_CASES) assert.equal(asPaste(text, bracketed), want, JSON.stringify(text));
});

test("which pastes ask first", () => {
  assert.deepEqual(assessPaste("ls -la", false), { lines: 1, runsLines: false, controls: false });
  assert.deepEqual(assessPaste("ls -la\n", false), { lines: 1, runsLines: true, controls: false }, "a trailing line break runs it");
  assert.deepEqual(assessPaste("a\r\nb\nc", false), { lines: 3, runsLines: true, controls: false });
  assert.deepEqual(assessPaste("a\nb", true), { lines: 2, runsLines: false, controls: false }, "bracketed: the shell waits for Enter");
  assert.equal(assessPaste("a\tb", false).controls, false, "Tab is fine");
  for (const c of ["\x03", "\x1b[A", "\x12", "\x7f", "\u009b"]) assert.equal(assessPaste("a" + c, true).controls, true, JSON.stringify(c));
  assert.equal(assessPaste("\x1b[201~", true).controls, false, "markers are removed before the check");
});

test("markers are removed until none is left (one can hide inside another)", () => {
  assert.equal(withoutPasteMarkers("\x1b[20\x1b[201~1~rm -rf ~\r"), "rm -rf ~\r");
  assert.equal(withoutPasteMarkers("a\x1b[20\x1b[20\x1b[201~1~1~b"), "ab", "twice nested");
  assert.equal(asPaste("\x1b[20\x1b[201~1~x", true), "\x1b[200~x\x1b[201~");
});
