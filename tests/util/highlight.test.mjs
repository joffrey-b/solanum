import test from "node:test";
import assert from "node:assert/strict";
import { createHighlighter, compileHighlightMatcher, DEFAULT_HIGHLIGHT_LISTS } from "./highlight.mjs";

export const matcher = compileHighlightMatcher(true, DEFAULT_HIGHLIGHT_LISTS);
export const bytes = (s) => Uint8Array.from(Array.from(s, (c) => c.charCodeAt(0)));
export const str = (b) => String.fromCharCode(...b);
const RED = "\x1b[38;2;248;113;113m", GREEN = "\x1b[38;2;74;222;128m", OFF = "\x1b[39m";

// [chunks, expected output of the last chunk]
export const CASES = [
  ["plain text", ["an error here"], `an ${RED}error${OFF} here`],
  ["window title", ["\x1b]0;error log\x07done"], `\x1b]0;error log\x07${GREEN}done${OFF}`],
  ["OSC 8 link", ["\x1b]8;;https://x/error\x1b\\error\x1b]8;;\x1b\\"], `\x1b]8;;https://x/error\x1b\\${RED}error${OFF}\x1b]8;;\x1b\\`],
  ["DCS payload", ["\x1bPq#0;error\x1b\\"], "\x1bPq#0;error\x1b\\"],
  ["APC payload", ["\x1b_Gfailed=1\x1b\\"], "\x1b_Gfailed=1\x1b\\"],
  ["title split across chunks", ["\x1b]0;fatal ", "error\x07"], "error\x07"],
  ["bold word", ["\x1b[1merror\x1b[0m"], `\x1b[1m${RED}error${OFF}\x1b[0m`],
  ["word glued to text across a colour code", ["foo\x1b[1merror"], "foo\x1b[1merror"],
  ["colour code inside the word", ["err\x1b[1mor"], "err\x1b[1mor"],
  ["word glued to the previous chunk", ["x", "error"], "error"],
  ["UTF-8 C1 OSC", ["\xc2\x9d0;error\x07"], "\xc2\x9d0;error\x07"],
  ["UTF-8 kept", ["caf\xc3\xa9 error"], `caf\xc3\xa9 ${RED}error${OFF}`],
];

test("highlighting colours shown text only, across chunks", () => {
  for (const [name, chunks, want] of CASES) {
    const h = createHighlighter();
    let out = "";
    for (const c of chunks) out = str(h.apply(bytes(c), matcher));
    assert.equal(JSON.stringify(out), JSON.stringify(want), name);
  }
});

test("off means untouched, and starting over afterwards", () => {
  const h = createHighlighter();
  const b = bytes("\x1b]0;error");
  assert.equal(h.apply(b, null), b);
  assert.equal(str(h.apply(bytes("error"), matcher)), `${RED}error${OFF}`);
});

// R-009: a pattern with letters beyond ASCII is matched as the UTF-8 bytes the
// output holds: whole characters, never part of one, and case-insensitive for
// its ASCII letters only (the byte view folds UTF-8 lead bytes into each other).
test("a non-ASCII pattern colours whole UTF-8 characters and nothing else (R-009)", () => {
  const rule = (id, pattern) => ({ id, pattern, color: "#f87171", enabled: true });
  const m = compileHighlightMatcher(true, [{ id: "u", name: "u", enabled: true, rules: [rule("e", "é"), rule("c", "Café")] }]);
  const run = (s) => str(createHighlighter().apply(bytes(s), m));
  assert.equal(JSON.stringify(run("un caf\xc3\xa9 ici")), JSON.stringify(`un ${RED}caf\xc3\xa9${OFF} ici`), "matched as UTF-8");
  assert.equal(JSON.stringify(run("CAF\xc3\xa9 x")), JSON.stringify(`${RED}CAF\xc3\xa9${OFF} x`), "ASCII letters in either case");
  assert.equal(JSON.stringify(run("a \xc3\xa9 b")), JSON.stringify(`a ${RED}\xc3\xa9${OFF} b`), "the character alone");
  // U+9640 starts with 0xE9, which is "é" in the byte view; U+3A40 starts with
  // 0xE3 0xA9, a case variant of é's 0xC3 0xA9 there; U+0250 starts with 0xC9 ("É").
  for (const other of ["\xe9\x99\x80", "\xe3\xa9\x80", "\xc9\x90"]) {
    assert.equal(JSON.stringify(run(`x ${other} y`)), JSON.stringify(`x ${other} y`), `split ${JSON.stringify(other)}`);
  }
});
