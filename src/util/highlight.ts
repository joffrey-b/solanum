// Terminal keyword highlighting (MobaXterm-style): a small set of named
// word/color lists, applied to remote output before it's written to xterm.
export type HighlightRule = { id: string; pattern: string; color: string; enabled: boolean };
export type HighlightList = { id: string; name: string; enabled: boolean; rules: HighlightRule[]; builtin?: boolean };
export type HighlightMatcher = { regex: RegExp; colorByKey: Map<string, string> };
export type HighlightMatch = { start: number; end: number; text: string; color: string };

const reds = ["error", "errors", "fail", "failed", "failure", "denied", "refused", "critical", "fatal", "exception", "no"];
const yellows = ["warning", "warn", "timeout", "retry"];
const blues = ["info", "information", "notice", "debug"];
const greens = ["success", "ok", "yes", "done", "connected"];

// Suffixed with a stable per-word id, not Date.now() — every DEFAULT_HIGHLIGHT_LISTS
// consumer treats id as a stable identity key, and a timestamp shared by every
// rule created in the same module-load tick would be a duplicate-id source
// for these specifically. Rules users add later use genId() below instead.
const ruleFor = (word: string, color: string): HighlightRule => ({ id: `default-${word}`, pattern: word, color, enabled: true });

export const DEFAULT_HIGHLIGHT_LISTS: HighlightList[] = [
  {
    id: "default",
    name: "Default",
    enabled: true,
    builtin: true,
    rules: [
      ...reds.map((w) => ruleFor(w, "#f87171")),
      ...yellows.map((w) => ruleFor(w, "#facc15")),
      ...blues.map((w) => ruleFor(w, "#60a5fa")),
      ...greens.map((w) => ruleFor(w, "#4ade80")),
    ],
  },
];

// Date.now() alone can collide (two rows created in the same millisecond get
// the same id, and id doubles as the React key and the update/delete target)
// — the random suffix makes that practically impossible without needing
// crypto.randomUUID(), which not every WebKitGTK build is guaranteed to have.
export function genId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

const escapeRegExp = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const isWordChar = (ch: string | undefined): boolean => !!ch && /[A-Za-z0-9_]/.test(ch);
const asciiLower = (s: string): string => s.replace(/[A-Z]/g, (c) => c.toLowerCase());

// A pattern as UTF-8 output holds it, in the byte-per-character view that
// createHighlighter matches against (R-009): "é" is the two bytes C3 A9 there,
// so a pattern kept as the one character U+00E9 never matched real output,
// and matched the lead byte of other characters instead (splitting them).
const outputView = (pattern: string): string => bytesToLatin1(new TextEncoder().encode(pattern));

// Regex source for one pattern in that view: ASCII letters in either case,
// every other byte exactly. Not the `i` flag: in the byte view it folds UTF-8
// lead bytes into each other (0xC3 "Ã" and 0xE3 "ã"), which would match part
// of another character.
const patternSource = (view: string): string =>
  Array.from(view, (c) => {
    if (/[A-Za-z]/.test(c)) return `[${c.toLowerCase()}${c.toUpperCase()}]`;
    const code = c.charCodeAt(0);
    return code >= 0x80 ? `\\x${code.toString(16).padStart(2, "0")}` : escapeRegExp(c);
  }).join("");

// One combined regex over every enabled rule in every enabled list, plus a
// lowercase-pattern -> color lookup (patterns in the output's byte view,
// lowercase for ASCII only). Returns null when highlighting is off
// or nothing is active, so the hot path in createHighlighter can bail instantly.
//
// Deliberately no `\b` in the regex itself — `\b` is a transition between a
// word char and a non-word char, so a pattern that's ENTIRELY punctuation
// (e.g. "->" or "50%") never has one at either edge and would silently never
// match anything, even surrounded by plain spaces. findHighlightMatches()
// below does the boundary check itself instead, by looking at the actual
// neighboring characters, which works the same way regardless of what kind
// of characters the pattern itself starts or ends with.
//
// If the same word appears in more than one enabled rule (built-in and a
// custom list both defining "error", say), the later list in the array wins
// for colorByKey — deliberate, not arbitrary: it lets a custom list added
// after Default override one of its words by just re-adding it.
export function compileHighlightMatcher(enabled: boolean, lists: HighlightList[]): HighlightMatcher | null {
  if (!enabled) return null;
  const colorByKey = new Map<string, string>();
  const patterns: string[] = [];
  for (const list of lists) {
    if (!list.enabled) continue;
    for (const rule of list.rules) {
      const pattern = rule.pattern.trim();
      if (!rule.enabled || !pattern) continue;
      const view = outputView(pattern);
      colorByKey.set(asciiLower(view), rule.color);
      patterns.push(view);
    }
  }
  if (patterns.length === 0) return null;
  // Longest-first so a multi-word phrase rule isn't pre-empted by a shorter
  // rule matching just part of it.
  patterns.sort((a, b) => b.length - a.length);
  const regex = new RegExp(`(?:${patterns.map(patternSource).join("|")})`, "g");
  return { regex, colorByKey };
}

// Shared by createHighlighter (real terminal output) and the Settings preview,
// so both apply exactly the same boundary rule and can never disagree about
// what would or wouldn't light up.
export function findHighlightMatches(text: string, matcher: HighlightMatcher): HighlightMatch[] {
  const results: HighlightMatch[] = [];
  matcher.regex.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = matcher.regex.exec(text))) {
    const start = m.index;
    const end = start + m[0].length;
    // Whole-match-only: a char adjacent to either edge that's itself a word
    // char means this is part of a larger word (e.g. a "no" rule shouldn't
    // light up "node"), regardless of whether the pattern's own edges are
    // word characters or punctuation.
    if (isWordChar(text[start - 1]) || isWordChar(text[end])) continue;
    const color = matcher.colorByKey.get(asciiLower(m[0]));
    if (!color) continue; // shouldn't happen, but never report a match with no color
    results.push({ start, end, text: m[0], color });
  }
  return results;
}

function hexToRgbInts(hex: string): { r: number; g: number; b: number } {
  const r = parseInt(hex.slice(1, 3), 16) || 0;
  const g = parseInt(hex.slice(3, 5), 16) || 0;
  const b = parseInt(hex.slice(5, 7), 16) || 0;
  return { r, g, b };
}

// Bytes -> a Latin1 (byte-preserving) string, in chunks rather than one
// `String.fromCharCode(...bytes)` spread (which can blow the engine's
// per-call argument limit on a large chunk) or a plain char-by-char `+=`
// loop (slow — this runs on every terminal-output event once highlighting
// is on, and the backend batches output up to 256 KiB specifically to keep
// this hot path cheap). Deliberately NOT `new TextDecoder('latin1')`: despite
// the name, browsers decode that label as windows-1252, not true Latin-1 —
// bytes 0x80-0x9F come back as different characters than their own code
// point, which would silently corrupt the 1:1 byte round-trip this whole
// approach depends on.
const CHUNK = 0x2000;
function bytesToLatin1(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += CHUNK) {
    out += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK) as unknown as number[]);
  }
  return out;
}

// Parser states, as far as highlighting needs them: only GROUND bytes are text
// on screen; everything else belongs to an escape sequence or a control string.
const GROUND = 0, ESC = 1, ESC_INTER = 2, CSI = 3, OSC = 4, STR = 5, STR_ESC = 6, OSC_ESC = 7;

export interface Highlighter {
  /** `bytes` with the matches in its on-screen text coloured. */
  apply(bytes: Uint8Array, matcher: HighlightMatcher | null): Uint8Array;
}

// One per terminal: keywords are coloured only
// in text that is shown, never inside an escape sequence or a control string
// (a window title, an OSC 8 link, a DCS or APC payload), where the colour code
// would end the string and print the rest. The parser state is carried from
// one chunk to the next, so a title split across two output events is still
// a title. Word boundaries are judged on the shown text (escape sequences
// skipped, the last shown character of the previous chunk remembered), and a
// match with an escape sequence inside it is left alone.
//
// Matches against a Latin1 (byte-preserving) view of the bytes, not a UTF-8
// decode: every byte maps 1:1 to a char code 0-255, so this can never
// misinterpret — or split — a multi-byte UTF-8 sequence, even one cut off
// mid-character at the end of this exact chunk (a real risk for a terminal:
// xterm.js's own writer buffers that safely, and a naive per-chunk UTF-8
// decode here would corrupt it into a replacement character instead).
// Patterns are compiled into the same byte view (compileHighlightMatcher), so a
// match is always whole UTF-8 characters: a UTF-8 continuation/lead byte is
// always >=128 and can't form a false ASCII word match, and a non-ASCII
// pattern's bytes are matched exactly. Every other byte is left untouched. C1 controls arrive UTF-8 encoded
// (0xC2 0x80-0x9F), which xterm decodes and obeys like their ESC forms.
// Highlighting is applied by splicing pure-ASCII SGR escape bytes (foreground
// set/reset, not a full reset, so bold/background survive) around each match.
//
// Accepted limitation: a keyword split across two separate *events* (the
// backend coalesces output, so not the common case) isn't caught, and a word
// that ends a chunk counts as ending there.
export function createHighlighter(): Highlighter {
  let state = GROUND;
  // The byte before this chunk was 0xC2 (a C1 control may follow).
  let afterC2 = false;
  let lastShown = "";

  // A C1 control (UTF-8 encoded): the state it starts, or -1.
  const c1 = (b: number): number => {
    if (b === 0x9b) return CSI;
    if (b === 0x9d) return OSC;
    if (b === 0x90 || b === 0x98 || b === 0x9e || b === 0x9f) return STR;
    if (b === 0x9c || b === 0x18 || b === 0x1a) return GROUND;
    return -1;
  };

  return {
    apply(bytes: Uint8Array, matcher: HighlightMatcher | null): Uint8Array {
      if (!matcher) {
        // Not tracked while off: the next chunk after turning it on starts
        // from scratch (a title already open then is the rare loss).
        state = GROUND;
        afterC2 = false;
        lastShown = "";
        return bytes;
      }
      const latin1 = bytesToLatin1(bytes);
      const shownAt: number[] = [];
      for (let i = 0; i < latin1.length; i++) {
        const b = latin1.charCodeAt(i);
        const prevC2 = afterC2;
        afterC2 = b === 0xc2;
        if (prevC2 && b >= 0x80 && b <= 0x9f) {
          const next = c1(b);
          if (state === OSC || state === STR || state === OSC_ESC || state === STR_ESC) {
            if (b === 0x9c || b === 0x18 || b === 0x1a) state = GROUND;
          } else if (next >= 0) {
            state = next;
          }
          // The 0xC2 before it was taken as shown text: take it back.
          if (shownAt.length && shownAt[shownAt.length - 1] === i - 1) shownAt.pop();
          continue;
        }
        if (b === 0x18 || b === 0x1a) { state = GROUND; continue; }
        switch (state) {
          case GROUND:
            if (b === 0x1b) state = ESC;
            else shownAt.push(i);
            break;
          case ESC:
            if (b === 0x5b) state = CSI;
            else if (b === 0x5d) state = OSC;
            else if (b === 0x50 || b === 0x58 || b === 0x5e || b === 0x5f) state = STR;
            else if (b >= 0x20 && b <= 0x2f) state = ESC_INTER;
            else if (b >= 0x30 && b <= 0x7e) state = GROUND;
            break;
          case ESC_INTER:
            if (b === 0x1b) state = ESC;
            else if (b >= 0x30 && b <= 0x7e) state = GROUND;
            break;
          case CSI:
            if (b === 0x1b) state = ESC;
            else if (b >= 0x40 && b <= 0x7e) state = GROUND;
            break;
          case OSC:
            if (b === 0x07) state = GROUND;
            else if (b === 0x1b) state = OSC_ESC;
            break;
          case STR:
            if (b === 0x1b) state = STR_ESC;
            break;
          case OSC_ESC:
          case STR_ESC:
            // ESC \ ends the string; ESC and anything else ends it and starts
            // a new sequence.
            state = b === 0x5c ? GROUND : ESC;
            if (state === ESC) i--;
            break;
        }
      }
      if (shownAt.length === 0) return bytes;
      const shown = shownAt.map((k) => latin1[k]).join("");
      const text = lastShown + shown;
      lastShown = shown[shown.length - 1];
      const offset = text.length - shown.length;
      const pieces: string[] = [];
      let last = 0;
      for (const m of findHighlightMatches(text, matcher)) {
        const start = m.start - offset, end = m.end - offset;
        if (start < 0) continue;
        const from = shownAt[start], to = shownAt[end - 1];
        if (to - from !== end - 1 - start) continue; // an escape sequence inside the word
        const { r, g, b } = hexToRgbInts(m.color);
        pieces.push(latin1.slice(last, from), `\x1b[38;2;${r};${g};${b}m`, latin1.slice(from, to + 1), "\x1b[39m");
        last = to + 1;
      }
      if (pieces.length === 0) return bytes;
      pieces.push(latin1.slice(last));
      const out = pieces.join("");
      const result = new Uint8Array(out.length);
      for (let k = 0; k < out.length; k++) result[k] = out.charCodeAt(k);
      return result;
    },
  };
}
