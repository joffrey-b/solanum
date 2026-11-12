// What the user types into a terminal, as far as the window can tell: the
// line being typed (for command history and snippets, F-023/F-084) and which
// input is not typing at all (xterm's answers to the program's queries).

// xterm answers some queries the program sends (device attributes, status and
// cursor position, mode and setting reports, colours, window size) and reports
// focus changes by sending text through onData, exactly like typed keys. That
// text belongs to this terminal's program only: it is not fanned out to other
// terminals (F-085) and does not change the line being typed. A cursor
// position report looks the same as Shift+F3 (CSI 1;2R).
const REPLY =
  /^(?:\x1b\[[?>]?[\d;]*c|\x1b\[\??\d+(?:;\d+)?[nR]|\x1b\[\??\d+;\d+\$y|\x1bP[01]\$r[^\x1b]*\x1b\\|\x1b\]\d+(?:;\d+)?;rgb:[0-9a-fA-F/]+(?:\x1b\\|\x07)|\x1b\[8;\d+;\d+t|\x1b\[[IO])$/;

export const isTerminalReply = (data: string): boolean => REPLY.test(data);

/** A line submitted with Enter. `start` is where its first character was typed. */
export interface Submitted<T> {
  text: string;
  /** Typed with nothing but printable characters and Backspace since the last
   *  Enter or Ctrl+C, one key at a time or as a one-line paste: what is on the
   *  line is then exactly `text`. */
  consistent: boolean;
  start: T | null;
}

const MAX_LINE = 4096;

/**
 * The line being typed, rebuilt from the keys sent (the shell's own editing is
 * invisible here). Once a key the tracker cannot follow is sent (a cursor or
 * function key, Tab completion, another control key, a paste of several
 * lines), the line is no longer `consistent` until the next Enter or Ctrl+C.
 * `onStart` is asked for a position when the first character of a line is
 * typed; a position the tracker drops unused goes to `onRelease`.
 */
export class LineTracker<T> {
  private chars: string[] = [];
  private ok = true;
  private startedAt: T | null = null;

  constructor(private onStart: () => T | null, private onRelease: (t: T) => void) {}

  get text(): string { return this.chars.join(""); }
  get consistent(): boolean { return this.ok; }
  get start(): T | null { return this.startedAt; }

  /** The run of non-blank characters right before the cursor. */
  currentWord(): string {
    let i = this.chars.length;
    while (i > 0 && !/\s/.test(this.chars[i - 1])) i--;
    return this.chars.slice(i).join("");
  }

  /** The last word was replaced by `text` (a snippet expansion). */
  replaceWord(word: string, text: string) {
    const n = Array.from(word).length;
    this.chars.splice(this.chars.length - n, n);
    for (const c of text) this.typed(c);
  }

  /** Feeds one chunk of input (one onData call); returns the lines it submitted. */
  feed(data: string): Submitted<T>[] {
    const out: Submitted<T>[] = [];
    if (isTerminalReply(data)) return out;
    // A chunk holding a line break that is not a lone Enter key is a paste of
    // several lines: none of it is typed input.
    const severalLines = data.length > 1 && /[\r\n]/.test(data);
    if (severalLines) this.ok = false;
    const cps = Array.from(data);
    for (let i = 0; i < cps.length; i++) {
      const c = cps[i];
      const cp = c.codePointAt(0)!;
      if (c === "\r" || c === "\n") {
        if (c === "\n" && cps[i - 1] === "\r") continue;
        out.push({ text: this.text, consistent: this.ok, start: this.startedAt });
        this.chars = [];
        this.startedAt = null;
        this.ok = !severalLines;
      } else if (c === "\x7f" || c === "\b") {
        this.chars.pop();
      } else if (c === "\x03") {
        this.reset(true);
      } else if (c === "\x15") {
        this.reset(false);
      } else if (c === "\x1b") {
        i = this.escape(cps, i);
      } else if (cp < 0x20 || (cp >= 0x80 && cp <= 0x9f)) {
        this.ok = false;
      } else {
        this.typed(c);
      }
    }
    // A pasted block that ended with a line break leaves a fresh line.
    if (severalLines && /[\r\n]$/.test(data)) this.ok = true;
    return out;
  }

  private typed(c: string) {
    if (c === "\r" || c === "\n" || /[\x00-\x1f\x7f-\x9f]/.test(c)) this.ok = false;
    if (this.chars.length === 0 && this.startedAt === null) this.startedAt = this.onStart();
    this.chars.push(c);
    if (this.chars.length > MAX_LINE) {
      this.chars = this.chars.slice(-MAX_LINE);
      this.ok = false;
    }
  }

  /** Ctrl+C abandons the line; Ctrl+U clears it, but after keys the tracker
   *  could not follow, text after the cursor may remain. */
  private reset(abandon: boolean) {
    this.chars = [];
    if (abandon) this.ok = true;
    if (this.startedAt !== null) this.onRelease(this.startedAt);
    this.startedAt = null;
  }

  /** An escape sequence starting at `i`; returns the index of its last character. */
  private escape(cps: string[], i: number): number {
    const next = cps[i + 1];
    if (next === "[") {
      let j = i + 2;
      while (j < cps.length && !/[\x40-\x7e]/.test(cps[j])) j++;
      const seq = cps.slice(i + 2, j + 1).join("");
      // Bracketed-paste markers around a one-line paste keep it typed text.
      if (seq !== "200~" && seq !== "201~") this.ok = false;
      return j;
    }
    this.ok = false;
    if (next === "O") return i + 2;
    return next === undefined ? i : i + 1;
  }
}

/** What `screenTextFrom` needs of an xterm buffer (`term.buffer.normal`). */
export interface ScreenBuffer {
  getLine(y: number): { isWrapped: boolean; translateToString(trimRight?: boolean, startColumn?: number): string } | undefined;
}

/** The text shown from column `x` of row `y` to the end of that line,
 *  following the rows it wrapped onto. */
export const screenTextFrom = (buffer: ScreenBuffer, y: number, x: number): string => {
  let line = buffer.getLine(y);
  let text = "";
  let column = x;
  while (line) {
    const next = buffer.getLine(y + 1);
    const wraps = !!next && next.isWrapped;
    text += line.translateToString(!wraps, column);
    if (!wraps) break;
    line = next;
    y += 1;
    column = 0;
  }
  return text;
};

/** Is `typed` shown where it was typed? Not at a prompt that does not echo
 *  (a password in any language), nor where each key shows as an asterisk. */
export const echoedAt = (buffer: ScreenBuffer, y: number, x: number, typed: string): boolean => {
  const text = typed.trimEnd();
  return text.length > 0 && screenTextFrom(buffer, y, x).startsWith(text);
};

/** For a snippet, decided as the trigger's delimiter is typed: is the line
 *  shown where it was typed, allowing the echo of the last few keys to be
 *  still on its way? Nothing shown (a prompt that does not echo) or something
 *  else shown (asterisks) is a no. */
export const echoedSoFar = (buffer: ScreenBuffer, y: number, x: number, typed: string): boolean => {
  const text = typed.trimEnd();
  const shown = screenTextFrom(buffer, y, x).trimEnd();
  if (text.length === 0 || shown.length === 0) return false;
  return shown.startsWith(text) || (text.startsWith(shown) && Array.from(text).length - Array.from(shown).length <= 3);
};

/** Bracketed-paste markers inside text a program receives as one paste would
 *  end that paste early and let the rest run as typed (F-083). Removed until
 *  none is left: taking one out can join the pieces of another
 *  (`ESC[20` + `ESC[201~` + `1~`). */
export const withoutPasteMarkers = (text: string): string => {
  let out = text;
  for (let before = ""; before !== out; ) {
    before = out;
    out = out.replace(/\x1b\[20[01]~/g, "");
  }
  return out;
};

/** `text` as the program should receive a paste of it: line breaks as Enter
 *  (CR, as xterm sends them) and, when the program asked for bracketed paste,
 *  between the markers so it takes it as one paste instead of typed lines. */
export const asPaste = (text: string, bracketed: boolean): string => {
  const body = withoutPasteMarkers(text).replace(/\r?\n/g, "\r");
  return bracketed ? `\x1b[200~${body}\x1b[201~` : body;
};

/** What a snippet expansion sends (F-084): one Backspace per code point of the
 *  trigger, the expansion (as a paste when it holds line breaks, so a program
 *  with bracketed paste does not run it line by line), then the delimiter if
 *  it was Space or Tab. Enter is not replayed: it only expands, and the next
 *  Enter runs the line once it has been seen. */
export const snippetKeys = (trigger: string, expansion: string, delimiter: string, bracketed: boolean): string => {
  const erase = "\x7f".repeat(Array.from(trigger).length);
  const body = /[\r\n]/.test(expansion) ? asPaste(expansion, bracketed) : expansion;
  return erase + body + (delimiter === "\r" ? "" : delimiter);
};

/** What a paste would do (F-083). `runsLines`: it holds line breaks and the
 *  program has not asked for bracketed paste, so each line runs as it
 *  arrives. `controls`: control characters other than Tab and line breaks,
 *  which the program may act on. */
export const assessPaste = (text: string, bracketed: boolean): { lines: number; runsLines: boolean; controls: boolean } => {
  const clean = withoutPasteMarkers(text);
  const breaks = (clean.match(/\r\n|\r|\n/g) || []).length;
  return {
    lines: clean.replace(/(?:\r\n|\r|\n)$/, "").split(/\r\n|\r|\n/).length,
    runsLines: breaks > 0 && !bracketed,
    controls: /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/.test(clean),
  };
};
