// Text a server chose (a file name, a path, an error that quotes one) exactly
// as it is, except that invisible and direction-changing characters are spelled
// out. Without this a hostile server could name a file "invoice\u202Efdp.exe",
// which renders as "invoiceexe.pdf" (U+202E reverses the text after it) -- the
// classic way to make a program look like a document -- or hide look-alike
// duplicates behind zero-width characters. Covers C0/C1 controls, soft hyphen,
// combining grapheme joiner,
// bidi marks, embeddings, overrides and isolates, zero-width and invisible
// fillers, interlinear annotation marks and the invisible tag characters.
// Use it for display only, never for a value that is sent back (a rename
// field must keep the real name).
const HIDDEN_OR_DIRECTIONAL =
  /[\u0000-\u001f\u007f-\u009f\u00ad\u034f\u061c\u115f\u1160\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\u3164\ufeff\uffa0\ufff9-\ufffb\u{e0000}-\u{e007f}]/gu;

export const visibleName = (name: string): string =>
  name.replace(HIDDEN_OR_DIRECTIONAL, (c) => {
    const cp = c.codePointAt(0)!;
    return cp > 0xffff ? `\\u{${cp.toString(16)}}` : `\\u${cp.toString(16).padStart(4, "0")}`;
  });

// Multi-line server text (a keyboard-interactive banner): the same, line by
// line, so line breaks stay line breaks and tabs become spaces.
export const visibleText = (text: string): string =>
  text
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .map((line) => visibleName(line.replace(/\t/g, "    ")))
    .join("\n");

// The text with hidden and direction-changing characters removed and
// compatibility forms folded (NFKC), for matching words in server text that
// may try to dodge the match ("Pass\u200bword").
export const withoutHidden = (text: string): string =>
  text.normalize("NFKC").replace(HIDDEN_OR_DIRECTIONAL, "");
