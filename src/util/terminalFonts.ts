// Bundled monospace fonts for the terminal. Loaded once, app-wide, via their
// fontsource CSS imports in main.tsx (400 + 700 weight each) — so rendering
// is identical regardless of what's actually installed on the host OS,
// instead of silently falling through a system-font stack (which is what
// the previous 'Consolas, "Courier New", monospace' stack did on Linux,
// where neither of the first two is normally installed). All five are SIL
// Open Font License 1.1 (see NOTICE and package-lock.json for provenance).
export type TerminalFont = { id: string; label: string; family: string };

export const TERMINAL_FONTS: TerminalFont[] = [
  { id: "jetbrains-mono", label: "JetBrains Mono", family: '"JetBrains Mono", monospace' },
  { id: "fira-code", label: "Fira Code", family: '"Fira Code", monospace' },
  { id: "cascadia-code", label: "Cascadia Code", family: '"Cascadia Code", monospace' },
  { id: "ibm-plex-mono", label: "IBM Plex Mono", family: '"IBM Plex Mono", monospace' },
  { id: "source-code-pro", label: "Source Code Pro", family: '"Source Code Pro", monospace' },
];

export const DEFAULT_TERMINAL_FONT_ID = "jetbrains-mono";

// Shared by terminalFontFamily below and by the Settings font picker's own
// "which row is selected" check — both need the exact same fallback rule
// (an id that no longer matches anything resolves to the actual default,
// not just "whatever happens to be first in the array") or the terminal and
// the Settings UI can end up disagreeing about what's selected.
export function resolveTerminalFontId(id: string | null | undefined): string {
  return TERMINAL_FONTS.some((f) => f.id === id) ? (id as string) : DEFAULT_TERMINAL_FONT_ID;
}

export function terminalFontFamily(id: string | null | undefined): string {
  const resolvedId = resolveTerminalFontId(id);
  return (TERMINAL_FONTS.find((f) => f.id === resolvedId) ?? TERMINAL_FONTS[0]).family;
}
