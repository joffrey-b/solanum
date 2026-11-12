// Built-in terminal color themes, plus the "app" theme that isn't a fixed
// palette at all — it derives background/cursor/selection from the user's
// own Appearance accent + background colors, which is what makes e.g.
// setting the background to pure #000000 for an OLED screen actually reach
// the terminal instead of just the app's own chrome.
//
// Named themes use each project's own well-known, widely-published 16-color
// ANSI mapping (the same values shipped in their official iTerm2/Windows
// Terminal/Alacritty profiles) so programs that lean on color — ls, git
// diff, vim, htop — look authentic, not just a background/foreground swap.

export interface TerminalThemeColors {
  background: string;
  foreground: string;
  cursor: string;
  selectionBackground: string;
  // Optional: "app" deliberately leaves these unset so xterm's own sensible
  // built-in ANSI defaults show through — it's meant to be "my accent +
  // background colors, otherwise untouched", not a fixed palette.
  black?: string; red?: string; green?: string; yellow?: string;
  blue?: string; magenta?: string; cyan?: string; white?: string;
  brightBlack?: string; brightRed?: string; brightGreen?: string; brightYellow?: string;
  brightBlue?: string; brightMagenta?: string; brightCyan?: string; brightWhite?: string;
}

export interface TerminalTheme {
  id: string;
  label: string;
  // null for "app" — see resolveTerminalTheme, which fills this in from the
  // user's own accent/background picks instead of a fixed palette.
  colors: TerminalThemeColors | null;
}

// primaryColor comes from Settings' free-text hex field (the paired
// <input type="color"> always yields a valid 6-digit hex, but that text
// field doesn't validate anything typed into it), so this has to tolerate
// 3-digit shorthand and outright garbage rather than silently mis-slicing
// a wrong-but-plausible-looking color out of it.
const HEX_COLOR_RE = /^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;
export const hexToRgba = (hex: string, alpha: number): string => {
  if (!HEX_COLOR_RE.test(hex)) return `rgba(96, 165, 250, ${alpha})`; // the app's own original default accent blue
  const full = hex.length === 4 ? `#${hex[1]}${hex[1]}${hex[2]}${hex[2]}${hex[3]}${hex[3]}` : hex;
  const r = parseInt(full.slice(1, 3), 16);
  const g = parseInt(full.slice(3, 5), 16);
  const b = parseInt(full.slice(5, 7), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha})`;
};

export const TERMINAL_THEMES: TerminalTheme[] = [
  { id: "app", label: "Match App Colors", colors: null },
  {
    id: "oled-black",
    label: "OLED Black",
    colors: {
      background: "#000000", foreground: "#e4e4e7", cursor: "#60a5fa",
      selectionBackground: "rgba(96, 165, 250, 0.3)",
      black: "#000000", red: "#ff5555", green: "#50fa7b", yellow: "#f1fa8c",
      blue: "#60a5fa", magenta: "#ff79c6", cyan: "#8be9fd", white: "#e4e4e7",
      brightBlack: "#4d4d4d", brightRed: "#ff6e6e", brightGreen: "#69ff94", brightYellow: "#ffffa5",
      brightBlue: "#93ddff", brightMagenta: "#ff92df", brightCyan: "#a4ffff", brightWhite: "#ffffff",
    },
  },
  {
    id: "dracula",
    label: "Dracula",
    colors: {
      background: "#282a36", foreground: "#f8f8f2", cursor: "#f8f8f2",
      selectionBackground: "rgba(68, 71, 90, 0.6)",
      black: "#21222c", red: "#ff5555", green: "#50fa7b", yellow: "#f1fa8c",
      blue: "#bd93f9", magenta: "#ff79c6", cyan: "#8be9fd", white: "#f8f8f2",
      brightBlack: "#6272a4", brightRed: "#ff6e6e", brightGreen: "#69ff94", brightYellow: "#ffffa5",
      brightBlue: "#d6acff", brightMagenta: "#ff92df", brightCyan: "#a4ffff", brightWhite: "#ffffff",
    },
  },
  {
    id: "nord",
    label: "Nord",
    colors: {
      background: "#2e3440", foreground: "#d8dee9", cursor: "#d8dee9",
      selectionBackground: "rgba(67, 76, 94, 0.8)",
      black: "#3b4252", red: "#bf616a", green: "#a3be8c", yellow: "#ebcb8b",
      blue: "#81a1c1", magenta: "#b48ead", cyan: "#88c0d0", white: "#e5e9f0",
      brightBlack: "#4c566a", brightRed: "#bf616a", brightGreen: "#a3be8c", brightYellow: "#ebcb8b",
      brightBlue: "#81a1c1", brightMagenta: "#b48ead", brightCyan: "#8fbcbb", brightWhite: "#eceff4",
    },
  },
  {
    id: "solarized-dark",
    label: "Solarized Dark",
    colors: {
      background: "#002b36", foreground: "#839496", cursor: "#839496",
      selectionBackground: "rgba(7, 54, 66, 0.8)",
      black: "#073642", red: "#dc322f", green: "#859900", yellow: "#b58900",
      blue: "#268bd2", magenta: "#d33682", cyan: "#2aa198", white: "#eee8d5",
      brightBlack: "#002b36", brightRed: "#cb4b16", brightGreen: "#586e75", brightYellow: "#657b83",
      brightBlue: "#839496", brightMagenta: "#6c71c4", brightCyan: "#93a1a1", brightWhite: "#fdf6e3",
    },
  },
  {
    id: "gruvbox-dark",
    label: "Gruvbox Dark",
    colors: {
      background: "#282828", foreground: "#ebdbb2", cursor: "#ebdbb2",
      selectionBackground: "rgba(60, 56, 54, 0.8)",
      black: "#282828", red: "#cc241d", green: "#98971a", yellow: "#d79921",
      blue: "#458588", magenta: "#b16286", cyan: "#689d6a", white: "#a89984",
      brightBlack: "#928374", brightRed: "#fb4934", brightGreen: "#b8bb26", brightYellow: "#fabd2f",
      brightBlue: "#83a598", brightMagenta: "#d3869b", brightCyan: "#8ec07c", brightWhite: "#ebdbb2",
    },
  },
  {
    id: "one-dark",
    label: "One Dark",
    colors: {
      background: "#282c34", foreground: "#abb2bf", cursor: "#528bff",
      selectionBackground: "rgba(62, 68, 81, 0.8)",
      black: "#282c34", red: "#e06c75", green: "#98c379", yellow: "#e5c07b",
      blue: "#61afef", magenta: "#c678dd", cyan: "#56b6c2", white: "#abb2bf",
      brightBlack: "#5c6370", brightRed: "#e06c75", brightGreen: "#98c379", brightYellow: "#e5c07b",
      brightBlue: "#61afef", brightMagenta: "#c678dd", brightCyan: "#56b6c2", brightWhite: "#ffffff",
    },
  },
  {
    id: "monokai",
    label: "Monokai",
    colors: {
      background: "#272822", foreground: "#f8f8f2", cursor: "#f8f8f0",
      selectionBackground: "rgba(73, 72, 62, 0.8)",
      black: "#272822", red: "#f92672", green: "#a6e22e", yellow: "#f4bf75",
      blue: "#66d9ef", magenta: "#ae81ff", cyan: "#a1efe4", white: "#f8f8f2",
      brightBlack: "#75715e", brightRed: "#f92672", brightGreen: "#a6e22e", brightYellow: "#f4bf75",
      brightBlue: "#66d9ef", brightMagenta: "#ae81ff", brightCyan: "#a1efe4", brightWhite: "#f9f8f5",
    },
  },
];

export const DEFAULT_TERMINAL_THEME_ID = "app";

// User-created themes, on top of the built-in list above — same shape
// (TerminalTheme with non-null colors), persisted per-device like every
// other appearance preference. A plain module-level localStorage read
// rather than something passed in from a caller: TerminalView's own
// loadTerminalTheme() already reads several keys directly the same way, and
// resolveTerminalTheme/resolveTerminalThemeId below need to see custom
// themes too (a terminal resolving "my-custom-id" has no other way to find
// it), so threading it through every call site's signature instead would
// just move the same localStorage read to each of them.
const CUSTOM_TERMINAL_THEMES_KEY = "solanum-custom-terminal-themes";

export function loadCustomTerminalThemes(): TerminalTheme[] {
  try {
    const raw = localStorage.getItem(CUSTOM_TERMINAL_THEMES_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch { return []; }
}

export function saveCustomTerminalThemes(themes: TerminalTheme[]): void {
  try { localStorage.setItem(CUSTOM_TERMINAL_THEMES_KEY, JSON.stringify(themes)); }
  catch { /* quota or private-mode storage — ignore */ }
}

// The full picker list: built-ins first, then whatever the user has saved.
export function allTerminalThemes(): TerminalTheme[] {
  return [...TERMINAL_THEMES, ...loadCustomTerminalThemes()];
}

// Same fallback-resolution shape as resolveTerminalFontId — an id that no
// longer matches anything (a stale localStorage value after a theme is ever
// renamed/removed) resolves to the actual default, not array[0] by accident.
export function resolveTerminalThemeId(id: string | null | undefined): string {
  return allTerminalThemes().some((t) => t.id === id) ? (id as string) : DEFAULT_TERMINAL_THEME_ID;
}

// Resolves a theme id into the actual xterm theme object to hand the
// terminal. For "app", background/cursor/selection are derived live from
// the user's own Appearance picks (foreground stays a fixed neutral — there
// is no separate "foreground color" setting to derive it from) rather than
// a fixed palette, which is what makes the Appearance background color
// actually reach the terminal instead of stopping at the app's own chrome.
export function resolveTerminalTheme(
  id: string | null | undefined,
  primaryColor: string,
  backgroundColor: string,
): TerminalThemeColors {
  const resolvedId = resolveTerminalThemeId(id);
  const def = allTerminalThemes().find((t) => t.id === resolvedId) ?? TERMINAL_THEMES[0];
  if (def.colors) return def.colors;
  return {
    background: backgroundColor,
    foreground: "#e4e4e7",
    cursor: primaryColor,
    selectionBackground: hexToRgba(primaryColor, 0.3),
  };
}
