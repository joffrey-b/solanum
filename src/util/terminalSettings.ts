// Terminal scrollback (F-031). xterm keeps roughly 12 bytes per cell, so a
// million 80-column lines is about 1 GB for one terminal: the setting is
// capped. "Always save terminal output to file" keeps everything instead.
export const DEFAULT_SCROLLBACK = 100_000;
export const MIN_SCROLLBACK = 1_000;
export const MAX_SCROLLBACK = 1_000_000;

export const clampScrollback = (n: number): number =>
  Number.isFinite(n) ? Math.min(MAX_SCROLLBACK, Math.max(MIN_SCROLLBACK, Math.round(n))) : DEFAULT_SCROLLBACK;

export const loadScrollback = (): number => {
  const raw = localStorage.getItem('solanum-terminal-scrollback');
  return raw === null ? DEFAULT_SCROLLBACK : clampScrollback(parseInt(raw, 10));
};

// Ask before a paste that holds control characters, or line breaks the program
// would run one by one (F-083). On unless turned off in Settings > Terminal.
export const loadConfirmRiskyPaste = (): boolean => localStorage.getItem('solanum-confirm-risky-paste') !== '0';
