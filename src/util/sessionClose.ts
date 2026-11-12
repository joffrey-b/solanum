// Shared "does closing this need a confirmation" logic. Used from both
// DesktopApp.tsx (closing a session's own top-level tab) and SessionView.tsx
// (closing one of its clone tabs, or cascading to the whole session when the
// last clone tab closes) so the two places can't drift out of sync the way
// they had — the top tab warned before a close, a clone tab never did.

export interface EndableTerminal {
  ended?: boolean;
}

// A single terminal / clone tab. Warn only if the setting is on AND its own
// shell hasn't already ended — once "Session stopped" has printed there's
// nothing live left in that specific tab to lose.
export function terminalCloseNeedsConfirm(
  terminal: EndableTerminal | undefined,
  warnEnabled: boolean,
): boolean {
  return warnEnabled && !!terminal && !terminal.ended;
}

// The whole session — closing its own top tab, or cascading from the last
// remaining clone tab closing. Warn only while actually connected AND at
// least one terminal in it hasn't ended yet: if every terminal has already
// printed "Session stopped", the underlying multiplexed connection may
// technically still be open, but there's no live shell left anywhere in the
// session worth confirming a drop for.
export function sessionCloseNeedsConfirm(
  terminals: EndableTerminal[],
  connectionStatus: string | undefined,
  warnEnabled: boolean,
): boolean {
  if (!warnEnabled || connectionStatus !== "connected") return false;
  const allEnded = terminals.length > 0 && terminals.every((t) => t.ended);
  return !allEnded;
}
