import { useEffect, useRef, useState } from 'react';
import { Terminal, IMarker } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { SearchAddon, ISearchOptions } from 'xterm-addon-search';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import 'xterm/css/xterm.css';
import { useIsNarrow } from '../hooks/useViewport';
import { MobileKeyBar, ModifiersState, ModKey } from './MobileKeyBar';
import { useBroadcast } from '../ui/broadcast';
import HistorySearchOverlay from './HistorySearchOverlay';
import { compileHighlightMatcher, createHighlighter, DEFAULT_HIGHLIGHT_LISTS, HighlightMatcher, HighlightList } from '../util/highlight';
import { createPortal } from 'react-dom';
import { terminalFontFamily } from '../util/terminalFonts';
import { resolveTerminalTheme } from '../util/terminalThemes';
import { buildSessionLogPath } from '../util/sessionLogging';
import { loadConfirmRiskyPaste, loadScrollback } from '../util/terminalSettings';
import { asPaste, assessPaste, echoedAt, echoedSoFar, isTerminalReply, LineTracker, snippetKeys, Submitted, withoutPasteMarkers } from '../util/terminalInput';
import { looksLikeSecretPrompt } from '../util/secretPrompt';
import { isRecordingPaused } from '../util/historyRecording';
import { useConfirm } from '../ui/confirm';
import { visibleName, visibleText } from '../util/visibleName';

// The terminal runs, but its "Always save terminal output to file" log could
// not be started: the open command returns why, shown as one yellow line in
// this terminal (N-007). Written locally, so it is not output the backend
// counts for acknowledgements. The shell may already be printing: the line
// starts on a line of its own and resets only the colour it set, so the
// program's other attributes are left as they were (review of batch 11).
const writeLogProblem = (term: Terminal, problem: unknown) => {
  if (typeof problem === 'string' && problem) term.write(`\r\n\x1b[33m[Solanum: ${visibleName(problem)}]\x1b[39m\r\n`);
};

const loadPuttyClipboard = (): boolean => localStorage.getItem('solanum-putty-clipboard') !== '0';
// Off by default — unlike the other toggles here, this one gates whether
// Ctrl+R is intercepted AT ALL, not just how something already-shown looks.
const loadUseCommandHistorySearch = (): boolean => localStorage.getItem('solanum-use-command-history-search') === '1';
// Off by default — same reasoning as Ctrl+R: typing should only ever produce
// what was typed unless the user opted in. Gates whether the onData handler
// even looks for a trigger match, not just whether one happens to be defined.
const loadUseTextSnippets = (): boolean => localStorage.getItem('solanum-use-text-snippets') === '1';
// The "app" theme (default) derives its colors from the same two keys
// DesktopApp's own Appearance picker writes — reading them here (rather
// than threading them down as props) is what makes e.g. an OLED-black
// background setting actually reach the terminal, not just the app chrome.
const loadTerminalTheme = () => resolveTerminalTheme(
  localStorage.getItem('solanum-terminal-theme'),
  localStorage.getItem('solanum-primary-color') || '#60a5fa',
  localStorage.getItem('solanum-bg-color') || '#0a0a0c',
);

// "Always save terminal output to file" — computed fresh at the moment a PTY
// is (re)opened, not cached: flipping the setting mid-session only affects
// the NEXT open/reconnect, the same way it couldn't retroactively change a
// file handle a backend task already has open. Returns undefined (no log
// path sent to the backend, which then just skips logging) when the setting
// is off or no folder has been chosen yet.
const sessionLogPathFor = (label: string): string | undefined => {
  if (localStorage.getItem('solanum-always-log-sessions') !== '1') return undefined;
  const dir = localStorage.getItem('solanum-session-log-dir');
  if (!dir) return undefined;
  return buildSessionLogPath(dir, label);
};

// Reads the same two keys DesktopApp's appSettings effect writes on every
// change, and recompiles a matcher from them — same pattern TerminalView
// already uses for `solanum-terminal-font-size` below. Falls back to
// DEFAULT_HIGHLIGHT_LISTS (not []) for a missing key, matching DesktopApp's
// own fallback for the same case — if a terminal ever mounted before that
// key was first written, an empty-list fallback here would silently disagree
// with what the Settings UI shows as active.
const loadHighlightMatcher = (): HighlightMatcher | null => {
  const enabled = localStorage.getItem('solanum-highlight-enabled') !== '0';
  let lists: HighlightList[] = DEFAULT_HIGHLIGHT_LISTS;
  try {
    const raw = localStorage.getItem('solanum-highlight-lists');
    if (raw) lists = JSON.parse(raw);
  } catch { /* fall through to the default list */ }
  return compileHighlightMatcher(enabled, lists);
};

// Shared by buildSelectedText (a selection range) and saveOutputToFile (the
// whole scrollback) below — term.getSelection()/a naive per-row join both
// emit one '\n' per buffer row, including rows that are mid-wrap
// continuations of the previous logical line, which round-trips as a
// phantom blank line. Walking the buffer with `isWrapped` joins a wrapped
// line back into one; plain (non-wrapped) row breaks stay '\n'.
const joinBufferRange = (term: Terminal, startY: number, endY: number, startX = 0, endX?: number): string => {
  const buf = term.buffer.active;
  const lines: string[] = [];
  for (let y = startY; y <= endY; y++) {
    const line = buf.getLine(y);
    if (!line) continue;
    const sx = y === startY ? startX : 0;
    const ex = y === endY ? endX : undefined;
    const text = line.translateToString(true, sx, ex);
    if (y > startY && line.isWrapped && lines.length > 0) {
      lines[lines.length - 1] += text;
    } else {
      lines.push(text);
    }
  }
  return lines.join('\n');
};

// Where the first character of the line being typed was shown: the echo check
// for command history and snippets reads the screen from there (F-023).
type LineStart = { marker: IMarker; x: number };

// A paste's first lines with hidden and control characters spelled out, for
// the question before a paste or a Library run (F-083, F-087).
const pastePreview = (text: string): string => {
  const lines = visibleText(withoutPasteMarkers(text).replace(/(?:\r\n|\r|\n)$/, "")).split("\n");
  const shown = lines.slice(0, 8).map((l) => (l.length > 120 ? l.slice(0, 120) + "…" : l));
  if (lines.length > 8) shown.push(`… and ${lines.length - 8} more line${lines.length === 9 ? "" : "s"}`);
  return shown.join("\n");
};

// The text of the question before a paste or a Library run.
const pasteQuestion = (notes: string[], text: string): string =>
  [...notes.filter(Boolean), pastePreview(text)].join("\n\n");

// The TerminalView that owns each terminal id's PTY now (F-086). Split view
// and its off-screen host remount a terminal under the same id, so an open
// that lands after its view unmounted may only close the PTY when no newer
// view has taken the id over.
const terminalOwners = new Map<string, symbol>();
const closeIfAbandoned = (terminalId: string) => {
  if (!terminalOwners.has(terminalId)) invoke('close_terminal', { terminalId }).catch(() => { /* already gone */ });
};

// When a command's echo has not reached the screen yet at Enter, the history
// check looks again this much later, then gives up (the row is dropped, never
// recorded unchecked).
const ECHO_RECHECKS_MS = [250, 750];

// Shared search options — highlight all matches in yellow, the active
// match in orange. `decorations` uses the marker overlay so the highlight
// survives scrollback and repaints (the addon's built-in selection-based
// mode would clobber the user's own selection every keystroke). The
// overview-ruler fields are typed as required in xterm-addon-search 0.13
// but we don't render an overview ruler (no `overviewRulerLane` on the
// terminal), so their values are cosmetic — mirror the match colors so
// they'd still read sensibly if a ruler were ever enabled.
const SEARCH_OPTIONS: ISearchOptions = {
  caseSensitive: false,
  decorations: {
    matchBackground: '#facc15',
    matchBorder: '#facc15',
    matchOverviewRuler: '#facc15',
    activeMatchBackground: '#f97316',
    activeMatchBorder: '#f97316',
    activeMatchColorOverviewRuler: '#f97316',
  },
};

// State machine for the modifier stickies on the mobile key bar.
// off → armed → locked → off (cycled by repeated taps).
const cycleMod = (s: "off" | "armed" | "locked"): "off" | "armed" | "locked" =>
  s === "off" ? "armed" : s === "armed" ? "locked" : "off";

// xterm renders the cursor differently once the terminal loses focus
// (cursorInactiveStyle), separately from cursorStyle. Its own default,
// 'outline' (a hollow block), ignores whatever shape cursorStyle is
// actually set to — so a 'bar' (line) cursor visibly turned into a block
// the moment focus left the terminal, instead of just going static. Mapping
// it to match keeps the unfocused cursor the same shape, just not blinking
// (which is also why a line cursor can look "not blinking" if the terminal
// itself never had real focus — an unfocused cursor doesn't blink either).
const cursorInactiveStyleFor = (style: "block" | "bar"): "outline" | "bar" =>
  style === "bar" ? "bar" : "outline";

// xterm's blink animation (a CSS box-shadow toggle) doesn't reliably render
// for a "bar" cursor the way it does for "block" — a known rough edge in the
// version pinned here, not something a Solanum-side option can paper over.
// Rather than ship a setting that silently does nothing for half its
// choices, blink is forced off whenever the style is "bar"; the Settings
// UI disables the toggle in that case too, so it doesn't look like a bug.
const effectiveCursorBlink = (style: "block" | "bar", blinkSetting: boolean): boolean =>
  style === "bar" ? false : blinkSetting;

const TerminalView = ({
  sessionId,
  terminalId,
  disabled = false,
  isActive = true,
  visible,
  suppressResize = false,
  containerExec,
  localShell,
  connectionEpoch = 0,
  serverId = 0,
  serverName = "",
  attachOnly = false,
  onExitTab,
  onRestartSession,
  onEndedChange,
}: {
  sessionId: string;
  terminalId: string;
  disabled?: boolean;
  /// Called when the user presses Return after "Session stopped" (the
  /// remote shell exited — exit/Ctrl+D/TMOUT). Closes this terminal's tab,
  /// or the whole session if it's the only one. Not used by attach-only
  /// instances, which never print that message in the first place.
  onExitTab?: () => void;
  /// Called when the user presses R after "Session stopped" while the
  /// session's connection is gone (the server ended the session, or the link
  /// was lost): the session logs in again instead of this terminal asking a
  /// closed connection for a shell (N-028).
  onRestartSession?: () => void;
  /// Mirrors `sessionEnded` up to the parent — SessionView threads it into
  /// its own `terminals` state so DesktopApp can tell "this session's ×
  /// button would drop a genuinely live shell" apart from "every terminal
  /// in it already ended, there's nothing left to confirm about".
  onEndedChange?: (ended: boolean) => void;
  /// Attach-only mode: the PTY behind this terminal is owned by
  /// another TerminalView instance (typically the one inside the
  /// session tab). This instance ONLY listens to output events and
  /// forwards input — it doesn't call open_terminal on mount,
  /// close_terminal on unmount, or fight over resize_terminal. Used
  /// by the Wall pinboard so pinning a terminal doesn't duplicate the
  /// PTY or tear it down when Wall is closed.
  attachOnly?: boolean;
  /// Tells us when this terminal is the visible one in its parent. Used to
  /// trigger a refit + refresh whenever we become visible — without this,
  /// xterm's internal canvas can be left holding stale glyphs from before
  /// the parent's display/opacity change and the prompt appears garbled
  /// until the user types something.
  isActive?: boolean;
  /// On screen, whether or not it is the focused one (split view shows
  /// several): it then follows its box's size (refit, and the PTY told).
  /// Defaults to `isActive`. A pane moved into a split keeps its old size
  /// otherwise until it is clicked (review of batch 11, N-025).
  visible?: boolean;
  /// True while SessionView is growing/shrinking the OS window to
  /// compensate for a tool pane opening or closing (see its
  /// adjustWindowWidth). The terminal's own box is briefly the wrong size
  /// for that whole round trip — sharing space with a pane the window
  /// hasn't grown into yet, or keeping space a just-closed pane no longer
  /// needs — before the window catches up and it snaps back to its
  /// "sacred" width. Blocking the ResizeObserver-driven refit for that
  /// window stops the transient size from ever reaching fitAddon/the PTY,
  /// so nothing visibly reflows; the one refit this unblocks on the way
  /// back to false lands once the terminal is already the right size
  /// again, so it's normally a no-op.
  suppressResize?: boolean;
  /// When set, this terminal runs `docker exec -it <container> <shell>`
  /// on the SSH host instead of the user's login shell. Used by the
  /// Docker tool to open an interactive session inside a
  /// specific container without leaving the app.
  containerExec?: { container: string; useSudo: boolean };
  /// When set, this terminal runs a local shell on the machine Solanum
  /// itself is running on — no SSH, no server — instead of either of the
  /// SSH-backed paths above. Mutually exclusive with `containerExec` in
  /// practice (a local shell has no SSH session to exec into); `sessionId`
  /// is still required even here, since it's still used for event scoping
  /// and command-history stamping, just against a synthetic local session.
  localShell?: { shellIndex?: number; shellName?: string; cwd?: string };
  /// Bumped by the parent SessionView on every successful reconnect.
  /// When the value changes we re-open a fresh PTY against the new SSH
  /// handle WITHOUT disposing xterm — the user keeps their scroll-back
  /// from before the drop and can copy/paste anything they did pre-drop.
  /// Initial mount is opened by the main effect, so we only act on
  /// value CHANGES after that.
  connectionEpoch?: number;
  /// Server id + name are used to stamp command-history rows so the
  /// Ctrl+R overlay can show which server the command was run against.
  /// Quick-connect sessions have serverId=0 and just record the display
  /// name — that's fine for search, since the row is orphaned from any
  /// saved node anyway.
  serverId?: number;
  serverName?: string;
}) => {
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const searchAddonRef = useRef<SearchAddon | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const openedRef = useRef(false);
  // Read by the long-lived output listener on every chunk; recompiled
  // (not just re-read) whenever settings change, so a rule edit takes
  // effect on the very next byte written without reopening the terminal.
  const matcherRef = useRef<HighlightMatcher | null>(null);
  // PuTTY-style clipboard mode — read by the mousedown/mouseup and
  // contextmenu handlers below, updated on every settings change the same
  // way matcherRef is.
  const puttyClipboardRef = useRef(true);
  // Gates the Ctrl+R command-history overlay — read by the document-level
  // keydown handler below, updated on every settings change the same way
  // matcherRef/puttyClipboardRef are.
  const useCommandHistorySearchRef = useRef(false);
  // Gates text-expansion in the onData handler below, updated on every
  // settings change the same way matcherRef/puttyClipboardRef are.
  const textSnippetsEnabledRef = useRef(false);
  // trigger -> expansion, fetched from the vault (Library > Snippets) on
  // mount and refreshed whenever that list changes elsewhere in the app —
  // see the solanum-snippets-changed listener below. Not a setting, so it
  // doesn't live in localStorage like the ref above.
  const snippetsMapRef = useRef<Record<string, string>>({});
  // The xterm `onData` callback is bound once and persists for the life of the
  // component. We read this ref inside the callback so the latest `disabled`
  // state is observed without having to tear down and rebuild xterm.
  const disabledRef = useRef(disabled);
  useEffect(() => {
    disabledRef.current = disabled;
  }, [disabled]);
  // True once the remote shell itself has exited (exit/Ctrl+D/TMOUT) — the
  // PTY is gone but the tab is still open. Distinct from `disabled` (the
  // whole SSH session/connection dropped): this is per-terminal, and the
  // underlying connection is usually still perfectly healthy. Mirrored into
  // a ref for onData's early-return the same way disabledRef is.
  const [sessionEnded, setSessionEnded] = useState(false);
  const sessionEndedRef = useRef(false);
  useEffect(() => {
    sessionEndedRef.current = sessionEnded;
  }, [sessionEnded]);
  useEffect(() => {
    onEndedChange?.(sessionEnded);
    // Only sessionEnded itself should trigger this — onEndedChange is a
    // fresh closure every SessionView render, and re-firing on that would
    // just be redundant (idempotent) work every time the parent re-renders.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionEnded]);
  // Set synchronously at the top of the unmount cleanup, before it calls
  // close_terminal — that call makes the backend's PTY loop emit the exact
  // same terminal-closed event a real shell exit does (dropping the last
  // Sender for this terminal_id breaks its read loop too), so without this
  // guard closing a tab normally would print "Session stopped" into it right
  // as the tab disappears.
  const intentionallyClosingRef = useRef(false);
  // Mirror of `onExitTab`, read by the long-lived (mount-once) keydown
  // effect below. That effect's own deps are `[]`, so without this it would
  // permanently capture whichever `onExitTab` closure existed at mount —
  // and SessionView passes a fresh `() => closeTerminalTab(t.id)` closure on
  // every one of its own renders, closing over that render's `terminals`
  // array by value. A tab opened or closed after this terminal mounted
  // would then have Return-to-exit act on a stale, out-of-date terminal
  // list (e.g. wrongly concluding "this is the last tab" and closing the
  // whole session).
  const onExitTabRef = useRef(onExitTab);
  useEffect(() => {
    onExitTabRef.current = onExitTab;
  }, [onExitTab]);
  const onRestartSessionRef = useRef(onRestartSession);
  useEffect(() => {
    onRestartSessionRef.current = onRestartSession;
  }, [onRestartSession]);
  // Mirror of `isActive` readable inside the ResizeObserver callback. The
  // observer is bound once at mount and runs for the lifetime of the
  // terminal, so a stale closure over the initial `isActive` would block
  // the gate from ever flipping. A ref is the cheapest way to expose live
  // state to that callback.
  const isActiveRef = useRef(isActive);
  useEffect(() => {
    isActiveRef.current = isActive;
  }, [isActive]);
  // On screen: read by the ResizeObserver, written during render like
  // suppressResizeRef below, so a layout change in this same render (a pane
  // moved into a split) is followed at once.
  const shownOnScreen = visible ?? isActive;
  const shownRef = useRef(shownOnScreen);
  shownRef.current = shownOnScreen;
  // Same mirror, same reason, for suppressResize — read inside the same
  // long-lived ResizeObserver callback below. Assigned directly during
  // render rather than via useEffect like isActiveRef above: the observer
  // can fire for a reflow that THIS SAME render just caused (SessionView's
  // tool-pane open/close toggles suppressResize and the DOM change that
  // needs suppressing in one React batch), before a useEffect reacting to
  // the prop would get a chance to run — that one-render lag was an
  // intermittent flicker on close. Writing the ref during render is safe
  // here since it's never read back to produce this render's own output.
  const suppressResizeRef = useRef(suppressResize);
  suppressResizeRef.current = suppressResize;
  // Mirror of containerExec for the reconnect effect — same reason as
  // isActiveRef. The reconnect effect is keyed on `connectionEpoch`
  // alone (the parent re-creates the containerExec object every render
  // so including it in deps would re-fire every paint).
  const containerExecRef = useRef(containerExec);
  useEffect(() => { containerExecRef.current = containerExec; }, [containerExec]);
  // Same mirroring, same reason, for a local (non-SSH) shell tab.
  const localShellRef = useRef(localShell);
  useEffect(() => { localShellRef.current = localShell; }, [localShell]);
  // Last connectionEpoch we acted on. Initial mount's PTY is opened by
  // the main effect, so we should NOT re-open on the first run of the
  // reconnect effect — only on subsequent value changes.
  const lastEpochRef = useRef(connectionEpoch);

  // Mobile-only sticky modifiers (Ctrl / Alt / Shift) for the on-screen
  // key bar. State doubles as render input (highlighting) and is mirrored
  // into a ref so the long-lived `term.onData` callback can read it without
  // re-binding every state change. Armed modifiers consume themselves on
  // the next typed char; locked modifiers persist until the user taps the
  // chip a third time.
  const isMobile = useIsNarrow();
  const [modifiers, setModifiers] = useState<ModifiersState>({ ctrl: "off", alt: "off", shift: "off" });
  const modifiersRef = useRef<ModifiersState>(modifiers);
  useEffect(() => { modifiersRef.current = modifiers; }, [modifiers]);

  // The wrapper div below frames xterm's own canvas with a few px of padding
  // (so the scrollbar/edge doesn't sit flush against other chrome) — it has
  // to carry its own copy of the resolved theme's background, in plain
  // React state, or that padding shows up as a mismatched border the moment
  // the terminal theme isn't xterm's old hardcoded default.
  const [termBg, setTermBg] = useState('#09090b');

  // In-terminal search (Ctrl+F / Cmd+F). Query state is component-scoped so
  // reopening the chip pre-fills the last search — matches VS Code / Chrome
  // muscle memory. showSearch drives the floating chip's mount so xterm
  // isn't burdened with a hidden overlay when the user isn't searching.
  const [showSearch, setShowSearch] = useState(false);
  const [query, setQuery] = useState('');

  // Command-history overlay (Ctrl+R / Cmd+R) — opt-in, off by default (see
  // useCommandHistorySearchRef / the "use command history search" setting).
  // Ctrl+R is reverse-i-search muscle memory in every shell; intercepting it
  // unconditionally would both surprise nobody-asked-for-it users and (see
  // the keydown handler below) fight the shell for the same keystroke. Same
  // document-level keydown gate as search when it IS enabled: only pop it
  // when the user is focused inside this terminal's DOM subtree, so
  // multi-tab windows don't fire N overlays.
  const [showHistory, setShowHistory] = useState(false);

  // Broadcast context. `stateRef` gives us live access from inside the
  // xterm.onData closure without re-binding on every state change.
  // Callback identities on `broadcast` are stable (useCallback) so the
  // register effect below can depend on those directly without churn.
  const broadcast = useBroadcast();
  const broadcastRef = broadcast.stateRef;
  // Set while this terminal's keys are kept from the broadcast group because
  // it looks like it is asking for a secret (F-085); shown as a banner.
  const [broadcastHeld, setBroadcastHeld] = useState(false);
  const broadcastHeldRef = useRef(false);
  const holdBroadcast = (held: boolean) => {
    if (broadcastHeldRef.current === held) return;
    broadcastHeldRef.current = held;
    setBroadcastHeld(held);
  };
  const registerActiveTerminal = broadcast.registerActiveTerminal;
  const unregisterActiveTerminal = broadcast.unregisterActiveTerminal;

  // Register this terminal as the "active" one for its session whenever
  // isActive flips true. Broadcast fan-out reads from sessionTerminalMap
  // to know which of a session's tabs is currently visible / receiving
  // input; a stale mapping to a background terminal would silently swallow
  // the mirrored keystrokes. Unregister only if we still hold the slot —
  // avoids racing with the newly-active terminal during a tab swap.
  useEffect(() => {
    if (!isActive) return;
    registerActiveTerminal(sessionId, terminalId);
    return () => {
      unregisterActiveTerminal(sessionId, terminalId);
    };
  }, [isActive, sessionId, terminalId, registerActiveTerminal, unregisterActiveTerminal]);

  // The line being typed, rebuilt from the keys sent, for command history
  // and snippets (util/terminalInput.ts). Created with the xterm instance.
  const trackerRef = useRef<LineTracker<LineStart> | null>(null);
  // Small tail of recent remote OUTPUT, kept only to recognise a prompt for a
  // secret (looksLikeSecretPrompt) — never persisted or displayed.
  const recentOutputRef = useRef<string>("");

  const toggleModifier = (m: ModKey) => {
    setModifiers(prev => ({ ...prev, [m]: cycleMod(prev[m]) }));
  };
  // Called after a transformed char is sent so armed modifiers reset back
  // to "off" while locked ones survive (matches Termux's behavior). Skipped
  // when nothing was actually armed — avoids a useless setState ping.
  const consumeArmedModifiers = () => {
    setModifiers(prev => {
      if (prev.ctrl !== "armed" && prev.alt !== "armed" && prev.shift !== "armed") return prev;
      return {
        ctrl:  prev.ctrl  === "armed" ? "off" : prev.ctrl,
        alt:   prev.alt   === "armed" ? "off" : prev.alt,
        shift: prev.shift === "armed" ? "off" : prev.shift,
      };
    });
  };

  // Esc / Tab from the bar bypass the onData modifier pipeline (those keys
  // produce escape sequences directly, not printable chars), but Shift+Tab
  // still has a meaningful encoding so we honor it here.
  const sendSpecialKey = (key: "esc" | "tab") => {
    if (disabledRef.current) return;
    let bytes: number[];
    let consumes = false;
    if (key === "esc") {
      bytes = [0x1b];
    } else {
      if (modifiersRef.current.shift !== "off") {
        // ESC [ Z = CSI Z = back-tab (the standard Shift+Tab sequence).
        bytes = [0x1b, 0x5b, 0x5a];
        consumes = true;
      } else {
        bytes = [0x09];
      }
    }
    invoke('write_terminal_data', { terminalId, data: bytes }).catch(console.error);
    if (consumes) consumeArmedModifiers();
  };

  // Re-opens the PTY for this terminal_id against the existing xterm (kept,
  // not disposed — scrollback survives) after writing a visible divider.
  // The backend's `terminal_txs` HashMap.insert overwrites the dead entry
  // transparently, so write_terminal_data routes to the new task without
  // changing terminal_id. Shared by the connectionEpoch-driven reconnect
  // below and by "R to restart" after "Session stopped" — same mechanism,
  // two different triggers (a dropped SSH connection vs. just
  // the remote shell having exited on an otherwise-healthy connection).
  // Attach-only viewers piggyback on someone else's PTY, so they never
  // re-open it themselves — the owner already did, and this instance just
  // keeps reading events off the same terminal_id.
  //
  // restartingRef guards "R to restart" specifically (see the keydown
  // effect below) against a second attempt firing — via OS key-repeat —
  // before the first invoke has even settled. sessionEndedRef alone isn't
  // enough for this: it only flips once the *successful* reopen resolves
  // (below), which for a real round-trip is easily slower than a held key's
  // repeat rate.
  const restartingRef = useRef(false);
  // False once this view has unmounted: a reopen landing after that closes
  // what it opened (closeIfAbandoned) instead of reviving the view.
  const liveRef = useRef(false);
  const reopenPty = (term: Terminal, dividerText: string, actionLabel: string) => {
    // Visible separator. \x1b[33m = yellow, \x1b[0m = reset.
    term.write(`\r\n\x1b[33m── ${dividerText} ──\x1b[0m\r\n`);
    if (attachOnly) return;
    const ce = containerExecRef.current;
    const ls = localShellRef.current;
    const opened = ce
      ? invoke<string | null>('open_container_terminal', {
          sessionId,
          terminalId,
          container: ce.container,
          cols: term.cols || 80,
          rows: term.rows || 24,
          useSudo: ce.useSudo,
          logFilePath: sessionLogPathFor(`${serverName || 'terminal'}-${ce.container}`),
        })
      : ls
      ? invoke<string | null>('open_local_terminal', {
          terminalId,
          cols: term.cols || 80,
          rows: term.rows || 24,
          shellIndex: ls.shellIndex ?? 0,
          cwd: ls.cwd,
          logFilePath: sessionLogPathFor(serverName || 'terminal'),
        })
      : invoke<string | null>('open_terminal', {
          sessionId,
          terminalId,
          cols: term.cols || 80,
          rows: term.rows || 24,
          logFilePath: sessionLogPathFor(serverName || 'terminal'),
        });
    opened
      .then((logProblem) => {
        if (!liveRef.current) { closeIfAbandoned(terminalId); return; }
        writeLogProblem(term, logProblem);
        // Only now — a *confirmed* fresh PTY — is it correct to say the
        // session isn't ended and let onData/typing through again. Setting
        // this unconditionally right after firing the invoke (the old
        // behavior) left a terminal permanently input-locked whenever the
        // reopen itself failed (e.g. restarting after the whole SSH session,
        // not just this shell, had also died): no further terminal-closed
        // event would ever arrive to re-show "Session stopped", since
        // open_terminal failing means the backend never even got as far as
        // spawning the task that emits it.
        sessionEndedRef.current = false;
        setSessionEnded(false);
      })
      .catch(e => {
        if (!liveRef.current) return;
        // Cancel in the backend's local-shell confirmation is not a failure.
        if (String(e).startsWith('[LOCAL_SHELL] CANCELLED')) {
          term.writeln('\x1b[33mLocal shell not started.\x1b[0m');
          return;
        }
        term.writeln(`\x1b[31m${actionLabel}${ce ? ' into container' : ''} failed: ${e}\x1b[0m`);
      })
      .finally(() => { restartingRef.current = false; });
  };

  // Reconnect handler: when the parent bumps connectionEpoch, re-open the
  // PTY against the new SSH handle.
  useEffect(() => {
    if (connectionEpoch === lastEpochRef.current) return;
    lastEpochRef.current = connectionEpoch;
    const term = xtermRef.current;
    if (!term) return;
    reopenPty(term, 'reconnected', 'Reconnect');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [connectionEpoch]);

  // Repaint (and, on desktop, focus) when this terminal becomes the active
  // one. The parent uses opacity (within a session) or display:none (across
  // sessions/tabs) to swap visible terminals — neither triggers xterm's
  // internal redraw, so the canvas can end up showing a stale row of glyphs
  // from before the switch. Calling `fit()` recomputes cols/rows and
  // `refresh()` forces every visible row to repaint. rAF defers until the
  // layout has settled — without it `fit()` would measure 0×0 in the
  // display:none case. This also fires on a brand-new session's very first
  // render (isActive starts true), which is what actually makes it ready to
  // type into immediately instead of needing a click first.
  //
  // Skipped on mobile: focusing xterm's hidden textarea pops the on-screen
  // keyboard, which is disruptive to do automatically the instant a session
  // opens or a tab is switched to, before the user has even looked at it —
  // tapping the terminal (as before) stays the way to bring up the keyboard.
  // Also skipped while the in-terminal search chip is open — switching back
  // to a tab left mid-search should return focus to that input, not yank it
  // onto the terminal underneath.
  //
  // Also skipped for attach-only instances: Wall renders several of these
  // side by side, each hardcoded isActive={true} purely so they all stay
  // repainted — that flag was never meant to single one out as "the" focused
  // pane there, and auto-focusing on it would just make Wall's tiles fight
  // over keyboard focus, with whichever mounts last silently winning.
  useEffect(() => {
    if (!isActive) return;
    const id = requestAnimationFrame(() => {
      try {
        fitAddonRef.current?.fit();
        const t = xtermRef.current;
        if (t) {
          t.refresh(0, Math.max(0, t.rows - 1));
          if (!isMobile && !showSearch && !attachOnly) t.focus();
        }
      } catch { /* terminal not ready yet — next tick will catch it */ }
    });
    return () => cancelAnimationFrame(id);
  }, [isActive]);

  // Shown without being the focused one (a split pane): fit to the box it
  // has now, without taking the focus.
  useEffect(() => {
    if (!shownOnScreen || isActive) return;
    const id = requestAnimationFrame(() => {
      try {
        fitAddonRef.current?.fit();
        const t = xtermRef.current;
        if (t) t.refresh(0, Math.max(0, t.rows - 1));
      } catch { /* terminal not ready yet */ }
    });
    return () => cancelAnimationFrame(id);
  }, [shownOnScreen, isActive]);

  // Reconcile once a suppressResize window ends (see the prop doc). By then
  // the OS window has finished growing/shrinking to keep this terminal's box
  // "sacred", so cols/rows are normally already correct and this is a no-op —
  // it exists only to catch the rare case where a real size change (e.g. the
  // user dragging the OS window itself) landed while resizes were blocked.
  useEffect(() => {
    if (suppressResize) return;
    const id = requestAnimationFrame(() => {
      try { fitAddonRef.current?.fit(); } catch { /* terminal not ready */ }
    });
    return () => cancelAnimationFrame(id);
  }, [suppressResize]);

  // Ctrl+F / Cmd+F opens the search chip — but only when the user is
  // focused inside this terminal's DOM subtree. Document-level listener is
  // needed because xterm's textarea steals keyboard focus, so the wrapper
  // never sees the keydown via bubbling within React's synthetic tree.
  // Gate on `document.activeElement` so multiple terminals in tabs / split
  // panes don't all pop their search chip on a single Ctrl+F.
  //
  // The same gate is reused for Ctrl+R / Cmd+R, which opens the command
  // history overlay ONLY when that's explicitly opted into (see
  // useCommandHistorySearchRef) — off by default, Ctrl+R is just forwarded
  // to the shell like any other keystroke, for its own native
  // reverse-i-search.
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const wrapper = terminalRef.current;
      if (!wrapper) return;
      const active = document.activeElement;
      if (!(active instanceof Node) || !wrapper.contains(active)) return;

      // "Session stopped" shortcuts — bare keys (no modifier), and only
      // once the remote shell has actually exited, so they never intercept
      // normal typing into a live shell. Needs stopPropagation, not just
      // preventDefault: xterm's own textarea has a CAPTURE-phase listener
      // (registered with useCapture=true) that calls stopPropagation for
      // exactly these keys — Enter and any plain letter are keys it has a
      // real translation for and actively cancels, via its own cancel()
      // helper (preventDefault + stopPropagation together). Without also
      // stopping propagation here, xterm's handler still runs first — this
      // effect is a document-level BUBBLE listener by default, which never
      // even sees an event xterm already stopped — so this branch is
      // registered in the capture phase too (see addEventListener below)
      // and must stop it before it reaches the textarea. Ctrl+F/Ctrl+R just
      // below need the exact same treatment, for a different reason: xterm
      // has no NAMED handling for either combo, but it still translates any
      // Ctrl+<letter> generically into its C0 control byte (Ctrl+R is 0x12,
      // a real shell control code — reverse-i-search) and forwards that to
      // the PTY. Skipping stopPropagation here used to mean BOTH our own
      // overlay opened AND the shell received the raw byte, so a cancelled
      // history search left the shell sitting in its own native
      // reverse-i-search prompt.
      if (sessionEndedRef.current && !e.ctrlKey && !e.metaKey && !e.altKey) {
        if (e.key === 'Enter') {
          e.preventDefault();
          e.stopPropagation();
          onExitTabRef.current?.();
          return;
        }
        if (e.key === 'r' || e.key === 'R') {
          e.preventDefault();
          e.stopPropagation();
          if (disabledRef.current && onRestartSessionRef.current) {
            onRestartSessionRef.current();
            return;
          }
          if (restartingRef.current) return; // key-repeat while one is already in flight
          const term = xtermRef.current;
          if (!term) return;
          restartingRef.current = true;
          reopenPty(term, 'restarted', 'Restart');
          return;
        }
        if (e.key === 's' || e.key === 'S') {
          e.preventDefault();
          e.stopPropagation();
          void saveOutputToFile();
          return;
        }
      }

      if (!(e.ctrlKey || e.metaKey)) return;
      if (e.key === 'f' || e.key === 'F') {
        e.preventDefault();
        e.stopPropagation();
        setShowSearch(true);
        // If already open, refocus the input so a second Ctrl+F selects the
        // existing query for a quick overwrite.
        requestAnimationFrame(() => {
          searchInputRef.current?.focus();
          searchInputRef.current?.select();
        });
      } else if ((e.key === 'r' || e.key === 'R') && useCommandHistorySearchRef.current) {
        // Gated on the opt-in setting — when it's off (the default), this
        // branch doesn't run at all, so neither preventDefault nor
        // stopPropagation fires and Ctrl+R falls through untouched to
        // xterm, which forwards it to the shell exactly like any other key.
        e.preventDefault();
        e.stopPropagation();
        setShowHistory(true);
      }
    };
    // Capture phase (the `true` third argument, on both add and remove —
    // they must match exactly or the remove silently no-ops and leaks a
    // listener on every remount): needed so the "Session stopped" branch
    // above gets to the event, and can stopPropagation it, before xterm's
    // own capture-phase textarea listener does.
    document.addEventListener('keydown', onKeyDown, true);
    return () => document.removeEventListener('keydown', onKeyDown, true);
  }, []);

  // "Save output to file…" from the session tab's right-click menu
  // (DesktopApp.tsx dispatches this on the active terminal's id) — same
  // targeted-CustomEvent convention already used for session-reconnect-*.
  useEffect(() => {
    if (attachOnly) return;
    const onSaveRequest = () => { void saveOutputToFile(); };
    const eventName = `terminal-save-output-${terminalId}`;
    window.addEventListener(eventName, onSaveRequest);
    return () => window.removeEventListener(eventName, onSaveRequest);
  }, [terminalId, attachOnly]);

  // Dispatched by DesktopApp after cancelling the "Close this session?"
  // confirm dialog. That dialog's own focus trap restores focus to whatever
  // had it before the dialog opened — which, for a click on the tab's ×
  // button, is the × button itself, not the terminal the user was actually
  // typing in. Rather than changing that shared, generic focus-trap
  // (every confirm dialog in the app relies on its current behavior),
  // DesktopApp knows which terminal was active and asks it to refocus.
  useEffect(() => {
    if (attachOnly) return;
    const onRefocusRequest = () => { xtermRef.current?.focus(); };
    const eventName = `terminal-refocus-${terminalId}`;
    window.addEventListener(eventName, onRefocusRequest);
    return () => window.removeEventListener(eventName, onRefocusRequest);
  }, [terminalId, attachOnly]);

  // See libraryInsert. `handled` tells the Library a terminal took it.
  useEffect(() => {
    if (attachOnly) return;
    const onInsert = (ev: Event) => {
      const detail = (ev as CustomEvent<{ text: string; run: boolean; handled: boolean }>).detail;
      detail.handled = true;
      void libraryInsert(detail.text, detail.run);
    };
    const eventName = `terminal-library-insert-${terminalId}`;
    window.addEventListener(eventName, onInsert);
    return () => window.removeEventListener(eventName, onInsert);
  }, [terminalId, attachOnly]);

  // Close + clear search decorations. Refocuses xterm so the user's next
  // keystroke goes to the shell, not to nowhere.
  const closeSearch = () => {
    const addon = searchAddonRef.current;
    // clearDecorations arrived in xterm-addon-search 0.13; guard for older
    // typings even though our lockfile pins 0.13.0.
    addon?.clearDecorations?.();
    setShowSearch(false);
    // Return focus to xterm so keystrokes resume typing at the prompt.
    xtermRef.current?.focus();
  };

  const runFind = (direction: 'next' | 'prev') => {
    const addon = searchAddonRef.current;
    if (!addon || !query) return;
    if (direction === 'next') addon.findNext(query, SEARCH_OPTIONS);
    else addon.findPrevious(query, SEARCH_OPTIONS);
  };

  // Tiny inline toast for clipboard feedback (copy / paste / errors). Pattern
  // matches the per-component notify() used in SftpWorkspace / FilePanel —
  // keeps the component self-contained without a global toast provider.
  const [toast, setToast] = useState<{ msg: string; tone: "ok" | "err" } | null>(null);
  const toastTimerRef = useRef<number | null>(null);
  const notify = (msg: string, tone: "ok" | "err" = "ok") => {
    setToast({ msg, tone });
    if (toastTimerRef.current) window.clearTimeout(toastTimerRef.current);
    toastTimerRef.current = window.setTimeout(() => setToast(null), 1400);
  };

  // ── Clipboard (shared by both PuTTY-style auto copy/paste and the
  // Copy/Paste context menu shown when that mode is off) ────────────────────
  // Component-level, not inside the mount effect below, since the context
  // menu's own buttons (rendered in this component's JSX) need to call these
  // too — reads xtermRef.current rather than closing over the effect's local
  // `term`, same as closeSearch/runFind above already do.
  // writeText() was never reported broken (only reading clipboard content
  // from another application was — see pasteFromClipboard below), so copy
  // stays on navigator.clipboard.writeText() here, same as every other
  // copy-to-clipboard button in the app, rather than introducing a second
  // parallel write mechanism for a path that didn't need fixing.
  const writeClipboard = async (text: string): Promise<boolean> => {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      return false;
    }
  };
  const buildSelectedText = (): string => {
    const term = xtermRef.current;
    if (!term) return '';
    const range = term.getSelectionPosition();
    if (!range) return '';
    return joinBufferRange(term, range.start.y, range.end.y, range.start.x, range.end.x);
  };
  const copySelectionIfAny = async () => {
    const text = buildSelectedText();
    if (!text) return;
    const ok = await writeClipboard(text);
    if (ok) notify('Copied');
  };
  // The whole scrollback, not just what's currently selected — same
  // wrapped-line handling as copy, just over the full buffer range instead
  // of a selection. Used by "Session stopped"'s S key and by the session
  // tab's right-click "Save output to file…" (DesktopApp.tsx
  // dispatches terminal-save-output-${terminalId}, listened for below).
  const saveOutputToFile = async () => {
    const term = xtermRef.current;
    if (!term) return;
    const content = joinBufferRange(term, 0, term.buffer.active.length - 1);
    try {
      const path = await invoke<string | null>('save_terminal_text', {
        defaultName: `${serverName || 'terminal'}.txt`,
        content,
      });
      if (path) notify('Saved');
    } catch {
      notify('Save failed', 'err');
    }
  };
  // Every paste into this terminal comes here: the keyboard's (the paste
  // event is caught before xterm's own handler), PuTTY-style right-click and
  // the menu (F-083). Bracketed-paste markers inside the text are removed (they
  // would end the paste early and let the rest run as typed); the user is asked
  // first when the text holds control characters, or line breaks the program
  // would run one by one because it has not asked for bracketed paste (a
  // setting, on by default; with bracketed paste the shell shows the lines and
  // waits for Enter). xterm's own paste then turns line breaks into Enter and
  // brackets the text when the program asked for it; like typing, it goes to
  // the broadcast group too.
  const confirm = useConfirm();
  // Set while xterm's own paste runs, so onData knows the text went through
  // pasteText already.
  const pastingRef = useRef(false);
  const pasteText = async (text: string) => {
    const term = xtermRef.current;
    if (!term || disabledRef.current || sessionEndedRef.current) return;
    const clean = withoutPasteMarkers(text);
    if (!clean) return;
    const check = assessPaste(clean, term.modes.bracketedPasteMode);
    // Broadcast types the same bytes into the other sessions, whose programs
    // may not take a bracketed paste: several lines there always ask.
    const bcast = broadcastRef.current;
    const others = bcast.enabled && bcast.targetSessionIds.size >= 2 && bcast.targetSessionIds.has(sessionId)
      ? bcast.targetSessionIds.size - 1 : 0;
    const intoOthers = others > 0 && /[\r\n]/.test(clean);
    if ((check.runsLines || check.controls || intoOthers) && loadConfirmRiskyPaste()) {
      const ok = await confirm({
        title: check.runsLines || intoOthers ? `Paste ${check.lines} line${check.lines === 1 ? "" : "s"}?` : "Paste control characters?",
        message: pasteQuestion([
          check.runsLines ? "The program in this terminal will run each line as it arrives: it has not turned on bracketed paste." : "",
          intoOthers ? `It is also typed into ${others} other broadcast session${others === 1 ? "" : "s"}, where each line may run.` : "",
          check.controls ? "The text holds control characters (spelled out below), which the program may act on." : "",
        ], clean),
        okLabel: "Paste",
        destructive: true,
        safeDefault: true,
      });
      term.focus();
      if (!ok || disabledRef.current || sessionEndedRef.current) return;
    }
    pastingRef.current = true;
    try { term.paste(clean); } finally { pastingRef.current = false; }
  };

  // A link the program printed (OSC 8 hyperlink). xterm itself ignores links
  // that are not http(s); its default for the others is window.confirm() and
  // window.open() inside this webview. Instead the address the link really
  // points to is shown (normalised by URL, so a look-alike host shows as
  // punycode; hidden characters spelled out), Cancel focused, and the system
  // browser opens it through Rust (open_external_url, http(s) only).
  const openLink = async (uri: string) => {
    let url: URL;
    try { url = new URL(uri); } catch { return; }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return;
    const ok = await confirm({
      title: 'Open link?',
      message: `The program in this terminal links to:\n\n${visibleName(url.href)}\n\nOpen it in your browser?`,
      okLabel: 'Open',
      safeDefault: true,
    });
    xtermRef.current?.focus();
    if (!ok) return;
    invoke('open_external_url', { url: url.href }).catch((e) => notify(`Could not open the link: ${e}`, 'err'));
  };

  // Reads through the backend's read_clipboard_text command
  // (tauri-plugin-clipboard-manager) rather than navigator.clipboard
  // directly: WebKitGTK's Async Clipboard API readText() only reliably
  // returns text the page itself just wrote, and silently denies reading
  // clipboard content set by any other application — pasting anything
  // copied from outside Solanum failed. The native plugin talks to the OS
  // clipboard over Tauri's own IPC instead, unaffected by that. An empty
  // clipboard comes back as "" (the command itself treats that case as
  // "nothing to paste", not an error), which pasteText already no-ops on.
  const pasteFromClipboard = async () => {
    if (disabledRef.current) return;
    let text = '';
    try { text = await invoke<string>('read_clipboard_text'); }
    catch (e) {
      // The backend reads the clipboard only while this window has the focus.
      notify(String(e).includes('NOT_FOCUSED') ? 'Click into the window, then paste again' : 'Clipboard read denied', 'err');
      return;
    }
    await pasteText(text);
  };

  // Library "Run" and "Paste (no Enter)" (CmdsPanel dispatches
  // terminal-library-insert-<id>; F-087). Not broadcast, as before; what it
  // sends is shown in the toast or refused there. "Paste" never ends with
  // Enter; several lines go in as one bracketed paste when the program asked
  // for it, and otherwise each would run, so the user is asked (owner
  // decision). "Run" of several lines always asks first.
  const libraryInsert = async (text: string, run: boolean) => {
    const term = xtermRef.current;
    if (!term) return;
    if (disabledRef.current || sessionEndedRef.current) { notify('Terminal not connected', 'err'); return; }
    const body = withoutPasteMarkers(text).replace(/(?:\r\n|\r|\n)+$/, '');
    if (!body) return;
    const bracketed = term.modes.bracketedPasteMode;
    const check = assessPaste(body, bracketed);
    const multiLine = check.lines > 1;
    if ((run && multiLine) || (!run && check.runsLines) || check.controls) {
      const ok = await confirm({
        title: run ? `Run ${check.lines} line${check.lines === 1 ? "" : "s"} in this terminal?` : `Paste ${check.lines} lines?`,
        message: pasteQuestion([
          !run && check.runsLines ? "The program in this terminal will run each line as it arrives: it has not turned on bracketed paste." : "",
          check.controls ? "The text holds control characters (spelled out below), which the program may act on." : "",
        ], body),
        okLabel: run ? "Run" : "Paste",
        destructive: true,
        safeDefault: true,
      });
      if (!ok) { term.focus(); return; }
      if (disabledRef.current || sessionEndedRef.current) { notify('Terminal not connected', 'err'); return; }
    }
    const keys = (multiLine ? asPaste(body, bracketed) : body) + (run ? '\r' : '');
    try {
      await invoke('write_terminal_data', { terminalId, data: Array.from(new TextEncoder().encode(keys)) });
      trackerRef.current?.feed(keys);
      notify(run ? 'Sent' : 'Pasted');
    } catch (e) {
      notify(`Could not write: ${e}`, 'err');
    }
    term.focus();
  };

  // Copy/Paste menu shown on right-click when PuTTY-style clipboard is off.
  // Position + whether a selection exists (to grey out Copy) are captured
  // once, at open time.
  const [clipMenu, setClipMenu] = useState<{ x: number; y: number; canCopy: boolean; canPaste: boolean } | null>(null);
  const clipMenuRef = useRef<HTMLDivElement | null>(null);
  // Closing the menu (for any reason a user actually dismissed it — picking
  // an action, clicking away, or Escape) should return focus to the
  // terminal, same as closeSearch() already does for the search chip.
  // Without this, clicking the menu's own Copy/Paste buttons — separate DOM
  // elements from the terminal — leaves focus stranded on whichever button
  // was clicked, and typing afterward silently goes nowhere until the user
  // clicks the terminal again.
  const closeClipMenu = () => {
    setClipMenu(null);
    xtermRef.current?.focus();
  };
  useEffect(() => {
    if (!clipMenu) return;
    const onWindowMouseDown = (ev: MouseEvent) => {
      const target = ev.target as Node | null;
      if (target && clipMenuRef.current?.contains(target)) return;
      setClipMenu(null);
      // Reclaim focus for the terminal only if this dismissing click didn't
      // already send focus elsewhere — a native input/button grabs it as
      // part of the same click, and forcing it onto the terminal regardless
      // (as closeClipMenu's own buttons correctly do) would instead yank
      // focus away from whatever the user actually clicked.
      requestAnimationFrame(() => {
        const active = document.activeElement;
        if (!active || active === document.body) xtermRef.current?.focus();
      });
    };
    const onKeyDown = (ev: KeyboardEvent) => { if (ev.key === 'Escape') closeClipMenu(); };
    // Same small delay FilePanel's own context menu uses — without it, the
    // mousedown that just opened this menu (via contextmenu) would also
    // immediately satisfy this listener and close it right back.
    const timer = window.setTimeout(() => {
      window.addEventListener('mousedown', onWindowMouseDown);
      window.addEventListener('keydown', onKeyDown);
    }, 50);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener('mousedown', onWindowMouseDown);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [clipMenu]);

  useEffect(() => {
    if (!terminalRef.current) return;

    matcherRef.current = loadHighlightMatcher();
    puttyClipboardRef.current = loadPuttyClipboard();
    useCommandHistorySearchRef.current = loadUseCommandHistorySearch();
    textSnippetsEnabledRef.current = loadUseTextSnippets();

    const initialCursorStyle = localStorage.getItem('solanum-terminal-cursor-style') === 'bar' ? 'bar' : 'block';
    const initialTheme = loadTerminalTheme();
    setTermBg(initialTheme.background);
    const term = new Terminal({
      cursorBlink: effectiveCursorBlink(initialCursorStyle, localStorage.getItem('solanum-terminal-cursor-blink') !== '0'),
      cursorStyle: initialCursorStyle,
      cursorInactiveStyle: cursorInactiveStyleFor(initialCursorStyle),
      fontSize: parseInt(localStorage.getItem('solanum-terminal-font-size') || '14'),
      fontFamily: terminalFontFamily(localStorage.getItem('solanum-terminal-font-family')),
      theme: initialTheme,
      allowProposedApi: true,
      linkHandler: { activate: (_event, uri) => { void openLink(uri); } },
      // A setting (Settings > Terminal, default 100,000 lines), not
      // unbounded: xterm's buffer grows with every line kept, about 1 GB per
      // million 80-column lines, so a chatty or hostile server could
      // otherwise exhaust the window's memory (F-031).
      scrollback: loadScrollback(),
    });

    const fitAddon = new FitAddon();
    fitAddonRef.current = fitAddon;
    term.loadAddon(fitAddon);
    const searchAddon = new SearchAddon();
    searchAddonRef.current = searchAddon;
    term.loadAddon(searchAddon);
    term.open(terminalRef.current);

    // Shared with the terminal-closed listener below (same banner, same
    // "Session stopped" state) — but also needed right here: if the PTY
    // never opens at all (invalid shell path, bad starting directory, a
    // session that dropped between SessionView confirming "connected" and
    // this setTimeout firing), no backend task ever starts, so the
    // terminal-closed-{id} event this listener normally reacts to would
    // never arrive either. Without this, a failed initial open left the tab
    // silently stuck "connected" forever — no restart hint, nothing — which
    // a bad path typed into the Local Shell modal makes easy to hit in
    // practice (SSH/container-exec terminals only open after SessionView
    // already confirmed a live connection, so this path was a much
    // narrower race there).
    const markSessionEnded = (bannerLine: string) => {
      term.write(
        `\r\n\x1b[1;31m${bannerLine}\x1b[0m\r\n` +
        '    Press <Return> to exit tab\r\n' +
        '    Press R to restart session\r\n' +
        '    Press S to save terminal output to file\r\n'
      );
      setSessionEnded(true);
    };

    // The PTY is opened a moment after mount, once fit() knows the real
    // size. A view that unmounts before then cancels it (F-086); one that
    // unmounts while the open is under way has the open close what it opened
    // when it lands (closeIfAbandoned).
    liveRef.current = true;
    let cancelled = false;
    const owner = Symbol(terminalId);
    if (!attachOnly) terminalOwners.set(terminalId, owner);
    const whenOpened = (open: Promise<string | null>, failed: (e: unknown) => void) => {
      open.then((logProblem) => { if (cancelled) closeIfAbandoned(terminalId); else writeLogProblem(term, logProblem); })
        .catch((e) => { if (!cancelled) failed(e); });
    };
    const openTimer = window.setTimeout(() => {
      if (cancelled) return;
      fitAddon.fit();

      // Start PTY Session with correct dimensions only ONCE. Attach-only
      // instances skip this entirely — they hitch onto an existing PTY
      // opened by the primary instance and would collide with it if they
      // tried to open the same terminal_id a second time.
      if (!openedRef.current && !attachOnly) {
        openedRef.current = true;
        // Branch: a `containerExec` prop means we want a docker-exec
        // session into a specific container, not the regular login
        // shell. Same xterm wiring, different backend command — the
        // PTY/data/resize event topology is identical so xterm doesn't
        // notice the difference.
        if (containerExec) {
          whenOpened(invoke<string | null>('open_container_terminal', {
            sessionId,
            terminalId,
            container: containerExec.container,
            cols: term.cols || 80,
            rows: term.rows || 24,
            useSudo: containerExec.useSudo,
            logFilePath: sessionLogPathFor(`${serverName || 'terminal'}-${containerExec.container}`),
          }), e => {
            term.writeln(`\x1b[31mFailed to attach to container: ${e}\x1b[0m`);
            markSessionEnded('Session failed to start');
          });
        } else if (localShell) {
          whenOpened(invoke<string | null>('open_local_terminal', {
            terminalId,
            cols: term.cols || 80,
            rows: term.rows || 24,
            shellIndex: localShell.shellIndex ?? 0,
            cwd: localShell.cwd,
            logFilePath: sessionLogPathFor(serverName || 'terminal'),
          }), e => {
            // Cancel in the backend's confirmation dialog is not a failure.
            if (String(e).startsWith('[LOCAL_SHELL] CANCELLED')) {
              term.writeln('\x1b[33mLocal shell not started.\x1b[0m');
              markSessionEnded('Not started');
              return;
            }
            term.writeln(`\x1b[31mFailed to open local shell: ${e}\x1b[0m`);
            markSessionEnded('Session failed to start');
          });
        } else {
          whenOpened(invoke<string | null>('open_terminal', {
            sessionId,
            terminalId,
            cols: term.cols || 80,
            rows: term.rows || 24,
            logFilePath: sessionLogPathFor(serverName || 'terminal'),
          }), e => {
            term.writeln(`\x1b[31mFailed to open terminal: ${e}\x1b[0m`);
            markSessionEnded('Session failed to start');
          });
        }
      }
    }, 50);

    xtermRef.current = term;

    // A newly-bundled font may still be loading (font-display: swap paints
    // with the CSS fallback first) when the fit() above runs, locking in a
    // character grid sized to the fallback font's glyph width instead of the
    // one actually selected — every one of these fonts starts with a cold
    // cache for anyone who hasn't opened a terminal since this shipped.
    // Re-fitting once the browser confirms every requested font has actually
    // loaded corrects that mismatch (it resizes the PTY too, same as any
    // other fit() — this is exactly what a real resize already does).
    // Comparing xtermRef.current to this specific `term` skips the work if
    // this instance was already replaced by a remount; a plain unmount is
    // harmless too, since xterm tolerates fit() calls after dispose().
    document.fonts?.ready.then(() => {
      if (xtermRef.current !== term) return;
      try { fitAddon.fit(); } catch { /* terminal not ready / already disposed */ }
    });

    // Handle Input — swallow keystrokes once the session is disconnected so
    // they don't pile up against a dead backend channel. When a mobile-key-bar
    // modifier is armed/locked we transform single printable characters into
    // the matching control sequence before sending (Ctrl+letter → 0x01-0x1a,
    // Alt+char → ESC-prefix). Multi-char inputs (paste, IME composition) are
    // forwarded verbatim because we can't sensibly "Ctrl" a phrase.
    // A line's start is a marker on the row where its first character was
    // typed, in the normal buffer only: a line typed into a full-screen
    // program (an editor, a pager) is never recorded or expanded.
    const tracker = new LineTracker<LineStart>(
      () => {
        if (term.buffer.active.type !== 'normal') return null;
        const marker = term.registerMarker(0);
        return marker ? { marker, x: term.buffer.active.cursorX } : null;
      },
      (start) => start.marker.dispose(),
    );
    trackerRef.current = tracker;
    let disposed = false;
    const echoTimers = new Set<number>();

    // Command history (F-023). Only a line typed one key at a time (or a
    // one-line paste) with nothing the tracker cannot follow, of 3 characters
    // or more, not at what looks like a prompt for a secret, in a session not
    // set to "Don't record", and only if the typed text is on screen where it
    // was typed: a prompt that does not echo (a password, in any language)
    // or that echoes asterisks fails that check. At most one call per Enter.
    const recordLine = (line: Submitted<LineStart>) => {
      const start = line.start;
      if (!start) return;
      if (!line.consistent || line.text.trim().length < 3 || isRecordingPaused(sessionId)
          || looksLikeSecretPrompt(recentOutputRef.current)) {
        start.marker.dispose();
        return;
      }
      const check = (retries: number[]) => {
        if (disposed || start.marker.isDisposed) return;
        if (echoedAt(term.buffer.normal, start.marker.line, start.x, line.text)) {
          start.marker.dispose();
          invoke('cmd_history_add', {
            serverId: serverId > 0 ? serverId : null,
            serverName: serverName || "",
            command: line.text,
          }).catch(() => { /* silent — history logging is best-effort */ });
        } else if (retries.length > 0) {
          const timer = window.setTimeout(() => { echoTimers.delete(timer); check(retries.slice(1)); }, retries[0]);
          echoTimers.add(timer);
        } else {
          start.marker.dispose();
        }
      };
      check(ECHO_RECHECKS_MS);
    };

    const onDataDisposable = term.onData((data) => {
      if (disabledRef.current || sessionEndedRef.current) return;
      // Text with line breaks that arrives without a paste event (a soft
      // keyboard's clipboard suggestion, an input method) takes the paste
      // path too: its markers are removed and it may ask first (F-083).
      if (!pastingRef.current && data.length > 1 && /[\r\n]/.test(data) && !data.startsWith('\x1b')) {
        void pasteText(data);
        return;
      }
      const mods = modifiersRef.current;
      const hasMod = mods.ctrl !== "off" || mods.alt !== "off";
      let bytes: number[];

      // ── Text-expansion snippets (F-084) ──────────────────────────────────
      // Fires only on a single plain delimiter keystroke (Space/Tab/Enter, no
      // Ctrl/Alt) whose preceding word matches a configured trigger exactly,
      // and only while the tracked line is known to match what the shell
      // holds: nothing but typed characters and Backspace since the line
      // began, shown on screen where it was typed (so never at a prompt that
      // does not echo, and never after cursor keys or completion), and not at
      // what looks like a prompt for a secret. The trigger is erased with one
      // Backspace per character (code point), the expansion typed in its
      // place, and Space/Tab replayed; Enter is not: it only expands, and the
      // next Enter runs the line the user has now seen (snippetKeys).
      let expandedBytes: number[] | null = null;
      let swallowedEnter = false;
      if (!hasMod && data.length === 1 && textSnippetsEnabledRef.current) {
        const ch0 = data.charCodeAt(0);
        if (ch0 === 0x20 || ch0 === 0x09 || ch0 === 0x0d) {
          const word = tracker.currentWord();
          const expansion = word ? snippetsMapRef.current[word] : undefined;
          const start = tracker.start;
          // A snippet of several lines is left alone where the program
          // would run each one (no bracketed paste): it never presses Enter.
          const runsLines = !!expansion && /[\r\n]/.test(expansion) && !term.modes.bracketedPasteMode;
          if (runsLines && tracker.consistent) notify('Snippet not expanded: its lines would run here', 'err');
          if (expansion && !runsLines && tracker.consistent && start && !start.marker.isDisposed
              && echoedSoFar(term.buffer.normal, start.marker.line, start.x, tracker.text)
              && !looksLikeSecretPrompt(recentOutputRef.current)) {
            const keys = snippetKeys(word, expansion, data, term.modes.bracketedPasteMode);
            expandedBytes = Array.from(new TextEncoder().encode(keys));
            // Keep the tracked line in sync with what actually ends up on
            // the line (the expansion), not the raw trigger that was typed.
            tracker.replaceWord(word, expansion);
            swallowedEnter = ch0 === 0x0d;
          }
        }
      }

      if (expandedBytes) {
        bytes = expandedBytes;
      } else if (hasMod && data.length === 1) {
        const code = data.charCodeAt(0);
        let ch = code;
        if (mods.ctrl !== "off") {
          if ((code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a)) {
            // Letters → C0 control (Ctrl+A = 0x01 … Ctrl+Z = 0x1a). `code & 0x1f`
            // does the right thing for both upper- and lower-case letters.
            ch = code & 0x1f;
          }
          // Non-letters under Ctrl are left as-is — Android's soft keyboard
          // rarely lets the user type the ones with defined C0 mappings
          // (Ctrl+@, Ctrl+[, Ctrl+\, Ctrl+] etc.) anyway, and silently
          // mangling normal punctuation while a Ctrl chip is lit would
          // confuse more than help.
        }
        bytes = [];
        if (mods.alt !== "off") bytes.push(0x1b); // ESC prefix → Meta
        bytes.push(ch);
        consumeArmedModifiers();
      } else {
        bytes = Array.from(new TextEncoder().encode(data));
      }
      invoke('write_terminal_data', {
        terminalId,
        data: bytes,
      }).catch(console.error);

      // ── Broadcast fan-out ────────────────────────────────────────────────
      // Broadcast writes AFTER the local write so if the fan-out throws
      // synchronously it doesn't drop the source shell's own byte. We only
      // fan out when there are 2+ selected targets — a single target would
      // let the user broadcast to a single foreign session, which is
      // technically fine but almost always a footgun ("wait, why did that
      // command run there instead of here?"). 2+ makes the intent explicit.
      const bcast = broadcastRef.current;
      // Fan out ONLY when the source session is itself one of the armed
      // targets. Without this guard, typing into an unrelated session (not in
      // the target set) still wrote to every target — so a command meant only
      // for the focused server would silently execute on the broadcast group.
      // Requiring the source to be a member makes "this pane broadcasts to the
      // group" the explicit, safe model.
      //
      // Not fanned out (F-085): xterm's answers to this terminal's own queries
      // (they belong to its program), and anything typed while this terminal
      // looks like it is asking for a secret: a sudo password typed here must
      // not be typed into the other sessions, whatever they are doing. A
      // banner says so until the prompt is gone.
      const broadcasting = bcast.enabled && bcast.targetSessionIds.size >= 2 && bcast.targetSessionIds.has(sessionId);
      const secretHere = broadcasting && looksLikeSecretPrompt(recentOutputRef.current);
      holdBroadcast(secretHere);
      if (broadcasting && !secretHere && !isTerminalReply(data)) {
        for (const targetSid of bcast.targetSessionIds) {
          if (targetSid === sessionId) continue; // skip source; already written
          const targetTid = bcast.sessionTerminalMap[targetSid];
          if (!targetTid) continue; // target has no live terminal — silently skip
          invoke('write_terminal_data', {
            terminalId: targetTid,
            data: bytes,
          }).catch(() => {
            // Dead target — do NOT surface. The user asked for fire-and-forget
            // fan-out; failures here would spam their console every keystroke.
          });
        }
      }

      // ── Command history capture ──────────────────────────────────────────
      // The tracker gets what was sent: a key-bar Ctrl or Alt turns a letter
      // into a control key. (An Enter that only expanded a snippet submitted
      // nothing.)
      const sent = hasMod && data.length === 1 && !expandedBytes ? String.fromCharCode(...bytes) : data;
      if (!swallowedEnter) for (const line of tracker.feed(sent)) recordLine(line);
    });

    // ---- Copy on select / paste on right-click (PuTTY-style), or a Copy/Paste
    // context menu instead when that setting is off ----------------------------
    // Selection-change fires per mouse move during a drag — that's noisy AND
    // it would clobber the clipboard mid-drag. We instead wait for the user
    // to release the mouse, then copy whatever is currently selected.
    //
    // Copy-on-select must fire wherever the mouse is RELEASED — not only inside
    // the terminal. A user who drags a selection and lets go past the terminal's
    // edge (a very natural motion) still expects the copy, but the old handler
    // listened for `mouseup` on the terminal element itself, so a release
    // outside it never fired and only left the text selected.
    //
    // Instead: ARM on a left-button mousedown that starts inside this terminal,
    // then catch `mouseup` on the DOCUMENT so the release is seen anywhere.
    // Requiring the drag to have started here keeps an unrelated release
    // elsewhere from touching the clipboard, and copySelectionIfAny() no-ops
    // when there's no real selection — so a plain click (which clears the
    // selection) still can't clobber it. The selection end is set by the last
    // mousemove, so it's final by the time we read it on mouseup.
    let selectionArmed = false;
    const onMouseDown = (ev: MouseEvent) => {
      // Assign (not just set-true) so a non-left mousedown re-disarms a flag
      // that got stuck from an earlier drag whose mouseup we never saw.
      selectionArmed = ev.button === 0;
    };
    const onDocMouseUp = (ev: MouseEvent) => {
      if (ev.button !== 0 || !selectionArmed) return;
      selectionArmed = false;
      if (!puttyClipboardRef.current) return;
      void copySelectionIfAny();
    };
    // If the window loses focus mid-drag (Alt-Tab, a focus-stealing dialog),
    // the button is released over another window and the matching `mouseup`
    // never reaches `document`, leaving selectionArmed stuck true. A later
    // unrelated left-click would then copy this terminal's stale selection and
    // clobber the clipboard. Disarm on blur so only a release we actually see
    // can copy.
    const onWindowBlur = () => { selectionArmed = false; };
    // Right-click always needs preventDefault to swallow the platform context
    // menu, regardless of mode. In the off mode it also opens our own small
    // Copy/Paste menu (rendered in this component's JSX, below) — pure state,
    // no clipboard access, so it's safe to do here. PuTTY mode's direct paste
    // is NOT done here — see onAuxClick just below for why.
    const onContextMenu = (ev: MouseEvent) => {
      ev.preventDefault();
      if (puttyClipboardRef.current) return;
      const MENU_W = 140, MENU_H = 76;
      const x = Math.max(4, Math.min(ev.clientX, window.innerWidth - MENU_W - 4));
      const y = Math.max(4, Math.min(ev.clientY, window.innerHeight - MENU_H - 4));
      setClipMenu({ x, y, canCopy: term.hasSelection(), canPaste: !disabledRef.current });
    };
    // Originally needed because WebKitGTK didn't treat a `contextmenu`
    // handler as a "real click" for the browser's own clipboard permission
    // model — verified directly against a live SSH session on Linux/
    // WebKitGTK, `auxclick` (the standard event for "a click with a non-
    // primary button") worked there where reading from `contextmenu` was
    // silently denied. pasteFromClipboard now goes through the backend's
    // read_clipboard_text command instead of navigator.clipboard, which
    // isn't subject to that browser-level restriction at all — but the split
    // is harmless to keep (both events fire from the same physical
    // right-click, paste still happens exactly once) and removing it isn't
    // needed to fix anything, so it stays.
    const onAuxClick = (ev: MouseEvent) => {
      if (ev.button !== 2 || !puttyClipboardRef.current) return;
      void pasteFromClipboard();
    };
    // The keyboard's paste (and a soft keyboard's) goes through pasteText
    // too: caught on the way down, before xterm's own paste handler runs.
    const onPaste = (ev: ClipboardEvent) => {
      ev.preventDefault();
      ev.stopPropagation();
      void pasteText(ev.clipboardData?.getData('text/plain') ?? '');
    };
    terminalRef.current.addEventListener('paste', onPaste, true);
    terminalRef.current.addEventListener('mousedown', onMouseDown);
    document.addEventListener('mouseup', onDocMouseUp);
    window.addEventListener('blur', onWindowBlur);
    terminalRef.current.addEventListener('contextmenu', onContextMenu);
    terminalRef.current.addEventListener('auxclick', onAuxClick);

    // Handle Resize
    const onResizeDisposable = term.onResize(({ cols, rows }) => {
      invoke('resize_terminal', { terminalId, cols, rows }).catch(console.error);
    });

    // Flow control (F-031): the backend stops sending this terminal's output
    // once 2 MiB are unacknowledged, so every batch is acknowledged after
    // xterm has processed it (its write callback). Acknowledgements are
    // summed and sent at most every 30 ms, or at once past 512 KiB. Only the
    // instance that owns the PTY acknowledges: Wall's attach-only copies
    // parse the same output on the same thread and cannot fall far behind.
    let ackPending = 0;
    let ackTimer = 0;
    const sendAck = () => {
      ackTimer = 0;
      const bytes = ackPending;
      ackPending = 0;
      if (bytes > 0) invoke('ack_terminal_output', { terminalId, bytes }).catch(() => { /* terminal gone */ });
    };
    const ackOutput = (bytes: number) => {
      ackPending += bytes;
      if (ackPending >= 512 * 1024) {
        if (ackTimer) window.clearTimeout(ackTimer);
        sendAck();
      } else if (!ackTimer) {
        ackTimer = window.setTimeout(sendAck, 30);
      }
    };

    // Keyword highlighting keeps its own parser state across output events.
    const highlighter = createHighlighter();

    // Handle Output with proper async cleanup for StrictMode
    const unlistenPromise = listen(`terminal-output-${terminalId}`, (event: any) => {
      // The backend now coalesces output and sends it base64-encoded (was a raw
      // JSON byte array — ~4x larger and one event per SSH packet, which flooded
      // this main-thread handler and froze the tab on big output). Decode back
      // to bytes; xterm buffers any multibyte sequence split across batches.
      const bin = atob(event.payload as string);
      const data = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) data[i] = bin.charCodeAt(i);
      // The size the backend counted: before highlighting adds colour codes.
      const received = data.length;
      term.write(highlighter.apply(data, matcherRef.current), attachOnly ? undefined : () => ackOutput(received));
      // Keep a short tail of decoded output so command-history capture can
      // recognize a no-echo password prompt and skip the typed secret.
      // Decodes the ORIGINAL bytes, not the highlighted ones — unaffected by
      // whatever the highlighter did above.
      try {
        const txt = new TextDecoder().decode(data);
        const combined = recentOutputRef.current + txt;
        recentOutputRef.current = combined.length > 512 ? combined.slice(-512) : combined;
      } catch { /* decode hiccup on a split multibyte chunk — ignore */ }
      if (broadcastHeldRef.current && !looksLikeSecretPrompt(recentOutputRef.current)) holdBroadcast(false);
    });

    // Fires when the backend's PTY read loop ends — the remote shell exited
    // (exit/Ctrl+D/TMOUT sends EOF), a write hit a dead transport, or this
    // terminal_id's entry was removed from terminal_txs (closing this tab
    // normally does that too, via close_terminal in the cleanup below —
    // intentionallyClosingRef tells the two apart). attachOnly instances
    // (Wall's mirrored viewers) don't own the PTY lifecycle, so they ignore
    // it entirely — showing "session stopped" there wouldn't offer a
    // sensible restart/exit anyway.
    //
    // Written directly into the terminal as text, not a separate floating
    // overlay — same treatment as the existing reconnect divider just above,
    // and it means the message is naturally part of "save output to file"
    // and needs no positioning/z-index work of its own.
    const unlistenClosedPromise = attachOnly
      ? Promise.resolve(() => {})
      : listen(`terminal-closed-${terminalId}`, () => {
          if (intentionallyClosingRef.current) return;
          markSessionEnded('Session stopped');
        });

    // Coalesce resize bursts via rAF, and skip the refit on hidden tabs
    // so SIGWINCH doesn't leak to background PTYs (the become-visible
    // effect refits when the tab is shown again).
    let rafId = 0;
    const resizeObserver = new ResizeObserver(() => {
      if (!xtermRef.current) return;
      if (!shownRef.current) return;
      if (suppressResizeRef.current) return; // tool pane transition in flight — see suppressResize
      if (rafId) return; // a rAF is already queued; coalesce
      rafId = requestAnimationFrame(() => {
        rafId = 0;
        if (!xtermRef.current) return;
        if (!shownRef.current) return;
        if (suppressResizeRef.current) return;
        try {
          fitAddon.fit();
          const t = xtermRef.current;
          t.refresh(0, Math.max(0, t.rows - 1));
        } catch { /* swallow — xterm tolerates transient 0×0 sizes */ }
      });
    });
    resizeObserver.observe(terminalRef.current);
    
    // Handle Settings Change
    const handleSettingsChange = () => {
      const newSize = parseInt(localStorage.getItem('solanum-terminal-font-size') || '14');
      let needsFit = false;
      if (term.options.fontSize !== newSize) {
        term.options.fontSize = newSize;
        needsFit = true;
      }
      const newFamily = terminalFontFamily(localStorage.getItem('solanum-terminal-font-family'));
      if (term.options.fontFamily !== newFamily) {
        term.options.fontFamily = newFamily;
        needsFit = true; // a different font's glyph width changes the cell grid
      }
      if (needsFit) fitAddon.fit();
      const scrollback = loadScrollback();
      if (term.options.scrollback !== scrollback) term.options.scrollback = scrollback;
      // Cursor style/blink don't affect cell geometry, so no re-fit needed —
      // xterm redraws the cursor itself as soon as these options change.
      const newCursorStyle = localStorage.getItem('solanum-terminal-cursor-style') === 'bar' ? 'bar' : 'block';
      term.options.cursorBlink = effectiveCursorBlink(newCursorStyle, localStorage.getItem('solanum-terminal-cursor-blink') !== '0');
      term.options.cursorStyle = newCursorStyle;
      term.options.cursorInactiveStyle = cursorInactiveStyleFor(newCursorStyle);
      // Covers both a direct theme-picker change AND tweaking the accent /
      // background colors while "Match App Colors" is the active theme —
      // loadTerminalTheme() re-reads all three keys every time regardless.
      // Guarded by VALUE, not assigned unconditionally: this handler fires
      // on every settings change, not just theme ones, and the "app" branch
      // builds a brand-new object on every call — xterm only skips its own
      // (expensive: full ANSI color-table rebuild + repaint) theme update
      // when the option reference changes, so without this check every
      // unrelated settings tweak, and every tick of a dragged color picker,
      // would force a full repaint in every open terminal.
      const newTheme = loadTerminalTheme();
      if (JSON.stringify(term.options.theme) !== JSON.stringify(newTheme)) {
        term.options.theme = newTheme;
        setTermBg(newTheme.background);
      }
      matcherRef.current = loadHighlightMatcher();
      puttyClipboardRef.current = loadPuttyClipboard();
      useCommandHistorySearchRef.current = loadUseCommandHistorySearch();
      textSnippetsEnabledRef.current = loadUseTextSnippets();
      // Flipping the setting while the off-mode menu happens to be open
      // would otherwise leave it showing, now stale, for whichever mode was
      // active when it was opened.
      setClipMenu(null);
    };
    window.addEventListener('solanum-settings-changed', handleSettingsChange);

    // Snippet data lives in the vault, not localStorage, so it needs its own
    // fetch (on mount) and its own refresh signal — Library dispatches this
    // after every add/edit/delete so an open terminal picks up the change
    // without having to be reopened. attachOnly instances fetch it too (a
    // mirrored terminal never types, so the map just goes unused there) —
    // simpler than threading an extra prop through just to skip a cheap call.
    const fetchSnippets = () => {
      invoke<{ trigger: string; expansion: string }[]>('get_snippets')
        .then((rows) => {
          const map: Record<string, string> = {};
          for (const r of rows) map[r.trigger] = r.expansion;
          snippetsMapRef.current = map;
        })
        .catch(() => { /* vault not reachable yet, or no snippets — leave the map as-is */ });
    };
    fetchSnippets();
    window.addEventListener('solanum-snippets-changed', fetchSnippets);

    // ── Mobile QoL ───────────────────────────────────────────────────────────
    // Capture the container ref here so the listener add/remove calls and the
    // cleanup closure all reference the same element — the live ref can flip
    // to null between mount and cleanup if React tears the subtree down out
    // of order, and we'd leak event handlers in that case.
    const container = terminalRef.current;
    // On soft-keyboard open (`visualViewport.resize` shrinks) refit so xterm's
    // row count matches the now-shorter visible area and scroll to the
    // prompt so the cursor row sits just above the kb.
    //
    // We deliberately do NOT hook mousedown / touchstart here. Those fire at
    // the START of a selection drag, and a scrollToBottom() there yanks the
    // viewport out from under the user's finger and destroys the selection
    // anchor (v0.2.30-v0.2.31 regression). xterm already scrolls on user
    // keystrokes via `scrollOnUserInput` (default true) and on PTY writes,
    // so tapping to focus + typing already reveals the prompt without our
    // help. This handler is what actually implements "keyboard opens →
    // prompt in view" and is the only trigger we want.
    //
    // No-op on desktop: visualViewport.resize doesn't fire from window resizes,
    // only virtual-keyboard / pinch-zoom.
    const scrollPromptIntoView = () => {
      requestAnimationFrame(() => {
        try { fitAddon.fit(); } catch { /* terminal not ready */ }
        term.scrollToBottom();
      });
    };

    let lastVvHeight = window.visualViewport?.height ?? window.innerHeight;
    const onVvResize = () => {
      const h = window.visualViewport?.height ?? window.innerHeight;
      if (h < lastVvHeight - 80) {
        // Drop ≥80px almost always means the soft keyboard opened (not a
        // small browser-UI reflow). 80px is comfortably above the URL-bar
        // collapse delta on Chrome/Android.
        scrollPromptIntoView();
      }
      lastVvHeight = h;
    };
    window.visualViewport?.addEventListener('resize', onVvResize);

    return () => {
      // First thing, synchronously: close_terminal below makes the backend
      // emit the exact same terminal-closed event a real shell exit does,
      // and this has to be set before that fires or "Session stopped" would
      // print into the terminal right as a normally-closed tab disappears.
      intentionallyClosingRef.current = true;
      liveRef.current = false;
      cancelled = true;
      window.clearTimeout(openTimer);
      if (terminalOwners.get(terminalId) === owner) terminalOwners.delete(terminalId);
      window.removeEventListener('solanum-settings-changed', handleSettingsChange);
      window.removeEventListener('solanum-snippets-changed', fetchSnippets);
      resizeObserver.disconnect();
      onDataDisposable.dispose();
      onResizeDisposable.dispose();
      if (container) {
        container.removeEventListener('paste', onPaste, true);
        container.removeEventListener('mousedown', onMouseDown);
        container.removeEventListener('contextmenu', onContextMenu);
        container.removeEventListener('auxclick', onAuxClick);
      }
      document.removeEventListener('mouseup', onDocMouseUp);
      window.removeEventListener('blur', onWindowBlur);
      window.visualViewport?.removeEventListener('resize', onVvResize);
      if (toastTimerRef.current) window.clearTimeout(toastTimerRef.current);
      if (ackTimer) window.clearTimeout(ackTimer);
      disposed = true;
      echoTimers.forEach((t) => window.clearTimeout(t));
      trackerRef.current = null;
      unlistenPromise.then(unlisten => unlisten());
      unlistenClosedPromise.then(unlisten => unlisten());
      searchAddon.dispose();
      searchAddonRef.current = null;
      term.dispose();
      // Only the PTY owner tears the backend PTY down on unmount.
      // Attach-only viewers unmount without closing so the primary
      // xterm (in the session tab) keeps working.
      if (!attachOnly) {
        invoke('close_terminal', { terminalId }).catch(console.error);
      }
    };
  }, [sessionId, terminalId]);

  return (
    // flex-col so the MobileKeyBar can pin to the bottom of the terminal
    // pane (between xterm and the system soft keyboard). On desktop the bar
    // isn't rendered at all, so the xterm child claims the full height as
    // before.
    <div className="h-full w-full p-2 pr-2 pb-0 relative flex flex-col" style={{ backgroundColor: termBg }}>
      <div
        ref={terminalRef}
        className="flex-1 min-h-0 w-full overflow-hidden select-text"
      />
      {/* Search chip — floats above xterm; positioned inside the outer
          flex column so it never displaces the terminal grid. Absolute
          top-2 right-2 keeps it clear of the disconnected badge (which
          centers) and the clipboard toast (bottom-right). */}
      {showSearch && (
        <div className="absolute top-2 right-2 z-20 flex items-center gap-1 rounded-md bg-zinc-800 border border-white/10 px-1.5 py-1 shadow-lg">
          <input
            ref={searchInputRef}
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              // Stop keys from leaking to the document listener (Ctrl+F
              // reopen loop) and to xterm's textarea (which would type
              // into the shell).
              if (e.key === 'Escape') {
                e.preventDefault();
                setQuery('');
                closeSearch();
              } else if (e.key === 'Enter') {
                e.preventDefault();
                runFind(e.shiftKey ? 'prev' : 'next');
              } else if ((e.ctrlKey || e.metaKey) && (e.key === 'f' || e.key === 'F')) {
                // Swallow so the outer document handler doesn't re-fire
                // (which would just refocus us — harmless but noisy).
                e.preventDefault();
                (e.currentTarget as HTMLInputElement).select();
              }
              e.stopPropagation();
            }}
            placeholder="Find"
            className="bg-transparent outline-none text-[12px] text-zinc-100 placeholder:text-zinc-500 w-40 px-1"
          />
          <button
            type="button"
            onClick={() => runFind('prev')}
            title="Previous match (Shift+Enter)"
            className="px-1.5 py-0.5 text-[11px] text-zinc-300 hover:text-white hover:bg-white/5 rounded"
          >
            {'↑'}
          </button>
          <button
            type="button"
            onClick={() => runFind('next')}
            title="Next match (Enter)"
            className="px-1.5 py-0.5 text-[11px] text-zinc-300 hover:text-white hover:bg-white/5 rounded"
          >
            {'↓'}
          </button>
          <button
            type="button"
            onClick={() => { setQuery(''); closeSearch(); }}
            title="Close (Esc)"
            className="px-1.5 py-0.5 text-[11px] text-zinc-400 hover:text-white hover:bg-white/5 rounded"
          >
            {'✕'}
          </button>
        </div>
      )}
      {isMobile && !disabled && (
        <MobileKeyBar
          modifiers={modifiers}
          onToggleModifier={toggleModifier}
          onSpecialKey={sendSpecialKey}
        />
      )}
      {/* Clipboard toast — bottom-right of the terminal pane. Pointer-events
          off so a stray hover never blocks selection / right-click. */}
      {toast && (
        <div className="absolute bottom-3 right-3 z-20 pointer-events-none">
          <span
            className={`px-2.5 py-1 rounded text-[10.5px] font-mono uppercase tracking-wider border ${
              toast.tone === 'err'
                ? 'bg-rose-500/15 border-rose-500/30 text-rose-300'
                : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
            }`}
          >
            {toast.msg}
          </span>
        </div>
      )}
      {/* Copy/Paste context menu — only ever mounted when PuTTY-style
          clipboard is off (the setting's other mode pastes directly on
          right-click instead, no menu). Portaled to <body> since this pane
          can sit inside a scrolled/transformed ancestor (session tabs, the
          Wall grid) where a merely `absolute` menu could end up clipped or
          mispositioned. */}
      {clipMenu && createPortal(
        <div
          ref={clipMenuRef}
          style={{ top: clipMenu.y, left: clipMenu.x }}
          className="fixed z-[9999] min-w-[130px] bg-[#0c0c0e] border border-white/10 rounded-lg shadow-2xl p-1 font-mono text-[11.5px] text-zinc-200"
        >
          <button
            onClick={() => { void copySelectionIfAny(); closeClipMenu(); }}
            disabled={!clipMenu.canCopy}
            className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-white/10 text-left hover:text-white disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-zinc-200 disabled:cursor-default"
          >
            <span>Copy</span>
          </button>
          <button
            onClick={() => { void pasteFromClipboard(); closeClipMenu(); }}
            disabled={!clipMenu.canPaste}
            title={clipMenu.canPaste ? undefined : "Disconnected — buffer is read-only"}
            className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-white/10 text-left hover:text-white disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-zinc-200 disabled:cursor-default"
          >
            <span>Paste</span>
          </button>
        </div>,
        document.body
      )}
      <HistorySearchOverlay
        isOpen={showHistory}
        onClose={() => {
          setShowHistory(false);
          // Return focus to xterm so the user can keep typing at the prompt
          // instead of losing keystrokes into the void.
          xtermRef.current?.focus();
        }}
        filterServerId={serverId > 0 ? serverId : null}
        onInsert={(command, execute) => {
          if (disabledRef.current) return;
          const payload = execute ? command + "\r" : command;
          const bytes = Array.from(new TextEncoder().encode(payload));
          invoke('write_terminal_data', { terminalId, data: bytes }).catch(console.error);
          // The tracked line gets what was inserted, as if typed (a run
          // command arrives as one chunk with Enter: not recorded again).
          trackerRef.current?.feed(payload);
        }}
      />
      {/* Disabled badge: NON-blocking. xterm stays interactive for scroll +
          mouse selection so the user can copy whatever was on screen at the
          time the session dropped. Keystrokes are still swallowed at the
          source via `disabledRef` in the onData callback — no input reaches
          a dead PTY. `pointer-events-none` keeps the badge from eating the
          select-drag that starts under it. */}
      {broadcastHeld && broadcast.enabled && !disabled && (
        <div className="absolute top-2 left-1/2 -translate-x-1/2 z-10 pointer-events-none max-w-[90%]">
          <span className="block px-2.5 py-1 rounded text-[10.5px] font-mono tracking-wide border bg-[#241c0b] border-amber-500/40 text-amber-200 shadow-lg text-center">
            Broadcast paused here: this terminal is asking for a password. What you type goes to this terminal only.
          </span>
        </div>
      )}
      {disabled && (
        <div className="absolute top-2 left-1/2 -translate-x-1/2 z-10 pointer-events-none">
          <span className="px-2.5 py-1 rounded text-[10.5px] font-mono uppercase tracking-wider border bg-rose-500/15 border-rose-500/30 text-rose-300 shadow-lg">
            Disconnected — buffer is read-only
          </span>
        </div>
      )}
    </div>
  );
};

export default TerminalView;