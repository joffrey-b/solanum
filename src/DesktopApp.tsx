import { useState, useEffect, useCallback, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  Plus, X, Key, Trash2,
  Shield, User, TerminalSquare, Edit2,
  StickyNote, Search, Square, Copy, ChevronLeft, MoreVertical, Radio,
  ChevronDown, Columns, LayoutGrid, Pin, PinOff, FolderOpen, Save, Zap
} from "lucide-react";
import { useBroadcast } from "./ui/broadcast";

import ProfileSelectPage from "./components/ProfileSelectPage";
import logoUrl from "./assets/logo.png";
import PasswordField from "./components/PasswordField";
import QuickConnectModal, { QuickAuth } from "./components/QuickConnectModal";
import { useConfirm, useTextPrompt } from "./ui/confirm";
import { exposureWarning, listensBeyondLoopback } from "./util/tunnelBind";
import { visibleName } from "./util/visibleName";
import { useIsNarrow } from "./hooks/useViewport";
import { useTauriEvent } from "./hooks/useTauriEvent";
import { unlistenWhenReady } from "./util/tauriEvents";
import { dropLegacyKeys, setStorageProfile } from "./util/profileStorage";
import { IS_ANDROID } from "./util/platform";
import { Sidebar } from "./components/Sidebar";
import { PinnedPanel } from "./components/PinnedPanel";
import { NodeGrid } from "./components/NodeGrid";
import AddNodePanel from "./components/AddNodePanel";
import TerminalView from "./components/TerminalView";
import SettingsPanel from "./components/SettingsPanel";
import { SessionView } from "./components/SessionView";
import LocalShellView from "./components/LocalShellView";
import LocalShellModal, { LocalShellOpts } from "./components/LocalShellModal";
import MonitoringPanel from "./components/MonitoringPanel";
import { ErrorBoundary } from "./ui/ErrorBoundary";
import { DEFAULT_HIGHLIGHT_LISTS, HighlightList } from "./util/highlight";
import { DEFAULT_TERMINAL_FONT_ID } from "./util/terminalFonts";
import { DEFAULT_TERMINAL_THEME_ID } from "./util/terminalThemes";
import { clampScrollback, loadConfirmRiskyPaste, loadScrollback } from "./util/terminalSettings";
import { isRecordingPaused, keepRecordingPausedFor, setRecordingPaused } from "./util/historyRecording";
import { sessionCloseNeedsConfirm } from "./util/sessionClose";

const appWindow = getCurrentWindow();

// Sessions can be either DB-backed (saved node, `serverId > 0`) or quick
// connect (one-shot, `serverId === 0` and `quickAuth` populated). SessionView
// forwards `quickAuth` to `initiate_connection` which uses it instead of
// looking up the DB row. A third kind, `kind: 'local'`, is a local (non-SSH)
// shell — serverId stays 0 (same orphaned-history sentinel quick connect
// already uses) and `localShell` carries the shell/cwd instead; it renders
// via LocalShellView, not SessionView (see that component's own comment).
type Session = { id: string; serverId: number; serverName: string; mirrors?: string; runOnConnect?: string; quickAuth?: QuickAuth | null; kind?: 'local'; localShell?: LocalShellOpts };

const hexToRgb = (hex: string) => {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return `${r} ${g} ${b}`;
};

function DesktopApp() {
  const [loading, setLoading] = useState(true);
  const [isUnlocked, setIsUnlocked] = useState(false);
  // Set at unlock and cleared at once when locking (not at the next render):
  // what arrives after a lock must not land in the next profile's state.
  const unlockedRef = useRef(false);
  // Multi-exec broadcast state lives in a shared provider (see App.tsx) so
  // TerminalView instances across every tab can read `enabled` + `targets`
  // without prop-drilling. The pill in the tab strip is the toggle + picker.
  const broadcast = useBroadcast();
  const [broadcastMenuOpen, setBroadcastMenuOpen] = useState(false);
  const [activeView, setActiveView] = useState<string>("nodes");
  const [sessions, setSessions] = useState<Session[]>([]);
  // Tracks the live status of each open session ('connecting' | 'connected'
  // | 'failed' | 'disconnected'). Updated via the callback every SessionView
  // fires on its own status change — single source of truth for the dot
  // colour on each tab. Cleared when a session is closed.
  const [sessionStatuses, setSessionStatuses] = useState<Record<string, string>>({});
  // Right-click menu pinned to a session tab. Closed by any click outside or
  // by choosing one of the menu items.
  const [tabMenu, setTabMenu] = useState<{ x: number; y: number; sessionId: string } | null>(null);
  // Sessions merged into the current session-view canvas. When a session
  // tab is being viewed and this set is non-empty, its SessionView renders
  // side-by-side with each merged partner instead of full-width. Used by
  // the "Merge with…" context action on session tabs so users don't need
  // a separate Compare page to see two servers together.
  const [mergedSessionIds, setMergedSessionIds] = useState<string[]>([]);
  // "Wall" pinboard — a permanent tab at the end of the session strip
  // that hosts a user-controlled grid of individual terminals. Each
  // pin is a (sessionId, terminalId) pair; the tile mounts its OWN
  // TerminalView with `attachOnly=true`, hitching onto the same PTY
  // as the primary xterm in the session tab. That means the session
  // still owns the PTY lifecycle (open on tab creation, close on tab
  // close) and the Wall tile is a live mirror — it receives every
  // byte the PTY writes and can also send input into it. Trade-off:
  // scrollback in the Wall tile only accumulates from the moment of
  // pin (the primary xterm holds the full pre-pin history), and the
  // two xterms may fight briefly over resize_terminal on view switch,
  // which reflows correctly once one settles.
  type WallItem = { id: string; sessionId: string; terminalId: string };
  const [wallItems, setWallItems] = useState<WallItem[]>([]);
  // User-controlled grid density. Higher = smaller tiles, tighter row
  // packing. Clamped at 1..6 which covers phone-portrait (1) through
  // wide-monitor (6) comfortably; anything past 6 makes xterm columns
  // useless.
  const [wallCols, setWallCols] = useState<number>(2);
  const [wallPickerOpen, setWallPickerOpen] = useState(false);
  // Per-session terminals + active terminal id, bubbled up from each
  // SessionView via onTerminalsChange. Sourced here so the Wall picker
  // and pin/unpin helpers can enumerate terminals without duplicating
  // SessionView's state.
  type SessionTerm = { id: string; title: string; container?: { name: string; useSudo: boolean }; ended?: boolean };
  const [sessionTerminals, setSessionTerminals] = useState<Record<string, SessionTerm[]>>({});
  const [sessionActiveTerm, setSessionActiveTerm] = useState<Record<string, string>>({});
  const handleTerminalsChange = useCallback((sid: string, terms: SessionTerm[], activeTermId: string) => {
    setSessionTerminals(prev => {
      const cur = prev[sid];
      if (cur && cur.length === terms.length && cur.every((t, i) => t.id === terms[i].id && t.title === terms[i].title && !!t.ended === !!terms[i].ended)) {
        return prev;
      }
      return { ...prev, [sid]: terms };
    });
    setSessionActiveTerm(prev => (prev[sid] === activeTermId ? prev : { ...prev, [sid]: activeTermId }));
  }, []);
  const wallHasTerminal = (terminalId: string) => wallItems.some(i => i.terminalId === terminalId);
  const pinTerminalToWall = (sid: string, terminalId: string) => {
    if (wallHasTerminal(terminalId)) return;
    setWallItems(prev => [...prev, { id: `wall-${terminalId}`, sessionId: sid, terminalId }]);
  };
  const unpinTerminalFromWall = (terminalId: string) => {
    setWallItems(prev => prev.filter(i => i.terminalId !== terminalId));
  };
  const unpinSessionFromWall = (sid: string) => {
    setWallItems(prev => prev.filter(i => i.sessionId !== sid));
  };
  // Mobile-only session picker toggle. Horizontally-scrolling tabs eat
  // the whole title row on a 400 px phone; replacing them with a compact
  // dropdown gives the tab strip predictable width and matches iOS/
  // Android convention of "current context on top, tap to switch".
  const [mobileSessionPickerOpen, setMobileSessionPickerOpen] = useState(false);
  const handleSessionStatus = useCallback((sessionId: string, status: string) => {
    setSessionStatuses((prev) => (prev[sessionId] === status ? prev : { ...prev, [sessionId]: status }));
  }, []);

  // Maximize state mirrored from the OS window so the title-bar button can
  // swap its icon (single square = maximize, overlapping squares = restore)
  // and so the double-click drag-region handler always knows the correct
  // direction to toggle. Tauri's onResized event fires for every maximize /
  // restore / OS-driven snap, so it's the authoritative signal.
  const [isMaximized, setIsMaximized] = useState(false);
  useEffect(() => {
    appWindow.isMaximized().then(setIsMaximized).catch(() => {});
    return unlistenWhenReady(appWindow.onResized(() => {
      appWindow.isMaximized().then(setIsMaximized).catch(() => {});
    }));
  }, []);
  const toggleMaximize = useCallback(() => {
    appWindow.toggleMaximize().catch(console.error);
  }, []);

  // Persist the user's current folder across NodeGrid unmount/remount cycles.
  // NodeGrid is conditionally rendered (`activeView === "nodes" && ...`), so
  // its local state used to vanish the moment the user opened a session tab
  // — and they'd come back to the root folder view instead of the folder
  // they were browsing. Lifting the state here keeps the position sticky
  // for the whole profile session.
  const [activeFolderId, setActiveFolderId] = useState<number | null>(null);
  const [isPanelOpen, setIsPanelOpen] = useState(false);
  const [isQuickConnectOpen, setIsQuickConnectOpen] = useState(false);
  const [isLocalShellOpen, setIsLocalShellOpen] = useState(false);
  const [servers, setServers] = useState<any[]>([]);
  const [credentials, setCredentials] = useState<any[]>([]);
  const [sshKeys, setSshKeys] = useState<any[]>([]);
  const [folders, setFolders] = useState<any[]>([]);
  const [commands, setCommands] = useState<any[]>([]);
  const [logs, setLogs] = useState<{ msg: string, type: string, time: string }[]>([]);
  const [isCommandPanelOpen, setIsCommandPanelOpen] = useState(false);
  const [editCommandData, setEditCommandData] = useState<{ id: number | null, title: string, content: string }>({ id: null, title: "", content: "" });

  const [notes, setNotes] = useState<any[]>([]);
  const [isNotePanelOpen, setIsNotePanelOpen] = useState(false);
  const [editNoteData, setEditNoteData] = useState<{ id: number | null, title: string, body: string }>({ id: null, title: "", body: "" });

  const [snippets, setSnippets] = useState<any[]>([]);
  const [isSnippetPanelOpen, setIsSnippetPanelOpen] = useState(false);
  const [editSnippetData, setEditSnippetData] = useState<{ id: number | null, trigger: string, expansion: string }>({ id: null, trigger: "", expansion: "" });
  // Shared query across Library sub-tabs. Persisting the string across a
  // Commands↔Notes↔Snippets switch lets the user narrow all three lists with
  // the same typing — filter is applied against whichever array is active.
  const [libraryQuery, setLibraryQuery] = useState("");
  const [libraryTab, setLibraryTab] = useState<"commands" | "notes" | "snippets">("commands");

  const [isCredPanelOpen, setIsCredPanelOpen] = useState(false);
  const [editCredData, setEditCredData] = useState<any>({ id: null, name: "", auth_type: "password", username: "", password: "", key_id: null });
  
  const [isKeyPanelOpen, setIsKeyPanelOpen] = useState(false);
  const [editKeyData, setEditKeyData] = useState<any>({ id: null, name: "", public_key: "", private_key: "", passphrase: "" });
  const [formError, setFormError] = useState("");

  // Lets the Add/Edit SSH Key panel populate a field from a file on disk
  // instead of a paste. Reads the file server-side (pick_key_file) and drops
  // its raw text straight into the matching textarea, overwriting whatever
  // was there — same as opening a file normally would.
  const browseKeyFile = async (kind: "public" | "private") => {
    try {
      const text = await invoke<string | null>("pick_key_file", { kind });
      if (text === null) return; // user cancelled the dialog
      setEditKeyData((prev: any) => ({
        ...prev,
        [kind === "public" ? "public_key" : "private_key"]: text,
      }));
    } catch (e) {
      reportError("Could not read the key file", e);
    }
  };

  const defaultNode = {
    id: null as number | null,
    name: "", host: "", port: 22, username: "", password: "",
    // "custom_pass" picked as default because most users adding a new
    // server have a password in hand; the vault option is mainly useful
    // *after* they've saved a few credentials and want to reuse one.
    authType: "custom_pass", credentialId: "", folderId: "", keyId: "",
    proxyType: "none", proxyHost: "", proxyPort: 1080,
    tunnels: [] as { local: string, remote: string, type: string }[],
    autostart: false,
    mirrors: [] as { local: string, remote: string, soft_delete: boolean, excludes: string[], conflict_resolution: string }[],
    color: null as string | null,
    // Free-form per-node description / runbook text. Lives on the server row
    // in the encrypted vault. Empty string by default — the textarea in the
    // panel renders a placeholder when blank.
    notes: "" as string,
    // Commands auto-typed into the FIRST terminal on the INITIAL connect only
    // (never on reconnect or extra shells). Newline-separated. Empty = off.
    runOnConnect: "" as string,
    // ProxyJump: id (as a string, like credentialId/folderId) of another node
    // to bounce through. Empty = connect directly. parseInt'd to a number (or
    // null) at save time.
    jumpHostId: "" as string,
    // Per-node opt-in for SHA-1 key exchange / MACs and ssh-rsa signatures.
    // Off by default; saved with the node by save_server.
    legacyAlgorithms: false,
    // A plain terminal, with no SFTP browser, live info or Docker. Saved with
    // the node by save_server, or from the notice a limited host gets.
    terminalOnly: false,
    // True only after the user typed into the password field on this form
    // instance. If still false at save time, the backend uses
    // `preserve_password` to keep the existing DB column. Without this
    // flag a transient `reveal_server_password` failure would silently
    // wipe the stored secret.
    password_dirty: false,
  };

  // Live width-based "narrow viewport" flag. Replaces a one-shot UA check
  // that couldn't see a desktop window being shrunk by the user — the new
  // hook updates on every resize so layout swaps follow the actual width.
  const isMobile = useIsNarrow();

  // Whether the pinned-servers panel is showing at all. Lifted up here (not
  // owned inside PinnedPanel) because two separate controls toggle it: the
  // panel's own small collapse button and a rail icon in Sidebar — both need
  // to drive the same boolean, and it has to survive PinnedPanel unmounting
  // entirely when closed.
  const [pinnedPanelOpen, setPinnedPanelOpen] = useState<boolean>(() => {
    const v = localStorage.getItem('solanum-pinned-panel-open');
    return v === null ? true : v === '1';
  });
  const togglePinnedPanel = () => {
    setPinnedPanelOpen((prev) => {
      const next = !prev;
      try { localStorage.setItem('solanum-pinned-panel-open', next ? '1' : '0'); } catch { /* per-viewer convenience only */ }
      return next;
    });
  };

  const loadHighlightLists = (): HighlightList[] => {
    try {
      const raw = localStorage.getItem('solanum-highlight-lists');
      return raw ? JSON.parse(raw) : DEFAULT_HIGHLIGHT_LISTS;
    } catch {
      return DEFAULT_HIGHLIGHT_LISTS;
    }
  };

  const [newNode, setNewNode] = useState(defaultNode);
  const closeNodePanel = () => { setIsPanelOpen(false); setNewNode(defaultNode); setFormError(""); };
  // Closing an editor drops what it held (F-022): a revealed password, key or
  // passphrase stays neither in state nor in an input of a hidden panel. The
  // editors are rendered only while open.
  const EMPTY_COMMAND = { id: null, title: "", content: "" };
  const EMPTY_NOTE = { id: null, title: "", body: "" };
  const EMPTY_SNIPPET = { id: null, trigger: "", expansion: "" };
  const EMPTY_CRED = { id: null, name: "", auth_type: "password", username: "", password: "", key_id: null };
  const EMPTY_KEY = { id: null, name: "", public_key: "", private_key: "", passphrase: "" };
  const closeCommandPanel = () => { setIsCommandPanelOpen(false); setEditCommandData(EMPTY_COMMAND); setFormError(""); };
  const closeNotePanel = () => { setIsNotePanelOpen(false); setEditNoteData(EMPTY_NOTE); setFormError(""); };
  const closeSnippetPanel = () => { setIsSnippetPanelOpen(false); setEditSnippetData(EMPTY_SNIPPET); setFormError(""); };
  const closeCredPanel = () => { setIsCredPanelOpen(false); setEditCredData(EMPTY_CRED); setFormError(""); };
  const closeKeyPanel = () => { setIsKeyPanelOpen(false); setEditKeyData(EMPTY_KEY); setFormError(""); };
  const [appSettings, setAppSettings] = useState({
    primaryColor: localStorage.getItem('solanum-primary-color') || '#60a5fa',
    backgroundColor: localStorage.getItem('solanum-bg-color') || '#0a0a0c',
    terminalFontSize: parseInt(localStorage.getItem('solanum-terminal-font-size') || '14'),
    terminalScrollback: loadScrollback(),
    // Stored as the font's id (e.g. "jetbrains-mono"), not its CSS
    // font-family string — keeps localStorage stable if a font's own family
    // string ever needs to change, and terminalFontFamily() in
    // util/terminalFonts.ts resolves it, falling back to the default for an
    // id that no longer exists (e.g. after a future list edit).
    terminalFontFamily: localStorage.getItem('solanum-terminal-font-family') || DEFAULT_TERMINAL_FONT_ID,
    // xterm's own ICursorStyle union also has "underline"; not offered here
    // since the ask was specifically block vs. line (xterm's "bar").
    terminalCursorStyle: (localStorage.getItem('solanum-terminal-cursor-style') === 'bar' ? 'bar' : 'block') as 'block' | 'bar',
    terminalCursorBlink: localStorage.getItem('solanum-terminal-cursor-blink') !== '0',
    // "app" (default) derives the terminal's background/cursor/selection
    // from primaryColor/backgroundColor below, which is what makes e.g. an
    // OLED-black background setting actually reach the terminal — named
    // themes use their own fixed, authentic palette instead. See
    // util/terminalThemes.ts.
    terminalThemeId: localStorage.getItem('solanum-terminal-theme') || DEFAULT_TERMINAL_THEME_ID,
    highlightEnabled: localStorage.getItem('solanum-highlight-enabled') !== '0',
    highlightLists: loadHighlightLists(),
    // PuTTY-style clipboard: select-to-copy, right-click-to-paste, no menu.
    // Off means neither happens automatically — right-click instead opens a
    // small Copy/Paste context menu (TerminalView owns both behaviors; this
    // is just the one flag it reads).
    puttyClipboard: localStorage.getItem('solanum-putty-clipboard') !== '0',
    // Ask before a paste that holds control characters or would run lines one
    // by one (F-083). On by default.
    confirmRiskyPaste: loadConfirmRiskyPaste(),
    // Gates the confirm dialog before dropping a session with a live shell
    // in it — both the session's own top tab and each of its clone tabs
    // (see sessionCloseNeedsConfirm / terminalCloseNeedsConfirm). Off means
    // every close happens immediately with no prompt, but the SSH
    // connection / PTY is still torn down exactly the same way either way —
    // this only ever skips the confirmation, never the actual cleanup.
    warnOnCloseActiveSession: localStorage.getItem('solanum-warn-close-active-session') !== '0',
    // Off by default: Ctrl+R (Cmd+R) is reverse-i-search muscle memory in
    // every shell, and nobody asked for it to be intercepted. When on,
    // TerminalView pops a cross-session command-history search instead
    // (backed by the vault's cmd_history table) and stops the keystroke from
    // also reaching the shell.
    useCommandHistorySearch: localStorage.getItem('solanum-use-command-history-search') === '1',
    // Off by default. When on, every terminal (including container exec
    // shells) writes a byte-for-byte transcript to sessionLogDir as it goes,
    // not just on an explicit "Save output to file". sessionLogDir is
    // resolved to a concrete path the first time this is turned on (see
    // SettingsPanel) — empty here just means "not chosen yet".
    alwaysLogSessions: localStorage.getItem('solanum-always-log-sessions') === '1',
    sessionLogDir: localStorage.getItem('solanum-session-log-dir') || '',
    // Off by default — same reasoning as Ctrl+R above: typing should never
    // do something other than what was typed unless the user explicitly
    // asked for it. When on, TerminalView expands a trigger word (defined
    // in Library > Snippets) into its full text the moment Space/Tab/Enter
    // is pressed right after it.
    useTextSnippets: localStorage.getItem('solanum-use-text-snippets') === '1',
  });

  // Tracks the last highlight fields actually written, so dragging an
  // unrelated control (the accent-color <input type="color"> fires onChange
  // continuously) doesn't re-serialize highlightLists — an array, unlike the
  // handful of primitives beside it — on every tick of an unrelated drag.
  // Reference equality is enough: highlightEnabled/highlightLists only ever
  // change via a genuinely new value from the Highlighting UI, never an
  // incidental copy from spreading `settings` elsewhere.
  const lastWrittenHighlightRef = useRef<{ enabled: boolean; lists: typeof appSettings.highlightLists } | null>(null);

  useEffect(() => {
    const rgb = hexToRgb(appSettings.primaryColor);
    document.documentElement.style.setProperty('--primary', rgb);
    document.documentElement.style.setProperty('--primary-hex', appSettings.primaryColor);
    document.documentElement.style.setProperty('--background', appSettings.backgroundColor);
    localStorage.setItem('solanum-primary-color', appSettings.primaryColor);
    localStorage.setItem('solanum-bg-color', appSettings.backgroundColor);
    localStorage.setItem('solanum-terminal-font-size', appSettings.terminalFontSize.toString());
    localStorage.setItem('solanum-terminal-scrollback', String(clampScrollback(appSettings.terminalScrollback)));
    localStorage.setItem('solanum-terminal-font-family', appSettings.terminalFontFamily);
    localStorage.setItem('solanum-terminal-cursor-style', appSettings.terminalCursorStyle);
    localStorage.setItem('solanum-terminal-cursor-blink', appSettings.terminalCursorBlink ? '1' : '0');
    localStorage.setItem('solanum-terminal-theme', appSettings.terminalThemeId);
    localStorage.setItem('solanum-putty-clipboard', appSettings.puttyClipboard ? '1' : '0');
    localStorage.setItem('solanum-confirm-risky-paste', appSettings.confirmRiskyPaste ? '1' : '0');
    localStorage.setItem('solanum-warn-close-active-session', appSettings.warnOnCloseActiveSession ? '1' : '0');
    localStorage.setItem('solanum-use-command-history-search', appSettings.useCommandHistorySearch ? '1' : '0');
    localStorage.setItem('solanum-always-log-sessions', appSettings.alwaysLogSessions ? '1' : '0');
    localStorage.setItem('solanum-session-log-dir', appSettings.sessionLogDir);
    localStorage.setItem('solanum-use-text-snippets', appSettings.useTextSnippets ? '1' : '0');
    const lastHighlight = lastWrittenHighlightRef.current;
    if (!lastHighlight || lastHighlight.enabled !== appSettings.highlightEnabled || lastHighlight.lists !== appSettings.highlightLists) {
      localStorage.setItem('solanum-highlight-enabled', appSettings.highlightEnabled ? '1' : '0');
      localStorage.setItem('solanum-highlight-lists', JSON.stringify(appSettings.highlightLists));
      lastWrittenHighlightRef.current = { enabled: appSettings.highlightEnabled, lists: appSettings.highlightLists };
    }
    // Tell already-mounted terminals to re-fit with the new font size, and
    // to recompile their highlight matcher from the two keys just above.
    // Without this dispatch the listener in TerminalView is dead code and
    // users have to close+reopen every terminal to see a change.
    window.dispatchEvent(new CustomEvent('solanum-settings-changed'));
  }, [appSettings]);

  useEffect(() => {
    const init = async () => {
      try {
        // Window size and position are remembered by tauri-plugin-window-state (see lib.rs).

        // `isMobile` is now driven by `useIsNarrow()` (live viewport hook)
        // — no one-shot UA detection here anymore.

        // Profile picker comes first now — we no longer probe a single
        // global vault file. `dbExists` is set inside `handleProfileSelected`
        // when the user picks a profile.

        // A reload (the error screen's button, a crashed web view, the dev
        // tools) leaves the backend as it was: lock it, so the picker this
        // lands on really is locked, with no session, tunnel or mirror of the
        // previous page still running out of sight (F-013).
        // Remembered folders and bookmarks from before they were kept per
        // profile belong to no known profile (F-070).
        dropLegacyKeys();
        await invoke("close_profile");
      } catch (e) {
        console.error("Initialization error", e);
        addLog(`INIT_EXCEPTION: ${e}`, "error"); 
      } finally { 
        setLoading(false); 
      }
    };
    init();
  }, []);

  // A closed session's "Don't record command history" goes with it: the next
  // session to that server (same id) records again. Every close path and
  // locking the profile end up here.
  useEffect(() => { keepRecordingPausedFor(sessions.map((s: any) => s.id)); }, [sessions]);

  // Stable per-session close handler. Allocated once per (sess.id) pair so
  // SessionView's memo comparison stays cheap and the prop reference doesn't
  // change just because some other session re-rendered. The closure reads
  // setters which are themselves stable via useState.
  const closeHandlersRef = useRef<Map<string, () => void>>(new Map());
  const getCloseHandler = useCallback((sessId: string) => {
    let h = closeHandlersRef.current.get(sessId);
    if (!h) {
      h = () => {
        setSessions(prev => prev.filter(s => s.id !== sessId));
        setSessionStatuses(prev => { const { [sessId]: _, ...rest } = prev; return rest; });
        setActiveView(prev => (prev === sessId ? "nodes" : prev));
        // Purge the closing session from broadcast state so a stale id doesn't
        // linger in the target set (would let a user re-enable broadcast and
        // silently exclude a phantom target from the count).
        broadcast.removeSession(sessId);
        // If the closing session was merged as a side pane in another
        // session's canvas, drop it — otherwise the tile would render
        // an empty <SessionView>. Collapse the whole split when it
        // falls below the 2-pane minimum.
        setMergedSessionIds(prev => {
          const next = prev.filter(id => id !== sessId);
          return next.length < 2 ? [] : next;
        });
        // Purge the closing session from the Wall pinboard too — a stale
        // tile with no backing SessionView would render blank.
        setWallItems(prev => prev.filter(i => i.sessionId !== sessId));
        closeHandlersRef.current.delete(sessId);
      };
      closeHandlersRef.current.set(sessId, h);
    }
    return h;
  }, [broadcast]);

  // Stable identity matters: SessionView memoises on prop equality, so a
  // fresh `addLog` reference on every DesktopApp render would force every
  // session subtree to re-render when one session's status flips. Same
  // reasoning as `handleSessionStatus` above.
  const addLog = useCallback((msg: string, type = "info") => {
    // Each entry gets a stable monotonically-increasing id so React can
    // reconcile rows correctly when the list is rendered reversed. Using
    // `key={index}` on a reverse-then-map list (the previous approach)
    // re-keys every row on every push and busts list reconciliation.
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    setLogs(prev => [...prev.slice(-99), { id, msg, type, time: new Date().toLocaleTimeString() }]);
  }, []);

  // Something the user asked for failed (F-045): said in a toast as well as
  // the Activity log, which nobody reads while it happens.
  const [errorToast, setErrorToast] = useState<{ id: number; text: string } | null>(null);
  const errorToastTimerRef = useRef<number | null>(null);
  const reportError = useCallback((what: string, e: unknown) => {
    const reason = typeof e === "string" ? e : (e as any)?.message ? String((e as any).message) : String(e);
    const text = `${what}: ${reason}`;
    addLog(text, "error");
    setErrorToast({ id: Date.now(), text });
    if (errorToastTimerRef.current) window.clearTimeout(errorToastTimerRef.current);
    errorToastTimerRef.current = window.setTimeout(() => setErrorToast(null), 8000);
  }, [addLog]);

  // Android: the keep-alive service (a notification, and the process kept
  // alive in the background) runs while this window has SSH sessions open
  // (F-004, F-032). Sent at every change, and once at start, which also ends
  // a service a reload left behind. A failure is reported once.
  const keepAliveSentRef = useRef<number | null>(null);
  const keepAliveFailedRef = useRef(false);
  useEffect(() => {
    if (!IS_ANDROID) return;
    const open = sessions.filter(s => s.kind !== 'local').length;
    if (keepAliveSentRef.current === open) return;
    keepAliveSentRef.current = open;
    invoke("android_keep_alive", { sessions: open }).catch((e) => {
      if (keepAliveFailedRef.current) return;
      keepAliveFailedRef.current = true;
      reportError("Sessions are not kept open in the background", e);
    });
  }, [sessions, reportError]);

  // Wrapped in useCallback because these are handed to memoised children
  // (SessionView, MirrorsPanel, etc.). Without stable identity every parent
  // render hands a fresh reference and defeats the child's memo gate.
  const refreshServers = useCallback(async () => {
    try { setServers((await invoke("get_servers")) as any[]); }
    catch (e) { reportError("Could not load the servers", e); }
  }, [reportError]);
  const refreshCredentials = useCallback(async () => {
    try { setCredentials((await invoke("get_credentials")) as any[]); }
    catch (e) { reportError("Could not load the saved logins", e); }
  }, [reportError]);
  const refreshSshKeys = useCallback(async () => {
    try { setSshKeys((await invoke("get_ssh_keys")) as any[]); }
    catch (e) { reportError("Could not load the SSH keys", e); }
  }, [reportError]);
  const refreshFolders = async () => {
    try { setFolders((await invoke("get_folders")) as any[]); }
    catch (e) { reportError("Could not load the folders", e); }
  };
  const refreshCommands = async () => {
    try { setCommands((await invoke("get_commands")) as any[]); }
    catch (e) { reportError("Could not load the commands", e); }
  };
  const refreshNotes = async () => {
    try { setNotes((await invoke("get_notes")) as any[]); }
    catch (e) { reportError("Could not load the notes", e); }
  };
  const refreshSnippets = async () => {
    try { setSnippets((await invoke("get_snippets")) as any[]); }
    catch (e) { reportError("Could not load the snippets", e); }
  };
  const refreshAll = async () => {
    await Promise.all([
      refreshServers(),
      refreshCredentials(),
      refreshSshKeys(),
      refreshFolders(),
      refreshCommands(),
      refreshNotes(),
      refreshSnippets(),
    ]);
  };

  const removeServer = async (id: number) => {
    try {
      await invoke("delete_server", { id });
      refreshServers();
      addLog("Server removed.", "info");
    } catch (e) { reportError("Could not delete the server", e); }
  };

  const createFolder = async (name: string) => {
    try {
      await invoke("add_folder", { name, parentId: null });
      await refreshFolders();
      addLog(`Folder "${name}" created.`, "success");
    } catch (e) {
      reportError("Could not create the folder", e);
      throw e; // bubble up so NodeGrid keeps the input open if the user wants to retry
    }
  };

  const pinServer = async (id: number, pinned: boolean) => {
    try {
      await invoke("set_server_pinned", { id, pinned });
      await refreshServers();
    } catch (e) { reportError(pinned ? "Could not pin the server" : "Could not unpin the server", e); }
  };

  const pinFolder = async (id: number, pinned: boolean) => {
    try {
      await invoke("set_folder_pinned", { id, pinned });
      await refreshFolders();
    } catch (e) { reportError(pinned ? "Could not pin the folder" : "Could not unpin the folder", e); }
  };

  const removeFolder = async (id: number) => {
    try {
      await invoke("delete_folder", { id });
      // delete_folder cascades to its servers (see main.rs), so refresh both.
      await Promise.all([refreshFolders(), refreshServers()]);
      addLog("Folder removed.", "info");
    } catch (e) { reportError("Could not delete the folder", e); }
  };

  const renameFolder = async (id: number, name: string) => {
    try {
      await invoke("rename_folder", { id, name });
      await refreshFolders();
      addLog(`Folder renamed to "${name}".`, "info");
    } catch (e) {
      reportError("Could not rename the folder", e);
      throw e; // bubble up so NodeGrid can keep the input open if the user wants to retry
    }
  };

  // ProfileSelectPage handles the entire profile pick + password + create
  // flow on a single screen. By the time it fires `onUnlocked`, the
  // backend has both selected the profile AND decrypted the DB — we just
  // flip the UI and refresh data.
  const handleProfileUnlocked = async (name: string) => {
    unlockedRef.current = true;
    // The unlocked vault's own name — vault files are one-per-name on disk
    // (CLAUDE.md), so it is what keeps the localStorage keys of one profile
    // apart from another's (F-070). Set before anything that remembers UI
    // state mounts.
    setStorageProfile(name);
    setIsUnlocked(true);
    addLog(`Profile "${name}" unlocked.`, "success");
    refreshAll();
    // Autostart sweep: load servers directly (refreshAll is also doing this
    // in parallel, but its state update is async and we can't read `servers`
    // back here without a stale-closure race), pick the ones flagged
    // autostart, and stage them all into the sessions tab strip in one
    // setSessions call. The user lands focused on the first autostart node;
    // each new SessionView component then kicks off its own connect on mount.
    try {
      const list = await invoke<any[]>("get_servers");
      const toStart = list.filter((s) => s.autostart);
      if (toStart.length === 0) return;
      const newSessions = toStart.map((s) => ({
        id: `session-${s.id}`,
        serverId: s.id,
        serverName: s.name,
        mirrors: s.mirrors,
      }));
      setSessions((prev: any[]) => {
        const seen = new Set(prev.map((p) => p.id));
        const fresh = newSessions.filter((n) => !seen.has(n.id));
        return [...prev, ...fresh];
      });
      setActiveView(newSessions[0].id);
      addLog(`Autostart: opened ${newSessions.length} node${newSessions.length === 1 ? "" : "s"}.`, "info");
    } catch (e) {
      reportError("Could not open the servers set to start with the profile", e);
    }
  };

  const confirm = useConfirm();

  // Whether a session tab may close: asks first when the "warn" setting is
  // on AND there's an actual live connection to drop — connecting/failed/
  // disconnected close instantly. Status source of truth is the same
  // sessionStatuses map that drives the tab's coloured dot. Also skipped once
  // every terminal in the session has already printed "Session stopped" — the
  // connection may technically still be open (one shell exiting doesn't
  // close the others' multiplexed channels), but there's no live shell left
  // anywhere in it worth confirming a drop for. Defaults to confirming
  // (terms.length === 0 keeps allEnded false) if per-terminal state hasn't
  // arrived yet — better an unnecessary confirm than silently dropping a live
  // one. Shared with SessionView's own clone-tab close
  // (sessionCloseNeedsConfirm) so the two can't drift apart, and used by every
  // way of closing a session tab: the desktop ×, the mobile picker's × and the
  // tab menu's "Close tab" (R-008).
  const confirmSessionClose = async (s: { id: string; kind?: string }): Promise<boolean> => {
    const terms = sessionTerminals[s.id] ?? [];
    if (!sessionCloseNeedsConfirm(terms, sessionStatuses[s.id], appSettings.warnOnCloseActiveSession)) return true;
    const ok = await confirm({
      title: "Close this session?",
      message: s.kind === 'local' ? "The shell will be closed." : "The SSH connection will be dropped.",
      okLabel: "Close",
      destructive: true,
    });
    if (!ok) {
      // The dialog's own focus trap restores focus to whatever had it before
      // opening — the × button itself, not the terminal the user was
      // actually typing in. Ask that specific terminal to reclaim it.
      const activeTid = sessionActiveTerm[s.id];
      if (activeTid) window.dispatchEvent(new CustomEvent(`terminal-refocus-${activeTid}`));
    }
    return ok;
  };
  const textPrompt = useTextPrompt();

  // Live edit ends when its session is disconnected or the profile locked,
  // after the file browser that shows per-session sync messages is gone, so
  // the end is reported here (this component stays mounted on the picker
  // too). A local copy holding changes that were not uploaded is kept by the
  // backend: say where, and offer to show it.
  useTauriEvent<{ message: string; keptPath?: string | null }>("live-edit-stopped", async (event) => {
    const { message, keptPath } = event.payload || ({} as any);
    // An end reported after a lock (the copy's final check can outlast it)
    // goes to no profile's Activity log; a kept copy is still shown.
    const log = unlockedRef.current ? addLog : () => {};
    if (!keptPath) {
      log(message || "Live edit stopped.", "info");
      return;
    }
    log(message, "error");
    const reveal = await confirm({
      title: "Changes not uploaded",
      message: visibleName(message),
      okLabel: "Show in folder",
      cancelLabel: "Close",
    });
    if (reveal) {
      invoke("local_open_in_explorer", { localPath: keptPath }).catch((e) => reportError("Could not show the folder", e));
    }
  });

  // A panel that is already gone (a session tab closed while its Library
  // draft was being saved) reports its failure here.
  useEffect(() => {
    const onError = (e: Event) => {
      const { what, error } = (e as CustomEvent<{ what: string; error: unknown }>).detail || ({} as any);
      if (what) reportError(what, error);
    };
    window.addEventListener("solanum-error", onError);
    return () => window.removeEventListener("solanum-error", onError);
  }, [reportError]);

  // Copies an earlier run left behind (it crashed, or was closed while they
  // held changes that were not uploaded): the backend's start-up sweep keeps
  // them, and this says where, once.
  useEffect(() => {
    invoke<string[]>("live_edit_leftovers").then(async (kept) => {
      if (!kept || kept.length === 0) return;
      addLog(`Live-edit copies kept from an earlier session: ${kept.join(", ")}`, "error");
      const reveal = await confirm({
        title: "Files kept from an earlier session",
        message: `Solanum ended while ${kept.length === 1 ? "this live-edit copy" : "these live-edit copies"} may have held changes that were not uploaded, so ${kept.length === 1 ? "it was" : "they were"} kept:\n\n${kept.map(visibleName).join("\n")}`,
        okLabel: "Show in folder",
        cancelLabel: "Close",
      });
      if (reveal) {
        invoke("local_open_in_explorer", { localPath: kept[0] }).catch((e) => reportError("Could not show the folder", e));
      }
    }).catch((e) => addLog(`LIVE_EDIT_LEFTOVERS: ${e}`, "error"));
  }, [addLog, confirm]);

  // Window-close guard. Keep `sessions` mirrored into a ref so the close
  // handler (which is registered ONCE inside useEffect, capturing snapshot
  // state) always sees the latest array — without this we'd race against
  // the user opening/closing tabs and either over- or under-confirm.
  const sessionsRef = useRef(sessions);
  useEffect(() => { sessionsRef.current = sessions; }, [sessions]);

  // Intercept BOTH the in-app X button (which calls appWindow.close()) AND
  // OS-level closes (Alt+F4, taskbar context-menu close, system shutdown).
  // Both paths fire `onCloseRequested`. Showing a confirm when at least one
  // SSH session is connected prevents the most painful misclick: closing
  // the window mid-deploy / mid-edit and losing the terminal scrollback +
  // any in-flight SFTP transfers in one go. `appWindow.destroy()` bypasses
  // the close-requested hook so confirming actually exits — calling
  // `close()` again here would loop us straight back into the same prompt.
  useEffect(() => {
    return unlistenWhenReady(appWindow.onCloseRequested(async (event) => {
      const n = sessionsRef.current.length;
      if (n === 0) return; // nothing to lose — let the close proceed
      event.preventDefault();
      const ok = await confirm({
        title: "Close Solanum?",
        message: `${n} SSH session${n === 1 ? "" : "s"} ${n === 1 ? "is" : "are"} still connected. Closing now disconnects ${n === 1 ? "it" : "them all"} and aborts any in-flight transfers.`,
        okLabel: "Close anyway",
        cancelLabel: "Stay",
        destructive: true,
      });
      if (!ok) return;
      // Unsaved Library drafts are saved first, as when locking (F-053).
      const pending: Promise<boolean>[] = [];
      window.dispatchEvent(new CustomEvent("solanum-flush-drafts", { detail: { pending } }));
      const saved = await Promise.all(pending);
      if (saved.some((done) => !done)) {
        const closeAnyway = await confirm({
          title: "Changes not saved",
          message: "Some changes in the Library panel could not be saved (the panel says why). Close anyway and lose them?",
          okLabel: "Close anyway",
          cancelLabel: "Stay",
          destructive: true,
        });
        if (!closeAnyway) return;
      }
      await appWindow.destroy();
    }));
  }, [confirm]);

  // Lock the current profile and return to the picker. Confirms first when
  // there are open SSH sessions because they will be torn down — accidental
  // double-clicks on the lock icon shouldn't kill the user's terminal work.
  const handleLogout = async () => {
    if (sessions.length > 0) {
      const ok = await confirm({
        title: "Switch profile?",
        message: `You have ${sessions.length} open SSH session${sessions.length === 1 ? "" : "s"}. Switching will disconnect ${sessions.length === 1 ? "it" : "them all"} and take you back to the profile picker.`,
        okLabel: "Switch",
        cancelLabel: "Stay",
        destructive: true,
      });
      if (!ok) return;
      // Unsaved Library drafts (node notes, an open command or note) are
      // saved while the vault is still open (F-053).
      const pending: Promise<boolean>[] = [];
      window.dispatchEvent(new CustomEvent("solanum-flush-drafts", { detail: { pending } }));
      const saved = await Promise.all(pending);
      if (saved.some((done) => !done)) {
        const lockAnyway = await confirm({
          title: "Changes not saved",
          message: "Some changes in the Library panel could not be saved (the panel says why). Lock anyway and lose them?",
          okLabel: "Lock anyway",
          cancelLabel: "Stay",
          destructive: true,
        });
        if (!lockAnyway) return;
      }
      // Best-effort: tell the backend to clean up each session. We don't
      // bail if one fails — `close_profile` will drop the DB anyway, and
      // the OS will eventually reap the sockets.
      for (const s of sessions) {
        try { await invoke("disconnect_session", { sessionId: s.id }); }
        catch (e) { console.error("disconnect on logout failed:", e); }
      }
    }
    let lockError: unknown = null;
    try { await invoke("close_profile"); }
    catch (e) { lockError = e; }
    resetProfileState();
    if (lockError) reportError("Locking the profile did not finish cleanly", lockError);
  };

  // Everything of the unlocked profile back to how a fresh unlock starts
  // (F-022): its servers, logins, keys, Library, sessions and their layout,
  // Wall, open editors (with any revealed secret), the folder being browsed,
  // the Activity log (owner decision), and broadcast, whose targets are
  // session ids that the next profile's servers would reuse. Preferences
  // (Settings, panel widths) stay. Add new profile-scoped state here.
  const resetProfileState = () => {
    unlockedRef.current = false;
    setStorageProfile(null);
    setIsUnlocked(false);
    setSessions([]);
    setSessionStatuses({});
    setTabMenu(null);
    setMergedSessionIds([]);
    setWallItems([]);
    setWallPickerOpen(false);
    setSessionTerminals({});
    setSessionActiveTerm({});
    setMobileSessionPickerOpen(false);
    setBroadcastMenuOpen(false);
    broadcast.reset();
    closeHandlersRef.current.clear();
    setActiveView("nodes");
    setActiveFolderId(null);
    setServers([]); setCredentials([]); setSshKeys([]); setFolders([]); setCommands([]);
    setNotes([]); setSnippets([]);
    setLibraryQuery("");
    setLibraryTab("commands");
    closeNodePanel();
    setIsQuickConnectOpen(false);
    setIsLocalShellOpen(false);
    closeCommandPanel(); closeNotePanel(); closeSnippetPanel(); closeCredPanel(); closeKeyPanel();
    setLogs([]);
    if (errorToastTimerRef.current) window.clearTimeout(errorToastTimerRef.current);
    setErrorToast(null);
  };

  const openServer = (server: any) => {
    const sessionId = `session-${server.id}`;
    const existing = sessions.find(s => s.id === sessionId);
    if (!existing) {
      setSessions([...sessions, {
        id: sessionId,
        serverId: server.id,
        serverName: server.name,
        // Pass the raw mirrors JSON through to SessionView so the
        // MirrorsPanel can pre-populate "Saved on this node" without
        // another round-trip to the backend.
        mirrors: server.mirrors,
        // Commands to auto-run once on the first terminal (see SessionView).
        runOnConnect: server.run_on_connect || "",
      }]);
    }

    setActiveView(sessionId);
  };

  // Spawn a session from inline Quick Connect auth AND leave behind a reusable
  // node in the root directory so the target can be reconnected later without
  // re-typing credentials. The connection itself still rides `quickAuth`
  // (serverId = 0 sentinel = "look at quickAuth, not the DB") so it works
  // exactly as before even if the save fails; the persisted node is a
  // best-effort side effect the backend dedups by (host, port, username).
  const openQuickConnect = (auth: QuickAuth) => {
    const sessionId = `session-quick-${Date.now()}`;
    const displayName = `${auth.username}@${auth.host}:${auth.port}`;
    setSessions((prev: Session[]) => [...prev, {
      id: sessionId,
      serverId: 0,
      serverName: displayName,
      quickAuth: auth,
    }]);
    setActiveView(sessionId);
    setIsQuickConnectOpen(false);
    addLog(`Quick connect → ${displayName}`, "info");
    // Persist a root-level profile for reuse. Best-effort: a failure here must
    // never block the live connection the user just asked for.
    invoke("save_quick_connect_node", { auth })
      .then(() => { refreshServers(); addLog(`Saved node → ${displayName}`, "success"); })
      .catch((e) => reportError("The quick-connect server was not saved", e));
  };

  // Local (non-SSH) shell tab. Modeled directly on openQuickConnect above —
  // same serverId=0 sentinel, same synthetic-id/setSessions/setActiveView
  // shape — minus anything SSH-specific (no auth, nothing to persist as a
  // reusable node: a local shell isn't "a server" to reconnect to later).
  const openLocalShell = (opts: LocalShellOpts) => {
    const sessionId = `session-local-${Date.now()}`;
    const displayName = opts.shellName || "Local Shell";
    setSessions((prev: Session[]) => [...prev, {
      id: sessionId,
      serverId: 0,
      serverName: displayName,
      kind: 'local',
      localShell: opts,
    }]);
    setActiveView(sessionId);
    setIsLocalShellOpen(false);
    addLog(`Local shell → ${displayName}`, "info");
  };

  const handleEditNode = async (server: any) => {
    // Servers come back from get_servers with `has_password` (boolean) but
    // no plaintext. Reveal the secret only when the user opens the edit
    // sheet — that way the password never sits in renderer memory during
    // the normal grid/sidebar lifetime.
    let revealedPassword = "";
    if (server.has_password) {
      try {
        const v = await invoke<string | null>("reveal_server_password", { id: server.id });
        revealedPassword = v || "";
      } catch (e) {
        reportError("Could not read the saved password (it is kept unless you type a new one)", e);
      }
    }
    setNewNode({
      id: server.id,
      name: server.name || "",
      host: server.host || "",
      port: server.port || 22,
      username: server.username || "",
      password: revealedPassword,
      authType: server.auth_type || (server.credential_id ? "vault" : "custom_pass"),
      credentialId: server.credential_id?.toString() || "",
      folderId: server.folder_id?.toString() || "",
      keyId: server.key_id?.toString() || "",
      proxyType: server.proxy_type || "none",
      proxyHost: server.proxy_host || "",
      proxyPort: server.proxy_port || 1080,
      tunnels: (() => {
        // A broken row must not turn Edit into a dead button (F-045).
        try { return server.tunnels ? JSON.parse(server.tunnels) : []; }
        catch (e) { reportError("This server's tunnel rules could not be read; they are shown empty", e); return []; }
      })(),
      autostart: !!server.autostart,
      mirrors: (() => {
        try { return JSON.parse(server.mirrors || "[]"); } catch { return []; }
      })(),
      color: server.color ?? null,
      notes: server.notes || "",
      runOnConnect: server.run_on_connect || "",
      jumpHostId: server.jump_host_id?.toString() || "",
      legacyAlgorithms: !!server.legacy_algorithms,
      terminalOnly: !!server.terminal_only,
      // Starts clean — only flips true if the user types into the password
      // field. Save handler reads this to decide between `preserve_password`
      // and a real overwrite.
      password_dirty: false,
    });
    setIsPanelOpen(true);
  };

  // Render helper, NOT a component — it is invoked as `{TitleBar()}` below,
  // never as `<TitleBar />`. Rendering it as a JSX element would give it a
  // fresh function identity on every DesktopApp render, so React would treat
  // it as a new component type and fully unmount + remount the whole title-bar
  // subtree (tab strip, pickers, window controls) on every render — throwing
  // away tab-strip scroll position and focus, and re-doing all that DOM work,
  // on every connect/reconnect and tab switch. Calling it inlines its JSX into
  // DesktopApp's own output with no component boundary, so React reconciles in
  // place. It closes over DesktopApp scope and uses no hooks, so a plain call
  // is safe. Do NOT convert this to `<TitleBar />`.
  const TitleBar = () => (
    <div
      data-tauri-drag-region
      onDoubleClick={(e) => {
        // Native double-click-to-maximize on the drag region matches OS
        // expectations on Windows/macOS/KDE. Tauri's drag region itself
        // doesn't dispatch this for us, so we wire it explicitly. Skip
        // when the click landed on an interactive child (tabs, buttons)
        // since those mark themselves with `no-drag`.
        const target = e.target as HTMLElement;
        if (target.closest('.no-drag')) return;
        toggleMaximize();
      }}
      className="h-10 bg-[#0d0d10] border-b border-white/5 flex items-center justify-between px-3 select-none shrink-0 z-50 drag absolute top-0 left-0 right-0"
    >
      {/* Logo + product name: hidden on phones to give the tab strip the
          whole row. Desktop keeps the original 75 px left padding for
          macOS traffic lights, plus the icon and brand. */}
      <div className="hidden sm:flex items-center gap-2 pr-4 pl-[75px] md:pl-2" data-tauri-drag-region>
        <img src={logoUrl} alt="" draggable={false} className="h-6 w-auto max-w-[24px] object-contain select-none" />
        <span className="text-[12px] font-bold text-white tracking-tight">Solanum</span>
      </div>

      {/* Mobile session picker — replaces the horizontal tab strip on
          narrow viewports so a phone doesn't spend its whole title row
          on 3-character truncated tabs. A single pill shows the current
          session (or a "Servers" placeholder when nothing is open); tap
          opens a dropdown listing every session with status + close +
          merge affordances. Desktop still gets the full scrolling tab
          strip below. */}
      {isMobile && sessions.length > 0 && (
        <div className="flex-1 flex items-end justify-start pb-1 no-drag pl-2 pr-1 min-w-0">
          <div className="relative w-full">
            <button
              type="button"
              onClick={() => setMobileSessionPickerOpen(v => !v)}
              className={`w-full h-7 px-3 rounded-full flex items-center gap-2 border transition-all ${
                activeView.startsWith('session-') || activeView === 'wall'
                  ? 'bg-primary/15 text-primary border-primary/40 shadow-inner'
                  : 'bg-white/[0.06] text-zinc-300 border-white/10'
              }`}
              aria-haspopup="listbox"
              aria-expanded={mobileSessionPickerOpen}
            >
              {(() => {
                const isWall = activeView === 'wall';
                const cur = sessions.find(s => s.id === activeView);
                const st = cur ? (sessionStatuses[cur.id] ?? 'connecting') : null;
                const dotTone =
                  st === 'connected'    ? 'bg-emerald-400' :
                  st === 'connecting'   ? 'bg-amber-400 animate-pulse' :
                  st === 'failed'       ? 'bg-rose-500' :
                  st === 'disconnected' ? 'bg-rose-500' :
                                          'bg-zinc-500';
                return (
                  <>
                    {isWall
                      ? <LayoutGrid size={12} className="shrink-0 text-primary" />
                      : (cur && <span className={`w-2 h-2 rounded-full shrink-0 ${dotTone}`} />)}
                    <span className="truncate flex-1 text-left text-[11px] font-bold">
                      {isWall
                        ? `Wall${wallItems.length > 0 ? ` · ${wallItems.length} pinned` : ''}`
                        : cur ? cur.serverName : `${sessions.length} open session${sessions.length === 1 ? '' : 's'}`}
                    </span>
                    {mergedSessionIds.length > 0 && (
                      <span className="shrink-0 h-4 px-1 rounded-full bg-primary/25 text-primary text-[9px] font-bold flex items-center gap-0.5">
                        <Columns size={8} /> +{mergedSessionIds.length}
                      </span>
                    )}
                    <ChevronDown size={12} className={`shrink-0 transition-transform ${mobileSessionPickerOpen ? 'rotate-180' : ''}`} />
                  </>
                );
              })()}
            </button>
            {mobileSessionPickerOpen && (
              <>
                <div className="fixed inset-0 z-[60]" onClick={() => setMobileSessionPickerOpen(false)} />
                <div
                  role="listbox"
                  className="absolute z-[70] top-8 left-0 right-0 bg-[#15151a] border border-white/10 rounded-xl shadow-2xl p-1.5 max-h-[60vh] overflow-y-auto custom-scrollbar"
                >
                  {sessions.map(s => {
                    const st = sessionStatuses[s.id] ?? 'connecting';
                    const dot =
                      st === 'connected'    ? 'bg-emerald-400' :
                      st === 'connecting'   ? 'bg-amber-400 animate-pulse' :
                      'bg-rose-500';
                    const isActive = activeView === s.id;
                    const isMerged = mergedSessionIds.includes(s.id);
                    return (
                      <div key={s.id} className="flex items-center gap-1">
                        <button
                          role="option"
                          aria-selected={isActive}
                          onClick={() => { setActiveView(s.id); setMobileSessionPickerOpen(false); }}
                          className={`flex-1 flex items-center gap-2 px-2.5 py-2 rounded-lg text-left transition-all ${
                            isActive
                              ? 'bg-primary/15 text-primary'
                              : isMerged
                                ? 'bg-primary/[0.05] text-primary/80'
                                : 'text-zinc-200 hover:bg-white/[0.06]'
                          }`}
                        >
                          <span className={`w-2 h-2 rounded-full shrink-0 ${dot}`} />
                          <span className="text-[12px] font-semibold truncate flex-1">{s.serverName}</span>
                          {isMerged && !isActive && (
                            <span className="text-[9px] font-bold uppercase tracking-wider text-primary/60">Split-in</span>
                          )}
                        </button>
                        {/* Merge/unmerge toggle — mobile equivalent of
                            the desktop tab context menu. Only offered
                            when the current view is another session AND
                            this row isn't the one on screen. */}
                        {activeView.startsWith('session-') && activeView !== s.id && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              if (isMerged) {
                                const next = mergedSessionIds.filter(id => id !== s.id);
                                // Below 2 members is a single view, not a split.
                                setMergedSessionIds(next.length < 2 ? [] : next);
                              } else {
                                // Fresh split: seed with the anchor so it
                                // holds visual position 0.
                                if (mergedSessionIds.length === 0) setMergedSessionIds([activeView, s.id]);
                                else setMergedSessionIds(prev => [...prev, s.id]);
                              }
                            }}
                            title={isMerged ? 'Remove from split view' : 'Split with current view'}
                            className={`h-8 w-8 shrink-0 rounded-lg flex items-center justify-center border transition-all ${
                              isMerged
                                ? 'bg-primary/15 text-primary border-primary/40'
                                : 'text-zinc-400 border-white/10 hover:bg-white/[0.06]'
                            }`}
                          >
                            <Columns size={13} />
                          </button>
                        )}
                        <button
                          onClick={async (e) => {
                            e.stopPropagation();
                            if (!(await confirmSessionClose(s))) return;
                            const sid = s.id;
                            invoke('disconnect_session', { sessionId: sid }).catch(() => {});
                            setSessions(prev => prev.filter(x => x.id !== sid));
                            setSessionStatuses(prev => { const { [sid]: _, ...rest } = prev; return rest; });
                            broadcast.removeSession(sid);
                            setMergedSessionIds(prev => {
                              const next = prev.filter(id => id !== sid);
                              return next.length < 2 ? [] : next;
                            });
                            unpinSessionFromWall(sid);
                            setActiveView(prev => (prev === sid ? 'nodes' : prev));
                          }}
                          title="Close session"
                          className="h-8 w-8 shrink-0 rounded-lg flex items-center justify-center text-zinc-400 hover:text-red-400 hover:bg-white/[0.06] transition-all"
                        >
                          <X size={13} />
                        </button>
                      </div>
                    );
                  })}
                  {/* Wall entry — mobile equivalent of the desktop Wall
                      tab. Same pinboard, same state; just a different
                      entry point since the horizontal tab strip is
                      replaced by this dropdown on phone. */}
                  <div className="border-t border-white/5 my-1" />
                  <button
                    onClick={() => {
                      setMergedSessionIds([]);
                      setActiveView('wall');
                      setMobileSessionPickerOpen(false);
                    }}
                    className={`w-full flex items-center gap-2 px-2.5 py-2 rounded-lg text-left transition-all ${
                      activeView === 'wall'
                        ? 'bg-primary/15 text-primary'
                        : 'text-zinc-200 hover:bg-white/[0.06]'
                    }`}
                  >
                    <LayoutGrid size={13} className="shrink-0" />
                    <span className="text-[12px] font-semibold flex-1">Wall</span>
                    {wallItems.length > 0 && (
                      <span className="text-[9px] font-bold uppercase tracking-wider text-primary/70">
                        {wallItems.length} pinned
                      </span>
                    )}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Tab strip is a drag region; tabs themselves opt out via no-drag so
          clicking a tab selects it instead of dragging the window. On phone
          the horizontal scroll is replaced by the dropdown above; the
          strip below is hidden on mobile. */}
      <div
        data-tauri-drag-region
        className={`${isMobile ? 'hidden' : 'flex'} flex-1 gap-1 overflow-x-auto no-scrollbar h-full items-end pb-1`}
        onWheel={(e) => { e.currentTarget.scrollLeft += e.deltaY; }}
      >
        {sessions.map(s => {
          const st = sessionStatuses[s.id] ?? "connecting";
          // Dot palette: green = connected, amber = connecting, red = failed
          // or disconnected. The pulse animation only runs while connecting
          // so a steady-state tab doesn't draw the eye every half second.
          const dotTone =
            st === "connected"    ? "bg-emerald-400" :
            st === "connecting"   ? "bg-amber-400 animate-pulse" :
            st === "failed"       ? "bg-rose-500" :
            st === "disconnected" ? "bg-rose-500" :
                                    "bg-zinc-500";
          const dotTitle =
            st === "connected"    ? "Connected" :
            st === "connecting"   ? "Connecting…" :
            st === "failed"       ? "Connection failed" :
            st === "disconnected" ? "Disconnected" :
                                    st;
          // Broadcast indicator: small orange dot next to the status dot when
          // this session is in the target set AND broadcast is armed. Kept
          // separate from the status dot so the user can still tell "is it
          // connected?" and "is it broadcasting?" at a glance.
          const isBroadcastTarget = broadcast.enabled && broadcast.targetSessionIds.has(s.id);
          const isMergedTab = mergedSessionIds.includes(s.id);
          return (
            <div
              key={s.id}
              onClick={(e) => {
                // Ctrl/⌘-click toggles this tab in the split beside the
                // currently-active session view — a quick keyboard-free
                // way to tile two servers together without going through
                // the right-click menu.
                if ((e.ctrlKey || e.metaKey) && activeView.startsWith('session-') && activeView !== s.id) {
                  setMergedSessionIds(prev => {
                    // Fresh split: seed with the anchor first so it holds
                    // position 0 for the rest of the split's lifetime.
                    if (prev.length === 0) return [activeView, s.id];
                    if (prev.includes(s.id)) {
                      const next = prev.filter(id => id !== s.id);
                      return next.length < 2 ? [] : next;
                    }
                    return [...prev, s.id];
                  });
                  return;
                }
                // Plain click on a tab that isn't part of the current
                // split exits the split — the user is asking for a
                // single-tab view of s.id, not "tile s.id next to the
                // sessions I had merged".
                if (!mergedSessionIds.includes(s.id)) setMergedSessionIds([]);
                setActiveView(s.id);
              }}
              onContextMenu={(e) => {
                e.preventDefault();
                setTabMenu({ x: e.clientX, y: e.clientY, sessionId: s.id });
              }}
              // No max-width / no truncate: the user explicitly wants full
              // node names visible even when many sessions are open. The tab
              // row itself is horizontally scrollable (overflow-x-auto +
              // wheel-to-horizontal scroll above), so wider tabs just mean
              // more scrolling — they never hide the name behind an ellipsis.
              // `whitespace-nowrap` keeps long names on a single line; without
              // it a tab with a 30-char hostname would wrap into a two-line
              // pill and break the row's height.
              title={isMergedTab ? `${s.serverName} · split beside current view (Ctrl-click to unpair)` : s.serverName}
              className={`group no-drag flex items-center h-7 px-2.5 sm:px-4 rounded-full cursor-pointer transition-all shrink-0 mr-1 ${
                activeView === s.id
                  ? 'bg-primary/15 text-primary border border-primary/40 shadow-inner shadow-primary/10'
                  : isMergedTab
                    ? 'bg-primary/[0.05] text-primary/80 border border-primary/25 hover:bg-primary/10'
                    : 'bg-white/[0.06] text-zinc-300 border border-white/10 hover:bg-white/[0.1] hover:border-white/20 hover:text-white'
              }`}
            >
              <span
                title={dotTitle}
                className={`w-2 h-2 rounded-full mr-2 shrink-0 ${dotTone}`}
                aria-label={dotTitle}
              />
              {isBroadcastTarget && (
                <span
                  title="Broadcast target"
                  aria-label="Broadcast target"
                  className="w-1.5 h-1.5 rounded-full mr-1.5 shrink-0 bg-orange-400 shadow-[0_0_6px_rgba(251,146,60,0.7)]"
                />
              )}
              {isMergedTab && (
                <Columns size={9} className="text-primary/70 mr-1 shrink-0" />
              )}
              {/* Node name display. Was 10 px + uppercase on desktop — that
                  combination gave the smallest, hardest-to-read name in the
                  whole title bar even though it's the ID users need most.
                  Bumping to 12 px and dropping the uppercase transform gives
                  the same tab pill roughly 30% more legible characters per
                  pixel (uppercase is wider per glyph) without changing the
                  strip height, which stays h-7. */}
              <span className="text-[11px] font-semibold whitespace-nowrap tracking-tight">{s.serverName}</span>
              {/* Mobile-only actions trigger. On phone we surface the same
                  tabMenu (Reconnect / Disconnect / Close) here since there
                  is no right-click on touch — a single kebab is a cleaner
                  affordance than a naked X plus a hidden long-press menu.
                  The X below is desktop-only so we don't stack both. */}
              <button
                type="button"
                aria-label="Session actions"
                className="sm:hidden ml-1 h-5 w-5 flex items-center justify-center rounded hover:bg-white/5 shrink-0 text-zinc-400"
                onClick={(e) => {
                  e.stopPropagation();
                  const rect = e.currentTarget.getBoundingClientRect();
                  setTabMenu({ x: rect.left, y: rect.bottom, sessionId: s.id });
                }}
              >
                <MoreVertical size={13} />
              </button>
              {/* Desktop-only inline close. Hidden until hover so the tab
                  reads clean at rest; sizing (w-5 h-5, 12 px icon) matches
                  the terminal-tab close inside SessionView so both tab
                  strips look like siblings. */}
              <button
                type="button"
                aria-label="Close session"
                className="hidden sm:flex ml-1 h-5 w-5 items-center justify-center rounded hover:bg-white/5 shrink-0 opacity-0 group-hover:opacity-100 text-zinc-400 hover:text-red-400 transition-opacity"
                onClick={async (e) => {
                  e.stopPropagation();
                  if (!(await confirmSessionClose(s))) return;
                  setSessions(prev => prev.filter(sess => sess.id !== s.id));
                  setSessionStatuses(prev => {
                    const { [s.id]: _, ...rest } = prev;
                    return rest;
                  });
                  broadcast.removeSession(s.id);
                  unpinSessionFromWall(s.id);
                  setActiveView(prev => (prev === s.id ? "nodes" : prev));
                }}
              >
                <X size={12} />
              </button>
            </div>
          );
        })}
      </div>
      {/* Wall trigger — moved OUT of the scrollable tab strip and next
          to the Broadcast pill so both multi-session affordances live
          in the same "utility cluster" at the right edge of the title
          bar. Icon-only on every viewport (mobile inherits from
          Broadcast's compact pattern), badge for pin count so state is
          legible without text. Visible whenever there's at least one
          open session — the Wall itself only becomes useful with pins
          but the button is the discoverability entry point. */}
      {sessions.length >= 1 && (
        <div className="relative no-drag shrink-0 mx-1">
          <button
            type="button"
            onClick={() => {
              // Plain click on Wall exits any active session-split —
              // split-view and Wall are two different multi-view modes
              // and switching between them shouldn't leave stale
              // merged state behind.
              setMergedSessionIds([]);
              setActiveView("wall");
            }}
            title={wallItems.length > 0
              ? `Wall · ${wallItems.length} pinned terminal${wallItems.length === 1 ? '' : 's'}`
              : "Wall — pinboard for terminals across servers"}
            aria-label="Wall pinboard"
            className={`relative flex items-center justify-center w-7 h-7 rounded-full transition-all ${
              activeView === "wall"
                ? "bg-primary/15 border border-primary/40 text-primary shadow-inner shadow-primary/10"
                : "bg-white/[0.06] border border-white/10 text-zinc-400 hover:bg-white/[0.1] hover:text-white"
            }`}
          >
            <LayoutGrid size={12} />
            {wallItems.length > 0 && (
              <span
                className="absolute -top-1 -right-1 min-w-[14px] h-[14px] px-1 rounded-full bg-primary text-[9px] font-bold text-black flex items-center justify-center leading-none"
                aria-hidden="true"
              >
                {wallItems.length}
              </span>
            )}
          </button>
        </div>
      )}
      {/* Broadcast trigger — session-scoped multi-exec. Lives OUTSIDE the
          scrollable tab strip so it stays anchored at the right edge no
          matter how many tabs are open. Compact icon-only button (no
          "Broadcast" text) to reclaim titlebar space; the dropdown reveals
          the full checkbox picker. When armed, a small orange count badge
          hangs off the corner so the state is legible at a glance without
          words. Hidden until there are 2+ sessions since a single session
          has no one to broadcast to. */}
      {sessions.length >= 2 && (
        <div className="relative no-drag shrink-0 mx-1">
          <button
            type="button"
            onClick={() => setBroadcastMenuOpen(v => !v)}
            title={broadcast.enabled
              ? `Broadcasting to ${broadcast.targetSessionIds.size} session${broadcast.targetSessionIds.size === 1 ? "" : "s"}`
              : "Broadcast input to multiple sessions"}
            aria-label="Broadcast input"
            className={`relative flex items-center justify-center w-7 h-7 rounded-full transition-all ${
              broadcast.enabled
                ? "bg-orange-500/15 border border-orange-400/40 text-orange-300 shadow-inner shadow-orange-400/10"
                : "bg-white/[0.06] border border-white/10 text-zinc-400 hover:bg-white/[0.1] hover:text-white"
            }`}
          >
            <Radio size={12} className={broadcast.enabled ? "animate-pulse" : ""} />
            {broadcast.enabled && broadcast.targetSessionIds.size > 0 && (
              <span
                className="absolute -top-1 -right-1 min-w-[14px] h-[14px] px-1 rounded-full bg-orange-500 text-[9px] font-bold text-black flex items-center justify-center leading-none"
                aria-hidden="true"
              >
                {broadcast.targetSessionIds.size}
              </span>
            )}
          </button>
          {broadcastMenuOpen && (
            <>
              <div
                className="fixed inset-0 z-[60]"
                onClick={() => setBroadcastMenuOpen(false)}
              />
              <div className="absolute z-[70] top-full mt-1 right-0 w-[280px] bg-[#15151a] border border-white/10 rounded-lg shadow-2xl p-2 text-[11px]">
                <div className="flex items-center justify-between mb-2 px-1">
                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      className="accent-orange-400"
                      checked={broadcast.enabled}
                      onChange={broadcast.toggleEnabled}
                    />
                    <span className="text-[11px] font-bold uppercase tracking-wider text-zinc-200">
                      Broadcast input
                    </span>
                  </label>
                  <button
                    onClick={() => setBroadcastMenuOpen(false)}
                    className="text-zinc-500 hover:text-white p-0.5"
                    aria-label="Close"
                  >
                    <X size={12} />
                  </button>
                </div>
                <div className="flex items-center gap-1.5 px-1 pb-2 border-b border-white/5">
                  <button
                    onClick={() => broadcast.selectAll(sessions.map(s => s.id))}
                    className="px-2 py-0.5 rounded bg-white/[0.04] border border-white/10 text-[10px] uppercase tracking-wider text-zinc-300 hover:bg-white/[0.08] hover:text-white"
                  >
                    All
                  </button>
                  <button
                    onClick={() => broadcast.selectNone()}
                    className="px-2 py-0.5 rounded bg-white/[0.04] border border-white/10 text-[10px] uppercase tracking-wider text-zinc-300 hover:bg-white/[0.08] hover:text-white"
                  >
                    None
                  </button>
                  <div className="flex-1" />
                  <span className={`text-[10px] font-bold uppercase tracking-wider ${
                    broadcast.enabled && broadcast.targetSessionIds.size >= 2
                      ? "text-orange-300"
                      : "text-zinc-500"
                  }`}>
                    {broadcast.enabled
                      ? (broadcast.targetSessionIds.size >= 2
                          ? `Live · ${broadcast.targetSessionIds.size}`
                          : "Pick 2+")
                      : "Off"}
                  </span>
                </div>
                <div className="max-h-[240px] overflow-y-auto custom-scrollbar mt-2 space-y-0.5">
                  {sessions.map(s => {
                    const checked = broadcast.targetSessionIds.has(s.id);
                    const st = sessionStatuses[s.id] ?? "connecting";
                    return (
                      <label
                        key={s.id}
                        className={`flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer ${
                          checked ? "bg-orange-500/10" : "hover:bg-white/[0.04]"
                        }`}
                      >
                        <input
                          type="checkbox"
                          className="accent-orange-400 shrink-0"
                          checked={checked}
                          onChange={() => broadcast.toggleTarget(s.id)}
                        />
                        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                          st === "connected" ? "bg-emerald-400" :
                          st === "connecting" ? "bg-amber-400" :
                          "bg-rose-500"
                        }`} />
                        <span className="truncate text-[11px] font-medium text-zinc-200 flex-1">
                          {s.serverName}
                        </span>
                      </label>
                    );
                  })}
                </div>
              </div>
            </>
          )}
        </div>
      )}
      {/* Window controls: desktop only. Android has its own gesture nav /
          system back button, and the WebView window has no minimise or
          maximise affordance to surface — so we hide the whole cluster on
          phone and reclaim ~120 px of titlebar for the tab strip. */}
      <div className="hidden sm:flex items-center h-full gap-1 no-drag">
        <button
          onClick={() => appWindow.minimize()}
          title="Minimize"
          className="w-10 h-full flex items-center justify-center hover:bg-white/5 transition-colors"
        ><div className="w-3.5 h-[1.5px] bg-zinc-600" /></button>
        <button
          onClick={toggleMaximize}
          title={isMaximized ? "Restore" : "Maximize"}
          className="w-10 h-full flex items-center justify-center hover:bg-white/5 transition-colors group"
        >
          {isMaximized
            ? <Copy size={12} className="text-zinc-600 group-hover:text-zinc-300 scale-x-[-1]" />
            : <Square size={11} className="text-zinc-600 group-hover:text-zinc-300" />}
        </button>
        <button onClick={() => appWindow.close()} className="w-10 h-full flex items-center justify-center hover:bg-red-500 group transition-all"><X size={14} className="text-zinc-600 group-hover:text-white" /></button>
      </div>
      {tabMenu && (() => {
        const targetId = tabMenu.sessionId;
        // Build the "Split view with" picker: every OTHER open session is
        // a candidate. When the target tab is the active view, ticked
        // entries are the current mergedSessionIds. When the target is
        // a different tab, we haven't switched to it yet — ticking a row
        // both switches focus to the target AND initializes the merged
        // set with the picked partner(s), so users don't need a "click
        // to focus, right-click to split" two-step.
        const targetIsActive = activeView === targetId;
        const currentMerges = targetIsActive ? mergedSessionIds : [];
        const others = sessions.filter(s => s.id !== targetId);
        return (
        <>
          <div className="fixed inset-0 z-[60]" onClick={() => setTabMenu(null)} onContextMenu={(e) => { e.preventDefault(); setTabMenu(null); }} />
          <div
            className="fixed z-[70] bg-[#15151a] border border-white/10 rounded-md shadow-2xl py-1 min-w-[240px] text-[11px] no-drag"
            style={{ left: Math.min(tabMenu.x, window.innerWidth - 260), top: Math.min(tabMenu.y, window.innerHeight - 380) }}
          >
            <button
              className="w-full text-left px-3 py-1.5 hover:bg-primary/15 hover:text-primary text-zinc-200 flex items-center gap-2"
              onClick={() => {
                window.dispatchEvent(new CustomEvent(`session-reconnect-${targetId}`));
                setTabMenu(null);
              }}
            >Reconnect</button>
            <button
              className="w-full text-left px-3 py-1.5 hover:bg-white/10 text-zinc-200"
              onClick={() => {
                invoke("disconnect_session", { sessionId: targetId }).catch(console.error);
                setTabMenu(null);
              }}
            >Disconnect</button>

            {/* Saves the session's currently-active terminal's full
                scrollback to a text file — same action as pressing S on
                that terminal's own "Session stopped" message, just reachable
                without needing the shell to have exited first. */}
            {sessionActiveTerm[targetId] && (
              <button
                className="w-full text-left px-3 py-1.5 hover:bg-primary/15 hover:text-primary text-zinc-200 flex items-center gap-2"
                onClick={() => {
                  window.dispatchEvent(new CustomEvent(`terminal-save-output-${sessionActiveTerm[targetId]}`));
                  setTabMenu(null);
                }}
              >
                <Save size={12} className="text-zinc-500" /> Save output to file…
              </button>
            )}

            {/* Typed commands of this session stay out of the command
                history while checked (until the session closes, F-023). */}
            <button
              className="w-full text-left px-3 py-1.5 hover:bg-primary/15 hover:text-primary text-zinc-200 flex items-center gap-2"
              onClick={() => {
                setRecordingPaused(targetId, !isRecordingPaused(targetId));
                setTabMenu(null);
              }}
            >
              <span className="w-3 text-primary">{isRecordingPaused(targetId) ? "✓" : ""}</span> Don't record command history
            </button>

            {/* Pin/Unpin the session's currently-active terminal to
                the Wall — one-click convenience so users don't have to
                open the picker + tick a specific terminal for the
                common "just pin what I'm looking at" case. The picker
                remains for choosing a specific non-active terminal or
                pinning multiple at once. */}
            {(() => {
              const activeTid = sessionActiveTerm[targetId];
              const activeTermPinned = activeTid ? wallHasTerminal(activeTid) : false;
              const anyPinned = wallItems.some(i => i.sessionId === targetId);
              return (
                <>
                  {activeTid && (
                    <button
                      className="w-full text-left px-3 py-1.5 hover:bg-primary/15 hover:text-primary text-zinc-200 flex items-center gap-2"
                      onClick={() => {
                        if (activeTermPinned) unpinTerminalFromWall(activeTid);
                        else pinTerminalToWall(targetId, activeTid);
                        setTabMenu(null);
                      }}
                    >
                      {activeTermPinned
                        ? (<><PinOff size={12} className="text-zinc-500" /> Unpin active terminal</>)
                        : (<><Pin size={12} className="text-zinc-500" /> Pin active terminal to Wall</>)}
                    </button>
                  )}
                  {anyPinned && (
                    <button
                      className="w-full text-left px-3 py-1.5 hover:bg-rose-500/10 hover:text-rose-300 text-zinc-400 flex items-center gap-2 text-[10.5px]"
                      onClick={() => { unpinSessionFromWall(targetId); setTabMenu(null); }}
                    >
                      <PinOff size={11} /> Unpin ALL from this session
                    </button>
                  )}
                </>
              );
            })()}

            {/* Split view picker — the user's requested UX. Right-click
                any tab, tick which OTHER tabs you want tiled beside it.
                The right-clicked tab becomes the focused pane; ticked
                rows become side panes. Ticking auto-applies so there's
                no "Apply" button to hunt. Hidden entirely when there's
                only one open session (nothing to pair with). */}
            {others.length > 0 && (
              <>
                <div className="border-t border-white/5 my-1" />
                <div className="px-3 pt-1 pb-1.5 flex items-center justify-between">
                  <span className="text-[9.5px] font-bold uppercase tracking-widest text-zinc-500">
                    Split view with
                  </span>
                  {targetIsActive && currentMerges.length > 0 && (
                    <button
                      onClick={() => { setMergedSessionIds([]); setTabMenu(null); }}
                      className="text-[9.5px] font-bold uppercase tracking-wider text-zinc-500 hover:text-white"
                    >
                      Clear
                    </button>
                  )}
                </div>
                <div className="max-h-[200px] overflow-y-auto custom-scrollbar px-1 pb-1">
                  {others.map(s => {
                    const st = sessionStatuses[s.id] ?? "connecting";
                    const checked = currentMerges.includes(s.id);
                    return (
                      <label
                        key={s.id}
                        className={`flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer ${
                          checked ? "bg-primary/10" : "hover:bg-white/[0.04]"
                        }`}
                      >
                        <input
                          type="checkbox"
                          className="accent-primary shrink-0"
                          checked={checked}
                          onChange={() => {
                            // Ticking: switch focus to the right-clicked
                            // tab (if not already) and add the picked
                            // partner. Unticking: drop the partner from
                            // the split — and collapse the split entirely
                            // when it would fall below the 2-pane minimum.
                            if (checked) {
                              const next = mergedSessionIds.filter(id => id !== s.id);
                              setMergedSessionIds(next.length < 2 ? [] : next);
                            } else {
                              if (!targetIsActive) {
                                setActiveView(targetId);
                                setMergedSessionIds([targetId, s.id]);
                              } else if (mergedSessionIds.length === 0) {
                                setMergedSessionIds([targetId, s.id]);
                              } else {
                                setMergedSessionIds(prev => prev.includes(s.id) ? prev : [...prev, s.id]);
                              }
                            }
                          }}
                        />
                        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                          st === "connected" ? "bg-emerald-400" :
                          st === "connecting" ? "bg-amber-400" :
                          "bg-rose-500"
                        }`} />
                        <span className="truncate text-[11px] font-medium text-zinc-200 flex-1">
                          {s.serverName}
                        </span>
                      </label>
                    );
                  })}
                </div>
              </>
            )}

            <div className="border-t border-white/5 my-1" />
            <button
              className="w-full text-left px-3 py-1.5 hover:bg-rose-500/15 hover:text-rose-300 text-zinc-200"
              onClick={async () => {
                const sid = targetId;
                setTabMenu(null);
                const target = sessions.find(sess => sess.id === sid);
                if (target && !(await confirmSessionClose(target))) return;
                invoke("disconnect_session", { sessionId: sid }).catch(() => {});
                setSessions(prev => prev.filter(sess => sess.id !== sid));
                setSessionStatuses(prev => { const { [sid]: _, ...rest } = prev; return rest; });
                broadcast.removeSession(sid);
                setMergedSessionIds(prev => {
                  const next = prev.filter(id => id !== sid);
                  return next.length < 2 ? [] : next;
                });
                unpinSessionFromWall(sid);
                setActiveView(prev => (prev === sid ? "nodes" : prev));
                setTabMenu(null);
              }}
            >Close tab</button>
          </div>
        </>
        );
      })()}
    </div>
  );

  // h-full (not h-screen) so the layout tracks --vv-h from main.tsx —
  // when the Android soft keyboard opens the visualViewport shrinks and the
  // whole flex chain cascades above the keyboard instead of anchoring to
  // the un-shrunken layout viewport.
  if (loading) return <div className="h-full bg-black flex items-center justify-center font-mono text-xs text-primary animate-pulse">Loading…</div>;

  return (
    <div className="h-full w-full bg-background flex flex-col overflow-hidden text-zinc-200 select-none">
      {TitleBar()}
      {!isUnlocked ? (
        <ProfileSelectPage onUnlocked={handleProfileUnlocked} />
      ) : (
        // Layout swap: on desktop the sidebar is a left rail (row).
        // On mobile we flip to flex-col-reverse so the sidebar component
        // renders at the bottom while staying first in DOM order — keyboard
        // tab-order stays intuitive and <main> grabs the full screen width
        // (terminal gains the ~50px the vertical rail used to eat).
        <div className={`flex-1 flex ${isMobile ? 'flex-col-reverse' : ''} overflow-hidden pt-10`}>
          <Sidebar
            activeTab={activeView.startsWith('session-') ? 'nodes' : activeView}
            setActiveTab={(tab: string) => {
              // Matches the existing Wall entry points (top tab, mobile
              // dropdown): switching into Wall exits any active session
              // split first, so it doesn't leave stale merged-view state
              // behind. Other tabs are untouched, same as before.
              if (tab === 'wall') setMergedSessionIds([]);
              setActiveView(tab);
            }}
            isMobile={isMobile}
            onLogout={handleLogout}
            pinnedPanelOpen={pinnedPanelOpen}
            onTogglePinnedPanel={togglePinnedPanel}
          />

          {/* Persistent regardless of activeView — unlike Sidebar's single-view
              swap, this is the whole point: a pinned server stays one click
              away even while looking at Settings or SSH Keys. Hidden on
              mobile, same convention as the rest of this layout. Unmounted
              entirely (not just visually collapsed) when closed, since the
              rail icon and the panel's own collapse button both mean "closed
              means gone", not "shrunk to an icon strip". */}
          {!isMobile && pinnedPanelOpen && (
            <PinnedPanel servers={servers} folders={folders} onOpenServer={openServer} onCollapse={togglePinnedPanel} />
          )}

          <main className="flex-1 flex flex-col min-w-0 min-h-0 bg-transparent relative">
            {activeView === "nodes" && (
              <NodeGrid
                servers={servers}
                folders={folders}
                activeFolderId={activeFolderId}
                onActiveFolderChange={setActiveFolderId}
                onOpenServer={openServer}
                onEditServer={handleEditNode}
                onAddClick={(folderId?: number | null) => {
                  // When invoked from inside a folder header, seed the new
                  // node's folderId so the user doesn't have to re-pick the
                  // folder they just clicked into. Bare invocation (from the
                  // root grid's "Add server" card) stays at the empty default.
                  setNewNode({
                    ...defaultNode,
                    folderId: folderId != null ? String(folderId) : "",
                  });
                  setIsPanelOpen(true);
                }}
                onQuickConnect={() => setIsQuickConnectOpen(true)}
                onLocalShell={() => setIsLocalShellOpen(true)}
                onRemoveServer={removeServer}
                onRemoveFolder={removeFolder}
                onRenameFolder={renameFolder}
                onCreateFolder={createFolder}
                onPinServer={pinServer}
                onPinFolder={pinFolder}
                onCloneServer={async (id: number) => {
                  try { await invoke("clone_server", { id }); refreshServers(); addLog("Node cloned.", "success"); }
                  catch (e) { reportError("Could not clone the server", e); }
                }}
                onReorderServers={async (ids: number[]) => {
                  // Rethrow on failure so NodeGrid drops its optimistic order
                  // override and reverts to the real (unchanged) arrangement.
                  try { await invoke("reorder_servers", { ids }); await refreshServers(); }
                  catch (e) { reportError("Could not save the new order", e); throw e; }
                }}
                isMobile={isMobile}
              />
            )}

            {activeView === "settings" && (
              <SettingsPanel
                settings={appSettings}
                setSettings={setAppSettings}
                isMobile={isMobile}
                onOpenLogs={() => setActiveView("logs")}
              />
            )}

            {activeView === "vault" && (
              <div className="flex-1 flex flex-col p-4 sm:p-8 space-y-6 sm:space-y-8 animate-in overflow-y-auto custom-scrollbar">
                <header className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 border-b border-zinc-700 pb-5 sm:pb-6 shrink-0">
                  <div className="min-w-0">
                    <h2 className="text-[18px] sm:text-[22px] font-bold text-white tracking-tight">Logins</h2>
                    <p className="hidden sm:block text-[13px] text-zinc-400">Your saved passwords and SSH keys.</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      onClick={() => { setEditCredData(EMPTY_CRED); setIsCredPanelOpen(true); }}
                      title="Add Password"
                      className="h-9 px-2.5 sm:px-4 bg-zinc-900 text-zinc-200 text-[12px] sm:text-[13px] font-bold rounded-xl border border-white/5 hover:bg-zinc-800 transition-all flex items-center gap-1.5"
                    >
                      <Plus size={14} /> <span className="hidden sm:inline">Add Password</span><span className="sm:hidden">Password</span>
                    </button>
                    <button
                      onClick={() => { setEditKeyData(EMPTY_KEY); setIsKeyPanelOpen(true); }}
                      title="Add Key"
                      className="h-9 px-2.5 sm:px-4 bg-zinc-900 text-zinc-200 text-[12px] sm:text-[13px] font-bold rounded-xl border border-white/5 hover:bg-zinc-800 transition-all flex items-center gap-1.5"
                    >
                      <Plus size={14} /> <span className="hidden sm:inline">Add Key</span><span className="sm:hidden">Key</span>
                    </button>
                    <button
                      onClick={async () => {
                        // Native window.prompt is a no-op in Tauri's Android
                        // WebView — themed useTextPrompt works everywhere.
                        const name = await textPrompt({
                          title: "Generate SSH key",
                          message: "Give this key a name — it's just for your reference here in Solanum.",
                          placeholder: "e.g. laptop-2026",
                          okLabel: "Generate",
                          validate: (v) => v.length === 0 ? "Name is required" : null,
                        });
                        if (name) invoke("generate_ssh_key", { name }).then(() => refreshSshKeys()).catch((e) => reportError("Could not generate the key", e));
                      }}
                      title="Generate Key"
                      className="h-9 px-2.5 sm:px-4 bg-primary text-black text-[12px] sm:text-[13px] font-bold rounded-xl shadow-lg shadow-primary/20 flex items-center gap-1.5"
                    >
                      <Key size={14} /> <span className="hidden sm:inline">Generate Key</span><span className="sm:hidden">Generate</span>
                    </button>
                  </div>
                </header>

                <div className="space-y-10 pb-10">
                  <section>
                    <h3 className="text-[13px] font-bold text-zinc-400 mb-4 flex items-center gap-2">
                      <Shield size={14} /> Saved passwords
                    </h3>
                    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-2">
                      {credentials.length === 0 ? (
                        <div className="col-span-full py-10 text-center text-zinc-600 text-[14px] italic border border-dashed border-white/5 rounded-2xl">Nothing here yet.</div>
                      ) : (
                        credentials.map(c => (
                          <div key={c.id} className="bg-[#16161a] border border-white/5 rounded-xl p-3 group relative hover:border-primary/30 transition-all">
                            <div className="flex justify-between items-start mb-1">
                              <h4 className="text-[14px] font-bold text-zinc-100 truncate pr-8">{c.name}</h4>
                              <div className="flex items-center gap-2 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity absolute right-3 top-3">
                                <button onClick={async () => {
                                  // Credentials list now ships `has_password` instead of plaintext;
                                  // pull the secret on demand for the edit sheet.
                                  let pw = "";
                                  if (c.has_password) {
                                    try { pw = (await invoke<string | null>("reveal_credential_password", { id: c.id })) || ""; }
                                    catch (e) { reportError("Could not read the saved password", e); }
                                  }
                                  setEditCredData({ ...c, password: pw });
                                  setIsCredPanelOpen(true);
                                }} className="text-zinc-500 hover:text-white"><Edit2 size={14} /></button>
                                <button onClick={async () => {
                                  const ok = await confirm({ title: "Delete saved password?", message: `“${c.name}” will be removed. Servers using this login will lose it.`, destructive: true });
                                  if (!ok) return;
                                  // Servers using it are unlinked in the vault; refresh them too so
                                  // editing one afterwards doesn't send the deleted id back.
                                  invoke("delete_credential", { id: c.id }).then(() => { refreshCredentials(); refreshServers(); })
                                    .catch((e) => reportError("Could not delete the saved login", e));
                                }} className="text-zinc-500 hover:text-red-500"><Trash2 size={14} /></button>
                              </div>
                            </div>
                            <div className="flex flex-col gap-0.5">
                              <div className="flex items-center gap-2 text-[11px] text-zinc-500 font-medium">
                                <User size={10} /> {c.username}
                              </div>
                              <div className="flex items-center gap-2 text-[11px] text-zinc-500 font-medium">
                                <Key size={10} /> {c.has_password ? "••••••••" : "Using SSH key"}
                              </div>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </section>

                  <section>
                    <h3 className="text-[13px] font-bold text-zinc-400 mb-4 flex items-center gap-2">
                      <Key size={14} /> SSH keys
                    </h3>
                    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-2">
                      {sshKeys.length === 0 ? (
                        <div className="col-span-full py-10 text-center text-zinc-600 text-[14px] italic border border-dashed border-white/5 rounded-2xl">No keys saved yet.</div>
                      ) : (
                        sshKeys.map((k: any) => (
                          <div key={k.id} className="bg-[#16161a] border border-white/5 rounded-xl p-3 group relative hover:border-primary/30 transition-all">
                            <div className="flex justify-between items-start mb-1">
                              <h4 className="text-[14px] font-bold text-zinc-100 truncate pr-8">{k.name}</h4>
                              <div className="flex items-center gap-2 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity absolute right-3 top-3">
                                <button onClick={async () => {
                                  // Same pattern as credentials — pull the private key + passphrase
                                  // on demand instead of leaking them in the list response.
                                  let secrets: { private_key?: string|null; passphrase?: string|null } = {};
                                  if (k.has_private_key || k.has_passphrase) {
                                    try { secrets = await invoke<any>("reveal_ssh_key", { id: k.id }); }
                                    catch (e) { reportError("Could not read the saved key", e); }
                                  }
                                  setEditKeyData({
                                    ...k,
                                    private_key: secrets.private_key || "",
                                    passphrase: secrets.passphrase || "",
                                  });
                                  setIsKeyPanelOpen(true);
                                }} className="text-zinc-500 hover:text-white"><Edit2 size={14} /></button>
                                <button onClick={async () => {
                                  const ok = await confirm({ title: "Delete SSH key?", message: `“${k.name}” will be removed. This key cannot be recovered.`, destructive: true });
                                  if (!ok) return;
                                  // Servers and saved logins using it are unlinked in the vault; refresh
                                  // them too so editing one afterwards doesn't send the deleted id back.
                                  invoke("delete_ssh_key", { id: k.id }).then(() => { refreshSshKeys(); refreshCredentials(); refreshServers(); })
                                    .catch((e) => reportError("Could not delete the SSH key", e));
                                }} className="text-zinc-500 hover:text-red-500"><Trash2 size={14} /></button>
                              </div>
                            </div>
                            <div className="flex flex-col gap-0.5">
                              <div className="flex items-center gap-2 text-[10px] text-zinc-500 font-mono truncate">
                                {k.public_key.substring(0, 24)}...
                              </div>
                              <div className="text-[10px] text-primary/50 font-medium">
                                Private key
                              </div>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </section>
                </div>
              </div>
            )}

            {/* Sessions live in an absolute layer that overlays the rest of
                `main` — that way each session's xterm stays mounted at its
                real measured size across tab switches, but doesn't take any
                layout space when the user navigates to notes / settings /
                etc. The previous `display:none` toggle caused a 0×0 →
                real-size reflow on every switch and corrupted the prompt
                with stacked fragments like `[root@local[root@local`. */}
            {(() => {
              // When the current view is a session and mergedSessionIds has
              // entries, tile the focused session and its merged partners
              // side-by-side inside the same canvas — the user's "put two
              // main tabs together as panes" request. Hidden sessions stay
              // mounted (absolute-positioned, opacity 0) so scrollback and
              // PTY state survive; visible ones are explicitly positioned
              // via left/width so the tile widths match the visible count
              // without triggering a display-mode flip that could reset
              // xterm layout.
              const viewIsSession = activeView.startsWith("session-") && sessions.some(s => s.id === activeView);
              // mergedSessionIds semantics: when non-empty it lists ALL
              // tiled panes (including the currently focused one) in
              // visual order. Visual order is deliberately independent
              // of activeView so that clicking a tile to focus it does
              // NOT slide the tile to position 0 — the user reported
              // the left pane "jumping to the other server" on focus
              // change and that reorder was the cause.
              const isTiled = viewIsSession
                && mergedSessionIds.length >= 2
                && mergedSessionIds.includes(activeView);
              const visibleIds = isTiled
                ? mergedSessionIds.filter(id => sessions.some(s => s.id === id))
                : (viewIsSession ? [activeView] : []);
              return (
                <div className={`absolute inset-0 flex flex-col overflow-hidden ${!viewIsSession ? 'opacity-0 pointer-events-none' : ''}`}>
                  <div className="flex-1 relative bg-black/40">
                    {sessions.map(sess => {
                      const idx = visibleIds.indexOf(sess.id);
                      const isVisible = idx >= 0;
                      const isFocused = activeView === sess.id;
                      const style: React.CSSProperties = isVisible
                        ? {
                            position: 'absolute',
                            top: 0,
                            bottom: 0,
                            left: `${(idx * 100) / visibleIds.length}%`,
                            width: `${100 / visibleIds.length}%`,
                          }
                        : {
                            position: 'absolute',
                            inset: 0,
                            opacity: 0,
                            pointerEvents: 'none',
                          };
                      return (
                        <div
                          key={sess.id}
                          style={style}
                          onMouseDownCapture={() => {
                            // Focus shift ONLY — tile positions live in
                            // mergedSessionIds and must stay stable across
                            // focus changes. Reordering here was the cause
                            // of the reported "left tile jumps to the other
                            // server when I click the right one" bug.
                            if (isTiled && !isFocused && isVisible) {
                              setActiveView(sess.id);
                            }
                          }}
                          // flex flex-col so SessionView's root `flex-1`
                          // actually fills the tile. Without this the tile
                          // has explicit position:absolute + top/bottom
                          // dimensions but SessionView's internal flex
                          // layout collapses to 0 height and the terminal
                          // + tool panels never draw.
                          className={`flex flex-col overflow-hidden ${
                            isVisible && isTiled
                              ? `border ${isFocused ? 'border-primary/40 shadow-[inset_0_0_0_1px_rgba(var(--primary),0.15)]' : 'border-white/[0.05]'}`
                              : ''
                          }`}
                        >
                          {/* Merged (non-focused) tile header. Only the
                              focused pane keeps its full tab strip + tool
                              rail (via SessionView's default chrome);
                              merged panes get a slim 28-px header with
                              server name + a click-to-focus hint + a
                              detach X. Everything below that header is a
                              chromeless SessionView so it renders ONLY
                              the currently-active terminal without
                              stacking a second toolbar next to the
                              focused one. Vertical space wasted per
                              merged tile drops from ~48 px (full chrome)
                              to ~28 px (slim header). */}
                          {isVisible && isTiled && !isFocused && (
                            <div className="h-7 shrink-0 flex items-center gap-2 px-2 border-b border-white/5 bg-[#111114] text-[10.5px]">
                              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                                (sessionStatuses[sess.id] ?? 'connecting') === 'connected' ? 'bg-emerald-400' :
                                (sessionStatuses[sess.id] ?? 'connecting') === 'connecting' ? 'bg-amber-400' :
                                'bg-rose-500'
                              }`} />
                              <span className="font-bold text-zinc-200 uppercase tracking-wider truncate flex-1">
                                {sess.serverName}
                              </span>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  const next = mergedSessionIds.filter(id => id !== sess.id);
                                  // Under 2 members isn't a split any more —
                                  // clear the list so the remaining pane
                                  // reverts to plain full-width single view.
                                  setMergedSessionIds(next.length < 2 ? [] : next);
                                }}
                                title="Remove this pane from the split view"
                                className="h-5 w-5 rounded flex items-center justify-center text-zinc-500 hover:text-red-400 hover:bg-white/[0.05] transition-all"
                              >
                                <X size={11} />
                              </button>
                            </div>
                          )}
                          <ErrorBoundary
                            label={sess.serverName}
                            onReset={() => {
                              setSessions(prev => prev.filter(s => s.id !== sess.id));
                              if (activeView === sess.id) setActiveView("nodes");
                            }}
                          >
                            {sess.kind === 'local' ? (
                              <LocalShellView
                                session={sess}
                                onClose={getCloseHandler(sess.id)}
                                onStatusChange={handleSessionStatus}
                                onTerminalsChange={handleTerminalsChange}
                              />
                            ) : (
                              <SessionView
                                session={sess}
                                onClose={getCloseHandler(sess.id)}
                                addLog={addLog}
                                onStatusChange={handleSessionStatus}
                                onTerminalsChange={handleTerminalsChange}
                                chromeless={isVisible && isTiled && !isFocused}
                                warnOnCloseActiveSession={appSettings.warnOnCloseActiveSession}
                                onServersChanged={refreshServers}
                              />
                            )}
                          </ErrorBoundary>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })()}

            {/* Wall canvas — a grid of individual terminal tiles pinned
                from any session. Independent of the session-split
                canvas above; the two live side-by-side in `main` with
                only one visible at a time. Wall tiles mount their own
                TerminalView in attach-only mode so xterm scrollback +
                PTY ownership stay with the primary xterm in the
                session tab. */}
            {activeView === "wall" && (
              <div className="absolute inset-0 flex flex-col overflow-hidden bg-[#0a0a0d]">
                {/* Toolbar: cols selector + Add + Clear. Rows are
                    derived automatically from tile count so users only
                    have to pick the horizontal density they want. */}
                <div className="h-10 shrink-0 border-b border-white/5 bg-[#111114] flex items-center gap-2 px-3">
                  <LayoutGrid size={12} className="text-primary/70 shrink-0" />
                  <span className="text-[10px] font-bold uppercase tracking-widest text-zinc-400 shrink-0">
                    Wall {wallItems.length > 0 ? `· ${wallItems.length}` : ''}
                  </span>
                  <div className="flex items-center gap-1 ml-2 shrink-0">
                    <span className="text-[9px] font-bold uppercase tracking-wider text-zinc-500">Cols</span>
                    {[1, 2, 3, 4, 5, 6].map(n => (
                      <button
                        key={n}
                        onClick={() => setWallCols(n)}
                        title={`${n} column${n === 1 ? '' : 's'} per row`}
                        className={`h-6 w-6 rounded flex items-center justify-center text-[10px] font-bold transition-all ${
                          wallCols === n
                            ? 'bg-primary/20 text-primary border border-primary/40'
                            : 'text-zinc-400 hover:bg-white/[0.06] border border-transparent'
                        }`}
                      >
                        {n}
                      </button>
                    ))}
                  </div>
                  <div className="flex-1" />
                  <button
                    onClick={() => setWallPickerOpen(v => !v)}
                    title="Pick terminals to pin"
                    className="px-3 py-1 bg-primary/15 hover:bg-primary/25 text-primary border border-primary/30 rounded-md text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5"
                  >
                    <Plus size={11} /> Add
                  </button>
                  {wallItems.length > 0 && (
                    <button
                      onClick={() => setWallItems([])}
                      title="Unpin everything (terminals stay open in their sessions)"
                      className="px-3 py-1 bg-white/[0.04] hover:bg-rose-500/15 hover:text-rose-300 border border-white/10 rounded-md text-[10px] font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-1.5"
                    >
                      <X size={11} /> Clear
                    </button>
                  )}
                </div>

                {/* Grid canvas. Empty state overlaid when nothing is
                    pinned so we don't just show a black rectangle to a
                    first-time visitor. */}
                <div className="flex-1 relative bg-black/40 overflow-auto custom-scrollbar">
                  {wallItems.length === 0 ? (
                    <div className="absolute inset-0 flex flex-col items-center justify-center gap-4 text-center px-6 pointer-events-none">
                      <LayoutGrid size={40} className="text-zinc-600" />
                      <div className="text-zinc-400 text-[13px] max-w-md leading-relaxed">
                        The Wall is a pinboard for watching multiple <em>terminals</em> at once.<br/>
                        Right-click a session tab or use the <span className="text-primary font-semibold">Add</span> button above to pin any terminal from any server.
                      </div>
                    </div>
                  ) : (
                    <div
                      className="min-h-full grid gap-1.5 p-1.5"
                      style={{
                        gridTemplateColumns: `repeat(${wallCols}, minmax(0, 1fr))`,
                        gridAutoRows: `minmax(220px, 1fr)`,
                      }}
                    >
                      {wallItems.map(item => {
                        const sess = sessions.find(s => s.id === item.sessionId);
                        if (!sess) return null;
                        const terms = sessionTerminals[item.sessionId] ?? [];
                        const term = terms.find(t => t.id === item.terminalId);
                        const st = sessionStatuses[item.sessionId] ?? 'connecting';
                        const dotTone =
                          st === 'connected'    ? 'bg-emerald-400' :
                          st === 'connecting'   ? 'bg-amber-400 animate-pulse' :
                                                  'bg-rose-500';
                        return (
                          <div
                            key={item.id}
                            className="flex flex-col overflow-hidden border border-white/10 rounded-md bg-[#09090b] shadow-[0_2px_10px_rgba(0,0,0,0.4)] hover:border-primary/30 transition-colors"
                          >
                            {/* Slim tile header — server + terminal
                                title, quick-jump into the session,
                                unpin. Terminal body below owns focus
                                so keystrokes go to xterm directly. */}
                            <div className="h-7 shrink-0 flex items-center gap-2 px-2 border-b border-white/5 bg-[#141418] text-[10.5px] select-none">
                              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotTone}`} />
                              <span className="font-bold text-zinc-200 uppercase tracking-wider truncate">
                                {sess.serverName}
                              </span>
                              <span className="text-zinc-600">·</span>
                              <span className="text-zinc-400 truncate flex-1">
                                {term?.title ?? item.terminalId}
                              </span>
                              <button
                                onClick={() => setActiveView(sess.id)}
                                title="Open this session in its own tab"
                                className="h-5 w-5 rounded flex items-center justify-center text-zinc-500 hover:text-primary hover:bg-white/[0.05] transition-all"
                              >
                                <TerminalSquare size={11} />
                              </button>
                              <button
                                onClick={() => unpinTerminalFromWall(item.terminalId)}
                                title="Unpin from Wall"
                                className="h-5 w-5 rounded flex items-center justify-center text-zinc-500 hover:text-red-400 hover:bg-white/[0.05] transition-all"
                              >
                                <PinOff size={11} />
                              </button>
                            </div>
                            {/* Attach-only TerminalView: hitches onto
                                the same PTY as the session's primary
                                xterm without owning the lifecycle, so
                                closing the Wall or unpinning doesn't
                                drop the session. */}
                            {sessionStatuses[item.sessionId] === 'connected' ? (
                              <div className="flex-1 min-h-0 relative">
                                <TerminalView
                                  sessionId={item.sessionId}
                                  terminalId={item.terminalId}
                                  attachOnly
                                  disabled={false}
                                  isActive={true}
                                  serverId={sess.serverId}
                                  serverName={sess.serverName}
                                />
                              </div>
                            ) : (
                              <div className="flex-1 flex items-center justify-center text-zinc-500 text-[10.5px] font-medium uppercase tracking-wider">
                                Session {st}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Wall picker popover — 2-level session → terminal
                    tree so users can precisely pick which shells to
                    pin. Ticking a terminal pins; unticking unpins.
                    Session rows aren't selectable themselves; they
                    only group their terminals visually. */}
                {wallPickerOpen && (
                  <>
                    <div className="fixed inset-0 z-[65]" onClick={() => setWallPickerOpen(false)} />
                    <div className="absolute top-12 right-3 z-[66] w-80 max-h-[70vh] bg-[#15151a] border border-white/10 rounded-xl shadow-2xl p-2 flex flex-col">
                      <div className="px-2 pb-2 flex items-center justify-between shrink-0">
                        <span className="text-[10px] font-bold uppercase tracking-widest text-zinc-500">
                          Pin terminals
                        </span>
                        <button
                          onClick={() => setWallPickerOpen(false)}
                          className="h-5 w-5 rounded flex items-center justify-center text-zinc-500 hover:text-white hover:bg-white/[0.05]"
                        >
                          <X size={11} />
                        </button>
                      </div>
                      {sessions.length === 0 ? (
                        <div className="px-2 py-6 text-center text-zinc-500 text-[11px]">
                          No open sessions yet.
                        </div>
                      ) : (
                        <div className="overflow-y-auto custom-scrollbar space-y-1 pr-1">
                          {sessions.map(s => {
                            const terms = sessionTerminals[s.id] ?? [];
                            const st = sessionStatuses[s.id] ?? 'connecting';
                            return (
                              <div key={s.id} className="rounded bg-white/[0.02] border border-white/5">
                                <div className="flex items-center gap-2 px-2 py-1.5 border-b border-white/5">
                                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                                    st === 'connected' ? 'bg-emerald-400' :
                                    st === 'connecting' ? 'bg-amber-400' :
                                    'bg-rose-500'
                                  }`} />
                                  <span className="text-[11px] font-bold text-zinc-200 truncate flex-1">
                                    {s.serverName}
                                  </span>
                                  <span className="text-[9px] uppercase tracking-wider text-zinc-500">
                                    {terms.length} term{terms.length === 1 ? '' : 's'}
                                  </span>
                                </div>
                                {terms.length === 0 ? (
                                  <div className="px-3 py-2 text-[10px] text-zinc-500 italic">
                                    Session not yet ready.
                                  </div>
                                ) : (
                                  <div className="p-1 space-y-0.5">
                                    {terms.map(t => {
                                      const checked = wallHasTerminal(t.id);
                                      return (
                                        <label
                                          key={t.id}
                                          className={`flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer ${
                                            checked ? 'bg-primary/10' : 'hover:bg-white/[0.04]'
                                          }`}
                                        >
                                          <input
                                            type="checkbox"
                                            className="accent-primary shrink-0"
                                            checked={checked}
                                            onChange={() => {
                                              if (checked) unpinTerminalFromWall(t.id);
                                              else pinTerminalToWall(s.id, t.id);
                                            }}
                                          />
                                          <TerminalSquare size={11} className="text-zinc-500 shrink-0" />
                                          <span className="text-[11px] text-zinc-200 truncate flex-1">
                                            {t.title}
                                          </span>
                                        </label>
                                      );
                                    })}
                                  </div>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>
            )}

            {/* Library = Commands + Notes merged.
                Commands and Notes used to be two distinct rails; both are
                per-profile lists of small text blobs stored inside the
                encrypted vault, and the only real difference is
                "runnable snippet vs freeform text". A single tab with an
                internal segmented control gives us the sidebar slot back
                on narrow viewports and puts both lists under one search
                box. The sub-tab state (`libraryTab`) is kept at the parent
                so it survives navigation elsewhere and back. */}
            {activeView === "library" && (() => {
              const q = libraryQuery.trim().toLowerCase();
              const filteredCommands = q
                ? commands.filter(c =>
                    (c.title || "").toLowerCase().includes(q) ||
                    (c.content || "").toLowerCase().includes(q))
                : commands;
              const filteredNotes = q
                ? notes.filter(n =>
                    (n.title || "").toLowerCase().includes(q) ||
                    (n.body || "").toLowerCase().includes(q))
                : notes;
              const filteredSnippets = q
                ? snippets.filter(s =>
                    (s.trigger || "").toLowerCase().includes(q) ||
                    (s.expansion || "").toLowerCase().includes(q))
                : snippets;
              const onCommandsTab = libraryTab === "commands";
              const onNotesTab = libraryTab === "notes";
              const onSnippetsTab = libraryTab === "snippets";
              const addLabel = onCommandsTab ? "Add Command" : onNotesTab ? "Add Note" : "Add Snippet";
              const openAdd = () => {
                if (onCommandsTab) {
                  setEditCommandData({ id: null, title: "", content: "" });
                  setIsCommandPanelOpen(true);
                } else if (onNotesTab) {
                  setEditNoteData({ id: null, title: "", body: "" });
                  setIsNotePanelOpen(true);
                } else {
                  setEditSnippetData({ id: null, trigger: "", expansion: "" });
                  setIsSnippetPanelOpen(true);
                }
              };
              return (
                <div className="flex-1 flex flex-col p-4 sm:p-8 space-y-5 sm:space-y-6 animate-in overflow-y-auto custom-scrollbar">
                  <header className="flex flex-col gap-3 border-b border-zinc-700 pb-5 sm:pb-6 shrink-0">
                    <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3">
                      <div className="min-w-0">
                        <h2 className="text-[18px] sm:text-[22px] font-bold text-white tracking-tight flex items-center gap-2">
                          Library
                          <span
                            title="All entries are AES-256-GCM encrypted inside the current profile vault."
                            className="inline-flex items-center gap-1 h-5 px-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-[9px] font-bold uppercase tracking-wider text-emerald-300"
                          >
                            <Shield size={9} /> Vault-locked
                          </span>
                        </h2>
                        <p className="hidden sm:block text-[13px] text-zinc-400">
                          Reusable commands, freeform notes, and typing-time expansions — encrypted with your profile key.
                        </p>
                      </div>
                      <div className="flex gap-2 items-center">
                        <div className="relative">
                          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none" />
                          <input
                            type="text"
                            value={libraryQuery}
                            onChange={(e) => setLibraryQuery(e.target.value)}
                            placeholder="Search title or content…"
                            className="h-9 pl-7 pr-3 w-44 sm:w-56 bg-black/40 border border-white/10 rounded-xl text-[12px] text-zinc-200 placeholder:text-zinc-600 outline-none focus:border-primary/40"
                          />
                        </div>
                        <button
                          onClick={openAdd}
                          title={addLabel}
                          className="h-9 px-3 sm:px-4 bg-primary text-black text-[12px] sm:text-[13px] font-bold rounded-xl shadow-lg shadow-primary/20 flex items-center gap-1.5 transition-all hover:brightness-110 self-start sm:self-auto"
                        >
                          <Plus size={14} /> {addLabel}
                        </button>
                      </div>
                    </div>
                    {/* Segmented control — Commands / Notes / Snippets. Counts
                        sit inside each pill so switching contexts is a single
                        glance. */}
                    <div className="flex items-center gap-1 self-start bg-black/30 border border-white/5 rounded-xl p-0.5">
                      <button
                        onClick={() => setLibraryTab("commands")}
                        className={`h-8 px-3 rounded-lg text-[11px] font-bold uppercase tracking-wider transition-all flex items-center gap-1.5 ${
                          onCommandsTab
                            ? "bg-primary/15 text-primary shadow-inner"
                            : "text-zinc-400 hover:text-zinc-100"
                        }`}
                      >
                        <TerminalSquare size={12} /> Commands
                        <span className={`text-[9px] font-bold ${onCommandsTab ? "text-primary/70" : "text-zinc-600"}`}>
                          {filteredCommands.length}
                        </span>
                      </button>
                      <button
                        onClick={() => setLibraryTab("notes")}
                        className={`h-8 px-3 rounded-lg text-[11px] font-bold uppercase tracking-wider transition-all flex items-center gap-1.5 ${
                          onNotesTab
                            ? "bg-primary/15 text-primary shadow-inner"
                            : "text-zinc-400 hover:text-zinc-100"
                        }`}
                      >
                        <StickyNote size={12} /> Notes
                        <span className={`text-[9px] font-bold ${onNotesTab ? "text-primary/70" : "text-zinc-600"}`}>
                          {filteredNotes.length}
                        </span>
                      </button>
                      <button
                        onClick={() => setLibraryTab("snippets")}
                        className={`h-8 px-3 rounded-lg text-[11px] font-bold uppercase tracking-wider transition-all flex items-center gap-1.5 ${
                          onSnippetsTab
                            ? "bg-primary/15 text-primary shadow-inner"
                            : "text-zinc-400 hover:text-zinc-100"
                        }`}
                      >
                        <Zap size={12} /> Snippets
                        <span className={`text-[9px] font-bold ${onSnippetsTab ? "text-primary/70" : "text-zinc-600"}`}>
                          {filteredSnippets.length}
                        </span>
                      </button>
                    </div>
                  </header>

                  {onCommandsTab ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pb-10">
                      {filteredCommands.length === 0 ? (
                        <div className="col-span-full py-12 text-center text-zinc-500 text-[14px] italic border border-dashed border-white/10 rounded-2xl">
                          {q ? `No commands match "${libraryQuery}".` : "No commands yet."}
                        </div>
                      ) : (
                        filteredCommands.map(cmd => (
                          <div key={cmd.id} className="bg-[#16161a] border border-white/5 rounded-2xl p-4 flex flex-col group relative overflow-hidden shadow-inner h-[150px]">
                            <div className="flex justify-between items-start mb-2">
                              <h3 className="text-[16px] font-bold text-primary tracking-tight truncate flex-1">{cmd.title}</h3>
                              <div className="flex items-center gap-2 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity">
                                <button onClick={() => { setEditCommandData(cmd); setIsCommandPanelOpen(true); }} className="text-zinc-500 hover:text-white transition-colors"><Edit2 size={14} /></button>
                                <button onClick={async () => {
                                  const ok = await confirm({ title: "Delete command?", message: `“${cmd.title}” will be removed.`, destructive: true });
                                  if (!ok) return;
                                  invoke("delete_command", { id: cmd.id }).then(() => { refreshCommands(); })
                                    .catch((e) => reportError("Could not delete the command", e));
                                }} className="text-zinc-500 hover:text-red-500 transition-colors"><Trash2 size={14} /></button>
                              </div>
                            </div>
                            <div className="bg-black/30 rounded-xl p-3 border border-white/5 flex-1 relative group-hover:border-primary/20 transition-colors overflow-hidden">
                              <pre className="text-[12px] text-zinc-400 font-mono whitespace-pre-wrap leading-relaxed line-clamp-3">{cmd.content}</pre>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  ) : onNotesTab ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pb-10">
                      {filteredNotes.length === 0 ? (
                        <div className="col-span-full py-12 text-center text-zinc-500 text-[14px] italic border border-dashed border-white/10 rounded-2xl">
                          {q ? `No notes match "${libraryQuery}".` : "No notes yet."}
                        </div>
                      ) : (
                        filteredNotes.map(n => (
                          <div key={n.id} className="bg-[#16161a] border border-white/5 rounded-2xl p-4 flex flex-col group relative overflow-hidden shadow-inner h-[170px]">
                            <div className="flex justify-between items-start mb-2 gap-2">
                              <h3 className="text-[15px] font-bold text-primary tracking-tight truncate flex-1">{n.title || "Untitled"}</h3>
                              <div className="flex items-center gap-2 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity shrink-0">
                                <button onClick={() => { setEditNoteData({ id: n.id, title: n.title || "", body: n.body || "" }); setIsNotePanelOpen(true); }} className="text-zinc-500 hover:text-white transition-colors"><Edit2 size={14} /></button>
                                <button onClick={async () => {
                                  const ok = await confirm({ title: "Delete note?", message: `“${n.title || "Untitled"}” will be removed.`, destructive: true });
                                  if (!ok) return;
                                  invoke("delete_note", { id: n.id }).then(() => { refreshNotes(); })
                                    .catch((e) => reportError("Could not delete the note", e));
                                }} className="text-zinc-500 hover:text-red-500 transition-colors"><Trash2 size={14} /></button>
                              </div>
                            </div>
                            <div className="bg-black/30 rounded-xl p-3 border border-white/5 flex-1 relative group-hover:border-primary/20 transition-colors overflow-hidden cursor-pointer"
                                 onClick={() => { setEditNoteData({ id: n.id, title: n.title || "", body: n.body || "" }); setIsNotePanelOpen(true); }}>
                              <pre className="text-[12px] text-zinc-400 whitespace-pre-wrap leading-relaxed line-clamp-4 font-sans">{n.body}</pre>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 pb-10">
                      {filteredSnippets.length === 0 ? (
                        <div className="col-span-full py-12 text-center text-zinc-500 text-[14px] italic border border-dashed border-white/10 rounded-2xl">
                          {q ? `No snippets match "${libraryQuery}".` : "No snippets yet — add one, then turn on \"Text-expansion snippets\" in Settings › Terminal."}
                        </div>
                      ) : (
                        filteredSnippets.map(s => (
                          <div key={s.id} className="bg-[#16161a] border border-white/5 rounded-2xl p-4 flex flex-col group relative overflow-hidden shadow-inner h-[150px]">
                            <div className="flex justify-between items-start mb-2 gap-2">
                              <h3 className="text-[16px] font-bold text-primary tracking-tight truncate flex-1 font-mono">{s.trigger}</h3>
                              <div className="flex items-center gap-2 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity shrink-0">
                                <button onClick={() => { setEditSnippetData(s); setIsSnippetPanelOpen(true); }} className="text-zinc-500 hover:text-white transition-colors"><Edit2 size={14} /></button>
                                <button onClick={async () => {
                                  const ok = await confirm({ title: "Delete snippet?", message: `“${s.trigger}” will be removed.`, destructive: true });
                                  if (!ok) return;
                                  invoke("delete_snippet", { id: s.id }).then(() => { refreshSnippets(); window.dispatchEvent(new CustomEvent('solanum-snippets-changed')); })
                                    .catch((e) => reportError("Could not delete the snippet", e));
                                }} className="text-zinc-500 hover:text-red-500 transition-colors"><Trash2 size={14} /></button>
                              </div>
                            </div>
                            <div className="bg-black/30 rounded-xl p-3 border border-white/5 flex-1 relative group-hover:border-primary/20 transition-colors overflow-hidden">
                              <pre className="text-[12px] text-zinc-400 font-mono whitespace-pre-wrap leading-relaxed line-clamp-3">{s.expansion}</pre>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  )}
                </div>
              );
            })()}

            {/* Monitor is mounted permanently and just CSS-hidden when not
                active. Unmounting would tear down the sample/history ring
                buffers, the per-node event listeners, and the 1s tick — so
                switching tabs felt like monitoring "stopped". Keeping it
                mounted preserves the live data; the backend pollers were
                always running, only the UI side was losing state. */}
            <div className={`flex-1 flex flex-col overflow-hidden ${activeView === "monitor" ? "" : "hidden"}`}>
              <MonitoringPanel servers={servers} refreshServers={refreshServers} addLog={addLog} />
            </div>

            {/* Compare workspace — pick any subset of open sessions and
                tile their currently-visible terminals in one canvas.
                Uses BroadcastContext.sessionTerminalMap to look up which
                of each session's tabs is the "current" one; a tile just
                re-mounts a TerminalView pointing at that (sessionId,
                terminalId) pair. Since the source SessionView also stays
                mounted, both instances stay in sync via the shared
                `terminal-output-<id>` events — closing a tile doesn't
                tear the terminal down, it just detaches this view.

                Layout: `grid-cols-N` for up to 4 tiles (1/2/2/2), then
                `grid-cols-3` for 5-9, then `grid-cols-4` for 10+. Rows
                fill down; each tile stretches equally so the user
                doesn't have to fiddle with dividers to compare row
                lengths — the whole point of compare mode is uniform
                side-by-side. */}
            {activeView === "logs" && (
              <div className="flex-1 flex flex-col p-3 sm:p-8 space-y-3 sm:space-y-6 animate-in overflow-hidden">
                <header className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-2 sm:gap-3 border-b border-zinc-700 pb-3 sm:pb-6 shrink-0">
                  <div className="flex items-center gap-2 min-w-0">
                    <button
                      onClick={() => setActiveView("settings")}
                      className="h-8 w-8 sm:hidden flex items-center justify-center rounded-lg text-zinc-400 hover:text-white hover:bg-white/5 transition-all shrink-0"
                      title="Back to Settings"
                    >
                      <ChevronLeft size={18} />
                    </button>
                    <div className="min-w-0">
                      <h2 className="text-[16px] sm:text-[22px] font-bold text-white tracking-tight">Activity</h2>
                      <p className="hidden sm:block text-[13px] text-zinc-400">What the app has been doing.</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 self-end sm:self-auto">
                    <button
                      onClick={() => setActiveView("settings")}
                      className="hidden sm:flex h-9 px-3 bg-white/[0.04] text-zinc-300 text-[12px] font-bold rounded-xl border border-white/5 hover:bg-white/10 hover:text-white transition-all items-center gap-1.5"
                    >
                      <ChevronLeft size={14} /> Settings
                    </button>
                    <button onClick={async () => {
                      const ok = await confirm({ title: "Clear activity log?", message: "All entries will be discarded.", destructive: true });
                      if (!ok) return;
                      setLogs([]);
                    }} className="h-8 sm:h-9 px-2.5 sm:px-4 bg-zinc-900 text-zinc-200 text-[11px] sm:text-[13px] font-bold rounded-xl border border-white/5 hover:bg-red-500/20 hover:text-red-400 hover:border-primary/50 transition-all flex items-center gap-1.5">
                      <Trash2 size={13} /> Clear
                    </button>
                  </div>
                </header>

                <div className="flex-1 overflow-y-auto custom-scrollbar bg-black/50 rounded-xl sm:rounded-2xl border border-white/5 p-2 sm:p-4 space-y-0.5 sm:space-y-1 shadow-inner select-text cursor-text">
                  {logs.length === 0 ? (
                    <div className="h-full flex items-center justify-center text-zinc-600 text-[12px] sm:text-[14px] font-mono italic">
                      Nothing yet.
                    </div>
                  ) : (
                    [...logs].reverse().map((log) => (
                      <div
                        key={(log as any).id ?? `${log.time}-${log.msg}`}
                        className="flex flex-col sm:flex-row sm:items-start sm:gap-3 text-[10px] sm:text-[12px] font-mono group hover:bg-white/5 p-1 rounded-md transition-colors"
                      >
                        <div className="flex items-baseline gap-2 sm:gap-3 sm:shrink-0">
                          <span className="text-zinc-600 sm:w-20 shrink-0">{log.time}</span>
                          <span className={`sm:w-24 shrink-0 font-bold uppercase ${log.type === 'error' ? 'text-red-500' : log.type === 'success' ? 'text-primary' : log.type === 'warn' ? 'text-amber-500' : 'text-sky-300'}`}>
                            [{log.type}]
                          </span>
                        </div>
                        <span className="text-zinc-300 break-all sm:flex-1">{log.msg}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

          </main>
        </div>
      )}

      {isPanelOpen && (
        <AddNodePanel
          isOpen={isPanelOpen} onClose={closeNodePanel}
          newNode={newNode} setNewNode={setNewNode}
          isEditMode={!!newNode.id}
          onSave={async () => {
            if (!newNode.name || !newNode.host) {
              setFormError("Name and Host are required.");
              addLog("Name and Host are required.", "error");
              return;
            }
            if (newNode.authType === "vault" && !newNode.credentialId) {
              setFormError("Please pick a saved login.");
              addLog("Please pick a saved login.", "error");
              return;
            }
            if (newNode.authType === "custom_key" && !newNode.keyId) {
              setFormError("Please pick an SSH key.");
              addLog("Please pick an SSH key.", "error");
              return;
            }
            // An empty port field is NaN; the backend checks the range too.
            const isPort = (p: number) => Number.isInteger(p) && p >= 1 && p <= 65535;
            if (!isPort(newNode.port)) {
              setFormError("Port must be between 1 and 65535.");
              addLog("Port must be between 1 and 65535.", "error");
              return;
            }
            if (newNode.proxyType !== "none" && !isPort(newNode.proxyPort || 1080)) {
              setFormError("Proxy port must be between 1 and 65535.");
              addLog("Proxy port must be between 1 and 65535.", "error");
              return;
            }
            // A tunnel rule that listens beyond loopback starts at every connect
            // without asking, so it is confirmed here when it is new or changed
            // (F-020, F-068). Cancel is the default.
            const savedRules: { type: string; local: string; remote: string }[] = (() => {
              const saved = newNode.id ? servers.find((s: any) => s.id === newNode.id)?.tunnels : null;
              try { return saved ? JSON.parse(saved) : []; } catch { return []; }
            })();
            const newlyExposed = (newNode.tunnels || []).filter((t: any) =>
              listensBeyondLoopback(t.local || "") &&
              !savedRules.some((r) => r.type === t.type && r.local === t.local && r.remote === t.remote));
            if (newlyExposed.length > 0) {
              const ok = await confirm({
                title: "Save a tunnel that listens beyond loopback?",
                message: newlyExposed.map((t: any) => `${t.local.trim()}: ${exposureWarning(t.type)}`).join("\n"),
                okLabel: "Save anyway",
                destructive: true,
                safeDefault: true,
              });
              if (!ok) return;
            }
            try {
              // Identity fields are only meaningful for inline (custom_*) modes;
              // in vault mode the credential owns username/password/key and we
              // send nulls so the DB row matches reality. The backend's
              // `normalize_server_identity` enforces this again on the server
              // side as a belt-and-suspenders guarantee.
              const isInline = newNode.authType === "custom_pass" || newNode.authType === "custom_key";
              // One command, one transaction (F-045): the row and its notes,
              // commands run on connect, jump host and legacy-algorithm setting
              // are saved together or not at all. Tunnel rules that would not
              // start are refused with the reason (N-017).
              const request = {
                id: newNode.id,
                name: newNode.name,
                host: newNode.host,
                port: newNode.port,
                username: isInline
                  ? (newNode.username?.trim() ? newNode.username.trim() : "root")
                  : null,
                password: newNode.authType === "custom_pass" ? (newNode.password || null) : null,
                // Edit mode + untouched password field = ask the backend to keep
                // the existing column. Otherwise the field's value (including
                // empty / null) overwrites it.
                preservePassword: !!newNode.id && !newNode.password_dirty,
                credentialId: (newNode.authType === "vault" && newNode.credentialId) ? parseInt(newNode.credentialId) : null,
                folderId: newNode.folderId ? parseInt(newNode.folderId) : null,
                proxyType: newNode.proxyType || "none",
                proxyHost: newNode.proxyHost || "",
                proxyPort: newNode.proxyPort || 1080,
                tunnels: newNode.tunnels || [],
                authType: newNode.authType,
                keyId: newNode.authType === "custom_key" && newNode.keyId ? parseInt(newNode.keyId) : null,
                autostart: !!newNode.autostart,
                mirrors: newNode.mirrors || [],
                color: newNode.color ?? null,
                notes: newNode.notes || "",
                runOnConnect: newNode.runOnConnect || "",
                jumpHostId: newNode.jumpHostId ? parseInt(newNode.jumpHostId) : null,
                legacyAlgorithms: !!newNode.legacyAlgorithms,
                terminalOnly: !!newNode.terminalOnly,
              };
              const saved = await invoke<{ id: number; persistError: string | null }>("save_server", { request });
              const savedId = saved.id;
              closeNodePanel();
              refreshServers();
              if (saved.persistError) {
                reportError("Saved for this session, but the profile file could not be written (the next change tries again)", saved.persistError);
              }
              // If we just edited a node whose session is live, re-apply its saved
              // forwarding rules now so a changed/added tunnel comes up without a
              // manual reconnect. The backend cleared the stale tunnel cache when
              // the rules changed, so this re-seeds from the freshly-saved DB rules
              // (idempotent + a no-op when nothing forwarding-related changed).
              if (newNode.id && sessionStatuses[`session-${savedId}`] === "connected") {
                invoke("restart_session_tunnels", { sessionId: `session-${savedId}`, serverId: savedId })
                  .catch((e) => reportError("Saved, but the open session's tunnels did not restart", e));
              }
              addLog(`Node ${newNode.id ? 'updated' : 'added'} successfully.`, "success");
            } catch (e) {
              setFormError(`Failed to save: ${e}`);
              addLog(`SAVE_ERROR: ${e}`, "error");
            }
          }}
          formError={formError}
          credentials={credentials} sshKeys={sshKeys} folders={folders} refreshFolders={refreshFolders}
          refreshServers={refreshServers}
          servers={servers}
          isMobile={isMobile}
        />
      )}

      {/* Rendered only while open, like the editors below (F-022). */}
      {isQuickConnectOpen && (
        <QuickConnectModal
          isOpen
          onClose={() => setIsQuickConnectOpen(false)}
          onConnect={openQuickConnect}
        />
      )}

      {isLocalShellOpen && (
        <LocalShellModal
          isOpen
          onClose={() => setIsLocalShellOpen(false)}
          onOpen={openLocalShell}
        />
      )}

      {isCommandPanelOpen && (
      <div className="fixed inset-0 z-50 flex justify-end bg-black/80 backdrop-blur-sm backdrop-in" onClick={closeCommandPanel}>
        <div className="w-full max-w-[400px] bg-[#09090b] border-l border-white/5 shadow-2xl h-full flex flex-col slide-over-in" onClick={(e) => e.stopPropagation()}>
          <div className="flex justify-between items-center p-6 border-b border-white/5 shrink-0">
            <h2 className="text-[15px] font-bold text-white tracking-tight flex items-center gap-2">
              <TerminalSquare size={18} className="text-primary" />
              {editCommandData.id ? "Edit command" : "New command"}
            </h2>
            <button onClick={closeCommandPanel} className="w-7 h-7 flex items-center justify-center text-zinc-500 hover:text-white bg-black border border-white/5 hover:bg-white/10 rounded-full transition-all">
              <X size={16} />
            </button>
          </div>
          <div className="p-6 flex-1 overflow-y-auto space-y-6">
            {formError && <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-500 text-[12px] font-bold">{formError}</div>}
            <div className="space-y-1.5">
              <label className="text-[12px] font-bold text-zinc-400 ml-1">Title</label>
              <input type="text" className="w-full h-10 bg-black rounded-lg px-3 text-[13px] text-white border border-white/10 outline-none focus:border-primary/50 focus:bg-zinc-900/50 transition-all shadow-inner" placeholder="e.g. Update packages" value={editCommandData.title} onChange={e => setEditCommandData({ ...editCommandData, title: e.target.value })} />
            </div>
            <div className="space-y-1.5 flex-1 flex flex-col h-64">
              <label className="text-[12px] font-bold text-zinc-400 ml-1">Command</label>
              <textarea className="w-full flex-1 bg-black rounded-lg p-3 text-[13px] text-zinc-300 font-mono border border-white/10 outline-none focus:border-primary/50 focus:bg-zinc-900/50 transition-all shadow-inner custom-scrollbar resize-none" placeholder="sudo apt update && sudo apt upgrade -y" value={editCommandData.content} onChange={e => setEditCommandData({ ...editCommandData, content: e.target.value })} />
            </div>
          </div>
          <div className="p-6 border-t border-white/5 shrink-0">
            <button 
              onClick={async () => {
                if (!editCommandData.title || !editCommandData.content) {
                  setFormError("Title and Content are required.");
                  return;
                }
                try {
                  const action = editCommandData.id 
                    ? invoke("edit_command", { id: editCommandData.id, title: editCommandData.title, content: editCommandData.content })
                    : invoke("add_command", { title: editCommandData.title, content: editCommandData.content });
                  await action;
                  closeCommandPanel();
                  refreshCommands();
                  addLog("Command saved.", "success");
                } catch (e) {
                  setFormError(`Failed to save command: ${e}`);
                  addLog(`COMMAND_SAVE_ERROR: ${e}`, "error");
                }
              }} 
              className="w-full h-10 bg-primary text-black font-bold rounded-lg text-[13px] tracking-tight hover:brightness-110 transition-all active:scale-[0.98] shadow-[0_0_15px_rgba(var(--primary),0.2)] flex items-center justify-center gap-2"
            >
              Save
            </button>
          </div>
        </div>
      </div>
      )}

      {isNotePanelOpen && (
      <div className="fixed inset-0 z-50 flex justify-end bg-black/80 backdrop-blur-sm backdrop-in" onClick={closeNotePanel}>
        <div className="w-full max-w-[480px] bg-[#09090b] border-l border-white/5 shadow-2xl h-full flex flex-col slide-over-in" onClick={(e) => e.stopPropagation()}>
          <div className="flex justify-between items-center p-6 border-b border-white/5 shrink-0">
            <h2 className="text-[15px] font-bold text-white tracking-tight flex items-center gap-2">
              <StickyNote size={18} className="text-primary" />
              {editNoteData.id ? "Edit note" : "New note"}
            </h2>
            <button onClick={closeNotePanel} className="w-7 h-7 flex items-center justify-center text-zinc-500 hover:text-white bg-black border border-white/5 hover:bg-white/10 rounded-full transition-all">
              <X size={16} />
            </button>
          </div>
          <div className="p-6 flex-1 overflow-y-auto space-y-6 flex flex-col">
            {formError && <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-500 text-[12px] font-bold">{formError}</div>}
            <div className="space-y-1.5">
              <label className="text-[12px] font-bold text-zinc-400 ml-1">Title</label>
              <input type="text" className="w-full h-10 bg-black rounded-lg px-3 text-[13px] text-white border border-white/10 outline-none focus:border-primary/50 focus:bg-zinc-900/50 transition-all shadow-inner" placeholder="e.g. Production credentials reminder" value={editNoteData.title} onChange={e => setEditNoteData({ ...editNoteData, title: e.target.value })} />
            </div>
            <div className="space-y-1.5 flex-1 flex flex-col min-h-[240px]">
              <label className="text-[12px] font-bold text-zinc-400 ml-1">Content</label>
              <textarea className="w-full flex-1 bg-black rounded-lg p-3 text-[13px] text-zinc-300 border border-white/10 outline-none focus:border-primary/50 focus:bg-zinc-900/50 transition-all shadow-inner custom-scrollbar resize-none leading-relaxed" placeholder="Write anything — markdown, paths, secrets you'd otherwise forget…" value={editNoteData.body} onChange={e => setEditNoteData({ ...editNoteData, body: e.target.value })} />
            </div>
          </div>
          <div className="p-6 border-t border-white/5 shrink-0">
            <button
              onClick={async () => {
                if (!editNoteData.title.trim() && !editNoteData.body.trim()) {
                  setFormError("Add a title or some content first.");
                  return;
                }
                try {
                  const action = editNoteData.id
                    ? invoke("edit_note", { id: editNoteData.id, title: editNoteData.title, body: editNoteData.body })
                    : invoke("add_note", { title: editNoteData.title, body: editNoteData.body });
                  await action;
                  closeNotePanel();
                  refreshNotes();
                  addLog("Note saved.", "success");
                } catch (e) {
                  setFormError(`Failed to save note: ${e}`);
                  addLog(`NOTE_SAVE_ERROR: ${e}`, "error");
                }
              }}
              className="w-full h-10 bg-primary text-black font-bold rounded-lg text-[13px] tracking-tight hover:brightness-110 transition-all active:scale-[0.98] shadow-[0_0_15px_rgba(var(--primary),0.2)] flex items-center justify-center gap-2"
            >
              Save
            </button>
          </div>
        </div>
      </div>
      )}

      {isSnippetPanelOpen && (
      <div className="fixed inset-0 z-50 flex justify-end bg-black/80 backdrop-blur-sm backdrop-in" onClick={closeSnippetPanel}>
        <div className="w-full max-w-[400px] bg-[#09090b] border-l border-white/5 shadow-2xl h-full flex flex-col slide-over-in" onClick={(e) => e.stopPropagation()}>
          <div className="flex justify-between items-center p-6 border-b border-white/5 shrink-0">
            <h2 className="text-[15px] font-bold text-white tracking-tight flex items-center gap-2">
              <Zap size={18} className="text-primary" />
              {editSnippetData.id ? "Edit snippet" : "New snippet"}
            </h2>
            <button onClick={closeSnippetPanel} className="w-7 h-7 flex items-center justify-center text-zinc-500 hover:text-white bg-black border border-white/5 hover:bg-white/10 rounded-full transition-all">
              <X size={16} />
            </button>
          </div>
          <div className="p-6 flex-1 overflow-y-auto space-y-6">
            {formError && <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-500 text-[12px] font-bold">{formError}</div>}
            <div className="space-y-1.5">
              <label className="text-[12px] font-bold text-zinc-400 ml-1">Trigger</label>
              <input type="text" className="w-full h-10 bg-black rounded-lg px-3 text-[13px] text-white font-mono border border-white/10 outline-none focus:border-primary/50 focus:bg-zinc-900/50 transition-all shadow-inner" placeholder="e.g. ;gs" value={editSnippetData.trigger} onChange={e => setEditSnippetData({ ...editSnippetData, trigger: e.target.value })} />
              <p className="text-[10.5px] text-zinc-600 ml-1">No spaces — typed alone, then Space/Tab/Enter, it expands below.</p>
            </div>
            <div className="space-y-1.5 flex-1 flex flex-col h-64">
              <label className="text-[12px] font-bold text-zinc-400 ml-1">Expansion</label>
              <textarea className="w-full flex-1 bg-black rounded-lg p-3 text-[13px] text-zinc-300 font-mono border border-white/10 outline-none focus:border-primary/50 focus:bg-zinc-900/50 transition-all shadow-inner custom-scrollbar resize-none" placeholder="git status" value={editSnippetData.expansion} onChange={e => setEditSnippetData({ ...editSnippetData, expansion: e.target.value })} />
            </div>
          </div>
          <div className="p-6 border-t border-white/5 shrink-0">
            <button
              onClick={async () => {
                const trigger = editSnippetData.trigger.trim();
                if (!trigger || !editSnippetData.expansion) {
                  setFormError("Trigger and Expansion are required.");
                  return;
                }
                if (/\s/.test(trigger)) {
                  setFormError("Trigger can't contain spaces — it's matched as a single word.");
                  return;
                }
                try {
                  const action = editSnippetData.id
                    ? invoke("edit_snippet", { id: editSnippetData.id, trigger, expansion: editSnippetData.expansion })
                    : invoke("add_snippet", { trigger, expansion: editSnippetData.expansion });
                  await action;
                  closeSnippetPanel();
                  setFormError("");
                  refreshSnippets();
                  window.dispatchEvent(new CustomEvent('solanum-snippets-changed'));
                  addLog("Snippet saved.", "success");
                } catch (e) {
                  setFormError(`Failed to save snippet: ${e}`);
                  addLog(`SNIPPET_SAVE_ERROR: ${e}`, "error");
                }
              }}
              className="w-full h-10 bg-primary text-black font-bold rounded-lg text-[13px] tracking-tight hover:brightness-110 transition-all active:scale-[0.98] shadow-[0_0_15px_rgba(var(--primary),0.2)] flex items-center justify-center gap-2"
            >
              Save
            </button>
          </div>
        </div>
      </div>
      )}

      {isCredPanelOpen && (
      <div className="fixed inset-0 z-50 flex justify-end bg-black/80 backdrop-blur-sm backdrop-in" onClick={closeCredPanel}>
        <div className="w-full max-w-[400px] bg-[#09090b] border-l border-white/5 shadow-2xl h-full flex flex-col slide-over-in" onClick={(e) => e.stopPropagation()}>
          <div className="flex justify-between items-center p-6 border-b border-white/5 shrink-0">
            <h2 className="text-[15px] font-bold text-white tracking-tight flex items-center gap-2">
              <Shield size={18} className="text-primary" />
              {editCredData.id ? "Edit login" : "New login"}
            </h2>
            <button onClick={closeCredPanel} className="w-7 h-7 flex items-center justify-center text-zinc-500 hover:text-white bg-black border border-white/5 hover:bg-white/10 rounded-full transition-all">
              <X size={16} />
            </button>
          </div>
          <div className="p-6 flex-1 overflow-y-auto space-y-6">
            {formError && <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-500 text-[12px] font-bold">{formError}</div>}
            <div className="space-y-1.5">
              <label className="text-[12px] font-bold text-zinc-400 ml-1">Name</label>
              <input type="text" className="w-full h-10 bg-black rounded-lg px-3 text-[13px] text-white border border-white/10 outline-none focus:border-primary/50 focus:bg-zinc-900/50 transition-all shadow-inner" placeholder="e.g. Work server" value={editCredData.name} onChange={e => setEditCredData({ ...editCredData, name: e.target.value })} />
            </div>
            <div className="space-y-1.5">
              <label className="text-[12px] font-bold text-zinc-400 ml-1">Username</label>
              <input type="text" className="w-full h-10 bg-black rounded-lg px-3 text-[13px] text-white border border-white/10 outline-none focus:border-primary/50 focus:bg-zinc-900/50 transition-all shadow-inner" placeholder="root" value={editCredData.username} onChange={e => setEditCredData({ ...editCredData, username: e.target.value })} />
            </div>
            <div className="space-y-4 pt-2">
              <div className="flex justify-between items-center">
                <label className="text-[12px] font-bold text-zinc-400 ml-1">Sign in with</label>
                <select
                  className="bg-transparent text-[12px] font-bold text-primary outline-none cursor-pointer"
                  value={editCredData.auth_type || "password"}
                  onChange={e => setEditCredData({ ...editCredData, auth_type: e.target.value })}
                >
                  <option value="password" className="bg-[#121215] text-primary">Password</option>
                  <option value="key" className="bg-[#121215] text-primary">SSH key</option>
                </select>
              </div>
            </div>
            {editCredData.auth_type === "key" ? (
              <div className="space-y-1.5 animate-in fade-in">
                <label className="text-[12px] font-bold text-zinc-400 ml-1">Pick a key</label>
                <select
                  className="w-full h-10 bg-black rounded-lg px-3 text-[13px] text-zinc-300 border border-white/10 outline-none focus:border-primary/50 transition-all shadow-inner"
                  value={editCredData.key_id?.toString() || ""}
                  onChange={e => setEditCredData({ ...editCredData, key_id: e.target.value ? parseInt(e.target.value) : null })}
                >
                  <option value="" className="bg-black text-zinc-500">-- Pick a key --</option>
                  {sshKeys?.map((k: any) => (
                    <option key={k.id} value={k.id.toString()} className="bg-black text-white">{k.name}</option>
                  ))}
                </select>
              </div>
            ) : (
              <div className="space-y-1.5 animate-in fade-in">
                <label className="text-[12px] font-bold text-zinc-400 ml-1">Password</label>
                <PasswordField
                  value={editCredData.password || ""}
                  onChange={(v) => setEditCredData({ ...editCredData, password: v })}
                  className="w-full h-10 bg-black rounded-lg px-3 text-[13px] text-white border border-white/10 outline-none focus:border-primary/50 focus:bg-zinc-900/50 transition-all shadow-inner"
                />
              </div>
            )}
          </div>
          <div className="p-6 border-t border-white/5 shrink-0">
            <button 
              onClick={async () => {
                if (!editCredData.name) {
                  setFormError("Name is required.");
                  addLog("Name is required.", "error");
                  return;
                }
                if (editCredData.auth_type === "key" && !editCredData.key_id) {
                  setFormError("Please select a linked SSH Private Key.");
                  addLog("Please select a linked SSH Private Key.", "error");
                  return;
                }
                try {
                  const payload = {
                    name: editCredData.name,
                    authType: editCredData.auth_type || "password",
                    username: editCredData.username?.trim() ? editCredData.username.trim() : "root",
                    password: editCredData.auth_type === "key" ? null : (editCredData.password || null),
                    keyId: editCredData.auth_type === "key" ? (editCredData.key_id ? parseInt(editCredData.key_id.toString()) : null) : null
                  };
                  const action = editCredData.id 
                    ? invoke("edit_credential", { id: editCredData.id, ...payload })
                    : invoke("add_credential", payload);
                  await action;
                  closeCredPanel();
                  refreshCredentials();
                  addLog("Credential saved.", "success");
                } catch (e) {
                  setFormError(`Failed to save credential: ${e}`);
                  addLog(`CRED_SAVE_ERROR: ${e}`, "error");
                }
              }} 
              className="w-full h-10 bg-primary text-black font-bold rounded-lg text-[13px] tracking-tight hover:brightness-110 transition-all active:scale-[0.98] flex items-center justify-center gap-2"
            >
              Save
            </button>
          </div>
        </div>
      </div>
      )}

      {isKeyPanelOpen && (
      <div className="fixed inset-0 z-50 flex justify-end bg-black/80 backdrop-blur-sm backdrop-in" onClick={closeKeyPanel}>
        <div className="w-full max-w-[450px] bg-[#09090b] border-l border-white/5 shadow-2xl h-full flex flex-col slide-over-in" onClick={(e) => e.stopPropagation()}>
          <div className="flex justify-between items-center p-6 border-b border-white/5 shrink-0">
            <h2 className="text-[15px] font-bold text-white tracking-tight flex items-center gap-2">
              <Key size={18} className="text-primary" />
              {editKeyData.id ? "Edit SSH key" : "New SSH key"}
            </h2>
            <button onClick={closeKeyPanel} className="w-7 h-7 flex items-center justify-center text-zinc-500 hover:text-white bg-black border border-white/5 hover:bg-white/10 rounded-full transition-all">
              <X size={16} />
            </button>
          </div>
          <div className="p-6 flex-1 overflow-y-auto space-y-6">
            {formError && <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-red-500 text-[12px] font-bold">{formError}</div>}
            <div className="space-y-1.5">
              <label className="text-[12px] font-bold text-zinc-400 ml-1">Name</label>
              <input type="text" className="w-full h-10 bg-black rounded-lg px-3 text-[13px] text-white border border-white/10 outline-none focus:border-primary/50 focus:bg-zinc-900/50 transition-all shadow-inner" placeholder="e.g. My laptop key" value={editKeyData.name} onChange={e => setEditKeyData({ ...editKeyData, name: e.target.value })} />
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center justify-between ml-1">
                <label className="text-[12px] font-bold text-zinc-400">Public key</label>
                <button
                  type="button"
                  onClick={() => browseKeyFile("public")}
                  title="Browse for a public key file"
                  className="flex items-center gap-1 text-[11px] font-bold text-primary hover:text-primary/80 transition-colors"
                >
                  <FolderOpen size={12} /> Browse…
                </button>
              </div>
              <textarea className="w-full h-24 bg-black rounded-lg p-3 text-[13px] text-zinc-400 font-mono border border-white/10 outline-none focus:border-primary/50 focus:bg-zinc-900/50 transition-all shadow-inner custom-scrollbar resize-none" placeholder="ssh-ed25519 ..." value={editKeyData.public_key} onChange={e => setEditKeyData({ ...editKeyData, public_key: e.target.value })} />
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center justify-between ml-1">
                <label className="text-[12px] font-bold text-zinc-400">Private key</label>
                <button
                  type="button"
                  onClick={() => browseKeyFile("private")}
                  title="Browse for a private key file (OpenSSH or PuTTY .ppk)"
                  className="flex items-center gap-1 text-[11px] font-bold text-primary hover:text-primary/80 transition-colors"
                >
                  <FolderOpen size={12} /> Browse…
                </button>
              </div>
              <textarea className="w-full h-32 bg-black rounded-lg p-3 text-[13px] text-zinc-400 font-mono border border-white/10 outline-none focus:border-primary/50 focus:bg-zinc-900/50 transition-all shadow-inner custom-scrollbar resize-none" placeholder="-----BEGIN OPENSSH PRIVATE KEY----- (or a PuTTY .ppk file)" value={editKeyData.private_key} onChange={e => setEditKeyData({ ...editKeyData, private_key: e.target.value })} />
            </div>
            <div className="space-y-1.5">
              <label className="text-[12px] font-bold text-zinc-400 ml-1">Passphrase (if any)</label>
              <PasswordField
                value={editKeyData.passphrase || ""}
                onChange={(v) => setEditKeyData({ ...editKeyData, passphrase: v })}
                className="w-full h-10 bg-black rounded-lg px-3 text-[13px] text-white border border-white/10 outline-none focus:border-primary/50 focus:bg-zinc-900/50 transition-all shadow-inner"
              />
            </div>
          </div>
          <div className="p-6 border-t border-white/5 shrink-0">
            <button 
              onClick={async () => {
                if (!editKeyData.name || !editKeyData.private_key) {
                  setFormError("Name and Private Key are required.");
                  return;
                }
                try {
                  const payload = {
                    name: editKeyData.name,
                    publicKey: editKeyData.public_key,
                    privateKey: editKeyData.private_key,
                    passphrase: editKeyData.passphrase || null
                  };
                  const action = editKeyData.id 
                    ? invoke("edit_ssh_key", { id: editKeyData.id, ...payload })
                    : invoke("add_ssh_key", payload);
                  await action;
                  closeKeyPanel();
                  refreshSshKeys();
                  addLog("SSH Key saved.", "success");
                } catch (e) {
                  setFormError(`Failed to save SSH Key: ${e}`);
                  addLog(`KEY_SAVE_ERROR: ${e}`, "error");
                }
              }} 
              className="w-full h-10 bg-primary text-black font-bold rounded-lg text-[13px] tracking-tight hover:brightness-110 transition-all active:scale-[0.98] flex items-center justify-center gap-2"
            >
              Save
            </button>
          </div>
        </div>
      </div>
      )}

      {errorToast && (
        <div key={errorToast.id} role="alert"
             className="fixed bottom-4 right-4 z-[100] max-w-[440px] flex items-start gap-2 px-3 py-2.5 rounded-xl border border-rose-500/40 bg-[#1a0f12]/95 shadow-2xl backdrop-blur-md text-[12px] text-rose-200 animate-in">
          <span className="flex-1 break-words select-text">{visibleName(errorToast.text)}</span>
          <button onClick={() => setErrorToast(null)} title="Dismiss" aria-label="Dismiss"
                  className="shrink-0 text-rose-300/70 hover:text-white">
            <X size={13} />
          </button>
        </div>
      )}
    </div>
  );
}

export default DesktopApp;