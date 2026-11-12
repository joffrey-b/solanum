import { useState, useEffect, useRef, memo } from "react";
import { createPortal } from "react-dom";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow, LogicalSize } from "@tauri-apps/api/window";
import { TerminalSquare, Folder, Network, AlertTriangle, Check, X, ShieldAlert, KeyRound, Play, Library, Info, Container, Box, Plus, SplitSquareHorizontal, Columns, Rows, RotateCw } from "lucide-react";
import TerminalView from "./TerminalView";
import SftpWorkspace from "./SftpWorkspace";
import TunnelsPanel from "./TunnelsPanel";
import InfoPanel from "./InfoPanel";
import DockerTab from "./DockerTab";
import { CmdsPanel } from "./CmdsPanel";
import { useIsCompact } from "../hooks/useViewport";
import { useConfirm } from "../ui/confirm";
import { terminalCloseNeedsConfirm, sessionCloseNeedsConfirm } from "../util/sessionClose";
import { resolveTerminalTheme } from "../util/terminalThemes";
import { visibleName, visibleText, withoutHidden } from "../util/visibleName";
// A keyboard-interactive label that asks for a secret: its answer is masked
// even when the server asked for echo (F-079); masking an answer that did not
// need it costs nothing.
import { SECRET_PROMPT } from "../util/secretPrompt";
import { needsAnotherChannel, terminalOnlyNotice, terminalOnlyReason, unavailableHint, type TerminalOnlyReason } from "../util/terminalOnly";

// Compact "run this tab on its own dedicated SSH connection" toggle, shown in
// the SFTP and Port-Forwarding tab headers. The status dot reflects the live
// state of the dedicated connection: green = up, amber (pulsing) = opening /
// applies-on-connect, red = couldn't be established (falling back to the main
// session). No dot when the toggle is off.
const SepToggle = ({ on, onToggle, status, title, onReconnect }: {
  on: boolean;
  onToggle: (v: boolean) => void;
  status: 'ready' | 'pending' | 'failed' | 'off';
  title: string;
  onReconnect?: () => void;
}) => (
  <span className="flex items-center gap-1.5">
    <label className="flex items-center gap-1.5 text-[10px] text-zinc-400 hover:text-zinc-200 cursor-pointer select-none" title={title}>
      <input type="checkbox" className="w-3 h-3 accent-primary" checked={on} onChange={(e) => onToggle(e.target.checked)} />
      <span className="uppercase tracking-wider font-bold">Dedicated session</span>
      {on && (
        <span
          className={`w-1.5 h-1.5 rounded-full shrink-0 ${
            status === 'ready' ? 'bg-emerald-400' : status === 'failed' ? 'bg-red-400' : 'bg-amber-400 animate-pulse'
          }`}
        />
      )}
    </label>
    {/* Reconnect just the dedicated connection — outside the <label> so a
        click can't toggle the checkbox. Shown whenever the toggle is on and
        no connect attempt is already in flight; also the retry affordance
        after a red (failed) dot. */}
    {on && onReconnect && status !== 'pending' && (
      <button
        onClick={onReconnect}
        title="Reconnect the dedicated session"
        className="p-0.5 rounded text-zinc-500 hover:text-white hover:bg-white/10 transition-colors"
      >
        <RotateCw size={10} />
      </button>
    )}
  </span>
);

const SessionViewImpl = ({ session, onClose, addLog, onStatusChange, chromeless = false, onTerminalsChange, warnOnCloseActiveSession = true, onServersChanged }: any) => {
  const [status, setStatus] = useState<'connecting' | 'connected' | 'failed' | 'disconnected'>('connecting');
  const confirmDialog = useConfirm();

  // Background for the split-pane row behind the terminal tiles (visible in
  // the gaps/dividers between panes). Same theme every TerminalView already
  // resolves for itself — read here too so this shared backdrop doesn't
  // stay stuck on the old hardcoded dark navy while the terminals around it
  // follow the user's chosen theme.
  const loadSplitPaneBg = () => resolveTerminalTheme(
    localStorage.getItem('solanum-terminal-theme'),
    localStorage.getItem('solanum-primary-color') || '#60a5fa',
    localStorage.getItem('solanum-bg-color') || '#0a0a0c',
  ).background;
  const [splitPaneBg, setSplitPaneBg] = useState(loadSplitPaneBg);
  useEffect(() => {
    const onSettingsChanged = () => setSplitPaneBg(loadSplitPaneBg());
    window.addEventListener('solanum-settings-changed', onSettingsChanged);
    return () => window.removeEventListener('solanum-settings-changed', onSettingsChanged);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Bubble every status change up to the parent so the session-tab strip
  // can draw a coloured dot (green / amber / red) next to the name without
  // having to mount its own listeners or duplicate the connection-event
  // wiring we already do here.
  useEffect(() => {
    if (typeof onStatusChange === "function") {
      onStatusChange(session?.id, status);
    }
  }, [status, session?.id, onStatusChange]);
  const [disconnectReason, setDisconnectReason] = useState<string>("");
  // The server ended the session (exit, an idle logout, a switch closing the
  // link) and Solanum closed it too: nothing reconnects by itself, R or
  // Reconnect logs in again (N-028).
  const [loggedOut, setLoggedOut] = useState(false);
  const [logs, setLogs] = useState<{ msg: string, type: string, time?: string }[]>([]);
  // Cap to keep a chatty session (monitors, mirrors, MOTD spam) from
  // ballooning React state — each render copies the whole array, so an
  // unbounded log makes the UI quadratically slower over time.
  const LOG_CAP = 500;
  const pushLog = (entry: { msg: string, type: string }) => {
    const stamped = { ...entry, time: new Date().toLocaleTimeString() };
    setLogs(prev => prev.length >= LOG_CAP
      ? [...prev.slice(prev.length - LOG_CAP + 1), stamped]
      : [...prev, stamped]);
  };
  const [fingerprintPrompt, setFingerprintPrompt] = useState<any>(null);
  // Keyboard-interactive (2FA / verification-code) prompt. `kbiPrompt` holds
  // the backend payload ({ nonce, host, name, instructions, prompts:[{prompt,echo}] });
  // `kbiValues` mirrors one editable answer per prompt.
  const [kbiPrompt, setKbiPrompt] = useState<any>(null);
  // The prompt on screen, for the dismiss listener (registered once).
  const kbiPromptRef = useRef<any>(null);
  useEffect(() => { kbiPromptRef.current = kbiPrompt; }, [kbiPrompt]);
  const [kbiValues, setKbiValues] = useState<string[]>([]);
  const [isAuthError, setIsAuthError] = useState(false);
  const [customPassword, setCustomPassword] = useState("");
  // The connect-time log box mirrors the terminal font-size setting, so the
  // user's chosen size applies to the startup logs too — not just the shell.
  // `solanum-settings-changed` (dispatched by Settings on save) keeps it live.
  const readLogFontSize = () =>
    Math.max(1, parseInt(localStorage.getItem('solanum-terminal-font-size') || '14') || 14);
  const [logFontSize, setLogFontSize] = useState(readLogFontSize);
  useEffect(() => {
    const sync = () => setLogFontSize(readLogFontSize());
    window.addEventListener('solanum-settings-changed', sync);
    return () => window.removeEventListener('solanum-settings-changed', sync);
  }, []);
  // The connection effect runs once and captures `customPassword=""` in its
  // closure. Auto-reconnect attempts and the disconnect listener that
  // schedules them must read the LATEST password the user typed into the
  // auth-error retry input — so we mirror it into a ref.
  const customPasswordRef = useRef("");
  useEffect(() => { customPasswordRef.current = customPassword; }, [customPassword]);

  // Mirror `status` into a ref so the one-shot effect below (which registers
  // the `connection-success` listener from its INITIAL closure) can see the
  // latest value. Without this ref, `wasReconnect` was computed against a
  // status snapshot captured at effect-run time (always `'connecting'`), so
  // a manual reconnect via the banner — which zeroes reconnectAttemptRef —
  // failed to bump `connectionEpoch`. TerminalView's per-epoch effect then
  // never re-called open_terminal against the new SSH handle, and the
  // reconnected terminal appeared frozen while SFTP/tunnels worked fine.
  const statusRef = useRef(status);
  useEffect(() => { statusRef.current = status; }, [status]);

  // Why this connection is a plain terminal, if it is: the server's setting,
  // its identification string, or a refused channel. From the backend, which
  // refuses the features itself; this hides them and says so.
  const [terminalOnly, setTerminalOnly] = useState<TerminalOnlyReason | null>(null);
  const terminalOnlyRef = useRef<TerminalOnlyReason | null>(null);
  // Closed by the user: stays closed for this tab, also across reconnects.
  const [terminalOnlyDismissed, setTerminalOnlyDismissed] = useState(false);
  const [terminalOnlySaveError, setTerminalOnlySaveError] = useState("");
  // Called from the listeners registered once below: the ref and setter only.
  const applyTerminalOnly = (value: unknown) => {
    const reason = terminalOnlyReason(value);
    if (reason && reason !== terminalOnlyRef.current && terminalOnlyNotice(reason, session.serverId).show) {
      addLog(`SSH_TERMINAL_ONLY [${session.serverName}]: SFTP, live info and Docker are unavailable on this host.`, "error");
    }
    terminalOnlyRef.current = reason;
    setTerminalOnly(reason);
  };
  const saveTerminalOnly = async () => {
    setTerminalOnlySaveError("");
    try {
      await invoke("set_server_terminal_only", { id: session.serverId, terminalOnly: true });
      setTerminalOnlyDismissed(true);
      addLog(`Node ${session.serverName} is now set to terminal only.`, "success");
      onServersChanged?.();
    } catch (e) {
      setTerminalOnlySaveError(String(e));
    }
  };

  // ---- Dedicated SSH connections for SFTP / port-forwarding -----------------
  // Two INDEPENDENT, per-tab toggles (the controls live in the SFTP and
  // Port-Forwarding tab headers, persisted globally in localStorage under
  // `solanum-separate-sftp` / `solanum-separate-fwd`, default OFF). When a
  // toggle is on we open a dedicated secondary SSH connection — keyed
  // `${session.id}::sftp` / `${session.id}::fwd` — as a pure TRANSPORT: the
  // backend routes SFTP subsystems and tunnels over it when it exists, while
  // everything stays keyed/tagged under the plain session id. The panels never
  // re-key, tunnels migrate live in both directions, and if a dedicated
  // connection can't be established (2FA server, network blip) everything just
  // rides the primary. Unexpected drops auto-retry with backoff, and each tab
  // header has a manual reconnect button for the dedicated connection.
  type SecondaryStatus = 'off' | 'connecting' | 'ready' | 'failed';
  const [separateSftp, setSeparateSftp] = useState(localStorage.getItem('solanum-separate-sftp') === 'true');
  const [separateFwd, setSeparateFwd] = useState(localStorage.getItem('solanum-separate-fwd') === 'true');
  const separateSftpRef = useRef(separateSftp);
  const separateFwdRef = useRef(separateFwd);
  useEffect(() => { separateSftpRef.current = separateSftp; }, [separateSftp]);
  useEffect(() => { separateFwdRef.current = separateFwd; }, [separateFwd]);

  // Live status of the dedicated connections — drives the tab-header dots and
  // the retry logic only; nothing routes on it (the backend picks transports).
  const [sftpConnStatus, setSftpConnStatus] = useState<SecondaryStatus>('off');
  const [fwdConnStatus, setFwdConnStatus] = useState<SecondaryStatus>('off');
  const sftpConnStatusRef = useRef<SecondaryStatus>('off');
  const fwdConnStatusRef = useRef<SecondaryStatus>('off');
  useEffect(() => { sftpConnStatusRef.current = sftpConnStatus; }, [sftpConnStatus]);
  useEffect(() => { fwdConnStatusRef.current = fwdConnStatus; }, [fwdConnStatus]);

  // Bounded auto-retry for unexpected secondary drops: 2s → 5s → 10s, then
  // give up (red dot; manual reconnect button still works). Counters reset on
  // success and on any manual action.
  const SECONDARY_RETRY_DELAYS = [2000, 5000, 10000];
  const sftpRetryRef = useRef(0);
  const fwdRetryRef = useRef(0);
  const sftpRetryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const fwdRetryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const clearSecondaryRetryTimers = () => {
    if (sftpRetryTimerRef.current) { clearTimeout(sftpRetryTimerRef.current); sftpRetryTimerRef.current = null; }
    if (fwdRetryTimerRef.current) { clearTimeout(fwdRetryTimerRef.current); fwdRetryTimerRef.current = null; }
  };

  const openSftpConn = () => {
    setSftpConnStatus('connecting');
    invoke("initiate_connection", {
      sessionId: `${session.id}::sftp`,
      serverId: session.serverId,
      customPassword: customPasswordRef.current || null,
      quickAuth: session.quickAuth || null,
      sessionRole: "sftp",
      separateSessions: false,
    }).catch((e) => {
      // Refused before it started (no connected-failed event follows): the
      // file browser keeps using the primary connection.
      pushLog({ msg: `Dedicated SFTP connection not started: ${e}`, type: 'error' });
      setSftpConnStatus('failed');
    });
  };
  const openFwdConn = () => {
    setFwdConnStatus('connecting');
    invoke("initiate_connection", {
      sessionId: `${session.id}::fwd`,
      serverId: session.serverId,
      customPassword: customPasswordRef.current || null,
      quickAuth: session.quickAuth || null,
      sessionRole: "forward",
      separateSessions: false,
    }).catch((e) => {
      pushLog({ msg: `Dedicated forwarding connection not started: ${e}`, type: 'error' });
      setFwdConnStatus('failed');
      restoreTunnelsOnPrimary();
    });
  };

  // Restore forwarding on the best available transport (primary, unless a
  // dedicated connection is up). Called when the dedicated path is abandoned —
  // toggle-off, or retries exhausted — so tunnels always land somewhere.
  const restoreTunnelsOnPrimary = () => {
    invoke("restart_session_tunnels", { sessionId: session.id, serverId: session.serverId })
      .catch((e) => pushLog({ msg: `Tunnels not restored: ${e}`, type: 'error' }));
  };

  // Whether the in-flight PRIMARY connect deferred its saved tunnels for a
  // `::fwd` connection (i.e. separateFwd was on when we sent it). If the user
  // toggles fwd OFF during the primary handshake, the primary won't have
  // started the tunnels AND openSecondaryConnections won't open `::fwd`, so
  // they'd start nowhere — the success handler reconciles using this.
  const primarySeparateRef = useRef(false);

  // Schedule an auto-retry for a dropped secondary. Fires only if the toggle
  // is still on and the primary is still connected at fire time.
  const scheduleSecondaryRetry = (which: 'sftp' | 'fwd') => {
    const retryRef = which === 'sftp' ? sftpRetryRef : fwdRetryRef;
    const timerRef = which === 'sftp' ? sftpRetryTimerRef : fwdRetryTimerRef;
    const enabledRef = which === 'sftp' ? separateSftpRef : separateFwdRef;
    const setStatus = which === 'sftp' ? setSftpConnStatus : setFwdConnStatus;
    if (retryRef.current >= SECONDARY_RETRY_DELAYS.length) {
      // Out of retries — mark failed; operations ride the primary. For
      // forwarding, explicitly restore the tunnels there.
      setStatus('failed');
      if (which === 'fwd') restoreTunnelsOnPrimary();
      return;
    }
    const delay = SECONDARY_RETRY_DELAYS[retryRef.current];
    retryRef.current += 1;
    setStatus('connecting');
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => {
      timerRef.current = null;
      if (!enabledRef.current || statusRef.current !== 'connected') return;
      if (which === 'sftp') openSftpConn(); else openFwdConn();
    }, delay);
  };

  // Open whichever dedicated connections are enabled — called from the primary
  // `connection-success` handler (first-connect AND reconnect; the backend
  // sweeps stale secondaries at the top of the primary's connect, so this is
  // clean). On `::fwd` success the backend migrates the session's tunnels onto
  // the fresh transport.
  const openSecondaryConnections = () => {
    // A terminal-only host has no SFTP for a dedicated connection to carry.
    if (separateSftpRef.current && !terminalOnlyRef.current) openSftpConn();
    if (separateFwdRef.current) openFwdConn();
  };

  // Reset secondary tracking when the primary drops / reconnects. The backend
  // has already torn the secondaries down (primary connect-teardown, or the
  // primary disconnect sweep); this just resets the indicators + retry state.
  const resetSecondaryStatus = () => {
    clearSecondaryRetryTimers();
    sftpRetryRef.current = 0;
    fwdRetryRef.current = 0;
    setSftpConnStatus('off');
    setFwdConnStatus('off');
  };

  // Manual reconnect buttons in the tab headers. initiate_connection sweeps
  // its own key's stale state, so a plain re-open is a full clean reconnect
  // of just the dedicated connection — never the whole server session.
  const reconnectSftpConn = () => {
    if (statusRef.current !== 'connected') return;
    sftpRetryRef.current = 0;
    openSftpConn();
  };
  const reconnectFwdConn = () => {
    if (statusRef.current !== 'connected') return;
    fwdRetryRef.current = 0;
    openFwdConn();
  };

  // Tab-header toggles. Persist immediately; apply live if the session is
  // already connected, otherwise they take effect on the next connect.
  const toggleSeparateSftp = (on: boolean) => {
    setSeparateSftp(on);
    // Sync ref update: the disconnect below emits session-disconnected-…::sftp,
    // and its listener consults this ref — the useEffect mirror only lands
    // after the next render, which can be AFTER the event. Without this, a
    // toggle-off could read a stale "on" and auto-retry the connection the
    // user just closed.
    separateSftpRef.current = on;
    localStorage.setItem('solanum-separate-sftp', String(on));
    sftpRetryRef.current = 0;
    if (statusRef.current !== 'connected') return;
    if (on) {
      if (sftpConnStatusRef.current !== 'ready' && sftpConnStatusRef.current !== 'connecting') openSftpConn();
    } else {
      setSftpConnStatus('off');
      // Backend drops the base SFTP cache with the transport, so the next
      // file operation transparently re-opens on the primary.
      invoke("disconnect_session", { sessionId: `${session.id}::sftp` }).catch(console.error);
    }
  };
  const toggleSeparateFwd = (on: boolean) => {
    setSeparateFwd(on);
    // Sync ref update — same stale-ref race as toggleSeparateSftp.
    separateFwdRef.current = on;
    localStorage.setItem('solanum-separate-fwd', String(on));
    fwdRetryRef.current = 0;
    if (statusRef.current !== 'connected') return;
    if (on) {
      if (fwdConnStatusRef.current !== 'ready' && fwdConnStatusRef.current !== 'connecting') openFwdConn();
    } else {
      setFwdConnStatus('off');
      // Order matters: the disconnect stops tunnels riding the dedicated
      // transport AND removes it from the connections map; only then does
      // the restart re-resolve the transport — now the primary — and bring
      // the same tunnels back up there.
      invoke("disconnect_session", { sessionId: `${session.id}::fwd` })
        .catch(console.error)
        .finally(() => { restoreTunnelsOnPrimary(); });
    }
  };

  // Terminal IDs MUST be unique across every open session, not just within
  // this one — the backend dispatches `terminal-output-<id>` events globally
  // and any collision means two tabs end up reading from the same PTY.
  // Scoping the id by `session.id` ensures Server A's "term-0" never clashes
  // with Server B's "term-0".
  // A terminal slot is either a regular login shell (the default) or a
  // docker-exec session into a specific container (spawned from the Info
  // panel). Container slots stay otherwise identical — same xterm, same
  // events — they just point the backend at `open_container_terminal`.
  // `ended` mirrors each terminal's own "Session stopped" state (its remote
  // shell exited) — bubbles up through onTerminalsChange to DesktopApp, so
  // the session tab's own close button can tell "this session still has a
  // genuinely live shell, worth confirming before dropping" apart from
  // "everything in it already ended, there's nothing left to confirm about".
  const [terminals, setTerminals] = useState<{id: string, title: string, container?: { name: string; useSudo: boolean }, ended?: boolean}[]>(() => {
    return [{ id: `${session.id}-term-0`, title: '1' }];
  });
  // Bumped on every successful reconnect. TerminalView watches this prop
  // and re-opens its PTY on change WITHOUT disposing its xterm instance,
  // so the user keeps the scroll-back from before the drop. Without this
  // we used to mint a brand-new terminal_id and remount TerminalView,
  // which dropped the entire visual buffer of their previous session.
  const [connectionEpoch, setConnectionEpoch] = useState(0);
  const openContainerTerminal = (containerName: string, useSudo: boolean) => {
    const newId = `${session.id}-term-${Date.now()}`;
    setTerminals(prev => [...prev, {
      id: newId,
      title: containerName.length > 10 ? `${containerName.slice(0, 9)}…` : containerName,
      container: { name: containerName, useSudo },
    }]);
    setActiveTab(newId);
    changeActiveTool(null);
  };

  // Updates one terminal's `ended` flag — wired into TerminalView's
  // onEndedChange, so DesktopApp's own tab-level close button can know
  // whether this session still has a genuinely live shell anywhere in it.
  // Guarded so a no-op update doesn't create a new `terminals` array
  // identity (and cascade a re-render) every time.
  const markTerminalEnded = (id: string, ended: boolean) => {
    setTerminals(prev => {
      const idx = prev.findIndex(x => x.id === id);
      if (idx === -1 || !!prev[idx].ended === ended) return prev;
      const next = [...prev];
      next[idx] = { ...next[idx], ended };
      return next;
    });
  };

  // Closes a single terminal tab within this session. If it's the ONLY
  // terminal left, there's nothing sensible to fall back to inside this
  // session — closes the whole session instead (same as its own tab's ×
  // button in DesktopApp.tsx), rather than leaving an empty session view
  // open. Shared by the tab's own × button below and TerminalView's
  // onExitTab (Return on "Session stopped").
  //
  // Gated the same way the session's own top tab is (see
  // sessionCloseNeedsConfirm / terminalCloseNeedsConfirm in
  // util/sessionClose.ts) — this used to close instantly with no warning
  // regardless of the terminal being live, which was the actual bug behind
  // the "closing a clone tab never warns" report; the top tab already
  // checked before dropping the whole session.
  const closeTerminalTab = async (id: string) => {
    if (terminals.length <= 1) {
      // Closing the last tab drops the whole session — same standard as the
      // session's own top tab, using OUR local `terminals`/`status` rather
      // than reaching back into DesktopApp's copy of either.
      if (sessionCloseNeedsConfirm(terminals, status, warnOnCloseActiveSession)) {
        const ok = await confirmDialog({
          title: "Close this session?",
          message: "The SSH connection will be dropped.",
          okLabel: "Close",
          destructive: true,
        });
        if (!ok) {
          window.dispatchEvent(new CustomEvent(`terminal-refocus-${id}`));
          return;
        }
      }
      onClose();
      return;
    }
    const target = terminals.find(x => x.id === id);
    if (terminalCloseNeedsConfirm(target, warnOnCloseActiveSession)) {
      const ok = await confirmDialog({
        title: "Close this terminal?",
        message: "The shell running in this tab will be closed. Other tabs in this session are not affected.",
        okLabel: "Close",
        destructive: true,
      });
      if (!ok) {
        window.dispatchEvent(new CustomEvent(`terminal-refocus-${id}`));
        return;
      }
    }
    // Computed from the FILTERED array, not the pre-filter `terminals[0]` —
    // closing the currently-active leftmost tab must land on the new
    // leftmost tab, not re-select the id that was just removed.
    const remaining = terminals.filter(x => x.id !== id);
    setTerminals(remaining);
    if (activeTab === id) setActiveTab(remaining[0].id);
    // Closing a terminal that's participating in the split has to drop it
    // from splitTerminals AND splitRatios or the flex layout renders a
    // torn-down partner.
    if (splitTerminals.includes(id)) {
      const idx = splitTerminals.indexOf(id);
      const nextTerms = splitTerminals.filter(tid => tid !== id);
      const nextRatios = splitRatios.filter((_, i) => i !== idx);
      // Falling below 2 members collapses back to the plain absolute-overlap
      // layout.
      if (nextTerms.length < 2) {
        setSplitTerminals([]);
        setSplitRatios([]);
      } else {
        setSplitTerminals(nextTerms);
        setSplitRatios(nextRatios);
      }
    }
  };

  const [activeTab, setActiveTab] = useState<string>(`${session.id}-term-0`);
  // Bubble our terminals + active-tab up to the parent (App) whenever
  // they change so the Wall pinboard and any other App-level consumers
  // don't have to duplicate the per-session terminal book-keeping.
  // Attach-only Wall tiles use these to know which (sessionId, terminalId)
  // pairs exist and which one is currently the session's own primary.
  useEffect(() => {
    if (typeof onTerminalsChange === "function") {
      onTerminalsChange(session.id, terminals, activeTab);
    }
  }, [session?.id, terminals, activeTab, onTerminalsChange]);
  const [activeTool, setActiveTool] = useState<'sftp' | 'tunnels' | 'mirrors' | 'cmds' | 'info' | 'docker' | null>(null);
  // Split-pane state — an ORDERED array of terminal IDs that currently
  // share the main pane. `[]` or a single-id array means "no split, use
  // the usual absolute-overlap layout"; length ≥ 2 means the panes tile
  // side-by-side (or stacked). `activeTab` still tracks which of the split
  // members owns keyboard focus; clicking any pane re-focuses it.
  //
  // We kept this an array instead of a recursive tree — tmux-style
  // arbitrary geometry is neat but 95% of users want "N shells sharing
  // one screen" and a flat layout is trivially resizable, mountable, and
  // reorderable. Add-to-split appends to the end; close-from-split
  // filters that id out.
  const [splitTerminals, setSplitTerminals] = useState<string[]>([]);
  // Horizontal (row) vs vertical (column). The trigger button next to
  // "+" hosts the orientation swap; the same right-click on any divider
  // also flips it.
  const [splitOrientation, setSplitOrientation] = useState<"h" | "v">("h");
  // Per-pane flex ratio, length always equal to `splitTerminals.length`.
  // Sum is arbitrary (we hand it directly to flex-grow so relative
  // proportions are what matters). Add-to-split appends `1` so the new
  // pane comes in equal-sized with its neighbours; drag between two
  // panes redistributes those two panes' share and leaves the rest
  // alone. Reset (double-click a divider) flattens back to all-equal.
  const [splitRatios, setSplitRatios] = useState<number[]>([]);
  // "+" button's secondary menu — surfaced via right-click / long-press
  // so the primary click stays a fast "new tab" without stealing the
  // advanced flows (split view, compare across servers). Coordinates are
  // window-space, matching the pattern used by the session tab menu at
  // App level.
  const [plusMenu, setPlusMenu] = useState<{ x: number; y: number } | null>(null);
  // On narrow viewports the side-by-side terminal+tool layout doesn't fit.
  // We collapse to a stacked single-pane view: when a tool is open, the
  // tool takes full width and the terminal is hidden behind a back-chip.
  const isCompact = useIsCompact();
  // Terminals tile side by side only with two or more in the split and room
  // for them; otherwise one shows at a time.
  const splitOn = splitTerminals.length >= 2 && !isCompact;
  // Width of the right-side tool pane in pixels. The divider drag updates this
  // and we sync it to localStorage so subsequent sessions remember the split.
  // First-time default is a quarter of the current window width — looks right
  // across both narrow and wide monitors without us picking a magic pixel.
  const [toolPanelWidth, setToolPanelWidth] = useState<number>(() => {
    const saved = parseInt(localStorage.getItem('solanum-tool-panel-width') || '', 10);
    if (Number.isFinite(saved) && saved >= 240) return saved;
    const quarter = Math.round((window.innerWidth || 1440) / 4);
    return Math.max(240, Math.min(900, quarter));
  });
  // True while a tool pane's open/close is growing or shrinking the OS
  // window to compensate — see the effect below. Passed to TerminalView as
  // suppressResize so its ResizeObserver ignores the transient wrong size
  // in between the DOM update and the window actually catching up.
  const [toolResizing, setToolResizing] = useState(false);

  // The session tab strip + tool rail header spans the FULL window (it sits
  // above both the terminal and the tool pane, not just the terminal), so
  // without this, growing the window to fit a tool pane also widens the
  // header itself and its right-aligned rail visibly slides further right in
  // lockstep — even though nothing about the rail changed. Frozen to the
  // header's own pre-open width (see changeActiveTool below) and applied as
  // an explicit width while any tool is open, so the rail stays put and just
  // changes appearance (the existing active/inactive button styling).
  const toolRailHeaderRef = useRef<HTMLDivElement>(null);
  const [pinnedHeaderWidth, setPinnedHeaderWidth] = useState<number | null>(null);

  // Every activeTool change needs suppressResize to go true in the SAME
  // commit as the DOM mutation it causes (the tool pane mounting/unmounting)
  // — a separate useEffect reacting to the change fires one render late,
  // after that mutation's own ResizeObserver notification may already have
  // fired and scheduled a real refit (an intermittent flicker: whichever
  // scheduling wins the race between React's passive-effect flush and the
  // browser's own resize-notify timing). Setting it here, synchronously in
  // the same handler that changes activeTool, means both land in one React
  // batch — used by the rail buttons, each tool panel's own close button,
  // and openContainerTerminal.
  const changeActiveTool = (next: typeof activeTool) => {
    if (!activeTool && next) {
      const w = toolRailHeaderRef.current?.getBoundingClientRect().width;
      if (w) setPinnedHeaderWidth(w);
    }
    setToolResizing(true);
    setActiveTool(next);
  };

  // A panel whose channel was just refused closes: the notice says why, and
  // the terminal gets its space back.
  useEffect(() => {
    if (terminalOnly && needsAnotherChannel(activeTool)) changeActiveTool(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [terminalOnly, activeTool]);

  const initiatedRef = useRef(false);
  // Guards the per-node "run on connect" commands to fire exactly once for
  // this session view — first successful connect only, never on reconnect.
  const ranOnConnectRef = useRef(false);

  // ---- Auto-reconnect: back-off, no attempt limit ------------------------
  // After a previously-good session drops we keep retrying, with no give-up,
  // so a session/tunnel comes back by itself once a flaky link (laptop sleep,
  // mobile-hotspot dropout) returns. The wait doubles from 5 s up to 60 s,
  // with jitter, so a long outage does not hammer the server (each attempt
  // can mean a key signature, see RUSTSEC-2023-0071 in SECURITY.md).
  // Retrying stops when the backend says it would not help (`retry: false`,
  // F-030): a refused or unanswered host-key prompt, a refused login, a
  // setting problem. A changed-key prompt re-shown every few seconds would
  // invite a click-through. Auth failures go to the password box; the other
  // refusals keep the terminal view with a red "stopped" banner. The
  // terminal/SFTP overlay stays in place the whole time.
  const RECONNECT_BASE_MS = 5000;
  const RECONNECT_MAX_MS = 60000;
  // Attempt n (1-based) waits 5 s, 10 s, 20 s, 40 s, then 60 s, each ±20%.
  const reconnectDelay = (attempt: number) => {
    const base = Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * 2 ** Math.max(0, attempt - 1));
    const jittered = base * (0.8 + Math.random() * 0.4);
    return Math.round(Math.min(RECONNECT_MAX_MS, Math.max(RECONNECT_BASE_MS, jittered)));
  };
  const [reconnectAttempt, setReconnectAttempt] = useState(0);
  const [nextReconnectAt, setNextReconnectAt] = useState<number | null>(null);
  // True once auto-reconnect gave up on a refusal (see above).
  const [reconnectStopped, setReconnectStopped] = useState(false);
  const reconnectAttemptRef = useRef(0);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const updateAttempt = (n: number) => {
    reconnectAttemptRef.current = n;
    setReconnectAttempt(n);
  };

  const clearReconnectTimer = () => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    setNextReconnectAt(null);
  };

  const cancelReconnect = () => {
    clearReconnectTimer();
    updateAttempt(0);
    setReconnectStopped(false);
  };

  // Ends an auto-reconnect cycle without leaving the session view: the
  // terminals stay, the banner turns red and says why, Reconnect is manual.
  const stopReconnect = (reason: string) => {
    clearReconnectTimer();
    setReconnectStopped(true);
    setDisconnectReason(reason);
    setStatus('failed');
  };

  useEffect(() => {
    if (initiatedRef.current) return;
    initiatedRef.current = true;

    // Start connection. We read from the ref so a password the user types
    // into the auth-retry input is picked up by later attempts inside this
    // same effect closure (the effect itself only runs once).
    primarySeparateRef.current = separateFwdRef.current;
    invoke("initiate_connection", { sessionId: session.id, serverId: session.serverId, customPassword: customPasswordRef.current || null, quickAuth: session.quickAuth || null, sessionRole: "primary", separateSessions: separateFwdRef.current })
      .catch(e => {
        pushLog({ msg: `Failed to initiate: ${e}`, type: 'error' });
        setStatus('failed');
      });

    // Setup listeners
    const unlistenLog = listen(`session-log-${session.id}`, (event: any) => {
      pushLog(event.payload);
      // The log window shows only during a first connection. What must not
      // disappear behind a reconnect goes to the Activity log as well.
      if (event.payload?.activity) addLog(`[${session.serverName}] ${event.payload.msg}`, event.payload.type);
    });

    const unlistenPrompt = listen(`fingerprint-prompt-${session.id}`, (event: any) => {
      setFingerprintPrompt(event.payload);
    });

    // A dismissal names the attempt it is for; one from an older attempt
    // must not close the prompt of a newer one (a reconnect meanwhile).
    const unlistenPromptDismiss = listen(`fingerprint-prompt-dismiss-${session.id}`, (event: any) => {
      const nonce = event.payload?.nonce;
      setFingerprintPrompt((p: any) => (nonce && p && p.nonce !== nonce ? p : null));
    });

    const unlistenKbi = listen(`kbi-prompt-${session.id}`, (event: any) => {
      const p = event.payload;
      setKbiPrompt(p);
      setKbiValues(Array.isArray(p?.prompts) ? p.prompts.map(() => "") : []);
    });

    const unlistenKbiDismiss = listen(`kbi-prompt-dismiss-${session.id}`, (event: any) => {
      const nonce = event.payload?.nonce;
      const shown = kbiPromptRef.current;
      if (nonce && shown && shown.nonce !== nonce) return;
      setKbiPrompt(null);
      setKbiValues([]);
    });

    // ---- Dedicated secondary connections (separate-sessions mode) ----------
    // These fire only when the setting is on and we opened `::sftp` / `::fwd`.
    // They drive the status dots + auto-retry; routing itself lives in the
    // backend (transport preference), so no keys flip here. The primary
    // session's own KBI / fingerprint prompts stay wired above.
    const unlistenSftpOk = listen(`connection-success-${session.id}::sftp`, () => {
      sftpRetryRef.current = 0;
      setSftpConnStatus('ready');
    });
    const unlistenSftpFail = listen(`connection-failed-${session.id}::sftp`, (event: any) => {
      // Auth-style failures (2FA-only server, bad credentials) and other
      // refusals won't get better on retry — go straight to failed; SFTP
      // rides the primary.
      if (event.payload?.is_auth_error || event.payload?.retry === false) setSftpConnStatus('failed');
      else if (separateSftpRef.current && statusRef.current === 'connected') scheduleSecondaryRetry('sftp');
      else setSftpConnStatus('off');
    });
    const unlistenSftpDown = listen(`session-disconnected-${session.id}::sftp`, (event: any) => {
      // Unexpected transport death (the backend already dropped the base SFTP
      // cache, so file ops already fall back to the primary) — try to bring
      // the dedicated connection back. A user-initiated disconnect (toggle
      // off) must never retry.
      const userInitiated = !!event.payload?.user_initiated;
      if (!userInitiated && separateSftpRef.current && statusRef.current === 'connected') scheduleSecondaryRetry('sftp');
      else setSftpConnStatus('off');
    });

    const unlistenFwdOk = listen(`connection-success-${session.id}::fwd`, () => {
      fwdRetryRef.current = 0;
      setFwdConnStatus('ready');
      // Tunnel migration onto the fresh transport happens backend-side.
    });
    const unlistenFwdFail = listen(`connection-failed-${session.id}::fwd`, (event: any) => {
      if (event.payload?.is_auth_error || event.payload?.retry === false) {
        // Won't get better on retry — run the tunnels on the primary instead.
        setFwdConnStatus('failed');
        restoreTunnelsOnPrimary();
      } else if (separateFwdRef.current && statusRef.current === 'connected') {
        // scheduleSecondaryRetry falls back to the primary (and restores the
        // tunnels there) once the retry budget is exhausted.
        scheduleSecondaryRetry('fwd');
      } else {
        setFwdConnStatus('off');
      }
    });
    const unlistenFwdDown = listen(`session-disconnected-${session.id}::fwd`, (event: any) => {
      // The watcher already stopped the tunnels that rode this transport.
      // Retry brings the transport back (backend migration restarts them on
      // it); exhausted retries restore them on the primary. A user-initiated
      // disconnect (toggle off — which restores tunnels itself) never retries.
      const userInitiated = !!event.payload?.user_initiated;
      if (!userInitiated && separateFwdRef.current && statusRef.current === 'connected') scheduleSecondaryRetry('fwd');
      else setFwdConnStatus('off');
    });

    const unlistenSuccess = listen(`connection-success-${session.id}`, (event: any) => {
      // Every connection starts from what the backend knows about it, before
      // the dedicated connections below look at it.
      applyTerminalOnly(event.payload?.terminal_only);
      setLoggedOut(false);
      // statusRef.current is authoritative here — the plain `status` we
      // could reach through closure is frozen at effect-run time.
      const prevStatus = statusRef.current;
      // Still 'connected' here: a manual reconnect that finished before React
      // rendered 'connecting', so the view with the old, now closed terminals
      // never left the screen. They need reopening like any other reconnect.
      const wasReconnect = reconnectAttemptRef.current > 0 || prevStatus === 'disconnected' || prevStatus === 'failed' || prevStatus === 'connected';
      setStatus('connected');
      cancelReconnect();
      // On a successful RECONNECT we bump connectionEpoch instead of
      // replacing the terminals array. The terminal_id stays the same
      // (so the existing event listener keeps catching output), the
      // xterm instance is preserved (so the user's scroll-back survives
      // the drop), and TerminalView's per-epoch effect re-invokes
      // open_terminal — backend's terminal_txs HashMap.insert replaces
      // the dead entry transparently so the user's next keystroke
      // routes into the fresh PTY.
      if (wasReconnect) {
        setConnectionEpoch(e => e + 1);
      } else if (session.runOnConnect && session.runOnConnect.trim() && !ranOnConnectRef.current) {
        // Per-node on-connect commands: auto-typed ONCE into the first
        // terminal on the INITIAL connect only (the `else` gates out
        // reconnects; ranOnConnectRef gates out any duplicate success
        // event). Delayed so the PTY is open and the shell has printed its
        // prompt — the commands then land after it instead of racing the
        // shell's startup and getting swallowed.
        ranOnConnectRef.current = true;
        const cmds = session.runOnConnect
          .split(/\r?\n/)
          .map((l: string) => l.trimEnd())
          .filter((l: string) => l.trim().length > 0)
          .join('\n') + '\n';
        const bytes = Array.from(new TextEncoder().encode(cmds));
        setTimeout(() => {
          invoke('write_terminal_data', { terminalId: `${session.id}-term-0`, data: bytes })
            .catch((e) => pushLog({ msg: `Commands to run on connect not sent: ${e}`, type: 'error' }));
        }, 700);
      }
      // The handshake may have inserted a row into `known_hosts` (user just
      // accepted a new fingerprint). Flush the encrypted vault so the entry
      // survives an app restart — otherwise the prompt would reappear every
      // session, which was especially painful for SOCKS-proxied connections.
      invoke("persist_vault").catch((e) => pushLog({ msg: `The profile file could not be written (a new host key may be asked for again): ${e}`, type: 'error' }));
      // Separate-sessions: now that the primary is up (and the host key is
      // saved, so no double fingerprint prompt), spin up the dedicated SFTP /
      // forwarding connections. No-op when the setting is off. Fires on
      // reconnect too — the backend already reaped the stale secondaries.
      resetSecondaryStatus();
      openSecondaryConnections();
      // Reconcile the toggled-off-during-handshake case: the primary deferred
      // its saved tunnels for a `::fwd` connection we are NOT going to open, so
      // nobody would start them — restore on the primary.
      if (primarySeparateRef.current && !separateFwdRef.current) {
        restoreTunnelsOnPrimary();
      }
    });

    // A channel beside the terminal was refused, so this connection is now
    // terminal only. Nothing else about the session changes.
    const unlistenTerminalOnly = listen(`session-terminal-only-${session.id}`, (event: any) => {
      applyTerminalOnly(event.payload?.terminal_only);
    });

    const unlistenFailed = listen(`connection-failed-${session.id}`, (event: any) => {
      pushLog({ msg: `Connection failed: ${event.payload?.reason}`, type: 'error' });
      // A prompt of the failed attempt can no longer be answered.
      setFingerprintPrompt(null);
      setKbiPrompt(null);
      setKbiValues([]);
      const isAuth = !!event.payload?.is_auth_error;
      // Older payloads had no `retry`: only an auth failure stopped the cycle.
      const retry = event.payload?.retry !== false && !isAuth;
      setStatus('failed');
      setIsAuthError(isAuth);
      resetSecondaryStatus();
      addLog(`SSH_CONNECTION_FAILED [${session.serverName}]: ${event.payload?.reason}`, "error");
      // During an auto-reconnect: try again later only if it may help.
      // Wrong credentials go to the password box (full-screen view); other
      // refusals stop the cycle but keep the terminals (F-030).
      if (isAuth) {
        cancelReconnect();
      } else if (reconnectAttemptRef.current > 0) {
        if (retry) scheduleReconnect(reconnectAttemptRef.current + 1);
        else stopReconnect(String(event.payload?.reason ?? "Connection refused"));
      }
    });

    // Backend fires `session-disconnected-{id}` from the keepalive watcher when
    // a previously-good session is detected as closed (network drop, server
    // kill, idle timeout). Flip into a frozen state — terminals + SFTP are
    // disabled until the user reconnects or closes the tab. Kick off
    // auto-reconnect immediately; the banner shows the countdown.
    const unlistenDisconnected = listen(`session-disconnected-${session.id}`, (event: any) => {
      const reason = event.payload?.reason || "Connection lost";
      const userInitiated = !!event.payload?.user_initiated;
      setStatus('disconnected');
      setDisconnectReason(reason);
      resetSecondaryStatus();
      if (event.payload?.logged_out) {
        // The server ended the session and Solanum closed it too: no
        // auto-reconnect. Logging in again is the user's call, and a password
        // typed for this session is asked for again, as after any logout.
        setLoggedOut(true);
        customPasswordRef.current = "";
        setCustomPassword("");
        addLog(`SSH_SESSION_ENDED [${session.serverName}]: ${reason}`, "info");
        cancelReconnect();
        return;
      }
      addLog(`SSH_DISCONNECTED [${session.serverName}]: ${reason}`, "error");
      // User-initiated disconnect (right-click → Disconnect) should NOT
      // bounce straight into auto-reconnect — the user explicitly asked
      // for the session to be dead. The "Reconnect" banner button is
      // still available if they change their mind.
      if (!userInitiated) {
        scheduleReconnect(1);
      } else {
        cancelReconnect();
      }
    });

    return () => {
      unlistenLog.then(f => f());
      unlistenPrompt.then(f => f());
      unlistenPromptDismiss.then(f => f());
      unlistenKbi.then(f => f());
      unlistenKbiDismiss.then(f => f());
      unlistenSftpOk.then(f => f());
      unlistenSftpFail.then(f => f());
      unlistenSftpDown.then(f => f());
      unlistenFwdOk.then(f => f());
      unlistenFwdFail.then(f => f());
      unlistenFwdDown.then(f => f());
      unlistenSuccess.then(f => f());
      unlistenTerminalOnly.then(f => f());
      unlistenFailed.then(f => f());
      unlistenDisconnected.then(f => f());

      if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
      clearSecondaryRetryTimers();
      invoke("disconnect_session", { sessionId: session.id }).catch(console.error);
    };
  }, [session.id, session.serverId]);

  // Force a re-render once per second so the countdown text in the banner
  // stays current without re-allocating timer state on every render.
  const [, forceTick] = useState(0);
  useEffect(() => {
    if (!nextReconnectAt) return;
    const t = setInterval(() => forceTick((n) => n + 1), 500);
    return () => clearInterval(t);
  }, [nextReconnectAt]);

  const scheduleReconnect = (attempt: number) => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    const delay = reconnectDelay(attempt);
    updateAttempt(attempt);
    setReconnectStopped(false);
    setNextReconnectAt(Date.now() + delay);
    reconnectTimerRef.current = setTimeout(attemptReconnect, delay);
  };

  // One reconnect attempt, with the terminals kept on screen (and their
  // scrollback): the full-screen view is only for a first connection.
  const attemptReconnect = () => {
    reconnectTimerRef.current = null;
    setNextReconnectAt(null);
    setStatus('connecting');
    primarySeparateRef.current = separateFwdRef.current;
    invoke("initiate_connection", {
      sessionId: session.id,
      serverId: session.serverId,
      customPassword: customPasswordRef.current || null,
      quickAuth: session.quickAuth || null,
      sessionRole: "primary",
      separateSessions: separateFwdRef.current,
    }).catch(e => {
      // Refused before any connection-failed event (server row gone,
      // vault locked, ...): no event would ever move the cycle on, so
      // end it here instead of sitting on "connecting" (N-001).
      pushLog({ msg: `Failed to initiate: ${e}`, type: 'error' });
      if (reconnectAttemptRef.current > 0) stopReconnect(String(e));
      else setStatus('failed');
    });
  };

  // R on "Session stopped", or Reconnect, once the connection is gone: log in
  // again from the start, the terminals and their scrollback kept (N-028).
  const restartSession = () => {
    if (statusRef.current === 'connecting' || statusRef.current === 'connected') return;
    clearReconnectTimer();
    setReconnectStopped(false);
    setLoggedOut(false);
    setDisconnectReason("");
    resetSecondaryStatus();
    updateAttempt(1);
    attemptReconnect();
  };

  const reconnect = () => {
    cancelReconnect();
    setStatus('connecting');
    setLogs([]);
    setIsAuthError(false);
    setDisconnectReason("");
    resetSecondaryStatus();
    primarySeparateRef.current = separateFwdRef.current;
    invoke("initiate_connection", {
      sessionId: session.id,
      serverId: session.serverId,
      customPassword: customPassword || null,
      quickAuth: session.quickAuth || null,
      sessionRole: "primary",
      separateSessions: separateFwdRef.current,
    }).catch(e => {
      pushLog({ msg: `Failed to initiate: ${e}`, type: 'error' });
      setStatus('failed');
    });
  };

  // Tab-strip right-click "Reconnect" fires a DOM CustomEvent rather than
  // round-tripping through React props — keeps DesktopApp's tab UI decoupled
  // from SessionView's reconnect lifecycle.
  useEffect(() => {
    const onReconnect = () => reconnect();
    const evt = `session-reconnect-${session.id}`;
    window.addEventListener(evt, onReconnect);
    return () => window.removeEventListener(evt, onReconnect);
  }, [session.id, customPassword]);

  // ---- Tool pane sizing + window growth ------------------------------------
  // Philosophy: the terminal column is sacred. Opening a tool pane or
  // dragging the divider grows or shrinks the OS window in lockstep so the
  // terminal's pixel width never changes underneath the user.

  const appWindow = getCurrentWindow();
  const toolWidthRef = useRef(toolPanelWidth);
  useEffect(() => { toolWidthRef.current = toolPanelWidth; }, [toolPanelWidth]);

  // window.innerWidth/innerHeight are already logical CSS pixels and — since
  // `decorations: false` (tauri.conf.json) means there's no native title bar
  // eating into it — equal to the window's own logical size. Reading them
  // synchronously (instead of the async appWindow.outerSize()/scaleFactor()
  // round trips this used to await first) lets setSize() fire on the very
  // same tick as the click, shrinking the gap during which the terminal's
  // flex sibling has to share space with a tool pane the window hasn't
  // grown to accommodate yet.
  const adjustWindowWidth = async (deltaPx: number) => {
    try {
      const next = Math.max(640, Math.round(window.innerWidth + deltaPx));
      await appWindow.setSize(new LogicalSize(next, window.innerHeight));
    } catch (e) {
      console.error("window resize failed", e);
    }
  };

  // Settles the DOM a couple frames past setSize()'s own promise — that
  // promise resolves once the resize request round-trips, not necessarily
  // once the webview has actually repainted at the new size.
  const settleAfterResize = () =>
    new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));

  // Grow the window when the tool pane is opened, shrink when it's closed.
  // The +4 accounts for the resize divider itself. toolResizing was already
  // set true by changeActiveTool, in the same commit as the activeTool
  // change that mounted/unmounted the tool pane — this effect just carries
  // out the actual (necessarily async) window resize and clears the flag
  // once it settles. Since the window always ends up back at the size that
  // keeps the terminal's own width unchanged, the one settle-fit this
  // unblocks at the end (see TerminalView's suppressResize prop) is
  // normally a no-op.
  const prevActiveToolRef = useRef<typeof activeTool>(null);
  useEffect(() => {
    const prev = prevActiveToolRef.current;
    prevActiveToolRef.current = activeTool;
    if (!prev && activeTool) {
      adjustWindowWidth(toolWidthRef.current + 4).then(settleAfterResize).finally(() => setToolResizing(false));
    } else if (prev && !activeTool) {
      adjustWindowWidth(-(toolWidthRef.current + 4)).then(settleAfterResize).finally(() => setToolResizing(false));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTool]);

  // If the user closes the session tab while a tool is open, give the
  // window space back rather than leaving it stretched.
  useEffect(() => {
    return () => {
      if (prevActiveToolRef.current) {
        adjustWindowWidth(-(toolWidthRef.current + 4));
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const startToolResize = (e: React.MouseEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = toolWidthRef.current;
    let lastCommittedWidth = startWidth;
    let pendingWidth = startWidth;
    let frameRequested = false;

    const onMove = (ev: MouseEvent) => {
      // Dragging LEFT (cursor moves left) widens the tool pane.
      const next = Math.max(240, Math.min(900, startWidth + (startX - ev.clientX)));
      pendingWidth = next;
      setToolPanelWidth(next);
      // Throttle window resizes to one per animation frame. setSize crosses an
      // IPC boundary and dispatching it on every mousemove makes the drag feel
      // laggy. We batch by recomputing the delta against last-committed width
      // inside the frame, so no mouse movement is dropped.
      if (!frameRequested) {
        frameRequested = true;
        requestAnimationFrame(() => {
          frameRequested = false;
          const delta = pendingWidth - lastCommittedWidth;
          if (delta !== 0) {
            lastCommittedWidth = pendingWidth;
            adjustWindowWidth(delta);
          }
        });
      }
    };

    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      try { localStorage.setItem("solanum-tool-panel-width", String(toolWidthRef.current)); }
      catch { /* ignore */ }
    };

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const handleFingerprintResponse = async (accepted: boolean) => {
    // The `nonce` came from the prompt event and binds this response 1:1
    // to the connect attempt that emitted it. The backend ignores any
    // response whose nonce isn't in its in-flight map, so stale clicks
    // (or a hostile script that knows only the session id) can't accept
    // a fingerprint on the user's behalf.
    const nonce = fingerprintPrompt?.nonce;
    setFingerprintPrompt(null);
    if (!nonce) return;
    try {
      await invoke("verify_fingerprint_response", { nonce, accepted });
    } catch (e) {
      pushLog({ msg: `Host key answer not delivered: ${e}`, type: 'error' });
    }
  };

  // Keyboard-interactive (2FA) submit / cancel. Like the fingerprint flow the
  // nonce binds the answer to this exact connect attempt; cancel sends `null`
  // so the backend aborts the interactive auth instead of waiting out its
  // 120s timeout.
  const handleKbiSubmit = async () => {
    const nonce = kbiPrompt?.nonce;
    const responses = kbiValues;
    setKbiPrompt(null);
    setKbiValues([]);
    if (!nonce) return;
    try {
      await invoke("submit_kbi_response", { nonce, responses });
    } catch (e) {
      pushLog({ msg: `Login answer not delivered: ${e}`, type: 'error' });
    }
  };

  const handleKbiCancel = async () => {
    const nonce = kbiPrompt?.nonce;
    setKbiPrompt(null);
    setKbiValues([]);
    if (!nonce) return;
    try {
      await invoke("submit_kbi_response", { nonce, responses: null });
    } catch (e) {
      pushLog({ msg: `Login cancel not delivered: ${e}`, type: 'error' });
    }
  };

  // Host-key fingerprint + keyboard-interactive (2FA) prompts, held in ONE
  // place so they render both in the first-connect full-screen view AND — via
  // a portal overlay (see the connected-state return) — during an auto-
  // reconnect. Previously these only lived inside the reconnectAttempt===0
  // early-return, so a changed-host-key or 2FA prompt fired mid-reconnect was
  // never drawn (the slim banner has no prompt UI), leaving the user unable to
  // respond and the reconnect cycle spinning.
  const authPrompts = (
    <>
      {/* Fingerprint Prompt — three flavors:
            • first time seeing this host → light warning
            • mismatch=true → host key CHANGED (same type, another key),
              looks like a MITM: red treatment + the old fingerprints
            • otherTypes non-empty → the host is trusted with a key of
              another type but presents this one instead (F-029); since
              known types are asked for first, a server that still had its
              trusted key would have used it: red treatment too */}
      {fingerprintPrompt && (() => {
        const isMismatch = !!fingerprintPrompt.mismatch;
        const otherTypes: { keyType: string; fingerprint: string }[] =
          Array.isArray(fingerprintPrompt.otherTypes) ? fingerprintPrompt.otherTypes : [];
        const isOtherType = !isMismatch && otherTypes.length > 0;
        const alarming = isMismatch || isOtherType;
        const tone = alarming
          ? "border-red-500/40 bg-red-500/10"
          : "border-amber-500/30 bg-amber-500/5";
        const accent = alarming ? "text-red-400" : "text-amber-500";
        const acceptBtn = alarming
          ? "bg-red-500 text-white hover:bg-red-400"
          : "bg-amber-500 text-black hover:bg-amber-400";
        return (
        <div className={`mt-6 p-4 border ${tone} rounded-xl animate-in fade-in slide-in-from-bottom-4`}>
          <div className="flex items-start gap-3">
            <ShieldAlert className={`${accent} mt-1`} size={20} />
            <div>
              <h3 className={`text-sm font-bold ${accent} uppercase tracking-widest`}>
                {isMismatch ? "Host key has CHANGED" : isOtherType ? "Different key type for a known host" : "Unknown host fingerprint"}
              </h3>
              {isOtherType ? (
                <p className="text-zinc-300 mt-2 mb-4 leading-relaxed">
                  The host '{fingerprintPrompt.host}' is already trusted with a {otherTypes.map(o => o.keyType).join(", ")} key, but it now presents a {fingerprintPrompt.keyType} key instead. A server that still had its trusted key would have used it, so this can mean a man-in-the-middle attack — or that the server's keys were replaced.<br/><br/>
                  New {fingerprintPrompt.keyType} fingerprint: <span className="text-white font-bold break-all">{fingerprintPrompt.fingerprint}</span><br/>
                  <span className="block mt-1 text-zinc-500 text-[11px]">
                    Already trusted: <span className="font-mono break-all">{otherTypes.map(o => `${o.keyType} ${o.fingerprint}`).join(", ")}</span>
                  </span>
                  <span className="block mt-3 text-red-300 text-[12px]">Verify the new fingerprint out-of-band (call the admin, check the server console) before accepting. Accepting keeps the key already on file.</span>
                  {fingerprintPrompt.legacyHint && (
                    <span className="block mt-2 text-zinc-400 text-[11px]">If this server's RSA key was trusted while its "Allow legacy algorithms" setting was on, an old server may only sign with SHA-1: turning the setting back on would bring the RSA key back.</span>
                  )}
                </p>
              ) : isMismatch ? (
                <p className="text-zinc-300 mt-2 mb-4 leading-relaxed">
                  The host '{fingerprintPrompt.host}' is presenting a different key than the one you trusted before. This is what a man-in-the-middle attack looks like — but it can also mean the server admin rotated the key.<br/><br/>
                  New {fingerprintPrompt.keyType} fingerprint: <span className="text-white font-bold break-all">{fingerprintPrompt.fingerprint}</span><br/>
                  {Array.isArray(fingerprintPrompt.priorFingerprints) && fingerprintPrompt.priorFingerprints.length > 0 && (
                    <span className="block mt-1 text-zinc-500 text-[11px]">
                      Previously trusted: <span className="font-mono break-all">{fingerprintPrompt.priorFingerprints.join(", ")}</span>
                    </span>
                  )}
                  <span className="block mt-3 text-red-300 text-[12px]">Verify the new fingerprint out-of-band (call the admin, check the server console) before accepting.</span>
                </p>
              ) : (
                <p className="text-zinc-400 mt-2 mb-4 leading-relaxed">
                  The authenticity of host '{fingerprintPrompt.host}' can't be established.<br/>
                  {fingerprintPrompt.keyType} key fingerprint is <span className="text-white font-bold break-all">{fingerprintPrompt.fingerprint}</span>.<br/>
                  Are you sure you want to continue connecting?
                </p>
              )}
              <div className="flex gap-3">
                <button
                  onClick={() => handleFingerprintResponse(true)}
                  className={`px-6 py-2 ${acceptBtn} font-bold text-xs uppercase tracking-wider rounded-lg transition-colors flex items-center gap-2`}
                >
                  <Check size={14} /> {alarming ? "Accept new key" : "Accept & save"}
                </button>
                <button
                  onClick={() => handleFingerprintResponse(false)}
                  className="px-6 py-2 bg-white/5 text-zinc-300 font-bold text-xs uppercase tracking-wider rounded-lg hover:bg-white/10 transition-colors flex items-center gap-2"
                >
                  <X size={14} /> {alarming ? "Abort" : "Reject"}
                </button>
              </div>
            </div>
          </div>
        </div>
        );
      })()}

      {/* Keyboard-Interactive (2FA / verification-code) prompt (F-079).
          Everything a server sends here is its own text, so the dialog
          keeps it visibly apart from the app's: the title is ours and names
          the host asking, the server's name, instructions and labels sit in
          a bordered "from the server" block with hidden and direction-
          changing characters spelled out, and an answer is masked unless
          the server asked for echo AND the label does not look like it asks
          for a secret (a server cannot make a password field show in clear). */}
      {kbiPrompt && (
        <div className="mt-6 p-4 border border-primary/30 bg-primary/5 rounded-xl animate-in fade-in slide-in-from-bottom-4">
          <div className="flex items-start gap-3">
            <KeyRound className="text-primary mt-1" size={20} />
            <div className="flex-1 min-w-0">
              <h3 className="text-sm font-bold text-primary uppercase tracking-widest break-words">
                Login prompt from {kbiPrompt.host ? visibleName(String(kbiPrompt.host)) : session.serverName}
              </h3>
              <p className="text-[11px] text-zinc-500 mt-1">
                The server is asking. The text in the box below comes from the server, not from Solanum: never type your Solanum master password here.
              </p>
              {((kbiPrompt.name && String(kbiPrompt.name).trim()) || (kbiPrompt.instructions && String(kbiPrompt.instructions).trim())) && (
                <div className="mt-3 border-l-2 border-zinc-600 bg-black/30 rounded-r-md px-3 py-2 font-mono text-[12px] text-zinc-300 whitespace-pre-wrap break-words">
                  {kbiPrompt.name && String(kbiPrompt.name).trim() && (
                    <div className="font-bold">{visibleText(String(kbiPrompt.name))}</div>
                  )}
                  {kbiPrompt.instructions && String(kbiPrompt.instructions).trim() && (
                    <div>{visibleText(String(kbiPrompt.instructions))}</div>
                  )}
                </div>
              )}
              <div className="mt-3 space-y-3">
                {(kbiPrompt.prompts || []).map((p: any, i: number) => {
                  const label = String(p?.prompt ?? "");
                  const masked = !p?.echo || SECRET_PROMPT.test(withoutHidden(label));
                  return (
                  <div key={i} className="space-y-1.5">
                    <label className="block text-[12px] text-zinc-300 font-mono break-words">
                      {label ? visibleName(label) : "Response"}
                    </label>
                    <input
                      type={masked ? "password" : "text"}
                      autoFocus={i === 0}
                      className="w-full h-9 bg-[#1a1a1e] rounded-lg px-3 text-sm text-white border border-white/10 outline-none focus:border-primary/50 focus:bg-[#232328] transition-all"
                      value={kbiValues[i] ?? ""}
                      onChange={e => setKbiValues(vals => {
                        const next = [...vals];
                        next[i] = e.target.value;
                        return next;
                      })}
                      onKeyDown={e => {
                        if (e.key === "Enter" && i === (kbiPrompt.prompts?.length ?? 1) - 1) handleKbiSubmit();
                      }}
                    />
                  </div>
                  );
                })}
              </div>
              <div className="flex gap-3 mt-4">
                <button
                  onClick={handleKbiSubmit}
                  className="px-6 py-2 bg-primary text-black font-bold text-xs uppercase tracking-wider rounded-lg hover:bg-primary/80 transition-colors flex items-center gap-2"
                >
                  <Check size={14} /> Submit
                </button>
                <button
                  onClick={handleKbiCancel}
                  className="px-6 py-2 bg-white/5 text-zinc-300 font-bold text-xs uppercase tracking-wider rounded-lg hover:bg-white/10 transition-colors flex items-center gap-2"
                >
                  <X size={14} /> Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );

  // Only render the full-screen log view for the FIRST connection — once an
  // auto-reconnect cycle is running, the user's terminal output and SFTP
  // state stay visible behind a slim banner.
  if (reconnectAttempt === 0 && (status === 'connecting' || status === 'failed')) {
    return (
      <div className="flex-1 flex flex-col p-4 sm:p-8 bg-[#0a0a0c] text-white overflow-hidden">
        <div className="max-w-2xl w-full mx-auto flex-1 flex flex-col min-h-0">
          {/* Header: on desktop, title row keeps title + actions side-by-side.
              On phone, wide letter-spacing on the title wraps "0-1 AMIR" onto
              three lines and the Reconnect / Close buttons get pushed past
              the viewport. We stack vertically and trim the typography so
              the whole header fits in two compact rows at any width. */}
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 mb-4 sm:mb-6">
            <div>
              <h2 className="text-base sm:text-xl font-black uppercase tracking-wider sm:tracking-[0.2em] break-words">
                {session.serverName}
              </h2>
              <p className="text-[10px] text-zinc-500 font-bold uppercase tracking-widest mt-1">
                {status === 'connecting' ? 'Establishing Connection...' : 'Connection Failed'}
              </p>
            </div>
            {status === 'failed' && (
              <div className="flex flex-wrap gap-2 items-center">
                {isAuthError && (
                  <input
                    type="password"
                    placeholder="Password..."
                    className="h-8 flex-1 min-w-0 sm:flex-none bg-[#1a1a1e] rounded-lg px-3 text-xs text-white border border-white/10 outline-none focus:border-primary/50"
                    value={customPassword}
                    onChange={e => setCustomPassword(e.target.value)}
                    onKeyDown={e => {
                      if(e.key === 'Enter') reconnect();
                    }}
                  />
                )}
                <button onClick={reconnect} className="flex-1 sm:flex-none px-4 py-2 bg-primary/10 text-primary hover:bg-primary/20 rounded-lg text-xs font-bold uppercase tracking-wider transition-colors">
                  Reconnect
                </button>
                <button onClick={onClose} className="flex-1 sm:flex-none px-4 py-2 bg-red-500/10 text-red-500 hover:bg-red-500/20 rounded-lg text-xs font-bold uppercase tracking-wider transition-colors">
                  Close Session
                </button>
              </div>
            )}
          </div>

          {/* Log Window. `min-h-0` is what makes it actually scroll: a flex
              child defaults to min-height:auto (its content height), so without
              this the box grows to fit every line and the parent's
              overflow-hidden clips it instead of the inner overflow-y-auto
              taking over — invisible on desktop with a tall window, but on a
              short Android viewport the log gets cut off with no way to scroll.
              overscroll-contain keeps a flick from scrolling the page behind it;
              WebkitOverflowScrolling gives older Android WebViews momentum. */}
          <div
            className="flex-1 min-h-0 bg-[#121214] border border-white/5 rounded-2xl p-4 font-mono overflow-y-auto overscroll-contain custom-scrollbar shadow-inner relative select-text cursor-text"
            style={{ WebkitOverflowScrolling: 'touch', fontSize: logFontSize, lineHeight: 1.5 }}
          >
            {logs.map((l, i) => (
              <div key={i} className={`mb-2 ${l.type === 'error' ? 'text-red-400' : l.type === 'success' ? 'text-primary' : 'text-zinc-400'}`}>
                <span className="text-zinc-600 opacity-50 mr-3">[{l.time}]</span>
                {l.msg}
              </div>
            ))}

            {authPrompts}
          </div>
        </div>
      </div>
    );
  }

  // Connected State with Nested Tabs
  return (
    <div className="flex-1 flex flex-col bg-background overflow-hidden animate-in fade-in">
      {/* Auth prompts during an AUTO-RECONNECT. The full-screen view above only
          renders on the first connect (reconnectAttempt===0); once a reconnect
          cycle is running we show the terminal behind a slim banner, so a
          fingerprint / 2FA prompt fired mid-reconnect would otherwise be
          invisible and unanswerable. Float it over everything via a portal. */}
      {(fingerprintPrompt || kbiPrompt) && createPortal(
        <div className="fixed inset-0 z-[200] flex items-start justify-center bg-black/70 backdrop-blur-sm p-4 sm:p-8 overflow-y-auto">
          {/* Opaque: the prompts' own panels are see-through, and over a
              terminal (R after a logout, N-028) its text showed through
              theirs. */}
          <div className="max-w-2xl w-full mt-6 sm:mt-12 bg-[#0a0a0c] rounded-xl">
            {authPrompts}
          </div>
        </div>,
        document.body
      )}
      {/* Nested Tab Bar — hidden in `chromeless` mode. Chromeless is
          used by the App-level Split-view tiling: merged (non-focused)
          panes show only the active terminal, no per-session tab strip
          + tool rail. Otherwise every merged tile would carry its own
          full chrome and 2-3 sessions side-by-side would fight for
          vertical space with duplicate toolbars. */}
      {!chromeless && (
      <div
        ref={toolRailHeaderRef}
        style={activeTool && !isCompact && pinnedHeaderWidth != null ? { width: pinnedHeaderWidth } : undefined}
        className="h-12 border-b border-white/5 bg-[#121214]/50 flex items-center px-2 sm:px-4 shrink-0 justify-between gap-1"
      >
        <div
          className="flex items-center gap-1 overflow-x-auto no-scrollbar flex-1 mr-1 sm:mr-4 mask-fade-right"
          onWheel={(e) => { e.currentTarget.scrollLeft += e.deltaY; }}
        >
        {terminals.map(t => {
          // Highlight every terminal currently participating in the split
          // — the keyboard-focused one gets the primary tint, the others
          // a softer accent, so the pairing is obvious at a glance.
          const isFocusedHalf = activeTab === t.id;
          const isSplitPartner = !!(splitTerminals.includes(t.id) && !isFocusedHalf);
          return (
          <div key={t.id} className="group relative flex items-center">
            <button
              onClick={() => {
                // Clicking a tab NOT participating in the current split
                // exits split mode entirely — split is scoped to the
                // panes it was built with; jumping elsewhere means the
                // user wants a plain full-pane view.
                if (splitTerminals.length >= 2 && !splitTerminals.includes(t.id)) {
                  setSplitTerminals([]);
                  setSplitRatios([]);
                }
                setActiveTab(t.id);
              }}
              title={t.container ? `Container: ${t.container.name}` : undefined}
              className={`h-8 px-3 sm:px-4 ${terminals.length > 1 ? 'pr-8' : ''} rounded-lg flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider transition-all ${
                isFocusedHalf
                  ? 'bg-primary/10 text-primary border border-primary/20 shadow-inner'
                  : isSplitPartner
                    ? 'bg-primary/[0.04] text-primary/70 border border-primary/10'
                    : 'text-zinc-300 bg-white/[0.04] border border-white/10 hover:bg-white/[0.08] hover:border-white/20 hover:text-white'
              } ${t.container ? 'ring-1 ring-sky-400/30' : ''}`}
            >
              {t.container
                ? <Container size={14} className="text-sky-300" />
                : <TerminalSquare size={14} />}
              {t.title}
              {isSplitPartner && (
                <SplitSquareHorizontal size={10} className="text-primary/60" />
              )}
            </button>
            {terminals.length > 1 && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  closeTerminalTab(t.id);
                }}
                aria-label="Close terminal"
                className="absolute right-1 top-1/2 -translate-y-1/2 w-5 h-5 flex items-center justify-center rounded opacity-100 sm:opacity-0 sm:group-hover:opacity-100 hover:bg-white/5 hover:text-red-400 text-zinc-500 transition-all"
              >
                <X size={12} />
              </button>
            )}
          </div>
          );
        })}

          {/* Single "+" affordance for all terminal-creation flavours.
              Click adds a plain tab (the 90% case). The right-click menu
              — also reachable via long-press on touch — surfaces the
              advanced modes: split-with-new-pane and un-split. That
              keeps the tab strip visually calm (one small button, no
              badges, no orientation glyphs stealing attention) while
              still exposing the power features via a discoverable
              secondary gesture. */}
          <button
            onClick={() => {
              const newId = `${session.id}-term-${Date.now()}`;
              setTerminals(prev => [...prev, { id: newId, title: `${prev.length + 1}` }]);
              setActiveTab(newId);
            }}
            onContextMenu={(e) => {
              e.preventDefault();
              const rect = e.currentTarget.getBoundingClientRect();
              setPlusMenu({ x: rect.left, y: rect.bottom + 4 });
            }}
            className="h-10 w-10 sm:h-8 sm:w-8 ml-1 shrink-0 rounded-lg flex items-center justify-center text-zinc-500 hover:bg-white/10 hover:text-white transition-all border border-dashed border-white/10 relative"
            title="New terminal · right-click for split view"
          >
            <Plus size={14} />
            {splitTerminals.length >= 2 && (
              <span
                className="absolute -top-1 -right-1 min-w-[14px] h-[14px] px-1 rounded-full bg-primary text-[9px] font-bold text-black flex items-center justify-center leading-none"
                aria-hidden="true"
                title={`Split active (${splitTerminals.length} panes)`}
              >
                {splitTerminals.length}
              </span>
            )}
          </button>
        </div>

        {/* Tool rail: icon + text label. The label collapses to icon-only on
            narrow viewports (below md) so the terminal tab strip keeps its
            horizontal real estate when space is tight; the full description
            stays in the tooltip either way. */}
        <div className="flex items-center gap-1 shrink-0 sm:border-l border-white/5 sm:pl-3 pl-1">
          {([
            { id: 'docker',  icon: Box,     label: 'Docker',  hint: 'Docker — containers, images, volumes' },
            { id: 'info',    icon: Info,    label: 'Info',    hint: 'Info — server overview' },
            { id: 'cmds',    icon: Library, label: 'Library', hint: 'Library — commands & notes' },
            { id: 'tunnels', icon: Network, label: 'Ports',   hint: 'Ports — port forwarding' },
            { id: 'sftp',    icon: Folder,  label: 'SFTP',    hint: 'SFTP — file browser' },
          ] as const).map(({ id, icon: Icon, label, hint }) => {
            const on = activeTool === id;
            const off = terminalOnly && needsAnotherChannel(id) ? unavailableHint(label, terminalOnly) : null;
            return (
              <button
                key={id}
                onClick={() => changeActiveTool(on ? null : id)}
                disabled={!!off}
                title={off ?? hint}
                aria-label={off ?? hint}
                aria-pressed={on}
                className={`h-10 sm:h-8 px-2.5 rounded-lg flex items-center gap-1.5 transition-all ${
                  off
                    ? 'text-zinc-600 bg-transparent border border-white/5 cursor-not-allowed'
                    : on
                    ? 'bg-primary/10 text-primary border border-primary/20 shadow-inner'
                    : 'text-zinc-300 bg-white/[0.04] border border-white/10 hover:bg-white/[0.08] hover:border-white/20 hover:text-white'
                }`}
              >
                <Icon size={14} className="shrink-0" />
                <span className="hidden md:inline text-[11px] font-semibold tracking-tight">{label}</span>
              </button>
            );
          })}
        </div>
      </div>
      )}

      {/* "+" secondary menu — right-click / long-press on the plus
          button. Kept intentionally short: same-server "split with new
          pane", the h/v orientation flip, and un-split. Cross-server
          split lives on the session tab strip (right-click any tab
          → the picker); one entry point per concept keeps the menu
          scannable. Everything else is one primary click on "+". */}
      {plusMenu && createPortal(
        <>
          <div
            className="fixed inset-0 z-[9998]"
            onClick={() => setPlusMenu(null)}
            onContextMenu={(e) => { e.preventDefault(); setPlusMenu(null); }}
          />
          <div
            style={{ left: Math.min(plusMenu.x, window.innerWidth - 260), top: Math.min(plusMenu.y, window.innerHeight - 220) }}
            className="fixed z-[9999] w-[240px] bg-[#15151a] border border-white/10 rounded-lg shadow-2xl py-1 text-[11.5px]"
          >
            {!isCompact && (
              <>
                <button
                  onClick={() => {
                    setPlusMenu(null);
                    const newId = `${session.id}-term-${Date.now()}`;
                    setTerminals(prev => [...prev, { id: newId, title: `${prev.length + 1}` }]);
                    if (splitTerminals.length >= 2) {
                      setSplitTerminals(prev => [...prev, newId]);
                      setSplitRatios(prev => [...prev, 1]);
                    } else {
                      setSplitTerminals([activeTab, newId]);
                      setSplitRatios([1, 1]);
                    }
                    setActiveTab(newId);
                  }}
                  className="w-full flex items-center gap-2.5 px-3 py-1.5 hover:bg-white/[0.06] text-zinc-200 hover:text-white text-left"
                >
                  {splitOrientation === "h" ? <Columns size={13} className="text-primary/70" /> : <Rows size={13} className="text-primary/70" />}
                  <span className="flex-1">{splitTerminals.length >= 2 ? `Add pane (${splitTerminals.length + 1}-way split)` : "Split with new pane"}</span>
                </button>
                <button
                  onClick={() => {
                    setSplitOrientation(o => o === "h" ? "v" : "h");
                    setPlusMenu(null);
                  }}
                  className="w-full flex items-center gap-2.5 px-3 py-1.5 hover:bg-white/[0.06] text-zinc-300 hover:text-white text-left"
                >
                  {splitOrientation === "h" ? <Rows size={13} className="text-zinc-500" /> : <Columns size={13} className="text-zinc-500" />}
                  <span className="flex-1">Flip orientation ({splitOrientation === "h" ? "→ vertical" : "→ horizontal"})</span>
                </button>
                {splitTerminals.length >= 2 && (
                  <button
                    onClick={() => {
                      setSplitTerminals([]);
                      setSplitRatios([]);
                      setPlusMenu(null);
                    }}
                    className="w-full flex items-center gap-2.5 px-3 py-1.5 hover:bg-white/[0.06] text-zinc-300 hover:text-white text-left"
                  >
                    <X size={13} className="text-zinc-500" />
                    <span className="flex-1">Exit split (keep terminals)</span>
                  </button>
                )}
              </>
            )}
            {/* Splitting THIS session's view with another server's tab
                lives on the session tab strip (right-click the tab).
                That way the picker is anchored to the tab it operates
                on and users don't have to know two entry points for the
                same feature. */}
          </div>
        </>,
        document.body
      )}

      {/* The host allows only a terminal. Non-blocking: the terminal works as
          usual beside it, and it can be closed or turned into the setting. */}
      {terminalOnlyNotice(terminalOnly, session.serverId).show && !terminalOnlyDismissed && (
        <div role="status" className="shrink-0 px-4 py-1.5 border-b flex items-center justify-between gap-3 bg-amber-500/10 border-amber-500/30 text-amber-300">
          <div className="flex items-center gap-2 min-w-0 text-[11px]">
            <AlertTriangle size={14} className="shrink-0" />
            <span>This host allows only a terminal: SFTP, live info and Docker are unavailable on it.</span>
            {terminalOnlySaveError && <span className="text-red-400">Not saved: {terminalOnlySaveError}</span>}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {terminalOnlyNotice(terminalOnly, session.serverId).offerSetting && (
              <button onClick={saveTerminalOnly} className="px-3 py-1.5 sm:py-1 min-h-8 sm:min-h-6 bg-white/5 text-zinc-300 hover:bg-white/10 hover:text-white rounded-md text-[10px] font-bold uppercase tracking-wider transition-colors">
                Always terminal only
              </button>
            )}
            <button onClick={() => setTerminalOnlyDismissed(true)} aria-label="Close this notice" title="Close this notice" className="p-1 rounded text-amber-300/70 hover:text-white hover:bg-white/10 transition-colors">
              <X size={12} />
            </button>
          </div>
        </div>
      )}

      {/* Disconnection / auto-reconnect banner. Pinned to the top so it's
          visible whether the terminal or SFTP is in focus. The disabled
          overlay inside TerminalView / SftpWorkspace / TunnelsPanel does the
          heavy lifting of locking input out. */}
      {(status === 'disconnected' || reconnectAttempt > 0) && (
        (() => {
          const isAttempting = reconnectAttempt > 0 && status === 'connecting';
          const isWaiting = reconnectAttempt > 0 && nextReconnectAt !== null;
          const countdown = nextReconnectAt
            ? Math.max(0, Math.ceil((nextReconnectAt - Date.now()) / 1000))
            : 0;
          const tone =
            isAttempting ? "bg-indigo-500/10 border-indigo-500/30 text-indigo-300" :
            isWaiting    ? "bg-amber-500/10 border-amber-500/30 text-amber-300" :
            loggedOut    ? "bg-white/[0.03] border-white/10 text-zinc-300" :
                           "bg-red-500/10 border-red-500/30 text-red-400";
          const heading =
            isAttempting ? `Reconnecting · attempt ${reconnectAttempt}` :
            isWaiting    ? `Auto-reconnect in ${countdown}s · attempt ${reconnectAttempt}` :
            reconnectStopped ? "Auto-reconnect stopped" :
            loggedOut    ? "Session ended" :
                           "Session disconnected";
          return (
            <div className={`shrink-0 px-4 py-2 border-b flex items-center justify-between gap-3 animate-in fade-in ${tone}`}>
              <div className="flex items-center gap-2 text-[11px] font-bold uppercase tracking-wider">
                <AlertTriangle size={14} />
                <span>{heading}</span>
                {disconnectReason && (
                  <span className="opacity-70 normal-case font-normal tracking-normal">— {disconnectReason}</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                {isWaiting && (
                  <button onClick={cancelReconnect} className="px-3 py-1.5 sm:py-1 min-h-8 sm:min-h-6 bg-white/5 text-zinc-300 hover:bg-white/10 hover:text-white rounded-md text-[10px] font-bold uppercase tracking-wider transition-colors">
                    Cancel
                  </button>
                )}
                <button onClick={loggedOut ? restartSession : reconnect} className="px-3 py-1.5 sm:py-1 min-h-8 sm:min-h-6 bg-primary/10 text-primary hover:bg-primary/20 rounded-md text-[10px] font-bold uppercase tracking-wider transition-colors flex items-center gap-1.5">
                  <Play size={12} /> {isWaiting ? "Now" : "Reconnect"}
                </button>
                <button onClick={onClose} className="px-3 py-1.5 sm:py-1 min-h-8 sm:min-h-6 bg-white/5 text-zinc-400 hover:bg-white/10 hover:text-white rounded-md text-[10px] font-bold uppercase tracking-wider transition-colors">
                  Close
                </button>
              </div>
            </div>
          );
        })()
      )}

      {/* Tab Content Split Pane. Side-by-side on roomy desktop; on narrow
          (`isCompact`) viewports the tool pane takes over the full width
          and the terminal is hidden — the tool tabs themselves act as the
          "back to terminal" affordance (clicking the active tool toggles
          it off). This avoids squeezing a usable terminal + tool into a
          mobile-sized window. */}
      <div className="flex-1 flex overflow-hidden relative" style={{ backgroundColor: splitPaneBg }}>
        {/* Left Panel: Active Terminals.
            On compact + activeTool, hide entirely so the tool fills the
            screen. Terminals stay mounted (no PTY teardown) — just CSS
            hidden so swapping back keeps the same shell session.

            Split mode: when `splitTerminals` holds 2+ ids and the
            viewport is roomy enough, we tile those terminals side-by-side
            (or stacked, per `splitOrientation`) with draggable dividers
            between adjacent panes. All OTHER terminals stay mounted but
            hidden — so switching a tab that isn't in the split preserves
            its scrollback. The tiles fill the whole left panel; the tool
            side panel continues to work exactly as before. */}
        <div className={`h-full relative ${activeTool && isCompact ? 'hidden' : 'flex-1 min-w-0'}`}>
          {/* Every terminal is rendered once, in this one keyed list under
              this one parent, whatever the layout: entering or leaving split
              view, crossing the compact breakpoint, or moving a terminal in
              or out of a pane only changes its wrapper's class and style.
              A different parent made React unmount the TerminalView, which
              closes its shell, and mount a new one (N-025). */}
          <div className={`absolute inset-0 ${splitOn ? `flex ${splitOrientation === "h" ? "flex-row" : "flex-col"}` : ""}`}>
            {terminals.map(t => {
              const slotIdx = splitOn ? splitTerminals.indexOf(t.id) : -1;
              const inSplit = slotIdx >= 0;
              const isFocused = activeTab === t.id;
              const notLast = inSplit && slotIdx < splitTerminals.length - 1;
              const wrapperClass = !splitOn
                ? `absolute inset-0 ${isFocused ? 'opacity-100 z-10' : 'opacity-0 z-0 pointer-events-none'}`
                : inSplit
                  ? `relative min-w-0 min-h-0 border ${
                      isFocused
                        ? "border-primary/40 shadow-[inset_0_0_0_1px_rgba(var(--primary),0.15)]"
                        : "border-white/[0.03]"
                    }`
                  // Not in the split: kept mounted, out of sight, so its shell
                  // and scrollback survive (the "compare" workflow swaps a
                  // partner in and out of a pane).
                  : "hidden";
              return (
                <div
                  key={t.id}
                  style={inSplit ? { flexGrow: splitRatios[slotIdx] ?? 1, flexBasis: 0, order: slotIdx } : undefined}
                  onMouseDown={inSplit ? () => setActiveTab(t.id) : undefined}
                  onTouchStart={inSplit ? () => setActiveTab(t.id) : undefined}
                  className={wrapperClass}
                >
                  <TerminalView
                    sessionId={session.id}
                    terminalId={t.id}
                    disabled={status !== 'connected'}
                    isActive={isFocused && (!splitOn || inSplit) && !(activeTool && isCompact)}
                    visible={(splitOn ? inSplit : isFocused) && !(activeTool && isCompact)}
                    suppressResize={toolResizing}
                    containerExec={t.container ? { container: t.container.name, useSudo: t.container.useSudo } : undefined}
                    connectionEpoch={connectionEpoch}
                    serverId={session.serverId}
                    serverName={session.serverName}
                    onExitTab={() => closeTerminalTab(t.id)}
                    onRestartSession={restartSession}
                    onEndedChange={(ended) => markTerminalEnded(t.id, ended)}
                  />
                  {inSplit && (
                    <>
                      {/* Per-pane detach affordance — pulls the pane out of
                          the split without killing the underlying terminal.
                          Positioned top-right so it doesn't fight the
                          divider (which lives on the pane's right/bottom
                          edge). Hidden until pane hover, tiny hit area. */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSplitTerminals(prev => prev.filter(id => id !== t.id));
                          setSplitRatios(prev => prev.filter((_, i) => i !== slotIdx));
                          // If the focused pane left the split, hand focus
                          // to whichever pane is left (or fall back to the
                          // orphan terminal itself).
                          if (isFocused) {
                            const remaining = splitTerminals.filter(id => id !== t.id);
                            setActiveTab(remaining[0] ?? t.id);
                          }
                        }}
                        title="Remove this pane from the split (keeps the terminal)"
                        className="absolute top-1 right-1 z-30 h-5 w-5 rounded flex items-center justify-center bg-black/40 border border-white/10 text-zinc-400 hover:text-white hover:bg-black/60 opacity-0 hover:opacity-100 group-hover/pane:opacity-100 transition-opacity"
                      >
                        <X size={11} />
                      </button>
                      {/* Divider between this pane and the next. Rendered
                          only when there IS a next pane — otherwise a
                          trailing divider would float in dead space. */}
                      {notLast && (
                        <div
                          onMouseDown={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            const container = e.currentTarget.parentElement?.parentElement;
                            if (!container) return;
                            const rect = container.getBoundingClientRect();
                            const total = splitOrientation === "h" ? rect.width : rect.height;
                            const startClient = splitOrientation === "h" ? e.clientX : e.clientY;
                            const sumGrow = splitRatios.reduce((a, b) => a + (b || 0), 0) || splitTerminals.length;
                            const pxPerUnit = total / sumGrow;
                            const startA = splitRatios[slotIdx] ?? 1;
                            const startB = splitRatios[slotIdx + 1] ?? 1;
                            const move = (ev: MouseEvent) => {
                              const client = splitOrientation === "h" ? ev.clientX : ev.clientY;
                              const deltaUnits = (client - startClient) / pxPerUnit;
                              // Redistribute between the two adjacent panes
                              // only — the rest of the row stays untouched.
                              // Clamp each so neither collapses below 0.3
                              // units (≈15% of the pair's original span).
                              const minPair = 0.3;
                              const combined = startA + startB;
                              const nextA = Math.max(minPair, Math.min(combined - minPair, startA + deltaUnits));
                              const nextB = combined - nextA;
                              setSplitRatios(prev => {
                                const copy = prev.slice();
                                copy[slotIdx] = nextA;
                                copy[slotIdx + 1] = nextB;
                                return copy;
                              });
                            };
                            const up = () => {
                              window.removeEventListener("mousemove", move);
                              window.removeEventListener("mouseup", up);
                            };
                            window.addEventListener("mousemove", move);
                            window.addEventListener("mouseup", up);
                          }}
                          onDoubleClick={(e) => {
                            e.stopPropagation();
                            // Reset all panes to equal share, not just this
                            // divider's pair — matches the "reset layout"
                            // idiom users expect from tmux/tiling WMs.
                            setSplitRatios(splitTerminals.map(() => 1));
                          }}
                          onContextMenu={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            setSplitOrientation(o => o === "h" ? "v" : "h");
                          }}
                          title="Drag to resize · double-click resets · right-click flips orientation"
                          className={`absolute z-20 bg-white/5 hover:bg-primary/40 transition-colors ${
                            splitOrientation === "h"
                              ? "top-0 bottom-0 right-0 w-1 cursor-col-resize"
                              : "left-0 right-0 bottom-0 h-1 cursor-row-resize"
                          }`}
                        />
                      )}
                    </>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Resizable divider — only useful when both panes are visible. */}
        {activeTool && !isCompact && (
          <div
            onMouseDown={startToolResize}
            className="w-1 shrink-0 cursor-col-resize bg-white/5 hover:bg-primary/40 transition-colors"
            title="Drag to resize"
          />
        )}

        {/* Tool side panel. MirrorsPanel stays mounted even when the user
            pops over to SFTP / Ports / CMDS so its live status, log, and
            event subscriptions don't reset every tool switch — a mirror in
            initial-sync used to "look like it restarted" because the React
            tree was torn down. Other tools still conditional-render: they
            don't carry live state worth preserving across switches. */}
        <div
          style={activeTool && !isCompact ? { width: `${toolPanelWidth}px` } : undefined}
          className={`${activeTool ? (isCompact ? 'flex-1 min-w-0' : 'shrink-0') : 'hidden'} bg-[#121214]/95 flex flex-col h-full overflow-hidden ${activeTool ? 'animate-in slide-in-from-right duration-300' : ''}`}
        >
          {activeTool === 'sftp' && (
            <div className="flex-1 flex flex-col overflow-hidden">
              <div className="h-10 px-4 flex items-center justify-between gap-3 border-b border-white/5 bg-white/5">
                <div className="flex items-center gap-3 min-w-0">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-zinc-400 shrink-0">SFTP File Browser</span>
                  <SepToggle
                    on={separateSftp}
                    onToggle={toggleSeparateSftp}
                    status={!separateSftp ? 'off' : sftpConnStatus === 'ready' ? 'ready' : sftpConnStatus === 'failed' ? 'failed' : 'pending'}
                    title="Run SFTP over its own dedicated SSH connection instead of sharing the terminal's session"
                    onReconnect={reconnectSftpConn}
                  />
                </div>
                <button onClick={() => changeActiveTool(null)} className="text-zinc-500 hover:text-white transition-colors shrink-0">
                  <X size={14} />
                </button>
              </div>
              <div className="flex-1 overflow-hidden relative">
                <SftpWorkspace
                  sessionId={session.id}
                  disabled={status !== 'connected'}
                  serverId={session.serverId}
                  mirrorsConfig={(() => {
                    try { return JSON.parse(session.mirrors || "[]"); } catch { return []; }
                  })()}
                />
              </div>
            </div>
          )}

          {activeTool === 'tunnels' && (
            <div className="flex-1 flex flex-col overflow-hidden">
              <div className="h-10 px-4 flex items-center justify-between gap-3 border-b border-white/5 bg-white/5">
                <div className="flex items-center gap-3 min-w-0">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-zinc-400 shrink-0">Port Forwarding</span>
                  <SepToggle
                    on={separateFwd}
                    onToggle={toggleSeparateFwd}
                    status={!separateFwd ? 'off' : fwdConnStatus === 'ready' ? 'ready' : fwdConnStatus === 'failed' ? 'failed' : 'pending'}
                    title="Run port-forwarding over its own dedicated SSH connection instead of sharing the terminal's session"
                    onReconnect={reconnectFwdConn}
                  />
                </div>
                <button onClick={() => changeActiveTool(null)} className="text-zinc-500 hover:text-white transition-colors shrink-0">
                  <X size={14} />
                </button>
              </div>
              <div className="flex-1 overflow-hidden relative">
                <TunnelsPanel sessionId={session.id} serverId={session.serverId} disabled={status !== 'connected'} />
              </div>
            </div>
          )}

          {activeTool === 'cmds' && (
            <CmdsPanel
              activeTab={activeTab}
              onClose={() => changeActiveTool(null)}
              serverId={session.serverId}
              serverName={session.serverName}
            />
          )}

          {/* InfoPanel stays mounted across tool switches so its cached
              probe result survives a SFTP-and-back trip — the user
              explicitly asked for "cache while session is alive", and a
              fresh remount would re-fire the probe every tab swap. */}
          <div className={`flex-1 flex flex-col overflow-hidden ${activeTool === 'info' ? '' : 'hidden'}`}>
            <div className="h-10 px-4 flex items-center justify-between border-b border-white/5 bg-white/5">
              <span className="text-[10px] font-bold uppercase tracking-wider text-zinc-400">Server Info</span>
              <button onClick={() => changeActiveTool(null)} className="text-zinc-500 hover:text-white transition-colors">
                <X size={14} />
              </button>
            </div>
            <InfoPanel
              sessionId={session.id}
              disabled={status !== 'connected' || !!terminalOnly}
              visible={activeTool === 'info'}
            />
          </div>

          {activeTool === 'docker' && (
            <div className="flex-1 flex flex-col overflow-hidden">
              <div className="h-10 px-4 flex items-center justify-between border-b border-white/5 bg-white/5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-zinc-400">Docker</span>
                <button onClick={() => changeActiveTool(null)} className="text-zinc-500 hover:text-white transition-colors">
                  <X size={14} />
                </button>
              </div>
              <div className="flex-1 overflow-y-auto custom-scrollbar p-3 select-text">
                <DockerTab
                  sessionId={session.id}
                  disabled={status !== 'connected'}
                  onOpenContainerTerminal={openContainerTerminal}
                />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );

};

/// Memoised export so a re-render in DesktopApp (sessionStatuses changing
/// when ANY session connects/reconnects/drops) doesn't cascade through
/// every other session subtree. The default shallow comparator is fine
/// because the parent now hands stable closures (`addLog`, `onClose`,
/// `onStatusChange`) and `session` only changes identity when the user
/// adds or edits a row.
export const SessionView = memo(SessionViewImpl);
