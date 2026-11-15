import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Cable, RotateCw, X, Zap } from "lucide-react";
import TerminalView from "./TerminalView";

// Session-level wrapper for a serial server's tab (schema 7). Like
// LocalShellView, not a branch of SessionView: a serial port has no SSH
// connection, so none of SessionView's state applies. It keeps the same
// contract toward DesktopApp (onStatusChange / onTerminalsChange with the same
// shapes), so tab dots, the Wall, broadcast and the close question work
// unchanged. One terminal per port: a port opens once.
//
// The port and its settings are read by Rust from the vault (`serverId`);
// `serial` here is only for the header.

interface SerialSession {
  id: string;
  serverId: number;
  serverName: string;
  runOnConnect?: string;
  serial?: { port: string; summary: string };
}

interface SessionTerm { id: string; title: string; ended?: boolean }

interface Props {
  session: SerialSession;
  onClose: () => void;
  onStatusChange: (sessionId: string, status: string) => void;
  onTerminalsChange: (sid: string, terms: SessionTerm[], activeTermId: string) => void;
}

const SerialView = ({ session, onClose, onStatusChange, onTerminalsChange }: Props) => {
  const terminalId = useRef(`serial-term-${session.id}`).current;
  const [ended, setEnded] = useState(false);
  // Bumped by Reconnect: TerminalView opens the port again, keeping what the
  // terminal already shows (as after an SSH reconnect).
  const [epoch, setEpoch] = useState(0);
  const [breakNote, setBreakNote] = useState<{ text: string; error: boolean } | null>(null);
  const [breaking, setBreaking] = useState(false);
  const noteTimer = useRef<number | undefined>(undefined);
  const title = session.serial?.port || session.serverName;

  useEffect(() => {
    onStatusChange(session.id, ended ? 'disconnected' : 'connected');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.id, ended]);

  useEffect(() => {
    onTerminalsChange(session.id, [{ id: terminalId, title, ended }], terminalId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.id, terminalId, title, ended]);

  useEffect(() => () => window.clearTimeout(noteTimer.current), []);

  // The node's commands run on connect: typed once, after the first open
  // only (never after Reconnect), as SessionView does for SSH. Each line ends
  // with a carriage return, which is what Enter sends and what a console
  // (Cisco IOS, a boot loader) expects. Marked done when it fires, so the
  // development build's double mount does not swallow it.
  const ranOnConnect = useRef(false);
  useEffect(() => {
    const lines = (session.runOnConnect || '').split(/\r?\n/).map((l) => l.trimEnd()).filter((l) => l.trim().length > 0);
    if (lines.length === 0 || ranOnConnect.current) return;
    const timer = window.setTimeout(() => {
      if (ranOnConnect.current) return;
      ranOnConnect.current = true;
      const data = Array.from(new TextEncoder().encode(lines.map((l) => `${l}\r`).join('')));
      invoke('write_terminal_data', { terminalId, data }).catch(() => { /* the port did not open: its terminal says why */ });
    }, 1000);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // The tab menu's Reconnect: open a closed port again, or close an open one
  // and open it once it has closed (it is opened exclusively).
  const reopenAfterClose = useRef(false);
  useEffect(() => {
    const onReconnect = () => {
      if (ended) {
        setEpoch((n) => n + 1);
      } else {
        reopenAfterClose.current = true;
        invoke('close_terminal', { terminalId }).catch(() => { reopenAfterClose.current = false; });
      }
    };
    const name = `session-reconnect-${session.id}`;
    window.addEventListener(name, onReconnect);
    return () => window.removeEventListener(name, onReconnect);
  }, [session.id, terminalId, ended]);
  useEffect(() => {
    if (ended && reopenAfterClose.current) {
      reopenAfterClose.current = false;
      setEpoch((n) => n + 1);
    }
  }, [ended]);

  const showNote = (text: string, error: boolean) => {
    setBreakNote({ text, error });
    window.clearTimeout(noteTimer.current);
    noteTimer.current = window.setTimeout(() => setBreakNote(null), error ? 8000 : 2500);
  };

  const sendBreak = async () => {
    if (breaking || ended) return;
    setBreaking(true);
    try {
      await invoke('serial_send_break', { terminalId });
      showNote('Break sent', false);
    } catch (e) {
      showNote(String(e).replace(/^\[SERIAL\] [A-Z_]+: /, ''), true);
    } finally {
      setBreaking(false);
    }
  };

  const button = "h-6 px-2 shrink-0 flex items-center gap-1 rounded text-[10.5px] font-bold uppercase tracking-wider transition-all disabled:opacity-40 disabled:cursor-not-allowed";

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden bg-[#09090b]">
      <div className="h-10 px-3 shrink-0 flex items-center justify-between gap-2 border-b border-white/5 bg-white/[0.02]">
        <span className="flex items-center gap-2 min-w-0 flex-1 text-[11px] font-bold uppercase tracking-wider text-zinc-300">
          <Cable size={13} className="text-primary shrink-0" />
          <span className="truncate min-w-0">
            {session.serverName}
            {session.serial && (
              <span className="font-mono normal-case tracking-normal text-zinc-500 font-normal"> · {session.serial.port} · {session.serial.summary}</span>
            )}
          </span>
        </span>
        {breakNote && (
          <span className={`text-[10.5px] truncate min-w-0 max-w-[40%] ${breakNote.error ? 'text-rose-400' : 'text-emerald-400'}`} title={breakNote.text}>
            {breakNote.text}
          </span>
        )}
        {ended ? (
          <button
            onClick={() => setEpoch((n) => n + 1)}
            title="Open the port again"
            className={`${button} text-primary bg-primary/10 border border-primary/30 hover:bg-primary/20`}
          >
            <RotateCw size={11} /> Reconnect
          </button>
        ) : (
          <button
            onClick={sendBreak}
            disabled={breaking}
            title="Send a break (hold the line low for 300 ms), as a router's ROMMON or a console server expects"
            className={`${button} text-zinc-300 border border-white/10 hover:text-white hover:bg-white/10`}
          >
            <Zap size={11} /> Send break
          </button>
        )}
        <button
          onClick={onClose}
          title="Close"
          className="h-6 w-6 shrink-0 flex items-center justify-center rounded text-zinc-500 hover:text-white hover:bg-white/10 transition-all"
        >
          <X size={14} />
        </button>
      </div>
      <div className="flex-1 min-h-0">
        <TerminalView
          sessionId={session.id}
          terminalId={terminalId}
          serverId={session.serverId}
          serverName={session.serverName}
          serialPort={{ serverId: session.serverId }}
          connectionEpoch={epoch}
          onExitTab={onClose}
          onEndedChange={setEnded}
        />
      </div>
    </div>
  );
};

export default SerialView;
