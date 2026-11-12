import { useEffect, useRef, useState } from "react";
import { TerminalSquare, X } from "lucide-react";
import TerminalView from "./TerminalView";

// Session-level wrapper for a local (non-SSH) shell tab. Deliberately NOT a
// branch inside SessionView.tsx — that component is ~1700 lines of SSH-shaped
// state (initiate_connection, connecting/connected/failed, SFTP/Docker/Ports/
// Info tool rail, clone tabs) none of which a local shell needs. Instead this
// mimics SessionView's OUTPUT CONTRACT toward DesktopApp.tsx — the same
// onStatusChange/onTerminalsChange callbacks, called with the same shapes —
// which is what lets every other DesktopApp.tsx feature that reads
// sessionStatuses[id]/sessionActiveTerm[id] (tab-strip status dots, "pin
// active terminal to Wall", the tab context menu, the warn-before-close
// logic in util/sessionClose.ts) keep working unmodified: they only ever
// consume those two callbacks, never SessionView itself.

interface LocalShellSession {
  id: string;
  serverName: string;
  localShell?: { shellIndex?: number; shellName?: string; cwd?: string };
}

interface SessionTerm { id: string; title: string; ended?: boolean }

interface Props {
  session: LocalShellSession;
  onClose: () => void;
  onStatusChange: (sessionId: string, status: string) => void;
  onTerminalsChange: (sid: string, terms: SessionTerm[], activeTermId: string) => void;
}

const LocalShellView = ({ session, onClose, onStatusChange, onTerminalsChange }: Props) => {
  // Stable across re-renders without needing its own state — one terminal
  // for the life of this session, no clone tabs (v1 scope).
  const terminalId = useRef(`local-term-${session.id}`).current;
  const [ended, setEnded] = useState(false);
  const title = session.localShell?.shellName || "Local Shell";

  // No handshake to wait on — report connected the instant this view mounts.
  // If the PTY spawn itself fails, TerminalView prints that inline (same
  // "Failed to open ..." treatment every other backend uses) rather than
  // this flipping to 'failed'; there's no separate connecting UI to recover
  // from here the way SessionView's retry banner handles an SSH failure.
  useEffect(() => {
    onStatusChange(session.id, 'connected');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.id]);

  useEffect(() => {
    onTerminalsChange(session.id, [{ id: terminalId, title, ended }], terminalId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.id, terminalId, title, ended]);

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden bg-[#09090b]">
      <div className="h-10 px-3 shrink-0 flex items-center justify-between border-b border-white/5 bg-white/[0.02]">
        <span className="flex items-center gap-2 min-w-0 flex-1 text-[11px] font-bold uppercase tracking-wider text-zinc-300">
          <TerminalSquare size={13} className="text-primary shrink-0" />
          <span className="truncate min-w-0">
            {session.serverName}
            {session.localShell?.cwd && (
              <span className="font-mono normal-case tracking-normal text-zinc-500 font-normal"> · {session.localShell.cwd}</span>
            )}
          </span>
        </span>
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
          serverName={session.serverName}
          localShell={session.localShell || {}}
          onExitTab={onClose}
          onEndedChange={setEnded}
        />
      </div>
    </div>
  );
};

export default LocalShellView;
