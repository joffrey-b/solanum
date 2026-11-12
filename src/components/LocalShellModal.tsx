import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { TerminalSquare, X, FolderSearch } from "lucide-react";

// Local (non-SSH) shell tab. Deliberately minimal next to QuickConnectModal:
// no auth, no host — just which shell and an optional starting directory.
// The shells are the ones the backend lists (`list_local_shells`: the default
// login shell, then /etc/shells, or the system shells on Windows); the tab
// sends back an index, never a program path, and the backend asks for
// confirmation in a native dialog before it starts anything.

export interface LocalShellOpts {
  shellIndex: number;
  shellName: string;
  cwd?: string;
}

interface LocalShellInfo {
  name: string;
  path: string;
}

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onOpen: (opts: LocalShellOpts) => void;
}

const LocalShellModal = ({ isOpen, onClose, onOpen }: Props) => {
  const [shells, setShells] = useState<LocalShellInfo[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [shellIndex, setShellIndex] = useState(0);
  const [cwd, setCwd] = useState("");
  const [browsing, setBrowsing] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    let cancelled = false;
    setListError(null);
    invoke<LocalShellInfo[]>("list_local_shells")
      .then((list) => { if (!cancelled) { setShells(list); setShellIndex(0); } })
      .catch((e) => { if (!cancelled) { setShells([]); setListError(String(e)); } });
    return () => { cancelled = true; };
  }, [isOpen]);

  if (!isOpen) return null;

  const reset = () => { setShellIndex(0); setCwd(""); };
  const close = () => { reset(); onClose(); };

  const chosen = shells?.[shellIndex];
  const open = () => {
    if (!chosen) return;
    const opts: LocalShellOpts = {
      shellIndex,
      shellName: chosen.name,
      cwd: cwd.trim() || undefined,
    };
    reset();
    onOpen(opts);
  };

  const browse = async () => {
    setBrowsing(true);
    try {
      const picked = await invoke<string | null>("select_local_folder");
      if (picked) setCwd(picked);
    } catch { /* native dialog unavailable — field stays as-is */ }
    finally { setBrowsing(false); }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-3" onClick={close}>
      <div className="w-full max-w-md flex flex-col bg-[#121214] border border-white/10 rounded-xl shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="shrink-0 px-4 py-3 border-b border-white/5 flex items-center justify-between">
          <span className="text-[12px] font-bold uppercase tracking-widest text-white flex items-center gap-2">
            <TerminalSquare size={13} className="text-primary" /> Local Shell
          </span>
          <button onClick={close} className="text-zinc-400 hover:text-white"><X size={16} /></button>
        </div>

        <div className="p-5 space-y-3">
          <div className="space-y-1">
            <label className="text-[10px] font-bold text-zinc-300 uppercase tracking-wider ml-0.5">Shell</label>
            <select
              value={shellIndex}
              onChange={(e) => setShellIndex(Number(e.target.value))}
              disabled={!shells || shells.length === 0}
              className="w-full h-9 px-3 bg-zinc-900/60 border border-white/10 rounded-lg text-[12.5px] font-mono text-zinc-50 outline-none focus:border-primary/50 disabled:opacity-50"
              autoFocus
            >
              {shells === null && <option>Loading…</option>}
              {shells?.map((s, i) => (
                <option key={`${i}-${s.path}`} value={i}>{s.name}</option>
              ))}
            </select>
            {chosen && <p className="text-[10.5px] font-mono text-zinc-500 ml-0.5 truncate" title={chosen.path}>{chosen.path}</p>}
            {listError && <p className="text-[10.5px] text-rose-400 ml-0.5">{listError}</p>}
          </div>

          <div className="space-y-1">
            <label className="text-[10px] font-bold text-zinc-300 uppercase tracking-wider ml-0.5">Starting directory (optional)</label>
            <div className="flex items-center gap-2">
              <input
                value={cwd}
                onChange={(e) => setCwd(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && open()}
                placeholder="Leave blank for your home directory"
                className="flex-1 min-w-0 h-9 px-3 bg-zinc-900/60 border border-white/10 rounded-lg text-[12.5px] font-mono text-zinc-50 outline-none focus:border-primary/50"
              />
              <button
                onClick={browse}
                disabled={browsing}
                title="Choose folder"
                className="shrink-0 h-9 px-3 rounded-lg bg-white/[0.04] border border-white/10 text-zinc-300 hover:bg-white/10 flex items-center gap-1.5 text-[10.5px] font-bold uppercase tracking-wider disabled:opacity-40"
              >
                <FolderSearch size={12} /> Browse
              </button>
            </div>
          </div>

          <p className="text-[10.5px] text-zinc-400 leading-snug pt-1">
            Runs directly on this machine — no server, no SSH. Solanum asks you to confirm in a system dialog before it starts. Not saved anywhere; set these again next time.
          </p>
        </div>

        <div className="shrink-0 px-5 py-3 border-t border-white/5 flex items-center gap-2">
          <button
            onClick={open}
            disabled={!chosen}
            className="flex-1 h-10 rounded-lg text-[11.5px] font-bold uppercase tracking-wider bg-primary text-black hover:shadow-[0_0_20px_rgba(var(--primary),0.3)] flex items-center justify-center gap-2 disabled:opacity-40"
          >
            <TerminalSquare size={14} /> Open
          </button>
          <button onClick={close} className="h-10 px-4 rounded-lg text-[11.5px] font-bold uppercase tracking-wider bg-white/5 text-zinc-200 border border-white/10 hover:bg-white/10">
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
};

export default LocalShellModal;
