import { useEffect, useRef, useState } from "react";
import { Pin, Folder, ChevronDown, ChevronRight, PanelLeftClose } from "lucide-react";
import { profileKey } from "../util/profileStorage";

const MIN_WIDTH = 140;
const MAX_WIDTH = 360;
const DEFAULT_WIDTH = 192;
const WIDTH_KEY = "solanum-pinned-panel-width";

// Persistent column between the icon rail and whatever view is active
// (Sidebar just swaps activeView; this doesn't). The whole point: a pinned
// server is one click away from any screen, not just the sessions grid —
// unlike the grid's own folder drill-down, a pinned folder expands in place
// here instead of navigating anywhere.
//
// Open/closed is owned by the parent (DesktopApp) since both this panel's
// own collapse button AND a rail icon in Sidebar toggle the same boolean —
// this component is simply not mounted at all while closed, via `onCollapse`.
export const PinnedPanel = ({ servers, folders, onOpenServer, onCollapse }: any) => {
  const [width, setWidth] = useState<number>(() => {
    const stored = parseInt(localStorage.getItem(WIDTH_KEY) || "", 10);
    return Number.isFinite(stored) ? Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, stored)) : DEFAULT_WIDTH;
  });
  const resizing = useRef(false);
  const startX = useRef(0);
  const startWidth = useRef(width);
  const rafRef = useRef<number | null>(null);
  const pendingClientXRef = useRef(0);

  const beginResize = (e: React.PointerEvent) => {
    e.preventDefault();
    resizing.current = true;
    startX.current = e.clientX;
    startWidth.current = width;
  };

  // Attached to `window`, not just the handle, so a fast drag that briefly
  // leaves the handle's few pixels doesn't drop the resize — standard
  // pattern for a drag that isn't confined to one element's own bounds.
  useEffect(() => {
    const onMove = (e: PointerEvent) => {
      if (!resizing.current) return;
      // Coalesced to one setWidth (and re-render) per animation frame rather
      // than one per native pointermove — same throttling this codebase
      // already applies to its other pointer-drag interactions.
      pendingClientXRef.current = e.clientX;
      if (rafRef.current != null) return;
      rafRef.current = requestAnimationFrame(() => {
        rafRef.current = null;
        const next = Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, startWidth.current + (pendingClientXRef.current - startX.current)));
        setWidth(next);
      });
    };
    const onUp = () => {
      if (!resizing.current) return;
      resizing.current = false;
      if (rafRef.current != null) { cancelAnimationFrame(rafRef.current); rafRef.current = null; }
      // Persist only on release, not on every pixel of movement. The
      // functional updater reads the latest state without this closure
      // needing to be re-created on every width change.
      setWidth((current) => {
        try { localStorage.setItem(WIDTH_KEY, String(current)); } catch { /* per-viewer convenience only */ }
        return current;
      });
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
    };
  }, []);

  // Folders first, then servers, each group sorted alphabetically — chosen
  // over pinned_at recency ordering because a stable, predictable place to
  // look for a pinned item beats "wherever it landed based on when you
  // pinned it". pinned_at itself still exists purely to mark pinned vs not.
  const pinnedFolders = (folders || [])
    .filter((f: any) => f.pinned_at)
    .sort((a: any, b: any) => (a.name || "").localeCompare(b.name || ""));
  const pinnedFolderIds = new Set(pinnedFolders.map((f: any) => f.id));
  // Excludes servers whose folder is also pinned — that folder's own group
  // already lists them, so without this a server pinned both individually
  // and via its pinned folder would render twice.
  const pinnedServers = (servers || [])
    .filter((s: any) => s.pinned_at && !pinnedFolderIds.has(s.folder_id))
    .sort((a: any, b: any) => (a.name || "").localeCompare(b.name || ""));

  const ResizeHandle = () => (
    <div
      onPointerDown={beginResize}
      title="Drag to resize"
      className="absolute right-0 top-0 bottom-0 w-1.5 cursor-col-resize group/handle z-10"
      style={{ touchAction: "none" }}
    >
      <div className="w-px h-full mx-auto bg-transparent group-hover/handle:bg-primary/40 transition-colors" />
    </div>
  );

  if (pinnedServers.length === 0 && pinnedFolders.length === 0) {
    // Nothing pinned yet: a slim, low-noise hint rather than rendering
    // nothing at all — an empty region with no explanation is easy to miss
    // entirely, and this is meant to be discoverable.
    return (
      <aside style={{ width }} className="h-full bg-background border-r border-white/5 shrink-0 relative flex flex-col items-center justify-center px-3 text-center gap-2">
        <ResizeHandle />
        <Pin size={16} className="text-zinc-700" />
        <p className="text-[10.5px] text-zinc-600 leading-snug">Pin a server or folder to see it here.</p>
      </aside>
    );
  }

  return (
    <aside style={{ width }} className="h-full bg-background border-r border-white/5 shrink-0 relative flex flex-col overflow-hidden">
      <ResizeHandle />
      <div className="flex items-center justify-between px-3 h-10 shrink-0 border-b border-white/5">
        <span className="text-[10px] font-bold uppercase tracking-[0.12em] text-zinc-500 flex items-center gap-1.5">
          <Pin size={11} /> Pinned
        </span>
        {onCollapse && (
          <button
            onClick={onCollapse}
            title="Hide pinned (same as the sidebar icon)"
            className="p-1 rounded-md text-zinc-600 hover:text-zinc-300 hover:bg-white/5 transition-all"
          >
            <PanelLeftClose size={14} />
          </button>
        )}
      </div>
      <div className="flex-1 overflow-y-auto custom-scrollbar py-2 px-2 space-y-0.5">
        {pinnedFolders.map((f: any) => (
          <PinnedFolderGroup key={`pin-f-${f.id}`} folder={f} servers={servers} onOpenServer={onOpenServer} />
        ))}

        {pinnedServers.map((s: any) => (
          <button
            key={`pin-s-${s.id}`}
            onClick={() => onOpenServer(s)}
            className="w-full flex items-center gap-2 h-8 px-2 rounded-lg text-left hover:bg-white/5 transition-all group"
          >
            <span
              aria-hidden
              className="w-1.5 h-1.5 rounded-full shrink-0"
              style={{ background: s.color || "rgb(var(--primary))" }}
            />
            <span className="text-[12px] text-zinc-300 group-hover:text-white truncate">{s.name}</span>
          </button>
        ))}
      </div>
    </aside>
  );
};

const PinnedFolderGroup = ({ folder, servers, onOpenServer }: any) => {
  // Namespaced by profile — folder ids are per-vault autoincrement, so two
  // different profiles can share the same folder id, and without this a
  // collapse/expand choice made in one profile would leak into another's
  // vault that happens to reuse the same id (profileKey; cleared with the
  // profile, F-070).
  const storageKey = profileKey(`pinned-folder-expanded-${folder.id}`);
  const [expanded, setExpanded] = useState<boolean>(() => {
    if (!storageKey) return true;
    try {
      const v = localStorage.getItem(storageKey);
      return v === null ? true : v === "1"; // expanded by default — that's the whole point vs. the grid's drill-down
    } catch { return true; }
  });
  const toggle = () => {
    const next = !expanded;
    setExpanded(next);
    if (!storageKey) return;
    try { localStorage.setItem(storageKey, next ? "1" : "0"); } catch { /* per-viewer convenience only */ }
  };
  const children = (servers || []).filter((s: any) => s.folder_id === folder.id);

  return (
    <div>
      <button
        onClick={toggle}
        className="w-full flex items-center gap-1 h-8 px-1.5 rounded-lg text-left hover:bg-white/5 transition-all group"
      >
        {expanded ? <ChevronDown size={12} className="text-zinc-600 shrink-0" /> : <ChevronRight size={12} className="text-zinc-600 shrink-0" />}
        <Folder size={13} className="shrink-0" style={{ color: folder.color || undefined }} />
        <span className="text-[12px] font-bold text-zinc-300 group-hover:text-white truncate">{folder.name}</span>
      </button>
      {expanded && (
        <div className="ml-4 border-l border-white/5 pl-2 space-y-0.5">
          {children.length === 0 ? (
            <p className="text-[10.5px] text-zinc-600 italic py-1 px-2">Empty</p>
          ) : (
            children.map((s: any) => (
              <button
                key={`pin-f-${folder.id}-s-${s.id}`}
                onClick={() => onOpenServer(s)}
                className="w-full flex items-center gap-2 h-7 px-2 rounded-lg text-left hover:bg-white/5 transition-all group"
              >
                <span aria-hidden className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: s.color || "rgb(var(--primary))" }} />
                <span className="text-[11.5px] text-zinc-400 group-hover:text-white truncate">{s.name}</span>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
};
