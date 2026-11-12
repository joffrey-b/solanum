import React, { useState, useEffect, useRef, useImperativeHandle, forwardRef } from "react";
import { createPortal } from "react-dom";
import { useTauriEvent } from "../hooks/useTauriEvent";
import { invoke } from "@tauri-apps/api/core";
import {
  Folder, File, ArrowUp, RefreshCw, Trash2, Edit3, Shield,
  X, ChevronUp, ChevronDown, Plus, MoreVertical, FolderSearch,
  Download, Upload, ExternalLink, Move, CheckSquare, Square, Search, Star,
} from "lucide-react";
import { FileEntry, FileProvider } from "../fs/types";
import { useConfirm, useOverwritePrompt, OverwriteChoice } from "../ui/confirm";
import { IS_ANDROID } from "../util/platform";
import { visibleName } from "../util/visibleName";
import { formatSize } from "../util/formatSize";

// Batch overwrite state shared across items in a single download/upload run.
// Once the user picks "Overwrite all" or "Skip all" the kind is sticky and we
// stop prompting; "ask" means we prompt on each individual conflict. Mutated
// in place inside the helper so the loop sees updates immediately.
type OverwriteBatchKind = "ask" | "overwrite-all" | "skip-all";
interface OverwriteBatch { kind: OverwriteBatchKind; }

// Backend errors carry a "[CODE] " prefix for the UI to branch on; the rest is
// the sentence to show.
const withoutCode = (err: unknown): string => String(err).replace(/^\[[A-Z_]+\]\s*/, "");

// Run a single transfer that may trip the backend's `EXISTS:<path>` sentinel.
// First attempt is always with overwrite=false unless the batch state already
// says "overwrite all". On EXISTS: consult batch state, prompt the user if
// needed, then either retry with overwrite=true or skip.
async function transferWithOverwriteCheck(
  invokeFn: (overwrite: boolean) => Promise<void>,
  name: string,
  direction: "download" | "upload",
  batchSize: number,
  batch: OverwriteBatch,
  overwritePrompt: (opts: { name: string; direction: "download" | "upload"; batchSize: number; isDir?: boolean }) => Promise<OverwriteChoice>,
  isDir: boolean = false,
): Promise<"done" | "skipped" | "cancelled"> {
  if (batch.kind === "overwrite-all") {
    await invokeFn(true);
    return "done";
  }
  try {
    await invokeFn(false);
    return "done";
  } catch (err: any) {
    const msg = String(err);
    if (!msg.startsWith("EXISTS:")) throw err;
    if (batch.kind === "skip-all") return "skipped";
    const choice = await overwritePrompt({ name, direction, batchSize, isDir });
    if (choice === "cancel") return "cancelled";
    if (choice === "skip") return "skipped";
    if (choice === "skip-all") { batch.kind = "skip-all"; return "skipped"; }
    if (choice === "overwrite-all") batch.kind = "overwrite-all";
    await invokeFn(true);
    return "done";
  }
}

// Generic two-mode file panel. Drives all I/O through a `FileProvider` so
// the same component renders either the local filesystem or the remote SFTP
// tree. Drag-out and drop integration are handled by the parent workspace —
// FilePanel just emits lifecycle callbacks.

type SortColumn = "name" | "size" | "modified" | "permissions";
interface SortState { column: SortColumn; asc: boolean; }

export interface ActiveDrag {
  paneId: "local" | "remote";
  entry: FileEntry;
  x: number;
  y: number;
}

export interface FilePanelProps {
  provider: FileProvider;
  /** True when the underlying session is disconnected — UI is dimmed and ops are blocked. */
  disabled?: boolean;
  /** Optional session id to scope OS drag-drop events (Tauri fires them globally). */
  sessionId?: string;
  /** Notifies the parent of an active cross-pane drag. */
  onDragMove: (drag: ActiveDrag | null) => void;
  /**
   * Optional starting directory. Overrides the provider's home. If listing it
   * fails (e.g. the saved dir was removed since last session), the panel falls
   * back to the provider's home without surfacing the error.
   */
  initialPath?: string;
  /** Fires after every successful navigation — workspace uses it to persist. */
  onPathChange?: (path: string) => void;
  /**
   * Live read of whatever directory the *other* pane is currently in. Wired
   * from SftpWorkspace via the sibling's FilePanelHandle. Used by the remote
   * pane's download action: if the local pane has a directory open, the
   * download lands there directly instead of popping a folder picker.
   */
  getOppositeDir?: () => string | undefined;
  /**
   * Refreshes the *other* pane's listing. Wired the same way as
   * getOppositeDir. A transfer changes what the opposite pane's current
   * directory contains (upload adds to it, download's source doesn't
   * change it — but download itself is initiated from the remote pane and
   * changes the LOCAL one) without that pane's own FilePanel instance
   * knowing anything happened, so without this its listing goes stale
   * until the user manually hits Refresh.
   */
  refreshOppositeDir?: () => void;
  /**
   * Bookmarked directories for this pane, and callbacks to add/remove one.
   * Owned by the parent workspace, same division of ownership as
   * initialPath/onPathChange: the remote list is scoped per-server, the
   * local one is a single list shared across every session (see
   * SftpWorkspace's useBookmarks calls).
   */
  bookmarks?: string[];
  onAddBookmark?: (path: string) => void;
  onRemoveBookmark?: (path: string) => void;
}

export interface FilePanelHandle {
  refresh: () => Promise<void>;
  currentDir: () => string;
}

const FilePanel = forwardRef<FilePanelHandle, FilePanelProps>(({
  provider,
  disabled = false,
  sessionId,
  onDragMove,
  initialPath,
  onPathChange,
  getOppositeDir,
  refreshOppositeDir,
  bookmarks,
  onAddBookmark,
  onRemoveBookmark,
}, ref) => {
  const [currentPath, setCurrentPath] = useState("");
  // Last five distinct directories visited in this panel, MRU first. Lives
  // in component state (cleared per session) — persistence didn't seem
  // worth the complexity given users usually want recents from this work
  // session, not whatever they were doing last week. Updated from `fetch`
  // when navigation succeeds.
  const [recentDirs, setRecentDirs] = useState<string[]>([]);
  const [recentOpen, setRecentOpen] = useState(false);
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [loading, setLoading] = useState(false);
  // Multi-selection lives as a Set of paths. Single-click replaces, Ctrl/⌘-
  // click toggles a row in/out, Shift-click extends from the last-clicked
  // anchor. lastSelectedPathRef remembers that anchor across renders.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const lastSelectedPathRef = useRef<string | null>(null);
  const [sort, setSort] = useState<SortState>({ column: "name", asc: true });

  const [tempInput, setTempInput] = useState("");
  const [inputFocused, setInputFocused] = useState(false);
  const [activeSuggestion, setActiveSuggestion] = useState(-1);
  // Path bar defaults to clickable breadcrumb segments (see `breadcrumbs`
  // below) so navigating up several levels doesn't mean hand-typing a path
  // — the raw text input (with its autocomplete) is still there, just
  // hidden until the user clicks into the bar, matching how VS Code's and
  // Nautilus's location bars toggle between the two.
  const [pathEditing, setPathEditing] = useState(false);
  const pathInputRef = useRef<HTMLInputElement>(null);
  // onBlur below delays closing the dropdown/edit mode so a click on a
  // suggestion has time to register first — but that's a bare setTimeout,
  // so refocusing the input inside that window (e.g. clicking straight back
  // in) must cancel it, or it fires later and yanks the user out of an
  // edit they're mid-typing.
  const pathBlurTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cancelPathBlurTimer = () => {
    if (pathBlurTimerRef.current) { clearTimeout(pathBlurTimerRef.current); pathBlurTimerRef.current = null; }
  };
  const startEditingPath = () => {
    cancelPathBlurTimer();
    setTempInput(currentPath);
    setPathEditing(true);
    requestAnimationFrame(() => pathInputRef.current?.focus());
  };
  // Shared exit for every path-editing dead end — Escape, a suggestion pick,
  // or Enter navigating — so the bar reliably drops back to breadcrumbs
  // instead of relying only on the input's own onBlur (which used to be the
  // sole way out, and didn't fire for Escape at all).
  const exitPathEditing = () => {
    cancelPathBlurTimer();
    setInputFocused(false);
    setPathEditing(false);
    setActiveSuggestion(-1);
  };
  // Name filter applied AFTER sort — substring, case-insensitive. Kept
  // separate from the path bar so the user can leave a filter active while
  // typing into the path. Sticky across `cd` so a quick filter session can
  // span sibling dirs; the X button or Escape on the input clears it.
  const [nameFilter, setNameFilter] = useState("");

  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; entry: FileEntry } | null>(null);
  const [modal, setModal] = useState<{ type: "rename" | "mkdir" | "properties" | "move" | "move-bulk"; entry?: FileEntry; v1?: string; v2?: string } | null>(null);
  const [notification, setNotification] = useState<{ msg: string; type: "info" | "success" | "error" } | null>(null);

  const [dragOver, setDragOver] = useState(false);
  const dropTargetRef = useRef<HTMLDivElement | null>(null);
  const menuRef = useRef<HTMLDivElement | null>(null);
  const currentPathRef = useRef(currentPath);
  useEffect(() => { currentPathRef.current = currentPath; }, [currentPath]);

  // Android quick-picker state. There is no OS-level folder picker that
  // returns a real filesystem path on Android (SAF returns content URIs
  // that Rust's std::fs can't open), so we replace the desktop rfd call
  // with a small popover of writable paths returned by the backend. Loaded
  // lazily the first time the user opens the popover so we don't burn a
  // touch-probe per directory on every panel mount.
  const [androidPickerOpen, setAndroidPickerOpen] = useState(false);
  const [androidQuickDirs, setAndroidQuickDirs] = useState<{ label: string; path: string }[] | null>(null);
  // True while the native "Upload…" file picker is open or its batch is
  // uploading — disables the button so a double-click can't stack two
  // native dialogs (and two independent upload batches) on top of each other.
  const [pickerBusy, setPickerBusy] = useState(false);

  // ---- helpers ----------------------------------------------------------------

  // Toasts quote names and backend errors, which may quote server-chosen paths.
  const notify = (msg: string, type: "info" | "success" | "error" = "info") => {
    setNotification({ msg: visibleName(msg), type });
    setTimeout(() => setNotification(null), 4000);
  };

  const formatRights = (isDir: boolean, perm?: number) => {
    if (perm === undefined) return isDir ? "d---------" : "----------";
    const r = (v: number) => (v & 4 ? "r" : "-");
    const w = (v: number) => (v & 2 ? "w" : "-");
    const x = (v: number) => (v & 1 ? "x" : "-");
    const u = (perm >> 6) & 7, g = (perm >> 3) & 7, o = perm & 7;
    return (isDir ? "d" : "-") + r(u) + w(u) + x(u) + r(g) + w(g) + x(g) + r(o) + w(o) + x(o);
  };

  const formatTime = (ts?: number) => {
    if (!ts) return "-";
    const d = new Date(ts * 1000);
    const pad = (n: number) => n.toString().padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };

  // ---- listing / navigation ---------------------------------------------------

  const pushRecent = (path: string) => {
    if (!path) return;
    setRecentDirs((prev) => {
      const next = [path, ...prev.filter((p) => p !== path)];
      return next.slice(0, 5);
    });
  };

  const fetch = async (path: string) => {
    setLoading(true);
    try {
      const result = await provider.list(path);
      setEntries(result.entries);
      setCurrentPath(result.currentPath);
      setTempInput(result.currentPath);
      setSelected(new Set());
      lastSelectedPathRef.current = null;
      onPathChange?.(result.currentPath);
      pushRecent(result.currentPath);
    } catch (err: any) {
      notify(`List failed: ${err}`, "error");
    } finally {
      setLoading(false);
    }
  };

  // Initial load: try the caller-supplied `initialPath` first (the
  // per-server-saved directory), and fall back to the provider's home if it
  // no longer exists — that way a saved path being removed doesn't strand
  // the user with an error screen.
  useEffect(() => {
    (async () => {
      const tryFetch = async (path: string) => {
        const result = await provider.list(path);
        setEntries(result.entries);
        setCurrentPath(result.currentPath);
        setTempInput(result.currentPath);
        setSelected(new Set());
      lastSelectedPathRef.current = null;
        onPathChange?.(result.currentPath);
        pushRecent(result.currentPath);
      };
      setLoading(true);
      try {
        if (initialPath) {
          try { await tryFetch(initialPath); return; }
          catch { /* fall through to home */ }
        }
        const home = await provider.homePath();
        await tryFetch(home);
      } catch (err: any) {
        notify(`Failed to load: ${err}`, "error");
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [provider]);

  useImperativeHandle(ref, () => ({
    refresh: () => fetch(currentPathRef.current),
    currentDir: () => currentPathRef.current,
  }), []);

  const goUp = () => fetch(provider.parentPath(currentPath));

  // ---- selection -------------------------------------------------------------

  // Three click modes match every desktop file manager people already know:
  //   - plain click  → replace selection with this row
  //   - Ctrl/⌘+click → toggle this row in / out of the existing set
  //   - Shift+click  → extend the range from the last anchor to this row
  // Shift-extend uses `sortedEntries` (the rendered order), not `entries`,
  // so the visual range matches what the user just dragged across.
  const onRowClick = (e: React.MouseEvent, entry: FileEntry, ordered: FileEntry[]) => {
    if (e.shiftKey && lastSelectedPathRef.current) {
      const a = ordered.findIndex(x => x.path === lastSelectedPathRef.current);
      const b = ordered.findIndex(x => x.path === entry.path);
      if (a >= 0 && b >= 0) {
        const [lo, hi] = a <= b ? [a, b] : [b, a];
        const range = ordered.slice(lo, hi + 1).map(x => x.path);
        setSelected(new Set([...selected, ...range]));
        return;
      }
    }
    if (e.ctrlKey || e.metaKey) {
      const next = new Set(selected);
      if (next.has(entry.path)) next.delete(entry.path);
      else next.add(entry.path);
      setSelected(next);
      lastSelectedPathRef.current = entry.path;
      return;
    }
    setSelected(new Set([entry.path]));
    lastSelectedPathRef.current = entry.path;
  };

  // Forward-walking autocomplete. As the user types a path, look at the
  // segment AFTER the last separator and prefix-match it against whichever
  // directory's listing applies. Three sources, in order of preference:
  //   1. typed path's parent matches the pane's current directory → use
  //      the already-loaded `entries` (free, no SFTP roundtrip).
  //   2. typed parent matches a previously-prefetched lookahead → reuse
  //      that cached listing.
  //   3. typed parent is somewhere else → kick a debounced provider.list
  //      to load it (effect below), then case 2 lights up.
  const [lookaheadParent, setLookaheadParent] = useState<string>("");
  const [lookaheadEntries, setLookaheadEntries] = useState<FileEntry[]>([]);

  // Split the typed input into (parent_dir, leaf_prefix) using either '/'
  // or '\' as the separator so Windows local paths work too.
  const splitInputPath = (input: string): { parent: string; leaf: string } | null => {
    const sep = Math.max(input.lastIndexOf('/'), input.lastIndexOf('\\'));
    if (sep < 0) return null;
    // Keep the trailing separator on the parent so "/var/" parses as
    // parent=/var/, leaf="" — that's what makes typing the slash trigger
    // a fresh listing of the directory below.
    const parent = input.substring(0, sep + 1);
    const leaf = input.substring(sep + 1);
    return { parent, leaf };
  };

  // Prefetch listings for typed paths outside the current directory. Debounced
  // so a fast typist doesn't fire one SFTP request per keystroke; skipped
  // when the typed parent already matches currentPath (free from `entries`).
  useEffect(() => {
    if (!inputFocused) return;
    const split = splitInputPath(tempInput);
    if (!split) return;
    // Normalize: most providers report paths without the trailing '/'.
    const probe = split.parent.replace(/[\\/]+$/, "") || "/";
    if (probe === currentPath || probe === lookaheadParent) return;
    const t = setTimeout(async () => {
      try {
        const result = await provider.list(probe);
        setLookaheadEntries(result.entries);
        setLookaheadParent(result.currentPath);
      } catch { /* parent doesn't exist (yet) — suggestions just stay empty */ }
    }, 220);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tempInput, inputFocused, currentPath]);

  const suggestions = (() => {
    if (!inputFocused) return [];
    const split = splitInputPath(tempInput);
    if (!split) return [];
    const probe = split.parent.replace(/[\\/]+$/, "") || "/";
    const source =
      probe === currentPath      ? entries :
      probe === lookaheadParent  ? lookaheadEntries :
                                   [];
    const leafLower = split.leaf.toLowerCase();
    return source.filter(e => e.name.toLowerCase().startsWith(leafLower));
  })();

  const pickSuggestion = (e: FileEntry) => {
    setTempInput(e.path);
    // Navigating (a directory) is a dead end for editing — drop back to
    // breadcrumbs the same as Enter does. Picking a file just fills in the
    // name for further typing, so editing stays open.
    if (e.isDir) { fetch(e.path); exitPathEditing(); }
    else setInputFocused(false);
  };

  // ---- context menu auto-close ------------------------------------------------

  useEffect(() => {
    if (!contextMenu) return;
    const onWindowMouseDown = (ev: MouseEvent) => {
      const target = ev.target as Node | null;
      if (target && menuRef.current?.contains(target)) return;
      setContextMenu(null);
    };
    const timer = setTimeout(() => window.addEventListener("mousedown", onWindowMouseDown), 50);
    return () => {
      clearTimeout(timer);
      window.removeEventListener("mousedown", onWindowMouseDown);
    };
  }, [contextMenu]);

  const openMenu = (e: React.MouseEvent, entry: FileEntry) => {
    e.preventDefault();
    e.stopPropagation();
    const MENU_W = 200, MENU_H = 320;
    const x = Math.min(e.clientX, window.innerWidth - MENU_W - 4);
    const y = Math.min(e.clientY, window.innerHeight - MENU_H - 4);
    // Right-click on a row that isn't already part of the selection should
    // switch focus to it (Explorer/Finder behaviour). Right-click on a row
    // that IS selected keeps the multi-selection so bulk actions apply.
    if (!selected.has(entry.path)) {
      setSelected(new Set([entry.path]));
      lastSelectedPathRef.current = entry.path;
    }
    setContextMenu({ x: Math.max(4, x), y: Math.max(4, y), entry });
  };

  // ---- drag-source -------------------------------------------------------------

  const DRAG_START_THRESHOLD = 6;

  const handleRowMouseDown = (e: React.MouseEvent, entry: FileEntry) => {
    if (disabled || e.button !== 0) return;

    const startX = e.clientX;
    const startY = e.clientY;
    let dragStarted = false;

    const onMove = (ev: MouseEvent) => {
      if (!dragStarted) {
        if (Math.abs(ev.clientX - startX) < DRAG_START_THRESHOLD &&
            Math.abs(ev.clientY - startY) < DRAG_START_THRESHOLD) return;
        dragStarted = true;
      }
      onDragMove({
        paneId: provider.id as "local" | "remote",
        entry,
        x: ev.clientX,
        y: ev.clientY,
      });
    };

    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      // Workspace listens for its own `mouseup` and uses the active drag (which
      // we keep up to date via `onDragMove`) to dispatch the cross-pane
      // transfer. We just clear our local indicator here.
      onDragMove(null);
    };

    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  // Live-edit toast. `sftp_open_remote_file` downloads the file to its own
  // private folder, opens it in the system editor, and watches that folder.
  // Every time the user saves a change, Rust pushes it back to the server
  // and emits `sftp-sync-status-{id}`. Surface the success path as a
  // notify() so the user sees their save actually landed; errors get the
  // full text from the backend. The end of syncing (disconnect, lock) is
  // reported app-wide instead (`live-edit-stopped`, DesktopApp): this panel
  // is usually gone by then.
  //
  // Same sessionId-means-two-things trap as the OS drag-drop listener
  // below: the local pane also carries a sessionId (for its own transfer
  // buttons), but this event is only ever emitted for a REMOTE live-edit
  // save — without the provider check both panes would subscribe and
  // every save would toast twice.
  const isRemotePane = !!sessionId && provider.id === "remote";

  // The files of this session being live-edited, with a Stop for each: the
  // list behind the toolbar's "Live edits" button. Refreshed when one opens,
  // syncs or ends.
  const [liveEdits, setLiveEdits] = useState<{ remotePath: string; name: string }[]>([]);
  const [liveEditsOpen, setLiveEditsOpen] = useState(false);
  const liveEditSupported = isRemotePane && !IS_ANDROID;
  const refreshLiveEdits = () => {
    if (!liveEditSupported) return;
    invoke<{ remotePath: string; name: string }[]>("live_edit_list", { sessionId })
      .then((list) => { setLiveEdits(list); if (list.length === 0) setLiveEditsOpen(false); })
      .catch((err) => notify(`Could not list the live edits: ${withoutCode(err)}`, "error"));
  };
  useEffect(() => { refreshLiveEdits(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [sessionId, liveEditSupported]);
  useTauriEvent(liveEditSupported ? "live-edit-stopped" : null, () => refreshLiveEdits());
  const stopLiveEdit = (remotePath: string) => {
    invoke("live_edit_stop", { sessionId, remotePath })
      .then(() => notify(`Stopped live edit of ${remotePath}`, "info"))
      .catch((err) => notify(`Not stopped: ${withoutCode(err)}`, "error"))
      .finally(refreshLiveEdits);
  };

  useTauriEvent<{ status: string; message?: string }>(
    isRemotePane ? `sftp-sync-status-${sessionId}` : null,
    (event) => {
      refreshLiveEdits();
      const { status, message } = event.payload || ({} as any);
      if (status === "success") {
        notify(message || "Changes uploaded", "success");
      } else if (status === "error") {
        notify(message || "Auto-sync failed", "error");
      } else if (status === "info") {
        notify(message || "", "info");
      }
    },
  );

  // ---- OS-level drag-drop into this pane --------------------------------------
  // Tauri 2 routes OS file drops through `tauri://drag-drop`; HTML5 drop events
  // fire too but their `File.path` is empty inside Tauri. We listen globally and
  // dispatch only when the cursor landed inside our root.

  // sessionId alone isn't "the remote pane" — the local pane carries one
  // too (its own transfer buttons need it), so without the provider check
  // this fires on BOTH panes and tries to sftp_upload_file using whatever
  // directory the LOCAL pane has open as if it were a remote path.
  useTauriEvent<{ paths: string[]; position: { x: number; y: number } }>(
    isRemotePane ? "tauri://drag-drop" : null,
    async (event) => {
      const { paths, position } = event.payload || ({} as any);
      if (!paths?.length || !dropTargetRef.current) return;
      const hit = document.elementFromPoint(position.x, position.y);
      if (!hit || !dropTargetRef.current.contains(hit)) return;
      setDragOver(false);
      const dir = currentPathRef.current;
      const batch: OverwriteBatch = { kind: "ask" };
      let cancelled = false;
      for (const p of paths) {
        if (cancelled) break;
        const name = p.split(/[\\/]/).pop() || "file";
        notify(`Uploading ${name}...`, "info");
        try {
          // The drag-drop event gives us raw paths with no metadata, so a
          // dropped folder needs its own stat before we know which
          // backend command applies — sftp_upload_dir (parent dir, no
          // name appended — it hangs the source basename underneath
          // itself) vs sftp_upload_file (full target path).
          let isDir = false;
          try { isDir = await invoke<boolean>("local_path_is_dir", { path: p }); }
          catch { /* stat failed — fall through and try the file path; the upload itself will surface a clear error */ }
          const res = isDir
            ? await transferWithOverwriteCheck(
                (ow) => invoke("sftp_upload_dir", { sessionId, localPath: p, remotePath: dir, overwrite: ow }),
                name, "upload", paths.length, batch, overwritePrompt, true
              )
            : await transferWithOverwriteCheck(
                (ow) => invoke("sftp_upload_file", {
                  sessionId, localPath: p,
                  remotePath: dir.endsWith("/") ? `${dir}${name}` : `${dir}/${name}`,
                  overwrite: ow,
                }),
                name, "upload", paths.length, batch, overwritePrompt, false
              );
          if (res === "done") notify(`Uploaded ${name}`, "success");
          if (res === "cancelled") { cancelled = true; notify("Upload batch cancelled", "info"); }
        } catch (err: any) {
          notify(`Upload failed: ${err}`, "error");
        }
      }
      await fetch(dir);
    },
  );

  // ---- modals -----------------------------------------------------------------

  const submitModal = async () => {
    if (!modal) return;
    const { type, entry, v1, v2 } = modal;
    try {
      if (type === "rename" && entry && v1) {
        const destDir = provider.parentPath(entry.path);
        const dest = provider.joinPath(destDir, v1);
        await provider.rename(entry.path, dest);
        notify(`Renamed to ${v1}`, "success");
      } else if (type === "move" && entry && v1) {
        // v1 is the destination *directory* the user typed (matches the
        // bulk-move semantics so users have a single mental model). We
        // append the entry's own name so the item keeps its filename. To
        // change the filename, the user picks "Rename" instead.
        const destDir = v1.replace(/[\\/]+$/, "");
        const dest = provider.joinPath(destDir, entry.name);
        if (dest === entry.path) throw new Error("Destination is the current location — nothing to move.");
        await provider.rename(entry.path, dest);
        notify(`Moved ${entry.name} → ${destDir}`, "success");
      } else if (type === "move-bulk" && v1) {
        // v1 is the destination *directory*; each selected item keeps its
        // own name under it.
        const dest = v1.replace(/[\\/]+$/, "");
        const items = sortedEntries.filter(e => selected.has(e.path));
        let count = 0;
        for (const it of items) {
          try {
            await provider.rename(it.path, provider.joinPath(dest, it.name));
            count++;
          } catch (err: any) {
            notify(`Move failed for ${it.name}: ${err}`, "error");
          }
        }
        if (count > 0) {
          setSelected(new Set());
          lastSelectedPathRef.current = null;
          notify(items.length === 1 ? `Moved ${items[0].name} → ${dest}` : `Moved ${count} of ${items.length} items → ${dest}`, "success");
        }
      } else if (type === "mkdir" && v1) {
        await provider.mkdir(provider.joinPath(currentPath, v1));
        notify(`Created ${v1}`, "success");
      } else if (type === "properties" && entry && v1 && provider.chmod) {
        // Only what was changed is sent. The dialog shows the rwx bits only,
        // so the setuid, setgid and sticky bits the item has are kept; the
        // group is never touched (the backend keeps the current one).
        const mode = parseInt(v1, 8);
        if (isNaN(mode)) throw new Error("Invalid octal mode");
        const shownMode = entry.permissions ? entry.permissions & 0o777 : 0o755;
        const uidText = (v2 ?? "").trim();
        const uidChanged = uidText !== "" && uidText !== (entry.uid?.toString() ?? "");
        if (uidChanged && !/^\d{1,10}$/.test(uidText)) throw new Error("Invalid owner UID");
        const uid = Number(uidText);
        if (uidChanged && uid > 0xffffffff) throw new Error("Invalid owner UID");
        let changed = false;
        if ((mode & 0o777) !== shownMode) {
          await provider.chmod(entry.path, ((entry.permissions ?? 0) & 0o7000) | (mode & 0o777));
          changed = true;
        }
        if (uidChanged && provider.chown) {
          await provider.chown(entry.path, uid);
          changed = true;
        }
        notify(changed ? "Properties updated" : "Nothing changed", changed ? "success" : "info");
      }
      await fetch(currentPath);
    } catch (err: any) {
      notify(`Failed: ${err}`, "error");
    } finally {
      setModal(null);
    }
  };

  // ---- removal ----------------------------------------------------------------

  const confirmDialog = useConfirm();
  const overwritePrompt = useOverwritePrompt();

  // Bulk-aware delete. Pops a single confirm dialog regardless of count, then
  // applies provider.remove to each item in turn — best-effort: per-item
  // failures notify but don't halt the rest. Selection is cleared on success
  // so the user isn't left with stale paths highlighted.
  const removeItems = async (items: FileEntry[]) => {
    if (items.length === 0) return;
    const ok = await confirmDialog({
      title: items.length === 1 ? "Delete item" : `Delete ${items.length} items`,
      message: items.length === 1
        ? (items[0].isDir
            ? `Permanently delete folder “${visibleName(items[0].name)}” and everything inside?`
            : `Permanently delete “${visibleName(items[0].name)}”?`)
        : `Permanently delete ${items.length} items? Folders include their contents.`,
      okLabel: "Delete",
      destructive: true,
    });
    if (!ok) return;
    let count = 0;
    for (const it of items) {
      try { await provider.remove(it.path, it.isDir); count++; }
      catch (err: any) { notify(`Delete failed for ${it.name}: ${err}`, "error"); }
    }
    if (count > 0) {
      setSelected(new Set());
      lastSelectedPathRef.current = null;
      notify(items.length === 1 ? `Deleted ${items[0].name}` : `Deleted ${count} of ${items.length} items`, "success");
      await fetch(currentPath);
    }
  };

  // ---- contextual actions -----------------------------------------------------

  // Remote → local download. Bulk-aware, folder-aware. Destination is
  // whatever the local pane is currently showing (`getOppositeDir`) — that's
  // almost always what the user wants and saves the round-trip through a
  // folder picker every single time. Only falls back to the native picker
  // if the sibling pane hasn't reported a directory yet (e.g. it's still
  // loading). Folders go through `sftp_download_dir` which walks the tree
  // and preserves structure; individual files go through the single-file
  // command. Both paths emit progress on the same `sftp-transfer-{id}`
  // channel so the user sees uniform cards.
  const downloadItems = async (items: FileEntry[]) => {
    if (!sessionId || items.length === 0) return;
    let dest = getOppositeDir?.();
    if (!dest) {
      // Fallback destination when the sibling pane hasn't reported a dir
      // yet. Desktop opens the rfd folder picker; Android has no picker
      // that returns a real filesystem path we can hand to Rust, so we
      // land in the app-visible default (Downloads or, if scoped storage
      // blocks it, app-scoped external files). Users can navigate from
      // there if they want a different subfolder.
      try {
        dest = IS_ANDROID
          ? ((await invoke<string>("android_default_local_dir")) || undefined)
          : ((await invoke<string | null>("select_local_folder")) || undefined);
      } catch (err: any) { notify(`Pick folder failed: ${err}`, "error"); return; }
      if (!dest) return;
    }
    const localDir = dest;
    const fileCount = items.filter(e => !e.isDir).length;
    const dirCount  = items.filter(e =>  e.isDir).length;
    const summary =
      items.length === 1
        ? `Downloading ${items[0].isDir ? "folder " : ""}${items[0].name}…`
        : `Downloading ${fileCount} files${dirCount ? ` + ${dirCount} folder${dirCount === 1 ? "" : "s"}` : ""}…`;
    notify(summary, "info");
    const batch: OverwriteBatch = { kind: "ask" };
    let count = 0;
    let cancelled = false;
    for (const e of items) {
      if (cancelled) break;
      // A real file name never contains "/" or NUL. The backend names the
      // local file after the last part of the path, so such a listing would
      // be saved (and asked about) under a different name than the one shown.
      if (e.name.includes("/") || e.name.includes("\0")) {
        notify(`Not downloaded: the server listed "${e.name}", which is not a single file name`, "error");
        continue;
      }
      try {
        // Only the folder is sent: the backend names the local file (or the
        // folder it creates) after the remote item and checks that name.
        const cmd = e.isDir ? "sftp_download_dir" : "sftp_download_file";
        const res = await transferWithOverwriteCheck(
          (ow) => invoke(cmd, { sessionId, remotePath: e.path, localDir, overwrite: ow }),
          e.name, "download", items.length, batch, overwritePrompt, e.isDir
        );
        if (res === "done") count++;
        if (res === "cancelled") { cancelled = true; }
      } catch (err: any) {
        notify(`Download failed for ${e.name}: ${err}`, "error");
      }
    }
    if (count > 0) {
      notify(items.length === 1 ? `Downloaded ${items[0].name}` : `Downloaded ${count} of ${items.length} items`, "success");
      // Refresh the local pane too — it's what actually received the
      // files, but this action runs from the remote pane's own FilePanel
      // instance, which has no other way to know the local listing changed.
      refreshOppositeDir?.();
    } else if (cancelled) {
      notify("Download batch cancelled", "info");
    }
  };

  // Local → remote upload. Mirror of downloadItems — handles both files
  // (sftp_upload_file) and directories (sftp_upload_dir recursive walk).
  // Destination is whatever directory the remote pane is showing; if the
  // remote pane hasn't reported one yet (still loading), we bail with a
  // clear error rather than guessing the home dir.
  const uploadItems = async (items: FileEntry[]) => {
    if (!sessionId || items.length === 0) return;
    const dest = getOppositeDir?.();
    if (!dest) { notify("Open a directory in the remote pane first.", "error"); return; }
    const trimmed = dest.replace(/[\\/]+$/, "");
    const fileCount = items.filter((e) => !e.isDir).length;
    const dirCount = items.filter((e) => e.isDir).length;
    const summary = items.length === 1
      ? `Uploading ${items[0].isDir ? "folder " : ""}${items[0].name}…`
      : `Uploading ${fileCount} file${fileCount === 1 ? "" : "s"}${dirCount ? ` + ${dirCount} folder${dirCount === 1 ? "" : "s"}` : ""}…`;
    notify(summary, "info");
    const batch: OverwriteBatch = { kind: "ask" };
    let count = 0;
    let cancelled = false;
    for (const e of items) {
      if (cancelled) break;
      try {
        // For files we pass the remote target as a full file path; for dirs
        // we pass the remote PARENT and sftp_upload_dir hangs the source
        // basename underneath it (same convention as sftp_download_dir).
        const remotePath = e.isDir ? trimmed : `${trimmed}/${e.name}`;
        const cmd = e.isDir ? "sftp_upload_dir" : "sftp_upload_file";
        const res = await transferWithOverwriteCheck(
          (ow) => invoke(cmd, { sessionId, localPath: e.path, remotePath, overwrite: ow }),
          e.name, "upload", items.length, batch, overwritePrompt, e.isDir
        );
        if (res === "done") count++;
        if (res === "cancelled") { cancelled = true; }
      } catch (err: any) {
        notify(`Upload failed for ${e.name}: ${err}`, "error");
      }
    }
    if (count > 0) {
      notify(items.length === 1 ? `Uploaded ${items[0].name}` : `Uploaded ${count} of ${items.length} items`, "success");
      // The remote pane's own FilePanel instance has no other way to learn
      // its listing just changed — this action runs from the local side.
      refreshOppositeDir?.();
    } else if (cancelled) {
      notify("Upload batch cancelled", "info");
    }
  };

  // Local pane's persistent "Upload…" button: picks file(s) via the native
  // OS dialog instead of requiring the user to first navigate this pane to
  // wherever the files happen to live, then select them. Desktop-only — see
  // select_local_files's own comment for why Android has no equivalent.
  const uploadViaPicker = async () => {
    if (pickerBusy) return; // guards against a double-click opening two native dialogs / upload batches at once
    setPickerBusy(true);
    try {
      let picked: string[];
      try {
        picked = await invoke<string[]>("select_local_files");
      } catch (err: any) { notify(`Pick files failed: ${err}`, "error"); return; }
      if (!picked.length) return;
      const items: FileEntry[] = picked.map((p) => ({
        path: p,
        // provider.pathSep, not a hardcoded [\\/] class: this pane is
        // always the LOCAL one (the only one that renders this button), so
        // splitting on both separators would wrongly treat a literal
        // backslash in a POSIX filename as a path separator and truncate it.
        name: p.slice(p.lastIndexOf(provider.pathSep) + 1) || p,
        isDir: false,
        size: 0,
      }));
      await uploadItems(items);
    } finally {
      setPickerBusy(false);
    }
  };

  // Remote: live edit. The backend downloads the file to a private temporary
  // folder, opens it (in the default app, or as plain text for a script the OS
  // would run), and uploads it back on every save. It asks first itself, in a
  // native dialog this webview cannot answer (Cancel is the default), and
  // refuses programs, installers and shortcuts outright: see open_guard.rs.
  // Resolves false when the user said no.
  const liveEditEntry = async (entry: FileEntry) => {
    if (!sessionId || entry.isDir) return;
    try {
      const opened = await invoke<boolean>("sftp_open_remote_file", { sessionId, remotePath: entry.path });
      if (opened) notify(`Opened ${entry.name}; saving it uploads your changes`, "info");
      refreshLiveEdits();
    } catch (err: any) {
      notify(`Not opened: ${withoutCode(err)}`, "error");
    }
  };

  // Local: open a file with its default app. The backend asks first in a native
  // dialog (the file may have come from a server) and never opens programs,
  // installers or shortcuts; for those it offers to show the file in its folder.
  const openLocalEntry = async (entry: FileEntry) => {
    if (entry.isDir) { fetch(entry.path); return; }
    try {
      await invoke<boolean>("local_open_file", { localPath: entry.path });
    } catch (err: any) {
      if (!String(err).startsWith("[OPEN_REFUSED]")) {
        notify(`Open failed: ${withoutCode(err)}`, "error");
        return;
      }
      const reveal = await confirmDialog({
        title: "Not opened",
        message: `"${visibleName(entry.name)}"\n\n${visibleName(withoutCode(err))}\n\nYou can show it in its folder instead.`,
        okLabel: "Show in folder",
        cancelLabel: "Close",
      });
      if (reveal) await revealLocalEntry(entry);
    }
  };

  // Local: reveal in OS file manager.
  const revealLocalEntry = async (entry: FileEntry) => {
    try {
      await invoke("local_open_in_explorer", { localPath: entry.path });
    } catch (err: any) {
      notify(`Reveal failed: ${err}`, "error");
    }
  };

  // ---- breadcrumbs --------------------------------------------------------------

  // Segments for the path bar's default display. Built by walking currentPath
  // upward via the SAME provider.parentPath() the Up button already uses,
  // rather than re-deriving segments from the raw string — that keeps this
  // correct for POSIX and Windows local paths (including drive roots) and
  // the always-POSIX remote provider without duplicating any path-parsing
  // logic. The two providers signal "reached the root" differently (local
  // returns "" past the top, remote returns "/" pointing at itself), so the
  // root check compares both after stripping trailing separators rather
  // than relying on either convention specifically.
  const breadcrumbs = (() => {
    const segments: { label: string; path: string }[] = [];
    const stripTrail = (s: string) => s.replace(/[\\/]+$/, "");
    let p = currentPath;
    let guard = 0;
    while (p && guard++ < 64) {
      const parent = provider.parentPath(p);
      const atRoot = !parent || stripTrail(parent) === stripTrail(p);
      const label = atRoot ? p : (p.slice(parent.length).replace(/^[\\/]+/, "") || p);
      segments.unshift({ label, path: p });
      if (atRoot) break;
      p = parent;
    }
    return segments;
  })();

  // ---- sorting ----------------------------------------------------------------

  const sortedEntries = (() => {
    const sorted = [...entries].sort((a, b) => {
      if (a.isDir !== b.isDir) return b.isDir ? 1 : -1;
      let va: any, vb: any;
      switch (sort.column) {
        case "name": va = a.name.toLowerCase(); vb = b.name.toLowerCase(); break;
        case "size": va = a.isDir ? -1 : a.size; vb = b.isDir ? -1 : b.size; break;
        case "modified": va = a.modified || 0; vb = b.modified || 0; break;
        case "permissions": va = a.permissions || 0; vb = b.permissions || 0; break;
      }
      if (va < vb) return sort.asc ? -1 : 1;
      if (va > vb) return sort.asc ? 1 : -1;
      return 0;
    });
    const needle = nameFilter.trim().toLowerCase();
    if (!needle) return sorted;
    return sorted.filter(e => e.name.toLowerCase().includes(needle));
  })();

  // ---- select-all -------------------------------------------------------------
  // Toggles the entire visible (sorted) list. Computed AFTER `sortedEntries`
  // so the const TDZ doesn't fire on first render. Cmd/Ctrl+A is the keyboard
  // counterpart; we let the browser handle Ctrl+A in text inputs by bailing
  // out when the focused element is editable.
  const selectAllVisible = () => {
    if (sortedEntries.length === 0) return;
    setSelected(new Set(sortedEntries.map(e => e.path)));
    lastSelectedPathRef.current = sortedEntries[sortedEntries.length - 1].path;
  };
  const clearSelection = () => {
    setSelected(new Set());
    lastSelectedPathRef.current = null;
  };
  const allSelected = sortedEntries.length > 0 && selected.size === sortedEntries.length;
  const toggleSelectAll = () => { allSelected ? clearSelection() : selectAllVisible(); };

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || e.key.toLowerCase() !== "a") return;
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.isContentEditable)) return;
      // Only fire when this panel owns the focus, so two side-by-side
      // FilePanel instances don't both select all on the same press.
      const root = dropTargetRef.current;
      if (root && document.activeElement && !root.contains(document.activeElement)) return;
      e.preventDefault();
      toggleSelectAll();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sortedEntries.length, allSelected]);

  const toggleSort = (col: SortColumn) =>
    setSort((p) => ({ column: col, asc: p.column === col ? !p.asc : true }));

  const sortIcon = (col: SortColumn) => {
    if (sort.column !== col) return null;
    return sort.asc
      ? <ChevronUp size={11} className="inline ml-1 text-indigo-400" />
      : <ChevronDown size={11} className="inline ml-1 text-indigo-400" />;
  };

  // ---- HTML5 dragover for visual feedback during OS-level drop ----------------

  const onDragOver = (e: React.DragEvent) => { e.preventDefault(); setDragOver(true); };
  const onDragLeave = (e: React.DragEvent) => { e.preventDefault(); setDragOver(false); };
  const onDrop = (e: React.DragEvent) => { e.preventDefault(); setDragOver(false); };

  const isRemote = provider.id === "remote";
  const showPerms = isRemote; // local entries don't carry perms here
  const isCurrentBookmarked = !!currentPath && !!bookmarks?.includes(currentPath);

  return (
    <div
      data-fs-pane={provider.id}
      data-fs-current-path={currentPath}
      className="flex-1 flex flex-col h-full bg-[#09090b] p-1.5 gap-1.5 overflow-hidden relative select-none"
    >
      {disabled && (
        <div className="absolute inset-0 z-30 bg-black/55 backdrop-blur-[1px] flex items-center justify-center text-zinc-300 text-xs font-mono uppercase">
          <span className="px-3 py-1.5 bg-red-500/15 border border-red-500/30 rounded text-red-300">
            Session disconnected
          </span>
        </div>
      )}

      {notification && (
        // Bottom-right of the pane, not top-right — top-right used to sit
        // on top of the path-bar header and obscure the first row of
        // entries on a short pane. Bottom keeps the file list visible.
        <div className={`absolute bottom-3 right-3 z-50 max-w-[80%] px-3 py-1.5 rounded-lg border text-[11px] font-mono shadow-2xl backdrop-blur-md animate-in fade-in slide-in-from-bottom-4 duration-300 ${
          notification.type === "success" ? "bg-emerald-950/90 border-emerald-500/30 text-emerald-400" :
          notification.type === "error"   ? "bg-rose-950/90 border-rose-500/30 text-rose-400" :
                                            "bg-indigo-950/90 border-indigo-500/30 text-indigo-400"
        }`}>{notification.msg}</div>
      )}

      {/* Header */}
      <div className="w-full flex items-center justify-between gap-1.5 p-1.5 bg-[#121214] border border-white/5 rounded-lg shrink-0 shadow-lg">
        <span className="text-[10px] font-black uppercase tracking-widest text-zinc-300 px-1.5 shrink-0">
          {provider.label}
        </span>
        <div className="h-5 w-px bg-white/10 shrink-0" />
        <div className="flex-1 flex items-center gap-1.5 min-w-0 relative">
          <button onClick={goUp} title="Up" className="p-1 rounded bg-white/[0.04] border border-white/10 text-zinc-200 hover:bg-white/10 shrink-0">
            <ArrowUp size={11} />
          </button>
          {bookmarks !== undefined && (
            <button
              onClick={() => isCurrentBookmarked ? onRemoveBookmark?.(currentPath) : onAddBookmark?.(currentPath)}
              disabled={!currentPath}
              title={isCurrentBookmarked ? "Remove bookmark" : "Bookmark this folder"}
              className={`p-1 rounded bg-white/[0.04] border border-white/10 hover:bg-white/10 shrink-0 disabled:opacity-30 disabled:cursor-not-allowed ${
                isCurrentBookmarked ? "text-amber-300" : "text-zinc-200"
              }`}
            >
              <Star size={11} className={isCurrentBookmarked ? "fill-amber-300" : ""} />
            </button>
          )}
          <div className="relative shrink-0">
            <button
              onClick={() => setRecentOpen((p) => !p)}
              onBlur={() => setTimeout(() => setRecentOpen(false), 200)}
              disabled={(bookmarks?.length ?? 0) === 0 && recentDirs.filter((p) => p !== currentPath).length === 0}
              title={bookmarks !== undefined ? "Bookmarked & recent directories" : "Recent directories"}
              className="p-1 rounded bg-white/[0.04] border border-white/10 text-zinc-200 hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed flex items-center"
            >
              <ChevronDown size={11} />
            </button>
            {recentOpen && (
              <div className="absolute top-[28px] left-0 z-50 min-w-[220px] max-h-[280px] overflow-y-auto bg-[#0c0c0e]/95 border border-white/10 rounded-lg shadow-2xl p-1 backdrop-blur-md font-mono text-[11px] text-zinc-200 no-scrollbar">
                {!!bookmarks?.length && (
                  <>
                    <div className="px-2 py-1 text-[9px] uppercase tracking-wider text-zinc-500 font-bold">Bookmarks</div>
                    {bookmarks.map((p) => (
                      <div key={p} className="w-full flex items-center rounded hover:bg-white/10 group">
                        <button
                          onMouseDown={(e) => { e.preventDefault(); setRecentOpen(false); fetch(p); }}
                          className="flex-1 min-w-0 flex items-center gap-2 p-1.5 text-left hover:text-white truncate"
                          title={visibleName(p)}
                        >
                          <Star size={11} className="text-amber-300 fill-amber-300 shrink-0" />
                          <span className="truncate">{visibleName(p)}</span>
                        </button>
                        <button
                          onMouseDown={(e) => { e.preventDefault(); onRemoveBookmark?.(p); }}
                          title="Remove bookmark"
                          className="p-1 mr-0.5 rounded text-zinc-500 hover:text-rose-300 hover:bg-white/10 shrink-0 opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity"
                        >
                          <X size={10} />
                        </button>
                      </div>
                    ))}
                  </>
                )}
                {recentDirs.filter((p) => p !== currentPath).length > 0 && (
                  <>
                    <div className="px-2 py-1 text-[9px] uppercase tracking-wider text-zinc-500 font-bold">Recent</div>
                    {recentDirs
                      .filter((p) => p !== currentPath)
                      .map((p) => (
                        <button
                          key={p}
                          onMouseDown={(e) => { e.preventDefault(); setRecentOpen(false); fetch(p); }}
                          className="w-full flex items-center gap-2 p-1.5 rounded text-left hover:bg-white/10 hover:text-white truncate"
                          title={visibleName(p)}
                        >
                          <Folder size={11} className="text-indigo-300 shrink-0" />
                          <span className="truncate">{visibleName(p)}</span>
                        </button>
                      ))}
                  </>
                )}
              </div>
            )}
          </div>
          {!pathEditing ? (
            // Default view: clickable breadcrumb segments. Clicking a segment
            // navigates straight there — no retyping the whole path just to
            // jump up a few levels. Clicking anywhere else in the bar (empty
            // space, or the bar itself when currentPath hasn't loaded yet)
            // drops into the same text input as before, for typing an exact
            // path or pasting one in.
            <div
              onClick={startEditingPath}
              title="Click to type a path"
              className="flex-1 h-6 px-1.5 bg-white/[0.04] border border-white/10 rounded flex items-center gap-0.5 overflow-x-auto no-scrollbar cursor-text whitespace-nowrap"
            >
              {breadcrumbs.length === 0 ? (
                <span className="text-zinc-500 text-[11px] font-mono">Path…</span>
              ) : breadcrumbs.map((crumb, i) => (
                <div key={crumb.path} className="flex items-center shrink-0">
                  {i > 0 && <span className="text-zinc-600 text-[10px] px-0.5 select-none">{provider.pathSep}</span>}
                  <button
                    onClick={(e) => { e.stopPropagation(); fetch(crumb.path); }}
                    className={`px-1 rounded text-[11px] font-mono hover:bg-white/10 hover:text-white ${
                      i === breadcrumbs.length - 1 ? "text-zinc-100 font-bold" : "text-zinc-400"
                    }`}
                  >
                    {visibleName(crumb.label)}
                  </button>
                </div>
              ))}
            </div>
          ) : (
          <div className="flex-1 relative">
            <input
              ref={pathInputRef}
              type="text"
              value={tempInput}
              onChange={(e) => { setTempInput(e.target.value); setActiveSuggestion(-1); }}
              onFocus={() => { cancelPathBlurTimer(); setInputFocused(true); }}
              onBlur={() => {
                pathBlurTimerRef.current = setTimeout(() => exitPathEditing(), 250);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  if (activeSuggestion >= 0 && activeSuggestion < suggestions.length) {
                    pickSuggestion(suggestions[activeSuggestion]);
                  } else {
                    const target = tempInput.trim();
                    if (target) {
                      // Drop back to breadcrumbs so the user clearly sees
                      // navigation kick off, and blur so browser default
                      // form-like behaviour doesn't kick in.
                      exitPathEditing();
                      (e.currentTarget as HTMLInputElement).blur();
                      fetch(target);
                    }
                  }
                } else if (e.key === "ArrowDown" && suggestions.length > 0) {
                  e.preventDefault(); setActiveSuggestion((p) => (p + 1) % suggestions.length);
                } else if (e.key === "ArrowUp" && suggestions.length > 0) {
                  e.preventDefault(); setActiveSuggestion((p) => (p - 1 + suggestions.length) % suggestions.length);
                } else if (e.key === "Escape") {
                  exitPathEditing();
                  (e.currentTarget as HTMLInputElement).blur();
                }
              }}
              placeholder="Path…"
              className="w-full h-6 px-2 bg-white/[0.04] border border-white/10 rounded text-[11px] text-zinc-100 font-mono focus:outline-none focus:border-indigo-400/50 focus:bg-white/10"
            />
            {inputFocused && suggestions.length > 0 && (
              <div className="absolute top-[28px] left-0 right-0 max-h-[220px] overflow-y-auto z-50 bg-[#0c0c0e]/95 border border-white/10 rounded-lg shadow-2xl p-1 backdrop-blur-md font-mono text-[11px] text-zinc-200 no-scrollbar">
                {suggestions.map((s, idx) => (
                  <button key={s.path} onClick={() => pickSuggestion(s)}
                    className={`w-full flex items-center justify-between p-1.5 rounded text-left transition-colors ${
                      idx === activeSuggestion ? "bg-indigo-500/30 text-white font-bold" : "hover:bg-white/5 hover:text-white"
                    }`}>
                    <div className="flex items-center gap-2 truncate">
                      {s.isDir ? <Folder size={11} className="text-indigo-300 shrink-0" /> : <File size={11} className="text-zinc-500 shrink-0" />}
                      <span className="truncate">{visibleName(s.name)}</span>
                    </div>
                    {s.isDir && <span className="text-[9px] bg-indigo-500/20 text-indigo-300 px-1 rounded">dir</span>}
                  </button>
                ))}
              </div>
            )}
          </div>
          )}
          <button onClick={() => fetch(currentPath)} title="Refresh"
            className={`p-1 rounded bg-white/[0.04] border border-white/10 text-zinc-200 hover:bg-white/10 shrink-0 ${loading ? "animate-spin" : ""}`}>
            <RefreshCw size={11} />
          </button>
        </div>
        <div className="h-5 w-px bg-white/10 shrink-0" />
        <div className="flex items-center gap-1 shrink-0 relative">
          {provider.id === "local" && (
            <button
              onClick={async () => {
                if (IS_ANDROID) {
                  // First open pulls the quick-dir list; subsequent opens
                  // reuse the cached list so scoped-storage probes don't
                  // rerun on every click.
                  if (!androidQuickDirs) {
                    try {
                      const dirs = await invoke<{ label: string; path: string }[]>("android_quick_dirs");
                      setAndroidQuickDirs(dirs);
                    } catch (err: any) {
                      notify(`Browse failed: ${err}`, "error");
                      return;
                    }
                  }
                  setAndroidPickerOpen((v) => !v);
                  return;
                }
                try {
                  const picked = await invoke<string | null>("select_local_folder");
                  if (picked) await fetch(picked);
                } catch (err: any) {
                  notify(`Browse failed: ${err}`, "error");
                }
              }}
              title="Browse for folder"
              className="p-1 rounded bg-white/[0.04] border border-white/10 text-emerald-300 hover:bg-white/10"
            >
              <FolderSearch size={11} />
            </button>
          )}
          {/* Persistent, always-visible transfer action — doesn't need a
              drag or a prior selection the way the floating bulk bar below
              does. Local picks file(s) via the native OS dialog (so the
              user doesn't have to navigate this pane to wherever the files
              already live) and uploads them to whatever directory the
              remote pane is showing; remote acts on the current selection
              since there's no OS-level picker into a server's filesystem. */}
          {provider.id === "local" && !IS_ANDROID && (
            <button
              onClick={uploadViaPicker}
              disabled={!sessionId || pickerBusy}
              title="Upload files…"
              className="p-1 rounded bg-white/[0.04] border border-white/10 text-sky-300 hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <Upload size={11} className={pickerBusy ? "animate-pulse" : ""} />
            </button>
          )}
          {isRemote && (
            <button
              onClick={() => downloadItems(sortedEntries.filter(e => selected.has(e.path)))}
              disabled={selected.size === 0}
              title={selected.size === 0
                ? "Select files to download"
                : getOppositeDir?.() ? `Download to ${getOppositeDir!()}` : "Pick a destination folder…"}
              className="p-1 rounded bg-white/[0.04] border border-white/10 text-emerald-300 hover:bg-white/10 disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <Download size={11} />
            </button>
          )}
          {liveEditSupported && liveEdits.length > 0 && (
            <button
              onClick={() => setLiveEditsOpen((v) => !v)}
              title="Files open for live edit: their saves are uploaded"
              className={`h-[22px] px-1.5 rounded border text-[10px] font-bold flex items-center gap-1 ${
                liveEditsOpen ? "bg-amber-500/20 border-amber-500/40 text-amber-200" : "bg-white/[0.04] border-white/10 text-amber-300 hover:bg-white/10"
              }`}
            >
              <Edit3 size={10} /> Live edits ({liveEdits.length})
            </button>
          )}
          {liveEditSupported && liveEditsOpen && liveEdits.length > 0 && (
            <div className="absolute top-[26px] right-0 z-50 w-[320px] max-h-[260px] overflow-y-auto bg-[#0c0c0e]/95 border border-white/10 rounded-lg shadow-2xl p-1 backdrop-blur-md font-mono text-[11px]">
              <div className="px-2 py-1 text-[9px] uppercase tracking-wider text-zinc-500 font-bold">
                Live edits · each save is uploaded until you stop it
              </div>
              {liveEdits.map((le) => (
                <div key={le.remotePath} className="flex items-center gap-2 p-1.5 rounded hover:bg-white/5">
                  <File size={11} className="text-amber-300 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="truncate text-zinc-200">{visibleName(le.name)}</div>
                    <div className="truncate text-[9.5px] text-zinc-500">{visibleName(le.remotePath)}</div>
                  </div>
                  <button
                    onClick={() => stopLiveEdit(le.remotePath)}
                    title="Upload a change still pending, then stop syncing this file"
                    className="shrink-0 h-6 px-2 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-500/10 border border-rose-500/30 text-rose-300 hover:bg-rose-500/20"
                  >
                    Stop
                  </button>
                </div>
              ))}
            </div>
          )}
          {IS_ANDROID && androidPickerOpen && androidQuickDirs && (
            <div className="absolute top-[24px] right-0 z-50 min-w-[180px] bg-[#0c0c0e]/95 border border-white/10 rounded-lg shadow-2xl p-1 backdrop-blur-md font-mono text-[11px]">
              {androidQuickDirs.length === 0 ? (
                <div className="p-2 text-zinc-400 text-[10.5px]">
                  No writable locations found. On Android 11+ shared storage
                  requires SAF — the app can only read/write its own scoped
                  storage directly.
                </div>
              ) : androidQuickDirs.map((d) => (
                <button
                  key={d.path}
                  onClick={() => { setAndroidPickerOpen(false); fetch(d.path); }}
                  className="w-full flex items-center gap-2 p-1.5 rounded text-left text-zinc-200 hover:bg-white/10 hover:text-white"
                >
                  <Folder size={11} className="text-indigo-300 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="truncate">{d.label}</div>
                    <div className="truncate text-[9.5px] text-zinc-500">{d.path}</div>
                  </div>
                </button>
              ))}
            </div>
          )}
          <button onClick={() => setModal({ type: "mkdir", v1: "" })} title="New Folder"
            className="p-1 rounded bg-white/[0.04] border border-white/10 text-indigo-300 hover:bg-white/10">
            <Folder size={11} />
          </button>
          <button
            onClick={toggleSelectAll}
            disabled={sortedEntries.length === 0}
            title={allSelected ? "Deselect all (Ctrl+A)" : "Select all (Ctrl+A)"}
            className={`p-1 rounded border border-white/10 hover:bg-white/10 disabled:opacity-30 ${
              allSelected
                ? "bg-indigo-500/20 text-indigo-200"
                : "bg-white/[0.04] text-zinc-300"
            }`}
          >
            {allSelected ? <CheckSquare size={11} /> : <Square size={11} />}
          </button>
        </div>
      </div>

      {/* Filter row — always visible, narrow (24 px). Lets the user trim
          the rendered list by name without touching sort or the path bar.
          Sticky across cd so they can hunt the same name across sibling
          dirs; the X clears, Esc on the input clears too. */}
      <div className="shrink-0 flex items-center gap-1 px-2 py-1 bg-[#0e0e10] border border-white/5 rounded text-[10.5px] font-mono">
        <Search size={11} className="text-zinc-500 shrink-0" />
        <input
          type="text"
          value={nameFilter}
          onChange={(e) => setNameFilter(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Escape") { setNameFilter(""); (e.currentTarget as HTMLInputElement).blur(); } }}
          placeholder="Filter by name…"
          className="flex-1 min-w-0 h-5 bg-transparent text-zinc-100 placeholder:text-zinc-600 focus:outline-none"
        />
        {nameFilter && (
          <>
            <span className="text-[9.5px] text-zinc-500 shrink-0">
              {sortedEntries.length}/{entries.length}
            </span>
            <button
              onClick={() => setNameFilter("")}
              title="Clear filter"
              className="shrink-0 p-0.5 rounded text-zinc-400 hover:text-white hover:bg-white/10"
            >
              <X size={10} />
            </button>
          </>
        )}
      </div>

      {/* Bulk action bar — shows for any non-empty selection so the user can
          send / move / delete with one click without right-clicking. It is a
          FLOATING overlay (absolute, pinned bottom-center) rather than a flex
          sibling, so its appearance never pushes the file list down — the rows
          stay exactly where they are when a selection starts. */}
      {selected.size > 0 && (
        <div className="absolute bottom-3 left-1/2 -translate-x-1/2 z-20 max-w-[calc(100%-1rem)] flex flex-wrap items-center justify-center gap-1.5 px-2.5 py-1.5 bg-indigo-950/95 border border-indigo-500/40 rounded-lg shadow-2xl shadow-black/50 backdrop-blur-md text-[10.5px] text-indigo-100 font-mono">
          <span className="font-bold uppercase tracking-wider text-[9.5px] text-indigo-300 shrink-0">
            {selected.size} selected
          </span>
          <div className="flex-1" />
          {/* Remote's Download is covered by the persistent header button
              above — no need to repeat it here too. Local keeps its own
              Upload since it's a distinct action from the header's
              picker-based one (this uploads what's already selected in
              THIS pane, not freshly-chosen files). */}
          {!isRemote && (
            <button
              onClick={() => uploadItems(sortedEntries.filter(e => selected.has(e.path)))}
              title={getOppositeDir?.()
                ? `Upload to ${getOppositeDir!()}`
                : "Open a remote directory first…"}
              disabled={!getOppositeDir?.()}
              className="px-2 py-0.5 rounded bg-sky-500/15 text-sky-300 hover:bg-sky-500/25 flex items-center gap-1 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Upload size={10} /> Upload
            </button>
          )}
          <button
            onClick={() => setModal({ type: "move-bulk", v1: currentPath })}
            className="px-2 py-0.5 rounded bg-white/5 text-zinc-200 hover:bg-white/10 flex items-center gap-1"
          >
            <Move size={10} /> Move…
          </button>
          <button
            onClick={() => removeItems(sortedEntries.filter(e => selected.has(e.path)))}
            className="px-2 py-0.5 rounded bg-rose-500/15 text-rose-300 hover:bg-rose-500/25 flex items-center gap-1"
          >
            <Trash2 size={10} /> Delete
          </button>
          <button
            onClick={() => { setSelected(new Set()); lastSelectedPathRef.current = null; }}
            className="px-2 py-0.5 rounded bg-white/5 text-zinc-400 hover:bg-white/10 flex items-center gap-1"
          >
            <X size={10} /> Clear
          </button>
        </div>
      )}

      {/* List */}
      <div
        ref={dropTargetRef}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onDrop={onDrop}
        className={`flex-1 border rounded-lg bg-[#121214] flex flex-col overflow-auto transition-all duration-200 border-indigo-500/30 shadow-2xl shadow-indigo-950/10 ${dragOver ? "border-indigo-400 bg-indigo-950/10" : ""}`}
      >
        {/* The select column is conditionally injected — only present when
            there's at least one selected row. With nothing selected the row
            content reclaims the 22px and the list reads cleanly. Discovery
            paths into multi-select that work without the column visible:
            row click (single select), Ctrl/Shift-click (extend), Ctrl+A
            (select all), right-click → context menu, and the header bar's
            select-all toggle to the right of the address bar. */}
        <div className={`group min-w-full grid ${
          showPerms
            ? "grid-cols-[22px_1fr] sm:grid-cols-[22px_minmax(180px,1fr)_65px_115px_85px]"
            : "grid-cols-[22px_1fr] sm:grid-cols-[22px_minmax(180px,1fr)_75px_125px]"
        } gap-1.5 px-2.5 bg-[#161619] border-b border-white/5 font-mono text-[10.5px] text-zinc-300 select-none font-bold shrink-0 sticky top-0 z-10 shadow-md`}>
          {/* Select-all — the 22px column is ALWAYS reserved (both here and in
              every row) so starting a selection never shifts the columns
              sideways. The control is revealed on header hover, or whenever a
              selection is already active. */}
          <div
            className={`bg-[#161619] flex items-center justify-center py-1.5 cursor-pointer hover:text-white transition-opacity ${selected.size > 0 ? "opacity-100" : "opacity-0 group-hover:opacity-100"}`}
            onClick={(e) => { e.stopPropagation(); toggleSelectAll(); }}
            title={allSelected ? "Deselect all" : "Select all"}
          >
            {allSelected ? <CheckSquare size={12} className="text-indigo-300" /> : <Square size={12} className="text-zinc-500" />}
          </div>
          <div className="bg-[#161619] cursor-pointer hover:text-white py-1.5" onClick={() => toggleSort("name")}>
            NAME {sortIcon("name")}
          </div>
          <div className="hidden sm:block bg-[#161619] cursor-pointer hover:text-white text-right py-1.5" onClick={() => toggleSort("size")}>
            SIZE {sortIcon("size")}
          </div>
          <div className="hidden sm:block bg-[#161619] cursor-pointer hover:text-white text-right py-1.5" onClick={() => toggleSort("modified")}>
            CHANGED {sortIcon("modified")}
          </div>
          {showPerms && (
            <div className="hidden sm:block bg-[#161619] cursor-pointer hover:text-white text-right py-1.5" onClick={() => toggleSort("permissions")}>
              RIGHTS {sortIcon("permissions")}
            </div>
          )}
        </div>

        <div className="min-w-full p-1 font-mono text-[11px]"
             onClick={(e) => {
               // Click landed on the bare list background (not on a row, since
               // rows stopPropagation via their own onClick chain implicitly
               // by being the click target). Clear selection so users can
               // escape a multi-selection without a keyboard shortcut.
               if (e.target === e.currentTarget) {
                 setSelected(new Set());
                 lastSelectedPathRef.current = null;
               }
             }}>
          {loading && sortedEntries.length === 0 ? (
            <div className="text-center py-14 text-zinc-400">Loading…</div>
          ) : sortedEntries.length === 0 ? (
            <div className="text-center py-14 text-zinc-500">Empty</div>
          ) : (
            sortedEntries.map((entry) => {
              const isSel = selected.has(entry.path);
              return (
              <div
                key={entry.path}
                onMouseDown={(e) => handleRowMouseDown(e, entry)}
                onContextMenu={(e) => openMenu(e, entry)}
                onClick={(e) => onRowClick(e, entry, sortedEntries)}
                onDoubleClick={() => {
                  if (entry.isDir) { fetch(entry.path); return; }
                  // For files: remote → live-edit (download + open editor +
                  // auto-upload on save); local → open in the OS default app.
                  // Both are desktop-only — on Android a double-tap on a file
                  // is a no-op (there's no OS default editor to hand off to).
                  if (IS_ANDROID) return;
                  if (isRemote) liveEditEntry(entry);
                  else openLocalEntry(entry);
                }}
                data-fs-row-path={entry.path}
                data-fs-row-isdir={entry.isDir ? "1" : "0"}
                className={`group grid ${
                  showPerms
                    ? "grid-cols-[22px_1fr] sm:grid-cols-[22px_minmax(180px,1fr)_65px_115px_85px]"
                    : "grid-cols-[22px_1fr] sm:grid-cols-[22px_minmax(180px,1fr)_75px_125px]"
                } gap-1.5 px-2.5 py-1 border-l-2 cursor-pointer transition-colors items-center ${
                  isSel
                    ? "bg-indigo-950/40 border-indigo-400 text-indigo-100 font-bold"
                    : "border-transparent text-zinc-200 hover:bg-white/5 hover:text-white"
                }`}
              >
                {/* Per-row checkbox. Its 22px column is always reserved, so the
                    box appearing never shifts the row's content sideways. Hidden
                    at rest, revealed on row hover or whenever a selection is
                    already active (so any row can be toggled). */}
                <div
                  className={`flex items-center justify-center transition-opacity ${isSel || selected.size > 0 ? "opacity-100" : "opacity-0 group-hover:opacity-100"}`}
                  onMouseDown={(e) => e.stopPropagation()}
                  onClick={(e) => {
                    // Pure toggle for this row — doesn't replace the
                    // selection the way a bare row click does. Keeps
                    // existing selection intact and just flips this entry
                    // in/out.
                    e.stopPropagation();
                    const next = new Set(selected);
                    if (next.has(entry.path)) next.delete(entry.path);
                    else next.add(entry.path);
                    setSelected(next);
                    lastSelectedPathRef.current = entry.path;
                  }}
                  title={isSel ? "Deselect" : "Select"}
                >
                  {isSel
                    ? <CheckSquare size={12} className="text-indigo-300" />
                    : <Square size={12} className="text-zinc-500 hover:text-zinc-300" />}
                </div>
                <div className="flex items-center gap-2 min-w-0 pr-1">
                  {entry.isDir
                    ? <Folder size={12} className="text-indigo-300 shrink-0" />
                    : <File size={12} className="text-zinc-500 shrink-0" />}
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-zinc-100 text-[11px]">{visibleName(entry.name)}</div>
                    {/* Narrow-viewport subline: on < sm the SIZE / CHANGED /
                        RIGHTS cells are display:none (so they don't force
                        horizontal scroll), and their info collapses into
                        this muted second line under the filename. */}
                    <div className="sm:hidden truncate text-[10px] text-zinc-500 font-mono">
                      {[
                        entry.isDir ? null : formatSize(entry.size),
                        formatTime(entry.modified),
                        showPerms ? formatRights(entry.isDir, entry.permissions) : null,
                      ].filter(Boolean).join(" · ")}
                    </div>
                  </div>
                </div>
                <div className="hidden sm:block text-right text-[10.5px] text-zinc-300 font-sans">
                  {entry.isDir ? "" : formatSize(entry.size)}
                </div>
                <div className="hidden sm:block text-right text-[9.5px] text-zinc-400 truncate">
                  {formatTime(entry.modified)}
                </div>
                {showPerms && (
                  <div className="hidden sm:flex text-right text-[10.5px] text-zinc-300 font-mono opacity-90 items-center justify-end gap-1">
                    <span className="truncate">{formatRights(entry.isDir, entry.permissions)}</span>
                    <button onClick={(e) => openMenu(e, entry)} title="Options"
                      className="opacity-60 hover:opacity-100 p-0.5 rounded hover:bg-white/10 text-zinc-400 hover:text-white shrink-0">
                      <MoreVertical size={11} />
                    </button>
                  </div>
                )}
              </div>
              );
            })
          )}
        </div>
      </div>

      {/* Context menu (portal) — bulk-aware. When the right-click anchor is
          part of a multi-selection, actions like Download / Move / Delete
          apply to the whole set; per-item actions (Rename, Properties,
          Edit) only show when exactly one row is selected. */}
      {contextMenu && createPortal((() => {
        const selectedEntries = sortedEntries.filter(e => selected.has(e.path));
        const acting = selectedEntries.length > 0 ? selectedEntries : [contextMenu.entry];
        const multi = acting.length > 1;
        const selectedFileCount = acting.filter(e => !e.isDir).length;
        return (
        <div ref={menuRef}
          style={{ top: contextMenu.y, left: contextMenu.x }}
          className="fixed z-[9999] min-w-[180px] bg-[#0c0c0e] border border-white/10 rounded-lg shadow-2xl p-1 backdrop-blur-md font-mono text-[11.5px] text-zinc-200">

          {/* Primary action: open folder, or transfer/edit file. The exact
              set depends on which side this panel is on. */}
          {contextMenu.entry.isDir && !multi ? (
            <button onClick={() => { setContextMenu(null); fetch(contextMenu.entry.path); }}
              className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-white/10 text-left hover:text-white">
              <Folder size={11} className="text-indigo-400" /><span>Open</span>
            </button>
          ) : isRemote ? (
            <>
              <button onClick={() => { setContextMenu(null); downloadItems(acting); }}
                className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-white/10 text-left hover:text-white">
                <Download size={11} className="text-emerald-400" />
                <span>Download{multi ? ` (${selectedFileCount})` : "…"}</span>
              </button>
              {/* Live-edit needs a local temp file + a native OS editor + a
                  filesystem watcher. Android has none of those in a form we
                  can bridge, so the backend command returns an error there
                  — hide the menu item entirely rather than surface it. */}
              {!multi && !contextMenu.entry.isDir && !IS_ANDROID && (
                <button onClick={() => { setContextMenu(null); liveEditEntry(contextMenu.entry); }}
                  className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-white/10 text-left hover:text-white">
                  <ExternalLink size={11} className="text-indigo-400" /><span>Edit (auto-upload)</span>
                </button>
              )}
            </>
          ) : (
            !multi && !contextMenu.entry.isDir && !IS_ANDROID && (
              <button onClick={() => { setContextMenu(null); openLocalEntry(contextMenu.entry); }}
                className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-white/10 text-left hover:text-white">
                <ExternalLink size={11} className="text-indigo-400" /><span>Open</span>
              </button>
            )
          )}

          {!isRemote && !multi && !IS_ANDROID && (
            <button onClick={() => { setContextMenu(null); revealLocalEntry(contextMenu.entry); }}
              className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-white/10 text-left hover:text-white">
              <FolderSearch size={11} className="text-emerald-300" /><span>Reveal in Explorer</span>
            </button>
          )}

          <div className="h-px bg-white/5 my-1" />

          <button onClick={() => { setContextMenu(null); setModal({ type: "mkdir", v1: "" }); }}
            className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-white/10 text-left hover:text-white">
            <Plus size={11} className="text-indigo-300" /><span>New Folder</span>
          </button>
          {!multi && (
            <button onClick={() => { setContextMenu(null); setModal({ type: "rename", entry: contextMenu.entry, v1: contextMenu.entry.name }); }}
              className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-white/10 text-left hover:text-white">
              <Edit3 size={11} /><span>Rename</span>
            </button>
          )}
          <button onClick={() => {
              setContextMenu(null);
              // Both single and bulk move ask for a destination *directory*
              // (we auto-append the original name). Defaulting v1 to the
              // current path means the user only edits the directory part —
              // no chance to fat-finger the filename and rename by accident.
              if (multi) setModal({ type: "move-bulk", v1: currentPath });
              else setModal({ type: "move", entry: contextMenu.entry, v1: currentPath });
            }}
            className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-white/10 text-left hover:text-white">
            <Move size={11} /><span>{multi ? `Move (${acting.length}) to…` : "Move to…"}</span>
          </button>
          {!multi && provider.chmod && (
            <button onClick={() => { setContextMenu(null); setModal({ type: "properties", entry: contextMenu.entry, v1: (contextMenu.entry.permissions ? (contextMenu.entry.permissions & 0o777).toString(8) : "755"), v2: contextMenu.entry.uid?.toString() }); }}
              className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-white/10 text-left hover:text-white">
              <Shield size={11} /><span>Properties</span>
            </button>
          )}

          <div className="h-px bg-white/5 my-1" />
          <button onClick={() => { setContextMenu(null); removeItems(acting); }}
            className="w-full flex items-center gap-2 p-1.5 rounded hover:bg-rose-950/20 text-left text-rose-400">
            <Trash2 size={11} /><span>Delete{multi ? ` (${acting.length})` : ""}</span>
          </button>
        </div>
        );
      })(),
        document.body
      )}

      {/* Modal */}
      {modal && (
        <div className="fixed inset-0 z-[9998] bg-black/60 backdrop-blur-sm flex items-center justify-center p-4" onClick={() => setModal(null)}>
          <div onClick={(e) => e.stopPropagation()}
            className="w-full max-w-[320px] bg-[#121214] border border-white/5 rounded-xl shadow-2xl p-4 font-mono text-[11px]">
            <div className="flex items-center justify-between mb-3">
              <span className="font-black uppercase tracking-wider text-zinc-300">
                {modal.type === "rename" ? "Rename" :
                 modal.type === "mkdir" ? "New Directory" :
                 modal.type === "move" ? "Move to…" :
                 modal.type === "move-bulk" ? `Move ${selected.size} items to…` : "Properties"}
              </span>
              <button onClick={() => setModal(null)} className="text-zinc-500 hover:text-white"><X size={12} /></button>
            </div>
            <div className="space-y-3">
              {modal.type === "properties" ? (
                <>
                  <div>Name: <span className="text-zinc-100 font-bold">{visibleName(modal.entry?.name ?? "")}</span></div>
                  <div>Path: <span className="text-zinc-400 text-[10px] block truncate">{visibleName(modal.entry?.path ?? "")}</span></div>

                  {/* RWX matrix — owner/group/other × read/write/execute. The
                      checkbox grid is the source of truth; the octal input
                      below mirrors it and accepts manual edits both ways. */}
                  {(() => {
                    const parsed = parseInt(modal.v1 || "0", 8);
                    const mode = isNaN(parsed) ? 0 : parsed & 0o777;
                    const roles: { key: "owner" | "group" | "other"; label: string; shift: number }[] = [
                      { key: "owner", label: "Owner", shift: 6 },
                      { key: "group", label: "Group", shift: 3 },
                      { key: "other", label: "Other", shift: 0 },
                    ];
                    const bits: { key: "r" | "w" | "x"; label: string; bit: number }[] = [
                      { key: "r", label: "R", bit: 4 },
                      { key: "w", label: "W", bit: 2 },
                      { key: "x", label: "X", bit: 1 },
                    ];
                    const toggle = (shift: number, bit: number) => {
                      const next = mode ^ (bit << shift);
                      setModal({ ...modal, v1: (next & 0o777).toString(8).padStart(3, "0") });
                    };
                    return (
                      <div className="pt-1">
                        <label className="text-[10px] text-zinc-400 block mb-1.5 uppercase tracking-wider">Permissions</label>
                        <div className="grid grid-cols-[60px_repeat(3,1fr)] gap-1 text-center text-[10px] text-zinc-400 font-mono">
                          <div />
                          {bits.map((b) => <div key={b.key} className="font-bold">{b.label}</div>)}
                          {roles.map((role) => (
                            <React.Fragment key={role.key}>
                              <div className="text-left text-zinc-300 self-center">{role.label}</div>
                              {bits.map((b) => {
                                const on = ((mode >> role.shift) & b.bit) !== 0;
                                return (
                                  <button
                                    key={b.key}
                                    type="button"
                                    onClick={() => toggle(role.shift, b.bit)}
                                    className={`h-6 rounded border transition-colors ${
                                      on
                                        ? "bg-indigo-500/20 border-indigo-400/40 text-indigo-200"
                                        : "bg-white/[0.04] border-white/10 text-zinc-500 hover:bg-white/[0.08]"
                                    }`}
                                  >
                                    {on ? "✓" : ""}
                                  </button>
                                );
                              })}
                            </React.Fragment>
                          ))}
                        </div>
                      </div>
                    );
                  })()}

                  <div className="flex gap-2 pt-1">
                    <div className="flex-1">
                      <label className="text-[10px] text-zinc-400 block mb-1">Octal</label>
                      <input type="text" value={modal.v1 || ""}
                        onChange={(e) => {
                          // Only accept 0–3 digits, each 0–7 — anything else is
                          // ignored so the checkbox grid never sees garbage.
                          const v = e.target.value.replace(/[^0-7]/g, "").slice(0, 3);
                          setModal({ ...modal, v1: v });
                        }}
                        className="w-full h-7 px-2 bg-white/5 border border-white/5 rounded text-zinc-200 focus:outline-none focus:border-indigo-400/40 text-[11.5px] font-mono" />
                    </div>
                    <div className="flex-1">
                      <label className="text-[10px] text-zinc-400 block mb-1">Owner UID</label>
                      <input type="text" value={modal.v2 || ""} onChange={(e) => setModal({ ...modal, v2: e.target.value })}
                        className="w-full h-7 px-2 bg-white/5 border border-white/5 rounded text-zinc-200 focus:outline-none focus:border-indigo-400/40 text-[11.5px]" />
                    </div>
                  </div>
                </>
              ) : (
                <div>
                  <label className="text-[10px] text-zinc-400 block mb-1">
                    {modal.type === "move" || modal.type === "move-bulk"
                      ? "Destination directory"
                      : "Name"}
                  </label>
                  <input type="text" autoFocus value={modal.v1 || ""}
                    onChange={(e) => setModal({ ...modal, v1: e.target.value })}
                    onKeyDown={(e) => e.key === "Enter" && submitModal()}
                    className="w-full h-7 px-2 bg-white/5 border border-white/5 rounded text-zinc-200 focus:outline-none focus:border-indigo-400/40 text-[11.5px] font-mono" />
                </div>
              )}
              <div className="flex gap-2 justify-end pt-2">
                <button onClick={() => setModal(null)} className="px-3 h-7 rounded border border-white/5 text-zinc-400 hover:text-white">Cancel</button>
                <button onClick={submitModal} className="px-3 h-7 rounded bg-indigo-500 text-white font-bold hover:bg-indigo-600">Apply</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
});

FilePanel.displayName = "FilePanel";

export default FilePanel;
