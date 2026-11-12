import { createContext, useCallback, useContext, useEffect, useReducer, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { AlertTriangle, X } from "lucide-react";
import { visibleName } from "../util/visibleName";
import { DialogQueue } from "../util/dialogQueue";

// Focus trap for our modal portals: while the dialog `id` is shown, move focus
// into the panel (unless React's autoFocus already did — we check
// panel.contains(activeElement) first) and intercept Tab / Shift+Tab so focus
// wraps inside the panel instead of tabbing into the underlying app (which is
// inert to sighted users but reachable via keyboard/AT without this). Where
// focus goes back to once the dialogs are answered is the provider's job (it
// knows what had focus before the first one opened). Scoped to this file.
const useFocusTrap = (id: number, panelRef: React.RefObject<HTMLDivElement | null>) => {
  useEffect(() => {
    const panel = panelRef.current;
    if (!panel) return;
    const getFocusable = () =>
      Array.from(
        panel.querySelectorAll<HTMLElement>(
          'button, input, textarea, [tabindex]:not([tabindex="-1"])'
        )
      ).filter((el) => !el.hasAttribute("disabled"));
    // Only override focus if React's autoFocus didn't already land inside.
    if (!panel.contains(document.activeElement)) {
      getFocusable()[0]?.focus();
    }
    // Every Tab moves focus here, never natively: with macOS's "Keyboard
    // navigation" off, WebKit's own Tab skips buttons and would leave the
    // panel (a following Enter then reaching the terminal behind it).
    // WebKitGTK reports Shift+Tab (ISO_Left_Tab) as key "Unidentified" with
    // code "Tab", hence both.
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Tab" && e.code !== "Tab") return;
      e.preventDefault();
      const items = getFocusable();
      if (items.length === 0) return;
      const at = items.indexOf(document.activeElement as HTMLElement);
      const next = at < 0
        ? (e.shiftKey ? items.length - 1 : 0)
        : (at + (e.shiftKey ? items.length - 1 : 1)) % items.length;
      items[next].focus();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [id, panelRef]);
};

// Themed replacement for the browser-native `confirm()` dialog. Anywhere in
// the tree, `useConfirm()` returns a function that opens the modal and
// resolves to true / false. Cross-platform (pure React + CSS), no native
// dialog quirks, and lets us style destructive actions consistently.
//
// Keys (F-048): Enter presses the button that has focus, nothing else; Esc
// and a click outside cancel. Focus starts on the confirm button, or on
// Cancel for a destructive or `safeDefault` dialog, so a reflexive Enter
// never approves those. Requests made while a dialog is open wait their turn.

export interface ConfirmOptions {
  title?: string;
  message: string;
  okLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
  /**
   * Focus starts on Cancel, so Enter cancels and approving takes a deliberate
   * click on the confirm button (or Tab to it, then Enter). Defaults to
   * `destructive`; set it for a warning that is not destructive itself.
   */
  safeDefault?: boolean;
  /**
   * The confirm button stays disabled until this exact text is typed into a
   * field the dialog shows (deleting a profile: its name).
   */
  typeToConfirm?: string;
}

// File-conflict modal. Returned from useOverwritePrompt(). The caller picks
// one of five outcomes; in a batch operation, the "all" variants are sticky
// — caller stores them in batch state so subsequent files don't re-prompt.
export type OverwriteChoice =
  | "overwrite"
  | "skip"
  | "overwrite-all"
  | "skip-all"
  | "cancel";

export interface OverwritePromptOptions {
  /** Display name (just the basename, not the full path). */
  name: string;
  /** "download" or "upload" — drives the wording. */
  direction: "download" | "upload";
  /** Total number of items in the batch, so we can hide "all" when only one. */
  batchSize: number;
  /**
   * The conflicting item is a folder — sftp_upload_dir/sftp_download_dir
   * MERGE into an existing destination folder (per-file overwrite inside
   * it) rather than replacing it wholesale, so the prompt says "Merge"
   * instead of "Overwrite" here to describe what actually happens.
   */
  isDir?: boolean;
}

// Themed replacement for browser-native `prompt()`. Tauri's Android WebView
// silently no-ops native prompt(), which broke callers like "Generate SSH
// key" that need to collect a short string from the user. Resolves to the
// trimmed input (or empty string when the user hits OK with empty input,
// which validators should reject), or null when cancelled. A `password`
// prompt's value is returned exactly as typed.
export interface TextPromptOptions {
  title?: string;
  message?: string;
  placeholder?: string;
  initialValue?: string;
  okLabel?: string;
  cancelLabel?: string;
  /** Mask the input (passwords / passphrases). */
  password?: boolean;
  /** Return an error string to block OK; return null to allow. */
  validate?: (v: string) => string | null;
}

type Dialog =
  | { kind: "confirm"; opts: ConfirmOptions }
  | { kind: "overwrite"; opts: OverwritePromptOptions }
  | { kind: "text"; opts: TextPromptOptions };

const ConfirmContext = createContext<((opts: ConfirmOptions | string) => Promise<boolean>) | null>(null);
const OverwriteContext = createContext<((opts: OverwritePromptOptions) => Promise<OverwriteChoice>) | null>(null);
const TextPromptContext = createContext<((opts: TextPromptOptions) => Promise<string | null>) | null>(null);

const BACKDROP = "fixed inset-0 z-[9999] bg-black/60 backdrop-blur-sm flex items-center justify-center p-4";
const PANEL = "bg-[#121214] border border-white/10 rounded-xl shadow-2xl p-4 font-mono text-[12px] animate-in zoom-in-95 fade-in duration-150";

const ConfirmDialog = ({ id, opts, answer }: { id: number; opts: ConfirmOptions; answer: (v: boolean) => void }) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useFocusTrap(id, panelRef);
  const safe = opts.safeDefault ?? !!opts.destructive;
  const [typed, setTyped] = useState("");
  const needsTyping = opts.typeToConfirm !== undefined;
  const typedOk = !needsTyping || typed === opts.typeToConfirm;
  return createPortal(
    <div className={BACKDROP} onClick={() => answer(false)}>
      <div ref={panelRef}
           role="dialog"
           aria-modal="true"
           aria-labelledby="confirm-modal-title"
           onClick={(e) => e.stopPropagation()}
           className={`w-full max-w-[380px] ${PANEL}`}>
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-2">
            <AlertTriangle size={14} className={opts.destructive ? "text-rose-400" : "text-amber-400"} />
            <span id="confirm-modal-title" className="text-[11px] font-black uppercase tracking-widest text-zinc-200">
              {opts.title || (opts.destructive ? "Confirm action" : "Are you sure?")}
            </span>
          </div>
          <button onClick={() => answer(false)} className="text-zinc-500 hover:text-white shrink-0" aria-label="Close">
            <X size={12} />
          </button>
        </div>
        <p className="text-[12px] text-zinc-300 leading-relaxed mb-4 whitespace-pre-wrap break-words">
          {opts.message}
        </p>
        {needsTyping && (
          <label className="block mb-4">
            <span className="block text-[11px] text-zinc-400 mb-1.5">
              Type <span className="text-zinc-100 font-bold">{opts.typeToConfirm}</span> to confirm.
            </span>
            <input
              autoFocus
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); if (typedOk) answer(true); } }}
              autoComplete="off"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              className="w-full h-9 px-3 bg-black/40 border border-white/10 rounded-lg text-[13px] text-zinc-100 outline-none focus:border-primary/50"
            />
          </label>
        )}
        <div className="flex justify-end gap-2">
          <button onClick={() => answer(false)} autoFocus={safe && !needsTyping}
                  className="px-3 h-8 rounded text-[11px] font-bold uppercase tracking-wider bg-white/[0.04] border border-white/10 text-zinc-300 hover:bg-white/[0.08] hover:text-white">
            {opts.cancelLabel || "Cancel"}
          </button>
          <button onClick={() => answer(true)} autoFocus={!safe && !needsTyping} disabled={!typedOk}
                  className={`px-3 h-8 rounded text-[11px] font-bold uppercase tracking-wider border disabled:opacity-40 disabled:cursor-not-allowed ${
                    opts.destructive
                      ? "bg-rose-500/15 border-rose-500/40 text-rose-300 hover:bg-rose-500/25"
                      : "bg-primary/15 border-primary/40 text-primary hover:bg-primary/25"
                  }`}>
            {opts.okLabel || (opts.destructive ? "Delete" : "OK")}
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
};

const OverwriteDialog = ({ id, opts, answer }: { id: number; opts: OverwritePromptOptions; answer: (c: OverwriteChoice) => void }) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useFocusTrap(id, panelRef);
  return createPortal(
    <div className={BACKDROP} onClick={() => answer("cancel")}>
      <div ref={panelRef}
           role="dialog"
           aria-modal="true"
           aria-labelledby="overwrite-modal-title"
           onClick={(e) => e.stopPropagation()}
           className={`w-full max-w-[420px] ${PANEL}`}>
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-2">
            <AlertTriangle size={14} className="text-amber-400" />
            <span id="overwrite-modal-title" className="text-[11px] font-black uppercase tracking-widest text-zinc-200">
              {opts.isDir
                ? (opts.direction === "download" ? "Local folder exists" : "Remote folder exists")
                : (opts.direction === "download" ? "Local file exists" : "Remote file exists")}
            </span>
          </div>
          <button onClick={() => answer("cancel")} className="text-zinc-500 hover:text-white shrink-0" aria-label="Close">
            <X size={12} />
          </button>
        </div>
        <p className="text-[12px] text-zinc-300 leading-relaxed mb-1 whitespace-pre-wrap break-words">
          {opts.isDir
            ? (opts.direction === "download"
                ? "A folder with this name already exists at the destination. Merging will copy into it — anything already there that isn't part of this transfer is left as-is:"
                : "A folder with this name already exists on the remote. Merging will copy into it — anything already there that isn't part of this transfer is left as-is:")
            : (opts.direction === "download"
                ? "A file with this name already exists at the destination:"
                : "A file with this name already exists on the remote:")}
        </p>
        <p className="text-[12px] text-amber-300 leading-relaxed mb-4 break-all">
          {visibleName(opts.name)}
        </p>
        {/* Focus starts on Skip: a reflexive Enter leaves the existing item
            alone (F-048). */}
        <div className="grid grid-cols-2 gap-2">
          <button onClick={() => answer("overwrite")}
                  className="h-9 rounded text-[11px] font-bold uppercase tracking-wider bg-primary/15 border border-primary/40 text-primary hover:bg-primary/25">
            {opts.isDir ? "Merge" : "Overwrite"}
          </button>
          <button onClick={() => answer("skip")} autoFocus
                  className="h-9 rounded text-[11px] font-bold uppercase tracking-wider bg-white/[0.04] border border-white/10 text-zinc-300 hover:bg-white/[0.08] hover:text-white">
            Skip
          </button>
          {opts.batchSize > 1 && (
            <>
              <button onClick={() => answer("overwrite-all")}
                      className="h-9 rounded text-[11px] font-bold uppercase tracking-wider bg-primary/10 border border-primary/30 text-primary hover:bg-primary/20">
                {opts.isDir ? "Merge all" : "Overwrite all"}
              </button>
              <button onClick={() => answer("skip-all")}
                      className="h-9 rounded text-[11px] font-bold uppercase tracking-wider bg-white/[0.03] border border-white/10 text-zinc-400 hover:bg-white/[0.06] hover:text-zinc-200">
                Skip all
              </button>
            </>
          )}
        </div>
        <div className="mt-3 flex justify-end">
          <button onClick={() => answer("cancel")}
                  className="px-3 h-7 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-500/10 border border-rose-500/30 text-rose-300 hover:bg-rose-500/20">
            Cancel batch
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
};

const TextPromptDialog = ({ id, opts, answer }: { id: number; opts: TextPromptOptions; answer: (v: string | null) => void }) => {
  const panelRef = useRef<HTMLDivElement | null>(null);
  useFocusTrap(id, panelRef);
  const [value, setValue] = useState(opts.initialValue ?? "");
  const [error, setError] = useState<string | null>(null);
  const submit = () => {
    // A password or passphrase may begin or end with spaces (F-048).
    const v = opts.password ? value : value.trim();
    const err = opts.validate?.(v) ?? null;
    if (err) { setError(err); return; }
    answer(v);
  };
  return createPortal(
    <div className={BACKDROP} onClick={() => answer(null)}>
      <div ref={panelRef}
           role="dialog"
           aria-modal="true"
           aria-labelledby="text-prompt-modal-title"
           onClick={(e) => e.stopPropagation()}
           className={`w-full max-w-[400px] ${PANEL}`}>
        <div className="flex items-start justify-between gap-3 mb-3">
          <span id="text-prompt-modal-title" className="text-[11px] font-black uppercase tracking-widest text-zinc-200">
            {opts.title || "Enter value"}
          </span>
          <button onClick={() => answer(null)} className="text-zinc-500 hover:text-white shrink-0" aria-label="Close">
            <X size={12} />
          </button>
        </div>
        {opts.message && (
          <p className="text-[12px] text-zinc-300 leading-relaxed mb-3 whitespace-pre-wrap break-words">
            {opts.message}
          </p>
        )}
        <input
          autoFocus
          type={opts.password ? "password" : "text"}
          value={value}
          onChange={(e) => { setValue(e.target.value); setError(null); }}
          onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); submit(); } }}
          placeholder={opts.placeholder}
          className="w-full h-10 px-3 mb-2 bg-black/40 border border-white/10 rounded-lg text-[13px] text-zinc-100 outline-none focus:border-primary/50 placeholder:text-zinc-600"
        />
        {error && (
          <p className="text-[11px] text-rose-300 mb-2">{error}</p>
        )}
        <div className="flex justify-end gap-2 mt-2">
          <button onClick={() => answer(null)}
                  className="px-3 h-8 rounded text-[11px] font-bold uppercase tracking-wider bg-white/[0.04] border border-white/10 text-zinc-300 hover:bg-white/[0.08] hover:text-white">
            {opts.cancelLabel || "Cancel"}
          </button>
          <button onClick={submit}
                  className="px-3 h-8 rounded text-[11px] font-bold uppercase tracking-wider bg-primary/15 border border-primary/40 text-primary hover:bg-primary/25">
            {opts.okLabel || "OK"}
          </button>
        </div>
      </div>
    </div>,
    document.body
  );
};

export const ConfirmProvider = ({ children }: { children: React.ReactNode }) => {
  const [, rerender] = useReducer((n: number) => n + 1, 0);
  const queueRef = useRef<DialogQueue<Dialog> | null>(null);
  if (!queueRef.current) queueRef.current = new DialogQueue<Dialog>(rerender);
  const queue = queueRef.current;
  // What had focus before the first of a run of dialogs: it gets focus back
  // once the last one is answered (if it is still on the page).
  const returnFocusRef = useRef<HTMLElement | null>(null);

  const open = useCallback(<T,>(dialog: Dialog): Promise<T> => {
    if (queue.size === 0) returnFocusRef.current = document.activeElement as HTMLElement | null;
    return queue.push<T>(dialog);
  }, [queue]);

  const confirm = useCallback((opts: ConfirmOptions | string) =>
    open<boolean>({ kind: "confirm", opts: typeof opts === "string" ? { message: opts } : opts }), [open]);
  const overwritePrompt = useCallback((opts: OverwritePromptOptions) =>
    open<OverwriteChoice>({ kind: "overwrite", opts }), [open]);
  const textPrompt = useCallback((opts: TextPromptOptions) =>
    open<string | null>({ kind: "text", opts }), [open]);

  const head = queue.head();
  const headId = head?.id ?? 0;
  const answer = (value: unknown) => { if (head) queue.settle(head.id, value); };

  // Esc cancels the dialog on screen (only that one).
  useEffect(() => {
    if (!head) return;
    const cancelValue = head.entry.kind === "confirm" ? false : head.entry.kind === "overwrite" ? "cancel" : null;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); queue.settle(head.id, cancelValue); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [headId]);

  // The queue is empty again: focus goes back where it was.
  useEffect(() => {
    if (headId !== 0) return;
    const el = returnFocusRef.current;
    returnFocusRef.current = null;
    if (el && el !== document.body && el.isConnected) el.focus?.();
  }, [headId]);

  return (
    <ConfirmContext.Provider value={confirm}>
     <OverwriteContext.Provider value={overwritePrompt}>
      <TextPromptContext.Provider value={textPrompt}>
      {children}
      {head?.entry.kind === "confirm" && <ConfirmDialog key={head.id} id={head.id} opts={head.entry.opts} answer={answer} />}
      {head?.entry.kind === "overwrite" && <OverwriteDialog key={head.id} id={head.id} opts={head.entry.opts} answer={answer} />}
      {head?.entry.kind === "text" && <TextPromptDialog key={head.id} id={head.id} opts={head.entry.opts} answer={answer} />}
      </TextPromptContext.Provider>
     </OverwriteContext.Provider>
    </ConfirmContext.Provider>
  );
};

export const useTextPrompt = () => {
  const ctx = useContext(TextPromptContext);
  if (!ctx) throw new Error("useTextPrompt must be used within <ConfirmProvider>");
  return ctx;
};

export const useConfirm = () => {
  const ctx = useContext(ConfirmContext);
  if (!ctx) throw new Error("useConfirm must be used within <ConfirmProvider>");
  return ctx;
};

export const useOverwritePrompt = () => {
  const ctx = useContext(OverwriteContext);
  if (!ctx) throw new Error("useOverwritePrompt must be used within <ConfirmProvider>");
  return ctx;
};
