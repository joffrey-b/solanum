import { useEffect, useRef, useState } from "react";
import { AlertTriangle, X } from "lucide-react";

// The legal texts that travel with Solanum, readable from inside the app, which
// is how GPL-3.0 section 5(d) asks a program with a user interface to offer
// them. `?raw` puts each file's text in a chunk of its own, loaded when its tab
// is opened (the third-party list is over a megabyte), and needs neither a
// backend command nor a looser CSP.
const DOCUMENTS = [
  { id: "license", label: "GPL-3.0", load: () => import("../../LICENSE?raw") },
  { id: "notice", label: "Notices", load: () => import("../../NOTICE?raw") },
  { id: "third-party", label: "Third-party", load: () => import("../../THIRD-PARTY-LICENSES.txt?raw") },
];

const LicenseViewer = ({ onClose }: { onClose: () => void }) => {
  const [active, setActive] = useState(DOCUMENTS[0].id);
  const [texts, setTexts] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const closeRef = useRef<HTMLButtonElement | null>(null);

  useEffect(() => { closeRef.current?.focus(); }, []);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  useEffect(() => {
    if (texts[active] !== undefined) return;
    let cancelled = false;
    setError(null);
    DOCUMENTS.find((d) => d.id === active)!.load()
      .then((m) => { if (!cancelled) setTexts((t) => ({ ...t, [active]: m.default })); })
      .catch((e) => { if (!cancelled) setError(String(e)); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  const text = texts[active];

  return (
    <div
      className="fixed inset-0 z-[60] bg-black/60 backdrop-blur-sm flex items-center justify-center p-3"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-label="Licences"
        className="w-full max-w-3xl h-full max-h-[85vh] flex flex-col bg-[#121214] border border-white/10 rounded-xl shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-4 py-3 border-b border-white/5 flex items-center justify-between gap-3 shrink-0">
          <div className="flex items-center gap-1 flex-wrap" role="tablist">
            {DOCUMENTS.map((d) => (
              <button
                key={d.id}
                role="tab"
                aria-selected={active === d.id}
                onClick={() => setActive(d.id)}
                className={`h-7 px-3 rounded text-[11.5px] font-bold transition-colors ${
                  active === d.id ? "bg-white/10 text-white" : "text-zinc-400 hover:text-white hover:bg-white/5"
                }`}
              >
                {d.label}
              </button>
            ))}
          </div>
          <button ref={closeRef} onClick={onClose} aria-label="Close" className="text-zinc-400 hover:text-white shrink-0">
            <X size={16} />
          </button>
        </div>

        {/* Keyed so that another document starts at its top. */}
        <div key={active} className="flex-1 min-h-0 overflow-y-auto">
          {error ? (
            <div className="m-4 px-3 py-2 bg-rose-500/15 border border-rose-500/30 rounded text-rose-200 text-[11.5px] flex items-start gap-2">
              <AlertTriangle size={12} className="mt-0.5 shrink-0" />
              <span className="flex-1 break-words">{error}</span>
            </div>
          ) : text === undefined ? (
            <p className="p-4 text-[11.5px] text-zinc-500">Loading…</p>
          ) : (
            <pre className="p-4 text-[11px] leading-relaxed font-mono text-zinc-300 whitespace-pre-wrap break-words select-text">
              {text}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
};

export default LicenseViewer;
