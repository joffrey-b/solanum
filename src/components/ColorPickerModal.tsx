import { useEffect, useMemo, useState } from "react";
import { X } from "lucide-react";
import { clamp255, rgbToHex, parseHex, hsvToRgb, rgbToHsv } from "../util/color";

// HSV is the source of truth while this is open — dragging the saturation/
// value square or the hue strip produces HSV directly, and round-tripping
// through RGB on every drag frame (RGB -> HSV -> RGB) would drift/jitter
// from rounding. RGB and hex are derived FROM hsv for display, and only
// feed back into it when the user types into one of those fields directly.

export interface SavedColor {
  id: string;
  name: string;
  value: string;
}

interface Props {
  isOpen: boolean;
  initialValue: string;
  onCancel: () => void;
  onSave: (color: { name: string; value: string }) => void;
  /** Dialog header text. Defaults to the generic "Color Picker". */
  title?: string;
  /**
   * Hides the Name field — for callers setting one specific color slot
   * (e.g. the terminal theme editor picking its "Red" ANSI color) rather
   * than saving a new reusable named swatch. `onSave`'s `name` is just
   * empty in that case; callers that don't need it simply don't read it.
   */
  showNameField?: boolean;
}

const ColorPickerModal = ({ isOpen, initialValue, onCancel, onSave, title = "Color Picker", showNameField = true }: Props) => {
  const [hsv, setHsv] = useState<[number, number, number]>(() => {
    const rgb = parseHex(initialValue) || [96, 165, 250];
    return rgbToHsv(...rgb);
  });
  const [name, setName] = useState("");
  // What the hex field shows while being typed into — kept separate from
  // the derived hex string so an in-progress edit (e.g. "#4b9" before the
  // 4th digit) doesn't get stomped by the derived value on every keystroke.
  const [hexDraft, setHexDraft] = useState("");

  // Re-seed from the current setting's color each time the modal opens,
  // rather than once at mount — this component stays mounted (isOpen just
  // toggles visibility) so its own state would otherwise carry over from
  // the last time it was opened for a different grid/color.
  useEffect(() => {
    if (!isOpen) return;
    const rgb = parseHex(initialValue) || [96, 165, 250];
    setHsv(rgbToHsv(...rgb));
    setName("");
  }, [isOpen, initialValue]);

  const [h, s, v] = hsv;
  const [r, g, b] = useMemo(() => hsvToRgb(h, s, v), [h, s, v]);
  const hex = useMemo(() => rgbToHex(r, g, b), [r, g, b]);
  useEffect(() => { setHexDraft(hex); }, [hex]);

  if (!isOpen) return null;

  const setFromSquare = (clientX: number, clientY: number, rect: DOMRect) => {
    const x = Math.min(Math.max(clientX - rect.left, 0), rect.width);
    const y = Math.min(Math.max(clientY - rect.top, 0), rect.height);
    setHsv([h, (x / rect.width) * 100, 100 - (y / rect.height) * 100]);
  };
  const setFromHueStrip = (clientY: number, rect: DOMRect) => {
    const y = Math.min(Math.max(clientY - rect.top, 0), rect.height);
    setHsv([(y / rect.height) * 360, s, v]);
  };

  const setRgbChannel = (channel: 0 | 1 | 2, value: number) => {
    const next: [number, number, number] = [r, g, b];
    next[channel] = clamp255(value);
    setHsv(rgbToHsv(...next));
  };

  // `allowShorthand` matters because `hexDraft` gets echoed back from the
  // derived `hex` (6-digit, canonical) on every successful commit: typing
  // "4b90fe" character by character passes through "4b9" along the way,
  // which is ALSO a valid 3-digit shorthand — live-accepting it there would
  // expand the field to "#44bb99" mid-keystroke and derail typing the rest
  // of the intended 6-digit value. So shorthand only commits on blur/Enter,
  // once the user has actually stopped; while typing, only a complete
  // 6-digit value (nothing left to continue) commits live.
  const commitHexDraft = (raw: string, allowShorthand: boolean) => {
    const bare = raw.trim().replace(/^#/, "");
    if (!allowShorthand && !/^[0-9a-fA-F]{6}$/.test(bare)) return;
    const parsed = parseHex(raw);
    if (parsed) setHsv(rgbToHsv(...parsed));
    // An unparseable draft is left as typed (no forced revert while the
    // user might still be mid-edit) — it snaps back to the last valid hex
    // via the `hex` effect above the next time `hsv` actually changes.
  };

  return (
    <div
      className="fixed inset-0 z-[70] bg-black/60 backdrop-blur-sm flex items-center justify-center p-3"
      // stopPropagation matters here specifically because this modal can be
      // opened FROM INSIDE another one (the terminal theme editor uses it
      // per-swatch) — without it, a backdrop click meant to dismiss just
      // this picker would bubble up to the parent modal's own backdrop
      // handler and close that too, discarding whatever else was being
      // edited there.
      onClick={(e) => { e.stopPropagation(); onCancel(); }}
    >
      <div className="w-full max-w-sm bg-[#121214] border border-white/10 rounded-xl shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-white/5 flex items-center justify-between">
          <span className="text-[13px] font-bold text-white">{title}</span>
          <button onClick={onCancel} className="text-zinc-400 hover:text-white"><X size={16} /></button>
        </div>

        <div className="p-4 space-y-4">
          <div className="flex gap-3">
            {/* Saturation/Value square. Pure CSS, no canvas: a hue-colored
                background with a white->transparent layer (saturation, left
                to right) and a black->transparent layer (value, bottom to
                top) stacked on top — the standard HSV-square trick. */}
            <div
              className="relative w-48 h-48 rounded-lg cursor-crosshair shrink-0 touch-none"
              style={{
                backgroundColor: `hsl(${h}, 100%, 50%)`,
                backgroundImage: "linear-gradient(to top, #000, transparent), linear-gradient(to right, #fff, transparent)",
              }}
              onPointerDown={(e) => {
                e.currentTarget.setPointerCapture(e.pointerId);
                setFromSquare(e.clientX, e.clientY, e.currentTarget.getBoundingClientRect());
              }}
              onPointerMove={(e) => {
                if (e.buttons !== 1) return;
                setFromSquare(e.clientX, e.clientY, e.currentTarget.getBoundingClientRect());
              }}
            >
              <div
                className="absolute w-4 h-4 rounded-full border-2 border-white shadow-[0_0_0_1px_rgba(0,0,0,0.5)] -translate-x-1/2 translate-y-1/2 pointer-events-none"
                style={{ left: `${s}%`, bottom: `${v}%` }}
              />
            </div>

            {/* Hue strip — a full rainbow top to bottom, matching the
                square's own vertical "value" axis so both read top = high. */}
            <div
              className="relative w-5 h-48 rounded-lg cursor-ns-resize shrink-0 touch-none"
              style={{ background: "linear-gradient(to bottom, #f00, #ff0, #0f0, #0ff, #00f, #f0f, #f00)" }}
              onPointerDown={(e) => {
                e.currentTarget.setPointerCapture(e.pointerId);
                setFromHueStrip(e.clientY, e.currentTarget.getBoundingClientRect());
              }}
              onPointerMove={(e) => {
                if (e.buttons !== 1) return;
                setFromHueStrip(e.clientY, e.currentTarget.getBoundingClientRect());
              }}
            >
              <div
                className="absolute left-1/2 w-6 h-2 rounded-sm border-2 border-white shadow-[0_0_0_1px_rgba(0,0,0,0.5)] -translate-x-1/2 -translate-y-1/2 pointer-events-none"
                style={{ top: `${(h / 360) * 100}%` }}
              />
            </div>

            <div className="flex-1 flex flex-col gap-1.5 min-w-0">
              {([["R", r, 0], ["G", g, 1], ["B", b, 2]] as const).map(([label, val, idx]) => (
                <div key={label} className="flex items-center gap-1.5">
                  <label className="w-3 text-[10px] font-bold text-zinc-500">{label}</label>
                  <input
                    type="number"
                    min={0}
                    max={255}
                    value={val}
                    onChange={(e) => setRgbChannel(idx, parseInt(e.target.value, 10) || 0)}
                    className="w-full h-7 px-1.5 bg-black border border-white/10 rounded text-[11px] text-zinc-200 outline-none focus:border-primary/50"
                  />
                </div>
              ))}
              <div className="flex items-center gap-1.5">
                <label className="w-3 text-[10px] font-bold text-zinc-500">#</label>
                <input
                  type="text"
                  value={hexDraft}
                  onChange={(e) => { setHexDraft(e.target.value); commitHexDraft(e.target.value, false); }}
                  onBlur={(e) => commitHexDraft(e.target.value, true)}
                  onKeyDown={(e) => { if (e.key === "Enter") commitHexDraft(hexDraft, true); }}
                  className="w-full h-7 px-1.5 bg-black border border-white/10 rounded text-[11px] font-mono text-zinc-200 outline-none focus:border-primary/50"
                />
              </div>
              <div className="flex-1 min-h-[28px] rounded-md border border-white/10 mt-1" style={{ backgroundColor: hex }} />
            </div>
          </div>

          {showNameField && (
            <div className="space-y-1">
              <label className="text-[10px] font-bold text-zinc-300 uppercase tracking-wider ml-0.5">Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Brand Blue — shown as a hover tooltip"
                className="w-full h-9 px-3 bg-black border border-white/10 rounded-lg text-[12.5px] text-zinc-50 outline-none focus:border-primary/50"
                autoFocus
              />
            </div>
          )}
        </div>

        <div className="px-4 py-3 border-t border-white/5 flex items-center justify-end gap-2">
          <button onClick={onCancel} className="h-9 px-4 rounded-lg text-[11.5px] font-bold uppercase tracking-wider bg-white/5 text-zinc-200 border border-white/10 hover:bg-white/10">
            Cancel
          </button>
          <button
            onClick={() => onSave({ name: name.trim() || hex, value: hex })}
            className="h-9 px-4 rounded-lg text-[11.5px] font-bold uppercase tracking-wider bg-primary text-black hover:brightness-110"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
};

export default ColorPickerModal;
