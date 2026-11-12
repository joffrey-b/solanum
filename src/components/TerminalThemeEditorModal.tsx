import { useEffect, useState } from "react";
import { X, RotateCcw } from "lucide-react";
import ColorPickerModal from "./ColorPickerModal";
import { TerminalTheme, TerminalThemeColors, TERMINAL_THEMES, allTerminalThemes, hexToRgba } from "../util/terminalThemes";
import { lightenHex } from "../util/color";

// Pairs a normal ANSI slot with its "bright" counterpart. Order here is also
// the display order (matches the classic 8-color terminal palette layout).
const ANSI_ROWS: { key: keyof TerminalThemeColors; brightKey: keyof TerminalThemeColors; label: string }[] = [
  { key: "black", brightKey: "brightBlack", label: "Black" },
  { key: "red", brightKey: "brightRed", label: "Red" },
  { key: "green", brightKey: "brightGreen", label: "Green" },
  { key: "yellow", brightKey: "brightYellow", label: "Yellow" },
  { key: "blue", brightKey: "brightBlue", label: "Blue" },
  { key: "magenta", brightKey: "brightMagenta", label: "Magenta" },
  { key: "cyan", brightKey: "brightCyan", label: "Cyan" },
  { key: "white", brightKey: "brightWhite", label: "White" },
];

// How much a bright color auto-lightens from its normal counterpart, until
// the user overrides that specific slot themselves.
const BRIGHTEN_FACTOR = 0.3;

// Starting point for a brand-new theme — OLED Black's own 16 colors, picked
// arbitrarily as a reasonable default to tweak from rather than inventing a
// third hardcoded palette just for this.
const DEFAULT_SEED_ID = "oled-black";
const DEFAULT_SEED = TERMINAL_THEMES.find((t) => t.id === DEFAULT_SEED_ID)!.colors as Required<TerminalThemeColors>;

interface Props {
  isOpen: boolean;
  onCancel: () => void;
  onSave: (theme: TerminalTheme) => void;
}

type EditingField = { key: keyof TerminalThemeColors; label: string } | null;

const TerminalThemeEditorModal = ({ isOpen, onCancel, onSave }: Props) => {
  const [name, setName] = useState("");
  const [colors, setColors] = useState<Required<TerminalThemeColors>>(DEFAULT_SEED);
  // Which bright slots hold an intentional value — either seeded from a real
  // theme (resetFrom marks all 8 this way) or set by the user directly —
  // rather than one just auto-tracking its normal counterpart live. Anything
  // NOT in here recomputes from the normal color on every edit (setNormalColor).
  const [overriddenBrights, setOverriddenBrights] = useState<Set<string>>(new Set());
  const [editingField, setEditingField] = useState<EditingField>(null);
  const [startFrom, setStartFrom] = useState(DEFAULT_SEED_ID);

  // "app" (Match App Colors) has no fixed palette of its own — excluded
  // here since there's nothing to copy ANSI colors from.
  const seedableThemes = allTerminalThemes().filter((t) => t.colors);

  const resetFrom = (themeId: string) => {
    const base = (seedableThemes.find((t) => t.id === themeId)?.colors ?? DEFAULT_SEED) as Required<TerminalThemeColors>;
    setColors(base);
    // Every seeded bright color (default OLED Black, or whatever "Start
    // from" theme was picked) is a real, deliberately-published value, not
    // a placeholder — so it starts "overridden" too, meaning it stays
    // exactly as seeded until the user does something to it. Without this,
    // starting from Dracula and tweaking only the normal Red would silently
    // discard Dracula's own hand-picked Bright Red the moment Red changed,
    // replacing it with a generic auto-lightened tint nobody asked for.
    // Clicking a bright swatch's own ↺ is how a slot opts INTO auto-tracking
    // its normal counterpart from that point on.
    setOverriddenBrights(new Set(ANSI_ROWS.map((r) => r.brightKey)));
  };

  // Re-seed every time this opens, not just once at mount — the component
  // stays around (isOpen just toggles visibility), so without this a second
  // "New Terminal Theme" would start from whatever was left over.
  useEffect(() => {
    if (!isOpen) return;
    setName("");
    setStartFrom(DEFAULT_SEED_ID);
    resetFrom(DEFAULT_SEED_ID);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isOpen]);

  if (!isOpen) return null;

  const setNormalColor = (key: keyof TerminalThemeColors, value: string) => {
    const row = ANSI_ROWS.find((r) => r.key === key);
    setColors((prev) => {
      const next = { ...prev, [key]: value };
      if (row && !overriddenBrights.has(row.brightKey)) {
        next[row.brightKey] = lightenHex(value, BRIGHTEN_FACTOR);
      }
      return next;
    });
  };

  const setBrightColor = (key: keyof TerminalThemeColors, value: string) => {
    setOverriddenBrights((prev) => new Set(prev).add(key));
    setColors((prev) => ({ ...prev, [key]: value }));
  };

  const clearBrightOverride = (brightKey: keyof TerminalThemeColors, normalKey: keyof TerminalThemeColors) => {
    setOverriddenBrights((prev) => { const next = new Set(prev); next.delete(brightKey); return next; });
    setColors((prev) => ({ ...prev, [brightKey]: lightenHex(prev[normalKey], BRIGHTEN_FACTOR) }));
  };

  const swatchClass = "rounded-lg border border-white/10 hover:border-primary/50 transition-colors";

  return (
    <div className="fixed inset-0 z-[60] bg-black/60 backdrop-blur-sm flex items-center justify-center p-3" onClick={onCancel}>
      <div className="w-full max-w-xl bg-[#121214] border border-white/10 rounded-xl shadow-2xl max-h-[90vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-white/5 flex items-center justify-between shrink-0">
          <span className="text-[13px] font-bold text-white">New Terminal Theme</span>
          <button onClick={onCancel} className="text-zinc-400 hover:text-white"><X size={16} /></button>
        </div>

        <div className="p-4 space-y-5 overflow-y-auto custom-scrollbar">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-[10px] font-bold text-zinc-300 uppercase tracking-wider ml-0.5">Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. My Theme"
                className="w-full h-9 px-3 bg-black border border-white/10 rounded-lg text-[12.5px] text-zinc-50 outline-none focus:border-primary/50"
                autoFocus
              />
            </div>
            <div className="space-y-1">
              <label className="text-[10px] font-bold text-zinc-300 uppercase tracking-wider ml-0.5">Start from</label>
              <select
                value={startFrom}
                onChange={(e) => { setStartFrom(e.target.value); resetFrom(e.target.value); }}
                className="w-full h-9 bg-black border border-white/10 rounded-lg px-2 text-[12px] text-zinc-50 outline-none focus:border-primary/50"
              >
                {seedableThemes.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
              </select>
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-[10px] font-bold text-zinc-300 uppercase tracking-wider ml-0.5">Core Colors</label>
            <div className="flex items-center gap-5">
              {([["background", "Background"], ["foreground", "Foreground"], ["cursor", "Cursor"]] as const).map(([key, label]) => (
                <div key={key} className="flex flex-col items-center gap-1">
                  <button
                    onClick={() => setEditingField({ key, label })}
                    className={`${swatchClass} w-9 h-9`}
                    style={{ backgroundColor: colors[key] }}
                    title={label}
                  />
                  <span className="text-[9px] text-zinc-500">{label}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-2">
            <label className="text-[10px] font-bold text-zinc-300 uppercase tracking-wider ml-0.5">ANSI Colors</label>
            <div className="grid grid-cols-8 gap-1.5">
              {ANSI_ROWS.map((row) => (
                <button
                  key={row.key}
                  onClick={() => setEditingField({ key: row.key, label: row.label })}
                  className={`${swatchClass} w-full aspect-square`}
                  style={{ backgroundColor: colors[row.key] }}
                  title={row.label}
                />
              ))}
              {ANSI_ROWS.map((row) => {
                const overridden = overriddenBrights.has(row.brightKey);
                return (
                  <div key={row.brightKey} className="relative">
                    <button
                      onClick={() => setEditingField({ key: row.brightKey, label: `Bright ${row.label}` })}
                      className={`${swatchClass} w-full aspect-square`}
                      style={{ backgroundColor: colors[row.brightKey] }}
                      title={overridden ? `Bright ${row.label}` : `Bright ${row.label} (auto, from ${row.label})`}
                    />
                    {overridden && (
                      <button
                        onClick={(e) => { e.stopPropagation(); clearBrightOverride(row.brightKey, row.key); }}
                        title="Reset to automatic"
                        className="absolute -top-1.5 -right-1.5 w-3.5 h-3.5 rounded-full bg-black border border-white/20 text-zinc-300 hover:text-primary flex items-center justify-center"
                      >
                        <RotateCcw size={8} />
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
            <p className="text-[10px] text-zinc-600 leading-snug">
              Top row: the 8 main colors. Bottom row: their "bright" variants, copied from the starting theme — click a bright swatch's own ↺ to make it auto-lighten from the color above it instead, live, as you adjust that color.
            </p>
          </div>
        </div>

        <div className="px-4 py-3 border-t border-white/5 flex items-center justify-end gap-2 shrink-0">
          <button onClick={onCancel} className="h-9 px-4 rounded-lg text-[11.5px] font-bold uppercase tracking-wider bg-white/5 text-zinc-200 border border-white/10 hover:bg-white/10">
            Cancel
          </button>
          <button
            onClick={() => {
              const theme: TerminalTheme = {
                id: `custom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                label: name.trim() || "Custom Theme",
                colors: { ...colors, selectionBackground: hexToRgba(colors.cursor, 0.3) },
              };
              onSave(theme);
            }}
            className="h-9 px-4 rounded-lg text-[11.5px] font-bold uppercase tracking-wider bg-primary text-black hover:brightness-110"
          >
            Save
          </button>
        </div>
      </div>

      {editingField && (
        <ColorPickerModal
          isOpen
          title={editingField.label}
          showNameField={false}
          initialValue={colors[editingField.key]}
          onCancel={() => setEditingField(null)}
          onSave={({ value }) => {
            const isBright = ANSI_ROWS.some((r) => r.brightKey === editingField.key);
            if (isBright) setBrightColor(editingField.key, value);
            else setNormalColor(editingField.key, value);
            setEditingField(null);
          }}
        />
      )}
    </div>
  );
};

export default TerminalThemeEditorModal;
