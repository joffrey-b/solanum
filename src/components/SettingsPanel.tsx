import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Settings, Palette, RefreshCw, List, Highlighter, ChevronDown, ChevronRight, Plus, Trash2, Check, X, FolderSearch } from "lucide-react";
import { compileHighlightMatcher, findHighlightMatches, genId, DEFAULT_HIGHLIGHT_LISTS, HighlightList, HighlightRule } from "../util/highlight";
import { TERMINAL_FONTS, DEFAULT_TERMINAL_FONT_ID, resolveTerminalFontId } from "../util/terminalFonts";
import { TERMINAL_THEMES, DEFAULT_TERMINAL_THEME_ID, resolveTerminalThemeId, resolveTerminalTheme, TerminalTheme, loadCustomTerminalThemes, saveCustomTerminalThemes } from "../util/terminalThemes";
import ColorPickerModal, { SavedColor } from "./ColorPickerModal";
import TerminalThemeEditorModal from "./TerminalThemeEditorModal";
import { clampScrollback, DEFAULT_SCROLLBACK, MAX_SCROLLBACK, MIN_SCROLLBACK } from "../util/terminalSettings";
import { useConfirm } from "../ui/confirm";
import { IS_ANDROID } from "../util/platform";

const SETTINGS_TAB_KEY = "solanum-settings-tab";

type SettingsTab = "appearance" | "terminal" | "highlighting" | "activity" | "maintenance";

const TABS: { id: SettingsTab; label: string; icon: any }[] = [
  { id: "appearance", label: "Appearance", icon: Palette },
  { id: "terminal", label: "Terminal", icon: Settings },
  { id: "highlighting", label: "Highlighting", icon: Highlighter },
  { id: "activity", label: "Activity", icon: List },
  { id: "maintenance", label: "Maintenance", icon: RefreshCw },
];

const PREVIEW_TEXT = 'The disk reported an ERROR after a WARNING about a timeout; here is some INFO — the retry finished with SUCCESS.';

// Reuses the real matching engine (not a copy) — findHighlightMatches is the
// exact same boundary-checked matcher the terminal's highlighter uses on real terminal
// output, so the preview can never show something the terminal wouldn't
// actually do (or vice versa). Forced "on" regardless of the master toggle,
// since the point is to preview the effect before committing to it.
function previewSegments(lists: HighlightList[]): { text: string; color?: string }[] {
  const matcher = compileHighlightMatcher(true, lists);
  if (!matcher) return [{ text: PREVIEW_TEXT }];
  const matches = findHighlightMatches(PREVIEW_TEXT, matcher);
  if (matches.length === 0) return [{ text: PREVIEW_TEXT }];
  const segments: { text: string; color?: string }[] = [];
  let last = 0;
  for (const m of matches) {
    if (m.start > last) segments.push({ text: PREVIEW_TEXT.slice(last, m.start) });
    segments.push({ text: m.text, color: m.color });
    last = m.end;
  }
  if (last < PREVIEW_TEXT.length) segments.push({ text: PREVIEW_TEXT.slice(last) });
  return segments;
}

// Shared by the Primary Accent and Background Theme pickers — preset
// swatches, then the user's own saved ones (removable on hover; presets
// aren't), then a dashed "+" tile that opens ColorPickerModal. Module-level
// (not defined inside SettingsPanel) since it holds no state of its own and
// a component nested in a render function would remount every render for
// no benefit.
function ColorGrid({ presets, customs, selected, onSelect, onAdd, onRemove }: {
  presets: { name: string; value: string }[];
  customs: SavedColor[];
  selected: string;
  onSelect: (value: string) => void;
  onAdd: () => void;
  onRemove: (id: string) => void;
}) {
  const swatchClass = (active: boolean) =>
    `w-full aspect-square rounded-xl border-2 transition-all ${active ? 'border-white scale-110 shadow-lg' : 'border-transparent hover:scale-105'}`;
  return (
    <div className="grid grid-cols-6 gap-3">
      {presets.map((c) => (
        <button key={c.value} onClick={() => onSelect(c.value)} className={swatchClass(selected === c.value)} style={{ backgroundColor: c.value }} title={c.name} />
      ))}
      {customs.map((c) => (
        <div key={c.id} className="relative group">
          <button onClick={() => onSelect(c.value)} className={swatchClass(selected === c.value)} style={{ backgroundColor: c.value }} title={c.name} />
          <button
            onClick={(e) => { e.stopPropagation(); onRemove(c.id); }}
            title="Remove this color"
            className="absolute -top-1.5 -right-1.5 w-4 h-4 rounded-full bg-black border border-white/20 text-zinc-300 hover:text-rose-300 hover:border-rose-400 flex items-center justify-center opacity-100 sm:opacity-0 sm:group-hover:opacity-100 transition-opacity"
          >
            <X size={9} />
          </button>
        </div>
      ))}
      <button
        onClick={onAdd}
        title="Add a custom color"
        className="w-full aspect-square rounded-xl border-2 border-dashed border-white/15 text-zinc-500 hover:border-primary/50 hover:text-primary flex items-center justify-center transition-all"
      >
        <Plus size={16} />
      </button>
    </div>
  );
}

const SettingsPanel = ({ settings, setSettings, onOpenLogs }: any) => {
  const confirm = useConfirm();
  const [historyNote, setHistoryNote] = useState<{ text: string; ok: boolean } | null>(null);
  // Command history lives in the profile's vault; this removes every row and
  // saves the vault (deleted rows are overwritten, not left in the file).
  const clearCommandHistory = async () => {
    const ok = await confirm({
      title: "Clear command history?",
      message: "Every command recorded in this profile is deleted, for all servers. The backup Solanum made when you unlocked this profile still holds the old list until you unlock it again.",
      okLabel: "Clear",
      destructive: true,
      safeDefault: true,
    });
    if (!ok) return;
    try {
      await invoke("cmd_history_clear");
      setHistoryNote({ text: "Command history cleared.", ok: true });
    } catch (e) {
      setHistoryNote({ text: `Could not clear it: ${e}`, ok: false });
    }
  };
  const [tab, setTab] = useState<SettingsTab>(() => {
    const stored = localStorage.getItem(SETTINGS_TAB_KEY) as SettingsTab | null;
    return stored && TABS.some((t) => t.id === stored) ? stored : "appearance";
  });
  const selectTab = (t: SettingsTab) => {
    setTab(t);
    try { localStorage.setItem(SETTINGS_TAB_KEY, t); } catch { /* per-viewer convenience only */ }
  };

  const accentColors = [
    { name: 'Light Blue', value: '#60a5fa' },
    { name: 'Sky', value: '#38bdf8' },
    { name: 'Cyan', value: '#22d3ee' },
    { name: 'Indigo', value: '#818cf8' },
    { name: 'Emerald', value: '#10b981' },
    { name: 'Rose', value: '#f43f5e' },
  ];

  const bgColors = [
    { name: 'Onyx', value: '#050505' },
    { name: 'Charcoal', value: '#0a0a0c' },
    { name: 'Slate', value: '#0f172a' },
    { name: 'Nord', value: '#2e3440' },
    { name: 'Dark Gray', value: '#1a1a1a' },
    { name: 'Deep Space', value: '#0d0d10' },
  ];

  // User-saved colors, on top of the two preset lists above. One
  // localStorage key for both grids (per-device, like everything else on
  // this page) — a small blob, no reason to split it in two.
  const CUSTOM_COLORS_KEY = "solanum-custom-colors";
  const loadCustomColors = (): { accent: SavedColor[]; background: SavedColor[] } => {
    try {
      const raw = localStorage.getItem(CUSTOM_COLORS_KEY);
      const parsed = raw ? JSON.parse(raw) : {};
      return { accent: Array.isArray(parsed.accent) ? parsed.accent : [], background: Array.isArray(parsed.background) ? parsed.background : [] };
    } catch { return { accent: [], background: [] }; }
  };
  const [customColors, setCustomColors] = useState(loadCustomColors);
  const persistCustomColors = (next: { accent: SavedColor[]; background: SavedColor[] }) => {
    setCustomColors(next);
    try { localStorage.setItem(CUSTOM_COLORS_KEY, JSON.stringify(next)); }
    catch { /* quota or private-mode storage — ignore */ }
  };
  const addCustomColor = (kind: "accent" | "background", color: SavedColor) => {
    persistCustomColors({ ...customColors, [kind]: [...customColors[kind], color] });
  };
  const removeCustomColor = (kind: "accent" | "background", id: string) => {
    persistCustomColors({ ...customColors, [kind]: customColors[kind].filter((c) => c.id !== id) });
  };
  // Which grid the picker modal is editing for, or null when it's closed.
  const [colorPickerTarget, setColorPickerTarget] = useState<"accent" | "background" | null>(null);

  // User-created terminal themes, on top of the built-in list. Kept as its
  // own state (not re-read from localStorage on every render) so saving or
  // deleting one re-renders the <select> and delete button immediately —
  // resolveTerminalTheme/resolveTerminalThemeId (util/terminalThemes.ts)
  // independently read the same storage directly, which is what lets the
  // terminal itself resolve a custom theme id without this component in
  // the loop at all.
  const [customTerminalThemes, setCustomTerminalThemes] = useState<TerminalTheme[]>(loadCustomTerminalThemes);
  const allThemes = [...TERMINAL_THEMES, ...customTerminalThemes];
  const [themeEditorOpen, setThemeEditorOpen] = useState(false);
  const saveNewTerminalTheme = (theme: TerminalTheme) => {
    const next = [...customTerminalThemes, theme];
    setCustomTerminalThemes(next);
    saveCustomTerminalThemes(next);
    setSettings({ ...settings, terminalThemeId: theme.id });
    setThemeEditorOpen(false);
  };
  const deleteCustomTerminalTheme = (id: string) => {
    const next = customTerminalThemes.filter((t) => t.id !== id);
    setCustomTerminalThemes(next);
    saveCustomTerminalThemes(next);
    // The theme that was just deleted can't stay selected — fall back to
    // the default the same way a stale localStorage id already would.
    if (settings.terminalThemeId === id) {
      setSettings({ ...settings, terminalThemeId: DEFAULT_TERMINAL_THEME_ID });
    }
  };

  // Resolved once so every row's `selected` check agrees on the same
  // fallback rule terminalFontFamily() uses for the terminal itself — an
  // id that no longer matches anything (e.g. a stale localStorage value)
  // falls back to the actual default instead of leaving no row selected.
  const currentFontId = resolveTerminalFontId(settings.terminalFontFamily);
  // Same reasoning, plus: resolving the actual colors here (not just the id)
  // lets the preview swatch below track "Match App Colors" live as the user
  // drags the accent/background pickers, the same way the terminal itself does.
  const currentThemeId = resolveTerminalThemeId(settings.terminalThemeId);
  const currentThemeColors = resolveTerminalTheme(currentThemeId, settings.primaryColor, settings.backgroundColor);

  return (
    <div className="flex-1 p-4 sm:p-10 overflow-y-auto custom-scrollbar animate-in">
      <header className="mb-6 sm:mb-8">
        <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight flex items-center gap-3">
          <Settings size={24} className="text-primary" /> Settings
        </h2>
        <p className="text-[13px] text-zinc-400 mt-2">
          Tweak how Solanum looks and feels.
          {' '}
          <span className="text-zinc-500 italic">Per-device — preferences live in this machine's local storage.</span>
        </p>
      </header>

      {/* Segmented control — one focused category at a time instead of a
          wall of cards of uneven height. Same pill pattern already used for
          the Library rail's Commands/Notes switch. */}
      <div className="flex items-center gap-1 mb-6 sm:mb-8 bg-black/30 border border-white/5 rounded-xl p-0.5 w-fit max-w-full overflow-x-auto">
        {TABS.map((t) => {
          if (t.id === "activity" && !onOpenLogs) return null;
          const active = tab === t.id;
          return (
            <button
              key={t.id}
              onClick={() => selectTab(t.id)}
              className={`h-8 px-2.5 sm:px-3 rounded-lg text-[11px] font-bold uppercase tracking-wider transition-all flex items-center gap-1.5 whitespace-nowrap shrink-0 ${
                active ? "bg-primary/15 text-primary shadow-inner" : "text-zinc-400 hover:text-zinc-100"
              }`}
            >
              <t.icon size={12} /> <span className="hidden sm:inline">{t.label}</span>
            </button>
          );
        })}
      </div>

      <div className="max-w-3xl space-y-3">
        {tab === "appearance" && (
          <section className="space-y-3">
            <div className="flex items-center gap-2 text-zinc-400 font-bold uppercase tracking-widest text-xs">
              <Palette size={14} /> UI Customization
            </div>
            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-8 shadow-xl">
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <label className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Primary Accent Color</label>
                  <div className="flex items-center gap-2">
                    <input
                      type="color"
                      value={settings.primaryColor}
                      onChange={(e) => setSettings({ ...settings, primaryColor: e.target.value })}
                      className="w-6 h-6 rounded-md bg-transparent cursor-pointer border-none p-0"
                    />
                    <input
                      type="text"
                      value={settings.primaryColor}
                      onChange={(e) => setSettings({ ...settings, primaryColor: e.target.value })}
                      className="w-20 h-6 bg-black border border-white/10 rounded px-1.5 text-[10px] font-mono text-zinc-400 focus:border-primary/50 outline-none"
                    />
                  </div>
                </div>
                <ColorGrid
                  presets={accentColors}
                  customs={customColors.accent}
                  selected={settings.primaryColor}
                  onSelect={(value) => setSettings({ ...settings, primaryColor: value })}
                  onAdd={() => setColorPickerTarget("accent")}
                  onRemove={(id) => removeCustomColor("accent", id)}
                />
              </div>

              <div className="space-y-4 pt-6 border-t border-white/5">
                <div className="flex justify-between items-center">
                  <label className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Background Theme</label>
                  <div className="flex items-center gap-2">
                    <input
                      type="color"
                      value={settings.backgroundColor}
                      onChange={(e) => setSettings({ ...settings, backgroundColor: e.target.value })}
                      className="w-6 h-6 rounded-md bg-transparent cursor-pointer border-none p-0"
                    />
                    <input
                      type="text"
                      value={settings.backgroundColor}
                      onChange={(e) => setSettings({ ...settings, backgroundColor: e.target.value })}
                      className="w-20 h-6 bg-black border border-white/10 rounded px-1.5 text-[10px] font-mono text-zinc-400 focus:border-primary/50 outline-none"
                    />
                  </div>
                </div>
                <ColorGrid
                  presets={bgColors}
                  customs={customColors.background}
                  selected={settings.backgroundColor}
                  onSelect={(value) => setSettings({ ...settings, backgroundColor: value })}
                  onAdd={() => setColorPickerTarget("background")}
                  onRemove={(id) => removeCustomColor("background", id)}
                />
              </div>
            </div>
          </section>
        )}

        {tab === "terminal" && (
          <section className="space-y-3">
            <div className="flex items-center gap-2 text-zinc-400 font-bold uppercase tracking-widest text-xs">
              <Settings size={14} /> Terminal Configuration
            </div>
            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-4 shadow-xl">
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <label className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Font Size (px)</label>
                  <input
                    type="number"
                    value={settings.terminalFontSize || 14}
                    onChange={(e) => setSettings({ ...settings, terminalFontSize: parseInt(e.target.value) || 14 })}
                    className="w-16 h-8 bg-black border border-white/10 rounded-lg px-2 text-[12px] font-bold text-white focus:border-primary/50 outline-none text-center"
                  />
                </div>
                <input
                  type="range"
                  min="1"
                  max="24"
                  value={settings.terminalFontSize || 14}
                  onChange={(e) => setSettings({ ...settings, terminalFontSize: parseInt(e.target.value) || 14 })}
                  className="w-full accent-primary"
                />
              </div>
            </div>

            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 shadow-xl">
              <ScrollbackField
                value={settings.terminalScrollback ?? DEFAULT_SCROLLBACK}
                onChange={(n) => setSettings({ ...settings, terminalScrollback: n })}
              />
            </div>

            {/* Bundled, not system fonts — a font name shown here is always
                actually available, unlike the old 'Consolas, "Courier New",
                monospace' stack, which silently fell through both named fonts
                on Linux (neither is normally installed there) to whatever
                generic "monospace" happened to resolve to, with metrics
                xterm's cursor rendering wasn't necessarily well-matched to.
                Each row previews the font's own name and a sample line
                rendered IN that font, so the effect is visible before
                committing to it — same idea as the highlight list's preview. */}
            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-3 shadow-xl">
              <label className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Font</label>
              <div className="space-y-1.5">
                {TERMINAL_FONTS.map((font) => {
                  const selected = currentFontId === font.id;
                  return (
                    <button
                      key={font.id}
                      onClick={() => setSettings({ ...settings, terminalFontFamily: font.id })}
                      className={`w-full text-left px-3 py-2.5 rounded-xl border transition-all flex items-center justify-between gap-3 ${
                        selected
                          ? "bg-primary/10 border-primary/40"
                          : "bg-black/20 border-white/5 hover:bg-white/[0.04] hover:border-white/10"
                      }`}
                    >
                      <div className="min-w-0">
                        <div
                          className={`text-[12px] font-bold uppercase tracking-wider ${selected ? "text-primary" : "text-zinc-500"}`}
                        >
                          {font.label}
                        </div>
                        {/* The actual preview — deliberately NOT in the label
                            above, which stays in the UI's own font so it's
                            legible as a plain setting name. 0O/1lI show the
                            zero/one/L/I disambiguation every one of these
                            fonts is specifically designed around (the whole
                            point of picking a coding font over a generic
                            system one), and != -> => are there because Fira
                            Code's signature trait is rendering those as
                            ligatures — without a sequence that triggers one,
                            it looks like just another sans monospace font
                            next to the other four. */}
                        <div className="text-[16px] text-zinc-200 mt-1 truncate" style={{ fontFamily: font.family }}>
                          0O 1lI {'!='} {'->'} {'=>'} fn()
                        </div>
                      </div>
                      {selected && <Check size={14} className="text-primary shrink-0" />}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* "Match App Colors" (the default) isn't a fixed palette — it
                derives background/cursor/selection from the Appearance
                accent + background pickers above, which is what makes e.g.
                setting the background to pure #000000 for an OLED screen
                actually reach the terminal. Named themes override that with
                their own authentic, fixed palette instead. */}
            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-3 shadow-xl">
              <label className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Terminal Theme</label>
              <div className="flex items-center gap-2">
                <select
                  value={currentThemeId}
                  onChange={(e) => setSettings({ ...settings, terminalThemeId: e.target.value })}
                  className="flex-1 min-w-0 h-9 bg-[#1a1a1e] rounded-lg px-3 text-[12px] text-white border border-white/10 outline-none focus:border-primary/50 focus:bg-[#232328] transition-all shadow-inner"
                >
                  {allThemes.map((t) => (
                    <option key={t.id} value={t.id}>{t.label}</option>
                  ))}
                </select>
                {customTerminalThemes.some((t) => t.id === currentThemeId) && (
                  <button
                    onClick={() => deleteCustomTerminalTheme(currentThemeId)}
                    title="Delete this theme"
                    className="shrink-0 h-9 w-9 rounded-lg bg-white/[0.04] border border-white/10 text-zinc-400 hover:text-rose-300 hover:border-rose-400/50 flex items-center justify-center transition-colors"
                  >
                    <Trash2 size={13} />
                  </button>
                )}
                <button
                  onClick={() => setThemeEditorOpen(true)}
                  title="Create a custom theme"
                  className="shrink-0 h-9 px-3 rounded-lg bg-white/[0.04] border border-white/10 text-zinc-300 hover:bg-white/10 hover:text-white flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider transition-colors"
                >
                  <Plus size={13} /> New
                </button>
              </div>
              <div
                className="flex items-center gap-1.5 px-2.5 h-9 rounded-lg border border-white/10"
                style={{ backgroundColor: currentThemeColors.background }}
              >
                <span className="text-[12px] font-mono mr-1" style={{ color: currentThemeColors.foreground }}>Aa</span>
                {/* "Match App Colors" leaves the ANSI slots undefined on
                    purpose (xterm's own built-in colors show through) — a
                    row of six swatches would just be six copies of the
                    accent color, implying a palette that isn't real. Only
                    named themes, which always define all six, show it. */}
                {currentThemeColors.red && (["red", "green", "yellow", "blue", "magenta", "cyan"] as const).map((k) => (
                  <span key={k} className="w-4 h-4 rounded-sm shrink-0" style={{ backgroundColor: currentThemeColors[k] }} />
                ))}
              </div>
            </div>

            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-4 shadow-xl">
              <div className="space-y-2">
                <label className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Cursor Style</label>
                <div className="grid grid-cols-2 gap-2">
                  {([
                    { id: "block", label: "Block" },
                    { id: "bar", label: "Line" },
                  ] as const).map((opt) => {
                    const selected = (settings.terminalCursorStyle || "block") === opt.id;
                    return (
                      <button
                        key={opt.id}
                        onClick={() => setSettings({ ...settings, terminalCursorStyle: opt.id })}
                        className={`px-3 py-2.5 rounded-xl border transition-all text-[12px] font-bold uppercase tracking-wider ${
                          selected
                            ? "bg-primary/10 border-primary/40 text-primary"
                            : "bg-black/20 border-white/5 text-zinc-500 hover:bg-white/[0.04] hover:border-white/10"
                        }`}
                      >
                        {opt.label}
                      </button>
                    );
                  })}
                </div>
              </div>
              <div className="flex items-center justify-between gap-4 pt-3 border-t border-white/5">
                <div>
                  <div className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Blinking Cursor</div>
                  {/* xterm's blink animation doesn't reliably render for the
                      Line style in the version this app is pinned to —
                      rather than ship a toggle that silently does nothing,
                      it's disabled (and forced off) whenever Line is picked. */}
                  {settings.terminalCursorStyle === "bar" && (
                    <p className="text-[10px] text-zinc-600 mt-1 leading-snug">Not supported with the Line style.</p>
                  )}
                </div>
                <button
                  type="button"
                  disabled={settings.terminalCursorStyle === "bar"}
                  onClick={() => setSettings({ ...settings, terminalCursorBlink: !settings.terminalCursorBlink })}
                  role="switch"
                  aria-checked={settings.terminalCursorStyle === "bar" ? false : settings.terminalCursorBlink}
                  className={`relative shrink-0 w-11 h-6 rounded-full transition-colors disabled:opacity-30 disabled:cursor-not-allowed ${
                    settings.terminalCursorStyle !== "bar" && settings.terminalCursorBlink ? "bg-primary" : "bg-white/10"
                  }`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-zinc-100 rounded-full shadow transition-transform ${
                      settings.terminalCursorStyle !== "bar" && settings.terminalCursorBlink ? "translate-x-5" : "translate-x-0"
                    }`}
                  />
                </button>
              </div>
            </div>

            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 shadow-xl">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <div className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">PuTTY-style copy/paste</div>
                  <p className="text-[11px] text-zinc-600 mt-1 leading-snug">
                    {settings.puttyClipboard
                      ? "On: selecting text copies it immediately, and right-click pastes."
                      : "Off: right-click opens a menu with Copy and Paste instead."}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setSettings({ ...settings, puttyClipboard: !settings.puttyClipboard })}
                  role="switch"
                  aria-checked={settings.puttyClipboard}
                  className={`relative shrink-0 w-11 h-6 rounded-full transition-colors ${settings.puttyClipboard ? "bg-primary" : "bg-white/10"}`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-zinc-100 rounded-full shadow transition-transform ${settings.puttyClipboard ? "translate-x-5" : "translate-x-0"}`}
                  />
                </button>
              </div>
            </div>

            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 shadow-xl">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <div className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Ask before a paste that could run commands</div>
                  <p className="text-[11px] text-zinc-600 mt-1 leading-snug">
                    {settings.confirmRiskyPaste
                      ? "On (default): a paste holding control characters, or several lines the program would run one by one (no bracketed paste), shows them first."
                      : "Off: every paste goes straight to the terminal. Bracketed-paste markers inside the text are still removed."}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setSettings({ ...settings, confirmRiskyPaste: !settings.confirmRiskyPaste })}
                  role="switch"
                  aria-checked={settings.confirmRiskyPaste}
                  className={`relative shrink-0 w-11 h-6 rounded-full transition-colors ${settings.confirmRiskyPaste ? "bg-primary" : "bg-white/10"}`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-zinc-100 rounded-full shadow transition-transform ${settings.confirmRiskyPaste ? "translate-x-5" : "translate-x-0"}`}
                  />
                </button>
              </div>
            </div>

            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 shadow-xl">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <div className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Warn before closing an active session</div>
                  <p className="text-[11px] text-zinc-600 mt-1 leading-snug">
                    {settings.warnOnCloseActiveSession
                      ? "On: closing a session's tab, or one of its terminal tabs, asks first if a shell is still running in it."
                      : "Off: closing happens immediately, with no prompt. The SSH connection is still closed properly either way."}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setSettings({ ...settings, warnOnCloseActiveSession: !settings.warnOnCloseActiveSession })}
                  role="switch"
                  aria-checked={settings.warnOnCloseActiveSession}
                  className={`relative shrink-0 w-11 h-6 rounded-full transition-colors ${settings.warnOnCloseActiveSession ? "bg-primary" : "bg-white/10"}`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-zinc-100 rounded-full shadow transition-transform ${settings.warnOnCloseActiveSession ? "translate-x-5" : "translate-x-0"}`}
                  />
                </button>
              </div>
            </div>

            {IS_ANDROID && <ScreenPrivacyCard />}

            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 shadow-xl">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <div className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Command history search (Ctrl+R)</div>
                  <p className="text-[11px] text-zinc-600 mt-1 leading-snug">
                    {settings.useCommandHistorySearch
                      ? "On: Ctrl+R opens a searchable history of commands you've run, across every server."
                      : "Off (default): Ctrl+R goes straight to the shell, for its own native reverse-search."}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setSettings({ ...settings, useCommandHistorySearch: !settings.useCommandHistorySearch })}
                  role="switch"
                  aria-checked={settings.useCommandHistorySearch}
                  className={`relative shrink-0 w-11 h-6 rounded-full transition-colors ${settings.useCommandHistorySearch ? "bg-primary" : "bg-white/10"}`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-zinc-100 rounded-full shadow transition-transform ${settings.useCommandHistorySearch ? "translate-x-5" : "translate-x-0"}`}
                  />
                </button>
              </div>
            </div>

            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 shadow-xl">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <div className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Text-expansion snippets</div>
                  <p className="text-[11px] text-zinc-600 mt-1 leading-snug">
                    {settings.useTextSnippets
                      ? "On: a trigger word (defined in Library › Snippets) followed by Space or Tab expands in place; followed by Enter it expands without running, and the next Enter runs the line. Only on a line typed key by key and shown as typed, never at a password prompt."
                      : "Off (default): what you type is exactly what reaches the shell."}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setSettings({ ...settings, useTextSnippets: !settings.useTextSnippets })}
                  role="switch"
                  aria-checked={settings.useTextSnippets}
                  className={`relative shrink-0 w-11 h-6 rounded-full transition-colors ${settings.useTextSnippets ? "bg-primary" : "bg-white/10"}`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-zinc-100 rounded-full shadow transition-transform ${settings.useTextSnippets ? "translate-x-5" : "translate-x-0"}`}
                  />
                </button>
              </div>
            </div>

            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-3 shadow-xl">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <div className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Always save terminal output to file</div>
                  <p className="text-[11px] text-zinc-600 mt-1 leading-snug">
                    {settings.alwaysLogSessions
                      ? "On: every terminal writes a full transcript to the folder below as it goes, named after the server and when it opened."
                      : "Off (default): nothing is written automatically — use a tab's own \"Save output to file\" for a one-off copy."}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={async () => {
                    const next = !settings.alwaysLogSessions;
                    // Resolve a concrete default the first time this is turned
                    // on (if the user hasn't already picked a folder) so Rust
                    // never has to guess one — empty stays empty if the lookup
                    // fails, which just means logging quietly no-ops until a
                    // folder is chosen below.
                    if (next && !settings.sessionLogDir) {
                      try {
                        const home = await invoke<string>("local_home_dir");
                        const sep = home.includes("\\") ? "\\" : "/";
                        setSettings({ ...settings, alwaysLogSessions: next, sessionLogDir: `${home}${sep}Solanum Logs` });
                        return;
                      } catch { /* fall through — toggle on anyway, pick a folder manually below */ }
                    }
                    setSettings({ ...settings, alwaysLogSessions: next });
                  }}
                  role="switch"
                  aria-checked={settings.alwaysLogSessions}
                  className={`relative shrink-0 w-11 h-6 rounded-full transition-colors ${settings.alwaysLogSessions ? "bg-primary" : "bg-white/10"}`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-zinc-100 rounded-full shadow transition-transform ${settings.alwaysLogSessions ? "translate-x-5" : "translate-x-0"}`}
                  />
                </button>
              </div>
              {settings.alwaysLogSessions && (
                <div className="flex items-center gap-2 pt-1">
                  <input
                    type="text"
                    readOnly
                    value={settings.sessionLogDir || "Choose a folder…"}
                    title={settings.sessionLogDir || undefined}
                    className="flex-1 min-w-0 h-8 px-2 bg-black border border-white/10 rounded-lg text-[11px] font-mono text-zinc-400 truncate"
                  />
                  <button
                    onClick={async () => {
                      try {
                        const picked = await invoke<string | null>("select_local_folder");
                        if (picked) setSettings({ ...settings, sessionLogDir: picked });
                      } catch { /* native dialog unavailable (e.g. Android) — field stays as-is */ }
                    }}
                    title="Choose folder"
                    className="shrink-0 h-8 px-3 rounded-lg bg-white/[0.04] border border-white/10 text-zinc-300 hover:bg-white/10 flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider"
                  >
                    <FolderSearch size={12} /> Browse
                  </button>
                </div>
              )}
            </div>
          </section>
        )}

        {tab === "highlighting" && <HighlightingSection settings={settings} setSettings={setSettings} />}

        {tab === "activity" && onOpenLogs && (
          <section className="space-y-3">
            <div className="flex items-center gap-2 text-zinc-400 font-bold uppercase tracking-widest text-xs">
              <List size={14} /> Activity Log
            </div>
            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-4 shadow-xl">
              <p className="text-sm text-zinc-400 leading-relaxed">
                Diagnostic timeline of what the app has been doing this session. Useful for confirming a connection actually failed or watching a transfer's progress in retrospect.
              </p>
              <button
                onClick={onOpenLogs}
                className="px-4 h-9 bg-primary/10 border border-primary/30 text-primary rounded-xl text-xs font-bold uppercase hover:bg-primary hover:text-zinc-950 transition-all w-full flex items-center justify-center gap-2"
              >
                <List size={14} /> View Activity Log
              </button>
            </div>
          </section>
        )}

        {tab === "maintenance" && (
          <section className="space-y-3">
            <div className="flex items-center gap-2 text-zinc-400 font-bold uppercase tracking-widest text-xs">
              <RefreshCw size={14} /> Maintenance
            </div>
            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-4 shadow-xl">
              <p className="text-sm text-zinc-400 leading-relaxed">
                These preferences are persisted in your local environment. Resetting will revert all UI aesthetics, terminal settings, and highlight rules to factory defaults.
              </p>
              <button
                onClick={async () => {
                  // The in-app dialog: window.confirm() does nothing in
                  // Android's WebView, so the reset never ran there.
                  const ok = await confirm({
                    title: "Reset to defaults?",
                    message: "Every UI customization goes back to its default, highlight rules included.",
                    okLabel: "Reset",
                    destructive: true,
                  });
                  if (ok) {
                    setSettings((s: any) => ({
                      ...s,
                      primaryColor: '#60a5fa',
                      backgroundColor: '#0a0a0c',
                      terminalFontSize: 14,
                      terminalScrollback: DEFAULT_SCROLLBACK,
                      terminalFontFamily: DEFAULT_TERMINAL_FONT_ID,
                      terminalCursorStyle: 'block',
                      terminalCursorBlink: true,
                      terminalThemeId: DEFAULT_TERMINAL_THEME_ID,
                      warnOnCloseActiveSession: true,
                      confirmRiskyPaste: true,
                      useCommandHistorySearch: false,
                      useTextSnippets: false,
                      // sessionLogDir is deliberately left alone — resetting
                      // display/behavior defaults shouldn't throw away a
                      // folder choice that took an actual picker round-trip.
                      alwaysLogSessions: false,
                      highlightEnabled: true,
                      highlightLists: DEFAULT_HIGHLIGHT_LISTS,
                    }));
                  }
                }}
                className="px-4 h-9 bg-zinc-900 border border-white/5 text-zinc-300 rounded-xl text-xs font-bold uppercase hover:bg-white/5 transition-all w-full"
              >
                Reset to Defaults
              </button>
            </div>
            <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-4 shadow-xl">
              <p className="text-sm text-zinc-400 leading-relaxed">
                Commands you type in terminals are kept in this profile's vault for the Ctrl+R search: only lines that were shown on screen as you typed them, so not what you type at a password prompt. A session's tab menu can turn this off for that session.
              </p>
              <button
                onClick={() => { void clearCommandHistory(); }}
                className="px-4 h-9 bg-zinc-900 border border-rose-500/20 text-rose-300 rounded-xl text-xs font-bold uppercase hover:bg-rose-500/10 transition-all w-full"
              >
                Clear Command History
              </button>
              {historyNote && (
                <p className={`text-[11px] ${historyNote.ok ? "text-emerald-400" : "text-rose-300"}`}>{historyNote.text}</p>
              )}
            </div>
          </section>
        )}
      </div>

      <ColorPickerModal
        isOpen={colorPickerTarget !== null}
        initialValue={colorPickerTarget === "accent" ? settings.primaryColor : settings.backgroundColor}
        onCancel={() => setColorPickerTarget(null)}
        onSave={({ name, value }) => {
          if (!colorPickerTarget) return;
          const color: SavedColor = { id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, name, value };
          addCustomColor(colorPickerTarget, color);
          setSettings({ ...settings, [colorPickerTarget === "accent" ? "primaryColor" : "backgroundColor"]: value });
          setColorPickerTarget(null);
        }}
      />

      <TerminalThemeEditorModal
        isOpen={themeEditorOpen}
        onCancel={() => setThemeEditorOpen(false)}
        onSave={saveNewTerminalTheme}
      />
    </div>
  );
};

// Lines of output a terminal keeps. Typed into a draft and applied on blur or
// Enter, clamped to the allowed range, so typing "5" on the way to "500000"
// does not shrink every open terminal's buffer to the minimum.
const ScrollbackField = ({ value, onChange }: { value: number; onChange: (n: number) => void }) => {
  const [draft, setDraft] = useState(String(value));
  const [lastValue, setLastValue] = useState(value);
  if (value !== lastValue) {
    setLastValue(value);
    setDraft(String(value));
  }
  const commit = () => {
    const n = clampScrollback(parseInt(draft, 10));
    setDraft(String(n));
    if (n !== value) onChange(n);
  };
  return (
    <div className="flex items-center justify-between gap-4">
      <div>
        <div className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Scrollback (lines)</div>
        <p className="text-[11px] text-zinc-600 mt-1 leading-snug">
          Lines each terminal keeps ({MIN_SCROLLBACK.toLocaleString()} to {MAX_SCROLLBACK.toLocaleString()}). Memory grows with it: about 100 MB per 100,000 full lines at 80 columns, more in wider terminals. "Always save terminal output to file" keeps everything.
        </p>
      </div>
      <input
        type="number"
        min={MIN_SCROLLBACK}
        max={MAX_SCROLLBACK}
        step={1000}
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onBlur={commit}
        onKeyDown={(e) => { if (e.key === "Enter") commit(); }}
        className="w-28 h-8 shrink-0 bg-black border border-white/10 rounded-lg px-2 text-[12px] font-bold text-white focus:border-primary/50 outline-none text-center"
      />
    </div>
  );
};

const HighlightingSection = ({ settings, setSettings }: any) => {
  const lists: HighlightList[] = settings.highlightLists || [];
  const enabled: boolean = settings.highlightEnabled;

  const updateLists = (next: HighlightList[]) => setSettings({ ...settings, highlightLists: next });
  const toggleEnabled = () => setSettings({ ...settings, highlightEnabled: !enabled });
  const toggleList = (id: string) => updateLists(lists.map((l) => (l.id === id ? { ...l, enabled: !l.enabled } : l)));
  const renameList = (id: string, name: string) => updateLists(lists.map((l) => (l.id === id ? { ...l, name } : l)));
  const deleteList = (id: string) => updateLists(lists.filter((l) => l.id !== id));
  const addList = (name: string) =>
    updateLists([...lists, { id: genId("list"), name, enabled: true, rules: [] }]);
  const updateRule = (listId: string, ruleId: string, patch: Partial<HighlightRule>) =>
    updateLists(lists.map((l) => (l.id !== listId ? l : { ...l, rules: l.rules.map((r) => (r.id === ruleId ? { ...r, ...patch } : r)) })));
  const deleteRule = (listId: string, ruleId: string) =>
    updateLists(lists.map((l) => (l.id !== listId ? l : { ...l, rules: l.rules.filter((r) => r.id !== ruleId) })));
  const addRule = (listId: string, pattern: string, color: string) =>
    updateLists(
      lists.map((l) => (l.id !== listId ? l : { ...l, rules: [...l.rules, { id: genId("rule"), pattern, color, enabled: true }] }))
    );

  return (
    <section className="space-y-3">
      <div className="flex items-center gap-2 text-zinc-400 font-bold uppercase tracking-widest text-xs">
        <Highlighter size={14} /> Text Highlighting
      </div>
      <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 space-y-6 shadow-xl">
        <div className="flex items-center justify-between gap-4">
          <div>
            <div className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Highlight keywords in terminal output</div>
            <p className="text-[11px] text-zinc-600 mt-1 leading-snug">Color words like "error" or "warning" automatically, MobaXterm-style.</p>
          </div>
          <button
            type="button"
            onClick={toggleEnabled}
            role="switch"
            aria-checked={enabled}
            className={`relative shrink-0 w-11 h-6 rounded-full transition-colors ${enabled ? "bg-primary" : "bg-white/10"}`}
          >
            <span
              className={`absolute top-0.5 left-0.5 w-5 h-5 bg-zinc-100 rounded-full shadow transition-transform ${enabled ? "translate-x-5" : "translate-x-0"}`}
            />
          </button>
        </div>

        <div className={`rounded-xl border border-white/5 bg-black/30 px-4 py-3 font-mono text-[11.5px] leading-relaxed transition-opacity ${enabled ? "" : "opacity-40"}`}>
          {previewSegments(lists).map((seg, i) =>
            seg.color ? (
              <span key={i} style={{ color: seg.color }} className="font-bold">{seg.text}</span>
            ) : (
              <span key={i} className="text-zinc-400">{seg.text}</span>
            )
          )}
        </div>

        <div className="space-y-3">
          {lists.map((list) => (
            <HighlightListCard
              key={list.id}
              list={list}
              onToggle={() => toggleList(list.id)}
              onRename={(name: string) => renameList(list.id, name)}
              onDelete={() => deleteList(list.id)}
              onAddRule={(pattern: string, color: string) => addRule(list.id, pattern, color)}
              onUpdateRule={(ruleId: string, patch: Partial<HighlightRule>) => updateRule(list.id, ruleId, patch)}
              onDeleteRule={(ruleId: string) => deleteRule(list.id, ruleId)}
            />
          ))}
        </div>
        <AddListRow onAdd={addList} />
      </div>
    </section>
  );
};

const HighlightListCard = ({ list, onToggle, onRename, onDelete, onAddRule, onUpdateRule, onDeleteRule }: any) => {
  const [expanded, setExpanded] = useState(true);
  const [renaming, setRenaming] = useState(false);
  const [draftName, setDraftName] = useState(list.name);
  const [newPattern, setNewPattern] = useState("");
  const [newColor, setNewColor] = useState("#60a5fa");
  // Escape unmounts this input (renaming -> false), and browsers fire a
  // native blur as part of removing a focused element — which would
  // otherwise re-run onBlur's commitRename with the very text Escape just
  // discarded. Set synchronously in the same handler, before that blur can
  // fire, so onBlur can tell "cancelled" apart from "clicked away".
  const cancellingRef = useRef(false);

  const commitRename = () => {
    if (cancellingRef.current) { cancellingRef.current = false; return; }
    onRename(draftName.trim() || list.name);
    setRenaming(false);
  };
  const commitNewRule = () => {
    const pattern = newPattern.trim();
    if (!pattern) return;
    onAddRule(pattern, newColor);
    setNewPattern("");
  };

  return (
    <div className="rounded-xl border border-white/5 bg-black/20">
      <div className="flex items-center gap-2 px-3 h-11">
        <button onClick={() => setExpanded((e) => !e)} className="text-zinc-500 hover:text-zinc-300 shrink-0">
          {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </button>
        <button
          type="button"
          role="switch"
          aria-checked={list.enabled}
          onClick={onToggle}
          title={list.enabled ? "Disable this list" : "Enable this list"}
          className={`relative shrink-0 w-8 h-[18px] rounded-full transition-colors ${list.enabled ? "bg-primary" : "bg-white/10"}`}
        >
          <span
            className={`absolute top-0.5 left-0.5 w-[14px] h-[14px] bg-zinc-100 rounded-full shadow transition-transform ${list.enabled ? "translate-x-[14px]" : "translate-x-0"}`}
          />
        </button>
        {renaming ? (
          <input
            autoFocus
            value={draftName}
            onChange={(e) => setDraftName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") { e.preventDefault(); commitRename(); }
              if (e.key === "Escape") {
                e.preventDefault();
                cancellingRef.current = true;
                setDraftName(list.name);
                setRenaming(false);
              }
            }}
            onBlur={commitRename}
            className="flex-1 h-7 bg-black border border-primary/40 rounded px-2 text-[12px] font-bold text-white outline-none min-w-0"
          />
        ) : (
          <button
            onClick={() => !list.builtin && setRenaming(true)}
            className="flex-1 text-left text-[12px] font-bold text-zinc-200 truncate min-w-0"
            title={list.builtin ? list.name : "Click to rename"}
          >
            {list.name}
          </button>
        )}
        <span className="text-[10px] text-zinc-600 font-mono shrink-0">{list.rules.length}</span>
        {!list.builtin && (
          <button onClick={onDelete} title="Delete list" className="p-1 rounded text-zinc-600 hover:text-rose-400 hover:bg-white/5 shrink-0">
            <Trash2 size={13} />
          </button>
        )}
      </div>
      {expanded && (
        <div className="border-t border-white/5 px-3 py-2.5 space-y-1.5">
          {list.rules.length === 0 && <p className="text-[11px] text-zinc-600 italic py-1">No rules yet.</p>}
          {list.rules.map((rule: HighlightRule) => (
            <div key={rule.id} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={rule.enabled}
                onChange={(e) => onUpdateRule(rule.id, { enabled: e.target.checked })}
                className="w-3.5 h-3.5 accent-primary shrink-0"
              />
              <input
                value={rule.pattern}
                onChange={(e) => onUpdateRule(rule.id, { pattern: e.target.value })}
                className="flex-1 h-7 bg-black/40 border border-white/10 rounded px-2 text-[11.5px] text-zinc-200 outline-none focus:border-primary/50 min-w-0"
              />
              <input
                type="color"
                value={rule.color}
                onChange={(e) => onUpdateRule(rule.id, { color: e.target.value })}
                className="w-6 h-6 rounded-md bg-transparent cursor-pointer border-none p-0 shrink-0"
              />
              <button onClick={() => onDeleteRule(rule.id)} className="p-1 rounded text-zinc-600 hover:text-rose-400 hover:bg-white/5 shrink-0">
                <Trash2 size={12} />
              </button>
            </div>
          ))}
          <div className="flex items-center gap-2 pt-1">
            <div className="w-3.5 shrink-0" />
            <input
              value={newPattern}
              onChange={(e) => setNewPattern(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); commitNewRule(); } }}
              placeholder="Add a word or phrase…"
              className="flex-1 h-7 bg-black/40 border border-dashed border-white/10 rounded px-2 text-[11.5px] text-zinc-400 outline-none focus:border-primary/50 placeholder:text-zinc-600 min-w-0"
            />
            <input
              type="color"
              value={newColor}
              onChange={(e) => setNewColor(e.target.value)}
              className="w-6 h-6 rounded-md bg-transparent cursor-pointer border-none p-0 shrink-0"
            />
            <button onClick={commitNewRule} title="Add rule" className="p-1 rounded text-primary hover:bg-primary/10 shrink-0">
              <Plus size={14} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

const AddListRow = ({ onAdd }: any) => {
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const commit = () => {
    const trimmed = name.trim();
    if (trimmed) onAdd(trimmed);
    setCreating(false);
    setName("");
  };

  if (!creating) {
    return (
      <button
        onClick={() => setCreating(true)}
        className="inline-flex items-center gap-1.5 h-8 px-3 rounded-lg bg-white/5 border border-white/10 text-zinc-300 text-[11px] font-bold uppercase tracking-wider hover:bg-white/10 hover:text-white transition-colors"
      >
        <Plus size={13} /> New list
      </button>
    );
  }
  return (
    <div className="flex items-center gap-1.5 animate-in fade-in">
      <input
        autoFocus
        value={name}
        onChange={(e) => setName(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") { e.preventDefault(); commit(); }
          if (e.key === "Escape") { e.preventDefault(); setCreating(false); setName(""); }
        }}
        placeholder="List name…"
        className="h-8 w-48 px-2.5 bg-black/40 border border-primary/40 rounded-lg text-[12px] font-bold text-white outline-none"
      />
      <button onClick={commit} title="Create list" className="w-8 h-8 flex items-center justify-center text-emerald-400 hover:bg-white/10 rounded-lg transition-colors">
        <Check size={14} />
      </button>
      <button onClick={() => { setCreating(false); setName(""); }} title="Cancel" className="w-8 h-8 flex items-center justify-center text-zinc-400 hover:text-rose-400 hover:bg-white/10 rounded-lg transition-colors">
        <X size={14} />
      </button>
    </div>
  );
};

export default SettingsPanel;

// Android only: Settings > "Hide Solanum from screenshots and Recents"
// (FLAG_SECURE). Kept by the Android side, which applies it before the first
// frame; this card only reads and changes it.
const ScreenPrivacyCard = () => {
  const [on, setOn] = useState<boolean | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let cancelled = false;
    invoke<boolean>("android_screen_privacy")
      .then((v) => { if (!cancelled) setOn(v); })
      .catch((e) => { if (!cancelled) setError(String(e)); });
    return () => { cancelled = true; };
  }, []);
  const toggle = () => {
    if (on === null) return;
    const next = !on;
    invoke("android_set_screen_privacy", { on: next })
      .then(() => { setOn(next); setError(""); })
      .catch((e) => setError(String(e)));
  };
  return (
    <div className="bg-[#121215] border border-white/5 rounded-2xl p-6 shadow-xl">
      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="text-[11px] font-black text-zinc-500 uppercase tracking-wider">Hide Solanum from screenshots and Recents</div>
          <p className="text-[11px] text-zinc-600 mt-1 leading-snug">
            {on === false
              ? "Off: screenshots, screen recordings, casting and the Recents preview show Solanum's window."
              : "On (default): Android shows Solanum's window blank in screenshots, screen recordings, casting and the Recents preview. Turn it off to take a screenshot."}
          </p>
          {error && <p className="text-[11px] text-rose-400 mt-1 leading-snug">{error}</p>}
        </div>
        <button
          type="button"
          disabled={on === null}
          onClick={toggle}
          role="switch"
          aria-checked={on === true}
          className={`relative shrink-0 w-11 h-6 rounded-full transition-colors disabled:opacity-30 ${on ? "bg-primary" : "bg-white/10"}`}
        >
          <span
            className={`absolute top-0.5 left-0.5 w-5 h-5 bg-zinc-100 rounded-full shadow transition-transform ${on ? "translate-x-5" : "translate-x-0"}`}
          />
        </button>
      </div>
    </div>
  );
};
