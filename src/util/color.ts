// Shared hex/RGB/HSV color math. Originally lived inside ColorPickerModal.tsx
// until the terminal-theme custom editor needed the same conversions plus a
// "derive a lighter variant" helper for auto-computed ANSI bright colors —
// pulled out here rather than duplicated a second time.

export const clamp255 = (n: number): number => Math.min(255, Math.max(0, Math.round(n)));
const toHex2 = (n: number): string => clamp255(n).toString(16).padStart(2, "0");
export const rgbToHex = (r: number, g: number, b: number): string => `#${toHex2(r)}${toHex2(g)}${toHex2(b)}`;

// Accepts #rgb or #rrggbb, with or without the leading #.
export function parseHex(input: string): [number, number, number] | null {
  const s = input.trim().replace(/^#/, "");
  if (/^[0-9a-fA-F]{3}$/.test(s)) {
    const [r, g, b] = s.split("").map((c) => parseInt(c + c, 16));
    return [r, g, b];
  }
  if (/^[0-9a-fA-F]{6}$/.test(s)) {
    return [parseInt(s.slice(0, 2), 16), parseInt(s.slice(2, 4), 16), parseInt(s.slice(4, 6), 16)];
  }
  return null;
}

export function hsvToRgb(h: number, s: number, v: number): [number, number, number] {
  s /= 100; v /= 100;
  const c = v * s;
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
  const m = v - c;
  let r = 0, g = 0, b = 0;
  if (h < 60) { r = c; g = x; b = 0; }
  else if (h < 120) { r = x; g = c; b = 0; }
  else if (h < 180) { r = 0; g = c; b = x; }
  else if (h < 240) { r = 0; g = x; b = c; }
  else if (h < 300) { r = x; g = 0; b = c; }
  else { r = c; g = 0; b = x; }
  return [Math.round((r + m) * 255), Math.round((g + m) * 255), Math.round((b + m) * 255)];
}

export function rgbToHsv(r: number, g: number, b: number): [number, number, number] {
  r /= 255; g /= 255; b /= 255;
  const max = Math.max(r, g, b), min = Math.min(r, g, b);
  const d = max - min;
  let h = 0;
  if (d !== 0) {
    if (max === r) h = ((g - b) / d) % 6;
    else if (max === g) h = (b - r) / d + 2;
    else h = (r - g) / d + 4;
    h *= 60;
    if (h < 0) h += 360;
  }
  const s = max === 0 ? 0 : (d / max) * 100;
  const v = max * 100;
  return [h, s, v];
}

// Blends a color toward white by `factor` (0-1) — used to auto-derive an
// ANSI "bright" color from its normal counterpart when the user hasn't
// manually overridden it. A real published palette (Dracula, Nord, ...)
// sometimes barely lightens at all and sometimes repeats the same color
// outright, so there's no one authentic ratio to match; this is a generic,
// reasonable-looking default a manual override can always replace.
export function lightenHex(hex: string, factor: number): string {
  const rgb = parseHex(hex);
  if (!rgb) return hex;
  const [r, g, b] = rgb;
  const blend = (c: number) => c + (255 - c) * factor;
  return rgbToHex(blend(r), blend(g), blend(b));
}
