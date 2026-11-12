// The file browser's sizes ("1.5 MB"). Units go up to EB, and beyond that the
// number grows: a size never comes out without a unit (R-010).
const UNITS = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];

export function formatSize(bytes: number): string {
  if (!bytes || !Number.isFinite(bytes) || bytes < 0) return "0 B";
  const k = 1024;
  const i = Math.max(0, Math.min(UNITS.length - 1, Math.floor(Math.log(bytes) / Math.log(k))));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + UNITS[i];
}
