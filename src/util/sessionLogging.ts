// "Always save terminal output to file" (Settings > Terminal). The
// directory is resolved once (see SettingsPanel's toggle handler) and
// stored as a concrete path — Rust never has to guess a default, it just
// gets a full file path or nothing. This file only builds that path: a
// sanitized server/container name plus a local timestamp, so repeated
// sessions against the same server never collide and sort chronologically
// by filename. Done in JS, not Rust, because Date already does local-time
// formatting without pulling in a date/time crate for one string.

// Characters Windows forbids in names, plus control, invisible and
// text-direction characters (the set the backend refuses in a local file
// name, `local_name_problem`): a container name comes from the server, and
// the backend refuses to create a log whose name contains any of them.
const ILLEGAL_FILENAME_CHARS =
  /[\\/:*?"<>|\u0000-\u001f\u007f-\u009f\u00ad\u034f\u061c\u115f\u1160\u180e\u200b\u200e\u200f\u2028-\u202e\u2060-\u206f\u3164\ufeff\uffa0\ufff9-\ufffb\u{e0000}-\u{e007f}]/gu;

function sanitizeForFilename(name: string): string {
  const cleaned = name.trim().replace(ILLEGAL_FILENAME_CHARS, "_");
  // Keep the whole file name under the 255-byte limit even in a 4-byte script
  // (50 code points + timestamp + a "-2" suffix); count code points so a
  // surrogate pair is never split.
  return Array.from(cleaned).slice(0, 50).join("") || "session";
}

const pad = (n: number) => n.toString().padStart(2, "0");

export function buildSessionLogPath(dir: string, label: string): string {
  const sep = dir.includes("\\") ? "\\" : "/";
  const base = dir.endsWith(sep) ? dir.slice(0, -1) : dir;
  const now = new Date();
  const stamp = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`
    + `_${pad(now.getHours())}-${pad(now.getMinutes())}-${pad(now.getSeconds())}`;
  return `${base}${sep}${sanitizeForFilename(label)}_${stamp}.log`;
}
