#!/usr/bin/env node
// Checks that the four places describing the app's IPC surface agree:
//
//   1. the `#[tauri::command]` functions in src-tauri/src/*.rs (names and
//      parameters; Tauri turns `snake_case` parameters into `camelCase` keys),
//   2. the `tauri::generate_handler![...]` registration list in lib.rs,
//   3. the app permissions in src-tauri/permissions/*.toml that a capability
//      in src-tauri/capabilities/ grants (what the webview may call), and
//   4. every `invoke(...)` call in src/ (including the few whose command name is
//      a ternary of two string literals, directly or through a `const` just
//      above), with the keys of its argument object.
//
// Fails (exit 1) on: a command invoked but not registered or not permitted; a
// command registered but not defined, or defined but not registered; a command
// registered or permitted that no screen calls (except NOT_CALLED_YET); an
// argument key the command does not take; a required parameter not sent;
// arguments it cannot read (anything but an object literal, or a `const` one
// in scope); and any way of reaching IPC it does not follow (importing invoke
// under another name, calling it as a property or passing it around, Tauri's
// IPC object, a dynamic import of @tauri-apps/api/core).
//
// Usage: node scripts/check-ipc.mjs   (or `npm run check:ipc`). Node built-ins only.

import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, relative, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const RUST_DIR = join(ROOT, "src-tauri", "src");
const PERMISSIONS_DIR = join(ROOT, "src-tauri", "permissions");
const CAPABILITIES_DIR = join(ROOT, "src-tauri", "capabilities");
const FRONTEND_DIR = join(ROOT, "src");

// Registered on purpose although no screen calls them yet. They must not be
// granted to the webview either (granted implies called).
const NOT_CALLED_YET = {};

// Parameters Tauri fills in itself; the webview never sends them.
const INJECTED_TYPE = /^(?:tauri::)?(?:State\s*<|AppHandle\b|Window\b|WebviewWindow\b|Webview\b|ipc::Request\b|ipc::Invoke\b)/;

const errors = [];
const fail = (msg) => errors.push(msg);
const rel = (p) => relative(ROOT, p).split("\\").join("/");

function listFiles(dir, exts) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listFiles(full, exts));
    else if (exts.some((e) => entry.name.endsWith(e))) out.push(full);
  }
  return out.sort();
}

function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text[i] === "\n") line++;
  return line;
}

// ---- Rust -------------------------------------------------------------------

// Blanks out comments (keeping offsets and newlines) so that a comment quoting
// `#[tauri::command]` or `generate_handler!` cannot be mistaken for code.
function stripRustComments(src) {
  const out = src.split("");
  let i = 0;
  const blank = (from, to) => { for (let k = from; k < to; k++) if (out[k] !== "\n") out[k] = " "; };
  while (i < src.length) {
    const c = src[i], n = src[i + 1];
    if (c === "/" && n === "/") {
      const end = src.indexOf("\n", i);
      const stop = end === -1 ? src.length : end;
      blank(i, stop);
      i = stop;
    } else if (c === "/" && n === "*") {
      let depth = 1, k = i + 2;
      while (k < src.length && depth > 0) {
        if (src[k] === "/" && src[k + 1] === "*") { depth++; k += 2; }
        else if (src[k] === "*" && src[k + 1] === "/") { depth--; k += 2; }
        else k++;
      }
      blank(i, k);
      i = k;
    } else if (c === "r" && (n === "#" || n === '"') && !/[A-Za-z0-9_]/.test(src[i - 1] || "")) {
      const m = /^r(#*)"/.exec(src.slice(i, i + 300));
      if (!m) { i++; continue; }
      const close = '"' + m[1];
      const end = src.indexOf(close, i + m[0].length);
      i = end === -1 ? src.length : end + close.length;
    } else if (c === '"') {
      let k = i + 1;
      while (k < src.length && src[k] !== '"') k += src[k] === "\\" ? 2 : 1;
      i = k + 1;
    } else if (c === "'") {
      // Char literal ('x', '\n', '\u{1F}') or a lifetime ('_, 'a).
      if (n === "\\") {
        const end = src.indexOf("'", i + 2);
        i = end === -1 ? src.length : end + 1;
      } else if (src[i + 2] === "'") {
        i += 3;
      } else {
        i++;
      }
    } else {
      i++;
    }
  }
  return out.join("");
}

// Splits on commas that are not nested inside <>, (), [] or {}.
function splitTopLevel(s) {
  const parts = [];
  let depth = 0, cur = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if ("<([{".includes(c)) depth++;
    else if (")]}".includes(c) || (c === ">" && s[i - 1] !== "-" && s[i - 1] !== "=")) depth--;
    if (c === "," && depth === 0) { parts.push(cur); cur = ""; } else cur += c;
  }
  if (cur.trim()) parts.push(cur);
  return parts.map((p) => p.trim()).filter(Boolean);
}

function camelCase(snake) {
  const words = snake.replace(/^_+/, "").split("_").filter(Boolean);
  return words.map((w, i) => (i === 0 ? w : w[0].toUpperCase() + w.slice(1))).join("");
}

function readRustCommands() {
  const commands = new Map(); // name -> { file, line, params: [{ key, optional }] }
  for (const file of listFiles(RUST_DIR, [".rs"])) {
    const src = stripRustComments(readFileSync(file, "utf8"));
    const re = /#\[tauri::command(\s*\(([^)]*)\))?\s*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>{]*>)?\s*\(/g;
    let m;
    while ((m = re.exec(src))) {
      const name = m[3];
      const snakeKeys = /rename_all\s*=\s*"snake_case"/.test(m[2] || "");
      let depth = 1, k = re.lastIndex;
      while (k < src.length && depth > 0) {
        if (src[k] === "(") depth++;
        else if (src[k] === ")") depth--;
        k++;
      }
      const params = [];
      for (const param of splitTopLevel(src.slice(re.lastIndex, k - 1))) {
        const colon = param.indexOf(":");
        if (colon === -1) { fail(`${rel(file)}:${lineOf(src, m.index)}: cannot read a parameter of ${name}: ${param}`); continue; }
        const pname = param.slice(0, colon).replace(/^mut\s+/, "").trim();
        const ptype = param.slice(colon + 1).trim();
        if (INJECTED_TYPE.test(ptype)) continue;
        params.push({ key: snakeKeys ? pname : camelCase(pname), optional: /^Option\s*</.test(ptype) });
      }
      if (commands.has(name)) fail(`command ${name} is defined twice (${commands.get(name).file} and ${rel(file)})`);
      commands.set(name, { file: rel(file), line: lineOf(src, m.index), params });
    }
  }
  return commands;
}

function readRegistered() {
  const file = join(RUST_DIR, "lib.rs");
  const src = stripRustComments(readFileSync(file, "utf8"));
  const start = src.indexOf("generate_handler![");
  if (start === -1) { fail("lib.rs: no generate_handler! list found"); return []; }
  const end = src.indexOf("]", start);
  const names = src.slice(start + "generate_handler![".length, end)
    .split(",").map((s) => s.trim()).filter(Boolean)
    .map((s) => s.split("::").pop());
  const seen = new Set();
  for (const n of names) {
    if (seen.has(n)) fail(`lib.rs: ${n} is registered twice`);
    seen.add(n);
  }
  return names;
}

// ---- Permissions ------------------------------------------------------------

// Returns null when the app has no permission files (Tauri then lets the local
// webview call every registered command), else the set of commands granted.
function readPermitted() {
  if (!existsSync(PERMISSIONS_DIR)) return null;
  const permissions = new Map(); // identifier -> commands it allows
  for (const file of listFiles(PERMISSIONS_DIR, [".toml"])) {
    const text = readFileSync(file, "utf8").replace(/^\s*#.*$/gm, "");
    for (const block of text.split(/^\s*\[\[permission\]\]\s*$/m).slice(1)) {
      const id = /^\s*identifier\s*=\s*"([^"]+)"/m.exec(block);
      const allow = /^\s*commands\.allow\s*=\s*\[([\s\S]*?)\]/m.exec(block);
      if (!id) { fail(`${rel(file)}: a [[permission]] without an identifier`); continue; }
      const cmds = allow ? [...allow[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]) : [];
      if (/^\s*commands\.deny\s*=/m.test(block)) fail(`${rel(file)}: ${id[1]} uses commands.deny, which this check does not understand`);
      permissions.set(id[1], { file: rel(file), cmds });
    }
  }
  const granted = new Set();
  const used = new Set();
  for (const file of listFiles(CAPABILITIES_DIR, [".json"])) {
    const cap = JSON.parse(readFileSync(file, "utf8"));
    for (const entry of cap.permissions || []) {
      const id = typeof entry === "string" ? entry : entry.identifier;
      if (id && permissions.has(id)) {
        used.add(id);
        for (const c of permissions.get(id).cmds) granted.add(c);
      }
    }
  }
  for (const [id, p] of permissions) if (!used.has(id)) fail(`${p.file}: permission ${id} is not granted by any capability`);
  for (const p of permissions.values()) {
    const seen = new Set();
    for (const c of p.cmds) { if (seen.has(c)) fail(`${p.file}: ${c} is listed twice`); seen.add(c); }
  }
  return granted;
}

// ---- Frontend ---------------------------------------------------------------

const REGEX_PREFIX_KEYWORDS = new Set(["return", "typeof", "case", "in", "of", "new", "delete", "void", "throw", "else", "do", "yield", "await"]);

// Blanks out comments in TypeScript (keeping offsets), tracking strings,
// template literals (with nested `${}`), and regex literals.
function stripTsComments(src) {
  const out = src.split("");
  const blank = (from, to) => { for (let k = from; k < to; k++) if (out[k] !== "\n") out[k] = " "; };
  const braceStack = []; // for each open `${`, the brace depth to return to a template
  let braceDepth = 0;
  let lastSignificant = ""; // last non-space token char (or word) outside comments
  let i = 0;

  const readTemplate = (from) => {
    // src[from] is the char after the opening backtick (or after a closing `}` of `${}`)
    let k = from;
    while (k < src.length) {
      if (src[k] === "\\") { k += 2; continue; }
      if (src[k] === "`") return { end: k + 1, open: false };
      if (src[k] === "$" && src[k + 1] === "{") return { end: k + 2, open: true };
      k++;
    }
    return { end: src.length, open: false };
  };

  while (i < src.length) {
    const c = src[i], n = src[i + 1];
    if (c === "/" && n === "/") {
      const end = src.indexOf("\n", i);
      const stop = end === -1 ? src.length : end;
      blank(i, stop);
      i = stop;
      continue;
    }
    if (c === "/" && n === "*") {
      const end = src.indexOf("*/", i + 2);
      const stop = end === -1 ? src.length : end + 2;
      blank(i, stop);
      i = stop;
      continue;
    }
    if (c === '"' || c === "'") {
      let k = i + 1;
      while (k < src.length && src[k] !== c && src[k] !== "\n") k += src[k] === "\\" ? 2 : 1;
      i = k + 1;
      lastSignificant = "a";
      continue;
    }
    if (c === "`") {
      const t = readTemplate(i + 1);
      if (t.open) { braceStack.push(braceDepth); braceDepth++; }
      i = t.end;
      lastSignificant = "a";
      continue;
    }
    if (c === "{") { braceDepth++; lastSignificant = c; i++; continue; }
    if (c === "}") {
      braceDepth--;
      if (braceStack.length && braceStack[braceStack.length - 1] === braceDepth) {
        braceStack.pop();
        const t = readTemplate(i + 1);
        if (t.open) { braceStack.push(braceDepth); braceDepth++; }
        i = t.end;
        lastSignificant = "a";
        continue;
      }
      lastSignificant = c;
      i++;
      continue;
    }
    if (c === "/") {
      const regexAllowed = lastSignificant === "" || "(,=:[!&|?{};+-*%<>~^".includes(lastSignificant) || REGEX_PREFIX_KEYWORDS.has(lastSignificant);
      if (regexAllowed) {
        let k = i + 1, inClass = false;
        while (k < src.length && src[k] !== "\n") {
          if (src[k] === "\\") { k += 2; continue; }
          if (src[k] === "[") inClass = true;
          else if (src[k] === "]") inClass = false;
          else if (src[k] === "/" && !inClass) break;
          k++;
        }
        k++;
        while (/[a-z]/.test(src[k] || "")) k++;
        i = k;
        lastSignificant = "a";
        continue;
      }
      lastSignificant = c;
      i++;
      continue;
    }
    if (/\s/.test(c)) { i++; continue; }
    if (/[A-Za-z_$]/.test(c)) {
      let k = i;
      while (/[A-Za-z0-9_$]/.test(src[k] || "")) k++;
      const word = src.slice(i, k);
      lastSignificant = REGEX_PREFIX_KEYWORDS.has(word) ? word : "a";
      i = k;
      continue;
    }
    lastSignificant = /[0-9.]/.test(c) ? "a" : c;
    i++;
  }
  return out.join("");
}

// From `src[open]` (an opening bracket), the index just past its match. Skips
// strings and template literals; comments are already blank.
function matchBracket(src, open) {
  const pairs = { "(": ")", "{": "}", "[": "]", "<": ">" };
  const stack = [pairs[src[open]]];
  let k = open + 1;
  while (k < src.length && stack.length) {
    const c = src[k];
    if (c === '"' || c === "'" || c === "`") { k = skipString(src, k); continue; }
    if (stack[stack.length - 1] === ">" ) {
      if (c === "<") stack.push(">");
      else if (c === ">" && src[k - 1] !== "=") stack.pop();
      k++;
      continue;
    }
    if (pairs[c] && c !== "<") stack.push(pairs[c]);
    else if (c === stack[stack.length - 1]) stack.pop();
    k++;
  }
  return k;
}

function skipString(src, i) {
  const q = src[i];
  let k = i + 1;
  if (q === "`") {
    while (k < src.length && src[k] !== "`") {
      if (src[k] === "\\") { k += 2; continue; }
      if (src[k] === "$" && src[k + 1] === "{") { k = matchBracket(src, k + 1); continue; }
      k++;
    }
    return k + 1;
  }
  while (k < src.length && src[k] !== q) k += src[k] === "\\" ? 2 : 1;
  return k + 1;
}

function splitArgs(src, from, to) {
  const parts = [];
  let k = from, start = from;
  while (k < to) {
    const c = src[k];
    if (c === '"' || c === "'" || c === "`") { k = skipString(src, k); continue; }
    if (c === "(" || c === "{" || c === "[") { k = matchBracket(src, k); continue; }
    if (c === ",") { parts.push(src.slice(start, k)); start = k + 1; }
    k++;
  }
  if (src.slice(start, to).trim()) parts.push(src.slice(start, to));
  return parts.map((p) => p.trim());
}

// `src` with the contents of strings and template literals blanked too, for
// checks about code structure (braces, the word `invoke`).
function blankStrings(src) {
  const out = src.split("");
  let k = 0;
  while (k < src.length) {
    const c = src[k];
    if (c === '"' || c === "'" || c === "`") {
      const end = skipString(src, k);
      for (let i = k + 1; i < end - 1 && i < src.length; i++) if (out[i] !== "\n") out[i] = " ";
      k = end;
    } else k++;
  }
  return out.join("");
}

// Whether a `const`/`let` declared at `decl` is visible at `use`: block
// scoping, judged by braces (the use must not be outside the block that holds
// the declaration).
function inScope(code, decl, use) {
  let depth = 0;
  for (let i = 0; i < decl; i++) depth += code[i] === "{" ? 1 : code[i] === "}" ? -1 : 0;
  let d = depth;
  for (let i = decl; i < use; i++) {
    d += code[i] === "{" ? 1 : code[i] === "}" ? -1 : 0;
    if (d < depth) return false;
  }
  return true;
}

// The nearest declaration of `name` before `use` that is in scope there, as
// the index just past its `=` (or past its opening brace with `object`).
function declarationOf(src, code, name, use, object) {
  const re = new RegExp(`\\b(?:const|let|var)\\s+${name}\\s*(?::[^=]+)?=\\s*${object ? "\\{" : ""}`, "g");
  let found = -1, m;
  while ((m = re.exec(code)) && m.index < use) if (inScope(code, m.index, use)) found = re.lastIndex;
  return found;
}

function stringLiterals(expr) {
  return [...expr.matchAll(/(["'`])((?:\\.|(?!\1)[^\\\n$])*)\1/g)].map((m) => m[2]);
}

// The command name(s) an invoke's first argument can evaluate to.
function commandNames(src, code, callIndex, arg) {
  if (/^["'`]/.test(arg)) return stringLiterals(arg).slice(0, 1);
  if (/^[^"'`]*\?/.test(arg) || /^\(/.test(arg)) {
    const lits = stringLiterals(arg);
    if (lits.length) return lits;
  }
  if (/^[A-Za-z_$][\w$]*$/.test(arg)) {
    // `const cmd = cond ? "a" : "b";` in scope above.
    const at = declarationOf(src, code, arg, callIndex, false);
    if (at !== -1) return stringLiterals(/^[^;\n]+/.exec(src.slice(at))[0]);
  }
  return [];
}

// The object literal a `const NAME = { ... }` in scope above `before` holds,
// or null.
function objectLiteralOf(src, code, name, before) {
  const at = declarationOf(src, code, name, before, true);
  if (at === -1) return null;
  return src.slice(at - 1, matchBracket(src, at - 1));
}

// Top-level keys of an object literal, plus whether something unknown is
// spread into it. A spread of a `const` object literal in scope counts as its
// keys.
function objectKeys(src, code, expr, before) {
  const inner = expr.trim().slice(1, -1);
  const keys = [];
  let open = false;
  for (const entry of splitArgs(inner, 0, inner.length)) {
    if (!entry) continue;
    if (entry.startsWith("...")) {
      const name = entry.slice(3).trim();
      const literal = /^[A-Za-z_$][\w$]*$/.test(name) ? objectLiteralOf(src, code, name, before) : null;
      if (literal) {
        const sub = objectKeys(src, code, literal, before);
        keys.push(...sub.keys);
        open = open || sub.open;
      } else open = true;
      continue;
    }
    if (entry.startsWith("[")) { open = true; continue; }
    const m = /^(?:"([^"]+)"|'([^']+)'|([A-Za-z_$][\w$]*))\s*(?::|$)/.exec(entry);
    if (!m) { open = true; continue; }
    keys.push(m[1] || m[2] || m[3]);
  }
  return { keys, open };
}

function readInvokeSites() {
  const sites = [];
  for (const file of listFiles(FRONTEND_DIR, [".ts", ".tsx"])) {
    const src = stripTsComments(readFileSync(file, "utf8"));
    const code = blankStrings(src);
    const at = (i) => `${rel(file)}:${lineOf(src, i)}`;
    // Only `import { invoke } from "@tauri-apps/api/core"` and direct calls of
    // it are understood; anything else could call a command unseen.
    for (const m of src.matchAll(/\bimport\s+([^;]*?)\s*from\s*["']@tauri-apps\/api\/core["']/g)) {
      if (!/^\{\s*invoke\s*,?\s*\}$/.test(m[1].trim())) fail(`${at(m.index)}: import ${m[1].trim()} from @tauri-apps/api/core: only "import { invoke }" is understood by this check`);
    }
    for (const m of src.matchAll(/\bimport\s*\(\s*["']@tauri-apps\/api\/core["']/g)) fail(`${at(m.index)}: dynamic import of @tauri-apps/api/core`);
    for (const m of code.matchAll(/__TAURI_INTERNALS__\s*[.[]|__TAURI__\b/g)) fail(`${at(m.index)}: uses Tauri's IPC object directly`);
    for (const m of code.matchAll(/(?<![\w$])invoke(?![\w$])/g)) {
      const before = code.slice(Math.max(0, m.index - 2), m.index);
      const after = code.slice(m.index + 6).match(/^\s*(.)/);
      const inImport = /\bimport\s*\{[^}]*$/.test(code.slice(Math.max(0, m.index - 60), m.index));
      if (inImport) continue;
      if (/\.\s*$/.test(before) || /\?\.$/.test(before)) { fail(`${at(m.index)}: calls invoke as a property; call the imported invoke directly`); continue; }
      if (!after || !"<(".includes(after[1])) fail(`${at(m.index)}: uses invoke other than by calling it (an alias would hide the command it calls)`);
    }
    const re = /(?<![\w$.])invoke\s*(?=[<(])/g;
    let m;
    while ((m = re.exec(src))) {
      let k = re.lastIndex;
      if (src[k] === "<") k = matchBracket(src, k);
      while (/\s/.test(src[k])) k++;
      if (src[k] !== "(") continue;
      const close = matchBracket(src, k) - 1;
      const args = splitArgs(src, k + 1, close);
      const where = `${rel(file)}:${lineOf(src, m.index)}`;
      if (!args.length) { fail(`${where}: invoke() without a command name`); continue; }
      const names = commandNames(src, code, m.index, args[0]);
      if (!names.length) { fail(`${where}: cannot tell which command ${args[0]} names`); continue; }
      let keys = [], open = false, checked = true;
      if (args[1] !== undefined) {
        const literal = args[1].startsWith("{") && args[1].endsWith("}")
          ? args[1]
          : /^[A-Za-z_$][\w$]*$/.test(args[1]) ? objectLiteralOf(src, code, args[1], m.index) : null;
        if (literal) ({ keys, open } = objectKeys(src, code, literal, m.index));
        else checked = false;
      }
      // Arguments this check cannot read could hold a wrong key unnoticed.
      if (!checked || open) {
        fail(`${where}: cannot check the arguments of ${names.join("/")}: pass an object literal, or a const object literal declared in the same scope, without other spreads`);
        checked = false;
      }
      sites.push({ where, names, keys, checked, dynamic: names.length > 1 || !/^["'`]/.test(args[0]) });
    }
  }
  return sites;
}

// ---- Checks -----------------------------------------------------------------

const commands = readRustCommands();
const registered = readRegistered();
const registeredSet = new Set(registered);
const permitted = readPermitted();
const sites = readInvokeSites();

for (const name of registered) if (!commands.has(name)) fail(`lib.rs: ${name} is registered but no #[tauri::command] fn ${name} exists`);
for (const [name, c] of commands) if (!registeredSet.has(name)) fail(`${c.file}:${c.line}: ${name} is a command but is not in generate_handler!`);

const invoked = new Set();
for (const site of sites) {
  for (const name of site.names) {
    invoked.add(name);
    if (!registeredSet.has(name)) { fail(`${site.where}: invokes ${name}, which is not registered`); continue; }
    if (permitted && !permitted.has(name)) fail(`${site.where}: invokes ${name}, which no capability grants (src-tauri/permissions/)`);
    const cmd = commands.get(name);
    if (!cmd) continue;
    if (!site.checked) continue;
    const params = new Map(cmd.params.map((p) => [p.key, p]));
    for (const key of site.keys) if (!params.has(key)) fail(`${site.where}: ${name} takes no argument "${key}" (it takes: ${[...params.keys()].join(", ") || "none"})`);
    for (const p of cmd.params) if (!p.optional && !site.keys.includes(p.key)) fail(`${site.where}: ${name} needs "${p.key}", which is not sent`);
  }
}

for (const name of registered) {
  if (invoked.has(name)) {
    if (NOT_CALLED_YET[name]) fail(`${name} is called now: remove it from NOT_CALLED_YET in scripts/check-ipc.mjs`);
    continue;
  }
  if (!NOT_CALLED_YET[name]) fail(`${name} is registered but no screen calls it: remove it, or wire it to the UI`);
}
for (const name of Object.keys(NOT_CALLED_YET)) if (!registeredSet.has(name)) fail(`NOT_CALLED_YET lists ${name}, which is not registered`);

if (permitted) {
  for (const name of permitted) {
    if (!registeredSet.has(name)) fail(`src-tauri/permissions: ${name} is granted but not registered`);
    else if (!invoked.has(name)) fail(`src-tauri/permissions: ${name} is granted to the webview but no screen calls it`);
  }
}

const dynamic = sites.filter((s) => s.dynamic).length;
if (errors.length) {
  console.error(`check-ipc: ${errors.length} problem(s)\n`);
  for (const e of errors) console.error(`  - ${e}`);
  process.exit(1);
}
console.log(
  `check-ipc: ${commands.size} commands, all registered; ` +
  (permitted ? `${permitted.size} granted to the webview; ` : "no app permissions (every registered command is callable); ") +
  `${sites.length} invoke sites (${dynamic} with a computed name), all arguments checked; ` +
  `${Object.keys(NOT_CALLED_YET).length} registered but not called yet (${Object.keys(NOT_CALLED_YET).join(", ")}). OK`,
);
