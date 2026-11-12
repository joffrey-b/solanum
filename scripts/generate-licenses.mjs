// Writes THIRD-PARTY-LICENSES.txt: every Rust crate and npm package Solanum is
// built from, with the licence texts they ship. Node built-ins and cargo only.
//
// Usage: npm run licenses                 write the file
//        npm run check:licenses           fail if the file is out of date (CI)
//        node scripts/generate-licenses.mjs [--check] [--root DIR] [--metadata FILE]
//
// It reads the crates from cargo's registry and the packages from node_modules,
// so it needs `npm ci` first and downloads any crate it is missing. Run it after
// any change to Cargo.lock or package-lock.json.
//
// --metadata reads saved `cargo metadata` output instead of running cargo (the
// tests use it).
//
// The output depends only on the lockfiles: packages and files are sorted, and
// it holds no date or local path, so --check can compare it byte for byte.
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { inflateSync } from "node:zlib";

const OUTPUT = "THIRD-PARTY-LICENSES.txt";

// What ships. A crate only some other platform needs is left out.
const TARGETS = [
  "x86_64-unknown-linux-gnu",
  "x86_64-pc-windows-msvc",
  "aarch64-apple-darwin",
  "aarch64-linux-android",
  "armv7-linux-androideabi",
];

// Development dependencies whose output ends up in the bundle all the same:
// Tailwind's base stylesheet and Vite's module-loading helper.
const BUILD_TOOLS_IN_THE_BUNDLE = ["tailwindcss", "vite"];

const LICENCE_FILE = /^(licen[cs]e|copying|notice|unlicense|copyright)([-._].*)?$/i;
const NOT_LICENCE_TEXT = /\.(rs|toml|json|js|cjs|mjs|ts|map|png|jpg|svg|py|sh|ya?ml|lock|spdx)$/i;

// Some crates ship no licence file. For those, the standard text of what they
// declare comes from a crate that has it unchanged. MIT needs no donor: every
// copy names its own copyright holder, so a template is the honest form.
const STANDARD_TEXT_FROM_CRATE = {
  "Apache-2.0": ["serde", "LICENSE-APACHE"],
  "BSD-3-Clause": ["alloc-no-stdlib", "LICENSE"],
  "BSL-1.0": ["error-code", "LICENSE"],
  "MPL-2.0": ["cssparser", "LICENSE"],
};

const MIT_TEMPLATE = `MIT License

Copyright (c) <year> <copyright holders>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`;

function option(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

function fail(message) {
  console.error(`generate-licenses: ${message}`);
  process.exit(1);
}

const root = option("--root") ?? join(dirname(fileURLToPath(import.meta.url)), "..");
const check = process.argv.includes("--check");

const byCodeUnit = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

// Text as it is shown: line endings and a byte-order mark are not content.
function clean(text) {
  return text.replace(/^﻿/, "").replace(/\r\n?/g, "\n").replace(/[ \t\n]+$/, "");
}

// Two copies are the same licence only if nothing but white space differs, so
// a copy naming another copyright holder always stays.
const sameTextKey = (text) => text.replace(/\s+/g, " ").trim();

function licenceFiles(folder) {
  const out = [];
  const names = readdirSync(folder, { withFileTypes: true })
    .filter((e) => e.isFile() && LICENCE_FILE.test(e.name) && !NOT_LICENCE_TEXT.test(e.name))
    .map((e) => e.name)
    .sort(byCodeUnit);
  for (const name of names) {
    const bytes = readFileSync(join(folder, name));
    if (bytes.includes(0)) continue;
    const text = clean(bytes.toString("utf8"));
    if (text) out.push({ name, text });
  }
  return out;
}

class Texts {
  constructor() {
    this.list = [];
    this.numbers = new Map();
  }
  add(text, origin) {
    const key = sameTextKey(text);
    let number = this.numbers.get(key);
    if (number === undefined) {
      this.list.push({ text, origin });
      number = this.list.length;
      this.numbers.set(key, number);
    }
    return number;
  }
}

function loadMetadata() {
  const saved = option("--metadata");
  if (saved) return JSON.parse(readFileSync(saved, "utf8"));
  const args = ["metadata", "--locked", "--format-version", "1"];
  for (const target of TARGETS) args.push("--filter-platform", target);
  try {
    const out = execFileSync("cargo", args, {
      cwd: join(root, "src-tauri"),
      encoding: "utf8",
      maxBuffer: 1 << 28,
      stdio: ["ignore", "pipe", "inherit"],
    });
    return JSON.parse(out);
  } catch (e) {
    fail(`cargo metadata failed: ${e.message}`);
  }
}

// Everything reachable from Solanum other than through a dev-dependency.
function shippedCrates(metadata) {
  const packages = new Map(metadata.packages.map((p) => [p.id, p]));
  const nodes = new Map(metadata.resolve.nodes.map((n) => [n.id, n]));
  const seen = new Set();
  const pending = [metadata.resolve.root];
  while (pending.length) {
    const id = pending.pop();
    if (seen.has(id)) continue;
    seen.add(id);
    for (const dep of nodes.get(id).deps) {
      if (dep.dep_kinds.some((k) => k.kind !== "dev")) pending.push(dep.pkg);
    }
  }
  seen.delete(metadata.resolve.root);
  return [...seen]
    .map((id) => packages.get(id))
    .sort((a, b) => byCodeUnit(a.name, b.name) || byCodeUnit(a.version, b.version));
}

function standardTextFor(id, crates, texts) {
  if (id === "MIT") return texts.add(MIT_TEMPLATE, "the MIT License, standard text");
  const donor = STANDARD_TEXT_FROM_CRATE[id];
  if (!donor) return undefined;
  const [crateName, file] = donor;
  const crate = crates.find((c) => c.name === crateName);
  if (!crate) fail(`the standard text of ${id} comes from crate ${crateName}, which is gone: name another in STANDARD_TEXT_FROM_CRATE.`);
  const path = join(dirname(crate.manifest_path), file);
  if (!existsSync(path)) fail(`${crateName} no longer ships ${file}: name another donor for ${id}.`);
  return texts.add(clean(readFileSync(path, "utf8")), `${file} of ${crate.name} ${crate.version}`);
}

// The licences of a crate that ships no file. With alternatives ("A OR B"),
// whichever texts are known are enough; with "AND" every one is needed.
function standardTextsOf(crate, crates, texts) {
  const expression = crate.license ?? "";
  const ids = expression.replace(/[()]/g, " ").split(/\s+OR\s+|\s+AND\s+|\s*\/\s*/)
    .map((part) => part.trim().split(/\s+WITH\s+/)[0])
    .filter(Boolean);
  const needsAll = /\bAND\b/.test(expression);
  const numbers = [];
  for (const id of ids) {
    const number = standardTextFor(id, crates, texts);
    if (number !== undefined) numbers.push(number);
    else if (needsAll) fail(`${crate.name} ${crate.version} ships no licence file and needs ${id}: add its text to STANDARD_TEXT_FROM_CRATE.`);
  }
  if (!numbers.length) fail(`${crate.name} ${crate.version} ships no licence file and declares "${expression}": add a text to STANDARD_TEXT_FROM_CRATE.`);
  return numbers;
}

const refs = (numbers) => [...new Set(numbers)].sort((a, b) => a - b).map((n) => `[${n}]`).join(" ");
const withoutEmail = (author) => author.replace(/\s*<[^>]*>/g, "").trim();

function crateSection(crates, texts) {
  const lines = [];
  for (const crate of crates) {
    const folder = dirname(crate.manifest_path);
    if (!existsSync(folder)) fail(`${crate.name} ${crate.version} is not on this machine (${crate.name}'s folder is missing).`);
    const files = licenceFiles(folder);
    if (crate.license_file) {
      const path = join(folder, crate.license_file);
      if (existsSync(path)) files.push({ name: crate.license_file, text: clean(readFileSync(path, "utf8")) });
    }
    const licence = crate.license ?? `see ${crate.license_file ?? "its source"}`;
    if (files.length) {
      const numbers = files.map((f) => texts.add(f.text, `${f.name} of ${crate.name} ${crate.version}`));
      lines.push(`${crate.name} ${crate.version}  |  ${licence}  |  ${refs(numbers)}`);
    } else {
      const numbers = standardTextsOf(crate, crates, texts);
      lines.push(`${crate.name} ${crate.version}  |  ${licence}  |  ${refs(numbers)}`);
      const authors = (crate.authors ?? []).map(withoutEmail).filter(Boolean).join(", ");
      lines.push(`    Ships no licence file; the standard text is given.${authors ? ` Authors: ${authors}.` : ""}${crate.repository ? ` Source: ${crate.repository}` : ""}`);
    }
  }
  return lines;
}

// The copyright string inside a font (the `name` table of its .woff, record 0).
// @fontsource's LICENSE sometimes names the wrong holder; the font does not.
function fontCopyright(file) {
  const woff = readFileSync(file);
  if (woff.toString("latin1", 0, 4) !== "wOFF") fail(`${file} is not a WOFF file.`);
  const tableCount = woff.readUInt16BE(12);
  for (let i = 0; i < tableCount; i += 1) {
    const entry = 44 + 20 * i;
    if (woff.toString("latin1", entry, entry + 4) !== "name") continue;
    const offset = woff.readUInt32BE(entry + 4);
    const stored = woff.readUInt32BE(entry + 8);
    const original = woff.readUInt32BE(entry + 12);
    const raw = woff.subarray(offset, offset + stored);
    const table = stored < original ? inflateSync(raw) : raw;
    const records = table.readUInt16BE(2);
    const strings = table.readUInt16BE(4);
    for (let r = 0; r < records; r += 1) {
      const record = 6 + 12 * r;
      const platform = table.readUInt16BE(record);
      const nameId = table.readUInt16BE(record + 6);
      if (platform !== 3 || nameId !== 0) continue;
      const length = table.readUInt16BE(record + 8);
      const start = strings + table.readUInt16BE(record + 10);
      return Buffer.from(table.subarray(start, start + length)).swap16().toString("utf16le");
    }
  }
  return undefined;
}

function npmSection(texts) {
  const lockPath = join(root, "package-lock.json");
  const lock = JSON.parse(readFileSync(lockPath, "utf8")).packages;
  const wanted = Object.entries(lock)
    .filter(([path, info]) => path && (!info.dev && !info.devOptional))
    .map(([path]) => path);
  for (const name of BUILD_TOOLS_IN_THE_BUNDLE) wanted.push(`node_modules/${name}`);
  const lines = [];
  for (const path of [...new Set(wanted)].sort(byCodeUnit)) {
    const name = path.replace(/^.*node_modules\//, "");
    const info = lock[path];
    if (!info) fail(`${name} is not in package-lock.json.`);
    const folder = join(root, path);
    if (!existsSync(folder)) fail(`${name} is not installed: run npm ci first.`);
    const files = licenceFiles(folder);
    if (!files.length) fail(`${name} ships no licence file: decide what to show for it.`);
    const numbers = files.map((f) => texts.add(f.text, `${f.name} of ${name} ${info.version}`));
    lines.push(`${name} ${info.version}  |  ${info.license}  |  ${refs(numbers)}`);
    if (name.startsWith("@fontsource/")) {
      const slug = name.slice("@fontsource/".length);
      const copyright = fontCopyright(join(folder, "files", `${slug}-latin-400-normal.woff`));
      if (copyright) lines.push(`    Copyright in the font files: ${copyright}`);
    }
  }
  return lines;
}

function otherSection(crates, texts) {
  const apache = standardTextFor("Apache-2.0", crates, texts);
  const mit = standardTextFor("MIT", crates, texts);
  const gradle = readFileSync(join(root, "src-tauri/gen/android/app/build.gradle.kts"), "utf8");
  const android = [...gradle.matchAll(/^\s*implementation\("([^"]+)"\)/gm)].map((m) => m[1]).sort(byCodeUnit);
  return [
    `The Rust standard library  |  MIT OR Apache-2.0  |  ${refs([mit, apache])}`,
    "    Linked into every build.",
    "",
    `Android libraries  |  Apache-2.0  |  ${refs([apache])}`,
    "    In the APK only: these, and the AndroidX and Kotlin libraries they bring in.",
    ...android.map((library) => `    ${library}`),
    "",
    "The Linux AppImage",
    "    Also contains copies of libraries from the Linux system that built it (WebKitGTK,",
    "    GTK, GLib and what they need), most of them under the LGPL. Each keeps its own",
    "    licence. Inside the image, usr/share/doc/solanum/APPIMAGE-LIBRARIES.txt lists",
    "    every one with its package, version, licence and where its source is, followed",
    "    by their copyright files and licence texts, and those of the tools that build",
    "    the image. Each release on GitHub publishes their source beside the AppImage,",
    "    in the file named like it with .sources.tar at the end.",
  ];
}

function rule(character) {
  return character.repeat(78);
}

function render(crateLines, npmLines, otherLines, texts, crateCount) {
  const npmCount = npmLines.filter((line) => !line.startsWith("    ")).length;
  const out = [
    "Third-party software in Solanum",
    rule("="),
    "",
    "Solanum is under GPL-3.0-only (see LICENSE). The notice of the original project it",
    "was forked from is in NOTICE. This file covers what Solanum is built from.",
    "",
    "It is generated from Cargo.lock and package-lock.json by scripts/generate-licenses.mjs:",
    "do not edit it by hand. It covers every platform, so an installer for one platform",
    "holds only a part of this list. Numbers in [brackets] point to section 4.",
    "",
    "  1. Rust crates",
    "  2. npm packages, the terminal fonts among them",
    "  3. Other components",
    "  4. Licence texts",
    "",
    "",
    `1. Rust crates (${crateCount})`,
    rule("-"),
    "",
    ...crateLines,
    "",
    "",
    `2. npm packages (${npmCount})`,
    rule("-"),
    "",
    ...npmLines,
    "",
    "",
    "3. Other components",
    rule("-"),
    "",
    ...otherLines,
    "",
    "",
    `4. Licence texts (${texts.list.length})`,
    rule("-"),
  ];
  texts.list.forEach(({ text, origin }, index) => {
    out.push("", "", rule("="), `[${index + 1}]  ${origin}`, rule("="), "", text);
  });
  return `${out.join("\n")}\n`;
}

const texts = new Texts();
const crates = shippedCrates(loadMetadata());
const crateLines = crateSection(crates, texts);
const npmLines = npmSection(texts);
const otherLines = otherSection(crates, texts);
const report = render(crateLines, npmLines, otherLines, texts, crates.length);

const target = join(root, OUTPUT);
if (check) {
  if (!existsSync(target)) fail(`${OUTPUT} is missing: run npm run licenses.`);
  if (readFileSync(target, "utf8").replace(/\r\n/g, "\n") !== report) {
    fail(`${OUTPUT} is out of date: run npm run licenses and commit the result.`);
  }
  console.log(`generate-licenses: ${OUTPUT} is up to date (${crates.length} crates, ${texts.list.length} licence texts).`);
} else {
  writeFileSync(target, report);
  console.log(`generate-licenses: wrote ${OUTPUT} (${crates.length} crates, ${texts.list.length} licence texts, ${report.length} characters).`);
}
