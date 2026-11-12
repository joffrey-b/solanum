// scripts/generate-licenses.mjs on a fake repository and saved cargo metadata.
// A notice that silently goes missing is what this file exists to catch.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "scripts", "generate-licenses.mjs");
const APACHE = "Apache License\nVersion 2.0, January 2004\n\nTerms of the licence.";

// A WOFF holding only a name table, with one copyright record, stored uncompressed.
function woff(copyright) {
  const string = Buffer.from(copyright, "utf16le").swap16();
  const name = Buffer.alloc(6 + 12 + string.length);
  name.writeUInt16BE(1, 2); // records
  name.writeUInt16BE(18, 4); // where the strings start
  name.writeUInt16BE(3, 6); // platform: Windows
  name.writeUInt16BE(0, 12); // name id: copyright
  name.writeUInt16BE(string.length, 14);
  string.copy(name, 18);
  const head = Buffer.alloc(44 + 20);
  head.write("wOFF", 0, "latin1");
  head.writeUInt16BE(1, 12); // one table
  head.write("name", 44, "latin1");
  head.writeUInt32BE(64, 48); // offset
  head.writeUInt32BE(name.length, 52); // stored
  head.writeUInt32BE(name.length, 56); // original
  return Buffer.concat([head, name]);
}

function crate(tree, name, version, files, extra = {}) {
  const folder = `registry/${name}-${version}`;
  tree[`${folder}/Cargo.toml`] = "";
  for (const [file, text] of Object.entries(files)) tree[`${folder}/${file}`] = text;
  return { name, version, license: "MIT", authors: [], ...extra, folder };
}

// `edit` may change the tree and the crate list before anything is written.
function repository(edit = () => {}) {
  const tree = {
    "package-lock.json": JSON.stringify({
      packages: {
        "": { name: "solanum" },
        "node_modules/react": { version: "18.0.0", license: "MIT" },
        "node_modules/@fontsource/mono": { version: "5.0.0", license: "OFL-1.1" },
        "node_modules/typescript": { version: "5.0.0", license: "Apache-2.0", dev: true },
        "node_modules/tailwindcss": { version: "3.0.0", license: "MIT", dev: true },
        "node_modules/vite": { version: "7.0.0", license: "MIT", dev: true },
      },
    }),
    "node_modules/react/LICENSE": "React licence",
    "node_modules/@fontsource/mono/LICENSE": "Google Inc.\n\nSIL Open Font License",
    "node_modules/@fontsource/mono/files/mono-latin-400-normal.woff": woff("Copyright 2024 The Real Foundry"),
    "node_modules/tailwindcss/LICENSE": "Tailwind licence",
    "node_modules/vite/LICENSE.md": "Vite licence",
    "src-tauri/gen/android/app/build.gradle.kts":
      'dependencies {\n    implementation("androidx.webkit:webkit:1.14.0")\n    testImplementation("junit:junit:4.13.2")\n}\n',
  };
  const crates = [
    crate(tree, "serde", "1.0.0", { "LICENSE-APACHE": APACHE }, { license: "MIT OR Apache-2.0" }),
    crate(tree, "alpha", "1.0.0", { "LICENSE-MIT": "MIT\n\nCopyright Alpha" }),
    crate(tree, "beta", "2.0.0", { "LICENSE-MIT": "MIT   \n\n\nCopyright   Alpha\n" }),
    crate(tree, "gamma", "3.0.0", { "LICENSE-MIT": "MIT\n\nCopyright Gamma" }),
    crate(tree, "bare", "0.1.0", {}, { authors: ["Bare Author <bare@example.invalid>", "Second Author"], repository: "https://example.invalid/bare" }),
    crate(tree, "devonly", "9.0.0", { LICENSE: "Dev only licence" }),
    crate(tree, "oddfiles", "1.0.0", {
      LICENSE: "Oddfiles licence",
      "license.rs": "fn not_a_licence() {}",
      "LICENSE.png": "image\u0000bytes",
      "NOTICE.bin": "binary\u0000notice",
    }),
  ];
  edit(tree, crates);
  return { tree, crates };
}

function metadata(root, crates) {
  const id = (c) => `${c.name} ${c.version}`;
  const rootId = "solanum 0.0.0";
  const packages = [
    { id: rootId, name: "solanum", version: "0.0.0", manifest_path: join(root, "src-tauri/Cargo.toml") },
    ...crates.map((c) => ({ ...c, id: id(c), manifest_path: join(root, c.folder, "Cargo.toml") })),
  ];
  const nodes = [
    {
      id: rootId,
      deps: crates.map((c) => ({ pkg: id(c), dep_kinds: [{ kind: c.name === "devonly" ? "dev" : null }] })),
    },
    ...crates.map((c) => ({ id: id(c), deps: [] })),
  ];
  return JSON.stringify({ packages, resolve: { root: rootId, nodes } });
}

function withRepository(edit, body) {
  const root = mkdtempSync(join(tmpdir(), "solanum-licenses-"));
  try {
    const { tree, crates } = repository(edit);
    for (const [path, content] of Object.entries(tree)) {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), content);
    }
    const saved = join(root, "metadata.json");
    writeFileSync(saved, metadata(root, crates));
    const run = (...args) => spawnSync(process.execPath, [SCRIPT, "--root", root, "--metadata", saved, ...args], { encoding: "utf8" });
    const report = () => readFileSync(join(root, "THIRD-PARTY-LICENSES.txt"), "utf8");
    return body({ root, run, report });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function generated(edit = () => {}) {
  return withRepository(edit, ({ run, report }) => {
    const result = run();
    assert.equal(result.status, 0, result.stderr);
    return report();
  });
}

test("lists crates and npm packages with their licence and text", () => {
  const out = generated();
  assert.match(out, /^alpha 1\.0\.0 {2}\| {2}MIT {2}\| {2}\[\d+\]$/m);
  assert.match(out, /^react 18\.0\.0 {2}\| {2}MIT {2}\| {2}\[\d+\]$/m);
  assert.ok(out.includes("Copyright Alpha"));
  assert.ok(out.includes("React licence"));
});

test("leaves out what is reachable only through a dev-dependency, and dev packages", () => {
  const out = generated();
  assert.ok(!out.includes("devonly"));
  assert.ok(!out.includes("Dev only licence"));
  assert.ok(!out.includes("typescript"));
});

test("keeps the build tools whose output is in the bundle", () => {
  const out = generated();
  assert.ok(out.includes("tailwindcss 3.0.0"));
  assert.ok(out.includes("Tailwind licence"));
  assert.ok(out.includes("Vite licence"), "LICENSE.md counts");
});

test("copies that differ only in white space become one text", () => {
  const out = generated();
  const number = (name) => out.match(new RegExp(`^${name} [^|]+\\|[^|]+\\| {2}\\[(\\d+)\\]$`, "m"))[1];
  assert.equal(number("alpha"), number("beta"));
  assert.equal(out.split("Copyright Alpha").length, 2);
});

test("a copy that names another holder stays", () => {
  const out = generated();
  const number = (name) => out.match(new RegExp(`^${name} [^|]+\\|[^|]+\\| {2}\\[(\\d+)\\]$`, "m"))[1];
  assert.notEqual(number("alpha"), number("gamma"));
  assert.ok(out.includes("Copyright Gamma"));
});

test("a crate with no licence file gets its authors, source and the standard text", () => {
  const out = generated();
  assert.match(out, /^bare 0\.1\.0 {2}\| {2}MIT {2}\| {2}\[\d+\]$/m);
  assert.ok(out.includes("Ships no licence file; the standard text is given. Authors: Bare Author, Second Author. Source: https://example.invalid/bare"));
  assert.ok(out.includes("Permission is hereby granted"));
  assert.ok(!out.includes("bare@example.invalid"), "no e-mail addresses");
});

test("of alternatives, a known text is enough", () => {
  const out = generated((tree, crates) => {
    crates.push(crate(tree, "either", "1.0.0", {}, { license: "Zlib OR Apache-2.0" }));
  });
  assert.match(out, /^either 1\.0\.0 {2}\| {2}Zlib OR Apache-2\.0 {2}\| {2}\[\d+\]$/m);
});

test("a licence nobody can supply stops the script and names the crate", () => {
  withRepository(
    (tree, crates) => { crates.push(crate(tree, "mystery", "1.0.0", {}, { license: "Foo-1.0" })); },
    ({ run }) => {
      const result = run();
      assert.equal(result.status, 1);
      assert.match(result.stderr, /mystery 1\.0\.0/);
      assert.match(result.stderr, /Foo-1\.0/);
    },
  );
});

test("with AND, every part must be known", () => {
  withRepository(
    (tree, crates) => { crates.push(crate(tree, "both", "1.0.0", {}, { license: "MIT AND Foo-1.0" })); },
    ({ run }) => {
      const result = run();
      assert.equal(result.status, 1);
      assert.match(result.stderr, /both 1\.0\.0/);
    },
  );
});

test("takes a font's copyright from the font, next to its licence", () => {
  const out = generated();
  assert.ok(out.includes("Copyright in the font files: Copyright 2024 The Real Foundry"));
  assert.ok(out.includes("SIL Open Font License"));
});

test("skips source files, images and binary files named like licences", () => {
  const out = generated();
  assert.ok(out.includes("Oddfiles licence"));
  assert.ok(!out.includes("not_a_licence"));
  assert.ok(!out.includes("binary"));
  assert.ok(!out.includes("LICENSE.png"));
});

test("line endings and a byte-order mark are not content", () => {
  const out = generated((tree, crates) => {
    crates.push(crate(tree, "crlf", "1.0.0", { LICENSE: "﻿Windows licence\r\nsecond line\r\n" }));
  });
  assert.ok(out.includes("Windows licence\nsecond line"));
  assert.ok(!out.includes("\r"));
  assert.ok(!out.includes("﻿"));
});

test("names the Android libraries and the AppImage's own", () => {
  const out = generated();
  assert.ok(out.includes("androidx.webkit:webkit:1.14.0"));
  assert.ok(!out.includes("junit"), "test libraries do not ship");
  assert.ok(out.includes("The Linux AppImage"));
});

test("the output does not depend on the machine", () => {
  withRepository(undefined, ({ root, run, report }) => {
    run();
    const first = report();
    run();
    assert.equal(report(), first);
    assert.ok(!first.includes(root), "no local path");
    assert.ok(!/20\d\d-\d\d-\d\d/.test(first), "no date");
  });
});

test("packages come out sorted whatever order cargo lists them in", () => {
  const out = generated((tree, crates) => { crates.reverse(); });
  assert.ok(out.indexOf("\nalpha 1.0.0") < out.indexOf("\nbeta 2.0.0"));
  assert.ok(out.indexOf("\nbeta 2.0.0") < out.indexOf("\ngamma 3.0.0"));
});

test("--check passes on a current file and leaves it alone", () => {
  withRepository(undefined, ({ run, report }) => {
    run();
    const before = report();
    const result = run("--check");
    assert.equal(result.status, 0, result.stderr);
    assert.equal(report(), before);
  });
});

test("--check fails on a stale file and on a missing one", () => {
  withRepository(undefined, ({ root, run }) => {
    const missing = run("--check");
    assert.equal(missing.status, 1);
    assert.match(missing.stderr, /missing/);
    run();
    writeFileSync(join(root, "THIRD-PARTY-LICENSES.txt"), "old");
    const stale = run("--check");
    assert.equal(stale.status, 1);
    assert.match(stale.stderr, /out of date/);
  });
});

test("a package that is not installed is an error, not a gap", () => {
  withRepository(
    (tree) => { delete tree["node_modules/react/LICENSE"]; },
    ({ run }) => {
      const result = run();
      assert.equal(result.status, 1);
      assert.match(result.stderr, /react/);
    },
  );
});

test("a package with no licence file is an error, not a gap", () => {
  withRepository(
    (tree) => { tree["node_modules/react/LICENSE"] = ""; },
    ({ run }) => {
      const result = run();
      assert.equal(result.status, 1);
      assert.match(result.stderr, /react ships no licence file/);
    },
  );
});
