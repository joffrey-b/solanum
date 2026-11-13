// scripts/check-elf-alignment.mjs (N-037): it passes an image whose LOAD
// segments are all aligned to 16 KB, fails one with any segment below, and
// fails what it cannot read rather than passing it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "scripts", "check-elf-alignment.mjs");
const PT_LOAD = 1;
const PT_DYNAMIC = 2;

// A minimal ELF image: the header and its program headers, nothing else.
// `segments` is a list of [type, align].
function elf({ is64 = true, littleEndian = true, segments }) {
  const ehsize = is64 ? 0x40 : 0x34;
  const phentsize = is64 ? 0x38 : 0x20;
  const buf = Buffer.alloc(ehsize + segments.length * phentsize);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  buf.set([0x7f, 0x45, 0x4c, 0x46, is64 ? 2 : 1, littleEndian ? 1 : 2, 1], 0);
  view.setUint16(0x10, 3, littleEndian); // ET_DYN
  if (is64) {
    view.setBigUint64(0x20, BigInt(ehsize), littleEndian);
    view.setUint16(0x36, phentsize, littleEndian);
    view.setUint16(0x38, segments.length, littleEndian);
  } else {
    view.setUint32(0x1c, ehsize, littleEndian);
    view.setUint16(0x2a, phentsize, littleEndian);
    view.setUint16(0x2c, segments.length, littleEndian);
  }
  segments.forEach(([type, align], i) => {
    const at = ehsize + i * phentsize;
    view.setUint32(at, type, littleEndian);
    if (is64) view.setBigUint64(at + 0x30, BigInt(align), littleEndian);
    else view.setUint32(at + 0x1c, align, littleEndian);
  });
  return buf;
}

function withFiles(files, body) {
  const dir = mkdtempSync(join(tmpdir(), "solanum-elf-"));
  try {
    const paths = Object.entries(files).map(([name, bytes]) => {
      const path = join(dir, name);
      writeFileSync(path, bytes);
      return path;
    });
    return body(paths, dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const run = (...args) => spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8" });

test("16 KB alignment passes, 64-bit and 32-bit, either byte order", () => {
  const files = {
    "le64.so": elf({ segments: [[PT_LOAD, 0x4000], [PT_DYNAMIC, 8], [PT_LOAD, 0x4000]] }),
    "be64.so": elf({ littleEndian: false, segments: [[PT_LOAD, 0x10000]] }),
    "le32.so": elf({ is64: false, segments: [[PT_LOAD, 0x4000], [PT_LOAD, 0x4000]] }),
  };
  withFiles(files, (paths) => {
    const r = run(...paths);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /le64\.so: 2 LOAD segments, all aligned to 0x4000 or more/);
    assert.match(r.stdout, /be64\.so: 1 LOAD segments/);
  });
});

test("a 4 KB segment fails, and other segment types do not count", () => {
  withFiles({ "lib.so": elf({ segments: [[PT_LOAD, 0x4000], [PT_DYNAMIC, 0x10], [PT_LOAD, 0x1000]] }) }, ([path]) => {
    const r = run(path);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /1 of 2 LOAD segments aligned below 0x4000 \(0x4000, 0x1000\)/);
    assert.match(r.stderr, /max-page-size=16384/);
  });
  withFiles({ "lib32.so": elf({ is64: false, segments: [[PT_LOAD, 0x1000]] }) }, ([path]) => {
    assert.equal(run(path).status, 1);
  });
});

test("every file is looked at: one bad file fails the run and the good one is still reported", () => {
  const files = { "good.so": elf({ segments: [[PT_LOAD, 0x4000]] }), "bad.so": elf({ segments: [[PT_LOAD, 0x1000]] }) };
  withFiles(files, (paths) => {
    const r = run(...paths);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /good\.so/);
    assert.match(r.stderr, /bad\.so/);
  });
});

test("--min sets another minimum and takes only a power of two", () => {
  withFiles({ "lib.so": elf({ segments: [[PT_LOAD, 0x1000]] }) }, ([path]) => {
    assert.equal(run("--min", "4096", path).status, 0);
    assert.equal(run("--min", "65536", path).status, 1);
    assert.equal(run("--min", "12288", path).status, 2);
    assert.equal(run("--min", "abc", path).status, 2);
  });
});

test("what it cannot read fails: not ELF, no LOAD segment, truncated headers, a missing file, no file", () => {
  const truncated = elf({ segments: [[PT_LOAD, 0x4000]] }).subarray(0, 0x50);
  const files = {
    "text.so": Buffer.from("not an ELF file at all, long enough to hold a header........"),
    "noload.so": elf({ segments: [[PT_DYNAMIC, 0x4000]] }),
    "short.so": truncated,
  };
  withFiles(files, ([text, noload, short], dir) => {
    assert.match(run(text).stderr, /not an ELF file/);
    assert.match(run(noload).stderr, /no LOAD segment/);
    assert.match(run(short).stderr, /past the end of the file/);
    for (const path of [text, noload, short, join(dir, "missing.so")]) assert.equal(run(path).status, 1, path);
  });
  assert.equal(run().status, 2);
});
