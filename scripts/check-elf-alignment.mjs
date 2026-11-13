// Fails unless every loadable segment of each ELF file given is aligned to at
// least 16 KB (N-037). Phones with 16 KB memory pages load a library only when
// its LOAD segments are aligned to that size, and Google Play requires it for
// apps that target Android 15 and later. The alignment comes from the linker
// (`-z max-page-size=16384`, added by `release-rustflags.mjs --android`), so a
// toolchain or flag change can quietly undo it: this is what would say so.
//
// Reads the program headers itself, so no NDK tool is needed:
//   node scripts/check-elf-alignment.mjs src-tauri/target/aarch64-linux-android/release/libsolanum_lib.so
// --min BYTES sets another minimum (a power of two).
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const PT_LOAD = 1;
const PN_XNUM = 0xffff;

// The LOAD segments' alignments of one ELF image, or an error message.
function loadAlignments(bytes) {
  if (bytes.length < 0x34 || bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) {
    return { error: "not an ELF file" };
  }
  const elfClass = bytes[4];
  const data = bytes[5];
  if (elfClass !== 1 && elfClass !== 2) return { error: `unknown ELF class ${elfClass}` };
  if (data !== 1 && data !== 2) return { error: `unknown ELF byte order ${data}` };
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const le = data === 1;
  const is64 = elfClass === 2;
  if (is64 && bytes.length < 0x40) return { error: "truncated ELF header" };
  const u16 = (at) => view.getUint16(at, le);
  const u32 = (at) => view.getUint32(at, le);
  const u64 = (at) => view.getBigUint64(at, le);

  const phoff = is64 ? u64(0x20) : BigInt(u32(0x1c));
  const phentsize = u16(is64 ? 0x36 : 0x2a);
  const phnum = u16(is64 ? 0x38 : 0x2c);
  if (phnum === PN_XNUM) return { error: "more program headers than the header can count (PN_XNUM): not supported" };
  const minEntry = is64 ? 0x38 : 0x20;
  if (phnum > 0 && phentsize < minEntry) return { error: `program header entries of ${phentsize} bytes` };
  const end = phoff + BigInt(phnum) * BigInt(phentsize);
  if (end > BigInt(bytes.length)) return { error: "program headers run past the end of the file" };

  const loads = [];
  for (let i = 0; i < phnum; i++) {
    const at = Number(phoff) + i * phentsize;
    if (u32(at) !== PT_LOAD) continue;
    loads.push(is64 ? u64(at + 0x30) : BigInt(u32(at + 0x1c)));
  }
  if (loads.length === 0) return { error: "no LOAD segment" };
  return { is64, loads };
}

// True when the file passes. Prints one line per file either way.
function checkFile(path, min) {
  let bytes;
  try {
    bytes = readFileSync(path);
  } catch (e) {
    console.error(`check-elf-alignment: ${path}: ${e.message}`);
    return false;
  }
  const r = loadAlignments(bytes);
  if (r.error) {
    console.error(`check-elf-alignment: ${path}: ${r.error}`);
    return false;
  }
  const shown = r.loads.map((a) => `0x${a.toString(16)}`).join(", ");
  const low = r.loads.filter((a) => a < min);
  if (low.length > 0) {
    console.error(
      `check-elf-alignment: ${path}: ${low.length} of ${r.loads.length} LOAD segments aligned below 0x${min.toString(16)} (${shown}); ` +
        "16 KB-page phones and Google Play need -z max-page-size=16384",
    );
    return false;
  }
  console.log(`check-elf-alignment: ${path}: ${r.loads.length} LOAD segments, all aligned to 0x${min.toString(16)} or more (${shown}).`);
  return true;
}

function main(argv) {
  let min = 0x4000n;
  const files = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--min") {
      const value = argv[++i];
      if (!/^[0-9]+$/.test(value ?? "") || BigInt(value) === 0n || (BigInt(value) & (BigInt(value) - 1n)) !== 0n) {
        console.error(`check-elf-alignment: --min takes a power of two, not ${value}`);
        return 2;
      }
      min = BigInt(value);
    } else {
      files.push(argv[i]);
    }
  }
  if (files.length === 0) {
    console.error("usage: node scripts/check-elf-alignment.mjs [--min BYTES] FILE...");
    return 2;
  }
  // Every file is looked at, so one run names all of them.
  const results = files.map((f) => checkFile(f, min));
  return results.every(Boolean) ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
