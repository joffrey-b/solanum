// Keeps build-machine paths out of release binaries: panic locations hold the
// absolute path of every dependency's source file, and `strip` does not remove
// them. A .cargo/config.toml cannot do this, because the paths differ on every
// machine.
//
// Prints the RUSTFLAGS for a release build. The working directory is the
// repository root, or pass --root DIR:
//   bash:       export RUSTFLAGS="$(node scripts/release-rustflags.mjs)"
//   PowerShell: $env:RUSTFLAGS = node scripts/release-rustflags.mjs
//
// rustc applies the last matching flag, so the cargo home wins when it sits
// inside the checkout, as it does in the GitLab Linux jobs.
//
// Add --android for `tauri android build`. Tauri passes its link flags through
// CARGO_TARGET_<triple>_RUSTFLAGS, and RUSTFLAGS replaces that variable, so they
// have to be repeated here. Without them the build still links, and whatever
// needed a missing library only fails on the device. After a Tauri bump, check
// them: run its cargo through a wrapper that logs that variable.
//
// With --check FILE it instead fails if a built binary still holds one of those
// paths, or the toolchain's own folders (the rustup home, and the NDK when
// NDK_HOME or ANDROID_NDK_HOME names one), so that nothing can quietly undo
// this. Those two are not remapped: Rust's standard library comes prebuilt with
// /rustc/<hash> paths, and C code compiled with the NDK keeps its paths only in
// debug information, which release builds strip. The check is what would say
// otherwise.
//   node scripts/release-rustflags.mjs --check src-tauri/target/release/solanum
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

function option(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

const root = resolve(option("--root") ?? process.cwd());
const cargoHome = resolve(process.env.CARGO_HOME || join(homedir(), ".cargo"));

const check = option("--check");
if (check !== undefined) {
  const binary = readFileSync(check);
  const rustupHome = resolve(process.env.RUSTUP_HOME || join(homedir(), ".rustup"));
  const ndk = [process.env.NDK_HOME, process.env.ANDROID_NDK_HOME].filter(Boolean).map((p) => resolve(p));
  const looked = [...new Set([root, cargoHome, rustupHome, ...ndk])];
  const leftovers = looked.filter((path) => binary.includes(path) || binary.includes(path.replaceAll("\\", "/")));
  if (leftovers.length > 0) {
    console.error(`release-rustflags: ${check} still holds a build-machine path: ${leftovers.join(", ")}`);
    process.exit(1);
  }
  console.log(`release-rustflags: ${check} holds no build-machine path.`);
  process.exit(0);
}

// Cargo splits RUSTFLAGS on spaces, so a path with one would break the build
// with a confusing error, or silently leave the path in.
for (const path of [root, cargoHome]) {
  if (/\s/.test(path)) {
    console.error(`release-rustflags: cannot remap a path with whitespace: ${path}`);
    process.exit(1);
  }
}

const flags = [`--remap-path-prefix=${root}=/solanum`, `--remap-path-prefix=${cargoHome}=/cargo`];
if (process.argv.includes("--android")) {
  flags.push("-Clink-arg=-landroid", "-Clink-arg=-llog", "-Clink-arg=-lOpenSLES");
  // N-037: 16 KB-page phones load a library only when its segments are
  // aligned to 16 KB, and Google Play requires it for apps that target
  // Android 15+. NDK 27's linker still defaults to 4 KB; the CI jobs check the
  // result with scripts/check-elf-alignment.mjs.
  flags.push("-Clink-arg=-Wl,-z,max-page-size=16384");
}
console.log(flags.join(" "));
