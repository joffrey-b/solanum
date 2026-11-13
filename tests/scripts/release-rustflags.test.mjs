// scripts/release-rustflags.mjs: what it prints, and that it refuses a path it
// could not express (cargo splits RUSTFLAGS on spaces).
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "scripts", "release-rustflags.mjs");

function run(root, cargoHome) {
  const env = { ...process.env, CARGO_HOME: cargoHome };
  return spawnSync(process.execPath, [SCRIPT, "--root", root], { encoding: "utf8", env });
}

test("the cargo home is mapped last, so it wins when it is inside the checkout", () => {
  const root = resolve("/work/solanum");
  const cargoHome = resolve("/work/solanum/.cargo");
  const r = run(root, cargoHome);
  assert.equal(r.status, 0, r.stderr);
  assert.equal(r.stdout.trim(), `--remap-path-prefix=${root}=/solanum --remap-path-prefix=${cargoHome}=/cargo`);
});

test("--android adds the link flags Tauri would otherwise pass (RUSTFLAGS replaces them) and 16 KB pages (N-037)", () => {
  const root = resolve("/work/solanum");
  const cargoHome = resolve("/cargo-home");
  const env = { ...process.env, CARGO_HOME: cargoHome };
  const r = spawnSync(process.execPath, [SCRIPT, "--root", root, "--android"], { encoding: "utf8", env });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(
    r.stdout.trim(),
    `--remap-path-prefix=${root}=/solanum --remap-path-prefix=${cargoHome}=/cargo -Clink-arg=-landroid -Clink-arg=-llog -Clink-arg=-lOpenSLES -Clink-arg=-Wl,-z,max-page-size=16384`,
  );
});

test("the 16 KB page flag is for Android only", () => {
  const r = spawnSync(process.execPath, [SCRIPT, "--root", resolve("/work/solanum")], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(!r.stdout.includes("max-page-size"), r.stdout);
});

test("without CARGO_HOME it uses the default under the home folder", () => {
  const dir = mkdtempSync(join(tmpdir(), "solanum-rustflags-"));
  try {
    const env = { ...process.env, HOME: dir, USERPROFILE: dir };
    delete env.CARGO_HOME;
    const r = spawnSync(process.execPath, [SCRIPT, "--root", resolve("/work/solanum")], { encoding: "utf8", env });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(r.stdout.includes(`--remap-path-prefix=${join(dir, ".cargo")}=/cargo`), r.stdout);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a path with whitespace is refused and nothing is printed", () => {
  for (const [root, cargoHome] of [
    [resolve("/work/my solanum"), resolve("/cargo")],
    [resolve("/work/solanum"), resolve("/my cargo")],
  ]) {
    const r = run(root, cargoHome);
    assert.equal(r.status, 1);
    assert.equal(r.stdout, "");
    assert.match(r.stderr, /whitespace/);
  }
});

test("--check passes a clean binary and fails one that holds the checkout or the cargo home", () => {
  const dir = mkdtempSync(join(tmpdir(), "solanum-rustflags-"));
  try {
    const root = join(dir, "checkout");
    const cargoHome = join(dir, "cargo");
    const file = join(dir, "binary");
    const check = () =>
      spawnSync(process.execPath, [SCRIPT, "--root", root, "--check", file], { encoding: "utf8", env: { ...process.env, CARGO_HOME: cargoHome } });

    writeFileSync(file, Buffer.concat([Buffer.from([0, 1, 2]), Buffer.from("/cargo/registry/src/x.rs"), Buffer.from([0])]));
    assert.equal(check().status, 0, "the remapped form is fine");

    writeFileSync(file, Buffer.concat([Buffer.from([0]), Buffer.from(`${root}/src/lib.rs`), Buffer.from([0])]));
    assert.equal(check().status, 1);

    writeFileSync(file, Buffer.concat([Buffer.from([0]), Buffer.from(`${cargoHome}/registry/src/x.rs`), Buffer.from([0])]));
    const r = check();
    assert.equal(r.status, 1);
    assert.match(r.stderr, /build-machine path/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// R-011: the toolchain's own folders. Rust's standard library comes prebuilt
// with /rustc/<hash> paths, and C code compiled with the NDK keeps its paths
// only in debug information, which is stripped; the check is what would say
// otherwise.
test("--check also fails a binary that holds the rustup home or the NDK (R-011)", () => {
  const dir = mkdtempSync(join(tmpdir(), "solanum-rustflags-"));
  try {
    const root = join(dir, "checkout");
    const file = join(dir, "binary");
    const env = { ...process.env, CARGO_HOME: join(dir, "cargo"), HOME: dir, USERPROFILE: dir };
    delete env.RUSTUP_HOME;
    delete env.NDK_HOME;
    delete env.ANDROID_NDK_HOME;
    const check = (extra = {}) => spawnSync(process.execPath, [SCRIPT, "--root", root, "--check", file], { encoding: "utf8", env: { ...env, ...extra } });
    const holding = (path) => writeFileSync(file, Buffer.concat([Buffer.from([0]), Buffer.from(`${path}/lib/x.rs`), Buffer.from([0])]));

    holding(join(dir, ".rustup", "toolchains", "stable"));
    assert.equal(check().status, 1, "the default rustup home under the home folder");
    holding(join(dir, "rustup-elsewhere", "toolchains"));
    assert.equal(check().status, 0, "not the rustup home unless RUSTUP_HOME says so");
    assert.equal(check({ RUSTUP_HOME: join(dir, "rustup-elsewhere") }).status, 1, "RUSTUP_HOME");

    holding(join(dir, "ndk", "27.1", "toolchains"));
    assert.equal(check().status, 0, "no NDK named: nothing to look for");
    assert.equal(check({ NDK_HOME: join(dir, "ndk", "27.1") }).status, 1, "NDK_HOME");
    const r = check({ ANDROID_NDK_HOME: join(dir, "ndk", "27.1") });
    assert.equal(r.status, 1, "ANDROID_NDK_HOME");
    assert.match(r.stderr, /build-machine path/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("--check on a missing file fails", () => {
  const r = spawnSync(process.execPath, [SCRIPT, "--check", join(tmpdir(), "solanum-no-such-binary")], { encoding: "utf8" });
  assert.notEqual(r.status, 0);
});
