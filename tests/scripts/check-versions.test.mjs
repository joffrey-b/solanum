// scripts/check-versions.mjs on a fake repository: it must pass on a consistent
// tree and name what is wrong on every kind of drift. A checker that always
// passes is worse than none.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "scripts", "check-versions.mjs");
const JAR = "not really a jar";
const JAR_HASH = createHash("sha256").update(JAR).digest("hex");
const DIST_HASH = "a".repeat(64);

function files(version = "1.2.3") {
  return {
    "package.json": JSON.stringify({ name: "solanum", version }),
    "package-lock.json": JSON.stringify({ name: "solanum", version, packages: { "": { name: "solanum", version } } }),
    "src-tauri/Cargo.toml": `[package]\nname = "solanum"\nversion = "${version}"\n\n[dependencies]\ntauri = { version = "2.1" }\nother = "9.9.9"\n`,
    "src-tauri/Cargo.lock": `version = 4\n\n[[package]]\nname = "other"\nversion = "9.9.9"\n\n[[package]]\nname = "solanum"\nversion = "${version}"\ndependencies = [\n "other",\n]\n`,
    "src-tauri/tauri.conf.json": JSON.stringify({ productName: "Solanum", version }),
    "src-tauri/tauri.android.conf.json": JSON.stringify({ bundle: { android: { minSdkVersion: 24 } } }),
    "src-tauri/gen/android/app/build.gradle.kts":
      'versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()\nversionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")\n',
    "packaging/arch/PKGBUILD": "pkgname=solanum\npkgver=0.0.0\npkgrel=1\n",
    "src-tauri/gen/android/gradle/wrapper/gradle-wrapper.properties": `distributionUrl=https\\://services.gradle.org/distributions/gradle-8.14.3-bin.zip\ndistributionSha256Sum=${DIST_HASH}\n`,
    "src-tauri/gen/android/gradle/wrapper/gradle-wrapper.jar": JAR,
  };
}

function run(tree, ...args) {
  const root = mkdtempSync(join(tmpdir(), "solanum-check-versions-"));
  try {
    for (const [path, content] of Object.entries(tree)) {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), content);
    }
    const r = spawnSync(process.execPath, [SCRIPT, "--root", root, "--wrapper-sha256", JAR_HASH, ...args], { encoding: "utf8" });
    return { status: r.status, output: r.stdout + r.stderr };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function assertFails(tree, expected, ...args) {
  const { status, output } = run(tree, ...args);
  assert.equal(status, 1, output);
  assert.match(output, expected);
}

test("a consistent tree passes", () => {
  const { status, output } = run(files());
  assert.equal(status, 0, output);
});

for (const path of ["package.json", "package-lock.json", "src-tauri/Cargo.toml", "src-tauri/Cargo.lock", "src-tauri/tauri.conf.json"]) {
  test(`drift in ${path} is named`, () => {
    const tree = files();
    tree[path] = files("1.2.4")[path];
    assertFails(tree, new RegExp(path.replace(".", "\\.") + ".*1\\.2\\.4"));
  });
}

test("the root entry of package-lock.json is checked on its own", () => {
  const tree = files();
  tree["package-lock.json"] = JSON.stringify({ version: "1.2.3", packages: { "": { version: "1.2.4" } } });
  assertFails(tree, /package-lock\.json.*1\.2\.4/);
});

test("only the [package] version of Cargo.toml counts, not a dependency's", () => {
  const tree = files();
  tree["src-tauri/Cargo.toml"] = `[dependencies]\nother = { version = "1.2.3" }\n\n[package]\nname = "solanum"\nversion = "1.2.4"\n`;
  assertFails(tree, /Cargo\.toml.*1\.2\.4/);
});

test("a missing solanum entry in Cargo.lock is an error", () => {
  const tree = files();
  tree["src-tauri/Cargo.lock"] = `version = 4\n\n[[package]]\nname = "other"\nversion = "1.2.3"\n`;
  assertFails(tree, /Cargo\.lock/);
});

test("the Android build must take its version from Tauri", () => {
  const tree = files();
  tree["src-tauri/gen/android/app/build.gradle.kts"] = 'versionCode = 7\nversionName = "1.2.3"\n';
  assertFails(tree, /build\.gradle\.kts/);
});

test("the Android config cannot override the version", () => {
  const tree = files();
  tree["src-tauri/tauri.android.conf.json"] = JSON.stringify({ version: "9.9.9" });
  assertFails(tree, /tauri\.android\.conf\.json/);
  const code = files();
  code["src-tauri/tauri.android.conf.json"] = JSON.stringify({ bundle: { android: { versionCode: 5 } } });
  assertFails(code, /tauri\.android\.conf\.json/);
});

test("a generated tauri.properties is compared when it exists", () => {
  const name = "src-tauri/gen/android/app/tauri.properties";
  const good = files();
  good[name] = "tauri.android.versionName=1.2.3\ntauri.android.versionCode=1002003\n";
  assert.equal(run(good).status, 0);
  const stale = files();
  stale[name] = "tauri.android.versionName=1.2.2\ntauri.android.versionCode=1002002\n";
  assertFails(stale, /tauri\.properties.*1\.2\.2/);
  const noCode = files();
  noCode[name] = "tauri.android.versionName=1.2.3\ntauri.android.versionCode=abc\n";
  assertFails(noCode, /tauri\.properties.*versionCode/);
});

test("PKGBUILD holds the placeholder or the real version, nothing else", () => {
  const real = files();
  real["packaging/arch/PKGBUILD"] = "pkgver=1.2.3\n";
  assert.equal(run(real).status, 0);
  const wrong = files();
  wrong["packaging/arch/PKGBUILD"] = "pkgver=1.2.2\n";
  assertFails(wrong, /PKGBUILD.*1\.2\.2/);
});

test("the wrapper distribution must carry a checksum", () => {
  const path = "src-tauri/gen/android/gradle/wrapper/gradle-wrapper.properties";
  const none = files();
  none[path] = "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.14.3-bin.zip\n";
  assertFails(none, /distributionSha256Sum/);
  const short = files();
  short[path] = none[path] + "distributionSha256Sum=abc\n";
  assertFails(short, /distributionSha256Sum/);
});

test("a changed wrapper jar is refused", () => {
  const tree = files();
  tree["src-tauri/gen/android/gradle/wrapper/gradle-wrapper.jar"] = "tampered";
  assertFails(tree, /gradle-wrapper\.jar/);
});

test("--tag: the base version of a tag must match the manifests", () => {
  assert.equal(run(files(), "--tag", "v1.2.3").status, 0);
  assert.equal(run(files(), "--tag", "v1.2.3-rc.1").status, 0, "a pre-release of the same version");
  assertFails(files(), /tag.*1\.2\.4/, "--tag", "v1.2.4");
  assertFails(files(), /tag/, "--tag", "main");
});

test("--tag: manifests that are themselves at a pre-release match that tag", () => {
  assert.equal(run(files("1.2.3-beta.1"), "--tag", "v1.2.3-beta.1").status, 0);
  assertFails(files("1.2.3-beta.1"), /tag/, "--tag", "v1.2.3-beta.2");
});

test("every problem is reported, not only the first", () => {
  const tree = files();
  tree["package.json"] = files("1.2.4")["package.json"];
  tree["packaging/arch/PKGBUILD"] = "pkgver=7.7.7\n";
  const { status, output } = run(tree);
  assert.equal(status, 1);
  assert.match(output, /package\.json/);
  assert.match(output, /PKGBUILD/);
});

test("a missing file is a clear error, not a stack trace", () => {
  const tree = files();
  delete tree["packaging/arch/PKGBUILD"];
  const { status, output } = run(tree);
  assert.equal(status, 1);
  assert.match(output, /PKGBUILD/);
  assert.doesNotMatch(output, /at .*\.mjs:\d+/);
});
