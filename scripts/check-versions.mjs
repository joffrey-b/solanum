// Checks that every manifest names the same version, and that the Gradle
// wrapper is pinned. Node built-ins only. Runs in CI and with
// `npm run check:versions`.
//
// Usage: node scripts/check-versions.mjs [--root DIR] [--tag vX.Y.Z]
//
// --tag is for the release workflow: a pushed tag must be the version the
// manifests name, or a pre-release of it, so a release cannot ship with metadata
// that disagrees with its tag. The workflow validates the tag's format first.
//
// Android has no version of its own: Tauri writes tauri.properties from
// tauri.conf.json at build time (the file is gitignored). So what is checked is
// that nothing overrides that, and, where the file exists, that it agrees.
// Tauri's rule for the exact versionCode is not asserted (0.3.8 gave 30084).
//
// The Arch package's pkgver is a placeholder that the release workflow stamps.
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// The committed gradle-wrapper.jar. This is Gradle's published checksum for the
// wrappers of 6.9.x and 7.0.x (https://gradle.org/release-checksums/). The
// release workflow also runs gradle/actions/wrapper-validation, which knows all
// of them; this one also works on the GitLab runners. Change it only for a jar
// whose checksum you found on that page.
const WRAPPER_JAR_SHA256 = "e996d452d2645e70c01c11143ca2d3742734a28da2bf61f25c82bdc288c9e637";

const PKGBUILD_PLACEHOLDER = "0.0.0";
const ANDROID = "src-tauri/gen/android";
const WRAPPER = `${ANDROID}/gradle/wrapper`;

function option(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

const root = option("--root") ?? join(dirname(fileURLToPath(import.meta.url)), "..");
const tag = option("--tag");
const wrapperSha256 = option("--wrapper-sha256") ?? WRAPPER_JAR_SHA256;

const problems = [];

function read(path, encoding = "utf8") {
  try {
    return readFileSync(join(root, path), encoding);
  } catch {
    problems.push(`${path}: cannot be read`);
    return null;
  }
}

function readJson(path) {
  const text = read(path);
  if (text === null) return null;
  try {
    return JSON.parse(text);
  } catch {
    problems.push(`${path}: not valid JSON`);
    return null;
  }
}

/** The `version` of the [package] table, whatever other tables come first. */
function cargoTomlVersion(text) {
  const table = /^\[package\]\s*$([\s\S]*?)(?=^\[|(?![\s\S]))/m.exec(text);
  return table ? /^version\s*=\s*"([^"]*)"/m.exec(table[1])?.[1] : undefined;
}

function cargoLockVersion(text) {
  for (const block of text.split("[[package]]")) {
    if (/^name\s*=\s*"solanum"\s*$/m.test(block)) {
      return /^version\s*=\s*"([^"]*)"/m.exec(block)?.[1];
    }
  }
  return undefined;
}

const found = [];
function record(label, version) {
  if (version === undefined || version === null) {
    problems.push(`${label}: no version found`);
  } else {
    found.push([label, version]);
  }
}

const pkg = readJson("package.json");
if (pkg) record("package.json", pkg.version);

const lock = readJson("package-lock.json");
if (lock) {
  record("package-lock.json", lock.version);
  record("package-lock.json (root package)", lock.packages?.[""]?.version);
}

const cargoToml = read("src-tauri/Cargo.toml");
if (cargoToml !== null) record("src-tauri/Cargo.toml", cargoTomlVersion(cargoToml));

const cargoLock = read("src-tauri/Cargo.lock");
if (cargoLock !== null) record("src-tauri/Cargo.lock", cargoLockVersion(cargoLock));

const conf = readJson("src-tauri/tauri.conf.json");
if (conf) record("src-tauri/tauri.conf.json", conf.version);

const versions = new Set(found.map(([, v]) => v));
if (versions.size > 1) {
  const width = Math.max(...found.map(([label]) => label.length));
  problems.push("the manifests disagree:\n" + found.map(([label, v]) => `    ${label.padEnd(width)}  ${v}`).join("\n"));
}
const version = found.length > 0 ? found[0][1] : undefined;

// Android takes its version from Tauri.
const gradle = read(`${ANDROID}/app/build.gradle.kts`);
if (gradle !== null) {
  for (const key of ["versionCode", "versionName"]) {
    const fromTauri = new RegExp(`^\\s*${key}\\s*=\\s*tauriProperties\\.getProperty\\("tauri\\.android\\.${key}"`, "m");
    if (!fromTauri.test(gradle)) {
      problems.push(`${ANDROID}/app/build.gradle.kts: ${key} must come from tauri.properties`);
    }
  }
}
const androidConf = readJson("src-tauri/tauri.android.conf.json");
if (androidConf) {
  const a = androidConf.bundle?.android ?? {};
  if ("version" in androidConf || "versionCode" in a || "versionName" in a) {
    problems.push("src-tauri/tauri.android.conf.json: must not override the version");
  }
}
if (conf && ("versionCode" in (conf.bundle?.android ?? {}) || "versionName" in (conf.bundle?.android ?? {}))) {
  problems.push("src-tauri/tauri.conf.json: must not set an Android version of its own");
}
const propertiesPath = `${ANDROID}/app/tauri.properties`;
if (existsSync(join(root, propertiesPath))) {
  const properties = read(propertiesPath) ?? "";
  const name = /^tauri\.android\.versionName=(.*?)\s*$/m.exec(properties)?.[1];
  const code = /^tauri\.android\.versionCode=(.*?)\s*$/m.exec(properties)?.[1];
  if (name !== version) problems.push(`${propertiesPath}: versionName is ${name}, the manifests say ${version} (delete the generated file or rebuild)`);
  if (!/^[1-9][0-9]*$/.test(code ?? "")) problems.push(`${propertiesPath}: versionCode is not a positive integer`);
}

// The Arch package.
const pkgbuild = read("packaging/arch/PKGBUILD");
if (pkgbuild !== null) {
  const pkgver = /^pkgver=(.*?)\s*$/m.exec(pkgbuild)?.[1];
  if (pkgver !== PKGBUILD_PLACEHOLDER && pkgver !== version) {
    problems.push(`packaging/arch/PKGBUILD: pkgver is ${pkgver}, expected the placeholder ${PKGBUILD_PLACEHOLDER} or ${version}`);
  }
}

// The Gradle wrapper.
const wrapperProperties = read(`${WRAPPER}/gradle-wrapper.properties`);
if (wrapperProperties !== null && !/^distributionSha256Sum=[0-9a-f]{64}\s*$/m.test(wrapperProperties)) {
  problems.push(`${WRAPPER}/gradle-wrapper.properties: distributionSha256Sum is missing or malformed`);
}
const jar = read(`${WRAPPER}/gradle-wrapper.jar`, null);
if (jar !== null) {
  const hash = createHash("sha256").update(jar).digest("hex");
  if (hash !== wrapperSha256) {
    problems.push(`${WRAPPER}/gradle-wrapper.jar: SHA-256 ${hash} is not the recorded official one`);
  }
}

// The tag of a release.
if (tag !== undefined) {
  const match = /^v?([0-9]+\.[0-9]+\.[0-9]+)(-[0-9A-Za-z.]+)?$/.exec(tag);
  if (!match) {
    problems.push("--tag: not a version");
  } else if (match[1] !== version && match[1] + (match[2] ?? "") !== version) {
    problems.push(`--tag: the tag's version is ${match[1]}${match[2] ?? ""}, the manifests say ${version}`);
  }
}

if (problems.length > 0) {
  console.error(`check-versions: ${problems.length} problem(s):`);
  for (const problem of problems) console.error(`  - ${problem}`);
  process.exit(1);
}
console.log(`check-versions: ${version} in every manifest, Gradle wrapper pinned.`);
