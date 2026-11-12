// Regenerates src-tauri/gen/android/gradle/verification-metadata.xml, the hash
// of every file Gradle downloads for the Android build. Run it after anything
// that changes an Android dependency: the Android Gradle Plugin, Kotlin, a
// library in build.gradle.kts, or a `tauri` or plugin bump (their Android parts
// bring their own). Until then Gradle refuses to build. Review the diff: a hash
// that changed for a version that did not change is the thing this file exists
// to catch.
//
// Needs one earlier `npm run android:build:apk` in this checkout, which writes
// the tauri.settings.gradle this reads. Needs the network, and a few minutes:
// it downloads everything again into a temporary Gradle home. With a warm cache
// Gradle does not visit every file a clean machine fetches, and the result would
// fail on the first clean build, which is what the release workflow always does.
//
// Usage: node scripts/update-gradle-verification.mjs [--root DIR]
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function option(name) {
  const i = process.argv.indexOf(name);
  return i === -1 ? undefined : process.argv[i + 1];
}

const root = option("--root") ?? join(dirname(fileURLToPath(import.meta.url)), "..");
const android = join(root, "src-tauri", "gen", "android");
const metadata = join(android, "gradle", "verification-metadata.xml");

if (!existsSync(join(android, "tauri.settings.gradle"))) {
  console.error("update-gradle-verification: run `npm run android:build:apk` once first (it writes tauri.settings.gradle).");
  process.exit(1);
}

// Release for what ships, debug for `npm run android:dev`. The Rust tasks are
// skipped: they download nothing from Gradle's repositories and need Tauri's CLI
// around them. `clean` makes every task resolve what it needs, aapt2 included.
const abis = ["Universal", "Arm64", "Arm", "X86", "X86_64"];
const skipRust = abis.flatMap((abi) => ["Debug", "Release"].flatMap((p) => ["-x", `rustBuild${abi}${p}`]));
const args = ["--no-daemon", "--write-verification-metadata", "sha256", "clean", "assembleUniversalRelease", "assembleUniversalDebug", ...skipRust];

// Start from nothing, so hashes of what is no longer used do not pile up.
rmSync(metadata, { force: true });
const windows = process.platform === "win32";
const gradleHome = mkdtempSync(join(tmpdir(), "solanum-gradle-home-"));
const gradle = spawnSync(windows ? "gradlew.bat" : "./gradlew", args, {
  cwd: android,
  stdio: "inherit",
  shell: windows,
  env: { ...process.env, GRADLE_USER_HOME: gradleHome },
});
rmSync(gradleHome, { recursive: true, force: true });
if (gradle.status !== 0) {
  console.error("update-gradle-verification: Gradle failed; the old file is in git.");
  process.exit(1);
}

// Gradle uses the platform's line endings; the repository uses LF.
let xml = readFileSync(metadata, "utf8").replaceAll("\r\n", "\n");

// aapt2 is the one artifact that comes per operating system, and Gradle only
// recorded the one it ran on. The Android build runs on Linux in CI and may run
// on any of the three by hand, so all three go in.
const aapt2 = /<component group="com\.android\.tools\.build" name="aapt2" version="([^"]+)">\n/.exec(xml);
if (!aapt2) {
  console.error("update-gradle-verification: no aapt2 component in the generated file; it would be incomplete.");
  process.exit(1);
}
const version = aapt2[1];
let added = "";
for (const os of ["linux", "osx", "windows"]) {
  const name = `aapt2-${version}-${os}.jar`;
  if (xml.includes(`<artifact name="${name}">`)) continue;
  const url = `https://dl.google.com/dl/android/maven2/com/android/tools/build/aapt2/${version}/${name}`;
  const response = await fetch(url);
  if (!response.ok) {
    console.error(`update-gradle-verification: ${url}: HTTP ${response.status}`);
    process.exit(1);
  }
  const hash = createHash("sha256").update(Buffer.from(await response.arrayBuffer())).digest("hex");
  added += `         <artifact name="${name}">\n            <sha256 value="${hash}" origin="Google Maven, added by update-gradle-verification.mjs"/>\n         </artifact>\n`;
}
xml = xml.replace(aapt2[0], aapt2[0] + added);

// An IDE asks for sources and documentation of what it opens. They never run.
if (!xml.includes("   </configuration>\n")) {
  console.error("update-gradle-verification: no <configuration> end in the generated file; Gradle's format changed.");
  process.exit(1);
}
xml = xml.replace(
  "   </configuration>\n",
  '      <trusted-artifacts>\n         <trust file=".*-javadoc[.]jar" regex="true"/>\n         <trust file=".*-sources[.]jar" regex="true"/>\n      </trusted-artifacts>\n   </configuration>\n',
);

writeFileSync(metadata, xml);
const count = (needle) => xml.split(needle).length - 1;
console.log(`update-gradle-verification: ${count("<component ")} components, ${count("<sha256 ")} hashes, aapt2 ${version} for linux, osx and windows.`);
