// The notices the licences require reach users: GPL-3.0 section 5(d) asks for
// them in the interface, the MIT License and the OFL for them to travel with
// every copy. Nothing else would fail if one of these lines went missing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const read = (path) => readFileSync(join(ROOT, path), "utf8");
const FILES = ["LICENSE", "NOTICE", "THIRD-PARTY-LICENSES.txt"];
const bundle = JSON.parse(read("src-tauri/tauri.conf.json")).bundle;

test("every bundle carries the three files, in a licenses folder", () => {
  for (const file of FILES) {
    assert.equal(bundle.resources[`../${file}`], `licenses/${file}`, file);
    assert.ok(existsSync(join(ROOT, file)), `${file} exists`);
  }
});

test("the installers name the licence and its holder, under the pseudonym", () => {
  assert.equal(bundle.license, "GPL-3.0-only");
  assert.equal(bundle.licenseFile, "../LICENSE");
  assert.equal(bundle.copyright, "Copyright (C) 2026 joffrey-b");
  assert.equal(bundle.publisher, "joffrey-b");
});

test("the Android copies are generated, not committed", () => {
  assert.match(read("src-tauri/gen/android/app/.gitignore"), /^\/src\/main\/assets\/licenses$/m);
});

test("the Arch package installs the three files where Arch expects them", () => {
  const pkgbuild = read("packaging/arch/PKGBUILD");
  for (const file of FILES) {
    assert.match(pkgbuild, new RegExp(`"\\$startdir/${file}"\\s+"\\$pkgdir/usr/share/licenses/solanum/${file}"`), file);
  }
});

test("the release workflow hands the three files to the Arch build", () => {
  const release = read(".github/workflows/release.yml");
  for (const file of FILES) assert.match(release, new RegExp(`cp ${file}\\s+arch-build/`), file);
});

test("NOTICE keeps the upstream MIT notice and points to the third-party list", () => {
  const notice = read("NOTICE");
  assert.ok(notice.includes("Copyright (c) 2026 Sina Xhpm"));
  assert.ok(notice.includes("The above copyright notice and this permission notice shall be included in all"));
  assert.ok(notice.includes("THIRD-PARTY-LICENSES.txt"));
  assert.ok(notice.includes("SIL Open Font License"));
});

test("the About panel shows the notices GPL-3.0 section 0 lists", () => {
  const about = read("src/components/AboutPanel.tsx");
  assert.ok(about.includes("Copyright (C) 2026 joffrey-b"), "copyright");
  assert.ok(about.includes("ABSOLUTELY NO WARRANTY"), "no warranty");
  assert.ok(about.includes("GPL-3.0-only"), "the licence");
  assert.ok(about.includes("Copyright (c) 2026 Sina Xhpm"), "the upstream notice");
  assert.ok(about.includes("View licences"), "how to see a copy");
});

test("the viewer offers the three files from inside the app", () => {
  const viewer = read("src/components/LicenseViewer.tsx");
  for (const file of FILES) assert.ok(viewer.includes(`../../${file}?raw`), file);
});

test("the third-party list covers the fonts and says how it is made", () => {
  const list = read("THIRD-PARTY-LICENSES.txt");
  assert.ok(list.includes("scripts/generate-licenses.mjs"));
  for (const font of ["cascadia-code", "fira-code", "ibm-plex-mono", "jetbrains-mono", "source-code-pro"]) {
    assert.ok(list.includes(`@fontsource/${font}`), font);
  }
  assert.ok(list.includes("SIL OPEN FONT LICENSE"));
});
