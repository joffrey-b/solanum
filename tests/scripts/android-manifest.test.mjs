// The Android manifest's batch 13 properties (F-004, F-032, F-033, F-089).
// `tauri android init` regenerates this file from Tauri's template, which has
// none of them; this test is what notices.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const MAIN = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "src-tauri", "gen", "android", "app", "src", "main");
const manifest = readFileSync(join(MAIN, "AndroidManifest.xml"), "utf8").replace(/<!--[\s\S]*?-->/g, "");

// The opening tag of the element of this type whose android:name is `name`.
function element(type, name) {
  const tags = manifest.match(new RegExp(`<${type}\\b[^>]*>`, "g")) ?? [];
  const tag = tags.find((t) => t.includes(`android:name="${name}"`));
  assert.ok(tag, `<${type} android:name="${name}"> is missing`);
  return tag;
}

function attribute(tag, name) {
  return tag.match(new RegExp(`android:${name}="([^"]*)"`))?.[1];
}

const permissions = [...manifest.matchAll(/<uses-permission\b[^>]*android:name="([^"]*)"/g)].map((m) => m[1]);

// wry's file chooser builds `${packageName}.fileprovider` URIs for camera
// capture (`<input type="file" accept="image/*" capture>`); without the
// provider it falls back to the plain picker. Solanum has no such input: a
// feature that adds one needs a provider scoped to one cache subfolder.
test("no FileProvider is declared and its path file is gone (F-089)", () => {
  assert.doesNotMatch(manifest, /<provider\b/);
  assert.equal(existsSync(join(MAIN, "res", "xml", "file_paths.xml")), false);
});

test("one Activity task: the notification and reopening return to it (F-033, N-034)", () => {
  assert.equal(attribute(element("activity", ".MainActivity"), "launchMode"), "singleTask");
});

test("the Activity handles every configuration change itself (F-032)", () => {
  // A recreated Activity gets a new WebView, whose start-up locks the profile
  // and ends every session. Every flag of SDK 36 except resourcesUnused.
  const handled = new Set(attribute(element("activity", ".MainActivity"), "configChanges")?.split("|"));
  const required = [
    "mcc", "mnc", "locale", "touchscreen", "keyboard", "keyboardHidden", "navigation", "orientation",
    "screenLayout", "uiMode", "screenSize", "smallestScreenSize", "density", "layoutDirection",
    "colorMode", "grammaticalGender", "fontScale", "fontWeightAdjustment", "assetsPaths",
  ];
  assert.deepEqual(required.filter((f) => !handled.has(f)), []);
});

test("importing a profile asks for no storage permission: the system picker grants the one file", () => {
  for (const p of ["READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "MANAGE_EXTERNAL_STORAGE"]) {
    assert.ok(!permissions.includes(`android.permission.${p}`), p);
  }
});

test("the keep-alive service is specialUse where that exists, and says why (F-004)", () => {
  const service = element("service", ".ConnectionKeeperService");
  assert.equal(attribute(service, "exported"), "false");
  assert.deepEqual(attribute(service, "foregroundServiceType")?.split("|").sort(), ["dataSync", "specialUse"]);
  const body = manifest.slice(manifest.indexOf(service), manifest.indexOf("</service>", manifest.indexOf(service)));
  assert.match(body, /<property\b[^>]*android:name="android\.app\.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"[^>]*android:value="[^"]{20,}"/);
});

test("the permissions are the ones the service and its notification use (F-004, F-033)", () => {
  for (const p of ["FOREGROUND_SERVICE", "FOREGROUND_SERVICE_SPECIAL_USE", "POST_NOTIFICATIONS", "INTERNET"]) {
    assert.ok(permissions.includes(`android.permission.${p}`), p);
  }
  // dataSync is passed to startForeground only below Android 14, where it
  // needs no permission of its own.
  assert.ok(!permissions.includes("android.permission.FOREGROUND_SERVICE_DATA_SYNC"));
});
