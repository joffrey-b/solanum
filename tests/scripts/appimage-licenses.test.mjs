// scripts/appimage-licenses.mjs (N-038): how it matches the AppImage's files
// to packages and what the notice says, on a made-up build machine.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  classify,
  composeNotice,
  declaredLicences,
  owner,
  parseOsRelease,
  referencedCommonLicences,
  RUNTIME_TEXTS,
  runtimeLicences,
  sourcesList,
  sourceUrl,
  squashfsOffset,
  TOOL_TEXTS,
} from "../../scripts/appimage-licenses.mjs";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const TEXTS = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "packaging", "appimage", "licenses");

const index = new Map([
  ["libgtk-3.so.0", [{ pkg: "libgtk-3-0t64:amd64", path: "/usr/lib/x86_64-linux-gnu/libgtk-3.so.0" }]],
  ["libpixbufloader-png.so", [{ pkg: "libgdk-pixbuf2.0-0:amd64", path: "/usr/lib/x86_64-linux-gnu/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-png.so" }]],
  ["org.gnome.foo.gschema.xml", [{ pkg: "foo", path: "/usr/share/glib-2.0/schemas/org.gnome.foo.gschema.xml" }]],
  ["xdg-open", [{ pkg: "xdg-utils", path: "/usr/bin/xdg-open" }]],
  // The same name in two packages: the path that ends like the image's wins.
  ["config", [
    { pkg: "a-pkg", path: "/etc/a/config" },
    { pkg: "b-pkg", path: "/usr/share/b/config" },
  ]],
]);

const DEP5 = (licences) => `Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\nFiles: *\nCopyright: someone\n${licences.map((l) => `License: ${l}\n See /usr/share/common-licenses/${l.replace("+", "")}.\n`).join("\n")}`;

function machine(overrides = {}) {
  const copyrights = {
    "libgtk-3-0t64:amd64": DEP5(["LGPL-2.1+"]),
    "libgdk-pixbuf2.0-0:amd64": DEP5(["LGPL-2.1+"]),
    foo: "free-form text, see /usr/share/common-licenses/GPL-2 and /usr/share/common-licenses/GFDL-1.1",
    "xdg-utils": DEP5(["Expat"]),
    "b-pkg": DEP5(["MIT"]),
  };
  return {
    index,
    osRelease: { PRETTY_NAME: "Ubuntu 22.04", ID: "ubuntu", ID_LIKE: "debian" },
    runtime: [{ part: "libfuse", licence: "https://github.com/libfuse/libfuse/blob/master/LGPL2.txt" }],
    packageInfo: (pkgs) => new Map(pkgs.map((p) => [p, { version: "1.0-1", source: p.replace(/:.*$/, "") + "-src", sourceVersion: "1.0-1" }])),
    copyright: (pkg) => copyrights[pkg],
    commonLicence: (name) => (name === "GFDL-1.1" ? null : `text of ${name}`),
    toolText: (file) => `licence text ${file}`,
    ...overrides,
  };
}

test("each path of the image is sorted into what it is", () => {
  assert.equal(classify("usr/bin/solanum"), "own");
  assert.equal(classify("usr/lib/Solanum/licenses/NOTICE"), "own");
  assert.equal(classify("Solanum.desktop"), "own");
  assert.equal(classify("solanum.png"), "own");
  assert.equal(classify(".DirIcon"), "own");
  assert.equal(classify("usr/share/icons/hicolor/32x32/apps/solanum.png"), "own");
  assert.equal(classify("usr/share/doc/solanum/APPIMAGE-LIBRARIES.txt"), "own");
  assert.equal(classify("AppRun"), "tool");
  assert.equal(classify("apprun-hooks/linuxdeploy-plugin-gtk.sh"), "tool");
  assert.equal(classify("usr/share/doc/libglib2.0-0t64/copyright"), "notice");
  assert.equal(classify("usr/lib/gtk-3.0/3.0.0/immodules.cache"), "generated");
  assert.equal(classify("usr/share/glib-2.0/schemas/gschemas.compiled"), "generated");
  assert.equal(classify("usr/lib/libgtk-3.so.0"), "package");
  assert.equal(classify("usr/share/icons/hicolor/32x32/apps/other.png"), "package", "only Solanum's own icons are its own");
});

test("a file is matched by name, the longest matching path end winning", () => {
  assert.equal(owner("usr/lib/libgtk-3.so.0", index).pkg, "libgtk-3-0t64:amd64", "linuxdeploy flattens libraries into usr/lib");
  assert.equal(owner("usr/lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-png.so", index).pkg, "libgdk-pixbuf2.0-0:amd64");
  assert.equal(owner("usr/share/b/config", index).pkg, "b-pkg");
  assert.equal(owner("etc/a/config", index).pkg, "a-pkg");
  assert.equal(owner("usr/lib/libnothing.so.1", index), null);
});

test("a same-sized file beats a name match, a native package a foreign one, and a folder never matches", () => {
  const twins = new Map([
    ["libz.so.1", [
      { pkg: "lib32z1", path: "/usr/lib32/libz.so.1" },
      { pkg: "zlib1g:amd64", path: "/usr/lib/x86_64-linux-gnu/libz.so.1" },
    ]],
    ["libfoo.so", [
      { pkg: "a-foo:i386", path: "/usr/lib/i386-linux-gnu/libfoo.so" },
      { pkg: "b-foo:amd64", path: "/usr/lib/x86_64-linux-gnu/libfoo.so" },
    ]],
    ["schemas", [{ pkg: "glib", path: "/usr/share/glib-2.0/schemas" }]],
  ]);
  const sizes = (same) => (rel, host) => (host === same ? "same" : "differs");
  // lib32z1 sorts first and both end in libz.so.1: the size decides.
  assert.equal(owner("usr/lib/libz.so.1", twins, sizes("/usr/lib/x86_64-linux-gnu/libz.so.1")).pkg, "zlib1g:amd64");
  assert.equal(owner("usr/lib/libz.so.1", twins, sizes("/usr/lib32/libz.so.1")).pkg, "lib32z1");
  assert.equal(owner("usr/lib/libfoo.so", twins, () => "same").pkg, "b-foo:amd64", "native before i386");
  assert.equal(owner("usr/share/glib-2.0/schemas", twins, () => "dir"), null);
  assert.deepEqual(referencedCommonLicences("see /usr/share/common-licenses/LGPL-2.1+ and /usr/share/common-licenses/GPL-2+."), ["GPL-2", "LGPL-2.1"]);
});

test("licence names come from machine-readable copyright files only", () => {
  assert.deepEqual(declaredLicences(DEP5(["LGPL-2.1+", "GPL-2+", "LGPL-2.1+"])), ["GPL-2+", "LGPL-2.1+"]);
  assert.deepEqual(declaredLicences("This package was debianized by someone.\nLicense: whatever\n"), []);
  assert.deepEqual(referencedCommonLicences("see /usr/share/common-licenses/LGPL-2.1. Or /usr/share/common-licenses/GPL-2, /usr/share/common-licenses/LGPL-2.1"), ["GPL-2", "LGPL-2.1"]);
});

test("the source address follows the distribution", () => {
  assert.equal(sourceUrl("gtk+3.0", "3.24.41-4ubuntu1.3", { ID: "linuxmint", ID_LIKE: "ubuntu debian" }), "https://launchpad.net/ubuntu/+source/gtk+3.0/3.24.41-4ubuntu1.3");
  assert.equal(sourceUrl("glib2.0", "2.74.6-2", { ID: "debian" }), "https://snapshot.debian.org/package/glib2.0/2.74.6-2/");
  assert.match(sourceUrl("x", "1", { ID: "fedora", PRETTY_NAME: "Fedora 41" }), /Fedora 41/);
  assert.deepEqual(parseOsRelease('NAME="Linux Mint"\nID=linuxmint\nID_LIKE="ubuntu debian"\n'), { NAME: "Linux Mint", ID: "linuxmint", ID_LIKE: "ubuntu debian" });
});

test("the runtime's end and its own licence statement are read from its bytes", () => {
  const elf = Buffer.alloc(128);
  elf.writeUInt32BE(0x7f454c46, 0);
  elf[4] = 2;
  elf.writeBigUInt64LE(1000n, 0x28);
  elf.writeUInt16LE(64, 0x3a);
  elf.writeUInt16LE(5, 0x3c);
  assert.equal(squashfsOffset(elf), 1320);
  assert.throws(() => squashfsOffset(Buffer.from("#!/bin/sh\n")));
  const runtime = Buffer.from("\0\x01  * libfuse, licensed under the terms of\n    https://github.com/libfuse/libfuse/blob/master/LGPL2.txt\0junk\0");
  assert.deepEqual(runtimeLicences(runtime), [{ part: "libfuse", licence: "https://github.com/libfuse/libfuse/blob/master/LGPL2.txt" }]);
});

const FILES = [
  "AppRun",
  "usr/bin/solanum",
  "usr/bin/xdg-open",
  "usr/lib/libgtk-3.so.0",
  "usr/lib/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-png.so",
  "usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache",
  "usr/share/glib-2.0/schemas/org.gnome.foo.gschema.xml",
  "usr/share/doc/libglib2.0-0t64/copyright",
];

test("the notice lists every package with its licence and source, and the texts once each", () => {
  const notice = composeNotice(FILES, machine());
  for (const pkg of ["libgtk-3-0t64:amd64 1.0-1", "libgdk-pixbuf2.0-0:amd64 1.0-1", "foo 1.0-1", "xdg-utils 1.0-1"]) {
    assert.ok(notice.includes(`\n${pkg}\n`), `${pkg} is listed`);
  }
  assert.ok(notice.includes("  Licence: LGPL-2.1+\n"));
  assert.ok(notice.includes("  Source: libgtk-3-0t64-src 1.0-1, https://launchpad.net/ubuntu/+source/libgtk-3-0t64-src/1.0-1\n"));
  assert.ok(notice.includes("  usr/lib/gdk-pixbuf-2.0/2.10.0/loaders.cache\n"), "a generated cache is named");
  assert.ok(notice.includes("libfuse (https://github.com/libfuse/libfuse/blob/master/LGPL2.txt): libfuse.txt"));
  // The two LGPL packages share one copyright text: printed once, under both.
  assert.equal(notice.split("See /usr/share/common-licenses/LGPL-2.1.").length - 1, 1);
  assert.match(notice, /libgdk-pixbuf2\.0-0:amd64 \(\/usr\/share\/doc\/libgdk-pixbuf2\.0-0\/copyright\)\nlibgtk-3-0t64:amd64/);
  assert.ok(notice.includes("text of LGPL-2.1") && notice.includes("text of GPL-2"), "the shared texts they name are included");
  assert.match(notice, /common-licenses\/GFDL-1\.1\n=+\n\(not on the build system/);
  assert.ok(!notice.includes("usr/bin/solanum"), "Solanum's own files are not listed as a package's");
  assert.equal(composeNotice(FILES, machine()), notice, "the same image gives the same notice");
  for (const file of ["linuxdeploy.txt", "appimagekit.txt", "linuxdeploy-plugin-gtk.txt", "libfuse.txt"]) {
    assert.ok(notice.includes(`licence text ${file}`), `${file}'s text is in the notice`);
  }
  assert.ok(notice.includes(".sources.tar"), "the notice says where a release publishes the sources");
});

test("the sources list names each listed package's source once", () => {
  const list = sourcesList(FILES, machine()).trim().split("\n");
  assert.deepEqual(list, ["foo-src 1.0-1", "libgdk-pixbuf2.0-0-src 1.0-1", "libgtk-3-0t64-src 1.0-1", "xdg-utils-src 1.0-1"]);
});

test("every bundling tool and runtime part has its licence text in the repository", () => {
  for (const file of [...TOOL_TEXTS.map(([, f]) => f), ...RUNTIME_TEXTS.values()]) {
    assert.ok(existsSync(join(TEXTS, file)), `${file} is missing`);
    assert.ok(readFileSync(join(TEXTS, file), "utf8").length > 500, `${file} looks empty`);
  }
});

test("a file no package installed stops the notice", () => {
  assert.throws(() => composeNotice([...FILES, "usr/lib/libsurprise.so.2"], machine()), /usr\/lib\/libsurprise\.so\.2/);
  assert.throws(() => composeNotice(FILES, machine({ runtime: [] })), /runtime states no licences/);
  assert.throws(() => composeNotice(FILES, machine({ runtime: [{ part: "newlib", licence: "https://example.invalid/L" }] })), /no licence text.*newlib/);
});
