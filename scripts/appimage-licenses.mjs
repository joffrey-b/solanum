// The AppImage carries libraries and data files of the machine that built it:
// linuxdeploy copies WebKitGTK, GTK, GLib and everything they load into the
// image. Most of them are under the LGPL, which wants its licence text and a
// way to the source with every copy (N-038). This script writes that notice
// from what the image really holds and the build machine's package database
// (Debian and Ubuntu: dpkg), and checks a rebuilt image against it.
//
//   node scripts/appimage-licenses.mjs --write <bundle/appimage folder> <out folder>
//       extracts the AppImage found there, writes <out>/APPIMAGE-LIBRARIES.txt,
//       <out>/tauri.appimage.json (a config overlay that adds the notice) and
//       <out>/sources.txt (each listed package's source package and version,
//       which release.yml downloads and publishes beside the AppImage)
//   npx tauri bundle --bundles appimage --config <out>/tauri.appimage.json
//       builds the image again, with the notice inside
//   node scripts/appimage-licenses.mjs --check <bundle/appimage folder>
//       fails unless the image holds the notice, and the notice is exactly
//       what this script writes for that image
//
// Every file is matched to the package that installed it (by name, the
// longest matching path end winning); a file no package installed and that is
// neither Solanum's own, linuxdeploy's nor a cache built from the others stops
// the build, so nothing new slips in unlisted.
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/** The licence texts of what the bundling tools put into the image. */
const TOOL_LICENCES = resolve(dirname(fileURLToPath(import.meta.url)), "..", "packaging", "appimage", "licenses");

/** Where the notice goes inside the image. */
export const NOTICE_PATH = "usr/share/doc/solanum/APPIMAGE-LIBRARIES.txt";

/** Every file and link below `root`, as forward-slash paths relative to it. */
export function listAppDir(root) {
  const out = [];
  const walk = (dir, rel) => {
    for (const name of readdirSync(dir).sort()) {
      const path = join(dir, name);
      const relPath = rel ? `${rel}/${name}` : name;
      const st = lstatSync(path);
      if (st.isDirectory()) walk(path, relPath);
      else out.push(relPath);
    }
  };
  walk(root, "");
  return out;
}

/**
 * What a path in the image is: Solanum's own ("own"), linuxdeploy's AppRun
 * and hook ("tool"), a copyright file linuxdeploy copied ("notice"), a cache
 * built at bundle time from the other files ("generated"), or a file some
 * package installed ("package").
 */
export function classify(rel) {
  const name = basename(rel);
  if (rel === NOTICE_PATH || rel.startsWith("usr/share/doc/solanum/")) return "own";
  if (rel === "usr/bin/solanum" || rel.startsWith("usr/lib/Solanum/") || rel === ".DirIcon") return "own";
  if (!rel.includes("/") && /^solanum\b/i.test(name)) return "own";
  if (rel === "usr/share/applications/Solanum.desktop") return "own";
  if (rel.startsWith("usr/share/icons/") && /^solanum\.(png|svg)$/i.test(name)) return "own";
  if (rel === "AppRun" || rel === "AppRun.wrapped" || rel.startsWith("apprun-hooks/")) return "tool";
  if (/^usr\/share\/doc\/[^/]+\/copyright$/.test(rel)) return "notice";
  if (/^(loaders|immodules|giomodule|icon-theme|mime)\.cache$|^gschemas\.compiled$/.test(name)) return "generated";
  return "package";
}

/** File name -> the packages' paths with that name, from dpkg's file lists. */
export function dpkgIndex(infoDir = "/var/lib/dpkg/info") {
  const index = new Map();
  for (const list of readdirSync(infoDir).filter((f) => f.endsWith(".list")).sort()) {
    const pkg = list.slice(0, -".list".length);
    for (const path of readFileSync(join(infoDir, list), "utf8").split("\n")) {
      if (!path.startsWith("/")) continue;
      const name = basename(path);
      if (!index.has(name)) index.set(name, []);
      index.get(name).push({ pkg, path });
    }
  }
  return index;
}

/** Lexicographic order of two equally long number lists. */
function compareKeys(a, b) {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

/**
 * The package file `rel` was copied from. `compare(rel, hostPath)` says what
 * the build machine has there: "same" (same size as the image's file),
 * "differs", "dir" or "missing". A same-sized file wins (linuxdeploy flattens
 * libraries into usr/lib, so a 32-bit package's copy can share the name),
 * then the longest matching path end, then a native package over a foreign
 * architecture's, then the name. A folder is never a match.
 */
export function owner(rel, index, compare = () => "same") {
  const want = rel.split("/").reverse();
  const rank = { same: 2, differs: 1, missing: 1 };
  let best = null;
  let bestKey = null;
  for (const candidate of index.get(basename(rel)) ?? []) {
    const kind = compare(rel, candidate.path);
    if (!(kind in rank)) continue;
    const have = candidate.path.split("/").reverse();
    let suffix = 0;
    while (suffix < want.length && suffix < have.length && want[suffix] === have[suffix]) suffix++;
    const native = /:(i386|armhf|armel)$/.test(candidate.pkg) ? 0 : 1;
    const key = [rank[kind], suffix, native];
    const order = best ? compareKeys(key, bestKey) : 1;
    if (order > 0 || (order === 0 && candidate.pkg < best.pkg)) {
      best = candidate;
      bestKey = key;
    }
  }
  return best;
}

/** The licence names a machine-readable (DEP-5) copyright file declares. */
export function declaredLicences(copyright) {
  if (!/^Format:\s*\S*copyright-format/m.test(copyright)) return [];
  const names = new Set();
  for (const m of copyright.matchAll(/^License:[ \t]*(\S[^\n]*)$/gm)) names.add(m[1].trim());
  return [...names].sort();
}

/** The shared licence texts a copyright file points to. */
export function referencedCommonLicences(copyright) {
  // "LGPL-2.1+" names the file LGPL-2.1: Debian keeps no "+" versions.
  const names = [...copyright.matchAll(/\/usr\/share\/common-licenses\/([A-Za-z0-9.+_-]*[A-Za-z0-9+_-])/g)].map((m) => m[1].replace(/\+$/, ""));
  return [...new Set(names)].sort();
}

/** Where the exact source of a package version is kept, for this distribution. */
export function sourceUrl(source, version, osRelease) {
  const family = `${osRelease.ID ?? ""} ${osRelease.ID_LIKE ?? ""}`;
  if (/\bubuntu\b/.test(family)) return `https://launchpad.net/ubuntu/+source/${source}/${version}`;
  if (/\bdebian\b/.test(family)) return `https://snapshot.debian.org/package/${source}/${version}/`;
  return `the source archive of ${osRelease.PRETTY_NAME ?? "the build system"}`;
}

export function parseOsRelease(text) {
  const out = {};
  for (const line of text.split("\n")) {
    const m = line.match(/^([A-Z_]+)=(.*)$/);
    if (m) out[m[1]] = m[2].replace(/^"(.*)"$/, "$1");
  }
  return out;
}

/** Where the squashfs starts: the end of the runtime's ELF section table. */
export function squashfsOffset(bytes) {
  if (bytes.length < 64 || bytes.readUInt32BE(0) !== 0x7f454c46 || bytes[4] !== 2) throw new Error("not a 64-bit ELF AppImage");
  const shoff = Number(bytes.readBigUInt64LE(0x28));
  return shoff + bytes.readUInt16LE(0x3a) * bytes.readUInt16LE(0x3c);
}

/** The runtime's own statement of its parts and their licences. */
export function runtimeLicences(runtime) {
  const strings = runtime.toString("latin1").split(/[^\x20-\x7e]+/).flatMap((s) => s.split("\n"));
  const parts = [];
  for (let i = 0; i < strings.length - 1; i++) {
    const m = strings[i].match(/^\s*\*\s*(.+), licensed under the terms of\s*$/);
    if (m && /^\s*https?:\/\//.test(strings[i + 1])) parts.push({ part: m[1].trim(), licence: strings[i + 1].trim() });
  }
  return parts;
}

const RULE = "=".repeat(78);

/**
 * The pieces of the image that come with the bundling tools, and the parts
 * the AppImage runtime names, each with its licence text in
 * packaging/appimage/licenses/ (see the README there).
 */
export const TOOL_TEXTS = [
  ["AppRun (the script linuxdeploy writes), https://github.com/linuxdeploy/linuxdeploy", "linuxdeploy.txt"],
  ["AppRun.wrapped (AppImageKit's AppRun, built by Tauri: https://github.com/tauri-apps/binary-releases), https://github.com/AppImage/AppImageKit", "appimagekit.txt"],
  ["apprun-hooks/linuxdeploy-plugin-gtk.sh, https://github.com/tauri-apps/linuxdeploy-plugin-gtk", "linuxdeploy-plugin-gtk.txt"],
];
export const RUNTIME_TEXTS = new Map([
  ["runtime", "type2-runtime.txt"],
  ["musl libc", "musl.txt"],
  ["libfuse", "libfuse.txt"],
  ["squashfuse", "squashfuse.txt"],
  ["libzstd", "zstd.txt"],
  ["zlib", "zlib.txt"],
]);

/** The name a release gives the archive of the packages' sources. */
export const SOURCES_SUFFIX = ".sources.tar";

/**
 * The notice for `files` (paths in the image). `sys` is the build machine:
 * index, compare(rel, hostPath) (see owner), packageInfo(pkgs) -> Map,
 * copyright(pkg), commonLicence(name) (or null), toolText(file) (a file of
 * packaging/appimage/licenses/), osRelease, runtime (the parts the AppImage
 * runtime states).
 */
export function composeNotice(files, sys) {
  return compose(files, sys).text;
}

/** The source package and version of every package the notice lists, one "name version" per line. */
export function sourcesList(files, sys) {
  return compose(files, sys).sources;
}

function compose(files, sys) {
  const byPackage = new Map();
  const generated = [];
  const unmatched = [];
  for (const rel of files) {
    const kind = classify(rel);
    if (kind === "generated") generated.push(rel);
    if (kind !== "package") continue;
    const found = owner(rel, sys.index, sys.compare);
    if (!found) {
      unmatched.push(rel);
      continue;
    }
    if (!byPackage.has(found.pkg)) byPackage.set(found.pkg, []);
    byPackage.get(found.pkg).push(rel);
  }
  if (unmatched.length > 0) {
    throw new Error(`no package installed these files of the AppImage (add them to classify() if they are expected):\n  ${unmatched.join("\n  ")}`);
  }
  if (sys.runtime.length === 0) throw new Error("the AppImage runtime states no licences: check what runtime the bundler used");
  const unknownParts = sys.runtime.filter(({ part }) => !RUNTIME_TEXTS.has(part)).map(({ part }) => part);
  if (unknownParts.length > 0) {
    throw new Error(`the AppImage runtime names parts with no licence text in packaging/appimage/licenses/: ${unknownParts.join(", ")}`);
  }
  const packages = [...byPackage.keys()].sort();
  const info = sys.packageInfo(packages);
  const copyrights = new Map(packages.map((p) => [p, sys.copyright(p)]));
  const common = [...new Set([...copyrights.values()].flatMap(referencedCommonLicences))].sort();

  const out = [];
  out.push("Libraries and data files in the Solanum AppImage", "");
  out.push(
    "Besides Solanum itself (whose licences are in usr/lib/Solanum/licenses/), the",
    `AppImage carries these files from the system that built it (${sys.osRelease.PRETTY_NAME ?? "unknown"}).`,
    "They keep their own licences, most of them the GNU LGPL. Section 4 has each",
    "package's copyright file (once for packages that share one) and section 5 the",
    "licence texts those files refer to.",
    "The source of every package, at the exact version used here, is kept at the",
    "address given with it, and each release on GitHub publishes all of them next",
    `to the AppImage, in the file named like it with ${SOURCES_SUFFIX} at the end.`,
    "",
  );
  out.push("1. Packages", "");
  for (const pkg of packages) {
    const i = info.get(pkg);
    if (!i) throw new Error(`dpkg-query knows nothing of ${pkg}`);
    const licences = declaredLicences(copyrights.get(pkg));
    const list = byPackage.get(pkg).sort();
    out.push(`${pkg} ${i.version}`);
    out.push(`  Licence: ${licences.length > 0 ? licences.join("; ") : "see its copyright file in section 4"}`);
    out.push(`  Source: ${i.source} ${i.sourceVersion}, ${sourceUrl(i.source, i.sourceVersion, sys.osRelease)}`);
    out.push(`  Files (${list.length}): ${list.slice(0, 6).join(", ")}${list.length > 6 ? ", ..." : ""}`);
    out.push("");
  }
  out.push("2. Files built while bundling, from the files above", "");
  for (const rel of generated.sort()) out.push(`  ${rel}`);
  out.push("");
  out.push(
    "3. Bundling tools and the AppImage runtime",
    "",
    "  These come with the tools Tauri's bundler uses to build the image. Their",
    "  licence texts follow this list.",
    "",
  );
  for (const [what, file] of TOOL_TEXTS) out.push(`  ${what}: ${file}`);
  out.push("", "  The AppImage runtime at the start of the file (it mounts the image) names its parts:");
  for (const { part, licence } of sys.runtime) out.push(`    ${part} (${licence}): ${RUNTIME_TEXTS.get(part)}`);
  out.push("  Its source, the libraries it links included: https://github.com/AppImage/type2-runtime", "");
  const toolFiles = [...new Set([...TOOL_TEXTS.map(([, file]) => file), ...sys.runtime.map(({ part }) => RUNTIME_TEXTS.get(part))])];
  for (const file of toolFiles) out.push(RULE, file, RULE, sys.toolText(file).trimEnd(), "");
  // Packages built from one source often share one copyright file (WebKit's
  // four): each text once, under every package it belongs to.
  out.push("4. Copyright files", "");
  const byText = new Map();
  for (const pkg of packages) {
    const text = copyrights.get(pkg).trimEnd();
    if (!byText.has(text)) byText.set(text, []);
    byText.get(text).push(pkg);
  }
  for (const [text, pkgs] of byText) {
    const heads = pkgs.map((pkg) => `${pkg} (/usr/share/doc/${pkg.replace(/:.*$/, "")}/copyright)`);
    out.push(RULE, ...heads, RULE, text, "");
  }
  out.push("5. Licence texts referred to", "");
  for (const name of common) {
    const text = sys.commonLicence(name);
    // Debian keeps only some versions there (GFDL-1.2 and 1.3, not 1.1): the
    // copyright file that names a missing one is the text to go by.
    const body = text === null ? "(not on the build system; see the copyright file in section 4 that names it)" : text.trimEnd();
    out.push(RULE, `/usr/share/common-licenses/${name}`, RULE, body, "");
  }
  const sources = [...new Set(packages.map((p) => `${info.get(p).source} ${info.get(p).sourceVersion}`))].sort();
  return { text: out.join("\n") + "\n", sources: sources.join("\n") + "\n" };
}

/** The build machine, as composeNotice needs it; `root` is the extracted image. */
function buildMachine(runtime, root) {
  return {
    index: dpkgIndex(),
    compare(rel, hostPath) {
      let host;
      try {
        host = statSync(hostPath);
      } catch {
        return "missing";
      }
      if (host.isDirectory()) return "dir";
      try {
        return statSync(join(root, rel)).size === host.size ? "same" : "differs";
      } catch {
        return "differs";
      }
    },
    osRelease: parseOsRelease(readFileSync("/etc/os-release", "utf8")),
    runtime,
    packageInfo(pkgs) {
      const r = spawnSync("dpkg-query", ["-W", "-f", "${binary:Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\n", ...pkgs], { encoding: "utf8" });
      if (r.status !== 0) throw new Error(`dpkg-query failed: ${r.stderr}`);
      const map = new Map();
      for (const line of r.stdout.split("\n").filter(Boolean)) {
        const [pkg, version, source, sourceVersion] = line.split("\t");
        map.set(pkg, { version, source, sourceVersion });
        if (!pkg.includes(":")) continue;
        map.set(pkg.replace(/:.*$/, ""), { version, source, sourceVersion });
      }
      // dpkg's list files name multi-arch packages with their architecture.
      for (const p of pkgs) if (!map.has(p) && map.has(p.replace(/:.*$/, ""))) map.set(p, map.get(p.replace(/:.*$/, "")));
      return map;
    },
    copyright(pkg) {
      const path = `/usr/share/doc/${pkg.replace(/:.*$/, "")}/copyright`;
      if (!existsSync(path)) throw new Error(`${pkg} has no ${path}`);
      return readFileSync(path, "utf8");
    },
    toolText(file) {
      return readFileSync(join(TOOL_LICENCES, file), "utf8");
    },
    commonLicence(name) {
      const path = `/usr/share/common-licenses/${name}`;
      return existsSync(path) ? readFileSync(path, "utf8") : null;
    },
  };
}

function findAppImage(folder) {
  const found = readdirSync(folder).filter((f) => f.endsWith(".AppImage"));
  if (found.length !== 1) throw new Error(`expected one .AppImage in ${folder}, found ${found.length}`);
  return resolve(folder, found[0]);
}

/** Extracts `appimage` into a new temporary folder (no FUSE needed). */
function extract(appimage) {
  const dir = mkdtempSync(join(tmpdir(), "solanum-appimage-"));
  // Without APPIMAGE_EXTRACT_AND_RUN (set in the CI jobs), which would make
  // the runtime start Solanum instead.
  const env = { ...process.env };
  delete env.APPIMAGE_EXTRACT_AND_RUN;
  const r = spawnSync(appimage, ["--appimage-extract"], { cwd: dir, env, stdio: ["ignore", "ignore", "pipe"], encoding: "utf8" });
  if (r.status !== 0) throw new Error(`could not extract ${appimage}: ${r.stderr}`);
  return { dir, root: join(dir, "squashfs-root") };
}

function noticeFor(appimage, root) {
  const bytes = readFileSync(appimage);
  const runtime = runtimeLicences(bytes.subarray(0, squashfsOffset(bytes)));
  return compose(listAppDir(root), buildMachine(runtime, root));
}

function main(argv) {
  const mode = argv[0];
  if (mode === "--write" && argv.length === 3) {
    const appimage = findAppImage(argv[1]);
    const out = resolve(argv[2]);
    const { dir, root } = extract(appimage);
    try {
      const { text: notice, sources } = noticeFor(appimage, root);
      mkdirSync(out, { recursive: true });
      const noticeFile = join(out, "APPIMAGE-LIBRARIES.txt");
      writeFileSync(noticeFile, notice);
      // What a release publishes the source of (release.yml: apt-get source).
      writeFileSync(join(out, "sources.txt"), sources);
      const overlay = { bundle: { linux: { appimage: { files: { [`/${NOTICE_PATH}`]: noticeFile } } } } };
      writeFileSync(join(out, "tauri.appimage.json"), JSON.stringify(overlay, null, 2) + "\n");
      console.log(`appimage-licenses: wrote ${noticeFile} (${notice.length} characters) and its config overlay.`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    return 0;
  }
  if (mode === "--check" && argv.length === 2) {
    const appimage = findAppImage(argv[1]);
    const { dir, root } = extract(appimage);
    try {
      const shipped = join(root, NOTICE_PATH);
      if (!existsSync(shipped)) throw new Error(`${appimage} holds no ${NOTICE_PATH}`);
      if (readFileSync(shipped, "utf8") !== noticeFor(appimage, root).text) {
        throw new Error(`${NOTICE_PATH} in ${appimage} does not match what the image holds: write it again from this image`);
      }
      console.log(`appimage-licenses: ${basename(appimage)} holds its notice, and it matches the image.`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    return 0;
  }
  console.error("usage: appimage-licenses.mjs --write <appimage folder> <out folder> | --check <appimage folder>");
  return 2;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    process.exit(main(process.argv.slice(2)));
  } catch (e) {
    console.error(`appimage-licenses: ${e.message}`);
    process.exit(1);
  }
}

