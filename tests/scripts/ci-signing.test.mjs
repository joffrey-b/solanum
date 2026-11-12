// Who can reach the Android signing key (R-001). A job that runs `npm ci`,
// cargo or Gradle runs the build code of every dependency, and on a shell
// runner that code can leave a process behind, replace a tool or read another
// job's environment. So the key may be handed only to a job on a machine no
// such job uses. On GitLab today no job signs; on GitHub only `android-sign`
// does, on a fresh hosted machine, with no checkout.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

// The top-level blocks of a YAML file at `indent` spaces: name -> its text.
function blocks(text, indent) {
  const out = new Map();
  const head = new RegExp(`^ {${indent}}([A-Za-z0-9_.-]+):(.*)$`);
  let name = null;
  let body = [];
  for (const line of text.split("\n")) {
    const m = line.match(head);
    if (m) {
      if (name) out.set(name, body.join("\n"));
      name = m[1];
      body = [m[2]];
    } else if (name !== null && (line.startsWith(" ".repeat(indent + 1)) || line.trim() === "" || line.trimStart().startsWith("#"))) {
      body.push(line);
    } else if (name !== null) {
      out.set(name, body.join("\n"));
      name = null;
      body = [];
    }
  }
  if (name) out.set(name, body.join("\n"));
  return out;
}

const withoutComments = (text) => text.split("\n").filter((l) => !l.trimStart().startsWith("#")).join("\n");

const gitlab = blocks(withoutComments(readFileSync(join(ROOT, ".gitlab-ci.yml"), "utf8")), 0);
const RESERVED = new Set(["stages", "workflow", "default", "variables", "include"]);

function list(body, key) {
  const m = body.match(new RegExp(`^\\s+${key}:\\s*(.+)$`, "m"));
  if (!m) return [];
  return m[1].replace(/^\[|\]$/g, "").split(",").map((s) => s.trim()).filter(Boolean);
}

// A job's text with the templates it extends and the anchors it uses.
function expanded(name, seen = new Set()) {
  if (seen.has(name)) return "";
  seen.add(name);
  let body = gitlab.get(name) ?? "";
  for (const parent of list(body, "extends")) body += "\n" + expanded(parent, seen);
  for (const [, anchor] of body.matchAll(/\*([A-Za-z0-9_-]+)/g)) {
    for (const [other, text] of gitlab) {
      if (text.includes(`&${anchor}`)) body += "\n" + expanded(other, seen);
    }
  }
  return body;
}

function tags(name) {
  return list(expanded(name), "tags");
}

const jobs = [...gitlab.keys()].filter((n) => !n.startsWith(".") && !RESERVED.has(n));
const builds = (body) => /\bnpm (ci|run|install)\b|\bnpx\b|\bcargo\b|\bgradlew?\b|\btauri\b/.test(body);
const signs = (body) => /SOLANUM_(KEYSTORE|KEY)_|apksigner"?\s+sign\b/.test(body);

test("the GitLab file is read: its build and test jobs are found", () => {
  for (const job of ["frontend", "test-rust-linux", "build-linux", "build-android"]) {
    assert.ok(jobs.includes(job), `${job} not found`);
    assert.ok(builds(expanded(job)), `${job} not seen as a build`);
    assert.ok(tags(job).length > 0, `${job} has no runner tag`);
  }
});

test("no GitLab job that holds the signing key shares a runner with a build or test job (R-001)", () => {
  const buildTags = new Set(jobs.filter((j) => builds(expanded(j))).flatMap(tags));
  for (const job of jobs.filter((j) => signs(expanded(j)))) {
    const shared = tags(job).filter((t) => buildTags.has(t));
    assert.deepEqual(shared, [], `${job} holds the signing key on a runner that builds: ${shared.join(", ")}`);
    assert.ok(!builds(expanded(job)), `${job} holds the signing key and builds`);
  }
});

test("GitLab's Android build runs Gradle without its daemon (R-001)", () => {
  for (const job of jobs.filter((j) => /android:build/.test(expanded(j)))) {
    assert.match(expanded(job), /GRADLE_OPTS:\s*"[^"]*-Dorg\.gradle\.daemon=false/, `${job} leaves the Gradle daemon on`);
  }
});

test("on GitHub only android-sign gets the key, and it checks out and builds nothing", () => {
  const release = readFileSync(join(ROOT, ".github", "workflows", "release.yml"), "utf8");
  const jobsText = release.slice(release.indexOf("\njobs:"));
  const github = blocks(withoutComments(jobsText), 2);
  assert.ok(github.has("android") && github.has("android-sign"), "release.yml jobs not found");
  const secret = /secrets\s*(\.\s*SOLANUM_|\[\s*['"]SOLANUM_)|toJSON\(\s*secrets\s*\)/;
  for (const [job, body] of github) {
    if (job === "android-sign") continue;
    assert.doesNotMatch(body, secret, `${job} is given a signing secret`);
  }
  // Nor through the workflow's own env, which every job inherits.
  assert.doesNotMatch(withoutComments(release.slice(0, release.indexOf("\njobs:"))), secret, "release.yml hands a signing secret to every job");
  const sign = github.get("android-sign");
  assert.doesNotMatch(sign, /actions\/checkout/, "android-sign checks out the repository");
  assert.ok(!builds(sign), "android-sign runs a build tool");
  assert.match(sign, /permissions:\s*\{\}/, "android-sign gets a token");
  for (const workflow of ["ci.yml", "audit.yml"]) {
    const text = readFileSync(join(ROOT, ".github", "workflows", workflow), "utf8");
    assert.doesNotMatch(text, /SOLANUM_|toJSON\(\s*secrets\s*\)/, `${workflow} names a signing secret`);
  }
});
