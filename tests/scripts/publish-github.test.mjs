// scripts/publish-github.mjs (F-021): one commit per release, main's exact
// tree, the noreply identity, nothing personal; on throwaway repositories.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join } from "node:path";
import { parseArgs, publish } from "../../scripts/publish-github.mjs";

const NOREPLY = "12345+joffrey-b@users.noreply.github.com";
const PERSONAL = "someone@example.invalid";

function sandbox() {
  const dir = mkdtempSync(join(tmpdir(), "solanum-publish-test-"));
  // Nobody's own git configuration (signing, hooks, a default branch).
  const env = { ...process.env, HOME: dir, GIT_CONFIG_GLOBAL: join(dir, "gitconfig"), GIT_CONFIG_NOSYSTEM: "1" };
  writeFileSync(env.GIT_CONFIG_GLOBAL, "[init]\n\tdefaultBranch = main\n");
  const git = (cwd, ...args) => {
    const r = spawnSync("git", args, { cwd, env, encoding: "utf8" });
    assert.equal(r.status, 0, `git ${args.join(" ")}: ${r.stderr}`);
    return r.stdout.trim();
  };
  const repo = join(dir, "dev");
  const hub = join(dir, "hub.git");
  mkdirSync(repo);
  git(dir, "init", "--bare", "--quiet", hub);
  git(repo, "init", "--quiet");
  git(repo, "config", "user.email", PERSONAL);
  git(repo, "config", "user.name", "dev");
  const commit = (files, message) => {
    for (const [name, text] of Object.entries(files)) {
      mkdirSync(join(repo, name, ".."), { recursive: true });
      writeFileSync(join(repo, name), text);
    }
    git(repo, "add", "-A");
    git(repo, "commit", "--quiet", "-m", message);
  };
  const run = (argv) => {
    const saved = { ...process.env };
    Object.assign(process.env, env);
    try {
      return publish(repo, parseArgs([...argv, "--url", hub]), () => {});
    } finally {
      for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
      Object.assign(process.env, saved);
    }
  };
  return { dir, repo, hub, git, commit, run, done: () => rmSync(dir, { recursive: true, force: true }) };
}

test("arguments: a version, a noreply address, no tag while replacing", () => {
  assert.throws(() => parseArgs(["1.0", "--email", NOREPLY]), /x\.y\.z/);
  assert.throws(() => parseArgs(["1.0.0"]), /--email/);
  assert.throws(() => parseArgs(["1.0.0", "--email", NOREPLY, "--tag", "--replace"]), /private phase/);
  assert.throws(() => parseArgs(["1.0.0", "--email", NOREPLY, "--co-author", "nobody"]), /Name <address>/);
  assert.deepEqual(parseArgs(["1.0.0", "--email", NOREPLY, "--exclude", "a", "--exclude", "b"]).exclude, ["a", "b"]);
});

test("each release is one commit on top of the last, with main's tree and the noreply identity", () => {
  const s = sandbox();
  try {
    s.commit({ "package.json": '{"version":"1.0.0"}\n', "src/a.txt": "a\n" }, "dev work 1");
    s.commit({ "src/b.txt": "b\n" }, "dev work 2");
    const first = s.run(["1.0.0", "--email", NOREPLY, "--tag", "--co-author", "Helper <helper@example.invalid>"]);
    assert.equal(s.git(s.hub, "rev-parse", "main"), first);
    assert.equal(s.git(s.hub, "rev-parse", "v1.0.0^{commit}"), first);
    assert.equal(s.git(s.hub, "rev-list", "--count", "main"), "1", "no development history");
    assert.equal(s.git(s.hub, "rev-parse", "main^{tree}"), s.git(s.repo, "rev-parse", "main^{tree}"));
    assert.equal(s.git(s.hub, "log", "-1", "--format=%an <%ae>|%cn <%ce>|%B", "main"), `joffrey-b <${NOREPLY}>|joffrey-b <${NOREPLY}>|Solanum v1.0.0\n\nCo-Authored-By: Helper <helper@example.invalid>`);
    assert.match(s.git(s.hub, "log", "-1", "--format=%ai|%ci", "main"), /\+0000\|.*\+0000$/, "dated in UTC");

    assert.throws(() => s.run(["1.0.0", "--email", NOREPLY]), /nothing to publish/);
    assert.throws(() => s.run(["1.0.0", "--email", NOREPLY, "--tag"]), /tag v1\.0\.0 already exists/);
    s.commit({ "package.json": '{"version":"1.0.1"}\n', "src/c.txt": "c\n" }, "dev work 3");
    assert.throws(() => s.run(["1.0.0", "--email", NOREPLY]), /version 1\.0\.1, not 1\.0\.0/, "the tree's version decides");
    const second = s.run(["1.0.1", "--email", NOREPLY]);
    assert.equal(s.git(s.hub, "rev-parse", "main^"), first, "on top of the previous release");
    assert.equal(s.git(s.hub, "rev-list", "--count", "main"), "2");
    assert.equal(s.git(s.hub, "rev-parse", "main"), second);
    const addresses = s.git(s.hub, "log", "--format=%ae%n%ce", "main").split("\n");
    assert.deepEqual([...new Set(addresses)], [NOREPLY]);
    assert.throws(() => s.run(["1.0.1", "--email", NOREPLY]), /nothing to publish/, "the same tree is not published twice");
    assert.equal(s.git(s.repo, "tag", "--list"), "", "tags are pushed by commit, never made here");
  } finally {
    s.done();
  }
});

test("a tree with the configured address or a profile path is not published", () => {
  const s = sandbox();
  try {
    s.commit({ "package.json": '{"version":"1.0.0"}\n', "README": `mail ${PERSONAL.toUpperCase()}\n` }, "oops");
    assert.throws(() => s.run(["1.0.0", "--email", NOREPLY]), /configured e-mail address/, "in any case");
    // Built here, so this file holds no such path itself (the scan would find it).
    const who = ["jdoe", "7421"].join("");
    for (const path of [`C:\\Users\\${who}\\Sdk`, `C:\\\\Users\\\\${who}\\\\Sdk`, `c:/users/${who}/sdk`]) {
      s.commit({ "README": "fine\n", "env.ps1": `$SDK = '${path}'\n` }, "oops 2");
      assert.throws(() => s.run(["1.0.0", "--email", NOREPLY]), /Windows profile path/, path);
    }
    s.commit({ "env.ps1": "# example: C:\\Users\\you\\AppData and C:\\Users\\me\n" }, "placeholders are fine");
    s.run(["1.0.0", "--email", NOREPLY, "--dry-run"]);
    s.commit({ "notes.txt": `built in /home/${userInfo().username}/src\n` }, "oops 3");
    assert.throws(() => s.run(["1.0.0", "--email", NOREPLY]), /home folder/);
    s.commit({ "notes.txt": "built\n", "env.ps1": "$SDK = $env:ANDROID_HOME\n" }, "fixed");
    s.run(["1.0.0", "--email", NOREPLY, "--dry-run"]);
    assert.equal(s.git(s.hub, "for-each-ref").length, 0, "a dry run pushes nothing");
  } finally {
    s.done();
  }
});

test("--exclude leaves files out, and --replace makes the first commit again", () => {
  const s = sandbox();
  try {
    s.commit({ "package.json": '{"version":"1.0.0"}\n', "keep.txt": "k\n", "private/notes.md": "n\n", "CLAUDE.md": "rules\n", "audit/REPORT.md": "r\n" }, "work");
    const first = s.run(["1.0.0", "--email", NOREPLY, "--exclude", "private"]);
    assert.equal(s.git(s.hub, "ls-tree", "-r", "--name-only", "main"), "keep.txt\npackage.json", "CLAUDE.md and audit/ stay on GitLab");
    s.commit({ "keep.txt": "k2\n" }, "a fix found on GitHub");
    const again = s.run(["1.0.0", "--email", NOREPLY, "--exclude", "private", "--replace"]);
    assert.notEqual(again, first);
    assert.equal(s.git(s.hub, "rev-list", "--count", "main"), "1", "still one commit");
    assert.equal(s.git(s.hub, "show", "main:keep.txt"), "k2");
  } finally {
    s.done();
  }
});

test("a main on GitHub this script did not make, an unpushed main, and --replace after a tag are refused", () => {
  const s = sandbox();
  try {
    s.commit({ "package.json": '{"version":"1.0.0"}\n', "a.txt": "a\n" }, "work");
    s.git(s.repo, "push", "--quiet", s.hub, "HEAD:refs/heads/main");
    assert.throws(() => s.run(["1.0.0", "--email", NOREPLY]), /not a release commit this script made/, "an edit made on GitHub is not overwritten");
    assert.equal(s.git(s.hub, "rev-list", "--count", "main"), "1");

    s.git(s.repo, "update-ref", "refs/remotes/origin/main", "HEAD");
    s.commit({ "b.txt": "b\n" }, "not pushed to GitLab yet");
    assert.throws(() => s.run(["1.0.0", "--email", NOREPLY, "--replace"]), /not origin\/main/);
    s.git(s.repo, "update-ref", "refs/remotes/origin/main", "HEAD");

    const first = s.run(["1.0.0", "--email", NOREPLY, "--replace"]);
    assert.equal(s.git(s.hub, "rev-parse", "main"), first, "the private phase may replace main");
    s.git(s.repo, "push", "--quiet", s.hub, `${first}:refs/tags/v1.0.0`);
    s.commit({ "c.txt": "c\n" }, "after the release");
    s.git(s.repo, "update-ref", "refs/remotes/origin/main", "HEAD");
    assert.throws(() => s.run(["1.0.0", "--email", NOREPLY, "--replace"]), /has tags/);
  } finally {
    s.done();
  }
});
