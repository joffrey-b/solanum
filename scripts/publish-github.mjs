// Publishes a version to GitHub as one commit: the development history stays
// on GitLab, and GitHub's `main` gets one commit per release, "Solanum
// v<version>", whose tree is exactly `main`'s here (the owner's choice for
// F-021: no history rewrite, nothing personal ever published).
//
//   node scripts/publish-github.mjs <version> --email <noreply address> [options]
//     --tag              also push the tag v<version> on the new commit
//     --replace          make the commit the first and only one, replacing
//                        GitHub's `main` (force push): only while the
//                        repository is private and has no tag
//     --exclude <path>   leave another file or folder out of the published tree
//                        (may be given more than once); CLAUDE.md and audit/
//                        are always left out (DEFAULT_EXCLUDE)
//     --co-author <who>  add a Co-Authored-By line ("Name <address>")
//     --url <url>        another repository (tests); default the public one
//     --dry-run          build and check the commit, push nothing
//
// The commit is built with `git commit-tree`, so no merge can change the tree,
// and its author and committer are `joffrey-b <noreply address>`, dated in UTC,
// for that one command: git's configuration is never changed. It refuses
// unless HEAD is `main` with no change to tracked files and equal to
// `origin/main` (the tree CI tested), the tree's version is <version>, and the
// tree (binary files included) holds neither this repository's configured
// e-mail address (in any case) nor a home or profile path of a user of this
// machine or any Windows profile path. The new commit's parent is GitHub's
// current `main`, fetched by URL (no remote is added), so GitHub's history is
// one commit per release and nobody's clone breaks; a `main` there that this
// script did not make (an edit on GitHub) is refused, not overwritten: bring
// that change into GitLab first.
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir, userInfo } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export const PUBLIC_URL = "https://github.com/joffrey-b/solanum.git";
/** What stays on the private GitLab only (owner, 2026-11-12): the instructions
 * file, which describes the build machines, and the audit records. */
export const DEFAULT_EXCLUDE = ["CLAUDE.md", "audit"];
const NAME = "joffrey-b";

function git(args, opts = {}) {
  const r = spawnSync("git", args, { encoding: "utf8", ...opts });
  if (r.status !== 0 && !opts.allowFail) throw new Error(`git ${args.join(" ")} failed: ${(r.stderr || r.stdout).trim()}`);
  return opts.allowFail ? r : r.stdout.trim();
}

export function parseArgs(argv) {
  const o = { version: null, email: null, tag: false, replace: false, exclude: [], coAuthor: null, url: PUBLIC_URL, dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const value = () => {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      return argv[++i];
    };
    if (a === "--email") o.email = value();
    else if (a === "--tag") o.tag = true;
    else if (a === "--replace") o.replace = true;
    else if (a === "--exclude") o.exclude.push(value());
    else if (a === "--co-author") o.coAuthor = value();
    else if (a === "--url") o.url = value();
    else if (a === "--dry-run") o.dryRun = true;
    else if (!a.startsWith("--") && o.version === null) o.version = a;
    else throw new Error(`unknown argument ${a}`);
  }
  if (!o.version || !/^\d+\.\d+\.\d+$/.test(o.version)) throw new Error("the version must be x.y.z");
  if (!o.email || !/^[^\s@<>]+@[^\s@<>]+$/.test(o.email)) throw new Error("--email <noreply address> is required");
  if (o.coAuthor !== null && !/^[^<>\n]+ <[^\s@<>]+@[^\s@<>]+>$/.test(o.coAuthor)) throw new Error('--co-author must be "Name <address>"');
  if (o.tag && o.replace) throw new Error("--replace is for the private phase, before any tag");
  return o;
}

// Names that stand for "some user" in tests and documentation.
const PLACEHOLDERS = new Set(["user", "username", "someone", "somebody", "example", "test", "tester", "public", "default", "you", "name"]);

const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Problems in what would be published; [] when there is none. */
export function treeProblems(repo, tree, personalEmail, localUser = userInfo().username) {
  const problems = [];
  // Files of `tree` that match (binary files too); git grep's exit 1 is "none".
  const matches = (pattern) => {
    const r = git(["grep", "-h", "-o", "-i", "-E", "-e", pattern, tree], { cwd: repo, allowFail: true });
    if (r.status === 1) return [];
    if (r.status !== 0) throw new Error(`git grep failed: ${(r.stderr || "").trim()}`);
    return r.stdout.split("\n").filter(Boolean);
  };
  const count = (pattern, { fixed = false, ignoreCase = false } = {}) => {
    const args = ["grep", "-c", fixed ? "-F" : "-E", ...(ignoreCase ? ["-i"] : []), "-e", pattern, tree];
    const r = git(args, { cwd: repo, allowFail: true });
    if (r.status === 0) return r.stdout.trim().split("\n").filter(Boolean).length;
    if (r.status === 1) return 0;
    throw new Error(`git grep failed: ${(r.stderr || "").trim()}`);
  };
  if (personalEmail) {
    const n = count(personalEmail, { fixed: true, ignoreCase: true });
    if (n > 0) problems.push(`${n} published file(s) hold this repository's configured e-mail address`);
  }
  // C:\Users\name, C:\\Users\\name (escaped in source) and C:/Users/name,
  // except the placeholders tests and docs use.
  const profiles = matches("[A-Za-z]:(\\\\{1,2}|/)Users(\\\\{1,2}|/)[A-Za-z0-9._-]+")
    .map((m) => m.replace(/^.*Users(\\{1,2}|\/)/i, ""))
    .filter((name) => name.length > 2 && !PLACEHOLDERS.has(name.toLowerCase()));
  if (profiles.length > 0) problems.push(`${profiles.length} published Windows profile path(s) name a user`);
  if (localUser && localUser.length >= 2) {
    const user = escapeRegExp(localUser);
    const homes = count(`(/home/|/Users/|\\\\Users\\\\)${user}([/\\\\]|$)`, { ignoreCase: true });
    if (homes > 0) problems.push(`${homes} published file(s) hold this machine's user's home folder`);
  }
  return problems;
}

/** Whether `commit` looks like one this script made for `email`. */
function isReleaseCommit(repo, commit, email) {
  const [who, subject] = git(["log", "-1", "--format=%an <%ae>|%cn <%ce>%n%s", commit], { cwd: repo }).split("\n");
  return who === `${NAME} <${email}>|${NAME} <${email}>` && /^Solanum v\d+\.\d+\.\d+$/.test(subject);
}

/** The tree to publish: `ref`'s, without `exclude` (paths that are not there are fine). */
function publishedTree(repo, ref, exclude) {
  if (exclude.length === 0) return git(["rev-parse", `${ref}^{tree}`], { cwd: repo });
  const dir = mkdtempSync(join(tmpdir(), "solanum-publish-"));
  try {
    const env = { ...process.env, GIT_INDEX_FILE: join(dir, "index") };
    git(["read-tree", ref], { cwd: repo, env });
    git(["rm", "-r", "--cached", "--quiet", "--ignore-unmatch", "--", ...exclude], { cwd: repo, env });
    return git(["write-tree"], { cwd: repo, env });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

/** The public `main` (fetched by URL, no remote added), or null when there is none. */
function publicMain(repo, url) {
  const heads = git(["ls-remote", url, "refs/heads/main"], { cwd: repo });
  if (!heads) return null;
  git(["fetch", "--quiet", "--no-tags", url, "refs/heads/main"], { cwd: repo });
  return git(["rev-parse", "FETCH_HEAD"], { cwd: repo });
}

export function publish(repo, o, log = console.log) {
  if (git(["rev-parse", "--abbrev-ref", "HEAD"], { cwd: repo }) !== "main") throw new Error("HEAD is not main");
  if (git(["status", "--porcelain", "--untracked-files=no"], { cwd: repo })) throw new Error("tracked files have changes");
  const upstream = git(["rev-parse", "--verify", "--quiet", "refs/remotes/origin/main"], { cwd: repo, allowFail: true }).stdout.trim();
  if (upstream && upstream !== git(["rev-parse", "main"], { cwd: repo })) {
    throw new Error("main is not origin/main: publish what was pushed and tested");
  }
  const version = JSON.parse(git(["show", "main:package.json"], { cwd: repo })).version;
  if (version !== o.version) throw new Error(`main is version ${version}, not ${o.version}`);

  const configured = git(["config", "user.email"], { cwd: repo, allowFail: true }).stdout?.trim() || null;
  const personal = configured && configured !== o.email ? configured : null;
  const tree = publishedTree(repo, "main", [...new Set([...DEFAULT_EXCLUDE, ...o.exclude])]);
  const problems = treeProblems(repo, tree, personal);
  if (problems.length > 0) throw new Error(`not published:\n  ${problems.join("\n  ")}`);

  if (o.tag) {
    const tags = git(["ls-remote", "--tags", o.url, `refs/tags/v${o.version}`], { cwd: repo });
    if (tags) throw new Error(`the tag v${o.version} already exists there`);
  }
  if (o.replace && git(["ls-remote", "--tags", o.url], { cwd: repo })) {
    throw new Error("--replace is only for before the first tag: the repository has tags");
  }
  const parent = o.replace ? null : publicMain(repo, o.url);
  if (parent && !isReleaseCommit(repo, parent, o.email)) {
    throw new Error("GitHub's main is not a release commit this script made (an edit on GitHub?): bring that change into GitLab first, nothing was published");
  }
  if (parent && git(["rev-parse", `${parent}^{tree}`], { cwd: repo }) === tree) {
    throw new Error("GitHub's main already has exactly this tree: nothing to publish");
  }
  if (parent) log(git(["diff", "--stat", parent, tree], { cwd: repo }).split("\n").pop() || "");

  let message = `Solanum v${o.version}\n`;
  if (o.coAuthor) message += `\nCo-Authored-By: ${o.coAuthor}\n`;
  if (personal && message.includes(personal)) throw new Error("the message holds the configured e-mail address");
  // In UTC: the local offset would tell where the owner lives.
  const now = `${Math.floor(Date.now() / 1000)} +0000`;
  const env = {
    ...process.env,
    GIT_AUTHOR_NAME: NAME,
    GIT_AUTHOR_EMAIL: o.email,
    GIT_AUTHOR_DATE: now,
    GIT_COMMITTER_NAME: NAME,
    GIT_COMMITTER_EMAIL: o.email,
    GIT_COMMITTER_DATE: now,
  };
  const commit = git(["commit-tree", tree, ...(parent ? ["-p", parent] : []), "-F", "-"], { cwd: repo, env, input: message });
  const who = git(["log", "-1", "--format=%an <%ae>|%cn <%ce>", commit], { cwd: repo });
  if (who !== `${NAME} <${o.email}>|${NAME} <${o.email}>`) throw new Error(`the commit carries ${who}`);
  log(`publish-github: ${commit} "Solanum v${o.version}" (${parent ? `after ${parent.slice(0, 12)}` : "first commit"}), tree ${tree.slice(0, 12)}`);

  if (o.dryRun) {
    log("publish-github: dry run, nothing pushed.");
    return commit;
  }
  git(["push", ...(o.replace ? ["--force"] : []), o.url, `${commit}:refs/heads/main`], { cwd: repo, stdio: ["pipe", "pipe", "pipe"] });
  log(`publish-github: pushed to main${o.replace ? " (replaced)" : ""}.`);
  if (o.tag) {
    git(["push", o.url, `${commit}:refs/tags/v${o.version}`], { cwd: repo });
    log(`publish-github: pushed the tag v${o.version}.`);
  }
  return commit;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    publish(process.cwd(), parseArgs(process.argv.slice(2)));
  } catch (e) {
    console.error(`publish-github: ${e.message}`);
    process.exit(1);
  }
}
