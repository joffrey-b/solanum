//! One-way live mirror, with a two-way initial reconciliation.
//!
//! Steady-state the mirror is unidirectional: a debounced local FS watcher
//! pushes every change up to a matching directory on the SSH server, and
//! we never read remote events back. SFTP has no push channel, so a fully
//! bidirectional live sync would mean polling — slow, racy, and
//! conflict-prone — which is why we don't.
//!
//! The *initial* sync is two-way though: we walk both sides, copy what is
//! missing on one side across, and settle files that differ by the mirror's
//! `conflict_resolution` ("local" wins by default; "remote"; "newer"). This
//! is what the user actually wants on "start mirror" — they have a folder
//! with some files locally and some files on the server, and the answer
//! "merge them" matches expectation. After this one-shot reconciliation
//! the watcher takes over and the rest of the session is push-only.
//!
//! Lifecycle of a single mirror:
//!
//!   1. `dry_run` walks both trees and reports what *would* move in either
//!      direction, and what it could not check (left alone). The UI uses
//!      this for the "N files to upload, M files to download — continue?"
//!      confirmation step. No FS state changes.
//!
//!   2. `start` checks both folders (F-008), performs the initial sync, then
//!      attaches a debounced FS watcher. Each event reduces to a single
//!      action — Upload if the path still exists locally, Delete if it
//!      vanished — because the debouncer collapses bursts and the actual
//!      operation we want depends only on the *current* state of the path.
//!      Deletions are judged as a burst by the mass-delete guard, which may
//!      hold them until the user resumes (`resume`).
//!
//!   3. `stop` asks the worker to end. A transfer in progress sees it at its
//!      next chunk and removes its partial file; whatever has not finished
//!      `CANCEL_GRACE` later is dropped, and a worker still running after
//!      `STOP_TIMEOUT` is aborted (F-009). Nothing waits on a dead link.
//!
//! Server files are replaced through `atomic_transfer` (owner, group, mode
//! and links kept; through a part file, except the files it may only rewrite
//! in place, which a stop lets finish), downloads written through a part
//! file, and nothing is read or written through a symbolic link inside the
//! mirrored folder. Deletes go to a `.solanum-trash/<stamp>/<path>` folder on
//! the remote by default (rename instead of remove), so a fat-fingered local
//! `rm -rf` doesn't nuke the remote copy; the initial sync puts the server
//! versions it replaces there too (or keeps them beside the file when the
//! trash cannot take them). The trash is never emptied automatically.
//! The user can flip `soft_delete = false` per mirror if they actually want
//! hard deletes.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use notify_debouncer_mini::{new_debouncer, notify::RecursiveMode, DebouncedEventKind};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::FileAttributes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinSet;

use crate::atomic_transfer::{self, ReplaceError, ReplaceOptions, Replaced};

/// The SSH connection a mirror works over (any russh client handler: the
/// app's, or a test's).
pub type SshHandle<H> = Arc<Mutex<russh::client::Handle<H>>>;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MirrorSpec {
    /// Absolute local directory. Watcher binds here and walks it for
    /// initial sync.
    pub local: String,
    /// Absolute remote directory. All local paths are translated against
    /// this prefix when computing the remote path.
    pub remote: String,
    /// When true (default), remote deletes go to `<remote>/.solanum-trash/`
    /// via rename instead of `remove_file`. Single point of recovery if the
    /// user accidentally `rm`'s something locally.
    #[serde(default = "default_true")]
    pub soft_delete: bool,
    /// Substring + `*.<ext>` filters. Match against the relative path; any
    /// hit skips upload / delete propagation.
    #[serde(default)]
    pub excludes: Vec<String>,
    /// How to resolve initial-sync conflicts (file exists on both sides
    /// with different content). Values:
    ///   - "local"  → local content overwrites remote (default; matches
    ///                rsync's source-wins convention and the live watcher's
    ///                push-only direction)
    ///   - "remote" → remote content overwrites local
    ///   - "newer"  → file with the later mtime wins
    /// Files missing on one side are always copied across (no conflict).
    #[serde(default = "default_conflict")]
    pub conflict_resolution: String,
}

fn default_true() -> bool { true }
fn default_conflict() -> String { "local".to_string() }

#[derive(Debug, Clone, Serialize)]
pub struct MirrorStatus {
    pub id: String,
    pub session_id: String,
    pub local: String,
    pub remote: String,
    /// "starting" | "scanning" | "initial-sync" | "watching" | "paused" |
    /// "error" | "stopped". "paused": deletions are held (mass-delete guard);
    /// uploads go on.
    pub state: String,
    /// Pending FS events queued for the worker.
    pub queue_depth: u32,
    pub uploaded: u32,
    /// Only incremented during the initial reconciliation; the watcher
    /// phase is push-only so it stays at the initial-sync value afterwards.
    pub downloaded: u32,
    pub deleted: u32,
    /// Files visited so far during the scan/compare phase. Lets the UI
    /// show "Scanning… (N files checked)" instead of an opaque spinner
    /// on big trees where compare_files can take a while.
    pub scanned: u32,
    /// Total transfers the initial sync will do (uploads + downloads).
    /// 0 until the scan completes.
    pub transfer_total: u32,
    /// Transfers finished so far during the initial sync — uploaded +
    /// downloaded combined. Lets the UI render a progress bar.
    pub transfer_done: u32,
    /// Wall-clock time (ms since epoch) of the most recent successful action.
    pub last_event_ms: u128,
    pub error: Option<String>,
    /// Local deletions held by the mass-delete guard (F-008).
    pub held_deletes: u32,
    /// Why deletions are held, while they are.
    pub pause_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DryRunEntry {
    pub path: String,
    pub size: u64,
    /// "upload-new" | "upload-modified" | "download-new" | "download-modified"
    pub action: String,
}

/// A path the scan could not check (a stat, listing or read that failed for
/// another reason than "no such file"): it is left alone on both sides
/// (F-046).
#[derive(Debug, Clone, Serialize)]
pub struct DryRunProblem {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DryRunReport {
    pub entries: Vec<DryRunEntry>,
    pub total_bytes: u64,
    pub problems: Vec<DryRunProblem>,
}

/// What a scan of both trees finds: the transfers to make, the local paths
/// it visited (so the remote walk adds only remote-only files), and what it
/// could not check.
#[derive(Default)]
struct Scan {
    entries: Vec<DryRunEntry>,
    total: u64,
    seen: HashSet<String>,
    scanned: u32,
    problems: Vec<DryRunProblem>,
}

impl Scan {
    fn problem(&mut self, path: &str, reason: impl std::fmt::Display) {
        self.problems.push(DryRunProblem { path: path.to_string(), reason: reason.to_string() });
    }

    fn add(&mut self, path: String, size: u64, action: &str) {
        self.entries.push(DryRunEntry { path, size, action: action.into() });
        self.total = self.total.saturating_add(size);
    }
}

/// Walk both trees: `walk_local` decides upload-* / download-* / skip for
/// every local file via compare_files (size, mtime, hash-on-tie);
/// `walk_remote` then only fills in the remote-only files (not in `seen`).
/// This split avoids hashing each ambiguous file twice.
async fn scan_trees(sftp: &SftpSession, local_root: &Path, spec: &MirrorSpec) -> Result<Scan, String> {
    // A missing server folder is created by the first upload; anything else
    // there must be a folder.
    match sftp.metadata(&spec.remote).await {
        Ok(attr) if attr.permissions.is_some() && !attr.is_dir() => {
            return Err(format!("The server path is not a folder: {}", spec.remote));
        }
        Ok(_) => {
            // A link to `/` would map the mirror onto the whole server.
            if let Ok(real) = sftp.canonicalize(&spec.remote).await {
                if real.trim_end_matches('/').is_empty() {
                    return Err(format!("The server folder {} is the server's root folder", spec.remote));
                }
            }
        }
        Err(e) if atomic_transfer::is_not_found(&e) => {}
        Err(e) => return Err(format!("Could not check the server folder {}: {}", spec.remote, e)),
    }
    let mut scan = Scan::default();
    walk_local(local_root, local_root, &spec.remote, &spec.excludes, sftp, &spec.conflict_resolution, &mut scan).await?;
    walk_remote(sftp, &spec.remote, &spec.remote, &spec.excludes, &mut scan).await?;
    Ok(scan)
}

pub struct ActiveMirror {
    pub status: Arc<Mutex<MirrorStatus>>,
    /// `true` asks the worker to stop; a transfer in progress reads it
    /// between chunks.
    pub stop: watch::Sender<bool>,
    pub join: Mutex<Option<tauri::async_runtime::JoinHandle<()>>>,
    /// For the final `stopped` report when the worker had to be aborted.
    pub events: MirrorEvents,
    /// Asks a paused worker to apply its held deletions.
    pub resume: tokio::sync::mpsc::UnboundedSender<()>,
}

pub type MirrorMap = Arc<Mutex<HashMap<String, ActiveMirror>>>;

/// How long a stopped mirror's worker gets before it is aborted.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the operation in progress gets, once a stop is asked, to notice it
/// (a transfer does at its next chunk) and clean up before it is dropped.
const CANCEL_GRACE: Duration = Duration::from_secs(2);

/// Resolves once the mirror is asked to stop (or its entry is gone).
async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|asked| *asked).await;
}

/// Whether a stop was asked; for the per-chunk checks.
fn stopping(stop: &watch::Receiver<bool>) -> bool {
    *stop.borrow() || stop.has_changed().is_err()
}

/// Runs `work` unless the mirror is asked to stop. Then `work` gets
/// `CANCEL_GRACE` to see the stop and clean up, and is dropped. `None`: stopped.
async fn unless_stopped<T>(work: impl std::future::Future<Output = T>, stop: &watch::Receiver<bool>) -> Option<T> {
    tokio::pin!(work);
    let mut stop = stop.clone();
    tokio::select! {
        out = &mut work => Some(out),
        _ = stopped(&mut stop) => {
            let _ = tokio::time::timeout(CANCEL_GRACE, &mut work).await;
            None
        }
    }
}

// ---------------------------------------------------------------------------
// IDs + helpers
// ---------------------------------------------------------------------------

fn next_mirror_id() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
    format!("mir-{}-{}", ms, n)
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// Folder names never mirrored, at any depth (with everything inside).
const EXCLUDED_DIRS: &[&str] = &[".git", "node_modules"];
/// Names never mirrored: system clutter, and vim's write test file.
/// All the default lists are lower case and compared without case: on a disk
/// that ignores case (macOS, Windows) a server's `.GIT/hooks` is `.git/hooks`.
const EXCLUDED_NAMES: &[&str] = &[".ds_store", "thumbs.db", "4913"];
/// Name beginnings: Office lock files, Emacs lock links, GIO's save temporaries.
const EXCLUDED_PREFIXES: &[&str] = &["~$", ".#", ".goutputstream-"];
/// Name endings: editor swap and backup files, downloads in progress, and
/// Solanum's own temporary, part and aside files (F-047).
const EXCLUDED_SUFFIXES: &[&str] =
    &["~", ".swp", ".swo", ".tmp", ".part", ".solanum-tmp", ".solanum-part", ".solanum-old"];

/// True if `rel` (a relative path under the mirror root) is not mirrored. The
/// defaults match whole names, at any folder level (an excluded folder takes
/// what it holds with it); the trash only at the top. User patterns: `*.<ext>`
/// is a suffix, anything else a substring of the relative path.
fn is_excluded(rel: &str, user_excludes: &[String]) -> bool {
    let rel_norm = rel.replace('\\', "/");
    let names: Vec<&str> = rel_norm.split('/').filter(|n| !n.is_empty()).collect();
    if names.first() == Some(&TRASH) {
        return true;
    }
    let default_hit = |name: &&str| {
        let name = name.to_ascii_lowercase();
        EXCLUDED_DIRS.contains(&name.as_str())
            || EXCLUDED_NAMES.contains(&name.as_str())
            || EXCLUDED_PREFIXES.iter().any(|p| name.starts_with(p))
            || EXCLUDED_SUFFIXES.iter().any(|s| name.ends_with(s))
    };
    if names.iter().any(default_hit) {
        return true;
    }
    for p in user_excludes {
        let p = p.trim();
        if p.is_empty() { continue; }
        if let Some(ext) = p.strip_prefix("*.") {
            if rel_norm.ends_with(&format!(".{}", ext)) { return true; }
            continue;
        }
        if rel_norm.contains(p) { return true; }
    }
    false
}

/// The local folder the worker walks and watches. On macOS the watcher
/// (FSEvents) reports canonical paths, so a folder reached through a link
/// (`/tmp` is `/private/tmp`) or typed in another case is used under its
/// canonical name, or no event would match it. Elsewhere events come under
/// the watched path as given.
fn working_root(local: &str) -> PathBuf {
    let given = PathBuf::from(local);
    if cfg!(target_os = "macos") {
        given.canonicalize().unwrap_or(given)
    } else {
        given
    }
}

/// Refuse folders a mirror must not work on (F-008): the server folder must
/// be an absolute path below `/` made of plain names, and the local folder
/// one files may be written into (`local_path::mirror_root_problem`).
fn check_roots(spec: &MirrorSpec) -> Result<(), String> {
    let remote = spec.remote.trim_end_matches('/');
    let plain = remote.split('/').skip(1).all(|c| !c.is_empty() && c != "." && c != "..");
    if !spec.remote.starts_with('/') || remote.is_empty() || !plain || spec.remote.contains('\0') {
        return Err(format!("The server folder must be an absolute path below / made of plain names: {:?}", spec.remote));
    }
    match crate::local_path::mirror_root_problem(Path::new(&spec.local)) {
        Some(why) => Err(why),
        None => Ok(()),
    }
}

/// Translate a local path under `local_root` into the corresponding remote
/// path under `remote_root`. POSIX-style ('/') separators on the remote
/// regardless of host platform.
fn local_to_remote(local: &Path, local_root: &Path, remote_root: &str) -> Option<String> {
    let rel = local.strip_prefix(local_root).ok()?;
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    let trimmed = remote_root.trim_end_matches('/');
    Some(if rel_str.is_empty() {
        trimmed.to_string()
    } else {
        format!("{}/{}", trimmed, rel_str)
    })
}

// ---------------------------------------------------------------------------
// Status + log emission
// ---------------------------------------------------------------------------

/// Where a mirror reports. Built from the `AppHandle` only in `lib.rs`
/// (`mirror_events`), so the mirror runs in tests without the Tauri runtime.
#[derive(Clone)]
pub struct MirrorEvents {
    /// Receives every status change (the `mirror-update-<session>` event).
    pub update: Arc<dyn Fn(&MirrorStatus) + Send + Sync>,
    /// Receives the session id and a log entry (`mirror-log-<session>`).
    pub log: Arc<LogSink>,
}

pub type LogSink = dyn Fn(&str, &MirrorLogEntry<'_>) + Send + Sync;

#[cfg(test)]
impl MirrorEvents {
    /// Reports nowhere.
    pub fn quiet() -> Self {
        MirrorEvents { update: Arc::new(|_: &MirrorStatus| {}), log: Arc::new(|_: &str, _: &MirrorLogEntry<'_>| {}) }
    }
}

async fn emit_update(events: &MirrorEvents, status: &MirrorStatus) {
    (events.update)(status);
}

#[derive(Debug, Clone, Serialize)]
pub struct MirrorLogEntry<'a> {
    pub mirror_id: &'a str,
    pub ts_ms: u128,
    pub level: &'a str,
    pub event: &'a str,
    pub path: Option<String>,
    pub message: Option<String>,
}

fn emit_log(
    events: &MirrorEvents,
    session_id: &str,
    mirror_id: &str,
    level: &str,
    event: &str,
    path: Option<String>,
    message: Option<String>,
) {
    let entry = MirrorLogEntry { mirror_id, ts_ms: now_ms(), level, event, path, message };
    (events.log)(session_id, &entry);
}

async fn set_state(events: &MirrorEvents, status: &Arc<Mutex<MirrorStatus>>, new: &str, err: Option<String>) {
    let snapshot = {
        let mut s = status.lock().await;
        s.state = new.into();
        if let Some(e) = err { s.error = Some(e); }
        s.clone()
    };
    emit_update(events, &snapshot).await;
}

// ---------------------------------------------------------------------------
// SFTP helpers
// ---------------------------------------------------------------------------

/// Open a dedicated SFTP session on the SSH handle. Each mirror gets its
/// own subsystem channel so it doesn't contend with the file browser or
/// another mirror task on a shared one. The commands that start a mirror have
/// checked the connection's gate (`refuse_if_terminal_only`); a refusal here
/// only fails this mirror.
async fn open_sftp<H: russh::client::Handler>(handle: &SshHandle<H>) -> Result<SftpSession, String> {
    let channel = crate::ssh_connect::open_feature_channel(handle, &Default::default())
        .await
        .map_err(|e| format!("open session: {}", e))?;
    channel.request_subsystem(true, "sftp").await
        .map_err(|e| format!("request sftp subsystem: {}", e))?;
    SftpSession::new(channel.into_stream()).await
        .map_err(|e| format!("sftp init: {}", e))
}

/// Equivalent of `mkdir -p` over SFTP. Walks the path components and
/// creates each missing intermediate directory. Treats AlreadyExists as
/// success since two mirror tasks may race to create the same parent.
pub(crate) async fn sftp_mkdir_p(sftp: &SftpSession, path: &str) -> Result<(), String> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').filter(|p| !p.is_empty()).collect();
    let mut cur = String::from("/");
    for p in parts {
        if cur != "/" { cur.push('/'); }
        cur.push_str(p);
        // Stat first so we don't churn through CREATE errors on every level.
        if sftp.metadata(&cur).await.is_ok() { continue; }
        match sftp.create_dir(&cur).await {
            Ok(_) => {}
            Err(e) => {
                // Another transfer may have created it meanwhile. OpenSSH
                // reports that as a bare "Failure", so look again (N-021).
                if sftp.metadata(&cur).await.map(|m| m.is_dir()).unwrap_or(false) { continue; }
                return Err(format!("mkdir {}: {}", cur, e));
            }
        }
    }
    Ok(())
}

/// Upload `local` over `remote` through the shared helper (F-007): a hidden
/// part file beside it, the server file's owner, group and mode kept, a link
/// kept as a link, the part file removed on every error and when a stop is
/// seen between chunks. A server file the helper may only rewrite in place
/// (see `atomic_transfer`) is finished despite a stop, since stopping would
/// cut it short; only a broken connection can leave it partial. A file the
/// server did not have gets the local file's permission bits, as the
/// server's umask allows (owner). `replace` false: a file that appeared at
/// the name since the scan is not replaced. `keep_previous`: where the
/// replaced version goes instead of being deleted. Then the server file gets
/// the local modification time (F-046).
///
/// Callers run it as a task of its own and, on a stop, stop waiting for it
/// rather than drop it: a dropped future could stop between the renames of
/// a replace and leave the name missing (review of batch 8).
async fn upload_file(
    sftp: &SftpSession,
    local: &Path,
    remote: &str,
    replace: bool,
    keep_previous: Option<&str>,
    stop: &watch::Receiver<bool>,
) -> Result<Replaced, String> {
    if let Some((parent, _)) = remote.rsplit_once('/') {
        if !parent.is_empty() {
            sftp_mkdir_p(sftp, parent).await?;
        }
    }
    let before = tokio::fs::metadata(local).await.map_err(|e| format!("local stat {:?}: {}", local, e))?;
    let options = ReplaceOptions {
        allow_replace: replace,
        new_file_mode: local_mode(&before),
        keep_previous,
        finish_in_place: true,
    };
    let replaced = atomic_transfer::replace_remote_file_with(sftp, remote, local, &options, &mut |_: u64, _: &[u8]| {
        !stopping(stop)
    })
    .await
    .map_err(|e| match e {
        ReplaceError::Cancelled => "stopped".to_string(),
        ReplaceError::Exists => {
            "a server file appeared at this name since the scan and was not replaced; start the mirror again to compare".to_string()
        }
        ReplaceError::Failed(m) => m,
    })?;
    keep_local_times(sftp, local, remote, &before).await;
    Ok(replaced)
}

#[cfg(unix)]
fn local_mode(meta: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode() & 0o777)
}

/// Windows has no Unix mode to carry over: the server's default applies.
#[cfg(not(unix))]
fn local_mode(_meta: &std::fs::Metadata) -> Option<u32> {
    None
}

fn unix_secs(time: std::io::Result<SystemTime>) -> Option<u32> {
    time.ok()?.duration_since(UNIX_EPOCH).ok()?.as_secs().try_into().ok()
}

/// Give the uploaded file the local file's times, so the next start finds it
/// in sync without reading it again (F-046). Only if the local file did not
/// change while it was uploaded: stamping older content with the new time
/// would hide the change from that check. Times only (a SETSTAT with the size
/// would truncate a file that grew). Best effort: a file written in place
/// that belongs to someone else cannot take them, and is then compared by
/// content as before.
async fn keep_local_times(sftp: &SftpSession, local: &Path, remote: &str, before: &std::fs::Metadata) {
    let Ok(after) = tokio::fs::metadata(local).await else { return };
    if after.len() != before.len() || after.modified().ok() != before.modified().ok() {
        return;
    }
    let Some(mtime) = unix_secs(before.modified()) else { return };
    let mut times = FileAttributes::empty();
    times.atime = Some(unix_secs(before.accessed()).unwrap_or(mtime));
    times.mtime = Some(mtime);
    let _ = sftp.set_metadata(remote, times).await;
}

/// What the log says about how an upload replaced the server file.
/// `keeping`: the previous version was to be kept in the trash.
fn upload_notes(replaced: &Replaced, keeping: bool) -> Vec<String> {
    let mut notes = Vec::new();
    match replaced {
        Replaced::KeptPrevious { at } => notes.push(format!("the previous server version is kept as {at}")),
        Replaced::InPlace(why) => {
            notes.push(format!("written in place because {why}"));
            if keeping {
                notes.push("the previous server version could not be kept".into());
            }
        }
        Replaced::Renamed | Replaced::MovedAside { .. } if keeping => {
            notes.push("the previous server version could not be moved to the trash".into());
        }
        _ => {}
    }
    notes.extend(replaced.note());
    notes
}

/// Where a soft delete, or an initial sync replacing a server file, puts the
/// server's version: `<root>/.solanum-trash/<stamp>/<relative path>`.
fn trash_path(remote_root: &str, stamp: u128, rel: &str) -> String {
    format!("{}/{}/{}/{}", remote_root.trim_end_matches('/'), TRASH, stamp, rel)
}

const TRASH: &str = ".solanum-trash";

/// The local file `rel` maps to under `root`, for a download (F-008): the
/// file must pass the write policy first (`guard_local_path`: no auto-start
/// folders, `~/.ssh`, ...; checked before any folder is created); every
/// folder on the way must be a real folder, never a link (a download must not
/// land outside the mirrored folder through one), and missing ones are
/// created one at a time; and each folder must be the one named, not another
/// spelling of an existing one. Names coming from the server were already
/// checked by `walk_remote`.
async fn local_target_for_write(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let names: Vec<&str> = rel.split('/').collect();
    if names.iter().any(|n| n.is_empty() || *n == "." || *n == "..") {
        return Err(format!("not a plain relative path: {:?}", rel));
    }
    let (leaf, folders) = names.split_last().ok_or_else(|| "empty path".to_string())?;
    let target = names.iter().fold(root.to_path_buf(), |p, n| p.join(n));
    crate::local_path::guard_local_path(&target, crate::local_path::LocalAccess::Write)?;
    let mut dir = root.to_path_buf();
    for name in folders {
        dir.push(name);
        match tokio::fs::symlink_metadata(&dir).await {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Err(format!("{:?} is a link or a file, not a folder; nothing is written through it", dir)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Err(e) = tokio::fs::create_dir(&dir).await {
                    // Created meanwhile by a parallel download: fine if it is a folder.
                    let made = tokio::fs::symlink_metadata(&dir).await.map(|m| m.is_dir()).unwrap_or(false);
                    if !made {
                        return Err(format!("local mkdir {:?}: {}", dir, e));
                    }
                }
            }
            Err(e) => return Err(format!("{:?}: {}", dir, e)),
        }
    }
    // Another spelling of an existing folder (a case variant on a disk that
    // ignores case, a Windows short name like `GIT~1`) would let a server's
    // `.GIT/hooks/x` land in `.git/hooks` (review of batch 8).
    if !folders.is_empty() {
        let real_root = tokio::fs::canonicalize(root).await.map_err(|e| format!("{:?}: {}", root, e))?;
        let real = tokio::fs::canonicalize(&dir).await.map_err(|e| format!("{:?}: {}", dir, e))?;
        let stored: Vec<String> = real
            .strip_prefix(&real_root)
            .map(|r| r.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        if !stored.iter().map(String::as_str).eq(folders.iter().copied()) {
            return Err(format!(
                "{:?} is another spelling of the existing folder {:?}; nothing is written there",
                folders.join("/"),
                stored.join("/")
            ));
        }
    }
    Ok(dir.join(leaf))
}

/// Whether `path` (under `root`) is reached without a link: every folder
/// between the root and it is a real folder (N-018). The watcher follows
/// links (notify adds its watches through them); the scan does not, and
/// neither may the uploads and deletions the watcher triggers. A folder on
/// the way that no longer exists is fine (that is a deletion).
async fn reached_without_link(root: &Path, path: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(root) else { return false };
    let names: Vec<_> = rel.components().collect();
    let mut dir = root.to_path_buf();
    for name in names.iter().take(names.len().saturating_sub(1)) {
        dir.push(name);
        match tokio::fs::symlink_metadata(&dir).await {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return false,
            Err(_) => return true,
        }
    }
    true
}

/// Stream a remote file down into a local path through `LocalPart`
/// (F-047): a part file beside the target, removed on any error and on a
/// stop, renamed into place only when complete. Only a regular file is
/// downloaded (following a server link), and never more than the size it
/// had when it was looked at: a link to `/dev/zero` must not fill the disk,
/// and a file that grew meanwhile is refused rather than written cut short.
/// `replace`: the local file there is replaced ("↓ mod"); otherwise a file
/// that appeared meanwhile is kept and the download refused. Then the local
/// file gets the server's mtime, so the next start does not see it as
/// "newer".
async fn sftp_download_file(
    sftp: &SftpSession,
    remote: &str,
    local: &Path,
    replace: bool,
    stop: &watch::Receiver<bool>,
) -> Result<(), String> {
    let attr = sftp.metadata(remote).await
        .map_err(|e| format!("sftp stat {}: {}", remote, e))?;
    if attr.permissions.is_some() && !attr.is_regular() {
        return Err("not a regular file on the server".into());
    }
    let size = attr.size.ok_or_else(|| "the server does not report the file's size".to_string())?;
    let mut handle = sftp.open(remote).await
        .map_err(|e| format!("sftp open {}: {}", remote, e))?;
    let mut part = atomic_transfer::LocalPart::create(local).await
        .map_err(|e| format!("local create {:?}: {}", local, e))?;
    let mut buf = vec![0u8; atomic_transfer::CHUNK];
    let mut received: u64 = 0;
    loop {
        let n = handle.read(&mut buf).await.map_err(|e| format!("sftp read: {}", e))?;
        if n == 0 { break; }
        received += n as u64;
        if received > size {
            return Err("the server file grew while it was downloaded; nothing was written".into());
        }
        if stopping(stop) { return Err("stopped".into()); }
        part.file().write_all(&buf[..n]).await.map_err(|e| format!("local write: {}", e))?;
    }
    part.commit(replace).await.map_err(|e| match e {
        atomic_transfer::CommitError::Exists => format!("{:?} appeared meanwhile and is kept", local),
        atomic_transfer::CommitError::Io(m) => format!("local rename {:?}: {}", local, m),
    })?;
    if let Some(secs) = attr.mtime {
        let ft = filetime::FileTime::from_unix_time(secs as i64, 0);
        let _ = filetime::set_file_mtime(local, ft);
    }
    Ok(())
}

/// Move the server copy of `rel` to `<remote_root>/.solanum-trash/<stamp>/<rel>`
/// (F-047: the relative path is kept, so it can be put back where it was).
/// Cheaper than a delete and recoverable without server-side support.
/// `Ok(false)`: it was not there (a folder moved earlier in the same batch
/// took it along).
async fn sftp_soft_delete(sftp: &SftpSession, remote_root: &str, rel: &str, stamp: u128) -> Result<bool, String> {
    let target = format!("{}/{}", remote_root.trim_end_matches('/'), rel);
    let dest = trash_path(remote_root, stamp, rel);
    if let Some((parent, _)) = dest.rsplit_once('/') {
        sftp_mkdir_p(sftp, parent).await?;
    }
    match sftp.rename(&target, &dest).await {
        Ok(()) => Ok(true),
        Err(e) if atomic_transfer::is_not_found(&e) => Ok(false),
        Err(e) => Err(format!("sftp soft-delete {}: {}", target, e)),
    }
}

/// Remove the server copy for good. A folder is removed only once empty
/// (its children come first in a batch); a link is removed, not followed.
/// `Ok(false)`: it was not there.
async fn sftp_hard_delete(sftp: &SftpSession, target: &str) -> Result<bool, String> {
    // OpenSSH answers `remove` on a folder with a bare "Failure" (N-022),
    // so look at what is there first.
    let meta = match sftp.symlink_metadata(target).await {
        Ok(m) => m,
        Err(e) if atomic_transfer::is_not_found(&e) => return Ok(false),
        Err(e) => return Err(format!("stat {}: {}", target, e)),
    };
    if meta.file_type().is_dir() {
        sftp.remove_dir(target).await.map_err(|e| format!("rmdir {}: {}", target, e))?;
    } else {
        sftp.remove_file(target).await.map_err(|e| format!("rm {}: {}", target, e))?;
    }
    Ok(true)
}

/// The order a batch of watcher events is applied in. Soft delete: parents
/// first, so a removed folder moves to the trash in one rename, its children
/// with it. Hard delete: children first, so a folder is empty when it goes.
fn order_batch(paths: &mut [PathBuf], soft_delete: bool) {
    paths.sort_by(|a, b| depth_order(a, b, soft_delete));
}

fn depth_order(a: &Path, b: &Path, soft_delete: bool) -> std::cmp::Ordering {
    let by_depth = a.components().count().cmp(&b.components().count());
    (if soft_delete { by_depth } else { by_depth.reverse() }).then_with(|| a.cmp(b))
}

// ---------------------------------------------------------------------------
// Content comparison
// ---------------------------------------------------------------------------
//
// rsync's default "quick check" treats two files as equal when both their
// size and mtime match. That's wrong in the strict sense — a file edited
// in-place that preserves its size and gets `touch -m`-ed back to the old
// mtime would slip through — but it's correct in every practical scenario
// and cheap. For the cases where the quick check *can't* decide (same
// size, different mtimes) we fall back to a full SHA-256 of both sides
// so we don't get fooled by a server with skewed clocks or an editor
// that touches mtime without changing content.
//
// Different sizes always mean different content; we don't bother hashing.
// "Newer wins" is then a stable rule for picking the direction of the
// transfer.

enum CompareResult {
    Identical,
    LocalNewer,
    RemoteNewer,
}

async fn local_sha256(path: &Path) -> Result<[u8; 32], String> {
    let mut f = tokio::fs::File::open(path).await
        .map_err(|e| format!("local open {:?}: {}", path, e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).await.map_err(|e| format!("local read: {}", e))?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

async fn sftp_sha256(sftp: &SftpSession, remote: &str) -> Result<[u8; 32], String> {
    let mut h = sftp.open(remote).await
        .map_err(|e| format!("sftp open {}: {}", remote, e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = h.read(&mut buf).await.map_err(|e| format!("sftp read: {}", e))?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

async fn compare_files(
    sftp: &SftpSession,
    local: &Path,
    remote: &str,
    local_meta: &std::fs::Metadata,
    remote_attr: &FileAttributes,
) -> Result<CompareResult, String> {
    let local_size = local_meta.len();
    let remote_size = remote_attr.size.unwrap_or(0);
    let local_secs = local_meta.modified().ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs()).unwrap_or(0);
    let remote_secs = remote_attr.mtime.map(|t| t as u64).unwrap_or(0);

    if local_size != remote_size {
        return Ok(if local_secs >= remote_secs { CompareResult::LocalNewer }
                  else { CompareResult::RemoteNewer });
    }
    // Same size, same mtime → call it equal. Empty files we also call equal
    // because the hash is degenerate and would just confirm what we know.
    if local_secs == remote_secs {
        return Ok(CompareResult::Identical);
    }
    // Same size, different mtime — the only ambiguous bucket. Hash both
    // sides and trust the digests. If they actually match, the difference
    // was clock drift / a metadata-only touch and there's nothing to move.
    let lh = local_sha256(local).await?;
    let rh = sftp_sha256(sftp, remote).await?;
    if lh == rh {
        return Ok(CompareResult::Identical);
    }
    Ok(if local_secs >= remote_secs { CompareResult::LocalNewer }
       else { CompareResult::RemoteNewer })
}

// ---------------------------------------------------------------------------
// Dry-run: walk both trees and report what to move
// ---------------------------------------------------------------------------

pub async fn dry_run<H: russh::client::Handler>(
    handle: SshHandle<H>,
    spec: MirrorSpec,
) -> Result<DryRunReport, String> {
    check_roots(&spec)?;
    let local_root = working_root(&spec.local);
    let sftp = open_sftp(&handle).await?;
    let scan = scan_trees(&sftp, &local_root, &spec).await?;
    Ok(DryRunReport { entries: scan.entries, total_bytes: scan.total, problems: scan.problems })
}

/// Recursive walk over the LOCAL tree. For each file we ask compare_files
/// whether the remote copy is missing / equal / newer / older, then pick a
/// direction using the mirror's `conflict_resolution` setting. Every
/// visited rel path goes into `seen` so walk_remote can identify which
/// remote files weren't covered here and need a download-new entry.
/// `scanned` increments once per file visited (for progress UI). Only "no
/// such file" makes a server file missing; any other failure leaves that
/// path (or folder) alone and records a problem (F-046). The root itself
/// failing to list is an error.
async fn walk_local(
    root: &Path,
    dir: &Path,
    remote_root: &str,
    excludes: &[String],
    sftp: &SftpSession,
    conflict_mode: &str,
    scan: &mut Scan,
) -> Result<(), String> {
    let dir_rel = dir.strip_prefix(root).unwrap_or(dir).to_string_lossy().replace('\\', "/");
    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(e) if dir == root => return Err(format!("read_dir {:?}: {}", dir, e)),
        Err(e) => {
            scan.problem(&dir_rel, format!("could not list the local folder: {e}"));
            return Ok(());
        }
    };
    loop {
        let entry = match rd.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) if dir == root => return Err(format!("dir iter: {}", e)),
            Err(e) => {
                scan.problem(&dir_rel, format!("could not list the local folder: {e}"));
                break;
            }
        };
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
        if is_excluded(&rel, excludes) { continue; }
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(e) => {
                scan.problem(&rel, format!("could not read the local file's details: {e}"));
                continue;
            }
        };
        if meta.is_dir() {
            Box::pin(walk_local(root, &path, remote_root, excludes, sftp, conflict_mode, scan)).await?;
            continue;
        }
        if !meta.is_file() { continue; } // skip symlinks / sockets / pipes
        scan.scanned = scan.scanned.saturating_add(1);
        let remote_path = match local_to_remote(&path, root, remote_root) {
            Some(r) => r, None => continue,
        };
        scan.seen.insert(rel.clone());
        let size = meta.len();
        let remote_attr = match sftp.metadata(&remote_path).await {
            Ok(attr) => Some(attr),
            Err(e) if atomic_transfer::is_not_found(&e) => None,
            Err(e) => {
                // Permission denied, a timeout, ...: not proof that it is
                // missing, so nothing is uploaded over it.
                scan.problem(&rel, format!("could not check the server copy: {e}"));
                continue;
            }
        };
        let action = match remote_attr {
            // Missing on the other side is never a conflict — copy across.
            None => "upload-new",
            Some(attr) => {
                let cmp = match compare_files(sftp, &path, &remote_path, &meta, &attr).await {
                    Ok(cmp) => cmp,
                    Err(e) => {
                        scan.problem(&rel, format!("could not compare: {e}"));
                        continue;
                    }
                };
                match cmp {
                    CompareResult::Identical => continue,
                    // Same-content cases that *do* differ — pick a side per mode.
                    CompareResult::LocalNewer | CompareResult::RemoteNewer => {
                        let local_wins = match conflict_mode {
                            "remote" => false,
                            "newer"  => matches!(cmp, CompareResult::LocalNewer),
                            _        => true,  // "local" or unknown → safe default
                        };
                        if local_wins { "upload-modified" } else { "download-modified" }
                    }
                }
            }
        };
        scan.add(rel, size, action);
    }
    Ok(())
}

/// Recursive walk over the remote tree via SFTP. walk_local already
/// covered every file that exists locally (and chose Identical / upload /
/// download for it via compare_files). All that's left for walk_remote is
/// the remote-only files: anything whose rel path isn't in `seen` is a
/// file the local tree doesn't have, so it becomes a download-new entry.
///
/// A missing remote root is treated as "nothing to do" rather than an
/// error — the user may legitimately be mirroring into a fresh remote
/// path that the upload pass will create. Any other listing failure is a
/// problem (that folder's server-only files are not downloaded). The trash
/// is excluded (`is_excluded`), so the soft-delete archive never gets
/// dragged back into the local tree.
async fn walk_remote(
    sftp: &SftpSession,
    remote_root: &str,
    remote_dir: &str,
    excludes: &[String],
    scan: &mut Scan,
) -> Result<(), String> {
    let trimmed_root = remote_root.trim_end_matches('/').to_string();
    let prefix = format!("{}/", trimmed_root);
    let read = match sftp.read_dir(remote_dir).await {
        Ok(r) => r,
        Err(e) if remote_dir == remote_root && atomic_transfer::is_not_found(&e) => return Ok(()),
        Err(e) => {
            let rel = remote_dir.strip_prefix(&prefix).unwrap_or("");
            scan.problem(rel, format!("could not list the server folder: {e}"));
            return Ok(());
        }
    };
    let items: Vec<_> = read.collect();
    for entry in items {
        let name = entry.file_name();
        let remote_path = format!("{}/{}", remote_dir.trim_end_matches('/'), name);
        let rel = remote_path.strip_prefix(&prefix)
            .unwrap_or(remote_path.as_str())
            .to_string();
        // Skip any entry whose name isn't a single plain component. A hostile
        // SFTP server can return `../../x` or `..\x`; that rel path later feeds
        // local_root.join(...) in the transfer pool and would escape the mirror
        // root (zip-slip → arbitrary local write). See is_safe_dir_entry_name.
        if !crate::is_safe_dir_entry_name(&name) {
            if name != "." && name != ".." {
                scan.problem(&rel, "the name cannot be used for a local file here");
            }
            continue;
        }
        if is_excluded(&rel, excludes) { continue; }

        if entry.file_type().is_dir() {
            Box::pin(walk_remote(sftp, remote_root, &remote_path, excludes, scan)).await?;
            continue;
        }
        scan.scanned = scan.scanned.saturating_add(1);
        // walk_local already decided this file's fate — don't double-emit.
        if scan.seen.contains(&rel) { continue; }
        let size = entry.metadata().size.unwrap_or(0);
        scan.add(rel, size, "download-new");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public entry — start_mirror
// ---------------------------------------------------------------------------

pub async fn start<H: russh::client::Handler + 'static>(
    events: MirrorEvents,
    session_id: String,
    handle: SshHandle<H>,
    map: MirrorMap,
    spec: MirrorSpec,
) -> Result<String, String> {
    let id = next_mirror_id();
    check_roots(&spec)?;

    let status = MirrorStatus {
        id: id.clone(),
        session_id: session_id.clone(),
        local: spec.local.clone(),
        remote: spec.remote.clone(),
        state: "starting".into(),
        queue_depth: 0,
        uploaded: 0,
        downloaded: 0,
        deleted: 0,
        scanned: 0,
        transfer_total: 0,
        transfer_done: 0,
        last_event_ms: now_ms(),
        error: None,
        held_deletes: 0,
        pause_reason: None,
    };
    let status_arc = Arc::new(Mutex::new(status.clone()));
    let (stop_tx, stop_rx) = watch::channel(false);
    let (resume_tx, resume_rx) = tokio::sync::mpsc::unbounded_channel();

    emit_update(&events, &status).await;
    emit_log(&events, &session_id, &id, "info", "start",
             Some(spec.local.clone()),
             Some(format!("Mirror starting → {}", spec.remote)));

    let events_t = events.clone();
    let session_t = session_id.clone();
    let status_t = Arc::clone(&status_arc);
    let map_t = Arc::clone(&map);
    let id_t = id.clone();
    let spec_t = spec.clone();
    // Locked from spawn to insert: a worker that ends at once removes its own
    // entry, which must be there by then (N-019).
    let mut mirrors = map.lock().await;
    let join = tauri::async_runtime::spawn(async move {
        let res = run_mirror(events_t.clone(), session_t.clone(), id_t.clone(), handle,
                              spec_t, Arc::clone(&status_t), Signals { stop: stop_rx, resume: resume_rx }).await;
        match res {
            Ok(()) => {
                set_state(&events_t, &status_t, "stopped", None).await;
                emit_log(&events_t, &session_t, &id_t, "info", "stopped", None, None);
            }
            Err(e) => {
                emit_log(&events_t, &session_t, &id_t, "error", "fatal", None, Some(e.clone()));
                set_state(&events_t, &status_t, "error", Some(e)).await;
            }
        }
        map_t.lock().await.remove(&id_t);
    });
    mirrors.insert(id.clone(), ActiveMirror {
        status: Arc::clone(&status_arc),
        stop: stop_tx,
        join: Mutex::new(Some(join)),
        events,
        resume: resume_tx,
    });
    Ok(id)
}

/// Resume a mirror paused by the mass-delete guard: its held deletions are
/// applied (each checked again).
pub async fn resume(map: &MirrorMap, id: &str) -> Result<(), String> {
    let map = map.lock().await;
    let m = map.get(id).ok_or_else(|| format!("no mirror {}", id))?;
    if m.status.lock().await.state != "paused" {
        return Err("This mirror is not paused.".into());
    }
    m.resume.send(()).map_err(|_| "The mirror has stopped.".to_string())
}

/// Stop one mirror; returns within `STOP_TIMEOUT` (plus the abort) whatever
/// the worker is waiting on.
pub async fn stop(map: &MirrorMap, id: &str) -> Result<(), String> {
    let entry = map.lock().await.remove(id).ok_or_else(|| format!("no mirror {}", id))?;
    stop_entries(vec![entry], STOP_TIMEOUT).await;
    Ok(())
}

/// Signal every entry, wait for all of them under one deadline (no map lock is
/// held: the entries were taken out of it), then abort the ones still running
/// and report them stopped, which they could not do themselves.
async fn stop_entries(entries: Vec<ActiveMirror>, wait: Duration) {
    let mut running = Vec::new();
    for m in entries {
        m.stop.send_replace(true);
        let join = m.join.lock().await.take();
        if let Some(join) = join {
            running.push((m, join));
        }
    }
    let deadline = tokio::time::Instant::now() + wait;
    for (m, mut join) in running {
        if tokio::time::timeout_at(deadline, &mut join).await.is_err() {
            join.abort();
            let snapshot = {
                let mut s = m.status.lock().await;
                s.state = "stopped".into();
                s.clone()
            };
            (m.events.update)(&snapshot);
        }
    }
}

pub async fn list(map: &MirrorMap, session_id: Option<&str>) -> Vec<MirrorStatus> {
    let map = map.lock().await;
    let mut out = Vec::new();
    for m in map.values() {
        let s = m.status.lock().await;
        if let Some(sid) = session_id { if s.session_id != sid { continue; } }
        out.push(s.clone());
    }
    out
}

/// Stop every mirror (the profile is being closed): signal them all, wait at
/// most `wait` for each worker, then abort the ones still running. The map
/// lock is not held while waiting.
pub async fn stop_all_within(map: &MirrorMap, wait: Duration) {
    let mirrors: Vec<ActiveMirror> = map.lock().await.drain().map(|(_, m)| m).collect();
    stop_entries(mirrors, wait).await;
}

/// Stop a session's mirrors (disconnect, reconnect, lost connection), all at
/// once and within `STOP_TIMEOUT`.
pub async fn stop_all_for_session(map: &MirrorMap, session_id: &str) {
    let entries = {
        let mut map = map.lock().await;
        let mut ids = Vec::new();
        for (id, m) in map.iter() {
            if m.status.lock().await.session_id == session_id {
                ids.push(id.clone());
            }
        }
        ids.iter().filter_map(|id| map.remove(id)).collect::<Vec<_>>()
    };
    stop_entries(entries, STOP_TIMEOUT).await;
}

// ---------------------------------------------------------------------------
// Worker: initial sync + watcher
// ---------------------------------------------------------------------------

/// What the worker is told while it runs.
struct Signals {
    /// `true`: stop.
    stop: watch::Receiver<bool>,
    /// Apply the deletions held by the mass-delete guard.
    resume: tokio::sync::mpsc::UnboundedReceiver<()>,
}

async fn run_mirror<H: russh::client::Handler>(
    app: MirrorEvents,
    session_id: String,
    mirror_id: String,
    handle: SshHandle<H>,
    spec: MirrorSpec,
    status: Arc<Mutex<MirrorStatus>>,
    signals: Signals,
) -> Result<(), String> {
    let Signals { stop, resume: mut resume_rx } = signals;
    let local_root = working_root(&spec.local);
    // Shared so the parallel transfer pool can hold references concurrently.
    // SftpSession is internally async-safe — concurrent ops multiplex over
    // request IDs on the same channel.
    let Some(sftp) = unless_stopped(open_sftp(&handle), &stop).await else { return Ok(()) };
    let sftp = Arc::new(sftp?);

    // --- Scan phase: walk both sides, decide what moves where -----------------
    // Separate from initial-sync state so a big tree doesn't look hung while
    // compare_files chews through SFTP metadata + hash compares.
    set_state(&app, &status, "scanning", None).await;
    emit_log(&app, &session_id, &mirror_id, "info", "scan-start",
             Some(spec.local.clone()), None);
    // The scan only reads, so dropping it at a stop leaves nothing behind.
    let Some(scan) = unless_stopped(scan_trees(&sftp, &local_root, &spec), &stop).await else { return Ok(()) };
    let Scan { entries: work, total, scanned, problems, .. } = scan?;
    for p in &problems {
        emit_log(&app, &session_id, &mirror_id, "warn", "scan-skip", Some(p.path.clone()), Some(p.reason.clone()));
    }
    {
        let mut s = status.lock().await;
        s.scanned = scanned;
        s.transfer_total = work.len() as u32;
        s.transfer_done = 0;
    }
    emit_update(&app, &status.lock().await.clone()).await;
    emit_log(&app, &session_id, &mirror_id, "info", "scan-done", None,
             Some(format!("scanned {} files, {} to transfer ({} bytes), {} left alone",
                          scanned, work.len(), total, problems.len())));

    // --- Transfer phase: parallel pool of N workers sharing one SFTP channel.
    // Big speedup on high-latency links because while one transfer is waiting
    // on packet round-trips, the others can be writing/reading.
    if !work.is_empty() {
        set_state(&app, &status, "initial-sync", None).await;
        const PARALLEL: usize = 4;
        let mut set: JoinSet<(DryRunEntry, Result<Vec<String>, String>, bool)> = JoinSet::new();
        let mut iter = work.into_iter();
        // One trash folder for everything this initial sync replaces.
        let stamp = now_ms();

        let spawn_one = |js: &mut JoinSet<_>, entry: DryRunEntry| {
            let is_download = entry.action.starts_with("download-");
            let sftp = Arc::clone(&sftp);
            let stop = stop.clone();
            let local_root = local_root.clone();
            let remote_root = spec.remote.clone();
            // Owner decision (F-007): with soft delete on, a server file the
            // initial sync replaces goes to the trash instead of away. A file
            // the scan found missing is never replaced: one that appeared
            // meanwhile is left alone.
            let replace = entry.action == "upload-modified";
            let keep = spec.soft_delete && replace;
            js.spawn(async move {
                let local_path = local_root.join(entry.path.replace('/', std::path::MAIN_SEPARATOR_STR));
                let remote_path = match local_to_remote(&local_path, &local_root, &remote_root) {
                    Some(r) => r,
                    None => return (entry, Err("path mapping failed".into()), is_download),
                };
                let res = if is_download {
                    match local_target_for_write(&local_root, &entry.path).await {
                        Ok(target) => {
                            let replace = entry.action == "download-modified";
                            sftp_download_file(&sftp, &remote_path, &target, replace, &stop).await.map(|()| Vec::new())
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    let mut notes = Vec::new();
                    let trash = keep.then(|| trash_path(&remote_root, stamp, &entry.path));
                    if let Some(at) = &trash {
                        let parent = at.rsplit_once('/').map(|(p, _)| p).unwrap_or(at);
                        if let Err(e) = sftp_mkdir_p(&sftp, parent).await {
                            notes.push(format!("the previous server version could not be kept: {e}"));
                        }
                    }
                    let keep_at = trash.as_deref().filter(|_| notes.is_empty());
                    upload_file(&sftp, &local_path, &remote_path, replace, keep_at, &stop).await.map(|replaced| {
                        notes.extend(upload_notes(&replaced, keep_at.is_some()));
                        notes
                    })
                };
                (entry, res, is_download)
            });
        };

        // Prime the pool.
        for _ in 0..PARALLEL {
            if let Some(e) = iter.next() { spawn_one(&mut set, e); } else { break; }
        }

        let mut stop_wait = stop.clone();
        while !set.is_empty() {
            // Race the stop signal against the next transfer finishing. On
            // stop the transfers see it at their next chunk and remove their
            // partial files; the pool gets CANCEL_GRACE for that. Whatever
            // is still running then is left to finish on its own, never
            // aborted: an abort could land between the renames of a replace
            // or in the middle of a file written in place.
            let joined = tokio::select! {
                _ = stopped(&mut stop_wait) => {
                    let _ = tokio::time::timeout(CANCEL_GRACE, async { while set.join_next().await.is_some() {} }).await;
                    set.detach_all();
                    return Ok(());
                }
                j = set.join_next() => j,
            };
            let Some(joined) = joined else { break };
            let (entry, res, is_download) = match joined {
                Ok(t) => t,
                Err(je) => {
                    // A panicked / cancelled worker — log it so the UI
                    // counters and the user can see that the slot was
                    // wasted, otherwise the pool would silently chew
                    // through the worklist with the success bar lying.
                    // `transfer_done` advances so the progress bar still
                    // hits 100% when the queue drains.
                    {
                        let mut s = status.lock().await;
                        s.transfer_done = s.transfer_done.saturating_add(1);
                    }
                    emit_update(&app, &status.lock().await.clone()).await;
                    emit_log(&app, &session_id, &mirror_id, "error",
                             "worker-crash", None,
                             Some(format!("Mirror worker panicked / was cancelled: {}", je)));
                    if let Some(e) = iter.next() { spawn_one(&mut set, e); }
                    continue;
                }
            };
            match res {
                Ok(notes) => {
                    {
                        let mut s = status.lock().await;
                        if is_download {
                            s.downloaded = s.downloaded.saturating_add(1);
                        } else {
                            s.uploaded = s.uploaded.saturating_add(1);
                        }
                        s.transfer_done = s.transfer_done.saturating_add(1);
                        s.last_event_ms = now_ms();
                    }
                    emit_update(&app, &status.lock().await.clone()).await;
                    let mut message = format!("{} ({} bytes)", entry.action, entry.size);
                    for note in notes {
                        message.push_str("; ");
                        message.push_str(&note);
                    }
                    emit_log(&app, &session_id, &mirror_id, "info",
                             if is_download { "download" } else { "upload" },
                             Some(entry.path.clone()),
                             Some(message));
                }
                Err(e) => {
                    {
                        let mut s = status.lock().await;
                        s.transfer_done = s.transfer_done.saturating_add(1);
                    }
                    emit_update(&app, &status.lock().await.clone()).await;
                    emit_log(&app, &session_id, &mirror_id, "error",
                             if is_download { "download-fail" } else { "upload-fail" },
                             Some(entry.path.clone()), Some(e));
                }
            }
            // Refill the slot the finished task vacated.
            if let Some(e) = iter.next() { spawn_one(&mut set, e); }
        }
    }

    // --- Watcher phase ---
    set_state(&app, &status, "watching", None).await;

    // notify-debouncer-mini uses std::sync::mpsc. Bridge into a tokio
    // channel so the async loop can `select!` cleanly with stop_rx.
    let (raw_tx, raw_rx) = std::sync::mpsc::channel();
    let (tok_tx, mut tok_rx) = tokio::sync::mpsc::channel::<Vec<PathBuf>>(256);
    let mut debouncer = new_debouncer(Duration::from_millis(500), raw_tx)
        .map_err(|e| format!("debouncer init: {}", e))?;
    debouncer.watcher()
        .watch(&local_root, RecursiveMode::Recursive)
        .map_err(|e| format!("watch {:?}: {}", local_root, e))?;
    // Forward loop runs on the blocking pool; std::mpsc::recv blocks. Keep
    // the JoinHandle so we can await it on the way out — without this the
    // task was abandoned, racing with the next mirror's spawn_blocking and
    // (more importantly) keeping the watcher OS handle alive for the brief
    // window between debouncer-drop and OS-cleanup.
    let session_for_forward = session_id.clone();
    let mirror_for_forward = mirror_id.clone();
    let app_for_forward = app.clone();
    let forward_join = tokio::task::spawn_blocking(move || {
        while let Ok(res) = raw_rx.recv() {
            match res {
                Ok(events) => {
                    let mut paths = Vec::with_capacity(events.len());
                    for ev in events {
                        if matches!(ev.kind, DebouncedEventKind::Any | DebouncedEventKind::AnyContinuous) {
                            paths.push(ev.path);
                        }
                    }
                    if !paths.is_empty() {
                        if tok_tx.blocking_send(paths).is_err() { break; }
                    }
                }
                Err(e) => {
                    emit_log(&app_for_forward, &session_for_forward, &mirror_for_forward,
                             "warn", "watch-error", None, Some(format!("{}", e)));
                }
            }
        }
    });

    // Tear the watcher and its forwarder down deterministically: dropping
    // the receiver ends a `blocking_send` the forwarder may be stuck in (a
    // full queue), dropping the debouncer closes `raw_tx`, which ends its
    // `recv`; then the blocking task is awaited.
    async fn shutdown(
        tok_rx: tokio::sync::mpsc::Receiver<Vec<PathBuf>>,
        debouncer: notify_debouncer_mini::Debouncer<notify::RecommendedWatcher>,
        forward_join: tokio::task::JoinHandle<()>,
    ) {
        drop(tok_rx);
        drop(debouncer);
        let _ = forward_join.await;
    }

    let ctx = Ctx {
        events: &app,
        session_id: &session_id,
        mirror_id: &mirror_id,
        local_root: &local_root,
        spec: &spec,
        sftp: &sftp,
        status: &status,
        stop: &stop,
    };
    let mut guard = DeleteGuard::default();
    let mut deletions = PendingDeletions::default();
    let mut stop_wait = stop.clone();
    loop {
        enum Next {
            Paths(Vec<PathBuf>),
            Decide,
            Resume,
            Stop,
        }
        // Far away when nothing waits: the branch is then disabled anyway.
        let decide_at = deletions.decide_at().unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(3600));
        let next = tokio::select! {
            _ = stopped(&mut stop_wait) => Next::Stop,
            maybe = tok_rx.recv() => match maybe {
                Some(p) => Next::Paths(p),
                // Forwarder side hung up (debouncer dropped on its own?).
                // Treat the same as stop and tear down.
                None => Next::Stop,
            },
            _ = tokio::time::sleep_until(decide_at), if deletions.waiting() => Next::Decide,
            Some(()) = resume_rx.recv() => Next::Resume,
        };
        let go_on = match next {
            Next::Stop => false,
            Next::Paths(paths) => apply_batch(&ctx, &mut deletions, paths).await,
            Next::Decide => decide_deletions(&ctx, &mut guard, deletions.take()).await,
            Next::Resume => apply_held(&ctx, &mut guard).await,
        };
        if !go_on {
            break;
        }
    }
    let not_applied = guard.held.len() + deletions.changes.len();
    if not_applied > 0 {
        ctx.log("info", "held-discarded", None,
                Some(format!("{} local deletion(s) were not applied on the server", not_applied)));
    }
    shutdown(tok_rx, debouncer, forward_join).await;
    Ok(())
}

/// What the watcher's steps share.
struct Ctx<'a> {
    events: &'a MirrorEvents,
    session_id: &'a str,
    mirror_id: &'a str,
    local_root: &'a Path,
    spec: &'a MirrorSpec,
    sftp: &'a Arc<SftpSession>,
    status: &'a Arc<Mutex<MirrorStatus>>,
    stop: &'a watch::Receiver<bool>,
}

impl Ctx<'_> {
    fn log(&self, level: &str, event: &str, path: Option<String>, message: Option<String>) {
        emit_log(self.events, self.session_id, self.mirror_id, level, event, path, message);
    }

    async fn update(&self, change: impl FnOnce(&mut MirrorStatus)) {
        let snapshot = {
            let mut s = self.status.lock().await;
            change(&mut s);
            s.clone()
        };
        emit_update(self.events, &snapshot).await;
    }
}

/// More local deletions than this within `MASS_DELETE_WINDOW` pause the
/// propagation of deletions (owner decision, F-008).
const MASS_DELETE_LIMIT: usize = 50;
const MASS_DELETE_WINDOW: Duration = Duration::from_secs(60);
/// Deletions are judged as a burst: they wait until none has arrived for
/// `DELETE_SETTLE` (at most `DELETE_SETTLE_MAX` after the first), so a large
/// `rm` that the watcher reports in several batches is held as a whole
/// instead of having its first 50 applied.
const DELETE_SETTLE: Duration = Duration::from_secs(2);
const DELETE_SETTLE_MAX: Duration = Duration::from_secs(10);

/// Local deletions seen by the watcher, waiting to be judged, by relative
/// path (a `cargo clean` can report tens of thousands).
#[derive(Default)]
struct PendingDeletions {
    changes: HashMap<String, LocalChange>,
    first: Option<tokio::time::Instant>,
    last: Option<tokio::time::Instant>,
}

impl PendingDeletions {
    fn add(&mut self, gone: Vec<LocalChange>, now: tokio::time::Instant) {
        if gone.is_empty() {
            return;
        }
        self.first.get_or_insert(now);
        self.last = Some(now);
        for change in gone {
            self.changes.insert(change.rel.clone(), change);
        }
    }

    fn waiting(&self) -> bool {
        !self.changes.is_empty()
    }

    fn decide_at(&self) -> Option<tokio::time::Instant> {
        Some((self.last? + DELETE_SETTLE).min(self.first? + DELETE_SETTLE_MAX))
    }

    fn take(&mut self) -> Vec<LocalChange> {
        self.first = None;
        self.last = None;
        self.changes.drain().map(|(_, c)| c).collect()
    }
}

/// The mass-delete circuit breaker (F-008). Deletions are let through while
/// they stay under the limit and the local folder looks like itself; past
/// that, they are held (uploads go on) until Resume applies them or Stop
/// drops them.
#[derive(Default)]
struct DeleteGuard {
    /// When the deletions let through recently happened.
    recent: std::collections::VecDeque<std::time::Instant>,
    /// Held deletions, as mirror-relative paths.
    held: std::collections::BTreeSet<String>,
    /// Why deletions are held; `None` while they are let through.
    reason: Option<String>,
}

/// What the local folder looks like when deletions arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootState {
    Present,
    /// Nothing in it but excluded names.
    Empty,
    /// Gone or not readable (an unmounted drive, a renamed folder).
    Missing,
}

impl DeleteGuard {
    /// Whether `count` deletions arriving `now` may be applied. If not, the
    /// guard is paused (with the reason) and they must be held.
    fn admit(&mut self, now: std::time::Instant, count: usize, root: RootState) -> bool {
        if self.reason.is_some() {
            return false;
        }
        while self.recent.front().is_some_and(|t| now.duration_since(*t) > MASS_DELETE_WINDOW) {
            self.recent.pop_front();
        }
        let why = match root {
            RootState::Missing => Some("the local folder is gone or cannot be read (unmounted, renamed or deleted?)".to_string()),
            RootState::Empty => Some("the local folder is now empty".to_string()),
            RootState::Present if self.recent.len() + count > MASS_DELETE_LIMIT => {
                Some(format!("more than {} files were deleted locally within a minute", MASS_DELETE_LIMIT))
            }
            RootState::Present => None,
        };
        if let Some(why) = why {
            self.reason = Some(why);
            return false;
        }
        self.recent.extend(std::iter::repeat_n(now, count));
        true
    }

    /// Let deletions through again: the held ones, to apply now.
    fn resume(&mut self) -> Vec<String> {
        self.reason = None;
        self.recent.clear();
        std::mem::take(&mut self.held).into_iter().collect()
    }
}

async fn root_state(root: &Path, excludes: &[String]) -> RootState {
    match tokio::fs::metadata(root).await {
        Ok(meta) if meta.is_dir() => {}
        _ => return RootState::Missing,
    }
    let Ok(mut entries) = tokio::fs::read_dir(root).await else { return RootState::Missing };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if !is_excluded(&entry.file_name().to_string_lossy(), excludes) {
            return RootState::Present;
        }
    }
    RootState::Empty
}

/// What a watcher event found at its path.
enum LocalState {
    Folder,
    File(u64),
    Gone,
    /// A link or a special file: skipped, as by the scan.
    Other,
    Unreadable(String),
}

/// One watcher event, looked at.
struct LocalChange {
    path: PathBuf,
    rel: String,
    remote: String,
    state: LocalState,
}

/// Look at a debounced event's path. `None`: it is not mirrored (excluded,
/// outside the root, or reached through a link: N-018).
async fn look_at(local_root: &Path, spec: &MirrorSpec, path: &Path) -> Option<LocalChange> {
    // Excludes — apply BEFORE we look at metadata so we don't even stat
    // huge dirs like node_modules.
    let rel = path.strip_prefix(local_root).map(|p| p.to_string_lossy().replace('\\', "/")).ok()?;
    if rel.is_empty() || is_excluded(&rel, &spec.excludes) { return None; }
    let remote = local_to_remote(path, local_root, &spec.remote)?;
    if !reached_without_link(local_root, path).await { return None; }
    // Not following a link at the path itself either: the scan skips links,
    // and a link's target may be anywhere (N-018).
    let state = match tokio::fs::symlink_metadata(path).await {
        Ok(meta) if meta.is_dir() => LocalState::Folder,
        Ok(meta) if meta.is_file() => LocalState::File(meta.len()),
        Ok(_) => LocalState::Other,
        // ONLY NotFound counts as "deleted"; every other io::ErrorKind is a
        // transient / environmental failure (Windows Defender share-lock
        // during atomic-save, OneDrive/Dropbox placeholder briefly
        // unhydrated, network-drive blip, EACCES from a rootful docker
        // remapping ownership) and would trigger a real remote delete
        // if we lumped them together — an unrecoverable hard-rm when
        // spec.soft_delete=false.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => LocalState::Gone,
        Err(e) => LocalState::Unreadable(e.to_string()),
    };
    Some(LocalChange { path: path.to_path_buf(), rel, remote, state })
}

/// Apply one debounced batch. Because the debouncer collapses bursts, only
/// the *current* state of each path matters: still present → upload
/// (overwrites) at once; gone → wait with the other deletions to be judged
/// by the mass-delete guard (`decide_deletions`). `false`: stopped.
async fn apply_batch(ctx: &Ctx<'_>, deletions: &mut PendingDeletions, mut paths: Vec<PathBuf>) -> bool {
    order_batch(&mut paths, ctx.spec.soft_delete);
    let mut changes = Vec::with_capacity(paths.len());
    for path in &paths {
        if let Some(change) = look_at(ctx.local_root, ctx.spec, path).await {
            changes.push(change);
        }
    }
    let (gone, rest): (Vec<_>, Vec<_>) = changes.into_iter().partition(|c| matches!(c.state, LocalState::Gone));
    deletions.add(gone, tokio::time::Instant::now());
    apply_all(ctx, &rest, now_ms()).await
}

/// Whether a local path is still gone, looked at again before its deletion
/// goes to the server; `Err` when the answer is not known. Only "not found"
/// says gone, as in `look_at`: a permission or a busy mount is not a
/// deletion (R-006).
async fn still_missing(path: &Path) -> Result<bool, String> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

/// Judge a burst of deletions: apply them, or hold them all and pause.
/// `false`: stopped.
async fn decide_deletions(ctx: &Ctx<'_>, guard: &mut DeleteGuard, gone: Vec<LocalChange>) -> bool {
    // Only what is still gone counts: a build that deletes and recreates its
    // files within the settle time deleted nothing.
    let mut still_gone = Vec::with_capacity(gone.len());
    for change in gone {
        match still_missing(&change.path).await {
            Ok(true) => still_gone.push(change),
            Ok(false) => {}
            Err(e) => ctx.log("warn", "stat-fail", Some(change.rel.clone()), Some(e)),
        }
    }
    let mut gone = still_gone;
    if gone.is_empty() {
        return true;
    }
    let root = root_state(ctx.local_root, &ctx.spec.excludes).await;
    if !guard.admit(std::time::Instant::now(), gone.len(), root) {
        guard.held.extend(gone.drain(..).map(|c| c.rel));
        let (held, reason) = (guard.held.len(), guard.reason.clone().unwrap_or_default());
        ctx.update(|s| {
            s.state = "paused".into();
            s.held_deletes = held as u32;
            s.pause_reason = Some(reason.clone());
        })
        .await;
        ctx.log("warn", "delete-paused", None, Some(format!(
            "{held} local deletion(s) held because {reason}. Resume applies them on the server; Stop leaves the server as it is.")));
        return true;
    }
    gone.sort_by(|a, b| depth_order(&a.path, &b.path, ctx.spec.soft_delete));
    // One trash folder per burst: a folder removed in one go lands in one
    // place (F-047).
    apply_all(ctx, &gone, now_ms()).await
}

/// Apply changes in order, each racing the stop: an upload on a dead link
/// must not hold a Stop, a disconnect or the health watcher (F-009).
/// `false`: stopped.
async fn apply_all(ctx: &Ctx<'_>, changes: &[LocalChange], stamp: u128) -> bool {
    if changes.is_empty() {
        return true;
    }
    ctx.update(|s| s.queue_depth = s.queue_depth.saturating_add(changes.len() as u32)).await;
    // Files with an event of their own here are uploaded by it, not again by
    // the walk of a folder event in the same batch (N-023).
    let own_events: HashSet<&Path> = changes.iter().map(|c| c.path.as_path()).collect();
    for change in changes {
        if unless_stopped(apply_change(ctx, change, stamp, &own_events), ctx.stop).await.is_none() {
            return false;
        }
        ctx.update(|s| s.queue_depth = s.queue_depth.saturating_sub(1)).await;
    }
    true
}

/// Resume after a mass-delete pause: apply the held deletions of paths
/// that are still gone. Refused while the local folder itself is missing.
/// `false`: stopped.
async fn apply_held(ctx: &Ctx<'_>, guard: &mut DeleteGuard) -> bool {
    if guard.reason.is_none() {
        return true;
    }
    if root_state(ctx.local_root, &ctx.spec.excludes).await == RootState::Missing {
        ctx.log("warn", "resume-refused", None,
                Some("the local folder is still gone or unreadable; nothing was deleted on the server".into()));
        return true;
    }
    let held = guard.resume();
    ctx.update(|s| {
        s.state = "watching".into();
        s.held_deletes = 0;
        s.pause_reason = None;
    })
    .await;
    ctx.log("info", "resume", None, Some(format!("applying {} held deletion(s)", held.len())));
    let mut paths: Vec<PathBuf> =
        held.iter().map(|rel| ctx.local_root.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR))).collect();
    order_batch(&mut paths, ctx.spec.soft_delete);
    let mut gone = Vec::with_capacity(paths.len());
    for path in &paths {
        // A path that exists again is uploaded by its own event.
        if let Some(change) = look_at(ctx.local_root, ctx.spec, path).await.filter(|c| matches!(c.state, LocalState::Gone)) {
            gone.push(change);
        }
    }
    apply_all(ctx, &gone, now_ms()).await
}

/// What a folder new on the server holds goes up too (N-023): a folder
/// renamed or moved into the mirrored one arrives as one watcher event, none
/// for its files. Walked with the initial sync's rules (`walk_local`:
/// excludes, no links, the conflict setting, a server copy that cannot be
/// checked left alone; a server file that appeared meanwhile is never
/// replaced, one replaced goes to the trash with soft delete on); upload only,
/// nothing is downloaded or deleted, and as in the initial sync an empty
/// folder inside is not created. Each upload is a task of its own (never
/// dropped mid-replace), and a stop is checked between them.
async fn upload_folder_contents(ctx: &Ctx<'_>, change: &LocalChange, own_events: &HashSet<&Path>, stamp: u128) {
    let mut scan = Scan::default();
    let walked = walk_local(
        ctx.local_root, &change.path, &ctx.spec.remote, &ctx.spec.excludes, ctx.sftp, &ctx.spec.conflict_resolution, &mut scan,
    )
    .await;
    if let Err(e) = walked {
        ctx.log("warn", "scan-fail", Some(change.rel.clone()), Some(e));
        return;
    }
    for problem in scan.problems {
        ctx.log("warn", "skipped", Some(problem.path), Some(problem.reason));
    }
    for entry in scan.entries {
        if !entry.action.starts_with("upload") {
            continue;
        }
        let local = ctx.local_root.join(entry.path.replace('/', std::path::MAIN_SEPARATOR_STR));
        if own_events.contains(local.as_path()) {
            continue;
        }
        let Some(remote) = local_to_remote(&local, ctx.local_root, &ctx.spec.remote) else { continue };
        if *ctx.stop.borrow() {
            return;
        }
        let replace = entry.action == "upload-modified";
        let mut notes = Vec::new();
        let trash = (ctx.spec.soft_delete && replace).then(|| trash_path(&ctx.spec.remote, stamp, &entry.path));
        if let Some(at) = &trash {
            let parent = at.rsplit_once('/').map(|(p, _)| p).unwrap_or(at);
            if let Err(e) = sftp_mkdir_p(ctx.sftp, parent).await {
                notes.push(format!("the previous server version could not be kept: {e}"));
            }
        }
        let keep_at = trash.filter(|_| notes.is_empty());
        let keeping = keep_at.is_some();
        let upload = tokio::spawn({
            let (sftp, stop) = (Arc::clone(ctx.sftp), ctx.stop.clone());
            async move { upload_file(&sftp, &local, &remote, replace, keep_at.as_deref(), &stop).await }
        });
        match upload.await.unwrap_or_else(|e| Err(format!("upload task: {e}"))) {
            Ok(replaced) => {
                ctx.update(|s| {
                    s.uploaded = s.uploaded.saturating_add(1);
                    s.last_event_ms = now_ms();
                })
                .await;
                let mut message = format!("{} bytes", entry.size);
                notes.extend(upload_notes(&replaced, keeping));
                for note in notes {
                    message.push_str("; ");
                    message.push_str(&note);
                }
                ctx.log("info", "upload", Some(entry.path), Some(message));
            }
            Err(e) => ctx.log("error", "upload-fail", Some(entry.path), Some(e)),
        }
    }
}

/// Apply one change to the server.
async fn apply_change(ctx: &Ctx<'_>, change: &LocalChange, stamp: u128, own_events: &HashSet<&Path>) {
    let rel = change.rel.clone();
    match &change.state {
        LocalState::Folder => {
            // Walked only when the server does not have the folder yet (one
            // renamed or moved in). Any other folder event (a chmod; on
            // Windows, an entry inside it changing) leaves its files to their
            // own events (review of batch 11). A server answer that is not
            // "missing" counts as "there".
            let new_on_server = matches!(
                ctx.sftp.symlink_metadata(&change.remote).await,
                Err(ref e) if atomic_transfer::is_not_found(e)
            );
            if let Err(e) = sftp_mkdir_p(ctx.sftp, &change.remote).await {
                ctx.log("warn", "mkdir-fail", Some(rel), Some(e));
                return;
            }
            if new_on_server {
                upload_folder_contents(ctx, change, own_events, stamp).await;
            }
        }
        LocalState::File(len) => {
            // The debounced FS event tells us the user JUST touched this file.
            // Any prior mtime guard here silently dropped edits under two very
            // common conditions:
            //   1. Client clock behind the server: local mtime <= remote mtime
            //      for content the user actually just changed, so the upload
            //      was skipped with no log entry and no counter bump — the
            //      user sees state=watching and thinks it's synced.
            //   2. Editors that preserve mtime (cp -p, IDE refactor tools):
            //      body changes but mtime stays equal, tripping the `<=`
            //      branch again.
            // Trust the watcher's event and just upload. It replaces the
            // server copy of the user's own previous version, so no copy of
            // it is kept (owner decision). A task of its own: on a stop the
            // worker stops waiting for it instead of dropping it halfway.
            let upload = tokio::spawn({
                let (sftp, local, remote, stop) =
                    (Arc::clone(ctx.sftp), change.path.clone(), change.remote.clone(), ctx.stop.clone());
                async move { upload_file(&sftp, &local, &remote, true, None, &stop).await }
            });
            match upload.await.unwrap_or_else(|e| Err(format!("upload task: {e}"))) {
                Ok(replaced) => {
                    ctx.update(|s| {
                        s.uploaded = s.uploaded.saturating_add(1);
                        s.last_event_ms = now_ms();
                    })
                    .await;
                    let mut message = format!("{} bytes", len);
                    for note in upload_notes(&replaced, false) {
                        message.push_str("; ");
                        message.push_str(&note);
                    }
                    ctx.log("info", "upload", Some(rel), Some(message));
                }
                Err(e) => ctx.log("error", "upload-fail", Some(rel), Some(e)),
            }
        }
        LocalState::Other => {}
        LocalState::Gone => {
            // Looked at again: a file recreated since the batch was read is
            // uploaded by its own event, never deleted on the server, and a
            // path that cannot be looked at is left alone (R-006).
            match still_missing(&change.path).await {
                Ok(true) => {}
                Ok(false) => return,
                Err(e) => {
                    ctx.log("warn", "stat-fail", Some(rel), Some(e));
                    return;
                }
            }
            let res = if ctx.spec.soft_delete {
                sftp_soft_delete(ctx.sftp, &ctx.spec.remote, &rel, stamp).await
            } else {
                sftp_hard_delete(ctx.sftp, &change.remote).await
            };
            match res {
                // Already gone on the server (a folder moved or removed
                // earlier in this batch): nothing to do or report.
                Ok(false) => {}
                Ok(true) => {
                    ctx.update(|s| {
                        s.deleted = s.deleted.saturating_add(1);
                        s.last_event_ms = now_ms();
                    })
                    .await;
                    ctx.log("info", if ctx.spec.soft_delete { "soft-delete" } else { "delete" }, Some(rel), None);
                }
                Err(e) => ctx.log("warn", "delete-fail", Some(rel), Some(e)),
            }
        }
        LocalState::Unreadable(e) => {
            // Non-NotFound metadata error — log and skip. The next watcher
            // event (retry after the AV lock releases, placeholder hydrates,
            // network mount recovers) will re-attempt without turning a
            // transient failure into a destructive remote delete.
            ctx.log("warn", "stat-fail", Some(rel), Some(e.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn quiet() -> MirrorEvents {
        MirrorEvents::quiet()
    }

    fn status(id: &str, session: &str) -> MirrorStatus {
        MirrorStatus {
            id: id.into(),
            session_id: session.into(),
            local: "/l".into(),
            remote: "/r".into(),
            state: "watching".into(),
            queue_depth: 0,
            uploaded: 0,
            downloaded: 0,
            deleted: 0,
            scanned: 0,
            transfer_total: 0,
            transfer_done: 0,
            last_event_ms: 0,
            error: None,
            held_deletes: 0,
            pause_reason: None,
        }
    }

    /// F-047: editor and system temporaries, and Solanum's own part, aside and
    /// temp files, are never mirrored; ordinary names still are.
    #[test]
    fn default_excludes_cover_editor_and_solanum_temporaries() {
        for name in [
            "notes.md~", "sub/notes.md~", "~$report.docx", "sub/~$book.xlsx", ".#notes.md", "4913", "sub/4913",
            ".goutputstream-ABC123", "sub/.goutputstream-X", "data.bin.solanum-tmp", ".a.txt.1a2b3c4d.solanum-part",
            "sub/.a.txt.1a2b3c4d.solanum-old", ".solanum-trash", ".solanum-trash/1700000000000/a.txt", ".git",
            "sub/.git", "node_modules", "web/node_modules", ".DS_Store", "x.swp",
            // An excluded folder takes what it holds along.
            ".git/HEAD", "web/node_modules/x/index.js", "backup~/in-folder.txt", "sub\\.git\\config",
            // Whatever the case: a disk that ignores case makes `.GIT` `.git`.
            ".GIT/hooks/post-checkout", "Node_Modules/x.js", "X.SWP", "THUMBS.DB", ".ds_store", "A.SOLANUM-PART",
        ] {
            assert!(is_excluded(name, &[]), "{name} should be excluded");
        }
        for name in [
            "notes.md", "my~notes.txt", "x.gitignore", "sub/.gitkeep", "49130", ".solanum-trash-not",
            "sub/.solanum-trash/x", "proj.git/readme", "a.partial",
        ] {
            assert!(!is_excluded(name, &[]), "{name} should be mirrored");
        }
        let user = vec!["*.log".to_string(), "build/".to_string()];
        assert!(is_excluded("logs/app.log", &user) && is_excluded("build/out.bin", &user));
        assert!(!is_excluded("app.logs", &user) && !is_excluded("rebuild.sh", &user));
    }

    /// F-047: soft delete applies a batch parents first (one rename moves a
    /// folder with its children), hard delete children first (a folder is
    /// empty when it is removed).
    #[test]
    fn a_batch_is_applied_in_folder_order() {
        let batch = ["/m/gone/inner/c.txt", "/m/gone", "/m/a.txt", "/m/gone/inner", "/m/gone/b.txt"];
        let mut paths: Vec<PathBuf> = batch.iter().map(PathBuf::from).collect();
        order_batch(&mut paths, true);
        let soft: Vec<&str> = paths.iter().map(|p| p.to_str().unwrap()).collect();
        assert_eq!(soft, ["/m/a.txt", "/m/gone", "/m/gone/b.txt", "/m/gone/inner", "/m/gone/inner/c.txt"]);
        order_batch(&mut paths, false);
        let hard: Vec<&str> = paths.iter().map(|p| p.to_str().unwrap()).collect();
        assert_eq!(hard, ["/m/gone/inner/c.txt", "/m/gone/b.txt", "/m/gone/inner", "/m/a.txt", "/m/gone"]);
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("solanum-mirror-{tag}-{}-{}", std::process::id(), now_ms()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// R-006: before a held or batched deletion goes to the server the local
    /// path is looked at again, and only "not found" lets it go ahead. A path
    /// that cannot be looked at (here: a folder without permissions) says
    /// nothing about whether the file is still there.
    #[cfg(unix)]
    #[tokio::test]
    async fn only_a_path_that_is_not_found_counts_as_deleted() {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch("recheck");
        let shut = root.join("shut");
        std::fs::create_dir(&shut).unwrap();
        std::fs::write(shut.join("kept.txt"), b"x").unwrap();
        assert_eq!(still_missing(&root.join("gone.txt")).await, Ok(true));
        assert_eq!(still_missing(&shut.join("kept.txt")).await, Ok(false));
        // Not "not found" for root either: a path below a file.
        assert!(still_missing(&shut.join("kept.txt").join("below")).await.is_err(), "ENOTDIR counted as deleted");
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000)).unwrap();
        // Root reads through any mode: nothing to test then.
        if std::fs::read_dir(&shut).is_err() {
            assert!(still_missing(&shut.join("kept.txt")).await.is_err(), "a file that cannot be looked at counted as deleted");
        }
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// F-008: a download lands in the mirrored folder, creating the folders it
    /// needs, and never through a link inside it.
    #[tokio::test]
    async fn downloads_land_inside_the_mirrored_folder_only() {
        let root = scratch("target");
        let made = local_target_for_write(&root, "new/deeper/file.txt").await.unwrap();
        assert!(made.ends_with("new/deeper/file.txt") || made.ends_with("new\\deeper\\file.txt"), "{made:?}");
        assert!(root.join("new/deeper").is_dir(), "the folders on the way are created");
        assert!(!made.exists(), "the file itself is left to the download");
        for bad in ["../escape.txt", "a/../../escape.txt", "./x", "a//b", ""] {
            assert!(local_target_for_write(&root, bad).await.is_err(), "{bad:?}");
        }
        std::fs::write(root.join("plain"), b"x").unwrap();
        assert!(local_target_for_write(&root, "plain/inside.txt").await.is_err(), "a file is not a folder");
        // The write policy is checked before any folder is created (Windows
        // auto-run folders are refused on every OS).
        assert!(local_target_for_write(&root, "AppData/Roaming/Microsoft/Windows/run.lnk").await.is_err());
        assert!(!root.join("AppData").exists(), "nothing was created for a refused file");
        #[cfg(unix)]
        {
            let outside = scratch("outside");
            std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
            assert!(local_target_for_write(&root, "link/planted.txt").await.is_err());
            assert!(local_target_for_write(&root, "link/sub/planted.txt").await.is_err());
            assert!(!outside.join("sub").exists(), "nothing is created through the link");
            let _ = std::fs::remove_dir_all(outside);
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// N-018: the watcher acts only on paths reached without a link.
    #[cfg(unix)]
    #[tokio::test]
    async fn watcher_events_through_a_link_are_ignored() {
        let root = scratch("reach");
        let outside = scratch("reach-outside");
        std::fs::create_dir_all(root.join("real/sub")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        assert!(reached_without_link(&root, &root.join("real/sub/file.txt")).await);
        assert!(reached_without_link(&root, &root.join("top.txt")).await);
        assert!(reached_without_link(&root, &root.join("gone/deleted.txt")).await, "a deletion under a vanished folder");
        assert!(!reached_without_link(&root, &root.join("link/secret.txt")).await);
        assert!(!reached_without_link(&root, &outside.join("secret.txt")).await, "not under the root at all");
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(outside);
    }

    /// F-008: the mass-delete guard lets ordinary deletions through, holds
    /// more than 50 within a minute, and always holds when the folder is gone
    /// or empty; Resume starts the count again.
    #[test]
    fn the_delete_guard_holds_mass_deletions() {
        let t0 = std::time::Instant::now();
        let mut guard = DeleteGuard::default();
        assert!(guard.admit(t0, 30, RootState::Present));
        assert!(guard.admit(t0 + Duration::from_secs(10), 20, RootState::Present), "50 within a minute pass");
        assert!(!guard.admit(t0 + Duration::from_secs(20), 1, RootState::Present), "the 51st is held");
        assert!(guard.reason.as_deref().unwrap().contains("more than 50"));
        assert!(!guard.admit(t0 + Duration::from_secs(300), 1, RootState::Present), "held until Resume");
        guard.held.extend(["b".to_string(), "a".to_string()]);
        assert_eq!(guard.resume(), ["a", "b"]);
        assert!(guard.admit(t0 + Duration::from_secs(301), 50, RootState::Present), "a fresh window after Resume");

        let mut slow = DeleteGuard::default();
        for minute in 0..5u64 {
            assert!(slow.admit(t0 + Duration::from_secs(61 * minute), 40, RootState::Present), "40 a minute pass");
        }
        assert!(!DeleteGuard::default().admit(t0, 51, RootState::Present), "one batch over the limit");
        let mut gone = DeleteGuard::default();
        assert!(!gone.admit(t0, 1, RootState::Missing));
        assert!(gone.reason.as_deref().unwrap().contains("gone"));
        assert!(!DeleteGuard::default().admit(t0, 1, RootState::Empty));
    }

    fn gone(rel: &str) -> LocalChange {
        LocalChange { path: PathBuf::from("/m").join(rel), rel: rel.into(), remote: format!("/r/{rel}"), state: LocalState::Gone }
    }

    /// F-008: deletions are judged as one burst: 2 s after the last one, but
    /// never more than 10 s after the first; a path reported twice counts once.
    #[test]
    fn deletions_wait_for_the_burst_to_end() {
        let t0 = tokio::time::Instant::now();
        let mut pending = PendingDeletions::default();
        assert!(!pending.waiting() && pending.decide_at().is_none());
        pending.add(vec![gone("a"), gone("b")], t0);
        assert_eq!(pending.decide_at(), Some(t0 + DELETE_SETTLE));
        pending.add(vec![gone("b"), gone("c")], t0 + Duration::from_secs(1));
        assert_eq!(pending.decide_at(), Some(t0 + Duration::from_secs(1) + DELETE_SETTLE), "a new deletion moves the decision");
        for i in 2..12 {
            pending.add(vec![gone(&format!("n{i}"))], t0 + Duration::from_secs(i));
        }
        assert_eq!(pending.decide_at(), Some(t0 + DELETE_SETTLE_MAX), "a steady stream is judged after 10 s");
        let mut taken: Vec<String> = pending.take().into_iter().map(|c| c.rel).collect();
        taken.sort();
        assert_eq!(taken.len(), 13, "{taken:?}");
        assert!(!pending.waiting() && pending.decide_at().is_none());
    }

    /// F-008: what the local folder looks like when deletions arrive.
    #[tokio::test]
    async fn the_root_state_tells_gone_empty_and_present_apart() {
        let root = scratch("rootstate");
        std::fs::create_dir_all(root.join(".git/objects")).unwrap();
        std::fs::write(root.join("notes.md~"), b"x").unwrap();
        assert_eq!(root_state(&root, &[]).await, RootState::Empty, "only excluded names left (rm * in a git checkout)");
        std::fs::write(root.join("kept.txt"), b"x").unwrap();
        assert_eq!(root_state(&root, &[]).await, RootState::Present);
        assert_eq!(root_state(&root, &["kept".to_string()]).await, RootState::Empty, "user excludes count too");
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(root_state(&root, &[]).await, RootState::Missing);
    }

    /// F-009: Stop returns even when the worker does not end: it is aborted
    /// after the bound and its entry goes.
    #[tokio::test(flavor = "multi_thread")]
    async fn stop_returns_for_a_worker_that_ignores_it() {
        let map: MirrorMap = Arc::default();
        let aborted = Arc::new(AtomicBool::new(false));
        struct SetOnDrop(Arc<AtomicBool>);
        impl Drop for SetOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let guard = SetOnDrop(Arc::clone(&aborted));
        let (stop_tx, _ignored) = watch::channel(false);
        let join = tauri::async_runtime::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        let reported: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
        let seen = Arc::clone(&reported);
        let events = MirrorEvents {
            update: Arc::new(move |s: &MirrorStatus| seen.lock().unwrap().push(s.state.clone())),
            log: Arc::new(|_: &str, _: &MirrorLogEntry<'_>| {}),
        };
        map.lock().await.insert(
            "stuck".into(),
            ActiveMirror {
                status: Arc::new(Mutex::new(status("stuck", "s1"))),
                stop: stop_tx,
                join: Mutex::new(Some(join)),
                events,
                resume: tokio::sync::mpsc::unbounded_channel().0,
            },
        );
        let started = std::time::Instant::now();
        let stopped = tokio::time::timeout(Duration::from_secs(20), stop(&map, "stuck")).await;
        assert!(stopped.is_ok(), "stop() returns although the worker never ends");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(map.lock().await.is_empty(), "the aborted mirror is no longer listed");
        assert!(crate::ssh_test_server::eventually(|| aborted.load(Ordering::SeqCst)).await, "the worker is aborted");
        assert_eq!(*reported.lock().unwrap(), ["stopped"], "the window is told it stopped");
    }

    /// F-009: a disconnect does not wait without end for its mirrors.
    #[tokio::test(flavor = "multi_thread")]
    async fn stopping_a_session_s_mirrors_is_bounded() {
        let map: MirrorMap = Arc::default();
        for id in ["a", "b"] {
            let (stop_tx, _ignored) = watch::channel(false);
            let join = tauri::async_runtime::spawn(std::future::pending::<()>());
            map.lock().await.insert(
                id.into(),
                ActiveMirror {
                    status: Arc::new(Mutex::new(status(id, "s1"))),
                    stop: stop_tx,
                    join: Mutex::new(Some(join)),
                    events: quiet(),
                    resume: tokio::sync::mpsc::unbounded_channel().0,
                },
            );
        }
        let started = std::time::Instant::now();
        let stopped = tokio::time::timeout(Duration::from_secs(30), stop_all_for_session(&map, "s1")).await;
        assert!(stopped.is_ok(), "the stop returns");
        assert!(started.elapsed() < Duration::from_secs(10), "both mirrors are stopped under one bound");
        assert!(map.lock().await.is_empty());
    }

    /// F-008: the remote root must be a plain absolute folder below `/`, and the
    /// local root a folder files may be written into.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_mirror_needs_sane_roots() {
        let (handle, _) = crate::ssh_test_server::logged_in(crate::ssh_test_server::Script::default()).await;
        let local = std::env::temp_dir().join(format!("solanum-mirror-roots-{}", std::process::id()));
        std::fs::create_dir_all(&local).unwrap();
        let spec = |local: &str, remote: &str| MirrorSpec {
            local: local.into(),
            remote: remote.into(),
            soft_delete: true,
            excludes: Vec::new(),
            conflict_resolution: "local".into(),
        };
        let ok_local = local.to_string_lossy().into_owned();
        let mut refused_locals: Vec<String> = Vec::new();
        #[cfg(unix)]
        refused_locals.extend(["/".to_string(), "/etc".to_string()]);
        #[cfg(windows)]
        refused_locals.extend(["C:\\".to_string(), "C:\\Windows".to_string()]);
        if let Some(home) = directories::UserDirs::new().map(|d| d.home_dir().to_string_lossy().into_owned()) {
            refused_locals.push(home);
        }
        let mut cases: Vec<(String, String)> =
            ["", "/", "//", "relative/dir", "/srv/../etc", "/srv/./x", "/srv//x"].iter().map(|r| (ok_local.clone(), r.to_string())).collect();
        cases.extend(refused_locals.into_iter().map(|l| (l, "/srv/mirror".to_string())));
        // A plain folder and a plain server path are accepted (the worker
        // then fails on this server, which has no SFTP).
        let map: MirrorMap = Arc::default();
        let id = start(quiet(), "s1".into(), Arc::clone(&handle), Arc::clone(&map), spec(&ok_local, "/srv/mirror/"))
            .await
            .expect("sane roots are accepted");
        let _ = stop(&map, &id).await;
        for (l, r) in cases {
            let map: MirrorMap = Arc::default();
            let started = start(quiet(), "s1".into(), Arc::clone(&handle), Arc::clone(&map), spec(&l, &r)).await;
            if let Ok(id) = &started {
                let _ = stop(&map, id).await;
            }
            assert!(started.is_err(), "local {l:?} -> remote {r:?} must be refused");
            assert!(map.lock().await.is_empty());
        }
        let _ = std::fs::remove_dir_all(&local);
    }
}
