//! Live edit: a remote file opened in a local app and uploaded back on every
//! save (F-001, F-015, F-016, F-024, F-034).
//!
//! - Every open gets its own private staging folder
//!   `<root>/sftp_<hex session id>/<hex>/<file name>`, so two remote files with
//!   the same name never share a copy. A registry keyed by (session, remote
//!   path) makes opening the same file again deliberate: a copy in sync with
//!   the server is refreshed, a copy with changes not uploaded yet is kept.
//! - One watcher serves every live edit: each staging folder is watched (not
//!   the file, whose inode an editor's rename-based save replaces) and an
//!   event in it wakes that copy's task. After each debounce the copy's SHA-256 is
//!   compared with what the server was last given, so only real changes are
//!   uploaded, through `atomic_transfer::replace_remote_file`.
//! - Syncing has no deadline. It ends when the session is disconnected or the
//!   profile is locked, and each end is reported. A copy holding changes that
//!   were not uploaded is never deleted; the report says where it is.
//! - Remote files are streamed to disk with a hard size cap
//!   (`LIVE_EDIT_MAX_BYTES`), never read whole into memory.
//! - Each copy remembers the server it came from (user, address and host
//!   key). If the session later reaches another server (its address was
//!   edited and the tab reconnected), saves are not uploaded and the copy is
//!   kept (N-012).
//! - Each process's staging root has a lock file beside it, held for the
//!   process's life, and each copy a `.synced` marker holding the hash of what
//!   the server has. At start-up, roots left by processes that are gone (quit,
//!   crashed, killed) are swept: copies matching their marker are deleted, the
//!   others are kept and listed for the window (F-061). Quitting removes this
//!   process's root once only kept copies, if any, are left.
//!
//! The registry reaches the server only through [`LiveEditLink`], so it is
//! tested without an `AppHandle` (in-memory server) and against the sshd
//! fixtures. Android has no live edit (the command refuses first), so nothing
//! here touches the file system there.

use crate::atomic_transfer;
use notify_debouncer_mini::notify::{RecommendedWatcher, RecursiveMode};
use notify_debouncer_mini::{new_debouncer, DebounceEventResult, Debouncer};
use russh_sftp::client::SftpSession;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

/// Largest remote file live edit opens (F-024). Bigger files are downloaded.
pub(crate) const LIVE_EDIT_MAX_BYTES: u64 = 50 * 1024 * 1024;

/// Coalesces an editor's burst of writes and renames into one upload.
const DEBOUNCE: Duration = Duration::from_millis(750);

pub(crate) type Hash = [u8; 32];
pub(crate) type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What an upload did: the hash of the bytes sent, and anything the user
/// should hear about (a previous version left on the server).
pub(crate) struct Stored {
    pub(crate) hash: Hash,
    pub(crate) note: Option<String>,
}

/// What a download into the staging folder brought back.
pub(crate) struct Fetched {
    pub(crate) hash: Hash,
    /// The first bytes, for `open_guard::content_problem`.
    pub(crate) head: Vec<u8>,
}

/// Which server a session is connected to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerIdentity {
    /// `user@host:port`, as shown to the user.
    pub(crate) address: String,
    /// The host key's fingerprint the connection trusted.
    pub(crate) host_key: String,
}

/// How the registry talks to the server and to the user.
pub(crate) trait LiveEditLink: Send + Sync + 'static {
    /// The server the session is connected to now (`None`: not connected).
    fn target(&self) -> Option<ServerIdentity>;
    /// Download `remote` into the new file `dest`, refusing more than `cap` bytes.
    fn fetch<'a>(&'a self, remote: &'a str, dest: &'a Path, cap: u64) -> BoxFut<'a, Result<Fetched, String>>;
    /// Upload `local` over `remote`.
    fn store<'a>(&'a self, local: &'a Path, remote: &'a str) -> BoxFut<'a, Result<Stored, String>>;
    fn report(&self, status: SyncStatus);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StatusKind {
    /// A save reached the server.
    Synced,
    /// A save did not reach the server; the next save tries again.
    Failed,
    /// Information about an open.
    Note,
    /// Syncing ended; the copy was in sync and is deleted.
    Stopped,
    /// Syncing ended with changes that were not uploaded; the copy is kept.
    StoppedKept,
}

#[derive(Clone, Debug)]
pub(crate) struct SyncStatus {
    pub(crate) kind: StatusKind,
    pub(crate) remote_path: String,
    pub(crate) message: String,
    /// `StoppedKept`: the local copy holding the changes.
    pub(crate) kept: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopReason {
    Disconnected,
    ProfileClosed,
    AppClosed,
    /// The user stopped this one file's live edit.
    Stopped,
    /// Its editor could not be started, so the user never had the copy open.
    NotOpened,
}

impl StopReason {
    fn describe(self) -> &'static str {
        match self {
            StopReason::Disconnected => "the session was closed",
            StopReason::ProfileClosed => "the profile was locked",
            StopReason::AppClosed => "Solanum was closed",
            StopReason::Stopped => "you stopped it",
            StopReason::NotOpened => "its editor could not be started",
        }
    }
}

/// A live edit, as the window lists it.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LiveEditInfo {
    pub(crate) remote_path: String,
    pub(crate) name: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OpenedHow {
    New,
    /// The copy was in sync and was downloaded again.
    Refreshed,
    /// The copy has changes that were not uploaded; it was left as it is.
    KeptLocalChanges,
}

pub(crate) struct Opened {
    pub(crate) path: PathBuf,
    /// Whether this open started the live edit (`open_and_launch` reads it);
    /// the app tells the user through the link's reports.
    pub(crate) how: OpenedHow,
}

/// Why live edit does not take a file of this size, if it does not.
pub(crate) fn size_refusal(size: u64) -> Option<String> {
    (size > LIVE_EDIT_MAX_BYTES).then(|| {
        format!(
            "The file is {:.1} MiB; live edit opens files up to {} MiB. Download it instead.",
            size as f64 / (1024.0 * 1024.0),
            LIVE_EDIT_MAX_BYTES / (1024 * 1024)
        )
    })
}

struct Entry {
    remote_path: String,
    name: String,
    /// The server the copy came from; uploads go only there (N-012).
    target: ServerIdentity,
    dir: PathBuf,
    file: PathBuf,
    /// The staging folder as created and in canonical form (macOS FSEvents
    /// reports `/private/var/...` for `/var/...`).
    watch_keys: Vec<PathBuf>,
    /// SHA-256 of what the server was last given or gave (`None`: unknown).
    synced: Mutex<Option<Hash>>,
    /// Serialises syncs, reopens and the final check.
    sync_lock: tokio::sync::Mutex<()>,
    stop: watch::Sender<Option<StopReason>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    link: Arc<dyn LiveEditLink>,
}

impl Entry {
    fn report(&self, kind: StatusKind, message: String) {
        let kept = (kind == StatusKind::StoppedKept).then(|| self.file.clone());
        self.link.report(SyncStatus { kind, remote_path: self.remote_path.clone(), message, kept });
    }

    /// Why the session's server is not the one this copy came from, if it
    /// is not (N-012).
    fn elsewhere(&self, now: &ServerIdentity) -> Option<String> {
        if *now == self.target {
            None
        } else if now.address == self.target.address {
            Some(format!("{} now presents another host key than when {} was opened", now.address, self.name))
        } else {
            Some(format!("{} was opened from {}, and the session now connects to {}", self.name, self.target.address, now.address))
        }
    }
}

/// The task to wake for events in one staging folder.
struct Route {
    wake: mpsc::Sender<()>,
}

struct StagingRoot {
    path: PathBuf,
    /// Owner at creation. If the folder is deleted (a temp cleaner) and
    /// another user takes the name, that folder is not used. (An inode number
    /// proves nothing: a new folder often gets the one just freed.)
    #[cfg(unix)]
    uid: u32,
    /// `<root>.lock`, locked for as long as this process uses the root: the
    /// start-up sweep of another instance leaves a locked root alone. `None`
    /// where the system has no file locks: there is no lock file then, and a
    /// root without one is never swept.
    _lock: Option<std::fs::File>,
    lock_path: PathBuf,
}

#[derive(Default)]
struct Registry {
    watcher: Option<Debouncer<RecommendedWatcher>>,
    routes: Arc<Mutex<HashMap<PathBuf, Route>>>,
    entries: HashMap<(String, String), Arc<Entry>>,
    opening: HashSet<(String, String)>,
    /// Files the user stopped whose last upload has not finished yet (true
    /// once it has): opening one again waits for it (review of batch 11).
    stopping: HashMap<(String, String), watch::Receiver<bool>>,
    /// Bumped when a session's live edits are stopped, so an open that was
    /// downloading meanwhile does not register into a closed session.
    generation: HashMap<String, u64>,
    root: Option<StagingRoot>,
}

pub(crate) struct LiveEdits {
    inner: Mutex<Registry>,
    /// Where the staging root is created (the OS temp folder).
    base: PathBuf,
    debounce: Duration,
    /// Copies the start-up sweep kept; `None` until it has run.
    leftovers: watch::Sender<Option<Vec<PathBuf>>>,
}

/// How long the window's question for the sweep's results may wait for it.
const LEFTOVERS_WAIT: Duration = Duration::from_secs(10);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// A folder only this user can enter (0700 on Unix), created exclusively.
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
    builder.create(path)
}

/// SHA-256 of the file, `None` if it does not exist (an editor's
/// delete-then-create save in progress). Runs on the blocking pool.
async fn hash_file(path: PathBuf) -> std::io::Result<Option<Hash>> {
    tokio::task::spawn_blocking(move || hash_file_now(&path)).await.map_err(std::io::Error::other)?
}

fn hash_file_now(path: &Path) -> std::io::Result<Option<Hash>> {
    use std::io::Read;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; atomic_transfer::CHUNK];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(Some(hasher.finalize().into()));
        }
        hasher.update(&buf[..n]);
    }
}

/// `<session folder>/<copy folder>.synced`: the SHA-256 of what the server
/// was last given or gave for the copy in `<copy folder>`. Only the start-up
/// sweep reads it: a copy that matches it is deleted, and so is a copy with
/// no marker at all, because the first one is written before the copy is
/// handed to an editor (or the open fails). A stale or torn marker (a failed
/// later write, a crash) makes it keep more.
fn marker_path(dir: &Path) -> PathBuf {
    let mut name = dir.file_name().unwrap_or_default().to_os_string();
    name.push(".synced");
    dir.with_file_name(name)
}

fn write_marker(dir: &Path, hash: &Hash) -> std::io::Result<()> {
    std::fs::write(marker_path(dir), hex::encode(hash))
}

fn read_marker(dir: &Path) -> Option<Hash> {
    let text = std::fs::read_to_string(marker_path(dir)).ok()?;
    hex::decode(text.trim()).ok()?.try_into().ok()
}

/// `<root>.lock`, beside the root.
fn lock_path_of(root: &Path) -> PathBuf {
    let mut name = root.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    root.with_file_name(name)
}

/// A new root's lock file, created exclusively (owner-only on Unix) and
/// locked. Where the system has no file locks it is removed again (`None`):
/// a root without a lock file is never swept, whatever another instance's
/// locking would say.
fn create_root_lock(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::Error(_)) => {
            drop(file);
            let _ = std::fs::remove_file(path);
            Ok(None)
        }
        Err(std::fs::TryLockError::WouldBlock) => Err(std::io::ErrorKind::AlreadyExists.into()),
    }
}

impl LiveEdits {
    pub(crate) fn new() -> Self {
        Self::new_in(std::env::temp_dir(), DEBOUNCE)
    }

    pub(crate) fn new_in(base: PathBuf, debounce: Duration) -> Self {
        Self { inner: Mutex::new(Registry::default()), base, debounce, leftovers: watch::channel(None).0 }
    }

    /// Sweep the staging roots of processes that are gone (F-061) and keep
    /// what it could not delete for `take_leftovers`. Blocking: run it on its
    /// own thread at start-up.
    pub(crate) fn sweep_at_start(&self) {
        let kept = sweep_stale_roots(&self.base);
        for path in &kept {
            eprintln!("[live-edit] kept from an earlier session (changes may not have been uploaded): {}", path.display());
        }
        self.leftovers.send_replace(Some(kept));
    }

    /// The copies the start-up sweep kept, once (later calls get nothing).
    /// Waits a moment for the sweep if it has not finished yet.
    pub(crate) async fn take_leftovers(&self) -> Vec<PathBuf> {
        let mut done = self.leftovers.subscribe();
        let _ = tokio::time::timeout(LEFTOVERS_WAIT, done.wait_for(Option::is_some)).await;
        let mut out = Vec::new();
        self.leftovers.send_modify(|v| {
            if let Some(list) = v {
                out = std::mem::take(list);
            }
        });
        out
    }

    /// The app is quitting and the live edits have ended: remove this
    /// process's staging root if only empty folders are left (copies with
    /// changes that were not uploaded stay for the next start's sweep), and
    /// release its lock.
    pub(crate) fn release_root(&self) {
        let Some(root) = lock(&self.inner).root.take() else { return };
        if let Ok(sessions) = std::fs::read_dir(&root.path) {
            for session in sessions.flatten() {
                let _ = std::fs::remove_dir(session.path());
            }
        }
        if std::fs::remove_dir(&root.path).is_ok() {
            let _ = std::fs::remove_file(&root.lock_path);
        }
    }

    /// Open `remote_path` (file name `leaf`, already checked) for live edit
    /// and return the local copy to launch. `refuse_content` sees the first
    /// bytes and may refuse the file (nothing is kept then).
    pub(crate) async fn open(
        &self,
        link: Arc<dyn LiveEditLink>,
        session_id: &str,
        remote_path: &str,
        leaf: &str,
        refuse_content: &(dyn Fn(&[u8]) -> Option<String> + Send + Sync),
    ) -> Result<Opened, String> {
        let key = (session_id.to_string(), remote_path.to_string());
        // A Stop of this file still uploading its last change: wait for it,
        // or the new copy would miss that change and a save of it would then
        // overwrite it on the server (review of batch 11).
        let stopping = lock(&self.inner).stopping.get(&key).cloned();
        if let Some(mut done) = stopping {
            if !*done.borrow() {
                link.report(SyncStatus {
                    kind: StatusKind::Note,
                    remote_path: remote_path.to_string(),
                    message: format!("{leaf} is still being uploaded after Stop; it opens once that is done."),
                    kept: None,
                });
                let _ = done.wait_for(|d| *d).await;
            }
            let mut r = lock(&self.inner);
            if r.stopping.get(&key).is_some_and(|d| *d.borrow()) {
                r.stopping.remove(&key);
            }
        }
        // One look at the registry: an open entry is reopened, otherwise this
        // call claims the key until it has registered (or failed).
        let claimed = {
            let mut r = lock(&self.inner);
            match r.entries.get(&key).cloned() {
                Some(entry) => Err(entry),
                None if !r.opening.insert(key.clone()) => return Err("This file is already being opened.".into()),
                None => Ok(r.generation.get(session_id).copied().unwrap_or(0)),
            }
        };
        let generation = match claimed {
            Ok(generation) => generation,
            Err(entry) => return reopen(&entry, refuse_content).await,
        };
        let _claim = OpeningClaim { edits: self, key: key.clone() };

        let target = link.target().ok_or("Cannot tell which server this session is connected to; reconnect and open the file again.")?;
        let dir = self.new_entry_dir(session_id)?;
        let file = dir.join(leaf);
        let fetched = match link.fetch(remote_path, &file, LIVE_EDIT_MAX_BYTES).await {
            Ok(f) => f,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(e);
            }
        };
        if let Some(why) = refuse_content(&fetched.head) {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(why);
        }
        self.register(key, generation, dir, file.clone(), leaf, fetched.hash, target, link)?;
        Ok(Opened { path: file, how: OpenedHow::New })
    }

    #[allow(clippy::too_many_arguments)]
    fn register(
        &self,
        key: (String, String),
        generation: u64,
        dir: PathBuf,
        file: PathBuf,
        leaf: &str,
        hash: Hash,
        target: ServerIdentity,
        link: Arc<dyn LiveEditLink>,
    ) -> Result<(), String> {
        let (wake_tx, wake_rx) = mpsc::channel(1);
        let (stop_tx, stop_rx) = watch::channel(None);
        let mut watch_keys = vec![dir.clone()];
        if let Ok(canonical) = dir.canonicalize() {
            if canonical != dir {
                watch_keys.push(canonical);
            }
        }
        let entry = Arc::new(Entry {
            remote_path: key.1.clone(),
            name: leaf.to_string(),
            target,
            dir: dir.clone(),
            file,
            watch_keys,
            synced: Mutex::new(Some(hash)),
            sync_lock: tokio::sync::Mutex::new(()),
            stop: stop_tx,
            task: Mutex::new(None),
            link,
        });

        let mut r = lock(&self.inner);
        let fail = |why: String| {
            let _ = std::fs::remove_dir_all(&dir);
            let _ = std::fs::remove_file(marker_path(&dir));
            Err(why)
        };
        if r.generation.get(&key.0).copied().unwrap_or(0) != generation {
            return fail("The session was closed while the file was being opened.".into());
        }
        if r.entries.contains_key(&key) {
            // Cannot happen while `opening` holds the key; never replace an
            // entry (its task would keep running unseen).
            return fail("This file is already open.".into());
        }
        // Before the copy can reach an editor: the sweep treats a copy
        // without a marker as one nobody ever edited.
        if let Err(e) = write_marker(&dir, &hash) {
            return fail(format!("Failed to write to the temp dir: {e}"));
        }
        if let Err(e) = self.ensure_watcher(&mut r) {
            return fail(e);
        }
        {
            let mut routes = lock(&r.routes);
            for k in &entry.watch_keys {
                routes.insert(k.clone(), Route { wake: wake_tx.clone() });
            }
        }
        let watched = r.watcher.as_mut().map(|w| w.watcher().watch(&dir, RecursiveMode::NonRecursive));
        if let Some(Err(e)) = watched {
            let mut routes = lock(&r.routes);
            for k in &entry.watch_keys {
                routes.remove(k);
            }
            drop(routes);
            // The editor is not launched: a copy nothing would upload is worse than an error.
            return fail(format!("Cannot watch the file for saves: {e}"));
        }
        let task = tokio::spawn(run_entry(Arc::clone(&entry), wake_rx, stop_rx));
        *lock(&entry.task) = Some(task);
        r.entries.insert(key, entry);
        Ok(())
    }

    fn ensure_watcher(&self, r: &mut Registry) -> Result<(), String> {
        if r.watcher.is_some() {
            return Ok(());
        }
        let routes = Arc::clone(&r.routes);
        let debouncer = new_debouncer(self.debounce, move |result: DebounceEventResult| {
            let routes = lock(&routes);
            match result {
                // Matched by folder, not by name: a staging folder holds one
                // copy (plus the editor's swap and backup files), and names
                // can come back in another form (decomposed on macOS, 8.3 on
                // Windows). The hash check makes extra wake-ups cheap.
                Ok(events) => {
                    for event in events {
                        if let Some(route) = event.path.parent().and_then(|parent| routes.get(parent)) {
                            let _ = route.wake.try_send(());
                        }
                    }
                }
                // The watcher lost track (e.g. its queue overflowed): check every copy.
                Err(_) => {
                    for route in routes.values() {
                        let _ = route.wake.try_send(());
                    }
                }
            }
        })
        .map_err(|e| format!("Cannot watch files for saves: {e}"))?;
        r.watcher = Some(debouncer);
        Ok(())
    }

    /// `<root>/sftp_<hex session>/<hex>`, each level created by this process
    /// and private.
    fn new_entry_dir(&self, session_id: &str) -> Result<PathBuf, String> {
        let mut r = lock(&self.inner);
        let root = self.staging_root(&mut r)?;
        let session_dir = root.join(session_dir_name(session_id));
        match create_private_dir(&session_dir) {
            Ok(()) => {}
            // The root is private to this process's user, so an existing
            // session folder is one of ours.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("Failed to create temp dir: {e}")),
        }
        for _ in 0..8 {
            let dir = session_dir.join(random_hex(4));
            match create_private_dir(&dir) {
                Ok(()) => return Ok(dir),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("Failed to create temp dir: {e}")),
            }
        }
        Err("Failed to create temp dir: no free name".into())
    }

    /// The process's random, private staging root under `base`, created on
    /// first use only. Recreated under a new name if it is gone, or if the
    /// folder there now has another owner or is open to others (N-011).
    fn staging_root(&self, r: &mut Registry) -> Result<PathBuf, String> {
        if let Some(root) = &r.root {
            if still_ours(root) {
                return Ok(root.path.clone());
            }
        }
        // Replaced: its lock file is ours to remove, its folder is not.
        if let Some(old) = r.root.take() {
            let _ = std::fs::remove_file(&old.lock_path);
        }
        for _ in 0..8 {
            let path = self.base.join(format!("solanum-{}", random_hex(12)));
            // The lock first, so no sweep ever sees this root unlocked.
            let lock_path = lock_path_of(&path);
            let lock_file = match create_root_lock(&lock_path) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("Failed to create temp dir: {e}")),
            };
            match create_private_dir(&path) {
                Ok(()) => {
                    let meta = std::fs::symlink_metadata(&path).map_err(|e| format!("Failed to create temp dir: {e}"))?;
                    #[cfg(not(unix))]
                    let _ = meta;
                    r.root = Some(StagingRoot {
                        path: path.clone(),
                        #[cfg(unix)]
                        uid: std::os::unix::fs::MetadataExt::uid(&meta),
                        _lock: lock_file,
                        lock_path,
                    });
                    return Ok(path);
                }
                Err(e) => {
                    drop(lock_file);
                    let _ = std::fs::remove_file(&lock_path);
                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                        continue;
                    }
                    return Err(format!("Failed to create temp dir: {e}"));
                }
            }
        }
        Err("Failed to create temp dir: no free name".into())
    }

    /// Stop every live edit of `session_id` (it was disconnected). Returns the
    /// tasks doing the final check, for tests to wait on.
    pub(crate) fn stop_session(&self, session_id: &str, reason: StopReason) -> Vec<tokio::task::JoinHandle<()>> {
        let mut r = lock(&self.inner);
        *r.generation.entry(session_id.to_string()).or_insert(0) += 1;
        let keys: Vec<_> = r.entries.keys().filter(|(s, _)| s == session_id).cloned().collect();
        keys.into_iter().filter_map(|k| stop_entry(&mut r, &k, reason)).collect()
    }

    /// `open`, then `launch` the copy in an editor. A launch that fails
    /// stops the live edit this open started before the error goes back
    /// (N-026): the window says the file was not opened, so the copy must not
    /// keep syncing. A reopen of a file already being edited leaves that live
    /// edit as it is (its editor may well be open).
    pub(crate) async fn open_and_launch(
        &self,
        link: Arc<dyn LiveEditLink>,
        session_id: &str,
        remote_path: &str,
        leaf: &str,
        refuse_content: &(dyn Fn(&[u8]) -> Option<String> + Send + Sync),
        launch: impl FnOnce(&Path) -> Result<(), String>,
    ) -> Result<(), String> {
        let opened = self.open(link, session_id, remote_path, leaf, refuse_content).await?;
        if let Err(e) = launch(&opened.path) {
            // Nothing was edited: the stop deletes the copy.
            if opened.how == OpenedHow::New {
                if let Ok(stopping) = self.stop_because(session_id, remote_path, StopReason::NotOpened) {
                    let _ = stopping.await;
                }
            }
            return Err(e);
        }
        Ok(())
    }

    /// The live edits of `session_id`, by server path.
    pub(crate) fn list(&self, session_id: &str) -> Vec<LiveEditInfo> {
        let r = lock(&self.inner);
        let mut edits: Vec<LiveEditInfo> = r
            .entries
            .iter()
            .filter(|((s, _), _)| s == session_id)
            .map(|(_, e)| LiveEditInfo { remote_path: e.remote_path.clone(), name: e.name.clone() })
            .collect();
        edits.sort_by(|a, b| a.remote_path.cmp(&b.remote_path));
        edits
    }

    /// Stop the live edit of one file (the user asked). A change still
    /// waiting to be uploaded is uploaded first; then, as for the other
    /// stops, a copy in sync is deleted and one that could not be uploaded
    /// is kept and reported. Returns the task doing that, for tests to wait on.
    pub(crate) fn stop_one(&self, session_id: &str, remote_path: &str) -> Result<tokio::task::JoinHandle<()>, String> {
        self.stop_because(session_id, remote_path, StopReason::Stopped)
    }

    fn stop_because(&self, session_id: &str, remote_path: &str, reason: StopReason) -> Result<tokio::task::JoinHandle<()>, String> {
        let mut r = lock(&self.inner);
        let key = (session_id.to_string(), remote_path.to_string());
        if !r.entries.contains_key(&key) {
            return Err("That file is not being live-edited (any more).".into());
        }
        let task = stop_entry(&mut r, &key, reason);
        r.stopping.retain(|_, done| !*done.borrow());
        let (done_tx, done_rx) = watch::channel(false);
        r.stopping.insert(key, done_rx);
        Ok(tokio::spawn(async move {
            if let Some(task) = task {
                let _ = task.await;
            }
            let _ = done_tx.send(true);
        }))
    }

    /// Stop every live edit (the profile was locked).
    pub(crate) fn stop_all(&self, reason: StopReason) -> Vec<tokio::task::JoinHandle<()>> {
        let mut r = lock(&self.inner);
        let sessions: HashSet<String> =
            r.entries.keys().map(|(s, _)| s.clone()).chain(r.opening.iter().map(|(s, _)| s.clone())).collect();
        for s in sessions {
            *r.generation.entry(s).or_insert(0) += 1;
        }
        let keys: Vec<_> = r.entries.keys().cloned().collect();
        let mut tasks: Vec<_> = keys.into_iter().filter_map(|k| stop_entry(&mut r, &k, reason)).collect();
        // Files the user stopped that are still uploading: waited for too.
        for (_, mut done) in r.stopping.drain() {
            if !*done.borrow() {
                tasks.push(tokio::spawn(async move {
                    let _ = done.wait_for(|d| *d).await;
                }));
            }
        }
        tasks
    }
}

/// The staging folder name of a session. Hex, so no id (`..`, `a/b`, a
/// `::sftp` suffix, which Windows does not allow in a name) can name anything
/// but one folder directly in the root; ids are also checked before any
/// command runs (`guard_ipc_ids`).
pub(crate) fn session_dir_name(session_id: &str) -> String {
    format!("sftp_{}", hex::encode(session_id))
}

fn still_ours(root: &StagingRoot) -> bool {
    match std::fs::symlink_metadata(&root.path) {
        Ok(meta) if meta.is_dir() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                meta.uid() == root.uid && meta.mode() & 0o777 == 0o700
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        _ => false,
    }
}

fn stop_entry(r: &mut Registry, key: &(String, String), reason: StopReason) -> Option<tokio::task::JoinHandle<()>> {
    let entry = r.entries.remove(key)?;
    // The reason first: the task may see its wake channel close at once.
    let _ = entry.stop.send(Some(reason));
    {
        let mut routes = lock(&r.routes);
        for k in &entry.watch_keys {
            routes.remove(k);
        }
    }
    // Before the copy can be deleted: Windows keeps a watched folder open.
    if let Some(w) = r.watcher.as_mut() {
        let _ = w.watcher().unwatch(&entry.dir);
    }
    let task = lock(&entry.task).take();
    task
}

struct OpeningClaim<'a> {
    edits: &'a LiveEdits,
    key: (String, String),
}

impl Drop for OpeningClaim<'_> {
    fn drop(&mut self) {
        lock(&self.edits.inner).opening.remove(&self.key);
    }
}

/// The same remote file opened again: refresh a copy that is in sync, keep
/// one with changes that were not uploaded.
async fn reopen(entry: &Entry, refuse_content: &(dyn Fn(&[u8]) -> Option<String> + Send + Sync)) -> Result<Opened, String> {
    let _sync = entry.sync_lock.lock().await;
    if entry.stop.borrow().is_some() {
        return Err("The session was closed; open the file again.".into());
    }
    match entry.link.target() {
        None => return Err("The session is not connected.".into()),
        Some(now) => {
            if let Some(why) = entry.elsewhere(&now) {
                return Err(format!("{why}. Disconnect to end its live edit, then open the file again."));
            }
        }
    }
    let local = hash_file(entry.file.clone()).await.map_err(|e| format!("Failed to read the local copy: {e}"))?;
    let synced = *lock(&entry.synced);
    if local.is_some() && local != synced {
        entry.report(
            StatusKind::Note,
            format!("{} has changes that were not uploaded yet; your copy was opened again, not downloaded again.", entry.name),
        );
        return Ok(Opened { path: entry.file.clone(), how: OpenedHow::KeptLocalChanges });
    }
    // Download beside the copy, then rename over it: the editor sees one change.
    let part = entry.dir.join(atomic_transfer::hidden_sibling_name(&entry.name, "solanum-part"));
    let fetched = match entry.link.fetch(&entry.remote_path, &part, LIVE_EDIT_MAX_BYTES).await {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            return Err(e);
        }
    };
    if let Some(why) = refuse_content(&fetched.head) {
        let _ = std::fs::remove_file(&part);
        return Err(why);
    }
    if local.is_some() && Some(fetched.hash) == synced {
        // The server has what the copy has: leave the copy alone (no
        // "changed on disk" prompt in the editor).
        let _ = std::fs::remove_file(&part);
        return Ok(Opened { path: entry.file.clone(), how: OpenedHow::Refreshed });
    }
    // A save during the download wins over the server's version.
    let now = hash_file(entry.file.clone()).await.map_err(|e| format!("Failed to read the local copy: {e}"))?;
    if now != local {
        let _ = std::fs::remove_file(&part);
        entry.report(
            StatusKind::Note,
            format!("{} was saved while it was being downloaded again; your copy was kept.", entry.name),
        );
        return Ok(Opened { path: entry.file.clone(), how: OpenedHow::KeptLocalChanges });
    }
    // Recorded before the rename, so the watcher's event for it uploads nothing.
    *lock(&entry.synced) = Some(fetched.hash);
    if let Err(e) = std::fs::rename(&part, &entry.file) {
        *lock(&entry.synced) = synced;
        let _ = std::fs::remove_file(&part);
        return Err(format!("Failed to refresh the local copy: {e}"));
    }
    let _ = write_marker(&entry.dir, &fetched.hash);
    Ok(Opened { path: entry.file.clone(), how: OpenedHow::Refreshed })
}

async fn run_entry(entry: Arc<Entry>, mut wake: mpsc::Receiver<()>, mut stop: watch::Receiver<Option<StopReason>>) {
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            got = wake.recv() => {
                if got.is_none() {
                    // Only stopping drops the routes, and it sends the reason.
                    let _ = stop.wait_for(Option::is_some).await;
                    break;
                }
                sync(&entry).await;
            }
        }
    }
    let reason = stop.borrow().unwrap_or(StopReason::Disconnected);
    if reason == StopReason::Stopped {
        // Stopped by the user, so the session is still there: a save the
        // debounce has not passed on yet is uploaded first.
        sync(&entry).await;
    }
    finish(&entry, reason).await;
}

/// Upload the copy if it differs from what the server has.
async fn sync(entry: &Entry) {
    let _sync = entry.sync_lock.lock().await;
    let local = match hash_file(entry.file.clone()).await {
        Ok(Some(h)) => h,
        // A delete-then-create save in progress: its second half wakes us again.
        Ok(None) => return,
        Err(e) => {
            entry.report(StatusKind::Failed, format!("Auto-sync failed for {}: cannot read the local copy: {e}", entry.name));
            return;
        }
    };
    if Some(local) == *lock(&entry.synced) {
        return;
    }
    match entry.link.target() {
        None => {
            entry.report(StatusKind::Failed, format!("Auto-sync failed for {}: the session is not connected. Save it again to retry.", entry.name));
            return;
        }
        Some(now) => {
            if let Some(why) = entry.elsewhere(&now) {
                entry.report(
                    StatusKind::Failed,
                    format!("{why}, so the change was not uploaded. Your copy is kept; disconnect to end its live edit."),
                );
                return;
            }
        }
    }
    match entry.link.store(&entry.file, &entry.remote_path).await {
        Ok(stored) => {
            *lock(&entry.synced) = Some(stored.hash);
            let _ = write_marker(&entry.dir, &stored.hash);
            let message = match stored.note {
                Some(note) => format!("Auto-synced {}. {}", entry.name, note),
                None => format!("Auto-synced {}", entry.name),
            };
            entry.report(StatusKind::Synced, message);
        }
        Err(e) => entry.report(
            StatusKind::Failed,
            format!("Auto-sync failed for {}: {e}. Save it again to retry.", entry.name),
        ),
    }
}

/// Syncing ended: delete a copy that is in sync, keep one that is not.
async fn finish(entry: &Entry, reason: StopReason) {
    let _sync = entry.sync_lock.lock().await;
    let unsynced = match hash_file(entry.file.clone()).await {
        Ok(Some(h)) => Some(h) != *lock(&entry.synced),
        Ok(None) => false,
        // Cannot tell: keep it.
        Err(_) => true,
    };
    if unsynced {
        entry.report(
            StatusKind::StoppedKept,
            format!(
                "Auto-sync of {} stopped ({}) before your last changes were uploaded. They are kept in {}",
                entry.name,
                reason.describe(),
                entry.file.display()
            ),
        );
        return;
    }
    remove_patiently(&entry.dir).await;
    // Kept while the folder is (an editor still holds the file on Windows):
    // the next sweep then sees a copy in sync, not one that lost its marker.
    if std::fs::symlink_metadata(&entry.dir).is_err() {
        let _ = std::fs::remove_file(marker_path(&entry.dir));
    }
    if let Some(session_dir) = entry.dir.parent() {
        // Only succeeds once the session's last copy is gone.
        let _ = std::fs::remove_dir(session_dir);
    }
    entry.report(StatusKind::Stopped, format!("Auto-sync of {} stopped ({}).", entry.name, reason.describe()));
}

/// A staging root's name: `solanum-` and 24 hex digits.
fn is_root_name(name: &str) -> bool {
    name.strip_prefix("solanum-").is_some_and(|hex| hex.len() == 24 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// This user's id: the owner of a file it creates (std has no getuid).
#[cfg(unix)]
fn current_uid(base: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let probe = base.join(format!(".solanum-uid-{}", random_hex(8)));
    let uid = std::fs::OpenOptions::new().write(true).create_new(true).open(&probe).and_then(|f| f.metadata()).map(|m| m.uid());
    let _ = std::fs::remove_file(&probe);
    uid.ok()
}

/// A folder, not a link, and (Unix) this user's and private to it.
fn owned_private_dir(path: &Path, #[cfg(unix)] uid: u32) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                meta.uid() == uid && meta.mode() & 0o777 == 0o700
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        _ => false,
    }
}

/// A regular file, not a link, and (Unix) this user's.
fn owned_file(path: &Path, #[cfg(unix)] uid: u32) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                meta.uid() == uid
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        _ => false,
    }
}

fn is_plain_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// Sweep the staging roots under `base` whose process is gone (its lock can
/// be taken): copies matching their marker and empty folders are deleted,
/// then the root and its lock if nothing is left. Returns the files kept.
/// A root without its lock file (an older build, or a temp cleaner took it),
/// one a live instance holds, or one not this user's and private is left
/// alone.
pub(crate) fn sweep_stale_roots(base: &Path) -> Vec<PathBuf> {
    let mut kept = Vec::new();
    let Ok(entries) = std::fs::read_dir(base) else { return kept };
    #[cfg(unix)]
    let Some(uid) = current_uid(base) else { return kept };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let (root, lock_path) = if is_root_name(name) {
            let root = entry.path();
            let lock_path = lock_path_of(&root);
            (root, lock_path)
        } else if name.strip_suffix(".lock").is_some_and(is_root_name) {
            // A lock file whose root is gone (only the lock is left to sweep).
            let lock_path = entry.path();
            let root = lock_path.with_extension("");
            if std::fs::symlink_metadata(&root).is_ok() {
                continue; // handled with its root
            }
            (root, lock_path)
        } else {
            continue;
        };
        #[cfg(unix)]
        let (root_ok, lock_ok) = (owned_private_dir(&root, uid), owned_file(&lock_path, uid));
        #[cfg(not(unix))]
        let (root_ok, lock_ok) = (owned_private_dir(&root), owned_file(&lock_path));
        let root_exists = std::fs::symlink_metadata(&root).is_ok();
        if !lock_ok || (root_exists && !root_ok) {
            continue;
        }
        let Ok(lock_file) = std::fs::OpenOptions::new().read(true).write(true).open(&lock_path) else { continue };
        if lock_file.try_lock().is_err() {
            continue; // a live instance holds it, or this system cannot tell
        }
        if root_exists {
            kept.extend(sweep_root(&root));
        }
        if !root_exists || std::fs::remove_dir(&root).is_ok() {
            let _ = std::fs::remove_file(&lock_path);
        }
    }
    kept
}

fn sweep_root(root: &Path) -> Vec<PathBuf> {
    let mut kept = Vec::new();
    let Ok(sessions) = std::fs::read_dir(root) else { return kept };
    for session in sessions.flatten() {
        let session_dir = session.path();
        if !is_plain_dir(&session_dir) {
            continue; // nothing this app makes: left as it is
        }
        let Ok(items) = std::fs::read_dir(&session_dir) else { continue };
        for item in items.flatten() {
            let dir = item.path();
            if !is_plain_dir(&dir) {
                continue;
            }
            match leftover_copy(&dir) {
                None => {
                    if std::fs::remove_dir_all(&dir).is_ok() {
                        let _ = std::fs::remove_file(marker_path(&dir));
                    }
                }
                Some(files) => kept.extend(files),
            }
        }
        // Markers whose copy is gone.
        if let Ok(items) = std::fs::read_dir(&session_dir) {
            for item in items.flatten() {
                let marker = item.path();
                if marker.extension().is_some_and(|e| e == "synced") && std::fs::symlink_metadata(marker.with_extension("")).is_err() {
                    let _ = std::fs::remove_file(&marker);
                }
            }
        }
        let _ = std::fs::remove_dir(&session_dir);
    }
    kept
}

/// What a copy folder of a gone process holds that may matter: `None` when
/// it can go (empty, or exactly one file matching its marker), else the files
/// to keep. Our own part files are removed first.
fn leftover_copy(dir: &Path) -> Option<Vec<PathBuf>> {
    let Ok(items) = std::fs::read_dir(dir) else { return Some(vec![dir.to_path_buf()]) };
    let (mut files, mut other) = (Vec::new(), false);
    for item in items.flatten() {
        let path = item.path();
        let is_file = std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file());
        let name = item.file_name().to_string_lossy().into_owned();
        if is_file && name.starts_with('.') && name.ends_with(".solanum-part") {
            let _ = std::fs::remove_file(&path);
        } else if is_file {
            files.push(path);
        } else {
            other = true;
        }
    }
    if std::fs::symlink_metadata(marker_path(dir)).is_err() {
        // No marker: the copy never reached an editor (a download the process
        // did not live to finish).
        return None;
    }
    match (files.as_slice(), other) {
        ([], false) => None,
        ([copy], false) if read_marker(dir).is_some_and(|synced| hash_file_now(copy).ok().flatten() == Some(synced)) => None,
        ([], true) => Some(vec![dir.to_path_buf()]),
        _ => Some(files),
    }
}

/// Delete a staging folder, trying again for about a second: on Windows the
/// watcher closes its handle on the folder shortly after `unwatch`, and an
/// editor or a virus scanner may hold a file for a moment. Best effort: a
/// folder that stays is left in the temp folder.
async fn remove_patiently(dir: &Path) {
    for _ in 0..10 {
        let _ = std::fs::remove_dir_all(dir);
        if std::fs::symlink_metadata(dir).is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Stream `remote` into the new file `dest` (owner-only), at most `cap` bytes.
pub(crate) async fn fetch_over_sftp(sftp: &SftpSession, remote: &str, dest: &Path, cap: u64) -> Result<Fetched, String> {
    let result = fetch_into(sftp, remote, dest, cap).await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(dest).await;
    }
    result
}

async fn fetch_into(sftp: &SftpSession, remote: &str, dest: &Path, cap: u64) -> Result<Fetched, String> {
    let mut source = sftp.open(remote).await.map_err(|e| format!("Failed to read remote file: {e}"))?;
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(dest).await.map_err(|e| format!("Failed to write temporary file: {e}"))?;
    let mut hasher = Sha256::new();
    let mut head = Vec::new();
    let mut total: u64 = 0;
    let mut buf = vec![0u8; atomic_transfer::CHUNK];
    loop {
        let n = source.read(&mut buf).await.map_err(|e| format!("Failed to read remote file: {e}"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > cap {
            return Err(size_refusal(total).unwrap_or_else(|| "The file is too large for live edit.".into()));
        }
        if head.len() < crate::open_guard::CONTENT_HEAD {
            let take = (crate::open_guard::CONTENT_HEAD - head.len()).min(n);
            head.extend_from_slice(&buf[..take]);
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n]).await.map_err(|e| format!("Failed to write temporary file: {e}"))?;
    }
    file.flush().await.map_err(|e| format!("Failed to write temporary file: {e}"))?;
    Ok(Fetched { hash: hasher.finalize().into(), head })
}

/// Upload `local` over `remote` (atomically where possible); the hash of the
/// bytes actually sent.
pub(crate) async fn store_over_sftp(sftp: &SftpSession, local: &Path, remote: &str) -> Result<Stored, String> {
    use atomic_transfer::ReplaceError;
    let mut hasher = Sha256::new();
    let mut on_chunk = |offset: u64, chunk: &[u8]| {
        if offset == 0 {
            // A restart (written in place after all): hash only what was sent last.
            hasher = Sha256::new();
        }
        hasher.update(chunk);
        true
    };
    match atomic_transfer::replace_remote_file(sftp, remote, local, true, &mut on_chunk).await {
        Ok(replaced) => Ok(Stored { hash: hasher.finalize().into(), note: replaced.note() }),
        Err(ReplaceError::Failed(e)) => Err(e),
        Err(ReplaceError::Exists) => Err("the file exists".into()),
        Err(ReplaceError::Cancelled) => Err("cancelled".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const WAIT: Duration = Duration::from_secs(10);
    const QUICK: Duration = Duration::from_millis(150);

    /// An in-memory server.
    struct FakeServer {
        files: Mutex<HashMap<String, Vec<u8>>>,
        stores: AtomicUsize,
        fail_stores: AtomicBool,
        /// When set, fetch waits for this before answering.
        fetch_gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
        /// When set, store waits for this before uploading.
        store_gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
        statuses: mpsc::UnboundedSender<SyncStatus>,
        /// The server the session reaches (`None`: not connected).
        target: Mutex<Option<ServerIdentity>>,
    }

    fn server(address: &str, host_key: &str) -> Option<ServerIdentity> {
        Some(ServerIdentity { address: address.into(), host_key: host_key.into() })
    }

    impl LiveEditLink for FakeServer {
        fn target(&self) -> Option<ServerIdentity> {
            lock(&self.target).clone()
        }
        fn fetch<'a>(&'a self, remote: &'a str, dest: &'a Path, cap: u64) -> BoxFut<'a, Result<Fetched, String>> {
            Box::pin(async move {
                let gate = lock(&self.fetch_gate).clone();
                if let Some(gate) = gate {
                    gate.notified().await;
                }
                let data = lock(&self.files).get(remote).cloned().ok_or("no such file")?;
                if data.len() as u64 > cap {
                    return Err("too large".into());
                }
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(dest).map_err(|e| e.to_string())?;
                std::io::Write::write_all(&mut f, &data).map_err(|e| e.to_string())?;
                Ok(Fetched { hash: Sha256::digest(&data).into(), head: data.iter().take(64).copied().collect() })
            })
        }
        fn store<'a>(&'a self, local: &'a Path, remote: &'a str) -> BoxFut<'a, Result<Stored, String>> {
            Box::pin(async move {
                let gate = lock(&self.store_gate).clone();
                if let Some(gate) = gate {
                    gate.notified().await;
                }
                if self.fail_stores.load(Ordering::SeqCst) {
                    return Err("connection lost".into());
                }
                let data = std::fs::read(local).map_err(|e| e.to_string())?;
                self.stores.fetch_add(1, Ordering::SeqCst);
                let hash = Sha256::digest(&data).into();
                lock(&self.files).insert(remote.to_string(), data);
                Ok(Stored { hash, note: None })
            })
        }
        fn report(&self, status: SyncStatus) {
            let _ = self.statuses.send(status);
        }
    }

    struct Setup {
        edits: LiveEdits,
        server: Arc<FakeServer>,
        statuses: mpsc::UnboundedReceiver<SyncStatus>,
        base: PathBuf,
    }

    impl Setup {
        fn new(files: &[(&str, &[u8])]) -> Self {
            let base = std::env::temp_dir().join(format!("solanum-live-edit-test-{}", random_hex(6)));
            std::fs::create_dir_all(&base).unwrap();
            let (tx, statuses) = mpsc::unbounded_channel();
            let server = Arc::new(FakeServer {
                files: Mutex::new(files.iter().map(|(p, d)| (p.to_string(), d.to_vec())).collect()),
                stores: AtomicUsize::new(0),
                fail_stores: AtomicBool::new(false),
                fetch_gate: Mutex::new(None),
                store_gate: Mutex::new(None),
                statuses: tx,
                target: Mutex::new(server("me@a.example:22", "key-a")),
            });
            Setup { edits: LiveEdits::new_in(base.clone(), Duration::from_millis(200)), server, statuses, base }
        }

        fn link(&self) -> Arc<dyn LiveEditLink> {
            Arc::clone(&self.server) as Arc<dyn LiveEditLink>
        }

        /// The staging root (its lock file sits beside it).
        fn root(&self) -> PathBuf {
            std::fs::read_dir(&self.base).unwrap().flatten().map(|e| e.path()).find(|p| p.is_dir()).expect("a staging root")
        }

        async fn open(&self, remote: &str) -> Result<Opened, String> {
            let leaf = remote.rsplit('/').next().unwrap();
            self.edits.open(self.link(), "s1", remote, leaf, &|_: &[u8]| None).await
        }

        fn server_file(&self, remote: &str) -> Vec<u8> {
            lock(&self.server.files).get(remote).cloned().unwrap_or_default()
        }

        async fn next(&mut self, kind: StatusKind, remote: &str) -> SyncStatus {
            let deadline = tokio::time::Instant::now() + WAIT;
            loop {
                let status = tokio::time::timeout_at(deadline, self.statuses.recv())
                    .await
                    .unwrap_or_else(|_| panic!("no {kind:?} status for {remote} within {WAIT:?}"))
                    .expect("status channel open");
                if status.kind == kind && status.remote_path == remote {
                    return status;
                }
                assert!(
                    !(status.remote_path == remote && matches!(status.kind, StatusKind::Stopped | StatusKind::StoppedKept)),
                    "syncing of {remote} ended early: {status:?}"
                );
            }
        }

        /// Nothing is reported within a few debounce periods.
        async fn quiet(&mut self) {
            tokio::time::sleep(Duration::from_millis(900)).await;
            if let Ok(status) = self.statuses.try_recv() {
                panic!("unexpected status: {status:?}");
            }
        }

        async fn stop(&self) {
            for task in self.edits.stop_session("s1", StopReason::Disconnected) {
                task.await.unwrap();
            }
        }
    }

    impl Drop for Setup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    /// An editor's rename-based save (vim, gedit, Kate): the old file moves to
    /// a backup name, a new file takes the name, the backup is deleted.
    fn rename_save(file: &Path, content: &[u8]) {
        let backup = file.with_file_name(format!("{}~", file.file_name().unwrap().to_string_lossy()));
        std::fs::rename(file, &backup).unwrap();
        std::fs::write(file, content).unwrap();
        std::fs::remove_file(&backup).unwrap();
    }

    #[test]
    fn files_over_the_cap_are_refused_by_size() {
        assert!(size_refusal(LIVE_EDIT_MAX_BYTES).is_none());
        let why = size_refusal(LIVE_EDIT_MAX_BYTES + 1).unwrap();
        assert!(why.contains("50 MiB") && why.contains("Download"), "{why}");
    }

    /// F-001: two remote files with the same name get their own copies, and
    /// each copy goes back to its own remote path.
    #[tokio::test(flavor = "multi_thread")]
    async fn same_named_files_get_their_own_copies_and_uploads() {
        let mut t = Setup::new(&[("/etc/nginx/nginx.conf", b"live config"), ("/backup/nginx.conf", b"old backup")]);
        let a = t.open("/etc/nginx/nginx.conf").await.unwrap();
        let b = t.open("/backup/nginx.conf").await.unwrap();
        assert_ne!(a.path, b.path);
        assert_eq!(a.path.file_name(), b.path.file_name());
        assert_eq!(std::fs::read(&a.path).unwrap(), b"live config", "opening the second did not touch the first");

        std::fs::write(&a.path, b"live config, edited").unwrap();
        t.next(StatusKind::Synced, "/etc/nginx/nginx.conf").await;
        std::fs::write(&b.path, b"old backup, edited").unwrap();
        t.next(StatusKind::Synced, "/backup/nginx.conf").await;
        assert_eq!(t.server_file("/etc/nginx/nginx.conf"), b"live config, edited");
        assert_eq!(t.server_file("/backup/nginx.conf"), b"old backup, edited");
        t.stop().await;
    }

    /// N-026: a copy whose editor did not start is not live-edited: the
    /// window says "Not opened", so a save of that copy (made by hand from the
    /// staging folder) must not reach the server.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_copy_whose_editor_did_not_start_is_not_kept_syncing() {
        let t = Setup::new(&[("/srv/app.conf", b"v0")]);
        let failed = t
            .edits
            .open_and_launch(t.link(), "s1", "/srv/app.conf", "app.conf", &|_: &[u8]| None, |_| Err("no application opens this type".into()))
            .await;
        assert_eq!(failed, Err("no application opens this type".to_string()));
        assert!(t.edits.list("s1").is_empty(), "the copy is still live-edited");

        // A file already being edited: a second Open whose launch fails
        // leaves that live edit alone (review of batch 15).
        t.edits.open_and_launch(t.link(), "s1", "/srv/app.conf", "app.conf", &|_: &[u8]| None, |_| Ok(())).await.unwrap();
        let again = t
            .edits
            .open_and_launch(t.link(), "s1", "/srv/app.conf", "app.conf", &|_: &[u8]| None, |_| Err("no application opens this type".into()))
            .await;
        assert!(again.is_err());
        assert_eq!(t.edits.list("s1").len(), 1, "the running live edit was stopped by a failed reopen");
        t.stop().await;
    }

    /// F-016: every rename-based save is uploaded, not only the first.
    #[tokio::test(flavor = "multi_thread")]
    async fn every_rename_based_save_is_uploaded() {
        let mut t = Setup::new(&[("/srv/app.conf", b"v0")]);
        let opened = t.open("/srv/app.conf").await.unwrap();
        for version in [&b"v1"[..], b"v2", b"v3"] {
            rename_save(&opened.path, version);
            t.next(StatusKind::Synced, "/srv/app.conf").await;
            assert_eq!(t.server_file("/srv/app.conf"), version);
        }
        t.stop().await;
    }

    /// F-015: a copy that is missing for a moment (delete, then create) does
    /// not end syncing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_copy_missing_for_a_moment_does_not_end_syncing() {
        let mut t = Setup::new(&[("/srv/app.conf", b"v0")]);
        let opened = t.open("/srv/app.conf").await.unwrap();
        std::fs::remove_file(&opened.path).unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;
        std::fs::write(&opened.path, b"recreated").unwrap();
        t.next(StatusKind::Synced, "/srv/app.conf").await;
        assert_eq!(t.server_file("/srv/app.conf"), b"recreated");
        t.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_save_without_changes_uploads_nothing() {
        let mut t = Setup::new(&[("/srv/app.conf", b"same")]);
        let opened = t.open("/srv/app.conf").await.unwrap();
        std::fs::write(&opened.path, b"same").unwrap();
        t.quiet().await;
        assert_eq!(t.server.stores.load(Ordering::SeqCst), 0);
        t.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn opening_again_refreshes_a_copy_in_sync() {
        let mut t = Setup::new(&[("/srv/app.conf", b"v0")]);
        let first = t.open("/srv/app.conf").await.unwrap();
        lock(&t.server.files).insert("/srv/app.conf".into(), b"changed on the server".to_vec());
        let again = t.open("/srv/app.conf").await.unwrap();
        assert_eq!(again.how, OpenedHow::Refreshed);
        assert_eq!(again.path, first.path);
        assert_eq!(std::fs::read(&again.path).unwrap(), b"changed on the server");
        t.quiet().await;
        assert_eq!(t.server.stores.load(Ordering::SeqCst), 0, "the refresh is not uploaded back");
        t.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn opening_again_keeps_changes_that_were_not_uploaded() {
        let mut t = Setup::new(&[("/srv/app.conf", b"v0")]);
        let first = t.open("/srv/app.conf").await.unwrap();
        t.server.fail_stores.store(true, Ordering::SeqCst);
        std::fs::write(&first.path, b"my unsaved work").unwrap();
        t.next(StatusKind::Failed, "/srv/app.conf").await;
        lock(&t.server.files).insert("/srv/app.conf".into(), b"changed on the server".to_vec());
        let again = t.open("/srv/app.conf").await.unwrap();
        assert_eq!(again.how, OpenedHow::KeptLocalChanges);
        assert_eq!(std::fs::read(&again.path).unwrap(), b"my unsaved work");
        t.next(StatusKind::Note, "/srv/app.conf").await;

        // The next save goes through once the server is reachable again.
        t.server.fail_stores.store(false, Ordering::SeqCst);
        std::fs::write(&first.path, b"my finished work").unwrap();
        t.next(StatusKind::Synced, "/srv/app.conf").await;
        assert_eq!(t.server_file("/srv/app.conf"), b"my finished work");
        t.stop().await;
    }

    /// The Stop control: a change saved just before it (still in the
    /// debounce) is uploaded first, the copy in sync is then deleted, and the
    /// other file keeps syncing.
    #[tokio::test(flavor = "multi_thread")]
    async fn stopping_one_file_uploads_its_last_change_and_leaves_the_others() {
        let mut t = Setup::new(&[("/srv/a.conf", b"a0"), ("/srv/b.conf", b"b0")]);
        let a = t.open("/srv/a.conf").await.unwrap();
        let b = t.open("/srv/b.conf").await.unwrap();
        let listed: Vec<String> = t.edits.list("s1").into_iter().map(|e| e.remote_path).collect();
        assert_eq!(listed, ["/srv/a.conf", "/srv/b.conf"]);
        assert!(t.edits.list("s2").is_empty());

        std::fs::write(&a.path, b"a1, saved right before Stop").unwrap();
        t.edits.stop_one("s1", "/srv/a.conf").unwrap().await.unwrap();
        assert_eq!(t.server_file("/srv/a.conf"), b"a1, saved right before Stop");
        let ended = t.next(StatusKind::Stopped, "/srv/a.conf").await;
        assert!(ended.message.contains("you stopped it"), "{}", ended.message);
        assert!(!a.path.parent().unwrap().exists(), "the copy in sync is deleted");
        assert_eq!(t.edits.list("s1").into_iter().map(|e| e.remote_path).collect::<Vec<_>>(), ["/srv/b.conf"]);
        assert!(t.edits.stop_one("s1", "/srv/a.conf").is_err(), "already stopped");

        std::fs::write(&b.path, b"b1").unwrap();
        t.next(StatusKind::Synced, "/srv/b.conf").await;
        t.stop().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stopping_a_file_that_cannot_be_uploaded_keeps_its_copy() {
        let mut t = Setup::new(&[("/srv/a.conf", b"a0")]);
        let a = t.open("/srv/a.conf").await.unwrap();
        t.server.fail_stores.store(true, Ordering::SeqCst);
        std::fs::write(&a.path, b"not uploaded").unwrap();
        t.edits.stop_one("s1", "/srv/a.conf").unwrap().await.unwrap();
        let kept = t.next(StatusKind::StoppedKept, "/srv/a.conf").await;
        assert_eq!(kept.kept.as_deref(), Some(a.path.as_path()));
        assert_eq!(std::fs::read(&a.path).unwrap(), b"not uploaded");
        assert!(t.edits.list("s1").is_empty());
    }

    /// Review of batch 11: opening a file again while its Stop is still
    /// uploading the last change waits for that upload, so the new copy has
    /// it (and a later save cannot overwrite it on the server).
    #[tokio::test(flavor = "multi_thread")]
    async fn opening_a_file_while_its_stop_is_uploading_waits_for_it() {
        let t = Setup::new(&[("/srv/a.conf", b"a0")]);
        let a = t.open("/srv/a.conf").await.unwrap();
        let gate = Arc::new(tokio::sync::Notify::new());
        *lock(&t.server.store_gate) = Some(Arc::clone(&gate));
        std::fs::write(&a.path, b"a1, the last change").unwrap();
        let stopping = t.edits.stop_one("s1", "/srv/a.conf").unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let release = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
            *lock(&t.server.store_gate) = None;
            gate.notify_one();
        };
        let (reopened, ()) = tokio::join!(t.open("/srv/a.conf"), release);
        let reopened = reopened.unwrap();
        stopping.await.unwrap();
        assert_eq!(std::fs::read(&reopened.path).unwrap(), b"a1, the last change");
        assert_eq!(t.server_file("/srv/a.conf"), b"a1, the last change");
        t.stop().await;
    }

    /// F-015: ending (disconnect) keeps a copy with changes that were not
    /// uploaded and says where; a copy in sync is deleted.
    #[tokio::test(flavor = "multi_thread")]
    async fn stopping_keeps_unsynced_changes_and_deletes_the_rest() {
        let mut t = Setup::new(&[("/srv/kept.conf", b"v0"), ("/srv/clean.conf", b"v0")]);
        let kept = t.open("/srv/kept.conf").await.unwrap();
        let clean = t.open("/srv/clean.conf").await.unwrap();
        t.server.fail_stores.store(true, Ordering::SeqCst);
        std::fs::write(&kept.path, b"not uploaded").unwrap();
        t.next(StatusKind::Failed, "/srv/kept.conf").await;

        let tasks = t.edits.stop_session("s1", StopReason::Disconnected);
        assert_eq!(tasks.len(), 2);
        for task in tasks {
            task.await.unwrap();
        }
        let mut seen = HashMap::new();
        while let Ok(s) = t.statuses.try_recv() {
            seen.insert(s.remote_path.clone(), s);
        }
        let k = &seen["/srv/kept.conf"];
        assert_eq!(k.kind, StatusKind::StoppedKept);
        assert!(k.message.contains(&kept.path.display().to_string()), "{}", k.message);
        assert_eq!(std::fs::read(&kept.path).unwrap(), b"not uploaded");
        assert_eq!(seen["/srv/clean.conf"].kind, StatusKind::Stopped);
        assert!(!clean.path.parent().unwrap().exists(), "the copy in sync is deleted");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn stopping_a_session_in_sync_leaves_no_staging_folder() {
        let mut t = Setup::new(&[("/srv/app.conf", b"v0")]);
        let opened = t.open("/srv/app.conf").await.unwrap();
        t.stop().await;
        t.next(StatusKind::Stopped, "/srv/app.conf").await;
        let session_dir = opened.path.parent().unwrap().parent().unwrap();
        assert!(!session_dir.exists());
        // A new open after a reconnect (same session id) works.
        let again = t.open("/srv/app.conf").await.unwrap();
        assert_eq!(again.how, OpenedHow::New);
        t.stop().await;
    }

    /// A disconnect while the file is still downloading: the open fails and
    /// leaves nothing behind.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_disconnect_during_an_open_leaves_nothing() {
        let t = Setup::new(&[("/srv/app.conf", b"v0")]);
        let gate = Arc::new(tokio::sync::Notify::new());
        *lock(&t.server.fetch_gate) = Some(Arc::clone(&gate));
        let opening = t.open("/srv/app.conf");
        let disconnect = async {
            tokio::time::sleep(QUICK).await;
            assert!(t.edits.stop_session("s1", StopReason::Disconnected).is_empty());
            gate.notify_one();
        };
        let (result, ()) = tokio::join!(opening, disconnect);
        assert!(result.is_err(), "the open must fail");
        let root = t.root();
        let session_dir = root.join(session_dir_name("s1"));
        assert_eq!(std::fs::read_dir(session_dir).unwrap().count(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn refused_content_leaves_nothing() {
        let t = Setup::new(&[("/srv/notes.txt", b"[Desktop Entry]\nExec=sh\n")]);
        let refuse = |head: &[u8]| head.starts_with(b"[Desktop Entry]").then(|| "a launcher".to_string());
        let result = t.edits.open(t.link(), "s1", "/srv/notes.txt", "notes.txt", &refuse).await;
        assert_eq!(result.err().as_deref(), Some("a launcher"));
        assert!(lock(&t.edits.inner).entries.is_empty());
        let root = t.root();
        let session_dir = root.join(session_dir_name("s1"));
        assert_eq!(std::fs::read_dir(session_dir).unwrap().count(), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_second_open_while_the_first_downloads_is_refused() {
        let t = Setup::new(&[("/srv/app.conf", b"v0")]);
        let gate = Arc::new(tokio::sync::Notify::new());
        *lock(&t.server.fetch_gate) = Some(Arc::clone(&gate));
        let first = t.open("/srv/app.conf");
        let second = async {
            tokio::time::sleep(QUICK).await;
            let r = t.open("/srv/app.conf").await;
            gate.notify_one();
            r
        };
        let (first, second) = tokio::join!(first, second);
        assert!(first.is_ok());
        assert_eq!(second.err().as_deref(), Some("This file is already being opened."));
        assert_eq!(lock(&t.edits.inner).entries.len(), 1);
        t.stop().await;
    }

    /// Locking the profile stops every session's live edits.
    #[tokio::test(flavor = "multi_thread")]
    async fn locking_the_profile_stops_every_session() {
        let mut t = Setup::new(&[("/srv/a.conf", b"a"), ("/srv/b.conf", b"b")]);
        t.open("/srv/a.conf").await.unwrap();
        t.edits.open(t.link(), "s2", "/srv/b.conf", "b.conf", &|_: &[u8]| None).await.unwrap();
        let tasks = t.edits.stop_all(StopReason::ProfileClosed);
        assert_eq!(tasks.len(), 2);
        for task in tasks {
            task.await.unwrap();
        }
        // Both tasks have ended, so both reports are queued (in either order).
        let mut seen = HashMap::new();
        while let Ok(status) = t.statuses.try_recv() {
            seen.insert(status.remote_path.clone(), status);
        }
        for remote in ["/srv/a.conf", "/srv/b.conf"] {
            let status = &seen[remote];
            assert_eq!(status.kind, StatusKind::Stopped);
            assert!(status.message.contains("the profile was locked"), "{}", status.message);
        }
        assert!(lock(&t.edits.inner).entries.is_empty());
    }

    /// Opening again while the server still has the same content leaves the
    /// copy alone (no "changed on disk" prompt in the editor).
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn opening_again_without_changes_leaves_the_copy_alone() {
        use std::os::unix::fs::MetadataExt;
        let t = Setup::new(&[("/srv/app.conf", b"v0")]);
        let first = t.open("/srv/app.conf").await.unwrap();
        let inode = std::fs::metadata(&first.path).unwrap().ino();
        let again = t.open("/srv/app.conf").await.unwrap();
        assert_eq!(again.how, OpenedHow::Refreshed);
        assert_eq!(std::fs::metadata(&again.path).unwrap().ino(), inode, "not replaced");
        assert_eq!(std::fs::read_dir(first.path.parent().unwrap()).unwrap().count(), 1, "no part file left");
        t.stop().await;
    }

    /// A save made while the file is being downloaded again is not
    /// overwritten by the server's version.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_save_during_a_reopen_is_kept() {
        let mut t = Setup::new(&[("/srv/app.conf", b"v0")]);
        let first = t.open("/srv/app.conf").await.unwrap();
        lock(&t.server.files).insert("/srv/app.conf".into(), b"changed on the server".to_vec());
        t.server.fail_stores.store(true, Ordering::SeqCst);
        let gate = Arc::new(tokio::sync::Notify::new());
        *lock(&t.server.fetch_gate) = Some(Arc::clone(&gate));
        let reopening = t.open("/srv/app.conf");
        let saving = async {
            tokio::time::sleep(QUICK).await;
            std::fs::write(&first.path, b"saved meanwhile").unwrap();
            gate.notify_one();
        };
        let (again, ()) = tokio::join!(reopening, saving);
        let again = again.unwrap();
        assert_eq!(again.how, OpenedHow::KeptLocalChanges);
        assert_eq!(std::fs::read(&again.path).unwrap(), b"saved meanwhile");
        t.next(StatusKind::Note, "/srv/app.conf").await;
        t.stop().await;
    }

    /// N-011: a staging root that is gone, or that another folder replaced,
    /// is not reused. (Unix: the temp folder is per user elsewhere.)
    #[cfg(unix)]
    #[test]
    fn a_replaced_staging_root_is_not_reused() {
        let base = std::env::temp_dir().join(format!("solanum-live-edit-root-{}", random_hex(6)));
        std::fs::create_dir_all(&base).unwrap();
        let edits = LiveEdits::new_in(base.clone(), DEBOUNCE);
        use std::os::unix::fs::PermissionsExt;
        let first = edits.new_entry_dir("s1").unwrap();
        let root = first.parent().unwrap().parent().unwrap().to_path_buf();
        assert_eq!(std::fs::metadata(&root).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(edits.new_entry_dir("s1").unwrap().starts_with(&root), "an intact root is kept");

        // Deleted, then a folder others can enter takes the name.
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        let second = edits.new_entry_dir("s1").unwrap();
        assert!(!second.starts_with(&root), "{} must not be under the replaced root", second.display());

        // Deleted and not replaced: a new root.
        let second_root = second.parent().unwrap().parent().unwrap().to_path_buf();
        std::fs::remove_dir_all(&second_root).unwrap();
        let third = edits.new_entry_dir("s1").unwrap();
        assert!(third.exists() && !third.starts_with(&second_root));
        std::fs::remove_dir_all(&base).unwrap();
    }

    // --- staging root lock, markers, start-up sweep, quit (F-061) ---

    fn sha(data: &[u8]) -> Hash {
        Sha256::digest(data).into()
    }

    /// The marker follows what the server has: at the open, after an upload
    /// and after a refresh.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_marker_follows_what_the_server_has() {
        let mut t = Setup::new(&[("/srv/app.conf", b"v0")]);
        let opened = t.open("/srv/app.conf").await.unwrap();
        let dir = opened.path.parent().unwrap().to_path_buf();
        assert_eq!(read_marker(&dir), Some(sha(b"v0")));
        std::fs::write(&opened.path, b"v1").unwrap();
        t.next(StatusKind::Synced, "/srv/app.conf").await;
        assert_eq!(read_marker(&dir), Some(sha(b"v1")));
        lock(&t.server.files).insert("/srv/app.conf".into(), b"v2 from the server".to_vec());
        assert_eq!(t.open("/srv/app.conf").await.unwrap().how, OpenedHow::Refreshed);
        assert_eq!(read_marker(&dir), Some(sha(b"v2 from the server")));
        t.stop().await;
        assert!(!marker_path(&dir).exists(), "deleted with the copy");
    }

    /// The root has a locked lock file beside it while it is in use.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_root_in_use_is_locked() {
        let t = Setup::new(&[("/srv/app.conf", b"v0")]);
        t.open("/srv/app.conf").await.unwrap();
        let lock_path = lock_path_of(&t.root());
        let other = std::fs::OpenOptions::new().read(true).write(true).open(&lock_path).unwrap();
        assert!(matches!(other.try_lock(), Err(std::fs::TryLockError::WouldBlock)), "another instance cannot take it");
        assert!(sweep_stale_roots(&t.base).is_empty());
        assert!(t.root().exists(), "the sweep leaves a root in use alone");
        t.stop().await;
    }

    /// A root as a process that is gone left it: the lock file unlocked,
    /// one copy in sync with its marker, one with changes the server never
    /// got, a part file, an empty copy folder, a copy that never got its
    /// marker (a first download cut short), a stray marker.
    fn dead_root(base: &Path, name: &str) -> PathBuf {
        let root = base.join(name);
        create_private_dir(&root).unwrap();
        drop(create_root_lock(&lock_path_of(&root)).unwrap());
        let session = root.join(session_dir_name("s1"));
        create_private_dir(&session).unwrap();
        let in_sync = session.join("aaaa0001");
        create_private_dir(&in_sync).unwrap();
        std::fs::write(in_sync.join("app.conf"), b"same as the server").unwrap();
        std::fs::write(in_sync.join(".app.conf.0123.solanum-part"), b"half").unwrap();
        write_marker(&in_sync, &sha(b"same as the server")).unwrap();
        let changed = session.join("aaaa0002");
        create_private_dir(&changed).unwrap();
        std::fs::write(changed.join("notes.txt"), b"edited, never uploaded").unwrap();
        write_marker(&changed, &sha(b"what the server had")).unwrap();
        create_private_dir(&session.join("aaaa0003")).unwrap();
        create_private_dir(&session.join("aaaa0004")).unwrap();
        std::fs::write(session.join("aaaa0004").join("big.log"), b"half downloaded").unwrap();
        std::fs::write(session.join("aaaa0009.synced"), hex::encode(sha(b"x"))).unwrap();
        root
    }

    #[test]
    fn the_sweep_deletes_copies_in_sync_and_keeps_changes_that_were_not_uploaded() {
        let base = std::env::temp_dir().join(format!("solanum-sweep-test-{}", random_hex(6)));
        std::fs::create_dir_all(&base).unwrap();
        let root = dead_root(&base, &format!("solanum-{}", random_hex(12)));
        let session = root.join(session_dir_name("s1"));

        let kept = sweep_stale_roots(&base);
        assert_eq!(kept, [session.join("aaaa0002").join("notes.txt")]);
        assert_eq!(std::fs::read(&kept[0]).unwrap(), b"edited, never uploaded");
        assert!(!session.join("aaaa0001").exists(), "the copy in sync is deleted");
        assert!(!marker_path(&session.join("aaaa0001")).exists());
        assert!(!session.join("aaaa0003").exists(), "empty folders go");
        assert!(!session.join("aaaa0004").exists(), "a copy that never reached an editor goes");
        assert!(!session.join("aaaa0009.synced").exists(), "markers without a copy go");
        assert!(lock_path_of(&root).exists(), "the root stays with what it keeps, and so does its lock");

        // Once the kept copy is dealt with, the next sweep removes the rest.
        std::fs::remove_dir_all(session.join("aaaa0002")).unwrap();
        assert!(sweep_stale_roots(&base).is_empty());
        assert!(!root.exists() && !lock_path_of(&root).exists());
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 0, "nothing left behind, not even the uid probe");
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn the_sweep_leaves_alone_what_it_cannot_prove_is_a_gone_processs() {
        let base = std::env::temp_dir().join(format!("solanum-sweep-test-{}", random_hex(6)));
        std::fs::create_dir_all(&base).unwrap();
        // A live instance's root (its lock is held).
        let live = dead_root(&base, &format!("solanum-{}", random_hex(12)));
        let held = std::fs::OpenOptions::new().read(true).write(true).open(lock_path_of(&live)).unwrap();
        held.try_lock().unwrap();
        // A root without its lock file (an older build, or a temp cleaner took it).
        let unlocked = dead_root(&base, &format!("solanum-{}", random_hex(12)));
        std::fs::remove_file(lock_path_of(&unlocked)).unwrap();
        // Names this app does not make.
        let other = dead_root(&base, "solanum-notours");
        // A lock file whose root is gone: removed.
        let orphan_lock = lock_path_of(&base.join(format!("solanum-{}", random_hex(12))));
        drop(create_root_lock(&orphan_lock).unwrap());

        assert!(sweep_stale_roots(&base).is_empty());
        for root in [&live, &unlocked, &other] {
            assert!(root.join(session_dir_name("s1")).join("aaaa0001").join("app.conf").exists(), "{} untouched", root.display());
        }
        assert!(!orphan_lock.exists());
        drop(held);
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_sweep_leaves_alone_roots_open_to_others_and_links() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("solanum-sweep-test-{}", random_hex(6)));
        std::fs::create_dir_all(&base).unwrap();
        let open = dead_root(&base, &format!("solanum-{}", random_hex(12)));
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        let target = dead_root(&base, "elsewhere");
        let link = base.join(format!("solanum-{}", random_hex(12)));
        std::os::unix::fs::symlink(&target, &link).unwrap();
        drop(create_root_lock(&lock_path_of(&link)).unwrap());

        assert!(sweep_stale_roots(&base).is_empty());
        assert!(open.join(session_dir_name("s1")).join("aaaa0001").exists());
        assert!(target.join(session_dir_name("s1")).join("aaaa0001").exists(), "a link is not followed");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Quitting: the root goes when every copy was in sync; a copy with
    /// changes that were not uploaded stays, and the next start lists it once.
    #[tokio::test(flavor = "multi_thread")]
    async fn quitting_removes_the_root_unless_a_copy_is_kept() {
        let mut t = Setup::new(&[("/srv/clean.conf", b"v0"), ("/srv/kept.conf", b"v0")]);
        t.open("/srv/clean.conf").await.unwrap();
        for task in t.edits.stop_all(StopReason::AppClosed) {
            task.await.unwrap();
        }
        t.edits.release_root();
        assert_eq!(std::fs::read_dir(&t.base).unwrap().count(), 0, "neither the root nor its lock is left");

        let kept = t.open("/srv/kept.conf").await.unwrap();
        t.server.fail_stores.store(true, Ordering::SeqCst);
        std::fs::write(&kept.path, b"not uploaded").unwrap();
        t.next(StatusKind::Failed, "/srv/kept.conf").await;
        for task in t.edits.stop_all(StopReason::AppClosed) {
            task.await.unwrap();
        }
        let stopped = t.next(StatusKind::StoppedKept, "/srv/kept.conf").await;
        assert!(stopped.message.contains("Solanum was closed"), "{}", stopped.message);
        t.edits.release_root();
        assert_eq!(std::fs::read(&kept.path).unwrap(), b"not uploaded");

        let next_start = LiveEdits::new_in(t.base.clone(), DEBOUNCE);
        next_start.sweep_at_start();
        assert_eq!(next_start.take_leftovers().await, std::slice::from_ref(&kept.path));
        assert!(next_start.take_leftovers().await.is_empty(), "listed once");
        assert_eq!(std::fs::read(&kept.path).unwrap(), b"not uploaded");
    }

    // --- the server a copy came from (N-012) ---

    /// The server's address was edited and the tab reconnected under the
    /// same session id: saves are not uploaded there, the copy is kept, and
    /// opening the file again does not fetch the other server's version.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_session_that_now_reaches_another_server_gets_no_uploads() {
        let mut t = Setup::new(&[("/etc/app.conf", b"from a")]);
        let opened = t.open("/etc/app.conf").await.unwrap();
        *lock(&t.server.target) = server("me@b.example:22", "key-b");
        std::fs::write(&opened.path, b"edited for a").unwrap();
        let failed = t.next(StatusKind::Failed, "/etc/app.conf").await;
        assert!(failed.message.contains("me@a.example:22") && failed.message.contains("me@b.example:22"), "{}", failed.message);
        assert_eq!(t.server.stores.load(Ordering::SeqCst), 0, "nothing goes to the other server");
        let again = t.open("/etc/app.conf").await.err().expect("not refreshed from the other server");
        assert!(again.contains("Disconnect"), "{again}");
        assert_eq!(std::fs::read(&opened.path).unwrap(), b"edited for a");

        for task in t.edits.stop_session("s1", StopReason::Disconnected) {
            task.await.unwrap();
        }
        let stopped = t.next(StatusKind::StoppedKept, "/etc/app.conf").await;
        assert_eq!(stopped.kept.as_deref(), Some(opened.path.as_path()), "the copy is kept");
    }

    /// The same address presenting another host key is another server too.
    #[tokio::test(flavor = "multi_thread")]
    async fn another_host_key_at_the_same_address_gets_no_uploads() {
        let mut t = Setup::new(&[("/etc/app.conf", b"v0")]);
        let opened = t.open("/etc/app.conf").await.unwrap();
        *lock(&t.server.target) = server("me@a.example:22", "key-other");
        std::fs::write(&opened.path, b"v1").unwrap();
        let failed = t.next(StatusKind::Failed, "/etc/app.conf").await;
        assert!(failed.message.contains("another host key"), "{}", failed.message);
        assert_eq!(t.server.stores.load(Ordering::SeqCst), 0);
        t.stop().await;
    }

    /// A reconnect to the same server (the connection drops, auto-reconnect
    /// brings it back) carries on: a save while it is down is retried.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reconnect_to_the_same_server_keeps_syncing() {
        let mut t = Setup::new(&[("/etc/app.conf", b"v0")]);
        let opened = t.open("/etc/app.conf").await.unwrap();
        let same = lock(&t.server.target).clone();
        *lock(&t.server.target) = None;
        std::fs::write(&opened.path, b"saved while down").unwrap();
        let failed = t.next(StatusKind::Failed, "/etc/app.conf").await;
        assert!(failed.message.contains("not connected"), "{}", failed.message);
        *lock(&t.server.target) = same;
        std::fs::write(&opened.path, b"saved again").unwrap();
        t.next(StatusKind::Synced, "/etc/app.conf").await;
        assert_eq!(t.server_file("/etc/app.conf"), b"saved again");
        t.stop().await;
    }

    /// Without a known server nothing is opened.
    #[tokio::test(flavor = "multi_thread")]
    async fn no_open_without_a_known_server() {
        let t = Setup::new(&[("/etc/app.conf", b"v0")]);
        *lock(&t.server.target) = None;
        assert!(t.open("/etc/app.conf").await.is_err());
        assert!(lock(&t.edits.inner).entries.is_empty());
    }
}
