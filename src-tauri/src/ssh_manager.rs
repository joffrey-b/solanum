use russh::client;
use russh::keys::{HashAlg, PublicKey, PublicKeyOrCertificate};
use std::collections::HashMap;
use std::sync::Arc;
use tauri::{AppHandle, Emitter};
use tokio::sync::{mpsc, oneshot, Mutex};

/// The fingerprint string kept in `known_hosts`: base64 without padding of the
/// SHA-256 of the public-key blob, i.e. `ssh-keygen -lf` output minus the
/// `SHA256:` prefix. This is exactly what russh-keys 0.40 produced, so vaults
/// written before the russh upgrade must keep matching (a different format
/// would flag every saved host as a changed key).
pub fn host_key_fingerprint(key: &PublicKey) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD
        .encode(key.fingerprint(HashAlg::Sha256).as_bytes())
}

/// Host-key algorithm label stored next to a fingerprint. An RSA key can be
/// offered under several signature names (`rsa-sha2-512`, `rsa-sha2-256`,
/// `ssh-rsa`) but is one key, so they all collapse to `ssh-rsa`.
pub fn normalize_host_key_label(label: &str) -> String {
    if label == "ssh-rsa" || label.starts_with("rsa-sha2-") {
        "ssh-rsa".to_string()
    } else {
        label.to_string()
    }
}

pub fn host_key_label(key: &PublicKey) -> String {
    normalize_host_key_label(key.algorithm().as_str())
}

/// What a public-key attempt came to.
#[derive(Debug)]
pub enum KeyAttempt {
    /// The server answered: success, or a failure saying whether the key was
    /// accepted as one step of several and what it wants next.
    Answered(client::AuthResult),
    /// An RSA key, and the server takes RSA keys only with SHA-1 signatures
    /// (it announces no `rsa-sha2-*`). Not sent without the server's legacy
    /// setting, as OpenSSH 8.8+ does (owner decision).
    NeedsSha1,
}

impl KeyAttempt {
    /// For tests: logins go through `ssh_connect::authenticate`, monitors too.
    #[cfg(test)]
    pub fn success(&self) -> bool {
        matches!(self, KeyAttempt::Answered(r) if r.success())
    }
}

/// Public-key authentication. For RSA the signature hash comes from what the
/// server advertised (`server-sig-algs`); a server that advertises no
/// `rsa-sha2-*` only knows the SHA-1 `ssh-rsa`, which is used only when
/// `allow_sha1` (the server's legacy setting) says so. Other key types ignore
/// the hash.
pub async fn authenticate_with_key<H: client::Handler>(
    session: &mut client::Handle<H>,
    user: &str,
    key: Arc<russh::keys::PrivateKey>,
    allow_sha1: bool,
) -> Result<KeyAttempt, russh::Error> {
    let hash = if key.algorithm().is_rsa() {
        match session.best_supported_rsa_hash().await?.flatten() {
            Some(hash) => Some(hash),
            None if allow_sha1 => None,
            None => return Ok(KeyAttempt::NeedsSha1),
        }
    } else {
        None
    };
    let key = russh::keys::PrivateKeyWithHashAlg::new(key, hash);
    Ok(KeyAttempt::Answered(session.authenticate_publickey(user, key).await?))
}

/// Logged when an RSA key was not used because only SHA-1 would do.
pub const NEEDS_SHA1_RSA: &str = "The server accepts RSA keys only with SHA-1 signatures (ssh-rsa), so the key was not used. Turn on \u{201c}Allow legacy algorithms\u{201d} in this server's settings to log in with it.";

/// Per-terminal command. We deliberately split data from resize at the
/// channel level: keystrokes flow through `Data` on an mpsc, while resizes
/// land in a tokio::sync::watch (last-wins, coalesces a 60Hz drag burst
/// into one effective resize). Keeping them on the same FIFO mpsc meant
/// typed bytes could queue behind dozens of resize events during a
/// window drag — visible as keystrokes arriving seconds late.
pub enum TerminalCommand {
    Data(Vec<u8>),
    /// Output bytes the window has processed (`terminal_io::MAX_UNACKED`).
    Ack(usize),
}

#[derive(Clone, Copy, Debug)]
pub struct PtySize {
    pub cols: u32,
    pub rows: u32,
}

pub(crate) type TerminalTxs = Arc<Mutex<HashMap<String, mpsc::Sender<TerminalCommand>>>>;
pub(crate) type ResizeTxs = Arc<Mutex<HashMap<String, tokio::sync::watch::Sender<PtySize>>>>;

/// A terminal whose task ended by itself (the shell exited, the channel
/// closed) forgets its input and resize senders, which stayed in the maps
/// until the tab was closed. The task drops its receivers first, so only its
/// own entries read as closed: a terminal restarted under the same id
/// meanwhile (R to restart) keeps its own.
pub(crate) async fn forget_ended_terminal(txs: &TerminalTxs, resizes: &ResizeTxs, terminal_id: &str) {
    {
        let mut txs = txs.lock().await;
        if txs.get(terminal_id).is_some_and(|tx| tx.is_closed()) {
            txs.remove(terminal_id);
        }
    }
    let mut resizes = resizes.lock().await;
    if resizes.get(terminal_id).is_some_and(|tx| tx.is_closed()) {
        resizes.remove(terminal_id);
    }
}

/// The terminals of `session_id` still running. Terminal ids are
/// `<session id>-term-<n>` (SessionView.tsx); the `-term-` keeps `session-1`
/// from counting the terminals of `session-10`.
pub(crate) async fn terminals_left(txs: &TerminalTxs, session_id: &str) -> usize {
    let prefix = format!("{session_id}-term-");
    txs.lock().await.iter().filter(|(id, tx)| id.starts_with(&prefix) && !tx.is_closed()).count()
}

/// Sends a coalesced batch of PTY output as one `terminal-output-{id}` event.
///
/// `terminal_io::pump` accumulates output and calls this on an ~8ms timer or a
/// size cap instead of emitting once per SSH packet. Two problems that fixes:
/// a firehose (`cat` of a big file) used to emit thousands of tiny events —
/// each a Tauri IPC dispatch the WebView main thread had to service — and each
/// `Vec<u8>` payload serialized as a JSON number array (`[104,105,...]`),
/// roughly 4x the bytes. Together they saturated the main thread and froze the
/// whole terminal tab until it was closed. Batching cuts the event count, and
/// base64 (~1.33x) keeps each payload compact. Bytes are sent (not a decoded
/// string) so xterm can buffer a multibyte sequence split across batches.
pub fn emit_terminal_batch(app: &AppHandle, terminal_id: &str, bytes: &[u8]) {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let _ = app.emit(&format!("terminal-output-{}", terminal_id), b64);
}

/// Opens the "Always save terminal output to file" log for a newly-opened
/// terminal, if the frontend asked for one (`path`; `None` or empty: no log).
/// The full path (sanitized server name, timestamp, directory) is built on
/// the frontend — see src/util/sessionLogging.ts — and
/// `local_path::create_session_log` creates it as a new owner-only `.log`
/// file (never an existing file, never in a protected folder). `Err` says why
/// it could not be started (missing permissions, a deleted directory, a full
/// disk, a refused path): a broken log never stops the terminal itself from
/// opening; it runs without one and shows the reason (N-007).
pub async fn open_session_log(path: &Option<String>) -> Result<Option<tokio::fs::File>, String> {
    let Some(path) = path.as_ref().filter(|p| !p.trim().is_empty()) else {
        return Ok(None);
    };
    let path = std::path::PathBuf::from(path);
    match tokio::task::spawn_blocking(move || crate::local_path::create_session_log(&path)).await {
        Ok(Ok(file)) => Ok(Some(tokio::fs::File::from_std(file))),
        Ok(Err(e)) => {
            eprintln!("[session-log] not logging this session: {}", e);
            Err(e)
        }
        Err(e) => {
            eprintln!("[session-log] not logging this session: {}", e);
            Err(e.to_string())
        }
    }
}

/// The log for a terminal being opened, and what its command returns to the
/// window when it could not be started.
pub async fn start_session_log(path: &Option<String>) -> (Option<tokio::fs::File>, Option<String>) {
    match open_session_log(path).await {
        Ok(log) => (log, None),
        Err(e) => (None, Some(format!("This terminal is not being saved to a file: {e}"))),
    }
}

/// Appends to an open session log, if there is one. Write failures are
/// swallowed the same way open_session_log's are — a disk filling up
/// mid-session must not kill the terminal, just silently stop logging from
/// that point on (the `take()` drops and closes the handle so we don't keep
/// retrying a broken destination on every subsequent byte).
pub async fn write_session_log(log: &mut Option<tokio::fs::File>, data: &[u8]) {
    use tokio::io::AsyncWriteExt;
    let Some(f) = log.as_mut() else { return };
    if f.write_all(data).await.is_err() {
        log.take();
    }
}

/// Pending keyboard-interactive answers by connect nonce (see `SshState::kbi_txs`).
pub type KbiTxs = Arc<Mutex<HashMap<String, oneshot::Sender<Option<Vec<String>>>>>>;

pub struct SshState {
    pub fp_txs: Arc<Mutex<HashMap<String, oneshot::Sender<bool>>>>,
    /// Pending keyboard-interactive (2FA / OTP) prompt responses, keyed by the
    /// same per-connect nonce as `fp_txs`. The value is `Some(answers)` when
    /// the user submits, or `None` when they cancel. A server can issue several
    /// sequential InfoRequests in one auth, so the connect worker re-inserts a
    /// fresh sender under the nonce for each round; `submit_kbi_response`
    /// removes-and-sends. Separate map from `fp_txs` because the two prompts
    /// never overlap in time (host-key check runs during the handshake,
    /// keyboard-interactive runs during auth) but carry different value types.
    pub kbi_txs: KbiTxs,
    pub connections: Arc<Mutex<HashMap<String, Arc<Mutex<client::Handle<ClientHandler>>>>>>,
    /// ProxyJump bastion handles, keyed by the TARGET session_id. Each target
    /// session that routes through a jump host stows the jump's live `Handle`
    /// here purely to keep it (and thus the direct-tcpip channel carrying the
    /// target's transport) alive for the session's lifetime. Removed — and so
    /// dropped/closed — on reconnect teardown, disconnect, and profile close.
    pub jump_connections: Arc<Mutex<HashMap<String, client::Handle<ClientHandler>>>>,
    pub terminal_txs: TerminalTxs,
    /// Per-terminal "last requested PTY size" watch. The PTY task selects
    /// on this in parallel with `terminal_txs` and forwards `window_change`
    /// to the server. Using a watch (last-wins) means a 60Hz resize burst
    /// during a window drag collapses to a single SSH message instead of
    /// dozens, AND the keystroke FIFO can't be blocked behind resizes.
    pub resize_txs: ResizeTxs,
    pub sftp_sessions: Arc<Mutex<HashMap<String, Arc<russh_sftp::client::SftpSession>>>>,
    /// Active SSH port-forwards keyed by tunnel id. See `crate::tunnel`.
    pub tunnels: Arc<Mutex<HashMap<String, crate::tunnel::ActiveTunnel>>>,
    /// For each connected session, the map of server ports we've asked the
    /// server to forward back to us. Populated by `tunnel::start_tunnel` for
    /// "R" tunnels and consulted by `ClientHandler` when a forwarded channel
    /// arrives.
    pub forwarded_targets: Arc<Mutex<HashMap<String, crate::tunnel::ForwardedTargets>>>,
    /// One AtomicBool per in-flight SFTP transfer, keyed by transfer id.
    /// `sftp_cancel_transfer` flips the flag; the chunked read/write loops
    /// in `sftp_download_file` / `sftp_upload_file` poll it each iteration
    /// and bail out with a cancelled-status event when it goes true.
    pub transfer_cancels: Arc<Mutex<HashMap<String, Arc<std::sync::atomic::AtomicBool>>>>,
    /// Per-session tunnel spec memory. Survives reconnect cycles so that
    /// `initiate_connection` can re-establish every forward the user had
    /// open — including ad-hoc ones not in the saved server row.
    pub session_tunnel_specs: Arc<Mutex<HashMap<String, Vec<crate::tunnel::TunnelSpec>>>>,
    /// Monotonic generation counter, bumped on every successful
    /// `initiate_connection` for a given session_id. The disconnect-watcher
    /// task captures the value at spawn time and bails out silently if it
    /// sees a newer generation — that's how we keep a stale watcher from
    /// double-firing `session-disconnected-{id}` after the user has
    /// already reconnected.
    pub session_generation: Arc<Mutex<HashMap<String, u64>>>,
    /// The Info tab's probes per session (`crate::InfoProbes`): at most two
    /// of them at a time on the connection, and the live status strip's
    /// previous snapshot (for CPU% and network rates) behind one lock (F-039).
    /// Removed on disconnect so a reconnect's first sample correctly reports
    /// "no previous sample yet" instead of diffing against a snapshot from a
    /// dead connection.
    pub(crate) info_probes: Arc<Mutex<HashMap<String, Arc<crate::InfoProbes>>>>,
    /// Remote files open for live edit, their staging copies and the watcher
    /// that uploads their saves. Stopped per session on disconnect and all
    /// together on profile close.
    pub(crate) live_edits: Arc<crate::live_edit::LiveEdits>,
    /// Docker live-log streams, each tied to its session (F-041).
    pub(crate) docker_streams: crate::docker::DockerStreams,
    /// The server each connection key reached (user, address, host key),
    /// recorded when it registers; live edit uploads only to the server a
    /// copy came from (N-012). A std mutex: never held across an await.
    pub(crate) session_targets: Arc<std::sync::Mutex<HashMap<String, crate::live_edit::ServerIdentity>>>,
    /// What each connection key's server allows beside its terminal. A std
    /// mutex: never held across an await.
    pub(crate) channel_gates: crate::ChannelGateMap,
    /// Bumped when a profile teardown starts and again when it ends (F-013).
    pub(crate) profile_epoch: Arc<std::sync::atomic::AtomicU64>,
}

/// The profile epoch seen when some work for the open profile started. Work
/// that outlives a teardown (a connect still handshaking, a tunnel replay
/// list being written, a local shell whose confirmation was answered late)
/// checks it before leaving anything behind: once a teardown has begun, the
/// result would belong to no profile, or to the next one.
#[derive(Clone)]
pub(crate) struct ProfileEpoch {
    counter: Arc<std::sync::atomic::AtomicU64>,
    seen: u64,
}

impl ProfileEpoch {
    pub(crate) fn current(&self) -> bool {
        self.counter.load(std::sync::atomic::Ordering::SeqCst) == self.seen
    }

    /// A teardown was running when this was taken (the epoch is bumped once
    /// at its start and once at its end): nothing new may start.
    pub(crate) fn closing(&self) -> bool {
        self.seen % 2 == 1
    }
}

/// Refused while the profile is being locked.
pub(crate) const PROFILE_CLOSING_MSG: &str = "[STATE] PROFILE_CLOSING: the profile is being locked";

impl SshState {
    pub fn new() -> Self {
        Self {
            fp_txs: Arc::new(Mutex::new(HashMap::new())),
            kbi_txs: Arc::new(Mutex::new(HashMap::new())),
            connections: Arc::new(Mutex::new(HashMap::new())),
            jump_connections: Arc::new(Mutex::new(HashMap::new())),
            terminal_txs: Arc::new(Mutex::new(HashMap::new())),
            resize_txs: Arc::new(Mutex::new(HashMap::new())),
            sftp_sessions: Arc::new(Mutex::new(HashMap::new())),
            tunnels: Arc::new(Mutex::new(HashMap::new())),
            forwarded_targets: Arc::new(Mutex::new(HashMap::new())),
            transfer_cancels: Arc::new(Mutex::new(HashMap::new())),
            session_tunnel_specs: Arc::new(Mutex::new(HashMap::new())),
            session_generation: Arc::new(Mutex::new(HashMap::new())),
            info_probes: Arc::new(Mutex::new(HashMap::new())),
            live_edits: Arc::new(crate::live_edit::LiveEdits::new()),
            docker_streams: crate::docker::DockerStreams::new(),
            session_targets: Arc::new(std::sync::Mutex::new(HashMap::new())),
            channel_gates: Arc::new(std::sync::Mutex::new(HashMap::new())),
            profile_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// The gate of a connection key. One that is not registered has no
    /// connection either, and fails on that before any channel is asked for.
    pub(crate) fn channel_gate(&self, key: &str) -> Arc<crate::ssh_connect::ChannelGate> {
        crate::channel_gate_of(&self.channel_gates, key)
    }

    pub(crate) fn epoch(&self) -> ProfileEpoch {
        ProfileEpoch { counter: Arc::clone(&self.profile_epoch), seen: self.profile_epoch.load(std::sync::atomic::Ordering::SeqCst) }
    }

    /// A teardown begins or ends: everything started before is out of date.
    pub(crate) fn next_epoch(&self) {
        self.profile_epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// How the host-key check of one connection attempt ended. Kept by the
/// handler and read by the connect driver when the handshake fails, so every
/// refusal gets its own message instead of a generic one (F-078).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum HostKeyOutcome {
    /// The check never ran (the handshake failed before it).
    NotReached = 0,
    /// The key was on file.
    Trusted,
    /// The user accepted the key and it was saved.
    Accepted,
    /// The user accepted the key, but saving it failed.
    AcceptedNotSaved,
    /// The user refused the key.
    Rejected,
    /// Nobody answered the prompt within its 90 s.
    PromptTimedOut,
    /// The prompt was withdrawn: the connection attempt ended meanwhile.
    Withdrawn,
    /// The server presented a host-key certificate.
    Certificate,
    /// The saved host keys could not be read (or no profile is open).
    StoreUnavailable,
    /// There was no way to ask the user.
    NoPrompt,
}

impl HostKeyOutcome {
    const ALL: [HostKeyOutcome; 10] = [
        HostKeyOutcome::NotReached,
        HostKeyOutcome::Trusted,
        HostKeyOutcome::Accepted,
        HostKeyOutcome::AcceptedNotSaved,
        HostKeyOutcome::Rejected,
        HostKeyOutcome::PromptTimedOut,
        HostKeyOutcome::Withdrawn,
        HostKeyOutcome::Certificate,
        HostKeyOutcome::StoreUnavailable,
        HostKeyOutcome::NoPrompt,
    ];

    /// Why the connection was refused, when the host key is the reason.
    pub(crate) fn refusal(self) -> Option<&'static str> {
        match self {
            HostKeyOutcome::NotReached
            | HostKeyOutcome::Trusted
            | HostKeyOutcome::Accepted
            | HostKeyOutcome::AcceptedNotSaved => None,
            HostKeyOutcome::Rejected => Some("Host key was not approved. Reconnect to see the fingerprint prompt again."),
            HostKeyOutcome::PromptTimedOut => Some("The fingerprint prompt was not answered within 90 seconds. Reconnect to see it again."),
            HostKeyOutcome::Withdrawn => Some("The fingerprint prompt was withdrawn because the connection attempt ended. Reconnect to see it again."),
            HostKeyOutcome::Certificate => Some("The server presented a host-key certificate, which Solanum does not support."),
            HostKeyOutcome::StoreUnavailable => Some("The saved host keys could not be read, so the server's key could not be checked and the connection was refused. Lock and unlock the profile, or restart Solanum."),
            HostKeyOutcome::NoPrompt => Some("The server's key could not be shown for approval. Reconnect to try again."),
        }
    }
}

/// The handler's [`HostKeyOutcome`], shared with the connect driver.
#[derive(Debug, Default)]
pub struct OutcomeCell(std::sync::atomic::AtomicU8);

impl OutcomeCell {
    pub(crate) fn set(&self, outcome: HostKeyOutcome) {
        self.0.store(outcome as u8, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn get(&self) -> HostKeyOutcome {
        let v = self.0.load(std::sync::atomic::Ordering::SeqCst);
        HostKeyOutcome::ALL.into_iter().find(|o| *o as u8 == v).unwrap_or(HostKeyOutcome::NotReached)
    }
}

/// What `known_hosts` says about the key a server offered.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KnownHost {
    /// This exact key is on file.
    Trusted,
    /// Another key of the same type is on file: the key changed. Rows from
    /// before key types were recorded (`key_type` NULL) count as the same
    /// type, so a real change is never downgraded to a first contact.
    Changed { prior: Vec<String> },
    /// The host is on file only with keys of other types, as
    /// (type, fingerprint) pairs. Since those types are asked for first
    /// (`ssh_connect::host_key_order`), a server that still had such a key
    /// would have used it (F-029).
    OtherTypes { others: Vec<(String, String)> },
    Unknown,
}

/// Looks the offered key up. Fails closed: an error reading the table, or no
/// open profile, is an `Err` that the caller refuses the connection on,
/// never "unknown host", which would turn a changed key into an ordinary
/// first-contact prompt (F-075).
pub(crate) fn lookup_known_host(
    conn: Option<&rusqlite::Connection>,
    host: &str,
    port: u16,
    fingerprint: &str,
    key_type: &str,
) -> Result<KnownHost, String> {
    let conn = conn.ok_or_else(|| "no profile is open".to_string())?;
    let mut stmt = conn
        .prepare("SELECT fingerprint, key_type FROM known_hosts WHERE host=?1 AND port=?2")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map(rusqlite::params![host, port], |r| {
            Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?))
        })
        .map_err(|e| e.to_string())?;
    let mut prior = Vec::new();
    let mut others = Vec::new();
    for row in rows {
        let (saved_fp, saved_type) = row.map_err(|e| e.to_string())?;
        let Some(saved_fp) = saved_fp else { continue };
        if saved_fp == fingerprint {
            return Ok(KnownHost::Trusted);
        }
        match saved_type.map(|t| normalize_host_key_label(&t)) {
            Some(t) if t != key_type => others.push((t, saved_fp)),
            _ => prior.push(saved_fp),
        }
    }
    Ok(if !prior.is_empty() {
        KnownHost::Changed { prior }
    } else if !others.is_empty() {
        KnownHost::OtherTypes { others }
    } else {
        KnownHost::Unknown
    })
}

/// The host-key types on file for a host and port, for the order in which a
/// connection asks for them (`ssh_connect::AlgorithmPolicy`).
pub(crate) fn known_key_types(conn: &rusqlite::Connection, host: &str, port: u16) -> rusqlite::Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT key_type FROM known_hosts WHERE host=?1 AND port=?2 AND key_type IS NOT NULL",
    )?;
    let types = stmt.query_map(rusqlite::params![host, port], |r| r.get::<_, String>(0))?;
    let mut out: Vec<String> = Vec::new();
    for t in types {
        let t = normalize_host_key_label(&t?);
        if !out.contains(&t) {
            out.push(t);
        }
    }
    Ok(out)
}

/// Saves an accepted key in one transaction. `replace_same_type` first
/// removes the keys of the same type (and untyped legacy rows) it replaces;
/// keys of other types stay, as in OpenSSH. On any error nothing changes.
pub(crate) fn store_host_key(
    conn: &rusqlite::Connection,
    host: &str,
    port: u16,
    fingerprint: &str,
    key_type: &str,
    replace_same_type: bool,
) -> rusqlite::Result<()> {
    conn.execute_batch("BEGIN")?;
    let written = (|| {
        if replace_same_type {
            conn.execute(
                "DELETE FROM known_hosts WHERE host=?1 AND port=?2 AND (key_type=?3 OR key_type IS NULL)",
                rusqlite::params![host, port, key_type],
            )?;
        }
        conn.execute(
            "INSERT INTO known_hosts (host, port, fingerprint, key_type) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![host, port, fingerprint, key_type],
        )?;
        conn.execute_batch("COMMIT")
    })();
    if written.is_err() {
        let _ = conn.execute_batch("ROLLBACK");
    }
    written
}

pub struct ClientHandler {
    pub app: AppHandle,
    pub session_id: String,
    /// Per-connect-attempt random nonce. Used as the key for the
    /// fingerprint-approval oneshot channel so a stale "accept" from a
    /// prior attempt (or a malicious frontend message that knows only
    /// `session_id`) cannot satisfy the prompt for a fresh connection.
    /// Echoed in the `fingerprint-prompt-{session_id}` event payload and
    /// must be sent back by the frontend in `verify_fingerprint_response`.
    pub connect_nonce: String,
    pub server_host: String,
    pub server_port: u16,
    pub db: Arc<std::sync::Mutex<Option<rusqlite::Connection>>>,
    pub fp_rx: Option<oneshot::Receiver<bool>>,
    /// Per-session map populated by R tunnels — when the server pushes a
    /// `forwarded-tcpip` channel back, we look the port up here to find the
    /// local target to bridge it to.
    pub forwarded_targets: crate::tunnel::ForwardedTargets,
    /// How the host-key check ended, written by `check_server_key`. The
    /// connect driver reads it when `connect_stream` fails, so a refused,
    /// expired or unreadable host key is reported as such instead of as a
    /// network drop or an algorithm mismatch.
    pub fp_outcome: Arc<OutcomeCell>,
    /// True while the host-key prompt waits for the user. The connect driver
    /// (`ssh_connect::handshake_within`) stops the handshake clock meanwhile,
    /// so the prompt's own 90 s bound is the only one that applies to it.
    pub prompt_open: Arc<tokio::sync::watch::Sender<bool>>,
    /// Set once the "weak algorithms in use" line was logged, so a re-key
    /// does not repeat it.
    pub weak_reported: bool,
    /// The server's legacy setting: without it `ssh-rsa` host keys are
    /// asked for only with SHA-2 signatures, which a server older than
    /// OpenSSH 7.2 cannot make (see the "different key type" prompt).
    pub legacy_algorithms: bool,
    /// The fingerprint of the host key this connection trusted (on file or
    /// accepted by the user): part of the server identity live edit checks
    /// before every upload (N-012).
    pub accepted_key: Arc<std::sync::Mutex<Option<String>>>,
    /// What this connection's server allows beside its terminal; its
    /// identification string goes in here.
    pub(crate) channel_gate: Arc<crate::ssh_connect::ChannelGate>,
    /// How the connection ended, for the health watcher.
    pub(crate) ended_because: Arc<std::sync::Mutex<Option<crate::ssh_connect::ConnectionEnd>>>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, offered: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let log = |msg: &str, ty: &str| {
            let _ = self.app.emit(&format!("session-log-{}", self.session_id), serde_json::json!({ "msg": msg, "type": ty }));
        };
        // We never advertise host-key certificates, so one showing up is
        // unexpected: refuse rather than guess whether to trust it.
        let server_public_key = match offered {
            PublicKeyOrCertificate::PublicKey { key, .. } => key,
            PublicKeyOrCertificate::Certificate(_) => {
                log("Server presented a host-key certificate, which is not supported. Refusing.", "error");
                self.fp_outcome.set(HostKeyOutcome::Certificate);
                return Ok(false);
            }
        };
        let fp_str = host_key_fingerprint(server_public_key);
        let key_type = host_key_label(server_public_key);
        log(&format!("Server offered key ({}): {}", key_type, fp_str), "info");

        // The std mutex guard must not cross an `.await`, hence the scope.
        // Any failure to read is a refusal (fail closed).
        let verdict = match self.db.lock() {
            Ok(guard) => lookup_known_host(guard.as_ref(), &self.server_host, self.server_port, &fp_str, &key_type),
            Err(_) => Err("the database lock is poisoned".to_string()),
        };
        let verdict = match verdict {
            Ok(v) => v,
            Err(e) => {
                log(&format!("Could not read the saved host keys ({}). Refusing the connection rather than treating the host as new.", e), "error");
                self.fp_outcome.set(HostKeyOutcome::StoreUnavailable);
                return Ok(false);
            }
        };

        let (prior_fingerprints, other_types): (Vec<String>, Vec<(String, String)>) = match &verdict {
            KnownHost::Trusted => {
                log("Host fingerprint found in known_hosts database. Verified.", "success");
                self.fp_outcome.set(HostKeyOutcome::Trusted);
                *self.accepted_key.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fp_str);
                return Ok(true);
            }
            KnownHost::Changed { prior } => {
                // The SSH "REMOTE HOST IDENTIFICATION HAS CHANGED" moment.
                log("⚠ WARNING: Remote host key has CHANGED since you last connected. This could indicate a man-in-the-middle attack, or the server's host key was rotated. Verify out-of-band before accepting.", "error");
                (prior.clone(), Vec::new())
            }
            KnownHost::OtherTypes { others } => {
                let types: Vec<&str> = others.iter().map(|(t, _)| t.as_str()).collect();
                log(&format!(
                    "⚠ WARNING: This host is already trusted with a different key ({}), but it now presents a {} key. A server that still had its trusted key would normally have used it. This could indicate a man-in-the-middle attack, or the server's keys were replaced. Verify out-of-band before accepting.",
                    types.join(", "), key_type
                ), "error");
                if types.contains(&"ssh-rsa") && !self.legacy_algorithms {
                    log("If this server's RSA key was trusted while its legacy setting was on, an old server may only sign with SHA-1: turning the setting back on would bring the RSA key back.", "warn");
                }
                (Vec::new(), others.clone())
            }
            KnownHost::Unknown => {
                log("Host fingerprint is unknown. Waiting for user approval...", "warn");
                (Vec::new(), Vec::new())
            }
        };
        let mismatch = matches!(verdict, KnownHost::Changed { .. });
        let legacy_hint = matches!(&verdict, KnownHost::OtherTypes { others } if others.iter().any(|(t, _)| t == "ssh-rsa"))
            && !self.legacy_algorithms;

        let _ = self.app.emit(&format!("fingerprint-prompt-{}", self.session_id), serde_json::json!({
            "host": self.server_host,
            "keyType": key_type,
            "fingerprint": fp_str,
            "mismatch": mismatch,
            "priorFingerprints": prior_fingerprints,
            "otherTypes": other_types
                .iter()
                .map(|(t, f)| serde_json::json!({ "keyType": t, "fingerprint": f }))
                .collect::<Vec<_>>(),
            "legacyHint": legacy_hint,
            // Frontend MUST echo this back via verify_fingerprint_response.
            // Without it the response is rejected. Defeats stale-channel /
            // session-id-guessing attacks against the TOFU prompt.
            "nonce": self.connect_nonce,
        }));
        // Carries the nonce, so the UI closes only this attempt's prompt.
        let dismiss = || {
            let _ = self.app.emit(
                &format!("fingerprint-prompt-dismiss-{}", self.session_id),
                serde_json::json!({ "nonce": self.connect_nonce }),
            );
        };

        let Some(rx) = self.fp_rx.take() else {
            log("The host key could not be shown for approval. Refusing.", "error");
            dismiss();
            self.fp_outcome.set(HostKeyOutcome::NoPrompt);
            return Ok(false);
        };
        // 90s is enough for a human to read the prompt, switch windows to
        // verify the fingerprint out-of-band, and click. The handshake
        // deadline is paused for exactly this wait.
        let prompt_open = Arc::clone(&self.prompt_open);
        let answer = {
            let _open = crate::ssh_connect::PromptOpen::new(&prompt_open);
            tokio::time::timeout(tokio::time::Duration::from_secs(90), rx).await
        };
        match answer {
            Ok(Ok(true)) => {
                // A changed key replaces the same-type rows it changes,
                // otherwise the next connection would still see "any row
                // matches the OLD fingerprint = trusted". Keys of other types
                // stay on file (owner decision, OpenSSH semantics).
                let saved = match self.db.lock() {
                    Ok(guard) => match guard.as_ref() {
                        Some(conn) => store_host_key(conn, &self.server_host, self.server_port, &fp_str, &key_type, mismatch)
                            .map_err(|e| e.to_string()),
                        None => Err("no profile is open".to_string()),
                    },
                    Err(_) => Err("the database lock is poisoned".to_string()),
                };
                match saved {
                    Ok(()) => {
                        log(match verdict {
                            KnownHost::Changed { .. } => "New host key accepted. Old entries replaced.",
                            KnownHost::OtherTypes { .. } => "Host key accepted and saved next to the key already on file.",
                            _ => "Host key accepted and saved.",
                        }, "success");
                        self.fp_outcome.set(HostKeyOutcome::Accepted);
                    }
                    Err(e) => {
                        log(&format!("Host key accepted for this connection, but it could not be saved ({}). You will be asked again next time.", e), "warn");
                        self.fp_outcome.set(HostKeyOutcome::AcceptedNotSaved);
                    }
                }
                *self.accepted_key.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(fp_str);
                Ok(true)
            }
            Ok(Ok(false)) => {
                log("Host key rejected by user.", "error");
                dismiss();
                self.fp_outcome.set(HostKeyOutcome::Rejected);
                Ok(false)
            }
            Err(_) => {
                log("Host key verification timed out (no response from user within 90 seconds).", "error");
                dismiss();
                self.fp_outcome.set(HostKeyOutcome::PromptTimedOut);
                Ok(false)
            }
            Ok(Err(_)) => {
                log("Host key verification withdrawn: the connection attempt ended.", "error");
                dismiss();
                self.fp_outcome.set(HostKeyOutcome::Withdrawn);
                Ok(false)
            }
        }
    }

    /// Says so when the key exchange settled on a legacy algorithm (possible
    /// only for a server whose legacy setting is on, F-076). Since russh 0.65
    /// this runs after every key exchange, re-keys included (one an hour), so
    /// each notice here must be said once per connection: `weak_reported`, and
    /// `note_server_ident`, which is true only when it sets the limit.
    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        if self.channel_gate.note_server_ident(session.remote_sshid()) {
            let ident = crate::open_guard::visible_text(&String::from_utf8_lossy(session.remote_sshid()));
            let _ = self.app.emit(&format!("session-log-{}", self.session_id), serde_json::json!({
                "msg": format!("This server identifies as {}, a kind of device that allows one channel per connection. Opening a plain terminal only.", ident),
                "type": "warn"
            }));
        }
        if !self.weak_reported {
            let weak = crate::ssh_connect::weak_algorithms(
                names.kex.as_ref(),
                names.key.as_str(),
                [names.client_mac.as_ref(), names.server_mac.as_ref()],
            );
            if !weak.is_empty() {
                self.weak_reported = true;
                let _ = self.app.emit(&format!("session-log-{}", self.session_id), serde_json::json!({
                    "msg": format!("Weak algorithms in use for this connection (allowed by this server's legacy setting): {}.", weak.join(", ")),
                    "type": "warn"
                }));
            }
        }
        Ok(())
    }

    /// Inbound channel from a server-side `tcpip_forward` we set up earlier
    /// (remote tunnel, the SSH `-R` shape). The server has accepted an
    /// outside connection on `connected_port`; we just need to bridge that
    /// channel to a local TCP socket pointed at the user's chosen target.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        _connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let originator = (originator_address, originator_port);
        crate::tunnel::accept_forwarded_channel(&self.forwarded_targets, connected_port, originator, channel, reply).await;
        Ok(())
    }

    /// Keeps the reason for the health watcher, which reports the end of a
    /// connection; the return values are russh's defaults.
    async fn disconnected(&mut self, reason: client::DisconnectReason<Self::Error>) -> Result<(), Self::Error> {
        *self.ended_because.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(crate::ssh_connect::ConnectionEnd::from_reason(&reason));
        match reason {
            client::DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            client::DisconnectReason::Error(e) => Err(e),
        }
    }
}


#[cfg(test)]
mod known_host_tests {
    use super::*;

    fn vault() -> rusqlite::Connection {
        let conn = crate::open_vault_memory_db().unwrap();
        crate::create_vault_schema(&conn).unwrap();
        conn
    }

    fn row(conn: &rusqlite::Connection, fp: &str, key_type: Option<&str>) {
        conn.execute(
            "INSERT INTO known_hosts (host, port, fingerprint, key_type) VALUES ('h', 22, ?1, ?2)",
            rusqlite::params![fp, key_type],
        )
        .unwrap();
    }

    fn rows(conn: &rusqlite::Connection) -> Vec<(String, Option<String>)> {
        let mut stmt = conn.prepare("SELECT fingerprint, key_type FROM known_hosts ORDER BY id").unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
    }

    #[test]
    fn the_verdict_tells_trusted_changed_other_type_and_unknown_apart() {
        let conn = vault();
        assert_eq!(lookup_known_host(Some(&conn), "h", 22, "A", "ssh-ed25519").unwrap(), KnownHost::Unknown);
        row(&conn, "A", Some("ssh-ed25519"));
        assert_eq!(lookup_known_host(Some(&conn), "h", 22, "A", "ssh-ed25519").unwrap(), KnownHost::Trusted);
        // Same type, another key: changed.
        assert_eq!(
            lookup_known_host(Some(&conn), "h", 22, "B", "ssh-ed25519").unwrap(),
            KnownHost::Changed { prior: vec!["A".into()] }
        );
        // Another type only: not a first contact any more (F-029).
        assert_eq!(
            lookup_known_host(Some(&conn), "h", 22, "R", "ssh-rsa").unwrap(),
            KnownHost::OtherTypes { others: vec![("ssh-ed25519".into(), "A".into())] }
        );
        // Another port is another host.
        assert_eq!(lookup_known_host(Some(&conn), "h", 2222, "B", "ssh-ed25519").unwrap(), KnownHost::Unknown);
        // A legacy row without a type counts as the same type: a change.
        let conn = vault();
        row(&conn, "OLD", None);
        assert_eq!(
            lookup_known_host(Some(&conn), "h", 22, "R", "ssh-rsa").unwrap(),
            KnownHost::Changed { prior: vec!["OLD".into()] }
        );
        // An RSA key stored under a signature name is still an RSA key.
        let conn = vault();
        row(&conn, "R1", Some("rsa-sha2-512"));
        assert_eq!(
            lookup_known_host(Some(&conn), "h", 22, "R2", "ssh-rsa").unwrap(),
            KnownHost::Changed { prior: vec!["R1".into()] }
        );
    }

    /// F-075: an unreadable store or no open profile is never "unknown host".
    #[test]
    fn a_store_that_cannot_be_read_fails_closed() {
        assert!(lookup_known_host(None, "h", 22, "A", "ssh-ed25519").is_err());
        let no_table = crate::open_vault_memory_db().unwrap();
        assert!(lookup_known_host(Some(&no_table), "h", 22, "A", "ssh-ed25519").is_err());
    }

    #[test]
    fn saving_replaces_only_the_same_type_and_keeps_other_types() {
        let conn = vault();
        row(&conn, "A", Some("ssh-ed25519"));
        row(&conn, "OLD", None);
        row(&conn, "E", Some("ecdsa-sha2-nistp256"));
        store_host_key(&conn, "h", 22, "B", "ssh-ed25519", true).unwrap();
        assert_eq!(
            rows(&conn),
            vec![("E".into(), Some("ecdsa-sha2-nistp256".into())), ("B".into(), Some("ssh-ed25519".into()))]
        );
        // A new type is added next to what is there.
        store_host_key(&conn, "h", 22, "R", "ssh-rsa", false).unwrap();
        assert_eq!(rows(&conn).len(), 3);
    }

    /// F-075: a failed save reports the error and leaves the old keys alone.
    #[test]
    fn a_failed_save_changes_nothing() {
        let conn = vault();
        row(&conn, "A", Some("ssh-ed25519"));
        conn.execute_batch(
            "CREATE TRIGGER no_insert BEFORE INSERT ON known_hosts BEGIN SELECT RAISE(ABORT, 'refused'); END;",
        )
        .unwrap();
        assert!(store_host_key(&conn, "h", 22, "B", "ssh-ed25519", true).is_err());
        assert_eq!(rows(&conn), vec![("A".into(), Some("ssh-ed25519".into()))]);
        // The connection is usable afterwards (no transaction left open).
        conn.execute_batch("DROP TRIGGER no_insert").unwrap();
        store_host_key(&conn, "h", 22, "B", "ssh-ed25519", true).unwrap();
        assert_eq!(rows(&conn), vec![("B".into(), Some("ssh-ed25519".into()))]);
    }

    /// F-078: every refusal has its own reason; accepted keys have none.
    #[test]
    fn each_host_key_refusal_has_its_own_reason() {
        let cell = OutcomeCell::default();
        assert_eq!(cell.get(), HostKeyOutcome::NotReached);
        let mut reasons = Vec::new();
        for outcome in HostKeyOutcome::ALL {
            cell.set(outcome);
            assert_eq!(cell.get(), outcome);
            match outcome {
                HostKeyOutcome::NotReached
                | HostKeyOutcome::Trusted
                | HostKeyOutcome::Accepted
                | HostKeyOutcome::AcceptedNotSaved => assert_eq!(outcome.refusal(), None),
                _ => reasons.push(outcome.refusal().expect("a refusal has a reason")),
            }
        }
        let mut distinct = reasons.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(distinct.len(), reasons.len());
    }
}

#[cfg(test)]
mod terminal_entry_tests {
    use super::*;

    /// N-007: a log that cannot be started says why, for the terminal to show.
    #[tokio::test]
    async fn a_refused_session_log_says_why() {
        assert!(matches!(open_session_log(&None).await, Ok(None)));
        assert!(matches!(open_session_log(&Some("  ".into())).await, Ok(None)));
        let dir = std::env::temp_dir().join(format!("solanum-log-test-{:016x}", rand::random::<u64>()));
        let refused = dir.join("session.txt").to_string_lossy().into_owned();
        let err = open_session_log(&Some(refused)).await.unwrap_err();
        assert!(err.contains("must end in .log"), "{err}");
        let fine = dir.join("session.log").to_string_lossy().into_owned();
        assert!(matches!(open_session_log(&Some(fine)).await, Ok(Some(_))));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A terminal that ended by itself forgets its own entries, and never
    /// those of a terminal restarted under the same id.
    #[tokio::test]
    async fn an_ended_terminal_forgets_only_its_own_entries() {
        let txs: TerminalTxs = Arc::new(Mutex::new(HashMap::new()));
        let resizes: ResizeTxs = Arc::new(Mutex::new(HashMap::new()));
        let size = PtySize { cols: 80, rows: 24 };

        let (tx, rx) = mpsc::channel(1);
        let (resize, resize_rx) = tokio::sync::watch::channel(size);
        txs.lock().await.insert("t1".into(), tx);
        resizes.lock().await.insert("t1".into(), resize);
        drop((rx, resize_rx)); // the shell exited
        forget_ended_terminal(&txs, &resizes, "t1").await;
        assert!(txs.lock().await.is_empty() && resizes.lock().await.is_empty());

        // Restarted under the same id before the old task got to its end.
        let (new_tx, _new_rx) = mpsc::channel(1);
        let (new_resize, _new_resize_rx) = tokio::sync::watch::channel(size);
        txs.lock().await.insert("t1".into(), new_tx);
        resizes.lock().await.insert("t1".into(), new_resize);
        forget_ended_terminal(&txs, &resizes, "t1").await;
        assert!(txs.lock().await.contains_key("t1") && resizes.lock().await.contains_key("t1"), "the new terminal keeps its entries");
    }

    /// N-028: a session's terminals still running, and only that session's.
    #[tokio::test]
    async fn the_terminals_left_are_counted_per_session() {
        let txs: TerminalTxs = Arc::new(Mutex::new(HashMap::new()));
        let mut keep = Vec::new();
        for id in ["session-1-term-0", "session-1-term-1700000000000", "session-10-term-0", "session-1x"] {
            let (tx, rx) = mpsc::channel(1);
            txs.lock().await.insert(id.into(), tx);
            keep.push(rx);
        }
        assert_eq!(terminals_left(&txs, "session-1").await, 2);
        assert_eq!(terminals_left(&txs, "session-10").await, 1);
        drop(keep.remove(0)); // session-1-term-0 ended, not forgotten yet
        assert_eq!(terminals_left(&txs, "session-1").await, 1);
        assert_eq!(terminals_left(&txs, "session-2").await, 0);
    }
}
