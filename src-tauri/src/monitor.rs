//! Lightweight, polling-based monitoring for saved nodes.
//!
//! Each monitored node owns a dedicated SSH session — separate from any
//! interactive session the user may have open. A per-node poller task wakes
//! every `interval_secs`, runs a single composite script over an exec
//! channel, parses the output, and reports one sample with the resolved
//! metrics (`MonitorEvents`; the app's `monitor-sample-{node_id}` event).
//! The frontend keeps a short ring buffer per metric (~5 min) for sparklines.
//!
//! * The node is reached as a session reaches it: through its jump host
//!   (single hop, the jump host's own login and legacy setting), or its
//!   SOCKS5 / HTTP proxy, or directly (F-062).
//! * No prompts: both host keys must already be in `known_hosts`, and the
//!   login is the saved key or password (no keyboard-interactive).
//! * The login is read from the vault at every connect. Anything only the
//!   user can fix (no login, unreadable key, host key not trusted) stops
//!   the monitor at once, three refused logins in a row stop it too, until
//!   the user resumes it (F-017); network trouble is retried with backoff.
//! * Six built-in metrics plus custom commands, one round-trip per poll,
//!   output capped (F-018).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use std::future::Future;
use std::pin::Pin;

use russh::client;
use russh::keys::PublicKeyOrCertificate;
use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, watch, Mutex};

// Defaults — overridable per-app via the `monitor_settings` table.
pub const DEFAULT_INTERVAL_SECS: u64 = 5;
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_POLL_TIMEOUT_SECS: u64 = 8;
pub const DEFAULT_OUTAGE_THRESHOLD: u32 = 3;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitorSettings {
    /// Time between successful polls. Hot-applied — change takes effect on
    /// the next cycle of each poller.
    pub interval_secs: u64,
    /// Per-connect TCP / SSH timeout. Hot-applied for the next reconnect.
    pub connect_timeout_secs: u64,
    /// Per-poll exec timeout (how long we wait for the probe script's
    /// stdout to drain).
    pub poll_timeout_secs: u64,
    /// Consecutive failed polls before flagging a node as "outage". The
    /// outage event also fires through the existing app log so the user
    /// has a historical record.
    pub outage_threshold: u32,
    /// Whether to emit toast notifications on outage / recovery. When off,
    /// events are still logged but no toast is shown.
    pub notify_on_outage: bool,
    /// Whether to play an audible beep when a node crosses into outage.
    /// Independent of the visual toast — some users want one without the
    /// other. The frontend coalesces beeps via `beep_cooldown_secs` so a
    /// bulk drop (e.g. the entire fleet flapping at once) plays a single
    /// alert rather than spamming.
    #[serde(default = "default_false")]
    pub beep_on_outage: bool,
    /// Minimum seconds between consecutive beeps. The frontend rate-limits
    /// using this — any outage events landing inside the cooldown window
    /// are silently logged but don't play sound. Bumping this is the
    /// answer to "the alarm keeps screaming".
    #[serde(default = "default_beep_cooldown")]
    pub beep_cooldown_secs: u32,
}

// `#[serde(default = ...)]` attributes need a function reference, not a
// literal — these tiny helpers exist purely to satisfy that requirement
// while keeping the JSON migration story painless for users upgrading
// from a profile that doesn't have the new fields yet.
fn default_false() -> bool { false }
fn default_beep_cooldown() -> u32 { 10 }

impl Default for MonitorSettings {
    fn default() -> Self {
        Self {
            interval_secs: DEFAULT_INTERVAL_SECS,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            poll_timeout_secs: DEFAULT_POLL_TIMEOUT_SECS,
            outage_threshold: DEFAULT_OUTAGE_THRESHOLD,
            notify_on_outage: true,
            beep_on_outage: false,
            beep_cooldown_secs: 10,
        }
    }
}

impl MonitorSettings {
    /// Clamp incoming user values to sane bounds so a typo can't break
    /// the poller (e.g. interval=0 spinning, or huge timeouts that hang
    /// the whole UI for minutes).
    pub fn sanitized(mut self) -> Self {
        self.interval_secs = self.interval_secs.clamp(1, 600);
        self.connect_timeout_secs = self.connect_timeout_secs.clamp(2, 120);
        self.poll_timeout_secs = self.poll_timeout_secs.clamp(2, 120);
        self.outage_threshold = self.outage_threshold.clamp(1, 100);
        // Cap the beep cooldown well above the polling interval so even a
        // typo can't disable the alarm entirely.
        self.beep_cooldown_secs = self.beep_cooldown_secs.clamp(0, 600);
        self
    }
}

pub type SharedSettings = Arc<Mutex<MonitorSettings>>;

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// One entry per monitored node. The `paused` flag is hot-toggleable from
/// the UI without restarting the poller. `stop_tx` is consumed once when
/// the monitor is removed; the poller task exits cleanly on receive.
pub struct MonitorEntry {
    pub node_id: i32,
    pub enabled_metrics: Arc<Mutex<Vec<String>>>,
    pub custom_metrics: Arc<Mutex<Vec<CustomMetric>>>,
    /// A paused (or stopped) poller waits for a change of this instead of
    /// waking every second.
    pub paused: watch::Sender<bool>,
    pub state: Arc<Mutex<MonitorState>>,
    /// Wrapped in `Mutex<Option<...>>` so the sender can be `take()`-en
    /// from any holder (the entry is shared via `Arc` between the map
    /// and the spawned poller, so `Arc::try_unwrap` is unreliable). On
    /// `stop_monitor` we lock, take, and `send(())` — the poller's
    /// `tokio::select!` arm on `stop_rx` fires immediately and the
    /// task exits cleanly instead of hanging until the next interval.
    pub stop_tx: Mutex<Option<oneshot::Sender<()>>>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct MonitorState {
    pub connected: bool,
    pub last_error: Option<String>,
    pub last_sample_ts: Option<u64>,
    /// Consecutive failed connect / poll attempts. Reset on every successful
    /// sample. Reaches `outage_threshold` → outage event fires.
    pub consecutive_failures: u32,
    /// `now_ms()` of the first failure in the current outage streak. None
    /// means "no active outage". Used both for the recovered-event payload
    /// (duration) and for the UI to show "offline for Xm".
    pub outage_since_ms: Option<u64>,
    /// Why the monitor stopped trying until the user resumes it: a refused
    /// login (three times in a row) or something only the user can fix
    /// (F-017). Cleared by Resume or Pause.
    pub auth_failed: Option<String>,
}

pub type MonitorMap = Arc<Mutex<HashMap<i32, Arc<MonitorEntry>>>>;

/// Live snapshot of one node as returned by `monitor_list`.
#[derive(Debug, Clone, Serialize)]
pub struct MonitorInfo {
    pub node_id: i32,
    pub enabled_metrics: Vec<String>,
    pub custom_metrics: Vec<CustomMetric>,
    pub paused: bool,
    pub connected: bool,
    pub last_error: Option<String>,
    pub last_sample_ts: Option<u64>,
    pub consecutive_failures: u32,
    pub outage_since_ms: Option<u64>,
    pub auth_failed: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Sample {
    pub node_id: i32,
    pub ts: u64,
    /// Map of metric_key → value. Net is reported as two synthetic keys
    /// ("net_in", "net_out") so the UI can render both as separate sparklines.
    /// Custom metrics with numeric `parse` mode show up here with their id.
    pub values: HashMap<String, f64>,
    /// Per-metric error string when a single metric failed to parse (e.g.
    /// `/proc/swaps` empty on a host with no swap). The connection may still
    /// be healthy.
    pub errors: HashMap<String, String>,
    /// Text-mode custom metrics — id → trimmed string. We don't push these
    /// into `values` because they're not numeric and don't go into the
    /// sparkline ring buffer.
    pub texts: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Public spec passed in from the command layer. Decoupled from DB rows so
// callers can build it from anywhere.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct NodeAuth {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    /// PEM-encoded private key body (already pulled from `ssh_keys` table by
    /// the caller) — and its optional passphrase.
    pub private_key: Option<String>,
    pub passphrase: Option<String>,
    /// "none", "socks5", or "http". Mirrors the interactive connect path so
    /// monitoring works through the same proxy the user configured for SSH.
    pub proxy_type: String,
    pub proxy_host: Option<String>,
    pub proxy_port: Option<u16>,
    /// The server's legacy setting and its stored host-key types, the same
    /// as for an interactive connection to it (F-076, F-029). Always read
    /// from the vault, never taken from outside.
    #[serde(skip)]
    pub policy: crate::ssh_connect::AlgorithmPolicy,
    /// The jump host's login and policy, when the node has one (F-062). It
    /// takes precedence over the proxy, as for sessions; its own proxy and
    /// jump host are not used (single hop).
    #[serde(skip)]
    pub jump: Option<Box<NodeAuth>>,
}

/// A user-defined metric. The probe loop wraps each command in BEGIN/END
/// markers so we can carve its output back out of the composite script's
/// single stdout stream — keeping us at one round-trip per poll cycle.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomMetric {
    /// Stable identifier used as the event key. Frontend generates it.
    pub id: String,
    pub name: String,
    /// Shell snippet, run in the account's login shell (`$SHELL -c`).
    /// Whatever it writes to stdout (and only stdout) lands in this
    /// metric's slice of the output.
    pub command: String,
    /// "number" (first numeric token), "regex" (first capture group as
    /// number), "text" (raw trimmed stdout).
    pub parse: String,
    /// Only consulted when parse=="regex".
    #[serde(default)]
    pub regex: Option<String>,
    /// Display hint for the frontend — "sparkline", "big_number", "text".
    pub display: String,
    /// Optional unit suffix shown after the number.
    #[serde(default)]
    pub unit: Option<String>,
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// What a poller reports: the app's `monitor-*-<node>` events (built in
/// lib.rs, `monitor_events`), a recorder in tests. Kept free of the Tauri
/// runtime so the poller runs in unit tests.
#[derive(Clone)]
pub struct MonitorEvents {
    pub status: Arc<dyn Fn(&MonitorInfo) + Send + Sync>,
    pub sample: Arc<dyn Fn(&Sample) + Send + Sync>,
    /// A node crossed the outage threshold.
    pub outage: Arc<dyn Fn(&OutageEvent) + Send + Sync>,
    /// A node that was in outage answers again.
    pub recovered: Arc<dyn Fn(&RecoveredEvent) + Send + Sync>,
    /// The monitor stopped trying until the user resumes it (F-017).
    pub stopped: Arc<dyn Fn(&StoppedEvent) + Send + Sync>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoppedEvent {
    pub node_id: i32,
    pub node_name: String,
    pub reason: String,
    pub notify: bool,
}

/// Refused logins in a row after which a monitor stops (F-017): fail2ban's
/// default bans after five failures.
pub const AUTH_STRIKES: u32 = 3;

#[derive(Debug, Clone, Serialize)]
pub struct OutageEvent {
    pub node_id: i32,
    pub node_name: String,
    pub since_ms: u64,
    pub consecutive_failures: u32,
    pub last_error: String,
    pub notify: bool,
    pub beep: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveredEvent {
    pub node_id: i32,
    pub node_name: String,
    pub since_ms: u64,
    pub duration_ms: u64,
    pub notify: bool,
}

/// What the poller logs in with, read from the vault (lib.rs,
/// `resolve_node_auth_for_monitor`).
pub type Resolver = Arc<dyn Fn() -> Result<NodeAuth, String> + Send + Sync>;

/// A boxed connect attempt.
pub type Connecting = Pin<Box<dyn Future<Output = Result<Link, ConnectError>> + Send>>;

/// Opens a monitor's connection: the network in the app (`connect_for_monitor`),
/// a scripted server in tests. Gets the node's login and the connect timeout.
pub type Connector = Arc<dyn Fn(NodeAuth, Duration) -> Connecting + Send + Sync>;

/// The app's connector.
pub fn network_connector(db: Arc<std::sync::Mutex<Option<rusqlite::Connection>>>) -> Connector {
    Arc::new(move |auth, timeout| {
        let db = Arc::clone(&db);
        Box::pin(async move { connect_for_monitor(&db, &auth, timeout).await })
    })
}

/// A monitor's live connection.
pub struct Link {
    session: client::Handle<MonitorHandler>,
    /// The jump host's connection the session rides on: kept as long as it.
    _hop: Option<client::Handle<MonitorHandler>>,
}

impl Link {
    #[cfg(test)]
    pub(crate) fn session(&self) -> &client::Handle<MonitorHandler> {
        &self.session
    }
}

/// The waits between reconnect attempts: shorter in tests.
#[derive(Clone, Copy, Debug)]
pub struct PollerTiming {
    pub first_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for PollerTiming {
    fn default() -> Self {
        PollerTiming { first_backoff: Duration::from_secs(2), max_backoff: Duration::from_secs(60) }
    }
}

/// Everything a poller needs besides its entry.
pub struct Poller {
    pub events: MonitorEvents,
    pub settings: SharedSettings,
    pub node_name: String,
    pub resolve: Resolver,
    pub connect: Connector,
    pub timing: PollerTiming,
}

/// Start (or resume) monitoring a node. Spawns the poller task and stashes
/// the entry in the map. Returns immediately — the connect happens inside
/// the spawned task so a slow / unreachable host doesn't block the caller.
pub async fn start_monitor(
    map: MonitorMap,
    node_id: i32,
    enabled_metrics: Vec<String>,
    custom_metrics: Vec<CustomMetric>,
    paused: bool,
    poller: Poller,
) {
    // If a poller already exists for this node, stop it first so we never
    // double-poll.
    let existing = map.lock().await.remove(&node_id);
    if let Some(prev) = existing {
        if let Some(tx) = prev.stop_tx.lock().await.take() {
            let _ = tx.send(());
        }
    }

    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let (paused_tx, paused_rx) = watch::channel(paused);
    let entry = Arc::new(MonitorEntry {
        node_id,
        enabled_metrics: Arc::new(Mutex::new(enabled_metrics)),
        custom_metrics: Arc::new(Mutex::new(custom_metrics)),
        paused: paused_tx,
        state: Arc::new(Mutex::new(MonitorState::default())),
        stop_tx: Mutex::new(Some(stop_tx)),
    });

    map.lock().await.insert(node_id, Arc::clone(&entry));

    tokio::spawn(run_poller(entry, poller, stop_rx, paused_rx));
}

pub async fn stop_monitor(map: MonitorMap, node_id: i32) {
    let removed = map.lock().await.remove(&node_id);
    if let Some(arc_entry) = removed {
        // Take the sender out of the Option and signal the poller.
        // The poller's `tokio::select!` arm on `stop_rx` fires within
        // the same tick — no waiting for the next interval like the
        // previous "paused=true and hope" pattern.
        if let Some(tx) = arc_entry.stop_tx.lock().await.take() {
            let _ = tx.send(());
        }
        // Also flip paused so any in-flight loop iteration short-circuits
        // before the select arm has a chance to run.
        arc_entry.paused.send_replace(true);
    }
}

pub async fn set_paused(map: MonitorMap, node_id: i32, paused: bool) -> Result<(), String> {
    let entry = map
        .lock()
        .await
        .get(&node_id)
        .cloned()
        .ok_or_else(|| format!("Node {} is not being monitored", node_id))?;
    // Pause and Resume both end a stop (F-017): Resume tries again, with
    // the login read from the vault again.
    entry.state.lock().await.auth_failed = None;
    // Notifies the poller even when the value is the same (a Resume of a
    // stopped monitor).
    entry.paused.send_replace(paused);
    Ok(())
}

pub async fn set_enabled_metrics(
    map: MonitorMap,
    node_id: i32,
    metrics: Vec<String>,
) -> Result<(), String> {
    let entry = map
        .lock()
        .await
        .get(&node_id)
        .cloned()
        .ok_or_else(|| format!("Node {} is not being monitored", node_id))?;
    *entry.enabled_metrics.lock().await = metrics;
    Ok(())
}

pub async fn set_custom_metrics(
    map: MonitorMap,
    node_id: i32,
    metrics: Vec<CustomMetric>,
) -> Result<(), String> {
    let entry = map
        .lock()
        .await
        .get(&node_id)
        .cloned()
        .ok_or_else(|| format!("Node {} is not being monitored", node_id))?;
    *entry.custom_metrics.lock().await = metrics;
    Ok(())
}

pub async fn list(map: MonitorMap) -> Vec<MonitorInfo> {
    let map = map.lock().await;
    let mut out = Vec::with_capacity(map.len());
    for entry in map.values() {
        out.push(entry_status(entry).await);
    }
    out
}

/// Stop every poller and forget them (the profile is being closed).
pub async fn stop_all(map: &MonitorMap) {
    let entries: Vec<Arc<MonitorEntry>> = map.lock().await.drain().map(|(_, e)| e).collect();
    for entry in entries {
        if let Some(tx) = entry.stop_tx.lock().await.take() {
            let _ = tx.send(());
        }
        entry.paused.send_replace(true);
    }
}

pub async fn pause_all(map: MonitorMap) {
    let snap: Vec<Arc<MonitorEntry>> = map.lock().await.values().cloned().collect();
    for e in snap {
        e.paused.send_replace(true);
    }
}

async fn entry_status(entry: &MonitorEntry) -> MonitorInfo {
    let metrics = entry.enabled_metrics.lock().await.clone();
    let customs = entry.custom_metrics.lock().await.clone();
    let paused = *entry.paused.borrow();
    let s = entry.state.lock().await;
    MonitorInfo {
        node_id: entry.node_id,
        enabled_metrics: metrics,
        custom_metrics: customs,
        paused,
        connected: s.connected,
        last_error: s.last_error.clone(),
        last_sample_ts: s.last_sample_ts,
        consecutive_failures: s.consecutive_failures,
        outage_since_ms: s.outage_since_ms,
        auth_failed: s.auth_failed.clone(),
    }
}

// ---------------------------------------------------------------------------
// Poller loop
// ---------------------------------------------------------------------------

async fn run_poller(
    entry: Arc<MonitorEntry>,
    poller: Poller,
    mut stop_rx: oneshot::Receiver<()>,
    mut paused_rx: watch::Receiver<bool>,
) {
    let Poller { events, settings, node_name, resolve, connect, timing } = poller;
    let node_id = entry.node_id;
    let mut last: Option<RawSnapshot> = None;
    let mut link: Option<Link> = None;
    let mut backoff = timing.first_backoff;
    let backoff_max = timing.max_backoff;
    // Refused logins since the last successful one.
    let mut strikes: u32 = 0;

    // Helper: record a failure, fire outage event if we just crossed the
    // threshold. Caller still has the responsibility to surface the actual
    // error to the user via mark_disconnected.
    async fn record_failure(
        events: &MonitorEvents,
        entry: &MonitorEntry,
        node_name: &str,
        threshold: u32,
        err: &str,
        notify: bool,
        beep: bool,
    ) {
        let (just_crossed, since_ms) = {
            let mut s = entry.state.lock().await;
            s.consecutive_failures = s.consecutive_failures.saturating_add(1);
            if s.outage_since_ms.is_none() {
                s.outage_since_ms = Some(now_ms());
            }
            let crossed = s.consecutive_failures == threshold;
            (crossed, s.outage_since_ms.unwrap_or_else(now_ms))
        };
        if just_crossed {
            // Outage event: one-shot per outage streak. The frontend toasts
            // it (when notify=true), logs it always, and the card shows a
            // persistent "Offline for Xm" badge. `beep` is a hint — the
            // frontend still applies its own cooldown to collapse bursts.
            (events.outage)(&OutageEvent {
                node_id: entry.node_id,
                node_name: node_name.to_string(),
                since_ms,
                consecutive_failures: threshold,
                last_error: err.to_string(),
                notify,
                beep,
            });
        }
    }

    // Recovery event: one-shot when we go from outage_since=Some → None.
    async fn record_recovery(
        events: &MonitorEvents,
        entry: &MonitorEntry,
        node_name: &str,
        notify: bool,
        was_outage_threshold: bool,
    ) {
        let (was_outage, since_ms, duration_ms) = {
            let mut s = entry.state.lock().await;
            let was = s.outage_since_ms.is_some();
            let since = s.outage_since_ms;
            s.consecutive_failures = 0;
            s.outage_since_ms = None;
            let duration = since.map(|t| now_ms().saturating_sub(t)).unwrap_or(0);
            (was, since.unwrap_or(0), duration)
        };
        if was_outage && was_outage_threshold {
            (events.recovered)(&RecoveredEvent {
                node_id: entry.node_id,
                node_name: node_name.to_string(),
                since_ms,
                duration_ms,
                notify,
            });
        }
    }

    loop {
        // Record the deadline BEFORE running the poll. If the poll
        // takes longer than `interval` we want the next tick to fire
        // immediately (catching up), not to drift by the cost of the
        // slow poll. Equivalent to tokio::time::interval with
        // MissedTickBehavior::Delay, but resilient to mid-flight
        // interval changes from hot-applied settings.
        let tick_started_at = std::time::Instant::now();

        // 1) Honour stop / pause / removal.
        if stop_rx.try_recv().is_ok() {
            break;
        }
        if Arc::strong_count(&entry) == 1 {
            break;
        }
        let paused = *paused_rx.borrow_and_update();
        if paused || entry.state.lock().await.auth_failed.is_some() {
            // A stopped monitor keeps its reason on the card.
            if paused {
                mark_disconnected(&events, &entry, None).await;
            }
            link = None;
            strikes = 0;
            // Pause should NOT count as outage: clear streak so a resume
            // doesn't instantly fire a recovered event.
            {
                let mut s = entry.state.lock().await;
                s.consecutive_failures = 0;
                s.outage_since_ms = None;
            }
            // Until Pause, Resume or a stop: no timer while parked.
            tokio::select! {
                _ = &mut stop_rx => break,
                changed = paused_rx.changed() => match changed {
                    Ok(()) => continue,
                    Err(_) => break,
                },
            }
        }

        // 2) Pull current settings (hot-applied each cycle).
        let cfg = settings.lock().await.clone();
        let threshold = cfg.outage_threshold;
        let notify = cfg.notify_on_outage;
        let beep = cfg.beep_on_outage;
        let connect_timeout = Duration::from_secs(cfg.connect_timeout_secs);
        let poll_timeout = Duration::from_secs(cfg.poll_timeout_secs);
        let interval = Duration::from_secs(cfg.interval_secs);

        // 3) Ensure we have a live SSH handle.
        if link.as_ref().map(|l| l.session.is_closed()).unwrap_or(true) {
            // The login is read from the vault for every connect (F-017): an
            // edited password, key, user, address or jump host is used, and
            // nothing of it is kept between connects.
            let attempt = match resolve() {
                Ok(auth) => {
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        attempt = connect(auth, connect_timeout) => attempt,
                    }
                }
                Err(e) => Err(ConnectError::NeedsUser(e)),
            };
            match attempt {
                Ok(l) => {
                    link = Some(l);
                    strikes = 0;
                    backoff = timing.first_backoff;
                    let was_outage_threshold = {
                        let s = entry.state.lock().await;
                        s.consecutive_failures >= threshold
                    };
                    record_recovery(&events, &entry, &node_name, notify, was_outage_threshold).await;
                    mark_connected(&events, &entry).await;
                    // Reset differential baseline so the first sample after
                    // reconnect doesn't produce a giant nonsense CPU/net spike.
                    last = None;
                }
                Err(ConnectError::NeedsUser(why)) => {
                    stop_until_resumed(&events, &entry, &node_name, why, notify).await;
                    continue;
                }
                Err(ConnectError::Refused(why)) if strikes + 1 >= AUTH_STRIKES => {
                    let why = format!(
                        "The login was refused {} times in a row, so monitoring stopped before the server locks you out. Fix the login. Last answer: {}",
                        AUTH_STRIKES, why
                    );
                    stop_until_resumed(&events, &entry, &node_name, why, notify).await;
                    continue;
                }
                Err(e) => {
                    // A refusal is not an outage: the host answered.
                    if matches!(e, ConnectError::Refused(_)) {
                        strikes += 1;
                    } else {
                        record_failure(&events, &entry, &node_name, threshold, e.reason(), notify, beep).await;
                    }
                    mark_disconnected(&events, &entry, Some(e.reason().to_string())).await;
                    tokio::select! {
                        _ = &mut stop_rx => break,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(backoff_max);
                    continue;
                }
            }
        }

        // 4) Poll once. Snapshot enabled + custom lists here so mid-cycle
        // hot-updates from the UI take effect on the NEXT cycle.
        let customs_snap: Vec<CustomMetric> = entry.custom_metrics.lock().await.clone();
        let h = &link.as_ref().expect("connected above").session;
        let polled = tokio::select! {
            _ = &mut stop_rx => break,
            polled = poll_once(h, &customs_snap, poll_timeout) => polled,
        };
        match polled {
            Ok(raw) => {
                let enabled_snap = entry.enabled_metrics.lock().await.clone();
                let sample = compute_sample(node_id, &raw, &last, &enabled_snap, &customs_snap);
                last = Some(raw);
                let cleared = {
                    let mut s = entry.state.lock().await;
                    s.last_sample_ts = Some(sample.ts);
                    s.connected = true;
                    s.last_error.take().is_some()
                };
                if cleared {
                    // A probe problem (PollError::Output) is over.
                    (events.status)(&entry_status(&entry).await);
                }
                let was_outage_threshold = {
                    let s = entry.state.lock().await;
                    s.consecutive_failures >= threshold
                };
                record_recovery(&events, &entry, &node_name, notify, was_outage_threshold).await;
                (events.sample)(&sample);
            }
            Err(PollError::Output(e)) => {
                // The host answers; its probe is broken. Every metric shows
                // the problem, the link stays, and it is not an outage.
                let enabled_snap = entry.enabled_metrics.lock().await.clone();
                let mut errors: HashMap<String, String> = HashMap::new();
                for key in enabled_snap.iter().chain(customs_snap.iter().map(|c| &c.id)) {
                    errors.insert(key.clone(), e.clone());
                }
                (events.sample)(&Sample { node_id, ts: now_ms(), values: HashMap::new(), errors, texts: HashMap::new() });
                let changed = {
                    let mut s = entry.state.lock().await;
                    let changed = s.last_error.as_deref() != Some(e.as_str());
                    s.last_error = Some(e);
                    changed
                };
                if changed {
                    (events.status)(&entry_status(&entry).await);
                }
            }
            Err(PollError::Down(e)) => {
                // The error names the host; it is in the monitor's state for the UI.
                dev_log!("[monitor] poll failed for node {}: {}", node_id, e);
                link = None;
                record_failure(&events, &entry, &node_name, threshold, &e, notify, beep).await;
                mark_disconnected(&events, &entry, Some(e)).await;
            }
        }

        // 5) Wait until the deadline computed at the START of this
        // iteration. A poll that overran `interval` sleeps zero and
        // the next tick fires immediately — drift bounded to one
        // interval regardless of how slow a single probe gets.
        let now = std::time::Instant::now();
        let next_tick = tick_started_at + interval;
        let wait = if next_tick > now { next_tick - now } else { Duration::ZERO };
        tokio::select! {
            _ = &mut stop_rx => break,
            _ = tokio::time::sleep(wait) => {}
            // A Pause takes effect now, not at the next tick.
            changed = paused_rx.changed() => if changed.is_err() { break },
        }
    }

    mark_disconnected(&events, &entry, None).await;
}

/// Parks the poller until the user resumes it, and says why (F-017).
async fn stop_until_resumed(events: &MonitorEvents, entry: &MonitorEntry, node_name: &str, reason: String, notify: bool) {
    {
        let mut s = entry.state.lock().await;
        s.connected = false;
        s.last_error = Some(reason.clone());
        s.auth_failed = Some(reason.clone());
        s.consecutive_failures = 0;
        s.outage_since_ms = None;
    }
    (events.status)(&entry_status(entry).await);
    (events.stopped)(&StoppedEvent { node_id: entry.node_id, node_name: node_name.to_string(), reason, notify });
}

async fn mark_connected(events: &MonitorEvents, entry: &MonitorEntry) {
    {
        let mut s = entry.state.lock().await;
        s.connected = true;
        s.last_error = None;
    }
    (events.status)(&entry_status(entry).await);
}

async fn mark_disconnected(events: &MonitorEvents, entry: &MonitorEntry, err: Option<String>) {
    let already = {
        let s = entry.state.lock().await;
        !s.connected && s.last_error == err
    };
    if already {
        return; // avoid spamming identical status events
    }
    {
        let mut s = entry.state.lock().await;
        s.connected = false;
        s.last_error = err;
    }
    (events.status)(&entry_status(entry).await);
}

// ---------------------------------------------------------------------------
// SSH connect
// ---------------------------------------------------------------------------

/// Why a monitor could not connect, which decides what it does next (F-017).
#[derive(Debug)]
pub enum ConnectError {
    /// Only the user can fix it: no login on file, a key that cannot be
    /// read, a host key that is not trusted, a server that wants answers
    /// typed in. The monitor stops at once and sends nothing more.
    NeedsUser(String),
    /// The server refused the login: counts toward the stop after
    /// `AUTH_STRIKES` refusals in a row.
    Refused(String),
    /// The network or the server failed: retried with backoff, counts
    /// toward an outage.
    Down(String),
}

impl ConnectError {
    fn reason(&self) -> &str {
        match self {
            ConnectError::NeedsUser(r) | ConnectError::Refused(r) | ConnectError::Down(r) => r,
        }
    }

    /// The same outcome, its reason starting with `prefix`.
    fn prefixed(self, prefix: &str) -> Self {
        match self {
            ConnectError::NeedsUser(r) => ConnectError::NeedsUser(format!("{}{}", prefix, r)),
            ConnectError::Refused(r) => ConnectError::Refused(format!("{}{}", prefix, r)),
            ConnectError::Down(r) => ConnectError::Down(format!("{}{}", prefix, r)),
        }
    }
}

/// What a monitor's host-key check saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyVerdict {
    Trusted,
    Unknown,
    /// Another key, or only keys of other types, are on file.
    NotTheTrustedKey,
    Certificate,
    /// The saved keys could not be read (the profile is closing).
    Unreadable,
}

/// Authorises only hosts whose key is already in `known_hosts`: a monitor
/// never prompts, so the user approves a key by connecting from a session
/// first. It records what it saw, for the refusal's message.
pub struct MonitorHandler {
    db: Arc<std::sync::Mutex<Option<rusqlite::Connection>>>,
    host: String,
    port: u16,
    verdict: Arc<std::sync::Mutex<Option<KeyVerdict>>>,
}

impl client::Handler for MonitorHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        offered: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        use crate::ssh_manager::{host_key_fingerprint, host_key_label, lookup_known_host, KnownHost};
        // Host-key certificates are never advertised, so refuse one outright.
        let verdict = match offered {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                let guard = self.db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                match lookup_known_host(guard.as_ref(), &self.host, self.port, &host_key_fingerprint(key), &host_key_label(key)) {
                    Ok(KnownHost::Trusted) => KeyVerdict::Trusted,
                    Ok(KnownHost::Unknown) => KeyVerdict::Unknown,
                    Ok(KnownHost::Changed { .. } | KnownHost::OtherTypes { .. }) => KeyVerdict::NotTheTrustedKey,
                    Err(_) => KeyVerdict::Unreadable,
                }
            }
            _ => KeyVerdict::Certificate,
        };
        *self.verdict.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(verdict);
        Ok(verdict == KeyVerdict::Trusted)
    }
}

/// Trait-object wrapper so we can hand russh's `connect_stream` either a
/// direct TcpStream, a tokio_socks SOCKS5 stream, or a CONNECT-tunneled
/// TcpStream — depending on the node's proxy config — via the same path.
trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> AsyncStream for T {}

struct StreamBox(Box<dyn AsyncStream>);
impl tokio::io::AsyncRead for StreamBox {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}
impl tokio::io::AsyncWrite for StreamBox {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut *self.0).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}

/// Build the underlying transport, honouring the node's proxy settings (a
/// jump host is handled by `connect_for_monitor`). Same matrix as the
/// interactive connect path.
async fn open_transport(auth: &NodeAuth, connect_timeout: Duration) -> Result<Box<dyn AsyncStream>, String> {
    match auth.proxy_type.as_str() {
        "socks5" => {
            let p_host = auth.proxy_host.as_deref().filter(|s| !s.is_empty())
                .ok_or("SOCKS5 proxy host is empty")?;
            let p_port = auth.proxy_port.unwrap_or(1080);
            let proxy_addr = format!("{}:{}", p_host, p_port);
            let stream = tokio::time::timeout(
                connect_timeout,
                tokio_socks::tcp::Socks5Stream::connect(proxy_addr.as_str(), (auth.host.as_str(), auth.port)),
            )
            .await
            .map_err(|_| format!("SOCKS5 proxy {} timed out", proxy_addr))?
            .map_err(|e| format!("SOCKS5: {}", e))?;
            Ok(Box::new(stream))
        }
        "http" => {
            let p_host = auth.proxy_host.as_deref().filter(|s| !s.is_empty())
                .ok_or("HTTP proxy host is empty")?;
            let p_port = auth.proxy_port.unwrap_or(8080);
            let mut tcp = tcp_within(p_host, p_port, connect_timeout, "HTTP proxy").await?;
            let _ = tcp.set_nodelay(true);
            tokio::time::timeout(
                connect_timeout,
                async_http_proxy::http_connect_tokio(&mut tcp, &auth.host, auth.port),
            )
            .await
            .map_err(|_| format!("HTTP CONNECT to {}:{} timed out", auth.host, auth.port))?
            .map_err(|e| format!("HTTP CONNECT: {}", e))?;
            Ok(Box::new(tcp))
        }
        _ => {
            let stream = tcp_within(&auth.host, auth.port, connect_timeout, "Connection").await?;
            let _ = stream.set_nodelay(true);
            Ok(Box::new(stream))
        }
    }
}

/// TCP to `host`, each resolved address with its own timeout as for a
/// session (F-077), all within the monitor's connect timeout.
async fn tcp_within(host: &str, port: u16, limit: Duration, label: &str) -> Result<tokio::net::TcpStream, String> {
    match tokio::time::timeout(limit, crate::ssh_connect::connect_tcp(host, port)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(crate::describe_tcp_failure(e, host, i32::from(port), label)),
        Err(_) => Err(format!("{}: {}:{} did not answer within {} seconds", label, host, port, limit.as_secs())),
    }
}

/// What a monitor logs in with, checked before anything is sent.
pub(crate) struct Login {
    user: String,
    key: Option<Arc<russh::keys::PrivateKey>>,
    /// Only sent when no key is configured: a rejected key never falls back
    /// to the password, which could leak it to a server the user chose key
    /// login for.
    password: Option<String>,
    allow_sha1_rsa: bool,
}

/// The node's login, or why a monitor cannot use it.
pub(crate) fn prepare_login(auth: &NodeAuth) -> Result<Login, ConnectError> {
    if auth.username.trim().is_empty() {
        return Err(ConnectError::NeedsUser("This server has no user name set.".into()));
    }
    let pem = auth.private_key.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let key = match pem {
        Some(pem) => match russh::keys::decode_secret_key(&pem.replace("\r\n", "\n"), auth.passphrase.as_deref()) {
            Ok(key) => Some(Arc::new(key)),
            Err(e) => {
                return Err(ConnectError::NeedsUser(format!(
                    "The private key could not be read ({}). Check the key and its passphrase.",
                    e
                )))
            }
        },
        None => None,
    };
    let password = auth.password.clone().filter(|p| !p.is_empty());
    if key.is_none() && password.is_none() {
        return Err(ConnectError::NeedsUser(
            "This server has no saved password or key, so a monitor cannot log in to it.".into(),
        ));
    }
    let password = if key.is_some() { None } else { password };
    Ok(Login { user: auth.username.trim().to_string(), key, password, allow_sha1_rsa: auth.policy.legacy })
}

async fn connect_for_monitor(
    db: &Arc<std::sync::Mutex<Option<rusqlite::Connection>>>,
    auth: &NodeAuth,
    connect_timeout: Duration,
) -> Result<Link, ConnectError> {
    let login = prepare_login(auth)?;
    if let Some(hop) = auth.jump.as_deref() {
        return connect_through(db, hop, auth, login, connect_timeout).await;
    }
    let transport = open_transport(auth, connect_timeout).await.map_err(ConnectError::Down)?;
    establish(StreamBox(transport), db, auth, login, connect_timeout).await
}

/// `ssh -J hop target`: log in to the jump host (by direct TCP, its key
/// already trusted, its own login), open a `direct-tcpip` channel to the
/// target and run the target's handshake over it (F-062).
async fn connect_through(
    db: &Arc<std::sync::Mutex<Option<rusqlite::Connection>>>,
    hop: &NodeAuth,
    target: &NodeAuth,
    login: Login,
    connect_timeout: Duration,
) -> Result<Link, ConnectError> {
    let on_hop = |e: ConnectError| e.prefixed(&format!("Jump host {}:{}: ", hop.host, hop.port));
    let hop_login = prepare_login(hop).map_err(on_hop)?;
    let tcp = tcp_within(&hop.host, hop.port, connect_timeout, "Connection").await.map_err(|e| on_hop(ConnectError::Down(e)))?;
    let _ = tcp.set_nodelay(true);
    let hop_link = establish(tcp, db, hop, hop_login, connect_timeout).await.map_err(on_hop)?;
    let opened = tokio::time::timeout(
        crate::ssh_connect::CHANNEL_OPEN_TIMEOUT,
        hop_link.session.channel_open_direct_tcpip(target.host.clone(), u32::from(target.port), "127.0.0.1", 0),
    )
    .await;
    let channel = match opened {
        Ok(Ok(channel)) => channel,
        Ok(Err(e)) => {
            let why = format!(
                "The jump host {}:{} could not open a channel to {}:{}: {}",
                hop.host, hop.port, target.host, target.port, e
            );
            // Forwarding switched off on the jump host is a setting, not an outage.
            return Err(match e {
                russh::Error::ChannelOpenFailure(russh::ChannelOpenFailure::AdministrativelyProhibited) => ConnectError::NeedsUser(why),
                _ => ConnectError::Down(why),
            });
        }
        Err(_) => {
            return Err(ConnectError::Down(format!(
                "The jump host {}:{} did not open a channel to {}:{} within {} seconds",
                hop.host, hop.port, target.host, target.port, crate::ssh_connect::CHANNEL_OPEN_TIMEOUT.as_secs()
            )))
        }
    };
    let mut link = establish(channel.into_stream(), db, target, login, connect_timeout).await?;
    link._hop = Some(hop_link.session);
    Ok(link)
}

/// Never asked: a monitor answers no keyboard-interactive questions.
struct NoPrompts;

impl crate::ssh_connect::KbiPrompter for NoPrompts {
    async fn ask(&self, _round: crate::ssh_connect::KbiRound) -> Option<Vec<String>> {
        None
    }
}

/// Handshake and `login` over `stream`, already connected to the node.
pub(crate) async fn establish<S>(
    stream: S,
    db: &Arc<std::sync::Mutex<Option<rusqlite::Connection>>>,
    auth: &NodeAuth,
    login: Login,
    connect_timeout: Duration,
) -> Result<Link, ConnectError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let target = format!("{}:{}", auth.host, auth.port);

    // Same algorithm policy as an interactive connection to this server: no
    // SHA-1 unless the server's legacy setting allows it, trusted key types
    // first (otherwise a host trusted under RSA would be asked for ed25519
    // here and refused, since monitors only accept keys already on file).
    let mut config = crate::ssh_connect::build_ssh_client_config(&auth.policy);
    config.keepalive_interval = Some(Duration::from_secs(30));
    let config = Arc::new(config);

    let verdict = Arc::new(std::sync::Mutex::new(None));
    let handler = MonitorHandler {
        db: Arc::clone(db),
        host: auth.host.clone(),
        port: auth.port,
        verdict: Arc::clone(&verdict),
    };

    // Handshake budget mirrors the interactive path. We don't expose it
    // separately in settings; it's bounded by `connect_timeout` * 2 so very
    // chatty hosts (algorithm negotiation through a slow proxy) still get
    // a fair shake without hanging the UI.
    let handshake_budget = connect_timeout * 2;
    let handshake = tokio::time::timeout(handshake_budget, client::connect_stream(config, stream, handler)).await;
    let seen = *verdict.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut session = match (handshake, seen) {
        (Ok(Ok(session)), _) => session,
        (_, Some(KeyVerdict::Unknown)) => {
            return Err(ConnectError::NeedsUser(format!(
                "The host key of {} is not among your trusted keys yet. Connect to it once from a session to check and accept the key.",
                target
            )))
        }
        (_, Some(KeyVerdict::NotTheTrustedKey)) => {
            return Err(ConnectError::NeedsUser(format!(
                "{} did not show the host key you trust (it changed, or it is of another type). Connect to it from a session to review the key.",
                target
            )))
        }
        (_, Some(KeyVerdict::Certificate)) => {
            return Err(ConnectError::NeedsUser(format!(
                "{} presented a host-key certificate, which Solanum does not support.",
                target
            )))
        }
        (_, Some(KeyVerdict::Unreadable)) => {
            return Err(ConnectError::Down("The saved host keys could not be read.".into()))
        }
        (Ok(Err(e)), _) => {
            return Err(match crate::ssh_connect::legacy_only_offer(&e) {
                Some(names) => ConnectError::NeedsUser(format!(
                    "{} offers only legacy algorithms ({}). If you trust it, turn on \u{201c}Allow legacy algorithms\u{201d} in its settings.",
                    target,
                    names.join(", ")
                )),
                None => ConnectError::Down(format!("SSH connect: {}", e)),
            })
        }
        (Err(_), _) => return Err(ConnectError::Down(format!("SSH handshake to {} timed out", target))),
    };

    // A server whose login needs what a monitor does not have (answers typed
    // in, say) is not tried at all: the `none` request lists its methods and
    // is not counted as a failed login.
    let none = tokio::time::timeout(crate::ssh_connect::AUTH_REPLY_TIMEOUT, session.authenticate_none(login.user.clone())).await;
    match none {
        Ok(Ok(client::AuthResult::Success)) => return Ok(Link { session, _hop: None }),
        Ok(Ok(client::AuthResult::Failure { remaining_methods, .. })) => {
            let usable = if login.key.is_some() {
                remaining_methods.contains(&russh::MethodKind::PublicKey)
            } else {
                remaining_methods.contains(&russh::MethodKind::Password)
            };
            if !usable && !remaining_methods.is_empty() {
                let offered: Vec<&str> = remaining_methods.iter().map(<&str>::from).collect();
                return Err(ConnectError::NeedsUser(format!(
                    "{} accepts only {} logins, which a monitor cannot use (it logs in with the saved {} and answers no questions).",
                    target,
                    offered.join(", "),
                    if login.key.is_some() { "key" } else { "password" }
                )));
            }
        }
        Ok(Err(e)) => return Err(ConnectError::Down(format!("SSH login: {}", e))),
        Err(_) => return Err(ConnectError::Down(format!("{} stopped answering during login", target))),
    }

    let creds = crate::ssh_connect::Credentials {
        key_login: login.key.is_some(),
        key: login.key,
        key_problem: None,
        password: login.password,
        password_can_be_typed: false,
        allow_sha1_rsa: login.allow_sha1_rsa,
    };
    let quiet = |_: &str, _: &str| {};
    let result = crate::ssh_connect::authenticate(
        &mut session,
        &login.user,
        creds,
        None::<&NoPrompts>,
        crate::ssh_connect::AuthLimits::default(),
        &quiet,
    )
    .await;
    match result {
        Ok(()) => Ok(Link { session, _hop: None }),
        Err(crate::ssh_connect::AuthFailure::Refused(reason)) => {
            Err(ConnectError::Refused(format!("{}@{}: {}", login.user, target, reason)))
        }
        // A second login step it cannot answer, or a key it cannot use.
        Err(crate::ssh_connect::AuthFailure::Unanswerable(reason)) => {
            Err(ConnectError::NeedsUser(format!("{}@{}: {}", login.user, target, reason)))
        }
        Err(crate::ssh_connect::AuthFailure::TimedOut(reason)) => Err(ConnectError::Down(reason)),
        // The server listed its methods a moment ago, so a connection ended
        // during the login is most likely a refusal by disconnect (OpenSSH
        // past MaxAuthTries): a strike, not a retry forever.
        Err(crate::ssh_connect::AuthFailure::Ssh(e)) => Err(ConnectError::Refused(format!(
            "{}@{}: the server closed the connection during the login ({})",
            login.user, target, e
        ))),
    }
}

// ---------------------------------------------------------------------------
// Polling: one composite script per cycle
// ---------------------------------------------------------------------------

/// Header lines for the built-in probe. Designed to run on the broadest
/// possible set of Linux distros — Debian/Ubuntu, RHEL/Fedora, Alpine
/// (busybox sh + busybox awk), embedded boxes with kernels predating
/// MemAvailable (~3.14), and minimal containers with only `/proc` mounted.
///
/// Tag-prefixed lines (`CPU …`, `MEM …` etc.) survive any MOTD or
/// shell-init noise the parser would otherwise have to filter. Each
/// command is wrapped to swallow stderr so a missing tool surfaces as a
/// missing tag in the parser (cleanly degraded) rather than a torrent of
/// "command not found" lines.
///
/// Only POSIX shell features + plain `awk` are used — no bash-isms, no
/// gawk extensions (`gensub`, length-of-array, etc.). Confirmed against
/// busybox 1.36 awk.
pub(crate) const BUILTIN_PROBE: &str = r#"
echo CPU $(awk '/^cpu /{print $2,$3,$4,$5,$6,$7,$8,$9}' /proc/stat 2>/dev/null)
echo MEM $(awk '
  /^MemTotal:/   {t=$2}
  /^MemAvailable:/ {a=$2; ok=1}
  /^MemFree:/    {f=$2}
  /^Buffers:/    {b=$2}
  /^Cached:/     {c=$2}
  END {
    # Kernels >= 3.14 have MemAvailable — use it directly. Older kernels
    # only have MemFree, so approximate "available" as Free + Buffers +
    # reclaimable Cached. Slightly optimistic but the best we can do.
    if (ok) print t, a; else print t+0, (f+b+c)+0
  }
' /proc/meminfo 2>/dev/null)
echo SWAP $(awk '
  /^SwapTotal:/{t=$2} /^SwapFree:/{f=$2}
  END {print t+0, f+0}
' /proc/meminfo 2>/dev/null)
echo LOAD $(awk '{print $1; exit}' /proc/loadavg 2>/dev/null)
# Disk usage on root: -k forces 1024-byte blocks so total/used are in KiB,
# which the parser already expects. -P keeps one line per filesystem; a df
# without it (old busybox) may put a long device name on a line of its own,
# so total and used are counted from the end of the joined data lines
# (... total used available capacity mountpoint).
echo DISK $( { df -kP / 2>/dev/null || df -k / 2>/dev/null; } | awk '
  NR > 1 { s = s " " $0 }
  END { n = split(s, f, " "); if (n >= 5) print f[n-4], f[n-3] }
')
# Network totals across all real interfaces (skip loopback). Tolerates
# both `eth0:` and `  eth0:` formatting variants found in /proc/net/dev.
echo NET $(awk '
  BEGIN{r=0; t=0}
  NR>2 {
    line=$0
    sub(/^[ \t]+/, "", line)
    if (line ~ /^lo:/) next
    gsub(":", " ", line)
    n=split(line, f, /[ \t]+/)
    if (n >= 10) { r += f[2]; t += f[10] }
  }
  END {print r+0, t+0}
' /proc/net/dev 2>/dev/null)
"#;

/// Sentinel pair around each custom command's stdout so the parser can
/// recover the per-metric slice.
fn build_probe_script(customs: &[CustomMetric]) -> String {
    use crate::remote_exec::sh_quote;
    let mut s = String::from(BUILTIN_PROBE);
    for cm in customs {
        // The probe runs in sh; a custom command runs in the account's login
        // shell, as `ssh host '<command>'` would run it (owner decision,
        // F-071), and in a process of its own, so a `cd` or `set -e` in one
        // cannot bleed into the next.
        s.push_str(&format!(
            "\necho {begin}\n\"${{SHELL:-/bin/sh}}\" -c {cmd} 2>/dev/null\necho {end}\n",
            begin = sh_quote(&format!("__SUB_C_BEGIN__{}", cm.id)),
            cmd = sh_quote(&cm.command.replace('\r', "")),
            end = sh_quote(&format!("__SUB_C_END__{}", cm.id)),
        ));
    }
    s
}

// pub(crate): reused as-is by lib.rs's ssh_info_live_sample for the session
// Info tab's live status strip, which needs the same probe/parse/diff logic
// but run over an already-open interactive session instead of this module's
// own dedicated connection — see that command's own comment.
#[derive(Debug, Clone, Default)]
pub(crate) struct RawSnapshot {
    pub(crate) ts: u64,
    /// Sum of all CPU jiffies, and the idle portion (idle + iowait). We
    /// compute usage as `(busy_now-busy_prev) / (total_now-total_prev)`.
    pub(crate) cpu_total: u64,
    pub(crate) cpu_idle: u64,
    pub(crate) mem_total_kb: u64,
    pub(crate) mem_avail_kb: u64,
    pub(crate) swap_total_kb: u64,
    pub(crate) swap_free_kb: u64,
    pub(crate) load1: f64,
    pub(crate) disk_total_kb: u64,
    pub(crate) disk_used_kb: u64,
    pub(crate) net_rx_bytes: u64,
    pub(crate) net_tx_bytes: u64,
    /// Per-custom-metric raw stdout slice (trimmed). Indexed by custom id.
    pub(crate) custom_text: HashMap<String, String>,
}

/// The most probe output a poll reads (F-018); more is a broken probe or a
/// hostile server, and the poll fails instead of holding it.
const PROBE_OUTPUT_LIMIT: usize = 1024 * 1024;

/// Why a poll gave no snapshot.
#[derive(Debug)]
pub(crate) enum PollError {
    /// The connection or the server failed (or did not answer in time):
    /// the link is dropped and the failure counts toward an outage.
    Down(String),
    /// The server answered, but the probe printed too much: the host is up,
    /// the link stays.
    Output(String),
}

pub(crate) async fn poll_once<H: client::Handler>(
    handle: &client::Handle<H>,
    customs: &[CustomMetric],
    poll_timeout: Duration,
) -> Result<RawSnapshot, PollError> {
    use crate::remote_exec::{Capture, Overflow, RunError};
    let script = build_probe_script(customs);
    // The whole poll, channel open included, is bounded by the poll timeout.
    let poll = async {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| PollError::Down(format!("open session: {}", e)))?;
        let capture = Capture::new(PROBE_OUTPUT_LIMIT, Overflow::Fail);
        match crate::remote_exec::run(channel, &script, capture, None, poll_timeout).await {
            Ok(out) => parse_probe(&out.text).map_err(PollError::Down),
            Err(RunError::Start(e)) => Err(PollError::Down(format!("exec: {}", e))),
            Err(RunError::TimedOut) => Err(PollError::Down("probe script timed out".into())),
            Err(RunError::Overflowed) => Err(PollError::Output(format!(
                "the probe printed more than {} MiB (a custom metric that prints too much?)",
                PROBE_OUTPUT_LIMIT >> 20
            ))),
        }
    };
    tokio::time::timeout(poll_timeout, poll)
        .await
        .unwrap_or_else(|_| Err(PollError::Down("probe script timed out".into())))
}

pub(crate) fn parse_probe(text: &str) -> Result<RawSnapshot, String> {
    let mut snap = RawSnapshot::default();
    snap.ts = now_ms();
    // Two-pass: first carve out the custom blocks (anything between
    // __SUB_C_BEGIN__<id> and __SUB_C_END__<id> belongs to the custom
    // metric, not to the built-in tag stream). Custom output can contain
    // multi-line text or even our own tag names without confusing the
    // built-in parser.
    let mut builtin_lines: Vec<&str> = Vec::new();
    let mut current_custom_id: Option<String> = None;
    let mut current_buf = String::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(id) = t.strip_prefix("__SUB_C_BEGIN__") {
            current_custom_id = Some(id.to_string());
            current_buf.clear();
            continue;
        }
        if let Some(id) = t.strip_prefix("__SUB_C_END__") {
            if let Some(open) = current_custom_id.take() {
                if open == id {
                    snap.custom_text.insert(open, current_buf.trim().to_string());
                }
            }
            current_buf.clear();
            continue;
        }
        if current_custom_id.is_some() {
            if !current_buf.is_empty() {
                current_buf.push('\n');
            }
            current_buf.push_str(line); // keep original (with leading whitespace)
        } else {
            builtin_lines.push(t);
        }
    }
    // If a BEGIN had no matching END (custom command crashed), drop the
    // partial buffer — better than reporting half a value.
    for line in builtin_lines {
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let tag = match it.next() {
            Some(t) => t,
            None => continue,
        };
        let rest: Vec<&str> = it.collect();
        match tag {
            "CPU" if rest.len() >= 4 => {
                // user nice system idle iowait irq softirq steal
                // Saturating arithmetic: the values come straight off the
                // monitored host's /proc/stat, so a malicious/compromised
                // server could send u64::MAX-scale tokens whose sum overflows
                // and panics this poller task in a debug build (overflow-checks
                // on). Saturate instead of trusting the remote input.
                let nums: Vec<u64> = rest.iter().map(|s| s.parse().unwrap_or(0)).collect();
                let total: u64 = nums.iter().fold(0u64, |acc, &n| acc.saturating_add(n));
                let idle = nums.get(3).copied().unwrap_or(0)
                    .saturating_add(nums.get(4).copied().unwrap_or(0));
                snap.cpu_total = total;
                snap.cpu_idle = idle;
            }
            "MEM" if rest.len() >= 2 => {
                snap.mem_total_kb = rest[0].parse().unwrap_or(0);
                snap.mem_avail_kb = rest[1].parse().unwrap_or(0);
            }
            "SWAP" if rest.len() >= 2 => {
                snap.swap_total_kb = rest[0].parse().unwrap_or(0);
                snap.swap_free_kb = rest[1].parse().unwrap_or(0);
            }
            "LOAD" if !rest.is_empty() => {
                snap.load1 = rest[0].parse().unwrap_or(0.0);
            }
            "DISK" if rest.len() >= 2 => {
                snap.disk_total_kb = rest[0].parse().unwrap_or(0);
                snap.disk_used_kb = rest[1].parse().unwrap_or(0);
            }
            "NET" if rest.len() >= 2 => {
                snap.net_rx_bytes = rest[0].parse().unwrap_or(0);
                snap.net_tx_bytes = rest[1].parse().unwrap_or(0);
            }
            _ => { /* ignore unknown tags */ }
        }
    }
    Ok(snap)
}

pub(crate) fn compute_sample(
    node_id: i32,
    now: &RawSnapshot,
    prev: &Option<RawSnapshot>,
    enabled: &[String],
    customs: &[CustomMetric],
) -> Sample {
    let mut values: HashMap<String, f64> = HashMap::new();
    let mut errors: HashMap<String, String> = HashMap::new();
    let mut texts: HashMap<String, String> = HashMap::new();
    let want = |k: &str| enabled.iter().any(|s| s == k);

    // CPU% — diff-based; needs prev. First sample yields no value (so the
    // sparkline is correctly empty rather than fake-zero).
    if want("cpu") {
        if let Some(p) = prev {
            let dt = now.cpu_total.saturating_sub(p.cpu_total);
            let di = now.cpu_idle.saturating_sub(p.cpu_idle);
            if dt > 0 {
                let busy = dt.saturating_sub(di) as f64;
                values.insert("cpu".into(), (busy / dt as f64) * 100.0);
            }
        }
    }
    if want("mem") {
        if now.mem_total_kb > 0 {
            let used = now.mem_total_kb.saturating_sub(now.mem_avail_kb);
            values.insert(
                "mem".into(),
                (used as f64 / now.mem_total_kb as f64) * 100.0,
            );
        } else {
            errors.insert("mem".into(), "memtotal=0".into());
        }
    }
    if want("swap") {
        if now.swap_total_kb > 0 {
            let used = now.swap_total_kb.saturating_sub(now.swap_free_kb);
            values.insert(
                "swap".into(),
                (used as f64 / now.swap_total_kb as f64) * 100.0,
            );
        } else {
            // Hosts without swap report 0/0 — that's fine, surface as 0%.
            values.insert("swap".into(), 0.0);
        }
    }
    if want("disk") {
        if now.disk_total_kb > 0 {
            values.insert(
                "disk".into(),
                (now.disk_used_kb as f64 / now.disk_total_kb as f64) * 100.0,
            );
        }
    }
    if want("load") {
        values.insert("load".into(), now.load1);
    }
    if want("net") {
        if let Some(p) = prev {
            let dt_ms = now.ts.saturating_sub(p.ts);
            if dt_ms > 0 {
                let secs = dt_ms as f64 / 1000.0;
                let dr = now.net_rx_bytes.saturating_sub(p.net_rx_bytes) as f64 / secs;
                let dt = now.net_tx_bytes.saturating_sub(p.net_tx_bytes) as f64 / secs;
                values.insert("net_in".into(), dr);
                values.insert("net_out".into(), dt);
            }
        }
    }
    // Custom metrics: pull each one's captured stdout and apply its parse
    // mode. Numeric outputs land in `values` (so the UI ring buffer picks
    // them up for sparklines); text outputs land in `texts`.
    for cm in customs {
        let raw = match now.custom_text.get(&cm.id) {
            Some(s) => s.trim().to_string(),
            None => {
                errors.insert(cm.id.clone(), "no output".into());
                continue;
            }
        };
        match cm.parse.as_str() {
            "number" => match extract_number(&raw) {
                Some(v) => { values.insert(cm.id.clone(), v); }
                None => { errors.insert(cm.id.clone(), "no numeric token in output".into()); }
            },
            "regex" => {
                let pattern = cm.regex.as_deref().unwrap_or("");
                match apply_regex_number(pattern, &raw) {
                    Ok(v) => { values.insert(cm.id.clone(), v); }
                    Err(e) => { errors.insert(cm.id.clone(), e); }
                }
            }
            // "text" or anything else → treat as text
            _ => {
                texts.insert(cm.id.clone(), raw);
            }
        }
    }

    // A hostile server's `nan`, `inf` or endless digit run is not a value
    // (serde_json would send it as null into the window's history).
    let bad: Vec<String> = values.iter().filter(|(_, v)| !v.is_finite()).map(|(k, _)| k.clone()).collect();
    for key in bad {
        values.remove(&key);
        errors.insert(key, "not a finite number".into());
    }

    Sample {
        node_id,
        ts: now.ts,
        values,
        errors,
        texts,
    }
}

/// Pull the first numeric token (possibly with sign and decimal) out of any
/// stdout. Tolerant: works for "42", "42.5", "load 1.2 1.0 0.9", "  3 ", etc.
fn extract_number(s: &str) -> Option<f64> {
    let mut chars = s.chars().peekable();
    let mut buf = String::new();
    let mut in_num = false;
    while let Some(&c) = chars.peek() {
        if !in_num {
            if c == '-' || c == '+' || c.is_ascii_digit() {
                in_num = true;
                buf.push(c);
                chars.next();
                continue;
            }
            chars.next();
        } else {
            if c.is_ascii_digit() || c == '.' {
                buf.push(c);
                chars.next();
            } else {
                break;
            }
        }
    }
    if buf.is_empty() { None } else { buf.parse::<f64>().ok() }
}

/// Apply a user-provided regex to the output and pull the first capture
/// group as a number. Empty pattern, compile failure, or non-numeric
/// capture all surface as a clear error for the UI.
fn apply_regex_number(pattern: &str, text: &str) -> Result<f64, String> {
    if pattern.trim().is_empty() {
        return Err("regex pattern is empty".into());
    }
    let re = regex::Regex::new(pattern).map_err(|e| format!("bad regex: {}", e))?;
    let caps = re.captures(text).ok_or("regex did not match")?;
    let m = caps.get(1).or_else(|| caps.get(0)).ok_or("no capture group")?;
    m.as_str().trim().parse::<f64>()
        .map_err(|e| format!("captured value not numeric: {}", e))
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_test_server::*;
    use std::sync::Mutex as StdMutex;

    type Db = Arc<std::sync::Mutex<Option<rusqlite::Connection>>>;
    type Servers = Arc<StdMutex<Vec<Arc<StdMutex<Seen>>>>>;

    /// A profile database that trusts the test server's host key for 127.0.0.1:22.
    fn trusting_db() -> Db {
        let conn = crate::open_vault_memory_db().unwrap();
        crate::create_vault_schema(&conn).unwrap();
        let fp = crate::ssh_manager::host_key_fingerprint(ed25519_key(1).public_key());
        conn.execute(
            "INSERT INTO known_hosts (host, port, fingerprint, key_type) VALUES ('127.0.0.1', 22, ?1, 'ssh-ed25519')",
            [fp],
        )
        .unwrap();
        Arc::new(std::sync::Mutex::new(Some(conn)))
    }

    fn node(password: &str) -> NodeAuth {
        NodeAuth {
            host: "127.0.0.1".into(),
            port: 22,
            username: USER.into(),
            password: Some(password.into()),
            private_key: None,
            passphrase: None,
            proxy_type: "none".into(),
            proxy_host: None,
            proxy_port: None,
            policy: Default::default(),
            jump: None,
        }
    }

    /// Connects every attempt to a fresh scripted server and keeps what each
    /// saw; like `connect_for_monitor`, the login is checked first.
    fn scripted(script: Script, db: Db, servers: Servers) -> Connector {
        Arc::new(move |auth, timeout| {
            let (script, db, servers) = (script.clone(), Arc::clone(&db), Arc::clone(&servers));
            Box::pin(async move {
                let login = prepare_login(&auth)?;
                let served = serve(script, vec![ed25519_key(1)]);
                servers.lock().unwrap().push(Arc::clone(&served.seen));
                establish(served.stream, &db, &auth, login, timeout).await
            })
        })
    }

    async fn link_to(script: Script, db: &Db) -> Link {
        let served = serve(script, vec![ed25519_key(1)]);
        let auth = node(PASSWORD);
        let login = prepare_login(&auth).unwrap();
        establish(served.stream, db, &auth, login, Duration::from_secs(5)).await.unwrap()
    }

    fn passwords_tried(servers: &Servers) -> usize {
        servers.lock().unwrap().iter().map(|s| s.lock().unwrap().passwords.len()).sum()
    }

    #[derive(Default)]
    struct Recorded {
        statuses: Vec<MonitorInfo>,
        samples: Vec<Sample>,
        outages: Vec<OutageEvent>,
        stops: Vec<StoppedEvent>,
    }

    fn recorder() -> (MonitorEvents, Arc<StdMutex<Recorded>>) {
        let rec = Arc::new(StdMutex::new(Recorded::default()));
        let (a, b, c, d) = (Arc::clone(&rec), Arc::clone(&rec), Arc::clone(&rec), Arc::clone(&rec));
        let events = MonitorEvents {
            status: Arc::new(move |i| a.lock().unwrap().statuses.push(i.clone())),
            sample: Arc::new(move |s| b.lock().unwrap().samples.push(s.clone())),
            outage: Arc::new(move |o| c.lock().unwrap().outages.push(o.clone())),
            recovered: Arc::new(|_| {}),
            stopped: Arc::new(move |e| d.lock().unwrap().stops.push(e.clone())),
        };
        (events, rec)
    }

    fn fast_settings() -> SharedSettings {
        Arc::new(Mutex::new(MonitorSettings {
            interval_secs: 1,
            connect_timeout_secs: 5,
            poll_timeout_secs: 5,
            ..MonitorSettings::default()
        }))
    }

    const FAST: PollerTiming = PollerTiming { first_backoff: Duration::from_millis(10), max_backoff: Duration::from_millis(40) };

    async fn start(map: &MonitorMap, events: MonitorEvents, resolve: Resolver, connect: Connector) {
        let poller = Poller { events, settings: fast_settings(), node_name: "web".into(), resolve, connect, timing: FAST };
        start_monitor(Arc::clone(map), 1, vec!["load".into()], Vec::new(), false, poller).await;
    }

    fn new_map() -> MonitorMap {
        Arc::new(Mutex::new(HashMap::new()))
    }

    async fn stopped_reason(map: &MonitorMap) -> Option<String> {
        let entry = map.lock().await.get(&1).cloned()?;
        let reason = entry.state.lock().await.auth_failed.clone();
        reason
    }

    async fn wait_stopped(map: &MonitorMap) -> String {
        for _ in 0..200 {
            if let Some(reason) = stopped_reason(map).await {
                return reason;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the monitor did not stop");
    }

    /// F-017: a refused login is tried three times in a row, then the monitor
    /// stops instead of hammering the server (fail2ban), and says why. It is
    /// not an outage. Resume tries again.
    #[tokio::test]
    async fn a_refused_login_stops_the_monitor_after_three_attempts() {
        let (db, servers, map) = (trusting_db(), Servers::default(), new_map());
        let (events, rec) = recorder();
        let connect = scripted(Script::default(), db, Arc::clone(&servers));
        start(&map, events, Arc::new(|| Ok(node("wrong"))), connect).await;
        let reason = wait_stopped(&map).await;
        assert!(reason.contains("refused 3 times"), "{reason}");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(passwords_tried(&servers), 3, "no attempt after the third refusal");
        {
            let rec = rec.lock().unwrap();
            assert!(rec.outages.is_empty(), "a refused login is not an outage");
            assert_eq!(rec.stops.len(), 1);
            assert!(rec.statuses.last().is_some_and(|s| s.auth_failed.is_some() && !s.connected));
        }
        set_paused(Arc::clone(&map), 1, false).await.unwrap();
        assert!(eventually(|| passwords_tried(&servers) == 6).await, "Resume tries three times again");
        wait_stopped(&map).await;
        stop_all(&map).await;
    }

    /// F-017: a server that refuses by dropping the connection (OpenSSH past
    /// MaxAuthTries) counts strikes too, instead of being retried forever as
    /// an outage.
    #[tokio::test]
    async fn a_refusal_by_disconnect_counts_as_a_strike() {
        let (db, servers, map) = (trusting_db(), Servers::default(), new_map());
        let (events, rec) = recorder();
        let script = Script { drop_on_auth: true, ..Script::default() };
        start(&map, events, Arc::new(|| Ok(node(PASSWORD))), scripted(script, db, Arc::clone(&servers))).await;
        let reason = wait_stopped(&map).await;
        assert!(reason.contains("refused 3 times") && reason.contains("closed the connection"), "{reason}");
        assert_eq!(servers.lock().unwrap().len(), 3);
        assert!(rec.lock().unwrap().outages.is_empty());
        stop_all(&map).await;
    }

    /// F-017: without anything to log in with, or with a key that cannot be
    /// read, the monitor stops at once and the server is not contacted.
    #[tokio::test]
    async fn a_login_it_cannot_use_stops_the_monitor_before_any_connect() {
        let mut no_credential = node("x");
        no_credential.password = None;
        let mut bad_key = node("x");
        bad_key.private_key = Some("-----BEGIN OPENSSH PRIVATE KEY-----\nnot a key\n-----END OPENSSH PRIVATE KEY-----".into());
        for (auth, expect) in [(no_credential, "no saved password or key"), (bad_key, "private key could not be read")] {
            let (db, servers, map) = (trusting_db(), Servers::default(), new_map());
            let (events, _rec) = recorder();
            start(&map, events, Arc::new(move || Ok(auth.clone())), scripted(Script::default(), db, Arc::clone(&servers))).await;
            let reason = wait_stopped(&map).await;
            assert!(reason.contains(expect), "{reason}");
            assert!(servers.lock().unwrap().is_empty(), "nothing was sent");
            stop_all(&map).await;
        }
    }

    /// N-003: a node whose login was deleted (the resolver refuses) stops
    /// with that reason.
    #[tokio::test]
    async fn a_deleted_login_stops_the_monitor_with_the_reason() {
        let (db, servers, map) = (trusting_db(), Servers::default(), new_map());
        let (events, _rec) = recorder();
        let resolve: Resolver = Arc::new(|| Err("This server uses a saved login, but none is set.".into()));
        start(&map, events, resolve, scripted(Script::default(), db, Arc::clone(&servers))).await;
        assert!(wait_stopped(&map).await.contains("saved login"));
        assert!(servers.lock().unwrap().is_empty());
        stop_all(&map).await;
    }

    /// F-017: a host key that is not trusted stops the monitor at once; no
    /// login is attempted.
    #[tokio::test]
    async fn an_untrusted_host_key_stops_the_monitor_without_a_login() {
        let conn = crate::open_vault_memory_db().unwrap();
        crate::create_vault_schema(&conn).unwrap();
        let db: Db = Arc::new(std::sync::Mutex::new(Some(conn)));
        let (servers, map) = (Servers::default(), new_map());
        let (events, _rec) = recorder();
        start(&map, events, Arc::new(|| Ok(node(PASSWORD))), scripted(Script::default(), db, Arc::clone(&servers))).await;
        let reason = wait_stopped(&map).await;
        assert!(reason.contains("not among your trusted keys"), "{reason}");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(servers.lock().unwrap().len(), 1, "one handshake, no retry");
        assert_eq!(passwords_tried(&servers), 0);
        stop_all(&map).await;
    }

    /// F-017: a server that only takes keyboard-interactive logins is not
    /// tried: the monitor stops before sending the password.
    #[tokio::test]
    async fn a_keyboard_interactive_only_server_is_not_tried() {
        let (db, servers, map) = (trusting_db(), Servers::default(), new_map());
        let (events, _rec) = recorder();
        let script = Script { steps: vec![russh::MethodKind::KeyboardInteractive], ..Script::default() };
        start(&map, events, Arc::new(|| Ok(node(PASSWORD))), scripted(script, db, Arc::clone(&servers))).await;
        let reason = wait_stopped(&map).await;
        assert!(reason.contains("keyboard-interactive"), "{reason}");
        assert_eq!(passwords_tried(&servers), 0);
        assert_eq!(servers.lock().unwrap()[0].lock().unwrap().kbi_rounds, 0);
        stop_all(&map).await;
    }

    /// F-017: the login is read again for each connect, so a password fixed
    /// in the vault is used without restarting the monitor.
    #[tokio::test]
    async fn the_login_is_read_again_for_each_connect() {
        let (db, servers, map) = (trusting_db(), Servers::default(), new_map());
        let (events, rec) = recorder();
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&reads);
        let resolve: Resolver = Arc::new(move || {
            let first = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
            Ok(node(if first { "old" } else { PASSWORD }))
        });
        let script = Script { exec_output: Some(b"LOAD 1\n".to_vec()), ..Script::default() };
        start(&map, events, resolve, scripted(script, db, Arc::clone(&servers))).await;
        assert!(eventually(|| !rec.lock().unwrap().samples.is_empty()).await);
        assert_eq!(passwords_tried(&servers), 2);
        assert!(stopped_reason(&map).await.is_none());
        stop_all(&map).await;
    }

    /// F-018: probe output is capped at 1 MiB; a server that prints more
    /// fails that poll instead of filling memory, and the connection stays.
    #[tokio::test]
    async fn probe_output_over_the_cap_fails_the_poll() {
        let db = trusting_db();
        let link = link_to(Script { exec_output: Some(vec![b'x'; 3 << 20]), ..Script::default() }, &db).await;
        let err = poll_once(&link.session, &[], Duration::from_secs(10)).await.unwrap_err();
        assert!(matches!(&err, PollError::Output(m) if m.contains("1 MiB")), "{err:?}");
        assert!(!link.session.is_closed(), "the connection stays");
    }

    /// F-018: the poller shows an over-cap probe as an error of every metric,
    /// keeps its connection and does not call it an outage.
    #[tokio::test]
    async fn an_over_cap_probe_is_a_metric_error_not_an_outage() {
        let (db, servers, map) = (trusting_db(), Servers::default(), new_map());
        let (events, rec) = recorder();
        let script = Script { exec_output: Some(vec![b'x'; 3 << 20]), ..Script::default() };
        start(&map, events, Arc::new(|| Ok(node(PASSWORD))), scripted(script, db, Arc::clone(&servers))).await;
        assert!(eventually(|| rec.lock().unwrap().samples.len() >= 2).await);
        {
            let rec = rec.lock().unwrap();
            assert!(rec.samples[0].errors.get("load").is_some_and(|e| e.contains("1 MiB")), "{:?}", rec.samples[0]);
            assert!(rec.samples[0].values.is_empty());
            assert!(rec.outages.is_empty());
            assert!(rec.statuses.last().is_some_and(|s| s.connected && s.last_error.as_deref().is_some_and(|e| e.contains("1 MiB"))));
        }
        assert_eq!(servers.lock().unwrap().len(), 1, "polled again on the same connection");
        stop_all(&map).await;
    }

    /// A paused monitor waits for Resume instead of waking every second, and
    /// starts at once when resumed.
    #[tokio::test]
    async fn a_paused_monitor_starts_as_soon_as_it_is_resumed() {
        let (db, servers, map) = (trusting_db(), Servers::default(), new_map());
        let (events, _rec) = recorder();
        let script = Script { exec_output: Some(b"LOAD 1\n".to_vec()), ..Script::default() };
        let poller = Poller {
            events,
            settings: fast_settings(),
            node_name: "web".into(),
            resolve: Arc::new(|| Ok(node(PASSWORD))),
            connect: scripted(script, db, Arc::clone(&servers)),
            timing: FAST,
        };
        start_monitor(Arc::clone(&map), 1, vec!["load".into()], Vec::new(), true, poller).await;
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert!(servers.lock().unwrap().is_empty(), "nothing while paused");
        for _ in 0..3 {
            set_paused(Arc::clone(&map), 1, true).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            let before = servers.lock().unwrap().len();
            let resumed = std::time::Instant::now();
            set_paused(Arc::clone(&map), 1, false).await.unwrap();
            while servers.lock().unwrap().len() == before {
                assert!(resumed.elapsed() < Duration::from_millis(500), "resumed within 500 ms (the old loop slept 1 s)");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        stop_all(&map).await;
    }

    /// A monitor logs in, runs its probe and reports a sample and its status.
    #[tokio::test]
    async fn a_monitor_logs_in_and_delivers_samples() {
        let (db, servers, map) = (trusting_db(), Servers::default(), new_map());
        let (events, rec) = recorder();
        let script = Script { exec_output: Some(b"LOAD 0.5\nMEM 1000 250\n".to_vec()), ..Script::default() };
        start(&map, events, Arc::new(|| Ok(node(PASSWORD))), scripted(script, db, Arc::clone(&servers))).await;
        assert!(eventually(|| !rec.lock().unwrap().samples.is_empty()).await);
        let sample = rec.lock().unwrap().samples[0].clone();
        assert_eq!(sample.values.get("load"), Some(&0.5));
        assert!(rec.lock().unwrap().statuses.iter().any(|s| s.connected));
        assert_eq!(passwords_tried(&servers), 1);
        stop_all(&map).await;
    }

    /// A hostile server's `nan`/`inf` or an endless digit run never reaches
    /// the window as a value: the metric reports an error instead.
    #[test]
    fn non_finite_values_are_dropped() {
        let long_number = "9".repeat(400);
        for probe in ["LOAD nan", "LOAD inf", "LOAD -infinity"] {
            let now = parse_probe(probe).unwrap();
            let s = compute_sample(1, &now, &None, &["load".into()], &[]);
            assert!(!s.values.contains_key("load"), "{probe}: {:?}", s.values);
            assert!(s.errors.contains_key("load"), "{probe}");
        }
        let customs = [
            CustomMetric { id: "n".into(), name: "n".into(), command: String::new(), parse: "number".into(), regex: None, display: "sparkline".into(), unit: None },
            CustomMetric { id: "r".into(), name: "r".into(), command: String::new(), parse: "regex".into(), regex: Some("v=(\\S+)".into()), display: "sparkline".into(), unit: None },
        ];
        let mut now = RawSnapshot::default();
        now.custom_text.insert("n".into(), long_number);
        now.custom_text.insert("r".into(), "v=inf".into());
        let s = compute_sample(1, &now, &None, &[], &customs);
        assert!(s.values.values().all(|v| v.is_finite()), "{:?}", s.values);
        assert!(s.errors.contains_key("n") && s.errors.contains_key("r"), "{:?}", s.errors);
    }
}
