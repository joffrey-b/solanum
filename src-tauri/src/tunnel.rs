//! SSH tunnel management, the three OpenSSH forward modes:
//!
//!   * **Local forward** (`-L`): bind a local TCP listener and, for each
//!     incoming connection, open a `direct-tcpip` channel through SSH to a
//!     fixed `host:port` reachable from the server.
//!
//!   * **Dynamic forward** (`-D`): bind a local TCP listener that speaks
//!     SOCKS4/4a, SOCKS5/5h (no authentication, CONNECT only) and HTTP
//!     (CONNECT and absolute-URI requests). Each request opens its own
//!     `direct-tcpip` channel to the requested target.
//!
//!   * **Remote forward** (`-R`): ask the server to listen (`tcpip-forward`);
//!     each connection it accepts arrives as a `forwarded-tcpip` channel that
//!     is bridged to a local `host:port`.
//!
//! A bare port listens on loopback on both sides, as with OpenSSH; a rule
//! that listens beyond it is flagged `exposed` (F-020, F-068). A connection
//! with no traffic for 15 minutes is closed (`IDLE_TIMEOUT`).
//!
//! Each tunnel has a stable `id` so the UI can list, refresh stats, and stop
//! it independently. State updates are pushed over the
//! `tunnel-update-{session_id}` event so the panel doesn't have to poll.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, oneshot, Mutex, Semaphore};

/// The SSH connection a tunnel rides, shared the way the app shares it. Any
/// client handler: the app's `ClientHandler`, or a test's.
type SshHandle<H> = Arc<Mutex<russh::client::Handle<H>>>;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelSpec {
    /// "D" (dynamic: SOCKS4/4a/5/5h and HTTP proxy), "L" (local forward),
    /// "R" (remote forward).
    #[serde(rename = "type")]
    pub kind: String,
    /// Where it listens: a port or "addr:port". For L and D on this machine
    /// (a bare port is 127.0.0.1); for R on the server (a bare port asks for
    /// `localhost`, port 0 lets the server choose).
    pub local: String,
    /// The target "host:port": reached from the server for L, from this
    /// machine for R. Ignored by D.
    #[serde(default)]
    pub remote: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TunnelStatus {
    pub id: String,
    pub session_id: String,
    pub kind: String,
    pub listen_addr: String,
    pub target: String,
    pub state: String, // "starting", "listening", "error", "closed"
    pub error: Option<String>,
    /// Listens beyond loopback (F-020, F-068): on this machine's network for
    /// L and D, on the server's for R (if its `GatewayPorts` allows).
    pub exposed: bool,
    /// Total accepted connections since this tunnel started (monotonic).
    pub conns_total: u32,
    /// Number of connections currently bridged through this tunnel. Backed
    /// by an RAII guard on each spawned bridge task: the count increments
    /// when the task starts and decrements when the task's future ends,
    /// regardless of whether it ended cleanly, with an error, or via the
    /// stop-signal shutdown path.
    pub conns_active: u32,
}

pub struct ActiveTunnel {
    pub status: Arc<Mutex<TunnelStatus>>,
    pub stop_tx: Option<oneshot::Sender<()>>,
    /// JoinHandle of the spawned listener task. Held so that
    /// `stop_all_for_session` (and explicit `stop_tunnel`) can await
    /// the task's actual exit before declaring the tunnel torn down.
    /// Without this the port stays bound for several seconds on Windows
    /// while the OS keeps the socket in TIME_WAIT, racing with reconnects.
    pub join: Option<tokio::task::JoinHandle<()>>,
    /// The original spec used to start this tunnel. Carried so that an
    /// explicit `stop_tunnel` command can drop the matching entry from the
    /// per-session replay list (otherwise stopped tunnels would silently
    /// re-open on the next reconnect).
    pub spec: TunnelSpec,
    /// Sends the "closed" update when a stop has to abort the task, which
    /// then never sends it itself. A boxed callback rather than an
    /// `AppHandle`, so code the unit tests reach never references event
    /// emission: that pulls Tauri's window runtime into the Windows test
    /// binary, whose menu code imports a Common Controls v6 function the
    /// test binary (built without the app's manifest) cannot load. `None`
    /// only in tests.
    pub on_forced_stop: Option<Box<dyn FnOnce() + Send + Sync>>,
}

pub type TunnelMap = Arc<Mutex<HashMap<String, ActiveTunnel>>>;

/// Where a tunnel reports: its status (sent as `tunnel-update-{session}` by
/// the app) and its connection log (`tunnel-log-{session}`). Callbacks built
/// in `lib.rs` (`tunnel_events`) rather than an `AppHandle`, so tunnels run
/// in unit tests: code the tests reach must not hold or call into the app
/// (see `ActiveTunnel::on_forced_stop`).
#[derive(Clone)]
pub struct TunnelEvents {
    pub update: Arc<dyn Fn(&TunnelStatus) + Send + Sync>,
    pub log: Arc<LogSink>,
}

/// Receives the session id and a log entry.
pub type LogSink = dyn Fn(&str, &TunnelLogEntry<'_>) + Send + Sync;

/// Lookup record for an active remote (-R) forward. The SSH server listens on
/// the port it is keyed by (registered via `tcpip_forward`); when an inbound
/// connection hits that port the server opens a `forwarded-tcpip` channel to
/// us, and our `ClientHandler` consults this map to know what local target
/// to bridge to. These entries live in `SshState`, which unit tests build and
/// drop, so nothing here holds an `AppHandle` (see `TunnelEvents`).
#[derive(Clone)]
pub struct ForwardEntry {
    /// The tunnel that registered this port: only it removes the entry.
    tunnel_id: String,
    target: Arc<ForwardTarget>,
    /// One permit per bridged connection: the cap local and dynamic tunnels
    /// have (F-065).
    limiter: Arc<Semaphore>,
    /// Ends every bridged connection when the tunnel stops. A bridge
    /// subscribes while it finds the entry (under the map lock, so it cannot
    /// miss a stop sent after the entry is removed) and holds only the
    /// receiver.
    shutdown: broadcast::Sender<()>,
    /// How long a bridged connection may take to reach the local target.
    connect_timeout: Duration,
}

/// What a remote forward's connections share: where they go, what they report.
struct ForwardTarget {
    host: String,
    port: u16,
    /// Tunnel status (shared with the listing UI): connection counts.
    status: Arc<Mutex<TunnelStatus>>,
    ctx: LogCtx,
    active: Arc<AtomicU32>,
}

/// Per-session map of `server_port → ForwardEntry`. Created once per SSH
/// connection in `initiate_connection`, handed to both the `ClientHandler`
/// (for inbound channel lookup) and to `tunnel::start_tunnel` (for "R"
/// registrations).
pub type ForwardedTargets = Arc<Mutex<HashMap<u32, ForwardEntry>>>;

// ---------------------------------------------------------------------------
// Spec parsing
// ---------------------------------------------------------------------------

/// Splits `host:port` or `[v6]:port`: the one place every address a tunnel is
/// given (rules, SOCKS and HTTP requests) is read (F-066). The host comes back
/// without brackets, which is what `direct-tcpip`, `tcpip-forward` and a local
/// connect take (RFC 4254 names hosts bare; sshd hands the string to
/// `getaddrinfo`, which refuses `[::1]`). The port is required, so an IPv6
/// address may also be written without brackets (`::1:80`, split at the last
/// `:`, as rules always were); the host must then be a valid IPv6 address.
fn split_host_port(s: &str) -> Result<(String, u16), String> {
    let s = s.trim();
    let (host, port) = match s.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']').ok_or_else(|| format!("{s:?} lacks the closing ]"))?;
            let port = after.strip_prefix(':').ok_or_else(|| format!("{s:?} must be [address]:port"))?;
            (host, port)
        }
        None => {
            let (host, port) = s.rsplit_once(':').ok_or_else(|| format!("{s:?} must be host:port"))?;
            if host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(format!("{s:?}: write an IPv6 address in brackets, like [::1]:80"));
            }
            (host, port)
        }
    };
    if host.is_empty() {
        return Err(format!("{s:?} has no host"));
    }
    let port = port.parse::<u16>().map_err(|_| format!("{s:?} has an invalid port"))?;
    Ok((host.to_string(), port))
}

/// `host:port` for display, with an IPv6 address bracketed again.
fn host_port(host: &str, port: impl std::fmt::Display) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// A host name a SOCKS client sent, brackets removed (`[::1]` is `::1`).
fn bare_host(name: String) -> String {
    match name.strip_prefix('[').and_then(|n| n.strip_suffix(']')) {
        Some(inner) => inner.to_string(),
        None => name,
    }
}

/// Where a local or dynamic tunnel listens: a bare port is loopback; a host
/// is an IP address or `localhost`. Other names are refused: what they
/// resolve to (and so who can connect) is unknown until bound.
fn parse_listen(local: &str) -> Result<SocketAddr, String> {
    let s = local.trim();
    if s.is_empty() {
        return Err("Local address is empty".into());
    }
    let (host, port) = if s.contains(':') {
        split_host_port(s).map_err(|e| format!("Bind address {e}"))?
    } else {
        let port = s.parse::<u16>().map_err(|_| format!("Invalid port {s:?}"))?;
        ("127.0.0.1".to_string(), port)
    };
    if port == 0 {
        return Err(format!("Bind address {s:?}: the port must be between 1 and 65535"));
    }
    let ip = if host.eq_ignore_ascii_case("localhost") {
        std::net::IpAddr::from(std::net::Ipv4Addr::LOCALHOST)
    } else {
        host.parse::<std::net::IpAddr>()
            .map_err(|_| format!("Bind address {s:?}: use an IP address or localhost"))?
    };
    Ok(SocketAddr::new(ip, port))
}

/// Where a remote tunnel asks the server to listen; the port may be 0.
fn parse_remote_bind(local: &str) -> Result<(String, u16), String> {
    let s = local.trim();
    if s.is_empty() {
        return Err("Server bind address is empty".into());
    }
    if s.contains(':') {
        return split_host_port(s).map_err(|e| format!("Server bind address {e}"));
    }
    let port = s.parse::<u16>().map_err(|_| format!("Invalid server port {s:?}"))?;
    // What `ssh -R port:...` asks for (OpenSSH's channel_rfwd_bind_host):
    // with `GatewayPorts clientspecified` sshd then listens on its loopback
    // only, both families (F-020). `GatewayPorts yes` listens everywhere
    // whatever is asked; `no` (the default) on loopback whatever is asked.
    Ok(("localhost".to_string(), port))
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Whether a rule listens beyond loopback: other machines could connect to
/// it (on this machine's network for L and D; on the server's for R, if the
/// server allows it). False for a rule that does not parse.
pub fn listens_beyond_loopback(spec: &TunnelSpec) -> bool {
    match spec.kind.as_str() {
        "L" | "D" => parse_listen(&spec.local).is_ok_and(|addr| !addr.ip().is_loopback()),
        "R" => parse_remote_bind(&spec.local).is_ok_and(|(host, _)| !is_loopback_host(&host)),
        _ => false,
    }
}

/// The warning a tunnel that listens beyond loopback logs when it starts.
pub fn exposure_warning(spec: &TunnelSpec) -> &'static str {
    match spec.kind.as_str() {
        "R" => "The server is asked to listen beyond its loopback: if its GatewayPorts setting allows it, machines on the server's network can connect to this port.",
        "D" => "Listens beyond loopback: machines that can reach this computer can use this proxy, and with it your SSH session, without a password.",
        _ => "Listens beyond loopback: machines that can reach this computer can connect to this port.",
    }
}

/// A tunnel's target (`L`, and the local side of `R`).
fn parse_target(remote: &str) -> Result<(String, u16), String> {
    let (host, port) = split_host_port(remote).map_err(|e| format!("Target {e}"))?;
    if port == 0 {
        return Err(format!("Target {:?}: the port must be between 1 and 65535", remote.trim()));
    }
    Ok((host, port))
}

/// Whether a rule would start: what `start_tunnel` parses, without binding
/// or asking the server anything. A node's rules are checked with it when the
/// node is saved, so a saved rule always parses (N-017).
pub fn check_spec(spec: &TunnelSpec) -> Result<(), String> {
    match spec.kind.as_str() {
        "L" => {
            parse_listen(&spec.local)?;
            parse_target(&spec.remote)?;
        }
        "D" => {
            parse_listen(&spec.local)?;
        }
        "R" => {
            parse_remote_bind(&spec.local)?;
            parse_target(&spec.remote)?;
        }
        other => return Err(format!("Unknown tunnel kind: {}", other)),
    }
    Ok(())
}

fn next_tunnel_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("tun-{}-{}", ms, n)
}

// ---------------------------------------------------------------------------
// Status update helpers
// ---------------------------------------------------------------------------

/// Per-event log entry pushed to `tunnel-log-{session_id}`. The UI keeps a
/// short rolling buffer per tunnel so the user can see what addresses traffic
/// is going to and which connections are failing without having to dig
/// through stderr or a debug log file.
#[derive(Debug, Clone, Serialize)]
pub struct TunnelLogEntry<'a> {
    pub tunnel_id: &'a str,
    /// Wall-clock millis since UNIX epoch. UI formats this on render so we
    /// don't pay a String-allocation cost on the hot bridge path.
    pub ts_ms: u128,
    /// "info" | "warn" | "error". Drives the UI colour.
    pub level: &'a str,
    /// Short human-readable event ("connect", "fail", "close", ...).
    pub event: &'a str,
    /// Destination the connection targeted, when known.
    pub target: Option<String>,
    /// Source peer (the client that connected to our local listener).
    pub peer: Option<String>,
    /// Free-form detail — typically the error string on failures.
    pub message: Option<String>,
}

fn now_ms() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// One tunnel's connection log: whose it is and where it goes.
#[derive(Clone)]
struct LogCtx {
    events: TunnelEvents,
    session_id: String,
    tunnel_id: String,
}

impl LogCtx {
    fn log(&self, level: &str, event: &str, target: Option<String>, peer: Option<String>, message: Option<String>) {
        let entry = TunnelLogEntry {
            tunnel_id: &self.tunnel_id,
            ts_ms: now_ms(),
            level,
            event,
            target,
            peer,
            message,
        };
        (self.events.log)(&self.session_id, &entry);
    }
}

/// RAII counter for in-flight bridged connections. Increments
/// `status.conns_active` on construction and decrements it on drop,
/// emitting an update either side so the UI tracks the change in real
/// time. Drop is sync, so the decrement-and-emit step is offloaded to a
/// short-lived spawned task — the count itself is held in an AtomicU32
/// shared across the listener so the actual increment/decrement is
/// instant and lock-free; the mutex'd `TunnelStatus` is only touched
/// for the UI emit.
struct ActiveGuard {
    counter: Arc<AtomicU32>,
    status: Arc<Mutex<TunnelStatus>>,
    events: TunnelEvents,
}

impl ActiveGuard {
    async fn enter(
        counter: Arc<AtomicU32>,
        status: Arc<Mutex<TunnelStatus>>,
        events: TunnelEvents,
    ) -> Self {
        let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
        let snapshot = {
            let mut s = status.lock().await;
            s.conns_active = n;
            s.conns_total = s.conns_total.saturating_add(1);
            s.clone()
        };
        (events.update)(&snapshot);
        Self { counter, status, events }
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        let n = self.counter.fetch_sub(1, Ordering::Relaxed).saturating_sub(1);
        let status = Arc::clone(&self.status);
        let events = self.events.clone();
        tokio::spawn(async move {
            let snapshot = {
                let mut s = status.lock().await;
                s.conns_active = n;
                s.clone()
            };
            (events.update)(&snapshot);
        });
    }
}

async fn set_state(
    events: &TunnelEvents,
    status_arc: &Arc<Mutex<TunnelStatus>>,
    state: &str,
    error: Option<String>,
) {
    let snapshot = {
        let mut s = status_arc.lock().await;
        s.state = state.to_string();
        if let Some(e) = error {
            s.error = Some(e);
        }
        s.clone()
    };
    (events.update)(&snapshot);
}

// ---------------------------------------------------------------------------
// Public entry: start a tunnel
// ---------------------------------------------------------------------------

/// Bind a local listener, retrying briefly on `AddrInUse`. A reconnect can race
/// the previous listener's teardown, and on Windows a just-freed port can linger
/// momentarily (there is no `SO_REUSEADDR` on the tokio listener), so a single
/// bind would spuriously fail the auto-restore — and the caller used to strip
/// the spec on that failure, dropping the tunnel for good until a manual
/// restart. Retrying over ~1.5s rides out that transient window; a
/// non-`AddrInUse` error (bad address, permission) still fails immediately.
async fn bind_with_retry(addr: &str) -> std::io::Result<TcpListener> {
    let mut last: Option<std::io::Error> = None;
    for _ in 0..6 {
        match TcpListener::bind(addr).await {
            Ok(l) => return Ok(l),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                last = Some(e);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::AddrInUse, "bind retries exhausted")))
}

pub async fn start_tunnel<H: russh::client::Handler + 'static>(
    events: TunnelEvents,
    session_id: String,
    handle: SshHandle<H>,
    tunnels_map: TunnelMap,
    forwarded_targets: ForwardedTargets,
    spec: TunnelSpec,
) -> Result<String, String> {
    let id = next_tunnel_id();
    let ctx = LogCtx { events: events.clone(), session_id: session_id.clone(), tunnel_id: id.clone() };
    let new_status = |kind: &str, listen_addr: String, target: String| TunnelStatus {
        id: id.clone(),
        session_id: session_id.clone(),
        kind: kind.into(),
        listen_addr,
        target,
        state: "starting".into(),
        error: None,
        exposed: listens_beyond_loopback(&spec),
        conns_total: 0,
        conns_active: 0,
    };
    let (stop_tx, stop_rx) = oneshot::channel::<()>();

    // Everything that can fail happens here, on the caller, before the task
    // exists: a local port that is taken or a forward the server refuses is
    // the command's error, rather than a later "error" update the UI may have
    // stopped watching (F-067).
    type Work = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
    let (status, work): (Arc<Mutex<TunnelStatus>>, Work) = match spec.kind.as_str() {
        "L" | "D" => {
            let addr = parse_listen(&spec.local)?;
            let target = if spec.kind == "L" { Some(parse_target(&spec.remote)?) } else { None };
            let listen_addr = addr.to_string();
            let listener = bind_with_retry(&listen_addr)
                .await
                .map_err(|e| format!("bind {}: {}", listen_addr, e))?;
            match target {
                Some((host, port)) => {
                    let status = Arc::new(Mutex::new(new_status("local", listen_addr, host_port(&host, port))));
                    let work = run_local_forward(ctx.clone(), handle, listener, (host, port), Arc::clone(&status), stop_rx);
                    (status, Box::pin(work))
                }
                None => {
                    let status = Arc::new(Mutex::new(new_status("dynamic", listen_addr, "SOCKS / HTTP".into())));
                    let work = run_dynamic_forward(ctx.clone(), handle, listener, Arc::clone(&status), stop_rx);
                    (status, Box::pin(work))
                }
            }
        }
        "R" => {
            let (bind, port) = parse_remote_bind(&spec.local)?;
            // Validate local target now so we don't register a server-side
            // listener that maps to nowhere.
            let target = parse_target(&spec.remote)?;
            let status = Arc::new(Mutex::new(new_status("remote", host_port(&bind, port), host_port(&target.0, target.1))));
            let forward =
                open_remote_forward(&ctx, &handle, &forwarded_targets, bind, port, target, Arc::clone(&status), FORWARD_REQUEST_TIMEOUT)
                    .await?;
            let work = run_remote_forward(ctx.clone(), handle, forward, forwarded_targets, Arc::clone(&status), stop_rx);
            (status, Box::pin(work))
        }
        other => return Err(format!("Unknown tunnel kind: {}", other)),
    };

    let snapshot = status.lock().await.clone();
    (events.update)(&snapshot);
    if snapshot.exposed {
        ctx.log("warn", "exposed", Some(snapshot.listen_addr.clone()), None, Some(exposure_warning(&spec).into()));
    }

    // The entry goes in before the task can end and remove it: the map stays
    // locked from the spawn to the insert. A task that ended first used to
    // leave an entry behind that counted as running for good.
    let mut map = tunnels_map.lock().await;
    let task_map = Arc::clone(&tunnels_map);
    let task_status = Arc::clone(&status);
    let task_events = events.clone();
    let task_id = id.clone();
    let join = tokio::spawn(async move {
        match work.await {
            Ok(()) => set_state(&task_events, &task_status, "closed", None).await,
            Err(e) => set_state(&task_events, &task_status, "error", Some(e)).await,
        }
        // Drop the entry from the map so list_tunnels reflects reality.
        task_map.lock().await.remove(&task_id);
    });
    map.insert(
        id.clone(),
        ActiveTunnel {
            status: Arc::clone(&status),
            stop_tx: Some(stop_tx),
            join: Some(join),
            spec,
            on_forced_stop: Some(Box::new(move || {
                tokio::spawn(async move {
                    set_state(&events, &status, "closed", Some("stopped without the server's confirmation".into())).await;
                });
            })),
        },
    );
    drop(map);

    Ok(id)
}

/// Starts several rules at once and gives each one's result, in order. A
/// remote forward waits for the server's answer (up to 10 s): one slow answer
/// must hold neither the other rules nor the caller (the connect worker starts
/// its health watcher after them).
pub async fn start_tunnels<H: russh::client::Handler + 'static>(
    events: &TunnelEvents,
    session_id: &str,
    handle: &SshHandle<H>,
    tunnels_map: &TunnelMap,
    forwarded_targets: &ForwardedTargets,
    specs: Vec<TunnelSpec>,
) -> Vec<(TunnelSpec, Result<String, String>)> {
    let mut starts = tokio::task::JoinSet::new();
    for (i, spec) in specs.into_iter().enumerate() {
        let (events, sid) = (events.clone(), session_id.to_string());
        let (handle, map, targets) = (Arc::clone(handle), Arc::clone(tunnels_map), Arc::clone(forwarded_targets));
        starts.spawn(async move {
            let result = start_tunnel(events, sid, handle, map, targets, spec.clone()).await;
            (i, spec, result)
        });
    }
    let mut done = Vec::new();
    while let Some(joined) = starts.join_next().await {
        if let Ok(result) = joined {
            done.push(result);
        }
    }
    done.sort_by_key(|(i, _, _)| *i);
    done.into_iter().map(|(_, spec, result)| (spec, result)).collect()
}

/// How long stopping a tunnel waits for its task to end before aborting it
/// (F-019). A remote forward's own stop is bounded by
/// [`FORWARD_REQUEST_TIMEOUT`], so this is a last resort.
const TUNNEL_STOP_TIMEOUT: Duration = Duration::from_secs(15);

pub async fn stop_tunnel(tunnels_map: &TunnelMap, id: &str) -> Result<(), String> {
    stop_tunnel_within(tunnels_map, id, TUNNEL_STOP_TIMEOUT).await
}

async fn stop_tunnel_within(tunnels_map: &TunnelMap, id: &str, wait: Duration) -> Result<(), String> {
    // Take the stop sender + join handle under the map lock, release the
    // lock, then await the task. Holding the map lock across the await
    // would deadlock anyone else inspecting / removing tunnels in the
    // meantime (the listener task itself removes its entry on exit).
    let join = {
        let mut map = tunnels_map.lock().await;
        match map.get_mut(id) {
            Some(t) => {
                if let Some(tx) = t.stop_tx.take() {
                    let _ = tx.send(());
                }
                t.join.take()
            }
            None => return Err(format!("No active tunnel with id {}", id)),
        }
    };
    if let Some(mut j) = join {
        // Bounded: teardown, reconnect and the health watcher's disconnect
        // event all wait here, so a task stuck on a wedged server must not
        // hold them. If the task already panicked or was aborted we still
        // return Ok so the caller's higher-level cleanup can proceed.
        if tokio::time::timeout(wait, &mut j).await.is_err() {
            j.abort();
            // The aborted task never reaches its own remove() or its
            // "closed" update; do both here so the panel drops the row.
            let removed = tunnels_map.lock().await.remove(id);
            if let Some(ActiveTunnel { on_forced_stop: Some(notify), .. }) = removed {
                notify();
            }
        } else {
            // The task removes its own entry; this covers one that ended
            // before it could (nothing may stay listed as running).
            tunnels_map.lock().await.remove(id);
        }
    }
    Ok(())
}

pub async fn list_tunnels(
    tunnels_map: &TunnelMap,
    session_id: Option<&str>,
) -> Vec<TunnelStatus> {
    let map = tunnels_map.lock().await;
    let mut out = Vec::new();
    for t in map.values() {
        let s = t.status.lock().await;
        if let Some(sid) = session_id {
            if s.session_id != sid {
                continue;
            }
        }
        out.push(s.clone());
    }
    out
}

pub async fn stop_all_for_session(tunnels_map: &TunnelMap, session_id: &str) {
    stop_all_for_session_within(tunnels_map, session_id, TUNNEL_STOP_TIMEOUT).await
}

/// Stop every tunnel of every session at once (the profile is being closed).
pub async fn stop_all(tunnels_map: &TunnelMap) {
    let ids: Vec<String> = tunnels_map.lock().await.keys().cloned().collect();
    let mut stops = tokio::task::JoinSet::new();
    for id in ids {
        let map = Arc::clone(tunnels_map);
        stops.spawn(async move {
            let _ = stop_tunnel_within(&map, &id, TUNNEL_STOP_TIMEOUT).await;
        });
    }
    while stops.join_next().await.is_some() {}
}

async fn stop_all_for_session_within(tunnels_map: &TunnelMap, session_id: &str, wait: Duration) {
    // Snapshot (id, status_arc) under the map lock — DO NOT take the
    // per-status mutex while holding the map mutex. The listener task's
    // emitter path already holds status.lock() and then briefly touches
    // the map on exit (`tunnels_map.lock()...remove(&id)`); nesting in
    // the opposite order here would form an AB-BA deadlock.
    let candidates: Vec<(String, Arc<Mutex<TunnelStatus>>)> = {
        let map = tunnels_map.lock().await;
        map.iter()
            .map(|(id, t)| (id.clone(), Arc::clone(&t.status)))
            .collect()
    };
    let mut ids = Vec::with_capacity(candidates.len());
    for (id, status) in candidates {
        if status.lock().await.session_id == session_id {
            ids.push(id);
        }
    }
    // All at once: a remote forward's stop may wait on the server (bounded),
    // and a dead link must not cost that wait once per tunnel before the
    // session can be declared disconnected or reconnect (F-019).
    let mut stops = tokio::task::JoinSet::new();
    for id in ids {
        let map = Arc::clone(tunnels_map);
        stops.spawn(async move {
            let _ = stop_tunnel_within(&map, &id, wait).await;
        });
    }
    while stops.join_next().await.is_some() {}
}

// ---------------------------------------------------------------------------
// Local forward
// ---------------------------------------------------------------------------

/// Socket options every tunnel data socket wants:
///   - TCP_NODELAY: don't Nagle-buffer interactive traffic.
///   - TCP keepalive: detect a peer that vanished WITHOUT a FIN/RST — a slept
///     laptop, a NAT that silently dropped the mapping, a yanked cable. The
///     data pump lets a connection sit idle for up to `IDLE_TIMEOUT` (15
///     minutes); within that window a half-open socket whose peer is gone
///     would otherwise park the bridge task on a read that never completes
///     and never errors. That task holds
///     one of MAX_CONCURRENT_CONNS permits for good, and once enough leak the
///     listener silently stops serving new connections while still reporting
///     "listening" — a tunnel that is up but passes no data. Kernel keepalive
///     turns that dead peer into a socket error within ~a minute, so the pump
///     returns and the permit is freed. A genuinely idle-but-alive connection
///     is untouched: its keepalive probes get ACKed.
fn apply_tunnel_sockopts(sock: &tokio::net::TcpStream) {
    use socket2::{SockRef, TcpKeepalive};
    let _ = sock.set_nodelay(true);
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    let _ = SockRef::from(sock).set_tcp_keepalive(&ka);
}

/// Whether an `accept()` error is a transient per-connection hiccup (the client
/// went away between SYN and accept) that we should just skip, versus something
/// that warrants a short breather before retrying so we don't hot-spin. Either
/// way a "permanent" tunnel must NEVER tear its listener down over one accept
/// error — that was itself a silent-death path: a momentary EMFILE would return
/// from the loop, unbind the port, and kill the tunnel.
fn transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(e.kind(), ConnectionAborted | ConnectionReset | Interrupted | WouldBlock)
}

/// How long a forwarded connection may go with ZERO bytes moving in EITHER
/// direction before we close it and free its permit. This is the real cure for
/// the "tunnel shows connected but passes no data until I restart it" leak: when
/// the remote end of a forwarded connection dies silently (the SSH channel never
/// delivers EOF) while the local peer is idle-but-alive (its TCP keepalive keeps
/// answering), `copy_bidirectional` parks forever and pins one of
/// MAX_CONCURRENT_CONNS permits — eventually the pool is exhausted and every new
/// connection is silently refused. The idle window RESETS on any traffic, so a
/// busy connection is never cut; only a truly-silent one is reaped, and the
/// listener stays up so the client just reconnects.
const IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// A passthrough AsyncRead+AsyncWrite that stamps `last` (millis since `base`)
/// whenever it actually moves bytes, so the idle watchdog in `pump_bidirectional`
/// can tell a quiet-but-alive connection from a wedged one. `S` is Unpin
/// (TcpStream and the russh channel stream both are — `copy_bidirectional`
/// already requires it), so the wrapper is Unpin and `get_mut()` is safe.
struct ActivityTracked<'a, S> {
    inner: &'a mut S,
    last: Arc<AtomicU64>,
    base: Instant,
}

impl<'a, S: AsyncRead + Unpin> AsyncRead for ActivityTracked<'a, S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let r = Pin::new(&mut *this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &r {
            if buf.filled().len() != before {
                this.last.store(this.base.elapsed().as_millis() as u64, Ordering::Relaxed);
            }
        }
        r
    }
}

impl<'a, S: AsyncWrite + Unpin> AsyncWrite for ActivityTracked<'a, S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let r = Pin::new(&mut *this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &r {
            if *n > 0 {
                this.last.store(this.base.elapsed().as_millis() as u64, Ordering::Relaxed);
            }
        }
        r
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut *this.inner).poll_shutdown(cx)
    }
}

/// Bidirectional copy that closes the connection after `IDLE_TIMEOUT` of no
/// traffic in either direction, freeing its permit. Drop-in for the old bare
/// `tokio::io::copy_bidirectional` at every bridge site — the only behavioural
/// change is that a silently-dead connection can no longer pin a permit forever.
async fn pump_bidirectional<A, B>(a: &mut A, b: &mut B)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    pump_bidirectional_with_idle(a, b, IDLE_TIMEOUT).await
}

/// Core of `pump_bidirectional` with an injectable idle window (tests use a
/// short one). Returns when either side closes/errors, or after `idle` of no
/// bytes moving in EITHER direction.
async fn pump_bidirectional_with_idle<A, B>(a: &mut A, b: &mut B, idle: Duration)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let base = Instant::now();
    let last = Arc::new(AtomicU64::new(0));
    let mut ta = ActivityTracked { inner: a, last: Arc::clone(&last), base };
    let mut tb = ActivityTracked { inner: b, last: Arc::clone(&last), base };
    let copy = tokio::io::copy_bidirectional(&mut ta, &mut tb);
    tokio::pin!(copy);
    // Poll the idle window at a quarter of its length so the reap lands within
    // ~idle of the last byte without spinning. Floor the tick so a tiny test
    // window still makes progress.
    let tick = (idle / 4).max(Duration::from_millis(1));
    let idle_ms = idle.as_millis() as u64;
    loop {
        tokio::select! {
            _ = &mut copy => break, // normal EOF / close / error on either side
            _ = tokio::time::sleep(tick) => {
                let now_ms = base.elapsed().as_millis() as u64;
                if now_ms.saturating_sub(last.load(Ordering::Relaxed)) >= idle_ms {
                    // Silent too long — drop both streams (closing the sockets /
                    // channel) and return so the bridge task ends and frees its
                    // permit.
                    break;
                }
            }
        }
    }
}

async fn run_local_forward<H: russh::client::Handler + 'static>(
    ctx: LogCtx,
    handle: SshHandle<H>,
    listener: TcpListener,
    target: (String, u16),
    status: Arc<Mutex<TunnelStatus>>,
    mut stop_rx: oneshot::Receiver<()>,
) -> Result<(), String> {
    let (target_host, target_port) = target;
    let shown = host_port(&target_host, target_port);
    set_state(&ctx.events, &status, "listening", None).await;
    ctx.log("info", "listen", Some(shown.clone()), None,
            Some(format!("Local forward up; forwarding to {}", shown)));

    let active = Arc::new(AtomicU32::new(0));
    let conn_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS));
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // The listener does ONE thing: accept incoming TCP connections and spawn
    // a bridge task for each. It does NOT poll the SSH handle's health. The
    // earlier version did, by lock()-ing the handle inside the select arm,
    // which could block `stop_rx` from firing whenever a slow bridge task
    // was already holding the mutex — symptom: clicking Stop did nothing
    // for several seconds while we waited on a wedged channel_open. The
    // main.rs watcher is the single authoritative SSH-death signal; it
    // calls `tunnel::stop_all_for_session` on detection, which signals
    // stop_tx here. Bridge tasks fail fast on their own when SSH is dead.

    loop {
        tokio::select! {
            _ = &mut stop_rx => {
                let _ = shutdown_tx.send(());
                break;
            }
            accepted = listener.accept() => {
                let (sock, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        // Keep the listener alive across accept errors — see
                        // transient_accept_error. Only a sustained resource
                        // error gets a short sleep to avoid a hot loop.
                        if !transient_accept_error(&e) {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        continue;
                    }
                };
                apply_tunnel_sockopts(&sock);
                // Hard cap on concurrent bridge tasks. try_acquire is
                // non-blocking: at the cap we close the new socket and keep
                // serving existing connections rather than queueing (an
                // unbounded queue is the same resource-exhaustion problem).
                let permit = match Arc::clone(&conn_limiter).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => { drop(sock); continue; }
                };
                let handle = Arc::clone(&handle);
                let status = Arc::clone(&status);
                let ctx = ctx.clone();
                let target_host = target_host.clone();
                let target_full = host_port(&target_host, target_port);
                let active = Arc::clone(&active);
                let mut shutdown_rx = shutdown_tx.subscribe();

                tokio::spawn(async move {
                    let _permit = permit; // released when this bridge task ends
                    let _guard = ActiveGuard::enter(active, Arc::clone(&status), ctx.events.clone()).await;
                    ctx.log("info", "connect", Some(target_full.clone()), Some(peer.to_string()), None);

                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            ctx.log("info", "stop", Some(target_full), Some(peer.to_string()),
                                    Some("Tunnel stopped".into()));
                        }
                        res = bridge_local_to_channel(handle, sock, peer, target_host, target_port) => {
                            match res {
                                Ok(()) => {
                                    ctx.log("info", "close", Some(target_full), Some(peer.to_string()), None);
                                }
                                Err(e) => {
                                    ctx.log("error", "fail", Some(target_full), Some(peer.to_string()), Some(e));
                                }
                            }
                        }
                    }
                });
            }
        }
    }
    ctx.log("info", "shutdown", None, None, None);
    Ok(())
}

async fn bridge_local_to_channel<H: russh::client::Handler>(
    handle: SshHandle<H>,
    mut sock: tokio::net::TcpStream,
    peer: SocketAddr,
    target_host: String,
    target_port: u16,
) -> Result<(), String> {
    let channel = open_channel_with_retry(
        &handle, &target_host, target_port as u32,
        &peer.ip().to_string(), peer.port() as u32,
    ).await.map_err(|e| format!("channel_open_direct_tcpip: {}", e))?;
    let mut stream = channel.into_stream();
    let _ = pump_bidirectional(&mut sock, &mut stream).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Dynamic forward (SOCKS4/4a, SOCKS5/5h and HTTP; CONNECT only, no auth)
// ---------------------------------------------------------------------------

async fn run_dynamic_forward<H: russh::client::Handler + 'static>(
    ctx: LogCtx,
    handle: SshHandle<H>,
    listener: TcpListener,
    status: Arc<Mutex<TunnelStatus>>,
    mut stop_rx: oneshot::Receiver<()>,
) -> Result<(), String> {
    set_state(&ctx.events, &status, "listening", None).await;
    ctx.log("info", "listen", Some("SOCKS4 / SOCKS5".into()), None,
            Some("Dynamic forward up; accepting SOCKS4, SOCKS5 and HTTP (CONNECT and plain requests)".into()));

    let active = Arc::new(AtomicU32::new(0));
    let conn_limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS));
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Single-responsibility listener: accept SOCKS / HTTP requests and spawn
    // a bridge task. SSH-liveness is NOT polled from here — see the matching
    // comment in run_local_forward for why. The main.rs watcher detects SSH
    // death and triggers `tunnel::stop_all_for_session`, which fires our
    // stop_rx and tears everything down cleanly.

    loop {
        tokio::select! {
            _ = &mut stop_rx => {
                let _ = shutdown_tx.send(());
                break;
            }
            accepted = listener.accept() => {
                let (sock, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        // Same resilience as run_local_forward: never let a
                        // single accept error kill the listener.
                        if !transient_accept_error(&e) {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        continue;
                    }
                };
                apply_tunnel_sockopts(&sock);
                // Hard cap on concurrent bridge tasks — see run_local_forward.
                // Non-blocking: at the cap we close the socket and keep serving.
                let permit = match Arc::clone(&conn_limiter).try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => { drop(sock); continue; }
                };
                let handle = Arc::clone(&handle);
                let status = Arc::clone(&status);
                let ctx = ctx.clone();
                let active = Arc::clone(&active);
                let mut shutdown_rx = shutdown_tx.subscribe();

                tokio::spawn(async move {
                    let _permit = permit; // released when this bridge task ends
                    let _guard = ActiveGuard::enter(active, Arc::clone(&status), ctx.events.clone()).await;

                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            ctx.log("info", "stop", None, Some(peer.to_string()), Some("Tunnel stopped".into()));
                        }
                        res = handle_dynamic_client(handle, sock, peer, &ctx) => {
                            if let Err(e) = res {
                                ctx.log("error", "fail", None, Some(peer.to_string()), Some(e));
                            }
                        }
                    }
                });
            }
        }
    }
    ctx.log("info", "shutdown", None, None, None);
    Ok(())
}

// ---------------------------------------------------------------------------
// Remote forward (server-side listener)
// ---------------------------------------------------------------------------
//
// Mechanics: we ask the server to bind a TCP listener (`tcpip_forward`),
// then sit waiting for the stop signal. When the server accepts a connection
// on that port it pushes us a `forwarded-tcpip` channel via
// `ClientHandler::server_channel_open_forwarded_tcpip`, which looks up the
// port in `ForwardedTargets` and bridges to the local target.
/// A remote forward the server accepted.
struct RemoteForward {
    bind: String,
    /// The port the server listens on (the one it chose, for port 0).
    port: u32,
    shutdown: broadcast::Sender<()>,
}

/// How long a connection the server forwards to us may take to reach the
/// local target before it is given up (F-065); a loopback service answers in
/// milliseconds, and the OS default is minutes.
const LOCAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Sets a remote forward up (F-067): reserves its port in this connection's
/// map, asks the server, and keys a server-chosen port (0) by the port it
/// grants. A connection holds one forward per port, so the port the server
/// names when it opens a channel identifies the tunnel. The address it names
/// is not compared (C5): OpenSSH echoes the address asked for, other servers
/// need not, and a hostile server can name any registered address anyway.
#[allow(clippy::too_many_arguments)]
async fn open_remote_forward<H: russh::client::Handler + 'static>(
    ctx: &LogCtx,
    handle: &SshHandle<H>,
    targets: &ForwardedTargets,
    bind: String,
    port: u16,
    target: (String, u16),
    status: Arc<Mutex<TunnelStatus>>,
    limit: Duration,
) -> Result<RemoteForward, String> {
    let (shutdown, _) = broadcast::channel(1);
    let entry = ForwardEntry {
        tunnel_id: ctx.tunnel_id.clone(),
        target: Arc::new(ForwardTarget {
            host: target.0,
            port: target.1,
            status: Arc::clone(&status),
            ctx: ctx.clone(),
            active: Arc::new(AtomicU32::new(0)),
        }),
        limiter: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS)),
        shutdown: shutdown.clone(),
        connect_timeout: LOCAL_CONNECT_TIMEOUT,
    };
    let requested = u32::from(port);
    if requested != 0 {
        // Registered before the request: the server may open the first
        // channel right after it answers.
        match targets.lock().await.entry(requested) {
            Entry::Occupied(_) => {
                return Err(format!("Port {port} on the server is already forwarded by another tunnel of this connection"));
            }
            Entry::Vacant(slot) => {
                slot.insert(entry.clone());
            }
        }
    }
    let granted = match request_remote_forward(handle, &bind, requested, limit).await {
        // The server names the port only when it chose it.
        Ok(granted) => if requested == 0 { granted } else { requested },
        Err(e) => {
            remove_forward(targets, requested, &ctx.tunnel_id).await;
            if matches!(e, RemoteForwardError::TimedOut) && requested != 0 {
                // The request may still be granted late: release the port
                // then, or it stays taken for the connection's life.
                let (handle, bind) = (Arc::clone(handle), bind.clone());
                tokio::spawn(async move {
                    cancel_remote_forward(&handle, &bind, requested, FORWARD_REQUEST_TIMEOUT).await;
                });
            }
            let at = host_port(&bind, port);
            return Err(match e {
                RemoteForwardError::Refused => format!(
                    "Server refused tcpip-forward on {at} — check sshd_config's `AllowTcpForwarding` / `GatewayPorts`"
                ),
                RemoteForwardError::TimedOut => format!(
                    "The server did not answer the tcpip-forward request for {at} within {} seconds",
                    FORWARD_REQUEST_TIMEOUT.as_secs()
                ),
                RemoteForwardError::Failed(e) => format!("tcpip-forward request failed: {e}"),
            });
        }
    };
    if requested == 0 {
        // Nobody can connect to the port before it is known, so registering
        // it after the answer loses nothing.
        let (taken, registered) = if granted == 0 {
            (false, false)
        } else {
            match targets.lock().await.entry(granted) {
                Entry::Occupied(_) => (true, false),
                Entry::Vacant(slot) => {
                    slot.insert(entry);
                    (false, true)
                }
            }
        };
        if !registered {
            // A port another tunnel holds is not cancelled: that would end
            // the other tunnel (only a misbehaving server grants it twice).
            if !taken {
                cancel_remote_forward(handle, &bind, granted, limit).await;
            }
            return Err(if granted == 0 {
                "The server accepted the forward without saying which port it chose".to_string()
            } else {
                format!("The server chose port {granted}, which another tunnel of this connection already forwards")
            });
        }
        status.lock().await.listen_addr = host_port(&bind, granted);
    }
    Ok(RemoteForward { bind, port: granted, shutdown })
}

/// Removes a port's entry, only if `tunnel_id` owns it: a failing or stopping
/// tunnel never takes another tunnel's mapping with it (F-067).
async fn remove_forward(targets: &ForwardedTargets, port: u32, tunnel_id: &str) {
    let mut map = targets.lock().await;
    if map.get(&port).is_some_and(|e| e.tunnel_id == tunnel_id) {
        map.remove(&port);
    }
}

async fn run_remote_forward<H: russh::client::Handler>(
    ctx: LogCtx,
    handle: SshHandle<H>,
    forward: RemoteForward,
    targets: ForwardedTargets,
    status: Arc<Mutex<TunnelStatus>>,
    stop_rx: oneshot::Receiver<()>,
) -> Result<(), String> {
    set_state(&ctx.events, &status, "listening", None).await;
    let (listen, target) = {
        let s = status.lock().await;
        (s.listen_addr.clone(), s.target.clone())
    };
    ctx.log("info", "listen", Some(target.clone()), None,
            Some(format!("Remote forward up; the server listens on {listen}, forwarding to {target}")));

    // Wait until the user stops the tunnel (or the session goes away and the
    // sender side is dropped — either way the channel resolves).
    let _ = stop_rx.await;

    // From here on nothing is bridged any more, whatever the server does with
    // the cancel: no new connection, and the open ones end (F-065). Then ask
    // the server to release the port (best effort, bounded).
    remove_forward(&targets, forward.port, &ctx.tunnel_id).await;
    let _ = forward.shutdown.send(());
    cancel_remote_forward(&handle, &forward.bind, forward.port, FORWARD_REQUEST_TIMEOUT).await;
    ctx.log("info", "shutdown", None, None, None);
    Ok(())
}

/// A remote forward's start or stop is one server round trip; a server that
/// never answers must not hold the tunnel's stop, and with it disconnect,
/// reconnect and the health watcher, under the connection mutex (F-019).
const FORWARD_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
enum RemoteForwardError {
    Refused,
    TimedOut,
    Failed(russh::Error),
}

async fn request_remote_forward<H: russh::client::Handler>(
    handle: &Mutex<russh::client::Handle<H>>,
    bind_addr: &str,
    port: u32,
    limit: Duration,
) -> Result<u32, RemoteForwardError> {
    // The bound covers the wait for the connection mutex too.
    let request = async {
        let h = handle.lock().await;
        h.tcpip_forward(bind_addr, port).await
    };
    match tokio::time::timeout(limit, request).await {
        Ok(Ok(port)) => Ok(port),
        Ok(Err(russh::Error::RequestDenied)) => Err(RemoteForwardError::Refused),
        Ok(Err(e)) => Err(RemoteForwardError::Failed(e)),
        Err(_) => Err(RemoteForwardError::TimedOut),
    }
}

/// Asks the server to stop listening; skipped when the connection is already
/// closed. Returns whether the server confirmed it in time.
async fn cancel_remote_forward<H: russh::client::Handler>(
    handle: &Mutex<russh::client::Handle<H>>,
    bind_addr: &str,
    port: u32,
    limit: Duration,
) -> bool {
    let cancel = async {
        let h = handle.lock().await;
        if h.is_closed() {
            return false;
        }
        h.cancel_tcpip_forward(bind_addr, port).await.is_ok()
    };
    tokio::time::timeout(limit, cancel).await.unwrap_or(false)
}

/// What a client handler does with a `forwarded-tcpip` channel the server
/// opened for one of our remote forwards (the app's `ClientHandler` and the
/// tests' client both call this, so they take the same path).
pub async fn accept_forwarded_channel(
    targets: &ForwardedTargets,
    connected_port: u32,
    originator: (&str, u32),
    channel: russh::Channel<russh::client::Msg>,
    reply: russh::client::ChannelOpenHandle,
) {
    // Subscribed under the lock: the stop removes the entry under it before
    // it sends, so a bridge either sees the stop or finds no entry.
    let found = {
        let map = targets.lock().await;
        map.get(&connected_port).map(|e| (Arc::clone(&e.target), Arc::clone(&e.limiter), e.connect_timeout, e.shutdown.subscribe()))
    };
    let Some((target, limiter, connect_timeout, shutdown)) = found else {
        // No tunnel registered for this port: dropping `reply` rejects the
        // open, which closes it on the server's side.
        drop(reply);
        return;
    };
    // At the cap the channel is refused, as a local or dynamic tunnel closes
    // its extra connections (F-065).
    let Ok(permit) = limiter.try_acquire_owned() else {
        reply.reject(russh::ChannelOpenFailure::ResourceShortage).await;
        return;
    };
    reply.accept().await;
    let peer = host_port(originator.0, originator.1);
    // Spawned so russh's protocol task is not held up.
    tokio::spawn(bridge_forwarded_channel(
        target,
        connect_timeout,
        permit,
        shutdown,
        peer,
        channel.into_stream(),
    ));
}

/// Bridges an inbound forwarded channel to the local target. The local
/// connect is bounded and the tunnel's stop ends the connection (F-065).
async fn bridge_forwarded_channel(
    target: Arc<ForwardTarget>,
    connect_timeout: Duration,
    permit: tokio::sync::OwnedSemaphorePermit,
    mut shutdown: broadcast::Receiver<()>,
    peer: String,
    mut stream: russh::ChannelStream<russh::client::Msg>,
) {
    let _permit = permit; // released when this bridge ends
    let _guard = ActiveGuard::enter(Arc::clone(&target.active), Arc::clone(&target.status), target.ctx.events.clone()).await;
    let to = host_port(&target.host, target.port);
    target.ctx.log("info", "connect", Some(to.clone()), Some(peer.clone()), None);
    let bridge = async {
        let connect = tokio::net::TcpStream::connect((target.host.as_str(), target.port));
        let mut local = match tokio::time::timeout(connect_timeout, connect).await {
            Ok(Ok(local)) => local,
            Ok(Err(e)) => return Err(format!("connect: {e}")),
            Err(_) => return Err(format!("connect timed out after {connect_timeout:?}")),
        };
        apply_tunnel_sockopts(&local);
        pump_bidirectional(&mut local, &mut stream).await;
        Ok(())
    };
    // Either way the channel stream is dropped at the end, which closes it:
    // the server then ends the outside connection.
    tokio::select! {
        _ = shutdown.recv() => {
            target.ctx.log("info", "stop", Some(to), Some(peer), Some("Tunnel stopped".into()));
        }
        res = bridge => match res {
            Ok(()) => target.ctx.log("info", "close", Some(to), Some(peer), None),
            Err(e) => target.ctx.log("error", "fail", Some(to), Some(peer), Some(e)),
        },
    }
}

/// Hard ceiling on a single `channel_open_direct_tcpip`. russh awaits the
/// server's CHANNEL_OPEN_CONFIRMATION with no timeout of its own, and we hold
/// the shared handle mutex across that await — so when the SSH transport is
/// silently wedged (a network blip the kernel/russh hasn't yet surfaced as a
/// close) ONE new connection's open parks forever WHILE HOLDING THE HANDLE
/// LOCK. That freezes the health watcher (its `is_closed()` poll and its active
/// probe both take the same lock), so the session is never declared dead, never
/// auto-reconnects, and the bridge task's permit never frees — the exact
/// "tunnel dead, UI still green, only a manual restart brings it back" report.
/// Bounding the open releases the lock (and the permit) within this window: the
/// watcher runs again and, if the link is truly gone, its own probe strikes out
/// and triggers a reconnect; if the link recovered, the next connection just
/// succeeds. A real open completes in one round-trip (milliseconds), so 10s
/// never trips a healthy link.
const CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Open a `direct-tcpip` channel through the SSH session, with ONE quick
/// retry on transient failure. Modern browsers fire bursts of channel-open
/// requests (preconnect pools, image sprites, prefetch) and some SSH
/// servers temporarily refuse new channels under that load with a
/// transport-shaped error even though the session itself is healthy. A
/// 120ms backoff + single retry papers over those without holding the
/// caller noticeably longer. Falls back to the original error on the
/// second failure. Every open is bounded by CHANNEL_OPEN_TIMEOUT — see there
/// for why an unbounded open is the root of the silent-tunnel-death bug.
async fn open_channel_with_retry<H: russh::client::Handler>(
    handle: &Mutex<russh::client::Handle<H>>,
    target_host: &str,
    target_port: u32,
    peer_ip: &str,
    peer_port: u32,
) -> Result<russh::Channel<russh::client::Msg>, String> {
    let first = {
        let h = handle.lock().await;
        tokio::time::timeout(
            CHANNEL_OPEN_TIMEOUT,
            h.channel_open_direct_tcpip(target_host.to_string(), target_port,
                                        peer_ip.to_string(), peer_port),
        ).await
    };
    let first_err: String = match first {
        Ok(Ok(c)) => return Ok(c),
        Ok(Err(e)) => e.to_string(),
        Err(_) => format!("channel open timed out after {:?}", CHANNEL_OPEN_TIMEOUT),
    };
    // Don't retry if the session is gone — wasted round-trip and the
    // user is about to see the disconnect banner anyway.
    let still_alive = {
        let h = handle.lock().await;
        !h.is_closed()
    };
    if !still_alive {
        return Err(first_err);
    }
    tokio::time::sleep(Duration::from_millis(120)).await;
    let second = {
        let h = handle.lock().await;
        tokio::time::timeout(
            CHANNEL_OPEN_TIMEOUT,
            h.channel_open_direct_tcpip(target_host.to_string(), target_port,
                                        peer_ip.to_string(), peer_port),
        ).await
    };
    match second {
        Ok(Ok(c)) => Ok(c),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("channel open timed out after {:?} (retry)", CHANNEL_OPEN_TIMEOUT)),
    }
}

/// Maximum concurrent bridge tasks per listener (and per remote forward). Each accepted connection
/// spawns one task holding a socket + FD; without a cap a flood (especially
/// stalled slowloris connections) spawns them unbounded and exhausts FDs /
/// memory. 512 is far above any legitimate interactive use (a browser opens
/// ~6 preconnects per host) while still bounding the blast radius. At the cap
/// new connections are closed immediately rather than queued.
const MAX_CONCURRENT_CONNS: usize = 512;

/// Maximum time any single handshake read may block. SOCKS/HTTP proxy
/// handshakes are a handful of small reads that finish in milliseconds for a
/// real client; a client that connects and then stalls mid-handshake must not
/// be able to park a spawned task forever holding a socket + FD (the slowloris
/// half of a resource-exhaustion DoS). The data-pump phase has only the
/// much longer idle rule (`IDLE_TIMEOUT`): a long-lived quiet tunnel is
/// legitimate.
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// `read_exact` with a per-read deadline. Semantically identical to
/// `sock.read_exact(buf)` except it returns an `ErrorKind::TimedOut` error
/// instead of blocking indefinitely when the peer stops sending. Used for
/// every read on the handshake path so a stalled client can't wedge the task.
async fn read_exact_to(
    sock: &mut tokio::net::TcpStream,
    buf: &mut [u8],
) -> std::io::Result<()> {
    match tokio::time::timeout(HANDSHAKE_READ_TIMEOUT, sock.read_exact(buf)).await {
        Ok(r) => r.map(|_| ()),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "handshake read timed out",
        )),
    }
}

/// `read_exact` bounded by an ABSOLUTE deadline shared across an entire
/// handshake phase. read_exact_to's per-read timeout is fine for the fixed-size
/// SOCKS reads (a bounded count, each capped at 30s), but the byte-at-a-time
/// loops below reset a per-read timeout on every single byte — so a client
/// dribbling one byte just under the limit could keep a task (and one of the
/// 512 connection permits) alive for hours: the slowloris DoS. Threading one
/// `deadline` through each loop caps the whole field/line/header read regardless
/// of how the peer paces individual bytes.
async fn read_exact_by(
    sock: &mut tokio::net::TcpStream,
    buf: &mut [u8],
    deadline: tokio::time::Instant,
) -> std::io::Result<()> {
    match tokio::time::timeout_at(deadline, sock.read_exact(buf)).await {
        Ok(r) => r.map(|_| ()),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "handshake timed out",
        )),
    }
}

/// Detect the protocol the client is speaking from its first byte and hand
/// off to the matching handler. The dynamic forward accepts:
///
///   * SOCKS5 / SOCKS5h (0x05) — domain mode covers hostname-resolving
///     clients, no separate version on the wire.
///   * SOCKS4 / SOCKS4a (0x04)
///   * HTTP CONNECT (covers all HTTPS tunneling, plus any client that
///     speaks the older RFC 2616 absolute-URI proxy form for plain HTTP).
///     Triggered by ANY ASCII uppercase letter — the only legitimate first
///     byte of an HTTP request method.
///
/// Anything else (control bytes, unknown SOCKS versions) gets a clean log
/// line and the connection closes; we don't try to autodetect TLS or other
/// raw bytes because there's no useful action we could take with them.
async fn handle_dynamic_client<H: russh::client::Handler>(
    handle: SshHandle<H>,
    mut sock: tokio::net::TcpStream,
    peer: SocketAddr,
    ctx: &LogCtx,
) -> Result<(), String> {
    let mut ver = [0u8; 1];
    // Browser preconnect pools (Chrome opens ~6 connections per host
    // proactively, even before the user types a URL), health probes and
    // OS-level connection scrubbers regularly open a TCP socket against
    // our SOCKS listener and close it WITHOUT sending the version byte.
    // The earlier code surfaced every one of these as `read version:
    // early eof` in the activity log, even though the SSH side was fine.
    // Treat both "EOF before any byte arrived" AND "no byte within 30s"
    // as a silent close — return Ok(()) so the listener doesn't log a
    // fail line. Anything else (interrupted read, TCP reset mid-byte)
    // is still surfaced.
    let read_res = tokio::time::timeout(Duration::from_secs(30),
                                        sock.read_exact(&mut ver)).await;
    match read_res {
        Err(_) => return Ok(()), // 30s and the client said nothing — drop quietly
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
        Ok(Err(e)) => return Err(format!("read version: {}", e)),
        Ok(Ok(_)) => {}
    }
    match ver[0] {
        0x05 => handle_socks5(handle, sock, peer, ctx).await,
        0x04 => handle_socks4(handle, sock, peer, ctx).await,
        b if b.is_ascii_uppercase() => {
            handle_http_proxy(handle, sock, peer, b, ctx).await
        }
        v => Err(format!("Unknown protocol version 0x{:02x}", v)),
    }
}

/// HTTP proxy handler covering both CONNECT (the modern way — tunnels
/// arbitrary TCP, used by every browser for HTTPS) and the older absolute-
/// URI form (`GET http://host/path HTTP/1.1`) for plain HTTP. The first
/// byte of the method was already consumed by the dispatcher and is passed
/// in so we can stitch it back when reading the request line.
async fn handle_http_proxy<H: russh::client::Handler>(
    handle: SshHandle<H>,
    mut sock: tokio::net::TcpStream,
    peer: SocketAddr,
    first_byte: u8,
    ctx: &LogCtx,
) -> Result<(), String> {
    // One absolute deadline for the ENTIRE HTTP handshake (request line +
    // headers). Shared across every loop read so cumulative time is bounded no
    // matter how the peer paces bytes — see read_exact_by.
    let hs_deadline = tokio::time::Instant::now() + HANDSHAKE_READ_TIMEOUT;
    // Reconstruct the request line: dispatcher ate one byte, read the rest.
    let mut rest = read_line_max(&mut sock, 8192, hs_deadline).await
        .map_err(|e| format!("http read req-line: {}", e))?;
    let mut line = Vec::with_capacity(rest.len() + 1);
    line.push(first_byte);
    line.append(&mut rest);
    let request_line = String::from_utf8_lossy(&line).into_owned();

    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        let _ = sock.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
        return Err(format!("http: malformed request line {:?}", request_line));
    }
    let method = parts[0].to_string();
    let uri = parts[1].to_string();

    if method == "CONNECT" {
        // `CONNECT host:port HTTP/1.1` — consume headers, open tunnel, reply 200.
        consume_headers(&mut sock, 16 * 1024, hs_deadline).await
            .map_err(|e| format!("http connect headers: {}", e))?;
        let (host, port) = split_host_port(&uri)
            .ok()
            .filter(|(_, port)| *port != 0)
            .ok_or_else(|| format!("http connect: bad target {:?}", uri))?;

        let target_full = host_port(&host, port);
        ctx.log("info", "connect",
                 Some(target_full.clone()), Some(peer.to_string()),
                 Some("via HTTP CONNECT".into()));

        let channel = open_channel_with_retry(
            &handle, &host, port as u32,
            &peer.ip().to_string(), peer.port() as u32,
        ).await;
        let channel = match channel {
            Ok(c) => {
                sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .map_err(|e| format!("http connect reply: {}", e))?;
                c
            }
            Err(e) => {
                let _ = sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                ctx.log("error", "fail",
                         Some(target_full), Some(peer.to_string()), Some(e.to_string()));
                return Err(format!("direct-tcpip {}:{} failed: {}", host, port, e));
            }
        };

        let mut stream = channel.into_stream();
        let _ = pump_bidirectional(&mut sock, &mut stream).await;
        ctx.log("info", "close",
                 Some(target_full), Some(peer.to_string()), None);
        return Ok(());
    }

    // Plain HTTP — clients send the absolute URI (`GET http://host/path`)
    // so the proxy can pick the destination. Bare-path requests (`GET /foo`)
    // mean the client thinks we're the origin server, which we aren't.
    let (host, port, path) = match parse_absolute_uri(&uri) {
        Some(t) => t,
        None => {
            let _ = sock.write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n\
                  Solanum HTTP proxy expects an absolute-URI request line \
                  (e.g. `GET http://example.com/path HTTP/1.1`).\n"
            ).await;
            return Err(format!("http: unsupported URI form {:?}", uri));
        }
    };
    let target_full = host_port(&host, port);
    ctx.log("info", "connect",
             Some(target_full.clone()), Some(peer.to_string()),
             Some(format!("via HTTP {} {}", method, path)));

    // Buffer the client headers so we can filter out the hop-by-hop /
    // proxy-only ones before forwarding. We also force Connection: close
    // upstream so we don't have to demultiplex a keep-alive pipeline back
    // to multiple destinations on the same socket.
    let headers_raw = read_headers_raw(&mut sock, 64 * 1024, hs_deadline).await
        .map_err(|e| format!("http headers: {}", e))?;
    let forwarded_headers = filter_and_rewrite_headers(&headers_raw);

    let channel = open_channel_with_retry(
        &handle, &host, port as u32,
        &peer.ip().to_string(), peer.port() as u32,
    ).await;
    let mut stream = match channel {
        Ok(c) => c.into_stream(),
        Err(e) => {
            let _ = sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n").await;
            ctx.log("error", "fail",
                     Some(target_full), Some(peer.to_string()), Some(e.to_string()));
            return Err(format!("direct-tcpip {}:{} failed: {}", host, port, e));
        }
    };

    // Send rewritten request to upstream: relative URI, filtered headers, blank line.
    let req_line = format!("{} {} HTTP/1.1\r\n", method, path);
    if let Err(e) = stream.write_all(req_line.as_bytes()).await {
        return Err(format!("http upstream write req-line: {}", e));
    }
    if let Err(e) = stream.write_all(&forwarded_headers).await {
        return Err(format!("http upstream write headers: {}", e));
    }
    if let Err(e) = stream.write_all(b"\r\n").await {
        return Err(format!("http upstream write blank: {}", e));
    }

    // Bridge body (request → upstream) and response (upstream → client) in
    // both directions until either side finishes. Connection: close on the
    // forwarded request makes the upstream close its half after one
    // response, which cascades to closing the client socket — exactly what
    // a non-pipelined HTTP proxy should do.
    let _ = pump_bidirectional(&mut sock, &mut stream).await;
    ctx.log("info", "close",
             Some(target_full), Some(peer.to_string()), None);
    Ok(())
}

// ----- HTTP helpers ---------------------------------------------------------

/// Read bytes until a CRLF terminator (the line itself is returned without
/// the CRLF). Capped at `max` bytes to refuse a malicious client streaming
/// indefinitely.
async fn read_line_max(sock: &mut tokio::net::TcpStream, max: usize, deadline: tokio::time::Instant) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(128);
    let mut b = [0u8; 1];
    let mut last_was_cr = false;
    loop {
        read_exact_by(sock, &mut b, deadline).await?;
        if b[0] == b'\n' && last_was_cr {
            out.pop(); // drop the trailing CR
            return Ok(out);
        }
        last_was_cr = b[0] == b'\r';
        out.push(b[0]);
        if out.len() > max {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "http line too long"));
        }
    }
}

/// Consume header block (lines until an empty line). Total bytes capped at
/// `max`. Used by the CONNECT path where we don't need to parse, just skip
/// past the headers.
async fn consume_headers(sock: &mut tokio::net::TcpStream, max: usize, deadline: tokio::time::Instant) -> std::io::Result<()> {
    let mut total = 0usize;
    loop {
        let line = read_line_max(sock, max, deadline).await?;
        total = total.saturating_add(line.len() + 2);
        if line.is_empty() {
            return Ok(());
        }
        if total > max {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "http headers too long"));
        }
    }
}

/// Read headers and return the raw bytes (each header line followed by
/// CRLF; terminator blank line is NOT included so the caller can substitute
/// its own rewritten header set + blank line).
async fn read_headers_raw(sock: &mut tokio::net::TcpStream, max: usize, deadline: tokio::time::Instant) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(512);
    loop {
        let line = read_line_max(sock, max, deadline).await?;
        if line.is_empty() {
            return Ok(out);
        }
        if out.len() + line.len() + 2 > max {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "http headers too long"));
        }
        out.extend_from_slice(&line);
        out.extend_from_slice(b"\r\n");
    }
}

/// Drop hop-by-hop and proxy-specific headers, and force Connection: close
/// on the forwarded request so the upstream tears down after one response
/// (saves us from having to demultiplex a keep-alive pipeline across
/// multiple destinations on the same client socket).
fn filter_and_rewrite_headers(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut saw_connection = false;
    for line in raw.split(|&b| b == b'\n') {
        let mut line = line;
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() { continue; }
        let lower = match std::str::from_utf8(line) {
            Ok(s) => s.to_ascii_lowercase(),
            Err(_) => continue, // skip non-utf8 garbage rather than relay it
        };
        // Hop-by-hop headers per RFC 7230 §6.1 + the proxy-* family.
        if lower.starts_with("proxy-connection:")
            || lower.starts_with("proxy-authenticate:")
            || lower.starts_with("proxy-authorization:")
            || lower.starts_with("keep-alive:")
            || lower.starts_with("te:")
            || lower.starts_with("trailers:")
            || lower.starts_with("upgrade:")
        {
            continue;
        }
        if lower.starts_with("connection:") {
            // Replace any Connection variant with `Connection: close`.
            saw_connection = true;
            out.extend_from_slice(b"Connection: close\r\n");
            continue;
        }
        out.extend_from_slice(line);
        out.extend_from_slice(b"\r\n");
    }
    if !saw_connection {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out
}

/// Parse an absolute-URI proxy request target (`http://host[:port]/path`)
/// into `(host, port, path)`. Returns None for anything that doesn't look
/// like an http(s) URI — we won't honour `file://`, `ftp://`, etc., so a
/// confused client gets a clean 400 instead of being silently rerouted.
fn parse_absolute_uri(uri: &str) -> Option<(String, u16, String)> {
    let (scheme, rest) = uri.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port: u16 = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // Authority may carry userinfo (`user:pass@host`) which we strip — the
    // proxy doesn't propagate that level of auth into the SSH channel.
    let authority = authority.rsplit_once('@').map(|x| x.1).unwrap_or(authority);
    // The port is optional here; with one, the authority is read like every
    // other address (split_host_port: host bare, IPv6 in brackets, F-066).
    let has_port = match authority.strip_prefix('[') {
        Some(rest) => rest.split_once(']').is_some_and(|(_, after)| !after.is_empty()),
        None => authority.contains(':'),
    };
    let (host, port) = if has_port {
        split_host_port(authority).ok().filter(|(_, port)| *port != 0)?
    } else if authority.starts_with('[') != authority.ends_with(']') {
        return None;
    } else {
        (bare_host(authority.to_string()), default_port)
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path.to_string()))
}

/// SOCKS4 / SOCKS4a — CONNECT (cmd 0x01) only. The version byte has already
/// been consumed by handle_socks. Format: VN(consumed) CD(1) DSTPORT(2)
/// DSTIP(4) USERID(null-terminated). If DSTIP is 0.0.0.X (SOCKS4a marker),
/// the hostname follows USERID, also null-terminated.
async fn handle_socks4<H: russh::client::Handler>(
    handle: SshHandle<H>,
    mut sock: tokio::net::TcpStream,
    peer: SocketAddr,
    ctx: &LogCtx,
) -> Result<(), String> {
    // One absolute deadline shared across BOTH NUL-terminated reads (userid +
    // optional SOCKS4a hostname) so the whole handshake is bounded regardless
    // of per-byte pacing — see read_exact_by.
    let hs_deadline = tokio::time::Instant::now() + HANDSHAKE_READ_TIMEOUT;
    let mut hdr = [0u8; 7]; // CD + DSTPORT(2) + DSTIP(4)
    read_exact_to(&mut sock, &mut hdr).await.map_err(|e| format!("socks4 read req: {}", e))?;
    let cmd = hdr[0];
    let port = u16::from_be_bytes([hdr[1], hdr[2]]);
    let ip = [hdr[3], hdr[4], hdr[5], hdr[6]];

    // Read userid (ignored — we don't authenticate) until NUL.
    let userid = read_until_nul(&mut sock, 256, hs_deadline).await
        .map_err(|e| format!("socks4 read userid: {}", e))?;
    let _ = userid;

    if cmd != 0x01 {
        // 0x5B = request rejected. SOCKS4 reply: VN(0) + CD(1) + ignored(6).
        let _ = sock.write_all(&[0x00, 0x5B, 0, 0, 0, 0, 0, 0]).await;
        return Err(format!("SOCKS4 command 0x{:02x} not supported (only CONNECT)", cmd));
    }

    // SOCKS4a hostname extension: DSTIP = 0.0.0.X with X != 0 → hostname
    // follows the userid, also NUL-terminated.
    let target_host = if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
        let host_bytes = read_until_nul(&mut sock, 256, hs_deadline).await
            .map_err(|e| format!("socks4a read host: {}", e))?;
        bare_host(String::from_utf8(host_bytes).map_err(|e| format!("socks4a host non-utf8: {}", e))?)
    } else {
        format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
    };

    let target_full = host_port(&target_host, port);
    ctx.log("info", "connect",
             Some(target_full.clone()), Some(peer.to_string()), Some("via SOCKS4".into()));

    let channel = open_channel_with_retry(
        &handle, &target_host, port as u32,
        &peer.ip().to_string(), peer.port() as u32,
    ).await;

    let channel = match channel {
        Ok(c) => {
            // 0x5A = request granted.
            sock.write_all(&[0x00, 0x5A, hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6]])
                .await
                .map_err(|e| format!("socks4 reply: {}", e))?;
            c
        }
        Err(e) => {
            let _ = sock.write_all(&[0x00, 0x5B, hdr[1], hdr[2], hdr[3], hdr[4], hdr[5], hdr[6]]).await;
            ctx.log("error", "fail",
                     Some(target_full), Some(peer.to_string()), Some(e.to_string()));
            return Err(format!("direct-tcpip {}:{} failed: {}", target_host, port, e));
        }
    };

    let mut stream = channel.into_stream();
    let _ = pump_bidirectional(&mut sock, &mut stream).await;
    ctx.log("info", "close",
             Some(target_full), Some(peer.to_string()), None);
    Ok(())
}

/// Read bytes from `sock` until either NUL or the cap is reached. Returns
/// everything BEFORE the NUL. Used to consume SOCKS4 USERID + the SOCKS4a
/// hostname extension, both of which are NUL-terminated and unbounded by
/// the spec — we cap at 256 bytes to refuse malicious clients trying to
/// stream forever.
async fn read_until_nul(sock: &mut tokio::net::TcpStream, max: usize, deadline: tokio::time::Instant) -> std::io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(32);
    let mut b = [0u8; 1];
    loop {
        read_exact_by(sock, &mut b, deadline).await?;
        if b[0] == 0 || out.len() >= max {
            break;
        }
        out.push(b[0]);
    }
    Ok(out)
}

/// SOCKS5 server: NO-AUTH greeting, CONNECT (cmd 0x01) only, IPv4 / IPv6 /
/// domain address types (domain mode is what SOCKS5h clients send — the
/// protocol doesn't have a separate version). Anything else gets a clean
/// error reply and the connection closes. The leading version byte was
/// already consumed by `handle_socks`.
async fn handle_socks5<H: russh::client::Handler>(
    handle: SshHandle<H>,
    mut sock: tokio::net::TcpStream,
    peer: SocketAddr,
    ctx: &LogCtx,
) -> Result<(), String> {
    // --- Greeting (version already consumed by handle_socks) ---
    let mut nm = [0u8; 1];
    read_exact_to(&mut sock, &mut nm).await.map_err(|e| format!("read methods cnt: {}", e))?;
    let n_methods = nm[0] as usize;
    let mut methods = vec![0u8; n_methods];
    read_exact_to(&mut sock, &mut methods).await.map_err(|e| format!("read methods: {}", e))?;
    // Always reply NO-AUTH (0x00). If the client didn't offer it, send
    // 0xFF and close.
    if !methods.contains(&0x00) {
        sock.write_all(&[0x05, 0xFF]).await.ok();
        return Err("client requires authentication, none supported".into());
    }
    sock.write_all(&[0x05, 0x00]).await.map_err(|e| format!("write method ack: {}", e))?;

    // --- Request ---
    let mut req_hdr = [0u8; 4];
    read_exact_to(&mut sock, &mut req_hdr).await.map_err(|e| format!("read req hdr: {}", e))?;
    if req_hdr[0] != 0x05 {
        return Err(format!("unexpected SOCKS version {:#x}", req_hdr[0]));
    }
    let cmd = req_hdr[1];
    let atyp = req_hdr[3];
    if cmd != 0x01 {
        // 0x07 = command not supported
        let _ = sock.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Err(format!("unsupported SOCKS command {:#x}", cmd));
    }

    let target_host: String = match atyp {
        0x01 => {
            // IPv4
            let mut octets = [0u8; 4];
            read_exact_to(&mut sock, &mut octets).await.map_err(|e| format!("read v4: {}", e))?;
            format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
        }
        0x03 => {
            // Domain
            let mut lenb = [0u8; 1];
            read_exact_to(&mut sock, &mut lenb).await.map_err(|e| format!("read dom len: {}", e))?;
            let mut name = vec![0u8; lenb[0] as usize];
            read_exact_to(&mut sock, &mut name).await.map_err(|e| format!("read dom: {}", e))?;
            bare_host(String::from_utf8(name).map_err(|e| format!("non-utf8 host: {}", e))?)
        }
        0x04 => {
            // IPv6 — let Ipv6Addr produce the canonical form (`::1`,
            // `2001:db8::1`, etc.) instead of the verbose
            // `0:0:0:0:0:0:0:1` shape, and bare: the server resolves the
            // direct-tcpip host as given, and `[::1]` is no address (F-066).
            let mut octets = [0u8; 16];
            read_exact_to(&mut sock, &mut octets).await.map_err(|e| format!("read v6: {}", e))?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        other => {
            let _ = sock.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            return Err(format!("unsupported address type {:#x}", other));
        }
    };
    let mut port_buf = [0u8; 2];
    read_exact_to(&mut sock, &mut port_buf).await.map_err(|e| format!("read port: {}", e))?;
    let target_port = u16::from_be_bytes(port_buf);

    let target_full = host_port(&target_host, target_port);
    let via = match atyp {
        0x01 => "via SOCKS5 (IPv4)",
        0x03 => "via SOCKS5h (hostname)",
        0x04 => "via SOCKS5 (IPv6)",
        _ => "via SOCKS5",
    };
    ctx.log("info", "connect",
             Some(target_full.clone()), Some(peer.to_string()), Some(via.into()));

    // --- Open the SSH direct-tcpip channel ---
    let channel = open_channel_with_retry(
        &handle, &target_host, target_port as u32,
        &peer.ip().to_string(), peer.port() as u32,
    ).await;

    let channel = match channel {
        Ok(c) => {
            // 0x00 = success. The bound address fields are filled with zeros —
            // most SOCKS clients ignore them.
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .map_err(|e| format!("write reply: {}", e))?;
            c
        }
        Err(e) => {
            // 0x05 = connection refused (best general-purpose code)
            let _ = sock.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            ctx.log("error", "fail",
                     Some(target_full), Some(peer.to_string()), Some(e.to_string()));
            return Err(format!("direct-tcpip {}:{} failed: {}", target_host, target_port, e));
        }
    };

    let mut stream = channel.into_stream();
    let _ = pump_bidirectional(&mut sock, &mut stream).await;
    ctx.log("info", "close",
             Some(target_full), Some(peer.to_string()), None);
    Ok(())
}

#[cfg(test)]
mod tunnel_tests {
    use super::{bind_with_retry, pump_bidirectional_with_idle};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // The reconnect fix: a bind that hits a transient AddrInUse (the previous
    // listener still releasing the port during a reconnect) must succeed once
    // the port frees, instead of failing and letting the caller drop the tunnel.
    #[tokio::test]
    async fn bind_with_retry_succeeds_once_the_port_frees() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{}", port);
        // Free the port partway through the retry window.
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            drop(l);
        });
        let got = tokio::time::timeout(Duration::from_secs(3), bind_with_retry(&addr))
            .await
            .expect("must not hang")
            .expect("must bind once the port frees");
        assert_eq!(got.local_addr().unwrap().port(), port);
    }

    // If the port never frees, it must give up cleanly (Err) rather than hang —
    // the caller keeps the spec and retries on the next reconnect.
    #[tokio::test]
    async fn bind_with_retry_gives_up_if_port_stays_taken() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{}", port);
        let r = tokio::time::timeout(Duration::from_secs(5), bind_with_retry(&addr))
            .await
            .expect("must return, not hang");
        assert!(r.is_err(), "must give up when the port never frees");
        drop(l);
    }

    // The pump must relay bytes in BOTH directions (it didn't break the copy
    // semantics) and finish cleanly when both ends close (EOF), not hang.
    #[tokio::test]
    async fn pump_relays_both_directions_and_finishes_on_eof() {
        let (mut ca, mut a) = tokio::io::duplex(64);
        let (mut cb, mut b) = tokio::io::duplex(64);
        let pump = tokio::spawn(async move {
            pump_bidirectional_with_idle(&mut a, &mut b, Duration::from_secs(30)).await;
        });

        // a-side client -> b-side client
        ca.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        cb.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // b-side client -> a-side client
        cb.write_all(b"pong").await.unwrap();
        let mut buf2 = [0u8; 4];
        ca.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"pong");

        // Both clients close -> pump sees EOF on both halves and returns.
        drop(ca);
        drop(cb);
        tokio::time::timeout(Duration::from_secs(5), pump)
            .await
            .expect("pump must finish on EOF, not hang")
            .unwrap();
    }

    // The core fix: a connection whose ends never close (no EOF) and never move
    // a byte must be REAPED after the idle window, freeing its permit — instead
    // of parking forever like the old bare copy_bidirectional.
    #[tokio::test]
    async fn pump_reaps_a_silent_connection() {
        let (ca, mut a) = tokio::io::duplex(64);
        let (cb, mut b) = tokio::io::duplex(64);
        let idle = Duration::from_millis(300);
        let start = Instant::now();
        // Clients are kept ALIVE (not dropped) for the whole call, so there is
        // no EOF — the only way this returns is the idle timeout.
        tokio::time::timeout(
            Duration::from_secs(5),
            pump_bidirectional_with_idle(&mut a, &mut b, idle),
        )
        .await
        .expect("a silent connection must be reaped by the idle timeout, not hang");
        assert!(start.elapsed() >= idle, "must not reap before the idle window elapses");
        drop(ca);
        drop(cb);
    }

    // The don't-break-active guarantee: while traffic keeps flowing (each byte
    // resets the idle window), the pump must NOT reap the connection.
    #[tokio::test]
    async fn pump_keeps_an_active_connection_open() {
        let (mut ca, mut a) = tokio::io::duplex(1024);
        let (mut cb, mut b) = tokio::io::duplex(1024);
        let idle = Duration::from_millis(300);
        let pump = tokio::spawn(async move {
            pump_bidirectional_with_idle(&mut a, &mut b, idle).await;
        });

        // One byte every 100ms (< idle) for ~1s — well past the idle window in
        // wall-clock time, but never idle for a full window.
        for _ in 0..10 {
            ca.write_all(b"x").await.unwrap();
            let mut buf = [0u8; 1];
            cb.read_exact(&mut buf).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(!pump.is_finished(), "an actively-used connection must not be reaped");

        // Stop traffic -> pump reaps (via EOF once we drop, or idle) and ends.
        drop(ca);
        drop(cb);
        tokio::time::timeout(Duration::from_secs(5), pump)
            .await
            .expect("pump must finish after traffic stops")
            .unwrap();
    }

    // --- F-019: a stop never hangs on a wedged server ---

    fn tunnel(join: tokio::task::JoinHandle<()>) -> super::ActiveTunnel {
        super::ActiveTunnel {
            status: std::sync::Arc::new(tokio::sync::Mutex::new(super::TunnelStatus {
                id: "t1".into(),
                session_id: "s".into(),
                kind: "remote".into(),
                listen_addr: String::new(),
                target: String::new(),
                state: "listening".into(),
                error: None,
                exposed: false,
                conns_total: 0,
                conns_active: 0,
            })),
            stop_tx: None,
            join: Some(join),
            spec: super::TunnelSpec { kind: "R".into(), local: "4000".into(), remote: "127.0.0.1:22".into() },
            on_forced_stop: None,
        }
    }

    /// Several stuck tunnels cost one wait, not one each.
    #[tokio::test]
    async fn a_session_s_tunnels_are_stopped_together() {
        let map: super::TunnelMap = Default::default();
        for i in 0..4 {
            let join = tokio::spawn(std::future::pending::<()>());
            map.lock().await.insert(format!("t{i}"), tunnel(join));
        }
        let started = Instant::now();
        super::stop_all_for_session_within(&map, "s", Duration::from_millis(300)).await;
        assert!(started.elapsed() < Duration::from_millis(1000), "{:?}", started.elapsed());
        assert!(map.lock().await.is_empty());
    }

    /// A task that never ends is aborted after the wait, and its entry goes.
    #[tokio::test]
    async fn stopping_a_tunnel_whose_task_never_ends_is_bounded() {
        let map: super::TunnelMap = Default::default();
        let join = tokio::spawn(std::future::pending::<()>());
        map.lock().await.insert("t1".into(), tunnel(join));
        let started = Instant::now();
        super::stop_tunnel_within(&map, "t1", Duration::from_millis(200)).await.unwrap();
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(map.lock().await.is_empty());
    }

    /// A server that never answers cancel-tcpip-forward: the stop gives up
    /// within the bound and the connection mutex is free again.
    #[tokio::test]
    async fn cancelling_a_remote_forward_is_bounded() {
        use crate::ssh_test_server::*;
        let served = serve(Script { stall_cancel_forward: true, ..Script::default() }, vec![ed25519_key(1)]);
        let (handler, _) = TestClient::new();
        let config = std::sync::Arc::new(crate::ssh_connect::build_ssh_client_config(&Default::default()));
        let mut h = russh::client::connect_stream(config, served.stream, handler).await.unwrap();
        assert!(h.authenticate_password(USER, PASSWORD).await.unwrap().success());
        let h = tokio::sync::Mutex::new(h);
        super::request_remote_forward(&h, "127.0.0.1", 4000, Duration::from_secs(2)).await.expect("forward set up");
        let started = Instant::now();
        assert!(!super::cancel_remote_forward(&h, "127.0.0.1", 4000, Duration::from_millis(300)).await);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(h.try_lock().is_ok());
    }

    // --- Tunnels on a connection to the in-process SSH server ---

    use super::{start_tunnel, ForwardedTargets, TunnelEvents, TunnelMap, TunnelSpec, TunnelStatus};
    use crate::ssh_test_server::{eventually, logged_in_forwarding, Script, Seen, TestClient};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::net::TcpStream;

    /// What the tunnels reported: status updates and (level, event, message).
    #[derive(Default)]
    struct Reported {
        updates: Vec<TunnelStatus>,
        logs: Vec<(String, String, Option<String>)>,
    }

    struct Rig {
        handle: Arc<tokio::sync::Mutex<russh::client::Handle<TestClient>>>,
        seen: Arc<StdMutex<Seen>>,
        targets: ForwardedTargets,
        map: TunnelMap,
        events: TunnelEvents,
        reported: Arc<StdMutex<Reported>>,
    }

    impl Rig {
        async fn new(script: Script) -> Rig {
            let targets: ForwardedTargets = Default::default();
            let (handle, seen) = logged_in_forwarding(script, Some(Arc::clone(&targets))).await;
            let reported = Arc::new(StdMutex::new(Reported::default()));
            let (a, b) = (Arc::clone(&reported), Arc::clone(&reported));
            let events = TunnelEvents {
                update: Arc::new(move |s: &TunnelStatus| a.lock().unwrap().updates.push(s.clone())),
                log: Arc::new(move |_session: &str, e: &super::TunnelLogEntry<'_>| {
                    b.lock().unwrap().logs.push((e.level.to_string(), e.event.to_string(), e.message.clone()))
                }),
            };
            Rig { handle, seen, targets, map: Default::default(), events, reported }
        }

        async fn start(&self, kind: &str, local: &str, remote: &str) -> Result<String, String> {
            let spec = TunnelSpec { kind: kind.into(), local: local.into(), remote: remote.into() };
            start_tunnel(self.events.clone(), "s".into(), Arc::clone(&self.handle), Arc::clone(&self.map), Arc::clone(&self.targets), spec).await
        }

        /// The last state the tunnel reported.
        fn state(&self, id: &str) -> Option<TunnelStatus> {
            self.reported.lock().unwrap().updates.iter().rev().find(|u| u.id == id).cloned()
        }

        async fn listening(&self, id: &str) -> bool {
            eventually(|| self.state(id).is_some_and(|s| s.state == "listening")).await
        }

        /// Pushes a `forwarded-tcpip` channel from the server, as sshd does
        /// when someone connects to a forwarded port.
        async fn connect_from_server(&self, port: u32) -> Result<russh::ChannelStream<russh::server::Msg>, russh::Error> {
            assert!(eventually(|| self.seen.lock().unwrap().handle.is_some()).await, "no forward was requested");
            let server = self.seen.lock().unwrap().handle.clone().unwrap();
            server.channel_open_forwarded_tcpip("localhost", port, "203.0.113.9", 5555).await.map(|c| c.into_stream())
        }
    }

    /// A free local port (bound and released: a tiny race, fine in tests).
    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    /// A local service that echoes every connection; returns its port.
    async fn echo_service() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = sock.into_split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        port
    }

    async fn round_trip<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> Vec<u8> {
        stream.write_all(data).await.unwrap();
        let mut back = vec![0u8; data.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back)).await.expect("echo in time").unwrap();
        back
    }

    #[tokio::test]
    async fn a_local_forward_carries_data_to_its_target() {
        let rig = Rig::new(Script::default()).await;
        let port = free_port();
        let id = rig.start("L", &port.to_string(), "intranet:80").await.unwrap();
        assert!(rig.listening(&id).await);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_eq!(round_trip(&mut client, b"hello").await, b"hello");
        assert_eq!(rig.seen.lock().unwrap().direct, [("intranet".to_string(), 80)]);
    }

    #[tokio::test]
    async fn a_dynamic_forward_answers_socks5() {
        let rig = Rig::new(Script::default()).await;
        let port = free_port();
        let id = rig.start("D", &port.to_string(), "").await.unwrap();
        assert!(rig.listening(&id).await);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        let mut request = vec![5, 1, 0, 3, 8];
        request.extend_from_slice(b"intranet");
        request.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "granted");
        assert_eq!(round_trip(&mut client, b"through").await, b"through");
        assert_eq!(rig.seen.lock().unwrap().direct, [("intranet".to_string(), 80)]);
    }

    #[tokio::test]
    async fn a_remote_forward_bridges_a_server_connection_to_its_target() {
        let rig = Rig::new(Script::default()).await;
        let service = echo_service().await;
        let id = rig.start("R", "4000", &format!("127.0.0.1:{service}")).await.unwrap();
        assert!(rig.listening(&id).await);
        let mut inbound = rig.connect_from_server(4000).await.expect("channel accepted");
        assert_eq!(round_trip(&mut inbound, b"from outside").await, b"from outside");
        assert!(eventually(|| rig.state(&id).is_some_and(|s| s.conns_total == 1)).await);
    }

    /// A local service that echoes and says when its (single) connection closed.
    async fn echo_service_reporting_close() -> (u16, tokio::sync::oneshot::Receiver<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sock.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = closed_tx.send(());
        });
        (port, closed_rx)
    }

    /// Writes one byte through a SOCKS5 or plain client so the tunnel opens
    /// its channel, then waits for the server to have seen it.
    async fn wait_for_direct(rig: &Rig) -> Vec<(String, u32)> {
        assert!(eventually(|| !rig.seen.lock().unwrap().direct.is_empty()).await, "no direct-tcpip open reached the server");
        rig.seen.lock().unwrap().direct.clone()
    }

    async fn socks5_connect(port: u16, address: &[u8], target_port: u16) -> (TcpStream, u8) {
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        let mut request = vec![5, 1, 0];
        request.extend_from_slice(address);
        request.extend_from_slice(&target_port.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut reply)).await.expect("socks reply").unwrap();
        (client, reply[1])
    }

    // F-020: a bare remote port asks the server for loopback, as `ssh -R` does.
    #[tokio::test]
    async fn a_bare_remote_port_asks_the_server_for_loopback() {
        let rig = Rig::new(Script::default()).await;
        let service = echo_service().await;
        let _ = rig.start("R", "8080", &format!("127.0.0.1:{service}")).await;
        assert!(eventually(|| !rig.seen.lock().unwrap().forwards.is_empty()).await);
        assert_eq!(rig.seen.lock().unwrap().forwards[0], ("localhost".to_string(), 8080));
    }

    #[test]
    fn rules_that_listen_beyond_loopback_are_told_apart() {
        let spec = |kind: &str, local: &str| TunnelSpec { kind: kind.into(), local: local.into(), remote: "intranet:80".into() };
        for (kind, local) in [("L", "8080"), ("D", "1080"), ("L", "localhost:8080"), ("D", "127.0.0.2:1080"), ("L", "[::1]:8080"),
                              ("R", "8080"), ("R", "localhost:8080"), ("R", "127.0.0.1:8080"), ("R", "[::1]:8080"), ("R", "0")] {
            assert!(!super::listens_beyond_loopback(&spec(kind, local)), "{kind} {local}");
        }
        for (kind, local) in [("L", "0.0.0.0:8080"), ("D", "[::]:1080"), ("D", "192.168.1.5:1080"),
                              ("R", "0.0.0.0:8080"), ("R", "[::]:8080"), ("R", "192.168.1.5:8080"), ("R", "intranet:8080")] {
            assert!(super::listens_beyond_loopback(&spec(kind, local)), "{kind} {local}");
        }
        assert!(!super::listens_beyond_loopback(&spec("L", "not an address")));
    }

    // A remote tunnel, so the test itself never listens beyond loopback (a
    // firewall prompt on a developer's machine).
    #[tokio::test]
    async fn a_tunnel_that_listens_beyond_loopback_says_so() {
        let rig = Rig::new(Script::default()).await;
        let id = rig.start("R", "0.0.0.0:4000", "127.0.0.1:9").await.unwrap();
        assert!(rig.listening(&id).await);
        assert!(rig.state(&id).unwrap().exposed);
        assert!(rig.reported.lock().unwrap().logs.iter().any(|(level, event, _)| level == "warn" && event == "exposed"));
        let quiet = rig.start("L", &free_port().to_string(), "intranet:80").await.unwrap();
        assert!(rig.listening(&quiet).await);
        assert!(!rig.state(&quiet).unwrap().exposed);
    }

    // F-066: an IPv6 target goes to the server without its brackets.
    #[tokio::test]
    async fn a_bracketed_ipv6_target_reaches_the_server_bare() {
        let rig = Rig::new(Script::default()).await;
        let port = free_port();
        let id = rig.start("L", &port.to_string(), "[::1]:5000").await.unwrap();
        assert!(rig.listening(&id).await);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(b"x").await.unwrap();
        assert_eq!(wait_for_direct(&rig).await, [("::1".to_string(), 5000)]);
    }

    #[tokio::test]
    async fn a_socks5_ipv6_request_reaches_the_server_bare() {
        let rig = Rig::new(Script::default()).await;
        let port = free_port();
        let id = rig.start("D", &port.to_string(), "").await.unwrap();
        assert!(rig.listening(&id).await);
        let mut address = vec![4];
        address.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        let (_client, code) = socks5_connect(port, &address, 5000).await;
        assert_eq!(code, 0);
        assert_eq!(wait_for_direct(&rig).await, [("::1".to_string(), 5000)]);
    }

    #[tokio::test]
    async fn an_http_connect_to_ipv6_reaches_the_server_bare() {
        let rig = Rig::new(Script::default()).await;
        let port = free_port();
        let id = rig.start("D", &port.to_string(), "").await.unwrap();
        assert!(rig.listening(&id).await);
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n").await.unwrap();
        let mut reply = [0u8; 12];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"HTTP/1.1 200");
        assert_eq!(wait_for_direct(&rig).await, [("::1".to_string(), 443)]);
    }

    // F-067: port 0 lets the server choose, and that port forwards.
    #[tokio::test]
    async fn a_server_chosen_port_forwards() {
        let rig = Rig::new(Script { granted_port: 40123, ..Script::default() }).await;
        let service = echo_service().await;
        let id = rig.start("R", "0", &format!("127.0.0.1:{service}")).await.unwrap();
        assert!(rig.listening(&id).await);
        assert!(rig.state(&id).unwrap().listen_addr.ends_with(":40123"), "{:?}", rig.state(&id));
        let mut inbound = rig.connect_from_server(40123).await.expect("the granted port forwards");
        assert_eq!(round_trip(&mut inbound, b"chosen").await, b"chosen");
    }

    // F-067: a second tunnel on a port already forwarded is refused, and the
    // first keeps forwarding.
    #[tokio::test]
    async fn a_duplicate_remote_port_leaves_the_first_tunnel_alone() {
        let rig = Rig::new(Script::default()).await;
        let service = echo_service().await;
        let target = format!("127.0.0.1:{service}");
        let first = rig.start("R", "4000", &target).await.unwrap();
        assert!(rig.listening(&first).await);
        let second = rig.start("R", "4000", &target).await;
        if let Ok(id) = &second {
            // Before the fix the refusal arrived later, as an update.
            assert!(eventually(|| rig.state(id).is_some_and(|s| s.state == "error")).await);
        }
        let inbound = rig.connect_from_server(4000).await;
        assert!(inbound.is_ok(), "the first tunnel must still forward: {:?}", inbound.err());
        assert!(second.is_err(), "the second start must be refused");
    }

    // A refused remote forward is the start's error, and leaves nothing behind.
    #[tokio::test]
    async fn a_refused_remote_forward_fails_to_start() {
        let rig = Rig::new(Script { refuse_forward: true, ..Script::default() }).await;
        let started = rig.start("R", "4000", "127.0.0.1:9").await;
        assert!(started.is_err(), "got {started:?}");
        assert!(eventually(|| rig.map.try_lock().is_ok_and(|m| m.is_empty())).await);
        assert!(rig.targets.lock().await.is_empty());
    }

    // Extra item (insert race): a tunnel whose task already ended is gone
    // after a stop, never left listed as running.
    #[tokio::test]
    async fn stopping_a_tunnel_whose_task_already_ended_forgets_it() {
        let map: super::TunnelMap = Default::default();
        map.lock().await.insert("t1".into(), tunnel(tokio::spawn(async {})));
        super::stop_tunnel_within(&map, "t1", Duration::from_secs(2)).await.unwrap();
        assert!(map.lock().await.is_empty());
    }

    // F-067: when the server answers a port-0 request without naming a
    // port, the forward is refused (it could never be matched).
    #[tokio::test]
    async fn a_server_chosen_port_that_is_never_named_is_refused() {
        let rig = Rig::new(Script { granted_port: 0, ..Script::default() }).await;
        assert!(rig.start("R", "0", "127.0.0.1:9").await.is_err());
        assert!(rig.targets.lock().await.is_empty());
    }

    // F-065: stopping a remote tunnel closes the connections it bridges.
    #[tokio::test]
    async fn stopping_a_remote_tunnel_closes_its_connections() {
        let rig = Rig::new(Script::default()).await;
        let (service, closed) = echo_service_reporting_close().await;
        let id = rig.start("R", "4000", &format!("127.0.0.1:{service}")).await.unwrap();
        assert!(rig.listening(&id).await);
        let mut inbound = rig.connect_from_server(4000).await.unwrap();
        assert_eq!(round_trip(&mut inbound, b"open").await, b"open");
        super::stop_tunnel(&rig.map, &id).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), closed).await.is_ok(),
            "the local connection must close when the tunnel stops"
        );
    }

    // F-065: beyond the cap, a forwarded channel is refused; a closed
    // connection gives its place back.
    #[tokio::test]
    async fn a_remote_tunnel_refuses_connections_beyond_its_cap() {
        let rig = Rig::new(Script::default()).await;
        let service = echo_service().await;
        let id = rig.start("R", "4000", &format!("127.0.0.1:{service}")).await.unwrap();
        assert!(rig.listening(&id).await);
        rig.targets.lock().await.get_mut(&4000).unwrap().limiter = Arc::new(tokio::sync::Semaphore::new(1));
        let mut first = rig.connect_from_server(4000).await.expect("first connection");
        assert_eq!(round_trip(&mut first, b"one").await, b"one");
        assert!(eventually(|| rig.state(&id).is_some_and(|s| s.conns_active == 1)).await, "R connections are counted");
        let second = rig.connect_from_server(4000).await;
        assert!(
            matches!(second, Err(russh::Error::ChannelOpenFailure(russh::ChannelOpenFailure::ResourceShortage))),
            "got {:?}", second.err()
        );
        drop(first);
        assert!(eventually(|| rig.state(&id).is_some_and(|s| s.conns_active == 0)).await);
        assert!(rig.connect_from_server(4000).await.is_ok(), "the place is free again");
    }

    // F-065: a local target that never answers is given up at the bound.
    // Linux only: there a listener whose backlog is full drops new SYNs, so
    // the connect hangs (other systems may refuse it at once instead).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_remote_tunnel_gives_up_on_a_local_target_that_never_answers() {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let full = socket.listen(1).unwrap(); // never accepts
        let addr = full.local_addr().unwrap();
        let mut queued = Vec::new();
        for _ in 0..16 {
            match tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr)).await {
                Ok(Ok(s)) => queued.push(s),
                _ => break,
            }
        }
        let rig = Rig::new(Script::default()).await;
        let id = rig.start("R", "4000", &addr.to_string()).await.unwrap();
        assert!(rig.listening(&id).await);
        rig.targets.lock().await.get_mut(&4000).unwrap().connect_timeout = Duration::from_millis(300);
        let mut inbound = rig.connect_from_server(4000).await.expect("accepted, then bridged");
        let mut buf = [0u8; 1];
        let ended = tokio::time::timeout(Duration::from_secs(3), inbound.read(&mut buf)).await;
        assert!(matches!(ended, Ok(Ok(0)) | Ok(Err(_))), "the channel must end once the connect gives up: {ended:?}");
        let logs = &rig.reported.lock().unwrap().logs;
        assert!(
            logs.iter().any(|(level, event, msg)| level == "error" && event == "fail" && msg.as_deref().is_some_and(|m| m.contains("timed out"))),
            "{logs:?}"
        );
        drop((full, queued));
    }

    // --- Parsers and the dynamic tunnel's protocols ---

    #[test]
    fn absolute_uris_give_host_port_and_path() {
        use super::parse_absolute_uri as uri;
        let some = |h: &str, p: u16, path: &str| Some((h.to_string(), p, path.to_string()));
        assert_eq!(uri("http://example.com/path?q=1"), some("example.com", 80, "/path?q=1"));
        assert_eq!(uri("HTTPS://example.com"), some("example.com", 443, "/"));
        assert_eq!(uri("http://example.com:8080/"), some("example.com", 8080, "/"));
        assert_eq!(uri("http://user:secret@example.com/x"), some("example.com", 80, "/x"));
        assert_eq!(uri("http://[::1]:8080/a"), some("::1", 8080, "/a"));
        assert_eq!(uri("http://[::1]/"), some("::1", 80, "/"));
        for bad in ["/relative", "ftp://example.com/", "file:///etc/passwd", "http:///x", "http://example.com:http/",
                    "http://example.com:0/", "http://::1/", "http://[::1/", "http://[]/"] {
            assert_eq!(uri(bad), None, "{bad}");
        }
    }

    #[test]
    fn forwarded_http_requests_lose_hop_by_hop_headers_and_close() {
        let raw = b"Host: a\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nKeep-Alive: 5\r\nTE: trailers\r\n\
                    Trailers: x\r\nUpgrade: h2c\r\nProxy-Authorization: Basic eA==\r\nProxy-Authenticate: x\r\nAccept: */*\r\n";
        assert_eq!(super::filter_and_rewrite_headers(raw), b"Host: a\r\nConnection: close\r\nAccept: */*\r\n".to_vec());
        // No Connection header: one is added. A line that is not UTF-8 is dropped.
        let raw = b"Host: a\r\nX-Bin: \xff\xfe\r\nAccept: */*\r\n";
        assert_eq!(super::filter_and_rewrite_headers(raw), b"Host: a\r\nAccept: */*\r\nConnection: close\r\n".to_vec());
    }

    /// A dynamic tunnel on a fresh port.
    async fn dynamic(script: Script) -> (Rig, u16) {
        let rig = Rig::new(script).await;
        let port = free_port();
        let id = rig.start("D", &port.to_string(), "").await.unwrap();
        assert!(rig.listening(&id).await);
        (rig, port)
    }

    /// Reads until the tunnel closes the connection.
    async fn read_to_close(client: &mut TcpStream) -> Vec<u8> {
        let mut all = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut all)).await.expect("closed in time").unwrap();
        all
    }

    #[tokio::test]
    async fn socks5_connects_by_ipv4_and_name_and_refuses_what_it_does_not_do() {
        let (rig, port) = dynamic(Script::default()).await;
        let (mut client, code) = socks5_connect(port, &[1, 10, 1, 2, 3], 80).await;
        assert_eq!(code, 0);
        assert_eq!(round_trip(&mut client, b"v4").await, b"v4");
        let mut named = vec![3, 8];
        named.extend_from_slice(b"intranet");
        let (_named, code) = socks5_connect(port, &named, 443).await;
        assert_eq!(code, 0);
        assert!(eventually(|| rig.seen.lock().unwrap().direct.len() == 2).await);
        assert_eq!(rig.seen.lock().unwrap().direct, [("10.1.2.3".to_string(), 80), ("intranet".to_string(), 443)]);

        // Each refusal below sends only what the proxy reads before refusing:
        // closing a socket with unread data resets it, and the reset would
        // discard the reply before the client reads it.
        // No NO-AUTH method offered: "no acceptable method", then closed.
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        assert_eq!(read_to_close(&mut client).await, [5, 0xFF]);
        // BIND (2) is not supported: reply 7.
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&[5, 1, 0, 5, 2, 0, 1]).await.unwrap();
        assert_eq!(read_to_close(&mut client).await, [5, 0, 5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
        // An unknown address type: reply 8.
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&[5, 1, 0, 5, 1, 0, 9]).await.unwrap();
        assert_eq!(read_to_close(&mut client).await, [5, 0, 5, 8, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn socks5_reports_a_refused_channel() {
        let (_rig, port) = dynamic(Script { refuse_direct: true, ..Script::default() }).await;
        let (_client, code) = socks5_connect(port, &[1, 10, 1, 2, 3], 80).await;
        assert_eq!(code, 5, "connection refused");
    }

    #[tokio::test]
    async fn socks4_and_socks4a_connect_and_report_a_refusal() {
        let (rig, port) = dynamic(Script::default()).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&[4, 1, 0, 80, 10, 1, 2, 3, b'u', 0]).await.unwrap();
        let mut reply = [0u8; 8];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[..2], [0, 0x5A]);
        assert_eq!(round_trip(&mut client, b"v4").await, b"v4");
        // SOCKS4a: address 0.0.0.x, the name after the user id.
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&[4, 1, 1, 187, 0, 0, 0, 1, 0]).await.unwrap();
        client.write_all(b"intranet\0").await.unwrap();
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[..2], [0, 0x5A]);
        assert!(eventually(|| rig.seen.lock().unwrap().direct.len() == 2).await);
        assert_eq!(rig.seen.lock().unwrap().direct, [("10.1.2.3".to_string(), 80), ("intranet".to_string(), 443)]);
        // Only CONNECT (the user id is read before the command is refused).
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&[4, 2, 0, 80, 10, 1, 2, 3, 0]).await.unwrap();
        assert_eq!(read_to_close(&mut client).await[..2], [0, 0x5B]);

        let (_rig, port) = dynamic(Script { refuse_direct: true, ..Script::default() }).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&[4, 1, 0, 80, 10, 1, 2, 3, 0]).await.unwrap();
        assert_eq!(read_to_close(&mut client).await[..2], [0, 0x5B]);
    }

    #[tokio::test]
    async fn http_connect_tunnels_and_reports_a_refusal() {
        let (rig, port) = dynamic(Script::default()).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(b"CONNECT intranet:443 HTTP/1.1\r\nHost: intranet:443\r\n\r\n").await.unwrap();
        let mut reply = [0u8; 39];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        assert_eq!(round_trip(&mut client, b"tls bytes").await, b"tls bytes");
        assert_eq!(wait_for_direct(&rig).await, [("intranet".to_string(), 443)]);

        let (_rig, port) = dynamic(Script { refuse_direct: true, ..Script::default() }).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(b"CONNECT intranet:443 HTTP/1.1\r\n\r\n").await.unwrap();
        assert!(read_to_close(&mut client).await.starts_with(b"HTTP/1.1 502"));
    }

    #[tokio::test]
    async fn a_plain_http_request_is_forwarded_with_a_relative_uri_and_filtered_headers() {
        let (rig, port) = dynamic(Script::default()).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client
            .write_all(b"GET http://intranet:8080/a?b=1 HTTP/1.1\r\nHost: intranet:8080\r\nProxy-Connection: keep-alive\r\n\r\n")
            .await
            .unwrap();
        // The test server echoes what reached it.
        let upstream = b"GET /a?b=1 HTTP/1.1\r\nHost: intranet:8080\r\nConnection: close\r\n\r\n";
        let mut got = vec![0u8; upstream.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut got)).await.unwrap().unwrap();
        assert_eq!(got, upstream.to_vec());
        assert_eq!(wait_for_direct(&rig).await, [("intranet".to_string(), 8080)]);
        // A request for this proxy itself is a 400 (refused after the request
        // line, so only that is sent: see the SOCKS5 test).
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(b"GET /x HTTP/1.1\r\n").await.unwrap();
        assert!(read_to_close(&mut client).await.starts_with(b"HTTP/1.1 400"));
    }

    #[tokio::test]
    async fn an_unknown_protocol_is_closed_and_logged() {
        let (rig, port) = dynamic(Script::default()).await;
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(&[0x16]).await.unwrap(); // a TLS hello's first byte
        assert!(read_to_close(&mut client).await.is_empty());
        assert!(eventually(|| rig.reported.lock().unwrap().logs.iter().any(|(_, event, msg)| {
            event == "fail" && msg.as_deref().is_some_and(|m| m.contains("Unknown protocol"))
        })).await);
        assert!(rig.seen.lock().unwrap().direct.is_empty());
    }

    fn starting_status() -> super::TunnelStatus {
        super::TunnelStatus {
            id: "t".into(),
            session_id: "s".into(),
            kind: "remote".into(),
            listen_addr: String::new(),
            target: String::new(),
            state: "starting".into(),
            error: None,
            exposed: false,
            conns_total: 0,
            conns_active: 0,
        }
    }

    // Review: a forward the server grants after the start gave up is
    // cancelled, or the port would stay taken for the connection's life.
    #[tokio::test]
    async fn a_forward_granted_after_the_start_gave_up_is_cancelled() {
        let rig = Rig::new(Script { forward_delay: Some(Duration::from_millis(800)), ..Script::default() }).await;
        let ctx = super::LogCtx { events: rig.events.clone(), session_id: "s".into(), tunnel_id: "t".into() };
        let status = Arc::new(tokio::sync::Mutex::new(starting_status()));
        let target = ("127.0.0.1".to_string(), 9);
        let opened = super::open_remote_forward(&ctx, &rig.handle, &rig.targets, "localhost".into(), 4000, target, status, Duration::from_millis(300)).await;
        assert!(opened.is_err());
        assert!(rig.targets.lock().await.is_empty());
        assert!(eventually(|| rig.seen.lock().unwrap().cancels == [("localhost".to_string(), 4000)]).await);
    }

    // Review: a server that grants port 0 a port another tunnel holds gets a
    // refusal, and the other tunnel is neither unmapped nor cancelled.
    #[tokio::test]
    async fn a_granted_port_another_tunnel_holds_leaves_that_tunnel_alone() {
        let rig = Rig::new(Script { granted_port: 4000, ..Script::default() }).await;
        let service = echo_service().await;
        let first = rig.start("R", "4000", &format!("127.0.0.1:{service}")).await.unwrap();
        assert!(rig.listening(&first).await);
        assert!(rig.start("R", "0", &format!("127.0.0.1:{service}")).await.is_err());
        let mut inbound = rig.connect_from_server(4000).await.expect("the first tunnel still forwards");
        assert_eq!(round_trip(&mut inbound, b"still").await, b"still");
        assert!(rig.seen.lock().unwrap().cancels.is_empty());
    }

    #[tokio::test]
    async fn a_channel_for_a_port_nobody_forwards_is_refused() {
        let rig = Rig::new(Script::default()).await;
        let id = rig.start("R", "4000", "127.0.0.1:9").await.unwrap();
        assert!(rig.listening(&id).await);
        assert!(rig.connect_from_server(4001).await.is_err());
    }

    // Review: rules start at once; a remote forward waiting for the server
    // holds neither the others nor, for long, the caller.
    #[tokio::test]
    async fn several_rules_start_at_once_and_report_in_order() {
        let rig = Arc::new(Rig::new(Script { forward_delay: Some(Duration::from_millis(1000)), ..Script::default() }).await);
        let port = free_port();
        let specs = vec![
            TunnelSpec { kind: "R".into(), local: "4000".into(), remote: "127.0.0.1:9".into() },
            TunnelSpec { kind: "L".into(), local: port.to_string(), remote: "intranet:80".into() },
        ];
        let r = Arc::clone(&rig);
        let all = tokio::spawn(async move { super::start_tunnels(&r.events, "s", &r.handle, &r.map, &r.targets, specs).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        let kinds: Vec<String> = {
            let map = rig.map.lock().await;
            let mut kinds = Vec::new();
            for t in map.values() {
                kinds.push(t.spec.kind.clone());
            }
            kinds
        };
        assert_eq!(kinds, ["L"], "the local tunnel is up while the remote one waits");
        let results = all.await.unwrap();
        assert_eq!(results.iter().map(|(s, _)| s.kind.as_str()).collect::<Vec<_>>(), ["R", "L"]);
        assert!(results.iter().all(|(_, r)| r.is_ok()), "{results:?}");
    }

    // N-017: a node's saved rules are checked with what start_tunnel parses.
    #[test]
    fn check_spec_accepts_what_starts_and_refuses_the_rest() {
        let spec = |kind: &str, local: &str, remote: &str| TunnelSpec { kind: kind.into(), local: local.into(), remote: remote.into() };
        for ok in [
            spec("L", "8080", "db.internal:5432"),
            spec("L", "127.0.0.1:8080", "[::1]:80"),
            spec("D", "1080", ""),
            spec("D", "localhost:1080", "ignored"),
            spec("R", "9000", "127.0.0.1:22"),
            spec("R", "0.0.0.0:0", "localhost:3000"),
        ] {
            assert_eq!(super::check_spec(&ok), Ok(()), "{ok:?}");
        }
        for (bad, why) in [
            (spec("L", "", "db:5432"), "empty"),
            (spec("L", "8080", ""), "must be host:port"),
            (spec("L", "8080", "db:0"), "between 1 and 65535"),
            (spec("L", "99999", "db:5432"), "Invalid port"),
            (spec("L", "intranet:8080", "db:5432"), "IP address or localhost"),
            (spec("D", "0", ""), "between 1 and 65535"),
            (spec("R", "9000", "nowhere"), "must be host:port"),
            (spec("R", "", "x:1"), "empty"),
            (spec("X", "1", "x:1"), "Unknown tunnel kind"),
        ] {
            let err = super::check_spec(&bad).expect_err(&format!("{bad:?}"));
            assert!(err.contains(why), "{bad:?}: {err}");
        }
    }

    // Extra item: a listener may be given as localhost.
    #[test]
    fn localhost_is_a_bind_address() {
        assert_eq!(super::parse_listen("localhost:1080"), Ok("127.0.0.1:1080".parse().unwrap()));
    }

    #[test]
    fn addresses_are_split_with_the_host_bare() {
        use super::split_host_port as split;
        assert_eq!(split("intranet:80"), Ok(("intranet".into(), 80)));
        assert_eq!(split(" 10.0.0.1:22 "), Ok(("10.0.0.1".into(), 22)));
        assert_eq!(split("[::1]:5000"), Ok(("::1".into(), 5000)));
        assert_eq!(split("[fe80::1%eth0]:22"), Ok(("fe80::1%eth0".into(), 22)));
        // The port is required, so an unbracketed IPv6 address splits at the
        // last colon (rules written that way kept working), if it is one.
        assert_eq!(split("::1:80"), Ok(("::1".into(), 80)));
        assert_eq!(split("fe80::1:22"), Ok(("fe80::1".into(), 22)));
        for bad in ["intranet", "::1", "fe80::1%eth0:22", "a:b:80", "[::1]80", "[::1:80", ":80", "[]:80", "host:", "host:65536", "host:-1", "host:http"] {
            assert!(split(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn shown_addresses_bracket_ipv6_again() {
        assert_eq!(super::host_port("::1", 80), "[::1]:80");
        assert_eq!(super::host_port("intranet", 80), "intranet:80");
        assert_eq!(super::bare_host("[::1]".into()), "::1");
        assert_eq!(super::bare_host("intranet".into()), "intranet");
    }

    #[test]
    fn listeners_take_a_port_an_ip_address_or_localhost() {
        let ok = |s: &str| super::parse_listen(s).unwrap().to_string();
        assert_eq!(ok("1080"), "127.0.0.1:1080");
        assert_eq!(ok("LOCALHOST:1080"), "127.0.0.1:1080");
        assert_eq!(ok("0.0.0.0:1080"), "0.0.0.0:1080");
        assert_eq!(ok("[::1]:1080"), "[::1]:1080");
        assert_eq!(ok("[::]:1080"), "[::]:1080");
        assert_eq!(ok("::1:1080"), "[::1]:1080");
        for bad in ["", "0", "65536", "x", "intranet:1080", "127.0.0.1:0", "[::1]"] {
            assert!(super::parse_listen(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn targets_need_a_host_and_a_port() {
        assert_eq!(super::parse_target("[::1]:80"), Ok(("::1".into(), 80)));
        assert!(super::parse_target("80").is_err());
        assert!(super::parse_target("intranet:0").is_err());
        // The server-side bind of a remote tunnel goes out bare too.
        assert_eq!(super::parse_remote_bind("[::]:8080"), Ok(("::".into(), 8080)));
        assert_eq!(super::parse_remote_bind("0"), Ok(("localhost".into(), 0)), "port 0: the server chooses");
        assert!(super::parse_remote_bind("65536").is_err());
    }
}
