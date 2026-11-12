// Docker management commands. Each runs through a fresh exec channel on
// the live SSH session, so the user's PTY is untouched, as a POSIX sh script
// (remote_exec): the host needs `sh` (Linux and macOS hosts; on Windows a WSL
// or similar shell). No remove / rm / down here (product directive), but
// kill is allowed, and prune deletes for good: stopped containers with their
// files, dangling images, unused networks and build cache. The UI lists what
// a prune would remove (`ssh_docker_prune_preview`) and asks first (F-042).

use crate::ssh_manager::SshState;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tauri::Emitter;
use tokio::sync::{oneshot, Mutex as TokioMutex};

/// Output kept per command (the head, or for logs the tail).
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// How long a stopping log stream may take to tell the server (signal, EOF,
/// close) before it ends anyway.
const LOG_STOP_GRACE: Duration = Duration::from_secs(2);
/// A log stream still running this long after being told to stop is aborted.
const LOG_STOP_TIMEOUT: Duration = Duration::from_secs(3);

/// Live log streams, keyed by the frontend's stream id. Each belongs to a
/// session: disconnecting or reconnecting it, its connection being lost and
/// locking the profile stop its streams (F-041), which would otherwise keep
/// the SSH connection up and `docker logs -f` running on the server. Lives in
/// `SshState`.
#[derive(Clone, Default)]
pub struct DockerStreams {
    streams: Arc<TokioMutex<HashMap<String, LogStream>>>,
}

struct LogStream {
    session_id: String,
    /// Tells this stream apart from a later one under the same id.
    token: u64,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

/// Where a log stream's output goes (the app's events; a recorder in tests).
pub(crate) struct LogSink {
    pub(crate) text: Box<dyn Fn(String) + Send + Sync>,
    /// The stream ended, whatever the reason.
    pub(crate) closed: Box<dyn Fn() + Send + Sync>,
}

impl DockerStreams {
    pub fn new() -> Self {
        Self::default()
    }

    /// Follow `channel`, already running the log command, until it ends or
    /// is stopped. A stream already running under `stream_id` is stopped.
    pub(crate) async fn start(&self, stream_id: String, session_id: String, channel: russh::Channel<russh::client::Msg>, sink: LogSink) {
        static NEXT_TOKEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let token = NEXT_TOKEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (stop, stopped) = oneshot::channel();
        let replaced = {
            // Spawned and registered under the lock, so the task's own removal
            // when it ends (which takes the lock) always comes after.
            let mut map = self.streams.lock().await;
            let streams = self.clone();
            let id = stream_id.clone();
            let task = tokio::spawn(async move {
                follow_log_stream(channel, stopped, &sink).await;
                (sink.closed)();
                streams.forget(&id, token).await;
            });
            map.insert(stream_id, LogStream { session_id, token, stop, task })
        };
        stop_streams(replaced.into_iter().collect()).await;
    }

    /// Stop one stream (the user stopped it, or closed its window).
    pub async fn stop(&self, stream_id: &str) {
        let stream = self.streams.lock().await.remove(stream_id);
        stop_streams(stream.into_iter().collect()).await;
    }

    /// Stop every stream of `session_id` (disconnect, reconnect, connection lost).
    pub async fn stop_session(&self, session_id: &str) {
        let streams: Vec<LogStream> = {
            let mut map = self.streams.lock().await;
            let ids: Vec<String> = map.iter().filter(|(_, s)| s.session_id == session_id).map(|(id, _)| id.clone()).collect();
            ids.iter().filter_map(|id| map.remove(id)).collect()
        };
        stop_streams(streams).await;
    }

    /// Stop every stream (the profile is being closed).
    pub async fn stop_all(&self) {
        let streams: Vec<LogStream> = self.streams.lock().await.drain().map(|(_, s)| s).collect();
        stop_streams(streams).await;
    }

    /// A stream that ended removes its own entry, never a newer stream's.
    async fn forget(&self, stream_id: &str, token: u64) {
        let mut map = self.streams.lock().await;
        if map.get(stream_id).is_some_and(|s| s.token == token) {
            map.remove(stream_id);
        }
    }

    #[cfg(test)]
    async fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.streams.lock().await.keys().cloned().collect();
        ids.sort();
        ids
    }
}

/// Tell each stream to stop, all at once; wait for them within
/// `LOG_STOP_TIMEOUT`, then abort what is still running.
async fn stop_streams(streams: Vec<LogStream>) {
    let mut tasks = Vec::with_capacity(streams.len());
    for stream in streams {
        let _ = stream.stop.send(());
        tasks.push(stream.task);
    }
    let deadline = tokio::time::Instant::now() + LOG_STOP_TIMEOUT;
    for mut task in tasks {
        if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
            task.abort();
        }
    }
}

/// Emit the complete-UTF-8 prefix of `out` and KEEP a trailing incomplete
/// multibyte sequence for the next read, so a character split across a flush
/// boundary (the 30 ms tick or the size cap) never turns into replacement
/// characters. A genuinely invalid byte is drained lossily so a malformed
/// stream cannot stall the buffer. `final_flush` emits the whole remainder
/// (the stream is ending; a trailing partial will never arrive).
fn flush_logs(out: &mut Vec<u8>, final_flush: bool, emit: &(dyn Fn(String) + Send + Sync)) {
    if out.is_empty() { return; }
    if final_flush {
        emit(String::from_utf8_lossy(&out[..]).into_owned());
        out.clear();
        return;
    }
    let take = match std::str::from_utf8(&out[..]) {
        Ok(_) => out.len(),
        Err(e) => match e.error_len() {
            // Incomplete tail: keep it buffered for the next read.
            None => e.valid_up_to(),
            // Invalid bytes never complete — emit through them lossily and
            // drain so `out` can't stall/grow on a malformed stream.
            Some(bad) => {
                let end = e.valid_up_to() + bad;
                emit(String::from_utf8_lossy(&out[..end]).into_owned());
                out.drain(..end);
                return;
            }
        },
    };
    if take == 0 { return; } // only a partial char buffered so far
    emit(String::from_utf8_lossy(&out[..take]).into_owned());
    out.drain(..take);
}

/// Forward a log command's output until it ends or `stop` fires (or its
/// sender is dropped). Stopping asks the server to end the command first
/// (`signal TERM`: OpenSSH's sshd signals the command's process group, which
/// ends `docker logs -f` and a `sudo` around it), then sends EOF and closes
/// the channel. Closing alone only closes the command's pipes, and a quiet
/// `docker logs -f` would live on until its next line.
async fn follow_log_stream(mut channel: russh::Channel<russh::client::Msg>, mut stop: oneshot::Receiver<()>, sink: &LogSink) {
    // Coalesce log output: a chatty container's `docker logs -f` can emit a
    // firehose, and one event per read flooded the frontend (each event
    // triggered a setLogs + full re-render of the growing <pre>). Accumulate
    // and flush at most every ~30 ms, or sooner past a size cap.
    // `channel.wait` is cancel-safe, so racing it in select! never drops data.
    const FLUSH_CAP: usize = 256 * 1024;
    let mut out: Vec<u8> = Vec::new();
    let mut flush = tokio::time::interval(Duration::from_millis(30));
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            msg = channel.wait() => match msg {
                Some(russh::ChannelMsg::Data { ref data }) => {
                    out.extend_from_slice(data);
                    if out.len() >= FLUSH_CAP { flush_logs(&mut out, false, &*sink.text); }
                }
                Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => {
                    flush_logs(&mut out, true, &*sink.text);
                    break;
                }
                Some(_) => {}
            },
            _ = flush.tick() => flush_logs(&mut out, false, &*sink.text),
            _ = &mut stop => {
                flush_logs(&mut out, true, &*sink.text);
                let _ = tokio::time::timeout(LOG_STOP_GRACE, async {
                    let _ = channel.signal(russh::Sig::TERM).await;
                    let _ = channel.eof().await;
                    let _ = channel.close().await;
                })
                .await;
                return;
            }
        }
    }
    let _ = tokio::time::timeout(LOG_STOP_GRACE, channel.close()).await;
}

// ---- helpers ----------------------------------------------------------------

// POSIX-safe quoting: every docker command runs in sh (remote_exec).
use crate::remote_exec::sh_quote as shq;

// Validate a docker object name (container/image/volume/network/project).
// Docker's accepted character set is roughly [a-zA-Z0-9_.-], plus colon
// and slash for image:tag and repo paths. Reject anything else so we never
// hand a shell-metachar-laced string to the remote shell. The first
// character is a letter or digit, as in every docker name and id, so a
// value like `-f` can never be read as an option (F-096).
fn is_safe_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 512 || !s.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@' | ':' | '/'))
}

// A compose file path can include spaces and unusual characters; we
// validate only against shell-injection risk (no $`;|&<>(){}newline).
fn is_safe_path(s: &str) -> bool {
    if s.is_empty() || s.len() > 4096 {
        return false;
    }
    !s.chars().any(|c| matches!(c,
        '\0' | '\n' | '\r' | ';' | '|' | '&' | '`' | '$' |
        '<' | '>' | '(' | ')' | '{' | '}' | '*' | '?' | '!' | '\\'
    ))
}

/// Which end of a long output a command's result keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Keep {
    /// The beginning (lists, inspect output).
    Head,
    /// The end: the newest lines of a log.
    Tail,
}

/// A command's exit code and output (stdout and stderr merged).
#[derive(Debug)]
pub(crate) struct CmdOutput {
    pub code: i32,
    pub text: String,
    /// The output was longer than `MAX_OUTPUT_BYTES` and only one end is kept.
    pub truncated: bool,
}

async fn run_capture(
    state: &SshState,
    session_id: &str,
    cmd: &str,
    timeout_secs: u64,
    keep: Keep,
) -> Result<CmdOutput, String> {
    let session_arc = {
        let connections = state.connections.lock().await;
        connections
            .get(session_id)
            .map(Arc::clone)
            .ok_or_else(|| "Session not connected".to_string())?
    };
    run_capture_on(&session_arc, &state.channel_gate(session_id), cmd, timeout_secs, keep).await
}

/// `run_capture` on a given connection.
pub(crate) async fn run_capture_on<H: russh::client::Handler>(
    handle: &TokioMutex<russh::client::Handle<H>>,
    gate: &crate::ssh_connect::ChannelGate,
    cmd: &str,
    timeout_secs: u64,
    keep: Keep,
) -> Result<CmdOutput, String> {
    use crate::remote_exec::{Capture, Overflow, RunError};
    let channel = crate::ssh_connect::open_feature_channel(handle, gate).await?;
    let wrapped = format!("{}\necho __DOCK_EXIT:$?", cmd);
    // Read to the end so the exit marker is seen; only one end is kept (F-072).
    let overflow = match keep {
        Keep::Head => Overflow::KeepHead,
        Keep::Tail => Overflow::KeepTail,
    };
    let limit = Duration::from_secs(timeout_secs);
    let out = crate::remote_exec::run(channel, &wrapped, Capture::new(MAX_OUTPUT_BYTES, overflow), Some("__DOCK_EXIT:"), limit)
        .await
        .map_err(|e| match e {
            RunError::Start(e) => e,
            RunError::TimedOut | RunError::Overflowed => format!("docker command timed out after {}s", timeout_secs),
        })?;
    Ok(CmdOutput { code: out.exit.unwrap_or(1), text: out.text.trim_end_matches('\n').to_string(), truncated: out.truncated })
}

/// A docker command's result: whether it succeeded, its output (stdout and
/// stderr merged), whether that was cut (`truncated`), and whether it took
/// `sudo -n`.
struct DockerRun {
    success: bool,
    output: String,
    truncated: bool,
    used_sudo: bool,
}

// Run a docker command, sudo-retry if the daemon-socket permission failed.
async fn run_docker_smart(
    state: &SshState,
    session_id: &str,
    docker_cmd: &str,
    timeout: u64,
    keep: Keep,
) -> Result<DockerRun, String> {
    let cmd = format!("{} 2>&1", docker_cmd);
    let first = run_capture(state, session_id, &cmd, timeout, keep).await?;
    let lower = first.text.to_lowercase();
    let needs_sudo = first.code != 0
        && (lower.contains("permission denied")
            || lower.contains("cannot connect to the docker daemon")
            || lower.contains("dial unix /var/run/docker.sock")
            || lower.contains("/var/run/docker.sock: connect: permission"));
    if first.code == 0 || !needs_sudo {
        return Ok(DockerRun { success: first.code == 0, output: first.text, truncated: first.truncated, used_sudo: false });
    }
    let sudo_cmd = format!("sudo -n {}", cmd);
    let second = run_capture(state, session_id, &sudo_cmd, timeout, keep).await?;
    Ok(DockerRun { success: second.code == 0, output: second.text, truncated: second.truncated, used_sudo: true })
}

#[derive(Serialize)]
pub struct DockerActionResult {
    pub success: bool,
    pub output: String,
    pub truncated: bool,
    pub used_sudo: bool,
}

#[derive(Serialize)]
pub struct DockerTextResult {
    pub success: bool,
    pub data: String,
    pub truncated: bool,
    pub used_sudo: bool,
}

impl From<DockerRun> for DockerActionResult {
    fn from(r: DockerRun) -> Self {
        DockerActionResult { success: r.success, output: r.output, truncated: r.truncated, used_sudo: r.used_sudo }
    }
}

impl From<DockerRun> for DockerTextResult {
    fn from(r: DockerRun) -> Self {
        DockerTextResult { success: r.success, data: r.output, truncated: r.truncated, used_sudo: r.used_sudo }
    }
}

// ---- container actions -----------------------------------------------------

#[tauri::command]
pub async fn ssh_docker_container_action(
    state: tauri::State<'_, SshState>,
    session_id: String,
    container: String,
    action: String,
) -> Result<DockerActionResult, String> {
    if !is_safe_name(&container) {
        return Err("invalid container name".into());
    }
    // Allow-list: no remove / rm — explicit product directive.
    let valid = matches!(
        action.as_str(),
        "start" | "stop" | "restart" | "pause" | "unpause" | "kill"
    );
    if !valid {
        return Err(format!("invalid action: {}", action));
    }
    let cmd = format!("docker {} {}", action, shq(&container));
    Ok(run_docker_smart(&state, &session_id, &cmd, 60, Keep::Head).await?.into())
}

// ---- inspect / stats / logs (one-shot) -------------------------------------

#[tauri::command]
pub async fn ssh_docker_inspect(
    state: tauri::State<'_, SshState>,
    session_id: String,
    kind: String,
    name: String,
) -> Result<DockerTextResult, String> {
    if !is_safe_name(&name) {
        return Err("invalid name".into());
    }
    let prefix = match kind.as_str() {
        "container" => "container",
        "image" => "image",
        "volume" => "volume",
        "network" => "network",
        _ => return Err("invalid inspect kind".into()),
    };
    let cmd = format!("docker {} inspect {}", prefix, shq(&name));
    Ok(run_docker_smart(&state, &session_id, &cmd, 20, Keep::Head).await?.into())
}

#[tauri::command]
pub async fn ssh_docker_stats(
    state: tauri::State<'_, SshState>,
    session_id: String,
    // Optional container filter. When Some, we ask docker for just that
    // one container's stats — an ~80 ms probe on a quiet daemon and a
    // few hundred bytes on the wire. When None, keep the full-list
    // behaviour so callers that render a resource panel across all
    // containers still work unchanged.
    container: Option<String>,
) -> Result<DockerTextResult, String> {
    // Lean field list (only what the Stats panel renders). Kept as a plain const
    // so the doubled `{{ }}` are literal docker-template braces, not format! args.
    const STATS_FMT: &str = "docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.BlockIO}}|{{.PIDs}}'";
    let cmd = match container.as_deref() {
        Some(name) => {
            if !is_safe_name(name) {
                return Err("invalid container name".into());
            }
            format!("{} {}", STATS_FMT, shq(name))
        }
        None => STATS_FMT.to_string(),
    };
    Ok(run_docker_smart(&state, &session_id, &cmd, 20, Keep::Head).await?.into())
}

#[tauri::command]
pub async fn ssh_docker_logs(
    state: tauri::State<'_, SshState>,
    session_id: String,
    container: String,
    tail: u32,
) -> Result<DockerTextResult, String> {
    if !is_safe_name(&container) {
        return Err("invalid container name".into());
    }
    let cap_tail = tail.min(50_000);
    let cmd = format!(
        "docker logs --tail {} --timestamps {}",
        cap_tail,
        shq(&container)
    );
    Ok(run_docker_smart(&state, &session_id, &cmd, 30, Keep::Tail).await?.into())
}

// ---- networks --------------------------------------------------------------

#[tauri::command]
pub async fn ssh_docker_networks(
    state: tauri::State<'_, SshState>,
    session_id: String,
) -> Result<DockerTextResult, String> {
    let cmd = "docker network ls --format '{{.ID}}|{{.Name}}|{{.Driver}}|{{.Scope}}'";
    Ok(run_docker_smart(&state, &session_id, cmd, 15, Keep::Head).await?.into())
}

// ---- lightweight per-resource list commands --------------------------------
// Separate from the umbrella `ssh_info_probe_section "docker"` so the Docker
// tab can ask for just what the active sub-tab needs — no `docker stats`,
// `docker system df`, or `docker images` round-trips on first paint when the
// user only wanted the container list. Each one runs a single docker call so
// the round-trip stays in the ~100–300 ms range on a quiet daemon.

#[tauri::command]
pub async fn ssh_docker_containers(
    state: tauri::State<'_, SshState>,
    session_id: String,
) -> Result<DockerTextResult, String> {
    // Lean field list (only what the UI renders) instead of `{{json .}}` — skips
    // the unused, often-bulky .Labels/.Mounts/.Networks/.Command per container.
    let cmd = "docker ps -a --format '{{.ID}}|{{.Image}}|{{.Names}}|{{.Status}}|{{.State}}|{{.Ports}}'";
    Ok(run_docker_smart(&state, &session_id, cmd, 15, Keep::Head).await?.into())
}

#[tauri::command]
pub async fn ssh_docker_images_list(
    state: tauri::State<'_, SshState>,
    session_id: String,
) -> Result<DockerTextResult, String> {
    let cmd = "docker images --format '{{.Repository}}|{{.Tag}}|{{.ID}}|{{.Size}}|{{.CreatedSince}}'";
    Ok(run_docker_smart(&state, &session_id, cmd, 15, Keep::Head).await?.into())
}

#[tauri::command]
pub async fn ssh_docker_volumes_list(
    state: tauri::State<'_, SshState>,
    session_id: String,
) -> Result<DockerTextResult, String> {
    let cmd = "docker volume ls --format '{{.Name}}|{{.Driver}}|{{.Mountpoint}}'";
    Ok(run_docker_smart(&state, &session_id, cmd, 15, Keep::Head).await?.into())
}

// ---- compose ---------------------------------------------------------------

// Per-container compose info. Reads docker's own labels — every container
// started by compose carries `com.docker.compose.project`, `…service`, and
// `…project.config_files`. Output is pipe-separated, one container per line:
//   <name>|<project>|<config_files>|<service>|<state>
// Containers without compose labels still appear (project + service empty)
// so the frontend can filter them out without a second round-trip.
#[tauri::command]
pub async fn ssh_docker_compose_per_container(
    state: tauri::State<'_, SshState>,
    session_id: String,
) -> Result<DockerTextResult, String> {
    // Note the unusual quoting: the docker format string itself contains
    // double quotes (Go template's `{{.Label "key"}}`), so we wrap the
    // whole thing in single quotes for the shell. r#"…"# lets us embed
    // those literal double quotes without backslash escaping.
    let cmd = r#"docker ps -a --no-trunc --format '{{.Names}}|{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.project.config_files"}}|{{.Label "com.docker.compose.service"}}|{{.State}}'"#;
    Ok(run_docker_smart(&state, &session_id, cmd, 15, Keep::Head).await?.into())
}

#[tauri::command]
pub async fn ssh_docker_compose_view(
    state: tauri::State<'_, SshState>,
    session_id: String,
    compose_file: String,
) -> Result<DockerTextResult, String> {
    if !is_safe_path(&compose_file) {
        return Err("invalid compose file path".into());
    }
    // Plain cat, no docker — works even if the file's project is stopped.
    // Hard-cap via head so a misconfigured path can't dump a binary at us.
    let cmd = format!("head -c 524288 -- {} 2>&1", shq(&compose_file));
    let out = run_capture(&state, &session_id, &cmd, 10, Keep::Head).await?;
    Ok(DockerTextResult {
        success: out.code == 0,
        data: out.text,
        truncated: out.truncated,
        used_sudo: false,
    })
}

// ---- prune -----------------------------------------------------------------

// Only `prune` without `-a` or `--volumes`: named volumes, tagged images and
// running containers are never touched. What it does remove is gone for good:
// every stopped container with the files inside it (it cannot be started
// again), dangling images, unused networks, dangling build cache. The UI shows
// the preview below and asks before calling this (F-042).
#[tauri::command]
pub async fn ssh_docker_prune(
    state: tauri::State<'_, SshState>,
    session_id: String,
    scope: String,
) -> Result<DockerActionResult, String> {
    let cmd = match scope.as_str() {
        "containers" => "docker container prune -f".to_string(),
        "images" => "docker image prune -f".to_string(), // dangling only — no -a
        "networks" => "docker network prune -f".to_string(),
        "builder" => "docker builder prune -f".to_string(),
        "system" => "docker system prune -f".to_string(), // safe defaults
        _ => return Err("invalid prune scope".into()),
    };
    Ok(run_docker_smart(&state, &session_id, &cmd, 120, Keep::Head).await?.into())
}

/// What each prune scope would remove, listed with docker's own filters: one
/// `kind|name|detail` line per item (F-042).
fn prune_preview_commands(scope: &str) -> Option<Vec<(&'static str, &'static str)>> {
    // `docker container prune` removes every container that is not running.
    const CONTAINERS: (&str, &str) = ("stopped containers", "docker ps -a --filter status=created --filter status=exited --filter status=dead --format 'container|{{.Names}}|{{.Image}}, {{.Status}}'");
    const IMAGES: (&str, &str) = ("dangling images", "docker images --filter dangling=true --format 'image|{{.ID}}|{{.Size}}, {{.CreatedSince}}'");
    const NETWORKS: (&str, &str) = ("unused networks", "docker network ls --filter type=custom --filter dangling=true --format 'network|{{.Name}}|{{.Driver}}'");
    const BUILD_CACHE: (&str, &str) = ("build cache", "docker system df --format '{{.Type}}|{{.Reclaimable}}|{{.Size}}'");
    Some(match scope {
        "containers" => vec![CONTAINERS],
        "images" => vec![IMAGES],
        "networks" => vec![NETWORKS],
        "builder" => vec![BUILD_CACHE],
        "system" => vec![CONTAINERS, NETWORKS, IMAGES, BUILD_CACHE],
        _ => return None,
    })
}

/// The preview lines of one listing's output. `docker system df` lists every
/// type; only the build cache is kept, as an upper bound (prune without `-a`
/// leaves cache that is still referenced). The predefined networks are never
/// pruned and never listed.
fn prune_preview_lines(what: &str, output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            if what == "build cache" {
                let mut cols = line.split('|');
                let (kind, reclaimable, size) = (cols.next()?, cols.next()?, cols.next()?);
                let empty = reclaimable.trim_start().starts_with('0') && !reclaimable.trim_start().starts_with("0.");
                (kind == "Build Cache" && !empty).then(|| format!("builder|Build cache|up to {} of {}", reclaimable.trim(), size.trim()))
            } else {
                let name = line.split('|').nth(1)?;
                let predefined = what == "unused networks" && matches!(name, "bridge" | "host" | "none");
                (!predefined).then(|| line.to_string())
            }
        })
        .collect()
}

#[tauri::command]
pub async fn ssh_docker_prune_preview(
    state: tauri::State<'_, SshState>,
    session_id: String,
    scope: String,
) -> Result<DockerTextResult, String> {
    let listings = prune_preview_commands(&scope).ok_or("invalid prune scope")?;
    let (mut lines, mut success, mut truncated, mut used_sudo) = (Vec::new(), true, false, false);
    for (what, cmd) in listings {
        // A listing that fails (or times out) is said as such; the others
        // are still shown.
        match run_docker_smart(&state, &session_id, cmd, 30, Keep::Head).await {
            Ok(run) if run.success => {
                truncated |= run.truncated;
                used_sudo |= run.used_sudo;
                lines.extend(prune_preview_lines(what, &run.output));
            }
            Ok(run) => {
                success = false;
                let why = run.output.lines().next().unwrap_or("failed").replace('|', "/");
                lines.push(format!("error|{}|{}", what, why));
            }
            Err(e) => {
                success = false;
                lines.push(format!("error|{}|{}", what, e.replace('|', "/")));
            }
        }
    }
    Ok(DockerTextResult { success, data: lines.join("\n"), truncated, used_sudo })
}

// ---- live logs streaming ---------------------------------------------------

#[tauri::command]
pub async fn ssh_docker_logs_start(
    app: tauri::AppHandle,
    state: tauri::State<'_, SshState>,
    session_id: String,
    stream_id: String,
    container: String,
    tail: u32,
) -> Result<(), String> {
    if !is_safe_name(&container) {
        return Err("invalid container name".into());
    }
    let cap_tail = tail.min(50_000);

    let session_arc = {
        let connections = state.connections.lock().await;
        connections
            .get(&session_id)
            .map(Arc::clone)
            .ok_or_else(|| "Session not connected".to_string())?
    };
    let channel = crate::ssh_connect::open_feature_channel(&session_arc, &state.channel_gate(&session_id)).await?;
    // -f for follow; we own the channel for the lifetime of the stream.
    // sudo fallback: we try plain first, but follow can't easily re-try
    // sudo mid-stream, so we pre-detect by running a quick probe.
    let probe_cmd = format!("docker inspect --type=container {} >/dev/null 2>&1; echo $?", shq(&container));
    let use_sudo = match run_capture(&state, &session_id, &probe_cmd, 10, Keep::Head).await {
        Ok(probe) => probe.text.trim() != "0",
        Err(_) => true,
    };

    let raw_cmd = format!(
        "docker logs -f --tail {} --timestamps {} 2>&1",
        cap_tail,
        shq(&container)
    );
    let cmd = if use_sudo {
        format!("sudo -n {}", raw_cmd)
    } else {
        raw_cmd
    };
    tokio::time::timeout(LOG_STOP_TIMEOUT, crate::remote_exec::send_script(&channel, &cmd))
        .await
        .map_err(|_| "the server did not take the log command".to_string())??;

    let event_name = format!("docker-logs-{}", stream_id);
    let close_event = format!("docker-logs-closed-{}", stream_id);
    let app_closed = app.clone();
    let sink = LogSink {
        text: Box::new(move |text| {
            let _ = app.emit(&event_name, text);
        }),
        closed: Box::new(move || {
            let _ = app_closed.emit(&close_event, serde_json::json!({}));
        }),
    };
    state.docker_streams.start(stream_id, session_id, channel, sink).await;
    Ok(())
}

#[tauri::command]
pub async fn ssh_docker_logs_stop(
    state: tauri::State<'_, SshState>,
    stream_id: String,
) -> Result<(), String> {
    state.docker_streams.stop(&stream_id).await;
    Ok(())
}

// ---- terminal exec into container ------------------------------------------

// Opens a PTY-backed exec channel running `docker exec -it <name> <shell>`
// with shell auto-detect: try bash → sh. Wires into the same terminal-IO
// pipeline (`terminal-output-<id>` events + write/resize/close commands)
// the regular shell terminal uses, so xterm.js on the frontend works
// without any branch — just a different exec target.
#[tauri::command]
pub async fn open_container_terminal(
    app: tauri::AppHandle,
    state: tauri::State<'_, SshState>,
    session_id: String,
    terminal_id: String,
    container: String,
    cols: u32,
    rows: u32,
    use_sudo: bool,
    log_file_path: Option<String>,
) -> Result<Option<String>, String> {
    use crate::ssh_manager::{TerminalCommand, start_session_log};

    if !is_safe_name(&container) {
        return Err("invalid container name".into());
    }
    let session_arc = {
        let connections = state.connections.lock().await;
        connections
            .get(&session_id)
            .map(Arc::clone)
            .ok_or_else(|| "Session not connected".to_string())?
    };
    let channel = crate::ssh_connect::open_feature_channel(&session_arc, &state.channel_gate(&session_id)).await?;
    channel
        .request_pty(false, "xterm-256color", cols, rows, 0, 0, &[])
        .await
        .map_err(|e| e.to_string())?;

    // Shell auto-detect runs inside the container: prefer bash, fall back to
    // sh, fall back to ash (Alpine). Anything more exotic and the user can
    // jump in via a regular ssh terminal and figure it out.
    let inner = r#"if command -v bash >/dev/null 2>&1; then exec bash; elif command -v sh >/dev/null 2>&1; then exec sh; elif command -v ash >/dev/null 2>&1; then exec ash; else echo 'no shell found in container' && exit 1; fi"#;
    let docker_cmd = format!("docker exec -it {} sh -c {}", shq(&container), shq(inner));
    let cmd = if use_sudo {
        format!("sudo -n {}", docker_cmd)
    } else {
        docker_cmd
    };
    channel
        .exec(true, cmd.as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    let (tx, rx) = tokio::sync::mpsc::channel::<TerminalCommand>(32);
    let (resize_tx, resize_rx) = tokio::sync::watch::channel(crate::ssh_manager::PtySize {
        cols,
        rows,
    });
    state
        .terminal_txs
        .lock()
        .await
        .insert(terminal_id.clone(), tx);
    state
        .resize_txs
        .lock()
        .await
        .insert(terminal_id.clone(), resize_tx);

    let terminal_id_clone = terminal_id.clone();
    let app_clone = app.clone();
    let (txs, resizes) = (Arc::clone(&state.terminal_txs), Arc::clone(&state.resize_txs));
    let connection = Arc::downgrade(&session_arc);
    // The same log and loop as the SSH terminal (see open_terminal), and the
    // same end: the session's last terminal takes the connection with it.
    let (session_log, log_problem) = start_session_log(&log_file_path).await;
    tauri::async_runtime::spawn(async move {
        let emit = |bytes: &[u8]| crate::ssh_manager::emit_terminal_batch(&app_clone, &terminal_id_clone, bytes);
        let ended = crate::terminal_io::pump(crate::terminal_io::SshTerminal::new(channel), rx, resize_rx, session_log, emit).await;
        crate::ssh_manager::forget_ended_terminal(&txs, &resizes, &terminal_id_clone).await;
        let _ = app_clone.emit(&format!("terminal-closed-{}", terminal_id_clone), serde_json::json!({}));
        if ended == crate::terminal_io::Ended::ByPeer {
            crate::end_session_after_its_last_terminal(&app_clone, &session_id, &connection).await;
        }
    });

    Ok(log_problem)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_test_server::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex as StdMutex;

    type Handle = Arc<TokioMutex<russh::client::Handle<TestClient>>>;

    fn recorder() -> (LogSink, Arc<StdMutex<String>>, Arc<AtomicBool>) {
        let text = Arc::new(StdMutex::new(String::new()));
        let closed = Arc::new(AtomicBool::new(false));
        let (t, c) = (Arc::clone(&text), Arc::clone(&closed));
        let sink = LogSink {
            text: Box::new(move |s| t.lock().unwrap().push_str(&s)),
            closed: Box::new(move || c.store(true, Ordering::SeqCst)),
        };
        (sink, text, closed)
    }

    async fn log_command(handle: &Handle, container: &str) -> russh::Channel<russh::client::Msg> {
        let channel = crate::ssh_connect::open_session_channel(handle).await.unwrap();
        channel.exec(true, format!("docker logs -f --tail 0 {}", shq(container)).as_bytes()).await.unwrap();
        channel
    }

    /// F-041: a session's streams stop with it, and the server is asked to
    /// end each command (TERM), then sees EOF and the channel close. Other
    /// sessions' streams keep running.
    #[tokio::test]
    async fn stopping_a_session_asks_the_server_to_end_its_log_streams() {
        let (handle, seen) = logged_in(Script::default()).await;
        let streams = DockerStreams::new();
        let (sink_a, _, closed_a) = recorder();
        let (sink_b, _, closed_b) = recorder();
        streams.start("a".into(), "session-1".into(), log_command(&handle, "web").await, sink_a).await;
        streams.start("b".into(), "session-2".into(), log_command(&handle, "db").await, sink_b).await;
        assert_eq!(streams.ids().await, ["a", "b"]);

        let started = std::time::Instant::now();
        streams.stop_session("session-1").await;
        assert!(started.elapsed() < LOG_STOP_TIMEOUT);
        assert!(closed_a.load(Ordering::SeqCst), "the window is told the stream ended");
        assert!(!closed_b.load(Ordering::SeqCst));
        assert_eq!(streams.ids().await, ["b"]);
        assert!(eventually(|| { let s = seen.lock().unwrap(); s.signals == ["TERM"] && s.eofs == 1 && s.closes == 1 }).await, "{:?}", seen.lock().unwrap());

        streams.stop_all().await;
        assert!(closed_b.load(Ordering::SeqCst));
        assert!(streams.ids().await.is_empty());
        assert!(eventually(|| seen.lock().unwrap().signals.len() == 2).await);
    }

    /// A stream whose command ends delivers its output, says it ended and
    /// removes its entry, but never a newer stream's under the same id.
    #[tokio::test]
    async fn a_stream_that_ends_by_itself_reports_and_forgets_only_itself() {
        let (handle, seen) = logged_in(Script { exec_output: Some("line 1\nline 2 ✓\n".as_bytes().to_vec()), ..Script::default() }).await;
        let streams = DockerStreams::new();
        let (sink, text, closed) = recorder();
        streams.start("s".into(), "session-1".into(), log_command(&handle, "web").await, sink).await;
        assert!(eventually(|| closed.load(Ordering::SeqCst)).await);
        assert_eq!(*text.lock().unwrap(), "line 1\nline 2 ✓\n");
        assert!(eventually(|| no_streams_left(&streams)).await);
        assert!(seen.lock().unwrap().signals.is_empty(), "nothing to stop");

        let (stop, _stopped) = oneshot::channel();
        let task = tokio::spawn(std::future::pending::<()>());
        streams.streams.lock().await.insert("s".into(), LogStream { session_id: "session-1".into(), token: 99, stop, task });
        streams.forget("s", 98).await;
        assert_eq!(streams.ids().await, ["s"], "an older stream's end leaves the newer one");
        streams.forget("s", 99).await;
        assert!(streams.ids().await.is_empty());
    }

    fn no_streams_left(streams: &DockerStreams) -> bool {
        streams.streams.try_lock().map(|m| m.is_empty()).unwrap_or(false)
    }

    /// F-042: every scope has a preview; "system" lists all four.
    #[test]
    fn every_prune_scope_has_a_preview() {
        for scope in ["containers", "images", "networks", "builder"] {
            assert_eq!(prune_preview_commands(scope).unwrap().len(), 1, "{scope}");
        }
        assert_eq!(prune_preview_commands("system").unwrap().len(), 4);
        assert!(prune_preview_commands("volumes").is_none());
        assert!(prune_preview_commands("containers").unwrap()[0].1.contains("status=exited"));
    }

    #[test]
    fn preview_lines_keep_what_prune_would_remove() {
        let containers = "container|web-old|nginx, Exited (0) 3 days ago\ncontainer|tmp|alpine, Created\n";
        assert_eq!(prune_preview_lines("stopped containers", containers).len(), 2);
        assert!(prune_preview_lines("unused networks", "network|bridge|bridge\nnetwork|app_net|bridge").iter().all(|l| l.contains("app_net")));
        assert_eq!(prune_preview_lines("stopped containers", "container|host|alpine, Exited (0)").len(), 1, "a container named host is listed");
        let df = "Images|11.6MB (70%)|16.4MB\nContainers|212B (100%)|212B\nBuild Cache|1.2GB|3GB\n";
        assert_eq!(prune_preview_lines("build cache", df), ["builder|Build cache|up to 1.2GB of 3GB"]);
        assert!(prune_preview_lines("build cache", "Build Cache|0B|0B").is_empty());
    }

    /// F-096: a name the remote command line would read as an option is refused.
    #[test]
    fn names_that_look_like_options_are_refused() {
        for ok in ["web", "my_app.1", "nginx:1.25", "registry.local:5000/team/app@sha256", "0f3a9c"] {
            assert!(is_safe_name(ok), "{ok}");
        }
        for bad in ["-f", "--help", ".hidden", "_x", "/abs", "a b", "a;b", ""] {
            assert!(!is_safe_name(bad), "{bad}");
        }
    }

    /// A stream whose task does not end when told is aborted after the bound.
    #[tokio::test]
    async fn a_stream_that_does_not_stop_is_aborted() {
        let streams = DockerStreams::new();
        let (stop, _ignored) = oneshot::channel();
        let task = tokio::spawn(std::future::pending::<()>());
        let abort = task.abort_handle();
        streams.streams.lock().await.insert("x".into(), LogStream { session_id: "session-1".into(), token: 1, stop, task });
        let started = std::time::Instant::now();
        streams.stop("x").await;
        assert!(started.elapsed() < LOG_STOP_TIMEOUT + Duration::from_secs(1));
        assert!(eventually(|| abort.is_finished()).await);
    }
}
