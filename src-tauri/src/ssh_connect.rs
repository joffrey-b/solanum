//! The parts of connecting to a server that do not need the app window: which
//! algorithms a connection offers, the handshake deadline, authentication,
//! reaching the host over TCP, and the bounded channel opens and liveness
//! probe an established connection relies on. `lib.rs` wires them to the UI
//! (events, the vault, the nonce maps); keeping them here lets the tests drive
//! them against an SSH server running inside the test process
//! (`ssh_test_server.rs`).
//!
//! Every wait on the server has a bound, and the waits on the user (a host-key
//! prompt, a keyboard-interactive question) have their own, separate bounds,
//! so a slow human never trips a network deadline and a stalled server never
//! hangs a connection attempt (F-026, F-028).

use russh::client;
use russh::keys::{Algorithm, PrivateKey};
use russh::{MethodKind, MethodSet};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Mutex};

/// The network part of the SSH handshake. Paused while a host-key prompt is open.
pub(crate) const HANDSHAKE_BUDGET: Duration = Duration::from_secs(15);
/// What is left at least to finish the handshake once the user answered.
pub(crate) const AFTER_PROMPT_GRACE: Duration = Duration::from_secs(10);
/// Each server round trip during authentication.
pub(crate) const AUTH_REPLY_TIMEOUT: Duration = Duration::from_secs(30);
/// The user's answer to a keyboard-interactive question (codes often mean
/// reaching for a phone).
pub(crate) const KBI_ANSWER_TIMEOUT: Duration = Duration::from_secs(120);
/// Keyboard-interactive rounds in one login, and rounds in a row without a
/// question. A server that keeps going past these is not logging anyone in.
pub(crate) const KBI_MAX_ROUNDS: usize = 8;
pub(crate) const KBI_MAX_EMPTY_ROUNDS: usize = 3;
/// Method attempts in one login (key, password and keyboard-interactive,
/// each at most once per step of a multi-step login).
pub(crate) const AUTH_MAX_ATTEMPTS: usize = 6;
/// The server's time in one login, all round trips together (the user's
/// answers not counted): a hostile server answering each round trip just in
/// time cannot keep "connecting..." going for minutes.
pub(crate) const AUTH_SERVER_BUDGET: Duration = Duration::from_secs(90);
/// Opening a session channel (a terminal, an exec, SFTP) or a ProxyJump
/// `direct-tcpip` channel. One round trip on a healthy link.
pub(crate) const CHANNEL_OPEN_TIMEOUT: Duration = Duration::from_secs(15);
/// The liveness probe's wait for the server's reply.
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
/// Name resolution, then the TCP connect over every address it gave.
pub(crate) const DNS_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const CONNECT_BUDGET: Duration = Duration::from_secs(20);
/// One address's share while more addresses are left to try.
pub(crate) const PER_ADDRESS_TIMEOUT: Duration = Duration::from_secs(6);

// ---------------------------------------------------------------------------
// Algorithms (F-076, F-029)
// ---------------------------------------------------------------------------

/// What a connection may negotiate, per server.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AlgorithmPolicy {
    /// The server's "Allow legacy algorithms" setting: SHA-1 key exchange and
    /// MACs, `ssh-rsa` (SHA-1) host-key signatures and SHA-1 signatures with an
    /// RSA user key. Off unless the user turned it on for that server.
    pub legacy: bool,
    /// Host-key types already trusted for this host and port. They go first,
    /// as OpenSSH does, so a server that still has the key on file is asked for
    /// it, and only a server that no longer has it shows a different type.
    pub known_key_types: Vec<String>,
}

/// ECDH on the NIST curves. russh's default list leaves them out, so a server
/// offering only these and SHA-1 DH (Cisco IOS) was left with SHA-1 or nothing.
pub(crate) const ECDH_KEX: [russh::kex::Name; 3] =
    [russh::kex::ECDH_SHA2_NISTP256, russh::kex::ECDH_SHA2_NISTP384, russh::kex::ECDH_SHA2_NISTP521];
pub(crate) const LEGACY_KEX: [russh::kex::Name; 2] = [russh::kex::DH_G14_SHA1, russh::kex::DH_G1_SHA1];
pub(crate) const LEGACY_MAC: [russh::mac::Name; 2] = [russh::mac::HMAC_SHA1_ETM, russh::mac::HMAC_SHA1];
/// The host-key signature name that means SHA-1 with an RSA key.
pub(crate) const LEGACY_HOST_KEY: &str = "ssh-rsa";

fn is_legacy_name(name: &str) -> bool {
    name == LEGACY_HOST_KEY
        || LEGACY_KEX.iter().any(|k| k.as_ref() == name)
        || LEGACY_MAC.iter().any(|m| m.as_ref() == name)
}

/// Host-key algorithms to offer: russh's strong-first list without SHA-1
/// `ssh-rsa` (appended last when legacy is allowed), with the types already on
/// file moved to the front in their usual relative order.
pub(crate) fn host_key_order(policy: &AlgorithmPolicy) -> Vec<Algorithm> {
    let mut keys: Vec<Algorithm> = russh::Preferred::DEFAULT
        .key
        .iter()
        .filter(|a| !matches!(a, Algorithm::Rsa { hash: None }))
        .cloned()
        .collect();
    if policy.legacy {
        keys.push(Algorithm::Rsa { hash: None });
    }
    let known = |a: &Algorithm| {
        let label = crate::ssh_manager::normalize_host_key_label(a.as_str());
        policy
            .known_key_types
            .iter()
            .any(|t| crate::ssh_manager::normalize_host_key_label(t) == label)
    };
    let (mut first, rest): (Vec<Algorithm>, Vec<Algorithm>) = keys.into_iter().partition(known);
    first.extend(rest);
    first
}

/// The russh client config for one connection (primary, ProxyJump hop,
/// dedicated SFTP/forwarding connection, monitor).
///
/// Starts from russh's strong-first defaults (modern key exchange including
/// the strict-KEX marker, AEAD/CTR ciphers, SHA-2 MACs), with ECDH on the NIST
/// curves right after curve25519, OpenSSH's order. The client's order decides
/// what a negotiation settles on, not the server's. Only with `policy.legacy`
/// are the SHA-1 key exchanges and MACs and `ssh-rsa` host keys added, and then
/// last, so a server that offers anything better still gets it. Compression: delayed `zlib@openssh.com` (after login) or none;
/// plain `zlib` would run the decompressor on the server's data before it has
/// even proved its identity.
pub(crate) fn build_ssh_client_config(policy: &AlgorithmPolicy) -> client::Config {
    let mut preferred = russh::Preferred::DEFAULT;
    let mut kex = preferred.kex.to_vec();
    let after_curve25519 = kex
        .iter()
        .rposition(|k| [russh::kex::CURVE25519, russh::kex::CURVE25519_PRE_RFC_8731].contains(k))
        .map_or(0, |at| at + 1);
    kex.splice(after_curve25519..after_curve25519, ECDH_KEX);
    if policy.legacy {
        for legacy in LEGACY_KEX {
            if !kex.contains(&legacy) {
                kex.push(legacy);
            }
        }
        let mut mac = preferred.mac.to_vec();
        for legacy in LEGACY_MAC {
            if !mac.contains(&legacy) {
                mac.push(legacy);
            }
        }
        preferred.mac = std::borrow::Cow::Owned(mac);
    }
    preferred.kex = std::borrow::Cow::Owned(kex);
    preferred.key = std::borrow::Cow::Owned(host_key_order(policy));
    preferred.compression = std::borrow::Cow::Borrowed(&[russh::compression::ZLIB_LEGACY, russh::compression::NONE]);
    client::Config {
        // SSH keepalive every 20s. The shorter interval matters because most
        // consumer routers drop idle NAT mappings around the 2-minute mark,
        // and many corporate firewalls are stricter still. russh also closes
        // the connection after `keepalive_max` unanswered keepalives; the
        // watcher loop additionally relies on `is_closed()` to surface drops
        // within a couple of seconds.
        keepalive_interval: Some(Duration::from_secs(20)),
        // Bigger receive window + max-allowed packet size: lets SFTP/tunnel
        // streams keep the BDP full on high-latency links.
        window_size: 8 * 1024 * 1024,
        maximum_packet_size: 65535,
        preferred,
        ..client::Config::default()
    }
}

/// The legacy algorithms among those a key exchange settled on, for the
/// "weak algorithms in use" line (`ClientHandler::kex_done`).
pub(crate) fn weak_algorithms(kex: &str, host_key: &str, macs: [&str; 2]) -> Vec<String> {
    let mut weak = Vec::new();
    for name in [kex, host_key, macs[0], macs[1]] {
        if is_legacy_name(name) && !weak.iter().any(|w| w == name) {
            weak.push(name.to_string());
        }
    }
    weak
}

/// When a negotiation failed because the server offers only legacy
/// algorithms, which ones, so the message can point to the per-server setting.
pub(crate) fn legacy_only_offer(e: &russh::Error) -> Option<Vec<String>> {
    match e {
        russh::Error::NoCommonAlgo { theirs, .. } => {
            let legacy: Vec<String> = theirs.iter().filter(|n| is_legacy_name(n)).cloned().collect();
            (!legacy.is_empty()).then_some(legacy)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Handshake (F-026)
// ---------------------------------------------------------------------------

/// Marks the host-key prompt as open for as long as it lives, also when the
/// waiting future is dropped half-way.
pub(crate) struct PromptOpen<'a>(&'a watch::Sender<bool>);

impl<'a> PromptOpen<'a> {
    pub(crate) fn new(flag: &'a watch::Sender<bool>) -> Self {
        flag.send_replace(true);
        PromptOpen(flag)
    }
}

impl Drop for PromptOpen<'_> {
    fn drop(&mut self) {
        self.0.send_replace(false);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct HandshakeTimedOut;

/// Runs the handshake future with `budget` for the network, not counting the
/// time a host-key prompt is open (`prompt` true): the prompt has its own 90 s
/// bound in `check_server_key`, and a user checking a fingerprint out of band
/// must never see it expire under them. Once the prompt closes at least
/// `grace` is left to finish.
pub(crate) async fn handshake_within<F: Future>(
    fut: F,
    budget: Duration,
    grace: Duration,
    mut prompt: watch::Receiver<bool>,
) -> Result<F::Output, HandshakeTimedOut> {
    let mut fut = std::pin::pin!(fut);
    let mut left = budget;
    // False once the flag's sender is gone (the handler ended): no prompt can
    // open any more, and `changed()` would return at once forever.
    let mut watching = true;
    loop {
        let open = watching && *prompt.borrow_and_update();
        if open {
            tokio::select! {
                out = &mut fut => return Ok(out),
                changed = prompt.changed() => {
                    watching = changed.is_ok();
                    left = left.max(grace);
                }
            }
        } else {
            let started = tokio::time::Instant::now();
            tokio::select! {
                out = &mut fut => return Ok(out),
                _ = tokio::time::sleep(left) => return Err(HandshakeTimedOut),
                changed = prompt.changed(), if watching => {
                    watching = changed.is_ok();
                    left = left.saturating_sub(started.elapsed());
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Authentication (F-028, C4)
// ---------------------------------------------------------------------------

/// Bounds for one login: the constants above in the app, shorter in tests.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthLimits {
    /// One server round trip.
    pub reply: Duration,
    /// The user's answer to one keyboard-interactive round.
    pub answer: Duration,
    pub kbi_rounds: usize,
    pub kbi_empty_rounds: usize,
    pub attempts: usize,
    /// All server round trips together.
    pub server_total: Duration,
}

impl Default for AuthLimits {
    fn default() -> Self {
        AuthLimits {
            reply: AUTH_REPLY_TIMEOUT,
            answer: KBI_ANSWER_TIMEOUT,
            kbi_rounds: KBI_MAX_ROUNDS,
            kbi_empty_rounds: KBI_MAX_EMPTY_ROUNDS,
            attempts: AUTH_MAX_ATTEMPTS,
            server_total: AUTH_SERVER_BUDGET,
        }
    }
}

/// What this side can log in with.
pub(crate) struct Credentials {
    /// The server is set to log in with a key (whether or not it could be read).
    pub key_login: bool,
    pub key: Option<Arc<PrivateKey>>,
    /// Why the configured key could not be used, for the final message.
    pub key_problem: Option<String>,
    /// In a password login, the password. In a key login, only a password the
    /// user typed after a failed attempt, sent after the key, as far as the
    /// server asks for one; a stored password is never sent instead of a key.
    pub password: Option<String>,
    /// Whether the user can type a password for a retry (the target's
    /// failed-connection box), which decides how a missing one is reported.
    pub password_can_be_typed: bool,
    /// The server's legacy setting (SHA-1 signatures with an RSA key).
    pub allow_sha1_rsa: bool,
}

/// One keyboard-interactive round as the server sent it: (prompt, echo).
pub(crate) struct KbiRound {
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<(String, bool)>,
}

/// Asks the user one keyboard-interactive round. `None` means cancelled.
/// Dropping the future withdraws the question.
pub(crate) trait KbiPrompter: Sync {
    fn ask(&self, round: KbiRound) -> impl Future<Output = Option<Vec<String>>> + Send;
}

/// How a login failed.
#[derive(Debug)]
pub(crate) enum AuthFailure {
    /// Refused: wrong credentials, a cancelled or unanswered prompt, a
    /// server that loops. Auto-reconnect stops and the password box appears.
    Refused(String),
    /// It cannot go on without something this side does not have: the
    /// server accepted a step and asks for another this connection cannot
    /// provide, or the configured key could not be used at all (unreadable,
    /// or RSA needing SHA-1 without the legacy setting) and the server
    /// refused nothing. A session treats it as `Refused`; a monitor stops at
    /// once instead of trying again (F-017).
    Unanswerable(String),
    /// The server stopped answering.
    TimedOut(String),
    /// The connection broke (also when it reads as a refusal, N-013), or
    /// russh failed.
    Ssh(russh::Error),
}

enum Step {
    Success,
    Failure { remaining: MethodSet, partial: bool },
}

fn method_names(methods: &[MethodKind]) -> String {
    methods.iter().map(<&str>::from).collect::<Vec<_>>().join(", ")
}

/// The server's time left in one login: every round trip draws on it, the
/// user's answers do not.
struct ServerClock {
    left: Duration,
    total: Duration,
}

impl ServerClock {
    async fn reply<T>(&mut self, limit: Duration, fut: impl Future<Output = Result<T, russh::Error>>) -> Result<T, AuthFailure> {
        let started = tokio::time::Instant::now();
        let out = tokio::time::timeout(limit.min(self.left), fut).await;
        self.left = self.left.saturating_sub(started.elapsed());
        match out {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(AuthFailure::Ssh(e)),
            Err(_) if self.left.is_zero() => Err(AuthFailure::TimedOut(format!(
                "The server took too long over the login (more than {} seconds of its own time).",
                self.total.as_secs()
            ))),
            Err(_) => Err(AuthFailure::TimedOut(format!(
                "The server stopped answering during login (no reply within {} seconds).",
                limit.as_secs()
            ))),
        }
    }
}

/// Logs in: public key, then password, then keyboard-interactive, each tried
/// only while the server still lists it, and at most once per step. When the
/// server accepts a method as one step of several (`partial_success`, an
/// OpenSSH `AuthenticationMethods publickey,password` setup), the login goes
/// on with the methods it asks for next instead of reading that as a
/// refusal (C4). Every server round trip is bounded by `limits.reply`, the
/// user's answers by `limits.answer`, keyboard-interactive by its round caps
/// (F-028).
pub(crate) async fn authenticate<H: client::Handler, P: KbiPrompter>(
    session: &mut client::Handle<H>,
    user: &str,
    creds: Credentials,
    prompter: Option<&P>,
    limits: AuthLimits,
    log: &(dyn Fn(&str, &str) + Sync),
) -> Result<(), AuthFailure> {
    let mut remaining: Option<MethodSet> = None;
    // Methods tried since the last partial success, and the steps passed.
    let mut tried: Vec<MethodKind> = Vec::new();
    let mut passed: Vec<MethodKind> = Vec::new();
    let mut notes: Vec<String> = creds.key_problem.iter().cloned().collect();
    // The server turned down a credential this side sent.
    let mut refused_by_server = false;
    let mut attempts = 0;
    let mut clock = ServerClock { left: limits.server_total, total: limits.server_total };
    if creds.key.is_none() && creds.password.is_none() && prompter.is_none() {
        log("Neither private key nor password auth credentials provided.", "error");
    }
    loop {
        let fresh = |m: MethodKind, tried: &[MethodKind]| {
            !tried.contains(&m) && !passed.contains(&m) && remaining.as_ref().is_none_or(|r| r.contains(&m))
        };
        let key_had_its_turn = creds.key.is_none() || tried.contains(&MethodKind::PublicKey) || passed.contains(&MethodKind::PublicKey);
        let next = if creds.key.is_some() && fresh(MethodKind::PublicKey, &tried) {
            MethodKind::PublicKey
        } else if creds.password.is_some() && fresh(MethodKind::Password, &tried) && (!creds.key_login || key_had_its_turn) {
            MethodKind::Password
        } else if prompter.is_some() && fresh(MethodKind::KeyboardInteractive, &tried) {
            MethodKind::KeyboardInteractive
        } else {
            break;
        };
        if attempts == limits.attempts {
            return Err(AuthFailure::Refused(format!("The login was stopped after {} attempts.", limits.attempts)));
        }
        attempts += 1;
        let step = match next {
            MethodKind::PublicKey => {
                log("Attempting Private Key Authentication...", "info");
                let key = Arc::clone(creds.key.as_ref().expect("checked above"));
                match clock
                    .reply(limits.reply, crate::ssh_manager::authenticate_with_key(session, user, key, creds.allow_sha1_rsa))
                    .await?
                {
                    crate::ssh_manager::KeyAttempt::NeedsSha1 => {
                        log(crate::ssh_manager::NEEDS_SHA1_RSA, "error");
                        notes.push(crate::ssh_manager::NEEDS_SHA1_RSA.to_string());
                        tried.push(MethodKind::PublicKey);
                        continue;
                    }
                    crate::ssh_manager::KeyAttempt::Answered(result) => result.into(),
                }
            }
            MethodKind::Password => {
                log("Attempting Password Authentication...", "info");
                let password = creds.password.clone().expect("checked above");
                clock.reply(limits.reply, session.authenticate_password(user, password)).await?.into()
            }
            _ => keyboard_interactive(session, user, prompter.expect("checked above"), limits, &mut clock, log).await?,
        };
        match step {
            Step::Success => return Ok(()),
            Step::Failure { remaining: methods, partial } => {
                // russh reports a connection that ended while it waited for
                // the answer as a refusal listing no methods (N-013).
                if methods.is_empty() && !partial {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                if session.is_closed() {
                    return Err(AuthFailure::Ssh(russh::Error::Disconnect));
                }
                if partial {
                    log(
                        &format!(
                            "The server accepted {} and asks for more: {}.",
                            <&str>::from(&next),
                            method_names(&methods)
                        ),
                        "info",
                    );
                    passed.push(next);
                    tried.clear();
                } else {
                    refused_by_server = true;
                    tried.push(next);
                }
                remaining = Some(methods);
            }
        }
    }
    let wants: Vec<MethodKind> = remaining.as_deref().unwrap_or(&[]).to_vec();
    if !passed.is_empty() {
        return Err(AuthFailure::Unanswerable(
            if wants.contains(&MethodKind::Password) && creds.password.is_none() && creds.password_can_be_typed {
                format!(
                    "The server accepted {} and also asks for a password. Type it below and reconnect.",
                    method_names(&passed)
                )
            } else {
                format!(
                    "The server accepted {} but asks for more ({}), which this connection cannot provide.",
                    method_names(&passed),
                    if wants.is_empty() { "nothing it named".to_string() } else { method_names(&wants) }
                )
            },
        ));
    }
    if !notes.is_empty() && !refused_by_server {
        return Err(AuthFailure::Unanswerable(notes.join(" ")));
    }
    let reason = if !notes.is_empty() {
        notes.join(" ")
    } else {
        "Authentication rejected by server (wrong password, missing key, or account locked).".to_string()
    };
    Err(AuthFailure::Refused(reason))
}

impl From<client::AuthResult> for Step {
    fn from(r: client::AuthResult) -> Self {
        match r {
            client::AuthResult::Success => Step::Success,
            client::AuthResult::Failure { remaining_methods, partial_success } => {
                Step::Failure { remaining: remaining_methods, partial: partial_success }
            }
        }
    }
}

/// One keyboard-interactive exchange (RFC 4256): relays each round with
/// questions to the prompter and answers rounds without questions itself,
/// within the round caps.
async fn keyboard_interactive<H: client::Handler, P: KbiPrompter>(
    session: &mut client::Handle<H>,
    user: &str,
    prompter: &P,
    limits: AuthLimits,
    clock: &mut ServerClock,
    log: &(dyn Fn(&str, &str) + Sync),
) -> Result<Step, AuthFailure> {
    use client::KeyboardInteractiveAuthResponse as Kbi;
    log("Attempting Keyboard-Interactive (verification code) authentication...", "info");
    let mut resp = clock.reply(limits.reply, session.authenticate_keyboard_interactive_start(user.to_string(), None)).await?;
    let (mut rounds, mut empty_in_a_row, mut asked) = (0, 0, false);
    loop {
        match resp {
            Kbi::Success => return Ok(Step::Success),
            Kbi::Failure { remaining_methods, partial_success } => {
                if asked && !partial_success {
                    log("Verification code rejected by server.", "error");
                }
                return Ok(Step::Failure { remaining: remaining_methods, partial: partial_success });
            }
            Kbi::InfoRequest { name, instructions, prompts } => {
                rounds += 1;
                if rounds > limits.kbi_rounds {
                    return Err(AuthFailure::Refused(format!(
                        "The server kept asking keyboard-interactive questions (more than {} rounds), so the login was stopped.",
                        limits.kbi_rounds
                    )));
                }
                let answers = if prompts.is_empty() {
                    // A banner-only round needs an empty answer to move on.
                    empty_in_a_row += 1;
                    if empty_in_a_row > limits.kbi_empty_rounds {
                        return Err(AuthFailure::Refused(format!(
                            "The server sent more than {} keyboard-interactive rounds in a row without a question, so the login was stopped.",
                            limits.kbi_empty_rounds
                        )));
                    }
                    Vec::new()
                } else {
                    empty_in_a_row = 0;
                    asked = true;
                    let count = prompts.len();
                    let round = KbiRound {
                        name,
                        instructions,
                        prompts: prompts.into_iter().map(|p| (p.prompt, p.echo)).collect(),
                    };
                    match tokio::time::timeout(limits.answer, prompter.ask(round)).await {
                        Ok(Some(mut answers)) => {
                            // Exactly one answer per prompt, or the server's
                            // state machine and ours disagree.
                            answers.resize(count, String::new());
                            answers
                        }
                        Ok(None) => return Err(AuthFailure::Refused("The verification prompt was cancelled.".into())),
                        Err(_) => {
                            return Err(AuthFailure::Refused(format!(
                                "The verification prompt was not answered within {} seconds.",
                                limits.answer.as_secs()
                            )))
                        }
                    }
                };
                resp = clock.reply(limits.reply, session.authenticate_keyboard_interactive_respond(answers)).await?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Channels on an established connection (F-028)
// ---------------------------------------------------------------------------

/// Why a connection runs a plain terminal and nothing beside it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TerminalOnly {
    /// The server's "Terminal only" setting.
    Setting,
    /// Its identification string names a device with one channel per connection.
    ServerIdent,
    /// It refused a channel while it had given this connection only one.
    RefusedChannel,
}

impl TerminalOnly {
    /// What a feature beside the terminal answers on such a connection.
    pub(crate) fn refusal(self) -> &'static str {
        match self {
            TerminalOnly::Setting => "This server is set to terminal only: SFTP, live info and Docker are off for it.",
            TerminalOnly::ServerIdent | TerminalOnly::RefusedChannel => {
                "This host allows one channel per connection, and the terminal uses it: SFTP, live info and Docker are unavailable on it."
            }
        }
    }
}

/// The software names, in the identification string (RFC 4253 section 4.2,
/// `SSH-<protocol>-<software>`), of devices known to give one channel per
/// connection. Any other such device is found by its first refusal instead.
const ONE_CHANNEL_SOFTWARE: &[&str] = &["Cisco"];

/// Whether a server's identification string names such a device. IOS sends
/// `SSH-2.0-Cisco-1.25`, or `SSH-1.99-Cisco-1.25` with SSH 1 still enabled.
pub(crate) fn is_one_channel_server(ident: &[u8]) -> bool {
    let ident = String::from_utf8_lossy(ident);
    let mut parts = ident.trim_end().splitn(3, '-');
    let (Some("SSH"), Some(_protocol), Some(software)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let name = software.split(['-', '_', ' ']).next().unwrap_or_default();
    ONE_CHANNEL_SOFTWARE.contains(&name)
}

/// What one connection's server allows beside the terminal. Every channel for
/// a feature goes through `open_feature_channel`, so once this says terminal
/// only, nothing asks the server again: a refused channel disables the feature
/// for this connection and touches nothing else.
pub(crate) struct ChannelGate {
    /// Session channels the server has accepted on this connection.
    accepted: AtomicU32,
    limit: watch::Sender<Option<TerminalOnly>>,
}

impl Default for ChannelGate {
    fn default() -> Self {
        ChannelGate::new(false)
    }
}

impl ChannelGate {
    /// `terminal_only`: the server's setting.
    pub(crate) fn new(terminal_only: bool) -> Self {
        let limit = terminal_only.then_some(TerminalOnly::Setting);
        ChannelGate { accepted: AtomicU32::new(0), limit: watch::channel(limit).0 }
    }

    pub(crate) fn limit(&self) -> Option<TerminalOnly> {
        *self.limit.borrow()
    }

    /// Told when the limit is set, for a window to hear about it.
    pub(crate) fn subscribe(&self) -> watch::Receiver<Option<TerminalOnly>> {
        self.limit.subscribe()
    }

    /// The first reason found stays. True when this call set it.
    fn set_limit(&self, why: TerminalOnly) -> bool {
        self.limit.send_if_modified(|limit| {
            let unset = limit.is_none();
            if unset {
                *limit = Some(why);
            }
            unset
        })
    }

    /// The identification string, known once the key exchange is done. True
    /// when it just made this connection terminal only.
    pub(crate) fn note_server_ident(&self, ident: &[u8]) -> bool {
        is_one_channel_server(ident) && self.set_limit(TerminalOnly::ServerIdent)
    }

    /// A refusal says "one channel per connection" only while the server has
    /// accepted exactly one. With none, there is no channel a limit could be
    /// counting. With more, the server has shown it can do better: this is
    /// `MaxSessions` or a passing shortage on a normal host, whose features
    /// must keep working once it has passed.
    fn note_refused(&self) {
        if self.accepted.load(Ordering::SeqCst) == 1 {
            self.set_limit(TerminalOnly::RefusedChannel);
        }
    }
}

/// Opens a session channel on a shared connection and records the answer. The
/// connection's mutex is held only for the open, and the open is bounded:
/// a server that never confirms must not freeze everything else that needs
/// the connection, the health watcher included.
async fn open_counted<H: client::Handler>(
    handle: &Mutex<client::Handle<H>>,
    gate: &ChannelGate,
    limit: Duration,
) -> Result<russh::Channel<client::Msg>, String> {
    let h = handle.lock().await;
    match tokio::time::timeout(limit, h.channel_open_session()).await {
        Ok(Ok(channel)) => {
            gate.accepted.fetch_add(1, Ordering::SeqCst);
            Ok(channel)
        }
        Ok(Err(e)) => {
            if matches!(e, russh::Error::ChannelOpenFailure(_)) {
                gate.note_refused();
                if let Some(why @ (TerminalOnly::ServerIdent | TerminalOnly::RefusedChannel)) = gate.limit() {
                    return Err(why.refusal().to_string());
                }
            }
            Err(e.to_string())
        }
        Err(_) => Err(format!("the server did not open a session channel within {} seconds", limit.as_secs())),
    }
}

/// The channel of a terminal tab. It is asked for whatever the gate says: the
/// terminal is the one thing a limited host does, and a refusal only fails this
/// tab.
pub(crate) async fn open_terminal_channel<H: client::Handler>(
    handle: &Mutex<client::Handle<H>>,
    gate: &ChannelGate,
) -> Result<russh::Channel<client::Msg>, String> {
    open_counted(handle, gate, CHANNEL_OPEN_TIMEOUT).await
}

/// The channel of a feature beside the terminal (SFTP, an Info probe, a Docker
/// command). A connection known to be terminal only gets its refusal here,
/// without asking the server.
pub(crate) async fn open_feature_channel<H: client::Handler>(
    handle: &Mutex<client::Handle<H>>,
    gate: &ChannelGate,
) -> Result<russh::Channel<client::Msg>, String> {
    if let Some(why) = gate.limit() {
        return Err(why.refusal().to_string());
    }
    open_counted(handle, gate, CHANNEL_OPEN_TIMEOUT).await
}

/// A channel for a test that is not about the gate.
#[cfg(test)]
pub(crate) async fn open_session_channel<H: client::Handler>(
    handle: &Mutex<client::Handle<H>>,
) -> Result<russh::Channel<client::Msg>, String> {
    open_session_channel_within(handle, CHANNEL_OPEN_TIMEOUT).await
}

#[cfg(test)]
pub(crate) async fn open_session_channel_within<H: client::Handler>(
    handle: &Mutex<client::Handle<H>>,
    limit: Duration,
) -> Result<russh::Channel<client::Msg>, String> {
    open_counted(handle, &ChannelGate::default(), limit).await
}

/// How a connection ended, as its handler saw it (`ClientHandler::disconnected`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConnectionEnd {
    /// The server said goodbye (`SSH_MSG_DISCONNECT`): its reason code and its
    /// own text, made visible.
    Goodbye { code: String, message: String },
    /// The other end closed the network connection without a goodbye: what a
    /// Cisco switch does after `exit` ("early eof").
    Closed,
    /// Anything else (a reset, a keepalive timeout, a protocol error), in words.
    Failed(String),
}

impl ConnectionEnd {
    pub(crate) fn from_reason(reason: &client::DisconnectReason<russh::Error>) -> Self {
        use client::DisconnectReason::{Error, ReceivedDisconnect};
        match reason {
            ReceivedDisconnect(info) => ConnectionEnd::Goodbye {
                code: format!("{:?}", info.reason_code),
                message: crate::open_guard::visible_text(&info.message),
            },
            Error(russh::Error::Disconnect) => ConnectionEnd::Closed,
            Error(russh::Error::IO(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => ConnectionEnd::Closed,
            Error(russh::Error::KeepaliveTimeout) => ConnectionEnd::Failed("the server stopped answering keepalives".to_string()),
            Error(e) => ConnectionEnd::Failed(format!("the connection failed: {e}")),
        }
    }

    /// Whether the server ended the session rather than the network losing
    /// it (N-028). A goodbye is always the server's. A plain close is too on a
    /// direct connection: a link that dies gives a reset or silence, not an
    /// orderly close. Through a proxy or a jump host the close may come from
    /// the hop when the path behind it breaks, so there it is a network problem.
    pub(crate) fn by_server(&self, direct: bool) -> bool {
        match self {
            ConnectionEnd::Goodbye { .. } => true,
            ConnectionEnd::Closed => direct,
            ConnectionEnd::Failed(_) => false,
        }
    }

    /// In words, for the log and the banner.
    pub(crate) fn describe(&self, direct: bool) -> String {
        match self {
            ConnectionEnd::Goodbye { code, message } if message.is_empty() => format!("the server ended the connection ({code})"),
            ConnectionEnd::Goodbye { code, message } => format!("the server ended the connection ({code}: {message})"),
            ConnectionEnd::Closed if direct => "the server closed the connection".to_string(),
            ConnectionEnd::Closed => "the connection was closed at the other end".to_string(),
            ConnectionEnd::Failed(why) => why.clone(),
        }
    }
}

/// What the health watcher reports when a connection ended: the reason, and
/// whether the server ended the session (no auto-reconnect; R logs in again)
/// rather than the network losing it. `transport_closed`: the connection ended
/// (otherwise the liveness probes gave up on it); `direct`: no proxy or jump
/// host in between.
pub(crate) fn connection_end_report(transport_closed: bool, end: Option<&ConnectionEnd>, direct: bool) -> (String, bool) {
    if !transport_closed {
        return (
            "Connection lost: the server did not answer two liveness probes in a row, so Solanum gave up on this connection".to_string(),
            false,
        );
    }
    match end {
        Some(end) if end.by_server(direct) => (end.describe(direct), true),
        Some(end) => (format!("Connection lost: {}", end.describe(direct)), false),
        None => ("Connection lost: the connection closed".to_string(), false),
    }
}

/// Whether an established connection still answers (F-027). It sends a
/// `keepalive@openssh.com` global request asking for a reply, as OpenSSH's
/// `ServerAliveInterval` does: any reply, success or failure, proves the
/// link. Only silence within `limit` or a closed connection counts against
/// it. The old probe opened a session channel, which used up one of the
/// server's `MaxSessions` slots and read a "too many sessions" refusal as a
/// dead link. (A connection that ends while the request waits also returns
/// here as answered; the watcher's `is_closed()` check sees it next.)
pub(crate) async fn probe_alive<H: client::Handler>(handle: &Mutex<client::Handle<H>>, limit: Duration) -> bool {
    let h = handle.lock().await;
    matches!(tokio::time::timeout(limit, h.send_ping()).await, Ok(Ok(())))
}

/// How long ending one connection may take when the profile is closed.
pub(crate) const CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Ends connections with an explicit SSH disconnect, all at once, each within
/// `limit` (the wait for its mutex included). Dropping our handle is not
/// enough: anything still holding one of its channels (a transfer, a log
/// stream) would keep the transport up until it lets go (F-013, F-041).
/// The connections of `SshState`, generic over the handler so tests can use
/// their own.
type Connections<H> = Mutex<std::collections::HashMap<String, Arc<Mutex<client::Handle<H>>>>>;
type JumpConnections<H> = Mutex<std::collections::HashMap<String, client::Handle<H>>>;

/// What the health watcher's "connection lost" took out of the maps.
pub(crate) enum Lost<H: client::Handler> {
    /// A reconnect registered another connection meanwhile: everything is
    /// left to that one.
    Superseded,
    /// Removed, with the jump host's connection that carried it, if any, for
    /// the caller to close.
    Removed(Option<client::Handle<H>>),
}

/// Removes `id`'s connection if it is still `ours`, and in the same locked
/// step the jump host's connection that carried it, so the bastion does not
/// stay logged in after its session (R-004). `also` runs there too, for the
/// maps kept beside it (server identity, channel gate). The jump handle is
/// registered under the same lock (`initiate_connection`), so the one found
/// here is always the lost connection's.
pub(crate) async fn take_lost_connection<H: client::Handler>(
    connections: &Connections<H>,
    jumps: &JumpConnections<H>,
    id: &str,
    ours: &Arc<Mutex<client::Handle<H>>>,
    also: impl FnOnce(),
) -> Lost<H> {
    let mut conns = connections.lock().await;
    match conns.get(id) {
        Some(current) if Arc::ptr_eq(current, ours) => {
            conns.remove(id);
            also();
            Lost::Removed(jumps.lock().await.remove(id))
        }
        _ => Lost::Superseded,
    }
}

pub(crate) async fn close_handles<H: client::Handler + 'static>(handles: Vec<Arc<Mutex<client::Handle<H>>>>, limit: Duration) {
    let mut closing = tokio::task::JoinSet::new();
    for handle in handles {
        closing.spawn(async move {
            let _ = tokio::time::timeout(limit, async {
                let h = handle.lock().await;
                let _ = h.disconnect(russh::Disconnect::ByApplication, "", "").await;
            })
            .await;
        });
    }
    while closing.join_next().await.is_some() {}
}

// ---------------------------------------------------------------------------
// TCP (F-077)
// ---------------------------------------------------------------------------

/// Why reaching a host over TCP failed.
#[derive(Debug)]
pub(crate) enum TcpConnectError {
    /// The name did not resolve, or not in time.
    Resolve(String),
    /// The last address tried refused or failed.
    Failed(std::io::Error),
    /// No address answered in time.
    TimedOut { tried: usize, budget: Duration },
}

/// Puts the resolver's addresses in the order to try them: families taking
/// turns, starting with the resolver's first choice (RFC 8305), so one family
/// that black-holes cannot use up the whole budget.
pub(crate) fn interleave_families(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first) = addrs.first().copied() else {
        return addrs;
    };
    let (mut lead, mut other): (std::collections::VecDeque<SocketAddr>, std::collections::VecDeque<SocketAddr>) =
        addrs.into_iter().partition(|a| a.is_ipv6() == first.is_ipv6());
    let mut out = Vec::with_capacity(lead.len() + other.len());
    loop {
        match (lead.pop_front(), other.pop_front()) {
            (None, None) => return out,
            (a, b) => out.extend(a.into_iter().chain(b)),
        }
    }
}

/// Tries `addrs` in order within `budget`. Each address gets at most
/// `per_address` while others are left; the last one gets what remains.
pub(crate) async fn try_addresses<T, F, Fut>(
    addrs: &[SocketAddr],
    budget: Duration,
    per_address: Duration,
    connect: F,
) -> Result<T, TcpConnectError>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = std::io::Result<T>>,
{
    let deadline = tokio::time::Instant::now() + budget;
    let (mut tried, mut last_error, mut last_timed_out) = (0, None, false);
    for (i, addr) in addrs.iter().enumerate() {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            last_timed_out = true;
            break;
        }
        let limit = if i + 1 == addrs.len() { left } else { left.min(per_address) };
        tried += 1;
        match tokio::time::timeout(limit, connect(*addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                last_error = Some(e);
                last_timed_out = false;
            }
            Err(_) => last_timed_out = true,
        }
    }
    match last_error {
        Some(e) if !last_timed_out => Err(TcpConnectError::Failed(e)),
        _ => Err(TcpConnectError::TimedOut { tried, budget }),
    }
}

/// Resolves `host`, then connects to its addresses one after the other
/// (families interleaved), each with its own timeout inside one overall
/// budget (F-077): a broken IPv6 route no longer uses up the time an IPv4
/// address would have answered in.
pub(crate) async fn connect_tcp(host: &str, port: u16) -> Result<tokio::net::TcpStream, TcpConnectError> {
    let addrs: Vec<SocketAddr> = match tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host((host, port))).await {
        Ok(Ok(found)) => found.collect(),
        Ok(Err(e)) => return Err(TcpConnectError::Resolve(e.to_string())),
        Err(_) => return Err(TcpConnectError::Resolve(format!("no answer within {} seconds", DNS_TIMEOUT.as_secs()))),
    };
    if addrs.is_empty() {
        return Err(TcpConnectError::Resolve("no address found".into()));
    }
    try_addresses(&interleave_families(addrs), CONNECT_BUDGET, PER_ADDRESS_TIMEOUT, tokio::net::TcpStream::connect).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_test_server::*;
    use std::sync::Arc;

    fn plain_config() -> Arc<client::Config> {
        Arc::new(build_ssh_client_config(&AlgorithmPolicy::default()))
    }

    /// R-004: when the watcher finds a connection lost, the jump host's
    /// connection that carried it goes too (it stayed logged in until the tab
    /// closed), and a connection a reconnect registered meanwhile is left
    /// alone, with its jump host.
    #[tokio::test]
    async fn a_lost_connection_takes_its_jump_host_with_it() {
        // An async fn, not a closure: a russh Handle is itself a future (it
        // ends with the session), which clippy's async_yields_async flags in
        // an async block.
        async fn bastion() -> client::Handle<TestClient> {
            Arc::try_unwrap(logged_in(Script::default()).await.0).ok().expect("one owner").into_inner()
        }
        let (primary, _) = logged_in(Script::default()).await;
        let (newer, _) = logged_in(Script::default()).await;
        let conns: Connections<TestClient> = Mutex::new(Default::default());
        let jumps: JumpConnections<TestClient> = Mutex::new(Default::default());

        conns.lock().await.insert("s1".into(), Arc::clone(&newer));
        jumps.lock().await.insert("s1".into(), bastion().await);
        let mut touched = false;
        let lost = take_lost_connection(&conns, &jumps, "s1", &primary, || touched = true).await;
        assert!(matches!(lost, Lost::Superseded) && !touched, "a newer connection is not ours to remove");
        assert!(conns.lock().await.contains_key("s1") && jumps.lock().await.contains_key("s1"));

        conns.lock().await.insert("s1".into(), Arc::clone(&primary));
        let lost = take_lost_connection(&conns, &jumps, "s1", &primary, || touched = true).await;
        assert!(touched);
        assert!(conns.lock().await.is_empty(), "the lost connection stays registered");
        assert!(jumps.lock().await.is_empty(), "the jump host's connection outlives its session");
        let Lost::Removed(Some(jump)) = lost else { panic!("the jump host's connection was not handed back to be closed") };
        let jump = Arc::new(Mutex::new(jump));
        close_handles(vec![Arc::clone(&jump)], CLOSE_TIMEOUT).await;
        assert!(jump.lock().await.is_closed());
    }

    fn names(keys: &[Algorithm]) -> Vec<String> {
        keys.iter().map(|a| a.to_string()).collect()
    }

    /// F-029/F-076: trusted key types first, in their usual order; SHA-1
    /// `ssh-rsa` only with the legacy setting, and then last.
    #[test]
    fn host_key_types_on_file_are_asked_for_first() {
        let default = names(&host_key_order(&AlgorithmPolicy::default()));
        assert_eq!(default[0], "ssh-ed25519");
        assert!(!default.contains(&"ssh-rsa".to_string()));

        let ecdsa = names(&host_key_order(&AlgorithmPolicy {
            known_key_types: vec!["ecdsa-sha2-nistp256".into()],
            ..AlgorithmPolicy::default()
        }));
        assert_eq!(ecdsa[0], "ecdsa-sha2-nistp256");
        assert_eq!(ecdsa[1], "ssh-ed25519");
        assert_eq!(ecdsa.len(), default.len());

        let rsa = AlgorithmPolicy { known_key_types: vec!["ssh-rsa".into()], ..AlgorithmPolicy::default() };
        assert_eq!(names(&host_key_order(&rsa))[..2], ["rsa-sha2-512", "rsa-sha2-256"]);
        let rsa_legacy = AlgorithmPolicy { legacy: true, ..rsa };
        assert_eq!(names(&host_key_order(&rsa_legacy))[..3], ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]);
        assert_eq!(names(&host_key_order(&AlgorithmPolicy { legacy: true, ..AlgorithmPolicy::default() })).last().unwrap(), "ssh-rsa");
    }

    #[test]
    fn negotiated_legacy_algorithms_are_named() {
        assert!(weak_algorithms("curve25519-sha256", "ssh-ed25519", ["hmac-sha2-256", "hmac-sha2-256"]).is_empty());
        assert!(weak_algorithms("curve25519-sha256", "rsa-sha2-512", ["none", "none"]).is_empty());
        assert_eq!(
            weak_algorithms("diffie-hellman-group14-sha1", "ssh-rsa", ["hmac-sha1", "hmac-sha1"]),
            ["diffie-hellman-group14-sha1", "ssh-rsa", "hmac-sha1"]
        );
    }

    #[test]
    fn a_server_offering_only_legacy_algorithms_is_recognised() {
        let no_common = |theirs: &[&str]| russh::Error::NoCommonAlgo {
            kind: russh::AlgorithmKind::Kex,
            ours: vec!["curve25519-sha256".into()],
            theirs: theirs.iter().map(|s| s.to_string()).collect(),
        };
        assert_eq!(
            legacy_only_offer(&no_common(&["diffie-hellman-group1-sha1", "kex-strict-s-v00@openssh.com"])),
            Some(vec!["diffie-hellman-group1-sha1".to_string()])
        );
        assert_eq!(legacy_only_offer(&no_common(&["sntrup761x25519-sha512"])), None);
        assert_eq!(legacy_only_offer(&russh::Error::UnknownKey), None);
    }

    /// F-029: a host trusted with its ECDSA key is asked for that key, not
    /// for the ed25519 key it also has.
    #[tokio::test]
    async fn the_trusted_key_type_is_negotiated() {
        for (known, expected) in [(vec![], "ssh-ed25519"), (vec!["ecdsa-sha2-nistp256".to_string()], "ecdsa-sha2-nistp256")] {
            let served = serve(Script::default(), vec![ed25519_key(1), ecdsa_key()]);
            let (handler, offered) = TestClient::new();
            let policy = AlgorithmPolicy { known_key_types: known, ..AlgorithmPolicy::default() };
            let _handle = client::connect_stream(Arc::new(build_ssh_client_config(&policy)), served.stream, handler)
                .await
                .expect("handshake");
            assert_eq!(offered.lock().unwrap().as_slice(), [expected]);
        }
    }

    /// F-026: a user who takes three times the budget to approve the host key
    /// still gets connected; the budget only counts network time.
    #[tokio::test]
    async fn a_slow_answer_to_the_host_key_prompt_does_not_expire_the_handshake() {
        let budget = Duration::from_millis(300);
        let served = serve(Script::default(), vec![ed25519_key(1)]);
        let (mut handler, _) = TestClient::new();
        let (prompt_tx, prompt_rx) = watch::channel(false);
        handler.answer_after = Some((budget * 3, Arc::new(prompt_tx)));
        let res = handshake_within(
            client::connect_stream(plain_config(), served.stream, handler),
            budget,
            Duration::from_millis(500),
            prompt_rx,
        )
        .await;
        let mut handle = res.expect("not cut off while the prompt was open").expect("handshake");
        assert!(handle.authenticate_password(USER, PASSWORD).await.unwrap().success());
    }

    /// A server that never gets going still runs into the budget.
    #[tokio::test]
    async fn a_silent_server_still_times_out() {
        let (handler, _) = TestClient::new();
        let (_prompt_tx, prompt_rx) = watch::channel(false);
        let started = std::time::Instant::now();
        let res = handshake_within(
            client::connect_stream(plain_config(), serve_silence(), handler),
            Duration::from_millis(300),
            Duration::from_millis(300),
            prompt_rx,
        )
        .await;
        assert_eq!(res.err(), Some(HandshakeTimedOut));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    /// The clock stops while the prompt is open and resumes with what was
    /// left, but never with less than the grace.
    #[tokio::test]
    async fn the_clock_resumes_after_the_prompt_with_at_least_the_grace() {
        for (grace_ms, finishes) in [(400, true), (50, false)] {
            let (prompt_tx, prompt_rx) = watch::channel(false);
            let prompt_tx = Arc::new(prompt_tx);
            let flag = Arc::clone(&prompt_tx);
            // Opens the prompt at once for 600 ms, then needs 200 ms more.
            let work = async move {
                {
                    let _open = PromptOpen::new(&flag);
                    tokio::time::sleep(Duration::from_millis(600)).await;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            };
            let res = handshake_within(work, Duration::from_millis(100), Duration::from_millis(grace_ms), prompt_rx).await;
            assert_eq!(res.is_ok(), finishes, "grace {grace_ms} ms");
        }
    }

    // --- authentication (F-028, C4, N-013) ---

    /// Answers every keyboard-interactive round the same way (or never).
    struct Prompter {
        answer: Option<Vec<String>>,
        never: bool,
        asked: std::sync::atomic::AtomicUsize,
    }

    impl Prompter {
        fn answering(answer: Option<&str>) -> Self {
            Prompter { answer: answer.map(|a| vec![a.to_string()]), never: false, asked: Default::default() }
        }
        fn asked(&self) -> usize {
            self.asked.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl KbiPrompter for Prompter {
        fn ask(&self, _round: KbiRound) -> impl Future<Output = Option<Vec<String>>> + Send {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (answer, never) = (self.answer.clone(), self.never);
            async move {
                if never {
                    std::future::pending::<()>().await;
                }
                answer
            }
        }
    }

    async fn handshaken(script: Script) -> (client::Handle<TestClient>, Arc<std::sync::Mutex<Seen>>) {
        let served = serve(script, vec![ed25519_key(1)]);
        let (handler, _) = TestClient::new();
        let handle = client::connect_stream(plain_config(), served.stream, handler).await.expect("handshake");
        (handle, served.seen)
    }

    fn creds(key: Option<PrivateKey>, password: Option<&str>) -> Credentials {
        Credentials {
            key_login: key.is_some(),
            key: key.map(Arc::new),
            key_problem: None,
            password: password.map(str::to_string),
            password_can_be_typed: true,
            allow_sha1_rsa: false,
        }
    }

    fn quick() -> AuthLimits {
        AuthLimits { reply: Duration::from_secs(2), answer: Duration::from_secs(2), ..AuthLimits::default() }
    }

    const NO_LOG: &(dyn Fn(&str, &str) + Sync) = &|_: &str, _: &str| {};

    async fn login(script: Script, creds: Credentials, prompter: Option<&Prompter>) -> (Result<(), AuthFailure>, Arc<std::sync::Mutex<Seen>>) {
        let (mut handle, seen) = handshaken(script).await;
        let res = tokio::time::timeout(
            Duration::from_secs(20),
            authenticate(&mut handle, USER, creds, prompter, quick(), NO_LOG),
        )
        .await
        .expect("the login itself must end");
        (res, seen)
    }

    /// The reason of a login that ended without success through no fault of
    /// the link: refused, or not answerable by this side.
    fn refused(res: Result<(), AuthFailure>) -> String {
        match res {
            Err(AuthFailure::Refused(reason) | AuthFailure::Unanswerable(reason)) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_password_login_succeeds_and_a_wrong_password_is_refused() {
        let (res, _) = login(Script::default(), creds(None, Some(PASSWORD)), None).await;
        assert!(res.is_ok());
        let (res, seen) = login(Script::default(), creds(None, Some("wrong")), None).await;
        assert!(refused(res).contains("Authentication rejected"));
        assert_eq!(seen.lock().unwrap().passwords, ["wrong"]);
    }

    /// F-028: a server that answers every round with another empty round is
    /// given up on after three in a row, instead of looping forever.
    #[tokio::test]
    async fn empty_keyboard_interactive_rounds_end_the_login() {
        let script = Script { steps: vec![MethodKind::KeyboardInteractive], kbi: Kbi::EmptyRoundsForever, ..Script::default() };
        let prompter = Prompter::answering(Some("x"));
        let (res, seen) = login(script, creds(None, None), Some(&prompter)).await;
        assert!(refused(res).contains("without a question"));
        assert_eq!(seen.lock().unwrap().kbi_rounds, KBI_MAX_EMPTY_ROUNDS + 1);
        assert_eq!(prompter.asked(), 0, "nothing to ask the user");
    }

    /// F-028: questions without end stop after the round cap.
    #[tokio::test]
    async fn endless_keyboard_interactive_questions_stop_at_the_cap() {
        let script = Script { steps: vec![MethodKind::KeyboardInteractive], kbi: Kbi::PromptsForever, ..Script::default() };
        let prompter = Prompter::answering(Some("123456"));
        let (res, _) = login(script, creds(None, None), Some(&prompter)).await;
        assert!(refused(res).contains("more than 8 rounds"));
        assert_eq!(prompter.asked(), KBI_MAX_ROUNDS);
    }

    /// F-028: a server that never answers the login request is given up on.
    #[tokio::test]
    async fn a_server_that_never_answers_the_login_is_given_up_on() {
        let (mut handle, _) = handshaken(Script { stall_auth: true, ..Script::default() }).await;
        let limits = AuthLimits { reply: Duration::from_millis(300), ..quick() };
        let started = std::time::Instant::now();
        let res = authenticate(&mut handle, USER, creds(None, Some(PASSWORD)), None::<&Prompter>, limits, NO_LOG).await;
        assert!(matches!(res, Err(AuthFailure::TimedOut(_))), "{res:?}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    /// N-013: a connection that drops during login is not a wrong password.
    #[tokio::test]
    async fn a_connection_lost_during_login_is_not_a_refusal() {
        let (res, _) = login(Script { drop_on_auth: true, ..Script::default() }, creds(None, Some(PASSWORD)), None).await;
        assert!(matches!(res, Err(AuthFailure::Ssh(_))), "{res:?}");
    }

    // russh's own server reports `partial_success` only after a
    // keyboard-interactive step (it clears the flag after publickey and
    // password), so the key-first multi-step logins are covered against
    // OpenSSH in the live tests (:2205, :2206); here partial success comes
    // from keyboard-interactive.

    /// C4: the key is accepted as one step and the typed password completes
    /// the login (the server lists only `password` after the key).
    #[tokio::test]
    async fn a_key_and_then_a_password_log_in() {
        let user_key = ed25519_key(9);
        let script = Script {
            steps: vec![MethodKind::PublicKey, MethodKind::Password],
            user_key: Some(user_key.public_key().clone()),
            ..Script::default()
        };
        let (res, seen) = login(script, creds(Some(user_key), Some(PASSWORD)), None).await;
        assert!(res.is_ok(), "{res:?}");
        assert_eq!(seen.lock().unwrap().passwords, [PASSWORD]);
    }

    /// C4: `AuthenticationMethods publickey,keyboard-interactive`.
    #[tokio::test]
    async fn a_key_and_then_keyboard_interactive_log_in() {
        let user_key = ed25519_key(9);
        let script = Script {
            steps: vec![MethodKind::PublicKey, MethodKind::KeyboardInteractive],
            user_key: Some(user_key.public_key().clone()),
            ..Script::default()
        };
        let prompter = Prompter::answering(Some(PASSWORD));
        let (res, _) = login(script, creds(Some(user_key), None), Some(&prompter)).await;
        assert!(res.is_ok(), "{res:?}");
        assert_eq!(prompter.asked(), 1);
    }

    /// C4: after a partial success a method refused earlier gets its turn
    /// again (`keyboard-interactive,publickey`: the key goes first and is
    /// refused, keyboard-interactive passes the first step, then the key).
    #[tokio::test]
    async fn a_passed_step_gives_an_earlier_refused_method_another_turn() {
        let user_key = ed25519_key(9);
        let script = Script {
            steps: vec![MethodKind::KeyboardInteractive, MethodKind::PublicKey],
            user_key: Some(user_key.public_key().clone()),
            ..Script::default()
        };
        let prompter = Prompter::answering(Some(PASSWORD));
        let (res, _) = login(script, creds(Some(user_key), None), Some(&prompter)).await;
        assert!(res.is_ok(), "{res:?}");
    }

    /// C4: a passed step followed by a password this side does not have is
    /// reported as exactly that, so the user knows to type it.
    #[tokio::test]
    async fn a_missing_second_step_password_is_named() {
        let script = Script { steps: vec![MethodKind::KeyboardInteractive, MethodKind::Password], ..Script::default() };
        let prompter = Prompter::answering(Some(PASSWORD));
        let (res, _) = login(script, creds(None, None), Some(&prompter)).await;
        assert!(matches!(&res, Err(AuthFailure::Unanswerable(_))), "a step this side cannot answer: {res:?}");
        assert!(refused(res).contains("also asks for a password"));
    }

    /// F-017: a configured key this side cannot use, and nothing refused by
    /// the server, is unanswerable (a monitor stops at once); a wrong
    /// password is a refusal.
    #[tokio::test]
    async fn an_unusable_key_is_unanswerable_and_a_wrong_password_refused() {
        let unusable = Credentials { key_login: true, key_problem: Some("The private key could not be read.".into()), ..creds(None, None) };
        let (res, seen) = login(Script::default(), unusable, None).await;
        assert!(matches!(&res, Err(AuthFailure::Unanswerable(r)) if r.contains("could not be read")), "{res:?}");
        assert!(seen.lock().unwrap().passwords.is_empty());
        let (res, _) = login(Script::default(), creds(None, Some("wrong")), None).await;
        assert!(matches!(&res, Err(AuthFailure::Refused(_))), "{res:?}");
    }

    /// Where no password can be typed (a jump host), the message does not ask
    /// for one.
    #[tokio::test]
    async fn a_missing_password_that_cannot_be_typed_is_not_asked_for() {
        let script = Script { steps: vec![MethodKind::KeyboardInteractive, MethodKind::Password], ..Script::default() };
        let prompter = Prompter::answering(Some(PASSWORD));
        let creds = Credentials { password_can_be_typed: false, ..creds(None, None) };
        let (res, _) = login(script, creds, Some(&prompter)).await;
        let reason = refused(res);
        assert!(reason.contains("cannot provide") && !reason.contains("Type it"), "{reason}");
    }

    /// F-028 (review): the server's time over all round trips is capped too.
    #[tokio::test]
    async fn the_server_s_total_login_time_is_capped() {
        let (mut handle, _) = handshaken(Script { stall_auth: true, ..Script::default() }).await;
        let limits = AuthLimits { reply: Duration::from_secs(5), server_total: Duration::from_millis(300), ..quick() };
        let started = std::time::Instant::now();
        let res = authenticate(&mut handle, USER, creds(None, Some(PASSWORD)), None::<&Prompter>, limits, NO_LOG).await;
        match res {
            Err(AuthFailure::TimedOut(reason)) => assert!(reason.contains("took too long"), "{reason}"),
            other => panic!("{other:?}"),
        }
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// A key login never sends a password the user did not type for it.
    #[tokio::test]
    async fn a_refused_key_does_not_fall_back_to_a_stored_password() {
        let script = Script { steps: vec![MethodKind::Password], ..Script::default() };
        // The caller passes no password in a key login unless one was typed.
        let (res, seen) = login(script, creds(Some(ed25519_key(9)), None), None).await;
        refused(res);
        assert!(seen.lock().unwrap().passwords.is_empty());
    }

    #[tokio::test]
    async fn a_cancelled_or_unanswered_question_ends_the_login() {
        let script = Script { steps: vec![MethodKind::KeyboardInteractive], ..Script::default() };
        let cancel = Prompter::answering(None);
        let (res, _) = login(script.clone(), creds(None, None), Some(&cancel)).await;
        assert!(refused(res).contains("cancelled"));

        let silent = Prompter { never: true, ..Prompter::answering(None) };
        let (mut handle, _) = handshaken(script).await;
        let limits = AuthLimits { answer: Duration::from_millis(300), ..quick() };
        let res = authenticate(&mut handle, USER, creds(None, None), Some(&silent), limits, NO_LOG).await;
        assert!(refused(res).contains("not answered"));
    }

    /// F-028: an open the server never confirms ends within the bound and
    /// leaves the connection usable by everyone else.
    #[tokio::test]
    async fn an_unconfirmed_channel_open_is_bounded_and_releases_the_connection() {
        let (mut handle, _) = handshaken(Script { sessions: Sessions::Stall, ..Script::default() }).await;
        assert!(handle.authenticate_password(USER, PASSWORD).await.unwrap().success());
        let handle = Mutex::new(handle);
        let started = std::time::Instant::now();
        let res = open_session_channel_within(&handle, Duration::from_millis(300)).await;
        assert!(res.is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(handle.try_lock().is_ok(), "the connection is free again");

        let (mut handle, _) = handshaken(Script::default()).await;
        assert!(handle.authenticate_password(USER, PASSWORD).await.unwrap().success());
        assert!(open_session_channel(&Mutex::new(handle)).await.is_ok());
    }

    // --- liveness probe (F-027) ---

    /// A server that refuses every session channel (its MaxSessions is used
    /// up) is alive, and probing it opens nothing.
    #[tokio::test]
    async fn a_server_refusing_channels_is_alive() {
        let (mut handle, seen) = handshaken(Script { sessions: Sessions::Refuse, ..Script::default() }).await;
        assert!(handle.authenticate_password(USER, PASSWORD).await.unwrap().success());
        let handle = Mutex::new(handle);
        for _ in 0..3 {
            assert!(probe_alive(&handle, Duration::from_secs(2)).await);
        }
        assert_eq!(seen.lock().unwrap().session_opens, 0);
    }

    #[test]
    fn network_devices_are_recognised_by_their_identification_string() {
        for ident in ["SSH-2.0-Cisco-1.25", "SSH-1.99-Cisco-1.25", "SSH-2.0-Cisco-2.0\r\n", "SSH-2.0-Cisco"] {
            assert!(is_one_channel_server(ident.as_bytes()), "{ident}");
        }
        for ident in ["SSH-2.0-OpenSSH_9.6p1 Ubuntu", "SSH-2.0-dropbear_2022.83", "SSH-2.0-CiscoLike-1", "SSH-2.0-NotCisco", "Cisco", "", "SSH-2.0-"] {
            assert!(!is_one_channel_server(ident.as_bytes()), "{ident}");
        }
        assert!(!is_one_channel_server(&[0xFF, 0xFE, b'-', 0x00]));
    }

    /// The first reason stays: a server set to terminal only keeps saying so,
    /// and is not offered a setting it already has.
    #[test]
    fn the_gate_keeps_the_first_reason() {
        let set = ChannelGate::new(true);
        assert_eq!(set.limit(), Some(TerminalOnly::Setting));
        assert!(!set.note_server_ident(b"SSH-2.0-Cisco-1.25"));
        assert_eq!(set.limit(), Some(TerminalOnly::Setting));

        let open = ChannelGate::default();
        assert_eq!(open.limit(), None);
        assert!(!open.note_server_ident(b"SSH-2.0-OpenSSH_9.6"));
        assert_eq!(open.limit(), None);
        assert!(open.note_server_ident(b"SSH-2.0-Cisco-1.25"));
        assert!(!open.note_server_ident(b"SSH-2.0-Cisco-1.25"), "said once");
        assert_eq!(open.limit(), Some(TerminalOnly::ServerIdent));
    }

    /// A normal host at `MaxSessions` is not a one-channel host: it has shown
    /// it can do better, so its features keep working. Neither is a server
    /// that refuses the very first channel.
    #[tokio::test]
    async fn only_a_refusal_after_exactly_one_channel_marks_the_connection() {
        let refused_first = ChannelGate::default();
        let (handle, _) = logged_in(Script { sessions: Sessions::Refuse, ..Script::default() }).await;
        assert!(open_terminal_channel(&handle, &refused_first).await.is_err());
        assert_eq!(refused_first.limit(), None, "nothing was open for a limit to count");

        // Accepted twice, then at its limit.
        let at_max_sessions = ChannelGate::default();
        at_max_sessions.accepted.store(2, Ordering::SeqCst);
        assert!(open_feature_channel(&handle, &at_max_sessions).await.is_err());
        assert_eq!(at_max_sessions.limit(), None, "its features stay on");
        assert!(open_feature_channel(&handle, &at_max_sessions).await.is_err(), "and are asked for again");

        let (handle, seen) = logged_in(Script { sessions: Sessions::FirstOnly, ..Script::default() }).await;
        let one_channel = ChannelGate::default();
        let _terminal = open_terminal_channel(&handle, &one_channel).await.unwrap();
        let refused = open_feature_channel(&handle, &one_channel).await.err().unwrap();
        assert_eq!(one_channel.limit(), Some(TerminalOnly::RefusedChannel));
        assert_eq!(refused, TerminalOnly::RefusedChannel.refusal());
        assert_eq!(seen.lock().unwrap().session_opens, 2);
        // Features do not ask any more; a terminal tab the user opens does.
        assert_eq!(open_feature_channel(&handle, &one_channel).await.err().unwrap(), TerminalOnly::RefusedChannel.refusal());
        assert_eq!(seen.lock().unwrap().session_opens, 2);
        assert!(open_terminal_channel(&handle, &one_channel).await.is_err());
        assert_eq!(seen.lock().unwrap().session_opens, 3);
    }

    /// A connection known to be terminal only never asks for a feature's
    /// channel, and still gets its terminal.
    #[tokio::test]
    async fn a_terminal_only_connection_asks_only_for_its_terminal() {
        let (handle, seen) = logged_in(Script::default()).await;
        for gate in [ChannelGate::new(true), { let g = ChannelGate::default(); g.note_server_ident(b"SSH-2.0-Cisco-1.25"); g }] {
            let before = seen.lock().unwrap().session_opens;
            assert!(open_feature_channel(&handle, &gate).await.is_err());
            assert_eq!(seen.lock().unwrap().session_opens, before);
            assert!(open_terminal_channel(&handle, &gate).await.is_ok());
            assert_eq!(seen.lock().unwrap().session_opens, before + 1);
        }
    }

    #[test]
    fn a_disconnect_is_described_in_words() {
        use client::DisconnectReason::{Error, ReceivedDisconnect};
        let received = |message: &str| {
            ConnectionEnd::from_reason(&ReceivedDisconnect(client::RemoteDisconnectInfo {
                reason_code: russh::Disconnect::ByApplication,
                message: message.to_string(),
                lang_tag: String::new(),
            }))
        };
        assert_eq!(received("").describe(true), "the server ended the connection (ByApplication)");
        assert_eq!(
            received("bye\u{202E}now\n").describe(true),
            "the server ended the connection (ByApplication: bye\\u202enow\\u000a)"
        );
        let early_eof = ConnectionEnd::from_reason(&Error(russh::Error::IO(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "early eof"))));
        assert_eq!(early_eof, ConnectionEnd::Closed);
        assert_eq!(early_eof.describe(true), "the server closed the connection");
        assert_eq!(ConnectionEnd::from_reason(&Error(russh::Error::Disconnect)), ConnectionEnd::Closed);
        assert!(ConnectionEnd::from_reason(&Error(russh::Error::KeepaliveTimeout)).describe(true).contains("keepalives"));
        let reset = ConnectionEnd::from_reason(&Error(russh::Error::IO(std::io::Error::from(std::io::ErrorKind::ConnectionReset))));
        assert!(matches!(reset, ConnectionEnd::Failed(_)), "{reset:?}");
    }

    /// N-028: the server ending a session is not auto-reconnected; a network
    /// failure still is.
    #[test]
    fn only_the_server_ending_a_session_stops_auto_reconnect() {
        let goodbye = ConnectionEnd::Goodbye { code: "ByApplication".into(), message: "Reload requested".into() };
        let failed = ConnectionEnd::Failed("the connection failed: Connection reset by peer".into());
        for direct in [true, false] {
            assert!(goodbye.by_server(direct), "a goodbye comes from the server, whatever is in between");
            assert!(!failed.by_server(direct));
        }
        assert!(ConnectionEnd::Closed.by_server(true), "a switch closing the link after exit");
        assert!(!ConnectionEnd::Closed.by_server(false), "through a hop the close may be the hop's");

        let (reason, ended) = connection_end_report(true, Some(&ConnectionEnd::Closed), true);
        assert_eq!((reason.as_str(), ended), ("the server closed the connection", true));
        let (reason, ended) = connection_end_report(true, Some(&failed), true);
        assert!(reason.starts_with("Connection lost: ") && !ended, "{reason}");
        let (reason, ended) = connection_end_report(false, Some(&ConnectionEnd::Closed), true);
        assert!(reason.contains("liveness probes") && !ended, "silence is the network's, whatever came before");
        assert!(!connection_end_report(true, None, true).1);
    }


    /// A server that stopped answering is a strike within the bound.
    #[tokio::test]
    async fn a_server_that_stopped_answering_is_not_alive() {
        let (mut handle, _) = handshaken(Script { stall_cancel_forward: true, ..Script::default() }).await;
        assert!(handle.authenticate_password(USER, PASSWORD).await.unwrap().success());
        handle.tcpip_forward("127.0.0.1", 4000).await.unwrap();
        let handle = Arc::new(Mutex::new(handle));
        // The server's session now hangs in a request it never answers.
        let wedge = Arc::clone(&handle);
        tokio::spawn(async move {
            let h = wedge.lock().await;
            let _ = tokio::time::timeout(Duration::from_millis(100), h.cancel_tcpip_forward("127.0.0.1", 4000)).await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let started = std::time::Instant::now();
        assert!(!probe_alive(&handle, Duration::from_millis(300)).await);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    // --- closing (F-013) ---

    /// Locking the profile ends each connection itself, without waiting
    /// longer than the bound for one whose mutex another task holds.
    #[tokio::test]
    async fn closing_ends_connections_within_the_bound() {
        let (mut first, _) = handshaken(Script::default()).await;
        assert!(first.authenticate_password(USER, PASSWORD).await.unwrap().success());
        let (mut second, _) = handshaken(Script::default()).await;
        assert!(second.authenticate_password(USER, PASSWORD).await.unwrap().success());
        let first = Arc::new(Mutex::new(first));
        let second = Arc::new(Mutex::new(second));
        let held = Arc::clone(&second);
        let (locked, is_locked) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _guard = held.lock().await;
            let _ = locked.send(());
            std::future::pending::<()>().await;
        });
        is_locked.await.unwrap();

        let started = std::time::Instant::now();
        close_handles(vec![Arc::clone(&first), second], Duration::from_millis(300)).await;
        assert!(started.elapsed() < Duration::from_secs(2), "a held mutex costs the bound, no more");
        tokio::time::timeout(Duration::from_secs(2), async {
            while !first.lock().await.is_closed() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the connection is closed");
    }

    // --- TCP connect (F-077) ---

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn address_families_take_turns() {
        let v6a = addr("[2001:db8::1]:22");
        let v6b = addr("[2001:db8::2]:22");
        let v4a = addr("192.0.2.1:22");
        let v4b = addr("192.0.2.2:22");
        assert_eq!(interleave_families(vec![v6a, v6b, v4a, v4b]), [v6a, v4a, v6b, v4b]);
        assert_eq!(interleave_families(vec![v4a, v6a, v4b]), [v4a, v6a, v4b]);
        assert_eq!(interleave_families(vec![v4a]), [v4a]);
        assert!(interleave_families(Vec::new()).is_empty());
    }

    /// An address that never answers costs only its share; the next one is
    /// reached. Nothing here touches the network: the connector is fake.
    #[tokio::test]
    async fn a_black_holed_address_does_not_use_up_the_budget() {
        let dead = addr("[2001:db8::1]:22");
        let alive = addr("192.0.2.1:22");
        let started = std::time::Instant::now();
        let got = try_addresses(&[dead, alive], Duration::from_secs(5), Duration::from_millis(200), |a| async move {
            if a == dead {
                std::future::pending::<std::io::Result<SocketAddr>>().await
            } else {
                Ok(a)
            }
        })
        .await
        .expect("the second address answers");
        assert_eq!(got, alive);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn the_overall_budget_holds_and_the_last_answer_is_reported() {
        let addrs = [addr("192.0.2.1:22"), addr("192.0.2.2:22"), addr("192.0.2.3:22")];
        let started = std::time::Instant::now();
        let res = try_addresses(&addrs, Duration::from_millis(500), Duration::from_millis(300), |_| {
            std::future::pending::<std::io::Result<()>>()
        })
        .await;
        assert!(matches!(res, Err(TcpConnectError::TimedOut { tried: 2, .. })), "{res:?}");
        assert!(started.elapsed() < Duration::from_secs(2));

        let res = try_addresses(&addrs, Duration::from_secs(1), Duration::from_millis(300), |_| async {
            Err::<(), _>(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
        })
        .await;
        assert!(matches!(res, Err(TcpConnectError::Failed(ref e)) if e.kind() == std::io::ErrorKind::ConnectionRefused));
    }

    /// Through the real resolver and sockets, on loopback only.
    #[tokio::test]
    async fn connecting_over_loopback_works_and_a_closed_port_is_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(connect_tcp("127.0.0.1", port).await.is_ok());
        drop(listener);
        assert!(matches!(connect_tcp("127.0.0.1", port).await, Err(TcpConnectError::Failed(_))));
    }

    #[test]
    fn the_prompt_flag_is_cleared_when_the_wait_is_dropped() {
        let (tx, rx) = watch::channel(false);
        {
            let _open = PromptOpen::new(&tx);
            assert!(*rx.borrow());
        }
        assert!(!*rx.borrow());
    }
}
