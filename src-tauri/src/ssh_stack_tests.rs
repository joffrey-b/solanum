//! Protocol-level checks of the SSH stack (russh) the app is built on.
//!
//! The plain tests run everywhere. The `live_*` tests talk to real sshd
//! servers and are `#[ignore]`d: they need the Docker fixtures (a modern sshd
//! on :2201, plus legacy-only ones on :2202 = DH-group14-SHA1 / ssh-rsa /
//! HMAC-SHA1 / AES-CTR, :2203 = DH-group1-SHA1, :2205/:2206 = a key and then a
//! password / keyboard-interactive, :2207 = modern key exchange with only
//! `ssh-rsa` host-key signatures, :2208 = `GatewayPorts clientspecified`) and
//! `SOLANUM_SSH_FIXTURES`
//! pointing at the fixture folder (`keys/` with the test private keys and
//! `out/hostkeys.txt` with the servers' `ssh-keygen -lf` output). Run with:
//! `cargo test --lib ssh_stack_tests -- --ignored --test-threads=1`.

use crate::ssh_connect::{build_ssh_client_config, AlgorithmPolicy};
use crate::ssh_manager::{authenticate_with_key, host_key_fingerprint, host_key_label, normalize_host_key_label, KeyAttempt};
use russh::client;
use russh::client::KeyboardInteractiveAuthResponse;
use russh::keys::{decode_secret_key, PublicKey, PublicKeyOrCertificate};
use russh::ChannelMsg;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// (OpenSSH public key, `ssh-keygen -lf` fingerprint without the `SHA256:` prefix, label)
const KEY_VECTORS: &[(&str, &str, &str)] = &[
    (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICbHHWTaAn0i6rhfYlgSn0q3k5Jg4bQp4ChYr/byvGDg t-ed",
        "lCM2kZ11BAExAbpaKRn7o1XgaUGvW3NS5zbV4di3lCM",
        "ssh-ed25519",
    ),
    (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCk5Cdj1mkp+3FmoRsnaSK9XdgxQqKJuf2o4tZVHeTY2HIbwNTayhvikwE4VEjHdY3LAre2eJcKcdXTePdkb0DeOI+zOTlW1/+VNs8U0FkSQGL0sZHV/qtKOZFy8NDCBRsWYF6ms4FZcZWGKGOrhom7KAgGE7CWn+KUrIUPwXHDPF3Y73XHx1Y8ncpul+JoPXhoHntDXbD0zww5k0s0QCmjZFOqREOsgXhL9ja4PxnUzK5Ih8RTqvwyYNjlhuG63AGL96xPow0Q/hqCkrgmR0xJ2OPPIlcNUGIFImzXnGwCZUgD4O6aLgf/zqcbIjHjdwSps3xYIS1wAh19EbHUPhsIByPpwlcyzuK0YpSEdIuMgTrozRP33zEBhQLlSadI9/B6Mg3zw8D5yo8aqKfw8jIekRHJf5C2j5Reupdy17KakLzz7ECnPN+cWGu9xJETgC3hvGvwOdbFBtvweQ+Kp9zWrUTX1iFMS8PUGLkMSMKPDTvgyJozYN7oivoShM27K7U= t-rsa",
        "h6/ven9Tdihex8Qn+X1TYJC0dXNadrWpAeYk5rV5zfQ",
        "ssh-rsa",
    ),
    (
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBED+5M9YSm2JSoJ4TrbfY71dMUObcd4sMpYv3L+5Z1oaROzg2eZGgpCcJKvi4QdDwyj+nJRLeVH0i+chINlAHoE= t-ec",
        "xgDDHMbzIDRh377uUH1/vRTnpYJgmlq+PkNlSR2pyR0",
        "ecdsa-sha2-nistp256",
    ),
];

/// The string stored in `known_hosts` by every vault written before the russh
/// upgrade is exactly `ssh-keygen -lf` minus its `SHA256:` prefix. If this
/// test breaks, every saved host would look like a changed key.
#[test]
fn stored_host_key_fingerprints_keep_the_ssh_keygen_format() {
    for (line, fingerprint, label) in KEY_VECTORS {
        let key = PublicKey::from_openssh(line).expect("test vector parses");
        assert_eq!(host_key_fingerprint(&key), *fingerprint, "fingerprint of {label}");
        assert_eq!(host_key_label(&key), *label);
    }
}

#[test]
fn one_rsa_key_offered_under_any_signature_name_is_one_key_type() {
    for name in ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"] {
        assert_eq!(normalize_host_key_label(name), "ssh-rsa");
    }
    assert_eq!(normalize_host_key_label("ssh-ed25519"), "ssh-ed25519");
    assert_eq!(normalize_host_key_label("ecdsa-sha2-nistp256"), "ecdsa-sha2-nistp256");
}

/// With a server's legacy setting on, the SHA-1 algorithms are offered, but
/// only after every strong one.
#[test]
fn strong_algorithms_are_negotiated_first_and_legacy_ones_only_last() {
    let preferred = build_ssh_client_config(&AlgorithmPolicy { legacy: true, ..AlgorithmPolicy::default() }).preferred;
    let kex: Vec<&str> = preferred.kex.iter().map(|n| n.as_ref()).collect();
    let mac: Vec<&str> = preferred.mac.iter().map(|n| n.as_ref()).collect();
    let pos = |list: &[&str], name: &str| list.iter().position(|n| *n == name);

    assert_eq!(pos(&kex, "curve25519-sha256").is_some(), true);
    for legacy in ["diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"] {
        let legacy_at = pos(&kex, legacy).expect("legacy kex kept for old servers");
        assert!(legacy_at > pos(&kex, "curve25519-sha256").unwrap());
        assert!(legacy_at > pos(&kex, "diffie-hellman-group14-sha256").unwrap());
    }
    for legacy in ["hmac-sha1", "hmac-sha1-etm@openssh.com"] {
        let legacy_at = pos(&mac, legacy).expect("legacy mac kept for old servers");
        assert!(legacy_at > pos(&mac, "hmac-sha2-256").unwrap());
        assert!(legacy_at > pos(&mac, "hmac-sha2-512-etm@openssh.com").unwrap());
    }
    let key: Vec<String> = preferred.key.iter().map(|a| a.to_string()).collect();
    assert_eq!(key.last().map(String::as_str), Some("ssh-rsa"), "SHA-1 host keys last");
    // The ext-info and strict-kex markers must stay: RSA hash selection and
    // the Terrapin countermeasure both depend on them.
    assert!(pos(&kex, "ext-info-c").is_some());
    assert!(pos(&kex, "kex-strict-c-v00@openssh.com").is_some());
}

/// F-076: without the server's legacy setting nothing SHA-1 is offered, and
/// compression is never negotiated before login.
#[test]
fn without_the_legacy_setting_no_sha1_algorithm_is_offered() {
    let preferred = build_ssh_client_config(&AlgorithmPolicy::default()).preferred;
    let kex: Vec<&str> = preferred.kex.iter().map(|n| n.as_ref()).collect();
    let mac: Vec<&str> = preferred.mac.iter().map(|n| n.as_ref()).collect();
    let key: Vec<String> = preferred.key.iter().map(|a| a.to_string()).collect();
    let compression: Vec<&str> = preferred.compression.iter().map(|n| n.as_ref()).collect();
    assert!(!kex.iter().any(|n| n.ends_with("-sha1")), "{kex:?}");
    assert!(!mac.iter().any(|n| n.starts_with("hmac-sha1")), "{mac:?}");
    assert!(!key.iter().any(|n| n == "ssh-rsa"), "{key:?}");
    assert!(key.iter().any(|n| n == "rsa-sha2-512") && key.iter().any(|n| n == "rsa-sha2-256"));
    assert_eq!(compression, ["zlib@openssh.com", "none"]);
    assert!(kex.contains(&"curve25519-sha256") && kex.contains(&"kex-strict-c-v00@openssh.com"));
    for legacy in [true, false] {
        let c = build_ssh_client_config(&AlgorithmPolicy { legacy, ..AlgorithmPolicy::default() }).preferred;
        assert!(!c.compression.iter().any(|n| n.as_ref() == "zlib"), "pre-auth zlib never offered");
    }
}

// ---------------------------------------------------------------------------
// A server that offers ECDH and SHA-1 key exchange (Cisco IOS)
// ---------------------------------------------------------------------------

/// The key exchange a connection to a server offering `offered` settles on,
/// or why it failed.
async fn negotiated_kex(offered: Vec<russh::kex::Name>, legacy: bool) -> Result<String, String> {
    use crate::ssh_test_server::{ed25519_key, serve, Script, TestClient};
    let served = serve(Script { kex: Some(offered), ..Script::default() }, vec![ed25519_key(1)]);
    let (handler, _offered) = TestClient::new();
    let negotiated = Arc::clone(&handler.negotiated_kex);
    let config = build_ssh_client_config(&AlgorithmPolicy { legacy, ..AlgorithmPolicy::default() });
    client::connect_stream(Arc::new(config), served.stream, handler).await.map_err(|e| e.to_string())?;
    let kex = negotiated.lock().unwrap().clone();
    kex.ok_or_else(|| "no key exchange finished".to_string())
}

/// What the switch in the bug report offers. Which of them wins is the
/// client's order, whatever the legacy setting says: never SHA-1 with ECDH on
/// offer.
#[tokio::test]
async fn ecdh_wins_over_sha1_key_exchange_with_and_without_the_legacy_setting() {
    use russh::kex::{DH_G14_SHA1, ECDH_SHA2_NISTP256, ECDH_SHA2_NISTP384, ECDH_SHA2_NISTP521};
    for legacy in [true, false] {
        let kex = negotiated_kex(vec![ECDH_SHA2_NISTP256, ECDH_SHA2_NISTP384, ECDH_SHA2_NISTP521, DH_G14_SHA1], legacy).await;
        assert_eq!(kex.as_deref(), Ok("ecdh-sha2-nistp256"), "legacy setting {legacy}");
    }
    // Each curve works, not only the first.
    assert_eq!(negotiated_kex(vec![ECDH_SHA2_NISTP384], false).await.as_deref(), Ok("ecdh-sha2-nistp384"));
    assert_eq!(negotiated_kex(vec![ECDH_SHA2_NISTP521], false).await.as_deref(), Ok("ecdh-sha2-nistp521"));
}

/// SHA-1 key exchange stays behind the per-server opt-in.
#[tokio::test]
async fn sha1_key_exchange_is_used_only_with_the_legacy_setting() {
    use russh::kex::DH_G14_SHA1;
    assert_eq!(negotiated_kex(vec![DH_G14_SHA1], true).await.as_deref(), Ok("diffie-hellman-group14-sha1"));
    assert!(negotiated_kex(vec![DH_G14_SHA1], false).await.is_err());
}

/// curve25519 is still preferred, ECDH comes right after it, and everything
/// else (SHA-1 last of all) after that.
#[test]
fn the_key_exchange_order_is_curve25519_then_ecdh_then_the_rest() {
    let preferred = build_ssh_client_config(&legacy()).preferred;
    let kex: Vec<&str> = preferred.kex.iter().map(|n| n.as_ref()).collect();
    let at = |name: &str| kex.iter().position(|n| *n == name).unwrap_or_else(|| panic!("{name} not offered: {kex:?}"));
    assert!(at("curve25519-sha256") < at("ecdh-sha2-nistp256"));
    assert!(at("curve25519-sha256@libssh.org") < at("ecdh-sha2-nistp256"));
    assert!(at("ecdh-sha2-nistp256") < at("ecdh-sha2-nistp384"));
    assert!(at("ecdh-sha2-nistp384") < at("ecdh-sha2-nistp521"));
    assert!(at("ecdh-sha2-nistp521") < at("diffie-hellman-group-exchange-sha256"));
    assert!(at("ecdh-sha2-nistp521") < at("diffie-hellman-group14-sha1"));
    assert!(at("diffie-hellman-group14-sha256") < at("diffie-hellman-group14-sha1"));
}

// ---------------------------------------------------------------------------
// One channel per connection
// ---------------------------------------------------------------------------

/// The bug report: a server that accepts the first channel and refuses every
/// other one, with a terminal on the first. Everything a tool panel opens is
/// refused once, is not asked for again, and the terminal and the connection
/// carry on: the health watcher's probe still answers, no close or end-of-file
/// goes to the terminal's channel, and keys still arrive.
#[tokio::test]
async fn refused_channels_leave_the_terminal_and_the_session_open() {
    use crate::ssh_connect::{open_feature_channel, open_terminal_channel, probe_alive, ChannelGate, TerminalOnly};
    use crate::ssh_manager::{PtySize, TerminalCommand};
    use crate::ssh_test_server::{eventually, logged_in, Script, Sessions};
    use crate::terminal_io::{pump, SshTerminal};

    let (handle, seen) = logged_in(Script { sessions: Sessions::FirstOnly, ..Script::default() }).await;
    let gate = ChannelGate::default();

    let terminal = open_terminal_channel(&handle, &gate).await.unwrap();
    terminal.exec(true, "shell").await.unwrap();
    let (keys, input) = tokio::sync::mpsc::channel(32);
    let (_sizes, sizes) = tokio::sync::watch::channel(PtySize { cols: 80, rows: 24 });
    let running = tokio::spawn(pump(SshTerminal::new(terminal), input, sizes, None, |_: &[u8]| {}));
    assert_eq!(gate.limit(), None, "one channel says nothing yet");

    // Every feature that opens a channel: live info, an Info action, Docker,
    // the SFTP browser.
    let refusal = TerminalOnly::RefusedChannel.refusal();
    assert_eq!(crate::info_script_on(&handle, &gate, crate::monitor::BUILTIN_PROBE, 5).await.err().unwrap(), refusal);
    assert_eq!(gate.limit(), Some(TerminalOnly::RefusedChannel), "the first refusal marks the connection");
    assert_eq!(seen.lock().unwrap().session_opens, 2, "the terminal's channel and the refused one");
    assert_eq!(crate::exec_capture_on(&handle, &gate, "true", 5, None).await.err().unwrap(), refusal);
    let docker = crate::docker::run_capture_on(&handle, &gate, "docker ps", 5, crate::docker::Keep::Head).await;
    assert_eq!(docker.err().unwrap(), refusal);
    assert_eq!(crate::open_sftp_on(&handle, &gate).await.err().unwrap(), refusal);
    for _ in 0..5 {
        assert!(open_feature_channel(&handle, &gate).await.is_err());
    }
    assert_eq!(seen.lock().unwrap().session_opens, 2, "and nothing asks the server again");

    // What the health watcher looks at: it must not see a dead connection.
    for _ in 0..3 {
        assert!(probe_alive(&handle, Duration::from_secs(2)).await, "a refused channel is no strike");
    }
    assert!(!handle.lock().await.is_closed());

    // The terminal is untouched and still works.
    keys.send(TerminalCommand::Data(b"show version\n".to_vec())).await.unwrap();
    assert!(eventually(|| seen.lock().unwrap().stdin.ends_with(b"show version\n")).await, "keys reach the terminal");
    {
        let seen = seen.lock().unwrap();
        assert_eq!((seen.closes, seen.eofs), (0, 0), "nothing closed the terminal's channel");
    }
    assert!(!running.is_finished(), "the terminal is still running");
    assert!(!handle.lock().await.is_closed());

    // Only closing its tab ends it, and then only its own channel.
    drop(keys);
    tokio::time::timeout(Duration::from_secs(5), running).await.unwrap().unwrap();
    assert!(eventually(|| seen.lock().unwrap().closes == 1).await);
    assert!(!handle.lock().await.is_closed(), "the connection outlives the terminal's channel");
}

/// The identification string reaches the code that decides, the way the app's
/// handler reads it: a server announcing itself as IOS gets a plain terminal
/// without one refused channel.
#[tokio::test]
async fn a_cisco_identification_string_makes_the_connection_terminal_only_up_front() {
    use crate::ssh_connect::{open_feature_channel, open_terminal_channel, ChannelGate, TerminalOnly};
    use crate::ssh_test_server::{ed25519_key, serve, Script, Seen, Sessions, PASSWORD, USER};

    struct Reads(Arc<ChannelGate>);
    impl client::Handler for Reads {
        type Error = russh::Error;
        async fn check_server_key(&mut self, _offered: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
            Ok(true)
        }
        async fn kex_done(
            &mut self,
            _shared_secret: Option<&[u8]>,
            _names: &russh::Names,
            session: &mut client::Session,
        ) -> Result<(), Self::Error> {
            self.0.note_server_ident(session.remote_sshid());
            Ok(())
        }
    }
    async fn connect(server_id: &'static str) -> (Arc<ChannelGate>, tokio::sync::Mutex<client::Handle<Reads>>, Arc<Mutex<Seen>>) {
        let served = serve(Script { sessions: Sessions::FirstOnly, server_id: Some(server_id), ..Script::default() }, vec![ed25519_key(1)]);
        let gate = Arc::new(ChannelGate::default());
        let config = Arc::new(build_ssh_client_config(&AlgorithmPolicy::default()));
        let mut handle = client::connect_stream(config, served.stream, Reads(Arc::clone(&gate))).await.expect("handshake");
        assert!(handle.authenticate_password(USER, PASSWORD).await.expect("login").success());
        (gate, tokio::sync::Mutex::new(handle), served.seen)
    }

    let (gate, handle, seen) = connect("SSH-2.0-Cisco-1.25").await;
    assert_eq!(gate.limit(), Some(TerminalOnly::ServerIdent));
    assert!(open_feature_channel(&handle, &gate).await.is_err());
    assert_eq!(seen.lock().unwrap().session_opens, 0, "nothing was asked of the server");
    assert!(open_terminal_channel(&handle, &gate).await.is_ok(), "the terminal opens");

    let (gate, handle, seen) = connect("SSH-2.0-OpenSSH_9.6").await;
    assert_eq!(gate.limit(), None, "a normal host keeps its features");
    assert!(open_terminal_channel(&handle, &gate).await.is_ok());
    assert_eq!(seen.lock().unwrap().session_opens, 1);
}

// ---------------------------------------------------------------------------
// Live tests against the Docker sshd fixtures
// ---------------------------------------------------------------------------

const USER: &str = "tester";
const PASSWORD: &str = "pw";
const MODERN: u16 = 2201;
const LEGACY_GROUP14: u16 = 2202;
const LEGACY_GROUP1: u16 = 2203;
const NO_FORWARDING: u16 = 2204;
/// `AuthenticationMethods publickey,password`.
const KEY_THEN_PASSWORD: u16 = 2205;
/// `AuthenticationMethods publickey,keyboard-interactive`.
const KEY_THEN_KBI: u16 = 2206;
/// Modern key exchange and MACs, but only `ssh-rsa` (SHA-1) host-key signatures.
const SHA1_HOST_KEY_ONLY: u16 = 2207;
/// `GatewayPorts clientspecified`: a remote forward listens where the client asks.
const GATEWAY_PORTS: u16 = 2208;
/// `MaxSessions 1`: one channel per connection.
const ONE_SESSION: u16 = 2209;
/// The key exchanges Cisco IOS offers: ECDH on the NIST curves and DH-group14-SHA1.
const ECDH_AND_SHA1_KEX: u16 = 2210;

fn legacy() -> AlgorithmPolicy {
    AlgorithmPolicy { legacy: true, ..AlgorithmPolicy::default() }
}

type Seen = Arc<Mutex<Vec<(String, String)>>>;

struct Probe {
    seen: Seen,
    echo_forwarded: bool,
}

impl client::Handler for Probe {
    type Error = russh::Error;

    async fn check_server_key(&mut self, offered: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = offered else {
            return Ok(false);
        };
        self.seen.lock().unwrap().push((host_key_fingerprint(key), host_key_label(key)));
        Ok(true)
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        if self.echo_forwarded {
            reply.accept().await;
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(channel.into_stream());
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
        Ok(())
    }
}

fn fixtures() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("SOLANUM_SSH_FIXTURES").expect("set SOLANUM_SSH_FIXTURES to the sshd fixture folder"),
    )
}

/// `ssh-keygen -lf` output of the servers' host keys, keyed by label.
fn server_host_keys() -> Vec<(String, String)> {
    let text = std::fs::read_to_string(fixtures().join("out/hostkeys.txt")).expect("hostkeys.txt");
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let _bits = parts.next()?;
            let fp = parts.next()?.strip_prefix("SHA256:")?.to_string();
            let label = match line.rsplit('(').next()?.trim_end_matches(')') {
                "ED25519" => "ssh-ed25519",
                "RSA" => "ssh-rsa",
                "ECDSA" => "ecdsa-sha2-nistp256",
                _ => return None,
            };
            Some((label.to_string(), fp))
        })
        .collect()
}

async fn try_connect_config(port: u16, echo_forwarded: bool, config: client::Config) -> (Result<client::Handle<Probe>, russh::Error>, Seen) {
    let seen: Seen = Arc::default();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.expect("tcp connect");
    let handle = tokio::time::timeout(
        Duration::from_secs(20),
        client::connect_stream(Arc::new(config), tcp, Probe { seen: Arc::clone(&seen), echo_forwarded }),
    )
    .await
    .expect("handshake timed out");
    (handle, seen)
}

async fn connect_config(port: u16, echo_forwarded: bool, config: client::Config) -> (client::Handle<Probe>, Seen) {
    let (handle, seen) = try_connect_config(port, echo_forwarded, config).await;
    (handle.expect("handshake failed"), seen)
}

async fn connect_with(port: u16, echo_forwarded: bool) -> (client::Handle<Probe>, Seen) {
    connect_config(port, echo_forwarded, build_ssh_client_config(&AlgorithmPolicy::default())).await
}

/// A client that does not announce ext-info support, so the server never
/// sends `server-sig-algs`: what an SSH server older than OpenSSH 7.2 looks
/// like from the client's side.
async fn connect_as_if_server_is_ancient(port: u16, policy: &AlgorithmPolicy) -> (client::Handle<Probe>, Seen) {
    let mut config = build_ssh_client_config(policy);
    let mut preferred = config.preferred.clone();
    let kex: Vec<_> = preferred.kex.iter().copied().filter(|n| n.as_ref() != "ext-info-c").collect();
    preferred.kex = std::borrow::Cow::Owned(kex);
    config.preferred = preferred;
    connect_config(port, false, config).await
}

async fn connect(port: u16) -> (client::Handle<Probe>, Seen) {
    connect_with(port, false).await
}

fn load_key(name: &str, passphrase: Option<&str>) -> russh::keys::PrivateKey {
    let text = std::fs::read_to_string(fixtures().join("keys").join(name)).expect("key file");
    decode_secret_key(&text.replace("\r\n", "\n"), passphrase).unwrap_or_else(|e| panic!("decode {name}: {e}"))
}

fn assert_seen_matches_server(seen: &Seen, expected_label: &str) {
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "check_server_key runs once per handshake");
    let (fp, label) = &seen[0];
    assert_eq!(label, expected_label);
    let server = server_host_keys();
    let want = server.iter().find(|(l, _)| l == expected_label).expect("server key on file");
    assert_eq!(fp, &want.1, "fingerprint must equal what `ssh-keygen -lf` reports for the server");
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_password_auth_and_host_key_format_on_a_modern_server() {
    let (mut handle, seen) = connect(MODERN).await;
    assert_seen_matches_server(&seen, "ssh-ed25519");
    let ok = handle.authenticate_password(USER, PASSWORD).await.unwrap().success();
    assert!(ok, "right password is accepted");

    let (mut handle, _) = connect(MODERN).await;
    let bad = handle.authenticate_password(USER, "not-the-password").await.unwrap().success();
    assert!(!bad, "wrong password is rejected");
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_every_supported_private_key_format_authenticates() {
    let cases: &[(&str, Option<&str>)] = &[
        ("ed25519", None),
        ("ed25519_pass", Some("secret-pass")),
        ("rsa", None),
        ("rsa_pem", None),
        ("ecdsa", None),
        // PuTTY .ppk fixtures bundled in the `ssh-key` crate's own test suite
        // (real puttygen output, not something we generate). "123" is that
        // crate's documented fixture passphrase, not a Solanum convention.
        ("id_ed25519.ppk", None),
        ("id_ed25519_enc.ppk", Some("123")),
        ("id_rsa_3072.ppk", None),
        ("id_rsa_3072_enc.ppk", Some("123")),
    ];
    for (name, pass) in cases {
        let (mut handle, _) = connect(MODERN).await;
        let attempt = authenticate_with_key(&mut handle, USER, Arc::new(load_key(name, *pass)), false).await.unwrap();
        assert!(attempt.success(), "{name} should authenticate without the legacy setting");
    }

    let (mut handle, _) = connect(MODERN).await;
    let stranger = russh::keys::PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[7u8; 32]));
    assert!(
        !authenticate_with_key(&mut handle, USER, Arc::new(stranger), false).await.unwrap().success(),
        "a key the server does not know is rejected"
    );
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_sec1_ecdsa_pem_key_decodes() {
    // The import validator still rejects `BEGIN EC PRIVATE KEY`. This records
    // whether russh could now take it, so the validator can be relaxed.
    let text = std::fs::read_to_string(fixtures().join("keys/ecdsa_pem")).unwrap();
    match decode_secret_key(&text, None) {
        Ok(key) => {
            let (mut handle, _) = connect(MODERN).await;
            let ok = authenticate_with_key(&mut handle, USER, Arc::new(key), false).await.unwrap().success();
            println!("SEC1 ECDSA PEM: decodes and authenticates = {ok}");
        }
        Err(e) => println!("SEC1 ECDSA PEM: not decodable ({e})"),
    }
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_keyboard_interactive_password_prompt() {
    let (mut handle, _) = connect(MODERN).await;
    let mut resp = handle.authenticate_keyboard_interactive_start(USER, None::<String>).await.unwrap();
    let mut prompted = false;
    loop {
        match resp {
            KeyboardInteractiveAuthResponse::Success => break,
            KeyboardInteractiveAuthResponse::Failure { .. } => panic!("keyboard-interactive was refused"),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                prompted = true;
                let answers = prompts.iter().map(|_| PASSWORD.to_string()).collect();
                resp = handle.authenticate_keyboard_interactive_respond(answers).await.unwrap();
            }
        }
    }
    assert!(prompted, "the server asked at least one question");
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_legacy_server_group14_sha1_ssh_rsa_hmac_sha1_aes_ctr() {
    let (mut handle, seen) = connect_config(LEGACY_GROUP14, false, build_ssh_client_config(&legacy())).await;
    assert_seen_matches_server(&seen, "ssh-rsa");
    assert!(handle.authenticate_password(USER, PASSWORD).await.unwrap().success());

    // This server only accepts SHA-1 `ssh-rsa` signatures for public keys.
    // (OpenSSH 9.2 still advertises rsa-sha2-* in server-sig-algs even when
    // PubkeyAcceptedAlgorithms excludes them, so the realistic stand-in for a
    // truly old server is one that never announces server-sig-algs at all.)
    for name in ["rsa", "rsa_pem"] {
        let (mut handle, _) = connect_as_if_server_is_ancient(LEGACY_GROUP14, &legacy()).await;
        assert!(
            authenticate_with_key(&mut handle, USER, Arc::new(load_key(name, None)), true).await.unwrap().success(),
            "{name} authenticates against an ssh-rsa-only server that sends no server-sig-algs"
        );
        // Without the legacy setting the key is not used at all (F-076).
        let (mut handle, _) = connect_as_if_server_is_ancient(LEGACY_GROUP14, &legacy()).await;
        assert!(matches!(
            authenticate_with_key(&mut handle, USER, Arc::new(load_key(name, None)), false).await.unwrap(),
            KeyAttempt::NeedsSha1
        ));
    }
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_legacy_server_group1_sha1() {
    let (mut handle, seen) = connect_config(LEGACY_GROUP1, false, build_ssh_client_config(&legacy())).await;
    assert_seen_matches_server(&seen, "ssh-rsa");
    assert!(handle.authenticate_password(USER, PASSWORD).await.unwrap().success());
}

/// F-076: without a server's legacy setting, SHA-1 key exchange and
/// `ssh-rsa` host keys are refused, and the error names what the server
/// offered so the app can point to the setting.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_legacy_algorithms_are_refused_without_the_setting() {
    for port in [LEGACY_GROUP14, LEGACY_GROUP1, SHA1_HOST_KEY_ONLY] {
        let (res, seen) = try_connect_config(port, false, build_ssh_client_config(&AlgorithmPolicy::default())).await;
        let err = res.err().unwrap_or_else(|| panic!(":{port} connected without the legacy setting"));
        let offered = crate::ssh_connect::legacy_only_offer(&err).unwrap_or_else(|| panic!(":{port}: {err:?}"));
        assert!(!offered.is_empty());
        assert!(seen.lock().unwrap().is_empty(), "no host key was even looked at");
    }
    // The host-key-only server works with the setting, over a modern key exchange.
    let (mut handle, seen) = connect_config(SHA1_HOST_KEY_ONLY, false, build_ssh_client_config(&legacy())).await;
    assert_seen_matches_server(&seen, "ssh-rsa");
    assert!(handle.authenticate_password(USER, PASSWORD).await.unwrap().success());
}

/// Answers every keyboard-interactive question with the test password.
struct PasswordPrompter;

impl crate::ssh_connect::KbiPrompter for PasswordPrompter {
    fn ask(&self, round: crate::ssh_connect::KbiRound) -> impl std::future::Future<Output = Option<Vec<String>>> + Send {
        let n = round.prompts.len();
        async move { Some(vec![PASSWORD.to_string(); n]) }
    }
}

fn key_login(name: &str, typed_password: Option<&str>) -> crate::ssh_connect::Credentials {
    crate::ssh_connect::Credentials {
        key_login: true,
        key: Some(Arc::new(load_key(name, None))),
        key_problem: None,
        password: typed_password.map(str::to_string),
        password_can_be_typed: true,
        allow_sha1_rsa: false,
    }
}

async fn ladder(port: u16, creds: crate::ssh_connect::Credentials) -> Result<(), crate::ssh_connect::AuthFailure> {
    let (mut handle, _) = connect(port).await;
    crate::ssh_connect::authenticate(
        &mut handle,
        USER,
        creds,
        Some(&PasswordPrompter),
        crate::ssh_connect::AuthLimits::default(),
        &|_: &str, _: &str| {},
    )
    .await
}

/// C4: OpenSSH with `AuthenticationMethods publickey,password` answers the
/// key with a partial success; the login goes on with the typed password,
/// and without one says what is missing.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_key_and_then_a_password_log_in() {
    let (mut handle, _) = connect(KEY_THEN_PASSWORD).await;
    match authenticate_with_key(&mut handle, USER, Arc::new(load_key("ed25519", None)), false).await.unwrap() {
        KeyAttempt::Answered(client::AuthResult::Failure { remaining_methods, partial_success }) => {
            assert!(partial_success, "the key is one accepted step");
            assert!(remaining_methods.contains(&russh::MethodKind::Password));
        }
        other => panic!("{other:?}"),
    }
    ladder(KEY_THEN_PASSWORD, key_login("ed25519", Some(PASSWORD))).await.expect("logs in");
    match ladder(KEY_THEN_PASSWORD, key_login("ed25519", None)).await {
        Err(crate::ssh_connect::AuthFailure::Unanswerable(reason)) => assert!(reason.contains("also asks for a password"), "{reason}"),
        other => panic!("{other:?}"),
    }
}

/// F-027: OpenSSH answers the keepalive request (with a failure reply), so
/// the probe sees a live connection without opening a channel.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_the_liveness_probe_gets_an_answer_from_openssh() {
    let handle = tokio::sync::Mutex::new(logged_in(MODERN, false).await);
    for _ in 0..3 {
        assert!(crate::ssh_connect::probe_alive(&handle, Duration::from_secs(5)).await);
    }
}

/// C4: `AuthenticationMethods publickey,keyboard-interactive` (PAM asks for
/// the password after the key).
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_key_and_then_keyboard_interactive_log_in() {
    ladder(KEY_THEN_KBI, key_login("ed25519", None)).await.expect("logs in");
}

async fn logged_in(port: u16, echo_forwarded: bool) -> client::Handle<Probe> {
    let (mut handle, _) = connect_with(port, echo_forwarded).await;
    assert!(handle.authenticate_password(USER, PASSWORD).await.unwrap().success());
    handle
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_exec_returns_output_and_exit_status() {
    let handle = logged_in(MODERN, false).await;
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, "echo hello-from-sshd; exit 3").await.unwrap();
    let (mut out, mut status) = (Vec::new(), None);
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => status = Some(exit_status),
                _ => {}
            }
        }
    })
    .await
    .expect("exec timed out");
    assert_eq!(String::from_utf8_lossy(&out).trim(), "hello-from-sshd");
    assert_eq!(status, Some(3));
}

/// Output of `command` run on its own channel.
async fn exec_output(handle: &client::Handle<Probe>, command: &str) -> String {
    let mut channel = handle.channel_open_session().await.unwrap();
    channel.exec(true, command).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(msg) = channel.wait().await {
            if let ChannelMsg::Data { data } = msg {
                out.extend_from_slice(&data);
            }
        }
    })
    .await
    .expect("exec timed out");
    String::from_utf8_lossy(&out).into_owned()
}

/// F-041: stopping a Docker live log ends the command on the server. A quiet
/// `tail -f` stands in for `docker logs -f` of an idle container: stopped
/// through `DockerStreams` (signal, EOF, close) it is gone; closed the old
/// way (the channel only) it keeps running, because sshd just closes its
/// pipes and it never writes.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_stopping_a_log_stream_ends_the_remote_command() {
    use rand::Rng;
    let control = logged_in(MODERN, false).await;
    let handle = Arc::new(tokio::sync::Mutex::new(logged_in(MODERN, false).await));
    let tag = format!("{:012x}", rand::thread_rng().gen::<u64>() & 0xffff_ffff_ffff);
    let marker = |which: &str| format!("/tmp/solanum-f041-{which}-{tag}");
    // A pattern that matches the marker but not the command line searching for it.
    let running = |which: &str| {
        let m = marker(which);
        let (head, tail) = m.split_at(1);
        format!("grep -l '[{head}]{tail}' /proc/[0-9]*/cmdline 2>/dev/null; true")
    };
    let follow = |which: &str| format!("touch {m} && exec tail -f {m}", m = marker(which));

    let stopped = crate::ssh_connect::open_session_channel(&handle).await.unwrap();
    stopped.exec(true, follow("new")).await.unwrap();
    let streams = crate::docker::DockerStreams::new();
    let sink = crate::docker::LogSink { text: Box::new(|_| {}), closed: Box::new(|| {}) };
    streams.start("logs".into(), "session-1".into(), stopped, sink).await;

    let old_way = handle.lock().await.channel_open_session().await.unwrap();
    old_way.exec(true, follow("old")).await.unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!exec_output(&control, &running("new")).await.trim().is_empty(), "the command runs");
    assert!(!exec_output(&control, &running("old")).await.trim().is_empty());

    streams.stop_session("session-1").await;
    drop(old_way.into_stream()); // what the old stop did: the channel is closed, nothing else
    let mut gone = false;
    for _ in 0..25 {
        if exec_output(&control, &running("new")).await.trim().is_empty() {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let old_still_running = !exec_output(&control, &running("old")).await.trim().is_empty();
    // Clean up the old-way process and the marker files.
    let pids = format!(
        "for f in $({}); do p=${{f#/proc/}}; kill ${{p%/cmdline}}; done; rm -f {} {}",
        running("old").trim_end_matches("; true"),
        marker("new"),
        marker("old")
    );
    exec_output(&control, &pids).await;
    assert!(gone, "a stopped log stream's command is ended on the server");
    assert!(old_still_running, "closing the channel alone leaves a quiet command running (why the signal is sent)");
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_direct_tcpip_reaches_a_service_behind_the_server() {
    let handle = logged_in(MODERN, false).await;
    let channel = handle.channel_open_direct_tcpip("127.0.0.1", MODERN as u32, "127.0.0.1", 0).await.unwrap();
    let mut stream = channel.into_stream();
    let mut banner = [0u8; 15];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut banner)).await.unwrap().unwrap();
    assert_eq!(&banner, b"SSH-2.0-OpenSSH");
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_remote_forward_bridges_inbound_connections_and_can_be_refused() {
    let a = logged_in(MODERN, true).await;
    a.tcpip_forward("127.0.0.1", 18022).await.expect("server accepts the forward");

    // A second connection dials the forwarded port from inside the server.
    let b = logged_in(MODERN, false).await;
    let channel = b.channel_open_direct_tcpip("127.0.0.1", 18022, "127.0.0.1", 0).await.unwrap();
    let mut stream = channel.into_stream();
    stream.write_all(b"ping-pong").await.unwrap();
    let mut echoed = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut echoed)).await.unwrap().unwrap();
    assert_eq!(&echoed, b"ping-pong");

    a.cancel_tcpip_forward("127.0.0.1", 18022).await.expect("forward can be cancelled");

    // An address the server cannot bind (its own sshd already listens on it)
    // comes back as a refusal, never as a silent "listening".
    let refused = a.tcpip_forward("127.0.0.1", MODERN as u32).await;
    assert!(matches!(refused, Err(russh::Error::RequestDenied)), "got {refused:?}");
}

/// Tunnel events nobody watches.
fn quiet_events() -> crate::tunnel::TunnelEvents {
    crate::tunnel::TunnelEvents { update: Arc::new(|_| {}), log: Arc::new(|_, _| {}) }
}

/// Starts a tunnel through the app's tunnel code on `handle`.
async fn tunnel_on(
    handle: &Arc<tokio::sync::Mutex<client::Handle<Probe>>>,
    tunnels: &crate::tunnel::TunnelMap,
    kind: &str,
    local: &str,
    remote: &str,
) -> Result<String, String> {
    let spec = crate::tunnel::TunnelSpec { kind: kind.into(), local: local.into(), remote: remote.into() };
    crate::tunnel::start_tunnel(quiet_events(), "live".into(), Arc::clone(handle), Arc::clone(tunnels), Default::default(), spec).await
}

/// F-020: against a server that lets the client choose the bind address, a
/// remote tunnel given a bare port listens on the server's loopback only, and
/// `0.0.0.0:port` on its network address as well.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_bare_remote_port_listens_on_the_server_s_loopback_only() {
    let owner = Arc::new(tokio::sync::Mutex::new(logged_in(GATEWAY_PORTS, false).await));
    let tunnels = crate::tunnel::TunnelMap::default();
    tunnel_on(&owner, &tunnels, "R", "18030", "127.0.0.1:9").await.expect("bare port forwarded");
    tunnel_on(&owner, &tunnels, "R", "0.0.0.0:18031", "127.0.0.1:9").await.expect("wide bind forwarded");

    // A second connection asks the server to connect to those ports, from
    // inside: on loopback, and on the container's own network address.
    let probe = logged_in(GATEWAY_PORTS, false).await;
    let address = exec_output(&probe, "hostname -I").await.split_whitespace().next().expect("an address").to_string();
    let reaches = |host: String, port: u32| {
        let probe = &probe;
        async move { probe.channel_open_direct_tcpip(host, port, "127.0.0.1", 0).await.is_ok() }
    };
    assert!(reaches("127.0.0.1".into(), 18030).await, "bare port: on loopback");
    assert!(!reaches(address.clone(), 18030).await, "bare port: not on {address}");
    assert!(reaches(address.clone(), 18031).await, "0.0.0.0: on {address} too");
    crate::tunnel::stop_all(&tunnels).await;
}

/// F-066: OpenSSH refuses a bracketed host in `direct-tcpip` (it hands the
/// string to getaddrinfo), and an L tunnel to `[::1]:port` sends it bare.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_an_ipv6_target_reaches_the_server_without_brackets() {
    let handle = Arc::new(tokio::sync::Mutex::new(logged_in(MODERN, false).await));
    let bracketed = handle.lock().await.channel_open_direct_tcpip("[::1]", MODERN as u32, "127.0.0.1", 0).await;
    assert!(bracketed.is_err(), "the server must refuse [::1]");
    let tunnels = crate::tunnel::TunnelMap::default();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    tunnel_on(&handle, &tunnels, "L", &port.to_string(), &format!("[::1]:{MODERN}")).await.expect("started");
    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut banner = [0u8; 15];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut banner)).await.unwrap().unwrap();
    assert_eq!(&banner, b"SSH-2.0-OpenSSH", "sshd answered on ::1");
    crate::tunnel::stop_all(&tunnels).await;
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_forwarding_disabled_by_the_server_is_reported_as_a_refusal() {
    let handle = logged_in(NO_FORWARDING, false).await;
    let remote = handle.tcpip_forward("127.0.0.1", 18023).await;
    assert!(matches!(remote, Err(russh::Error::RequestDenied)), "remote forward: got {remote:?}");
    let local = handle.channel_open_direct_tcpip("127.0.0.1", MODERN as u32, "127.0.0.1", 0).await;
    assert!(local.is_err(), "direct-tcpip must fail when the server forbids forwarding");
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_sftp_roundtrip_with_a_multi_megabyte_file() {
    use russh_sftp::protocol::OpenFlags;
    let handle = logged_in(MODERN, false).await;
    let channel = handle.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream()).await.unwrap();

    let dir = "/tmp/solanum-sftp-test";
    let _ = sftp.remove_dir(dir).await;
    sftp.create_dir(dir).await.unwrap();

    // 6 MiB of deterministic pseudo-random bytes, written in 256 KiB chunks
    // exactly like the app's uploader.
    let mut state = 0x9E3779B97F4A7C15u64;
    let payload: Vec<u8> = (0..6 * 1024 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect();
    let path = format!("{dir}/blob.bin");
    let mut remote = sftp
        .open_with_flags(&path, OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE)
        .await
        .unwrap();
    for chunk in payload.chunks(256 * 1024) {
        remote.write_all(chunk).await.unwrap();
    }
    remote.shutdown().await.unwrap();

    assert_eq!(sftp.metadata(&path).await.unwrap().size, Some(payload.len() as u64));
    let mut back = Vec::new();
    sftp.open(&path).await.unwrap().read_to_end(&mut back).await.unwrap();
    assert!(back == payload, "downloaded bytes match what was uploaded");

    let names: Vec<String> = sftp.read_dir(dir).await.unwrap().map(|e| e.file_name()).collect();
    assert_eq!(names, vec!["blob.bin".to_string()]);

    sftp.rename(&path, format!("{dir}/renamed.bin")).await.unwrap();
    sftp.remove_file(format!("{dir}/renamed.bin")).await.unwrap();
    sftp.remove_dir(dir).await.unwrap();
}

// ---------------------------------------------------------------------------
// Live tests of the SFTP helpers (atomic_transfer.rs)
// ---------------------------------------------------------------------------

/// A logged-in SFTP session; the handle must outlive it.
async fn sftp_session() -> (client::Handle<Probe>, russh_sftp::client::SftpSession) {
    let handle = logged_in(MODERN, false).await;
    let channel = handle.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream()).await.unwrap();
    (handle, sftp)
}

/// A fresh, empty remote folder for one test.
async fn fresh_dir(sftp: &russh_sftp::client::SftpSession, name: &str) -> String {
    let dir = format!("/tmp/solanum-live-{name}");
    let _ = crate::remove_remote_tree(sftp, &dir).await;
    sftp.create_dir(&dir).await.unwrap();
    dir
}

async fn put(sftp: &russh_sftp::client::SftpSession, path: &str, data: &[u8]) {
    use russh_sftp::protocol::OpenFlags;
    let mut f = sftp.open_with_flags(path, OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE).await.unwrap();
    f.write_all(data).await.unwrap();
    f.shutdown().await.unwrap();
}

async fn listing(sftp: &russh_sftp::client::SftpSession, dir: &str) -> Vec<String> {
    let mut names: Vec<String> = sftp.read_dir(dir).await.unwrap().map(|e| e.file_name()).collect();
    names.sort();
    names
}

/// `data` written to a local file, the source an upload reads.
struct LocalSource(std::path::PathBuf);

impl LocalSource {
    fn new(data: &[u8]) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir()
            .join(format!("solanum-upload-src-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&path, data).unwrap();
        LocalSource(path)
    }
}

impl Drop for LocalSource {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn upload(
    sftp: &russh_sftp::client::SftpSession,
    path: &str,
    data: &[u8],
    allow_replace: bool,
) -> Result<crate::atomic_transfer::Replaced, crate::atomic_transfer::ReplaceError> {
    let source = LocalSource::new(data);
    crate::atomic_transfer::replace_remote_file(sftp, path, &source.0, allow_replace, &mut |_: u64, _: &[u8]| true).await
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_replace_remote_file_keeps_the_mode_and_leaves_nothing_behind() {
    use crate::atomic_transfer::{ReplaceError, Replaced};
    let (_handle, sftp) = sftp_session().await;
    let dir = fresh_dir(&sftp, "replace").await;

    let new = format!("{dir}/new.txt");
    assert_eq!(upload(&sftp, &new, b"first", false).await, Ok(Replaced::New));
    assert_eq!(sftp.read(&new).await.unwrap(), b"first");

    let tool = format!("{dir}/tool.sh");
    put(&sftp, &tool, b"#!/bin/sh\necho old\n").await;
    let mut mode = russh_sftp::protocol::FileAttributes::empty();
    mode.permissions = Some(0o754);
    sftp.set_metadata(&tool, mode).await.unwrap();
    let payload = pattern(700 * 1024, 7);
    // OpenSSH's rename refuses an existing target, so this takes the move-aside path.
    assert_eq!(upload(&sftp, &tool, &payload, true).await, Ok(Replaced::MovedAside { leftover: None }));
    assert!(sftp.read(&tool).await.unwrap() == payload, "the new content is in place");
    let after = sftp.metadata(&tool).await.unwrap();
    assert_eq!(after.permissions.unwrap() & 0o7777, 0o754, "the mode is kept");

    assert_eq!(upload(&sftp, &tool, b"never", false).await, Err(ReplaceError::Exists));
    assert!(sftp.read(&tool).await.unwrap() == payload, "an existing file is not touched without consent");

    assert_eq!(listing(&sftp, &dir).await, vec!["new.txt", "tool.sh"], "no part or aside file is left");
}

/// F-025: a cancelled (or failed) upload leaves the server file as it was.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_cancelled_upload_leaves_the_target_untouched() {
    use crate::atomic_transfer::ReplaceError;
    let (_handle, sftp) = sftp_session().await;
    let dir = fresh_dir(&sftp, "cancel").await;
    let target = format!("{dir}/data.bin");
    let original = pattern(1024 * 1024, 1);
    put(&sftp, &target, &original).await;

    let source = LocalSource::new(&pattern(1024 * 1024, 2));
    let mut chunks = 0;
    let result = crate::atomic_transfer::replace_remote_file(&sftp, &target, &source.0, true, &mut |_: u64, _: &[u8]| {
        chunks += 1;
        chunks < 2
    })
    .await;
    assert_eq!(result, Err(ReplaceError::Cancelled));
    assert!(sftp.read(&target).await.unwrap() == original, "the target keeps its old content");
    assert_eq!(listing(&sftp, &dir).await, vec!["data.bin"], "the part file is removed");
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_replacing_through_a_symlink_keeps_the_link() {
    let (_handle, sftp) = sftp_session().await;
    let dir = fresh_dir(&sftp, "link").await;
    let real = format!("{dir}/real.conf");
    let link = format!("{dir}/link.conf");
    put(&sftp, &real, b"old").await;
    // OpenSSH takes SSH_FXP_SYMLINK's arguments in reverse order (target first).
    sftp.symlink("real.conf", &link).await.unwrap();
    assert!(sftp.symlink_metadata(&link).await.unwrap().file_type().is_symlink(), "test setup: a link");

    upload(&sftp, &link, b"new through the link", true).await.unwrap();
    assert!(sftp.symlink_metadata(&link).await.unwrap().file_type().is_symlink(), "the link stays a link");
    assert_eq!(sftp.read(&real).await.unwrap(), b"new through the link");
    assert_eq!(listing(&sftp, &dir).await, vec!["link.conf", "real.conf"]);
}

/// A file whose group is not the user's primary group (the user is in that
/// group) keeps it: the part file gets it before any content is sent.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_replace_keeps_a_group_other_than_the_users_own() {
    use crate::atomic_transfer::Replaced;
    let (_handle, sftp) = sftp_session().await;
    let team = "/srv/solanum/team/team.txt";
    let before = sftp.metadata(team).await.unwrap();
    let r = upload(&sftp, team, b"edited by tester", true).await.unwrap();
    assert_eq!(r, Replaced::MovedAside { leftover: None });
    let after = sftp.metadata(team).await.unwrap();
    assert_eq!((after.uid, after.gid), (before.uid, before.gid), "owner and group kept");
    assert_eq!(after.permissions.unwrap() & 0o7777, 0o664);
    assert_eq!(sftp.read(team).await.unwrap(), b"edited by tester");
}

/// A file nobody may write is not replaced around its mode: the upload fails
/// as the old in-place write did.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_read_only_file_is_not_replaced() {
    let (_handle, sftp) = sftp_session().await;
    let dir = fresh_dir(&sftp, "readonly").await;
    let target = format!("{dir}/frozen.txt");
    put(&sftp, &target, b"keep").await;
    sftp.set_metadata(&target, crate::mode_change(0o444)).await.unwrap();
    assert!(upload(&sftp, &target, b"overwrite", true).await.is_err());
    assert_eq!(sftp.read(&target).await.unwrap(), b"keep");
    assert_eq!(listing(&sftp, &dir).await, vec!["frozen.txt"]);
}

/// Owner decision: when the new file could not keep the target's owner, or the
/// folder is not writable, the file is written in place.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_files_that_cannot_keep_their_identity_are_written_in_place() {
    use crate::atomic_transfer::Replaced;
    let (_handle, sftp) = sftp_session().await;

    let root_owned = "/srv/solanum/root-owned.txt";
    let r = upload(&sftp, root_owned, b"written by tester", true).await.unwrap();
    assert!(matches!(r, Replaced::InPlace(_)), "got {r:?}");
    assert_eq!(sftp.metadata(root_owned).await.unwrap().uid, Some(0), "still owned by root");
    assert_eq!(sftp.read(root_owned).await.unwrap(), b"written by tester");

    let locked = "/srv/solanum/locked/mine.txt";
    let r = upload(&sftp, locked, b"in a folder I cannot write", true).await.unwrap();
    assert!(matches!(r, Replaced::InPlace(_)), "got {r:?}");
    assert_eq!(sftp.read(locked).await.unwrap(), b"in a folder I cannot write");
    assert_eq!(listing(&sftp, "/srv/solanum").await, vec!["locked", "root-owned.txt", "team"], "no part file left");
    assert_eq!(listing(&sftp, "/srv/solanum/locked").await, vec!["mine.txt"]);
}

/// The folder mirror's options: the replaced version moved to a given place
/// (kept), or replaced as usual when that place is refused; a new file gets
/// the given mode.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_replace_can_keep_the_previous_version() {
    use crate::atomic_transfer::{replace_remote_file_with, ReplaceOptions, Replaced};
    let (_handle, sftp) = sftp_session().await;
    let dir = fresh_dir(&sftp, "keep-previous").await;
    let target = format!("{dir}/conf.txt");
    put(&sftp, &target, b"version 1").await;
    sftp.set_metadata(&target, crate::mode_change(0o640)).await.unwrap();
    sftp.create_dir(format!("{dir}/kept")).await.unwrap();
    let kept_at = format!("{dir}/kept/conf.txt");
    let source = LocalSource::new(b"version 2");
    let mut go_on = |_: u64, _: &[u8]| true;

    let keep = ReplaceOptions { allow_replace: true, keep_previous: Some(&kept_at), ..ReplaceOptions::default() };
    let r = replace_remote_file_with(&sftp, &target, &source.0, &keep, &mut go_on).await;
    assert_eq!(r, Ok(Replaced::KeptPrevious { at: kept_at.clone() }));
    assert_eq!(sftp.read(&target).await.unwrap(), b"version 2");
    assert_eq!(sftp.read(&kept_at).await.unwrap(), b"version 1", "the previous version is where it was asked to go");
    assert_eq!(sftp.metadata(&target).await.unwrap().permissions.unwrap() & 0o7777, 0o640);

    // A place that cannot take it (no such folder): the old version stays
    // beside the file under its hidden aside name, never deleted.
    let nowhere = format!("{dir}/no-such-folder/conf.txt");
    let refused = ReplaceOptions { allow_replace: true, keep_previous: Some(&nowhere), ..ReplaceOptions::default() };
    let source3 = LocalSource::new(b"version 3");
    let r = replace_remote_file_with(&sftp, &target, &source3.0, &refused, &mut go_on).await;
    let Ok(Replaced::KeptPrevious { at }) = r else { panic!("got {r:?}") };
    assert!(at.starts_with(&format!("{dir}/.conf.txt.")) && at.ends_with(".solanum-old"), "{at}");
    assert_eq!(sftp.read(&at).await.unwrap(), b"version 2");
    assert_eq!(sftp.read(&target).await.unwrap(), b"version 3");
    sftp.remove_file(&at).await.unwrap();

    // Nothing to keep for a new file, which gets the mode asked for, as the
    // server's umask (022 here) allows: 0750 stays, 0777 becomes 0755.
    let fresh = format!("{dir}/fresh.sh");
    let new_mode = ReplaceOptions { allow_replace: true, new_file_mode: Some(0o750), keep_previous: Some(&nowhere), finish_in_place: false };
    let r = replace_remote_file_with(&sftp, &fresh, &source.0, &new_mode, &mut go_on).await;
    assert_eq!(r, Ok(Replaced::New));
    assert_eq!(sftp.metadata(&fresh).await.unwrap().permissions.unwrap() & 0o7777, 0o750);
    let wide = format!("{dir}/wide.txt");
    let wide_mode = ReplaceOptions { allow_replace: true, new_file_mode: Some(0o777), ..ReplaceOptions::default() };
    replace_remote_file_with(&sftp, &wide, &source.0, &wide_mode, &mut go_on).await.unwrap();
    assert_eq!(sftp.metadata(&wide).await.unwrap().permissions.unwrap() & 0o7777, 0o755, "never wider than the umask allows");
    assert_eq!(listing(&sftp, &dir).await, vec!["conf.txt", "fresh.sh", "kept", "wide.txt"], "no part or aside file is left");
}

/// Review of batch 8: a file that can only be written in place is finished
/// when `finish_in_place` is set, even if the caller asks to stop; without
/// it the stop cuts it short (the user's own cancel of an upload).
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_file_written_in_place_is_finished_despite_a_stop() {
    use crate::atomic_transfer::{replace_remote_file_with, ReplaceError, ReplaceOptions, Replaced};
    let (_handle, sftp) = sftp_session().await;
    let root_owned = "/srv/solanum/root-owned.txt";
    let payload = pattern(900 * 1024, 9);
    let source = LocalSource::new(&payload);
    let finish = ReplaceOptions { allow_replace: true, finish_in_place: true, ..ReplaceOptions::default() };
    let mut chunks = 0;
    let r = replace_remote_file_with(&sftp, root_owned, &source.0, &finish, &mut |_: u64, _: &[u8]| {
        chunks += 1;
        false
    })
    .await;
    assert!(matches!(r, Ok(Replaced::InPlace(_))), "got {r:?}");
    assert!(chunks >= 3, "every chunk was still reported ({chunks})");
    assert!(sftp.read(root_owned).await.unwrap() == payload, "the whole file is there");

    let cancel = ReplaceOptions { allow_replace: true, ..ReplaceOptions::default() };
    let r = replace_remote_file_with(&sftp, root_owned, &source.0, &cancel, &mut |_: u64, _: &[u8]| false).await;
    assert_eq!(r, Err(ReplaceError::Cancelled), "a user's cancel still stops it");
    put(&sftp, root_owned, b"written by tester").await;
}

// ---------------------------------------------------------------------------
// Live edit against a real server (live_edit.rs)
// ---------------------------------------------------------------------------

struct FixtureLink {
    sftp: russh_sftp::client::SftpSession,
    statuses: tokio::sync::mpsc::UnboundedSender<crate::live_edit::SyncStatus>,
}

impl crate::live_edit::LiveEditLink for FixtureLink {
    fn target(&self) -> Option<crate::live_edit::ServerIdentity> {
        Some(crate::live_edit::ServerIdentity { address: format!("{USER}@127.0.0.1:{MODERN}"), host_key: "fixture".into() })
    }
    fn fetch<'a>(
        &'a self,
        remote: &'a str,
        dest: &'a std::path::Path,
        cap: u64,
    ) -> crate::live_edit::BoxFut<'a, Result<crate::live_edit::Fetched, String>> {
        Box::pin(crate::live_edit::fetch_over_sftp(&self.sftp, remote, dest, cap))
    }
    fn store<'a>(
        &'a self,
        local: &'a std::path::Path,
        remote: &'a str,
    ) -> crate::live_edit::BoxFut<'a, Result<crate::live_edit::Stored, String>> {
        Box::pin(crate::live_edit::store_over_sftp(&self.sftp, local, remote))
    }
    fn report(&self, status: crate::live_edit::SyncStatus) {
        let _ = self.statuses.send(status);
    }
}

async fn wait_for_sync(
    statuses: &mut tokio::sync::mpsc::UnboundedReceiver<crate::live_edit::SyncStatus>,
    remote: &str,
) {
    use crate::live_edit::StatusKind;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let status = tokio::time::timeout_at(deadline, statuses.recv())
            .await
            .unwrap_or_else(|_| panic!("{remote} was not synced in time"))
            .expect("status channel open");
        if status.remote_path == remote {
            assert_ne!(status.kind, StatusKind::Failed, "{}", status.message);
            if status.kind == StatusKind::Synced {
                return;
            }
        }
    }
}

/// F-001: two remote files with the same name, opened in one session, each
/// save to their own remote path (the old staging gave them one local copy,
/// and the first file's watcher uploaded the second file's content).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_edit_same_named_files_sync_to_their_own_paths() {
    let (_handle, sftp) = sftp_session().await;
    let dir_a = fresh_dir(&sftp, "edit-a").await;
    let dir_b = fresh_dir(&sftp, "edit-b").await;
    let (remote_a, remote_b) = (format!("{dir_a}/x.conf"), format!("{dir_b}/x.conf"));
    put(&sftp, &remote_a, b"server A config").await;
    put(&sftp, &remote_b, b"backup B config").await;

    let base = std::env::temp_dir().join(format!("solanum-live-edit-live-{}", std::process::id()));
    std::fs::create_dir_all(&base).unwrap();
    let edits = crate::live_edit::LiveEdits::new_in(base.clone(), Duration::from_millis(200));
    let (tx, mut statuses) = tokio::sync::mpsc::unbounded_channel();
    let link = Arc::new(FixtureLink { sftp, statuses: tx });
    let as_link = || Arc::clone(&link) as Arc<dyn crate::live_edit::LiveEditLink>;
    let no_refusal = |_: &[u8]| None;

    let a = edits.open(as_link(), "s1", &remote_a, "x.conf", &no_refusal).await.unwrap();
    let b = edits.open(as_link(), "s1", &remote_b, "x.conf", &no_refusal).await.unwrap();
    assert_ne!(a.path, b.path, "each file has its own local copy");
    assert_eq!(std::fs::read(&a.path).unwrap(), b"server A config");

    std::fs::write(&a.path, b"server A config, edited").unwrap();
    wait_for_sync(&mut statuses, &remote_a).await;
    std::fs::write(&b.path, b"backup B config, edited").unwrap();
    wait_for_sync(&mut statuses, &remote_b).await;

    assert_eq!(link.sftp.read(&remote_a).await.unwrap(), b"server A config, edited");
    assert_eq!(link.sftp.read(&remote_b).await.unwrap(), b"backup B config, edited");
    assert_eq!(listing(&link.sftp, &dir_a).await, vec!["x.conf"], "nothing left beside the file");

    for task in edits.stop_session("s1", crate::live_edit::StopReason::Disconnected) {
        task.await.unwrap();
    }
    std::fs::remove_dir_all(&base).unwrap();
}

/// F-024: the download into the staging folder is capped whatever the
/// server announced, and a refused download leaves no copy.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_edit_download_is_capped_and_hashed() {
    use sha2::Digest;
    let (_handle, sftp) = sftp_session().await;
    let dir = fresh_dir(&sftp, "edit-cap").await;
    let remote = format!("{dir}/big.log");
    let content = pattern(1001, 3);
    put(&sftp, &remote, &content).await;

    let local_dir = std::env::temp_dir().join(format!("solanum-live-edit-cap-{}", std::process::id()));
    std::fs::create_dir_all(&local_dir).unwrap();
    let dest = local_dir.join("big.log");
    let refused = crate::live_edit::fetch_over_sftp(&sftp, &remote, &dest, 1000).await;
    assert!(refused.is_err(), "one byte over the cap is refused");
    assert!(!dest.exists(), "and leaves no copy");

    let fetched = crate::live_edit::fetch_over_sftp(&sftp, &remote, &dest, 1001).await.unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), content);
    assert_eq!(fetched.hash, <[u8; 32]>::from(sha2::Sha256::digest(&content)));
    assert_eq!(fetched.head, content[..64]);
    std::fs::remove_dir_all(&local_dir).unwrap();
}

// ---------------------------------------------------------------------------
// Folder delete and attribute changes (F-074)
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_folder_delete_removes_the_contents_but_never_follows_a_link() {
    let (_handle, sftp) = sftp_session().await;
    let outside = fresh_dir(&sftp, "delete-outside").await;
    put(&sftp, &format!("{outside}/keep.txt"), b"keep").await;
    let tree = fresh_dir(&sftp, "delete-tree").await;
    sftp.create_dir(format!("{tree}/sub")).await.unwrap();
    sftp.create_dir(format!("{tree}/sub/deeper")).await.unwrap();
    for f in ["a.txt", "sub/b.txt", "sub/deeper/c.txt"] {
        put(&sftp, &format!("{tree}/{f}"), b"x").await;
    }
    // OpenSSH takes SSH_FXP_SYMLINK's arguments in reverse order (target first).
    sftp.symlink(&outside, format!("{tree}/sub/link-to-folder")).await.unwrap();
    sftp.symlink(format!("{outside}/keep.txt"), format!("{tree}/link-to-file")).await.unwrap();

    crate::remove_remote_tree(&sftp, &tree).await.unwrap();
    assert!(sftp.symlink_metadata(&tree).await.is_err(), "the folder and everything in it are gone");
    assert_eq!(sftp.read(format!("{outside}/keep.txt")).await.unwrap(), b"keep", "nothing behind a link is touched");

    // A path that is itself a link to a folder: only the link goes.
    let link = format!("{outside}-link");
    let _ = sftp.remove_file(&link).await;
    sftp.symlink(&outside, &link).await.unwrap();
    crate::remove_remote_tree(&sftp, &link).await.unwrap();
    assert!(sftp.symlink_metadata(&link).await.is_err());
    assert_eq!(listing(&sftp, &outside).await, vec!["keep.txt"]);

    assert!(crate::remove_remote_tree(&sftp, "/").await.is_err());
    assert!(crate::remove_remote_tree(&sftp, "relative/folder").await.is_err());
    assert!(crate::remove_remote_tree(&sftp, &format!("{outside}/keep.txt")).await.is_err(), "a file is not a folder");
}

#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mode_and_owner_changes_touch_nothing_else() {
    let (_handle, sftp) = sftp_session().await;
    let dir = fresh_dir(&sftp, "attrs").await;
    let shared = format!("{dir}/shared");
    sftp.create_dir(&shared).await.unwrap();
    sftp.set_metadata(&shared, crate::mode_change(0o2775)).await.unwrap();
    assert_eq!(sftp.metadata(&shared).await.unwrap().permissions.unwrap() & 0o7777, 0o2775, "setgid is set and kept");

    let file = format!("{dir}/data.bin");
    put(&sftp, &file, &pattern(4096, 5)).await;
    let before = sftp.metadata(&file).await.unwrap();
    sftp.set_metadata(&file, crate::mode_change(0o640)).await.unwrap();
    let after = sftp.metadata(&file).await.unwrap();
    assert_eq!(after.permissions.unwrap() & 0o7777, 0o640);
    assert_eq!((after.size, after.uid, after.gid), (before.size, before.uid, before.gid));

    // Changing only the group keeps the owner (the user's own group here).
    let attrs = crate::owner_change(None, before.gid, Some(&before)).unwrap();
    sftp.set_metadata(&file, attrs).await.unwrap();
    let again = sftp.metadata(&file).await.unwrap();
    assert_eq!((again.uid, again.gid, again.size), (before.uid, before.gid, before.size));
}

// ---------------------------------------------------------------------------
// Folder mirror against a real server (mirror.rs)
// ---------------------------------------------------------------------------

/// N-021: transfers running at once may all need the same new folder; each
/// of them gets it (OpenSSH answers the losing `mkdir` with a bare "Failure").
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_folders_created_at_once_all_succeed() {
    let (_handle, sftp) = sftp_session().await;
    let base = fresh_dir(&sftp, "mirror-mkdir-race").await;
    let sftp = Arc::new(sftp);
    for round in 0..5 {
        let path = format!("{base}/r{round}/a/b/c");
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let sftp = Arc::clone(&sftp);
                let path = path.clone();
                tokio::spawn(async move { crate::mirror::sftp_mkdir_p(&sftp, &path).await })
            })
            .collect();
        for task in tasks {
            assert_eq!(task.await.unwrap(), Ok(()), "round {round}");
        }
    }
}

/// What a mirror reported: its states in order and its log lines.
#[derive(Default)]
struct MirrorSeen {
    states: Vec<String>,
    /// (event, path, message)
    logs: Vec<(String, Option<String>, Option<String>)>,
    last: Option<crate::mirror::MirrorStatus>,
}

fn mirror_recorder() -> (crate::mirror::MirrorEvents, Arc<Mutex<MirrorSeen>>) {
    let seen: Arc<Mutex<MirrorSeen>> = Arc::default();
    let (updates, logs) = (Arc::clone(&seen), Arc::clone(&seen));
    let events = crate::mirror::MirrorEvents {
        update: Arc::new(move |status: &crate::mirror::MirrorStatus| {
            let mut seen = updates.lock().unwrap();
            if seen.states.last() != Some(&status.state) {
                seen.states.push(status.state.clone());
            }
            seen.last = Some(status.clone());
        }),
        log: Arc::new(move |_session: &str, entry: &crate::mirror::MirrorLogEntry<'_>| {
            logs.lock().unwrap().logs.push((entry.event.to_string(), entry.path.clone(), entry.message.clone()));
        }),
    };
    (events, seen)
}

/// Wait (up to `secs`) until `done` holds.
async fn within(secs: u64, done: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < deadline {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    done()
}

/// A fresh, empty local folder for one mirror test.
fn local_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("solanum-live-mirror-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn mirror_spec(local: &std::path::Path, remote: &str) -> crate::mirror::MirrorSpec {
    crate::mirror::MirrorSpec {
        local: local.to_string_lossy().into_owned(),
        remote: remote.to_string(),
        soft_delete: true,
        excludes: Vec::new(),
        conflict_resolution: "local".into(),
    }
}

/// A mirror of `local` to `remote` on its own connection, started and
/// watching. Returns the map it is registered in and what it reported.
async fn running_mirror(
    spec: crate::mirror::MirrorSpec,
) -> (crate::mirror::MirrorMap, String, Arc<Mutex<MirrorSeen>>) {
    let handle = Arc::new(tokio::sync::Mutex::new(logged_in(MODERN, false).await));
    let map: crate::mirror::MirrorMap = Arc::default();
    let (events, seen) = mirror_recorder();
    let id = crate::mirror::start(events, "s1".into(), handle, Arc::clone(&map), spec).await.expect("mirror starts");
    let watching = within(30, || seen.lock().unwrap().states.iter().any(|s| s == "watching" || s == "error")).await;
    assert!(watching, "the mirror reaches the watching state");
    assert!(
        !seen.lock().unwrap().states.iter().any(|s| s == "error"),
        "mirror failed: {:?}",
        seen.lock().unwrap().logs
    );
    (map, id, seen)
}

/// Content of a remote file, or None when it is missing.
async fn remote_content(sftp: &russh_sftp::client::SftpSession, path: &str) -> Option<Vec<u8>> {
    sftp.read(path).await.ok()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_syncs_a_folder_and_watches_it() {
    let (_handle, sftp) = sftp_session().await;
    let remote = fresh_dir(&sftp, "mirror-smoke").await;
    put(&sftp, &format!("{remote}/from-server.txt"), b"server side").await;
    let local = local_dir("smoke");
    std::fs::write(local.join("a.txt"), b"alpha").unwrap();
    std::fs::create_dir_all(local.join("sub")).unwrap();
    std::fs::write(local.join("sub/b.txt"), b"bravo").unwrap();

    let (map, id, _seen) = running_mirror(mirror_spec(&local, &remote)).await;
    assert_eq!(remote_content(&sftp, &format!("{remote}/a.txt")).await.as_deref(), Some(&b"alpha"[..]));
    assert_eq!(remote_content(&sftp, &format!("{remote}/sub/b.txt")).await.as_deref(), Some(&b"bravo"[..]));
    assert_eq!(std::fs::read(local.join("from-server.txt")).unwrap(), b"server side", "remote-only files come down");

    std::fs::write(local.join("c.txt"), b"charlie").unwrap();
    let c = format!("{remote}/c.txt");
    let mut uploaded = false;
    for _ in 0..100 {
        if remote_content(&sftp, &c).await.as_deref() == Some(&b"charlie"[..]) {
            uploaded = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(uploaded, "a new local file is uploaded by the watcher");

    crate::mirror::stop(&map, &id).await.unwrap();
    assert!(within(5, || map.try_lock().map(|m| m.is_empty()).unwrap_or(false)).await, "the stopped mirror leaves the map");
    let _ = std::fs::remove_dir_all(&local);
}

/// Wait (up to `secs`) until the remote file has `want` (None: is missing).
async fn remote_becomes(sftp: &russh_sftp::client::SftpSession, path: &str, want: Option<&[u8]>, secs: u64) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let now = remote_content(sftp, path).await;
        if now.as_deref() == want {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Every file under a remote folder, as paths relative to it.
async fn remote_files(sftp: &russh_sftp::client::SftpSession, dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![String::new()];
    while let Some(rel) = stack.pop() {
        let path = if rel.is_empty() { dir.to_string() } else { format!("{dir}/{rel}") };
        let Ok(entries) = sftp.read_dir(&path).await else { continue };
        for e in entries {
            let name = e.file_name();
            let child = if rel.is_empty() { name } else { format!("{rel}/{name}") };
            if e.file_type().is_dir() {
                stack.push(child);
            } else {
                out.push(child);
            }
        }
    }
    out.sort();
    out
}

/// Every file under a local folder (not following links), relative to it.
fn local_files(dir: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let e = e.unwrap();
            let kind = e.file_type().unwrap();
            if kind.is_dir() {
                stack.push(e.path());
            } else {
                out.push(e.path().strip_prefix(dir).unwrap().to_string_lossy().replace('\\', "/"));
            }
        }
    }
    out.sort();
    out
}

/// N-023: a folder renamed or moved into the mirrored folder arrives as one
/// watcher event, none for its files; what it holds is uploaded with it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_uploads_a_folder_moved_in_with_its_files() {
    let (_handle, sftp) = sftp_session().await;
    let remote = fresh_dir(&sftp, "mirror-moved-in").await;
    let local = local_dir("moved-in");
    let outside = local_dir("moved-in-outside");
    std::fs::create_dir_all(outside.join("proj/sub")).unwrap();
    std::fs::write(outside.join("proj/a.txt"), b"alpha").unwrap();
    std::fs::write(outside.join("proj/sub/b.txt"), b"bravo").unwrap();
    let (map, id, _seen) = running_mirror(mirror_spec(&local, &remote)).await;

    std::fs::rename(outside.join("proj"), local.join("proj")).unwrap();
    assert!(
        remote_becomes(&sftp, &format!("{remote}/proj/sub/b.txt"), Some(&b"bravo"[..]), 15).await,
        "the files of a folder moved in reach the server: {:?}",
        remote_files(&sftp, &remote).await
    );
    assert_eq!(remote_content(&sftp, &format!("{remote}/proj/a.txt")).await.as_deref(), Some(&b"alpha"[..]));

    // Renamed inside the mirror: the new name gets the files too (the old
    // one goes to the trash, soft delete being on).
    std::fs::rename(local.join("proj"), local.join("renamed")).unwrap();
    assert!(
        remote_becomes(&sftp, &format!("{remote}/renamed/sub/b.txt"), Some(&b"bravo"[..]), 15).await,
        "the files of a renamed folder reach the server: {:?}",
        remote_files(&sftp, &remote).await
    );
    assert_eq!(remote_content(&sftp, &format!("{remote}/renamed/a.txt")).await.as_deref(), Some(&b"alpha"[..]));

    crate::mirror::stop(&map, &id).await.unwrap();
    let _ = std::fs::remove_dir_all(&local);
    let _ = std::fs::remove_dir_all(&outside);
}

/// N-023 (review of batch 11): only a folder that is new on the server is
/// walked. Any other event on a folder (a chmod here; on Windows, a change of
/// an entry inside it) leaves its files to their own events, so a newer
/// server copy is not overwritten by a walk.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_an_event_on_an_existing_folder_walks_nothing() {
    let (_handle, sftp) = sftp_session().await;
    let remote = fresh_dir(&sftp, "mirror-existing-folder").await;
    let local = local_dir("existing-folder");
    std::fs::create_dir_all(local.join("keep")).unwrap();
    let x = local.join("keep/x.txt");
    std::fs::write(&x, b"local v1").unwrap();
    filetime::set_file_mtime(&x, filetime::FileTime::from_unix_time(1_000_000_000, 0)).unwrap();
    let (map, id, seen) = running_mirror(mirror_spec(&local, &remote)).await;
    assert_eq!(remote_content(&sftp, &format!("{remote}/keep/x.txt")).await.as_deref(), Some(&b"local v1"[..]));
    put(&sftp, &format!("{remote}/keep/x.txt"), b"edited on the server").await;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(local.join("keep"), std::fs::Permissions::from_mode(0o750)).unwrap();
    }
    std::fs::write(local.join("keep/new.txt"), b"new").unwrap();
    assert!(
        remote_becomes(&sftp, &format!("{remote}/keep/new.txt"), Some(&b"new"[..]), 15).await,
        "the new file is uploaded by its own event: {:?}",
        seen.lock().unwrap().logs
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        remote_content(&sftp, &format!("{remote}/keep/x.txt")).await.as_deref(),
        Some(&b"edited on the server"[..]),
        "the folder event did not walk the folder"
    );

    crate::mirror::stop(&map, &id).await.unwrap();
    let _ = std::fs::remove_dir_all(&local);
}

/// F-007: the mirror replaces server files through the shared helper: the
/// mode and a link survive, nothing is left beside them, and (owner) the
/// version an initial sync replaces is kept in the trash; a file the mirror
/// creates gets the local file's mode.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_keeps_mode_links_and_the_replaced_version() {
    let (_handle, sftp) = sftp_session().await;
    let target_dir = fresh_dir(&sftp, "mirror-identity-target").await;
    put(&sftp, &format!("{target_dir}/real.conf"), b"old").await;
    let remote = fresh_dir(&sftp, "mirror-identity").await;
    put(&sftp, &format!("{remote}/tool.sh"), b"#!/bin/sh\necho old\n").await;
    sftp.set_metadata(format!("{remote}/tool.sh"), crate::mode_change(0o754)).await.unwrap();
    sftp.symlink(format!("{target_dir}/real.conf"), format!("{remote}/link.conf")).await.unwrap();

    let local = local_dir("identity");
    std::fs::write(local.join("tool.sh"), b"#!/bin/sh\necho new and longer\n").unwrap();
    std::fs::write(local.join("link.conf"), b"new through the link").unwrap();
    std::fs::write(local.join("new.sh"), b"#!/bin/sh\n").unwrap();
    std::fs::write(local.join("secret.txt"), b"s3cret").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(local.join("new.sh"), std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::set_permissions(local.join("secret.txt"), std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let (map, id, _seen) = running_mirror(mirror_spec(&local, &remote)).await;
    let mode = |m: russh_sftp::protocol::FileAttributes| m.permissions.unwrap() & 0o7777;
    assert_eq!(sftp.read(format!("{remote}/tool.sh")).await.unwrap(), b"#!/bin/sh\necho new and longer\n");
    assert_eq!(mode(sftp.metadata(format!("{remote}/tool.sh")).await.unwrap()), 0o754, "the server file keeps its mode");
    assert!(sftp.symlink_metadata(format!("{remote}/link.conf")).await.unwrap().file_type().is_symlink(), "the link stays a link");
    assert_eq!(sftp.read(format!("{target_dir}/real.conf")).await.unwrap(), b"new through the link");
    #[cfg(unix)]
    {
        assert_eq!(mode(sftp.metadata(format!("{remote}/new.sh")).await.unwrap()), 0o750, "a new file gets the local mode");
        assert_eq!(mode(sftp.metadata(format!("{remote}/secret.txt")).await.unwrap()), 0o600);
    }
    let kept = remote_files(&sftp, &format!("{remote}/.solanum-trash")).await;
    assert!(kept.iter().any(|p| p.ends_with("/tool.sh")), "the replaced server version is in the trash: {kept:?}");
    let kept_tool = kept.iter().find(|p| p.ends_with("/tool.sh")).unwrap();
    assert_eq!(sftp.read(format!("{remote}/.solanum-trash/{kept_tool}")).await.unwrap(), b"#!/bin/sh\necho old\n");
    assert_eq!(listing(&sftp, &remote).await, vec![".solanum-trash", "link.conf", "new.sh", "secret.txt", "tool.sh"], "nothing left beside the files");

    // A watcher upload: same rules, and no copy of your own previous upload.
    std::fs::write(local.join("tool.sh"), b"#!/bin/sh\necho third\n").unwrap();
    assert!(remote_becomes(&sftp, &format!("{remote}/tool.sh"), Some(b"#!/bin/sh\necho third\n"), 20).await);
    assert_eq!(mode(sftp.metadata(format!("{remote}/tool.sh")).await.unwrap()), 0o754);
    assert_eq!(remote_files(&sftp, &format!("{remote}/.solanum-trash")).await.len(), kept.len(), "watcher uploads keep no copies");
    assert_eq!(listing(&sftp, &remote).await, vec![".solanum-trash", "link.conf", "new.sh", "secret.txt", "tool.sh"]);

    crate::mirror::stop(&map, &id).await.unwrap();
    let _ = std::fs::remove_dir_all(&local);
}

/// F-046: an uploaded file gets the local modification time, so the next
/// start sees it as in sync without reading it again.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_stamps_uploads_with_the_local_mtime() {
    let (_handle, sftp) = sftp_session().await;
    let remote = fresh_dir(&sftp, "mirror-mtime").await;
    let local = local_dir("mtime");
    std::fs::write(local.join("dated.txt"), b"from 2001").unwrap();
    filetime::set_file_mtime(local.join("dated.txt"), filetime::FileTime::from_unix_time(1_000_000_000, 0)).unwrap();

    let (map, id, _seen) = running_mirror(mirror_spec(&local, &remote)).await;
    assert_eq!(sftp.metadata(format!("{remote}/dated.txt")).await.unwrap().mtime, Some(1_000_000_000));

    std::fs::write(local.join("later.txt"), b"later").unwrap();
    filetime::set_file_mtime(local.join("later.txt"), filetime::FileTime::from_unix_time(1_100_000_000, 0)).unwrap();
    let later = format!("{remote}/later.txt");
    let mut stamped = false;
    for _ in 0..200 {
        if sftp.metadata(&later).await.ok().and_then(|m| m.mtime) == Some(1_100_000_000) {
            stamped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(stamped, "a watcher upload is stamped too");
    crate::mirror::stop(&map, &id).await.unwrap();

    // A second start finds nothing to do.
    let handle = Arc::new(tokio::sync::Mutex::new(logged_in(MODERN, false).await));
    let report = crate::mirror::dry_run(handle, mirror_spec(&local, &remote)).await.unwrap();
    assert!(report.entries.is_empty(), "{:?}", report.entries);
    let _ = std::fs::remove_dir_all(&local);
}

/// F-046: a server file the mirror cannot check (here: in a folder the user
/// may not search) is left alone and reported, never treated as missing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_leaves_alone_what_it_could_not_check() {
    let (_handle, sftp) = sftp_session().await;
    let _ = sftp.set_metadata("/tmp/solanum-live-mirror-unreadable/locked", crate::mode_change(0o755)).await;
    let remote = fresh_dir(&sftp, "mirror-unreadable").await;
    let locked = format!("{remote}/locked");
    sftp.create_dir(&locked).await.unwrap();
    put(&sftp, &format!("{locked}/x.txt"), b"server copy").await;
    sftp.set_metadata(&locked, crate::mode_change(0o000)).await.unwrap();

    let local = local_dir("unreadable");
    std::fs::create_dir_all(local.join("locked")).unwrap();
    std::fs::write(local.join("locked/x.txt"), b"local copy, longer").unwrap();
    std::fs::write(local.join("plain.txt"), b"plain").unwrap();

    let handle = Arc::new(tokio::sync::Mutex::new(logged_in(MODERN, false).await));
    let report = crate::mirror::dry_run(handle, mirror_spec(&local, &remote)).await;
    sftp.set_metadata(&locked, crate::mode_change(0o755)).await.unwrap();
    let report = report.unwrap();
    assert!(
        !report.entries.iter().any(|e| e.path == "locked/x.txt"),
        "a file that could not be checked is not uploaded over: {:?}",
        report.entries
    );
    assert!(report.entries.iter().any(|e| e.path == "plain.txt" && e.action == "upload-new"));
    assert!(
        report.problems.iter().any(|p| p.path == "locked/x.txt" && p.reason.contains("could not check")),
        "and it is reported: {:?}",
        report.problems
    );
    let _ = std::fs::remove_dir_all(&local);
}

/// F-047: a soft delete keeps the file's relative path in the trash, and a
/// folder removed in one go lands in one place.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_trash_keeps_the_relative_path() {
    let (_handle, sftp) = sftp_session().await;
    let remote = fresh_dir(&sftp, "mirror-trash").await;
    let local = local_dir("trash");
    std::fs::create_dir_all(local.join("sub/deep")).unwrap();
    std::fs::write(local.join("sub/deep/file.txt"), b"file").unwrap();
    std::fs::write(local.join("sub/deep/keep.txt"), b"keep").unwrap();
    std::fs::create_dir_all(local.join("gone/inner")).unwrap();
    for f in ["gone/a.txt", "gone/b.txt", "gone/inner/c.txt"] {
        std::fs::write(local.join(f), f.as_bytes()).unwrap();
    }
    let (map, id, _seen) = running_mirror(mirror_spec(&local, &remote)).await;

    std::fs::remove_file(local.join("sub/deep/file.txt")).unwrap();
    assert!(remote_becomes(&sftp, &format!("{remote}/sub/deep/file.txt"), None, 20).await);
    let trash = format!("{remote}/.solanum-trash");
    let kept = remote_files(&sftp, &trash).await;
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert!(kept[0].ends_with("/sub/deep/file.txt"), "the relative path is kept: {kept:?}");

    std::fs::remove_dir_all(local.join("gone")).unwrap();
    assert!(remote_becomes(&sftp, &format!("{remote}/gone/a.txt"), None, 20).await);
    tokio::time::sleep(Duration::from_secs(2)).await;
    let kept: Vec<String> = remote_files(&sftp, &trash).await.into_iter().filter(|p| !p.ends_with("/sub/deep/file.txt")).collect();
    let stamps: std::collections::BTreeSet<&str> = kept.iter().map(|p| p.split('/').next().unwrap()).collect();
    assert_eq!(stamps.len(), 1, "one removal, one trash folder: {kept:?}");
    let stamp = stamps.iter().next().unwrap();
    assert_eq!(kept, vec![format!("{stamp}/gone/a.txt"), format!("{stamp}/gone/b.txt"), format!("{stamp}/gone/inner/c.txt")]);
    assert_eq!(sftp.read(format!("{remote}/sub/deep/keep.txt")).await.unwrap(), b"keep");

    crate::mirror::stop(&map, &id).await.unwrap();
    let _ = std::fs::remove_dir_all(&local);
}

/// F-047: a download that fails half way (here: a server link to a folder,
/// listed as a file, whose read fails) leaves no temporary file behind.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_failed_download_leaves_no_temporary_file() {
    let (_handle, sftp) = sftp_session().await;
    let remote = fresh_dir(&sftp, "mirror-faildown").await;
    sftp.create_dir(format!("{remote}/realdir")).await.unwrap();
    put(&sftp, &format!("{remote}/realdir/f.txt"), b"f").await;
    sftp.symlink(format!("{remote}/realdir"), format!("{remote}/dirlink")).await.unwrap();
    // A hostile server's link to an endless device must not fill the disk.
    sftp.symlink("/dev/zero", format!("{remote}/zero")).await.unwrap();
    let local = local_dir("faildown");

    let (map, id, seen) = running_mirror(mirror_spec(&local, &remote)).await;
    for name in ["dirlink", "zero"] {
        assert!(
            seen.lock().unwrap().logs.iter().any(|(event, path, message)| event == "download-fail"
                && path.as_deref() == Some(name)
                && message.as_deref().is_some_and(|m| m.contains("not a regular file"))),
            "{name}: {:?}",
            seen.lock().unwrap().logs
        );
    }
    assert_eq!(local_files(&local), vec!["realdir/f.txt"], "nothing but the real file");
    crate::mirror::stop(&map, &id).await.unwrap();
    let _ = std::fs::remove_dir_all(&local);
}

/// F-008 and N-018: a link inside the mirrored folder is never written
/// through by a download nor read through by the watcher.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_never_goes_through_a_local_link() {
    let (_handle, sftp) = sftp_session().await;
    let remote = fresh_dir(&sftp, "mirror-locallink").await;
    sftp.create_dir(format!("{remote}/linkdir")).await.unwrap();
    put(&sftp, &format!("{remote}/linkdir/planted.txt"), b"from the server").await;
    let outside = local_dir("locallink-outside");
    let local = local_dir("locallink");
    std::os::unix::fs::symlink(&outside, local.join("linkdir")).unwrap();

    let (map, id, _seen) = running_mirror(mirror_spec(&local, &remote)).await;
    assert!(!outside.join("planted.txt").exists(), "a download does not land outside the mirrored folder");

    std::fs::write(outside.join("secret.txt"), b"not for the server").unwrap();
    std::fs::write(local.join("ok.txt"), b"ok").unwrap();
    assert!(remote_becomes(&sftp, &format!("{remote}/ok.txt"), Some(b"ok"), 20).await, "the watcher runs");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(remote_content(&sftp, &format!("{remote}/linkdir/secret.txt")).await, None, "nothing behind the link is uploaded");

    crate::mirror::stop(&map, &id).await.unwrap();
    let _ = std::fs::remove_dir_all(&local);
    let _ = std::fs::remove_dir_all(&outside);
}

/// F-008: many local deletions at once are held, not propagated.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_pauses_on_a_mass_delete() {
    let (_handle, sftp) = sftp_session().await;
    let remote = fresh_dir(&sftp, "mirror-massdel").await;
    let local = local_dir("massdel");
    std::fs::write(local.join("keep.txt"), b"keep").unwrap();
    std::fs::write(local.join("extra.txt"), b"extra").unwrap();
    for i in 0..60 {
        std::fs::write(local.join(format!("f{i:02}.txt")), format!("{i}")).unwrap();
    }
    let (map, id, seen) = running_mirror(mirror_spec(&local, &remote)).await;
    assert_eq!(remote_files(&sftp, &remote).await.len(), 62);

    for i in 0..60 {
        std::fs::remove_file(local.join(format!("f{i:02}.txt"))).unwrap();
    }
    let held = || seen.lock().unwrap().last.as_ref().map(|s| (s.state.clone(), s.held_deletes));
    assert!(within(10, || held() == Some(("paused".into(), 60))).await, "paused with 60 held: {:?}", held());
    tokio::time::sleep(Duration::from_secs(1)).await;
    let left: Vec<String> = remote_files(&sftp, &remote).await.into_iter().filter(|p| !p.starts_with(".solanum-trash")).collect();
    assert_eq!(left.len(), 62, "nothing is deleted on the server yet");

    // Uploads go on while deletions are held; more deletions join the held ones.
    std::fs::write(local.join("new.txt"), b"new").unwrap();
    assert!(remote_becomes(&sftp, &format!("{remote}/new.txt"), Some(b"new"), 20).await);
    std::fs::remove_file(local.join("extra.txt")).unwrap();
    assert!(within(10, || held() == Some(("paused".into(), 61))).await, "61 held: {:?}", held());
    // A held path that exists again is not deleted by Resume.
    std::fs::write(local.join("f00.txt"), b"back").unwrap();
    assert!(remote_becomes(&sftp, &format!("{remote}/f00.txt"), Some(b"back"), 20).await);

    crate::mirror::resume(&map, &id).await.unwrap();
    let mut applied = false;
    for _ in 0..200 {
        let left: Vec<String> = remote_files(&sftp, &remote).await.into_iter().filter(|p| !p.starts_with(".solanum-trash")).collect();
        if left == ["f00.txt", "keep.txt", "new.txt"] {
            applied = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(applied, "Resume applies the held deletions, except the path that came back");
    assert_eq!(sftp.read(format!("{remote}/f00.txt")).await.unwrap(), b"back");
    assert_eq!(remote_files(&sftp, &format!("{remote}/.solanum-trash")).await.len(), 60, "into the trash");
    assert_eq!(held(), Some(("watching".into(), 0)));
    assert!(crate::mirror::resume(&map, &id).await.is_err(), "nothing to resume any more");

    crate::mirror::stop(&map, &id).await.unwrap();
    let _ = std::fs::remove_dir_all(&local);
}

/// F-008: a local folder that disappears (unmounted, renamed, deleted) does
/// not empty the server folder.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_pauses_when_the_local_folder_goes() {
    let (_handle, sftp) = sftp_session().await;
    let remote = fresh_dir(&sftp, "mirror-rootgone").await;
    let local = local_dir("rootgone");
    for f in ["a.txt", "b.txt", "c.txt"] {
        std::fs::write(local.join(f), f).unwrap();
    }
    let (map, id, seen) = running_mirror(mirror_spec(&local, &remote)).await;
    std::fs::remove_dir_all(&local).unwrap();
    let paused = || seen.lock().unwrap().last.as_ref().is_some_and(|s| s.state == "paused" && s.pause_reason.as_deref().is_some_and(|r| r.contains("gone")));
    assert!(within(10, paused).await, "{:?}", seen.lock().unwrap().last);
    // Resume is refused while the folder is still missing.
    crate::mirror::resume(&map, &id).await.unwrap();
    assert!(within(10, || seen.lock().unwrap().logs.iter().any(|(event, _, _)| event == "resume-refused")).await);
    tokio::time::sleep(Duration::from_secs(1)).await;
    let left: Vec<String> = remote_files(&sftp, &remote).await.into_iter().filter(|p| !p.starts_with(".solanum-trash")).collect();
    assert_eq!(left, vec!["a.txt", "b.txt", "c.txt"], "the server keeps everything");
    crate::mirror::stop(&map, &id).await.unwrap();
    assert!(
        seen.lock().unwrap().logs.iter().any(|(event, _, _)| event == "held-discarded"),
        "Stop says the held deletions were not applied"
    );
}

/// A TCP relay to a fixture that can freeze the link: the connection stays
/// open but no byte gets through, which is what a dead network path looks
/// like to both ends.
struct FreezableLink {
    port: u16,
    frozen: Arc<std::sync::atomic::AtomicBool>,
}

async fn freezable_link_to(target: u16) -> FreezableLink {
    use std::sync::atomic::{AtomicBool, Ordering};
    async fn pump(
        mut from: tokio::net::tcp::OwnedReadHalf,
        mut to: tokio::net::tcp::OwnedWriteHalf,
        frozen: Arc<AtomicBool>,
    ) {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match from.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            while frozen.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if to.write_all(&buf[..n]).await.is_err() {
                return;
            }
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let frozen = Arc::new(AtomicBool::new(false));
    let f = Arc::clone(&frozen);
    tokio::spawn(async move {
        let (inbound, _) = listener.accept().await.unwrap();
        let outbound = tokio::net::TcpStream::connect(("127.0.0.1", target)).await.unwrap();
        let (in_r, in_w) = inbound.into_split();
        let (out_r, out_w) = outbound.into_split();
        tokio::spawn(pump(in_r, out_w, Arc::clone(&f)));
        tokio::spawn(pump(out_r, in_w, f));
    });
    FreezableLink { port, frozen }
}

/// F-009: Stop returns promptly while the mirror waits on a dead link (every
/// SFTP request there waits for russh-sftp's 10 s timeout).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_stop_returns_on_a_frozen_link() {
    let (_handle, sftp) = sftp_session().await;
    let remote = fresh_dir(&sftp, "mirror-frozen").await;
    let local = local_dir("frozen");
    std::fs::write(local.join("first.txt"), b"first").unwrap();

    let link = freezable_link_to(MODERN).await;
    let (handle, _) = connect_config(link.port, false, build_ssh_client_config(&AlgorithmPolicy::default())).await;
    let mut handle = handle;
    assert!(handle.authenticate_password(USER, PASSWORD).await.unwrap().success());
    let map: crate::mirror::MirrorMap = Arc::default();
    let (events, seen) = mirror_recorder();
    let id = crate::mirror::start(events, "s1".into(), Arc::new(tokio::sync::Mutex::new(handle)), Arc::clone(&map), mirror_spec(&local, &remote))
        .await
        .unwrap();
    assert!(within(30, || seen.lock().unwrap().states.iter().any(|s| s == "watching")).await);

    link.frozen.store(true, std::sync::atomic::Ordering::SeqCst);
    for i in 0..3 {
        std::fs::write(local.join(format!("queued{i}.txt")), b"queued").unwrap();
    }
    // Debounce (0.5 s), then the worker is inside its first event.
    let busy = || seen.lock().unwrap().last.as_ref().is_some_and(|s| s.queue_depth > 0);
    assert!(within(10, busy).await, "the worker is working on the queued events");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let started = std::time::Instant::now();
    let stopped = tokio::time::timeout(Duration::from_secs(90), crate::mirror::stop(&map, &id)).await;
    let took = started.elapsed();
    assert!(stopped.is_ok(), "stop returns");
    assert!(took < Duration::from_secs(6), "stop took {took:?}");

    // The link comes back: the upload that was under way sees the stop and
    // cleans up after itself; the queued ones never start.
    link.frozen.store(false, std::sync::atomic::Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(5)).await;
    let names = listing(&sftp, &remote).await;
    assert!(!names.iter().any(|n| n.contains(".solanum-part") || n.contains(".solanum-old")), "{names:?}");
    assert!(!names.iter().any(|n| n == "queued1.txt" || n == "queued2.txt"), "{names:?}");
    let _ = std::fs::remove_dir_all(&local);
}

/// Review of batch 8: a stop during the initial sync leaves the server file
/// whole: the upload under way removes its part file, nothing is aborted
/// between the renames of a replace.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_stop_during_the_initial_sync_leaves_the_server_file_whole() {
    let (_handle, sftp) = sftp_session().await;
    let remote = fresh_dir(&sftp, "mirror-stop-sync").await;
    put(&sftp, &format!("{remote}/big.bin"), b"old version").await;
    let local = local_dir("stop-sync");
    let big = std::fs::File::create(local.join("big.bin")).unwrap();
    big.set_len(300 * 1024 * 1024).unwrap();
    drop(big);

    let handle = Arc::new(tokio::sync::Mutex::new(logged_in(MODERN, false).await));
    let map: crate::mirror::MirrorMap = Arc::default();
    let (events, seen) = mirror_recorder();
    let id = crate::mirror::start(events, "s1".into(), handle, Arc::clone(&map), mirror_spec(&local, &remote)).await.unwrap();
    assert!(within(30, || seen.lock().unwrap().states.iter().any(|s| s == "initial-sync")).await);
    let started = std::time::Instant::now();
    crate::mirror::stop(&map, &id).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(6), "stop took {:?}", started.elapsed());

    tokio::time::sleep(Duration::from_secs(3)).await;
    let names: Vec<String> = listing(&sftp, &remote).await.into_iter().filter(|n| n != ".solanum-trash").collect();
    assert_eq!(names, vec!["big.bin"], "no part or aside file left");
    let size = sftp.metadata(format!("{remote}/big.bin")).await.unwrap().size;
    assert!(
        size == Some(11) || size == Some(300 * 1024 * 1024),
        "the server file is the old one or the whole new one, never part of it: {size:?}"
    );
    let _ = std::fs::remove_dir_all(&local);
}

/// The key exchange against a real server offering what the switch offers:
/// ECDH, whatever the legacy setting says.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_ecdh_wins_over_sha1_key_exchange() {
    use crate::ssh_test_server::TestClient;
    for legacy in [true, false] {
        let (handler, _) = TestClient::new();
        let negotiated = Arc::clone(&handler.negotiated_kex);
        let config = build_ssh_client_config(&AlgorithmPolicy { legacy, ..AlgorithmPolicy::default() });
        let _handle = client::connect(Arc::new(config), ("127.0.0.1", ECDH_AND_SHA1_KEX), handler).await.expect("handshake");
        assert_eq!(negotiated.lock().unwrap().as_deref(), Some("ecdh-sha2-nistp256"), "legacy setting {legacy}");
    }
}

/// Reads a shell until `text` appears, and says whether it did.
async fn shell_prints(shell: &mut russh::Channel<client::Msg>, text: &str) -> bool {
    let wait = async {
        let mut output = Vec::new();
        while let Some(message) = shell.wait().await {
            if let ChannelMsg::Data { data } = message {
                output.extend_from_slice(&data);
                if String::from_utf8_lossy(&output).contains(text) {
                    return true;
                }
            }
        }
        false
    };
    tokio::time::timeout(Duration::from_secs(10), wait).await.unwrap_or(false)
}

/// Real OpenSSH refusing a second session (`MaxSessions 1`), the same refusal
/// the switch gives: the feature is off for this connection, nothing asks
/// again, and the shell and the connection carry on.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_host_with_one_session_keeps_its_terminal() {
    use crate::ssh_connect::{open_terminal_channel, probe_alive, ChannelGate, TerminalOnly};
    let handle = tokio::sync::Mutex::new(logged_in(ONE_SESSION, false).await);
    let gate = ChannelGate::default();
    let mut shell = open_terminal_channel(&handle, &gate).await.unwrap();
    shell.request_pty(false, "xterm-256color", 80, 24, 0, 0, &[]).await.unwrap();
    shell.request_shell(true).await.unwrap();

    let refused = crate::info_script_on(&handle, &gate, crate::monitor::BUILTIN_PROBE, 10).await;
    assert_eq!(refused.err().as_deref(), Some(TerminalOnly::RefusedChannel.refusal()));
    assert_eq!(gate.limit(), Some(TerminalOnly::RefusedChannel));
    assert!(crate::open_sftp_on(&handle, &gate).await.is_err());

    assert!(probe_alive(&handle, Duration::from_secs(5)).await);
    assert!(!handle.lock().await.is_closed());
    shell.data(&b"echo alive-$((40+2))\n"[..]).await.unwrap();
    assert!(shell_prints(&mut shell, "alive-42").await, "the shell still answers");
}

/// N-028: what OpenSSH does when a shell exits. It closes that channel and
/// keeps the connection, which is why Solanum closes the connection itself
/// once the session's last terminal has ended.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_shell_that_exits_ends_its_terminal_and_leaves_the_connection() {
    use crate::terminal_io::{pump, Ended, SshTerminal};
    let handle = tokio::sync::Mutex::new(logged_in(MODERN, false).await);
    let shell = crate::ssh_connect::open_session_channel(&handle).await.unwrap();
    shell.request_pty(false, "xterm-256color", 80, 24, 0, 0, &[]).await.unwrap();
    shell.request_shell(true).await.unwrap();
    let (keys, input) = tokio::sync::mpsc::channel(32);
    let (_sizes, sizes) = tokio::sync::watch::channel(crate::ssh_manager::PtySize { cols: 80, rows: 24 });
    let running = tokio::spawn(pump(SshTerminal::new(shell), input, sizes, None, |_: &[u8]| {}));
    keys.send(crate::ssh_manager::TerminalCommand::Data(b"exit\n".to_vec())).await.unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(10), running).await.expect("the shell did not end").unwrap();
    assert_eq!(ended, Ended::ByPeer, "the server closed the shell's channel");
    assert!(!handle.lock().await.is_closed(), "OpenSSH keeps the connection: closing it is the client's job");
    assert!(crate::ssh_connect::probe_alive(&handle, Duration::from_secs(5)).await);
}

/// A normal host changes nothing: the terminal and every feature beside it
/// run at once, and the connection is not marked.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_normal_host_keeps_every_feature() {
    use crate::ssh_connect::{open_terminal_channel, ChannelGate};
    let handle = tokio::sync::Mutex::new(logged_in(MODERN, false).await);
    let gate = ChannelGate::default();
    let mut shell = open_terminal_channel(&handle, &gate).await.unwrap();
    shell.request_pty(false, "xterm-256color", 80, 24, 0, 0, &[]).await.unwrap();
    shell.request_shell(true).await.unwrap();

    let live = crate::info_script_on(&handle, &gate, crate::monitor::BUILTIN_PROBE, 20).await.expect("live info");
    assert!(!live.data.is_empty());
    let docker = crate::docker::run_capture_on(&handle, &gate, "echo docker-ok", 20, crate::docker::Keep::Head).await.expect("Docker helper");
    assert!(docker.text.contains("docker-ok"));
    let sftp = crate::open_sftp_on(&handle, &gate).await.expect("SFTP browser");
    assert!(sftp.canonicalize(".").await.is_ok());
    assert_eq!(gate.limit(), None);

    shell.data(&b"echo alive-$((40+2))\n"[..]).await.unwrap();
    assert!(shell_prints(&mut shell, "alive-42").await);
}

/// N-022: with soft delete off, a folder deleted locally goes on the server
/// too. OpenSSH answers `remove` on a folder with a bare "Failure".
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_mirror_hard_delete_removes_a_folder() {
    let (_handle, sftp) = sftp_session().await;
    let remote = fresh_dir(&sftp, "mirror-harddel").await;
    let local = local_dir("harddel");
    std::fs::create_dir_all(local.join("gone/inner")).unwrap();
    std::fs::write(local.join("gone/a.txt"), b"a").unwrap();
    std::fs::write(local.join("gone/inner/b.txt"), b"b").unwrap();
    std::fs::write(local.join("keep.txt"), b"keep").unwrap();
    let mut spec = mirror_spec(&local, &remote);
    spec.soft_delete = false;
    let (map, id, seen) = running_mirror(spec).await;
    assert_eq!(remote_files(&sftp, &remote).await, vec!["gone/a.txt", "gone/inner/b.txt", "keep.txt"]);

    std::fs::remove_dir_all(local.join("gone")).unwrap();
    let gone = format!("{remote}/gone");
    let mut removed = false;
    for _ in 0..200 {
        if sftp.symlink_metadata(&gone).await.is_err() {
            removed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(removed, "the folder is removed on the server: {:?}", seen.lock().unwrap().logs);
    assert_eq!(listing(&sftp, &remote).await, vec!["keep.txt"], "and nothing goes to a trash");
    crate::mirror::stop(&map, &id).await.unwrap();
    let _ = std::fs::remove_dir_all(&local);
}

// ---------------------------------------------------------------------------
// Remote scripts (F-071, F-072)
// ---------------------------------------------------------------------------

/// Login shells of the fixture's users: bash, tcsh and fish.
const SHELL_USERS: [&str; 3] = [USER, "cshuser", "fishuser"];

async fn logged_in_as(port: u16, user: &str) -> client::Handle<Probe> {
    let (mut handle, _) = connect_with(port, false).await;
    assert!(handle.authenticate_password(user, PASSWORD).await.unwrap().success(), "{user} logs in");
    handle
}

/// F-071: the probes, Info scripts, Docker commands and service actions are
/// POSIX sh scripts; they must give the same results whatever the account's
/// login shell is (sshd runs an `exec` request through it).
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_scripts_run_in_sh_whatever_the_login_shell() {
    use crate::monitor::{parse_probe, poll_once, CustomMetric, BUILTIN_PROBE};
    for user in SHELL_USERS {
        let handle = logged_in_as(MODERN, user).await;
        let custom = CustomMetric {
            id: "m".into(),
            name: "m".into(),
            command: "echo 42".into(),
            parse: "number".into(),
            regex: None,
            display: "sparkline".into(),
            unit: None,
        };
        let snap = poll_once(&handle, &[custom], Duration::from_secs(20)).await.expect("monitor probe");
        assert!(snap.mem_total_kb > 0 && snap.disk_total_kb > 0, "{user}: monitor probe {snap:?}");
        assert_eq!(snap.custom_text.get("m").map(String::as_str), Some("42"), "{user}: custom metric");

        let shared = tokio::sync::Mutex::new(handle);
        let live = crate::info_script_on(&shared, &Default::default(), BUILTIN_PROBE, 20).await.expect("live strip");
        let live = parse_probe(&live.data).unwrap();
        assert!(live.mem_total_kb > 0, "{user}: live strip");
        let overview = crate::info_script_on(&shared, &Default::default(), crate::INFO_SCRIPT_OVERVIEW, 20).await.expect("overview");
        assert!(overview.data.contains("MEMFMT:") && overview.data.contains("DFFMT:"), "{user}: overview {:?}", overview.data);

        let docker = crate::docker::run_capture_on(&shared, &Default::default(), "x=$(echo hello); echo \"$x\"; (exit 3)", 20, crate::docker::Keep::Head)
            .await
            .expect("docker-style command");
        assert_eq!((docker.code, docker.text.as_str()), (3, "hello"), "{user}: docker-style command");

        let action = crate::exec_capture_on(&shared, &Default::default(), "OUT=$(echo fw); printf '%s' \"$OUT\"; echo __SUB_EXITCODE:$?", 20, Some(crate::EXIT_MARKER))
            .await
            .expect("service-style command");
        assert_eq!((action.exit, action.text.as_str()), (Some(0), "fw"), "{user}: service-style command");
    }
}

/// F-072: an output over the cap keeps its exit code, says it was cut, and
/// keeps the end that matters (the newest lines of a log).
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_long_output_keeps_its_exit_code_and_the_right_end() {
    use crate::docker::{run_capture_on, Keep};
    let shared = tokio::sync::Mutex::new(logged_in(MODERN, false).await);
    let tail = run_capture_on(&shared, &Default::default(), "seq 1 1000000", 60, Keep::Tail).await.unwrap();
    assert_eq!(tail.code, 0, "exit status kept");
    assert!(tail.truncated, "cut");
    assert!(tail.text.ends_with("\n1000000"), "newest lines kept: ...{:?}", &tail.text[tail.text.len().saturating_sub(40)..]);
    let head = run_capture_on(&shared, &Default::default(), "seq 1 1000000", 60, Keep::Head).await.unwrap();
    assert_eq!((head.code, head.truncated), (0, true));
    assert!(head.text.starts_with("1\n2\n3\n"));

    let action = crate::exec_capture_on(&shared, &Default::default(), "seq 1 100000; echo __SUB_EXITCODE:$?", 60, Some(crate::EXIT_MARKER)).await.unwrap();
    assert_eq!((action.exit, action.truncated), (Some(0), true), "a long service action is not a failure");
    assert!(crate::action_outcome(action).1.ends_with("(output cut at 64 KiB)"));
}

/// Not published: only reachable from inside the fixture container, i.e.
/// through a jump host.
const INTERNAL_ONLY: u16 = 2299;

/// F-062: a monitor for a server behind a jump host goes through the jump
/// host, as a session does (resolved from the vault, the real connector).
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_monitor_reaches_a_server_behind_its_jump_host() {
    let conn = crate::open_vault_memory_db().unwrap();
    crate::create_vault_schema(&conn).unwrap();
    conn.execute_batch(&format!(
        "INSERT INTO servers(id,name,host,port,username,password,auth_type) VALUES (1,'bastion','127.0.0.1',{MODERN},'{USER}','{PASSWORD}','custom_password');
         INSERT INTO servers(id,name,host,port,username,password,auth_type,jump_host_id) VALUES (2,'inner','127.0.0.1',{INTERNAL_ONLY},'{USER}','{PASSWORD}','custom_password',1);"
    ))
    .unwrap();
    for (label, fp) in server_host_keys() {
        for port in [MODERN, INTERNAL_ONLY] {
            conn.execute(
                "INSERT INTO known_hosts (host, port, fingerprint, key_type) VALUES ('127.0.0.1', ?1, ?2, ?3)",
                rusqlite::params![port, fp, label],
            )
            .unwrap();
        }
    }
    let auth = crate::resolve_node_auth_for_monitor(&conn, 2).expect("resolves");
    let db = Arc::new(std::sync::Mutex::new(Some(conn)));
    let connect = crate::monitor::network_connector(db);
    let link = match connect(auth, Duration::from_secs(10)).await {
        Ok(link) => link,
        Err(e) => panic!("the monitor connects through the jump host: {e:?}"),
    };
    let snap = crate::monitor::poll_once(link.session(), &[], Duration::from_secs(20)).await.expect("polls");
    assert!(snap.mem_total_kb > 0, "{snap:?}");
}

/// F-071 with F-041: a live log started the way `ssh_docker_logs_start` starts
/// it (a script under `remote_exec`'s sh, so the command is not the session's
/// own process) is still ended on the server by its Stop, for a bash and a
/// tcsh login shell: sshd signals the session's whole process group.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_log_stream_started_as_a_script_is_ended_by_stop() {
    use rand::Rng;
    for user in [USER, "cshuser"] {
        let control = logged_in(MODERN, false).await;
        let handle = Arc::new(tokio::sync::Mutex::new(logged_in_as(MODERN, user).await));
        let m = format!("/tmp/solanum-f071-{:012x}", rand::thread_rng().gen::<u64>() & 0xffff_ffff_ffff);
        let (head, tail) = m.split_at(1);
        let running = format!("grep -l '[{head}]{tail}' /proc/[0-9]*/cmdline 2>/dev/null; true");

        let channel = crate::ssh_connect::open_session_channel(&handle).await.unwrap();
        crate::remote_exec::send_script(&channel, &format!("touch {m}; tail -f {m} 2>&1")).await.unwrap();
        let streams = crate::docker::DockerStreams::new();
        let sink = crate::docker::LogSink { text: Box::new(|_| {}), closed: Box::new(|| {}) };
        streams.start("logs".into(), "session-1".into(), channel, sink).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!exec_output(&control, &running).await.trim().is_empty(), "{user}: the command runs");

        streams.stop_session("session-1").await;
        let mut gone = false;
        for _ in 0..25 {
            if exec_output(&control, &running).await.trim().is_empty() {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let cleanup = format!(
            "for f in $({}); do p=${{f#/proc/}}; kill ${{p%/cmdline}}; done; rm -f {m}",
            running.trim_end_matches("; true")
        );
        exec_output(&control, &cleanup).await;
        assert!(gone, "{user}: a stopped log stream's command is ended on the server");
    }
}

/// F-017: a key the server accepts as one step of two (`publickey,
/// keyboard-interactive`) is a login a monitor cannot finish: it stops at
/// once instead of counting three refusals.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_monitor_stops_at_once_when_the_server_wants_a_second_step() {
    use crate::monitor::{establish, prepare_login, ConnectError, NodeAuth};
    let conn = crate::open_vault_memory_db().unwrap();
    crate::create_vault_schema(&conn).unwrap();
    for (label, fp) in server_host_keys() {
        conn.execute(
            "INSERT INTO known_hosts (host, port, fingerprint, key_type) VALUES ('127.0.0.1', ?1, ?2, ?3)",
            rusqlite::params![KEY_THEN_KBI, fp, label],
        )
        .unwrap();
    }
    let db = Arc::new(std::sync::Mutex::new(Some(conn)));
    let auth = NodeAuth {
        host: "127.0.0.1".into(),
        port: KEY_THEN_KBI,
        username: USER.into(),
        password: None,
        private_key: Some(std::fs::read_to_string(fixtures().join("keys/ed25519")).unwrap()),
        passphrase: None,
        proxy_type: "none".into(),
        proxy_host: None,
        proxy_port: None,
        policy: AlgorithmPolicy::default(),
        jump: None,
    };
    let login = prepare_login(&auth).unwrap();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", KEY_THEN_KBI)).await.unwrap();
    match establish(tcp, &db, &auth, login, Duration::from_secs(10)).await {
        Err(ConnectError::NeedsUser(reason)) => assert!(reason.contains("asks for more"), "{reason}"),
        Err(other) => panic!("expected a stop at once, got {other:?}"),
        Ok(_) => panic!("a monitor cannot answer keyboard-interactive"),
    }
}

/// F-031: a terminal whose window acknowledges nothing while its program
/// floods it keeps reading (the window gets its 2 MiB, 4 MiB more are held,
/// the rest is dropped with a notice), so the same SSH connection stays
/// usable: russh tops the window up as data arrives, and a channel nobody
/// reads would stall every other channel on the connection behind it.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_flooded_terminal_keeps_its_connection_usable() {
    use crate::ssh_manager::PtySize;
    let handle = logged_in(MODERN, false).await;
    let channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(false, "xterm-256color", 80, 24, 0, 0, &[]).await.unwrap();
    channel.exec(true, "head -c 24000000 /dev/zero | tr '\\0' a; echo; echo flood-done").await.unwrap();
    let (_input, input_rx) = tokio::sync::mpsc::channel(32);
    let (_sizes, sizes_rx) = tokio::sync::watch::channel(PtySize { cols: 80, rows: 24 });
    let shown = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = Arc::clone(&shown);
    let pump = tokio::spawn(crate::terminal_io::pump(crate::terminal_io::SshTerminal::new(channel), input_rx, sizes_rx, None, move |b: &[u8]| {
        sink.lock().unwrap().extend_from_slice(b)
    }));
    let started = std::time::Instant::now();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let answer = tokio::time::timeout(Duration::from_secs(60), exec_output(&handle, "echo still-here"))
        .await
        .expect("the connection waited on the flooded terminal");
    let answered = started.elapsed();
    assert_eq!(answer.trim(), "still-here");
    tokio::time::timeout(Duration::from_secs(120), pump).await.expect("the flood did not end").unwrap();
    eprintln!("second command answered after {answered:?}, flood over after {:?}", started.elapsed());
    let shown = shown.lock().unwrap();
    let limit = crate::terminal_io::MAX_UNACKED + crate::terminal_io::FLUSH_CAP + crate::terminal_io::BACKLOG_CAP + 4096;
    assert!(shown.len() <= limit, "{} bytes shown", shown.len());
    let text = String::from_utf8_lossy(&shown);
    assert!(text.contains("of output not shown"), "no notice");
    assert!(text.trim_end().ends_with("flood-done"), "the newest output is kept");
}

/// Review of F-031: a big paste into a program that echoes it. While the
/// terminal waits for the server to take more input it must keep reading the
/// echo: otherwise russh's queue for the channel fills, its session loop
/// waits, the server's window adjustment is never read, and the connection
/// stops for good.
#[tokio::test]
#[ignore = "needs the Docker sshd fixtures"]
async fn live_a_big_paste_into_an_echoing_program_does_not_freeze_the_connection() {
    use crate::ssh_manager::{PtySize, TerminalCommand};
    let handle = logged_in(MODERN, false).await;
    let channel = handle.channel_open_session().await.unwrap();
    channel.request_pty(false, "xterm-256color", 80, 24, 0, 0, &[]).await.unwrap();
    channel.exec(true, "cat > /dev/null").await.unwrap();
    let (input, input_rx) = tokio::sync::mpsc::channel(32);
    let (_sizes, sizes_rx) = tokio::sync::watch::channel(PtySize { cols: 80, rows: 24 });
    let shown = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sink = Arc::clone(&shown);
    let pump = tokio::spawn(crate::terminal_io::pump(crate::terminal_io::SshTerminal::new(channel), input_rx, sizes_rx, None, move |b: &[u8]| {
        sink.fetch_add(b.len(), std::sync::atomic::Ordering::SeqCst);
    }));
    let line = [vec![b'x'; 79], vec![b'\n']].concat();
    let mut paste: Vec<u8> = line.iter().copied().cycle().take(80 * 80_000).collect();
    // One write, as the window sends a paste (xterm's paste is one input
    // event), with the end of input after it: keys sent while more than
    // INPUT_QUEUE_CAP waits for the server are refused (R-002).
    paste.push(0x04);
    let sent = tokio::time::timeout(Duration::from_secs(60), input.send(TerminalCommand::Data(paste))).await;
    assert!(matches!(sent, Ok(Ok(()))), "the terminal stopped taking input");
    tokio::time::timeout(Duration::from_secs(60), pump).await.expect("the program never got all of it").unwrap();
    let answer = tokio::time::timeout(Duration::from_secs(10), exec_output(&handle, "echo still-here")).await.expect("the connection is frozen");
    assert_eq!(answer.trim(), "still-here");
    assert!(shown.load(std::sync::atomic::Ordering::SeqCst) > 0);
}
