//! An SSH server inside the test process: russh's own server over an in-memory
//! pipe, scripted to behave in the ways the connect path has to survive (it
//! stalls, refuses channels, loops keyboard-interactive rounds, wants a second
//! login step). Test-only; nothing here touches the network.

use russh::keys::{Algorithm, EcdsaCurve, PrivateKey, PublicKey, PublicKeyOrCertificate};
use russh::server::{self, Auth, Msg, Response, Session};
use russh::{client, Channel, ChannelId, MethodKind, MethodSet, Sig};
use std::borrow::Cow;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub(crate) const USER: &str = "tester";
pub(crate) const PASSWORD: &str = "pw";

/// What the keyboard-interactive method does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kbi {
    /// One round asking for the password (what PAM does on most servers).
    PasswordPrompt,
    /// Rounds with no prompt at all, forever.
    EmptyRoundsForever,
    /// Rounds with one prompt, forever, whatever the answer.
    PromptsForever,
}

/// What happens to a session-channel open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sessions {
    Accept,
    Refuse,
    /// The first is accepted and every later one refused, whether the first
    /// is still open or not (a network switch: one channel per connection).
    FirstOnly,
    /// Never answered.
    Stall,
}

#[derive(Clone, Debug)]
pub(crate) struct Script {
    /// The methods a login needs, in order (one OpenSSH `AuthenticationMethods`
    /// list): every step but the last ends in a partial success.
    pub steps: Vec<MethodKind>,
    /// The user key `publickey` accepts.
    pub user_key: Option<PublicKey>,
    pub kbi: Kbi,
    /// Never answer an authentication request.
    pub stall_auth: bool,
    /// Drop the connection when an authentication request arrives.
    pub drop_on_auth: bool,
    pub sessions: Sessions,
    /// Never answer `cancel-tcpip-forward`.
    pub stall_cancel_forward: bool,
    /// Refuse every `tcpip-forward` (a port the server cannot bind).
    pub refuse_forward: bool,
    /// The port a `tcpip-forward` for port 0 is given.
    pub granted_port: u32,
    /// Refuse every `direct-tcpip` open (otherwise the channel echoes).
    pub refuse_direct: bool,
    /// Answer a `tcpip-forward` only after this long.
    pub forward_delay: Option<Duration>,
    /// What an `exec` writes before it ends the channel; `None` stays quiet
    /// and open (a `docker logs -f` of an idle container). A script sent
    /// through `remote_exec` gets it once its stdin has ended, as `sh` would.
    pub exec_output: Option<Vec<u8>>,
    /// The key exchanges the server offers, in its order; `None` is russh's list.
    pub kex: Option<Vec<russh::kex::Name>>,
    /// The identification string the server sends; `None` is russh's own.
    pub server_id: Option<&'static str>,
    /// An `exec` keeps its channel open after writing `exec_output` (a shell
    /// that printed something and waits).
    pub exec_stays_open: bool,
    /// Never take what the client writes: the first data packet blocks the
    /// server's session, so the client's window to it is never topped up
    /// again (a hostile server, or a program that stopped reading).
    pub stall_stdin: bool,
    /// The window the server gives the client; `None` is russh's default.
    pub window_size: Option<u32>,
}

impl Default for Script {
    fn default() -> Self {
        Script {
            steps: vec![MethodKind::Password],
            user_key: None,
            kbi: Kbi::PasswordPrompt,
            stall_auth: false,
            drop_on_auth: false,
            sessions: Sessions::Accept,
            stall_cancel_forward: false,
            refuse_forward: false,
            granted_port: 40000,
            refuse_direct: false,
            forward_delay: None,
            exec_output: None,
            kex: None,
            server_id: None,
            exec_stays_open: false,
            stall_stdin: false,
            window_size: None,
        }
    }
}

/// What the server saw, for assertions.
#[derive(Default, Debug)]
pub(crate) struct Seen {
    pub passwords: Vec<String>,
    pub kbi_rounds: usize,
    pub session_opens: usize,
    pub execs: Vec<String>,
    /// Everything the client wrote to its channels.
    pub stdin: Vec<u8>,
    pub signals: Vec<String>,
    pub eofs: usize,
    pub closes: usize,
    /// Every `tcpip-forward` request: (address, port), as sent.
    pub forwards: Vec<(String, u32)>,
    /// Every `direct-tcpip` open: (host, port), as sent.
    pub direct: Vec<(String, u32)>,
    /// Every `cancel-tcpip-forward`: (address, port).
    pub cancels: Vec<(String, u32)>,
    /// The server's side of the session, for a test that opens
    /// `forwarded-tcpip` channels to the client or ends the connection (set at
    /// the first forward or session channel).
    pub handle: Option<server::Handle>,
}

struct TestServer {
    script: Script,
    done: usize,
    seen: Arc<Mutex<Seen>>,
    /// Session-channel opens held unanswered (`Sessions::Stall`).
    held: Vec<server::ChannelOpenHandle>,
    /// Ports forwarded now: a second request for one is refused, as sshd
    /// refuses a port it already listens on.
    forwarded: Vec<u32>,
    /// Channels running a script read from stdin: they answer at its end.
    reading_stdin: Vec<ChannelId>,
}

impl TestServer {
    fn wanted(&self) -> Option<MethodKind> {
        self.script.steps.get(self.done).copied()
    }

    /// The answer after `method` was checked: `ok` means the credential was right.
    fn step(&mut self, method: MethodKind, ok: bool) -> Auth {
        if ok && self.wanted() == Some(method) {
            self.done += 1;
            if self.done == self.script.steps.len() {
                return Auth::Accept;
            }
            return Auth::Reject {
                proceed_with_methods: Some(MethodSet::from(&self.script.steps[self.done..=self.done])),
                partial_success: true,
            };
        }
        Auth::Reject {
            proceed_with_methods: self.wanted().map(|m| MethodSet::from(&[m][..])),
            partial_success: false,
        }
    }

    /// Writes the scripted output of an exec and ends the channel.
    fn answer_exec(&self, channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
        if let Some(out) = &self.script.exec_output {
            session.data(channel, out.clone())?;
            if !self.script.exec_stays_open {
                session.eof(channel)?;
                session.close(channel)?;
            }
        }
        Ok(())
    }

    /// Stalls or drops the connection when the script says so; an error
    /// from a handler ends the server's session and closes the pipe.
    async fn stall_if_asked(&self) -> Result<(), russh::Error> {
        if self.script.drop_on_auth {
            tokio::time::sleep(Duration::from_millis(50)).await;
            return Err(russh::Error::Disconnect);
        }
        if self.script.stall_auth {
            std::future::pending::<()>().await;
        }
        Ok(())
    }
}

fn prompts(list: &[(&'static str, bool)]) -> Cow<'static, [(Cow<'static, str>, bool)]> {
    Cow::Owned(list.iter().map(|(p, e)| (Cow::Borrowed(*p), *e)).collect())
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    /// Lists the method the next step wants, as sshd lists its methods.
    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject { proceed_with_methods: self.wanted().map(|m| MethodSet::from(&[m][..])), partial_success: false })
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        self.stall_if_asked().await?;
        self.seen.lock().unwrap().passwords.push(password.to_string());
        Ok(self.step(MethodKind::Password, user == USER && password == PASSWORD))
    }

    async fn auth_publickey_offered(&mut self, _user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        self.stall_if_asked().await?;
        let known = self.script.user_key.as_ref().is_some_and(|k| k.key_data() == key.key_data());
        if known && self.wanted() == Some(MethodKind::PublicKey) {
            Ok(Auth::Accept)
        } else {
            Ok(self.step(MethodKind::PublicKey, false))
        }
    }

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        self.stall_if_asked().await?;
        let known = self.script.user_key.as_ref().is_some_and(|k| k.key_data() == key.key_data());
        Ok(self.step(MethodKind::PublicKey, user == USER && known))
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self,
        user: &str,
        _submethods: &str,
        response: Option<Response<'a>>,
    ) -> Result<Auth, Self::Error> {
        self.stall_if_asked().await?;
        if self.wanted() != Some(MethodKind::KeyboardInteractive) {
            return Ok(self.step(MethodKind::KeyboardInteractive, false));
        }
        self.seen.lock().unwrap().kbi_rounds += 1;
        let ask = |list: &[(&'static str, bool)]| Auth::Partial {
            name: Cow::Borrowed("Test"),
            instructions: Cow::Borrowed(""),
            prompts: prompts(list),
        };
        match (self.script.kbi, response) {
            (Kbi::EmptyRoundsForever, _) => Ok(ask(&[])),
            (Kbi::PromptsForever, _) => Ok(ask(&[("Code: ", false)])),
            (Kbi::PasswordPrompt, None) => Ok(ask(&[("Password: ", false)])),
            (Kbi::PasswordPrompt, Some(mut answers)) => {
                let answer = answers.next().map(|b| String::from_utf8_lossy(&b).into_owned());
                let ok = user == USER && answer.as_deref() == Some(PASSWORD);
                Ok(self.step(MethodKind::KeyboardInteractive, ok))
            }
        }
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let opens = {
            let mut seen = self.seen.lock().unwrap();
            seen.session_opens += 1;
            seen.handle.get_or_insert_with(|| session.handle());
            seen.session_opens
        };
        match self.script.sessions {
            Sessions::Accept => reply.accept().await,
            Sessions::Refuse => drop(reply),
            Sessions::FirstOnly if opens == 1 => reply.accept().await,
            Sessions::FirstOnly => drop(reply),
            Sessions::Stall => self.held.push(reply),
        }
        Ok(())
    }

    async fn exec_request(&mut self, channel: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).into_owned();
        self.seen.lock().unwrap().execs.push(command.clone());
        session.channel_success(channel)?;
        if command == crate::remote_exec::SH_FROM_STDIN {
            self.reading_stdin.push(channel);
        } else {
            self.answer_exec(channel, session)?;
        }
        Ok(())
    }

    async fn data(&mut self, _channel: ChannelId, data: &[u8], _session: &mut Session) -> Result<(), Self::Error> {
        self.seen.lock().unwrap().stdin.extend_from_slice(data);
        if self.script.stall_stdin {
            std::future::pending::<()>().await;
        }
        Ok(())
    }

    async fn signal(&mut self, _channel: ChannelId, signal: Sig, _session: &mut Session) -> Result<(), Self::Error> {
        self.seen.lock().unwrap().signals.push(format!("{signal:?}"));
        Ok(())
    }

    async fn channel_eof(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        self.seen.lock().unwrap().eofs += 1;
        if let Some(i) = self.reading_stdin.iter().position(|c| *c == channel) {
            self.reading_stdin.remove(i);
            self.answer_exec(channel, session)?;
        }
        Ok(())
    }

    async fn channel_close(&mut self, _channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        self.seen.lock().unwrap().closes += 1;
        Ok(())
    }

    async fn tcpip_forward(&mut self, address: &str, port: &mut u32, session: &mut Session) -> Result<bool, Self::Error> {
        {
            let mut seen = self.seen.lock().unwrap();
            seen.forwards.push((address.to_string(), *port));
            seen.handle = Some(session.handle());
        }
        if let Some(delay) = self.script.forward_delay {
            tokio::time::sleep(delay).await;
        }
        if self.script.refuse_forward || self.forwarded.contains(port) {
            return Ok(false);
        }
        if *port == 0 {
            *port = self.script.granted_port;
        }
        self.forwarded.push(*port);
        Ok(true)
    }

    async fn cancel_tcpip_forward(&mut self, address: &str, port: u32, _session: &mut Session) -> Result<bool, Self::Error> {
        self.seen.lock().unwrap().cancels.push((address.to_string(), port));
        if self.script.stall_cancel_forward {
            std::future::pending::<()>().await;
        }
        self.forwarded.retain(|p| *p != port);
        Ok(true)
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.seen.lock().unwrap().direct.push((host_to_connect.to_string(), port_to_connect));
        if self.script.refuse_direct {
            drop(reply);
            return Ok(());
        }
        reply.accept().await;
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(channel.into_stream());
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        Ok(())
    }
}

pub(crate) fn ed25519_key(seed: u8) -> PrivateKey {
    PrivateKey::from(russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]))
}

pub(crate) fn ecdsa_key() -> PrivateKey {
    PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 })
        .expect("ecdsa test key")
}

/// A running scripted server: the client's end of the pipe and what the
/// server saw.
pub(crate) struct Served {
    pub stream: tokio::io::DuplexStream,
    pub seen: Arc<Mutex<Seen>>,
}

/// Starts a scripted server on one end of an in-memory pipe.
pub(crate) fn serve(script: Script, host_keys: Vec<PrivateKey>) -> Served {
    let (client_end, server_end) = tokio::io::duplex(1 << 20);
    let mut config = server::Config {
        keys: host_keys,
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        max_auth_attempts: 1000,
        inactivity_timeout: None,
        ..server::Config::default()
    };
    if let Some(kex) = &script.kex {
        config.preferred.kex = Cow::Owned(kex.clone());
    }
    if let Some(id) = script.server_id {
        config.server_id = russh::SshId::Standard(Cow::Borrowed(id));
    }
    if let Some(window) = script.window_size {
        config.window_size = window;
    }
    let seen = Arc::new(Mutex::new(Seen::default()));
    let handler = TestServer { script, done: 0, seen: Arc::clone(&seen), held: Vec::new(), forwarded: Vec::new(), reading_stdin: Vec::new() };
    tokio::spawn(async move {
        if let Ok(running) = server::run_stream(Arc::new(config), server_end, handler).await {
            let _ = running.await;
        }
    });
    Served { stream: client_end, seen }
}

/// A connection to a scripted server, logged in with the password, shared the
/// way the app shares its connections.
pub(crate) async fn logged_in(script: Script) -> (Arc<tokio::sync::Mutex<client::Handle<TestClient>>>, Arc<Mutex<Seen>>) {
    logged_in_forwarding(script, None).await
}

/// `logged_in`, with the client handing `forwarded-tcpip` channels to the
/// tunnel code through `forwarded`, as the app's handler does.
pub(crate) async fn logged_in_forwarding(
    script: Script,
    forwarded: Option<crate::tunnel::ForwardedTargets>,
) -> (Arc<tokio::sync::Mutex<client::Handle<TestClient>>>, Arc<Mutex<Seen>>) {
    let served = serve(script, vec![ed25519_key(1)]);
    let (mut handler, _) = TestClient::new();
    handler.forwarded = forwarded;
    let config = Arc::new(crate::ssh_connect::build_ssh_client_config(&Default::default()));
    let mut handle = client::connect_stream(config, served.stream, handler).await.expect("handshake");
    assert!(handle.authenticate_password(USER, PASSWORD).await.expect("login").success());
    (Arc::new(tokio::sync::Mutex::new(handle)), served.seen)
}

/// Waits up to two seconds for `done` (what the server saw arrives a moment
/// after the client sent it).
pub(crate) async fn eventually(done: impl Fn() -> bool) -> bool {
    for _ in 0..100 {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    done()
}

/// A peer that sends an SSH identification line and then nothing at all.
pub(crate) fn serve_silence() -> tokio::io::DuplexStream {
    use tokio::io::AsyncWriteExt;
    let (client_end, mut server_end) = tokio::io::duplex(1 << 16);
    tokio::spawn(async move {
        let _ = server_end.write_all(b"SSH-2.0-silent\r\n").await;
        std::future::pending::<()>().await;
        drop(server_end);
    });
    client_end
}

/// Client-side handler for tests: records the host-key types it is shown and
/// can play a user who takes `answer_after` to approve the key, marking the
/// prompt open meanwhile the way the app's handler does.
pub(crate) struct TestClient {
    pub offered: Arc<Mutex<Vec<String>>>,
    pub answer_after: Option<(Duration, Arc<tokio::sync::watch::Sender<bool>>)>,
    /// Remote forwards to bridge `forwarded-tcpip` channels to; `None`
    /// refuses them.
    pub forwarded: Option<crate::tunnel::ForwardedTargets>,
    /// The key exchange the connection settled on.
    pub negotiated_kex: Arc<Mutex<Option<String>>>,
}

impl TestClient {
    pub(crate) fn new() -> (Self, Arc<Mutex<Vec<String>>>) {
        let offered = Arc::new(Mutex::new(Vec::new()));
        (TestClient { offered: Arc::clone(&offered), answer_after: None, forwarded: None, negotiated_kex: Arc::default() }, offered)
    }
}

impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(&mut self, offered: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = offered else {
            return Ok(false);
        };
        self.offered.lock().unwrap().push(crate::ssh_manager::host_key_label(key));
        if let Some((delay, prompt)) = &self.answer_after {
            let _open = crate::ssh_connect::PromptOpen::new(prompt);
            tokio::time::sleep(*delay).await;
        }
        Ok(true)
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        names: &russh::Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        *self.negotiated_kex.lock().unwrap() = Some(names.kex.as_ref().to_string());
        Ok(())
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<client::Msg>,
        _connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        let originator = (originator_address, originator_port);
        match &self.forwarded {
            Some(targets) => crate::tunnel::accept_forwarded_channel(targets, connected_port, originator, channel, reply).await,
            None => drop(reply),
        }
        Ok(())
    }
}
