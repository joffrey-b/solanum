//! The loop behind every terminal tab: a shell on a server, a shell inside a
//! container and a local shell all move output, keys and sizes the same way.

use crate::ssh_manager::{write_session_log, PtySize, TerminalCommand};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Output waiting this long is sent at once, and no event carries more.
pub(crate) const FLUSH_CAP: usize = 256 * 1024;
/// Otherwise output is sent this long after its first byte arrived:
/// imperceptible for typed echo, and a firehose (`cat` of a big file) becomes
/// a handful of events instead of one per SSH packet, which used to flood the
/// window's main thread.
const FLUSH_WINDOW: Duration = Duration::from_millis(8);
/// Output the window has been sent but has not acknowledged yet (F-031). The
/// window acknowledges what xterm has processed (`ack_terminal_output`); a
/// window that falls behind, or a hidden one the webview suspended, gets no
/// more until it catches up, so xterm never holds enough to throw output away
/// and the webview's memory stays bounded.
pub(crate) const MAX_UNACKED: usize = 2 * 1024 * 1024;
/// Output held here while the window is behind. The program's output is
/// still read (with russh a channel that is not read stalls its whole
/// connection: every other channel and the keepalive replies wait behind it),
/// so beyond this the oldest held output is dropped and the window is told
/// how much (owner decision). The session log still gets every byte. It drops
/// down to three quarters at once, so a flood moves the held bytes about once
/// per MiB instead of on every read.
pub(crate) const BACKLOG_CAP: usize = 4 * 1024 * 1024;
/// When dropping, what is kept starts at a line break found this close.
const LINE_SEARCH: usize = 64 * 1024;
/// Keys and terminal answers handed to a terminal's writer and not written yet
/// (R-002). A server that keeps its channel window shut, or a program that
/// stops reading its input, takes nothing, while the window's terminal keeps
/// answering what the output asks (`ESC[6n` and the like): without a cap that
/// queue grows for as long as the tab stays open. Past it, keys are refused
/// with one notice. A single chunk is taken whatever its size while nothing
/// waits, so a big paste still goes through as before.
pub(crate) const INPUT_QUEUE_CAP: usize = 1024 * 1024;

/// Output on its way to the window.
#[derive(Default)]
struct Outbox {
    held: Vec<u8>,
    unacked: usize,
    skipped: u64,
}

impl Outbox {
    fn hold(&mut self, data: &[u8]) {
        self.held.extend_from_slice(data);
        if self.held.len() > BACKLOG_CAP {
            let excess = self.held.len() - BACKLOG_CAP / 4 * 3;
            let cut = self.held[excess..]
                .iter()
                .take(LINE_SEARCH)
                .position(|&b| b == b'\n')
                .map_or(excess, |i| excess + i + 1);
            self.held.drain(..cut);
            self.skipped += cut as u64;
        }
    }

    /// Sends what the window has room for.
    fn send(&mut self, emit: &mut impl FnMut(&[u8])) {
        while self.unacked < MAX_UNACKED && !self.held.is_empty() {
            self.send_batch(emit);
        }
    }

    /// The terminal ended: the rest goes whatever the window's room.
    fn send_all(&mut self, emit: &mut impl FnMut(&[u8])) {
        while !self.held.is_empty() {
            self.send_batch(emit);
        }
    }

    fn send_batch(&mut self, emit: &mut impl FnMut(&[u8])) {
        let mut batch = Vec::new();
        if self.skipped > 0 {
            batch.extend_from_slice(skipped_notice(self.skipped).as_bytes());
            self.skipped = 0;
        }
        let n = self.held.len().min(FLUSH_CAP);
        batch.extend(self.held.drain(..n));
        self.unacked += batch.len();
        emit(&batch);
    }

    fn ack(&mut self, bytes: usize) {
        self.unacked = self.unacked.saturating_sub(bytes);
    }
}

/// The line shown where output was dropped. CAN first ends any escape
/// sequence the output before it left open, so the line is shown as text.
fn skipped_notice(bytes: u64) -> String {
    let amount = if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{} KiB", bytes.div_ceil(1024))
    };
    format!("\x18\x1b[0m\r\n\x1b[33m[Solanum: {amount} of output not shown: the window could not keep up]\x1b[0m\r\n")
}

/// What became of keys handed to a terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Input {
    /// On their way to the program.
    Accepted,
    /// Dropped: the program has not taken `waiting` bytes sent before.
    /// `first`: the first refusal since it last took everything.
    Refused { waiting: usize, first: bool },
    /// The terminal cannot take keys any more.
    Gone,
}

/// The bytes a terminal's writer has not written yet, and whether keys are
/// being refused. Once one chunk is refused, every later one is too until
/// the writer has caught up completely, so no key slips through behind keys
/// that were dropped (a command typed with letters missing).
#[derive(Default)]
pub(crate) struct InputQueue {
    waiting: Arc<AtomicUsize>,
    refusing: bool,
}

/// One chunk's place in an `InputQueue`, given back when the writer is done
/// with it (written, failed or dropped).
pub(crate) struct Queued {
    waiting: Arc<AtomicUsize>,
    len: usize,
}

impl Drop for Queued {
    fn drop(&mut self) {
        self.waiting.fetch_sub(self.len, Ordering::SeqCst);
    }
}

impl InputQueue {
    /// A place for `len` more bytes, or why there is none.
    pub(crate) fn admit(&mut self, len: usize) -> Result<Queued, Input> {
        let waiting = self.waiting.load(Ordering::SeqCst);
        if waiting > 0 && (self.refusing || waiting.saturating_add(len) > INPUT_QUEUE_CAP) {
            let first = !self.refusing;
            self.refusing = true;
            return Err(Input::Refused { waiting, first });
        }
        self.refusing = false;
        self.waiting.fetch_add(len, Ordering::SeqCst);
        Ok(Queued { waiting: Arc::clone(&self.waiting), len })
    }

    /// Bytes not written yet.
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.waiting)
    }
}

/// The line shown once when keys start being refused. CAN first, as for
/// `skipped_notice`.
fn refused_notice(waiting: usize) -> String {
    format!(
        "\x18\x1b[0m\r\n\x1b[33m[Solanum: keys not sent: the other end has not taken the last {} KiB yet. Typing works again once it has.]\x1b[0m\r\n",
        waiting.div_ceil(1024)
    )
}

/// One terminal's program: an SSH channel or a local PTY.
pub(crate) trait TerminalIo: Send {
    /// The next piece of output; `None` once the terminal has ended. Must be
    /// cancel-safe: the loop drops it when keys or a size arrive first.
    fn next_output(&mut self) -> impl Future<Output = Option<Vec<u8>>> + Send;
    /// Keys typed, or a terminal's answer to the output.
    fn send_input(&mut self, data: Vec<u8>) -> impl Future<Output = Input> + Send;
    fn resize_pty(&mut self, size: PtySize) -> impl Future<Output = ()> + Send;
    /// The tab closed or the profile locked: end the channel or the program.
    fn end(&mut self) -> impl Future<Output = ()> + Send;
    /// Once the output has ended: whether the other side ended it (the server
    /// closed the channel, the program exited), rather than the connection
    /// going away under it.
    fn ended_by_peer(&self) -> bool;
}

/// Why a terminal ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ended {
    /// The program or the server ended it: `exit`, an idle logout, a reboot.
    ByPeer,
    /// Its connection went away under it.
    Lost,
    /// Solanum ended it: the tab closed, a reconnect replaced the connection,
    /// the profile locked.
    Closed,
}

/// The SSH case (a login shell, or `docker exec` in a container). Keys, sizes
/// and the close go through a task of their own, because writing waits for the
/// server's window, which only the connection's session loop reads: were the
/// output not read while a big paste waits (a program echoing it), russh's
/// queue for the channel would fill, its session loop would wait on it, the
/// window adjustment would never be read, and the whole connection would stop.
pub(crate) struct SshTerminal {
    output: russh::ChannelReadHalf,
    writes: mpsc::UnboundedSender<Write>,
    writer: tokio::task::JoinHandle<()>,
    /// What the writer holds for a server that has not taken it.
    queue: InputQueue,
    /// The server sent end-of-file or closed the channel.
    closed_by_server: bool,
}

enum Write {
    Keys(Vec<u8>, Queued),
    Size(PtySize),
    End,
}

impl SshTerminal {
    pub(crate) fn new(channel: russh::Channel<russh::client::Msg>) -> Self {
        let (output, half) = channel.split();
        let (writes, mut queue) = mpsc::unbounded_channel();
        let writer = tokio::spawn(async move {
            while let Some(write) = queue.recv().await {
                match write {
                    Write::Keys(data, _place) => {
                        if half.data(&data[..]).await.is_err() {
                            break;
                        }
                    }
                    Write::Size(size) => {
                        let _ = half.window_change(size.cols, size.rows, 0, 0).await;
                    }
                    Write::End => {
                        let _ = half.close().await;
                        break;
                    }
                }
            }
        });
        SshTerminal { output, writes, writer, queue: InputQueue::default(), closed_by_server: false }
    }

    #[cfg(test)]
    fn waiting(&self) -> Arc<AtomicUsize> {
        self.queue.waiting()
    }
}

/// A terminal that ended by itself takes its pending keys with it.
impl Drop for SshTerminal {
    fn drop(&mut self) {
        self.writer.abort();
    }
}

impl TerminalIo for SshTerminal {
    async fn next_output(&mut self) -> Option<Vec<u8>> {
        use russh::ChannelMsg;
        loop {
            match self.output.wait().await {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => return Some(data.to_vec()),
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) => {
                    self.closed_by_server = true;
                    return None;
                }
                // The connection ended without the channel being closed.
                None => return None,
                Some(_) => {}
            }
        }
    }

    /// `Gone` once a write failed (the channel is gone).
    async fn send_input(&mut self, data: Vec<u8>) -> Input {
        let place = match self.queue.admit(data.len()) {
            Ok(place) => place,
            Err(refused) => return refused,
        };
        if self.writes.send(Write::Keys(data, place)).is_ok() {
            Input::Accepted
        } else {
            Input::Gone
        }
    }

    async fn resize_pty(&mut self, size: PtySize) {
        let _ = self.writes.send(Write::Size(size));
    }

    /// Closes the channel after the keys already sent, waiting at most 2 s for
    /// a server that does not take them.
    async fn end(&mut self) {
        let _ = self.writes.send(Write::End);
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut self.writer).await;
    }

    fn ended_by_peer(&self) -> bool {
        self.closed_by_server
    }
}

/// Runs a terminal until it ends: output goes to `emit` (and the session
/// log, byte for byte), keys and sizes come from `input` and `sizes`. Ends
/// when the program does, when the terminal cannot take keys any more, or
/// when the tab drops `input` or `sizes` (the program is then ended too), and
/// says which.
pub(crate) async fn pump<I: TerminalIo>(
    mut io: I,
    mut input: mpsc::Receiver<TerminalCommand>,
    mut sizes: watch::Receiver<PtySize>,
    mut log: Option<tokio::fs::File>,
    mut emit: impl FnMut(&[u8]) + Send,
) -> Ended {
    let gone = |io: &I| if io.ended_by_peer() { Ended::ByPeer } else { Ended::Lost };
    let mut out = Outbox::default();
    // Armed only while output waits, so an idle terminal never wakes this task.
    let park = || tokio::time::Instant::now() + Duration::from_secs(24 * 3600);
    let flush_timer = tokio::time::sleep_until(park());
    tokio::pin!(flush_timer);
    loop {
        tokio::select! {
            chunk = io.next_output() => match chunk {
                Some(chunk) => {
                    write_session_log(&mut log, &chunk).await;
                    let was_empty = out.held.is_empty();
                    out.hold(&chunk);
                    if out.held.len() >= FLUSH_CAP {
                        out.send(&mut emit);
                    } else if was_empty {
                        flush_timer.as_mut().reset(tokio::time::Instant::now() + FLUSH_WINDOW);
                    }
                }
                None => {
                    out.send_all(&mut emit);
                    return gone(&io);
                }
            },
            // Output still held after this waits for an acknowledgement.
            _ = &mut flush_timer => {
                out.send(&mut emit);
                flush_timer.as_mut().reset(park());
            },
            command = input.recv() => match command {
                Some(TerminalCommand::Data(data)) => match io.send_input(data).await {
                    Input::Accepted => {}
                    // Said once, not written to the session log (it is not the
                    // program's output).
                    Input::Refused { waiting, first } => {
                        if first {
                            out.hold(refused_notice(waiting).as_bytes());
                            out.send(&mut emit);
                        }
                    }
                    Input::Gone => {
                        out.send_all(&mut emit);
                        return gone(&io);
                    }
                },
                Some(TerminalCommand::Ack(bytes)) => {
                    out.ack(bytes);
                    out.send(&mut emit);
                }
                None => {
                    io.end().await;
                    out.send_all(&mut emit);
                    return Ended::Closed;
                }
            },
            // A burst of resizes (a window drag) collapses to the latest size.
            changed = sizes.changed() => {
                if changed.is_err() {
                    io.end().await;
                    out.send_all(&mut emit);
                    return Ended::Closed;
                }
                let size = *sizes.borrow();
                io.resize_pty(size).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A terminal whose output the test feeds and whose input it reads.
    struct FakeIo {
        output: mpsc::UnboundedReceiver<Vec<u8>>,
        seen: Arc<FakeSeen>,
    }

    #[derive(Default)]
    struct FakeSeen {
        read: AtomicUsize,
        input: Mutex<Vec<u8>>,
        sizes: Mutex<Vec<(u32, u32)>>,
        ended: AtomicBool,
        refuse_input: AtomicBool,
        /// The fake program ends its output by itself.
        exits: AtomicBool,
    }

    impl TerminalIo for FakeIo {
        async fn next_output(&mut self) -> Option<Vec<u8>> {
            let chunk = self.output.recv().await?;
            self.seen.read.fetch_add(chunk.len(), Ordering::SeqCst);
            Some(chunk)
        }
        async fn send_input(&mut self, data: Vec<u8>) -> Input {
            if self.seen.refuse_input.load(Ordering::SeqCst) {
                return Input::Gone;
            }
            self.seen.input.lock().unwrap().extend_from_slice(&data);
            Input::Accepted
        }
        async fn resize_pty(&mut self, size: PtySize) {
            self.seen.sizes.lock().unwrap().push((size.cols, size.rows));
        }
        async fn end(&mut self) {
            self.seen.ended.store(true, Ordering::SeqCst);
        }
        fn ended_by_peer(&self) -> bool {
            self.seen.exits.load(Ordering::SeqCst)
        }
    }

    struct Running {
        output: mpsc::UnboundedSender<Vec<u8>>,
        input: mpsc::Sender<TerminalCommand>,
        sizes: watch::Sender<PtySize>,
        seen: Arc<FakeSeen>,
        emitted: Arc<Mutex<Vec<Vec<u8>>>>,
        task: tokio::task::JoinHandle<Ended>,
    }

    impl Running {
        fn shown(&self) -> Vec<u8> {
            self.emitted.lock().unwrap().concat()
        }
    }

    fn start() -> Running {
        let (output, output_rx) = mpsc::unbounded_channel();
        let (input, input_rx) = mpsc::channel(32);
        let (sizes, sizes_rx) = watch::channel(PtySize { cols: 80, rows: 24 });
        let seen = Arc::new(FakeSeen::default());
        let emitted = Arc::new(Mutex::new(Vec::new()));
        let io = FakeIo { output: output_rx, seen: Arc::clone(&seen) };
        let sink = Arc::clone(&emitted);
        let task = tokio::spawn(pump(io, input_rx, sizes_rx, None, move |b: &[u8]| sink.lock().unwrap().push(b.to_vec())));
        Running { output, input, sizes, seen, emitted, task }
    }

    async fn ends(task: tokio::task::JoinHandle<Ended>) -> Ended {
        tokio::time::timeout(Duration::from_secs(5), task).await.expect("the pump did not end").unwrap()
    }

    #[tokio::test]
    async fn output_reaches_the_window_in_order_and_the_rest_is_sent_at_the_end() {
        let t = start();
        let mut sent = Vec::new();
        for i in 0..200u32 {
            let chunk = format!("line {i}\r\n").into_bytes();
            sent.extend_from_slice(&chunk);
            t.output.send(chunk).unwrap();
        }
        let big = vec![b'x'; FLUSH_CAP + 10];
        sent.extend_from_slice(&big);
        t.output.send(big).unwrap();
        t.output.send(b"tail".to_vec()).unwrap();
        sent.extend_from_slice(b"tail");
        let (emitted, task) = (Arc::clone(&t.emitted), t.task);
        drop(t.output);
        ends(task).await;
        assert_eq!(emitted.lock().unwrap().concat(), sent);
    }

    #[tokio::test]
    async fn small_output_is_sent_after_a_moment_without_more_output() {
        let t = start();
        t.output.send(b"$ ".to_vec()).unwrap();
        assert!(crate::ssh_test_server::eventually(|| t.shown() == b"$ ").await);
        assert_eq!(t.emitted.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn keys_and_sizes_reach_the_program_and_a_closed_tab_ends_it() {
        let t = start();
        t.input.send(TerminalCommand::Data(b"ls\r".to_vec())).await.unwrap();
        t.sizes.send(PtySize { cols: 120, rows: 40 }).unwrap();
        let seen = Arc::clone(&t.seen);
        assert!(crate::ssh_test_server::eventually(|| seen.input.lock().unwrap().as_slice() == b"ls\r"
            && seen.sizes.lock().unwrap().last() == Some(&(120, 40))).await);
        let Running { input, task, output: _output, sizes: _sizes, .. } = t;
        drop(input);
        ends(task).await;
        assert!(seen.ended.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn dropping_the_size_channel_ends_the_program_too() {
        let t = start();
        let seen = Arc::clone(&t.seen);
        let Running { sizes, task, output: _output, input: _input, .. } = t;
        drop(sizes);
        ends(task).await;
        assert!(seen.ended.load(Ordering::SeqCst));
    }

    /// F-031: a window that does not keep up gets at most 2 MiB it has not
    /// acknowledged, while the program's output is still read (an SSH
    /// connection must never wait on one terminal).
    #[tokio::test]
    async fn a_window_that_does_not_acknowledge_gets_no_more_than_its_credit() {
        let t = start();
        let total = 8 * 1024 * 1024;
        for _ in 0..total / 65536 {
            t.output.send(vec![b'a'; 65536]).unwrap();
        }
        assert!(crate::ssh_test_server::eventually(|| t.seen.read.load(Ordering::SeqCst) == total).await, "the output was not all read");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let shown = t.shown().len();
        assert!(shown <= 2 * 1024 * 1024 + 256 * 1024, "{shown} bytes sent to a window that acknowledged none");
    }

    /// What was held while the window was behind arrives, in order and
    /// complete, once it acknowledges.
    #[tokio::test]
    async fn acknowledgements_release_held_output_in_order() {
        let t = start();
        let sent: Vec<u8> = (0..5 * 1024 * 1024u32).map(|i| (i % 253) as u8).collect();
        for chunk in sent.chunks(40_000) {
            t.output.send(chunk.to_vec()).unwrap();
        }
        assert!(crate::ssh_test_server::eventually(|| t.seen.read.load(Ordering::SeqCst) == sent.len()).await);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(t.shown().len() < sent.len());
        // An acknowledgement bigger than what is outstanding is harmless.
        for _ in 0..4 {
            t.input.send(TerminalCommand::Ack(usize::MAX / 8)).await.unwrap();
        }
        assert!(crate::ssh_test_server::eventually(|| t.shown().len() == sent.len()).await);
        assert_eq!(t.shown(), sent);
    }

    /// Beyond what may be held, the oldest held output goes; the window is told
    /// how much, and what it gets after that is the newest output, from a line.
    #[tokio::test]
    async fn output_beyond_the_backlog_drops_the_oldest_and_says_so() {
        let t = start();
        let mut sent = Vec::new();
        let mut i = 0u64;
        while sent.len() < 12 * 1024 * 1024 {
            sent.extend_from_slice(format!("line {i:08}\r\n").as_bytes());
            i += 1;
        }
        for chunk in sent.chunks(50_000) {
            t.output.send(chunk.to_vec()).unwrap();
        }
        assert!(crate::ssh_test_server::eventually(|| t.seen.read.load(Ordering::SeqCst) == sent.len()).await);
        let (emitted, task) = (Arc::clone(&t.emitted), t.task);
        drop(t.output);
        ends(task).await;
        let shown = emitted.lock().unwrap().concat();
        let notice = b"\x18\x1b[0m\r\n\x1b[33m[Solanum: ";
        let at = shown.windows(notice.len()).position(|w| w == notice).expect("no notice");
        let rest = &shown[at..];
        let close = b"]\x1b[0m\r\n";
        let end = rest.windows(close.len()).position(|w| w == close).expect("notice not closed") + close.len();
        let (head, notice_text, tail) = (&shown[..at], &rest[..end], &rest[end..]);
        assert!(String::from_utf8_lossy(notice_text).contains("MiB of output not shown"));
        assert!(head.len() <= MAX_UNACKED + FLUSH_CAP && sent.starts_with(head));
        assert!(tail.len() <= BACKLOG_CAP && sent.ends_with(tail), "kept {} bytes", tail.len());
        assert!(tail.starts_with(b"line "), "what is kept starts at a line");
        assert!(head.len() + tail.len() < sent.len());
    }

    /// The window's side of the contract: it acknowledges exactly the length of
    /// every batch it got, notice included, and after a flood that dropped
    /// output the credit is whole again (new output shows at once).
    #[tokio::test]
    async fn exact_acknowledgements_leave_no_credit_behind_after_a_drop() {
        let (output, output_rx) = mpsc::unbounded_channel();
        let (input, input_rx) = mpsc::channel(32);
        let (_sizes, sizes_rx) = watch::channel(PtySize { cols: 80, rows: 24 });
        let seen = Arc::new(FakeSeen::default());
        let io = FakeIo { output: output_rx, seen: Arc::clone(&seen) };
        let (lengths, mut to_ack) = mpsc::unbounded_channel::<usize>();
        let shown = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = Arc::clone(&shown);
        tokio::spawn(pump(io, input_rx, sizes_rx, None, move |b: &[u8]| {
            sink.lock().unwrap().extend_from_slice(b);
            lengths.send(b.len()).unwrap();
        }));
        // A window that is slow to start: nothing acknowledged until the
        // flood has been read, then each batch as it comes.
        let total = 12 * 1024 * 1024;
        for _ in 0..total / 32768 {
            output.send(vec![b'y'; 32768]).unwrap();
        }
        assert!(crate::ssh_test_server::eventually(|| seen.read.load(Ordering::SeqCst) == total).await);
        let acks = input.clone();
        tokio::spawn(async move {
            while let Some(n) = to_ack.recv().await {
                let _ = acks.send(TerminalCommand::Ack(n)).await;
            }
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let before = shown.lock().unwrap().len();
        assert!(String::from_utf8_lossy(&shown.lock().unwrap()).contains("of output not shown"));
        output.send(b"after".to_vec()).unwrap();
        assert!(crate::ssh_test_server::eventually(|| shown.lock().unwrap().ends_with(b"after")).await, "new output waits for credit");
        assert!(before < total);
    }

    /// A flood without line breaks is cut where it has to be.
    #[tokio::test]
    async fn a_drop_without_a_line_break_nearby_keeps_the_newest_bytes() {
        let t = start();
        let sent: Vec<u8> = (0..10 * 1024 * 1024u32).map(|i| b'a' + (i % 26) as u8).collect();
        for chunk in sent.chunks(65536) {
            t.output.send(chunk.to_vec()).unwrap();
        }
        assert!(crate::ssh_test_server::eventually(|| t.seen.read.load(Ordering::SeqCst) == sent.len()).await);
        let (emitted, task) = (Arc::clone(&t.emitted), t.task);
        drop(t.output);
        ends(task).await;
        let shown = emitted.lock().unwrap().concat();
        let close = b"]\x1b[0m\r\n";
        let end = shown.windows(close.len()).rposition(|w| w == close).expect("no notice") + close.len();
        let tail = &shown[end..];
        assert!(!tail.is_empty() && tail.len() <= BACKLOG_CAP && sent.ends_with(tail), "kept {} bytes", tail.len());
    }

    /// The SSH side: everything the channel prints reaches the window, and the
    /// terminal ends with the channel.
    #[tokio::test]
    async fn an_ssh_channel_runs_through_the_pump() {
        use crate::ssh_test_server::{logged_in, Script};
        let printed: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let (handle, _seen) = logged_in(Script { exec_output: Some(printed.clone()), ..Script::default() }).await;
        let channel = crate::ssh_connect::open_session_channel(&handle).await.unwrap();
        channel.exec(true, "cat").await.unwrap();
        let (_input, input_rx) = mpsc::channel(32);
        let (_sizes, sizes_rx) = watch::channel(PtySize { cols: 80, rows: 24 });
        let emitted = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = Arc::clone(&emitted);
        let task = tokio::spawn(pump(SshTerminal::new(channel), input_rx, sizes_rx, None, move |b: &[u8]| sink.lock().unwrap().extend_from_slice(b)));
        assert_eq!(ends(task).await, Ended::ByPeer, "the server closed the channel");
        assert_eq!(*emitted.lock().unwrap(), printed);
    }

    /// N-028: a connection that goes away under a running terminal is not the
    /// server ending it (a switch that drops the link, a dead network), and a
    /// terminal the tab closes is neither.
    #[tokio::test]
    async fn how_an_ssh_terminal_ended_is_told_apart() {
        use crate::ssh_test_server::{eventually, logged_in, Script};
        let (handle, seen) = logged_in(Script::default()).await;
        let open = || async {
            let channel = crate::ssh_connect::open_session_channel(&handle).await.unwrap();
            channel.exec(true, "shell").await.unwrap();
            let (input, input_rx) = mpsc::channel(32);
            let (sizes, sizes_rx) = watch::channel(PtySize { cols: 80, rows: 24 });
            (tokio::spawn(pump(SshTerminal::new(channel), input_rx, sizes_rx, None, |_: &[u8]| {})), input, sizes)
        };

        let (closed, input, _sizes) = open().await;
        drop(input);
        assert_eq!(ends(closed).await, Ended::Closed);

        let (lost, _input, _sizes) = open().await;
        let server = seen.lock().unwrap().handle.clone().expect("the server's side");
        assert!(eventually(|| !lost.is_finished()).await);
        server.disconnect(russh::Disconnect::ByApplication, "bye".into(), String::new()).await.unwrap();
        assert_eq!(ends(lost).await, Ended::Lost, "the channel was never closed: the connection went");
    }

    #[tokio::test]
    async fn a_terminal_that_refuses_keys_ends_after_showing_what_it_printed() {
        let t = start();
        t.output.send(b"bye".to_vec()).unwrap();
        assert!(crate::ssh_test_server::eventually(|| t.seen.read.load(Ordering::SeqCst) == 3).await);
        t.seen.refuse_input.store(true, Ordering::SeqCst);
        t.input.send(TerminalCommand::Data(b"x".to_vec())).await.unwrap();
        let (emitted, task, _keep) = (Arc::clone(&t.emitted), t.task, (t.output, t.sizes));
        assert_eq!(ends(task).await, Ended::Lost, "keys that cannot be sent: the terminal is gone, nobody ended it");
        assert_eq!(emitted.lock().unwrap().concat(), b"bye");
    }

    /// R-002: one chunk goes through while nothing waits, whatever its size;
    /// beyond the cap keys are refused, and keep being refused until the
    /// writer has written everything, so none slips in behind dropped ones.
    #[test]
    fn the_input_queue_refuses_past_its_cap_until_everything_was_written() {
        let mut q = InputQueue::default();
        let paste = q.admit(5 * INPUT_QUEUE_CAP).expect("a big paste while nothing waits");
        assert_eq!(q.admit(1).err(), Some(Input::Refused { waiting: 5 * INPUT_QUEUE_CAP, first: true }));
        assert_eq!(q.admit(1).err(), Some(Input::Refused { waiting: 5 * INPUT_QUEUE_CAP, first: false }));
        drop(paste);
        let most = q.admit(INPUT_QUEUE_CAP - 10).expect("taken again once written");
        let rest = q.admit(10).expect("up to the cap");
        assert!(matches!(q.admit(1), Err(Input::Refused { first: true, .. })));
        drop(most);
        assert!(q.admit(1).is_err(), "still refused while anything waits");
        drop(rest);
        assert!(q.admit(1).is_ok());
    }

    /// R-002: a server that never takes what the terminal sends (its window
    /// stays shut) and keeps asking where the cursor is. Every question gets
    /// its answer, as xterm gives one, and what waits for the server stays
    /// under the cap; the window is told once.
    #[tokio::test]
    async fn a_server_that_takes_no_input_gets_no_more_than_the_cap_queued() {
        use crate::ssh_test_server::{logged_in, Script};
        const QUERIES: usize = 300_000;
        const ANSWER: &[u8] = b"\x1b[1;1R";
        let script = Script {
            exec_output: Some(b"\x1b[6n".repeat(QUERIES)),
            exec_stays_open: true,
            stall_stdin: true,
            window_size: Some(32 * 1024),
            ..Script::default()
        };
        let (handle, _seen) = logged_in(script).await;
        let channel = crate::ssh_connect::open_session_channel(&handle).await.unwrap();
        channel.exec(true, "shell").await.unwrap();
        let terminal = SshTerminal::new(channel);
        let waiting = terminal.waiting();
        let (input, input_rx) = mpsc::channel(32);
        let (_sizes, sizes_rx) = watch::channel(PtySize { cols: 80, rows: 24 });
        let (asked, mut questions) = mpsc::unbounded_channel::<usize>();
        let shown = Arc::new(Mutex::new(Vec::<u8>::new()));
        let sink = Arc::clone(&shown);
        let mut carry = Vec::new();
        let _pump = tokio::spawn(pump(terminal, input_rx, sizes_rx, None, move |b: &[u8]| {
            sink.lock().unwrap().extend_from_slice(b);
            carry.extend_from_slice(b);
            let n = carry.windows(4).filter(|w| *w == b"\x1b[6n").count();
            let keep = carry.len().saturating_sub(3);
            carry.drain(..keep);
            let _ = asked.send(n);
        }));
        let answered = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&answered);
        tokio::spawn(async move {
            while let Some(n) = questions.recv().await {
                for _ in 0..n {
                    if input.send(TerminalCommand::Data(ANSWER.to_vec())).await.is_err() {
                        return;
                    }
                    count.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while answered.load(Ordering::SeqCst) < QUERIES && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(answered.load(Ordering::SeqCst), QUERIES, "not every question was answered");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let held = waiting.load(Ordering::SeqCst);
        assert!(held <= INPUT_QUEUE_CAP + ANSWER.len(), "{held} bytes wait for a server that takes none");
        let text = String::from_utf8_lossy(&shown.lock().unwrap()).into_owned();
        assert_eq!(text.matches("keys not sent").count(), 1, "the window is told once");
    }

    /// A program that ends its output itself ended the terminal; the tab
    /// dropping its input is Solanum's doing.
    #[tokio::test]
    async fn a_program_that_exits_ended_its_terminal_and_a_closed_tab_did_not() {
        let t = start();
        t.seen.exits.store(true, Ordering::SeqCst);
        let (task, _keep) = (t.task, (t.input, t.sizes));
        drop(t.output);
        assert_eq!(ends(task).await, Ended::ByPeer);
        let t = start();
        let (task, _keep) = (t.task, (t.output, t.sizes));
        drop(t.input);
        assert_eq!(ends(task).await, Ended::Closed);
    }
}
