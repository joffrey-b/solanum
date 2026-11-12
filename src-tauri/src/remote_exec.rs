//! Running a script on a server: how it is sent, and how its output is read.
//! Every probe, Info section, Docker command and service or process action
//! goes through here.

use russh::client;
use russh::Channel;

/// The command every script runs under: `sh` reading the whole script from
/// stdin before running any of it (F-071). sshd runs an `exec` request
/// through the account's login shell, and the scripts are POSIX sh, which
/// csh/tcsh and fish do not understand; this one line parses the same in sh,
/// bash, zsh, ksh, csh/tcsh and fish (single quotes, no newline, backslash or
/// `!`). Since `cat` has read stdin to its end first, a command in the script
/// that reads stdin gets end-of-file instead of the rest of the script.
pub(crate) const SH_FROM_STDIN: &str = "sh -c 'eval \"$(cat)\"'";

/// Starts `script` on `channel` under [`SH_FROM_STDIN`].
pub(crate) async fn send_script(channel: &Channel<client::Msg>, script: &str) -> Result<(), String> {
    channel.exec(true, SH_FROM_STDIN).await.map_err(|e| e.to_string())?;
    // A server that cannot run `sh` closes the channel (its message goes to
    // stderr, which the readers here do not keep): the caller then sees no
    // output and no exit marker. A failed send is not an error of its own.
    let _ = channel.data(script.as_bytes()).await;
    let _ = channel.eof().await;
    Ok(())
}

/// `s` as one POSIX sh word (single quotes; a quote inside becomes `'"'"'`).
pub(crate) fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// What happens to output beyond a capture's limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Overflow {
    /// The read fails: more output means the script is broken (the monitor
    /// probe, F-018).
    Fail,
    /// The beginning is kept; the rest is read and dropped.
    KeepHead,
    /// The end is kept: the newest lines of a log.
    KeepTail,
}

/// How many of the newest bytes are always kept, so the exit marker a script
/// prints last is found even when only the head of the output is kept (with
/// room for what a background process might still print after it).
const MARKER_WINDOW: usize = 4096;

/// A script's output held under a byte limit (F-072). Reading always goes on
/// to the end (except with `Overflow::Fail`), so the exit marker the script
/// prints last is read, and a long output is reported as cut, not as failed.
pub(crate) struct Capture {
    limit: usize,
    overflow: Overflow,
    /// `KeepHead`/`Fail`: the first `limit` bytes. `KeepTail`: the newest
    /// bytes (at least `limit + MARKER_WINDOW` of them once that many came).
    kept: Vec<u8>,
    /// `KeepHead`: the newest bytes, for the marker.
    newest: Vec<u8>,
    /// Bytes seen.
    total: usize,
}

/// The output went over the limit of an `Overflow::Fail` capture.
#[derive(Debug)]
pub(crate) struct Overflowed;

/// What a script printed.
#[derive(Debug)]
pub(crate) struct Captured {
    /// The kept part of the output, without the exit marker line.
    pub text: String,
    /// The output was longer than the limit.
    pub truncated: bool,
    /// The code after the last exit marker, when there was one.
    pub exit: Option<i32>,
}

impl Capture {
    pub(crate) fn new(limit: usize, overflow: Overflow) -> Self {
        Capture { limit, overflow, kept: Vec::new(), newest: Vec::new(), total: 0 }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), Overflowed> {
        // A server decides how much it sends, and usize is 32 bits on armv7.
        self.total = self.total.saturating_add(bytes.len());
        match self.overflow {
            Overflow::Fail => {
                if self.total > self.limit {
                    return Err(Overflowed);
                }
                self.kept.extend_from_slice(bytes);
            }
            Overflow::KeepHead => {
                let room = self.limit - self.kept.len();
                self.kept.extend_from_slice(&bytes[..room.min(bytes.len())]);
                self.newest.extend_from_slice(bytes);
                // Trimmed in batches, so a long output is not shifted on every read.
                if self.newest.len() > 2 * MARKER_WINDOW {
                    let cut = self.newest.len() - MARKER_WINDOW;
                    self.newest.drain(..cut);
                }
            }
            Overflow::KeepTail => {
                self.kept.extend_from_slice(bytes);
                let keep = self.limit + MARKER_WINDOW;
                if self.kept.len() > 2 * keep {
                    let cut = self.kept.len() - keep;
                    self.kept.drain(..cut);
                }
            }
        }
        Ok(())
    }

    /// The output, cut at the last `marker` (whose code becomes `exit`), with
    /// at most `limit` bytes of it kept.
    pub(crate) fn finish(self, marker: Option<&str>) -> Captured {
        // A window that ends with the newest byte, and where it starts.
        let (window, window_start) = match self.overflow {
            Overflow::KeepTail => (&self.kept, self.total - self.kept.len()),
            Overflow::KeepHead if self.total > self.kept.len() => (&self.newest, self.total - self.newest.len()),
            _ => (&self.kept, 0),
        };
        let found = marker.and_then(|m| rfind(window, m.as_bytes()).map(|at| (at, m.len())));
        let (end, exit) = match found {
            Some((at, len)) => {
                let after = String::from_utf8_lossy(&window[at + len..]);
                let code = after.split_whitespace().next().and_then(|c| c.parse().ok()).unwrap_or(1);
                (window_start + at, Some(code))
            }
            None => (self.total, None),
        };
        let (bytes, truncated) = match self.overflow {
            Overflow::KeepTail => {
                let kept_start = self.total - self.kept.len();
                let from = end.saturating_sub(self.limit).max(kept_start);
                let mut bytes = &self.kept[from - kept_start..end - kept_start];
                let at_line_start = from > kept_start && self.kept[from - kept_start - 1] == b'\n';
                if from > 0 && !at_line_start {
                    // Start at a whole line (a log's), or at least at a whole character.
                    let skip = match bytes.iter().position(|b| *b == b'\n') {
                        Some(nl) if nl + 1 < bytes.len() => nl + 1,
                        _ => bytes.iter().take(3).take_while(|b| (**b & 0xC0) == 0x80).count(),
                    };
                    bytes = &bytes[skip..];
                }
                (bytes, from > 0)
            }
            _ => {
                let mut bytes = &self.kept[..end.min(self.kept.len())];
                let truncated = end > self.kept.len();
                if truncated {
                    // Do not end in the middle of a character.
                    if let Err(e) = std::str::from_utf8(bytes) {
                        if e.error_len().is_none() {
                            bytes = &bytes[..e.valid_up_to()];
                        }
                    }
                }
                (bytes, truncated)
            }
        };
        Captured { text: String::from_utf8_lossy(bytes).into_owned(), truncated, exit }
    }
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).rev().find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// Why running a script gave no output.
#[derive(Debug)]
pub(crate) enum RunError {
    /// The exec request failed.
    Start(String),
    TimedOut,
    /// More output than an `Overflow::Fail` capture takes.
    Overflowed,
}

/// Runs `script` on `channel` and reads its output into `capture` within
/// `limit`, to the end (the channel closes when the result is dropped).
pub(crate) async fn run(
    channel: Channel<client::Msg>,
    script: &str,
    mut capture: Capture,
    marker: Option<&str>,
    limit: std::time::Duration,
) -> Result<Captured, RunError> {
    use tokio::io::AsyncReadExt;
    // Sending counts too: a server that never opens its window would hold
    // the send forever.
    let run = async {
        send_script(&channel, script).await.map_err(RunError::Start)?;
        let mut stream = channel.into_stream();
        let mut buf = [0u8; 8192];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return Ok(()),
                Ok(n) => capture.push(&buf[..n]).map_err(|Overflowed| RunError::Overflowed)?,
            }
        }
    };
    match tokio::time::timeout(limit, run).await {
        Err(_) => Err(RunError::TimedOut),
        Ok(Err(e)) => Err(e),
        Ok(Ok(())) => Ok(capture.finish(marker)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_test_server::*;

    /// Overflow checks are on in release too, and `usize` is 32 bits on armv7:
    /// a server that keeps sending 4 GiB must not panic this count.
    #[test]
    fn the_count_of_what_a_server_sent_cannot_overflow() {
        for overflow in [Overflow::KeepHead, Overflow::KeepTail] {
            let mut c = Capture::new(4, overflow);
            c.total = usize::MAX - 1;
            assert!(c.push(b"abc").is_ok());
            assert_eq!(c.total, usize::MAX);
        }
    }

    fn captured(limit: usize, overflow: Overflow, chunks: &[&[u8]], marker: Option<&str>) -> Captured {
        let mut c = Capture::new(limit, overflow);
        for chunk in chunks {
            c.push(chunk).unwrap();
        }
        c.finish(marker)
    }

    /// F-072: a short output comes back whole, the marker line removed.
    #[test]
    fn a_short_output_is_whole_and_gives_its_exit_code() {
        for overflow in [Overflow::KeepHead, Overflow::KeepTail, Overflow::Fail] {
            let c = captured(100, overflow, &[b"line 1\nline", b" 2\n__EXIT:", b"3\n"], Some("__EXIT:"));
            assert_eq!((c.text.as_str(), c.truncated, c.exit), ("line 1\nline 2\n", false, Some(3)), "{overflow:?}");
            let c = captured(100, overflow, &[b"no marker"], Some("__EXIT:"));
            assert_eq!((c.text.as_str(), c.truncated, c.exit), ("no marker", false, None));
        }
    }

    /// F-072: a long output keeps its exit code; the head or the tail is kept.
    #[test]
    fn a_long_output_keeps_its_exit_code_and_one_end() {
        let body: Vec<u8> = (0..1000).flat_map(|i| format!("{i:04}\n").into_bytes()).collect();
        let chunks: Vec<&[u8]> = body.chunks(333).chain(std::iter::once(&b"__EXIT:0\n"[..])).collect();
        let head = captured(100, Overflow::KeepHead, &chunks, Some("__EXIT:"));
        assert_eq!((head.exit, head.truncated), (Some(0), true));
        assert_eq!(head.text.as_bytes(), &body[..100]);
        let tail = captured(100, Overflow::KeepTail, &chunks, Some("__EXIT:"));
        assert_eq!((tail.exit, tail.truncated), (Some(0), true));
        assert_eq!(tail.text.as_bytes(), &body[body.len() - 100..]);
        assert!(tail.text.ends_with("0999\n"));
    }

    /// Output that is exactly the limit, followed by the marker, is not cut.
    #[test]
    fn output_of_exactly_the_limit_is_not_cut() {
        let body = vec![b'a'; 100];
        for overflow in [Overflow::KeepHead, Overflow::KeepTail] {
            let c = captured(100, overflow, &[&body, b"__EXIT:7\n"], Some("__EXIT:"));
            assert_eq!((c.text.len(), c.truncated, c.exit), (100, false, Some(7)), "{overflow:?}");
        }
    }

    /// Output that prints a marker of its own: the last one (the script's) wins.
    #[test]
    fn the_last_marker_wins() {
        let c = captured(100, Overflow::KeepHead, &[b"__EXIT:0\nlater\n__EXIT:2\n"], Some("__EXIT:"));
        assert_eq!((c.text.as_str(), c.exit), ("__EXIT:0\nlater\n", Some(2)));
    }

    /// A kept tail does not start in the middle of a character, nor of a
    /// line when it has one; a kept head does not end inside a character.
    #[test]
    fn a_cut_never_splits_a_character_and_a_tail_starts_at_a_line() {
        let body = "é".repeat(100); // 200 bytes, no line break
        let c = captured(101, Overflow::KeepTail, &[body.as_bytes()], None);
        assert!(c.truncated);
        assert_eq!(c.text, "é".repeat(50));
        let c = captured(101, Overflow::KeepHead, &[body.as_bytes()], None);
        assert_eq!((c.text.as_str(), c.truncated), ("é".repeat(50).as_str(), true));
        let log: String = (0..100).map(|i| format!("line {i}\n")).collect();
        let c = captured(100, Overflow::KeepTail, &[log.as_bytes()], None);
        assert!(c.text.starts_with("line ") && c.text.ends_with("line 99\n"), "{:?}", c.text);
    }

    /// Output after the marker (a background process still writing) does not
    /// hide it, while it stays within the window.
    #[test]
    fn output_after_the_marker_does_not_hide_it() {
        let after = vec![b'z'; 3000];
        let c = captured(100, Overflow::KeepHead, &[&[b'a'; 500], b"\n__EXIT:4\n", &after], Some("__EXIT:"));
        assert_eq!((c.exit, c.truncated), (Some(4), true));
    }

    #[test]
    fn a_failing_capture_stops_at_the_limit() {
        let mut c = Capture::new(100, Overflow::Fail);
        assert!(c.push(&[0; 100]).is_ok());
        assert!(c.push(&[0; 1]).is_err());
    }

    /// F-071: the exec request is the fixed `sh` line; the script follows on
    /// stdin, then end-of-file.
    #[tokio::test]
    async fn a_script_goes_to_sh_on_stdin() {
        let (handle, seen) = logged_in(Script { exec_output: Some(b"hi\n".to_vec()), ..Script::default() }).await;
        let channel = crate::ssh_connect::open_session_channel(&handle).await.unwrap();
        send_script(&channel, "echo \"it's\" | cat\n").await.unwrap();
        let mut out = Vec::new();
        let mut channel = channel;
        while let Some(msg) = channel.wait().await {
            if let russh::ChannelMsg::Data { data } = msg {
                out.extend_from_slice(&data);
            }
        }
        assert_eq!(out, b"hi\n");
        let seen = seen.lock().unwrap();
        assert_eq!(seen.execs, [SH_FROM_STDIN]);
        assert_eq!(seen.stdin, b"echo \"it's\" | cat\n");
        assert_eq!(seen.eofs, 1);
    }

    #[test]
    fn quoting_keeps_every_character() {
        assert_eq!(sh_quote("plain"), "'plain'");
        assert_eq!(sh_quote("it's $HOME `x` \\x2d"), "'it'\"'\"'s $HOME `x` \\x2d'");
    }
}
