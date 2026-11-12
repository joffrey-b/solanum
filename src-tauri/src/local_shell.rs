// Local (non-SSH) shell tab. Wires a real local PTY into the exact same
// terminal-IO pipeline every other terminal kind already uses: a
// `TerminalCommand` sender in `SshState.terminal_txs`, a `PtySize` watch
// sender in `.resize_txs`, `emit_terminal_batch` for output, and a
// `terminal-closed-{id}` event on exit. See `open_terminal` (lib.rs) and
// `open_container_terminal` (docker.rs) for the two existing instances of
// this same registration pattern — this is a third. Because all of that is
// already generic over `terminal_id`, `write_terminal_data`,
// `resize_terminal` and `close_terminal` need no changes at all, and
// TerminalView's "Session stopped" overlay / R-to-restart / session-logging
// features all work here for free.
//
// What runs is not the webview's choice: `list_local_shells` offers the
// shells this machine has (Unix: `/etc/shells`; Windows: a fixed set of
// system shells by absolute path), the UI sends an index into that list, and
// Rust shows a native confirmation (`open_guard::confirm`, Cancel by default)
// before every spawn. A script running in the webview can therefore neither
// start an arbitrary program nor open a shell silently; it could still type
// into a shell the user opened (documented in SECURITY.md).
//
// Not available on Android — there's no local-shell concept in Tauri's
// Android sandbox (no predictable shell binary, no notion of a user home
// directory the way desktop has). `portable-pty` is a desktop-only
// dependency (see Cargo.toml), so only its import and the real
// implementation live behind `#[cfg(not(target_os = "android"))]`; the
// command function's SIGNATURE always exists, same convention as
// `select_local_folder` elsewhere in this codebase, so it can be registered
// unconditionally in `tauri::generate_handler!` without the macro ever
// having to understand a conditional parameter list.

use crate::ssh_manager::SshState;
#[cfg(not(target_os = "android"))]
use crate::open_guard;
#[cfg(not(target_os = "android"))]
use crate::ssh_manager::{start_session_log, PtySize as OurPtySize, TerminalCommand};
use std::path::{Path, PathBuf};
#[cfg(not(target_os = "android"))]
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
#[cfg(not(target_os = "android"))]
use std::io::{Read, Write};
#[cfg(not(target_os = "android"))]
use tauri::Emitter;

#[cfg(not(target_os = "android"))]
fn clamp_u16(v: u32) -> u16 {
    v.min(u16::MAX as u32) as u16
}

/// One entry of the shell list the UI offers.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ShellChoice {
    name: String,
    /// Shown to the user (the program's path, or a description of the default).
    shown: String,
    program: ShellProgram,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ShellProgram {
    /// portable-pty's `new_default_prog()`: `$SHELL` if it is executable, else
    /// the login shell from the user database, started as a login shell.
    #[cfg_attr(windows, allow(dead_code))]
    UnixLoginShell,
    /// An absolute path to an executable.
    Path(PathBuf),
}

#[derive(serde::Serialize)]
pub struct LocalShellInfo {
    name: String,
    path: String,
}

/// The canonical target of `path` if it is an executable regular file.
#[cfg(unix)]
fn executable_file(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        return None;
    }
    std::fs::canonicalize(path).ok()
}

/// The shells listed in `/etc/shells` content: absolute paths only, kept when
/// `usable` resolves them (to the file they really are), each target once
/// (Debian lists `/bin/bash` and `/usr/bin/bash`), in file order.
#[cfg(unix)]
fn shells_from_etc_shells(content: &str, usable: impl Fn(&Path) -> Option<PathBuf>) -> Vec<ShellChoice> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let path = Path::new(line);
        if line.is_empty() || !path.is_absolute() {
            continue;
        }
        let Some(target) = usable(path) else { continue };
        if !seen.insert(target) {
            continue;
        }
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| line.to_string());
        out.push(ShellChoice { name, shown: line.to_string(), program: ShellProgram::Path(path.to_path_buf()) });
    }
    out
}

/// The default login shell first, then `/etc/shells`.
#[cfg(unix)]
fn available_shells() -> Vec<ShellChoice> {
    let login = std::env::var_os("SHELL")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute() && executable_file(p).is_some());
    let mut shells = vec![ShellChoice {
        name: match &login {
            Some(p) => format!("Default ({})", p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()),
            None => "Default".into(),
        },
        shown: match &login {
            Some(p) => format!("{} (login shell)", p.display()),
            None => "your login shell".into(),
        },
        program: ShellProgram::UnixLoginShell,
    }];
    let listed = std::fs::read_to_string("/etc/shells").unwrap_or_default();
    shells.extend(shells_from_etc_shells(&listed, executable_file));
    shells
}

/// The Windows shells, by absolute path under `windows_dir` and
/// `program_files`, in order of preference; the first one present is the
/// default. Absolute paths mean no `PATH` search can substitute another
/// program.
#[cfg(any(windows, test))]
fn windows_shell_candidates(windows_dir: &Path, program_files: &Path) -> Vec<(&'static str, PathBuf)> {
    let system32 = windows_dir.join("System32");
    vec![
        ("Windows PowerShell", system32.join("WindowsPowerShell").join("v1.0").join("powershell.exe")),
        ("PowerShell 7", program_files.join("PowerShell").join("7").join("pwsh.exe")),
        ("Command Prompt", system32.join("cmd.exe")),
        ("WSL", system32.join("wsl.exe")),
        ("Git Bash", program_files.join("Git").join("bin").join("bash.exe")),
    ]
}

#[cfg(windows)]
fn available_shells() -> Vec<ShellChoice> {
    let windows_dir = crate::open_guard::windows_dir();
    let program_files = crate::open_guard::absolute_env_dir("ProgramFiles", r"C:\Program Files");
    windows_shell_candidates(&windows_dir, &program_files)
        .into_iter()
        .filter(|(_, path)| path.is_file())
        .map(|(name, path)| ShellChoice { name: name.into(), shown: path.display().to_string(), program: ShellProgram::Path(path) })
        .collect()
}

/// The local shells this machine offers, default first. The UI shows these and
/// sends back an index (`open_local_terminal`'s `shell_index`).
#[tauri::command]
pub async fn list_local_shells() -> Result<Vec<LocalShellInfo>, String> {
    #[cfg(target_os = "android")]
    {
        Err("Local shell is not available on Android.".into())
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(available_shells().into_iter().map(|s| LocalShellInfo { name: s.name, path: s.shown }).collect())
    }
}

/// The starting folder for a local shell: it must pass the read policy and
/// be an existing folder; the resolved path is used.
#[cfg(not(target_os = "android"))]
fn checked_cwd(dir: &str) -> Result<PathBuf, String> {
    let resolved = crate::local_path::guard_local_path(dir, crate::local_path::LocalAccess::Read)
        .map_err(|e| format!("[LOCAL_SHELL] BAD_CWD: {}", e))?;
    if !resolved.is_dir() {
        return Err(format!("[LOCAL_SHELL] BAD_CWD: {} is not a folder", open_guard::visible_text(dir)));
    }
    Ok(resolved)
}

/// A local shell for `terminal_io::pump`: its PTY is read and written by two
/// threads of its own (portable-pty's reader and writer block).
#[cfg(not(target_os = "android"))]
struct LocalPty {
    output: tokio::sync::mpsc::Receiver<Vec<u8>>,
    input: tokio::sync::mpsc::UnboundedSender<(Vec<u8>, crate::terminal_io::Queued)>,
    /// What the writer thread holds for a program that has not read it (R-002).
    queue: crate::terminal_io::InputQueue,
    killer: Box<dyn portable_pty::ChildKiller + Send + Sync>,
    master: Box<dyn portable_pty::MasterPty + Send>,
}

#[cfg(not(target_os = "android"))]
impl LocalPty {
    /// Starts `cmd` on a new PTY of `cols`×`rows`.
    fn start(cmd: CommandBuilder, cols: u32, rows: u32) -> Result<LocalPty, String> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: clamp_u16(rows),
                cols: clamp_u16(cols),
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| format!("[LOCAL_SHELL] PTY_OPEN_FAILED: {}", e))?;

        let mut child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| format!("[LOCAL_SHELL] SPAWN_FAILED: {}", e))?;
        // Only the master side is needed past this point; dropping our end
        // of the slave explicitly (rather than waiting for portable-pty to
        // do it implicitly) ensures the child sees normal EOF behavior
        // instead of a held slave fd keeping the pty "open" from our side.
        drop(pair.slave);

        // Split out a killer BEFORE child moves into the reader thread below
        // (see its own comment) — this is the documented way to retain the
        // ability to terminate the child from this task while `.wait()` runs
        // on a different, blocked thread.
        let killer = child.clone_killer();

        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| format!("[LOCAL_SHELL] READER_FAILED: {}", e))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| format!("[LOCAL_SHELL] WRITER_FAILED: {}", e))?;
        let master = pair.master;

        // portable-pty's reader/writer are blocking std::io::{Read,Write},
        // not async — each gets a dedicated OS thread bridged into the tokio
        // world over an mpsc, the standard pattern for wrapping blocking I/O
        // for an async task. The async task below never makes a blocking call
        // itself. The output side is bounded (F-031): should the task fall
        // behind, the reader waits and the shell's writes block in the PTY
        // instead of the output piling up here.
        //
        // Reader thread also reaps the child with `.wait()` right after EOF,
        // on the same thread, so closing a local-shell tab doesn't leave a
        // zombie process behind.
        let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        std::thread::spawn(move || {
            let mut buf = [0u8; 32 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = child.wait();
        });

        // Writer thread: same reasoning, opposite direction. `blocking_recv`
        // is the tokio mpsc receiver's escape hatch for exactly this — a
        // plain OS thread pulling from a channel the async side sends into.
        // A program that stops reading leaves this thread blocked in the PTY;
        // the queue in front of it is capped (`InputQueue`).
        let (in_tx, mut in_rx) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, crate::terminal_io::Queued)>();
        std::thread::spawn(move || {
            let mut writer = writer;
            while let Some((data, _place)) = in_rx.blocking_recv() {
                if writer.write_all(&data).is_err() {
                    break;
                }
            }
        });
        Ok(LocalPty { output: out_rx, input: in_tx, queue: Default::default(), killer, master })
    }
}

#[cfg(not(target_os = "android"))]
impl crate::terminal_io::TerminalIo for LocalPty {
    async fn next_output(&mut self) -> Option<Vec<u8>> {
        self.output.recv().await
    }

    async fn send_input(&mut self, data: Vec<u8>) -> crate::terminal_io::Input {
        use crate::terminal_io::Input;
        let place = match self.queue.admit(data.len()) {
            Ok(place) => place,
            Err(refused) => return refused,
        };
        if self.input.send((data, place)).is_ok() {
            Input::Accepted
        } else {
            Input::Gone
        }
    }

    async fn resize_pty(&mut self, size: OurPtySize) {
        let _ = self.master.resize(PtySize {
            rows: clamp_u16(size.rows),
            cols: clamp_u16(size.cols),
            pixel_width: 0,
            pixel_height: 0,
        });
    }

    /// Unlike an SSH channel, dropping our side does not make a local
    /// program exit, so closing the tab kills it.
    async fn end(&mut self) {
        let _ = self.killer.kill();
    }

    /// The PTY's output ends when its shell exits.
    fn ended_by_peer(&self) -> bool {
        true
    }
}

pub(crate) const LOCAL_SHELL_CANCELLED: &str = "[LOCAL_SHELL] CANCELLED: the local shell was not started";

#[tauri::command]
pub async fn open_local_terminal(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: tauri::State<'_, SshState>,
    terminal_id: String,
    cols: u32,
    rows: u32,
    shell_index: u32,
    cwd: Option<String>,
    log_file_path: Option<String>,
) -> Result<Option<String>, String> {
    #[cfg(target_os = "android")]
    {
        // Silence "unused" warnings for the params this branch doesn't
        // touch — the signature has to stay identical to the real one.
        let _ = (&app, &window, &state, &terminal_id, cols, rows, shell_index, &cwd, &log_file_path);
        return Err("Local shell is not available on Android.".into());
    }

    #[cfg(not(target_os = "android"))]
    {
        let choice = available_shells()
            .into_iter()
            .nth(shell_index as usize)
            .ok_or("[LOCAL_SHELL] UNKNOWN_SHELL: that shell is not in this computer's list of shells")?;
        let cwd = cwd.as_deref().map(checked_cwd).transpose()?;
        // A lock (or a reload) while the question is open: no shell after it.
        let epoch = state.epoch();
        if epoch.closing() {
            return Err(crate::ssh_manager::PROFILE_CLOSING_MSG.into());
        }
        let request = open_guard::confirm_local_shell(&choice.shown, cwd.as_deref(), open_guard::Platform::current());
        if !open_guard::confirm(&window, request).await? || !epoch.current() {
            return Err(LOCAL_SHELL_CANCELLED.into());
        }

        let mut cmd = match &choice.program {
            ShellProgram::UnixLoginShell => CommandBuilder::new_default_prog(),
            ShellProgram::Path(path) => CommandBuilder::new(path),
        };
        if let Some(dir) = &cwd {
            cmd.cwd(dir);
        }
        // The user's environment, not the one Solanum's window runs with (F-014).
        crate::child_env::scrub_pty(&mut cmd, crate::child_env::for_children());
        let mut io = LocalPty::start(cmd, cols, rows)?;

        let (tx, rx) = tokio::sync::mpsc::channel::<TerminalCommand>(32);
        let (resize_tx, resize_rx) = tokio::sync::watch::channel(OurPtySize { cols, rows });
        {
            // Checked under the map's lock: a teardown that began meanwhile
            // has cleared it, or will clear it after this insert.
            let mut txs = state.terminal_txs.lock().await;
            if !epoch.current() {
                drop(txs);
                let _ = io.killer.kill();
                return Err(LOCAL_SHELL_CANCELLED.into());
            }
            txs.insert(terminal_id.clone(), tx);
        }
        state.resize_txs.lock().await.insert(terminal_id.clone(), resize_tx);

        let terminal_id_clone = terminal_id.clone();
        let app_clone = app.clone();
        let (txs, resizes) = (std::sync::Arc::clone(&state.terminal_txs), std::sync::Arc::clone(&state.resize_txs));
        // "Always save terminal output to file": see open_terminal.
        let (session_log, log_problem) = start_session_log(&log_file_path).await;
        tauri::async_runtime::spawn(async move {
            let emit = |bytes: &[u8]| crate::ssh_manager::emit_terminal_batch(&app_clone, &terminal_id_clone, bytes);
            crate::terminal_io::pump(io, rx, resize_rx, session_log, emit).await;
            crate::ssh_manager::forget_ended_terminal(&txs, &resizes, &terminal_id_clone).await;
            let _ = app_clone.emit(&format!("terminal-closed-{}", terminal_id_clone), serde_json::json!({}));
        });

        Ok(log_problem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A local shell through the terminal loop: output arrives, keys reach
    /// the program, and closing the tab kills it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_local_pty_runs_through_the_pump_and_closing_kills_it() {
        use crate::ssh_manager::{PtySize as Size, TerminalCommand};
        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.args(["-c", "echo ready; read x; echo got-$x; exec sleep 60"]);
        let io = LocalPty::start(cmd, 80, 24).unwrap();
        let (input, input_rx) = tokio::sync::mpsc::channel(32);
        let (_sizes, sizes_rx) = tokio::sync::watch::channel(Size { cols: 80, rows: 24 });
        let shown = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let sink = std::sync::Arc::clone(&shown);
        let pump = tokio::spawn(crate::terminal_io::pump(io, input_rx, sizes_rx, None, move |b: &[u8]| sink.lock().unwrap().extend_from_slice(b)));
        let has = |s: &str| String::from_utf8_lossy(&shown.lock().unwrap()).contains(s);
        assert!(crate::ssh_test_server::eventually(|| has("ready")).await);
        input.send(TerminalCommand::Data(b"abc\r".to_vec())).await.unwrap();
        assert!(crate::ssh_test_server::eventually(|| has("got-abc")).await);
        drop(input);
        tokio::time::timeout(std::time::Duration::from_secs(5), pump).await.expect("closing the tab did not end the shell").unwrap();
    }

    /// Output nobody acknowledges does not stop a local program: it runs to
    /// the end, the window gets its credit and the notice.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_local_flood_runs_to_the_end_without_acknowledgements() {
        use crate::ssh_manager::PtySize as Size;
        let mut cmd = CommandBuilder::new("/bin/sh");
        cmd.args(["-c", "head -c 12000000 /dev/zero | tr '\\0' a; echo; echo local-done"]);
        let io = LocalPty::start(cmd, 80, 24).unwrap();
        let (_input, input_rx) = tokio::sync::mpsc::channel(32);
        let (_sizes, sizes_rx) = tokio::sync::watch::channel(Size { cols: 80, rows: 24 });
        let shown = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let sink = std::sync::Arc::clone(&shown);
        let pump = tokio::spawn(crate::terminal_io::pump(io, input_rx, sizes_rx, None, move |b: &[u8]| sink.lock().unwrap().extend_from_slice(b)));
        tokio::time::timeout(std::time::Duration::from_secs(60), pump).await.expect("the program did not finish").unwrap();
        let text = String::from_utf8_lossy(&shown.lock().unwrap()).into_owned();
        assert!(text.contains("of output not shown") && text.trim_end().ends_with("local-done"));
    }

    #[cfg(unix)]
    #[test]
    fn etc_shells_gives_absolute_usable_shells_once_each() {
        let content = "# /etc/shells: valid login shells\n/bin/sh\n/usr/bin/sh\n\n/bin/bash  # the usual\nbash\n./zsh\n/usr/bin/bash\n/opt/missing\n/usr/bin/zsh\n/usr/bin/tmux\n";
        // /bin and /usr/bin are the same folder (merged /usr); /opt/missing does not exist.
        let usable = |p: &Path| -> Option<PathBuf> {
            let s = p.to_str().unwrap();
            if s == "/opt/missing" { return None; }
            Some(PathBuf::from(s.replace("/usr/bin/", "/bin/")))
        };
        let shells = shells_from_etc_shells(content, usable);
        let shown: Vec<&str> = shells.iter().map(|s| s.shown.as_str()).collect();
        assert_eq!(shown, ["/bin/sh", "/bin/bash", "/usr/bin/zsh", "/usr/bin/tmux"]);
        let names: Vec<&str> = shells.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["sh", "bash", "zsh", "tmux"]);
        assert!(shells.iter().all(|s| matches!(&s.program, ShellProgram::Path(p) if p.is_absolute())));
        assert!(shells_from_etc_shells("", usable).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn only_executable_regular_files_count_as_shells() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("solanum-shells-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("goodsh");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let plain = dir.join("plainsh");
        std::fs::write(&plain, b"").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.join("linksh");
        std::os::unix::fs::symlink(&exe, &link).unwrap();
        let content = format!("{}\n{}\n{}\n{}\n{}\n", exe.display(), plain.display(), dir.display(), link.display(), dir.join("nope").display());
        let shells = shells_from_etc_shells(&content, executable_file);
        let shown: Vec<String> = shells.iter().map(|s| s.shown.clone()).collect();
        // The link is the same program as goodsh, so it is listed once.
        assert_eq!(shown, [exe.display().to_string()]);
        // The default entry always comes first.
        let all = available_shells();
        assert_eq!(all[0].program, ShellProgram::UnixLoginShell);
        assert!(all[1..].iter().all(|s| matches!(&s.program, ShellProgram::Path(p) if p.is_absolute())));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn windows_shells_are_absolute_paths_under_the_system_folders() {
        let windows = Path::new("/W");
        let program_files = Path::new("/P");
        let candidates = windows_shell_candidates(windows, program_files);
        assert_eq!(candidates[0].0, "Windows PowerShell");
        for (name, path) in &candidates {
            assert!(path.starts_with(windows) || path.starts_with(program_files), "{name}: {path:?}");
            assert!(path.extension().is_some_and(|e| e == "exe"), "{name}: {path:?}");
        }
        assert!(candidates.iter().any(|(_, p)| p == &windows.join("System32").join("cmd.exe")));
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn the_starting_folder_must_be_an_existing_folder() {
        let dir = std::env::temp_dir().join(format!("solanum-shell-cwd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        assert_eq!(checked_cwd(dir.to_str().unwrap()).unwrap(), std::fs::canonicalize(&dir).unwrap());
        assert!(checked_cwd(file.to_str().unwrap()).unwrap_err().contains("not a folder"));
        assert!(checked_cwd(dir.join("missing").to_str().unwrap()).unwrap_err().contains("BAD_CWD"));
        #[cfg(target_os = "linux")]
        assert!(checked_cwd("/proc/self").unwrap_err().contains("BAD_CWD"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
