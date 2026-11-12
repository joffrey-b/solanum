//! What the webview may ask Rust to hand to the operating system: a file to open
//! in its default app, or a local shell to start.
//!
//! Any script running in the webview can call any command it is granted, so a
//! confirmation the webview shows (or a flag it sends saying "the user agreed")
//! proves nothing. Here the confirmation is a native dialog that Rust shows and
//! the webview cannot answer: [`confirm`]. Cancel is its default on every
//! platform, so a reflexive Enter never approves.
//!
//! Some files are never handed over at all, whatever the user answers: on each
//! OS, [`open_verdict`] refuses the types that run as programs, install
//! something or point somewhere else (`.exe`, `.desktop`, `.app`, `.lnk`, ...),
//! and turns scripts the OS would run instead of showing (`.ps1`, `.js` on
//! Windows) into "open as plain text in the text editor".

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// How long the accept button stays disabled after a dialog appears (and, on
/// Linux, after it gets the focus back). Someone typing (Tab, then Enter) when
/// a script makes the dialog pop up would otherwise press Open by accident.
pub(crate) const ACCEPT_DELAY: Duration = Duration::from_millis(1000);

/// Whose file-type rules apply. A parameter (not a `cfg!`) so that every rule
/// set is unit-tested on every OS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Platform {
    Linux,
    MacOs,
    Windows,
}

impl Platform {
    pub(crate) fn current() -> Self {
        if cfg!(windows) {
            Platform::Windows
        } else if cfg!(target_os = "macos") {
            Platform::MacOs
        } else {
            Platform::Linux
        }
    }
}

/// How a file that may be opened is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenAs {
    /// The default app for its type.
    DefaultApp,
    /// A script the default app would run: shown as plain text in the text
    /// editor instead (Windows: Notepad; macOS: the default text editor).
    Text,
}

/// Programs, installers, shortcuts and disk images Windows runs, installs,
/// follows or mounts when they are opened.
const WINDOWS_REFUSED: &[&str] = &[
    "exe", "com", "scr", "pif", "cpl", "msi", "msp", "mst", "msu", "msix", "msixbundle",
    "appx", "appxbundle", "appinstaller", "application", "appref-ms", "gadget", "lnk", "url",
    "website", "scf", "library-ms", "searchconnector-ms", "search-ms", "settingcontent-ms",
    "jar", "jnlp", "chm", "hlp", "msc", "diagcab", "diagcfg", "diagpkg", "xll", "xbap", "vsto",
    "iso", "img", "vhd", "vhdx", "wsb", "theme", "themepack", "deskthemepack", "rdp", "pyc",
    "pyo",
];

/// Text files Windows runs instead of showing (Windows Script Host, cmd,
/// PowerShell, HTML applications, registry imports, and the Python, Perl,
/// Ruby, Tcl, AutoHotkey, AutoIt and Git Bash launchers when installed).
const WINDOWS_SCRIPTS: &[&str] = &[
    "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "wsh", "wsc", "ws", "sct", "hta", "ps1",
    "psm1", "psd1", "ps1xml", "psc1", "reg", "inf", "py", "pyw", "pyz", "pyzw", "pl", "rb", "sh",
    "bash", "tcl", "ahk", "au3",
];

/// Applications and other bundles, installers, disk images, Terminal and
/// Automator documents, and location files macOS runs, installs, mounts or
/// follows when they are opened.
const MACOS_REFUSED: &[&str] = &[
    "app", "command", "tool", "pkg", "mpkg", "dmg", "iso", "img", "sparseimage",
    "sparsebundle", "terminal", "workflow", "action", "wflow", "definition", "prefpane",
    "saver", "kext", "plugin", "bundle", "osax", "qlgenerator", "mdimporter", "xpc",
    "systemextension", "mobileconfig", "webloc", "inetloc", "fileloc", "jar", "jnlp", "pyc",
    "pyo",
];

/// The python.org "Python Launcher" runs these in Terminal when opened.
const MACOS_SCRIPTS: &[&str] = &["py", "pyw"];

/// Desktop entries, AppImages, Java archives, package files, and the Windows
/// programs Wine registers itself for.
const LINUX_REFUSED: &[&str] = &[
    "desktop", "appimage", "jar", "jnlp", "flatpakref", "flatpakrepo", "flatpak", "snap", "deb",
    "rpm", "exe", "com", "msi", "msp", "bat", "cmd", "lnk", "scr", "pif",
];

/// With an execute bit, these (and names without an extension) are programs:
/// macOS runs an executable without an extension in Terminal, and Linux file
/// handlers may offer to run it. A document with an execute bit (every file on
/// a FAT or exFAT stick has one) is still opened.
const UNIX_EXECUTABLE_SCRIPTS: &[&str] =
    &["sh", "bash", "zsh", "ksh", "csh", "fish", "py", "pl", "rb", "run", "bin", "command"];

/// Case-folded text after the last dot, as the OS shell sees it. A leading-dot
/// name (".desktop") counts: file-type globs like `*.desktop` match it.
/// Trailing dots and spaces are dropped first: Windows does that itself
/// ("evil.exe. " opens "evil.exe"), and elsewhere a name that only differs by
/// them is suspect anyway. Folding through upper case maps look-alikes such as
/// the long s ("\u{17F}") and dotless i to the ASCII letters a case-insensitive
/// file-type lookup would match.
fn extension_for(name: &str, _platform: Platform) -> Option<String> {
    let name = name.trim_end_matches(['.', ' ']);
    name.rsplit_once('.').map(|(_, ext)| ext.to_uppercase().to_lowercase()).filter(|ext| !ext.is_empty())
}

/// Why a file whose first bytes are `head` must not be opened, judging by its
/// content where the platform does: Linux desktops pick a file's handler by
/// content when its name does not decide (a Windows program with any unknown
/// extension goes to Wine; a desktop entry named `notes.txt` is still a
/// launcher), and on Unix an executable that starts like a program is one,
/// whatever its name (`tool.x86_64`, `a.out`).
pub(crate) fn content_problem(head: &[u8], platform: Platform, executable: bool) -> Option<&'static str> {
    if platform == Platform::Linux {
        let text = head.strip_prefix(b"\xEF\xBB\xBF".as_slice()).unwrap_or(head);
        let launcher = [b"[Desktop Entry]".as_slice(), b"[Desktop Action", b"[KDE Desktop Entry]", b"# Config File", b"# KDE Config File"];
        if launcher.iter().any(|m| text.starts_with(m)) {
            return Some("It is a desktop launcher, whatever its name says.");
        }
        if head.starts_with(b"MZ") {
            return Some("It is a Windows program, which this system may run (Wine), whatever its name says.");
        }
    }
    if platform != Platform::Windows && executable {
        let program = [
            b"\x7FELF".as_slice(), b"#!", b"\xFE\xED\xFA\xCE", b"\xFE\xED\xFA\xCF", b"\xCE\xFA\xED\xFE",
            b"\xCF\xFA\xED\xFE", b"\xCA\xFE\xBA\xBE", b"\xBE\xBA\xFE\xCA",
        ];
        if program.iter().any(|m| head.starts_with(m)) {
            return Some("It is a program marked executable, so opening it could run it.");
        }
    }
    None
}

/// How many leading bytes [`content_problem`] needs.
pub(crate) const CONTENT_HEAD: usize = 64;

/// Whether a file named `name` may be handed to the OS on `platform`, and how.
/// `executable` is the file's Unix execute bit (ignored on Windows). The error
/// says why not, in words for the user.
pub(crate) fn open_verdict(name: &str, platform: Platform, executable: bool) -> Result<OpenAs, String> {
    if platform == Platform::Windows && name.contains(':') {
        return Err("Its name contains \":\", which Windows reads as a hidden stream of another file.".into());
    }
    let ext = extension_for(name, platform);
    let ext = ext.as_deref();
    let (refused, scripts): (&[&str], &[&str]) = match platform {
        Platform::Windows => (WINDOWS_REFUSED, WINDOWS_SCRIPTS),
        Platform::MacOs => (MACOS_REFUSED, MACOS_SCRIPTS),
        Platform::Linux => (LINUX_REFUSED, &[]),
    };
    if let Some(ext) = ext {
        if refused.contains(&ext) {
            return Err(format!(
                "Solanum does not open programs, installers, shortcuts or disk images, and .{ext} files are one of those on this system."
            ));
        }
    }
    if platform != Platform::Windows && executable && ext.is_none_or(|e| UNIX_EXECUTABLE_SCRIPTS.contains(&e)) {
        return Err("It is marked executable, so opening it could run it.".into());
    }
    match ext {
        Some(ext) if scripts.contains(&ext) => Ok(OpenAs::Text),
        _ => Ok(OpenAs::DefaultApp),
    }
}

/// `text` as it is, except that control, invisible and direction-changing
/// characters are spelled out (`\u202e`, `\u{e0001}`), the same way the
/// webview's `visibleName()` does: a dialog must show the real name, not one a
/// server dressed up ("invoice\u{202E}fdp.exe" renders as "invoiceexe.pdf").
pub(crate) fn visible_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() || crate::local_path::is_spoofing_char(c) || c == '\u{200C}' || c == '\u{200D}' {
            let cp = c as u32;
            if cp > 0xFFFF {
                out.push_str(&format!("\\u{{{cp:x}}}"));
            } else {
                out.push_str(&format!("\\u{cp:04x}"));
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// What a confirmation dialog says. `accept` labels the button that goes ahead
/// (macOS and Linux; Windows message boxes only have OK and Cancel, so the
/// message must say what OK does).
pub(crate) struct Confirm {
    pub(crate) title: String,
    pub(crate) message: String,
    // Windows message boxes have no button label to put it in (N-033).
    #[cfg_attr(windows, allow(dead_code))]
    pub(crate) accept: String,
}

fn kind_of(name: &str, platform: Platform) -> String {
    match extension_for(name, platform) {
        Some(ext) => format!("This .{} file", visible_text(&ext)),
        None => "This file (it has no extension)".into(),
    }
}

fn ok_hint(platform: Platform, what: &str) -> String {
    if platform == Platform::Windows {
        format!("\n\nChoose OK to {what}, Cancel to leave it.")
    } else {
        String::new()
    }
}

fn text_editor(platform: Platform) -> &'static str {
    if platform == Platform::Windows { "Notepad" } else { "your default text editor" }
}

const UNTRUSTED_FILE_WARNING: &str = "Opening a file you do not fully trust can run malicious code on this computer, whatever its type: documents, images and archives can carry exploits too.";

/// `\\?\C:\dir\file` as `C:\dir\file` (and `\\?\UNC\server\share\x` as
/// `\\server\share\x`) when the short form names the same file: under 260
/// characters and every name in it one Windows reads as typed (no trailing
/// dot or space, no device name). `canonicalize` returns the long form, which
/// people do not recognise and some programs cannot open.
pub(crate) fn simplify_verbatim(path: &str) -> Option<String> {
    let short = if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        let rest = path.strip_prefix(r"\\?\")?;
        let b = rest.as_bytes();
        if !(b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') {
            return None;
        }
        rest.to_string()
    };
    if short.encode_utf16().count() >= 260 {
        return None;
    }
    let names = short.trim_start_matches('\\').split('\\').skip(1);
    let ok = names.filter(|n| !n.is_empty()).all(|n| crate::local_path::local_name_problem(n, crate::local_path::LocalOs::Windows).is_none());
    ok.then_some(short)
}

/// A path as the user should read it (and, on Windows, as programs get it).
pub(crate) fn shown_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    if cfg!(windows) {
        if let Some(short) = simplify_verbatim(&text) {
            return short;
        }
    }
    text.into_owned()
}

/// The dialog for opening a local file (already resolved to `path`).
pub(crate) fn confirm_local_open(path: &Path, how: OpenAs, platform: Platform) -> Confirm {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let what = match how {
        OpenAs::DefaultApp => format!("{} will be opened with the default app for its type.", kind_of(&name, platform)),
        OpenAs::Text => format!(
            "{} is a script. It will be shown as plain text in {}, not run.",
            kind_of(&name, platform),
            text_editor(platform)
        ),
    };
    Confirm {
        title: "Open this file?".into(),
        message: format!(
            "{}\n\n{what} A file that came from a server, including one downloaded with Solanum, may not be what it claims. {UNTRUSTED_FILE_WARNING}{}",
            visible_text(&shown_path(path)),
            ok_hint(platform, "open it")
        ),
        accept: "Open".into(),
    }
}

/// The dialog for live-editing a remote file: downloaded to a private staging
/// folder, opened, and uploaded back on every save.
pub(crate) fn confirm_remote_open(remote_path: &str, leaf: &str, how: OpenAs, platform: Platform) -> Confirm {
    let opened = match how {
        OpenAs::DefaultApp => "opened with the default app for its type".to_string(),
        OpenAs::Text => format!("shown as plain text in {} (it is a script; it is not run)", text_editor(platform)),
    };
    Confirm {
        title: "Open a file from the server?".into(),
        message: format!(
            "{}\n\n{} will be downloaded to a private temporary folder on this computer and {opened}. Changes you save there are uploaded back to the server. {UNTRUSTED_FILE_WARNING} Continue only if you trust both the server and this file.{}",
            visible_text(remote_path),
            kind_of(leaf, platform),
            ok_hint(platform, "download and open it")
        ),
        accept: "Download and open".into(),
    }
}

/// The dialog before starting a local shell.
pub(crate) fn confirm_local_shell(program: &str, cwd: Option<&Path>, platform: Platform) -> Confirm {
    let starts_in = match cwd {
        Some(dir) => visible_text(&shown_path(dir)),
        None => "your home folder".into(),
    };
    Confirm {
        title: "Start a local shell?".into(),
        message: format!(
            "Program: {}\nStarts in: {starts_in}\n\nIt runs on this computer with your account's rights, like any terminal window. Continue only if you just asked Solanum for a local shell.{}",
            visible_text(program),
            ok_hint(platform, "start it")
        ),
        accept: "Start shell".into(),
    }
}

/// True while a confirmation is on screen. One at a time: a script cannot
/// stack dialogs, and a second request is refused instead of queued.
static CONFIRM_SHOWING: AtomicBool = AtomicBool::new(false);

struct ShowingGuard;

impl Drop for ShowingGuard {
    fn drop(&mut self) {
        CONFIRM_SHOWING.store(false, Ordering::SeqCst);
    }
}

pub(crate) const CONFIRM_BUSY: &str = "[CONFIRM_BUSY] Another confirmation is waiting for an answer.";

/// Asks the user, in a native dialog owned by `window`, whether to go ahead.
/// `Ok(false)` when they cancel, close the dialog or press Enter or Escape
/// without choosing the accept button.
pub(crate) async fn confirm(window: &tauri::WebviewWindow, request: Confirm) -> Result<bool, String> {
    if CONFIRM_SHOWING.swap(true, Ordering::SeqCst) {
        return Err(CONFIRM_BUSY.into());
    }
    let _showing = ShowingGuard;
    native::ask(window, request).await
}

#[cfg(target_os = "linux")]
pub(crate) mod native {
    use super::Confirm;

    /// A GTK message dialog, modal to and centred on the app window, built on
    /// the main thread (GTK objects live there).
    pub(super) async fn ask(window: &tauri::WebviewWindow, request: Confirm) -> Result<bool, String> {
        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
        let owner = window.clone();
        window
            .run_on_main_thread(move || {
                use gtk::prelude::*;
                let parent = owner.gtk_window().ok();
                show(parent.as_ref().map(|w| w.upcast_ref::<gtk::Window>()), request, move |yes| {
                    let _ = tx.send(yes);
                });
            })
            .map_err(|e| format!("[CONFIRM] Could not show the confirmation dialog: {e}"))?;
        // A dropped sender (the dialog never answered) counts as Cancel.
        Ok(rx.await.unwrap_or(false))
    }

    /// Shows the dialog; `answer` runs once, with `true` only for the accept
    /// button. Cancel is the default response and has the focus, so Enter
    /// cancels; Escape and closing the window answer "delete-event", which is
    /// not Accept either; the accept button is disabled for `ACCEPT_DELAY`
    /// after the dialog appears or regains the focus. The text is plain: a
    /// name containing Pango markup is shown as typed.
    pub(crate) fn show(parent: Option<&gtk::Window>, request: Confirm, answer: impl FnOnce(bool) + 'static) -> gtk::MessageDialog {
        use gtk::prelude::*;
        let dialog = gtk::MessageDialog::new(
            parent,
            gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
            gtk::MessageType::Warning,
            gtk::ButtonsType::None,
            &request.title,
        );
        dialog.set_secondary_text(Some(&request.message));
        dialog.add_button("Cancel", gtk::ResponseType::Cancel);
        dialog.add_button(&request.accept, gtk::ResponseType::Accept);
        dialog.set_default_response(gtk::ResponseType::Cancel);
        // Open stays disabled for ACCEPT_DELAY after the dialog appears and
        // each time it gets the focus back, so keys typed for something else
        // (Tab, then Enter) cannot reach it. A newer arming supersedes an
        // older timer.
        let armed = std::rc::Rc::new(std::cell::Cell::new(0u32));
        let arm = {
            let weak = dialog.downgrade();
            std::rc::Rc::new(move || {
                let Some(dialog) = weak.upgrade() else { return };
                dialog.set_response_sensitive(gtk::ResponseType::Accept, false);
                let generation = armed.get().wrapping_add(1);
                armed.set(generation);
                let (weak, armed) = (dialog.downgrade(), armed.clone());
                gtk::glib::timeout_add_local_once(super::ACCEPT_DELAY, move || {
                    if let (true, Some(dialog)) = (armed.get() == generation, weak.upgrade()) {
                        dialog.set_response_sensitive(gtk::ResponseType::Accept, true);
                    }
                });
            })
        };
        arm();
        dialog.connect_focus_in_event(move |_, _| {
            arm();
            gtk::glib::Propagation::Proceed
        });
        // Long paths have no spaces to break at.
        if let Ok(area) = dialog.message_area().downcast::<gtk::Container>() {
            for child in area.children() {
                if let Ok(label) = child.downcast::<gtk::Label>() {
                    label.set_line_wrap_mode(gtk::pango::WrapMode::WordChar);
                }
            }
        }
        let answer = std::cell::RefCell::new(Some(answer));
        dialog.connect_response(move |dialog, response| {
            if let Some(answer) = answer.borrow_mut().take() {
                answer(response == gtk::ResponseType::Accept);
            }
            // SAFETY: nothing uses the dialog after this point (the test
            // keeps a reference but only drops it). Destroying a dialog from
            // its own "response" handler is the standard GTK pattern.
            unsafe { dialog.destroy() };
        });
        dialog.show_all();
        if let Some(cancel) = dialog.widget_for_response(gtk::ResponseType::Cancel) {
            cancel.grab_focus();
        }
        dialog
    }
}

#[cfg(windows)]
mod native {
    use super::Confirm;
    use core::ffi::c_void;
    use std::sync::atomic::{AtomicIsize, Ordering};

    type Hwnd = *mut c_void;
    type HookProc = unsafe extern "system" fn(i32, usize, isize) -> isize;
    type TimerProc = unsafe extern "system" fn(Hwnd, u32, usize, u32);

    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(owner: Hwnd, text: *const u16, caption: *const u16, style: u32) -> i32;
        fn SetWindowsHookExW(id: i32, hook: Option<HookProc>, module: *mut c_void, thread: u32) -> *mut c_void;
        fn UnhookWindowsHookEx(hook: *mut c_void) -> i32;
        fn CallNextHookEx(hook: *mut c_void, code: i32, wparam: usize, lparam: isize) -> isize;
        fn GetDlgItem(dialog: Hwnd, id: i32) -> Hwnd;
        fn EnableWindow(window: Hwnd, enable: i32) -> i32;
        fn SetTimer(window: Hwnd, id: usize, milliseconds: u32, timer: Option<TimerProc>) -> usize;
        fn KillTimer(window: Hwnd, id: usize) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThreadId() -> u32;
    }
    const MB_OKCANCEL: u32 = 0x0000_0001;
    const MB_ICONWARNING: u32 = 0x0000_0030;
    const MB_DEFBUTTON2: u32 = 0x0000_0100;
    const MB_SETFOREGROUND: u32 = 0x0001_0000;
    const IDOK: i32 = 1;
    const WH_CBT: i32 = 5;
    const HCBT_ACTIVATE: i32 = 5;
    const ENABLE_OK_TIMER: usize = 0x501A;

    /// The hook around the one message box on screen (one dialog at a time).
    static HOOK: AtomicIsize = AtomicIsize::new(0);

    /// Runs on the message box's thread when its window is about to be
    /// activated: disable OK, and re-enable it after `ACCEPT_DELAY`. Once.
    unsafe extern "system" fn on_cbt(code: i32, wparam: usize, lparam: isize) -> isize {
        let hook = HOOK.load(Ordering::SeqCst) as *mut c_void;
        let next = CallNextHookEx(hook, code, wparam, lparam);
        if code == HCBT_ACTIVATE && HOOK.swap(0, Ordering::SeqCst) != 0 {
            UnhookWindowsHookEx(hook);
            let dialog = wparam as Hwnd;
            let ok = GetDlgItem(dialog, IDOK);
            if !ok.is_null() {
                EnableWindow(ok, 0);
                SetTimer(dialog, ENABLE_OK_TIMER, super::ACCEPT_DELAY.as_millis() as u32, Some(enable_ok));
            }
        }
        next
    }

    unsafe extern "system" fn enable_ok(dialog: Hwnd, _message: u32, timer: usize, _time: u32) {
        KillTimer(dialog, timer);
        let ok = GetDlgItem(dialog, IDOK);
        if !ok.is_null() {
            EnableWindow(ok, 1);
        }
    }

    /// A system message box owned by the app window (which it disables while
    /// open). `MB_DEFBUTTON2` makes Cancel the default button, so Enter
    /// cancels; Escape and the close box answer Cancel too; OK is disabled
    /// for `ACCEPT_DELAY` after the box appears (a thread-local CBT hook finds
    /// the box). Runs on a blocking thread: `MessageBoxW` returns only when
    /// the user answers.
    pub(super) async fn ask(window: &tauri::WebviewWindow, request: Confirm) -> Result<bool, String> {
        let owner = window.hwnd().map(|h| h.0 as isize).unwrap_or(0);
        tokio::task::spawn_blocking(move || {
            let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
            let (text, caption) = (wide(&request.message), wide(&request.title));
            // SAFETY: a hook for this thread only (no module handle needed);
            // `on_cbt` removes it at the first activation, and it is removed
            // here if that never happened.
            unsafe {
                let hook = SetWindowsHookExW(WH_CBT, Some(on_cbt), core::ptr::null_mut(), GetCurrentThreadId());
                HOOK.store(hook as isize, Ordering::SeqCst);
            }
            // SAFETY: both buffers are NUL-terminated UTF-16 that outlive the
            // call (the text has no interior NUL: `visible_text` spells
            // control characters out), and `owner` is this app's own window
            // handle or null.
            let answer = unsafe {
                MessageBoxW(
                    owner as Hwnd,
                    text.as_ptr(),
                    caption.as_ptr(),
                    MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND,
                )
            };
            let left = HOOK.swap(0, Ordering::SeqCst);
            if left != 0 {
                // SAFETY: the handle came from SetWindowsHookExW above and was not removed yet.
                unsafe { UnhookWindowsHookEx(left as *mut c_void) };
            }
            answer == IDOK
        })
        .await
        .map_err(|e| format!("[CONFIRM] The confirmation dialog failed: {e}"))
    }
}

#[cfg(target_os = "macos")]
mod native {
    use super::Confirm;

    /// An `NSAlert` sheet on the app window, through rfd (which runs it on the
    /// main thread). `NSAlert` makes its first button the default (Return),
    /// so Cancel is added first: Return cancels, and Escape either cancels or
    /// does nothing; the accept button needs a click (or Tab and Space when
    /// Full Keyboard Access is on). rfd cannot disable it for `ACCEPT_DELAY`.
    pub(super) async fn ask(window: &tauri::WebviewWindow, request: Confirm) -> Result<bool, String> {
        let accept = request.accept.clone();
        let answer = rfd::AsyncMessageDialog::new()
            .set_level(rfd::MessageLevel::Warning)
            .set_title(request.title)
            .set_description(request.message)
            .set_buttons(rfd::MessageButtons::OkCancelCustom("Cancel".into(), request.accept))
            .set_parent(window)
            .show()
            .await;
        Ok(answer == rfd::MessageDialogResult::Custom(accept))
    }
}

#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
mod native {
    use super::Confirm;

    /// No native dialog here (Android has no file opening or local shell).
    pub(super) async fn ask(_window: &tauri::WebviewWindow, _request: Confirm) -> Result<bool, String> {
        Err("[CONFIRM] Confirmation dialogs are not available on this platform.".into())
    }
}

/// Hands `path` to the OS as `how` says. Desktop only.
#[cfg(not(target_os = "android"))]
pub(crate) fn launch(path: &Path, how: OpenAs) -> Result<(), String> {
    match how {
        // `child_env::open_detached`: on Windows ShellExecuteExW (the
        // `shellexecute-on-windows` feature). `open::that` runs
        // `cmd /c start "" "<path>"`, and cmd expands `%VAR%` even inside
        // quotes, so "run.ex%TEMP:~0,0%e" would start "run.exe". On Linux the
        // app gets the user's environment, not Solanum's workarounds (F-014).
        OpenAs::DefaultApp => {
            crate::child_env::open_detached(shown_path(path).as_ref()).map_err(|e| format!("Failed to open file: {e}"))
        }
        OpenAs::Text => open_as_text(path),
    }
}

#[cfg(windows)]
fn open_as_text(path: &Path) -> Result<(), String> {
    let notepad = windows_dir().join("System32").join("notepad.exe");
    if !notepad.is_file() {
        return Err("Notepad is not installed, and Solanum does not hand scripts to the app that would run them.".into());
    }
    std::process::Command::new(notepad)
        .arg(shown_path(path))
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Failed to start Notepad: {e}"))
}

#[cfg(target_os = "macos")]
fn open_as_text(path: &Path) -> Result<(), String> {
    // `open -t`: the user's default text editor, whatever the file's type.
    let status = std::process::Command::new("/usr/bin/open")
        .arg("-t")
        .arg(path)
        .status()
        .map_err(|e| format!("Failed to open file: {e}"))?;
    if status.success() { Ok(()) } else { Err(format!("Failed to open file: open -t exited with {status}")) }
}

#[cfg(all(not(windows), not(target_os = "macos"), not(target_os = "android")))]
fn open_as_text(_path: &Path) -> Result<(), String> {
    // `open_verdict` has no script category on Linux.
    Err("Opening as text is not available on this system.".into())
}

/// The Windows folder (`%SystemRoot%`), only if the environment names an
/// absolute path; `C:\Windows` otherwise. Used to start system programs by
/// absolute path, never through a `PATH` search.
#[cfg(windows)]
pub(crate) fn windows_dir() -> PathBuf {
    absolute_env_dir("SystemRoot", r"C:\Windows")
}

/// `%name%` if it is an absolute path, else `fallback`.
#[cfg(windows)]
pub(crate) fn absolute_env_dir(name: &str, fallback: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from(fallback))
}

/// A local file that may be opened: where it resolves to, how it is opened,
/// and enough about it (size, times, and on Unix device, inode and mode) to
/// notice that it was swapped or changed while the dialog was up.
#[derive(Debug, PartialEq)]
pub(crate) struct LocalOpen {
    pub(crate) path: PathBuf,
    pub(crate) how: OpenAs,
    stamp: FileStamp,
}

#[derive(Debug, PartialEq)]
struct FileStamp {
    len: u64,
    modified: Option<std::time::SystemTime>,
    created: Option<std::time::SystemTime>,
    dev: u64,
    ino: u64,
    mode: u32,
}

/// What a local file resolves to and how it may be opened: the path goes
/// through the read policy, must be a regular file (folders, macOS bundles
/// included, are browsed, not opened; FIFOs and devices are refused), both the
/// name the caller gave and the resolved name pass [`open_verdict`], and its
/// first bytes pass [`content_problem`]. Errors start with `[OPEN_REFUSED]`
/// when the file exists but may not be opened.
pub(crate) fn check_local_open(path: &str, platform: Platform) -> Result<LocalOpen, String> {
    use std::io::Read;
    let resolved = crate::local_path::guard_local_path(path, crate::local_path::LocalAccess::Read)?;
    let meta = std::fs::metadata(&resolved).map_err(|e| format!("Cannot open {}: {e}", visible_text(path)))?;
    if meta.is_dir() {
        return Err("[OPEN_REFUSED] It is a folder; Solanum opens folders in its own file browser.".into());
    }
    if !meta.is_file() {
        return Err("[OPEN_REFUSED] It is not a regular file.".into());
    }
    #[cfg(unix)]
    let (executable, unix_id) = {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        (meta.permissions().mode() & 0o111 != 0, (meta.dev(), meta.ino(), meta.mode()))
    };
    #[cfg(not(unix))]
    let (executable, unix_id) = (false, (0, 0, 0));

    let given = Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let real = resolved.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let refuse = |why: String| format!("[OPEN_REFUSED] {why}");
    open_verdict(&given, platform, executable).map_err(refuse)?;
    let how = open_verdict(&real, platform, executable).map_err(refuse)?;

    let mut head = Vec::with_capacity(CONTENT_HEAD);
    std::fs::File::open(&resolved)
        .and_then(|f| f.take(CONTENT_HEAD as u64).read_to_end(&mut head))
        .map_err(|e| format!("Cannot read {}: {e}", visible_text(path)))?;
    if let Some(why) = content_problem(&head, platform, executable) {
        return Err(refuse(why.to_string()));
    }
    let stamp = FileStamp {
        len: meta.len(),
        modified: meta.modified().ok(),
        created: meta.created().ok(),
        dev: unix_id.0,
        ino: unix_id.1,
        mode: unix_id.2,
    };
    Ok(LocalOpen { path: resolved, how, stamp })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Platform; 3] = [Platform::Linux, Platform::MacOs, Platform::Windows];

    #[test]
    fn programs_installers_and_shortcuts_are_refused_on_their_platform() {
        for (platform, list) in [(Platform::Windows, WINDOWS_REFUSED), (Platform::MacOs, MACOS_REFUSED), (Platform::Linux, LINUX_REFUSED)] {
            for ext in list {
                for name in [format!("x.{ext}"), format!("X.{}", ext.to_uppercase()), format!("invoice.pdf.{ext}"), format!(".{ext}")] {
                    let err = open_verdict(&name, platform, false).unwrap_err();
                    assert!(!err.contains("decrypt"), "{err}");
                    assert!(err.contains(ext), "{platform:?} {name}: {err}");
                }
            }
        }
        // The ones the batch spec names explicitly, per platform.
        for ext in ["exe", "bat", "cmd", "com", "scr", "msi", "lnk", "url", "js", "vbs", "hta", "ps1", "reg", "cpl"] {
            assert_ne!(open_verdict(&format!("a.{ext}"), Platform::Windows, false), Ok(OpenAs::DefaultApp), "{ext}");
        }
        for ext in ["app", "command", "pkg", "dmg", "terminal"] {
            assert!(open_verdict(&format!("a.{ext}"), Platform::MacOs, false).is_err(), "{ext}");
        }
        for name in ["a.desktop", "a.AppImage"] {
            assert!(open_verdict(name, Platform::Linux, false).is_err(), "{name}");
        }
    }

    #[test]
    fn scripts_the_os_would_run_open_as_text() {
        for ext in WINDOWS_SCRIPTS {
            assert_eq!(open_verdict(&format!("deploy.{ext}"), Platform::Windows, false), Ok(OpenAs::Text), "{ext}");
            assert_eq!(open_verdict(&format!("DEPLOY.{}", ext.to_uppercase()), Platform::Windows, false), Ok(OpenAs::Text), "{ext}");
        }
        assert_eq!(open_verdict("tool.py", Platform::MacOs, false), Ok(OpenAs::Text));
        // A Linux desktop opens a non-executable script in its text editor anyway.
        assert_eq!(open_verdict("deploy.sh", Platform::Linux, false), Ok(OpenAs::DefaultApp));
        assert_eq!(open_verdict("tool.py", Platform::Linux, false), Ok(OpenAs::DefaultApp));
    }

    #[test]
    fn windows_sees_the_extension_windows_acts_on() {
        for name in ["evil.exe.", "evil.exe ", "evil.exe. .", "EVIL.EXE...", "notes.txt:evil.exe", "notes.txt:x", "doc.pdf::$DATA"] {
            assert!(open_verdict(name, Platform::Windows, false).is_err(), "{name}");
        }
        // Elsewhere a colon is an ordinary character; trailing dots and
        // spaces are dropped everywhere before the extension is read.
        assert_eq!(open_verdict("2024:01:01.log", Platform::Linux, false), Ok(OpenAs::DefaultApp));
        assert_eq!(open_verdict("report.pdf.", Platform::Linux, false), Ok(OpenAs::DefaultApp));
        for name in ["evil.desktop ", "evil.desktop.", "evil.desktop. ."] {
            assert!(open_verdict(name, Platform::Linux, false).is_err(), "{name:?}");
        }
        // Characters whose upper case is ASCII: long s, dotless i.
        assert!(open_verdict("evil.\u{17F}cr", Platform::Windows, false).is_err());
        assert!(open_verdict("evil.p\u{131}f", Platform::Windows, false).is_err());
        assert!(open_verdict("evil.\u{17F}h", Platform::Windows, false) == Ok(OpenAs::Text));
    }

    #[test]
    fn content_decides_where_the_desktop_would_sniff_it() {
        let elf = b"\x7FELF\x02\x01\x01";
        let macho = b"\xCF\xFA\xED\xFE\x07";
        // Linux: launchers and Windows programs, whatever the name or mode.
        for head in [b"[Desktop Entry]\nExec=sh".as_slice(), b"\xEF\xBB\xBF[Desktop Entry]", b"# Config File\n", b"[KDE Desktop Entry]", b"MZ\x90\x00"] {
            assert!(content_problem(head, Platform::Linux, false).is_some(), "{head:?}");
        }
        assert!(content_problem(b"MZ", Platform::MacOs, false).is_none());
        assert!(content_problem(b"MZ", Platform::Windows, false).is_none());
        // Unix: an executable that starts like a program is one.
        for platform in [Platform::Linux, Platform::MacOs] {
            for head in [elf.as_slice(), macho, b"#!/bin/sh\n", b"\xCA\xFE\xBA\xBE"] {
                assert!(content_problem(head, platform, true).is_some(), "{platform:?} {head:?}");
                assert!(content_problem(head, platform, false).is_none(), "{platform:?} {head:?} not executable");
            }
            for head in [b"%PDF-1.7".as_slice(), b"\x89PNG", b"", b"plain text"] {
                assert!(content_problem(head, platform, true).is_none(), "{platform:?} {head:?}");
            }
        }
        assert!(content_problem(elf, Platform::Windows, true).is_none());
    }

    #[test]
    fn verbatim_paths_are_shown_short_only_when_that_is_the_same_file() {
        assert_eq!(simplify_verbatim(r"\\?\C:\Users\u\report.pdf").as_deref(), Some(r"C:\Users\u\report.pdf"));
        assert_eq!(simplify_verbatim(r"\\?\UNC\server\share\a.txt").as_deref(), Some(r"\\server\share\a.txt"));
        assert_eq!(simplify_verbatim(r"\\?\C:\").as_deref(), Some(r"C:\"));
        // Names Windows would read differently without the prefix stay long.
        for long in [r"\\?\C:\dir\evil.exe.", r"\\?\C:\dir\CON", r"\\?\C:\dir\a ", r"\\?\Volume{x}\a", r"C:\plain"] {
            assert_eq!(simplify_verbatim(long), None, "{long}");
        }
        let deep = format!(r"\\?\C:\{}", "d\\".repeat(130));
        assert_eq!(simplify_verbatim(&deep), None);
    }

    #[test]
    fn the_execute_bit_refuses_programs_but_not_documents_on_unix() {
        for platform in [Platform::Linux, Platform::MacOs] {
            for name in ["tool", "Makefile", "install.sh", "run.bin", "setup.run", "x.py", "go.command", "build.ZSH"] {
                assert!(open_verdict(name, platform, true).is_err(), "{platform:?} {name}");
            }
            // FAT/exFAT sticks mark every file executable.
            for name in ["report.pdf", "photo.jpg", "notes.txt", "data.csv"] {
                assert_eq!(open_verdict(name, platform, true), Ok(OpenAs::DefaultApp), "{platform:?} {name}");
            }
        }
        // Windows has no execute bit.
        assert_eq!(open_verdict("tool", Platform::Windows, true), Ok(OpenAs::DefaultApp));
    }

    #[test]
    fn ordinary_documents_open_with_their_default_app_everywhere() {
        for platform in ALL {
            for name in ["report.pdf", "photo.JPG", "notes.txt", "archive.tar.gz", "README", ".bashrc", "config.yaml", "invoice.exe.pdf"] {
                assert_eq!(open_verdict(name, platform, false), Ok(OpenAs::DefaultApp), "{platform:?} {name}");
            }
        }
        // Each platform's list is its own: a .desktop file is text on Windows.
        assert_eq!(open_verdict("app.desktop", Platform::Windows, false), Ok(OpenAs::DefaultApp));
        assert_eq!(open_verdict("setup.ps1", Platform::Linux, false), Ok(OpenAs::DefaultApp));
    }

    #[test]
    fn visible_text_spells_out_what_would_disguise_a_name() {
        assert_eq!(visible_text("invoice\u{202E}fdp.exe"), "invoice\\u202efdp.exe");
        assert_eq!(visible_text("a\u{200B}b\u{200D}c\u{E0041}"), "a\\u200bb\\u200dc\\u{e0041}");
        assert_eq!(visible_text("line\nbreak\0nul\u{7F}"), "line\\u000abreak\\u0000nul\\u007f");
        assert_eq!(visible_text("caf\u{E9} <b>&amp;</b> \u{2764}\u{FE0F}"), "caf\u{E9} <b>&amp;</b> \u{2764}\u{FE0F}");
    }

    #[test]
    fn dialogs_name_the_file_and_what_will_happen() {
        let c = confirm_remote_open("/srv/a\u{202E}b.ps1", "a\u{202E}b.ps1", OpenAs::Text, Platform::Windows);
        assert!(c.message.starts_with("/srv/a\\u202eb.ps1\n\n"), "{}", c.message);
        assert!(c.message.contains(".ps1 file") && c.message.contains("Notepad") && c.message.contains("not run"));
        assert!(c.message.contains("uploaded back") && c.message.ends_with("Choose OK to download and open it, Cancel to leave it."));
        let c = confirm_local_open(Path::new("/home/u/report.pdf"), OpenAs::DefaultApp, Platform::Linux);
        assert!(c.message.starts_with("/home/u/report.pdf\n\nThis .pdf file will be opened with the default app"));
        assert!(!c.message.contains("Choose OK"));
        assert_eq!((c.title.as_str(), c.accept.as_str()), ("Open this file?", "Open"));
        let c = confirm_local_open(Path::new("/home/u/README"), OpenAs::DefaultApp, Platform::MacOs);
        assert!(c.message.contains("no extension"));
    }

    #[test]
    fn the_shell_dialog_names_the_program_and_folder() {
        let c = confirm_local_shell("/usr/bin/zsh", Some(Path::new("/home/u/x\u{202E}y")), Platform::Linux);
        assert_eq!(c.title, "Start a local shell?");
        assert!(c.message.starts_with("Program: /usr/bin/zsh\nStarts in: /home/u/x\\u202ey\n\n"), "{}", c.message);
        let c = confirm_local_shell(r"C:\Windows\System32\cmd.exe", None, Platform::Windows);
        assert!(c.message.contains("Starts in: your home folder") && c.message.ends_with("Choose OK to start it, Cancel to leave it."));
    }

    #[test]
    fn only_one_confirmation_at_a_time() {
        assert!(!CONFIRM_SHOWING.swap(true, Ordering::SeqCst));
        {
            let _showing = ShowingGuard;
            assert!(CONFIRM_SHOWING.load(Ordering::SeqCst));
        }
        assert!(!CONFIRM_SHOWING.load(Ordering::SeqCst));
    }

    /// The real GTK dialog: Enter, Space and Escape answer no, only the accept
    /// button answers yes, and the text is not markup. Needs a display, and
    /// core X input events (GTK's simulated keys are core events, which GDK
    /// ignores in its default XInput2 mode):
    /// `GDK_CORE_DEVICE_EVENTS=1 xvfb-run -a cargo test --lib -- --ignored native_dialog`.
    /// (The Gdk-CRITICAL lines it prints come from each simulated key release
    /// arriving after the press already closed the dialog.)
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn native_dialog_only_the_accept_button_says_yes() {
        use gtk::prelude::*;
        use std::{cell::Cell, rc::Rc, time::{Duration, Instant}};
        gtk::init().expect("needs a display: run under xvfb-run");
        let run = |act: &dyn Fn(&gtk::MessageDialog)| -> Option<bool> {
            let got = Rc::new(Cell::new(None));
            let seen = got.clone();
            let request = Confirm { title: "Open this file?".into(), message: "/tmp/<b>bold</b>.pdf".into(), accept: "Open".into() };
            let dialog = native::show(None, request, move |yes| seen.set(Some(yes)));
            dialog.present();
            let settle = Instant::now() + Duration::from_millis(300);
            while Instant::now() < settle {
                gtk::main_iteration_do(false);
                std::thread::sleep(Duration::from_millis(5));
            }
            let cancel = dialog.widget_for_response(gtk::ResponseType::Cancel).unwrap();
            assert_eq!(dialog.focused_widget().as_ref(), Some(&cancel), "Cancel has the focus");
            assert_eq!(dialog.default_widget().as_ref(), Some(&cancel), "Cancel is the default");
            let labels: Vec<gtk::Label> = dialog.message_area().downcast::<gtk::Container>().unwrap()
                .children().into_iter().filter_map(|w| w.downcast::<gtk::Label>().ok()).collect();
            assert!(labels.iter().all(|l| !l.uses_markup()), "plain text");
            assert!(labels.iter().any(|l| l.text() == "/tmp/<b>bold</b>.pdf"), "shown as typed");
            act(&dialog);
            let deadline = Instant::now() + Duration::from_secs(5);
            while got.get().is_none() && Instant::now() < deadline {
                gtk::main_iteration_do(false);
                std::thread::sleep(Duration::from_millis(5));
            }
            got.get()
        };
        let key = |k: gtk::gdk::keys::Key| move |d: &gtk::MessageDialog| assert!(gtk::test_widget_send_key(d, *k, gtk::gdk::ModifierType::empty()));
        assert_eq!(run(&key(gtk::gdk::keys::constants::Return)), Some(false), "Enter");
        assert_eq!(run(&key(gtk::gdk::keys::constants::KP_Enter)), Some(false), "keypad Enter");
        assert_eq!(run(&key(gtk::gdk::keys::constants::space)), Some(false), "Space on the focused button");
        assert_eq!(run(&key(gtk::gdk::keys::constants::Escape)), Some(false), "Escape");
        // Tab then Enter right away: Open is still disabled, so Tab cannot
        // reach it and Enter presses Cancel.
        let tab_enter = |d: &gtk::MessageDialog| {
            let accept = d.widget_for_response(gtk::ResponseType::Accept).unwrap();
            assert!(!accept.is_sensitive(), "Open is disabled at first");
            for k in [gtk::gdk::keys::constants::Tab, gtk::gdk::keys::constants::Return] {
                assert!(gtk::test_widget_send_key(d, *k, gtk::gdk::ModifierType::empty()));
            }
        };
        assert_eq!(run(&tab_enter), Some(false), "Tab, Enter at once");
        // After the delay, Tab reaches Open and Enter presses it.
        let wait_then_tab_enter = |d: &gtk::MessageDialog| {
            let accept = d.widget_for_response(gtk::ResponseType::Accept).unwrap();
            let until = Instant::now() + super::ACCEPT_DELAY + Duration::from_millis(300);
            while Instant::now() < until {
                gtk::main_iteration_do(false);
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(accept.is_sensitive(), "Open is enabled after the delay");
            for k in [gtk::gdk::keys::constants::Tab, gtk::gdk::keys::constants::Return] {
                assert!(gtk::test_widget_send_key(d, *k, gtk::gdk::ModifierType::empty()));
            }
        };
        assert_eq!(run(&wait_then_tab_enter), Some(true), "Tab, Enter after the delay");
    }

    #[cfg(unix)]
    #[test]
    fn local_files_are_checked_by_what_they_resolve_to() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("solanum-open-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let s = |p: &Path| p.to_str().unwrap().to_string();

        let doc = dir.join("report.pdf");
        std::fs::write(&doc, b"%PDF").unwrap();
        let first = check_local_open(&s(&doc), Platform::Linux).unwrap();
        assert_eq!((first.path.clone(), first.how), (std::fs::canonicalize(&doc).unwrap(), OpenAs::DefaultApp));
        // The same file checks the same; a changed one does not.
        assert_eq!(check_local_open(&s(&doc), Platform::Linux).unwrap(), first);
        std::fs::write(&doc, b"%PDF-1.7 and more").unwrap();
        assert_ne!(check_local_open(&s(&doc), Platform::Linux).unwrap(), first);
        let other = dir.join("other.pdf");
        std::fs::write(&other, b"%PDF").unwrap();
        let before = check_local_open(&s(&doc), Platform::Linux).unwrap();
        std::fs::rename(&other, &doc).unwrap();
        assert_ne!(check_local_open(&s(&doc), Platform::Linux).unwrap(), before, "swapped for another file");

        // Content: a launcher or Windows program under a harmless name.
        let fake_txt = dir.join("readme.txt");
        std::fs::write(&fake_txt, b"[Desktop Entry]\nExec=sh -c id\n").unwrap();
        assert!(check_local_open(&s(&fake_txt), Platform::Linux).unwrap_err().contains("launcher"));
        let fake_dat = dir.join("game.dat");
        std::fs::write(&fake_dat, b"MZ\x90\x00").unwrap();
        assert!(check_local_open(&s(&fake_dat), Platform::Linux).unwrap_err().contains("Windows program"));
        // An executable program with an extension no list knows.
        let elf = dir.join("tool.x86_64");
        std::fs::write(&elf, b"\x7FELF\x02\x01").unwrap();
        std::fs::set_permissions(&elf, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_local_open(&s(&elf), Platform::Linux).unwrap_err().contains("program"));
        std::fs::set_permissions(&elf, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(check_local_open(&s(&elf), Platform::Linux).is_ok(), "not executable: opened by its name");

        // A link that looks like a document but resolves to a launcher.
        let launcher = dir.join("evil.desktop");
        std::fs::write(&launcher, b"[Desktop Entry]\nExec=sh\n").unwrap();
        let disguised = dir.join("notes.txt");
        symlink(&launcher, &disguised).unwrap();
        let err = check_local_open(&s(&disguised), Platform::Linux).unwrap_err();
        assert!(err.starts_with("[OPEN_REFUSED]") && err.contains(".desktop"), "{err}");
        // And the other way round: the name the caller gave counts too.
        let named = dir.join("run.desktop");
        symlink(&doc, &named).unwrap();
        assert!(check_local_open(&s(&named), Platform::Linux).unwrap_err().starts_with("[OPEN_REFUSED]"));

        // Execute bit: a program without an extension is refused, a document is not.
        let prog = dir.join("tool");
        std::fs::write(&prog, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_local_open(&s(&prog), Platform::Linux).unwrap_err().contains("executable"));
        std::fs::set_permissions(&doc, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_local_open(&s(&doc), Platform::Linux).is_ok());

        // Folders are browsed, not opened (a macOS .app is a folder).
        let bundle = dir.join("Thing.app");
        std::fs::create_dir(&bundle).unwrap();
        assert!(check_local_open(&s(&bundle), Platform::MacOs).unwrap_err().contains("folder"));
        assert!(check_local_open(&s(&dir), Platform::Linux).unwrap_err().contains("folder"));
        // Missing files and device files.
        assert!(!check_local_open(&s(&dir.join("missing.pdf")), Platform::Linux).unwrap_err().starts_with("[OPEN_REFUSED]"));
        assert!(check_local_open("/dev/null", Platform::Linux).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
