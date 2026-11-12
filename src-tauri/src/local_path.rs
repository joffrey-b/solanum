//! Turning names and paths this app does not control into local paths.
//!
//! Two kinds of input are untrusted here:
//!
//! * **Names from the SFTP wire.** A malicious or compromised server picks every
//!   file name it lists, and an SFTP name is an opaque byte string: it can be
//!   `../.bashrc`, `..\..\Startup\x.bat`, `C:x`, `CON`, or `invoice\u{202E}fdp.exe`
//!   (which displays as "invoiceexe.pdf"). Such a name is checked once, at the
//!   point where it becomes a local path ([`local_name_problem`]), with the rules
//!   of the OS this app runs on: a backslash is an ordinary character on Linux but
//!   a separator on Windows. Listings show every entry and remote-side operations
//!   (rename, delete, chmod) keep working on odd names; only turning one into a
//!   local file is refused.
//! * **Paths from the webview.** The local file browser legitimately roams the
//!   user's disk, so [`guard_local_path`] cannot confine it to one folder. It
//!   refuses what no file browser needs: changing system folders, auto-start
//!   locations and the user's own start-up and credential files, deleting the
//!   home folder, and reading device or kernel files.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

/// Whose file-name rules apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocalOs {
    /// Linux, macOS, Android: only `/` and NUL are special.
    Unix,
    /// Separators, drive letters, stream names, device names, trailing dots.
    Windows,
}

impl LocalOs {
    pub(crate) fn current() -> Self {
        if cfg!(windows) { LocalOs::Windows } else { LocalOs::Unix }
    }
}

/// Characters that make a name lie about itself on screen: bidi controls (U+202E
/// turns "invoice\u{202E}fdp.exe" into "invoiceexe.pdf") and invisible ones that
/// make look-alike duplicates: soft hyphen, combining grapheme joiner, Hangul
/// and Mongolian fillers, zero-width space, line and paragraph separators, word
/// joiner and invisible operators, deprecated format characters, BOM,
/// interlinear annotation marks and tag characters. ZWNJ/ZWJ (U+200C, U+200D)
/// and variation selectors are not here: Persian, Indic scripts and emoji
/// ("\u{2764}\u{FE0F}") need them.
pub(crate) fn is_spoofing_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{180E}'
        | '\u{200B}' | '\u{200E}' | '\u{200F}' | '\u{2028}'..='\u{202E}'
        | '\u{2060}'..='\u{206F}' | '\u{3164}' | '\u{FEFF}' | '\u{FFA0}'
        | '\u{FFF9}'..='\u{FFFB}' | '\u{E0000}'..='\u{E007F}')
}

/// Device names Windows reserves in every folder, with or without an extension
/// and in any case (`con`, `Con.txt`, `NUL .tar.gz`).
fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$") {
        return true;
    }
    (stem.starts_with("COM") || stem.starts_with("LPT"))
        && matches!(&stem[3..], "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "\u{B9}" | "\u{B2}" | "\u{B3}")
}

/// Why `name` cannot be used as a single local file name on `os`, or `None` if it can.
pub(crate) fn local_name_problem(name: &str, os: LocalOs) -> Option<&'static str> {
    if name.is_empty() {
        return Some("the name is empty");
    }
    if name == "." || name == ".." {
        return Some("the name is a path step");
    }
    if name.contains('/') {
        return Some("the name contains a path separator");
    }
    // Cc: NUL and the other C0 controls, DEL, and the C1 controls.
    if name.chars().any(char::is_control) {
        return Some("the name contains control characters");
    }
    if name.chars().any(is_spoofing_char) {
        return Some("the name contains invisible or text-direction characters");
    }
    match os {
        LocalOs::Unix => {
            if name.len() > 255 {
                return Some("the name is too long");
            }
        }
        LocalOs::Windows => {
            if name.encode_utf16().count() > 255 {
                return Some("the name is too long");
            }
            if name.contains(['\\', ':', '*', '?', '"', '<', '>', '|']) {
                return Some("the name contains a character Windows does not allow (\\ : * ? \" < > |)");
            }
            if name.ends_with('.') || name.ends_with(' ') {
                return Some("the name ends with a dot or a space, which Windows drops");
            }
            if is_windows_device_name(name) {
                return Some("the name is reserved for a device on Windows");
            }
        }
    }
    None
}

/// True when an SFTP directory-entry name can be joined onto a local folder as
/// one plain file name on this OS (see [`local_name_problem`]). Callers skip a
/// rejected entry.
pub(crate) fn is_safe_dir_entry_name(name: &str) -> bool {
    local_name_problem(name, LocalOs::current()).is_none()
}

/// The last component of a remote (POSIX) path: the name its local copy gets.
/// A path with `.`/`..` steps or a NUL is refused: listings never produce one
/// (folders come from the server's `realpath`, and a real name cannot contain
/// `/`), so it can only come from a listed name that smuggles in a `/`.
pub(crate) fn remote_leaf(remote_path: &str) -> Result<&str, String> {
    let trimmed = remote_path.trim_end_matches('/');
    let unsafe_path = trimmed.contains('\0') || trimmed.split('/').any(|c| c == "." || c == "..");
    let leaf = trimmed.rsplit('/').next().unwrap_or("");
    if unsafe_path || leaf.is_empty() {
        return Err(format!("[UNSAFE_NAME] {:?} does not name a single remote file or folder", remote_path));
    }
    Ok(leaf)
}

/// Where the download of a remote item named `leaf` lands in the user's chosen
/// folder `local_dir`, or why it cannot. The folder must exist; the name must be
/// a plain local name on this OS; the joined path must sit directly in the
/// (canonical) folder; and it must pass the write policy.
pub(crate) fn download_target(local_dir: &str, leaf: &str) -> Result<PathBuf, String> {
    download_target_for(local_dir, leaf, LocalOs::current(), home_for_policy().as_deref())
}

fn download_target_for(local_dir: &str, leaf: &str, os: LocalOs, home: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(why) = local_name_problem(leaf, os) {
        return Err(format!(
            "[UNSAFE_NAME] {:?} can't be saved under that name on this computer: {}. Rename it on the server first.",
            leaf, why
        ));
    }
    let dir = Path::new(local_dir);
    if !dir.is_absolute() {
        return Err("Destination folder: not an absolute path".into());
    }
    let dir = dir.canonicalize().map_err(|e| format!("Destination folder: {}", e))?;
    if !dir.is_dir() {
        return Err("Destination is not a folder".into());
    }
    // A dot name directly in the home folder is a configuration file that the
    // shell or some program may load (`.bash_aliases`, `.bashrc.d/`, `.vimrc`,
    // ...): too many to list, and no download needs to create one there.
    if leaf.starts_with('.') && home == Some(dir.as_path()) {
        return Err(format!(
            "Refusing to save {:?} directly in your home folder: names starting with a dot there are configuration files. Download it into another folder.",
            leaf
        ));
    }
    let target = dir.join(leaf);
    // The validator is the gate; this is the proof. Nothing the join produced may
    // have replaced the folder (a drive-relative name on Windows does) or added steps.
    if target.parent() != Some(dir.as_path()) || target.file_name() != Some(OsStr::new(leaf)) {
        return Err(format!("[UNSAFE_NAME] {:?} would not land inside the chosen folder", leaf));
    }
    guard_path(&target, LocalAccess::Write, os, home)
}

/// Create the session log at `path` ("Always save terminal output to file"):
/// always a new file, owner-only (0600 on Unix), never an existing one. The
/// folder comes from the frontend's settings, so a compromised webview could
/// point it anywhere: the name must end in `.log` and be a plain local name,
/// and the file must pass the write policy. Folders created on the way are
/// owner-only (0700) too. If the name is taken, `-2`, `-3`, ... is appended
/// before `.log`.
pub(crate) fn create_session_log(path: &Path) -> Result<std::fs::File, String> {
    create_session_log_for(path, LocalOs::current(), home_for_policy().as_deref())
}

fn create_session_log_for(path: &Path, os: LocalOs, home: Option<&Path>) -> Result<std::fs::File, String> {
    let name = path.file_name().and_then(OsStr::to_str).unwrap_or("");
    let stem = name.strip_suffix(".log").filter(|s| !s.is_empty())
        .ok_or_else(|| format!("a session log name must end in .log: {:?}", name))?;
    if let Some(why) = local_name_problem(name, os) {
        return Err(format!("unusable session log name {:?}: {}", name, why));
    }
    let checked = guard_path(path, LocalAccess::Write, os, home)?;
    let dir = checked.parent().ok_or("session log has no folder")?;
    create_private_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
    for n in 1..=99 {
        let candidate = if n == 1 { checked.clone() } else { dir.join(format!("{}-{}.log", stem, n)) };
        match crate::create_private_file(&candidate, true) {
            Ok(file) => return Ok(file),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {}", candidate.display(), e)),
        }
    }
    Err(format!("too many session logs named {:?} already", name))
}

/// `create_dir_all`, with the folders it creates owner-only on Unix (existing
/// ones are left as they are).
fn create_private_dir_all(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Why `path` cannot be the local folder of a folder mirror, or `None`. A
/// mirror reads every file in that folder and writes downloads into it, so it
/// must be an existing folder, a new file directly inside it must pass the
/// write policy (no system folders, `~/.ssh`, auto-start folders, ...), and it
/// may be neither the filesystem root nor the home folder nor a folder that
/// holds the home folder (the mirror would upload every key and token in it).
/// The folder itself is never replaced, so one that only holds protected
/// entries (`~/.config`) is accepted: each file written later is checked on
/// its own (F-008).
pub(crate) fn mirror_root_problem(path: &Path) -> Option<String> {
    mirror_root_problem_for(path, LocalOs::current(), home_for_policy().as_deref())
}

fn mirror_root_problem_for(path: &Path, os: LocalOs, home: Option<&Path>) -> Option<String> {
    if !path.is_absolute() {
        return Some(format!("The local folder must be an absolute path: {}", path.display()));
    }
    let real = match path.canonicalize() {
        Ok(real) => real,
        Err(e) => return Some(format!("The local folder cannot be used ({}): {}", e, path.display())),
    };
    if !real.is_dir() {
        return Some(format!("The local path is not a folder: {}", path.display()));
    }
    if real.parent().is_none() {
        return Some(format!("Refusing to mirror the filesystem root: {}", path.display()));
    }
    if let Some(home) = home {
        let home_norm = normalize_for_policy(&home.to_string_lossy());
        if is_at_or_under(&home_norm, &normalize_for_policy(&real.to_string_lossy())) {
            return Some(format!("Refusing to mirror your home folder or a folder that contains it: {}", path.display()));
        }
    }
    check_policy(&real.join("solanum-mirror-check"), LocalAccess::Write, os, home)
        .err()
        .map(|why| format!("The mirror cannot write into this folder. {}", why))
}

/// What a webview-supplied local path is about to be used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocalAccess {
    /// Listing, reading an upload source, opening or revealing. Must exist.
    Read,
    /// Creating or replacing: download targets, new folders, rename targets,
    /// session logs. Missing folders on the way are allowed (checked before
    /// anything is created).
    Write,
    /// Deleting, or moving away (a rename source). Must exist. The last component
    /// is never followed: a symlink is removed or moved itself.
    Remove,
}

/// Check a webview-supplied local path for `access` and return the path to act
/// on: canonical for `Read`; for `Write` and `Remove`, the canonical parent joined
/// with the path's own last component (so a symlink there is the thing changed,
/// not what it points to). Refused: relative paths, the filesystem root, and
/// what the policy forbids (see [`policy_violation`]).
pub(crate) fn guard_local_path(path: impl AsRef<Path>, access: LocalAccess) -> Result<PathBuf, String> {
    guard_path(path.as_ref(), access, LocalOs::current(), home_for_policy().as_deref())
}

/// The user's home folder, canonical, for the home-relative rules.
fn home_for_policy() -> Option<PathBuf> {
    let home = directories::UserDirs::new()?.home_dir().to_path_buf();
    Some(home.canonicalize().unwrap_or(home))
}

fn guard_path(path: &Path, access: LocalAccess, os: LocalOs, home: Option<&Path>) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("Invalid path (not absolute): {}", path.display()));
    }
    // On Windows `name:stream` and `dir::$INDEX_ALLOCATION` name NTFS streams;
    // a file browser never needs them, and they are other names for files.
    if os == LocalOs::Windows
        && path.components().any(|c| matches!(c, Component::Normal(n) if n.to_string_lossy().contains(':')))
    {
        return Err(format!("Invalid path (':' after the drive): {}", path.display()));
    }
    let resolved = match access {
        LocalAccess::Read => path.canonicalize().map_err(|e| format!("Invalid path: {}", e))?,
        LocalAccess::Write | LocalAccess::Remove => {
            let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
                return Err(format!("Refusing to operate on filesystem root: {}", path.display()));
            };
            let parent = if access == LocalAccess::Remove {
                parent.canonicalize().map_err(|e| format!("Invalid path: {}", e))?
            } else {
                resolve_with_new_tail(parent)?
            };
            let own = parent.join(name);
            match std::fs::symlink_metadata(&own) {
                Ok(meta) if meta.file_type().is_symlink() && access == LocalAccess::Write => {
                    // Writing to a symlink writes to its target: that is what has to pass.
                    let target = own.canonicalize()
                        .map_err(|_| format!("Refusing to write through a broken symbolic link: {}", own.display()))?;
                    check_policy(&target, access, os, home)?;
                }
                Ok(_) => {
                    // An existing name can be another spelling of a protected
                    // file (a Windows 8.3 short name like `GITCON~1`, a case
                    // variant on macOS): check the name the system stored too.
                    if let Ok(real) = own.canonicalize() {
                        if real != own {
                            check_policy(&real, access, os, home)?;
                        }
                    }
                }
                Err(e) if access == LocalAccess::Remove => return Err(format!("Invalid path: {}", e)),
                Err(_) => {}
            }
            own
        }
    };
    check_policy(&resolved, access, os, home)?;
    Ok(resolved)
}

/// Canonicalise the longest existing ancestor of `path` and re-append the
/// missing rest, so a path several new folders deep is checked against where it
/// really lands before any of them is created. The missing part may only hold
/// plain names, and a broken symlink on the way is refused.
fn resolve_with_new_tail(path: &Path) -> Result<PathBuf, String> {
    let mut existing = path;
    let mut tail: Vec<&OsStr> = Vec::new();
    loop {
        match std::fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let Some(Component::Normal(name)) = existing.components().next_back() else {
                    return Err(format!("Invalid path: {}", path.display()));
                };
                tail.push(name);
                existing = existing.parent().ok_or_else(|| format!("Invalid path: {}", path.display()))?;
            }
            Err(e) => return Err(format!("Invalid path: {}", e)),
        }
    }
    let mut out = existing.canonicalize().map_err(|e| format!("Invalid path: {}", e))?;
    for name in tail.iter().rev() {
        out.push(name);
    }
    Ok(out)
}

fn check_policy(path: &Path, access: LocalAccess, os: LocalOs, home: Option<&Path>) -> Result<(), String> {
    if path.parent().is_none() {
        return Err(format!("Refusing to operate on filesystem root: {}", path.display()));
    }
    let norm = normalize_for_policy(&path.to_string_lossy());
    let home_norm = home.map(|h| normalize_for_policy(&h.to_string_lossy()));
    match policy_violation(&norm, access, os, home_norm.as_deref()) {
        Some(why) => Err(format!("{}: {}", why, path.display())),
        None => Ok(()),
    }
}

/// Lower-cased, `/`-separated, without Windows' verbatim (`\\?\`, `\\?\UNC\`) or
/// device (`\\.\`) prefixes and without a trailing slash: the form the lists below use.
fn normalize_for_policy(path: &str) -> String {
    let mut norm = path.to_lowercase().replace('\\', "/");
    // canonicalize() on Windows returns verbatim paths (`\\?\C:\Windows`), which
    // would never match `c:/windows`.
    if let Some(rest) = norm.strip_prefix("//?/unc/") {
        norm = format!("//{}", rest);
    } else if let Some(rest) = norm.strip_prefix("//?/") {
        norm = rest.to_string();
    } else if let Some(rest) = norm.strip_prefix("//./") {
        norm = rest.to_string();
    }
    let trimmed = norm.trim_end_matches('/');
    if trimmed.is_empty() { "/".into() } else { trimmed.to_string() }
}

/// System folders nothing in the file browser should change. Linux, plus where
/// macOS resolves its `/etc`, `/var` and `/tmp` symlinks (`/private/...`, which a
/// canonical path always shows) and its own system folders. `/var/run` resolves
/// to `/run` on current Linux systems.
const SYSTEM_UNIX: &[&str] = &[
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/boot",
    "/sys", "/proc", "/dev", "/var/log", "/var/run", "/run", "/root",
    "/system", "/library", "/applications", "/var/root", "/var/db",
    "/private/etc", "/private/var/log", "/private/var/run", "/private/var/root", "/private/var/db",
];
/// Inside `SYSTEM_UNIX` but ordinary user storage: udisks mounts removable
/// drives under `/run/media`; `/run/user/<uid>` is the user's own runtime folder
/// (GVFS shares, MTP phones, the document portal), except its `systemd` folder
/// (see [`is_user_runtime_systemd`]).
const SYSTEM_UNIX_EXCEPTIONS: &[&str] = &["/run/media", "/run/user"];
const SYSTEM_WINDOWS: &[&str] = &[
    "c:/windows", "c:/program files", "c:/program files (x86)",
    "c:/programdata", "c:/system volume information", "c:/$recycle.bin",
];
/// Device and kernel trees: not files anyone uploads or browses (reading
/// `/dev/zero` never ends, a FIFO blocks).
const READ_REFUSED_UNIX: &[&str] = &["/proc", "/sys", "/dev"];

/// Windows auto-run and login locations, matched as whole path components
/// anywhere in the path because they sit inside per-user profiles (or a
/// redirected, e.g. OneDrive, Documents folder) that no fixed prefix catches.
/// They never match on other systems' paths except in a folder copied from
/// Windows, which is refused too. (macOS and Linux equivalents are in the
/// home and system lists.)
const AUTORUN_MARKERS: &[&str] = &[
    "start menu/programs/startup",           // Windows Startup (per-user and all-users)
    "appdata/roaming/microsoft/windows",     // Windows autorun / machine-managed
    "appdata/local/microsoft/windows",
    "appdata/local/microsoft/windowsapps",   // on PATH
    "documents/powershell",                  // PowerShell 7 profile
    "documents/windowspowershell",           // Windows PowerShell 5 profile
];

/// True when `marker` (components separated by `/`) appears in `norm` as whole components.
fn has_components(norm: &str, marker: &str) -> bool {
    format!("{}/", norm).contains(&format!("/{}/", marker))
}

/// `/run/user/<uid>/systemd`: the user's service manager loads units from there.
fn is_user_runtime_systemd(norm: &str) -> bool {
    let mut parts = norm.trim_start_matches('/').split('/');
    parts.next() == Some("run") && parts.next() == Some("user") && parts.next().is_some()
        && parts.next() == Some("systemd")
}

/// Files and folders in the home folder that run code or hold credentials:
/// SSH keys and `authorized_keys`/`config`, GnuPG, shell start-up files, git's
/// config (`core.fsmonitor`, `core.pager` run commands), and the user-level
/// service, environment, autostart and application-launcher folders.
const HOME_SENSITIVE: &[&str] = &[
    ".ssh", ".gnupg",
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile",
    ".bash_aliases", ".bashrc.d",
    ".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout",
    ".kshrc", ".mkshrc", ".cshrc", ".tcshrc", ".login", ".logout",
    ".xprofile", ".xinitrc", ".xsession", ".xsessionrc", ".pam_environment",
    ".gitconfig", ".config/git",
    ".config/fish", ".config/powershell",
    ".config/systemd", ".config/environment.d", ".config/autostart", ".config/autostart-scripts",
    ".config/plasma-workspace",
    ".local/share/systemd", ".local/share/applications",
    "library/launchagents",
];
/// The same for Windows profiles: the PowerShell profiles and the folders that
/// run at login or sit on PATH. Listed here as well as in the markers so that
/// their parents (`Documents`, `AppData`) cannot be moved away and replaced.
const HOME_SENSITIVE_WINDOWS: &[&str] = &[
    "documents/powershell", "documents/windowspowershell",
    "appdata/roaming/microsoft/windows", "appdata/local/microsoft/windows",
    "appdata/local/microsoft/windowsapps",
];

fn is_at_or_under(path: &str, prefix: &str) -> bool {
    path == prefix || (path.starts_with(prefix) && path[prefix.len()..].starts_with('/'))
        || (prefix == "/" && path.starts_with('/'))
}

/// Why `norm` (see [`normalize_for_policy`]) may not be used for `access`, or `None`.
/// `home` is the normalised home folder, if known.
fn policy_violation(norm: &str, access: LocalAccess, os: LocalOs, home: Option<&str>) -> Option<String> {
    if access == LocalAccess::Read {
        if os == LocalOs::Unix && READ_REFUSED_UNIX.iter().any(|p| is_at_or_under(norm, p)) {
            return Some("Refusing to read device or kernel files".into());
        }
        return None;
    }

    let system: &[&str] = match os {
        LocalOs::Unix => SYSTEM_UNIX,
        LocalOs::Windows => SYSTEM_WINDOWS,
    };
    let excepted = os == LocalOs::Unix
        && SYSTEM_UNIX_EXCEPTIONS.iter().any(|p| is_at_or_under(norm, p))
        && !is_user_runtime_systemd(norm);
    if !excepted && system.iter().any(|p| is_at_or_under(norm, p)) {
        return Some("Refusing operation on system path".into());
    }
    if AUTORUN_MARKERS.iter().any(|m| has_components(norm, m)) {
        return Some("Refusing operation on auto-run / persistence path".into());
    }
    if let Some(home) = home {
        if access == LocalAccess::Remove && is_at_or_under(home, norm) {
            return Some("Refusing to delete or move your home folder or a folder that contains it".into());
        }
        if let Some(rel) = norm.strip_prefix(home).and_then(|r| r.strip_prefix('/')) {
            let windows: &[&str] = if os == LocalOs::Windows { HOME_SENSITIVE_WINDOWS } else { &[] };
            let sensitive = || HOME_SENSITIVE.iter().chain(windows);
            if sensitive().any(|s| is_at_or_under(rel, s)) {
                return Some("Refusing to change SSH keys, shell start-up files or similar in your home folder".into());
            }
            // Replacing or removing a folder that holds one of them (`~/.config`,
            // `~/.local/share`, `~/Documents` on Windows) would swap it for
            // something else just the same.
            if sensitive().any(|s| is_at_or_under(s, rel)) {
                return Some("Refusing to replace or remove a folder that holds SSH keys, start-up files or similar".into());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use std::fs;

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("solanum-path-test-{:016x}", rand::thread_rng().gen::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    /// `base` joined with a `/`-separated relative path, one component at a time
    /// (Windows verbatim paths do not split on `/`).
    fn under(base: &Path, rel: &str) -> PathBuf {
        rel.split('/').fold(base.to_path_buf(), |p, c| p.join(c))
    }

    /// The hostile-name corpus: refused on every OS.
    const BAD_EVERYWHERE: &[&str] = &[
        "", ".", "..", "../x", "a/../../b", "/etc/passwd", "a/b", "with\0nul",
        "line\nbreak", "bell\u{7}", "del\u{7f}", "c1\u{85}",
        "invoice\u{202E}fdp.exe", "isolate\u{2067}x", "mark\u{200F}x", "alm\u{061C}x",
        "zero\u{200B}width", "joiner\u{2060}x", "bom\u{FEFF}x",
        "report\u{2063}.pdf", "soft\u{00AD}hyphen", "line\u{2028}sep", "tag\u{E0041}x", "cgj\u{034F}x",
        "filler\u{3164}x", "anno\u{FFF9}x",
    ];
    /// Refused on Windows only: legal, ordinary names on Linux and macOS.
    const BAD_ON_WINDOWS_ONLY: &[&str] = &[
        "..\\x", "a\\b", "C:x", "x:stream", "C:", "a*b", "a?b", "a\"b", "a<b", "a>b", "a|b",
        "trailing.", "trailing ", "CON", "con", "Con.txt", "NUL", "nul .tar.gz", "PRN", "AUX",
        "COM1", "com9.log", "LPT1", "lpt0", "COM\u{B9}", "LPT\u{B3}.txt", "CONIN$", "conout$",
    ];
    const GOOD_EVERYWHERE: &[&str] = &[
        "file.txt", "notes 2024.md", ".bashrc", "..foo", "release-v0.2.37",
        "Ω_unicode_名前", "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}", // Persian with ZWNJ
        "family\u{1F468}\u{200D}\u{1F469}", "heart\u{2764}\u{FE0F}.txt", "CONSOLE", "COM10", "LPT",
        "NULL.txt", "aux_files",
    ];

    #[test]
    fn hostile_names_are_refused_on_every_os() {
        for os in [LocalOs::Unix, LocalOs::Windows] {
            for bad in BAD_EVERYWHERE {
                assert!(local_name_problem(bad, os).is_some(), "{os:?} should refuse {bad:?}");
            }
        }
        for os in [LocalOs::Unix, LocalOs::Windows] {
            for ok in GOOD_EVERYWHERE {
                assert_eq!(local_name_problem(ok, os), None, "{os:?} should accept {ok:?}");
            }
        }
    }

    #[test]
    fn windows_rules_apply_only_to_windows() {
        for name in BAD_ON_WINDOWS_ONLY {
            assert!(local_name_problem(name, LocalOs::Windows).is_some(), "Windows should refuse {name:?}");
            assert_eq!(local_name_problem(name, LocalOs::Unix), None, "Unix should accept {name:?}");
        }
    }

    #[test]
    fn overlong_names_are_refused() {
        let ascii_255 = "a".repeat(255);
        let ascii_256 = "a".repeat(256);
        let cjk_200 = "名".repeat(200); // 600 bytes, 200 UTF-16 units
        assert_eq!(local_name_problem(&ascii_255, LocalOs::Unix), None);
        assert!(local_name_problem(&ascii_256, LocalOs::Unix).is_some());
        assert!(local_name_problem(&ascii_256, LocalOs::Windows).is_some());
        assert!(local_name_problem(&cjk_200, LocalOs::Unix).is_some(), "Unix limits bytes");
        assert_eq!(local_name_problem(&cjk_200, LocalOs::Windows), None, "Windows limits UTF-16 units");
    }

    #[test]
    fn the_local_name_comes_from_the_last_step_of_a_clean_remote_path() {
        assert_eq!(remote_leaf("/home/u/file.txt").unwrap(), "file.txt");
        assert_eq!(remote_leaf("/home/u/data/").unwrap(), "data");
        assert_eq!(remote_leaf("relative/x").unwrap(), "x");
        // A listed name "x/.." or "../../.bashrc" shows up as steps in the path.
        for bad in ["/home/u/x/..", "/home/u/../../.bashrc", "/home/u/./x", "/", "", "/a/b\0c"] {
            assert!(remote_leaf(bad).is_err(), "should refuse {bad:?}");
        }
    }

    #[test]
    fn a_download_lands_directly_in_the_chosen_folder_or_nowhere() {
        let dir = scratch_dir();
        let d = dir.to_str().unwrap();
        let ok = download_target_for(d, "report.pdf", LocalOs::Unix, None).unwrap();
        assert_eq!(ok, dir.join("report.pdf"));
        // A trailing separator on the folder is fine.
        let with_sep = format!("{d}{}", std::path::MAIN_SEPARATOR);
        assert_eq!(download_target_for(&with_sep, "report.pdf", LocalOs::Unix, None).unwrap(), ok);
        for bad in ["../outside.txt", "..", "a/b", "invoice\u{202E}fdp.exe", ""] {
            let err = download_target_for(d, bad, LocalOs::Unix, None).unwrap_err();
            assert!(err.contains("UNSAFE_NAME"), "{bad:?}: {err}");
        }
        assert!(download_target_for(d, "CON", LocalOs::Windows, None).unwrap_err().contains("UNSAFE_NAME"));
        assert!(download_target_for(d, "C:evil", LocalOs::Windows, None).unwrap_err().contains("UNSAFE_NAME"));
        // The folder has to exist and be a folder; relative folders are refused.
        assert!(download_target_for(dir.join("missing").to_str().unwrap(), "x", LocalOs::Unix, None).is_err());
        fs::write(dir.join("plain"), b"").unwrap();
        assert!(download_target_for(dir.join("plain").to_str().unwrap(), "x", LocalOs::Unix, None).is_err());
        assert!(download_target_for("relative/dir", "x", LocalOs::Unix, None).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_download_into_the_home_folder_cannot_replace_start_up_or_ssh_files() {
        let home = scratch_dir();
        let h = home.to_str().unwrap();
        for leaf in [".bashrc", ".profile", ".ssh", ".gitconfig"] {
            let err = download_target_for(h, leaf, LocalOs::Unix, Some(&home)).unwrap_err();
            assert!(err.contains("Refusing"), "{leaf}: {err}");
        }
        assert!(download_target_for(h, "notes.txt", LocalOs::Unix, Some(&home)).is_ok());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn writes_are_checked_where_they_land_even_several_new_folders_deep() {
        let home = scratch_dir();
        let unit = under(&home, ".config/systemd/user/default.target.wants/x.service");
        assert!(guard_path(&unit, LocalAccess::Write, LocalOs::Unix, Some(&home)).is_err());
        let fine = under(&home, "Documents/new/deeper/file.txt");
        assert_eq!(guard_path(&fine, LocalAccess::Write, LocalOs::Unix, Some(&home)).unwrap(), fine);
        // `..` in the part that does not exist yet cannot be resolved, so it is refused.
        #[cfg(unix)]
        assert!(guard_path(&home.join("missing/../.bashrc"), LocalAccess::Write, LocalOs::Unix, Some(&home)).is_err());
        assert!(guard_path(Path::new("relative/x"), LocalAccess::Write, LocalOs::Unix, Some(&home)).is_err());
        let _ = fs::remove_dir_all(home);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_cannot_carry_a_write_into_a_protected_place() {
        use std::os::unix::fs::symlink;
        let home = scratch_dir();
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(home.join("Downloads")).unwrap();
        // A link at the target pointing into ~/.ssh.
        fs::write(home.join(".ssh/authorized_keys"), b"").unwrap();
        symlink(home.join(".ssh/authorized_keys"), home.join("Downloads/keys.txt")).unwrap();
        let err = guard_path(&home.join("Downloads/keys.txt"), LocalAccess::Write, LocalOs::Unix, Some(&home)).unwrap_err();
        assert!(err.contains("SSH keys"), "{err}");
        // A linked folder on the way.
        symlink(home.join(".ssh"), home.join("Downloads/sshdir")).unwrap();
        assert!(guard_path(&home.join("Downloads/sshdir/new/x"), LocalAccess::Write, LocalOs::Unix, Some(&home)).is_err());
        // A dangling link at the target: where it would write is unknown.
        symlink(home.join("nowhere"), home.join("Downloads/dangling")).unwrap();
        let err = guard_path(&home.join("Downloads/dangling"), LocalAccess::Write, LocalOs::Unix, Some(&home)).unwrap_err();
        assert!(err.contains("broken symbolic link"), "{err}");
        let _ = fs::remove_dir_all(home);
    }

    #[cfg(unix)]
    #[test]
    fn removing_a_symlink_removes_the_link_not_what_it_points_to() {
        // N-006: delete/rename used to act on the canonical path, i.e. the target.
        let home = scratch_dir();
        fs::create_dir_all(home.join("Documents")).unwrap();
        fs::create_dir_all(home.join("Desktop")).unwrap();
        fs::write(home.join("Documents/notes.txt"), b"keep me").unwrap();
        let link = home.join("Desktop/notes-link");
        std::os::unix::fs::symlink(home.join("Documents/notes.txt"), &link).unwrap();
        let to_remove = guard_path(&link, LocalAccess::Remove, LocalOs::Unix, Some(&home)).unwrap();
        assert_eq!(to_remove, link);
        fs::remove_file(&to_remove).unwrap();
        assert_eq!(fs::read(home.join("Documents/notes.txt")).unwrap(), b"keep me");
        // Removing needs something there.
        assert!(guard_path(&home.join("Desktop/missing"), LocalAccess::Remove, LocalOs::Unix, Some(&home)).is_err());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn the_home_folder_and_its_parents_cannot_be_deleted() {
        let base = scratch_dir();
        let home = under(&base, "users/me");
        fs::create_dir_all(home.join("old")).unwrap();
        for p in [home.clone(), base.join("users"), base.clone()] {
            let err = guard_path(&p, LocalAccess::Remove, LocalOs::Unix, Some(&home)).unwrap_err();
            assert!(err.contains("home folder"), "{p:?}: {err}");
        }
        assert!(guard_path(&home.join("old"), LocalAccess::Remove, LocalOs::Unix, Some(&home)).is_ok());
        // Listing them is fine.
        assert!(guard_path(&base.join("users"), LocalAccess::Read, LocalOs::Unix, Some(&home)).is_ok());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn reading_system_files_is_allowed_but_changing_them_is_not() {
        let w = LocalAccess::Write;
        let r = LocalAccess::Read;
        let x = LocalAccess::Remove;
        let unix = LocalOs::Unix;
        for p in ["/etc/hosts", "/usr/share/doc/x", "/run/systemd/x", "/var/run/x", "/run/user/1000/systemd/user/x.service",
                  "/private/etc/hosts", "/private/var/log/system.log", "/system/library/x",
                  "/library/preferences/x", "/applications/x.app", "/proc/self/environ"] {
            assert!(policy_violation(p, w, unix, None).is_some(), "write {p}");
            assert!(policy_violation(p, x, unix, None).is_some(), "remove {p}");
        }
        for p in ["/etc/hosts", "/usr/share/doc/x", "/private/etc/hosts", "/applications/x.app"] {
            assert_eq!(policy_violation(p, r, unix, None), None, "read {p}");
        }
        for p in ["/proc/self/environ", "/sys/kernel/x", "/dev/zero"] {
            assert!(policy_violation(p, r, unix, None).is_some(), "read {p}");
        }
        // Ordinary places, including temp folders, removable drives and the
        // user's own runtime folder (GVFS shares, the document portal).
        for p in ["/home/me/downloads/x", "/tmp/x", "/private/tmp/x", "/private/var/folders/ab/t/x",
                  "/run/media/me/usb/x", "/media/usb/x", "/mnt/data/x", "/volumes/usb/x",
                  "/run/user/1000/gvfs/smb-share:server=nas,share=data/x", "/run/user/1000/doc/ab12/x",
                  "/run/user/1000/systemd-notes.txt"] {
            assert_eq!(policy_violation(p, w, unix, None), None, "write {p}");
        }
        // Prefixes match whole components only.
        assert_eq!(policy_violation("/etcetera/x", w, unix, None), None);
        assert_eq!(policy_violation("/runner/x", w, unix, None), None);
    }

    #[test]
    fn the_home_relative_rules_cover_credentials_and_start_up_files() {
        let home = Some("/home/me");
        let w = LocalAccess::Write;
        for p in ["/home/me/.ssh", "/home/me/.ssh/authorized_keys", "/home/me/.bashrc", "/home/me/.zshenv",
                  "/home/me/.gnupg/x", "/home/me/.gitconfig", "/home/me/.config/git/config",
                  "/home/me/.config/systemd/user/x.service", "/home/me/.config/autostart/x.desktop",
                  "/home/me/.config/autostart-scripts/x.sh", "/home/me/.config/environment.d/x.conf",
                  "/home/me/.config/fish/config.fish", "/home/me/.local/share/applications/x.desktop",
                  "/home/me/library/launchagents/x.plist"] {
            assert!(policy_violation(p, w, LocalOs::Unix, home).is_some(), "{p}");
        }
        for p in ["/home/me/.bashrc.bak", "/home/me/.sshkeys-backup/x", "/home/me/documents/.ssh-notes",
                  "/home/me/projects/.profile-ideas", "/home/me/downloads/.bashrc"] {
            assert_eq!(policy_violation(p, w, LocalOs::Unix, home), None, "{p}");
        }
        // Only relative to the home folder: another folder's ".ssh" or a copied
        // ".config/autostart" is not special.
        assert_eq!(policy_violation("/srv/backup/.ssh/x", w, LocalOs::Unix, home), None);
        assert_eq!(policy_violation("/home/me/downloads/dotfiles/.config/autostart/x", w, LocalOs::Unix, home), None);
        // Shell files that a default .bashrc loads.
        assert!(policy_violation("/home/me/.bash_aliases", w, LocalOs::Unix, home).is_some());
        assert!(policy_violation("/home/me/.bashrc.d/x.log", w, LocalOs::Unix, home).is_some());
    }

    #[test]
    fn a_folder_holding_protected_files_cannot_be_replaced_or_removed() {
        let home = Some("/home/me");
        for access in [LocalAccess::Write, LocalAccess::Remove] {
            for p in ["/home/me/.config", "/home/me/.local", "/home/me/.local/share", "/home/me/library"] {
                assert!(policy_violation(p, access, LocalOs::Unix, home).is_some(), "{access:?} {p}");
            }
            for p in ["/home/me/.config/foo.conf", "/home/me/.local/share/fonts/x.ttf", "/home/me/documents"] {
                assert_eq!(policy_violation(p, access, LocalOs::Unix, home), None, "{access:?} {p}");
            }
            let wh = Some("c:/users/me");
            for p in ["c:/users/me/documents", "c:/users/me/appdata", "c:/users/me/appdata/roaming",
                      "c:/users/me/.config"] {
                assert!(policy_violation(p, access, LocalOs::Windows, wh).is_some(), "{access:?} {p}");
            }
            assert_eq!(policy_violation("c:/users/me/documents/x.docx", access, LocalOs::Windows, wh), None);
        }
        // Reading them is fine.
        assert_eq!(policy_violation("/home/me/.config", LocalAccess::Read, LocalOs::Unix, home), None);
    }

    #[test]
    fn auto_start_markers_match_whole_folder_names_only() {
        let w = LocalAccess::Write;
        let home = Some("c:/users/me");
        for p in ["c:/users/me/documents/powershell_cheatsheet.pdf", "c:/users/me/documents/powershell-notes/x",
                  "c:/users/me/appdata/local/microsoft/windowsterminal/x"] {
            assert_eq!(policy_violation(p, w, LocalOs::Windows, home), None, "{p}");
        }
        for p in ["c:/users/me/documents/powershell", "c:/users/me/documents/powershell/profile.ps1",
                  "d:/backup/users/me/appdata/roaming/microsoft/windows/start menu/programs/startup/x.bat"] {
            assert!(policy_violation(p, w, LocalOs::Windows, home).is_some(), "{p}");
        }
    }

    #[test]
    fn a_server_cannot_place_a_dot_file_directly_in_the_home_folder() {
        let home = scratch_dir();
        let h = home.to_str().unwrap();
        for leaf in [".bash_aliases", ".bashrc.d", ".vimrc", ".config", ".hidden"] {
            let err = download_target_for(h, leaf, LocalOs::Unix, Some(&home)).unwrap_err();
            assert!(err.contains("home folder"), "{leaf}: {err}");
        }
        fs::create_dir_all(home.join("Downloads")).unwrap();
        let downloads = home.join("Downloads");
        assert!(download_target_for(downloads.to_str().unwrap(), ".hidden", LocalOs::Unix, Some(&home)).is_ok());
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn ntfs_stream_names_are_refused_on_windows() {
        let dir = scratch_dir();
        for p in [dir.join("a:b"), dir.join(".ssh::$INDEX_ALLOCATION")] {
            assert!(guard_path(&p, LocalAccess::Write, LocalOs::Windows, None).is_err(), "{p:?}");
        }
        #[cfg(unix)]
        assert!(guard_path(&dir.join("a:b"), LocalAccess::Write, LocalOs::Unix, None).is_ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn windows_paths_are_compared_without_their_verbatim_prefix() {
        assert_eq!(normalize_for_policy(r"\\?\C:\Windows\System32\"), "c:/windows/system32");
        assert_eq!(normalize_for_policy(r"\\?\UNC\server\share\x"), "//server/share/x");
        assert_eq!(normalize_for_policy(r"\\.\C:\x"), "c:/x");
        let home = Some("c:/users/me");
        let w = LocalAccess::Write;
        let win = LocalOs::Windows;
        for p in ["c:/windows/system32/x.dll", "c:/program files/x", "c:/programdata/x",
                  "c:/users/me/appdata/roaming/microsoft/windows/start menu/programs/startup/x.bat",
                  "c:/users/me/appdata/local/microsoft/windowsapps/python.exe",
                  "c:/users/me/documents/powershell/profile.ps1",
                  "c:/users/me/onedrive/documents/windowspowershell/profile.ps1",
                  "c:/users/me/.ssh/authorized_keys", "c:/users/me/.gitconfig"] {
            assert!(policy_violation(p, w, win, home).is_some(), "{p}");
        }
        assert_eq!(policy_violation("c:/users/me/downloads/x.zip", w, win, home), None);
        assert_eq!(policy_violation("d:/data/x", w, win, home), None);
        assert!(policy_violation("c:/users", LocalAccess::Remove, win, home).is_some());
        assert!(policy_violation("c:/users/me", LocalAccess::Remove, win, home).is_some());
        assert_eq!(policy_violation("c:/windows/system32/x.dll", LocalAccess::Read, win, home), None);
    }

    #[test]
    fn a_session_log_is_always_a_new_file_and_never_touches_an_existing_one() {
        let home = scratch_dir();
        let logs = under(&home, "Solanum Logs");
        let first = logs.join("web_2026-10-07_10-00-00.log");
        fs::create_dir_all(&logs).unwrap();
        fs::write(&first, b"an older transcript").unwrap();
        // The name is taken: the next free one is used and the old file is untouched.
        drop(create_session_log_for(&first, LocalOs::Unix, Some(&home)).unwrap());
        assert_eq!(fs::read(&first).unwrap(), b"an older transcript");
        assert!(logs.join("web_2026-10-07_10-00-00-2.log").exists());
        drop(create_session_log_for(&first, LocalOs::Unix, Some(&home)).unwrap());
        assert!(logs.join("web_2026-10-07_10-00-00-3.log").exists());
        // Only new .log files, never a file the webview names.
        for bad in [home.join("notes.txt"), home.join(".log"), home.join("x.log.txt")] {
            fs::write(&bad, b"keep me").unwrap_or(());
            assert!(create_session_log_for(&bad, LocalOs::Unix, Some(&home)).is_err(), "{bad:?}");
        }
        assert_eq!(fs::read(home.join("notes.txt")).unwrap(), b"keep me");
        // Not inside protected places.
        let err = create_session_log_for(&under(&home, ".ssh/x.log"), LocalOs::Unix, Some(&home)).unwrap_err();
        assert!(err.contains("SSH keys"), "{err}");
        assert!(!home.join(".ssh").exists(), "nothing is created before the check");
        assert!(create_session_log_for(&home.join("bad\u{202E}gol.log"), LocalOs::Unix, Some(&home)).is_err());
        let _ = fs::remove_dir_all(home);
    }

    #[cfg(unix)]
    #[test]
    fn session_logs_and_the_folders_made_for_them_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let home = scratch_dir();
        fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap();
        let log = under(&home, "Solanum Logs/sub/s.log");
        drop(create_session_log_for(&log, LocalOs::Unix, Some(&home)).unwrap());
        assert_eq!(mode(&log), 0o600);
        assert_eq!(mode(&home.join("Solanum Logs")), 0o700);
        assert_eq!(mode(&under(&home, "Solanum Logs/sub")), 0o700);
        assert_eq!(mode(&home), 0o755, "an existing folder keeps its mode");
        // A symlink planted at the log's name is not followed.
        let victim = home.join("victim.txt");
        fs::write(&victim, b"keep me").unwrap();
        let planted = under(&home, "Solanum Logs/planted.log");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();
        drop(create_session_log_for(&planted, LocalOs::Unix, Some(&home)).unwrap());
        assert_eq!(fs::read(&victim).unwrap(), b"keep me");
        assert!(under(&home, "Solanum Logs/planted-2.log").exists());
        let _ = fs::remove_dir_all(home);
    }

    /// F-008: a mirror's local folder must be a plain folder files may be
    /// written into, and not the home folder or one that holds it.
    #[test]
    fn mirror_roots_are_folders_files_may_be_written_into() {
        let base = scratch_dir();
        let home = base.join("home");
        for d in ["projects/site", ".ssh", ".config/autostart", ".config/app"] {
            fs::create_dir_all(under(&home, d)).unwrap();
        }
        fs::write(home.join("file.txt"), b"x").unwrap();
        let ok = |p: &Path| mirror_root_problem_for(p, LocalOs::Unix, Some(&home));
        assert_eq!(ok(&under(&home, "projects/site")), None);
        assert_eq!(ok(&under(&home, ".config")), None, "a folder holding protected entries; each file is checked later");
        assert_eq!(ok(&under(&home, ".config/app")), None);
        for refused in [home.clone(), base.clone(), under(&home, ".ssh"), under(&home, ".config/autostart"), home.join("file.txt"), home.join("missing")] {
            assert!(ok(&refused).is_some(), "{refused:?} must be refused");
        }
        assert!(ok(Path::new("relative/folder")).is_some());
        #[cfg(unix)]
        {
            assert!(ok(Path::new("/")).is_some());
            assert!(ok(Path::new("/etc")).is_some());
        }
        let _ = fs::remove_dir_all(base);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_linux_paths_resolve_before_they_are_checked() {
        // /var/run is a symlink to /run on current systems; the old list missed it.
        if Path::new("/var/run").exists() {
            assert!(guard_local_path("/var/run/solanum-test-x", LocalAccess::Write).is_err());
        }
        assert!(guard_local_path("/", LocalAccess::Read).is_err(), "root");
        assert!(guard_local_path("/proc/self/status", LocalAccess::Read).is_err());
        assert!(guard_local_path("/etc", LocalAccess::Read).is_ok(), "listing /etc is fine");
        assert!(guard_local_path("/etc/solanum-test-x", LocalAccess::Write).is_err());
    }
}
