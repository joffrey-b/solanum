//! Writing a file so that whoever reads it sees either its old content or the
//! complete new one, never a half-written file (F-025).
//!
//! Remote: [`replace_remote_file`] uploads into a hidden part file next to the
//! target and renames it into place. russh-sftp 3.0 does not expose
//! `posix-rename@openssh.com`, and a plain SFTP v3 rename refuses to replace an
//! existing file (OpenSSH implements it as link + unlink), so an existing
//! target is first moved aside, then the part is renamed in, then the old file
//! is removed; a failure in between puts the old file back. The name is missing
//! for those two round trips, but no content is ever lost. The file is written
//! in place as before (owner decision, like vim's `backupcopy=auto`) when the
//! new file could not carry the target's identity (its owner or group cannot
//! be set, the folder is not writable, the server does not report them), when
//! the target is read-only, is a link to something that is not a regular file,
//! or cannot be renamed (a mount point): a failure there can still leave it
//! partial.
//!
//! [`ReplaceOptions`] adds what the folder mirror needs: the mode of a file
//! that did not exist yet, and a place to move the replaced version to
//! instead of deleting it.
//!
//! Local: [`LocalPart`] writes a download into `<name>.<hex>.part` beside the
//! target and renames it over the target only once it is complete.

use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Chunk size for streaming: large enough to keep the SSH window busy on
/// high-latency links, small enough for smooth progress and quick cancels.
pub(crate) const CHUNK: usize = 256 * 1024;

/// Name bytes kept from the target's name in a hidden part or aside name, so
/// that `.<name>.<hex>.solanum-part` stays under the usual 255-byte limit.
const MAX_NAME_IN_PART: usize = 200;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReplaceError {
    /// The target exists (or appeared meanwhile) and replacing it was not allowed.
    Exists,
    /// The chunk callback asked to stop. The target is unchanged unless the
    /// file was being written in place.
    Cancelled,
    Failed(String),
}

/// How the remote file was written.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Replaced {
    /// There was no file: a part file was renamed to the name.
    New,
    /// The server replaced the target in one rename.
    Renamed,
    /// The target was moved aside, the part renamed into place and the old file
    /// removed. `leftover` names the old file if removing it failed.
    MovedAside { leftover: Option<String> },
    /// Written into the existing file, for the reason given.
    InPlace(&'static str),
    /// The target was moved to [`ReplaceOptions::keep_previous`] (`at`) and the
    /// part renamed into place.
    KeptPrevious { at: String },
}

impl Replaced {
    /// What the user should be told, if anything: a hidden copy of the
    /// previous version that could not be removed.
    pub(crate) fn note(&self) -> Option<String> {
        match self {
            Replaced::MovedAside { leftover: Some(old) } => {
                Some(format!("The previous version could not be deleted and is still on the server as {old}"))
            }
            _ => None,
        }
    }
}

/// Sees each chunk once it was sent, with its offset in the file, and returns
/// false to cancel. The offset starts again at 0 when the upload is redone in
/// place (a target that could not be renamed), so a hash or a progress count
/// can start again too.
pub(crate) type OnChunk<'a> = dyn FnMut(u64, &[u8]) -> bool + Send + 'a;

/// What [`replace_remote_file_with`] does besides writing the content.
#[derive(Default)]
pub(crate) struct ReplaceOptions<'a> {
    /// An existing file at the name may be replaced (otherwise `Exists`).
    pub allow_replace: bool,
    /// Permission bits asked for when a file that did not exist is created;
    /// `None`: the server's default. The server's umask still applies, as
    /// rsync does for new files: never wider than these bits nor than what
    /// the server allows new files.
    pub new_file_mode: Option<u32>,
    /// Move the file being replaced here (its folder must exist) instead of
    /// deleting it. Not possible when the file is written in place. When that
    /// place is refused, the old file stays beside the target under its
    /// hidden `.solanum-old` name; the result says where it is.
    pub keep_previous: Option<&'a str>,
    /// A file written in place is finished even when `on_chunk` asks to stop:
    /// stopping there would leave it cut short. (A part file still stops at
    /// once; the target is untouched then.)
    pub finish_in_place: bool,
}

enum Target {
    New(String),
    Existing { path: String, attrs: FileAttributes },
    InPlace { path: String, why: &'static str },
}

fn status_code(e: &SftpError) -> Option<StatusCode> {
    match e {
        SftpError::Status(s) => Some(s.status_code),
        _ => None,
    }
}

pub(crate) fn is_not_found(e: &SftpError) -> bool {
    status_code(e) == Some(StatusCode::NoSuchFile)
}

/// Folder and name of a remote (POSIX) path; the folder is empty for a bare name.
fn split_remote(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(0) => ("/", &path[1..]),
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    }
}

fn join_remote(dir: &str, name: &str) -> String {
    match dir {
        "" => name.to_string(),
        "/" => format!("/{name}"),
        _ => format!("{dir}/{name}"),
    }
}

/// `.<name>.<8 hex>.<suffix>`, the name shortened (on a character boundary) so
/// the result stays a valid file name.
pub(crate) fn hidden_sibling_name(name: &str, suffix: &str) -> String {
    let mut end = name.len().min(MAX_NAME_IN_PART);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    format!(".{}.{}.{}", &name[..end], random_hex(4), suffix)
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

async fn open_source(source: &Path) -> Result<tokio::fs::File, ReplaceError> {
    tokio::fs::File::open(source)
        .await
        .map_err(|e| ReplaceError::Failed(format!("read {}: {e}", source.display())))
}

/// Upload the local file `source` to `remote_path` without ever leaving a
/// half-written file under that name (see the module comment for the cases
/// written in place). `allow_replace` false: an existing file at the name is
/// `Exists`, never touched.
pub(crate) async fn replace_remote_file(
    sftp: &SftpSession,
    remote_path: &str,
    source: &Path,
    allow_replace: bool,
    on_chunk: &mut OnChunk<'_>,
) -> Result<Replaced, ReplaceError> {
    let options = ReplaceOptions { allow_replace, ..ReplaceOptions::default() };
    replace_remote_file_with(sftp, remote_path, source, &options, on_chunk).await
}

/// [`replace_remote_file`] with [`ReplaceOptions`].
pub(crate) async fn replace_remote_file_with(
    sftp: &SftpSession,
    remote_path: &str,
    source: &Path,
    options: &ReplaceOptions<'_>,
    on_chunk: &mut OnChunk<'_>,
) -> Result<Replaced, ReplaceError> {
    match plan_target(sftp, remote_path, options.allow_replace).await? {
        Target::New(path) => write_through_part(sftp, &path, None, source, options, on_chunk).await,
        Target::Existing { path, attrs } => {
            write_through_part(sftp, &path, Some(attrs), source, options, on_chunk).await
        }
        Target::InPlace { path, why } => write_in_place(sftp, &path, source, options, on_chunk, why).await,
    }
}

async fn plan_target(sftp: &SftpSession, remote_path: &str, allow_replace: bool) -> Result<Target, ReplaceError> {
    let meta = match sftp.symlink_metadata(remote_path).await {
        Ok(m) => m,
        Err(e) if is_not_found(&e) => return Ok(Target::New(remote_path.to_string())),
        Err(e) => return Err(ReplaceError::Failed(format!("{remote_path}: {e}"))),
    };
    let kind = meta.file_type();
    if kind.is_dir() {
        return Err(ReplaceError::Failed(format!("{remote_path} is a folder")));
    }
    if !allow_replace {
        return Err(ReplaceError::Exists);
    }
    if kind.is_symlink() {
        // Replace the file the link leads to, so the link stays a link
        // (OpenSSH's realpath resolves links). Anything else is written
        // through the link, as before.
        if let Ok(real) = sftp.canonicalize(remote_path).await {
            if let Ok(real_meta) = sftp.symlink_metadata(&real).await {
                if real_meta.file_type().is_file() {
                    return Ok(existing_or_in_place(real, real_meta));
                }
            }
        }
        return Ok(Target::InPlace {
            path: remote_path.to_string(),
            why: "it is a link that does not lead to a regular file",
        });
    }
    if kind.is_file() {
        return Ok(existing_or_in_place(remote_path.to_string(), meta));
    }
    if meta.permissions.is_none() {
        return Ok(Target::InPlace { path: remote_path.to_string(), why: UNREPORTED });
    }
    Ok(Target::InPlace { path: remote_path.to_string(), why: "it is not a regular file" })
}

const UNREPORTED: &str = "the server does not report its permissions and owner";

/// A regular file is replaced through a part file only when its identity is
/// known and may be reproduced. A file nobody may write is written in place,
/// which fails as it did before (unless the account may write anything):
/// replacing it would go around its read-only mode.
fn existing_or_in_place(path: String, attrs: FileAttributes) -> Target {
    match attrs.permissions {
        Some(p) if p & 0o222 == 0 => Target::InPlace { path, why: "it is read-only" },
        Some(_) if attrs.uid.is_some() && attrs.gid.is_some() => Target::Existing { path, attrs },
        _ => Target::InPlace { path, why: UNREPORTED },
    }
}

async fn write_through_part(
    sftp: &SftpSession,
    target: &str,
    existing: Option<FileAttributes>,
    source: &Path,
    options: &ReplaceOptions<'_>,
    on_chunk: &mut OnChunk<'_>,
) -> Result<Replaced, ReplaceError> {
    let allow_replace = options.allow_replace;
    let (dir, name) = split_remote(target);
    let part = join_remote(dir, &hidden_sibling_name(name, "solanum-part"));
    let mode = match &existing {
        Some(attrs) => attrs.permissions.map(|p| p & 0o7777),
        None => options.new_file_mode.map(|m| m & 0o777),
    };

    // Created exclusively, never readable by more people than the target.
    let mut create_attrs = FileAttributes::empty();
    create_attrs.permissions = mode.map(|m| m & 0o777);
    let mut file = match sftp
        .open_with_flags_and_attributes(&part, OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::WRITE, create_attrs)
        .await
    {
        Ok(f) => f,
        Err(e) if existing.is_some() && status_code(&e) == Some(StatusCode::PermissionDenied) => {
            return write_in_place(sftp, target, source, options, on_chunk, "its folder is not writable").await;
        }
        Err(e) => {
            // No answer (a timeout): the request may still reach the server
            // and create the part file, so ask for it to go too.
            if status_code(&e).is_none() {
                let _ = sftp.remove_file(&part).await;
            }
            return Err(ReplaceError::Failed(format!("create {part}: {e}")));
        }
    };

    if let Some(attrs) = &existing {
        if let Err(why) = keep_identity(&file, attrs, mode).await {
            drop(file);
            let _ = sftp.remove_file(&part).await;
            return write_in_place(sftp, target, source, options, on_chunk, why).await;
        }
    }

    let written = match open_source(source).await {
        Ok(mut local) => pump(&mut local, &mut file, on_chunk).await,
        Err(e) => Err(e),
    };
    // A replaced file gets its exact mode back; a new one keeps what it was
    // created with (the server's umask applied).
    let exact_mode = if existing.is_some() { mode } else { None };
    let finished = match written {
        Ok(()) => finish_part(&mut file, exact_mode, existing.is_some()).await,
        Err(e) => Err(e),
    };
    if let Err(e) = finished {
        drop(file);
        let _ = sftp.remove_file(&part).await;
        return Err(e);
    }
    drop(file);

    // Keeping the old version means moving it away first, so the one-step
    // rename (which would replace it on servers that allow that) is skipped.
    let keep = options.keep_previous.filter(|_| existing.is_some());
    if keep.is_none() {
        let first_error = match sftp.rename(&part, target).await {
            Ok(()) => return Ok(if existing.is_some() { Replaced::Renamed } else { Replaced::New }),
            Err(e) => e,
        };
        // The rename failed. If the target exists, this server does not replace on
        // rename (OpenSSH): move the old file aside first.
        match sftp.symlink_metadata(target).await {
            Ok(_) => {}
            Err(e) => {
                let _ = sftp.remove_file(&part).await;
                let detail = if is_not_found(&e) { first_error.to_string() } else { e.to_string() };
                return Err(ReplaceError::Failed(format!("rename into {target}: {detail}")));
            }
        }
        if !allow_replace {
            let _ = sftp.remove_file(&part).await;
            return Err(ReplaceError::Exists);
        }
        if existing.is_none() {
            // A file appeared at the name while uploading; its owner and mode
            // were never read, so do not replace it blindly.
            let _ = sftp.remove_file(&part).await;
            return Err(ReplaceError::Failed(format!("{target} appeared while uploading; try again")));
        }
    }
    let hidden_aside = || join_remote(dir, &hidden_sibling_name(name, "solanum-old"));
    let mut aside = match keep {
        Some(at) => at.to_string(),
        None => hidden_aside(),
    };
    let mut moved = sftp.rename(target, &aside).await;
    if keep.is_some() {
        if let Err(e) = &moved {
            // The keeping place was refused (another file system, a name
            // already taken) and the file is still there: move it aside as
            // usual, and keep it there instead of deleting it.
            if status_code(e).is_some() && sftp.symlink_metadata(target).await.is_ok() {
                aside = hidden_aside();
                moved = sftp.rename(target, &aside).await;
            }
        }
    }
    if let Err(e) = moved {
        let _ = sftp.remove_file(&part).await;
        return match sftp.symlink_metadata(target).await {
            // The server refused and the file is where it was (a mount point,
            // an immutable file): write it in place, as before.
            Ok(_) if status_code(&e).is_some() => {
                write_in_place(sftp, target, source, options, on_chunk, "it cannot be renamed (for example a mount point)").await
            }
            Ok(_) => Err(ReplaceError::Failed(format!("could not move {target} aside: {e}"))),
            // No answer came back, but the rename may have happened: put it back.
            Err(_) => Err(ReplaceError::Failed(match sftp.rename(&aside, target).await {
                Ok(()) => format!("could not move {target} aside: {e}"),
                Err(_) => format!("could not move {target} aside: {e}; if it is missing, the previous file may be at {aside}"),
            })),
        };
    }
    if let Err(e) = sftp.rename(&part, target).await {
        let restored = sftp.rename(&aside, target).await;
        let _ = sftp.remove_file(&part).await;
        return Err(ReplaceError::Failed(match restored {
            Ok(()) => format!("rename into {target}: {e}"),
            Err(r) => format!("rename into {target}: {e}; the previous file is kept as {aside} ({r})"),
        }));
    }
    if keep.is_some() {
        return Ok(Replaced::KeptPrevious { at: aside });
    }
    let leftover = match sftp.remove_file(&aside).await {
        Ok(()) => None,
        Err(_) => Some(aside),
    };
    Ok(Replaced::MovedAside { leftover })
}

/// Give the (still empty) part file the target's owner, group and mode, or say
/// why that is not possible. Checked before any content is sent.
async fn keep_identity(
    file: &russh_sftp::client::fs::File,
    target: &FileAttributes,
    mode: Option<u32>,
) -> Result<(), &'static str> {
    const OWNER: &str = "its owner or group cannot be kept";
    const MODE: &str = "its permissions cannot be kept";
    let now = file.metadata().await.map_err(|_| OWNER)?;
    let differs = |want: Option<u32>, have: Option<u32>| want.is_some() && want != have;
    if differs(target.uid, now.uid) || differs(target.gid, now.gid) {
        let mut owner = FileAttributes::empty();
        owner.uid = target.uid.or(now.uid);
        owner.gid = target.gid.or(now.gid);
        if owner.uid.is_none() || owner.gid.is_none() {
            return Err(OWNER);
        }
        file.set_metadata(owner).await.map_err(|_| OWNER)?;
    }
    if let Some(m) = mode {
        let mut perms = FileAttributes::empty();
        perms.permissions = Some(m);
        file.set_metadata(perms).await.map_err(|_| MODE)?;
    }
    let after = file.metadata().await.map_err(|_| OWNER)?;
    if differs(target.uid, after.uid) || differs(target.gid, after.gid) {
        return Err(OWNER);
    }
    if mode.is_some() && after.permissions.map(|p| p & 0o7777) != mode {
        return Err(MODE);
    }
    Ok(())
}

/// After the content: the exact mode again (a write by a non-owner clears
/// setuid/setgid), fsync when replacing (if the server offers it), close.
async fn finish_part(
    file: &mut russh_sftp::client::fs::File,
    mode: Option<u32>,
    replacing: bool,
) -> Result<(), ReplaceError> {
    if let Some(m) = mode {
        let mut perms = FileAttributes::empty();
        perms.permissions = Some(m);
        file.set_metadata(perms).await.map_err(|e| ReplaceError::Failed(format!("set permissions: {e}")))?;
    }
    if replacing {
        file.sync_all().await.map_err(|e| ReplaceError::Failed(format!("sync: {e}")))?;
    }
    file.shutdown().await.map_err(|e| ReplaceError::Failed(format!("close: {e}")))
}

async fn write_in_place(
    sftp: &SftpSession,
    target: &str,
    source: &Path,
    options: &ReplaceOptions<'_>,
    on_chunk: &mut OnChunk<'_>,
    why: &'static str,
) -> Result<Replaced, ReplaceError> {
    let mut local = open_source(source).await?;
    let mut file = sftp
        .open_with_flags(target, OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE)
        .await
        .map_err(|e| ReplaceError::Failed(format!("open {target}: {e}")))?;
    let mut finishing = |offset: u64, chunk: &[u8]| {
        let go_on = on_chunk(offset, chunk);
        go_on || options.finish_in_place
    };
    if let Err(e) = pump(&mut local, &mut file, &mut finishing).await {
        let _ = file.shutdown().await;
        return Err(e);
    }
    file.shutdown().await.map_err(|e| ReplaceError::Failed(format!("close {target}: {e}")))?;
    Ok(Replaced::InPlace(why))
}

async fn pump(
    source: &mut tokio::fs::File,
    file: &mut russh_sftp::client::fs::File,
    on_chunk: &mut OnChunk<'_>,
) -> Result<(), ReplaceError> {
    let mut buf = vec![0u8; CHUNK];
    let mut offset: u64 = 0;
    loop {
        let n = source.read(&mut buf).await.map_err(|e| ReplaceError::Failed(format!("read: {e}")))?;
        if n == 0 {
            return Ok(());
        }
        file.write_all(&buf[..n]).await.map_err(|e| ReplaceError::Failed(format!("write: {e}")))?;
        if !on_chunk(offset, &buf[..n]) {
            return Err(ReplaceError::Cancelled);
        }
        offset += n as u64;
    }
}

/// A download in progress: `<name>.<hex>.part` beside the target, renamed over
/// it by [`LocalPart::commit`]. Dropped without a commit (an error, a cancel),
/// the part file is removed and the target was never touched.
pub(crate) struct LocalPart {
    part: PathBuf,
    target: PathBuf,
    file: Option<tokio::fs::File>,
    committed: bool,
}

#[derive(Debug)]
pub(crate) enum CommitError {
    /// A file appeared at the target and replacing was not allowed.
    Exists,
    Io(String),
}

impl LocalPart {
    /// `target` must already be checked (`local_path::download_target`, or the
    /// folder-download checks): the part goes in the same folder.
    pub(crate) async fn create(target: &Path) -> std::io::Result<Self> {
        let dir = target
            .parent()
            .ok_or_else(|| std::io::Error::other("the target has no folder"))?;
        let name = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mut options = tokio::fs::OpenOptions::new();
        // create_new: never follows or reuses something already there.
        options.write(true).create_new(true);
        // A file being replaced: the part is never readable by more people
        // than the file it replaces (the umask may narrow it further; commit
        // sets the exact mode).
        #[cfg(unix)]
        if let Some(mode) = replaced_mode(target) {
            options.mode(mode);
        }
        for _ in 0..8 {
            let part = dir.join(local_part_name(&name));
            match options.open(&part).await {
                Ok(file) => {
                    return Ok(Self { part, target: target.to_path_buf(), file: Some(file), committed: false })
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::other("could not pick a free temporary name"))
    }

    pub(crate) fn file(&mut self) -> &mut tokio::fs::File {
        self.file.as_mut().expect("the part file is open until commit")
    }

    /// Put the finished part in place. `replace`: the user agreed to replace
    /// whatever is at the target (synced to disk first, then renamed over it,
    /// which replaces a symlink there rather than writing through it).
    /// Otherwise nothing at the target is ever replaced: `Exists` if a file
    /// appeared meanwhile.
    pub(crate) async fn commit(mut self, replace: bool) -> Result<(), CommitError> {
        let io = |e: std::io::Error| CommitError::Io(e.to_string());
        let mut file = self.file.take().expect("commit runs once");
        file.flush().await.map_err(io)?;
        if replace {
            file.sync_all().await.map_err(io)?;
        }
        drop(file);
        if replace {
            // Overwriting used to truncate the file in place, which kept its
            // mode (a 0600 file stays 0600). Setuid/setgid are not carried
            // over: a write by its owner would have cleared them too.
            #[cfg(unix)]
            if let Some(mode) = replaced_mode(&self.target) {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&self.part, std::fs::Permissions::from_mode(mode)).await.map_err(io)?;
            }
            tokio::fs::rename(&self.part, &self.target).await.map_err(io)?;
        } else {
            match tokio::fs::hard_link(&self.part, &self.target).await {
                Ok(()) => {
                    let _ = tokio::fs::remove_file(&self.part).await;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(CommitError::Exists),
                Err(_) => {
                    // No hard links here (FAT, some network shares): check, then rename.
                    if tokio::fs::symlink_metadata(&self.target).await.is_ok() {
                        return Err(CommitError::Exists);
                    }
                    tokio::fs::rename(&self.part, &self.target).await.map_err(io)?;
                }
            }
        }
        self.committed = true;
        Ok(())
    }
}

impl Drop for LocalPart {
    fn drop(&mut self) {
        if !self.committed {
            drop(self.file.take());
            let _ = std::fs::remove_file(&self.part);
        }
    }
}

/// The permission bits (without setuid/setgid/sticky) of the regular file at
/// `target`, following a link, if there is one.
#[cfg(unix)]
fn replaced_mode(target: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(target).ok().filter(|m| m.is_file()).map(|m| m.permissions().mode() & 0o777)
}

/// `<name>.<8 hex>.part`, or `solanum-<16 hex>.part` when that would not be a
/// usable name here (too long).
fn local_part_name(name: &str) -> String {
    let candidate = format!("{}.{}.part", name, random_hex(4));
    let fits = candidate.len() <= 255 && candidate.encode_utf16().count() <= 255;
    if fits && crate::local_path::local_name_problem(&candidate, crate::local_path::LocalOs::current()).is_none() {
        candidate
    } else {
        format!("solanum-{}.part", random_hex(8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("solanum-atomic-{tag}-{}", random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> =
            std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        v.sort();
        v
    }

    async fn write_part(target: &Path, data: &[u8]) -> LocalPart {
        let mut part = LocalPart::create(target).await.unwrap();
        part.file().write_all(data).await.unwrap();
        part
    }

    #[test]
    fn remote_paths_split_and_join() {
        assert_eq!(split_remote("/etc/nginx/nginx.conf"), ("/etc/nginx", "nginx.conf"));
        assert_eq!(split_remote("/top"), ("/", "top"));
        assert_eq!(split_remote("bare"), ("", "bare"));
        assert_eq!(join_remote("/", "x"), "/x");
        assert_eq!(join_remote("", "x"), "x");
        assert_eq!(join_remote("/a/b", "x"), "/a/b/x");
    }

    #[test]
    fn hidden_names_stay_short_and_valid() {
        let n = hidden_sibling_name("config.yml", "solanum-part");
        assert!(n.starts_with(".config.yml.") && n.ends_with(".solanum-part"), "{n}");
        let long = "é".repeat(200); // 400 bytes
        let n = hidden_sibling_name(&long, "solanum-part");
        assert!(n.len() <= 255, "{} bytes", n.len());
        assert!(!n.contains('/'));
    }

    #[tokio::test]
    async fn a_finished_download_appears_and_leaves_no_part() {
        let dir = scratch("new");
        let target = dir.join("report.pdf");
        write_part(&target, b"complete").await.commit(false).await.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"complete");
        assert_eq!(names(&dir), vec!["report.pdf"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// F-025: an overwriting download that fails or is cancelled leaves the
    /// existing file as it was (the old code truncated it when opening it).
    #[tokio::test]
    async fn a_failed_overwriting_download_keeps_the_old_file() {
        let dir = scratch("keep");
        let target = dir.join("report.pdf");
        std::fs::write(&target, b"the old, complete content").unwrap();
        drop(write_part(&target, b"partial").await);
        assert_eq!(std::fs::read(&target).unwrap(), b"the old, complete content");
        assert_eq!(names(&dir), vec!["report.pdf"], "the part file is removed");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn replacing_puts_the_new_content_in_place() {
        let dir = scratch("replace");
        let target = dir.join("report.pdf");
        std::fs::write(&target, b"old").unwrap();
        write_part(&target, b"new and longer").await.commit(true).await.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new and longer");
        assert_eq!(names(&dir), vec!["report.pdf"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_file_that_appeared_meanwhile_is_not_replaced() {
        let dir = scratch("race");
        let target = dir.join("report.pdf");
        let part = write_part(&target, b"downloaded").await;
        std::fs::write(&target, b"someone else's").unwrap();
        assert!(matches!(part.commit(false).await, Err(CommitError::Exists)));
        assert_eq!(std::fs::read(&target).unwrap(), b"someone else's");
        assert_eq!(names(&dir), vec!["report.pdf"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_name_too_long_for_a_suffix_gets_a_short_part_name() {
        let dir = scratch("long");
        let target = dir.join("n".repeat(250));
        let part = write_part(&target, b"x").await;
        let part_name = part.part.file_name().unwrap().to_string_lossy().into_owned();
        assert!(part_name.starts_with("solanum-") && part_name.ends_with(".part"), "{part_name}");
        part.commit(false).await.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"x");
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Overwriting keeps the local file's mode, as the old in-place write did.
    #[cfg(unix)]
    #[tokio::test]
    async fn overwriting_keeps_the_local_file_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("mode");
        let target = dir.join(".env");
        std::fs::write(&target, b"SECRET=old").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let part = write_part(&target, b"SECRET=new").await;
        let while_writing = std::fs::metadata(&part.part).unwrap().permissions().mode() & 0o777;
        assert_eq!(while_writing & !0o600, 0, "the part is never wider than the file it replaces: {while_writing:o}");
        part.commit(true).await.unwrap();
        assert_eq!(std::fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read(&target).unwrap(), b"SECRET=new");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replacing_a_symlink_replaces_the_link_not_what_it_points_to() {
        let dir = scratch("link");
        let outside = scratch("outside");
        let elsewhere = outside.join("precious.txt");
        std::fs::write(&elsewhere, b"keep me").unwrap();
        let target = dir.join("report.pdf");
        std::os::unix::fs::symlink(&elsewhere, &target).unwrap();
        write_part(&target, b"downloaded").await.commit(true).await.unwrap();
        assert!(!std::fs::symlink_metadata(&target).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(&target).unwrap(), b"downloaded");
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"keep me");
        std::fs::remove_dir_all(dir).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
}
