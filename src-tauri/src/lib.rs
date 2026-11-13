// windows_subsystem is bin-only; the matching attribute lives in main.rs.

use aes_gcm::{aead::{Aead, KeyInit, Payload}, Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use zeroize::{Zeroize, Zeroizing};
use rand::Rng;
use rusqlite::{ffi, Connection, MAIN_DB};
use rusqlite::serialize::OwnedData;
use std::ptr::NonNull;
use std::sync::Mutex as StdMutex;
use std::path::PathBuf;
use std::fs;
use tauri::Manager;
use serde_json::json;
use russh::keys::ssh_key::{self, private::Ed25519Keypair, PrivateKey};

/// A console line for development builds only (F-064). Connection details
/// (hosts, ports, user names) must not reach a release build's stdout or
/// stderr, which desktop sessions keep in the user journal or
/// `~/.xsession-errors`. The arguments are type-checked in every build.
macro_rules! dev_log {
    ($($arg:tt)*) => {
        if cfg!(debug_assertions) {
            println!($($arg)*);
        }
    };
}

mod ssh_manager;
#[cfg(test)]
mod ssh_stack_tests;
#[cfg(test)]
mod ssh_test_server;
mod ssh_connect;
mod tunnel;
mod monitor;
mod about;
mod android;
mod mirror;
mod docker;
mod remote_exec;
mod terminal_io;
// Android has no local shell, so most of it is unused there.
#[cfg_attr(target_os = "android", allow(dead_code))]
mod local_shell;
mod local_path;
// Android opens no files and starts no local shell, so most of it is unused there.
#[cfg_attr(target_os = "android", allow(dead_code))]
mod open_guard;
mod atomic_transfer;
// Android starts no local programs, so most of it is unused there.
#[cfg_attr(target_os = "android", allow(dead_code))]
mod child_env;
// Android has no live edit (the command refuses first), so most of it is unused there.
#[cfg_attr(target_os = "android", allow(dead_code))]
mod live_edit;
use ssh_manager::SshState;
use local_path::{guard_local_path, LocalAccess};
// The mirror's remote walk uses the same name check as downloads.
pub(crate) use local_path::is_safe_dir_entry_name;
use monitor::{MonitorMap, SharedSettings};
use mirror::MirrorMap;
use std::sync::Arc;

// On-disk vault layout (format version 2):
//   bytes 0..4    magic ("SLNV") — this app's own. The original cloud-enabled
//                 Submarine app used a different one, so its profiles are refused
//                 on sight instead of being half-understood.
//   byte  4       format version (2)
//   byte  5       KDF id (1 = Argon2id, version 0x13)
//   bytes 6..10   Argon2 m_cost in KiB (u32, little-endian)
//   bytes 10..14  Argon2 t_cost (u32 LE)
//   bytes 14..18  Argon2 p_cost (u32 LE)
//   bytes 18..34  salt (16 bytes, per-profile)
//   bytes 34..46  nonce (12 bytes, per-save)
//   rest          AES-256-GCM(zstd(serialised-sqlite)) + 16-byte tag
// The whole header (bytes 0..46) is the AES-GCM associated data, so changing any
// byte of it makes the file fail to open. The KDF parameters are read from the
// header and checked against hard bounds before any key derivation runs.
const VAULT_MAGIC: &[u8; 4] = b"SLNV";
/// Shown whenever a file or database that is not this app's (e.g. one from the original
/// Submarine app) is opened.
/// Must NOT contain the word "decrypt": the picker turns that into "Wrong password.".
const FOREIGN_PROFILE_MSG: &str = "This profile wasn't created by this app. Profiles from the original cloud-enabled Submarine use an incompatible format and can't be opened here: create a new profile and re-enter your servers. Your old profile file is left untouched.";
/// Tail of every "this is a real but older Solanum profile" refusal (file format or schema).
/// Must NOT contain the word "decrypt" either.
const OUTDATED_PROFILE_TAIL: &str = "This app is still in early development, so there isn't an automatic upgrade path yet for old profiles — create a new profile and re-enter your servers. Your old profile file is left untouched.";
const VAULT_VERSION: u8 = 2;
/// KDF id stored in byte 5: Argon2id, version 0x13.
const KDF_ARGON2ID_V13: u8 = 1;
/// zstd compression level. 3 is the library default — fast enough that
/// save latency is dominated by sqlite serialisation, with compression
/// ratios within a couple percent of the slower levels for SQL-like data.
const VAULT_COMPRESS_LEVEL: i32 = 3;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 4 + 1 + 1 + 3 * 4 + SALT_LEN + NONCE_LEN;

#[derive(Default)]
pub struct DbState {
    pub conn: std::sync::Arc<StdMutex<Option<Connection>>>,
    /// What it takes to write the open vault back to disk. Always locked
    /// AFTER `conn` (open, save and close all take them in that order), so a
    /// save sees the connection and the key/path of the same profile.
    vault: std::sync::Arc<StdMutex<Option<OpenVault>>>,
    /// Name of the profile the user picked on the launch screen. Drives the
    /// vault path (under `<app_data>/profiles/<name>.solanum`) and is
    /// cleared by `close_profile` so the app returns to the picker.
    pub active_profile: StdMutex<Option<String>>,
    /// The file the import picker last returned (R-012): `import_profile_save`
    /// reads only that one, so a script in the window cannot import another
    /// readable file by sending its path.
    picked_import: StdMutex<Option<PathBuf>>,
}

/// The picked import file, when `given` is the path the picker returned.
fn picked_import_source(picked: &StdMutex<Option<PathBuf>>, given: &str) -> Result<PathBuf, String> {
    match picked.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_ref() {
        Some(path) if path.to_string_lossy() == given => Ok(path.clone()),
        _ => Err("[FILE] IMPORT_NOT_PICKED: Choose the profile file again.".into()),
    }
}

/// The unlocked profile's file-side state.
struct OpenVault {
    /// `Zeroizing` wipes the 32-byte AES-256-GCM key on drop. Without
    /// this, the master key lives on in the heap allocator until the
    /// slot is reused — long enough to land in a crash dump or swap
    /// file. The mutex slot itself is overwritten with None on profile
    /// close which triggers the Zeroize Drop.
    key: Zeroizing<[u8; 32]>,
    /// The KDF parameters and salt from this vault's own header. Saves write
    /// them back unchanged: the key was derived with them.
    kdf: KdfParams,
    path: PathBuf,
    /// Held for as long as the profile is open; dropping it releases the lock.
    _lock: ProfileLock,
}

/// Must NOT contain the word "decrypt": the picker turns that into "Wrong password.".
/// Also used when this same window still holds it (e.g. deleting it after a reload).
const PROFILE_IN_USE_MSG: &str = "[VAULT] PROFILE_IN_USE: This profile is open in a Solanum window. Close or lock it there first.";

/// `<file name>.<suffix>` next to `path`, e.g. `work.solanum.lock` for `work.solanum`.
fn sidecar_path(path: &std::path::Path, suffix: &str) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!("{}.{}", name, suffix))
}

/// Exclusive OS lock on `<profile>.solanum.lock`, held while the profile is open.
/// Two processes with the same profile open would each rewrite the whole vault
/// from their own in-memory copy and silently discard the other's changes. The
/// OS releases the lock when the handle closes, crashes included, so a stale
/// lock file never blocks anyone.
struct ProfileLock {
    _file: fs::File,
}

impl ProfileLock {
    fn acquire(vault_path: &std::path::Path) -> Result<Self, String> {
        let lock_path = sidecar_path(vault_path, "lock");
        let mut opts = fs::OpenOptions::new();
        // No truncate: the file carries no data, and truncating a file another
        // process holds a lock on is asking for platform-specific trouble.
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        // Messages carry no path: it contains the profile name, and the picker
        // treats any message containing "decrypt" as a wrong password.
        let file = opts
            .open(&lock_path)
            .map_err(|e| format!("[FILE] PROFILE_LOCK_OPEN_FAILED: {}", e))?;
        #[cfg(unix)]
        {
            // `mode` only applies to files this call creates.
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        // Exclusive, non-blocking: flock on Unix and Android, LockFileEx on Windows.
        // Both are per handle, so a second handle in this same process conflicts too.
        match file.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => return Err(PROFILE_IN_USE_MSG.into()),
            Err(fs::TryLockError::Error(e)) => {
                // No usable file locks here (an unsupported platform, NFS without a
                // lock daemon, ...). The lock guards against lost edits, not against
                // an attacker, and refusing would lock the user out of their data, so
                // carry on without it, loudly.
                eprintln!("[solanum] could not lock the profile ({}); it is open without a profile lock", e);
                return Ok(ProfileLock { _file: file });
            }
        }
        // A concurrent delete_profile may have unlinked the lock file between our
        // open and our lock: we would then hold a lock on an orphaned file while
        // the next opener creates and locks a new one. Treat that as "in use".
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let same_file = match (file.metadata(), fs::metadata(&lock_path)) {
                (Ok(held), Ok(at_path)) => held.dev() == at_path.dev() && held.ino() == at_path.ino(),
                _ => false,
            };
            if !same_file {
                return Err(PROFILE_IN_USE_MSG.into());
            }
        }
        Ok(ProfileLock { _file: file })
    }
}

/// Test-only KDF settings at the lower bounds, so tests that derive keys stay fast.
#[cfg(test)]
fn test_kdf(salt_byte: u8) -> KdfParams {
    KdfParams { m_cost: ARGON2_M_COST_MIN, t_cost: 1, p_cost: 1, salt: [salt_byte; SALT_LEN] }
}

/// Test-only open-vault state with a fixed key (no KDF run).
#[cfg(test)]
fn test_open_vault(path: &std::path::Path, key: [u8; 32]) -> OpenVault {
    OpenVault {
        key: Zeroizing::new(key),
        kdf: test_kdf(3),
        path: path.to_path_buf(),
        _lock: ProfileLock::acquire(path).expect("test profile lock"),
    }
}

// ---------------------------------------------------------------------------
// Profile path helpers
// ---------------------------------------------------------------------------

/// Where all profile files live. Created on first use. Each profile is an
/// independently encrypted `.solanum` file — no shared salt, no shared key.
pub(crate) fn profiles_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let data_dir = app.path().app_data_dir()
        .map_err(|e| format!("[SYSTEM] APP_DATA_DIR_NOT_FOUND: {}", e))?;
    Ok(data_dir.join("profiles"))
}

/// Compute the on-disk path for a named profile. Caller has already
/// validated the name with `validate_profile_name`.
pub(crate) fn profile_path(app: &tauri::AppHandle, name: &str) -> Result<PathBuf, String> {
    Ok(profiles_dir(app)?.join(format!("{}.solanum", name)))
}

/// Reject names that would let a user escape the profiles dir or collide
/// with reserved filenames on Windows. Keep the charset narrow on purpose
/// so a profile name is always a safe filename component on every OS.
/// The name is checked exactly as given, never trimmed: it is used as-is for
/// the file name and the active profile, so `" work"` must not pass as `"work"`
/// (the picker trims what the user typed before sending it).
pub(crate) fn validate_profile_name(name: &str) -> Result<(), String> {
    let n = name;
    if n.is_empty() {
        return Err("Profile name cannot be empty".into());
    }
    if n.len() > 32 {
        return Err("Profile name too long (max 32 chars)".into());
    }
    if !n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("Profile name may only contain letters, numbers, '-' and '_'".into());
    }
    // Windows reserved device names — also weird on macOS/Linux as filename roots.
    let upper = n.to_uppercase();
    let reserved = ["CON", "PRN", "AUX", "NUL"];
    // `last_byte` is safe here because we already enforced ASCII-only at
    // the charset check above — but we still use `?`/`.map(...)` rather
    // than `.unwrap()` so a future relaxation can never silently panic.
    let last_ascii_digit = upper.as_bytes().last().is_some_and(|b| b.is_ascii_digit());
    if reserved.contains(&upper.as_str())
        || (upper.starts_with("COM") && upper.len() == 4 && last_ascii_digit)
        || (upper.starts_with("LPT") && upper.len() == 4 && last_ascii_digit)
    {
        return Err(format!("'{}' is a reserved name on Windows", n));
    }
    Ok(())
}

// Argon2id parameters for NEW vaults:
//   m_cost   64 MiB  — memory hardness; raises cost of GPU/ASIC attacks
//   t_cost   3       — passes over the buffer
//   p_cost   4       — parallelism; up to 4 lanes if available
//   output   32 B    — AES-256-GCM key length
// Tuned higher than OWASP's interactive-login defaults because this protects
// the entire profile vault, not a single-request login. Every vault stores the
// values it was created with in its header and keeps them on every save, so
// changing these affects only vaults created afterwards.
const ARGON2_M_COST: u32 = 64 * 1024;
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;
// Hard bounds for the parameters read from a vault header, checked before any
// derivation: a damaged or hostile file can't make the app allocate more than
// 512 MiB or grind for minutes. The memory floor is OWASP's smallest Argon2id
// setting; the ceiling leaves room to raise the default later (including on Android).
const ARGON2_M_COST_MIN: u32 = 19 * 1024;
const ARGON2_M_COST_MAX: u32 = 512 * 1024;
const ARGON2_T_COST_MAX: u32 = 10;
const ARGON2_P_COST_MAX: u32 = 16;

/// Argon2id settings and salt of one vault, as stored in its header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KdfParams {
    /// Memory in KiB.
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    salt: [u8; SALT_LEN],
}

impl KdfParams {
    /// Settings for a brand-new vault: today's defaults and a fresh random salt.
    fn for_new_vault() -> Self {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill(&mut salt);
        KdfParams { m_cost: ARGON2_M_COST, t_cost: ARGON2_T_COST, p_cost: ARGON2_P_COST, salt }
    }

    /// Refuse settings outside the hard bounds. Must NOT contain the word "decrypt".
    fn check_bounds(&self) -> Result<(), String> {
        let in_bounds = (ARGON2_M_COST_MIN..=ARGON2_M_COST_MAX).contains(&self.m_cost)
            && (1..=ARGON2_T_COST_MAX).contains(&self.t_cost)
            && (1..=ARGON2_P_COST_MAX).contains(&self.p_cost);
        if in_bounds {
            Ok(())
        } else {
            Err(format!(
                "[VAULT] KDF_PARAMS_UNSUPPORTED: This file asks for key-derivation settings outside what Solanum accepts ({} KiB of memory, {} passes, {} lanes). It is damaged or not a genuine Solanum profile, so it was not opened.",
                self.m_cost, self.t_cost, self.p_cost,
            ))
        }
    }
}

fn derive_key(password: &str, kdf: &KdfParams) -> Result<[u8; 32], String> {
    // Callers parse the header first, which already checks this; repeated here so
    // no path can ever reach Argon2 with unchecked parameters.
    kdf.check_bounds()?;
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32))
        .map_err(|e| format!("[CRYPTO] ARGON2_PARAMS: {}", e))?;
    // Argon2's working memory (m_cost KiB) is reserved here rather than by
    // `hash_password_into`, whose allocation aborts the whole app when it
    // fails, as up to 512 MiB can on 32-bit Android (N-005). Must NOT contain
    // the word "decrypt".
    let mut blocks: Vec<Block> = Vec::new();
    blocks.try_reserve_exact(params.block_count()).map_err(|_| {
        format!(
            "[VAULT] KDF_MEMORY_UNAVAILABLE: This profile needs {} MiB of memory to unlock, more than this device can give. It was not opened.",
            kdf.m_cost / 1024,
        )
    })?;
    blocks.resize(params.block_count(), Block::default());
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    // Raw API: write derived bytes directly into the key buffer. Avoids
    // the PHC-string round-trip (encode then truncate b64) the previous
    // implementation used, which was fragile and made parameter changes
    // invisible to type-checking.
    let hashed = argon2.hash_password_into_with_memory(password.as_bytes(), &kdf.salt, &mut key, &mut blocks);
    // The blocks hold the state the key is computed from.
    blocks.zeroize();
    hashed.map_err(|e| format!("[CRYPTO] HASH_FAILED: {}", e))?;
    Ok(key)
}

/// The fixed-size header at the start of a vault file. Its bytes are also the
/// file's AES-GCM associated data.
struct VaultHeader {
    kdf: KdfParams,
    nonce: [u8; NONCE_LEN],
}

impl VaultHeader {
    fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut h = [0u8; HEADER_LEN];
        h[0..4].copy_from_slice(VAULT_MAGIC);
        h[4] = VAULT_VERSION;
        h[5] = KDF_ARGON2ID_V13;
        h[6..10].copy_from_slice(&self.kdf.m_cost.to_le_bytes());
        h[10..14].copy_from_slice(&self.kdf.t_cost.to_le_bytes());
        h[14..18].copy_from_slice(&self.kdf.p_cost.to_le_bytes());
        h[18..18 + SALT_LEN].copy_from_slice(&self.kdf.salt);
        h[HEADER_LEN - NONCE_LEN..].copy_from_slice(&self.nonce);
        h
    }
}

/// Parse and check the header at the start of a vault file without the password.
/// Everything a hostile file could use to make unlocking expensive is refused here,
/// before any key derivation. None of the refusals contains the word "decrypt".
fn parse_vault_header(data: &[u8]) -> Result<VaultHeader, String> {
    if data.len() >= VAULT_MAGIC.len() && &data[..VAULT_MAGIC.len()] != VAULT_MAGIC {
        return Err(format!("[VAULT] UNSUPPORTED_PROFILE: {}", FOREIGN_PROFILE_MSG));
    }
    if data.len() < VAULT_MAGIC.len() + 1 {
        return Err("[VAULT] INVALID_FORMAT: the file is too short to be a profile.".into());
    }
    let version = data[4];
    if version == 1 {
        return Err(format!(
            "[VAULT] FORMAT_BEHIND_BINARY: This profile was saved in an older Solanum file format (v{}) that this build no longer reads. {}",
            version, OUTDATED_PROFILE_TAIL,
        ));
    }
    if version > VAULT_VERSION {
        return Err(format!(
            "[VAULT] FORMAT_AHEAD_OF_BINARY: this profile was written by a newer build (file format v{}), this app understands v{}. Upgrade the app before opening it.",
            version, VAULT_VERSION,
        ));
    }
    if version != VAULT_VERSION {
        return Err(format!("[VAULT] UNSUPPORTED_PROFILE: {}", FOREIGN_PROFILE_MSG));
    }
    if data.len() < HEADER_LEN {
        return Err("[VAULT] INVALID_FORMAT: the file is truncated (incomplete header).".into());
    }
    if data[5] != KDF_ARGON2ID_V13 {
        return Err(format!(
            "[VAULT] KDF_PARAMS_UNSUPPORTED: This file uses an unknown key-derivation method ({}). It is damaged or not a genuine Solanum profile, so it was not opened.",
            data[5],
        ));
    }
    let word = |at: usize| u32::from_le_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]]);
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&data[18..18 + SALT_LEN]);
    let kdf = KdfParams { m_cost: word(6), t_cost: word(10), p_cost: word(14), salt };
    kdf.check_bounds()?;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&data[HEADER_LEN - NONCE_LEN..HEADER_LEN]);
    Ok(VaultHeader { kdf, nonce })
}

/// Split a whole vault file into its checked header and the ciphertext (tag included).
fn parse_vault_blob(data: &[u8]) -> Result<(VaultHeader, &[u8]), String> {
    let header = parse_vault_header(data)?;
    if data.len() < HEADER_LEN + TAG_LEN {
        return Err("[VAULT] INVALID_FORMAT: the file is truncated (no encrypted body).".into());
    }
    Ok((header, &data[HEADER_LEN..]))
}

/// Encrypt `plaintext` into a complete vault file: header (with a fresh nonce)
/// followed by AES-256-GCM ciphertext, the header bound as associated data.
fn seal_vault_blob(plaintext: &[u8], key: &[u8; 32], kdf: &KdfParams) -> Result<Vec<u8>, String> {
    let header = VaultHeader { kdf: *kdf, nonce: rand::thread_rng().gen() }.to_bytes();
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(&header[HEADER_LEN - NONCE_LEN..]);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad: &header })
        .map_err(|e| format!("[CRYPTO] ENCRYPT_FAILED: {}", e))?;
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Check and decrypt a complete vault file. Returns the (still compressed) body.
/// A wrong key and any modified byte, header included, both end here as a
/// "decrypt" failure, which the picker shows as "Wrong password.".
fn open_vault_blob(data: &[u8], key: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, String> {
    let (header, ciphertext) = parse_vault_blob(data)?;
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(&header.nonce), Payload { msg: ciphertext, aad: &data[..HEADER_LEN] })
        .map(Zeroizing::new)
        .map_err(|e| format!("[CRYPTO] DECRYPT_FAILURE: Possible wrong key or corrupted data. Details: {}", e))
}

/// Copies `data` into a sqlite-allocated buffer wrapped in `OwnedData`.
/// `Connection::deserialize` requires a buffer allocated by `sqlite3_malloc`
/// because it frees it via `SQLITE_DESERIALIZE_FREEONCLOSE`.
fn to_sqlite_owned(data: &[u8]) -> Result<OwnedData, String> {
    let sz = data.len();
    let raw = unsafe { ffi::sqlite3_malloc64(sz as u64) } as *mut u8;
    let ptr = NonNull::new(raw).ok_or("[DATABASE] SQLITE_MALLOC_FAILED")?;
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr.as_ptr(), sz);
        Ok(OwnedData::from_raw_nonnull(ptr, sz))
    }
}

/// Compress the plaintext SQLite serialisation before it is encrypted.
/// Errors here are surfaced as crypto-domain errors because the caller's
/// invariant ("save the DB") is what's broken, not just I/O.
fn vault_compress(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    zstd::stream::encode_all(plaintext, VAULT_COMPRESS_LEVEL)
        .map_err(|e| format!("[VAULT] COMPRESS_FAILED: {}", e))
}

/// Decompress the post-decrypt body when a vault is read. Bounded by a
/// generous max-size guard so a corrupt or hostile file can't make us
/// allocate gigabytes — a real Solanum SQLite snapshot is well under
/// 64 MiB even with thousands of nodes.
fn vault_decompress(compressed: &[u8]) -> Result<Vec<u8>, String> {
    const MAX_DECOMPRESSED: usize = 64 * 1024 * 1024;
    let mut out = Vec::new();
    let mut decoder = zstd::stream::Decoder::new(compressed)
        .map_err(|e| format!("[VAULT] DECOMPRESS_INIT_FAILED: {}", e))?;
    use std::io::Read;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = decoder.read(&mut buf)
            .map_err(|e| format!("[VAULT] DECOMPRESS_FAILED: {}", e))?;
        if n == 0 { break; }
        if out.len() + n > MAX_DECOMPRESSED {
            return Err("[VAULT] DECOMPRESS_TOO_LARGE: refusing to inflate past 64 MiB".into());
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// Create a file that only its owner can read or write (0600 on Unix; elsewhere the parent folder's
/// per-user permissions apply). Vaults are encrypted, but there is no reason for other local users
/// to be able to copy one and guess passwords offline. With `create_new` it fails, atomically,
/// if the path already exists (a symlink counts), so it can never clobber or follow anything.
fn create_private_file(path: &std::path::Path, create_new: bool) -> std::io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true);
    if create_new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        // `mode` only applies to files this call creates: tighten a leftover from an older build too.
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// The profiles folder, created (and kept owner-only on Unix) if it doesn't exist yet.
fn ensure_profiles_dir(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = profiles_dir(app)?;
    fs::create_dir_all(&dir).map_err(|e| format!("[FILE] MKDIR_FAILED: {}", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

/// Write an imported profile to `dst`, refusing to overwrite anything. The existence check in the
/// caller only gives a friendly early error; this is the check that can't be raced. A partly
/// written file is removed again so a failed import never leaves a broken profile in the picker.
fn write_new_profile_file(dst: &std::path::Path, bytes: &[u8], name: &str) -> Result<(), String> {
    use std::io::Write;
    let mut f = create_private_file(dst, true).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!("Profile '{}' already exists", name)
        } else {
            format!("[FILE] IMPORT_WRITE_FAILED to {:?}: {}", dst, e)
        }
    })?;
    if let Err(e) = f.write_all(bytes).and_then(|_| f.sync_all()) {
        drop(f);
        let _ = fs::remove_file(dst);
        return Err(format!("[FILE] IMPORT_WRITE_FAILED to {:?}: {}", dst, e));
    }
    Ok(())
}

/// Save from a command body. The work blocks (serialise, compress, encrypt,
/// fsync), so it runs inside `block_in_place`: the runtime hands this worker's
/// other tasks to another thread meanwhile, so terminal output and keystrokes
/// keep flowing. Not `save_vault_async` here: the command bodies still have a
/// `&Connection` borrowed from a std guard in scope, which makes an `.await`
/// non-`Send`, and re-scoping every one of them would be a large diff for the
/// same effect. Commands run on Tauri's multi-threaded tokio runtime, which
/// `block_in_place` requires (it panics on a current-thread runtime).
fn save_vault_internal(state: &DbState) -> Result<(), String> {
    tokio::task::block_in_place(|| save_locked_vault(&state.conn, &state.vault))
}

/// Lock the connection, then the open-vault state (the order every path uses),
/// and write the vault. Both come from the same lock scope, so a save can never
/// mix one profile's database with another profile's key or path.
fn save_locked_vault(
    conn: &StdMutex<Option<Connection>>,
    vault: &StdMutex<Option<OpenVault>>,
) -> Result<(), String> {
    let mut conn_guard = conn.lock().map_err(|_| "[STATE] MUTEX_POISON_CONN")?;
    let vault_guard = vault.lock().map_err(|_| "[STATE] MUTEX_POISON_VAULT")?;
    match (&mut *conn_guard, &*vault_guard) {
        (Some(conn), Some(vault)) => save_vault_blocking(conn, vault),
        _ => Err("[STATE] MISSING_REQUIRED_RESOURCES_FOR_SAVE".into()),
    }
}

/// Pure-sync vault serialise + encrypt + atomic write. Run on the blocking
/// pool by `save_vault_async`, so the SQLite serialise, zstd compression,
/// AES-GCM encrypt, and fsync stay off the tokio worker pool.
fn save_vault_blocking(conn: &mut Connection, vault: &OpenVault) -> Result<(), String> {
    let serialized = conn.serialize(MAIN_DB)
        .map_err(|e| format!("[DATABASE] SERIALIZE_FAILED: {}", e))?;
    // Compress-then-encrypt. Order matters: compressing AFTER encryption
    // is useless because AES-GCM ciphertext is indistinguishable from
    // random. Doing it before keeps the on-disk file small AND keeps
    // ciphertext semantically secure.
    let compressed = Zeroizing::new(vault_compress(&serialized)?);
    let blob = seal_vault_blob(&compressed, &vault.key, &vault.kdf)?;
    write_file_atomically(&vault.path, &blob)
}

/// Atomic write: fresh temp file next to `path` -> fsync -> rename over `path`.
/// A crash or power loss mid-write leaves the previous file intact. The temp name
/// is random and created with `create_new`, so two writers never share one and
/// nothing planted at a predictable name is followed or clobbered. Leftovers of a
/// crashed write (`<name>.<random>.tmp`) are swept when the profile is next opened.
fn write_file_atomically(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let tmp_path = sidecar_path(path, &format!("{:016x}.tmp", rand::thread_rng().gen::<u64>()));
    let written = (|| {
        let mut f = create_private_file(&tmp_path, true)
            .map_err(|e| format!("[FILE] VAULT_TMP_CREATE_FAILED at {:?}: {}", tmp_path, e))?;
        f.write_all(bytes)
            .map_err(|e| format!("[FILE] VAULT_TMP_WRITE_FAILED at {:?}: {}", tmp_path, e))?;
        f.sync_all()
            .map_err(|e| format!("[FILE] VAULT_TMP_SYNC_FAILED at {:?}: {}", tmp_path, e))?;
        drop(f);
        fs::rename(&tmp_path, path)
            .map_err(|e| format!("[FILE] VAULT_RENAME_FAILED {:?} -> {:?}: {}", tmp_path, path, e))
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    written?;
    // Make the rename itself durable (Unix: fsync the folder; elsewhere a no-op).
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Remove temp files left by a write that crashed half-way (`<name>.*.tmp`,
/// including the fixed `<name>.tmp` older builds used). Called only with the
/// profile lock held, so no live save of this profile can own them.
fn sweep_stale_temp_files(vault_path: &std::path::Path) {
    let (Some(dir), Some(name)) = (vault_path.parent(), vault_path.file_name().and_then(|n| n.to_str())) else {
        return;
    };
    let prefix = format!("{}.", name);
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        if file_name.to_str().is_some_and(|f| f.starts_with(&prefix) && f.ends_with(".tmp")) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

// ---------------------------------------------------------------------------
// Vault schema: creation and loading
// ---------------------------------------------------------------------------

/// Schema version of a vault created by this app.
///
/// This app is standalone: it opens only vaults it created itself, at exactly this
/// version. Anything else — a file from the original Submarine app, or a vault
/// written by a newer build of this app — is refused rather than half-understood.
/// When the schema changes, bump this AND add a migration from the previous
/// version in `load_vault` — unless, as with the 1->2 bump (added `pinned_at`
/// to `servers`/`folders`), the 2->3 bump (added the `snippets` table), the
/// 3->4 bump (foreign keys on every reference, shipped together with vault file
/// format 2), the 4->5 bump (per-server `legacy_algorithms`) and the 5->6 bump
/// (per-server `terminal_only`), there's no real vault yet worth preserving
/// across the change;
/// pre-release, a clean break (old vaults refused like any other incompatible
/// file, just recreate them) is simpler than migration machinery nobody needs
/// yet. Once real vaults exist, go back to migrating. A pre-release bump also
/// means regenerating the fixture vault (see `fixture_vault_tests`).
const SCHEMA_VERSION: i64 = 6;

/// The in-memory database that holds a decrypted vault. EVERY vault connection
/// must come from here.
///
/// `temp_store = MEMORY` is a security setting, not a tuning knob. This database
/// holds every credential in plaintext, and by default SQLite spills large
/// temporary structures (a `VACUUM` copy, big sorts) into files in the OS temp
/// directory — which would put plaintext secrets on disk in a vault the user
/// believes is encrypted at rest. Measured with strace before this was set:
/// vacuuming a 22 MB vault wrote a plaintext copy to `/var/tmp/etilqs_*`.
///
/// `foreign_keys = ON` is per connection and off by default in SQLite, so it is
/// set here too: without it every `REFERENCES ... ON DELETE` in the schema is
/// silently ignored.
///
/// `secure_delete = ON` (`SECURE_DELETE_PRAGMA`): the saved vault is the
/// database's whole image, and SQLite otherwise leaves deleted content (cleared
/// command history, a deleted login or key) in free pages, so it would stay in
/// the file until those pages happen to be reused (F-023).
/// Kept by SQLite per database, not per connection: loading a vault
/// (`deserialize`) resets it, so `load_vault` sets it again.
const SECURE_DELETE_PRAGMA: &str = "PRAGMA secure_delete = ON;";

fn open_vault_memory_db() -> Result<Connection, String> {
    let conn = Connection::open_in_memory()
        .map_err(|e| format!("[DATABASE] MEM_INIT_FAILED: {}", e))?;
    conn.execute_batch("PRAGMA temp_store = MEMORY; PRAGMA foreign_keys = ON;")
        .map_err(|e| format!("[DATABASE] PRAGMA_FAILED: {}", e))?;
    conn.execute_batch(SECURE_DELETE_PRAGMA)
        .map_err(|e| format!("[DATABASE] PRAGMA_FAILED: {}", e))?;
    Ok(conn)
}

/// Create the schema of a brand-new vault.
///
/// `servers.legacy_algorithms` (schema 5) is the per-server opt-in for SHA-1 key
/// exchange, MACs and `ssh-rsa` signatures (`ssh_connect::AlgorithmPolicy`).
/// `servers.terminal_only` (schema 6) makes a connection to that server a plain
/// terminal, with no SFTP, live info or Docker (`ssh_connect::ChannelGate`).
///
/// References and what deleting the referenced row does (schema 4 and 5):
/// - `folders.parent_id`, `servers.folder_id`: CASCADE — a folder takes its
///   sub-folders and servers with it (the UI says so).
/// - `servers.credential_id`, `servers.key_id`, `credentials.key_id`: SET NULL —
///   the row stays; its `auth_type` still says a login/key is needed, which is how
///   the connect path can tell the user it was deleted (`missing_identity_reason`).
/// - `servers.jump_host_id`: NO ACTION — deleting a server other servers jump
///   through is refused (owner decision: never silently switch them to a direct
///   connection). Not RESTRICT: NO ACTION is checked at the end of the statement,
///   so a folder holding both a bastion and the servers behind it can still be
///   deleted in one go.
/// - `monitor_configs.node_id`: CASCADE.
/// - `cmd_history.server_id` has no foreign key on purpose: it is a log that keeps
///   `server_name` alongside, ids are never reused (AUTOINCREMENT), and an FK would
///   turn a stale id into a silently dropped history row.
/// - `known_hosts` is keyed by host and port, not by server: a host key belongs
///   to the host, and several servers can share it.
fn create_vault_schema(conn: &Connection) -> Result<(), String> {
    conn.execute_batch(&format!(
        "CREATE TABLE folders (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, parent_id INTEGER REFERENCES folders(id) ON DELETE CASCADE, color TEXT, pinned_at INTEGER);
         CREATE TABLE ssh_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, public_key TEXT, private_key TEXT, passphrase TEXT);
         CREATE TABLE credentials (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, auth_type TEXT, username TEXT, password TEXT, key_id INTEGER REFERENCES ssh_keys(id) ON DELETE SET NULL);
         CREATE TABLE servers (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, host TEXT, port INTEGER, username TEXT, password TEXT, credential_id INTEGER REFERENCES credentials(id) ON DELETE SET NULL, folder_id INTEGER REFERENCES folders(id) ON DELETE CASCADE, proxy_type TEXT DEFAULT 'none', proxy_host TEXT, proxy_port INTEGER, tunnels TEXT, auth_type TEXT DEFAULT 'vault', key_id INTEGER REFERENCES ssh_keys(id) ON DELETE SET NULL, autostart INTEGER NOT NULL DEFAULT 0, mirrors TEXT NOT NULL DEFAULT '[]', color TEXT, notes TEXT NOT NULL DEFAULT '', run_on_connect TEXT NOT NULL DEFAULT '', jump_host_id INTEGER REFERENCES servers(id) ON DELETE NO ACTION, position INTEGER NOT NULL DEFAULT 0, pinned_at INTEGER, legacy_algorithms INTEGER NOT NULL DEFAULT 0, terminal_only INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE commands (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, content TEXT);
         CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, body TEXT);
         CREATE TABLE snippets (id INTEGER PRIMARY KEY AUTOINCREMENT, trigger_text TEXT NOT NULL UNIQUE, expansion_text TEXT NOT NULL);
         INSERT INTO snippets (trigger_text, expansion_text) VALUES
             (';gs', 'git status'),
             (';gc', 'git commit -m \"'),
             (';ll', 'ls -la');
         CREATE TABLE known_hosts (id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT, port INTEGER, fingerprint TEXT, key_type TEXT);
         CREATE TABLE monitor_configs (node_id INTEGER PRIMARY KEY, enabled_metrics TEXT NOT NULL DEFAULT '[\"cpu\",\"mem\",\"disk\",\"load\"]', custom_metrics TEXT NOT NULL DEFAULT '[]', paused INTEGER NOT NULL DEFAULT 1, FOREIGN KEY(node_id) REFERENCES servers(id) ON DELETE CASCADE);
         CREATE TABLE monitor_settings (id INTEGER PRIMARY KEY, json TEXT NOT NULL);
         CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
         CREATE TABLE cmd_history (id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER, server_name TEXT, command TEXT NOT NULL, ts INTEGER NOT NULL, exit_code INTEGER);
         CREATE INDEX idx_cmd_history_ts ON cmd_history(ts DESC);
         INSERT INTO schema_meta (key, value) VALUES ('schema_version', '{SCHEMA_VERSION}');"
    ))
    .map_err(|e| format!("[DATABASE] SCHEMA_CREATION_FAILED: {}", e))
}

/// Accept a vault only if it carries exactly this app's schema version. Nothing
/// is ever rewritten here: a refused vault is left exactly as it was.
fn check_vault_schema(conn: &Connection) -> Result<(), String> {
    // A database with no `schema_meta` (a foreign file) reads as version 0.
    let stored: i64 = conn
        .query_row(
            "SELECT CAST(value AS INTEGER) FROM schema_meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0);
    if stored > SCHEMA_VERSION {
        return Err(format!(
            "[DATABASE] SCHEMA_AHEAD_OF_BINARY: this profile was written by a newer build (schema v{}), this app understands v{}. Upgrade the app before opening it.",
            stored, SCHEMA_VERSION,
        ));
    }
    if stored < SCHEMA_VERSION {
        // stored == 0 means no schema_meta row at all — genuinely not one of
        // ours. stored > 0 means this really was a Solanum vault, just at an
        // older internal schema this pre-release build no longer reads (no
        // migration path yet, see SCHEMA_VERSION's doc comment) — that's a
        // different, more honest thing to tell the user than "foreign file".
        if stored == 0 {
            return Err(format!("[VAULT] UNSUPPORTED_PROFILE: {}", FOREIGN_PROFILE_MSG));
        }
        return Err(format!(
            "[VAULT] SCHEMA_BEHIND_BINARY: This profile was created by an older version of Solanum's internal format (schema v{}) that this build no longer reads. {}",
            stored, OUTDATED_PROFILE_TAIL,
        ));
    }
    Ok(())
}

/// Decrypt a whole `.solanum` file with `key` and load it into an in-memory
/// database. Only this app's own vaults load: a foreign header is refused by
/// `parse_vault_blob`, a foreign or newer schema by `check_vault_schema`.
fn load_vault(encrypted_data: &[u8], key: &[u8; 32]) -> Result<Connection, String> {
    let raw = open_vault_blob(encrypted_data, key)?;
    let decrypted_data = Zeroizing::new(vault_decompress(&raw)?);

    let mut conn = open_vault_memory_db()?;
    let owned = to_sqlite_owned(&decrypted_data)?;
    conn.deserialize(MAIN_DB, owned, false)
        .map_err(|e| format!("[DATABASE] DESERIALIZE_FAILED: {}", e))?;
    conn.execute_batch(SECURE_DELETE_PRAGMA)
        .map_err(|e| format!("[DATABASE] PRAGMA_FAILED: {}", e))?;
    check_vault_schema(&conn)?;
    check_vault_integrity(&conn)?;
    Ok(conn)
}

/// Refuse a vault whose rows point at rows that don't exist. A vault this app
/// wrote can't contain such rows (foreign keys are enforced on every
/// connection), so this means a damaged or hand-edited file. Never rewrites it.
/// Must NOT contain the word "decrypt".
fn check_vault_integrity(conn: &Connection) -> Result<(), String> {
    let broken: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT \"table\" || ' -> ' || parent FROM pragma_foreign_key_check")
            .map_err(|e| format!("[DATABASE] INTEGRITY_CHECK_FAILED: {}", e))?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| format!("[DATABASE] INTEGRITY_CHECK_FAILED: {}", e))?;
        rows.collect::<Result<_, _>>()
            .map_err(|e| format!("[DATABASE] INTEGRITY_CHECK_FAILED: {}", e))?
    };
    if broken.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "[VAULT] INTEGRITY_FAILED: This profile's data is inconsistent ({} broken reference(s), e.g. {}), so it was not opened. Your profile file is left untouched; the backup next to it (.solanum.bak) may still be intact.",
            broken.len(), broken[0],
        ))
    }
}

#[cfg(test)]
mod vault_schema_tests {
    use super::*;
    use rusqlite::Connection;

    /// A small but realistic fresh vault, with secrets in several tables.
    fn fresh_vault_conn() -> Connection {
        let conn = open_vault_memory_db().unwrap();
        create_vault_schema(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO folders(name) VALUES ('Prod');
             INSERT INTO ssh_keys(name,public_key,private_key,passphrase) VALUES ('deploy','pub','SECRET-KEY-BYTES','key-pass');
             INSERT INTO credentials(name,auth_type,username,password) VALUES ('root','password','root','cred-secret-pw');
             INSERT INTO servers(name,host,port,username,password,folder_id) VALUES ('bastion','203.0.113.10',22,'admin','bastion-pw',1);
             INSERT INTO commands(title,content) VALUES ('restart','systemctl restart app');
             INSERT INTO notes(title,body) VALUES ('runbook','call the on-call first');
             INSERT INTO monitor_configs(node_id) VALUES (1);
             INSERT INTO known_hosts(host,port,fingerprint,key_type) VALUES ('203.0.113.10',22,'SHA256:abc','ssh-ed25519');",
        )
        .unwrap();
        conn
    }

    fn seal(conn: &mut Connection, key: &[u8; 32], salt: &[u8; SALT_LEN]) -> Vec<u8> {
        let bytes = conn.serialize(MAIN_DB).unwrap().to_vec();
        let compressed = vault_compress(&bytes).unwrap();
        seal_vault_blob(&compressed, key, &KdfParams { salt: *salt, ..test_kdf(0) }).unwrap()
    }

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("solanum-schema-test-{:016x}", rand::thread_rng().gen::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle.as_bytes())
    }

    fn temp_store(conn: &Connection) -> i64 {
        conn.query_row("PRAGMA temp_store", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn fresh_vault_round_trips_and_is_really_encrypted_on_disk() {
        let dir = scratch_dir();
        let key = [0x42u8; 32];
        let vault = dir.join("p.solanum");

        save_vault_blocking(&mut fresh_vault_conn(), &test_open_vault(&vault, key)).unwrap();
        let on_disk = fs::read(&vault).unwrap();

        // Nothing readable in the file itself.
        for secret in ["cred-secret-pw", "SECRET-KEY-BYTES", "bastion-pw", "203.0.113.10", "call the on-call first"] {
            assert!(!contains(&on_disk, secret), "{secret:?} must not appear in the encrypted file");
        }
        // ...but everything comes back with the right key.
        let loaded = load_vault(&on_disk, &key).unwrap();
        assert_eq!(count(&loaded, "SELECT COUNT(*) FROM servers WHERE password='bastion-pw' AND host='203.0.113.10'"), 1);
        assert_eq!(count(&loaded, "SELECT COUNT(*) FROM credentials WHERE password='cred-secret-pw'"), 1);
        assert_eq!(count(&loaded, "SELECT COUNT(*) FROM ssh_keys WHERE private_key='SECRET-KEY-BYTES'"), 1);
        assert_eq!(count(&loaded, "SELECT CAST(value AS INTEGER) FROM schema_meta WHERE key='schema_version'"), SCHEMA_VERSION);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_fresh_vault_carries_no_sync_or_cloud_leftovers() {
        let conn = fresh_vault_conn();
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger'"), 0, "no triggers");
        assert_eq!(count(&conn, "SELECT COUNT(*) FROM sqlite_master WHERE lower(name) LIKE '%sync%'"), 0, "no sync objects");
        let tables: Vec<String> = {
            let mut st = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").unwrap();
            st.query_map([], |r| r.get::<_, String>(0)).unwrap().map(|r| r.unwrap()).collect()
        };
        assert!(!tables.is_empty());
        for t in tables {
            for col in ["uuid", "updated_at", "deleted", "edited_by"] {
                let n: i64 = conn
                    .query_row("SELECT COUNT(*) FROM pragma_table_info(?1) WHERE name = ?2", [t.as_str(), col], |r| r.get(0))
                    .unwrap();
                assert_eq!(n, 0, "{t}.{col} must not exist");
            }
        }
    }

    #[test]
    fn a_profile_from_the_original_cloud_build_is_refused_by_its_header() {
        let key = [0x11u8; 32];
        let mut blob = seal(&mut fresh_vault_conn(), &key, &[1u8; SALT_LEN]);
        blob[..4].copy_from_slice(b"OMNV"); // the original app's file header
        let err = load_vault(&blob, &key).unwrap_err();
        assert!(err.contains("UNSUPPORTED_PROFILE"), "{err}");
        // The picker turns any message containing "decrypt" into "Wrong password." — this one must not.
        assert!(!err.to_lowercase().contains("decrypt"), "{err}");
    }

    fn stored_version(conn: &Connection) -> i64 {
        count(conn, "SELECT COALESCE((SELECT CAST(value AS INTEGER) FROM schema_meta WHERE key='schema_version'), -1)")
    }

    #[test]
    fn a_vault_with_another_schema_version_is_refused_and_never_touched() {
        // OLDER than this app's schema (no version recorded at all) -> "not one of ours".
        let no_version = fresh_vault_conn();
        no_version.execute("DELETE FROM schema_meta WHERE key='schema_version'", []).unwrap();
        let err = check_vault_schema(&no_version).unwrap_err();
        assert!(err.contains("UNSUPPORTED_PROFILE"), "{err}");
        assert!(!err.to_lowercase().contains("decrypt"), "{err}");
        assert_eq!(stored_version(&no_version), -1, "read-only: nothing may be written back");

        // A database from somewhere else entirely: no schema_meta table.
        let foreign = Connection::open_in_memory().unwrap();
        foreign.execute_batch("CREATE TABLE something_else(a);").unwrap();
        assert!(check_vault_schema(&foreign).unwrap_err().contains("UNSUPPORTED_PROFILE"));

        // NEWER than this app's schema -> "upgrade the app", again without touching anything.
        for newer in [SCHEMA_VERSION + 1, SCHEMA_VERSION + 3, 99] {
            let conn = fresh_vault_conn();
            conn.execute("UPDATE schema_meta SET value=?1 WHERE key='schema_version'", [newer.to_string()]).unwrap();
            let err = check_vault_schema(&conn).unwrap_err();
            assert!(err.contains("SCHEMA_AHEAD_OF_BINARY"), "v{newer}: {err}");
            assert!(!err.to_lowercase().contains("decrypt"), "{err}");
            assert_eq!(stored_version(&conn), newer, "read-only");
        }

        // OLDER but a REAL prior Solanum version (not a foreign/missing one) ->
        // a distinct, honest message: this genuinely was one of ours, this
        // build just doesn't read that old a schema — not "foreign file".
        for older in 1..SCHEMA_VERSION {
            let conn = fresh_vault_conn();
            conn.execute("UPDATE schema_meta SET value=?1 WHERE key='schema_version'", [older.to_string()]).unwrap();
            let err = check_vault_schema(&conn).unwrap_err();
            assert!(err.contains("SCHEMA_BEHIND_BINARY"), "v{older}: {err}");
            assert!(!err.contains("UNSUPPORTED_PROFILE"), "must not read as a foreign file: {err}");
            assert!(!err.to_lowercase().contains("decrypt"), "{err}");
            assert_eq!(stored_version(&conn), older, "read-only");
        }

        // The current version passes.
        assert!(check_vault_schema(&fresh_vault_conn()).is_ok());

        // And the check really is wired into the real path: encrypted files holding a wrong schema are refused.
        let key = [0x33u8; 32];
        let mut older = fresh_vault_conn();
        older.execute("DELETE FROM schema_meta WHERE key='schema_version'", []).unwrap();
        let err = load_vault(&seal(&mut older, &key, &[4u8; SALT_LEN]), &key).unwrap_err();
        assert!(err.contains("UNSUPPORTED_PROFILE"), "{err}");
        let mut newer = fresh_vault_conn();
        newer.execute("UPDATE schema_meta SET value=?1 WHERE key='schema_version'", [(SCHEMA_VERSION + 1).to_string()]).unwrap();
        let err = load_vault(&seal(&mut newer, &key, &[5u8; SALT_LEN]), &key).unwrap_err();
        assert!(err.contains("SCHEMA_AHEAD_OF_BINARY"), "{err}");
    }

    #[test]
    fn the_wrong_password_still_reads_as_a_decrypt_failure() {
        let blob = seal(&mut fresh_vault_conn(), &[0x42u8; 32], &[7u8; SALT_LEN]);
        let err = load_vault(&blob, &[0u8; 32]).unwrap_err();
        assert!(err.to_lowercase().contains("decrypt"), "the picker relies on this to say 'Wrong password.': {err}");
    }

    #[test]
    fn every_vault_connection_keeps_temporary_data_in_memory() {
        // 2 = MEMORY. With the default (0/1) SQLite may write a plaintext copy of the vault to the OS temp dir.
        assert_eq!(temp_store(&open_vault_memory_db().unwrap()), 2, "fresh-vault connection");
        let key = [0x21u8; 32];
        let loaded = load_vault(&seal(&mut fresh_vault_conn(), &key, &[2u8; SALT_LEN]), &key).unwrap();
        assert_eq!(temp_store(&loaded), 2, "connection returned by load_vault (used for the whole session)");
    }

    /// F-023: a deleted row (cleared command history, a deleted login) is not
    /// left behind in the saved vault, which is the database's whole image:
    /// SQLite keeps deleted content in free pages unless `secure_delete` is on.
    /// Checked on a new vault and on one loaded from its file.
    #[test]
    fn deleted_rows_do_not_stay_in_the_saved_image() {
        let key = [0x5au8; 32];
        let loaded = load_vault(&seal(&mut fresh_vault_conn(), &key, &[6u8; SALT_LEN]), &key).unwrap();
        for (what, mut conn) in [("new vault", fresh_vault_conn()), ("loaded vault", loaded)] {
            for i in 0..300 {
                conn.execute(
                    "INSERT INTO cmd_history(server_id,server_name,command,ts) VALUES (1,'s',?1,?2)",
                    rusqlite::params![format!("mysql -p typed-secret-{i:04}"), i],
                )
                .unwrap();
            }
            // Long enough to live in overflow pages.
            let long = format!("typed-secret-long {}", "z".repeat(20_000));
            conn.execute("INSERT INTO cmd_history(server_id,server_name,command,ts) VALUES (1,'s',?1,999)", [&long]).unwrap();
            conn.execute("DELETE FROM cmd_history", []).unwrap();
            conn.execute("DELETE FROM credentials", []).unwrap();
            let image = conn.serialize(MAIN_DB).unwrap().to_vec();
            assert!(!contains(&image, "typed-secret-"), "{what}: cleared history is still in the image");
            assert!(!contains(&image, &"z".repeat(64)), "{what}: an overflow page of it is still in the image");
            assert!(!contains(&image, "cred-secret-pw"), "{what}: a deleted login is still in the image");
        }
    }

    /// "This server only" in the history search finds a server's rows even
    /// when many newer rows of other servers come first.
    #[test]
    fn history_of_one_server_is_filtered_before_the_limit() {
        let conn = fresh_vault_conn();
        for i in 0..50 {
            conn.execute("INSERT INTO cmd_history(server_id,server_name,command,ts) VALUES (2,'b',?1,?2)", rusqlite::params![format!("tail -f b-{i}.log"), i]).unwrap();
        }
        for i in 0..300 {
            conn.execute("INSERT INTO cmd_history(server_id,server_name,command,ts) VALUES (1,'a',?1,?2)", rusqlite::params![format!("tail -f a-{i}.log"), 1000 + i]).unwrap();
        }
        let rows = cmd_history_rows(&conn, "", 200, Some(2)).unwrap();
        assert_eq!(rows.len(), 50);
        assert!(rows.iter().all(|r| r["server_id"] == 2));
        assert_eq!(rows[0]["command"], "tail -f b-49.log", "newest first");
        assert_eq!(cmd_history_rows(&conn, "b-1", 200, Some(2)).unwrap().len(), 11, "with a search too");
        assert_eq!(cmd_history_rows(&conn, "", 200, None).unwrap().len(), 200, "all servers");
        assert_eq!(cmd_history_rows(&conn, "50%_\\", 200, None).unwrap().len(), 0, "LIKE characters match literally");
    }
}

#[cfg(test)]
mod vault_format_tests {
    use super::*;

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("solanum-format-test-{:016x}", rand::thread_rng().gen::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn small_vault_conn() -> Connection {
        let conn = open_vault_memory_db().unwrap();
        create_vault_schema(&conn).unwrap();
        conn.execute("INSERT INTO servers(name,host,port,password) VALUES ('s','198.51.100.7',22,'pw-on-file')", []).unwrap();
        conn
    }

    fn seal_with(conn: &mut Connection, key: &[u8; 32], kdf: &KdfParams) -> Vec<u8> {
        let bytes = conn.serialize(MAIN_DB).unwrap().to_vec();
        seal_vault_blob(&vault_compress(&bytes).unwrap(), key, kdf).unwrap()
    }

    /// A v2 header with arbitrary (possibly hostile) fields, followed by a fake body.
    fn raw_header(version: u8, kdf_id: u8, m: u32, t: u32, p: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(VAULT_MAGIC);
        h.push(version);
        h.push(kdf_id);
        for v in [m, t, p] {
            h.extend_from_slice(&v.to_le_bytes());
        }
        h.extend_from_slice(&[7u8; SALT_LEN]);
        h.extend_from_slice(&[9u8; NONCE_LEN]);
        h.extend_from_slice(&[0xAAu8; 64]);
        h
    }

    fn no_decrypt(err: &str) {
        assert!(!err.to_lowercase().contains("decrypt"), "the picker would call this a wrong password: {err}");
    }

    #[test]
    fn the_header_carries_the_kdf_settings_and_round_trips() {
        let key = [0x51u8; 32];
        let kdf = KdfParams { m_cost: 20 * 1024, t_cost: 2, p_cost: 3, salt: [0x5Au8; SALT_LEN] };
        let blob = seal_with(&mut small_vault_conn(), &key, &kdf);
        assert_eq!(&blob[..4], VAULT_MAGIC);
        assert_eq!(blob[4], 2, "format version");
        assert_eq!(blob[5], KDF_ARGON2ID_V13);
        let header = parse_vault_header(&blob).unwrap();
        assert_eq!(header.kdf, kdf);
        assert_eq!(&header.to_bytes()[..], &blob[..HEADER_LEN], "parse and serialise agree byte for byte");
        let loaded = load_vault(&blob, &key).unwrap();
        let pw: String = loaded.query_row("SELECT password FROM servers", [], |r| r.get(0)).unwrap();
        assert_eq!(pw, "pw-on-file");
    }

    #[test]
    fn changing_any_byte_of_the_header_or_body_makes_the_file_unreadable() {
        let key = [0x52u8; 32];
        let blob = seal_with(&mut small_vault_conn(), &key, &test_kdf(4));
        assert!(load_vault(&blob, &key).is_ok(), "control: the untouched file opens");
        let regions = [
            ("magic", 0), ("version", 4), ("kdf id", 5), ("m_cost", 6), ("t_cost", 10),
            ("p_cost", 14), ("salt", 18), ("salt end", 33), ("nonce", 34), ("nonce end", 45),
            ("ciphertext", HEADER_LEN), ("tag", blob.len() - 1),
        ];
        for (name, at) in regions {
            let mut bad = blob.clone();
            // Bit 1, not bit 0: with the floor settings (t=1, p=1) that keeps
            // m/t/p inside the bounds, so only the authenticated header can catch it.
            bad[at] ^= 0x02;
            let err = match load_vault(&bad, &key) {
                Ok(_) => panic!("a modified {name} byte (offset {at}) still opened"),
                Err(e) => e,
            };
            // m/t/p/salt/nonce flips that stay inside the bounds are caught by the
            // authenticated header (AES-GCM associated data), not by any explicit check.
            if ["m_cost", "t_cost", "p_cost", "salt", "salt end", "nonce", "nonce end", "ciphertext", "tag"].contains(&name) {
                assert!(err.contains("DECRYPT_FAILURE"), "{name}: {err}");
            }
        }
        // Truncation anywhere is refused too.
        for len in [0, 3, 4, 5, HEADER_LEN - 1, HEADER_LEN, HEADER_LEN + TAG_LEN - 1, blob.len() - 1] {
            assert!(load_vault(&blob[..len], &key).is_err(), "truncated to {len} bytes still opened");
        }
    }

    #[test]
    fn hostile_kdf_settings_are_refused_before_any_key_derivation() {
        let dir = scratch_dir();
        let cases = [
            ("4 TiB of memory", raw_header(2, 1, u32::MAX, 3, 4)),
            ("1 GiB of memory", raw_header(2, 1, 1024 * 1024, 3, 4)),
            ("below the memory floor", raw_header(2, 1, 8 * 1024, 3, 4)),
            ("a thousand passes", raw_header(2, 1, 64 * 1024, 1000, 4)),
            ("zero passes", raw_header(2, 1, 64 * 1024, 0, 4)),
            ("zero lanes", raw_header(2, 1, 64 * 1024, 3, 0)),
            ("too many lanes", raw_header(2, 1, 64 * 1024, 3, 17)),
            ("an unknown KDF", raw_header(2, 9, 64 * 1024, 3, 4)),
        ];
        for (what, bytes) in cases {
            let err = parse_vault_header(&bytes).map(|_| ()).unwrap_err();
            assert!(err.contains("KDF_PARAMS_UNSUPPORTED"), "{what}: {err}");
            no_decrypt(&err);
            // The real unlock path stops at the same check: with 4 TiB requested,
            // reaching Argon2 would fail differently (or exhaust memory).
            let path = dir.join("hostile.solanum");
            fs::write(&path, &bytes).unwrap();
            let err = open_profile_vault(&path, "irrelevant-password", OpenMode::OpenOnly).map(|_| ()).unwrap_err();
            assert!(err.contains("KDF_PARAMS_UNSUPPORTED"), "{what}: {err}");
            assert_eq!(fs::read(&path).unwrap(), bytes, "{what}: a refused file is never written");
        }
        // derive_key re-checks on its own.
        let hostile = KdfParams { m_cost: u32::MAX, ..test_kdf(1) };
        assert!(derive_key("pw", &hostile).unwrap_err().contains("KDF_PARAMS_UNSUPPORTED"));
        let _ = fs::remove_dir_all(dir);
    }

    /// N-005: a header within the bounds can still ask for more memory than
    /// the process can get (512 MiB on 32-bit Android). That must be a
    /// refusal, not an allocation failure, which aborts the whole app. The
    /// test runs itself again as a child that limits its own address space
    /// to what it already uses plus 256 MiB (util-linux `prlimit`), then
    /// derives with the maximum.
    ///
    /// Ignored in the normal run: while a child process is being started it
    /// holds copies of every open file of the test binary, the profile locks
    /// of tests running beside it included, which then fail with
    /// PROFILE_IN_USE. CI runs it on its own (`-- --ignored --exact`).
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "starts a child process; run alone: cargo test --lib -- --ignored --exact vault_format_tests::argon2_memory_the_process_cannot_get_is_refused_not_an_abort"]
    fn argon2_memory_the_process_cannot_get_is_refused_not_an_abort() {
        const CHILD: &str = "SOLANUM_TEST_ARGON2_CHILD";
        const NAME: &str = "vault_format_tests::argon2_memory_the_process_cannot_get_is_refused_not_an_abort";
        if std::env::var_os(CHILD).is_some() {
            let status = fs::read_to_string("/proc/self/status").unwrap();
            let vm_kib: u64 = status
                .lines()
                .find_map(|l| l.strip_prefix("VmSize:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
                .unwrap();
            let limit = (vm_kib + 256 * 1024) * 1024;
            let ok = std::process::Command::new("prlimit")
                .arg(format!("--pid={}", std::process::id()))
                .arg(format!("--as={limit}"))
                .status()
                .expect("prlimit (util-linux) is needed for this test");
            assert!(ok.success());
            let kdf = KdfParams { m_cost: ARGON2_M_COST_MAX, ..test_kdf(1) };
            let err = derive_key("pw", &kdf).unwrap_err();
            println!("REFUSED: {err}");
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", NAME, "--nocapture", "--test-threads=1"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "child {:?}\n{stdout}\n{stderr}", out.status);
        // libtest prints the child's line after its own "test ... ".
        let err = stdout.lines().find_map(|l| l.split_once("REFUSED: ").map(|(_, e)| e)).unwrap_or_else(|| panic!("{stdout}"));
        assert!(err.contains("KDF_MEMORY_UNAVAILABLE") && err.contains("512 MiB"), "{err}");
        no_decrypt(err);
    }

    #[test]
    fn older_newer_and_foreign_formats_are_refused_untouched_with_their_own_message() {
        let dir = scratch_dir();
        let path = dir.join("old.solanum");
        // A format-1 file: SLNV | 1 | salt | nonce | body.
        let mut v1 = Vec::new();
        v1.extend_from_slice(VAULT_MAGIC);
        v1.push(1);
        v1.extend_from_slice(&[3u8; SALT_LEN + NONCE_LEN + 64]);
        fs::write(&path, &v1).unwrap();
        let err = open_profile_vault(&path, "some-password", OpenMode::OpenOnly).map(|_| ()).unwrap_err();
        assert!(err.contains("FORMAT_BEHIND_BINARY"), "{err}");
        assert!(err.contains("left untouched"), "{err}");
        no_decrypt(&err);
        assert_eq!(fs::read(&path).unwrap(), v1, "the old file must stay byte-for-byte as it was");

        let err = parse_vault_header(&raw_header(3, 1, 64 * 1024, 3, 4)).map(|_| ()).unwrap_err();
        assert!(err.contains("FORMAT_AHEAD_OF_BINARY"), "{err}");
        no_decrypt(&err);
        let err = parse_vault_header(&raw_header(0, 1, 64 * 1024, 3, 4)).map(|_| ()).unwrap_err();
        assert!(err.contains("UNSUPPORTED_PROFILE"), "{err}");
        no_decrypt(&err);
        let err = parse_vault_header(b"OMNV\x01rest-of-an-original-app-file").map(|_| ()).unwrap_err();
        assert!(err.contains("UNSUPPORTED_PROFILE"), "{err}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unlocking_uses_the_settings_stored_in_the_file_and_saving_keeps_them() {
        let dir = scratch_dir();
        let path = dir.join("p.solanum");
        let kdf = KdfParams { m_cost: 24 * 1024, t_cost: 2, p_cost: 2, salt: [0x33u8; SALT_LEN] };
        let key = derive_key("correct horse battery", &kdf).unwrap();
        let vault = OpenVault { key: Zeroizing::new(key), kdf, path: path.clone(), _lock: ProfileLock::acquire(&path).unwrap() };
        save_vault_blocking(&mut small_vault_conn(), &vault).unwrap();
        drop(vault); // "closes" the profile

        let err = open_profile_vault(&path, "wrong horse battery", OpenMode::OpenOnly).map(|_| ()).unwrap_err();
        assert!(err.to_lowercase().contains("decrypt"), "a wrong password must still read as one: {err}");

        let (mut conn, opened) = open_profile_vault(&path, "correct horse battery", OpenMode::OpenOnly).unwrap();
        assert_eq!(opened.kdf, kdf, "parameters come from the header, not from today's defaults");
        conn.execute("INSERT INTO notes(title,body) VALUES ('n','b')", []).unwrap();
        save_vault_blocking(&mut conn, &opened).unwrap();
        assert_eq!(parse_vault_header(&fs::read(&path).unwrap()).unwrap().kdf, kdf, "a re-save keeps the vault's own settings");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_new_profile_gets_todays_settings_and_refuses_to_replace_an_existing_one() {
        let dir = scratch_dir();
        let path = dir.join("new.solanum");
        let err = open_profile_vault(&path, "short", OpenMode::CreateOnly).map(|_| ()).unwrap_err();
        assert!(err.contains("WEAK_MASTER_PASSWORD"), "{err}");
        assert!(!path.exists());

        let (_conn, vault) = open_profile_vault(&path, "a long enough password", OpenMode::CreateOnly).unwrap();
        let kdf = parse_vault_header(&fs::read(&path).unwrap()).unwrap().kdf;
        assert_eq!((kdf.m_cost, kdf.t_cost, kdf.p_cost), (ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST));
        assert_eq!(vault.kdf, kdf);
        drop(vault);

        let before = fs::read(&path).unwrap();
        let err = open_profile_vault(&path, "a long enough password", OpenMode::CreateOnly).map(|_| ()).unwrap_err();
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(open_profile_vault(&path, "a long enough password", OpenMode::OpenOnly).is_ok());
        let _ = fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod profile_lock_tests {
    use super::*;

    const PW: &str = "lock-test password";

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("solanum-lock-test-{:016x}", rand::thread_rng().gen::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn assert_in_use(err: &str) {
        assert!(err.contains("PROFILE_IN_USE"), "{err}");
        assert!(!err.to_lowercase().contains("decrypt"), "the picker would call this a wrong password: {err}");
    }

    #[test]
    fn a_profile_open_in_one_place_cannot_be_opened_in_another_until_it_is_closed() {
        let dir = scratch_dir();
        let path = dir.join("work.solanum");
        let (_conn, first) = open_profile_vault(&path, PW, OpenMode::CreateOnly).unwrap();

        // A second opener (another window: a separate lock handle) is refused,
        // whether it unlocks, creates, or just takes the lock.
        assert_in_use(&open_profile_vault(&path, PW, OpenMode::OpenOnly).map(|_| ()).unwrap_err());
        assert_in_use(&open_profile_vault(&path, PW, OpenMode::CreateOnly).map(|_| ()).unwrap_err());
        assert_in_use(&ProfileLock::acquire(&path).map(|_| ()).unwrap_err());
        // ...even with a wrong password: the lock is checked before anything else.
        assert_in_use(&open_profile_vault(&path, "not the password", OpenMode::OpenOnly).map(|_| ()).unwrap_err());

        // A different profile in the same folder is unaffected.
        let (_c2, other) = open_profile_vault(&dir.join("home.solanum"), PW, OpenMode::CreateOnly).unwrap();
        drop(other);

        drop(first); // close_profile drops the OpenVault, which releases the lock
        assert!(open_profile_vault(&path, PW, OpenMode::OpenOnly).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(sidecar_path(&path, "lock")).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn deleting_or_importing_over_an_open_profile_is_refused() {
        let dir = scratch_dir();
        let path = dir.join("work.solanum");
        let (_conn, open) = open_profile_vault(&path, PW, OpenMode::CreateOnly).unwrap();
        drop(open);
        let (_conn, open) = open_profile_vault(&path, PW, OpenMode::OpenOnly).unwrap(); // writes the .bak
        let bytes = fs::read(&path).unwrap();
        assert!(sidecar_path(&path, "bak").exists());

        assert_in_use(&delete_profile_files(&path).unwrap_err());
        assert!(path.exists(), "a refused delete leaves the profile alone");

        let other = dir.join("copy.solanum");
        let held = ProfileLock::acquire(&other).unwrap();
        assert_in_use(&import_profile_bytes(&other, &bytes, "copy").unwrap_err());
        assert!(!other.exists());
        drop(held);
        import_profile_bytes(&other, &bytes, "copy").unwrap();
        assert_eq!(fs::read(&other).unwrap(), bytes);

        drop(open);
        delete_profile_files(&path).unwrap();
        for leftover in [path.clone(), sidecar_path(&path, "bak"), sidecar_path(&path, "lock")] {
            assert!(!leftover.exists(), "{leftover:?} must be gone after delete");
        }
        // Deleting what is already gone, or in a folder that doesn't exist, is fine.
        delete_profile_files(&path).unwrap();
        delete_profile_files(&dir.join("missing").join("x.solanum")).unwrap();
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_save_never_writes_through_a_file_planted_at_the_old_temp_name() {
        let dir = scratch_dir();
        let victim = dir.join("victim.txt");
        fs::write(&victim, b"precious").unwrap();
        let vault = dir.join("p.solanum");
        std::os::unix::fs::symlink(&victim, dir.join("p.solanum.tmp")).unwrap();
        let mut conn = open_vault_memory_db().unwrap();
        create_vault_schema(&conn).unwrap();
        save_vault_blocking(&mut conn, &test_open_vault(&vault, [1u8; 32])).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        assert!(load_vault(&fs::read(&vault).unwrap(), &[1u8; 32]).is_ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_writers_never_leave_a_mixed_or_partial_vault() {
        let dir = scratch_dir();
        let path = dir.join("p.solanum");
        let key = [0x77u8; 32];
        // Eight distinct, complete vault files, each written 15 times by its own
        // thread, all racing on the same path (what two processes without the
        // lock used to do, sharing one temp file).
        let blobs: Vec<Vec<u8>> = (0..8)
            .map(|i| {
                let mut conn = open_vault_memory_db().unwrap();
                create_vault_schema(&conn).unwrap();
                conn.execute("INSERT INTO notes(title,body) VALUES (?1, ?2)", rusqlite::params![format!("writer {i}"), "x".repeat(20_000 + i * 997)]).unwrap();
                let bytes = conn.serialize(MAIN_DB).unwrap().to_vec();
                seal_vault_blob(&vault_compress(&bytes).unwrap(), &key, &test_kdf(1)).unwrap()
            })
            .collect();
        std::thread::scope(|scope| {
            for blob in &blobs {
                let path = &path;
                scope.spawn(move || {
                    for _ in 0..15 {
                        let res = write_file_atomically(path, blob);
                        // Windows may refuse a rename onto a file another thread is
                        // replacing at that instant (production saves never race:
                        // they are serialised in-process and by the profile lock).
                        // The failed write must still clean up after itself, which
                        // the leftover check below verifies.
                        #[cfg(not(windows))]
                        res.unwrap();
                        #[cfg(windows)]
                        let _ = res;
                    }
                });
            }
        });
        let final_bytes = fs::read(&path).unwrap();
        assert!(blobs.contains(&final_bytes), "the vault is exactly one writer's complete file");
        assert!(load_vault(&final_bytes, &key).is_ok());
        let leftovers: Vec<_> = fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).filter(|n| n != "p.solanum").collect();
        assert!(leftovers.is_empty(), "no temp files left behind: {leftovers:?}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn opening_sweeps_crashed_temp_files_and_keeps_a_backup_from_the_start_of_the_session() {
        let dir = scratch_dir();
        let path = dir.join("p.solanum");
        let (mut conn, vault) = open_profile_vault(&path, PW, OpenMode::CreateOnly).unwrap();
        conn.execute("INSERT INTO notes(title,body) VALUES ('before','session 1')", []).unwrap();
        save_vault_blocking(&mut conn, &vault).unwrap();
        drop((conn, vault));
        let at_unlock = fs::read(&path).unwrap();

        let planted = ["p.solanum.tmp", "p.solanum.0123456789abcdef.tmp", "p.solanum.bak.fedcba9876543210.tmp"];
        for name in planted {
            fs::write(dir.join(name), b"half-written").unwrap();
        }
        fs::write(dir.join("other.solanum.tmp"), b"another profile's").unwrap();

        let (mut conn, vault) = open_profile_vault(&path, PW, OpenMode::OpenOnly).unwrap();
        for name in planted {
            assert!(!dir.join(name).exists(), "{name} should have been swept");
        }
        assert!(dir.join("other.solanum.tmp").exists(), "another profile's files are not touched");

        let bak = sidecar_path(&path, "bak");
        assert_eq!(fs::read(&bak).unwrap(), at_unlock, "the backup is the file as it was at unlock");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&bak).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // Saves during the session leave the backup alone (rotation is per unlock).
        conn.execute("DELETE FROM notes", []).unwrap();
        save_vault_blocking(&mut conn, &vault).unwrap();
        save_vault_blocking(&mut conn, &vault).unwrap();
        assert_eq!(fs::read(&bak).unwrap(), at_unlock);
        assert_ne!(fs::read(&path).unwrap(), at_unlock);
        drop((conn, vault));

        // Recovering is a rename: the backup opens with the same password and
        // still holds what the session deleted.
        let restored = dir.join("restored.solanum");
        fs::copy(&bak, &restored).unwrap();
        let (conn, _vault) = open_profile_vault(&restored, PW, OpenMode::OpenOnly).unwrap();
        let body: String = conn.query_row("SELECT body FROM notes WHERE title='before'", [], |r| r.get(0)).unwrap();
        assert_eq!(body, "session 1");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unlocking_never_creates_a_missing_profile_and_oversized_files_are_not_read() {
        let dir = scratch_dir();
        let path = dir.join("gone.solanum");
        let err = open_profile_vault(&path, PW, OpenMode::OpenOnly).map(|_| ()).unwrap_err();
        assert!(err.contains("PROFILE_MISSING"), "{err}");
        assert!(!path.exists(), "unlocking must not create a profile");

        let big = dir.join("big.solanum");
        let f = fs::File::create(&big).unwrap();
        f.set_len(MAX_VAULT_FILE_BYTES + 1).unwrap(); // sparse: no real disk use
        drop(f);
        for err in [
            open_profile_vault(&big, PW, OpenMode::OpenOnly).map(|_| ()).unwrap_err(),
            read_vault_file(&big).map(|_| ()).unwrap_err(),
        ] {
            assert!(err.contains("FILE_TOO_LARGE"), "{err}");
            assert!(!err.to_lowercase().contains("decrypt"), "{err}");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reopening_the_profile_this_process_has_open_works_and_a_second_process_is_refused() {
        let dir = scratch_dir();
        let path = dir.join("p.solanum");
        let window = DbState::default();
        open_profile_into_state(&window, path.clone(), PW.into(), OpenMode::CreateOnly).await.unwrap();
        *window.conn.lock().unwrap() = None;
        *window.vault.lock().unwrap() = None;
        open_profile_into_state(&window, path.clone(), PW.into(), OpenMode::OpenOnly).await.unwrap();
        let bak = fs::read(sidecar_path(&path, "bak")).unwrap();
        window.conn.lock().unwrap().as_ref().unwrap()
            .execute("INSERT INTO notes(title,body) VALUES ('unsaved','kept')", []).unwrap();

        // The webview reloads and the user unlocks the same profile again: with a
        // wrong password nothing changes, with the right one the open state is kept
        // as it is (unsaved rows, session-start backup).
        let err = open_profile_into_state(&window, path.clone(), "wrong password!".into(), OpenMode::OpenOnly).await.unwrap_err();
        assert!(err.to_lowercase().contains("decrypt"), "the picker must show 'Wrong password.': {err}");
        assert!(window.vault.lock().unwrap().is_some(), "a wrong password does not close the open profile");
        open_profile_into_state(&window, path.clone(), PW.into(), OpenMode::OpenOnly).await.unwrap();
        let kept: i64 = window.conn.lock().unwrap().as_ref().unwrap()
            .query_row("SELECT COUNT(*) FROM notes WHERE title='unsaved'", [], |r| r.get(0)).unwrap();
        assert_eq!(kept, 1, "the open database is kept, unsaved rows included");
        assert_eq!(fs::read(sidecar_path(&path, "bak")).unwrap(), bak, "the session-start backup is not replaced");

        let other_process = DbState::default();
        let err = open_profile_into_state(&other_process, path.clone(), PW.into(), OpenMode::OpenOnly).await.unwrap_err();
        assert_in_use(&err);
        assert!(other_process.conn.lock().unwrap().is_none());

        *window.conn.lock().unwrap() = None;
        *window.vault.lock().unwrap() = None; // what close_profile does
        open_profile_into_state(&other_process, path, PW.into(), OpenMode::OpenOnly).await.unwrap();
        let _ = fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod vault_integrity_tests {
    use super::*;

    fn vault() -> Connection {
        let conn = open_vault_memory_db().unwrap();
        create_vault_schema(&conn).unwrap();
        conn.execute_batch(
            "INSERT INTO ssh_keys(id,name,private_key) VALUES (1,'deploy','KEY-1'), (2,'spare','KEY-2');
             INSERT INTO credentials(id,name,auth_type,username,key_id) VALUES (1,'ops','key','ops',1);
             INSERT INTO credentials(id,name,auth_type,username,password) VALUES (2,'root','password','root','pw');
             INSERT INTO folders(id,name) VALUES (1,'prod');
             INSERT INTO folders(id,name,parent_id) VALUES (2,'prod/db',1), (3,'prod/db/replicas',2);
             INSERT INTO folders(id,name) VALUES (4,'lab');
             INSERT INTO servers(id,name,host,port,auth_type,key_id,folder_id) VALUES (1,'bastion','192.0.2.1',22,'custom_key',1,1);
             INSERT INTO servers(id,name,host,port,auth_type,credential_id,folder_id,jump_host_id) VALUES (2,'db1','192.0.2.2',22,'vault',1,2,1);
             INSERT INTO servers(id,name,host,port,auth_type,credential_id,folder_id,jump_host_id) VALUES (3,'replica','192.0.2.3',22,'vault',2,3,1);
             INSERT INTO servers(id,name,host,port,auth_type,credential_id,folder_id) VALUES (4,'lab-box','192.0.2.4',22,'vault',2,4);
             INSERT INTO monitor_configs(node_id) VALUES (2), (3);",
        )
        .unwrap();
        conn
    }

    fn one<T: rusqlite::types::FromSql>(conn: &Connection, sql: &str) -> T {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn foreign_keys_on(conn: &Connection) -> bool {
        one::<i64>(conn, "PRAGMA foreign_keys") == 1
    }

    #[test]
    fn foreign_keys_are_enforced_on_fresh_and_loaded_vaults() {
        assert!(foreign_keys_on(&open_vault_memory_db().unwrap()));
        let key = [0x61u8; 32];
        let bytes = vault().serialize(MAIN_DB).unwrap().to_vec();
        let blob = seal_vault_blob(&vault_compress(&bytes).unwrap(), &key, &test_kdf(6)).unwrap();
        let loaded = load_vault(&blob, &key).unwrap();
        assert!(foreign_keys_on(&loaded), "the pragma must survive deserialize");
        let err = loaded.execute("UPDATE servers SET key_id = 99 WHERE id = 1", []).unwrap_err();
        assert!(err.to_string().contains("FOREIGN KEY"), "{err}");
    }

    #[test]
    fn deleting_a_key_or_login_unlinks_it_and_keeps_the_mode_that_needed_it() {
        let conn = vault();
        conn.execute("DELETE FROM ssh_keys WHERE id = 1", []).unwrap();
        assert_eq!(one::<Option<i64>>(&conn, "SELECT key_id FROM servers WHERE id = 1"), None);
        assert_eq!(one::<String>(&conn, "SELECT auth_type FROM servers WHERE id = 1"), "custom_key");
        assert_eq!(one::<Option<i64>>(&conn, "SELECT key_id FROM credentials WHERE id = 1"), None, "no raw constraint error any more");
        assert_eq!(one::<String>(&conn, "SELECT auth_type FROM credentials WHERE id = 1"), "key");

        conn.execute("DELETE FROM credentials WHERE id = 2", []).unwrap();
        assert_eq!(one::<Option<i64>>(&conn, "SELECT credential_id FROM servers WHERE id = 3"), None);
        assert_eq!(one::<String>(&conn, "SELECT auth_type FROM servers WHERE id = 3"), "vault");
        assert_eq!(one::<i64>(&conn, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    }

    #[test]
    fn deleting_a_folder_takes_its_whole_subtree() {
        let conn = vault();
        // Not the bastion's folder: "lab" holds one server nobody jumps through.
        let doomed = servers_in_folder_tree(&conn, 4).unwrap();
        assert_eq!(doomed, vec![4]);
        refuse_if_jump_host_in_use(&conn, &doomed).unwrap();

        // "prod" holds the bastion AND both servers behind it, three levels deep.
        let mut doomed = servers_in_folder_tree(&conn, 1).unwrap();
        doomed.sort();
        assert_eq!(doomed, vec![1, 2, 3]);
        refuse_if_jump_host_in_use(&conn, &doomed).unwrap();
        conn.execute("DELETE FROM folders WHERE id = 1", []).unwrap();
        assert_eq!(one::<i64>(&conn, "SELECT COUNT(*) FROM folders"), 1, "sub-folders went too");
        assert_eq!(one::<i64>(&conn, "SELECT COUNT(*) FROM servers"), 1);
        assert_eq!(one::<i64>(&conn, "SELECT COUNT(*) FROM monitor_configs"), 0);
        assert_eq!(one::<i64>(&conn, "SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    }

    #[test]
    fn a_jump_host_in_use_cannot_be_deleted_alone_or_with_its_folder() {
        let conn = vault();
        let err = refuse_if_jump_host_in_use(&conn, &[1]).unwrap_err();
        assert!(err.contains("JUMP_HOST_IN_USE") && err.contains("\"db1\" (via \"bastion\")") && err.contains("\"replica\""), "{err}");
        // The schema refuses too, so no path can leave a dangling jump host.
        assert!(conn.execute("DELETE FROM servers WHERE id = 1", []).is_err());

        // Move "replica" out of "prod": deleting "prod" would now strand it.
        conn.execute("UPDATE servers SET folder_id = 4 WHERE id = 3", []).unwrap();
        let doomed = servers_in_folder_tree(&conn, 1).unwrap();
        let err = refuse_if_jump_host_in_use(&conn, &doomed).unwrap_err();
        assert!(err.contains("replica") && !err.contains("db1"), "only servers outside the folder count: {err}");
        assert!(conn.execute("DELETE FROM folders WHERE id = 1", []).is_err());
        assert_eq!(one::<i64>(&conn, "SELECT COUNT(*) FROM servers"), 4, "a refused delete removes nothing");

        // Once nobody uses it, it goes.
        conn.execute("UPDATE servers SET jump_host_id = NULL", []).unwrap();
        refuse_if_jump_host_in_use(&conn, &[1]).unwrap();
        conn.execute("DELETE FROM servers WHERE id = 1", []).unwrap();
        // A server set as its own jump host can still be deleted.
        conn.execute("UPDATE servers SET jump_host_id = 4 WHERE id = 4", []).unwrap();
        refuse_if_jump_host_in_use(&conn, &[4]).unwrap();
        conn.execute("DELETE FROM servers WHERE id = 4", []).unwrap();
    }

    #[test]
    fn a_folder_cycle_does_not_hang_the_subtree_query() {
        let conn = vault();
        conn.execute_batch("PRAGMA foreign_keys = OFF; UPDATE folders SET parent_id = 3 WHERE id = 1; PRAGMA foreign_keys = ON;").unwrap();
        let mut doomed = servers_in_folder_tree(&conn, 2).unwrap();
        doomed.sort();
        assert_eq!(doomed, vec![1, 2, 3]);
    }

    #[test]
    fn a_vault_with_dangling_references_is_refused_untouched() {
        let mut conn = vault();
        conn.execute_batch("PRAGMA foreign_keys = OFF; DELETE FROM ssh_keys WHERE id = 1; PRAGMA foreign_keys = ON;").unwrap();
        let key = [0x62u8; 32];
        let bytes = conn.serialize(MAIN_DB).unwrap().to_vec();
        let blob = seal_vault_blob(&vault_compress(&bytes).unwrap(), &key, &test_kdf(7)).unwrap();
        let err = load_vault(&blob, &key).map(|_| ()).unwrap_err();
        assert!(err.contains("INTEGRITY_FAILED"), "{err}");
        assert!(!err.to_lowercase().contains("decrypt"), "{err}");
    }

    #[test]
    fn connecting_after_a_key_or_login_was_deleted_says_so() {
        use super::missing_identity_reason as why;
        assert_eq!(why("vault", true, Some("password"), false), None);
        assert_eq!(why("vault", true, Some("key"), true), None);
        assert_eq!(why("custom_key", false, None, true), None);
        assert_eq!(why("custom_pass", false, None, false), None);
        assert!(why("vault", false, None, false).unwrap().contains("saved login"));
        assert!(why("vault", true, Some("key"), false).unwrap().contains("no SSH key"));
        assert!(why("custom_key", false, None, false).unwrap().contains("SSH key"));

        // Through the real ProxyJump resolver.
        let conn = vault();
        assert!(resolve_jump_auth(&conn, 1).unwrap().is_some(), "control: the bastion resolves");
        conn.execute("DELETE FROM ssh_keys WHERE id = 1", []).unwrap();
        let err = resolve_jump_auth(&conn, 1).err().expect("refused");
        assert!(err.starts_with("Jump host: ") && err.contains("SSH key"), "{err}");
        let err = resolve_jump_auth(&conn, 2).err().expect("refused");
        assert!(err.contains("saved login this server uses has no SSH key"), "{err}");
        conn.execute("DELETE FROM credentials WHERE id = 2", []).unwrap();
        let err = resolve_jump_auth(&conn, 4).err().expect("refused");
        assert!(err.contains("uses a saved login, but none is set"), "{err}");
    }

    /// F-062, N-003: a monitor reads its node's login and its jump host's,
    /// and refuses, with the connect path's message, a login or key that was
    /// deleted, on the node or on its jump host.
    #[test]
    fn the_monitor_resolver_includes_the_jump_host_and_refuses_deleted_logins() {
        let conn = vault();
        let db1 = resolve_node_auth_for_monitor(&conn, 2).unwrap();
        assert_eq!((db1.host.as_str(), db1.username.as_str(), db1.private_key.as_deref()), ("192.0.2.2", "ops", Some("KEY-1")));
        let hop = db1.jump.expect("through the bastion");
        assert_eq!((hop.host.as_str(), hop.private_key.as_deref(), hop.username.as_str()), ("192.0.2.1", Some("KEY-1"), "root"));
        assert!(hop.jump.is_none(), "single hop");
        assert!(resolve_node_auth_for_monitor(&conn, 4).unwrap().jump.is_none());

        conn.execute("UPDATE servers SET key_id = NULL WHERE id = 1", []).unwrap();
        let err = resolve_node_auth_for_monitor(&conn, 3).expect_err("the jump host has no key any more");
        assert!(err.starts_with("Jump host: ") && err.contains("SSH key"), "{err}");
        let err = resolve_node_auth_for_monitor(&conn, 1).expect_err("the node itself has no key any more");
        assert!(err.contains("SSH key"), "{err}");
        conn.execute("UPDATE servers SET credential_id = NULL WHERE id = 4", []).unwrap();
        let err = resolve_node_auth_for_monitor(&conn, 4).expect_err("no saved login");
        assert!(err.contains("uses a saved login, but none is set"), "{err}");
    }
}

#[cfg(test)]
mod profile_input_tests {
    use super::*;

    #[test]
    fn profile_names_are_taken_exactly_as_given() {
        for ok in ["work", "work-1_A", "a", &"x".repeat(32)] {
            assert!(validate_profile_name(ok).is_ok(), "{ok:?} should be accepted");
        }
        for bad in [
            "", " work", "work ", "work\n", "\twork", "wo rk", "work\u{a0}", "\u{2003}work",
            "../work", "work.solanum", "wörk", "CON", "nul", "COM1", "lpt9", &"x".repeat(33),
        ] {
            assert!(validate_profile_name(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn the_password_floor_counts_characters_not_bytes_or_utf16_units() {
        // 4 characters, but 8 UTF-16 units and 16 bytes: the old picker check let it through.
        assert!(check_new_master_password("🔑🔑🔑🔑").is_err());
        assert!(check_new_master_password("seven77").is_err());
        assert!(check_new_master_password("").is_err());
        // 8 characters in scripts that take 2 or 3 bytes each.
        assert!(check_new_master_password("пароль12").is_ok());
        assert!(check_new_master_password("暗号のパスワード").is_ok());
        assert!(check_new_master_password("🔑🔑🔑🔑🔑🔑🔑🔑").is_ok());
        assert!(check_new_master_password("eight888").is_ok());
    }
}

#[cfg(test)]
mod vault_state_tests {
    use super::*;

    #[test]
    fn closing_recovers_from_a_poisoned_vault_mutex_and_releases_the_lock() {
        let dir = std::env::temp_dir().join(format!("solanum-state-test-{:016x}", rand::thread_rng().gen::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.solanum");
        let state = DbState::default();
        let (conn, vault) = open_profile_vault(&path, "state-test password", OpenMode::CreateOnly).unwrap();
        *state.conn.lock().unwrap() = Some(conn);
        *state.vault.lock().unwrap() = Some(vault);
        *state.active_profile.lock().unwrap() = Some("p".into());

        // A command panics while holding the connection.
        std::thread::scope(|s| {
            let _ = s.spawn(|| {
                let _guard = state.conn.lock().unwrap();
                panic!("simulated panic inside a vault command");
            }).join();
        });
        assert!(state.conn.is_poisoned());
        assert!(save_locked_vault(&state.conn, &state.vault).is_err(), "poisoned: commands fail");

        clear_profile_state(&state);
        assert!(!state.conn.is_poisoned());
        assert!(state.conn.lock().unwrap().is_none());
        assert!(state.vault.lock().unwrap().is_none());
        assert!(state.active_profile.lock().unwrap().is_none());
        // The profile lock went with the vault state: the profile opens again.
        assert!(open_profile_vault(&path, "state-test password", OpenMode::OpenOnly).is_ok());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn saving_from_a_command_body_works_on_the_multi_thread_runtime() {
        let dir = std::env::temp_dir().join(format!("solanum-state-test-{:016x}", rand::thread_rng().gen::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.solanum");
        let state = DbState::default();
        open_profile_into_state(&state, path.clone(), "state-test password".into(), OpenMode::CreateOnly).await.unwrap();
        {
            let guard = state.conn.lock().unwrap();
            guard.as_ref().unwrap().execute("INSERT INTO notes(title,body) VALUES ('t','saved by a command')", []).unwrap();
        }
        save_vault_internal(&state).unwrap();
        save_vault_async(&state).await.unwrap();
        clear_profile_state(&state);
        let (conn, _vault) = open_profile_vault(&path, "state-test password", OpenMode::OpenOnly).unwrap();
        let body: String = conn.query_row("SELECT body FROM notes", [], |r| r.get(0)).unwrap();
        assert_eq!(body, "saved by a command");
        let _ = fs::remove_dir_all(dir);
    }
}

/// F-013: locking the profile (and reloading or quitting, which do the same)
/// leaves nothing of it running.
#[cfg(test)]
mod teardown_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    const PW: &str = "teardown-test password";

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("solanum-teardown-test-{:016x}", rand::thread_rng().gen::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mirror_status(id: &str, session: &str) -> mirror::MirrorStatus {
        mirror::MirrorStatus {
            id: id.into(),
            session_id: session.into(),
            local: "/l".into(),
            remote: "/r".into(),
            state: "watching".into(),
            queue_depth: 0,
            uploaded: 0,
            downloaded: 0,
            deleted: 0,
            scanned: 0,
            transfer_total: 0,
            transfer_done: 0,
            last_event_ms: 0,
            error: None,
            held_deletes: 0,
            pause_reason: None,
        }
    }

    /// A mirror whose worker ends when told to, and says so.
    async fn add_mirror(mirrors: &MirrorMap, id: &str, session: &str) -> Arc<AtomicBool> {
        let stopped = Arc::new(AtomicBool::new(false));
        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let flag = Arc::clone(&stopped);
        let join = tauri::async_runtime::spawn(async move {
            let _ = stop_rx.wait_for(|asked| *asked).await;
            flag.store(true, Ordering::SeqCst);
        });
        mirrors.lock().await.insert(
            id.into(),
            mirror::ActiveMirror {
                status: Arc::new(tokio::sync::Mutex::new(mirror_status(id, session))),
                stop: stop_tx,
                join: tokio::sync::Mutex::new(Some(join)),
                events: mirror::MirrorEvents::quiet(),
                resume: tokio::sync::mpsc::unbounded_channel().0,
            },
        );
        stopped
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn locking_stops_everything_the_profile_has_running() {
        let dir = scratch_dir();
        let path = dir.join("p.solanum");
        let db = DbState::default();
        open_profile_into_state(&db, path.clone(), PW.into(), OpenMode::CreateOnly).await.unwrap();
        let ssh = SshState::new();
        let monitors: MonitorMap = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        let mirrors: MirrorMap = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        let settings: SharedSettings = Arc::new(tokio::sync::Mutex::new(monitor::MonitorSettings {
            interval_secs: 99,
            ..monitor::MonitorSettings::default()
        }));

        let (monitor_stop, mut monitor_stopped) = tokio::sync::oneshot::channel::<()>();
        monitors.lock().await.insert(
            7,
            Arc::new(monitor::MonitorEntry {
                node_id: 7,
                enabled_metrics: Arc::new(tokio::sync::Mutex::new(Vec::new())),
                custom_metrics: Arc::new(tokio::sync::Mutex::new(Vec::new())),
                paused: tokio::sync::watch::channel(false).0,
                state: Arc::new(tokio::sync::Mutex::new(monitor::MonitorState::default())),
                stop_tx: tokio::sync::Mutex::new(Some(monitor_stop)),
            }),
        );
        let mirror_stopped = add_mirror(&mirrors, "m1", "session-1").await;
        // A connect still handshaking for session-1 (it registers only if the
        // generation is still 1 when it is done), a transfer, a terminal and a
        // host-key prompt waiting for the user.
        ssh.session_generation.lock().await.insert("session-1".into(), 1);
        let cancelled = Arc::new(AtomicBool::new(false));
        ssh.transfer_cancels.lock().await.insert("transfer-1".into(), Arc::clone(&cancelled));
        let (terminal, mut terminal_input) = tokio::sync::mpsc::channel(1);
        ssh.terminal_txs.lock().await.insert("session-1-term-1".into(), terminal);
        let (prompt, prompt_answer) = tokio::sync::oneshot::channel();
        ssh.fp_txs.lock().await.insert("nonce".into(), prompt);
        // A Docker live log on a quiet container (F-041).
        let (server, seen) = ssh_test_server::logged_in(ssh_test_server::Script::default()).await;
        let log_channel = ssh_connect::open_session_channel(&server).await.unwrap();
        log_channel.exec(true, &b"docker logs -f web"[..]).await.unwrap();
        let log_closed = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&log_closed);
        let sink = docker::LogSink { text: Box::new(|_| {}), closed: Box::new(move || flag.store(true, Ordering::SeqCst)) };
        ssh.docker_streams.start("logs-1".into(), "session-1".into(), log_channel, sink).await;
        ssh.channel_gates.lock().unwrap().insert("session-1".into(), Arc::new(ssh_connect::ChannelGate::new(true)));
        let before = ssh.epoch();
        assert!(before.current() && !before.closing());

        let finishing = teardown_profile(&db, &ssh, &monitors, &mirrors, &settings, live_edit::StopReason::ProfileClosed).await;
        assert!(finishing.is_empty(), "no live edits were open");
        assert!(
            ssh.channel_gate("session-1").limit().is_none(),
            "session ids restart in the next vault, and so does what their servers allow"
        );

        assert_eq!(*settings.lock().await, monitor::MonitorSettings::default(), "the next profile starts from its own settings");
        assert!(monitor_stopped.try_recv().is_ok(), "the poller is told to stop");
        assert!(monitors.lock().await.is_empty());
        assert!(mirror_stopped.load(Ordering::SeqCst), "the mirror is stopped");
        assert!(mirrors.lock().await.is_empty());
        assert_eq!(
            ssh.session_generation.lock().await.get("session-1"),
            Some(&2),
            "a connect still running sees a newer generation and drops itself"
        );
        assert!(cancelled.load(Ordering::SeqCst), "transfers are cancelled");
        assert!(log_closed.load(Ordering::SeqCst), "Docker live logs are stopped");
        assert!(
            ssh_test_server::eventually(|| seen.lock().unwrap().signals == ["TERM"]).await,
            "the server is asked to end `docker logs -f`"
        );
        assert!(terminal_input.recv().await.is_none(), "terminals end");
        assert_eq!(prompt_answer.await, Ok(false), "a waiting host-key prompt is refused");
        assert!(ssh.transfer_cancels.lock().await.is_empty());
        assert!(ssh.terminal_txs.lock().await.is_empty());
        assert!(ssh.connections.lock().await.is_empty());
        assert!(ssh.fp_txs.lock().await.is_empty());
        assert!(db.conn.lock().unwrap().is_none(), "the vault is closed");
        assert!(ProfileLock::acquire(&path).is_ok(), "the profile lock is released");
        assert!(!before.current(), "a connect or shell begun before the lock does not register after it");
        assert!(!ssh.epoch().closing(), "once the lock is done, new work may start (it needs a profile)");
        let _ = fs::remove_dir_all(dir);
    }

    /// While a teardown runs, nothing new may start; whatever began during it
    /// is out of date once it ends.
    #[test]
    fn the_profile_epoch_marks_a_teardown_in_progress() {
        let ssh = SshState::new();
        let idle = ssh.epoch();
        ssh.next_epoch();
        let during = ssh.epoch();
        assert!(during.closing() && !idle.current());
        ssh.next_epoch();
        assert!(!during.current() && !ssh.epoch().closing());
    }

    /// N-020: a mirror that registered after a disconnect or a lock swept the
    /// session's mirrors is stopped again; one that did not is kept.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_mirror_started_too_late_is_stopped_again() {
        let ssh = SshState::new();
        let mirrors: MirrorMap = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        ssh.session_generation.lock().await.insert("s1".into(), 4);

        let kept = add_mirror(&mirrors, "kept", "s1").await;
        let epoch = ssh.epoch();
        assert!(!stop_mirror_started_too_late(&ssh.session_generation, &mirrors, "s1", 4, &epoch, "kept").await);
        assert!(!kept.load(Ordering::SeqCst) && mirrors.lock().await.contains_key("kept"));

        // A disconnect bumped the generation meanwhile.
        let late = add_mirror(&mirrors, "late", "s1").await;
        ssh.session_generation.lock().await.insert("s1".into(), 5);
        assert!(stop_mirror_started_too_late(&ssh.session_generation, &mirrors, "s1", 4, &epoch, "late").await);
        assert!(late.load(Ordering::SeqCst) && !mirrors.lock().await.contains_key("late"));

        // A lock began meanwhile.
        let locked = add_mirror(&mirrors, "locked", "s1").await;
        ssh.next_epoch();
        assert!(stop_mirror_started_too_late(&ssh.session_generation, &mirrors, "s1", 5, &epoch, "locked").await);
        assert!(locked.load(Ordering::SeqCst) && !mirrors.lock().await.contains_key("locked"));
    }

    /// A mirror whose worker ignores the stop is aborted after the bound.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_mirror_that_does_not_stop_is_aborted() {
        struct SetOnDrop(Arc<AtomicBool>);
        impl Drop for SetOnDrop {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let mirrors: MirrorMap = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        let dropped = Arc::new(AtomicBool::new(false));
        let guard = SetOnDrop(Arc::clone(&dropped));
        let (stop_tx, _ignored) = tokio::sync::watch::channel(false);
        let join = tauri::async_runtime::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        mirrors.lock().await.insert(
            "stuck".into(),
            mirror::ActiveMirror {
                status: Arc::new(tokio::sync::Mutex::new(mirror_status("stuck", "session-1"))),
                stop: stop_tx,
                join: tokio::sync::Mutex::new(Some(join)),
                events: mirror::MirrorEvents::quiet(),
                resume: tokio::sync::mpsc::unbounded_channel().0,
            },
        );
        let started = std::time::Instant::now();
        mirror::stop_all_within(&mirrors, std::time::Duration::from_millis(200)).await;
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(mirrors.lock().await.is_empty());
        for _ in 0..50 {
            if dropped.load(Ordering::SeqCst) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(dropped.load(Ordering::SeqCst), "the stuck worker was aborted");
    }

    /// F-080: an opened profile gets its own saved monitor settings, or the
    /// defaults, never the previous profile's.
    #[tokio::test]
    async fn each_profile_gets_its_own_monitor_settings() {
        let settings: SharedSettings = Arc::new(tokio::sync::Mutex::new(monitor::MonitorSettings::default()));
        let db = DbState::default();
        let first = open_vault_memory_db().unwrap();
        create_vault_schema(&first).unwrap();
        let saved = monitor::MonitorSettings { interval_secs: 42, outage_threshold: 9, ..monitor::MonitorSettings::default() }.sanitized();
        first
            .execute("INSERT INTO monitor_settings (id, json) VALUES (1, ?1)", [serde_json::to_string(&saved).unwrap()])
            .unwrap();
        *db.conn.lock().unwrap() = Some(first);
        load_monitor_settings(&db, &settings).await;
        assert_eq!(*settings.lock().await, saved);

        let second = open_vault_memory_db().unwrap();
        create_vault_schema(&second).unwrap();
        *db.conn.lock().unwrap() = Some(second);
        load_monitor_settings(&db, &settings).await;
        assert_eq!(*settings.lock().await, monitor::MonitorSettings::default());
    }
}

/// What the import picker does with a file before the user names the profile.
/// On Android the file name comes from a document provider, so it is untrusted.
#[cfg(test)]
mod import_pick_tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../testdata/vault-v2-schema6.solanum");

    fn with_file<T>(bytes: &[u8], body: impl FnOnce(&std::path::Path) -> T) -> T {
        let dir = std::env::temp_dir().join(format!("solanum-import-pick-{:016x}", rand::thread_rng().gen::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("picked.solanum");
        fs::write(&path, bytes).unwrap();
        let out = body(&path);
        let _ = fs::remove_dir_all(&dir);
        out
    }

    /// R-012: only the file the picker returned is imported, whatever path
    /// the window sends.
    #[test]
    fn only_the_picked_file_is_imported() {
        let picked = StdMutex::new(None);
        assert!(picked_import_source(&picked, "/home/u/a.solanum").is_err(), "nothing was picked");
        *picked.lock().unwrap() = Some(PathBuf::from("/home/u/a.solanum"));
        assert!(picked_import_source(&picked, "/home/u/.ssh/other.solanum").is_err());
        assert_eq!(picked_import_source(&picked, "/home/u/a.solanum").unwrap(), PathBuf::from("/home/u/a.solanum"));
    }

    /// R-012: the path an import reads comes from the window, so it is
    /// checked like any other, and only a regular file is read: a FIFO would
    /// hold the command until something writes to it, a device would be read
    /// up to the cap.
    #[cfg(unix)]
    #[test]
    fn an_import_reads_only_a_regular_file() {
        with_file(FIXTURE, |picked| {
            assert_eq!(read_import_source(picked).unwrap(), FIXTURE);
            assert!(read_import_source(std::path::Path::new("picked.solanum")).is_err(), "a relative path");
            let dir = picked.parent().unwrap();
            assert!(read_import_source(dir).is_err(), "a folder");
            let fifo = dir.join("fifo");
            if std::process::Command::new("mkfifo").arg(&fifo).status().map(|s| s.success()).unwrap_or(false) {
                let (tx, rx) = std::sync::mpsc::channel();
                let path = fifo.clone();
                std::thread::spawn(move || {
                    let _ = tx.send(read_import_source(&path));
                });
                let answer = rx.recv_timeout(std::time::Duration::from_secs(2));
                if answer.is_err() {
                    // Lets the reader that is still waiting go.
                    let _ = fs::OpenOptions::new().write(true).open(&fifo);
                }
                assert!(matches!(answer, Ok(Err(_))), "a FIFO held the import: {answer:?}");
            }
        });
    }

    #[test]
    fn the_suggested_name_is_the_file_name_without_its_extension() {
        assert_eq!(suggested_profile_name(Some("laptop.solanum")), "laptop");
        assert_eq!(suggested_profile_name(Some("prod-2_b.solanum")), "prod-2_b");
        assert_eq!(suggested_profile_name(Some("no-extension")), "no-extension");
    }

    #[test]
    fn characters_a_profile_name_cannot_hold_become_underscores() {
        assert_eq!(suggested_profile_name(Some("my work (2).solanum")), "my_work__2_");
        assert_eq!(suggested_profile_name(Some("caf\u{e9}.solanum")), "caf_");
    }

    #[test]
    fn the_suggestion_is_always_a_name_the_profile_rules_accept() {
        let long = "a".repeat(200);
        for name in [
            "../../evil.solanum", "..\\..\\evil.solanum", "/etc/passwd", "CON.solanum", "NUL", "LPT1.solanum",
            "", ".", "..", ".solanum", "...", "\u{202e}gpj.solanum", "a\0b.solanum", long.as_str(),
        ] {
            let suggested = suggested_profile_name(Some(name));
            assert!(validate_profile_name(&suggested).is_ok(), "{name:?} gave {suggested:?}");
        }
    }

    #[test]
    fn a_name_with_nothing_usable_in_it_falls_back() {
        assert_eq!(suggested_profile_name(None), "imported");
        assert_eq!(suggested_profile_name(Some("")), "imported");
        assert_eq!(suggested_profile_name(Some("\u{65e5}\u{672c}\u{8a9e}.solanum")), "imported");
        assert_eq!(suggested_profile_name(Some("CON.solanum")), "imported");
    }

    #[test]
    fn a_vault_this_build_can_open_passes_the_header_check() {
        with_file(FIXTURE, |path| check_import_header(path).unwrap());
    }

    #[test]
    fn anything_else_is_refused_before_the_user_names_it() {
        let mut older = FIXTURE.to_vec();
        older[4] = 1;
        let mut newer = FIXTURE.to_vec();
        newer[4] = VAULT_VERSION + 1;
        for bytes in [&b"this is not a solanum profile"[..], &b""[..], &b"SLN"[..], &older[..], &newer[..]] {
            let err = with_file(bytes, |path| check_import_header(path).unwrap_err());
            assert!(!err.to_lowercase().contains("decrypt"), "the picker would say wrong password: {err}");
        }
    }

    #[test]
    fn a_missing_file_is_an_error_not_a_panic() {
        let err = check_import_header(std::path::Path::new("/nonexistent/solanum/picked.solanum")).unwrap_err();
        assert!(err.starts_with("[FILE]"), "{err}");
    }
}

/// The committed fixture vault: a regression anchor for the on-disk format and
/// the schema. Fake password, synthetic content (TEST-NET addresses, no real
/// key material), KDF settings at the lower bounds so the test stays fast.
///
/// When `SCHEMA_VERSION` or the file format changes BEFORE the first release,
/// regenerate it: `SOLANUM_REGENERATE_FIXTURE=1 cargo test --lib -- --ignored regenerate_fixture_vault`
/// (the variable keeps a plain `cargo test -- --ignored` from rewriting it).
/// After real user vaults exist, keep this file as it is, add a fixture for the
/// new version, and make the old one open through the migration instead.
#[cfg(test)]
mod fixture_vault_tests {
    use super::*;

    const FIXTURE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/vault-v2-schema6.solanum");
    const FIXTURE_PASSWORD: &str = "solanum-fixture-password";

    fn fixture_content(conn: &Connection) {
        conn.execute_batch(
            "INSERT INTO folders(id,name) VALUES (1,'Fixture prod');
             INSERT INTO folders(id,name,parent_id) VALUES (2,'Fixture prod/db',1);
             INSERT INTO ssh_keys(id,name,public_key,private_key,passphrase) VALUES (1,'fixture-key','ssh-ed25519 AAAAFIXTURE','NOT A REAL KEY: fixture text only',NULL);
             INSERT INTO credentials(id,name,auth_type,username,key_id) VALUES (1,'fixture-ops','key','ops',1);
             INSERT INTO credentials(id,name,auth_type,username,password) VALUES (2,'fixture-root','password','root','fixture-password-1');
             INSERT INTO servers(id,name,host,port,auth_type,key_id,username,folder_id,position) VALUES (1,'fixture-bastion','192.0.2.10',22,'custom_key',1,'jump',1,0);
             INSERT INTO servers(id,name,host,port,auth_type,credential_id,folder_id,jump_host_id,notes,position) VALUES (2,'fixture-db','192.0.2.20',2222,'vault',1,2,1,'fixture note',0);
             INSERT INTO servers(id,name,host,port,auth_type,username,password,position,legacy_algorithms,terminal_only) VALUES (3,'fixture-lab','198.51.100.30',22,'custom_pass','lab','fixture-password-2',0,1,1);
             INSERT INTO commands(title,content) VALUES ('fixture command','uptime');
             INSERT INTO notes(title,body) VALUES ('fixture runbook','synthetic text');
             INSERT INTO known_hosts(host,port,fingerprint,key_type) VALUES ('192.0.2.10',22,'AAAAfixturefingerprint','ssh-ed25519');
             INSERT INTO monitor_configs(node_id) VALUES (2);
             INSERT INTO cmd_history(server_id,server_name,command,ts) VALUES (3,'fixture-lab','ls -la',1759600000000);",
        )
        .unwrap();
    }

    #[test]
    #[ignore = "writes testdata/vault-v2-schema6.solanum; run only when the format or schema changes pre-release"]
    fn regenerate_fixture_vault() {
        if std::env::var_os("SOLANUM_REGENERATE_FIXTURE").is_none() {
            eprintln!("regenerate_fixture_vault: set SOLANUM_REGENERATE_FIXTURE=1 to rewrite the committed fixture");
            return;
        }
        let kdf = KdfParams::for_new_vault();
        let kdf = KdfParams { m_cost: ARGON2_M_COST_MIN, t_cost: 1, p_cost: 1, ..kdf };
        let key = derive_key(FIXTURE_PASSWORD, &kdf).unwrap();
        let mut conn = open_vault_memory_db().unwrap();
        create_vault_schema(&conn).unwrap();
        fixture_content(&conn);
        let bytes = conn.serialize(MAIN_DB).unwrap().to_vec();
        let blob = seal_vault_blob(&vault_compress(&bytes).unwrap(), &key, &kdf).unwrap();
        fs::create_dir_all(std::path::Path::new(FIXTURE_PATH).parent().unwrap()).unwrap();
        fs::write(FIXTURE_PATH, blob).unwrap();
    }

    #[test]
    fn the_committed_fixture_vault_still_opens() {
        let bytes = fs::read(FIXTURE_PATH).expect("testdata/vault-v2-schema6.solanum is missing");
        let header = parse_vault_header(&bytes).unwrap();
        assert_eq!(bytes[4], VAULT_VERSION, "fixture file format");
        assert_eq!((header.kdf.m_cost, header.kdf.t_cost, header.kdf.p_cost), (ARGON2_M_COST_MIN, 1, 1));

        // Through the real unlock path, on a copy (it writes a lock file and a backup).
        let dir = std::env::temp_dir().join(format!("solanum-fixture-test-{:016x}", rand::thread_rng().gen::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("fixture.solanum");
        fs::write(&copy, &bytes).unwrap();
        let (conn, _vault) = match open_profile_vault(&copy, FIXTURE_PASSWORD, OpenMode::OpenOnly) {
            Ok(v) => v,
            Err(e) => panic!(
                "the committed fixture vault no longer opens: {e}\n\
                 Pre-release: regenerate it with `SOLANUM_REGENERATE_FIXTURE=1 cargo test --lib -- --ignored regenerate_fixture_vault`.\n\
                 After the first release: write a migration instead (see SCHEMA_VERSION)."
            ),
        };
        let one = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(one("SELECT CAST(value AS INTEGER) FROM schema_meta WHERE key='schema_version'"), SCHEMA_VERSION);
        assert_eq!(one("SELECT COUNT(*) FROM servers"), 3);
        assert_eq!(one("SELECT COUNT(*) FROM folders WHERE parent_id = 1"), 1);
        assert_eq!(one("SELECT COUNT(*) FROM servers WHERE jump_host_id = 1"), 1);
        assert_eq!(one("SELECT COUNT(*) FROM credentials WHERE key_id = 1"), 1);
        assert_eq!(one("SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
        let pw: String = conn.query_row("SELECT password FROM servers WHERE name='fixture-lab'", [], |r| r.get(0)).unwrap();
        assert_eq!(pw, "fixture-password-2");
        assert_eq!(one("SELECT COUNT(*) FROM servers WHERE legacy_algorithms = 1"), 1);
        assert_eq!(one("SELECT COUNT(*) FROM servers WHERE terminal_only = 1"), 1);
        let jump = resolve_jump_auth(&conn, 1).unwrap().unwrap();
        assert_eq!((jump.host.as_str(), jump.legacy_algorithms), ("192.0.2.10", false));
        assert_eq!(fs::read(sidecar_path(&copy, "bak")).unwrap(), bytes, "backup written on unlock");
        let _ = fs::remove_dir_all(dir);
    }
}

/// Async-friendly vault save: the SQLite serialise + zstd + AES-GCM + fsync
/// chain runs on a blocking-pool thread so concurrent terminal output and
/// keystrokes don't stall on the tokio worker pool. The connection and the
/// open-vault state are locked together inside that thread (see
/// `save_locked_vault`), so the snapshot is consistent even if the profile is
/// closed or switched meanwhile.
async fn save_vault_async(state: &DbState) -> Result<(), String> {
    let conn = Arc::clone(&state.conn);
    let vault = Arc::clone(&state.vault);
    tokio::task::spawn_blocking(move || save_locked_vault(&conn, &vault))
        .await
        .map_err(|e| format!("[CRYPTO] VAULT_JOIN: {}", e))?
}

/// Returns the list of available profile names (sorted, lowercased not enforced).
#[tauri::command]
async fn list_profiles(app_handle: tauri::AppHandle) -> Result<Vec<String>, String> {
    let dir = profiles_dir(&app_handle)?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).map_err(|e| format!("[FILE] READ_DIR_FAILED: {}", e))? {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        let path = entry.path();
        if !path.is_file() { continue; }
        if path.extension().and_then(|e| e.to_str()) != Some("solanum") { continue; }
        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
            // Hide anything that wouldn't pass our name validator — likely
            // a manually-placed file or stray artefact. We don't surface it
            // because the user has no way to act on it from the UI.
            if validate_profile_name(stem).is_ok() {
                out.push(stem.to_string());
            }
        }
    }
    out.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));
    Ok(out)
}

/// Mark a profile as the active one. Subsequent `setup_master_db` calls
/// operate against that profile's file. Returns
/// whether the profile's encrypted file already exists (caller uses this
/// to decide between "ask for password" and "this profile is empty / not
/// yet created" flows).
#[tauri::command]
async fn select_profile(
    app_handle: tauri::AppHandle,
    state: tauri::State<'_, DbState>,
    name: String,
) -> Result<bool, String> {
    validate_profile_name(&name)?;
    *state.active_profile.lock().map_err(|_| "[STATE] LOCK_FAILED")? = Some(name.clone());
    Ok(profile_path(&app_handle, &name)?.exists())
}

/// Lock the profile: stop everything it has running and close the vault, so
/// the UI can return to the picker. The frontend also calls this when it
/// starts (a reload or a crashed web view must land on a really locked app),
/// and the exit hook runs the same teardown.
#[tauri::command]
async fn close_profile(
    state: tauri::State<'_, DbState>,
    ssh: tauri::State<'_, SshState>,
    monitor_map: tauri::State<'_, MonitorMap>,
    mirrors: tauri::State<'_, MirrorMap>,
    settings: tauri::State<'_, SharedSettings>,
) -> Result<(), String> {
    teardown_profile(&state, &ssh, &monitor_map, &mirrors, &settings, live_edit::StopReason::ProfileClosed).await;
    Ok(())
}

/// How long a mirror gets to stop before its worker is aborted.
const MIRROR_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Everything the open profile has running, stopped, and the vault closed
/// (F-013). Per-profile state must not survive: live sessions, tunnels and
/// mirrors would keep running with no UI that shows them, and a host-key
/// write they triggered would land in the NEXT profile's vault. Free of
/// `AppHandle` (unit-tested). Returns the live edits' final checks, for a
/// caller that must wait for them (the exit hook).
async fn teardown_profile(
    state: &DbState,
    ssh: &SshState,
    monitor_map: &MonitorMap,
    mirrors: &MirrorMap,
    settings: &SharedSettings,
    reason: live_edit::StopReason,
) -> Vec<tokio::task::JoinHandle<()>> {
    // Work begun before this point must not register anything from now on
    // (a connect still handshaking, a tunnel replay list being seeded).
    ssh.next_epoch();
    // Save first: command history (written without a save per keystroke)
    // and anything else not on disk yet. Best effort: a vault that cannot be
    // saved must not keep the rest running.
    let _ = save_vault_async(state).await;

    // Retire every session id before removing anything, as every teardown
    // does: a connect still handshaking registers only if its generation is
    // current, and a health watcher bows out on a newer one.
    {
        let mut ids: std::collections::HashSet<String> = ssh.connections.lock().await.keys().cloned().collect();
        ids.extend(ssh.jump_connections.lock().await.keys().cloned());
        let mut generations = ssh.session_generation.lock().await;
        ids.extend(generations.keys().cloned());
        for id in ids {
            let next = generations.get(&id).copied().unwrap_or(0).wrapping_add(1);
            generations.insert(id, next);
        }
    }

    // Refuse the prompts still waiting for the user: a connect does not sit on
    // its 90 s host-key or 120 s keyboard-interactive wait after the lock.
    let waiters: Vec<tokio::sync::oneshot::Sender<bool>> =
        ssh.fp_txs.lock().await.drain().map(|(_, v)| v).collect();
    for tx in waiters {
        let _ = tx.send(false);
    }
    let kbi_waiters: Vec<tokio::sync::oneshot::Sender<Option<Vec<String>>>> =
        ssh.kbi_txs.lock().await.drain().map(|(_, v)| v).collect();
    for tx in kbi_waiters {
        let _ = tx.send(None);
    }

    monitor::stop_all(monitor_map).await;

    // Each live edit deletes its copy, or keeps it and says where when it
    // holds changes that were not uploaded.
    let finishing = ssh.live_edits.stop_all(reason);

    // Before the connections close: a stream's stop asks the server to end
    // its `docker logs -f`, which a closed connection would leave running.
    ssh.docker_streams.stop_all().await;
    mirror::stop_all_within(mirrors, MIRROR_STOP_TIMEOUT).await;
    tunnel::stop_all(&ssh.tunnels).await;

    // Transfers stop at their next chunk.
    for flag in ssh.transfer_cancels.lock().await.drain().map(|(_, f)| f) {
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    // Terminals: each task sees its input end, closes its channel, and a
    // local shell's task kills the shell.
    ssh.terminal_txs.lock().await.clear();
    ssh.resize_txs.lock().await.clear();

    // Connections last, closed explicitly so nothing still holding a channel
    // keeps one up.
    let connections: Vec<_> = ssh.connections.lock().await.drain().map(|(_, h)| h).collect();
    let jumps: Vec<_> = ssh
        .jump_connections
        .lock()
        .await
        .drain()
        .map(|(_, h)| Arc::new(tokio::sync::Mutex::new(h)))
        .collect();
    ssh.sftp_sessions.lock().await.clear();
    ssh.forwarded_targets.lock().await.clear();
    // The tunnel replay lists belong to this profile: server ids, and so
    // session ids, start again from 1 in every vault.
    ssh.session_tunnel_specs.lock().await.clear();
    ssh.session_targets.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
    ssh.channel_gates.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
    ssh.info_probes.lock().await.clear();
    ssh.tunnels.lock().await.clear();
    ssh_connect::close_handles(connections, ssh_connect::CLOSE_TIMEOUT).await;
    ssh_connect::close_handles(jumps, ssh_connect::CLOSE_TIMEOUT).await;

    // The next profile starts from its own monitor settings (F-080).
    *settings.lock().await = monitor::MonitorSettings::default();

    // The vault last: key wiped, profile lock released. Work that started
    // while this ran (its epoch is the one bumped above) is out of date too.
    clear_profile_state(state);
    ssh.next_epoch();
    finishing
}

/// Forget the open profile: database, key (zeroized on drop), profile lock
/// (released on drop) and name, in the usual conn-then-vault order. A panic
/// while one of these std mutexes was held poisons it, after which every vault
/// command fails with LOCK_FAILED; recover the slot here so locking the app
/// always works and the profile can be opened again without a restart.
fn clear_profile_state(state: &DbState) {
    fn clear<T>(slot: &StdMutex<Option<T>>) {
        *slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        slot.clear_poison();
    }
    clear(&state.conn);
    clear(&state.vault);
    clear(&state.active_profile);
}

/// Permanently delete a profile's encrypted file. The caller must NOT be
/// "in" that profile (would orphan in-memory state pointing at a deleted
/// file). UI enforces this by only showing the delete button on the picker
/// screen.
#[tauri::command]
async fn delete_profile(app_handle: tauri::AppHandle, name: String) -> Result<(), String> {
    validate_profile_name(&name)?;
    let path = profile_path(&app_handle, &name)?;
    delete_profile_files(&path)
}

/// Remove a profile's vault, its backup and any leftovers. Refused while any
/// Solanum window (this one included) has the profile open.
fn delete_profile_files(path: &std::path::Path) -> Result<(), String> {
    if !path.parent().is_some_and(|dir| dir.exists()) {
        return Ok(());
    }
    let lock = ProfileLock::acquire(path)?;
    for file in [path.to_path_buf(), sidecar_path(path, "bak")] {
        match fs::remove_file(&file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("[FILE] DELETE_PROFILE_FAILED at {:?}: {}", file, e)),
        }
    }
    sweep_stale_temp_files(path);
    let _ = fs::remove_file(sidecar_path(path, "lock"));
    drop(lock);
    Ok(())
}

/// Copy a profile's encrypted file to a user-chosen location so it can be
/// backed up or moved between machines. The file is already encrypted at
/// rest — we just copy bytes; we never decrypt or re-encrypt.
///
/// Returns `Some(path)` on success (on Android the saved document's name, which
/// is all it has) or `None` if the user cancels the save dialog. Errors bubble
/// up as `Err`.
#[tauri::command]
async fn export_profile(
    app_handle: tauri::AppHandle,
    name: String,
) -> Result<Option<String>, String> {
    validate_profile_name(&name)?;
    let src = profile_path(&app_handle, &name)?;
    if !src.exists() {
        return Err(format!("Profile '{}' not found on disk", name));
    }

    #[cfg(target_os = "android")]
    {
        return android::save_profile_file(&app_handle, &src, &format!("{}.solanum", name)).await;
    }
    #[cfg(not(target_os = "android"))]
    {
        // rfd's blocking dialog must not run on the main thread on macOS — we're
        // already off the UI thread in a tauri async command so a direct call is
        // fine. spawn_blocking would be needed if this was wrapped differently.
        let default_name = format!("{}.solanum", name);
        let chosen = rfd::FileDialog::new()
            .set_title("Export profile")
            .set_file_name(&default_name)
            .add_filter("Solanum profile", &["solanum"])
            .save_file();

        let dst = match chosen {
            Some(p) => p,
            None => return Ok(None),
        };

        fs::copy(&src, &dst)
            .map_err(|e| format!("[FILE] EXPORT_COPY_FAILED to {:?}: {}", dst, e))?;
        Ok(Some(dst.to_string_lossy().to_string()))
    }
}

/// Neutralizes path separators and other filename-invalid characters in a
/// name that's about to be handed to a native save dialog as the suggested
/// filename — `default_name` here is built from a user-editable server
/// nickname, not a name this app already validated like `validate_profile_name`
/// enforces for vault profiles. This is a light sanitize, not that stricter
/// reject-based check: the user can freely retype the field in the dialog
/// anyway, so the only goal is making sure the SUGGESTED value can't smuggle
/// a path traversal or an OS-reserved character into it. Falls back to a
/// generic name if that leaves nothing usable.
fn sanitize_suggested_filename(name: &str) -> String {
    let cleaned: String = name
        .trim()
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c => c,
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "terminal.txt".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Save a terminal's full scrollback (already assembled by the frontend from
/// its own xterm buffer — there's no reason to round-trip it through some
/// other representation) to a user-chosen text file. Same shape as
/// `export_profile` just above: native save dialog, Android refuses (no
/// desktop file dialog there), `Some(path)` on success or `None` on cancel.
#[tauri::command]
async fn save_terminal_text(default_name: String, content: String) -> Result<Option<String>, String> {
    #[cfg(target_os = "android")]
    {
        let _ = (default_name, content);
        return Err("Saving terminal output is not available on Android.".into());
    }
    #[cfg(not(target_os = "android"))]
    {
        let chosen = rfd::FileDialog::new()
            .set_title("Save terminal output")
            .set_file_name(&sanitize_suggested_filename(&default_name))
            .add_filter("Text", &["txt"])
            .save_file();

        let dst = match chosen {
            Some(p) => p,
            None => return Ok(None),
        };

        fs::write(&dst, content).map_err(|e| format!("[FILE] SAVE_TERMINAL_OUTPUT_FAILED to {:?}: {}", dst, e))?;
        Ok(Some(dst.to_string_lossy().to_string()))
    }
}

/// The first bytes of a picked file, read before the user picks a name and
/// gets a confusing error later. Same checks as unlocking: foreign, older or
/// newer formats and out-of-bounds KDF settings are all refused with their own
/// message. No key derivation: that needs the password.
fn check_import_header(path: &std::path::Path) -> Result<(), String> {
    use std::io::Read;
    let mut header = Vec::with_capacity(HEADER_LEN);
    let f = fs::File::open(path).map_err(|e| format!("[FILE] IMPORT_OPEN_FAILED: {}", e))?;
    f.take(HEADER_LEN as u64)
        .read_to_end(&mut header)
        .map_err(|e| format!("[FILE] IMPORT_READ_FAILED: {}", e))?;
    parse_vault_header(&header)?;
    Ok(())
}

/// The name offered for a picked file, within the profile-name rules, so the
/// user can hit Enter without re-typing in the common case. On Android a
/// document provider chooses the file name, so nothing about it is trusted.
fn suggested_profile_name(file_name: Option<&str>) -> String {
    let suggested: String = file_name
        .and_then(|name| std::path::Path::new(name).file_stem())
        .and_then(|stem| stem.to_str())
        .unwrap_or("")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .take(32)
        .collect();
    if suggested.chars().any(|c| c.is_ascii_alphanumeric()) && validate_profile_name(&suggested).is_ok() {
        suggested
    } else {
        "imported".to_string()
    }
}

/// Open a file picker and verify the chosen file looks like a Solanum
/// vault (right header bytes). We do NOT decrypt — that requires the
/// profile password, which the user enters after import via the regular
/// unlock flow.
///
/// Returns `(source_path, suggested_name)` so the UI can confirm or rename
/// before committing the copy. On Android `source_path` is a private copy of
/// the chosen document.
#[tauri::command]
async fn import_profile_pick(app_handle: tauri::AppHandle, state: tauri::State<'_, DbState>) -> Result<Option<(String, String)>, String> {
    *state.picked_import.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    #[cfg(target_os = "android")]
    {
        let Some(picked) = android::pick_profile_file(&app_handle, MAX_VAULT_FILE_BYTES).await? else {
            return Ok(None);
        };
        if let Err(refused) = check_import_header(std::path::Path::new(&picked.path)) {
            android::discard_staged_import();
            return Err(refused);
        }
        let suggested = suggested_profile_name(picked.name.as_deref());
        *state.picked_import.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(PathBuf::from(&picked.path));
        return Ok(Some((picked.path, suggested)));
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app_handle;
        let picked = rfd::FileDialog::new()
            .set_title("Import profile")
            .add_filter("Solanum profile", &["solanum"])
            .pick_file();

        let path = match picked {
            Some(p) => p,
            None => return Ok(None),
        };
        check_import_header(&path)?;
        let suggested = suggested_profile_name(path.file_name().and_then(|n| n.to_str()));
        let shown = path.to_string_lossy().to_string();
        *state.picked_import.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(path);
        Ok(Some((shown, suggested)))
    }
}

/// Commit a picked vault file into the profiles dir under `name`. Refuses
/// to overwrite an existing profile — the UI must prompt the user to pick
/// a different name (or delete the existing one) in that case.
#[tauri::command]
async fn import_profile_save(
    app_handle: tauri::AppHandle,
    state: tauri::State<'_, DbState>,
    source_path: String,
    name: String,
) -> Result<(), String> {
    validate_profile_name(&name)?;
    let src = picked_import_source(&state.picked_import, &source_path)?;

    ensure_profiles_dir(&app_handle)?;
    let dst = profile_path(&app_handle, &name)?;
    if dst.exists() {
        return Err(format!("Profile '{}' already exists", name));
    }

    // Single-read import: load the file into memory ONCE, validate the
    // header on the in-memory bytes, then write to the destination. The
    // previous "read 5 bytes to validate, then fs::copy" was TOCTOU —
    // an attacker (or a script running in parallel) could swap the file
    // between the header read and the copy and we'd import garbage.
    // Files, the lock and the write: off the async workers (R-012).
    tokio::task::spawn_blocking(move || {
        let bytes = read_import_source(&src)?;
        import_profile_bytes(&dst, &bytes, &name)
    })
    .await
    .map_err(|e| format!("[FILE] IMPORT_FAILED: {}", e))??;
    *state.picked_import.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    #[cfg(target_os = "android")]
    android::discard_staged_import();
    Ok(())
}

/// The file a profile import reads. Its path comes from the window, so it is
/// checked like any other webview path, and only a regular file is read
/// (R-012): opening a FIFO waits for a writer, and a device would be read up
/// to the cap. Looked at before the open, and `read_vault_file` looks at the
/// open handle again.
fn read_import_source(path: &std::path::Path) -> Result<Vec<u8>, String> {
    if !path.exists() {
        return Err("Source file no longer exists.".into());
    }
    let src = local_path::guard_local_path(path, local_path::LocalAccess::Read)?;
    if !fs::metadata(&src).map(|m| m.is_file()).unwrap_or(false) {
        return Err("[FILE] IMPORT_NOT_A_FILE: Only a profile file can be imported.".into());
    }
    read_vault_file(&src)
}

/// Write imported vault bytes as the new profile at `dst`, holding that
/// profile's lock so no other window can create or open it meanwhile.
fn import_profile_bytes(dst: &std::path::Path, bytes: &[u8], name: &str) -> Result<(), String> {
    parse_vault_blob(bytes)?;
    let _lock = ProfileLock::acquire(dst)?;
    write_new_profile_file(dst, bytes, name)
}

/// Open (or, for a brand-new profile, create) the active profile's vault with
/// `password`. The strength floor applies to creation only — see
/// `open_profile_vault`.
#[tauri::command]
async fn setup_master_db(
    app_handle: tauri::AppHandle,
    password: String,
    state: tauri::State<'_, DbState>,
    settings: tauri::State<'_, SharedSettings>,
) -> Result<(), String> {
    // The active profile must be picked before this command — the UI does
    // it from the picker screen. Refuse early instead of silently writing
    // to a default path.
    let profile_name = state.active_profile.lock()
        .map_err(|_| "[STATE] LOCK_FAILED_PROFILE")?
        .clone()
        .ok_or("[STATE] NO_PROFILE_SELECTED")?;

    ensure_profiles_dir(&app_handle)?;
    let path = profile_path(&app_handle, &profile_name)?;
    open_profile_into_state(&state, path, password, OpenMode::OpenOnly).await?;
    load_monitor_settings(&state, &settings).await;
    Ok(())
}

/// Whether opening a profile may create it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OpenMode {
    /// Unlock an existing vault; refuse if the file is gone (unlocking must
    /// never quietly create an empty profile under a name the picker listed).
    OpenOnly,
    /// Create a new vault; refuse if the file already exists.
    CreateOnly,
}

/// Larger than any real vault can be: the decompressed database is capped at
/// 64 MiB, and zstd never makes it much bigger than that. Checked before a file
/// is read whole, so a hostile file can't make the app read gigabytes into memory.
const MAX_VAULT_FILE_BYTES: u64 = 128 * 1024 * 1024;

/// Read a whole vault file, refusing anything over `MAX_VAULT_FILE_BYTES`.
/// Must NOT contain the word "decrypt".
fn read_vault_file(path: &std::path::Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let file = fs::File::open(path).map_err(|e| format!("[FILE] VAULT_READ_FAILED: {}", e))?;
    if !file.metadata().map(|m| m.is_file()).unwrap_or(false) {
        return Err("[FILE] VAULT_READ_FAILED: not a regular file.".into());
    }
    let mut data = Vec::new();
    file.take(MAX_VAULT_FILE_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|e| format!("[FILE] VAULT_READ_FAILED: {}", e))?;
    if data.len() as u64 > MAX_VAULT_FILE_BYTES {
        return Err("[VAULT] FILE_TOO_LARGE: This file is larger than any Solanum profile can be (over 128 MiB), so it was not opened.".into());
    }
    Ok(data)
}

/// Compare two keys without stopping at the first differing byte.
fn keys_match(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Unlock (or create) the vault at `path`: everything opening a profile does
/// with files and crypto. Synchronous and free of `AppHandle`, so the commands
/// run it on the blocking pool and tests can drive it directly.
fn open_profile_vault(
    path: &std::path::Path,
    password: &str,
    mode: OpenMode,
) -> Result<(Connection, OpenVault), String> {
    // Lock first: everything below (existence check, read, temp sweep, backup)
    // must not race another process that opens or creates the same profile.
    let lock = ProfileLock::acquire(path)?;
    sweep_stale_temp_files(path);
    let name = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    if path.exists() {
        if mode == OpenMode::CreateOnly {
            return Err(format!("Profile '{}' already exists", name));
        }
        let encrypted_data = read_vault_file(path)?;
        // Header first: a foreign, outdated or hostile file is refused here,
        // before the KDF runs with parameters taken from it.
        let kdf = parse_vault_blob(&encrypted_data)?.0.kdf;
        let key = Zeroizing::new(derive_key(password, &kdf)?);
        // Decrypt and load. Only this app's own vaults open; anything else is
        // refused here and the file is never written.
        let conn = load_vault(&encrypted_data, &key)?;
        // One backup generation, rotated once per unlock rather than on every
        // save: the app saves on almost every action, so a per-save copy would be
        // seconds old and already contain the mistake one wants to undo. This is
        // the profile as it was when the session started, known to open with this
        // password. The vault file itself is never moved, so it always exists.
        if let Err(e) = write_file_atomically(&sidecar_path(path, "bak"), &encrypted_data) {
            eprintln!("[solanum] could not write the profile backup: {}", e);
        }
        Ok((conn, OpenVault { key, kdf, path: path.to_path_buf(), _lock: lock }))
    } else {
        if mode == OpenMode::OpenOnly {
            return Err(format!("[VAULT] PROFILE_MISSING: Profile '{}' no longer exists on disk.", name));
        }
        check_new_master_password(password)?;
        let kdf = KdfParams::for_new_vault();
        let key = Zeroizing::new(derive_key(password, &kdf)?);
        let mut conn = open_vault_memory_db()?;
        create_vault_schema(&conn)?;
        let vault = OpenVault { key, kdf, path: path.to_path_buf(), _lock: lock };
        // A new vault is on disk (encrypted) before the profile counts as open.
        save_vault_blocking(&mut conn, &vault)?;
        Ok((conn, vault))
    }
}

/// Master-password strength floor — enforced ONLY at vault CREATION, not on
/// unlock (an existing vault with a short password must still open). This
/// password is the single cryptographic root protecting every stored
/// credential and private key, so a trivial one is a real risk. Counted in
/// Unicode code points (`chars()`), not bytes, so non-Latin passwords aren't
/// over-counted; the picker counts the same way (`[...s].length`), not in
/// UTF-16 units. 8 is a floor, not a ceiling — the UI should also nudge.
const MIN_MASTER_PASSWORD_CHARS: usize = 8;

fn check_new_master_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_MASTER_PASSWORD_CHARS {
        return Err("[CRYPTO] WEAK_MASTER_PASSWORD: choose at least 8 characters — this password protects every saved credential.".into());
    }
    Ok(())
}

/// Run `open_profile_vault` on the blocking pool and install the result in
/// `state`. Argon2id with m=64MiB is CPU-heavy (≈0.5–2s depending on hardware);
/// running it on the async runtime would block every other Tauri command for
/// that duration. The password buffer is zeroized once the closure is done.
async fn open_profile_into_state(
    state: &DbState,
    path: PathBuf,
    mut password: String,
    mode: OpenMode,
) -> Result<(), String> {
    // Unlocking the profile this process already has open (the webview was
    // reloaded without locking first): our own profile lock would refuse a second
    // open. Check the password against the key in memory instead and keep
    // everything as it is: unsaved changes, live sessions, the session-start
    // backup. A wrong password changes nothing either. Opening a DIFFERENT
    // profile keeps the old state, and its lock, until the new one is open.
    if mode == OpenMode::OpenOnly {
        let open_here = state.vault.lock()
            .map_err(|_| "[STATE] LOCK_FAILED_VAULT")?
            .as_ref()
            .filter(|v| v.path == path)
            .map(|v| (v.kdf, v.key.clone()));
        if let Some((kdf, open_key)) = open_here {
            let matches = tokio::task::spawn_blocking(move || {
                let res = derive_key(&password, &kdf).map(|k| keys_match(&Zeroizing::new(k), &open_key));
                password.zeroize();
                res
            })
            .await
            .map_err(|e| format!("[CRYPTO] KDF_JOIN: {}", e))??;
            return if matches {
                Ok(())
            } else {
                // Contains "decrypt" on purpose: the picker shows "Wrong password.".
                Err("[CRYPTO] DECRYPT_FAILURE: wrong password for this profile.".into())
            };
        }
    }
    let (conn, vault) = tokio::task::spawn_blocking(move || {
        let res = open_profile_vault(&path, &password, mode);
        password.zeroize();
        res
    })
    .await
    .map_err(|e| format!("[CRYPTO] KDF_JOIN: {}", e))??;

    // Reset every monitor to paused on profile open. Pollers don't survive
    // app restart, so a row with `paused=0` left over from the previous
    // session would advertise itself as "running" in the UI while no actual
    // backend task is spinning. Forcing pause makes the displayed state
    // truthful and matches the user's preference for explicit start.
    let _ = conn.execute("UPDATE monitor_configs SET paused = 1", []);

    // Take both slots before filling either, so a poisoned mutex can't leave
    // DbState half-initialised (a connection without the key to save it).
    let mut conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED_CONN")?;
    let mut vault_guard = state.vault.lock().map_err(|_| "[STATE] LOCK_FAILED_VAULT")?;
    *conn_guard = Some(conn);
    *vault_guard = Some(vault);
    Ok(())
}

/// Flush the in-memory vault to disk. Used by the frontend after a successful
/// SSH connection so any `known_hosts` row that `check_server_key` inserted
/// during the handshake survives an app restart — otherwise the user would
/// see the same fingerprint prompt every time they reconnect.
#[tauri::command]
async fn persist_vault(state: tauri::State<'_, DbState>) -> Result<(), String> {
    save_vault_async(&state).await
}

/// Create a brand-new profile, encrypted with `password`, and select it as
/// the active profile so the app can proceed directly into the main view
/// without bouncing back through `select_profile + setup_master_db`.
/// Rejected if a profile with the same name already exists — the picker
/// surfaces existing names so a clobber would be the user's mistake to
/// recover from, not something we should silently do.
#[tauri::command]
async fn create_profile(
    app_handle: tauri::AppHandle,
    state: tauri::State<'_, DbState>,
    settings: tauri::State<'_, SharedSettings>,
    name: String,
    password: String,
) -> Result<(), String> {
    validate_profile_name(&name)?;
    if password.is_empty() {
        return Err("Password cannot be empty".into());
    }
    ensure_profiles_dir(&app_handle)?;
    let path = profile_path(&app_handle, &name)?;
    if path.exists() {
        return Err(format!("Profile '{}' already exists", name));
    }
    *state.active_profile.lock().map_err(|_| "[STATE] LOCK_FAILED")? = Some(name);
    // A new vault is written to disk (encrypted) before this returns.
    open_profile_into_state(&state, path, password, OpenMode::CreateOnly).await?;
    load_monitor_settings(&state, &settings).await;
    Ok(())
}

#[tauri::command]
async fn generate_ssh_key(state: tauri::State<'_, DbState>, name: String) -> Result<(), String> {
    use rand::RngCore;
    use zeroize::Zeroize;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let keypair = Ed25519Keypair::from_seed(&seed);
    seed.zeroize();
    let priv_key = PrivateKey::from(keypair);
    let pub_ssh = priv_key.public_key().to_openssh()
        .map_err(|e| format!("[SSH] PUB_EXPORT_FAILED: {}", e))?;
    let priv_ssh = priv_key.to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| format!("[SSH] PRIV_EXPORT_FAILED: {}", e))?.to_string();

    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    
    conn.execute("INSERT INTO ssh_keys (name, public_key, private_key) VALUES (?1, ?2, ?3)", rusqlite::params![name, pub_ssh, priv_ssh])
        .map_err(|e| format!("[DATABASE] KEY_INSERT_FAILED: {}", e))?;
    
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

/// Reject key formats the SSH client cannot use, so failures surface when the
/// user enters the key rather than when they try to connect.
fn validate_ssh_private_key(private_key: &str) -> Result<(), String> {
    let trimmed = private_key.trim();

    // Legacy RSA PEM (PKCS#1) is decoded by russh directly.
    if trimmed.starts_with("-----BEGIN RSA PRIVATE KEY-----") {
        return Ok(());
    }
    // ECDSA in SEC1 PEM decodes and authenticates (checked against a real sshd).
    if trimmed.starts_with("-----BEGIN EC PRIVATE KEY-----") {
        return Ok(());
    }
    if trimmed.starts_with("-----BEGIN DSA PRIVATE KEY-----") {
        // DSA is dead. Tell the user to replace the key rather than pretending
        // the format is fine.
        return Err("[SSH] UNSUPPORTED_KEY_FORMAT: DSA keys aren't supported. Generate a fresh Ed25519 key (or use an RSA / ECDSA key).".into());
    }

    if trimmed.starts_with("PuTTY-User-Key-File-") {
        // Full validation happens at connect time via russh's ssh-key::from_ppk
        // (see decode_secret_key call sites), same lenient pattern as the RSA/EC
        // PEM branches above — we don't duplicate that parsing here, especially
        // since the private section may be passphrase-encrypted and we don't
        // have the passphrase field at validation time.
        return Ok(());
    }

    if trimmed.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----") {
        // Inspect the algorithm without requiring the passphrase — the algorithm
        // header is unencrypted even when the body is encrypted.
        if let Ok(parsed) = ssh_key::PrivateKey::from_openssh(trimmed) {
            match parsed.algorithm() {
                ssh_key::Algorithm::Ed25519
                | ssh_key::Algorithm::Rsa { .. }
                | ssh_key::Algorithm::Ecdsa { .. } => {}
                other => {
                    return Err(format!(
                        "[SSH] UNSUPPORTED_KEY_TYPE: {} keys are not supported.",
                        other.as_str()
                    ));
                }
            }
        }
        // If parsing fails entirely (unexpected header layout), let it through;
        // the connect path will surface a clearer error.
        return Ok(());
    }

    Err("[SSH] UNRECOGNIZED_KEY_FORMAT: Expected an OpenSSH-format private key (begins with -----BEGIN OPENSSH PRIVATE KEY-----), RSA/EC PEM, or a PuTTY .ppk file.".into())
}

/// Open a native file picker and return the chosen key file's raw text, so the
/// Add/Edit SSH Key form can populate a field from disk instead of a paste.
/// Reads the file server-side and hands back only its contents — the same
/// trust boundary as typing/pasting, since it lands in the same add_ssh_key /
/// edit_ssh_key call either way.
#[tauri::command]
async fn pick_key_file(kind: String) -> Result<Option<String>, String> {
    #[cfg(target_os = "android")]
    {
        return Err("File picker not available on Android.".into());
    }
    #[cfg(not(target_os = "android"))]
    {
        let is_public = kind == "public";
        let mut dialog = rfd::FileDialog::new().set_title(if is_public {
            "Select public key file"
        } else {
            "Select private key file"
        });
        dialog = if is_public {
            dialog.add_filter("Public key", &["pub"])
        } else {
            // OpenSSH private keys conventionally have no extension at all
            // (e.g. id_ed25519), so an empty filter is deliberate here.
            dialog.add_filter("Private key", &["pem", "key", "ppk", ""])
        };
        let Some(path) = dialog.pick_file() else {
            return Ok(None);
        };
        fs::read_to_string(&path)
            .map(Some)
            .map_err(|e| format!("[FILE] KEY_READ_FAILED: {}", e))
    }
}

#[tauri::command]
async fn add_ssh_key(state: tauri::State<'_, DbState>, name: String, public_key: String, private_key: String, passphrase: Option<String>) -> Result<(), String> {
    validate_ssh_private_key(&private_key)?;

    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;

    conn.execute("INSERT INTO ssh_keys (name, public_key, private_key, passphrase) VALUES (?1, ?2, ?3, ?4)", rusqlite::params![name, public_key, private_key, passphrase])
        .map_err(|e| format!("[DATABASE] KEY_INSERT_FAILED: {}", e))?;

    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn edit_ssh_key(state: tauri::State<'_, DbState>, id: i32, name: String, public_key: String, private_key: String, passphrase: Option<String>) -> Result<(), String> {
    validate_ssh_private_key(&private_key)?;

    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;

    conn.execute("UPDATE ssh_keys SET name=?1, public_key=?2, private_key=?3, passphrase=?4 WHERE id=?5", rusqlite::params![name, public_key, private_key, passphrase, id])
        .map_err(|e| format!("[DATABASE] KEY_UPDATE_FAILED: {}", e))?;

    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn delete_ssh_key(state: tauri::State<'_, DbState>, id: i32) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    
    conn.execute("DELETE FROM ssh_keys WHERE id=?1", rusqlite::params![id])
        .map_err(|e| format!("[DATABASE] KEY_DELETE_FAILED: {}", e))?;
    
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

/// Canonicalize a node row's identity fields based on the chosen auth_type.
/// The principle: a node either authenticates via a vault credential OR via
/// inline node-level fields — never a hybrid. Storing only the relevant
/// fields makes the connection-time resolution unambiguous and keeps the DB
/// honest about which mode a node really uses.
fn normalize_server_identity(
    auth_type: &str,
    username: Option<String>,
    password: Option<String>,
    key_id: Option<i32>,
    credential_id: Option<i32>,
) -> (Option<String>, Option<String>, Option<i32>, Option<i32>) {
    // Treat empty / whitespace-only usernames as absent so the DB stays clean.
    let username = username.and_then(|s| {
        let t = s.trim();
        if t.is_empty() { None } else { Some(t.to_string()) }
    });
    match auth_type {
        "vault" => {
            // Credential carries everything; the node row stores only the link.
            (None, None, None, credential_id)
        }
        "custom_key" => {
            // No password, no credential link — node owns username + key.
            (username, None, key_id, None)
        }
        // "custom_pass" and any unknown fallback: node owns username + password.
        _ => (username, password, None, None),
    }
}

/// Persist a Quick Connect target as a reusable node in the ROOT directory
/// (folder_id NULL). Quick Connect is otherwise ephemeral; this leaves behind a
/// saved profile the user can reconnect to later without re-typing credentials.
/// Deduplicates by (host, port, username) among root nodes so repeatedly
/// quick-connecting to the same host doesn't pile up identical rows — the
/// existing node's id is returned instead. Password targets are stored as
/// `custom_pass` (inline username + password); key targets save the private key
/// into `ssh_keys` (public_key left empty — the connect path derives everything
/// it needs from the private key via decode_secret_key, see the custom_key
/// branch in initiate_connection) and reference it as `custom_key`.
#[tauri::command]
async fn save_quick_connect_node(
    state: tauri::State<'_, DbState>,
    auth: QuickAuth,
) -> Result<i64, String> {
    checked_port(auth.port, "Port")?;
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;

    let username = {
        let t = auth.username.trim();
        if t.is_empty() { "root".to_string() } else { t.to_string() }
    };

    // Dedup against existing ROOT nodes with the same identity so the grid
    // doesn't fill with duplicates on repeated quick connects.
    let existing = conn.query_row(
        "SELECT id FROM servers WHERE folder_id IS NULL AND host = ?1 AND port = ?2 AND COALESCE(username,'') = ?3 LIMIT 1",
        rusqlite::params![auth.host, auth.port, username],
        |r| r.get::<_, i64>(0),
    );
    match existing {
        Ok(id) => return Ok(id),
        Err(rusqlite::Error::QueryReturnedNoRows) => {}
        Err(e) => return Err(format!("[DATABASE] QUICK_NODE_LOOKUP_FAILED: {}", e)),
    }

    let new_id = write_quick_node(conn, &auth, &username)?;
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(new_id)
}

/// The rows a Quick Connect "save as node" writes: its key, if it came with
/// one, then the server at the bottom of the root order, in one transaction
/// (R-013): a failure leaves no key behind that nothing uses.
fn write_quick_node(conn: &Connection, auth: &QuickAuth, username: &str) -> Result<i64, String> {
    let name = format!("{}@{}", username, auth.host);
    if let Some(pem) = auth.private_key.as_ref().filter(|s| !s.trim().is_empty()) {
        validate_ssh_private_key(pem)?;
    }
    // Rolled back when dropped without the commit.
    let tx = conn.unchecked_transaction().map_err(|e| format!("[DATABASE] QUICK_NODE_INSERT_FAILED: {}", e))?;
    let conn = &*tx;

    // A private key wins over a password if both somehow arrived.
    let (auth_type, db_password, db_key_id): (&str, Option<String>, Option<i64>) =
        if let Some(pem) = auth.private_key.as_ref().filter(|s| !s.trim().is_empty()) {
            conn.execute(
                "INSERT INTO ssh_keys (name, public_key, private_key, passphrase) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![name, "", pem, auth.passphrase],
            ).map_err(|e| format!("[DATABASE] QUICK_KEY_INSERT_FAILED: {}", e))?;
            ("custom_key", None, Some(conn.last_insert_rowid()))
        } else {
            ("custom_pass", auth.password.clone(), None)
        };

    conn.execute(
        "INSERT INTO servers (name, host, port, username, password, credential_id, folder_id, proxy_type, proxy_host, proxy_port, tunnels, auth_type, key_id, autostart, mirrors, color) \
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, 'none', '', 1080, '[]', ?6, ?7, 0, '[]', NULL)",
        rusqlite::params![name, auth.host, auth.port, username, db_password, auth_type, db_key_id],
    ).map_err(|e| format!("[DATABASE] QUICK_NODE_INSERT_FAILED: {}", e))?;

    let new_id = conn.last_insert_rowid();
    // Append to the bottom of the root order (mirrors save_server's position calc).
    conn.execute(
        "UPDATE servers SET position = COALESCE((SELECT MAX(position) FROM servers WHERE id != ?1 AND folder_id IS NULL), -1) + 1 WHERE id = ?1",
        rusqlite::params![new_id],
    ).map_err(|e| format!("[DATABASE] QUICK_NODE_INSERT_FAILED: {}", e))?;
    tx.commit().map_err(|e| format!("[DATABASE] QUICK_NODE_INSERT_FAILED: {}", e))?;
    Ok(new_id)
}

/// One node as the node form saves it (F-045): the server row and the
/// settings that used to go through commands of their own (notes, commands
/// run on connect, jump host, legacy algorithms), written in one transaction
/// with one vault write, so a save either happens whole or not at all. No
/// `Debug`: it carries the plaintext password.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServerSave {
    /// `None`: a new server.
    id: Option<i32>,
    name: String,
    host: String,
    port: i32,
    username: Option<String>,
    password: Option<String>,
    /// Edit only: keep the stored password. The form sends this when its
    /// password field was not touched, so a failed `reveal_server_password`
    /// (blank field) cannot wipe the stored secret.
    #[serde(default)]
    preserve_password: bool,
    credential_id: Option<i32>,
    folder_id: Option<i32>,
    proxy_type: String,
    proxy_host: String,
    proxy_port: i32,
    tunnels: Vec<serde_json::Value>,
    auth_type: String,
    key_id: Option<i32>,
    #[serde(default)]
    autostart: bool,
    #[serde(default)]
    mirrors: Vec<serde_json::Value>,
    color: Option<String>,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    run_on_connect: String,
    jump_host_id: Option<i32>,
    #[serde(default)]
    legacy_algorithms: bool,
    #[serde(default)]
    terminal_only: bool,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ServerSaved {
    id: i64,
    /// The node is saved in the open vault, but writing the profile file
    /// failed; the next change that saves writes it.
    persist_error: Option<String>,
}

/// Every tunnel rule the node form sends must parse the way it will be
/// started (N-017).
fn check_tunnel_rows(rows: &[serde_json::Value]) -> Result<(), String> {
    for (i, row) in rows.iter().enumerate() {
        let spec: tunnel::TunnelSpec = serde_json::from_value(row.clone())
            .map_err(|e| format!("Tunnel rule {}: {}", i + 1, e))?;
        tunnel::check_spec(&spec).map_err(|e| format!("Tunnel rule {} ({} {}): {}", i + 1, spec.kind, spec.local.trim(), e))?;
    }
    Ok(())
}

fn server_write_error(e: rusqlite::Error) -> String {
    match e.sqlite_error_code() {
        Some(rusqlite::ErrorCode::ConstraintViolation) => {
            "The saved login, SSH key, folder or jump host this server uses no longer exists; pick it again.".into()
        }
        _ => format!("[DATABASE] SERVER_SAVE_FAILED: {}", e),
    }
}

/// Checks a node and writes it, with all its settings, in one transaction.
/// Returns its id and whether its tunnel rules changed.
fn write_server_row(conn: &Connection, s: &ServerSave) -> Result<(i64, bool), String> {
    checked_port(s.port, "Port")?;
    let proxy_port = checked_proxy_port(&s.proxy_type, s.proxy_port)?;
    check_tunnel_rows(&s.tunnels)?;
    if s.id.is_some() && s.jump_host_id == s.id {
        return Err("A server cannot be its own jump host.".into()); // N-002
    }
    let tunnels_json = serde_json::to_string(&s.tunnels).map_err(|e| format!("[DATABASE] SERIALIZE_FAILED: {}", e))?;
    let mirrors_json = serde_json::to_string(&s.mirrors).map_err(|e| format!("[DATABASE] SERIALIZE_FAILED: {}", e))?;
    // Enforce the "one source of truth" rule at write time: in vault mode the
    // node row carries no identity at all; in custom_* mode the credential
    // link is dropped.
    let (db_username, db_password, db_key_id, db_credential_id) = normalize_server_identity(
        &s.auth_type, s.username.clone(), s.password.clone(), s.key_id, s.credential_id,
    );
    let autostart_i: i32 = if s.autostart { 1 } else { 0 };

    let tx = conn.unchecked_transaction().map_err(server_write_error)?;
    let saved = match s.id {
        None => {
            tx.execute(
                "INSERT INTO servers (name, host, port, username, password, credential_id, folder_id, proxy_type, proxy_host, proxy_port, tunnels, auth_type, key_id, autostart, mirrors, color, notes, run_on_connect, jump_host_id, legacy_algorithms, terminal_only) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
                rusqlite::params![s.name, s.host, s.port, db_username, db_password, db_credential_id, s.folder_id, s.proxy_type, s.proxy_host, proxy_port, tunnels_json, s.auth_type, db_key_id, autostart_i, mirrors_json, s.color, s.notes, s.run_on_connect, s.jump_host_id, s.legacy_algorithms, s.terminal_only],
            ).map_err(server_write_error)?;
            let new_id = tx.last_insert_rowid();
            // Append to the bottom of its folder's manual order: one past the
            // current max position among the folder's other rows (`IS ?2` is
            // NULL-safe so the root folder groups correctly). Without this a new
            // node would inherit the default position 0 and jump to the TOP of a
            // folder the user reordered.
            tx.execute(
                "UPDATE servers SET position = COALESCE((SELECT MAX(position) FROM servers WHERE id != ?1 AND folder_id IS ?2), -1) + 1 WHERE id = ?1",
                rusqlite::params![new_id, s.folder_id],
            ).map_err(server_write_error)?;
            (new_id, false)
        }
        Some(id) => {
            let (old_tunnels_json, old_folder_id): (String, Option<i32>) = tx
                .query_row("SELECT COALESCE(tunnels,'[]'), folder_id FROM servers WHERE id=?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|e| match e {
                    rusqlite::Error::QueryReturnedNoRows => "This server no longer exists.".to_string(),
                    other => server_write_error(other),
                })?;
            // With `preserve_password` the password column is wrapped in
            // COALESCE(?, password) so a NULL bind keeps the existing value. It
            // matters only for custom_pass: normalize_server_identity clears
            // the password for the other modes.
            let password_sql = if s.preserve_password && s.auth_type == "custom_pass" { "COALESCE(?5, password)" } else { "?5" };
            tx.execute(
                &format!("UPDATE servers SET name=?1, host=?2, port=?3, username=?4, password={password_sql}, credential_id=?6, folder_id=?7, proxy_type=?8, proxy_host=?9, proxy_port=?10, tunnels=?11, auth_type=?12, key_id=?13, autostart=?14, mirrors=?15, color=?16, notes=?17, run_on_connect=?18, jump_host_id=?19, legacy_algorithms=?20, terminal_only=?21 WHERE id=?22"),
                rusqlite::params![s.name, s.host, s.port, db_username, db_password, db_credential_id, s.folder_id, s.proxy_type, s.proxy_host, proxy_port, tunnels_json, s.auth_type, db_key_id, autostart_i, mirrors_json, s.color, s.notes, s.run_on_connect, s.jump_host_id, s.legacy_algorithms, s.terminal_only, id],
            ).map_err(server_write_error)?;
            // Folder changed → re-append to the bottom of the destination
            // folder's manual order, or the row keeps its stale rank from the
            // old folder and can collide at the top of the new one.
            if old_folder_id != s.folder_id {
                tx.execute(
                    "UPDATE servers SET position = COALESCE((SELECT MAX(position) FROM servers WHERE id != ?1 AND folder_id IS ?2), -1) + 1 WHERE id = ?1",
                    rusqlite::params![id, s.folder_id],
                ).map_err(server_write_error)?;
            }
            (id as i64, old_tunnels_json != tunnels_json)
        }
    };
    tx.commit().map_err(server_write_error)?;
    Ok(saved)
}

/// Add or edit a node with every setting of the node form (F-045).
#[tauri::command]
async fn save_server(
    state: tauri::State<'_, DbState>,
    ssh_state: tauri::State<'_, SshState>,
    request: ServerSave,
) -> Result<ServerSaved, String> {
    // The non-Send connection guard is dropped before the await below.
    let (id, tunnels_changed) = {
        let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
        let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
        write_server_row(conn, &request)?
    };
    let persist_error = save_vault_internal(&state).err();
    // Forwarding rules changed → drop this server's live tunnel replay cache so
    // every (re)connect / restore path re-seeds from the freshly-saved rules
    // instead of clinging to a stale (or failure-emptied) in-memory list. All
    // those paths seed from the node's `tunnels` JSON precisely when the key is
    // ABSENT. Session ids are `session-{server_id}` (openServer in the frontend).
    if tunnels_changed {
        ssh_state.session_tunnel_specs.lock().await.remove(&format!("session-{}", id));
    }
    Ok(ServerSaved { id, persist_error })
}

#[cfg(test)]
mod server_save_tests {
    use super::*;

    fn vault() -> Connection {
        let conn = open_vault_memory_db().unwrap();
        create_vault_schema(&conn).unwrap();
        conn
    }

    /// R-013: a Quick Connect saved with a key writes the key and the server
    /// together or not at all; a failure after the key was written used to
    /// leave the key behind, owned by nothing.
    #[test]
    fn a_quick_connect_node_is_saved_whole_or_not_at_all() {
        let conn = vault();
        let pem = crate::ssh_test_server::ed25519_key(7).to_openssh(russh::keys::ssh_key::LineEnding::LF).unwrap().to_string();
        let auth = QuickAuth { host: "10.0.0.9".into(), port: 22, username: "ops".into(), password: None, private_key: Some(pem), passphrase: None };
        let count = |table: &str| conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get::<_, i64>(0)).unwrap();

        conn.execute_batch("CREATE TEMP TRIGGER refuse_servers BEFORE INSERT ON servers BEGIN SELECT RAISE(ABORT, 'refused'); END;").unwrap();
        assert!(write_quick_node(&conn, &auth, "ops").is_err());
        assert_eq!(count("ssh_keys"), 0, "the key outlived the failed save");
        assert_eq!(count("servers"), 0);

        conn.execute_batch("DROP TRIGGER refuse_servers;").unwrap();
        let id = write_quick_node(&conn, &auth, "ops").unwrap();
        assert_eq!((count("ssh_keys"), count("servers")), (1, 1));
        let key: Option<i64> = conn.query_row("SELECT key_id FROM servers WHERE id = ?1", [id], |r| r.get(0)).unwrap();
        assert!(key.is_some(), "the server uses the key written with it");
    }

    fn node(name: &str) -> ServerSave {
        ServerSave {
            id: None,
            name: name.into(),
            host: "10.0.0.5".into(),
            port: 22,
            username: Some("ops".into()),
            password: Some("pw-1".into()),
            preserve_password: false,
            credential_id: None,
            folder_id: None,
            proxy_type: "none".into(),
            proxy_host: String::new(),
            proxy_port: 1080,
            tunnels: vec![],
            auth_type: "custom_pass".into(),
            key_id: None,
            autostart: false,
            mirrors: vec![],
            color: None,
            notes: String::new(),
            run_on_connect: String::new(),
            jump_host_id: None,
            legacy_algorithms: false,
            terminal_only: false,
        }
    }

    fn row(conn: &Connection, id: i64) -> (String, Option<String>, String, String, Option<i64>, bool, String) {
        conn.query_row(
            "SELECT name, password, notes, run_on_connect, jump_host_id, legacy_algorithms, tunnels FROM servers WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
        )
        .unwrap()
    }

    fn count(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM servers", [], |r| r.get(0)).unwrap()
    }

    #[test]
    fn a_new_node_is_written_with_every_setting_in_one_call() {
        let conn = vault();
        let (bastion, _) = write_server_row(&conn, &node("bastion")).unwrap();
        let mut n = node("db");
        n.notes = "runbook".into();
        n.run_on_connect = "uptime".into();
        n.jump_host_id = Some(bastion as i32);
        n.legacy_algorithms = true;
        n.tunnels = vec![json!({"type": "L", "local": "5432", "remote": "127.0.0.1:5432"})];
        let (id, _) = write_server_row(&conn, &n).unwrap();
        let (name, pw, notes, run, jump, legacy, tunnels) = row(&conn, id);
        assert_eq!((name.as_str(), pw.as_deref(), notes.as_str(), run.as_str()), ("db", Some("pw-1"), "runbook", "uptime"));
        assert_eq!((jump, legacy), (Some(bastion), true));
        assert!(tunnels.contains("127.0.0.1:5432"), "{tunnels}");
    }

    /// The setting is saved, changed by an edit, and copied with the server.
    #[test]
    fn terminal_only_is_written_edited_and_cloned() {
        let conn = vault();
        let read = |id: i64| -> bool { conn.query_row("SELECT terminal_only FROM servers WHERE id=?1", [id], |r| r.get(0)).unwrap() };
        let mut n = node("switch");
        n.terminal_only = true;
        let (id, _) = write_server_row(&conn, &n).unwrap();
        assert!(read(id));
        assert!(!read(write_server_row(&conn, &node("linux")).unwrap().0), "off by default");
        clone_server_row(&conn, id as i32).unwrap();
        assert!(read(conn.last_insert_rowid()), "a copy keeps it");
        n.id = Some(id as i32);
        n.terminal_only = false;
        write_server_row(&conn, &n).unwrap();
        assert!(!read(id));
    }

    #[test]
    fn an_edit_keeps_the_password_when_asked_and_reports_changed_rules() {
        let conn = vault();
        let (id, _) = write_server_row(&conn, &node("web")).unwrap();
        let mut n = node("web2");
        n.id = Some(id as i32);
        n.password = None;
        n.preserve_password = true;
        assert_eq!(write_server_row(&conn, &n).unwrap(), (id, false));
        assert_eq!(row(&conn, id).1.as_deref(), Some("pw-1"));
        n.tunnels = vec![json!({"type": "D", "local": "1080"})];
        assert_eq!(write_server_row(&conn, &n).unwrap(), (id, true));
        n.preserve_password = false;
        write_server_row(&conn, &n).unwrap();
        assert_eq!(row(&conn, id).1, None);
    }

    // N-017: a rule that would not start is refused, and nothing is written.
    #[test]
    fn a_bad_tunnel_rule_refuses_the_whole_save() {
        let conn = vault();
        let mut n = node("web");
        n.tunnels = vec![
            json!({"type": "L", "local": "8080", "remote": "127.0.0.1:80"}),
            json!({"type": "L", "local": "8081", "remote": "intranet"}),
        ];
        let err = write_server_row(&conn, &n).unwrap_err();
        assert!(err.starts_with("Tunnel rule 2 (L 8081)"), "{err}");
        n.tunnels = vec![json!({"type": "L"})];
        assert!(write_server_row(&conn, &n).unwrap_err().starts_with("Tunnel rule 1:"));
        assert_eq!(count(&conn), 0);
    }

    // N-002.
    #[test]
    fn a_server_is_not_its_own_jump_host() {
        let conn = vault();
        let (id, _) = write_server_row(&conn, &node("web")).unwrap();
        let mut n = node("web");
        n.id = Some(id as i32);
        n.jump_host_id = Some(id as i32);
        assert_eq!(write_server_row(&conn, &n).unwrap_err(), "A server cannot be its own jump host.");
        assert_eq!(row(&conn, id).4, None);
    }

    // F-045: the old save wrote the row first and the jump host afterwards, so
    // a jump host deleted meanwhile left the edited row saved without it.
    #[test]
    fn a_missing_jump_host_or_login_changes_nothing() {
        let conn = vault();
        let (id, _) = write_server_row(&conn, &node("web")).unwrap();
        let mut n = node("renamed");
        n.id = Some(id as i32);
        n.notes = "new notes".into();
        n.jump_host_id = Some(4242);
        let err = write_server_row(&conn, &n).unwrap_err();
        assert!(err.contains("no longer exists"), "{err}");
        let (name, _, notes, ..) = row(&conn, id);
        assert_eq!((name.as_str(), notes.as_str()), ("web", ""));

        let mut fresh = node("vaulted");
        fresh.auth_type = "vault".into();
        fresh.credential_id = Some(77);
        fresh.notes = "x".into();
        assert!(write_server_row(&conn, &fresh).unwrap_err().contains("no longer exists"));
        assert_eq!(count(&conn), 1);
    }

    #[test]
    fn an_edit_of_a_deleted_server_and_bad_ports_are_refused() {
        let conn = vault();
        let mut n = node("ghost");
        n.id = Some(9);
        assert_eq!(write_server_row(&conn, &n).unwrap_err(), "This server no longer exists.");
        let mut p = node("p");
        p.port = 70000;
        assert!(write_server_row(&conn, &p).is_err());
        let mut q = node("q");
        q.proxy_type = "socks5".into();
        q.proxy_port = 0;
        assert!(write_server_row(&conn, &q).is_err());
        assert_eq!(count(&conn), 0);
    }

    #[test]
    fn the_request_is_read_from_the_forms_camel_case_keys() {
        let n: ServerSave = serde_json::from_value(json!({
            "id": null, "name": "a", "host": "h", "port": 22, "username": "u", "password": null,
            "preservePassword": true, "credentialId": null, "folderId": null, "proxyType": "none",
            "proxyHost": "", "proxyPort": 1080, "tunnels": [], "authType": "custom_pass", "keyId": null,
            "autostart": true, "mirrors": [], "color": null, "notes": "n", "runOnConnect": "r",
            "jumpHostId": 3, "legacyAlgorithms": true, "terminalOnly": true
        }))
        .unwrap();
        assert!(n.preserve_password && n.autostart && n.legacy_algorithms && n.terminal_only);
        assert_eq!((n.run_on_connect.as_str(), n.jump_host_id), ("r", Some(3)));
    }
}

/// Append a single mirror spec to a saved server's mirrors column.
///
/// Exists so the live MirrorsPanel's "new mirror" flow can persist the
/// mirror it just started without round-tripping the whole save_server
/// payload (which would force the panel to know about every other
/// node field — username, tunnels, auth_type, etc.). Pairs with
/// re-encrypting the vault on the way out, the same as the full edit
/// path does. Duplicate (local, remote) entries are coalesced so
/// hitting "Start mirror" twice on the same pair doesn't bloat the row.
#[tauri::command]
async fn add_mirror_to_server(
    state: tauri::State<'_, DbState>,
    server_id: i32,
    mirror: serde_json::Value,
) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;

    let existing: String = conn.query_row(
        "SELECT mirrors FROM servers WHERE id = ?1",
        rusqlite::params![server_id],
        |row| row.get::<_, Option<String>>(0).map(|v| v.unwrap_or_else(|| "[]".into())),
    ).map_err(|e| format!("[DATABASE] SERVER_LOOKUP_FAILED: {}", e))?;

    let mut list: Vec<serde_json::Value> = serde_json::from_str(&existing).unwrap_or_default();
    let local  = mirror.get("local").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let remote = mirror.get("remote").and_then(|v| v.as_str()).unwrap_or("").to_string();
    if local.is_empty() || remote.is_empty() {
        return Err("mirror needs both local and remote paths".into());
    }
    // Replace any prior entry for the same (local, remote) pair so the
    // latest spec (e.g. updated excludes / conflict mode) wins instead of
    // piling a duplicate row beside it.
    list.retain(|m| {
        m.get("local").and_then(|v| v.as_str()) != Some(&local)
            || m.get("remote").and_then(|v| v.as_str()) != Some(&remote)
    });
    list.push(mirror);

    let next = serde_json::to_string(&list).map_err(|e| format!("[DATABASE] SERIALIZE_FAILED: {}", e))?;
    conn.execute(
        "UPDATE servers SET mirrors = ?1 WHERE id = ?2",
        rusqlite::params![next, server_id],
    ).map_err(|e| format!("[DATABASE] MIRROR_SAVE_FAILED: {}", e))?;

    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

/// Reveal the plaintext password for a single server row. Used by the edit
/// panel — only the row the user is editing has its secret crossing IPC.
/// Returns `Ok(None)` if the server uses a vault credential (no inline
/// password) or the password column is empty.
#[tauri::command]
async fn reveal_server_password(state: tauri::State<'_, DbState>, id: i32) -> Result<Option<String>, String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    conn.query_row(
        "SELECT password FROM servers WHERE id = ?1",
        rusqlite::params![id],
        |row| row.get::<_, Option<String>>(0),
    ).map_err(|e| format!("[DATABASE] REVEAL_FAILED: {}", e))
}

/// Reveal the plaintext password for a single saved credential. Same shape
/// and rationale as `reveal_server_password`.
#[tauri::command]
async fn reveal_credential_password(state: tauri::State<'_, DbState>, id: i32) -> Result<Option<String>, String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    conn.query_row(
        "SELECT password FROM credentials WHERE id = ?1",
        rusqlite::params![id],
        |row| row.get::<_, Option<String>>(0),
    ).map_err(|e| format!("[DATABASE] REVEAL_FAILED: {}", e))
}

/// Reveal the stored private key + passphrase for an SSH key entry. Used
/// by the key editor and by any future "show key" affordance. The list
/// view never sees these fields.
#[tauri::command]
async fn reveal_ssh_key(state: tauri::State<'_, DbState>, id: i32) -> Result<serde_json::Value, String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    conn.query_row(
        "SELECT private_key, passphrase FROM ssh_keys WHERE id = ?1",
        rusqlite::params![id],
        |row| {
            Ok(json!({
                "private_key": row.get::<_, Option<String>>(0)?,
                "passphrase": row.get::<_, Option<String>>(1)?,
            }))
        },
    ).map_err(|e| format!("[DATABASE] REVEAL_FAILED: {}", e))
}

/// Persist a manual drag-to-reorder of the node grid. `ids` is the full list
/// of server ids in their new visual order (typically the servers of one
/// folder); we write each id's index as its `position`, so `get_servers`'
/// `ORDER BY position, id` reproduces the arrangement. Writing 0..n only for
/// the passed ids is safe: positions are compared within a folder after
/// `get_servers` filters, and id breaks any cross-folder ties.
#[tauri::command]
async fn reorder_servers(state: tauri::State<'_, DbState>, ids: Vec<i32>) -> Result<(), String> {
    {
        let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
        let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
        for (idx, id) in ids.iter().enumerate() {
            // Only touch rows whose position actually changes, so a reorder
            // rewrites just the rows that genuinely moved.
            conn.execute(
                "UPDATE servers SET position=?1 WHERE id=?2 AND (position IS NULL OR position<>?1)",
                rusqlite::params![idx as i64, id],
            ).map_err(|e| format!("[DATABASE] SERVER_REORDER_FAILED: {}", e))?;
        }
    }
    save_vault_internal(&state)?;
    Ok(())
}

/// Unix seconds for a just-pinned row, or None to unpin. A timestamp rather
/// than a bare boolean gives pin order (most recently pinned first) for free,
/// with no separate ordering column.
fn pinned_at_value(pinned: bool) -> Option<i64> {
    if !pinned {
        return None;
    }
    Some(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            // 1, not 0: every consumer treats pinned_at as a plain truthy
            // check (frontend `.filter(s => s.pinned_at)`), and a clock set
            // at/before the epoch would otherwise store a "pinned" row as 0,
            // indistinguishable from unpinned.
            .unwrap_or(1),
    )
}

#[tauri::command]
async fn set_server_pinned(state: tauri::State<'_, DbState>, id: i32, pinned: bool) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    conn.execute(
        "UPDATE servers SET pinned_at=?1 WHERE id=?2",
        rusqlite::params![pinned_at_value(pinned), id],
    ).map_err(|e| format!("[DATABASE] SERVER_PIN_FAILED: {}", e))?;
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn set_folder_pinned(state: tauri::State<'_, DbState>, id: i32, pinned: bool) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    conn.execute(
        "UPDATE folders SET pinned_at=?1 WHERE id=?2",
        rusqlite::params![pinned_at_value(pinned), id],
    ).map_err(|e| format!("[DATABASE] FOLDER_PIN_FAILED: {}", e))?;
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

/// Update the free-form notes / description blob attached to a node. Stored
/// as plain text in the `notes` column; the UI renders it monospace and lets
/// the user dump runbook snippets, contact info, alerts to remember, etc.
#[tauri::command]
async fn set_server_notes(state: tauri::State<'_, DbState>, id: i32, notes: String) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    conn.execute(
        "UPDATE servers SET notes=?1 WHERE id=?2",
        rusqlite::params![notes, id],
    ).map_err(|e| format!("[DATABASE] SERVER_NOTES_FAILED: {}", e))?;
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

/// The session's offer to keep a limited host terminal only, or any other
/// change of that one setting. It applies from the server's next connection.
#[tauri::command]
async fn set_server_terminal_only(state: tauri::State<'_, DbState>, id: i32, terminal_only: bool) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    let changed = conn
        .execute("UPDATE servers SET terminal_only=?1 WHERE id=?2", rusqlite::params![terminal_only, id])
        .map_err(|e| format!("[DATABASE] SERVER_SAVE_FAILED: {}", e))?;
    if changed == 0 {
        return Err("This server no longer exists.".into());
    }
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

/// Duplicate a server row verbatim — including credentials linkage, tunnels,
/// mirrors, proxy config, colour. The clone gets a "{name} (copy)" suffix so
/// it shows up beside the original in the grid; everything else is identical
/// so the user can connect to the same target with a different label or
/// tweak one field without retyping the rest.
#[tauri::command]
async fn clone_server(state: tauri::State<'_, DbState>, id: i32) -> Result<i64, String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    let new_id = clone_server_row(conn, id)?;
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(new_id)
}

/// The row behind `clone_server`.
fn clone_server_row(conn: &Connection, id: i32) -> Result<i64, String> {
    let affected = conn.execute(
        "INSERT INTO servers (name, host, port, username, password, credential_id, folder_id, proxy_type, proxy_host, proxy_port, tunnels, auth_type, key_id, autostart, mirrors, color, notes, run_on_connect, jump_host_id, legacy_algorithms, terminal_only)
         SELECT name || ' (copy)', host, port, username, password, credential_id, folder_id, proxy_type, proxy_host, proxy_port, tunnels, auth_type, key_id, 0, mirrors, color, notes, run_on_connect, jump_host_id, legacy_algorithms, terminal_only
         FROM servers WHERE id = ?1",
        rusqlite::params![id],
    ).map_err(|e| format!("[DATABASE] SERVER_CLONE_FAILED: {}", e))?;
    if affected == 0 {
        return Err(format!("[DATABASE] SERVER_CLONE_FAILED: no row with id {}", id));
    }
    let new_id = conn.last_insert_rowid();
    // Place the clone at the bottom of its folder's manual order (the INSERT
    // above doesn't copy `position`, so without this it would default to 0 and
    // jump to the top). Same append logic as save_server, folder taken from the
    // clone's own row.
    let _ = conn.execute(
        "UPDATE servers SET position = COALESCE((SELECT MAX(position) FROM servers s2 WHERE s2.id != servers.id AND s2.folder_id IS servers.folder_id), -1) + 1 WHERE id = ?1",
        rusqlite::params![new_id],
    );
    Ok(new_id)
}

#[tauri::command]
async fn delete_server(
    state: tauri::State<'_, DbState>,
    map: tauri::State<'_, MonitorMap>,
    id: i32,
) -> Result<(), String> {
    // Refuse before stopping anything if other servers jump through this one.
    {
        let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
        let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
        refuse_if_jump_host_in_use(conn, &[id])?;
    }
    // Stop the poller BEFORE the row goes away. The monitor_configs row does
    // cascade-delete with the server, but that only removes the config — the
    // spawned poller lives in MonitorMap and would keep opening SSH connections
    // to the host on its interval, using credentials the user just deleted.
    // Worse, it becomes unreachable: monitor_list JOINs servers, so the node
    // vanishes from the UI and monitor_remove (the only other caller of
    // stop_monitor) can no longer be invoked for it. Only an app restart
    // stopped it.
    monitor::stop_monitor(map.inner().clone(), id).await;

    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;

    conn.execute("DELETE FROM servers WHERE id=?1", rusqlite::params![id])
        .map_err(|e| format!("[DATABASE] SERVER_DELETE_FAILED: {}", e))?;

    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn get_servers(state: tauri::State<'_, DbState>) -> Result<Vec<serde_json::Value>, String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    // Secrets stay server-side: this listing returns `has_password` instead
    // of the plaintext column, so the password never crosses the IPC bridge
    // unless someone explicitly invokes `reveal_server_password`. The edit
    // panel calls reveal on open, but the cards / sidebar / quick-connect
    // grid never see the plaintext.
    // ORDER BY (position, id): `position` is the manual drag-to-reorder rank
    // (default 0 for never-reordered rows), and id breaks ties so the order is
    // stable and, before any reorder, identical to the old rowid order.
    let mut stmt = conn.prepare("SELECT id, name, host, port, username, password, credential_id, folder_id, proxy_type, proxy_host, proxy_port, tunnels, auth_type, key_id, autostart, mirrors, color, notes, run_on_connect, jump_host_id, position, pinned_at, legacy_algorithms, terminal_only FROM servers ORDER BY position, id")
        .map_err(|e| format!("[DATABASE] PREPARE_FAILED: {}", e))?;

    let rows = stmt.query_map([], |row| {
        let pw: Option<String> = row.get::<_, Option<String>>(5)?;
        Ok(json!({
            "id": row.get::<_, i32>(0)?,
            "name": row.get::<_, String>(1)?,
            "host": row.get::<_, String>(2)?,
            "port": row.get::<_, i32>(3)?,
            "username": row.get::<_, Option<String>>(4)?.unwrap_or_default(),
            "has_password": pw.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
            "credential_id": row.get::<_, Option<i32>>(6)?,
            "folder_id": row.get::<_, Option<i32>>(7)?,
            "proxy_type": row.get::<_, Option<String>>(8)?.unwrap_or_else(|| "none".to_string()),
            "proxy_host": row.get::<_, Option<String>>(9)?.unwrap_or_default(),
            "proxy_port": row.get::<_, Option<i32>>(10)?.unwrap_or(1080),
            "tunnels": row.get::<_, Option<String>>(11)?.unwrap_or_else(|| "[]".to_string()),
            "auth_type": row.get::<_, Option<String>>(12)?.unwrap_or_else(|| "vault".to_string()),
            "key_id": row.get::<_, Option<i32>>(13)?,
            "autostart": row.get::<_, i32>(14).unwrap_or(0) != 0,
            "mirrors": row.get::<_, Option<String>>(15)?.unwrap_or_else(|| "[]".to_string()),
            "color": row.get::<_, Option<String>>(16)?,
            "notes": row.get::<_, Option<String>>(17)?.unwrap_or_default(),
            "run_on_connect": row.get::<_, Option<String>>(18)?.unwrap_or_default(),
            "jump_host_id": row.get::<_, Option<i32>>(19)?,
            // Manual drag-to-reorder rank (see ORDER BY above).
            "position": row.get::<_, i64>(20).unwrap_or(0),
            // Unix seconds when pinned, or null — doubles as pin order (most
            // recently pinned first) so no separate ordering column is needed.
            "pinned_at": row.get::<_, Option<i64>>(21)?,
            "legacy_algorithms": row.get::<_, i64>(22)? != 0,
            "terminal_only": row.get::<_, i64>(23)? != 0,
        }))
    }).map_err(|e| format!("[DATABASE] QUERY_MAPPING_FAILED: {}", e))?;

    let mut list = Vec::new();
    for r in rows {
        list.push(r.map_err(|e| format!("[DATABASE] ROW_FETCH_FAILED: {}", e))?);
    }
    Ok(list)
}

#[tauri::command]
async fn get_ssh_keys(state: tauri::State<'_, DbState>) -> Result<Vec<serde_json::Value>, String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    // Private key + passphrase do NOT cross IPC in the listing — only the
    // public key (which is safe by definition) and presence flags. The edit
    // sheet calls `reveal_ssh_key` when it needs the secrets to display.
    let mut stmt = conn.prepare("SELECT id, name, public_key, private_key, passphrase FROM ssh_keys").map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| {
        let priv_present: Option<String> = row.get::<_, Option<String>>(3)?;
        let pp_present: Option<String> = row.get::<_, Option<String>>(4)?;
        Ok(json!({
            "id": row.get::<_, i32>(0)?,
            "name": row.get::<_, String>(1)?,
            "public_key": row.get::<_, String>(2)?,
            "has_private_key": priv_present.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
            "has_passphrase": pp_present.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
        }))
    }).map_err(|e| e.to_string())?;
    
    let mut list = Vec::new();
    for r in rows {
        list.push(r.map_err(|e| format!("[DATABASE] ROW_FETCH_FAILED: {}", e))?);
    }
    Ok(list)
}

#[tauri::command]
async fn get_credentials(state: tauri::State<'_, DbState>) -> Result<Vec<serde_json::Value>, String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    // Same pattern as get_servers / get_ssh_keys: only `has_password` is
    // listed. The credential edit panel reveals on open via the dedicated
    // command.
    let mut stmt = conn.prepare("SELECT id, name, auth_type, username, password, key_id FROM credentials").map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| {
        let pw: Option<String> = row.get::<_, Option<String>>(4)?;
        Ok(json!({
            "id": row.get::<_, i32>(0)?,
            "name": row.get::<_, String>(1)?,
            "auth_type": row.get::<_, String>(2)?,
            "username": row.get::<_, String>(3)?,
            "has_password": pw.as_deref().map(|s| !s.is_empty()).unwrap_or(false),
            "key_id": row.get::<_, Option<i32>>(5)?
        }))
    }).map_err(|e| e.to_string())?;
    
    let mut list = Vec::new();
    for r in rows {
        list.push(r.map_err(|e| format!("[DATABASE] ROW_FETCH_FAILED: {}", e))?);
    }
    Ok(list)
}

#[tauri::command]
async fn add_credential(state: tauri::State<'_, DbState>, name: String, auth_type: String, username: String, password: Option<String>, key_id: Option<i32>) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    
    conn.execute("INSERT INTO credentials (name, auth_type, username, password, key_id) VALUES (?1, ?2, ?3, ?4, ?5)", rusqlite::params![name, auth_type, username, password, key_id])
        .map_err(|e| format!("[DATABASE] CREDENTIAL_INSERT_FAILED: {}", e))?;
    
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn edit_credential(state: tauri::State<'_, DbState>, id: i32, name: String, auth_type: String, username: String, password: Option<String>, key_id: Option<i32>) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    
    conn.execute("UPDATE credentials SET name=?1, auth_type=?2, username=?3, password=?4, key_id=?5 WHERE id=?6", rusqlite::params![name, auth_type, username, password, key_id, id])
        .map_err(|e| format!("[DATABASE] CREDENTIAL_UPDATE_FAILED: {}", e))?;
    
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn delete_credential(state: tauri::State<'_, DbState>, id: i32) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    
    conn.execute("DELETE FROM credentials WHERE id=?1", rusqlite::params![id])
        .map_err(|e| format!("[DATABASE] CREDENTIAL_DELETE_FAILED: {}", e))?;
    
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn add_folder(state: tauri::State<'_, DbState>, name: String, parent_id: Option<i32>) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    
    conn.execute(
        "INSERT INTO folders (name, parent_id) VALUES (?1, ?2)",
        rusqlite::params![name, parent_id],
    ).map_err(|e| format!("[DATABASE] FOLDER_INSERT_FAILED: {}", e))?;
    
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn rename_folder(state: tauri::State<'_, DbState>, id: i32, name: String) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("[VALIDATION] FOLDER_NAME_EMPTY".into());
    }
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    let affected = conn.execute(
        "UPDATE folders SET name=?1 WHERE id=?2",
        rusqlite::params![trimmed, id],
    ).map_err(|e| format!("[DATABASE] FOLDER_RENAME_FAILED: {}", e))?;
    if affected == 0 {
        return Err(format!("[DATABASE] FOLDER_RENAME_FAILED: no folder with id {}", id));
    }
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn delete_folder(
    state: tauri::State<'_, DbState>,
    map: tauri::State<'_, MonitorMap>,
    id: i32,
) -> Result<(), String> {
    // The folder goes with everything inside it: sub-folders at any depth and
    // their servers (ON DELETE CASCADE). Same orphaned-poller problem as
    // delete_server, so collect those servers while the rows still exist, refuse
    // if one of them is the jump host of a server outside the folder, and stop
    // their monitors before deleting.
    let doomed: Vec<i32> = {
        let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
        let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
        let doomed = servers_in_folder_tree(conn, id)?;
        refuse_if_jump_host_in_use(conn, &doomed)?;
        doomed
    };
    for node_id in doomed {
        monitor::stop_monitor(map.inner().clone(), node_id).await;
    }

    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    // One statement, so the whole subtree goes or nothing does.
    conn.execute("DELETE FROM folders WHERE id=?1", rusqlite::params![id])
        .map_err(|e| format!("[DATABASE] FOLDER_DELETE_FAILED: {}", e))?;

    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

/// Every server in folder `folder_id` or any of its sub-folders.
fn servers_in_folder_tree(conn: &Connection, folder_id: i32) -> Result<Vec<i32>, String> {
    // UNION (not UNION ALL) also stops the recursion on a parent_id cycle.
    let mut stmt = conn
        .prepare(
            "WITH RECURSIVE tree(id) AS (
                 SELECT ?1 UNION SELECT f.id FROM folders f JOIN tree t ON f.parent_id = t.id
             )
             SELECT id FROM servers WHERE folder_id IN tree",
        )
        .map_err(|e| format!("[DATABASE] FOLDER_SERVERS_QUERY_FAILED: {}", e))?;
    let rows = stmt
        .query_map(rusqlite::params![folder_id], |r| r.get::<_, i32>(0))
        .map_err(|e| format!("[DATABASE] FOLDER_SERVERS_QUERY_FAILED: {}", e))?;
    rows.collect::<Result<_, _>>()
        .map_err(|e| format!("[DATABASE] FOLDER_SERVERS_QUERY_FAILED: {}", e))
}

/// Refuse to delete the `doomed` servers while a server that is NOT being
/// deleted uses one of them as its ProxyJump host. The schema refuses too
/// (`jump_host_id ... ON DELETE NO ACTION`), but with a bare "FOREIGN KEY
/// constraint failed"; this says who is affected and what to do.
fn refuse_if_jump_host_in_use(conn: &Connection, doomed: &[i32]) -> Result<(), String> {
    let mut stmt = conn
        .prepare("SELECT s.id, COALESCE(s.name, ''), COALESCE(j.name, '') FROM servers s JOIN servers j ON j.id = s.jump_host_id WHERE s.jump_host_id = ?1")
        .map_err(|e| format!("[DATABASE] JUMP_HOST_QUERY_FAILED: {}", e))?;
    let mut users = Vec::new();
    for &bastion in doomed {
        let rows = stmt
            .query_map(rusqlite::params![bastion], |r| Ok((r.get::<_, i32>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))
            .map_err(|e| format!("[DATABASE] JUMP_HOST_QUERY_FAILED: {}", e))?;
        for row in rows {
            let (user_id, user, via) = row.map_err(|e| format!("[DATABASE] JUMP_HOST_QUERY_FAILED: {}", e))?;
            if !doomed.contains(&user_id) {
                users.push(format!("\"{}\" (via \"{}\")", user, via));
            }
        }
    }
    if users.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "[VALIDATION] JUMP_HOST_IN_USE: Not deleted: other servers use it as their jump host: {}. Pick another jump host for them (or none) first.",
            users.join(", "),
        ))
    }
}

#[tauri::command]
async fn get_folders(state: tauri::State<'_, DbState>) -> Result<Vec<serde_json::Value>, String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    let mut stmt = conn.prepare("SELECT id, name, parent_id, color, pinned_at FROM folders").map_err(|e| e.to_string())?;

    let rows = stmt.query_map([], |row| {
        Ok(json!({
            "id": row.get::<_, i32>(0)?,
            "name": row.get::<_, String>(1)?,
            "parent_id": row.get::<_, Option<i32>>(2)?,
            "color": row.get::<_, Option<String>>(3)?,
            "pinned_at": row.get::<_, Option<i64>>(4)?,
        }))
    }).map_err(|e| e.to_string())?;
    
    let mut list = Vec::new();
    for r in rows {
        list.push(r.map_err(|e| format!("[DATABASE] ROW_FETCH_FAILED: {}", e))?);
    }
    Ok(list)
}

#[tauri::command]
async fn add_command(state: tauri::State<'_, DbState>, title: String, content: String) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    
    conn.execute(
        "INSERT INTO commands (title, content) VALUES (?1, ?2)",
        rusqlite::params![title, content],
    ).map_err(|e| format!("[DATABASE] COMMAND_INSERT_FAILED: {}", e))?;
    
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn edit_command(state: tauri::State<'_, DbState>, id: i32, title: String, content: String) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    
    conn.execute(
        "UPDATE commands SET title=?1, content=?2 WHERE id=?3",
        rusqlite::params![title, content, id],
    ).map_err(|e| format!("[DATABASE] COMMAND_UPDATE_FAILED: {}", e))?;
    
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn delete_command(state: tauri::State<'_, DbState>, id: i32) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    
    conn.execute(
        "DELETE FROM commands WHERE id=?1",
        rusqlite::params![id],
    ).map_err(|e| format!("[DATABASE] COMMAND_DELETE_FAILED: {}", e))?;
    
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn get_commands(state: tauri::State<'_, DbState>) -> Result<Vec<serde_json::Value>, String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    let mut stmt = conn.prepare("SELECT id, title, content FROM commands").map_err(|e| e.to_string())?;
    
    let rows = stmt.query_map([], |row| {
        Ok(json!({
            "id": row.get::<_, i32>(0)?, 
            "title": row.get::<_, String>(1)?, 
            "content": row.get::<_, String>(2)?
        }))
    }).map_err(|e| e.to_string())?;
    
    let mut list = Vec::new();
    for r in rows {
        list.push(r.map_err(|e| format!("[DATABASE] ROW_FETCH_FAILED: {}", e))?);
    }
    Ok(list)
}

// ───────────────────────── Text-expansion snippets ─────────────────────────
// A trigger word the user types in any terminal, followed by Space/Tab/Enter,
// is replaced in place with its expansion before the delimiter reaches the
// remote shell (TerminalView does the actual swap client-side — this is just
// storage). `trigger_text` is UNIQUE so two snippets can never race for the
// same trigger; the INSERT/UPDATE error on a collision is mapped to a plain
// message rather than the raw SQLite constraint text.

fn map_snippet_write_error(e: rusqlite::Error, verb: &str) -> String {
    if let rusqlite::Error::SqliteFailure(_, Some(msg)) = &e {
        if msg.contains("UNIQUE constraint failed") {
            return "A snippet with that trigger already exists.".into();
        }
    }
    format!("[DATABASE] SNIPPET_{}_FAILED: {}", verb, e)
}

#[tauri::command]
async fn add_snippet(state: tauri::State<'_, DbState>, trigger: String, expansion: String) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;

    conn.execute(
        "INSERT INTO snippets (trigger_text, expansion_text) VALUES (?1, ?2)",
        rusqlite::params![trigger, expansion],
    ).map_err(|e| map_snippet_write_error(e, "INSERT"))?;

    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn edit_snippet(state: tauri::State<'_, DbState>, id: i32, trigger: String, expansion: String) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;

    conn.execute(
        "UPDATE snippets SET trigger_text=?1, expansion_text=?2 WHERE id=?3",
        rusqlite::params![trigger, expansion, id],
    ).map_err(|e| map_snippet_write_error(e, "UPDATE"))?;

    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn delete_snippet(state: tauri::State<'_, DbState>, id: i32) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;

    conn.execute(
        "DELETE FROM snippets WHERE id=?1",
        rusqlite::params![id],
    ).map_err(|e| format!("[DATABASE] SNIPPET_DELETE_FAILED: {}", e))?;

    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn get_snippets(state: tauri::State<'_, DbState>) -> Result<Vec<serde_json::Value>, String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    let mut stmt = conn.prepare("SELECT id, trigger_text, expansion_text FROM snippets").map_err(|e| e.to_string())?;

    let rows = stmt.query_map([], |row| {
        Ok(json!({
            "id": row.get::<_, i32>(0)?,
            "trigger": row.get::<_, String>(1)?,
            "expansion": row.get::<_, String>(2)?
        }))
    }).map_err(|e| e.to_string())?;

    let mut list = Vec::new();
    for r in rows {
        list.push(r.map_err(|e| format!("[DATABASE] ROW_FETCH_FAILED: {}", e))?);
    }
    Ok(list)
}

// ───────────────────────── Command History ─────────────────────────
// Ctrl+R-style rolling log of commands the user typed into any terminal.
// Populated best-effort by TerminalView (buffered keystrokes → Enter →
// insert). Read by HistorySearchOverlay through the three commands below.
// Capped at 1000 rows — dropping the oldest — so a chatty user can't blow
// the vault size up over months of use.

const CMD_HISTORY_CAP: i64 = 1000;

#[tauri::command]
async fn cmd_history_add(
    state: tauri::State<'_, DbState>,
    server_id: Option<i32>,
    server_name: String,
    command: String,
) -> Result<i64, String> {
    let trimmed = command.trim().to_string();
    if trimmed.is_empty() {
        return Err("[HISTORY] EMPTY_COMMAND".into());
    }
    let ts: i64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;

    // De-dupe against the immediately-previous row for the same server so a
    // user re-running `ls` five times in a row doesn't fill five slots. Match
    // by (server_id, command); leave older reruns alone so search still finds
    // "ran this yesterday morning too".
    let last: Option<(i64, String, Option<i32>)> = conn.query_row(
        "SELECT id, command, server_id FROM cmd_history ORDER BY ts DESC LIMIT 1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<i32>>(2)?)),
    ).ok();
    if let Some((id, prev_cmd, prev_sid)) = last {
        if prev_cmd == trimmed && prev_sid == server_id {
            // Refresh the timestamp on the existing row instead of writing a
            // duplicate — keeps the "most recent first" ordering honest.
            let _ = conn.execute(
                "UPDATE cmd_history SET ts = ?1 WHERE id = ?2",
                rusqlite::params![ts, id],
            );
            return Ok(id);
        }
    }

    conn.execute(
        "INSERT INTO cmd_history (server_id, server_name, command, ts) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![server_id, server_name, trimmed, ts],
    ).map_err(|e| format!("[DATABASE] CMD_HISTORY_INSERT_FAILED: {}", e))?;

    let new_id = conn.last_insert_rowid();

    // Prune the tail so the table stays bounded. LIMIT/OFFSET in a subquery
    // gives us "keep the newest N, drop everything older".
    let _ = conn.execute(
        "DELETE FROM cmd_history WHERE id IN (
            SELECT id FROM cmd_history ORDER BY ts DESC LIMIT -1 OFFSET ?1
        )",
        rusqlite::params![CMD_HISTORY_CAP],
    );

    // History isn't secret but the encrypted vault is the only place it can
    // land; we DO NOT call save_vault_internal on every keystroke — that'd
    // fsync per command and thrash disk. The next save_vault_* call (any
    // node edit, key add, etc., or profile-close teardown) picks it up.
    Ok(new_id)
}

#[tauri::command]
async fn cmd_history_list(
    state: tauri::State<'_, DbState>,
    query: Option<String>,
    limit: Option<u32>,
    server_id: Option<i32>,
) -> Result<Vec<serde_json::Value>, String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    let lim = limit.unwrap_or(200).min(1000) as i64;
    cmd_history_rows(conn, query.as_deref().unwrap_or_default(), lim, server_id)
}

/// The newest `limit` history rows whose command contains `query` (all when
/// empty), of one server only when `server_id` is given. The server is
/// filtered here, not by the caller after the fact, or a server's older rows
/// would hide behind the newest rows of every other server.
fn cmd_history_rows(conn: &Connection, query: &str, limit: i64, server_id: Option<i32>) -> Result<Vec<serde_json::Value>, String> {
    // Escape LIKE metacharacters (%, _, backslash) so the user's raw input
    // matches literally. Uses `\` as the escape character.
    let escaped = query
        .trim()
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    let like = format!("%{}%", escaped);
    let mut stmt = conn.prepare(
        "SELECT id, server_id, server_name, command, ts, exit_code
         FROM cmd_history
         WHERE command LIKE ?1 ESCAPE '\\' AND (?3 IS NULL OR server_id = ?3)
         ORDER BY ts DESC LIMIT ?2"
    ).map_err(|e| format!("[DATABASE] CMD_HISTORY_PREP_FAILED: {}", e))?;
    let mapped = stmt.query_map(rusqlite::params![like, limit, server_id], |row| {
        Ok(json!({
            "id": row.get::<_, i64>(0)?,
            "server_id": row.get::<_, Option<i32>>(1)?,
            "server_name": row.get::<_, Option<String>>(2)?,
            "command": row.get::<_, String>(3)?,
            "ts": row.get::<_, i64>(4)?,
            "exit_code": row.get::<_, Option<i32>>(5)?,
        }))
    }).map_err(|e| format!("[DATABASE] CMD_HISTORY_QUERY_FAILED: {}", e))?;
    let mut out = Vec::new();
    for r in mapped {
        out.push(r.map_err(|e| format!("[DATABASE] CMD_HISTORY_ROW_FAILED: {}", e))?);
    }
    Ok(out)
}

#[tauri::command]
async fn cmd_history_clear(state: tauri::State<'_, DbState>) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    conn.execute("DELETE FROM cmd_history", [])
        .map_err(|e| format!("[DATABASE] CMD_HISTORY_CLEAR_FAILED: {}", e))?;
    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

// ───────────────────────── Notes ─────────────────────────
// Free-form text notes stored alongside the rest of the profile. Mirrors the
// commands CRUD shape exactly — title + body, no FK, no timestamps. Search
// is done client-side over the returned list so the user can match against
// title and body in one go without us pushing a LIKE query through SQLite.

#[tauri::command]
async fn add_note(state: tauri::State<'_, DbState>, title: String, body: String) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;

    conn.execute(
        "INSERT INTO notes (title, body) VALUES (?1, ?2)",
        rusqlite::params![title, body],
    ).map_err(|e| format!("[DATABASE] NOTE_INSERT_FAILED: {}", e))?;

    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn edit_note(state: tauri::State<'_, DbState>, id: i32, title: String, body: String) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;

    conn.execute(
        "UPDATE notes SET title=?1, body=?2 WHERE id=?3",
        rusqlite::params![title, body, id],
    ).map_err(|e| format!("[DATABASE] NOTE_UPDATE_FAILED: {}", e))?;

    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn delete_note(state: tauri::State<'_, DbState>, id: i32) -> Result<(), String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;

    conn.execute(
        "DELETE FROM notes WHERE id=?1",
        rusqlite::params![id],
    ).map_err(|e| format!("[DATABASE] NOTE_DELETE_FAILED: {}", e))?;

    drop(conn_guard);
    save_vault_internal(&state)?;
    Ok(())
}

#[tauri::command]
async fn get_notes(state: tauri::State<'_, DbState>) -> Result<Vec<serde_json::Value>, String> {
    let conn_guard = state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
    let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
    // Newest first — matches how users think about notes (last-touched up top).
    let mut stmt = conn.prepare("SELECT id, title, body FROM notes ORDER BY id DESC").map_err(|e| e.to_string())?;

    let rows = stmt.query_map([], |row| {
        Ok(json!({
            "id": row.get::<_, i32>(0)?,
            "title": row.get::<_, String>(1)?,
            "body": row.get::<_, String>(2)?
        }))
    }).map_err(|e| e.to_string())?;

    let mut list = Vec::new();
    for r in rows {
        list.push(r.map_err(|e| format!("[DATABASE] ROW_FETCH_FAILED: {}", e))?);
    }
    Ok(list)
}

/// A TCP port from the UI or the vault, as the `u16` it must be. Out-of-range
/// values used to be truncated with `as u16` (65536 became port 0, 70022 port
/// 4486), connecting somewhere the user never typed.
fn checked_port(value: i32, what: &str) -> Result<u16, String> {
    u16::try_from(value)
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| format!("{} must be between 1 and 65535 (got {})", what, value))
}

/// The proxy port to store: checked when a proxy is in use; otherwise an
/// unusable leftover from the form is replaced by the default.
fn checked_proxy_port(proxy_type: &str, proxy_port: i32) -> Result<i32, String> {
    match proxy_type {
        "socks5" | "http" => checked_port(proxy_port, "Proxy port").map(i32::from),
        _ => Ok(if checked_port(proxy_port, "Proxy port").is_ok() { proxy_port } else { 1080 }),
    }
}

/// One-shot inline auth bundle for "quick connect" — connecting to a host
/// without saving anything in the vault. Mirrors the subset of node fields
/// that the connection flow actually needs: address, identity, and either
/// a password or a PEM key body. Proxy + tunnel auto-start are deliberately
/// omitted; the user can save a real node if they need those.
#[derive(Debug, Clone, serde::Deserialize)]
struct QuickAuth {
    host: String,
    port: i32,
    username: String,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    passphrase: Option<String>,
}

/// Relays keyboard-interactive rounds (2FA / verification codes, RFC 4256)
/// to the session's UI as `kbi-prompt-{session_id}` and waits for
/// `submit_kbi_response` with this attempt's nonce. The bounds and round caps
/// live in `ssh_connect::authenticate`.
struct UiKbiPrompter<'a> {
    app: &'a tauri::AppHandle,
    session_id: &'a str,
    nonce: &'a str,
    /// The host asking: the dialog names it (F-079).
    host: &'a str,
    kbi_txs: &'a ssh_manager::KbiTxs,
}

/// A question on screen. Dropped before the answer (the wait timed out, the
/// attempt ended), it takes the question down and its nonce out of the map.
struct KbiPending {
    app: tauri::AppHandle,
    session_id: String,
    nonce: String,
    kbi_txs: ssh_manager::KbiTxs,
    armed: bool,
}

impl Drop for KbiPending {
    fn drop(&mut self) {
        use tauri::Emitter;
        if !self.armed {
            return;
        }
        let _ = self.app.emit(&format!("kbi-prompt-dismiss-{}", self.session_id), json!({ "nonce": self.nonce }));
        let kbi_txs = std::sync::Arc::clone(&self.kbi_txs);
        let nonce = std::mem::take(&mut self.nonce);
        tauri::async_runtime::spawn(async move {
            kbi_txs.lock().await.remove(&nonce);
        });
    }
}

impl ssh_connect::KbiPrompter for UiKbiPrompter<'_> {
    fn ask(&self, round: ssh_connect::KbiRound) -> impl std::future::Future<Output = Option<Vec<String>>> + Send {
        async move {
            use tauri::Emitter;
            let (tx, rx) = tokio::sync::oneshot::channel::<Option<Vec<String>>>();
            self.kbi_txs.lock().await.insert(self.nonce.to_string(), tx);
            let mut pending = KbiPending {
                app: self.app.clone(),
                session_id: self.session_id.to_string(),
                nonce: self.nonce.to_string(),
                kbi_txs: std::sync::Arc::clone(self.kbi_txs),
                armed: true,
            };
            let prompts: Vec<serde_json::Value> =
                round.prompts.iter().map(|(prompt, echo)| json!({ "prompt": prompt, "echo": echo })).collect();
            let _ = self.app.emit(
                &format!("kbi-prompt-{}", self.session_id),
                json!({
                    "nonce": self.nonce,
                    "host": self.host,
                    "name": round.name,
                    "instructions": round.instructions,
                    "prompts": prompts,
                }),
            );
            let answer = rx.await.ok().flatten();
            pending.armed = false;
            self.kbi_txs.lock().await.remove(self.nonce);
            let _ = self.app.emit(&format!("kbi-prompt-dismiss-{}", self.session_id), json!({ "nonce": self.nonce }));
            answer
        }
    }
}

/// Why a connection attempt failed, for the `connection-failed` event.
struct ConnectFailure {
    reason: String,
    kind: ConnectErrorKind,
}

impl ConnectFailure {
    /// A setting or saved item problem (missing login, bad port, ...).
    fn config(reason: impl Into<String>) -> Self {
        ConnectFailure { reason: reason.into(), kind: ConnectErrorKind::Config }
    }
}

/// Turns the ladder's failure into what the UI is told. `who` prefixes the
/// reason ("jump host ...") when it is not the target that failed.
fn auth_failure(failure: ssh_connect::AuthFailure, target: &str) -> ConnectFailure {
    match failure {
        ssh_connect::AuthFailure::Refused(reason) | ssh_connect::AuthFailure::Unanswerable(reason) => {
            ConnectFailure { reason, kind: ConnectErrorKind::Auth }
        }
        ssh_connect::AuthFailure::TimedOut(reason) => ConnectFailure { reason, kind: ConnectErrorKind::Timeout },
        ssh_connect::AuthFailure::Ssh(e) => {
            let kind = classify_russh_error(&e);
            ConnectFailure { reason: format!("{} (raw: {})", describe_error_kind(kind, target), e), kind }
        }
    }
}

/// The key a server is set to log in with, decoded. A key that cannot be
/// read is logged and reported at the end if nothing else logs in.
fn decode_login_key(
    key_data: Option<(String, Option<String>)>,
    log: &dyn Fn(&str, &str),
) -> (Option<std::sync::Arc<russh::keys::PrivateKey>>, Option<String>) {
    let Some((private_key, passphrase)) = key_data else {
        return (None, None);
    };
    match russh::keys::decode_secret_key(&private_key.replace("\r\n", "\n"), passphrase.as_deref()) {
        Ok(key) => (Some(std::sync::Arc::new(key)), None),
        Err(e) => {
            log(&format!("Failed to parse private key: {}", e), "error");
            (None, Some(format!("The private key could not be read ({}). Check the key and its passphrase.", e)))
        }
    }
}

/// OS-level TCP keepalive on an SSH transport socket. Complements the SSH
/// protocol keepalive (`keepalive_interval` below): russh 0.40 has no
/// `keepalive_max`, so an unanswered protocol keepalive never tears the
/// connection down — but with TCP keepalive the kernel itself probes an idle
/// peer (30s idle, then every 10s) and errors the socket when the peer is
/// truly gone, which russh's run loop surfaces as `is_closed()`. That gives
/// dead-link detection during long-idle periods without any SSH traffic, and
/// keeps NAT/firewall mappings warm on flaky consumer networks. Best-effort:
/// failure to set it is never a reason to abort a connect. (`with_retries`
/// is deliberately not used — socket2 doesn't support it on Windows.)
fn apply_tcp_keepalive(stream: &tokio::net::TcpStream) {
    use socket2::{SockRef, TcpKeepalive};
    let ka = TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(30))
        .with_interval(std::time::Duration::from_secs(10));
    let _ = SockRef::from(stream).set_tcp_keepalive(&ka);
}

/// Why a saved server can't log in with what is on file any more, if that is
/// the case. Deleting a saved login or key sets the reference to NULL (schema 4)
/// but leaves `auth_type` alone, so "needs one, has none" is how a deletion shows
/// up. Without this the connect path would try without a key and report
/// "Authentication rejected by server", which sends the user to the wrong place.
/// `key_found`: the key the mode needs was loaded.
fn missing_identity_reason(
    server_auth_type: &str,
    credential_found: bool,
    cred_auth_type: Option<&str>,
    key_found: bool,
) -> Option<&'static str> {
    match server_auth_type {
        "vault" if !credential_found => Some("This server uses a saved login, but none is set (it may have been deleted). Edit the server and pick one."),
        "vault" if cred_auth_type == Some("key") && !key_found => Some("The saved login this server uses has no SSH key any more (it was deleted). Edit the login and pick a key."),
        "custom_key" if !key_found => Some("This server is set to use an SSH key, but none is set (it may have been deleted). Edit the server and pick a key."),
        _ => None,
    }
}

/// Minimal auth/identity resolver for a ProxyJump bastion. Mirrors the
/// vault-vs-custom / credential-join / key-loading rules of the main connect
/// path but returns only what a jump hop needs (host, port, user, password,
/// optional key). Deliberately kept separate from `initiate_connection`'s
/// inline resolver so the primary connection path is byte-for-byte untouched.
/// It never reads `jump_host_id`, which makes ProxyJump strictly single-hop —
/// there is no way for it to recurse.
///
/// Runs fully synchronously (no `.await`) so the non-`Send` rusqlite
/// `Connection` never has to be held across a suspension point.
/// What a ProxyJump hop needs to log in to the bastion.
struct JumpIdentity {
    host: String,
    port: i32,
    user: String,
    password: Option<String>,
    /// Private key text and passphrase.
    key: Option<(String, Option<String>)>,
    /// The bastion's own "Allow legacy algorithms" setting.
    legacy_algorithms: bool,
}

fn resolve_jump_auth(conn: &rusqlite::Connection, server_id: i32) -> Result<Option<JumpIdentity>, String> {
    let mut stmt = conn
        .prepare(
            "
            SELECT s.host, s.port,
                   s.username as s_user, c.username as c_user,
                   s.password as s_pass, c.password as c_pass,
                   s.key_id   as s_key,  c.key_id   as c_key,
                   s.auth_type, c.auth_type as cred_auth_type, c.id,
                   s.legacy_algorithms
            FROM servers s
            LEFT JOIN credentials c ON s.credential_id = c.id
            WHERE s.id=?1
        ",
        )
        .map_err(|e| e.to_string())?;
    let mut rows = stmt.query([server_id]).map_err(|e| e.to_string())?;
    let row = match rows.next().map_err(|e| e.to_string())? {
        Some(r) => r,
        None => return Ok(None),
    };
    let host: String = row.get::<_, String>(0).map_err(|e| format!("[DB] jump host: {}", e))?;
    let port: i32 = row.get::<_, i32>(1).map_err(|e| format!("[DB] jump port: {}", e))?;
    let s_user: Option<String> = row.get::<_, Option<String>>(2).unwrap_or_default();
    let c_user: Option<String> = row.get::<_, Option<String>>(3).unwrap_or_default();
    let s_pass: Option<String> = row.get::<_, Option<String>>(4).unwrap_or_default();
    let c_pass: Option<String> = row.get::<_, Option<String>>(5).unwrap_or_default();
    let s_key: Option<i32> = row.get::<_, Option<i32>>(6).unwrap_or_default();
    let c_key: Option<i32> = row.get::<_, Option<i32>>(7).unwrap_or_default();
    let server_auth_type: String = row
        .get::<_, Option<String>>(8)
        .unwrap_or_default()
        .unwrap_or_else(|| "vault".to_string());
    let cred_auth_type: Option<String> = row.get::<_, Option<String>>(9).unwrap_or_default();
    let credential_found = row.get::<_, Option<i32>>(10).unwrap_or_default().is_some();
    let legacy_algorithms = row.get::<_, i64>(11).map_err(|e| format!("[DB] jump legacy_algorithms: {}", e))? != 0;

    let (username, password, key_id) = if server_auth_type == "vault" {
        (c_user.unwrap_or_default(), c_pass, c_key)
    } else {
        (s_user.unwrap_or_default(), s_pass, s_key)
    };
    let effective_key_id = if server_auth_type == "vault" {
        if cred_auth_type.as_deref() == Some("key") { key_id } else { None }
    } else if server_auth_type == "custom_key" {
        key_id
    } else {
        None
    };
    let key_data = if let Some(kid) = effective_key_id {
        let mut key_stmt = conn
            .prepare("SELECT private_key, passphrase FROM ssh_keys WHERE id = ?1")
            .map_err(|e| e.to_string())?;
        let mut key_rows = key_stmt.query([kid]).map_err(|e| e.to_string())?;
        if let Some(key_row) = key_rows.next().map_err(|e| e.to_string())? {
            let private_key: String = key_row.get::<_, String>(0).map_err(|e| e.to_string())?;
            let passphrase: Option<String> = key_row.get::<_, Option<String>>(1).map_err(|e| e.to_string())?;
            Some((private_key, passphrase))
        } else {
            None
        }
    } else {
        None
    };

    if let Some(reason) = missing_identity_reason(&server_auth_type, credential_found, cred_auth_type.as_deref(), key_data.is_some()) {
        return Err(format!("Jump host: {}", reason));
    }

    Ok(Some(JumpIdentity { host, port, user: username, password, key: key_data, legacy_algorithms }))
}

/// Establish + authenticate an SSH connection to a ProxyJump intermediate
/// ("bastion") host and return its live `Handle`. The caller opens a
/// `direct-tcpip` channel over this handle to reach the real target, then keeps
/// the handle alive for the target session's lifetime (see
/// `SshState::jump_connections`).
///
/// The bastion is reached by a DIRECT TCP connection — its own proxy config, if
/// any, is not honored (bastions are normally directly reachable). Its host key
/// is verified through the SAME frontend prompt as the target (events emitted
/// under the target's `session_id`, keyed by a distinct nonce), and it supports
/// the full key → password → keyboard-interactive auth ladder.
async fn connect_jump_host(
    app: &tauri::AppHandle,
    db: &std::sync::Arc<std::sync::Mutex<Option<rusqlite::Connection>>>,
    fp_txs: &std::sync::Arc<
        tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<bool>>>,
    >,
    kbi_txs: &ssh_manager::KbiTxs,
    session_id: &str,
    jump_server_id: i32,
    // Host-key and keyboard-interactive questions need the session's UI; a
    // dedicated SFTP/forwarding connection has none (see `allow_kbi` in
    // initiate_connection), so it is refused instead of waiting on them.
    interactive: bool,
) -> Result<russh::client::Handle<ssh_manager::ClientHandler>, ConnectFailure> {
    use tauri::Emitter;

    let log = |msg: &str, ty: &str| {
        dev_log!("[LOG-{}] [jump] {}", session_id, msg);
        let _ = app.emit(
            &format!("session-log-{}", session_id),
            serde_json::json!({"msg": msg, "type": ty}),
        );
    };

    // 1. Resolve the bastion's config synchronously and drop the DB guard
    //    before any await (rusqlite Connection is not Send).
    let (jump, known_key_types) = {
        let guard = db.lock().map_err(|_| ConnectFailure::config("[STATE] LOCK_FAILED"))?;
        let conn = guard
            .as_ref()
            .ok_or_else(|| ConnectFailure::config("[STATE] DATABASE_NOT_INITIALIZED"))?;
        let jump = match resolve_jump_auth(conn, jump_server_id).map_err(ConnectFailure::config)? {
            Some(v) => v,
            None => return Err(ConnectFailure::config("jump host not found")),
        };
        let port = checked_port(jump.port, "Jump host port").map_err(ConnectFailure::config)?;
        // Unreadable here means unreadable in the host-key check too, which
        // then refuses the connection; the order alone is not worth failing on.
        let known = ssh_manager::known_key_types(conn, &jump.host, port).unwrap_or_default();
        (jump, known)
    };
    let JumpIdentity { host, port, user, password, key: key_data, legacy_algorithms } = jump;
    let policy = ssh_connect::AlgorithmPolicy { legacy: legacy_algorithms, known_key_types };
    let effective_user = if user.trim().is_empty() {
        "root".to_string()
    } else {
        user.trim().to_string()
    };
    let port_u16 = checked_port(port, "Jump host port").map_err(ConnectFailure::config)?;

    // 2. Direct TCP to the bastion.
    log(&format!("Connecting to jump host {}:{}...", host, port), "info");
    let tcp = match ssh_connect::connect_tcp(&host, port_u16).await {
        Ok(s) => {
            let _ = s.set_nodelay(true);
            apply_tcp_keepalive(&s);
            s
        }
        Err(e) => {
            let kind = match e {
                ssh_connect::TcpConnectError::TimedOut { .. } => ConnectErrorKind::Timeout,
                _ => ConnectErrorKind::Unreachable,
            };
            return Err(ConnectFailure { reason: describe_tcp_failure(e, &host, port, "Jump host connection"), kind });
        }
    };

    // 3. Host-key round-trip: own nonce, shared fp_txs map + frontend session.
    let (fp_tx, fp_rx) = tokio::sync::oneshot::channel();
    let jump_nonce: String = {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill(&mut bytes);
        hex::encode(bytes)
    };
    fp_txs.lock().await.insert(jump_nonce.clone(), fp_tx);
    let fp_outcome = std::sync::Arc::new(ssh_manager::OutcomeCell::default());
    let (prompt_tx, prompt_rx) = tokio::sync::watch::channel(false);

    let handler = ssh_manager::ClientHandler {
        app: app.clone(),
        session_id: session_id.to_string(),
        connect_nonce: jump_nonce.clone(),
        server_host: host.clone(),
        server_port: port_u16,
        db: std::sync::Arc::clone(db),
        fp_rx: interactive.then_some(fp_rx),
        forwarded_targets: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        fp_outcome: std::sync::Arc::clone(&fp_outcome),
        prompt_open: std::sync::Arc::new(prompt_tx),
        weak_reported: false,
        accepted_key: Arc::new(std::sync::Mutex::new(None)),
        legacy_algorithms: policy.legacy,
        // A hop only carries the target's connection: nothing here reads these.
        channel_gate: Arc::default(),
        ended_because: Arc::default(),
    };

    // 4. Handshake. Its clock stops while the host-key prompt is open.
    let config = std::sync::Arc::new(ssh_connect::build_ssh_client_config(&policy));
    log("Jump host: SSH handshake...", "info");
    let connect_res = ssh_connect::handshake_within(
        russh::client::connect_stream(config, tcp, handler),
        ssh_connect::HANDSHAKE_BUDGET,
        ssh_connect::AFTER_PROMPT_GRACE,
        prompt_rx,
    )
    .await;
    // The host-key prompt (if any) is resolved by now — drop the sender.
    fp_txs.lock().await.remove(&jump_nonce);

    let mut session = match connect_res {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return Err(match (fp_outcome.get().refusal(), ssh_connect::legacy_only_offer(&e)) {
                (Some(reason), _) => ConnectFailure {
                    reason: format!("jump host {}:{}: {}", host, port, reason),
                    kind: ConnectErrorKind::HostKey,
                },
                (None, Some(names)) => ConnectFailure {
                    reason: format!(
                        "jump host {}:{} offers only legacy algorithms ({}). If you trust it, turn on \u{201c}Allow legacy algorithms\u{201d} in the jump host's settings.",
                        host, port, names.join(", ")
                    ),
                    kind: ConnectErrorKind::Algorithm,
                },
                (None, None) => {
                    let kind = classify_russh_error(&e);
                    ConnectFailure { reason: format!("jump host handshake failed: {}", e), kind }
                }
            })
        }
        Err(_) => {
            return Err(ConnectFailure {
                reason: format!(
                    "jump host {}:{} did not finish the SSH handshake within {} seconds (time spent on the fingerprint prompt not counted)",
                    host, port, ssh_connect::HANDSHAKE_BUDGET.as_secs()
                ),
                kind: ConnectErrorKind::Timeout,
            })
        }
    };

    // 5. Log in: key, password, keyboard-interactive (bounded; see
    //    ssh_connect::authenticate). Its questions name the jump host.
    let key_login = key_data.is_some();
    let (key, key_problem) = decode_login_key(key_data, &log);
    let creds = ssh_connect::Credentials {
        key_login,
        key,
        key_problem,
        password: if key_login { None } else { password },
        // The failed-connection password box is for the target, not the hop.
        password_can_be_typed: false,
        allow_sha1_rsa: policy.legacy,
    };
    let prompter = UiKbiPrompter { app, session_id, nonce: &jump_nonce, host: &host, kbi_txs };
    let result = ssh_connect::authenticate(
        &mut session,
        &effective_user,
        creds,
        interactive.then_some(&prompter),
        ssh_connect::AuthLimits::default(),
        &log,
    )
    .await;
    // Belt-and-suspenders: no dangling interactive sender for this hop.
    kbi_txs.lock().await.remove(&jump_nonce);

    match result {
        Ok(()) => {
            log("Jump host authenticated.", "success");
            Ok(session)
        }
        Err(failure) => {
            let target = format!("jump host {}:{}", host, port);
            let ConnectFailure { reason, kind } = auth_failure(failure, &target);
            Err(ConnectFailure { reason: format!("jump host {}:{}: {}", host, port, reason), kind })
        }
    }
}

/// Reports a failed connection attempt. A host-key or keyboard-interactive
/// prompt of the attempt that is still on screen is closed first: nothing
/// would read its answer any more (F-026). `is_auth_error` makes the UI offer
/// its password box; `retry` false stops auto-reconnect (F-030): a refused
/// host key or login, or a setting problem, would only fail again, and a
/// changed-key prompt shown over and over invites a click-through.
fn emit_connection_failed(app: &tauri::AppHandle, session_id: &str, reason: &str, kind: ConnectErrorKind) {
    use tauri::Emitter;
    let _ = app.emit(&format!("fingerprint-prompt-dismiss-{}", session_id), json!({}));
    let _ = app.emit(&format!("kbi-prompt-dismiss-{}", session_id), json!({}));
    let _ = app.emit(
        &format!("connection-failed-{}", session_id),
        json!({ "reason": reason, "is_auth_error": kind.is_auth(), "retry": kind.retry() }),
    );
}

/// Reports the failure of connect attempt `generation` unless a newer attempt
/// (a reconnect) or a teardown has superseded it: the UI then shows the newer
/// attempt, whose prompts a stale failure would close.
async fn report_connection_failed(
    app: &tauri::AppHandle,
    generations: &std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, u64>>>,
    session_id: &str,
    generation: u64,
    reason: &str,
    kind: ConnectErrorKind,
) {
    let current = generations.lock().await.get(session_id).copied().unwrap_or(0) == generation;
    if current {
        emit_connection_failed(app, session_id, reason, kind);
    }
}

/// Fully tear down ONE connection map-entry by its exact key. Used to reap the
/// dedicated `::sftp` / `::fwd` secondary connections the separate-sessions
/// feature spins up, so disconnecting or reconnecting the PRIMARY never orphans
/// them (a leaked secondary would hold a live TCP + SSH session forever). Safe
/// to call on a key that doesn't exist — every step is then a no-op. Bumps the
/// key's generation so the secondary's own health watcher observes the change on
/// its next tick and bows out WITHOUT emitting a `session-disconnected-{key}`.
async fn teardown_connection_key(state: &SshState, mirrors: &MirrorMap, key: &str) {
    // Bump the generation FIRST — before removing the connection — so a connect
    // worker for this key that's still handshaking observes the newer value at
    // its "still wanted?" registration guard and bails instead of registering a
    // zombie. (Worker holds the generation lock across its check+insert, and we
    // bump-then-remove here, so the two orderings can't leave a stray entry.)
    {
        let mut g = state.session_generation.lock().await;
        let next = g.get(key).copied().unwrap_or(0).wrapping_add(1);
        g.insert(key.to_string(), next);
    }
    // Stop forwarders first so their listener sockets release before the SSH
    // handle drops — same ordering rationale as disconnect_session.
    tunnel::stop_all_for_session(&state.tunnels, key).await;
    state.forwarded_targets.lock().await.remove(key);
    state.session_tunnel_specs.lock().await.remove(key);
    mirror::stop_all_for_session(mirrors, key).await;
    state.docker_streams.stop_session(key).await;
    state.info_probes.lock().await.remove(key);
    state.sftp_sessions.lock().await.remove(key);
    // The base session's cached SFTP subsystem may be riding this dedicated
    // `::sftp` transport — drop it so the next file op re-opens on whatever
    // transport remains instead of erroring on a closed channel.
    if let Some(base) = key.strip_suffix("::sftp") {
        state.sftp_sessions.lock().await.remove(base);
    }
    let removed = state.connections.lock().await.remove(key);
    state.session_targets.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(key);
    state.channel_gates.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(key);
    let removed_jump = state.jump_connections.lock().await.remove(key);
    // Live edits are opened under the base session id, so this is normally
    // a no-op; it keeps the rule "a key's teardown ends its live edits".
    state.live_edits.stop_session(key, live_edit::StopReason::Disconnected);
    // Ended explicitly: a channel something still holds would keep it up.
    let ended: Vec<_> = removed.into_iter().chain(removed_jump.map(|h| Arc::new(tokio::sync::Mutex::new(h)))).collect();
    ssh_connect::close_handles(ended, ssh_connect::CLOSE_TIMEOUT).await;
}

#[tauri::command]
async fn initiate_connection(
    app: tauri::AppHandle,
    state: tauri::State<'_, SshState>,
    db_state: tauri::State<'_, DbState>,
    mirrors: tauri::State<'_, MirrorMap>,
    session_id: String,
    server_id: i32,
    custom_password: Option<String>,
    quick_auth: Option<QuickAuth>,
    // Separate-sessions feature (default OFF). `session_role` marks whether this
    // is the primary terminal connection ("primary", the default) or a dedicated
    // secondary connection carved off for SFTP ("sftp") or port-forwarding
    // ("forward"). `separate_sessions` is only meaningful on the PRIMARY call: it
    // tells the primary to NOT auto-start the saved tunnels itself, because the
    // dedicated "forward" connection (opened by the frontend right after) will.
    // See the connection topology notes near the auth block below.
    session_role: Option<String>,
    separate_sessions: Option<bool>,
) -> Result<(), String> {
    use tauri::Emitter;
    use tokio::time::Duration;
    use russh::client;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Connection role + topology flags. Kept as plain locals so the whole
    // function (worker included) can branch on them without re-parsing.
    let role: String = session_role
        .as_deref()
        .map(str::to_string)
        .unwrap_or_else(|| "primary".to_string());
    let is_secondary = role != "primary";
    let separate = separate_sessions.unwrap_or(false);
    // Only the PRIMARY asks the user anything (host-key prompt, keyboard-
    // interactive / 2FA questions). A secondary connection's prompt would go
    // to a suffixed session id the UI isn't wired to answer, so it would just
    // hang. Instead the secondary fails at once and the frontend falls back
    // to routing SFTP / forwarding over the primary connection.
    let allow_kbi = !is_secondary;
    // Which connection auto-starts this server's saved tunnels inline:
    //   - primary + shared mode    → yes (unchanged legacy behaviour)
    //   - primary + separate mode  → no  (the "forward" connection takes over)
    //   - "forward" secondary      → never inline; it runs the MIGRATION block
    //     instead (stop anything running under the base tag, then restart the
    //     full replay list on itself, still tagged under the base session id)
    //   - "sftp" secondary         → no
    let start_tunnels_inline = role == "primary" && !separate;
    // A lock that begins before this connection registers makes it drop
    // itself; while one runs, nothing new connects.
    let epoch = state.epoch();
    if epoch.closing() {
        return Err(ssh_manager::PROFILE_CLOSING_MSG.into());
    }

    dev_log!("[BACKEND] initiate_connection invoked for session_id: {} (role: {}, separate: {}), server_id: {}", session_id, role, separate, server_id);

    // Reconnect path: if a previous session under this id is still registered,
    // tear it down before starting the fresh handshake. Without this, the
    // duplicate-detection early-return below would silently drop every
    // reconnect attempt and the UI would just sit on "connecting…" forever.
    // Tunnels + forwarded_targets get the same treatment further down via the
    // stop_all_for_session call, so we don't duplicate that here.
    let stale = {
        state.session_targets.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&session_id);
        let mut conns = state.connections.lock().await;
        let stale = conns.remove(&session_id);
        if stale.is_some() {
            dev_log!("[BACKEND] Tearing down stale session for reconnect: {}", session_id);
        }
        stale
    };
    state.channel_gates.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&session_id);
    // Drop any ProxyJump bastion handle from a prior attempt — dropping it
    // closes the old jump connection so the reconnect opens a fresh one.
    let stale_jump = state.jump_connections.lock().await.remove(&session_id);
    state.sftp_sessions.lock().await.remove(&session_id);
    // A dedicated `::sftp` transport being replaced: the base session's cached
    // SFTP subsystem rides it and would keep reaching the old server until
    // the new one registers (N-012).
    if let Some(base) = session_id.strip_suffix("::sftp") {
        state.sftp_sessions.lock().await.remove(base);
    }
    // Terminal IDs are `${session_id}-term-N` (see SessionView.tsx), so we
    // sweep every PTY task tied to the old handle. Match by the exact
    // `${session_id}-term-` prefix so id `session-1` doesn't sweep the
    // terminals of `session-10`, `session-11`, ... — a `contains`-based
    // match here silently tore down unrelated live sessions once server
    // IDs (which are SQLite autoincrement ints) crossed 10.
    let term_prefix = format!("{}-term-", session_id);
    let closed_terminals = {
        let mut txs = state.terminal_txs.lock().await;
        let before = txs.len();
        txs.retain(|k, _| !k.starts_with(&term_prefix));
        before - txs.len()
    };
    state.resize_txs.lock().await.retain(|k, _| !k.starts_with(&term_prefix));
    // These closes start here, in Solanum, and the server only sees a client
    // logging out: say so, or a reconnect looks as if the server dropped them.
    // The connection may be gone from the map already (the health watcher gave
    // up on it) with its terminals still open. `activity`: the session's log
    // window shows only during a first connection.
    if stale.is_some() || closed_terminals > 0 {
        let _ = app.emit(
            &format!("session-log-{}", session_id),
            json!({
                "msg": format!("Reconnecting: Solanum is closing the previous connection and its open terminals ({}).", closed_terminals),
                "type": "warn",
                "activity": true
            }),
        );
    }
    // Bump the generation so any watcher task still alive from the prior
    // attempt sees a newer value next tick and bails silently instead of
    // racing the new connect to emit `session-disconnected-{id}`.
    let connect_generation: u64 = {
        let mut g = state.session_generation.lock().await;
        let next = g.get(&session_id).copied().unwrap_or(0).wrapping_add(1);
        g.insert(session_id.clone(), next);
        next
    };
    // Docker live logs ride the old connection and would keep it up (F-041).
    state.docker_streams.stop_session(&session_id).await;
    // The new connection's first live sample has nothing to diff against.
    state.info_probes.lock().await.remove(&session_id);
    // The connection being replaced is ended explicitly (in the background):
    // anything still holding one of its channels would otherwise keep it up.
    let replaced: Vec<_> = stale.into_iter().chain(stale_jump.map(|h| Arc::new(Mutex::new(h)))).collect();
    if !replaced.is_empty() {
        tauri::async_runtime::spawn(ssh_connect::close_handles(replaced, ssh_connect::CLOSE_TIMEOUT));
    }

    dev_log!("[BACKEND] No duplicates found. Registering oneshot channel and spawning connection worker...");
    let (fp_tx, fp_rx) = tokio::sync::oneshot::channel();
    // Random per-connect nonce — keys the fp_txs map so a stale `accept`
    // for one attempt (frontend bug, malicious IPC call, retry race)
    // cannot satisfy the prompt of a fresh connection. Hex over 16 bytes
    // = 128 bits of entropy, plenty for a single-use guard.
    let connect_nonce: String = {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill(&mut bytes);
        hex::encode(bytes)
    };
    // NB: the fp_txs insert is deliberately deferred until AFTER the DB
    // resolution below. The resolution block has several `?` early-returns; if
    // we inserted here, any of them would return before the worker (which owns
    // the FpCleanupGuard) is spawned, orphaning the sender in the map forever.

    let session_id_clone = session_id.clone();
    let state_connections = Arc::clone(&state.connections);
    let state_sftp_sessions = Arc::clone(&state.sftp_sessions);
    let state_tunnels = Arc::clone(&state.tunnels);
    let state_session_tunnel_specs = Arc::clone(&state.session_tunnel_specs);
    let state_session_generation = Arc::clone(&state.session_generation);
    let fp_txs_clone = Arc::clone(&state.fp_txs);
    let kbi_txs_clone = Arc::clone(&state.kbi_txs);
    let state_jump_connections = Arc::clone(&state.jump_connections);
    let state_docker_streams = state.docker_streams.clone();
    let state_info_probes = Arc::clone(&state.info_probes);
    let state_session_targets = Arc::clone(&state.session_targets);
    let state_channel_gates = Arc::clone(&state.channel_gates);
    // Second Arc into the DB for the ProxyJump hop — the handler below moves
    // the primary `db_conn_shared`, and the spawned worker needs its own owned
    // handle to resolve the bastion's credentials.
    let db_for_jump = Arc::clone(&db_state.conn);
    let db_conn_shared = Arc::clone(&db_state.conn);

    // Reconnect path: tear down any stale listeners + R-tunnel registrations
    // bound to this session_id. Without this, the old TCP listener stays bound
    // to the local port, the new start_tunnel below hits a bind conflict, and
    // every existing tunnel silently routes traffic into a dead SSH handle.
    // First-connect is a no-op (no entries to remove).
    tunnel::stop_all_for_session(&state.tunnels, &session_id).await;
    state.forwarded_targets.lock().await.remove(&session_id);
    // Same story for mirrors — a reconnect must not inherit a mirror worker
    // that still holds an Arc<SftpSession> pointing at the DEAD handle from
    // the previous attempt. Without this the reconnected session appears
    // fine but the mirror keeps writing upload-fail logs against the old
    // socket forever, and manual Stop is the only way to clear it.
    mirror::stop_all_for_session(&mirrors, &session_id).await;

    // Separate-sessions: a PRIMARY (re)connect must reap any stale dedicated
    // `::sftp` / `::fwd` connections from a previous attempt, so the frontend can
    // re-open fresh ones after this success. Gated to the primary so a secondary
    // connect doesn't try to sweep its own (non-existent) grandchildren. Skipped
    // entirely for keys that already carry a `::` suffix (i.e. this IS a
    // secondary), and a plain no-op on first connect / shared mode.
    if !is_secondary {
        teardown_connection_key(state.inner(), mirrors.inner(), &format!("{}::sftp", session_id)).await;
        teardown_connection_key(state.inner(), mirrors.inner(), &format!("{}::fwd", session_id)).await;
    } else {
        // Dedicated-transport reconnect (manual button / auto-retry) OVER a
        // still-live old handle: the base-tagged tunnels ride this transport and
        // the base SFTP cache points at it, so release them before the new
        // handshake. Otherwise, if the fresh attempt fails, the old tunnels keep
        // running on a connection nobody watches (zombie) and file ops hit a
        // dead subsystem. Mirrors disconnect_session's dedicated-transport hooks.
        if let Some(base) = session_id.strip_suffix("::fwd") {
            tunnel::stop_all_for_session(&state.tunnels, base).await;
        }
        if let Some(base) = session_id.strip_suffix("::sftp") {
            state.sftp_sessions.lock().await.remove(base);
        }
    }

    // Per-session map for R-tunnel target lookups. Created here so the same
    // Arc can be handed to both the ClientHandler (consulted on incoming
    // forwarded-tcpip channels) and to tunnel::start_tunnel (which writes the
    // mapping when a remote tunnel is set up).
    let session_forwarded_targets: tunnel::ForwardedTargets =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    state.forwarded_targets.lock().await.insert(
        session_id.clone(),
        Arc::clone(&session_forwarded_targets),
    );

    // Quick connect bypasses the DB lookup entirely — we fabricate the
    // same tuple shape from the inline values so all downstream code
    // (auth, tunnel-start, handler setup) doesn't need to branch.
    // Set by the saved-server lookup below when the login or key the server
    // needs was deleted (see `missing_identity_reason`).
    let mut identity_gap: Option<&'static str> = None;
    let quick_connect = quick_auth.is_some();
    let db_res = if let Some(q) = quick_auth.as_ref() {
        let key_data = q.private_key
            .clone()
            .filter(|s| !s.trim().is_empty())
            .map(|pk| (pk, q.passphrase.clone()));
        let auth_type = if key_data.is_some() { "custom_key" } else { "custom_pass" };
        Some((
            q.host.clone(),
            q.port,
            q.username.clone(),
            q.password.clone(),
            key_data,
            "none".to_string(),         // proxy_type — no proxy in quick mode
            None,                       // proxy_host
            None,                       // proxy_port
            auth_type.to_string(),      // server_auth_type
            None,                       // cred_auth_type (unused for custom_*)
            None,                       // db_key_id (debug-log only)
            None,                       // effective_key_id (auth code branches on key_data, not this)
            "[]".to_string(),           // tunnels_json — no auto-start tunnels
            None,                       // jump_host_id — quick connect never bounces through a bastion
            false,                      // legacy_algorithms — never for a one-off target
            false,                      // terminal_only — no saved setting; detection still applies
        ))
    } else {
    // Fetch DB record inside a nested block to drop non-Send Rows/Statement before any await
    {
        let conn_guard = db_state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
        let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
        
        // Pull both server-side and credential-side identity fields separately
        // and resolve in Rust. The previous COALESCE was order-of-precedence
        // magic that hid the actual rule from anyone reading the SQL — now the
        // rule is "vault mode → credential fields; custom_* mode → node fields"
        // and nothing else can mix the two.
        let mut stmt = conn.prepare("
            SELECT s.host, s.port,
                   s.username as s_user, c.username as c_user,
                   s.password as s_pass, c.password as c_pass,
                   s.key_id   as s_key,  c.key_id   as c_key,
                   s.proxy_type, s.proxy_host, s.proxy_port,
                   s.auth_type, c.auth_type as cred_auth_type, s.tunnels,
                   s.jump_host_id, c.id, s.legacy_algorithms, s.terminal_only
            FROM servers s
            LEFT JOIN credentials c ON s.credential_id = c.id
            WHERE s.id=?1
        ").map_err(|e| e.to_string())?;

        let mut rows = stmt.query([server_id]).map_err(|e| e.to_string())?;
        if let Some(row) = rows.next().map_err(|e| e.to_string())? {
            // host/port are NOT NULL in the schema, but propagating
            // errors instead of `.unwrap()` means a manual DB edit or a
            // future schema relaxation can never silently panic the
            // spawned connection worker — the user gets a clean error.
            let host: String = row.get::<_, String>(0).map_err(|e| format!("[DB] host: {}", e))?;
            let port: i32 = row.get::<_, i32>(1).map_err(|e| format!("[DB] port: {}", e))?;
            let s_user: Option<String> = row.get::<_, Option<String>>(2).unwrap_or_default();
            let c_user: Option<String> = row.get::<_, Option<String>>(3).unwrap_or_default();
            let s_pass: Option<String> = row.get::<_, Option<String>>(4).unwrap_or_default();
            let c_pass: Option<String> = row.get::<_, Option<String>>(5).unwrap_or_default();
            let s_key:  Option<i32>    = row.get::<_, Option<i32>>(6).unwrap_or_default();
            let c_key:  Option<i32>    = row.get::<_, Option<i32>>(7).unwrap_or_default();
            let proxy_type: String = row.get::<_, Option<String>>(8).unwrap_or_default().unwrap_or_else(|| "none".to_string());
            let proxy_host: Option<String> = row.get::<_, Option<String>>(9).unwrap_or_default();
            let proxy_port: Option<i32> = row.get::<_, Option<i32>>(10).unwrap_or_default();
            let server_auth_type: String = row.get::<_, Option<String>>(11).unwrap_or_default().unwrap_or_else(|| "vault".to_string());
            let cred_auth_type: Option<String> = row.get::<_, Option<String>>(12).unwrap_or_default();
            let tunnels_json: String = row.get::<_, Option<String>>(13).unwrap_or_default().unwrap_or_else(|| "[]".to_string());
            let jump_host_id: Option<i32> = row.get::<_, Option<i32>>(14).unwrap_or_default();
            let credential_found = row.get::<_, Option<i32>>(15).unwrap_or_default().is_some();
            let legacy_algorithms = row.get::<_, i64>(16).map_err(|e| format!("[DB] legacy_algorithms: {}", e))? != 0;
            let terminal_only = row.get::<_, i64>(17).map_err(|e| format!("[DB] terminal_only: {}", e))? != 0;

            // Single source of truth per auth_type — no field mixing.
            // - vault: identity comes ENTIRELY from the credential row. Any
            //   stale username/password/key on the node row is ignored.
            // - custom_pass / custom_key: identity comes ENTIRELY from the
            //   node row.
            let (username, password, key_id) = if server_auth_type == "vault" {
                (c_user.unwrap_or_default(), c_pass, c_key)
            } else {
                (s_user.unwrap_or_default(), s_pass, s_key)
            };

            // Whether to actually load a key file:
            // - vault: only if the chosen credential is itself key-typed
            // - custom_key: yes, use the node's selected key
            // - custom_pass: no
            let effective_key_id = if server_auth_type == "vault" {
                if cred_auth_type.as_deref() == Some("key") { key_id } else { None }
            } else if server_auth_type == "custom_key" {
                key_id
            } else {
                None
            };

            // Fetch key details if a key is needed
            let key_data = if let Some(kid) = effective_key_id {
                let mut key_stmt = conn.prepare("SELECT private_key, passphrase FROM ssh_keys WHERE id = ?1").map_err(|e| e.to_string())?;
                let mut key_rows = key_stmt.query([kid]).map_err(|e| e.to_string())?;
                if let Some(key_row) = key_rows.next().map_err(|e| e.to_string())? {
                    let private_key: String = key_row.get::<_, String>(0).map_err(|e| e.to_string())?;
                    let passphrase: Option<String> = key_row.get::<_, Option<String>>(1).map_err(|e| e.to_string())?;
                    Some((private_key, passphrase))
                } else {
                    None
                }
            } else {
                None
            };
            identity_gap = missing_identity_reason(&server_auth_type, credential_found, cred_auth_type.as_deref(), key_data.is_some());

            Some((host, port, username, password, key_data, proxy_type, proxy_host, proxy_port, server_auth_type, cred_auth_type, key_id, effective_key_id, tunnels_json, jump_host_id, legacy_algorithms, terminal_only))
        } else {
            None
        }
    }
    };

    let (host, port, user, password, key_data, proxy_type, proxy_host, proxy_port, server_auth_type, cred_auth_type, db_key_id, effective_key_id, tunnels_json, jump_host_id, legacy_algorithms, terminal_only) = match db_res {
        Some(val) => val,
        None => {
            return Err("Server not found".into());
        }
    };

    // The login or key this server needs was deleted: say so instead of trying
    // without it and blaming the server. Reported like an auth failure, so the
    // UI stops auto-reconnecting and offers its password box; a password typed
    // there is used as usual when there is a username to go with it (a deleted
    // saved login takes the username with it, so that case stays refused).
    if let Some(reason) = identity_gap {
        let typed_password = custom_password.as_deref().is_some_and(|p| !p.is_empty());
        if !typed_password || user.trim().is_empty() {
            use tauri::Emitter;
            let _ = app.emit(&format!("session-log-{}", session_id), json!({"msg": reason, "type": "error"}));
            emit_connection_failed(&app, &session_id, reason, ConnectErrorKind::Auth);
            return Err(reason.to_string());
        }
    }

    // Ports are checked when saved (quick connect included); one out of range
    // anyway (a row from an older build, a direct call) is refused here instead
    // of being truncated to some other port.
    let ports = checked_port(port, "Port").and_then(|p| {
        let proxy = match proxy_type.as_str() {
            "socks5" => Some(checked_port(proxy_port.unwrap_or(1080), "Proxy port")?),
            "http" => Some(checked_port(proxy_port.unwrap_or(8080), "Proxy port")?),
            _ => None,
        };
        Ok((p, proxy))
    });
    let (port_u16, proxy_port_u16) = match ports {
        Ok(v) => v,
        Err(reason) => {
            use tauri::Emitter;
            let _ = app.emit(&format!("session-log-{}", session_id), json!({"msg": reason, "type": "error"}));
            emit_connection_failed(&app, &session_id, &reason, ConnectErrorKind::Config);
            return Err(reason);
        }
    };

    // What this connection may negotiate: the server's legacy setting, and the
    // host-key types already trusted for it first (F-076, F-029). A store that
    // cannot be read here cannot be read by the host-key check either, which
    // then refuses the connection; the order alone is not worth failing on.
    let policy = {
        let known_key_types = match db_state.conn.lock() {
            Ok(guard) => guard
                .as_ref()
                .and_then(|conn| ssh_manager::known_key_types(conn, &host, port_u16).ok())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        ssh_connect::AlgorithmPolicy { legacy: legacy_algorithms, known_key_types }
    };

    // DB resolution succeeded — now register the fingerprint sender. From here
    // on the worker is always spawned, so its FpCleanupGuard guarantees this
    // entry is removed even on the failure paths.
    state.fp_txs.lock().await.insert(connect_nonce.clone(), fp_tx);

    // Shared between the handler and the connect driver so a host-key refusal
    // is reported as what it is (see ssh_manager::HostKeyOutcome).
    let fp_outcome = std::sync::Arc::new(ssh_manager::OutcomeCell::default());
    let fp_outcome_for_driver = std::sync::Arc::clone(&fp_outcome);
    // The host key the handler trusted, read when the connection registers (N-012).
    let accepted_key_for_worker: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let (prompt_tx, prompt_rx) = tokio::sync::watch::channel(false);
    // What the server allows beside the terminal: its setting, then what the
    // handler and the channel opens find out. Registered with the connection.
    let channel_gate = Arc::new(ssh_connect::ChannelGate::new(terminal_only));
    // How the connection ended, from the handler, for the health watcher; and
    // whether nothing stands between Solanum and the server, which decides
    // what a plain close means (`ConnectionEnd::by_server`).
    let ended_because: Arc<std::sync::Mutex<Option<ssh_connect::ConnectionEnd>>> = Arc::default();
    let direct_tcp = jump_host_id.is_none() && !matches!(proxy_type.as_str(), "socks5" | "http");

    let handler = ssh_manager::ClientHandler {
        app: app.clone(),
        session_id: session_id.clone(),
        connect_nonce: connect_nonce.clone(),
        server_host: host.clone(),
        server_port: port_u16,
        db: db_conn_shared,
        // A dedicated SFTP/forwarding connection has no UI for the prompt
        // (the primary trusted the key just before): refuse at once rather
        // than wait 90 s on a question nobody sees.
        fp_rx: allow_kbi.then_some(fp_rx),
        forwarded_targets: Arc::clone(&session_forwarded_targets),
        fp_outcome: std::sync::Arc::clone(&fp_outcome),
        prompt_open: Arc::new(prompt_tx),
        weak_reported: false,
        accepted_key: Arc::clone(&accepted_key_for_worker),
        legacy_algorithms: policy.legacy,
        channel_gate: Arc::clone(&channel_gate),
        ended_because: Arc::clone(&ended_because),
    };

    let cleanup_nonce = connect_nonce.clone();
    // Own an Arc into MirrorMap so the outer spawn (which requires 'static)
    // doesn't try to borrow the caller's `mirrors: State<'_, MirrorMap>`.
    // The Arc is 'static; the State reference is not.
    let mirrors_owned: MirrorMap = mirrors.inner().clone();

    tauri::async_runtime::spawn(async move {
        dev_log!("[BACKEND WORKER] Started connection worker thread for session: {}", session_id_clone);

        struct FpCleanupGuard {
            fp_txs: Arc<Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<bool>>>>,
            kbi_txs: Arc<Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<Option<Vec<String>>>>>>,
            nonce: String,
        }
        impl Drop for FpCleanupGuard {
            fn drop(&mut self) {
                let fp_txs = Arc::clone(&self.fp_txs);
                let kbi_txs = Arc::clone(&self.kbi_txs);
                let nonce = self.nonce.clone();
                tauri::async_runtime::spawn(async move {
                    fp_txs.lock().await.remove(&nonce);
                    // Worker died mid keyboard-interactive prompt — drop any
                    // dangling sender so a late frontend response is a no-op.
                    kbi_txs.lock().await.remove(&nonce);
                });
            }
        }
        let _guard = FpCleanupGuard {
            fp_txs: Arc::clone(&fp_txs_clone),
            kbi_txs: Arc::clone(&kbi_txs_clone),
            nonce: cleanup_nonce.clone(),
        };

        let emit_log = |msg: &str, log_type: &str| {
            dev_log!("[LOG-{}] {}", session_id_clone, msg);
            let _ = app.emit(&format!("session-log-{}", session_id_clone), serde_json::json!({"msg": msg, "type": log_type}));
        };

        let cleanup = || async {
            // Already handled by Drop Guard, but keeping for immediate eviction if needed
            fp_txs_clone.lock().await.remove(&cleanup_nonce);
        };

        emit_log("Initializing SSH connection process...", "info");
        let effective_user = if user.trim().is_empty() {
            emit_log("Username is empty. Defaulting to 'root'.", "info");
            "root".to_string()
        } else {
            user.trim().to_string()
        };
        emit_log(&format!("Server Details -> Host: {}, Port: {}, User: {}", host, port, effective_user), "info");
        emit_log(&format!("[DEBUG] Server Auth Method: {}", server_auth_type), "info");
        if server_auth_type == "vault" {
            emit_log(&format!("[DEBUG] Vault Identity Auth Type: {:?}", cred_auth_type), "info");
        }
        emit_log(&format!("[DEBUG] SQLite DB key_id: {:?}", db_key_id), "info");
        emit_log(&format!("[DEBUG] effective_key_id determined: {:?}", effective_key_id), "info");
        if let Some((ref priv_key, ref passphrase)) = key_data {
            emit_log(&format!("[DEBUG] SSH Key loaded from DB. Private Key length: {} chars, Has Passphrase: {}", priv_key.len(), passphrase.is_some()), "info");
            if priv_key.trim().is_empty() {
                emit_log("[DEBUG] WARNING: SSH Key content is EMPTY!", "error");
            } else {
                let first_line = priv_key.lines().next().unwrap_or("");
                emit_log(&format!("[DEBUG] SSH Key Header: {}", first_line), "info");
            }
        } else {
            emit_log("[DEBUG] No SSH Key was loaded from database for this session.", "info");
        }

        // Set up generic stream based on proxy configuration
        trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {}
        impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> AsyncStream for T {}

        struct StreamWrapper(Box<dyn AsyncStream>);
        impl tokio::io::AsyncRead for StreamWrapper {
            fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut *self.0).poll_read(cx, buf)
            }
        }
        impl tokio::io::AsyncWrite for StreamWrapper {
            fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
                std::pin::Pin::new(&mut *self.0).poll_write(cx, buf)
            }
            fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut *self.0).poll_flush(cx)
            }
            fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
                std::pin::Pin::new(&mut *self.0).poll_shutdown(cx)
            }
        }

        // ProxyJump takes precedence over a direct / proxied transport. When a
        // bastion is configured we connect+auth to it first, then open a
        // `direct-tcpip` channel to the REAL target over that connection and
        // use the channel as the transport for the primary handshake — exactly
        // what `ssh -J bastion target` does. The bastion's own Handle is parked
        // in `jump_handle_holder` so it lives through the target handshake; on
        // success it moves into `state_jump_connections` for the session's life.
        let mut jump_handle_holder: Option<russh::client::Handle<ssh_manager::ClientHandler>> = None;
        let stream_res: Result<Box<dyn AsyncStream>, ConnectFailure> = if let Some(jid) = jump_host_id {
            emit_log(&format!("ProxyJump: routing through jump host (server id {})...", jid), "info");
            match connect_jump_host(&app, &db_for_jump, &fp_txs_clone, &kbi_txs_clone, &session_id_clone, jid, allow_kbi).await {
                Ok(jump_handle) => {
                    // Originator address is cosmetic (logged by the bastion); the
                    // pair below is what OpenSSH sends for a -J hop. Bounded: a
                    // bastion that never answers must not hang the attempt.
                    match tokio::time::timeout(
                        ssh_connect::CHANNEL_OPEN_TIMEOUT,
                        jump_handle.channel_open_direct_tcpip(host.clone(), u32::from(port_u16), "127.0.0.1", 0),
                    )
                    .await
                    {
                        Ok(Ok(channel)) => {
                            emit_log(&format!("ProxyJump: opened tunnel to {}:{} through the jump host.", host, port), "success");
                            let boxed: Box<dyn AsyncStream> = Box::new(channel.into_stream());
                            jump_handle_holder = Some(jump_handle);
                            Ok(boxed)
                        }
                        Ok(Err(e)) => Err(ConnectFailure {
                            reason: format!(
                                "ProxyJump: could not open a channel to {}:{} through the jump host: {}",
                                host, port, e
                            ),
                            kind: ConnectErrorKind::Unreachable,
                        }),
                        Err(_) => Err(ConnectFailure {
                            reason: format!(
                                "ProxyJump: the jump host did not open a channel to {}:{} within {} seconds",
                                host, port, ssh_connect::CHANNEL_OPEN_TIMEOUT.as_secs()
                            ),
                            kind: ConnectErrorKind::Timeout,
                        }),
                    }
                }
                Err(failure) => Err(ConnectFailure {
                    reason: format!("ProxyJump: {}", failure.reason),
                    // A refused jump-host login is not this server's password:
                    // no password box, and no retry (fix the jump host's login).
                    kind: if failure.kind == ConnectErrorKind::Auth { ConnectErrorKind::Config } else { failure.kind },
                }),
            }
        } else {
        let direct: Result<Box<dyn AsyncStream>, String> = match proxy_type.as_str() {
            "socks5" => {
                let p_host = match proxy_host.as_ref().filter(|h| !h.is_empty()) {
                    Some(h) => h,
                    None => {
                        let err_msg = "SOCKS5 Proxy Host is empty";
                        emit_log(&format!("Error: {}", err_msg), "error");
                        cleanup().await;
                        report_connection_failed(&app, &state_session_generation, &session_id_clone, connect_generation, err_msg, ConnectErrorKind::Config).await;
                        return;
                    }
                };
                let p_port = proxy_port_u16.unwrap_or(1080);
                emit_log(&format!("Connecting via SOCKS5 Proxy {}:{}...", p_host, p_port), "info");
                
                let proxy_addr = format!("{}:{}", p_host, p_port);
                match tokio::time::timeout(
                    Duration::from_secs(10),
                    tokio_socks::tcp::Socks5Stream::connect(proxy_addr.as_str(), (host.as_str(), port_u16))
                ).await {
                    Ok(Ok(stream)) => {
                        emit_log("SOCKS5 Proxy tunnel established successfully.", "success");
                        // Socks5Stream derefs to the inner TcpStream, so the
                        // kernel keepalive applies to the real proxy socket.
                        apply_tcp_keepalive(&stream);
                        Ok(Box::new(stream))
                    }
                    Ok(Err(e)) => {
                        Err(humanize_network_err(&e.to_string(), &host, port, "SOCKS5 proxy"))
                    }
                    Err(_) => {
                        Err(format!("SOCKS5 proxy {}:{} did not respond in time", p_host, p_port))
                    }
                }
            }
            "http" => {
                let p_host = match proxy_host.as_ref().filter(|h| !h.is_empty()) {
                    Some(h) => h,
                    None => {
                        let err_msg = "HTTP Proxy Host is empty";
                        emit_log(&format!("Error: {}", err_msg), "error");
                        cleanup().await;
                        report_connection_failed(&app, &state_session_generation, &session_id_clone, connect_generation, err_msg, ConnectErrorKind::Config).await;
                        return;
                    }
                };
                let p_port = proxy_port_u16.unwrap_or(8080);
                emit_log(&format!("Connecting via HTTP Proxy {}:{}...", p_host, p_port), "info");

                match ssh_connect::connect_tcp(p_host, p_port).await {
                    Ok(mut tcp_stream) => {
                        // Disable Nagle: SSH is heavily interactive (keystrokes,
                        // small control packets) and batching adds noticeable
                        // round-trip latency. Ignore failures — set_nodelay is
                        // best-effort; some platforms / virtual NICs reject it.
                        let _ = tcp_stream.set_nodelay(true);
                        apply_tcp_keepalive(&tcp_stream);
                        emit_log(&format!("Requesting HTTP CONNECT tunnel to {}:{}...", host, port), "info");
                        match tokio::time::timeout(
                            Duration::from_secs(10),
                            async_http_proxy::http_connect_tokio(&mut tcp_stream, &host, port_u16)
                        ).await {
                            Ok(Ok(_)) => {
                                emit_log("HTTP Proxy tunnel established successfully.", "success");
                                Ok(Box::new(tcp_stream))
                            }
                            Ok(Err(e)) => {
                                Err(humanize_network_err(&e.to_string(), &host, port, "HTTP CONNECT tunnel"))
                            }
                            Err(_) => {
                                Err(format!("HTTP CONNECT tunnel to {}:{} timed out", host, port))
                            }
                        }
                    }
                    Err(e) => Err(describe_tcp_failure(e, p_host, i32::from(p_port), "HTTP proxy")),
                }
            }
            _ => {
                emit_log(&format!("Connecting directly to {}:{}...", host, port), "info");
                match ssh_connect::connect_tcp(&host, port_u16).await {
                    Ok(stream) => {
                        // See HTTP-proxy branch — SSH wants every packet on the
                        // wire immediately, no Nagle batching.
                        let _ = stream.set_nodelay(true);
                        apply_tcp_keepalive(&stream);
                        emit_log("Direct TCP Connection established successfully.", "success");
                        Ok(Box::new(stream))
                    }
                    Err(e) => Err(describe_tcp_failure(e, &host, port, "Connection")),
                }
            }
        };
        direct.map_err(|reason| ConnectFailure { reason, kind: ConnectErrorKind::Unreachable })
        };

        let stream = match stream_res {
            Ok(s) => s,
            Err(failure) => {
                emit_log(&failure.reason, "error");
                cleanup().await;
                report_connection_failed(&app, &state_session_generation, &session_id_clone, connect_generation, &failure.reason, failure.kind).await;
                return;
            }
        };

        emit_log("Starting SSH Handshake and establishing secure session...", "info");
        // Config (keepalive, windows, algorithm negotiation): see
        // ssh_connect::build_ssh_client_config for the full rationale.
        let config = Arc::new(ssh_connect::build_ssh_client_config(&policy));

        let connect_future = client::connect_stream(config, StreamWrapper(stream), handler);

        // The handshake's clock stops while the host-key prompt waits for the
        // user (F-026): the prompt has its own 90 s bound.
        match ssh_connect::handshake_within(
            connect_future,
            ssh_connect::HANDSHAKE_BUDGET,
            ssh_connect::AFTER_PROMPT_GRACE,
            prompt_rx,
        )
        .await
        {
            Ok(Ok(mut session)) => {
                emit_log("SSH Handshake complete. Authenticating user...", "info");

                // Log in: key, password, keyboard-interactive (2FA codes), each
                // as far as the server still offers it, multi-step logins
                // included, every wait bounded (ssh_connect::authenticate).
                // In a key login only a password the user typed is sent, and
                // only after the key; a stored password never replaces a key.
                let key_login = key_data.is_some();
                let (key, key_problem) = decode_login_key(key_data, &emit_log);
                let creds = ssh_connect::Credentials {
                    key_login,
                    key,
                    key_problem,
                    password: if key_login { custom_password } else { custom_password.or(password) },
                    password_can_be_typed: true,
                    allow_sha1_rsa: policy.legacy,
                };
                let prompter = UiKbiPrompter {
                    app: &app,
                    session_id: &session_id_clone,
                    nonce: &connect_nonce,
                    host: &host,
                    kbi_txs: &kbi_txs_clone,
                };
                let auth = ssh_connect::authenticate(
                    &mut session,
                    &effective_user,
                    creds,
                    allow_kbi.then_some(&prompter),
                    ssh_connect::AuthLimits::default(),
                    &emit_log,
                )
                .await;

                match auth {
                    Ok(()) => {
                        let session_arc = Arc::new(Mutex::new(session));
                        // "Still wanted?" registration guard. The handshake can
                        // take up to ~15s (longer via proxy/jump). If, meanwhile,
                        // a reconnect for this key bumped the generation or a
                        // disconnect/teardown swept it (both of which bump the
                        // generation BEFORE removing the connection), registering
                        // now would create a ZOMBIE: a live SSH connection with a
                        // watcher that immediately exits on the generation
                        // mismatch, plus — for ::fwd — tunnels migrated onto a
                        // connection nobody tracks. Do the check and the insert
                        // TOGETHER under the generation lock so a concurrent
                        // teardown can't interleave: we either observe the newer
                        // generation and bail, or insert first and the teardown's
                        // later connection-remove reaps us.
                        let registered = {
                            let g = state_session_generation.lock().await;
                            if g.get(&session_id_clone).copied().unwrap_or(0) == connect_generation && epoch.current() {
                                let mut conns = state_connections.lock().await;
                                conns.insert(session_id_clone.clone(), Arc::clone(&session_arc));
                                // ProxyJump: the bastion's handle is parked for the
                                // session's life in the same locked step (R-004): a
                                // teardown between the two would find no entry to
                                // remove, and the bastion would stay logged in. A
                                // superseded connection never parks it: the holder
                                // drops it on return, closing it.
                                if let Some(jh) = jump_handle_holder.take() {
                                    state_jump_connections.lock().await.insert(session_id_clone.clone(), jh);
                                }
                                drop(conns);
                                // Which server this is, for live edit (N-012).
                                // Without a trusted key on record no upload
                                // is ever allowed over it.
                                let mut targets = state_session_targets.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                match accepted_key_for_worker.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone() {
                                    Some(host_key) => {
                                        targets.insert(
                                            session_id_clone.clone(),
                                            live_edit::ServerIdentity { address: format!("{}@{}:{}", effective_user, host, port), host_key },
                                        );
                                    }
                                    None => {
                                        targets.remove(&session_id_clone);
                                    }
                                }
                                state_channel_gates
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .insert(session_id_clone.clone(), Arc::clone(&channel_gate));
                                true
                            } else {
                                false
                            }
                        };
                        if !registered {
                            emit_log("Connection superseded before it was ready — dropping it.", "info");
                            // `session_arc` drops here, closing the transport.
                            // The FpCleanupGuard's Drop still clears the nonce.
                            return;
                        }
                        emit_log("Authentication successful. Session ready.", "success");
                        // A dedicated `::sftp` transport just came up — drop the
                        // base session's cached SFTP subsystem (it rides the
                        // primary). The next file operation re-opens on this
                        // dedicated connection via get_sftp_session's
                        // transport preference. Live migration, no re-keying.
                        if let Some(base) = session_id_clone.strip_suffix("::sftp") {
                            state_sftp_sessions.lock().await.remove(base);
                        }
                        // The window hears when a refused channel makes this a
                        // terminal-only connection. Ends with the gate, or once
                        // said. Before the success event, which carries a limit
                        // already known, so none falls between the two.
                        if !is_secondary {
                            let mut limit = channel_gate.subscribe();
                            let (app_l, sid_l) = (app.clone(), session_id_clone.clone());
                            tauri::async_runtime::spawn(async move {
                                while limit.changed().await.is_ok() {
                                    let Some(why) = *limit.borrow_and_update() else { continue };
                                    let _ = app_l.emit(
                                        &format!("session-log-{}", sid_l),
                                        json!({"msg": format!("The server refused another channel while one was open. {} The terminal is not affected.", why.refusal()), "type": "warn"}),
                                    );
                                    let _ = app_l.emit(&format!("session-terminal-only-{}", sid_l), json!({ "terminal_only": why }));
                                    break;
                                }
                            });
                        }
                        let _ = app.emit(
                            &format!("connection-success-{}", session_id_clone),
                            serde_json::json!({ "terminal_only": channel_gate.limit() }),
                        );

                        // Separate-sessions topology: in shared mode the primary
                        // owns the saved tunnels; in separate mode the dedicated
                        // `::fwd` connection owns them (it re-enters this same
                        // block under its own suffixed session id, so the tunnels
                        // are tagged/keyed against `::fwd` and ride that handle).
                        // `start_tunnels_inline` is false for the `::sftp`
                        // connection and for the primary when `separate` is on.
                        if start_tunnels_inline {
                        // Auto-start every tunnel attached to this session.
                        // Source of truth is the in-memory `session_tunnel_specs`
                        // map, which carries both the DB-saved rules AND any
                        // ad-hoc tunnels the user opened during the previous
                        // session lifetime. On first connect it's empty, so
                        // we seed it from the DB row's `tunnels` JSON.
                        let specs_to_start: Vec<tunnel::TunnelSpec> = {
                            let mut map = state_session_tunnel_specs.lock().await;
                            // A PRESENT replay list — even an empty one — is
                            // authoritative, exactly as in the ::fwd branch below
                            // and in restart_session_tunnels. An empty list means
                            // the user stopped every tunnel; only an ABSENT key is
                            // a genuine first engagement worth seeding from the
                            // node's saved rules. Treating empty as "unset" here
                            // meant every reconnect — including the health
                            // watcher's automatic one — silently reopened local
                            // listeners the user had deliberately closed.
                            match map.get(&session_id_clone).cloned() {
                                Some(existing) => existing,
                                None => match serde_json::from_str::<Vec<tunnel::TunnelSpec>>(&tunnels_json) {
                                    Ok(db_specs) => {
                                        // Not after a lock began: session ids restart
                                        // in every vault, the next profile would replay it.
                                        if epoch.current() {
                                            map.insert(session_id_clone.clone(), db_specs.clone());
                                        }
                                        db_specs
                                    }
                                    Err(e) => {
                                        emit_log(&format!("Tunnels JSON parse error: {}", e), "error");
                                        Vec::new()
                                    }
                                }
                            }
                        };
                        let mut started_here = Vec::new();
                        // All at once: a remote forward waits for the server,
                        // and the health watcher below starts after these.
                        let results = tunnel::start_tunnels(
                            &tunnel_events(&app),
                            &session_id_clone,
                            &session_arc,
                            &state_tunnels,
                            &session_forwarded_targets,
                            specs_to_start,
                        ).await;
                        for (spec, started) in results {
                            match started {
                                Ok(id) => {
                                    emit_log(&format!("Tunnel started [{}]: {} {}", id, spec.kind, spec.local), "info");
                                    if tunnel::listens_beyond_loopback(&spec) {
                                        emit_log(&format!("Tunnel [{}] {}", id, tunnel::exposure_warning(&spec)), "warn");
                                    }
                                    started_here.push(id);
                                }
                                Err(e) => {
                                    // KEEP the spec in the replay list on failure
                                    // so the NEXT reconnect retries it. Stripping
                                    // it here (the old behaviour) turned a
                                    // transient rebind race on a flaky network —
                                    // a momentary AddrInUse while the previous
                                    // listener finished releasing the port — into
                                    // permanent loss of the tunnel until the user
                                    // manually restarted it. bind_with_retry now
                                    // absorbs that race; anything still failing is
                                    // logged and retried on the next reconnect
                                    // rather than silently dropped.
                                    emit_log(
                                        &format!("Tunnel start failed ({} {}): {} — will retry on next reconnect", spec.kind, spec.local, e),
                                        "error",
                                    );
                                }
                            }
                        }
                        stop_tunnels_if_superseded(&state_session_generation, &session_id_clone, connect_generation, &state_tunnels, &started_here).await;
                        } // end if start_tunnels_inline

                        // Dedicated `::fwd` transport: MIGRATE the session's
                        // tunnels onto this fresh connection. Stop whatever is
                        // running under the base tag (riding the primary, or a
                        // previous dead `::fwd`) so re-binding the same local
                        // ports can't conflict, then start the full replay
                        // list — seeded from the node's saved tunnels on first
                        // engagement — on this handle, still tagged under the
                        // BASE session id so the Tunnels panel / list / events
                        // never re-key. This runs on fresh connects, live
                        // toggle-on, the reconnect button, and auto-retry.
                        if role == "forward" {
                            let base = session_id_clone
                                .strip_suffix("::fwd")
                                .unwrap_or(&session_id_clone)
                                .to_string();
                            tunnel::stop_all_for_session(&state_tunnels, &base).await;
                            let specs: Vec<tunnel::TunnelSpec> = {
                                let mut map = state_session_tunnel_specs.lock().await;
                                // A PRESENT replay list — even an empty one — is
                                // authoritative: the session is already engaged
                                // and an empty list means the user stopped every
                                // tunnel. Only seed from the node's saved tunnels
                                // when the key is ABSENT (genuine first
                                // engagement) — otherwise stopped tunnels would
                                // resurrect on every ::fwd reconnect / toggle.
                                match map.get(&base).cloned() {
                                    Some(existing) => existing,
                                    None => match serde_json::from_str::<Vec<tunnel::TunnelSpec>>(&tunnels_json) {
                                        Ok(db_specs) => {
                                            if !db_specs.is_empty() && epoch.current() {
                                                map.insert(base.clone(), db_specs.clone());
                                            }
                                            db_specs
                                        }
                                        Err(e) => {
                                            emit_log(&format!("Tunnels JSON parse error: {}", e), "error");
                                            Vec::new()
                                        }
                                    },
                                }
                            };
                            if !specs.is_empty() {
                                emit_log("Dedicated forwarding connection ready — moving tunnels onto it.", "info");
                                let started_here = start_tunnel_specs_on(
                                    &app,
                                    &base,
                                    &session_arc,
                                    &session_forwarded_targets,
                                    &state_tunnels,
                                    &state_session_tunnel_specs,
                                    specs,
                                    &epoch,
                                )
                                .await;
                                stop_tunnels_if_superseded(&state_session_generation, &session_id_clone, connect_generation, &state_tunnels, &started_here).await;
                            }
                        }

                        // Health watcher: polls the SSH handle every 5s. If
                        // `is_closed()` flips to true while the session is
                        // still registered (i.e. the user did NOT call
                        // disconnect_session explicitly), we fire a
                        // `session-disconnected-{id}` event so the UI can lock
                        // down the terminal/SFTP and show a reconnect prompt.
                        // An explicit disconnect removes the map entry, which
                        // the watcher detects and exits silently — no event.
                        let app_w = app.clone();
                        let sid_w = session_id_clone.clone();
                        let state_w = Arc::clone(&state_connections);
                        let state_sftp_w = Arc::clone(&state_sftp_sessions);
                        let state_gen_w = Arc::clone(&state_session_generation);
                        let state_tunnels_w = Arc::clone(&state_tunnels);
                        let state_mirrors_w: MirrorMap = mirrors_owned.clone();
                        let docker_streams_w = state_docker_streams.clone();
                        let info_probes_w = Arc::clone(&state_info_probes);
                        let targets_lost_w = Arc::clone(&state_session_targets);
                        let gates_lost_w = Arc::clone(&state_channel_gates);
                        let jumps_lost_w = Arc::clone(&state_jump_connections);
                        let ended_because_w = Arc::clone(&ended_because);
                        let epoch_w = epoch.clone();
                        // Captured so the watcher can periodically re-attempt a
                        // configured tunnel that failed to bind while the session
                        // stays alive (see the retry block in the loop below).
                        let state_specs_w = Arc::clone(&state_session_tunnel_specs);
                        let targets_w = Arc::clone(&session_forwarded_targets);
                        let my_gen = connect_generation;
                        tauri::async_runtime::spawn(async move {
                            // Two-tier liveness check:
                            //   - Every 2s: cheap is_closed() poll. Catches TCP
                            //     RST / FIN, russh's own teardown, AND — now that
                            //     the transport socket carries OS TCP keepalive
                            //     (see apply_tcp_keepalive) — kernel-detected
                            //     dead peers during long idle.
                            //   - Slow active probe: a keepalive request that
                            //     needs the server's reply (ssh_connect::
                            //     probe_alive; no channel, so no MaxSessions
                            //     slot and no "refused" read as dead, F-027),
                            //     catching black-holes the kernel hasn't
                            //     flagged yet. Primary every
                            //     ~30s, dedicated `::sftp`/`::fwd` secondaries
                            //     every ~60s (they matter less urgently and the
                            //     probes multiply per-session overhead).
                            //     TWO consecutive probe failures are required
                            //     before declaring death: on poor networks a
                            //     single 10s latency spike is common, and the
                            //     old one-strike/5s-timeout probe tore down
                            //     perfectly recoverable sessions — the exact
                            //     opposite of what a flaky link needs.
                            let probe_every: u32 = if sid_w.contains("::") { 30 } else { 15 };
                            let mut tick: u32 = 0;
                            let mut probe_strikes: u8 = 0;
                            loop {
                                tokio::time::sleep(Duration::from_secs(2)).await;
                                tick = tick.wrapping_add(1);

                                // Generation guard: a reconnect under the same
                                // session_id bumps the counter. If we observe a
                                // newer value here, a fresh watcher has already
                                // taken over — bow out silently so we don't
                                // double-emit `session-disconnected-{id}`.
                                {
                                    let g = state_gen_w.lock().await;
                                    if g.get(&sid_w).copied().unwrap_or(0) != my_gen {
                                        break;
                                    }
                                }

                                let handle_opt = {
                                    let conns = state_w.lock().await;
                                    conns.get(&sid_w).cloned()
                                };
                                let handle_arc = match handle_opt {
                                    Some(h) => h,
                                    None => break, // explicit disconnect — quiet
                                };

                                let is_closed = {
                                    let h = handle_arc.lock().await;
                                    h.is_closed()
                                };

                                let mut dead = is_closed;

                                if !dead && tick % probe_every == 0 {
                                    // Active probe: holds the handle lock for
                                    // the round trip, at most 10s — generous
                                    // enough that a congested-but-alive link
                                    // doesn't strike out spuriously. Only no
                                    // answer at all is a strike.
                                    if ssh_connect::probe_alive(&handle_arc, ssh_connect::PROBE_TIMEOUT).await {
                                        probe_strikes = 0;
                                    } else {
                                        probe_strikes += 1;
                                        if probe_strikes >= 2 {
                                            dead = true;
                                        } else {
                                            // One strike: re-probe on the
                                            // next 2s tick instead of a
                                            // full interval away, so a
                                            // real death still surfaces
                                            // promptly.
                                            tick = probe_every.wrapping_sub(1);
                                        }
                                    }
                                }

                                // While the session is ALIVE, periodically re-attempt
                                // any configured tunnel that isn't currently running.
                                // A listener that failed to bind (its local port was
                                // briefly taken) otherwise stays dead until the user
                                // closes and reopens the tab — nothing retries it
                                // without a full reconnect. `start_tunnel_specs_on`
                                // skips specs already running (anywhere under this
                                // session), so this is a no-op once everything is up
                                // and can't create duplicates. Gated to the primary
                                // session id: the dedicated `::fwd`/`::sftp`
                                // transports have their own migration/restore paths,
                                // and the primary handle is the correct transport for
                                // the default (shared) topology. Spawned so a slow
                                // bind retry never delays death detection.
                                if !dead && tick % 30 == 0 && !sid_w.contains("::") {
                                    let specs = state_specs_w.lock().await.get(&sid_w).cloned().unwrap_or_default();
                                    if !specs.is_empty() {
                                        let app_r = app_w.clone();
                                        let sid_r = sid_w.clone();
                                        let handle_r = Arc::clone(&handle_arc);
                                        let targets_r = Arc::clone(&targets_w);
                                        let tunnels_r = Arc::clone(&state_tunnels_w);
                                        let specs_r = Arc::clone(&state_specs_w);
                                        let gen_r = Arc::clone(&state_gen_w);
                                        let epoch_r = epoch_w.clone();
                                        tauri::async_runtime::spawn(async move {
                                            let started = start_tunnel_specs_on(&app_r, &sid_r, &handle_r, &targets_r, &tunnels_r, &specs_r, specs, &epoch_r).await;
                                            stop_tunnels_if_superseded(&gen_r, &sid_r, my_gen, &tunnels_r, &started).await;
                                        });
                                    }
                                }

                                if dead {
                                    // Re-check generation + verify OUR handle is
                                    // still the registered one before tearing
                                    // anything down. A slow probe holds the handle
                                    // lock up to 10s; during that window a manual
                                    // reconnect / auto-retry can bump the
                                    // generation and register a fresh, healthy
                                    // connection. Without this guard we'd remove
                                    // that NEW connection and kill its just-
                                    // migrated tunnels. Bail silently on mismatch.
                                    {
                                        let g = state_gen_w.lock().await;
                                        if g.get(&sid_w).copied().unwrap_or(0) != my_gen {
                                            break;
                                        }
                                    }
                                    // Compare-and-remove: only drop the map entry
                                    // if it's still OUR handle (Arc identity),
                                    // and the jump host's connection with it.
                                    let lost = ssh_connect::take_lost_connection(&state_w, &jumps_lost_w, &sid_w, &handle_arc, || {
                                        targets_lost_w.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&sid_w);
                                        gates_lost_w.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&sid_w);
                                    })
                                    .await;
                                    let jump = match lost {
                                        ssh_connect::Lost::Removed(jump) => jump,
                                        // Superseded by a fresh connection: leave it be.
                                        ssh_connect::Lost::Superseded => break,
                                    };
                                    state_sftp_w.lock().await.remove(&sid_w);
                                    // Tear down all tunnels bound to this
                                    // session so their listeners release the
                                    // local ports + bridge tasks exit. Without
                                    // this, the listeners stayed up holding
                                    // the now-dead Arc<Handle>, and stop_tunnel
                                    // calls during reconnect raced with the
                                    // replay logic. This is the single
                                    // authoritative SSH-death tunnel-teardown
                                    // path; the listener tasks themselves no
                                    // longer probe the handle.
                                    tunnel::stop_all_for_session(&state_tunnels_w, &sid_w).await;
                                    // Dedicated-transport death: tunnels are
                                    // tagged under the BASE session id but ride
                                    // this `::fwd` connection — stop them so
                                    // their listeners release; the frontend's
                                    // auto-retry either brings the transport
                                    // back (migration restarts them on it) or
                                    // falls back to the primary. Same for the
                                    // base SFTP cache riding a dead `::sftp`.
                                    if let Some(base) = sid_w.strip_suffix("::fwd") {
                                        tunnel::stop_all_for_session(&state_tunnels_w, base).await;
                                    }
                                    if let Some(base) = sid_w.strip_suffix("::sftp") {
                                        state_sftp_w.lock().await.remove(base);
                                    }
                                    // Stop any mirrors bound to this session too — otherwise the
                                    // mirror worker keeps its own Arc<SftpSession> pointing at
                                    // this dead handle and hammers upload-fail on every future
                                    // FS event until the app is quit.
                                    mirror::stop_all_for_session(&state_mirrors_w, &sid_w).await;
                                    // And its Docker live logs (F-041), and its Info probes' state.
                                    docker_streams_w.stop_session(&sid_w).await;
                                    info_probes_w.lock().await.remove(&sid_w);
                                    // Says which it was: the server ended the session
                                    // (a goodbye, or a direct connection it closed:
                                    // a switch after `exit`), the network lost it, or
                                    // the probes gave up and Solanum is the one ending
                                    // it. Only a lost connection reconnects by itself,
                                    // and that must not hide why (N-028). A dedicated
                                    // `::sftp`/`::fwd` connection is retried as before.
                                    let end = ended_because_w.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
                                    let (reason, by_server) = ssh_connect::connection_end_report(is_closed, end.as_ref(), direct_tcp);
                                    let logged_out = by_server && !sid_w.contains("::");
                                    if logged_out {
                                        // As Disconnect does: the dedicated
                                        // connections and everything else go too.
                                        use tauri::Manager;
                                        end_session(&app_w.state::<SshState>(), &state_mirrors_w, &sid_w).await;
                                    }
                                    let _ = app_w.emit(
                                        &format!("session-log-{}", sid_w),
                                        serde_json::json!({ "msg": if logged_out { format!("Session ended: {reason}.") } else { reason.clone() }, "type": if logged_out { "info" } else { "error" } }),
                                    );
                                    let _ = app_w.emit(
                                        &format!("session-disconnected-{}", sid_w),
                                        serde_json::json!({
                                            "reason": reason,
                                            "logged_out": logged_out
                                        }),
                                    );
                                    // The bastion's connection goes with the session
                                    // it carried (R-004), after the window has heard.
                                    if let Some(jump) = jump {
                                        ssh_connect::close_handles(vec![Arc::new(tokio::sync::Mutex::new(jump))], ssh_connect::CLOSE_TIMEOUT).await;
                                    }
                                    break;
                                }
                            }
                        });
                    },
                    Err(failure) => {
                        // Only a refusal (or a login that cannot go on without
                        // the user) is an auth failure; a server that stopped
                        // answering or a dropped connection is not relabelled
                        // as one.
                        let ConnectFailure { reason, kind } = auth_failure(failure, &format!("{}:{}", host, port));
                        emit_log(&reason, "error");
                        report_connection_failed(&app, &state_session_generation, &session_id_clone, connect_generation, &reason, kind).await;
                    }
                }
            },
            Ok(Err(e)) => {
                // Connect-stream failed AFTER the TCP socket opened — most
                // commonly this is the host-key check ending in a refusal.
                // Read the outcome the handler stashed and surface a precise
                // reason instead of letting it ride the generic buckets.
                let (reason, kind) = match (fp_outcome_for_driver.get().refusal(), ssh_connect::legacy_only_offer(&e)) {
                    (Some(reason), _) => (reason.to_string(), ConnectErrorKind::HostKey),
                    // An old server: say what would make it work, and where.
                    (None, Some(names)) => (
                        format!(
                            "{}:{} offers only legacy algorithms ({}). If you trust this server, turn on \u{201c}Allow legacy algorithms\u{201d} in its settings{}.",
                            host,
                            port,
                            names.join(", "),
                            if quick_connect { " (save it as a server first)" } else { "" }
                        ),
                        ConnectErrorKind::Algorithm,
                    ),
                    (None, None) => {
                        let kind = classify_russh_error(&e);
                        let target = format!("{}:{}", host, port);
                        (describe_error_kind(kind, &target), kind)
                    }
                };
                emit_log(&format!("{} (raw: {})", reason, e), "error");
                report_connection_failed(&app, &state_session_generation, &session_id_clone, connect_generation, &reason, kind).await;
            },
            Err(_) => {
                // The TCP socket is up but the SSH handshake did not complete
                // within its budget (prompt time not counted). Distinct enough
                // from the auth path to deserve its own message.
                let msg = format!(
                    "{}:{} did not finish the SSH handshake within {} seconds (time spent on the fingerprint prompt not counted) — the host may be filtering SSH or running a non-SSH service on this port.",
                    host, port, ssh_connect::HANDSHAKE_BUDGET.as_secs()
                );
                emit_log(&msg, "error");
                report_connection_failed(&app, &state_session_generation, &session_id_clone, connect_generation, &msg, ConnectErrorKind::Timeout).await;
            }
        }

        cleanup().await;
    });
    
    Ok(())
}

/// Frontend acknowledgement of the SSH host-key prompt. The `nonce` must
/// match the value the matching `fingerprint-prompt-{session_id}` event
/// carried — without that match the response is dropped on the floor. Any
/// stale "accept" from a previous attempt cannot satisfy a fresh prompt.
#[tauri::command]
async fn verify_fingerprint_response(
    state: tauri::State<'_, SshState>,
    nonce: String,
    accepted: bool,
) -> Result<(), String> {
    if let Some(tx) = state.fp_txs.lock().await.remove(&nonce) {
        let _ = tx.send(accepted);
    }
    Ok(())
}

/// Frontend callback for a keyboard-interactive (2FA / verification-code)
/// prompt. `responses` is `Some(answers)` when the user submits, or `None`
/// when they cancel. Mirrors `verify_fingerprint_response`: the nonce binds
/// the answer 1:1 to the connect attempt that emitted the prompt, and a nonce
/// with no in-flight entry is silently a no-op (stale / forged responses can't
/// satisfy a fresh prompt).
#[tauri::command]
async fn submit_kbi_response(
    state: tauri::State<'_, SshState>,
    nonce: String,
    responses: Option<Vec<String>>,
) -> Result<(), String> {
    if let Some(tx) = state.kbi_txs.lock().await.remove(&nonce) {
        let _ = tx.send(responses);
    }
    Ok(())
}

// ---- Port forwarding (tunnels) ---------------------------------------------

/// A tunnel's status updates and connection log, sent to the window. Built
/// here, where the `AppHandle` is: tunnel code itself never holds one, so the
/// unit tests run it (see `tunnel::TunnelEvents`).
fn tunnel_events(app: &tauri::AppHandle) -> tunnel::TunnelEvents {
    use tauri::Emitter;
    let (updates, logs) = (app.clone(), app.clone());
    tunnel::TunnelEvents {
        update: Arc::new(move |status: &tunnel::TunnelStatus| {
            let _ = updates.emit(&format!("tunnel-update-{}", status.session_id), status);
        }),
        log: Arc::new(move |session_id: &str, entry: &tunnel::TunnelLogEntry<'_>| {
            let _ = logs.emit(&format!("tunnel-log-{}", session_id), entry);
        }),
    }
}

/// Resolve the SSH transport a session's tunnels should ride: the dedicated
/// `::fwd` connection when the per-tab toggle has one up, else the primary.
/// The forwarded-targets map MUST belong to the same connection as the handle
/// — for R tunnels the server pushes `forwarded-tcpip` channels back on the
/// connection that sent `tcpip_forward`, and its ClientHandler consults only
/// its own map (ssh_manager.rs::server_channel_open_forwarded_tcpip).
async fn resolve_tunnel_transport(
    state: &SshState,
    session_id: &str,
) -> Result<(Arc<tokio::sync::Mutex<russh::client::Handle<ssh_manager::ClientHandler>>>, tunnel::ForwardedTargets), String> {
    let fwd_key = format!("{}::fwd", session_id);
    let (primary, dedicated) = {
        let conns = state.connections.lock().await;
        (conns.get(session_id).cloned(), if session_id.contains("::") { None } else { conns.get(&fwd_key).cloned() })
    };
    let targets_map = state.forwarded_targets.lock().await;
    if let Some(h) = dedicated {
        // The `::fwd` entry's forwarded-targets map is created by its own
        // initiate_connection; if it's somehow missing, fall through to the
        // primary rather than starting an R tunnel whose inbound channels
        // would never resolve.
        if let Some(t) = targets_map.get(&fwd_key) {
            return Ok((h, Arc::clone(t)));
        }
    }
    let h = primary.ok_or_else(|| "Session not connected".to_string())?;
    let t = targets_map
        .get(session_id)
        .cloned()
        .ok_or_else(|| "Session forwarded-targets map missing — reconnect first".to_string())?;
    Ok((h, t))
}

/// Start every spec in `specs` that isn't already running under `sid`'s tag,
/// on the given transport. Successes are recorded into the session's replay
/// list; failures are logged to the session log and the spec is KEPT in the
/// replay list, so the next reconnect (or the health watcher's retry) tries
/// it again: a transient bind race must not drop a tunnel for good.
/// Used by the `::fwd` migration (connect success), the fallback/restore
/// command, and shares its semantics with the primary's auto-start.
#[allow(clippy::too_many_arguments)]
async fn start_tunnel_specs_on(
    app: &tauri::AppHandle,
    sid: &str,
    handle: &Arc<tokio::sync::Mutex<russh::client::Handle<ssh_manager::ClientHandler>>>,
    targets: &tunnel::ForwardedTargets,
    tunnels: &Arc<tokio::sync::Mutex<std::collections::HashMap<String, tunnel::ActiveTunnel>>>,
    specs_map: &Arc<tokio::sync::Mutex<std::collections::HashMap<String, Vec<tunnel::TunnelSpec>>>>,
    specs: Vec<tunnel::TunnelSpec>,
    epoch: &ssh_manager::ProfileEpoch,
) -> Vec<String> {
    use tauri::Emitter;
    let emit_log = |msg: &str, log_type: &str| {
        let _ = app.emit(
            &format!("session-log-{}", sid),
            serde_json::json!({ "msg": msg, "type": log_type }),
        );
    };
    // Snapshot running specs for this tag. Two-phase (ids under the map lock,
    // status after releasing it) to respect the same lock-ordering rule as
    // tunnel::stop_all_for_session.
    let candidates: Vec<(tunnel::TunnelSpec, Arc<tokio::sync::Mutex<tunnel::TunnelStatus>>)> = {
        let map = tunnels.lock().await;
        map.values().map(|t| (t.spec.clone(), Arc::clone(&t.status))).collect()
    };
    let mut running: Vec<tunnel::TunnelSpec> = Vec::new();
    for (spec, status) in candidates {
        if status.lock().await.session_id == sid {
            running.push(spec);
        }
    }
    let mut started = Vec::new();
    let to_start: Vec<tunnel::TunnelSpec> = specs.into_iter().filter(|spec| !running.contains(spec)).collect();
    // All at once: a remote forward waits for the server.
    for (spec, result) in tunnel::start_tunnels(&tunnel_events(app), sid, handle, tunnels, targets, to_start).await {
        match result {
            Ok(id) => {
                emit_log(&format!("Tunnel started [{}]: {} {}", id, spec.kind, spec.local), "info");
                if tunnel::listens_beyond_loopback(&spec) {
                    emit_log(&format!("Tunnel [{}] {}", id, tunnel::exposure_warning(&spec)), "warn");
                }
                started.push(id);
                let mut map = specs_map.lock().await;
                if epoch.current() {
                    let entry = map.entry(sid.to_string()).or_insert_with(Vec::new);
                    if !entry.contains(&spec) {
                        entry.push(spec);
                    }
                }
            }
            Err(e) => {
                // KEEP the spec so the next reconnect retries it — never strip a
                // user's tunnel on a transient restore failure (see the matching
                // inline-restore comment; the old strip caused permanent loss of
                // forwards on flaky networks). Ensure it's present in the replay
                // list so a spec seeded from the DB (not yet recorded) survives.
                emit_log(&format!("Tunnel start failed ({} {}): {} — will retry on next reconnect", spec.kind, spec.local, e), "error");
                let mut map = specs_map.lock().await;
                if epoch.current() {
                    let entry = map.entry(sid.to_string()).or_insert_with(Vec::new);
                    if !entry.contains(&spec) {
                        entry.push(spec);
                    }
                }
            }
        }
    }
    // A profile lock that ran meanwhile swept the tunnels before these were
    // listed; callers check their own connection's generation.
    if !epoch.current() {
        for id in started.drain(..) {
            let _ = tunnel::stop_tunnel(tunnels, &id).await;
        }
    }
    started
}

/// The generations of a session's primary and `::fwd` connections (a tunnel
/// rides one of them), read before tunnels start and compared after.
async fn tunnel_transport_generations(
    generations: &Arc<tokio::sync::Mutex<std::collections::HashMap<String, u64>>>,
    session_id: &str,
) -> (u64, u64) {
    let g = generations.lock().await;
    (
        g.get(session_id).copied().unwrap_or(0),
        g.get(&format!("{}::fwd", session_id)).copied().unwrap_or(0),
    )
}

/// Tunnels that started while a disconnect, a reconnect or a profile lock
/// ran were listed after its stop sweep (a remote forward waits for the
/// server first): stop them again, as `stop_tunnels_if_superseded` does for
/// the connect worker. Returns whether it did.
async fn stop_tunnels_started_too_late(
    generations: &Arc<tokio::sync::Mutex<std::collections::HashMap<String, u64>>>,
    tunnels: &tunnel::TunnelMap,
    session_id: &str,
    before: (u64, u64),
    epoch: &ssh_manager::ProfileEpoch,
    started: &[String],
) -> bool {
    if started.is_empty()
        || (epoch.current() && tunnel_transport_generations(generations, session_id).await == before)
    {
        return false;
    }
    for id in started {
        let _ = tunnel::stop_tunnel(tunnels, id).await;
    }
    true
}

#[cfg(test)]
mod late_tunnel_tests {
    use super::*;

    fn running(join: tokio::task::JoinHandle<()>) -> tunnel::ActiveTunnel {
        tunnel::ActiveTunnel {
            status: Arc::new(tokio::sync::Mutex::new(tunnel::TunnelStatus {
                id: "t1".into(),
                session_id: "s".into(),
                kind: "remote".into(),
                listen_addr: String::new(),
                target: String::new(),
                state: "listening".into(),
                error: None,
                exposed: false,
                conns_total: 0,
                conns_active: 0,
            })),
            stop_tx: None,
            join: Some(join),
            spec: tunnel::TunnelSpec { kind: "R".into(), local: "4000".into(), remote: "127.0.0.1:9".into() },
            on_forced_stop: None,
        }
    }

    /// Review of batch 7: a tunnel whose start outlasted a disconnect, a
    /// reconnect of the primary or `::fwd` connection, or a profile lock is
    /// stopped again; one that did not is left alone.
    #[tokio::test]
    async fn tunnels_started_across_a_disconnect_or_a_lock_are_stopped_again() {
        for change in ["none", "s", "s::fwd", "lock"] {
            let state = SshState::new();
            let epoch = state.epoch();
            let before = tunnel_transport_generations(&state.session_generation, "s").await;
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
            let mut entry = running(tokio::spawn(async move {
                let _ = stop_rx.await;
            }));
            entry.stop_tx = Some(stop_tx);
            state.tunnels.lock().await.insert("t1".into(), entry);
            match change {
                "lock" => {
                    state.profile_epoch.fetch_add(2, std::sync::atomic::Ordering::SeqCst);
                }
                "none" => {}
                key => {
                    state.session_generation.lock().await.insert(key.to_string(), 1);
                }
            }
            let stopped = stop_tunnels_started_too_late(&state.session_generation, &state.tunnels, "s", before, &epoch, &["t1".to_string()]).await;
            assert_eq!(stopped, change != "none", "{change}");
            assert_eq!(state.tunnels.lock().await.is_empty(), change != "none", "{change}");
        }
    }
}

/// N-015: a connection checks its generation once, when it registers. If a
/// disconnect or a profile lock ran while it then started its tunnels, they
/// would keep listening with no session behind them: stop them again.
async fn stop_tunnels_if_superseded(
    generations: &Arc<tokio::sync::Mutex<std::collections::HashMap<String, u64>>>,
    key: &str,
    generation: u64,
    tunnels: &tunnel::TunnelMap,
    started: &[String],
) {
    if started.is_empty() || generations.lock().await.get(key).copied().unwrap_or(0) == generation {
        return;
    }
    for id in started {
        let _ = tunnel::stop_tunnel(tunnels, id).await;
    }
}

#[tauri::command]
async fn start_tunnel(
    app: tauri::AppHandle,
    state: tauri::State<'_, SshState>,
    session_id: String,
    spec: tunnel::TunnelSpec,
) -> Result<String, String> {
    // Dedicated-transport aware: rides the `::fwd` connection when one is up,
    // the primary otherwise. The tunnel is TAGGED under the plain session id
    // either way, so the Tunnels panel / list / teardown never re-key.
    let epoch = state.epoch();
    let before = tunnel_transport_generations(&state.session_generation, &session_id).await;
    let (handle, forwarded) = resolve_tunnel_transport(state.inner(), &session_id).await?;
    let id = tunnel::start_tunnel(tunnel_events(&app), session_id.clone(), handle, Arc::clone(&state.tunnels), forwarded, spec.clone()).await?;
    let stale = stop_tunnels_started_too_late(&state.session_generation, &state.tunnels, &session_id, before, &epoch, std::slice::from_ref(&id));
    if stale.await {
        return Err("The session was closed or reconnected while the tunnel started; start it again.".into());
    }
    // Record this ad-hoc spec against the session so a future reconnect can
    // re-open it. Dedup against (kind, local, remote) so toggling the same
    // tunnel off-and-on doesn't accumulate duplicates.
    {
        let mut map = state.session_tunnel_specs.lock().await;
        if epoch.current() {
            let entry = map.entry(session_id).or_insert_with(Vec::new);
            if !entry.contains(&spec) {
                entry.push(spec);
            }
        }
    }
    Ok(id)
}

#[tauri::command]
async fn stop_tunnel(
    state: tauri::State<'_, SshState>,
    tunnel_id: String,
) -> Result<(), String> {
    // Snapshot spec + session BEFORE stop — the listener task removes itself
    // from the tunnels map on exit, racing this lookup. With the snapshot in
    // hand we can drop the matching entry from the session's replay list so
    // a user who explicitly stopped a tunnel doesn't see it return on the
    // next reconnect.
    let snapshot = {
        let map = state.tunnels.lock().await;
        match map.get(&tunnel_id) {
            Some(t) => {
                let status = t.status.lock().await;
                Some((t.spec.clone(), status.session_id.clone()))
            }
            None => None,
        }
    };
    tunnel::stop_tunnel(&state.tunnels, &tunnel_id).await?;
    if let Some((spec, sid)) = snapshot {
        let mut map = state.session_tunnel_specs.lock().await;
        if let Some(list) = map.get_mut(&sid) {
            list.retain(|s| s != &spec);
        }
    }
    Ok(())
}

#[tauri::command]
async fn list_tunnels(
    state: tauri::State<'_, SshState>,
    session_id: Option<String>,
) -> Result<Vec<tunnel::TunnelStatus>, String> {
    Ok(tunnel::list_tunnels(&state.tunnels, session_id.as_deref()).await)
}

/// Persist the session's current live tunnel set to the node's saved `tunnels`
/// column so ad-hoc port-forwards a user adds (or removes) during a session
/// survive to the next time the node is opened. The Tunnels panel calls this
/// after a successful start/stop. A quick-connect session (server_id <= 0) has
/// no node to save to, so it's a no-op.
#[tauri::command]
async fn persist_session_tunnels(
    state: tauri::State<'_, SshState>,
    db_state: tauri::State<'_, DbState>,
    session_id: String,
    server_id: i32,
) -> Result<(), String> {
    if server_id <= 0 {
        return Ok(());
    }
    let specs = state
        .session_tunnel_specs
        .lock()
        .await
        .get(&session_id)
        .cloned()
        .unwrap_or_default();
    let json = serde_json::to_string(&specs).unwrap_or_else(|_| "[]".to_string());
    {
        // Scoped so the non-Send rusqlite guard drops before save_vault_internal.
        let conn_guard = db_state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
        let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
        conn.execute(
            "UPDATE servers SET tunnels=?1 WHERE id=?2",
            rusqlite::params![json, server_id],
        )
        .map_err(|e| format!("[DATABASE] TUNNELS_SAVE_FAILED: SQL_ERROR={}", e))?;
    }
    save_vault_internal(&db_state)?;
    Ok(())
}

/// (Re)start every tunnel the session should have — the in-memory replay list
/// when it's non-empty, else the node's saved tunnels JSON — on the best
/// available transport (`::fwd` when the dedicated connection is up, primary
/// otherwise). Idempotent: specs already running under the session's tag are
/// skipped. The frontend calls this to restore forwarding after the dedicated
/// connection fails or is toggled off, so tunnels always land somewhere.
#[tauri::command]
async fn restart_session_tunnels(
    app: tauri::AppHandle,
    state: tauri::State<'_, SshState>,
    db_state: tauri::State<'_, DbState>,
    session_id: String,
    server_id: i32,
) -> Result<(), String> {
    // In-memory replay list first — it carries ad-hoc tunnels too. A PRESENT
    // list (even empty) is authoritative (user stopped everything); only seed
    // from the node's saved tunnels when the key is ABSENT (first engagement),
    // so explicitly-stopped tunnels don't resurrect on a restore.
    let epoch = state.epoch();
    let existing: Option<Vec<tunnel::TunnelSpec>> =
        state.session_tunnel_specs.lock().await.get(&session_id).cloned();
    let mut specs: Vec<tunnel::TunnelSpec> = existing.clone().unwrap_or_default();
    if existing.is_none() && server_id > 0 {
        // Nested block so the non-Send rusqlite guard drops before any await.
        let tunnels_json: String = {
            let conn_guard = db_state.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
            let conn = conn_guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
            let mut stmt = conn
                .prepare("SELECT tunnels FROM servers WHERE id=?1")
                .map_err(|e| e.to_string())?;
            let mut rows = stmt.query([server_id]).map_err(|e| e.to_string())?;
            match rows.next().map_err(|e| e.to_string())? {
                Some(row) => row
                    .get::<_, Option<String>>(0)
                    .unwrap_or_default()
                    .unwrap_or_else(|| "[]".to_string()),
                None => "[]".to_string(),
            }
        };
        specs = serde_json::from_str(&tunnels_json).unwrap_or_default();
        if !specs.is_empty() {
            let mut map = state.session_tunnel_specs.lock().await;
            if epoch.current() {
                map.insert(session_id.clone(), specs.clone());
            }
        }
    }
    if specs.is_empty() {
        return Ok(());
    }

    let before = tunnel_transport_generations(&state.session_generation, &session_id).await;
    let (handle, targets) = resolve_tunnel_transport(state.inner(), &session_id).await?;
    let started = start_tunnel_specs_on(
        &app,
        &session_id,
        &handle,
        &targets,
        &state.tunnels,
        &state.session_tunnel_specs,
        specs,
        &epoch,
    )
    .await;
    stop_tunnels_started_too_late(&state.session_generation, &state.tunnels, &session_id, before, &epoch, &started).await;
    Ok(())
}

// ----- Mirror commands -----------------------------------------------------

#[tauri::command]
async fn mirror_dry_run(
    ssh: tauri::State<'_, SshState>,
    session_id: String,
    spec: mirror::MirrorSpec,
) -> Result<mirror::DryRunReport, String> {
    mirror_available()?;
    refuse_if_terminal_only(&ssh, &session_id)?;
    let handle = {
        let conns = ssh.connections.lock().await;
        conns.get(&session_id).cloned()
            .ok_or_else(|| "Session not connected".to_string())?
    };
    mirror::dry_run(handle, spec).await
}

#[tauri::command]
async fn start_mirror(
    app: tauri::AppHandle,
    ssh: tauri::State<'_, SshState>,
    mirrors: tauri::State<'_, MirrorMap>,
    session_id: String,
    spec: mirror::MirrorSpec,
) -> Result<String, String> {
    mirror_available()?;
    refuse_if_terminal_only(&ssh, &session_id)?;
    // A lock that runs while this mirror starts sweeps the mirrors before it
    // is registered; while one runs, nothing new starts (N-020).
    let epoch = ssh.epoch();
    if epoch.closing() {
        return Err(ssh_manager::PROFILE_CLOSING_MSG.into());
    }
    let before = ssh.session_generation.lock().await.get(&session_id).copied().unwrap_or(0);
    let handle = {
        let conns = ssh.connections.lock().await;
        conns.get(&session_id).cloned()
            .ok_or_else(|| "Session not connected".to_string())?
    };
    let id = mirror::start(mirror_events(&app), session_id.clone(), handle, Arc::clone(&mirrors), spec).await?;
    if stop_mirror_started_too_late(&ssh.session_generation, &mirrors, &session_id, before, &epoch, &id).await {
        return Err("The session was disconnected or the profile locked while the mirror started, so it was stopped again.".into());
    }
    Ok(id)
}

/// A mirror rides SFTP, whose file panel is what finds a refusing server first
/// (the mirror tab sits behind it), so checking here is enough.
fn refuse_if_terminal_only(ssh: &SshState, session_id: &str) -> Result<(), String> {
    match ssh.channel_gate(session_id).limit() {
        Some(why) => Err(why.refusal().to_string()),
        None => Ok(()),
    }
}

/// Folder mirror is desktop-only (owner decision): the tab is hidden on
/// Android, and its file-system watcher does not fit Android's storage.
fn mirror_available() -> Result<(), String> {
    if cfg!(target_os = "android") {
        return Err("Folder mirror is not available on Android.".into());
    }
    Ok(())
}

/// A mirror registered after a disconnect, a reconnect or a profile lock had
/// already swept the session's mirrors would run with nothing to show or
/// stop it (N-020): stop it again. `before`: the session's generation when
/// the start began.
async fn stop_mirror_started_too_late(
    generations: &Arc<tokio::sync::Mutex<std::collections::HashMap<String, u64>>>,
    mirrors: &MirrorMap,
    session_id: &str,
    before: u64,
    epoch: &ssh_manager::ProfileEpoch,
    id: &str,
) -> bool {
    let now = generations.lock().await.get(session_id).copied().unwrap_or(0);
    if epoch.current() && now == before {
        return false;
    }
    let _ = mirror::stop(mirrors, id).await;
    true
}

/// The mirror's reports as window events. The only place a mirror meets the
/// `AppHandle` (see `mirror::MirrorEvents`).
fn mirror_events(app: &tauri::AppHandle) -> mirror::MirrorEvents {
    use tauri::Emitter;
    let (updates, logs) = (app.clone(), app.clone());
    mirror::MirrorEvents {
        update: Arc::new(move |status: &mirror::MirrorStatus| {
            let _ = updates.emit(&format!("mirror-update-{}", status.session_id), status);
        }),
        log: Arc::new(move |session_id: &str, entry: &mirror::MirrorLogEntry<'_>| {
            let _ = logs.emit(&format!("mirror-log-{}", session_id), entry);
        }),
    }
}

#[tauri::command]
async fn stop_mirror(
    mirrors: tauri::State<'_, MirrorMap>,
    mirror_id: String,
) -> Result<(), String> {
    mirror::stop(&mirrors, &mirror_id).await
}

/// Apply the deletions a mirror's mass-delete guard is holding (F-008).
#[tauri::command]
async fn resume_mirror(
    mirrors: tauri::State<'_, MirrorMap>,
    mirror_id: String,
) -> Result<(), String> {
    mirror::resume(&mirrors, &mirror_id).await
}

#[tauri::command]
async fn list_mirrors(
    mirrors: tauri::State<'_, MirrorMap>,
    session_id: Option<String>,
) -> Result<Vec<mirror::MirrorStatus>, String> {
    Ok(mirror::list(&mirrors, session_id.as_deref()).await)
}

/// Native OS folder picker. Used by MirrorsPanel to fill in `local`.
#[tauri::command]
async fn pick_local_directory() -> Result<Option<String>, String> {
    #[cfg(target_os = "android")]
    {
        return Err("Folder picker not available on Android.".into());
    }
    #[cfg(not(target_os = "android"))]
    {
        let path = rfd::AsyncFileDialog::new().pick_folder().await;
        Ok(path.map(|p| p.path().to_string_lossy().into_owned()))
    }
}

/// Ends a session as Disconnect does: everything it runs stopped, its
/// connection (and its dedicated `::sftp`/`::fwd` ones) closed with an SSH
/// disconnect. Also what ends a session the server ended (N-028).
async fn end_session(state: &SshState, mirrors: &MirrorMap, session_id: &str) {
    let session_id = session_id.to_string();
    // Invalidate any connect worker still handshaking for THIS key: bump the
    // generation before removing anything, so a late auth-success hits its
    // "still wanted?" guard and drops instead of re-registering a transport the
    // user just turned off (which would then steal / strand tunnels). Done for
    // every key, including secondaries — this is the toggle-off / reconnect-
    // button invalidation path.
    {
        let mut g = state.session_generation.lock().await;
        // A primary's dedicated connections are retired now as well, before
        // its tunnels are stopped: a `::fwd` connection moving tunnels onto
        // itself meanwhile would otherwise start them after the stop (N-015).
        let mut keys = vec![session_id.to_string()];
        if !session_id.contains("::") {
            keys.push(format!("{}::sftp", session_id));
            keys.push(format!("{}::fwd", session_id));
        }
        for key in keys {
            let next = g.get(&key).copied().unwrap_or(0).wrapping_add(1);
            g.insert(key, next);
        }
    }
    // Disconnecting a dedicated transport directly (toggle-off / reconnect
    // button): tunnels are tagged under the BASE session id but ride this
    // `::fwd` connection. Stop them ONLY when the dedicated connection actually
    // exists — i.e. the tunnels really are riding it. If it's absent (a failed
    // `::fwd` that never registered, so the tunnels fell back to the primary),
    // stopping base-tagged tunnels here would needlessly bounce every live
    // primary tunnel. The caller restarts them on the best transport via
    // restart_session_tunnels afterwards.
    if let Some(base) = session_id.strip_suffix("::fwd") {
        if state.connections.lock().await.contains_key(&session_id) {
            tunnel::stop_all_for_session(&state.tunnels, base).await;
        }
    }
    // `::sftp`: remove the dedicated transport FIRST, then purge the base SFTP
    // cache — so an SFTP op racing this teardown can't re-cache a subsystem on
    // the dying transport after the purge (get_sftp_session's still-current
    // check would then see the transport gone and refuse to cache).
    let mut ended = Vec::new();
    if session_id.ends_with("::sftp") {
        ended.extend(state.connections.lock().await.remove(&session_id));
        state.session_targets.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&session_id);
        state.channel_gates.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&session_id);
        if let Some(base) = session_id.strip_suffix("::sftp") {
            state.sftp_sessions.lock().await.remove(base);
        }
    }
    // Stop all forwarders so their listener sockets are released before the
    // SSH handle is dropped (otherwise newly-incoming connections would just
    // bounce off a dead channel).
    tunnel::stop_all_for_session(&state.tunnels, &session_id).await;
    state.forwarded_targets.lock().await.remove(&session_id);
    // Explicit user disconnect — drop the replay list too. (Auto-reconnect
    // calls `initiate_connection` directly and never hits this path, so
    // those tunnels survive the cycle.)
    state.session_tunnel_specs.lock().await.remove(&session_id);
    // Same idea for any mirror that's still running — its watcher would
    // try to push uploads through a dead SSH handle otherwise.
    mirror::stop_all_for_session(&mirrors, &session_id).await;
    // Docker live logs: each would keep the connection up and its
    // `docker logs -f` running on the server (F-041).
    state.docker_streams.stop_session(&session_id).await;
    // Drop SFTP first so the channel it holds is freed before we tear down the
    // underlying SSH handle.
    state.sftp_sessions.lock().await.remove(&session_id);
    ended.extend(state.connections.lock().await.remove(&session_id));
    state.session_targets.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&session_id);
    state.channel_gates.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&session_id);
    // Drop the Info tab's live-strip snapshot cache too — otherwise a
    // reconnect's first sample would diff CPU%/network against a snapshot
    // from the dead connection instead of correctly reporting "no previous
    // sample yet".
    state.info_probes.lock().await.remove(&session_id);
    // Drop any ProxyJump bastion handle for this session — closes the jump
    // connection once the target it was carrying is gone.
    ended.extend(state.jump_connections.lock().await.remove(&session_id).map(|h| Arc::new(tokio::sync::Mutex::new(h))));
    // Drop terminal tx/resize entries so a subsequent reconnect doesn't try
    // to write into a dead PTY task. Match by the exact `${session_id}-term-`
    // prefix — a `contains` here silently tears down session-10's terminals
    // when the user disconnects session-1.
    let term_prefix = format!("{}-term-", session_id);
    state.terminal_txs.lock().await.retain(|k, _| !k.starts_with(&term_prefix));
    state.resize_txs.lock().await.retain(|k, _| !k.starts_with(&term_prefix));
    // End this session's live edits: each staging copy is deleted, or kept
    // (and reported) when it holds changes that were not uploaded.
    state.live_edits.stop_session(&session_id, live_edit::StopReason::Disconnected);
    // Separate-sessions: reap the dedicated `::sftp` / `::fwd` secondaries so an
    // explicit primary disconnect doesn't leak their SSH sessions. Only when
    // this IS a primary id (no `::` suffix) — a direct disconnect of a secondary
    // must not recurse into non-existent grandchildren.
    if !session_id.contains("::") {
        teardown_connection_key(state, mirrors, &format!("{}::sftp", session_id)).await;
        teardown_connection_key(state, mirrors, &format!("{}::fwd", session_id)).await;
    }
    // Ended explicitly: a stream or transfer that started while this ran
    // and still holds a channel would otherwise keep the connection up.
    ssh_connect::close_handles(ended, ssh_connect::CLOSE_TIMEOUT).await;
}

#[tauri::command]
async fn disconnect_session(
    app: tauri::AppHandle,
    state: tauri::State<'_, SshState>,
    mirrors: tauri::State<'_, MirrorMap>,
    session_id: String,
) -> Result<(), String> {
    end_session(&state, &mirrors, &session_id).await;
    // Tell the UI so the tab status dot flips to red. `user_initiated` keeps
    // SessionView from kicking off an auto-reconnect cycle for an intentional
    // disconnect — distinct from the watcher path which has no such flag.
    use tauri::Emitter;
    let _ = app.emit(
        &format!("session-disconnected-{}", session_id),
        serde_json::json!({
            "reason": "User disconnected",
            "user_initiated": true,
        }),
    );
    Ok(())
}

/// The server ended a terminal of `session_id` (`exit`, an idle logout, a
/// reboot). If it was the session's last one, the session ends as with
/// Disconnect, so nothing stays logged in on the server, and the window hears
/// that the server ended it: no auto-reconnect, R logs in again (N-028). A
/// terminal that ends while others of the session run leaves the connection to
/// them. `connection`: the one the terminal ran on; a reconnect may have
/// replaced it meanwhile, and the new one is left alone.
async fn end_session_after_its_last_terminal(
    app: &tauri::AppHandle,
    session_id: &str,
    connection: &std::sync::Weak<tokio::sync::Mutex<russh::client::Handle<ssh_manager::ClientHandler>>>,
) {
    use tauri::{Emitter, Manager};
    let state = app.state::<SshState>();
    if ssh_manager::terminals_left(&state.terminal_txs, session_id).await > 0 {
        return;
    }
    let Some(connection) = connection.upgrade() else { return };
    let current = state.connections.lock().await.get(session_id).is_some_and(|c| Arc::ptr_eq(c, &connection));
    drop(connection);
    if !current {
        return;
    }
    end_session(&state, &app.state::<MirrorMap>(), session_id).await;
    let reason = "the server ended the shell, and it was this session's last terminal, so Solanum closed the connection";
    let _ = app.emit(&format!("session-log-{}", session_id), json!({ "msg": format!("Session ended: {reason}."), "type": "info" }));
    let _ = app.emit(&format!("session-disconnected-{}", session_id), json!({ "reason": reason, "logged_out": true }));
}

#[tauri::command]
/// `Ok(Some(reason))`: the terminal runs, but its session log could not be
/// started (N-007).
async fn open_terminal(app: tauri::AppHandle, state: tauri::State<'_, SshState>, session_id: String, terminal_id: String, cols: u32, rows: u32, log_file_path: Option<String>) -> Result<Option<String>, String> {
    use tauri::Emitter;
    use std::sync::Arc;
    use crate::ssh_manager::{TerminalCommand, start_session_log};

    let session_arc = {
        let mut connections = state.connections.lock().await;
        if let Some(sess) = connections.get_mut(&session_id) {
            Arc::clone(sess)
        } else {
            return Err("Session not connected".into());
        }
    };

    // Bounded, and the connection mutex is released right after the open
    // (F-028): request_pty / request_shell below only send.
    let channel = ssh_connect::open_terminal_channel(&session_arc, &state.channel_gate(&session_id)).await?;

    // Request PTY
    channel.request_pty(false, "xterm-256color", cols, rows, 0, 0, &[]).await.map_err(|e| e.to_string())?;
    channel.request_shell(true).await.map_err(|e| e.to_string())?;

    let (tx, rx) = tokio::sync::mpsc::channel::<TerminalCommand>(32);
    // Last-wins watch channel for PTY resizes. The PTY task selects on
    // changes; bursty resize events (e.g. window drag) collapse to the
    // final value rather than competing with keystrokes on the data
    // mpsc. Seed with the initial size so the watch is always populated.
    let (resize_tx, resize_rx) = tokio::sync::watch::channel(
        crate::ssh_manager::PtySize { cols, rows },
    );
    state.terminal_txs.lock().await.insert(terminal_id.clone(), tx);
    state.resize_txs.lock().await.insert(terminal_id.clone(), resize_tx);

    let terminal_id_clone = terminal_id.clone();
    let app_clone = app.clone();
    let (txs, resizes) = (Arc::clone(&state.terminal_txs), Arc::clone(&state.resize_txs));
    let connection = Arc::downgrade(&session_arc);
    // "Always save terminal output to file" (Settings > Terminal): the
    // frontend built the full path and sends one only when the setting is
    // on. The log gets the raw channel bytes (`terminal_io::pump`).
    let (session_log, log_problem) = start_session_log(&log_file_path).await;

    tauri::async_runtime::spawn(async move {
        let emit = |bytes: &[u8]| crate::ssh_manager::emit_terminal_batch(&app_clone, &terminal_id_clone, bytes);
        let ended = crate::terminal_io::pump(crate::terminal_io::SshTerminal::new(channel), rx, resize_rx, session_log, emit).await;
        crate::ssh_manager::forget_ended_terminal(&txs, &resizes, &terminal_id_clone).await;
        let _ = app_clone.emit(&format!("terminal-closed-{}", terminal_id_clone), serde_json::json!({}));
        if ended == crate::terminal_io::Ended::ByPeer {
            end_session_after_its_last_terminal(&app_clone, &session_id, &connection).await;
        }
    });

    Ok(log_problem)
}

#[tauri::command]
async fn write_terminal_data(state: tauri::State<'_, SshState>, terminal_id: String, data: Vec<u8>) -> Result<(), String> {
    use crate::ssh_manager::TerminalCommand;
    // Clone the Sender OUT of the map, then release the map lock before we
    // await on send(). If we held the guard across the send, a saturated
    // 32-slot mpsc on a slow SSH link would block every other terminal's
    // write path — one slow terminal freezes the entire app-wide typing
    // experience because the shared map guard is a global gate.
    // mpsc::Sender is cheap to clone.
    let tx = state.terminal_txs.lock().await.get(&terminal_id).cloned();
    if let Some(tx) = tx {
        let _ = tx.send(TerminalCommand::Data(data)).await;
    }
    Ok(())
}

/// The window has processed `bytes` of this terminal's output; without these
/// the terminal stops sending output to the window after
/// `terminal_io::MAX_UNACKED` (F-031).
#[tauri::command]
async fn ack_terminal_output(state: tauri::State<'_, SshState>, terminal_id: String, bytes: u32) -> Result<(), String> {
    use crate::ssh_manager::TerminalCommand;
    let tx = state.terminal_txs.lock().await.get(&terminal_id).cloned();
    if let Some(tx) = tx {
        let _ = tx.send(TerminalCommand::Ack(bytes as usize)).await;
    }
    Ok(())
}

/// Real OS clipboard access for reading (only) — not the webview's own
/// navigator.clipboard: WebKitGTK's Async Clipboard API readText() only
/// reliably returns text the page itself just wrote, and denies reading
/// clipboard content set by any other application — so pasting anything
/// copied from outside Solanum silently failed. writeText() was never
/// reported broken, so copy stays on navigator.clipboard.writeText() in
/// TerminalView.tsx, same as every other copy-to-clipboard button in the
/// app — this command exists only for the read side that actually needed
/// fixing. tauri-plugin-clipboard-manager talks to the OS clipboard over
/// Tauri's own IPC instead, unaffected by any webview's clipboard permission
/// model. Used only from Rust, same as tauri-plugin-opener's
/// open_external_url in about.rs — no clipboard-manager:* permission is
/// needed in capabilities/default.json because the webview never calls the
/// plugin directly, only this command.
///
/// `async fn`, not a plain `fn`: `Clipboard::read_text()`'s own doc comment
/// warns it "should not be used on the main thread! Otherwise the underlying
/// libraries may deadlock on Linux... if the user copies text from the
/// WebView" — a plain `fn` command runs inline on the thread handling the
/// IPC call (Tauri's synchronous dispatch path), which on WebKitGTK/X11 can
/// be the same thread an X11 SelectionRequest needs serviced on, causing
/// exactly that deadlock. `async fn` routes it through Tauri's async
/// dispatch (`tauri::async_runtime::spawn`) instead, off that thread —
/// matching how the plugin's own upstream `read_text` command is `async fn`
/// for the same reason.
///
/// Trust: any script running in the webview can call this, just as the UI's
/// paste does; no token or gesture check can tell the two apart from here
/// (F-056, accepted and documented in SECURITY.md). It is refused while the
/// window does not have the focus, so a script cannot sample the clipboard
/// while the user copies a password in another app.
#[tauri::command]
async fn read_clipboard_text(app: tauri::AppHandle, window: tauri::WebviewWindow) -> Result<String, String> {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    #[cfg(not(target_os = "android"))]
    if !clipboard_read_allowed(window.is_focused()) {
        return Err("[CLIPBOARD] NOT_FOCUSED: click into the Solanum window, then paste again".into());
    }
    #[cfg(target_os = "android")]
    let _ = &window;
    match app.clipboard().read_text() {
        Ok(text) => Ok(text),
        // An empty clipboard (or one holding something that isn't text, e.g.
        // a copied image) surfaces as this specific, stable arboard error
        // message, not as "" the way navigator.clipboard.readText() used to
        // — treat it the same way that was already treated: nothing to
        // paste, not a failure. Any other error is a genuine problem and
        // still surfaces as one.
        Err(e) if e.to_string().contains("clipboard is empty") => Ok(String::new()),
        Err(e) => Err(format!("[CLIPBOARD] {}", e)),
    }
}

/// Whether the window's focus state allows a clipboard read: only a definite
/// "not focused" refuses. If the platform cannot tell, paste keeps working.
#[cfg_attr(target_os = "android", allow(dead_code))]
fn clipboard_read_allowed<E>(focused: Result<bool, E>) -> bool {
    !matches!(focused, Ok(false))
}

#[tauri::command]
async fn resize_terminal(state: tauri::State<'_, SshState>, terminal_id: String, cols: u32, rows: u32) -> Result<(), String> {
    if let Some(tx) = state.resize_txs.lock().await.get(&terminal_id) {
        // send_replace overwrites the current value unconditionally —
        // perfect for a coalescing last-wins channel.
        let _ = tx.send(crate::ssh_manager::PtySize { cols, rows });
    }
    Ok(())
}

#[tauri::command]
async fn close_terminal(state: tauri::State<'_, SshState>, terminal_id: String) -> Result<(), String> {
    state.terminal_txs.lock().await.remove(&terminal_id);
    state.resize_txs.lock().await.remove(&terminal_id);
    Ok(())
}

// Read-only Info-panel probes. Each tab fetches its own section on first
// click — the user explicitly wanted lazy per-tab fetch instead of one
// upfront mega-probe. Splitting the scripts keeps each round-trip small
// (≤200 ms typical) and lets a failing section never block the others.
const INFO_SCRIPT_OVERVIEW: &str = r#"echo __SUB_INFO_OV_SEP__
hostname 2>/dev/null
echo __SUB_INFO_OV_SEP__
( . /etc/os-release 2>/dev/null && printf "%s" "$PRETTY_NAME" ) || cat /etc/issue 2>/dev/null
printf "\n"
echo __SUB_INFO_OV_SEP__
uname -srm 2>/dev/null
echo __SUB_INFO_OV_SEP__
uptime 2>/dev/null
echo __SUB_INFO_OV_SEP__
# Memory. procps `free -b` gives bytes + an `available` column; busybox `free`
# ignores `-b` (prints KiB) and has no `available`, so fall back to the
# universal /proc/meminfo (kB) with a format tag the frontend switches on.
if F=$(free -b 2>/dev/null) && printf '%s' "$F" | grep -q '^Mem:'; then
  printf 'MEMFMT:free-b\n'; printf '%s\n' "$F"
else
  printf 'MEMFMT:meminfo\n'; cat /proc/meminfo 2>/dev/null
fi
echo __SUB_INFO_OV_SEP__
# Disks. `-T` (fs-type column) + `-k` (1 KiB blocks) is GNU coreutils; busybox
# df lacks `-T`, so fall back to the no-type layout. `-k` pins the block size
# so the frontend's *1024 is always correct.
if D=$(df -PTk 2>/dev/null) && [ -n "$D" ]; then
  printf 'DFFMT:pt\n'; printf '%s\n' "$D"
else
  printf 'DFFMT:p\n'; df -Pk 2>/dev/null
fi
echo __SUB_INFO_OV_SEP__
# CPU count: coreutils nproc -> POSIX getconf -> /proc/cpuinfo (universal floor).
nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null
echo __SUB_INFO_OV_SEP__
cat /proc/loadavg 2>/dev/null
echo __SUB_INFO_OV_SEP__
"#;

// Network probe layout (sections delimited by SEP):
//   [0] empty (printed before first SEP)
//   [1] NIC list   — first line `ADDRFMT:<ip-json|ip-oneline|ifconfig|none>`
//   [2] route table — first line `ROUTEFMT:<ip-json|ip-oneline|route|netstat|none>`
//   [3] firewall summary:
//         line 1: 'FW:<engine>' where engine is one of
//                 firewalld | firewalld-sudo |
//                 ufw       | ufw-sudo       |
//                 iptables  | iptables-sudo  | iptables-denied |
//                 nft       | nft-sudo       | nft-denied       | none
//         A high-level manager (firewalld on RHEL/Fedora, ufw on Ubuntu) is
//         detected FIRST and, when running, shown instead of the raw tables
//         it auto-generates. Body rows depend on the engine:
//                 firewalld: 'DEFAULT|<zone>' then per active zone
//                            'ZONE|<zone>|<interfaces>',
//                            'SVC|<zone>|<services>', 'PORT|<zone>|<ports>'
//                 ufw:       'UFW|active' then the raw `ufw status verbose`
//                            lines, shown verbatim (already human-readable)
//                 iptables:  'table|chain|policy|count'
//                 nft:       'family|table|chain|type|count'
//         For iptables/nft the rows are per-chain summaries, not the full
//         ruleset — the ruleset for a specific chain is fetched lazily on
//         expand via ssh_iptables_chain / ssh_nft_chain — the wire cost
//         of first paint drops from ~50-500 KB to ~1-2 KB, which is the
//         single biggest bandwidth win for low-bandwidth SSH users.
//         firewalld/ufw summaries are already compact, so they ship inline.
//   [4] DNS resolvers — first line `DNSFMT:list`, then raw lines from
//         resolvectl / systemd-resolve / resolv.conf; the frontend extracts
//         IPs, dedupes, and flags the systemd-resolved 127.0.0.53 stub.
// The firewall block tries the user's own credentials first, falls back to
// non-interactive sudo (`sudo -n`) so we never hang waiting for a password,
// and prefers iptables over nft because iptables-nft on modern Debian-family
// systems still reports both — picking iptables gives a consistent first
// hit even on hybrid hosts.
const INFO_SCRIPT_NETWORK: &str = r#"echo __SUB_INFO_NET_SEP__
# NIC addresses. First line is a format tag the frontend switches on. `ip -j`
# (JSON) needs iproute2 >= 4.13, so RHEL/CentOS 7 (4.11) falls back to the
# text `ip -o` layout, then net-tools ifconfig for hosts without `ip` at all.
if J=$(ip -j addr 2>/dev/null) && [ -n "$J" ]; then
  printf 'ADDRFMT:ip-json\n'; printf '%s\n' "$J"
elif command -v ip >/dev/null 2>&1; then
  printf 'ADDRFMT:ip-oneline\n'
  ip -o link show 2>/dev/null
  echo __SUB_INFO_NET_SUB__
  ip -o addr show 2>/dev/null
elif command -v ifconfig >/dev/null 2>&1; then
  printf 'ADDRFMT:ifconfig\n'; ifconfig -a 2>/dev/null
else
  printf 'ADDRFMT:none\n'
fi
echo __SUB_INFO_NET_SEP__
# Routes, same tag+fallback idea.
if J=$(ip -j route 2>/dev/null) && [ -n "$J" ]; then
  printf 'ROUTEFMT:ip-json\n'; printf '%s\n' "$J"
elif command -v ip >/dev/null 2>&1; then
  printf 'ROUTEFMT:ip-oneline\n'; ip -o route show 2>/dev/null
elif command -v route >/dev/null 2>&1; then
  printf 'ROUTEFMT:route\n'; route -n 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then
  printf 'ROUTEFMT:netstat\n'; netstat -rn 2>/dev/null
else
  printf 'ROUTEFMT:none\n'
fi
echo __SUB_INFO_NET_SEP__
# High-level firewall managers FIRST. On RHEL/Fedora/Rocky/Alma (firewalld) and
# Ubuntu (ufw) the raw iptables/nft ruleset is auto-generated boilerplate the
# manager owns — showing it is confusing and doesn't reflect the operator's
# actual zones/rules. So when a manager is actually RUNNING we surface ITS view
# and skip the raw tables; only if no manager is active do we fall through to
# iptables -> nft -> none below. `FW_DONE` gates that fall-through.
FW_DONE=""
# firewalld (RHEL family default). `--state` and the list queries work over
# D-Bus and are usually readable without root; sudo -n is a fallback.
if command -v firewall-cmd >/dev/null 2>&1; then
  FC=""
  # `firewall-cmd --state` exits 0 only when the daemon is RUNNING (252 when
  # not). Rely on the exit code, not a grep — "not running" contains the
  # substring "running", so grepping would false-positive on a stopped daemon.
  if firewall-cmd --state >/dev/null 2>&1; then
    FC="firewall-cmd"; printf 'FW:firewalld\n'
  elif sudo -n firewall-cmd --state >/dev/null 2>&1; then
    FC="sudo -n firewall-cmd"; printf 'FW:firewalld-sudo\n'
  fi
  if [ -n "$FC" ]; then
    FW_DONE=1
    printf 'DEFAULT|%s\n' "$($FC --get-default-zone 2>/dev/null)"
    for Z in $($FC --get-active-zones 2>/dev/null | awk '/^[^ \t]/{print $1}'); do
      printf 'ZONE|%s|%s\n' "$Z" "$($FC --zone="$Z" --list-interfaces 2>/dev/null)"
      printf 'SVC|%s|%s\n'  "$Z" "$($FC --zone="$Z" --list-services 2>/dev/null)"
      printf 'PORT|%s|%s\n' "$Z" "$($FC --zone="$Z" --list-ports 2>/dev/null)"
    done
  fi
fi
# ufw (Debian/Ubuntu). Only surface it when ACTIVE — an installed-but-inactive
# ufw means the host is really using the raw tables, so fall through instead.
# `ufw status` needs root, so try direct then sudo -n.
if [ -z "$FW_DONE" ] && command -v ufw >/dev/null 2>&1; then
  US=""; SUF=""
  if ufw status verbose 2>/dev/null | grep -qi 'Status:'; then
    US=$(ufw status verbose 2>/dev/null)
  elif sudo -n ufw status verbose 2>/dev/null | grep -qi 'Status:'; then
    US=$(sudo -n ufw status verbose 2>/dev/null); SUF="-sudo"
  fi
  if printf '%s\n' "$US" | grep -qiE 'Status:[[:space:]]*active'; then
    printf 'FW:ufw%s\n' "$SUF"
    printf 'UFW|active\n'
    printf '%s\n' "$US"
    FW_DONE=1
  fi
fi
if [ -z "$FW_DONE" ] && command -v iptables >/dev/null 2>&1; then
  IPT=""
  # `-S` (rule-spec dump) is lighter than `-L`: no formatted table, no counter
  # columns, no reverse-DNS, no header rows — just the rules, which is all the
  # per-chain summary needs. The full ruleset for one chain is still fetched
  # lazily on expand via ssh_iptables_chain.
  if iptables -t filter -S >/dev/null 2>&1; then
    IPT="iptables"; printf 'FW:iptables\n'
  elif sudo -n iptables -t filter -S >/dev/null 2>&1; then
    IPT="sudo -n iptables"; printf 'FW:iptables-sudo\n'
  else
    printf 'FW:iptables-denied\n'
  fi
  if [ -n "$IPT" ]; then
    for T in filter nat mangle raw; do
      # -P <chain> <policy> = built-in chain + policy; -N <chain> = custom chain
      # (policy '-'); -A <chain> ... = one rule. Emit 'table|chain|policy|count'.
      $IPT -t $T -S 2>/dev/null | awk -v t="$T" '
        /^-P / { pol[$2]=$3; if(!($2 in seen)){seen[$2]=1; order[++n]=$2} next }
        /^-N / { if(!($2 in seen)){seen[$2]=1; order[++n]=$2; pol[$2]="-"} next }
        /^-A / { c=$2; cnt[c]++; if(!(c in seen)){seen[c]=1; order[++n]=c; pol[c]="-"} next }
        END { for(i=1;i<=n;i++){ ch=order[i]; print t "|" ch "|" (ch in pol?pol[ch]:"-") "|" (cnt[ch]+0) } }
      '
    done
  fi
elif [ -z "$FW_DONE" ] && command -v nft >/dev/null 2>&1; then
  NFT=""
  if nft list ruleset >/dev/null 2>&1; then
    NFT="nft"; printf 'FW:nft\n'
  elif sudo -n nft list ruleset >/dev/null 2>&1; then
    NFT="sudo -n nft"; printf 'FW:nft-sudo\n'
  else
    printf 'FW:nft-denied\n'
  fi
  if [ -n "$NFT" ]; then
    $NFT list ruleset 2>/dev/null | awk '
      /^table / { fam=$2; tbl=$3; chain=""; next }
      /^\tchain / { chain=$2; type=""; count=0; next }
      /^\tset / || /^\tmap / || /^\tflowtable / || /^\tct / {
        if (chain != "") { print fam "|" tbl "|" chain "|" type "|" count; chain="" }
        chain=""; next
      }
      /^\t}/ {
        if (chain != "") { print fam "|" tbl "|" chain "|" type "|" count; chain="" }
        next
      }
      chain == "" { next }
      $1 == "type" { type=$2; next }
      $1 == "hook" || $1 == "policy" || $1 == "priority" || $1 == "flags" || $1 == "device" { next }
      NF > 0 { count++ }
    '
  fi
elif [ -z "$FW_DONE" ]; then
  printf 'FW:none\n'
fi
echo __SUB_INFO_NET_SEP__
# DNS resolvers. systemd-resolved stubs /etc/resolv.conf at 127.0.0.53 and hides
# the real upstreams behind resolvectl, so we gather from BOTH sources and let
# the frontend extract IPs, dedupe, and flag the local stub. `systemd-resolve`
# is the pre-239 name for resolvectl. Always emits the DNSFMT tag so the
# frontend can tell "no resolvers found" from "section missing".
printf 'DNSFMT:list\n'
if command -v resolvectl >/dev/null 2>&1; then
  resolvectl dns 2>/dev/null
elif command -v systemd-resolve >/dev/null 2>&1; then
  systemd-resolve --status 2>/dev/null | grep -iE 'DNS Servers|Current DNS Server'
fi
if [ -r /etc/resolv.conf ]; then
  grep -E '^[[:space:]]*nameserver[[:space:]]' /etc/resolv.conf 2>/dev/null
fi
"#;

// Ports: ss is preferred (parseable, modern). Falls back to netstat. The -p
// flag returns process info for sockets the user owns; non-root users see
// blank process columns for foreign sockets — that's a permission limit, not
// an error. We surface it gracefully on the UI.
const INFO_SCRIPT_PORTS: &str = r#"if command -v ss >/dev/null 2>&1; then
  printf 'ENGINE:ss\n'
  ss -tuln -p 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then
  printf 'ENGINE:netstat\n'
  netstat -tulnp 2>/dev/null
else
  printf 'ENGINE:none\n'
fi
"#;

// Process list for the Processes tab. First line is a format tag the frontend
// switches on. Prefer the procps `-eo` custom format (Linux); fall back to
// BSD-style `ps aux` for busybox / minimal userlands. Sorting + capping happen
// client-side so the probe stays a single cheap snapshot suitable for a ~1s
// auto-refresh.
const INFO_SCRIPT_PROCESSES: &str = r#"if ps -eo pid,user,pcpu,pmem,rss,comm >/dev/null 2>&1; then
  printf 'PSFMT:full\n'
  ps -eo pid,user,pcpu,pmem,rss,comm 2>/dev/null
elif ps aux >/dev/null 2>&1; then
  printf 'PSFMT:aux\n'
  ps aux 2>/dev/null
else
  printf 'PSFMT:none\n'
  ps 2>/dev/null
fi
"#;

const INFO_SCRIPT_SERVICES: &str = r#"if command -v systemctl >/dev/null 2>&1; then
  printf 'ENGINE:systemd\n'
  systemctl list-units --type=service --no-legend --plain --no-pager --state=running,failed,activating 2>/dev/null
else
  printf 'ENGINE:none\n'
fi
"#;

const INFO_SCRIPT_DOCKER: &str = r#"if ! command -v docker >/dev/null 2>&1; then
  printf 'DOCKER:missing\n'
  exit 0
fi
if ! docker info >/dev/null 2>&1; then
  printf 'DOCKER:denied\n'
  exit 0
fi
printf 'DOCKER:ok\n'
echo __SUB_INFO_DOCK_SEP__
docker ps -a --format '{{json .}}' 2>/dev/null
echo __SUB_INFO_DOCK_SEP__
docker volume ls --format '{{json .}}' 2>/dev/null
echo __SUB_INFO_DOCK_SEP__
docker images --format '{{json .}}' 2>/dev/null
echo __SUB_INFO_DOCK_SEP__
docker system df 2>/dev/null
"#;

#[derive(serde::Serialize, Default)]
struct InfoSectionResult {
    data: String,
    truncated: bool,
    exec_ms: u64,
}

// Run a script through a fresh exec channel on the live SSH session and
// return everything it printed (up to a 1 MB cap). Stays read-only — the
// callers in this module only invoke shell built-ins and inspection tools.
async fn run_info_script(
    state: &SshState,
    session_id: &str,
    script: &str,
    timeout_secs: u64,
) -> Result<InfoSectionResult, String> {
    let session_arc = {
        let connections = state.connections.lock().await;
        connections.get(session_id).map(Arc::clone)
            .ok_or_else(|| "Session not connected".to_string())?
    };
    let probes = info_probes_for(state, session_id).await;
    probes.run(&session_arc, &state.channel_gate(session_id), script, timeout_secs).await
}

/// The Info tab's probes of one session (F-039). Every probe opens an exec
/// channel; the pollers tick every 1-5 s, and a slow server must not pile
/// channels up toward its `MaxSessions` (the terminal, SFTP and forwards
/// need them too).
pub(crate) struct InfoProbes {
    /// Probes running at once on the session's connection.
    gate: tokio::sync::Semaphore,
    /// The live strip's previous snapshot, held from reading it to storing
    /// the next one, so two samples never diff out of order.
    live: tokio::sync::Mutex<Option<monitor::RawSnapshot>>,
}

impl InfoProbes {
    const AT_ONCE: usize = 2;

    fn new() -> Self {
        InfoProbes { gate: tokio::sync::Semaphore::new(Self::AT_ONCE), live: tokio::sync::Mutex::new(None) }
    }

    /// Runs `script` once a slot is free; the wait counts in its time.
    async fn run<H: russh::client::Handler>(
        &self,
        handle: &tokio::sync::Mutex<russh::client::Handle<H>>,
        gate: &ssh_connect::ChannelGate,
        script: &str,
        timeout_secs: u64,
    ) -> Result<InfoSectionResult, String> {
        let limit = std::time::Duration::from_secs(timeout_secs);
        let started = std::time::Instant::now();
        let _slot = tokio::time::timeout(limit, self.gate.acquire())
            .await
            .map_err(|_| format!("probe timed out after {}s (other probes of this session were still running)", timeout_secs))?
            .map_err(|_| "probe cancelled".to_string())?;
        let left = limit.saturating_sub(started.elapsed()).as_secs().max(1);
        info_script_on(handle, gate, script, left).await
    }
}

async fn info_probes_for(state: &SshState, session_id: &str) -> Arc<InfoProbes> {
    let mut probes = state.info_probes.lock().await;
    Arc::clone(probes.entry(session_id.to_string()).or_insert_with(|| Arc::new(InfoProbes::new())))
}

/// `run_info_script` on a given connection.
async fn info_script_on<H: russh::client::Handler>(
    handle: &tokio::sync::Mutex<russh::client::Handle<H>>,
    gate: &ssh_connect::ChannelGate,
    script: &str,
    timeout_secs: u64,
) -> Result<InfoSectionResult, String> {
    let start = std::time::Instant::now();
    let channel = ssh_connect::open_feature_channel(handle, gate).await?;
    // 1 MB cap — defends the UI against pathological output (e.g. a server
    // with thousands of veth interfaces or hundreds of stopped containers).
    const MAX_BYTES: usize = 1024 * 1024;
    let capture = remote_exec::Capture::new(MAX_BYTES, remote_exec::Overflow::KeepHead);
    let out = remote_exec::run(channel, script, capture, None, std::time::Duration::from_secs(timeout_secs))
        .await
        .map_err(|e| match e {
            remote_exec::RunError::Start(e) => e,
            _ => format!("probe timed out after {}s", timeout_secs),
        })?;
    Ok(InfoSectionResult {
        data: out.text,
        truncated: out.truncated,
        exec_ms: start.elapsed().as_millis() as u64,
    })
}

#[tauri::command]
async fn ssh_info_probe_section(
    state: tauri::State<'_, SshState>,
    session_id: String,
    section: String,
) -> Result<InfoSectionResult, String> {
    let (script, timeout) = match section.as_str() {
        "overview" => (INFO_SCRIPT_OVERVIEW, 10u64),
        "network"  => (INFO_SCRIPT_NETWORK, 10u64),
        "ports"    => (INFO_SCRIPT_PORTS, 10u64),
        "processes" => (INFO_SCRIPT_PROCESSES, 10u64),
        "services" => (INFO_SCRIPT_SERVICES, 15u64),
        "docker"   => (INFO_SCRIPT_DOCKER, 20u64),
        other => return Err(format!("unknown info section: {}", other)),
    };
    run_info_script(&state, &session_id, script, timeout).await
}

/// One tick of the session Info tab's live status strip (System sub-tab) —
/// CPU%, RAM, disk, network throughput, load average, refreshed by the
/// frontend every second. Flat struct rather than `monitor::Sample`'s
/// generic metric map: that shape fits a dashboard of arbitrary enabled
/// metrics, but the status strip always shows the same fixed fields, some
/// of which (RAM/disk) want the raw used/total bytes for an "X GB / Y GB"
/// display, not just the computed percentage.
#[derive(serde::Serialize, Default)]
struct LiveInfoSample {
    /// None on the very first sample for a session — there's nothing to
    /// diff against yet (same "no fake zero" rule monitor.rs's own sampler
    /// follows), and on the next tick after a reconnect for the same reason.
    cpu_pct: Option<f64>,
    mem_total_kb: u64,
    mem_avail_kb: u64,
    disk_total_kb: u64,
    disk_used_kb: u64,
    net_in_bps: Option<f64>,
    net_out_bps: Option<f64>,
}

// Reuses crate::monitor's own probe script and CPU%/network diff math
// (BUILTIN_PROBE / parse_probe / compute_sample) — see that module for the
// actual cross-distro awk/busybox handling — but runs it over THIS session's
// already-open connection via the existing run_info_script helper, instead
// of opening a dedicated connection as monitor.rs does.
#[tauri::command]
async fn ssh_info_live_sample(
    state: tauri::State<'_, SshState>,
    session_id: String,
) -> Result<LiveInfoSample, String> {
    if !state.connections.lock().await.contains_key(&session_id) {
        return Err("Session not connected".into());
    }
    // One sample at a time per session, its previous snapshot read and the
    // new one stored under the same lock (F-039).
    let probes = info_probes_for(&state, &session_id).await;
    let mut previous = probes.live.lock().await;
    let result = run_info_script(&state, &session_id, monitor::BUILTIN_PROBE, 5).await?;
    let now = monitor::parse_probe(&result.data)?;

    let sample = monitor::compute_sample(
        0,
        &now,
        &previous,
        &["cpu".to_string(), "net".to_string()],
        &[],
    );
    *previous = Some(now.clone());

    Ok(LiveInfoSample {
        cpu_pct: sample.values.get("cpu").copied(),
        mem_total_kb: now.mem_total_kb,
        mem_avail_kb: now.mem_avail_kb,
        disk_total_kb: now.disk_total_kb,
        disk_used_kb: now.disk_used_kb,
        net_in_bps: sample.values.get("net_in").copied(),
        net_out_bps: sample.values.get("net_out").copied(),
    })
}

// Validate an iptables/nft table/chain identifier — strict allow-list.
// Chain names on real hosts are alphanumeric plus `-` `_` `.` and occasional
// `@`; anything else would risk shell injection when we splice into the
// command string. This function is the *only* thing keeping the below
// commands from executing arbitrary shell. The first character is a letter,
// a digit or `_` (nft identifiers may start with one), never `-`, so the
// value cannot be read as an option (F-096).
fn is_safe_fw_ident(s: &str) -> bool {
    if s.is_empty() || s.len() > 128 { return false; }
    if !s.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') { return false; }
    s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@'))
}

// Two-stage firewall probe (lazy detail fetch). The network section returns
// a per-chain summary only; this command pulls the raw rules for one chain
// on user expand. Wire cost stays proportional to what the user actually
// looks at, not the size of the whole ruleset.
#[tauri::command]
async fn ssh_iptables_chain(
    state: tauri::State<'_, SshState>,
    session_id: String,
    table: String,
    chain: String,
) -> Result<String, String> {
    // Locked table allow-list; anything not here is rejected. Matches what
    // the probe script iterates over, plus `security` which some hardened
    // distros expose.
    if !matches!(table.as_str(), "filter" | "nat" | "mangle" | "raw" | "security") {
        return Err("invalid table".to_string());
    }
    if !is_safe_fw_ident(&chain) {
        return Err("invalid chain name".to_string());
    }
    // Retry with `sudo -n` when the direct call comes back empty — mirrors
    // the semantics of the summary probe so the expand behaves consistently
    // on hosts where only root can read the ruleset. `-v` adds the per-rule
    // `pkts`/`bytes` match-counter columns (human-readable K/M/G suffixes) so
    // the operator can see how much traffic each rule has actually handled.
    let cmd = format!(
        "OUT=$(iptables -t {t} -n -v -L {c} --line-numbers 2>/dev/null); \
if [ -z \"$OUT\" ]; then OUT=$(sudo -n iptables -t {t} -n -v -L {c} --line-numbers 2>/dev/null); fi; \
printf '%s' \"$OUT\"",
        t = table, c = chain
    );
    run_exec_capture(&state, &session_id, &cmd, 15, None).await.map(with_cut_note)
}

#[tauri::command]
async fn ssh_nft_chain(
    state: tauri::State<'_, SshState>,
    session_id: String,
    family: String,
    table: String,
    chain: String,
) -> Result<String, String> {
    if !matches!(family.as_str(), "ip" | "ip6" | "inet" | "arp" | "bridge" | "netdev") {
        return Err("invalid family".to_string());
    }
    if !is_safe_fw_ident(&table) || !is_safe_fw_ident(&chain) {
        return Err("invalid table or chain name".to_string());
    }
    let cmd = format!(
        "OUT=$(nft list chain {f} {t} {c} 2>/dev/null); \
if [ -z \"$OUT\" ]; then OUT=$(sudo -n nft list chain {f} {t} {c} 2>/dev/null); fi; \
printf '%s' \"$OUT\"",
        f = family, t = table, c = chain
    );
    run_exec_capture(&state, &session_id, &cmd, 15, None).await.map(with_cut_note)
}

#[derive(serde::Serialize)]
struct SystemctlActionResult {
    success: bool,
    exit_code: i32,
    stdout: String,
    stderr: String,
    used_sudo: bool,
}

async fn run_exec_capture(
    state: &SshState,
    session_id: &str,
    cmd: &str,
    timeout_secs: u64,
    marker: Option<&str>,
) -> Result<remote_exec::Captured, String> {
    use std::sync::Arc;

    let session_arc = {
        let connections = state.connections.lock().await;
        connections.get(session_id).map(Arc::clone)
            .ok_or_else(|| "Session not connected".to_string())?
    };
    exec_capture_on(&session_arc, &state.channel_gate(session_id), cmd, timeout_secs, marker).await
}

/// `run_exec_capture` on a given connection: at most 64 KiB of output are
/// kept, read to the end so a trailing `marker` (`EXIT_MARKER`) gives the
/// exit code even after a long output (F-072).
async fn exec_capture_on<H: russh::client::Handler>(
    handle: &tokio::sync::Mutex<russh::client::Handle<H>>,
    gate: &ssh_connect::ChannelGate,
    cmd: &str,
    timeout_secs: u64,
    marker: Option<&str>,
) -> Result<remote_exec::Captured, String> {
    let channel = ssh_connect::open_feature_channel(handle, gate).await?;
    let capture = remote_exec::Capture::new(EXEC_CAPTURE_BYTES, remote_exec::Overflow::KeepHead);
    remote_exec::run(channel, cmd, capture, marker, std::time::Duration::from_secs(timeout_secs))
        .await
        .map_err(|e| match e {
            remote_exec::RunError::Start(e) => e,
            _ => format!("exec timed out after {}s", timeout_secs),
        })
}

const EXEC_CAPTURE_BYTES: usize = 64 * 1024;

/// Printed after a service or process action, followed by its exit code.
const EXIT_MARKER: &str = "__SUB_EXITCODE:";

/// A captured listing, with a last line saying so when it was cut.
fn with_cut_note(out: remote_exec::Captured) -> String {
    if out.truncated {
        format!("{}\n(output cut at {} KiB)", out.text.trim_end_matches('\n'), EXEC_CAPTURE_BYTES / 1024)
    } else {
        out.text
    }
}

/// The exit code and output of an action run with `EXIT_MARKER`.
fn action_outcome(out: remote_exec::Captured) -> (i32, String) {
    let code = out.exit.unwrap_or(1);
    (code, with_cut_note(remote_exec::Captured { text: out.text.trim_end_matches('\n').to_string(), ..out }))
}

/// The command line of a systemctl action. The unit comes after `--` and in
/// single quotes (F-096): systemd's escaped names keep their `\x2d`, and a
/// name starting with `-` (`-.mount`) is a unit, not an option.
fn systemctl_command(action: &str, unit: &str, sudo: bool) -> String {
    format!(
        "{}systemctl {} -- {} 2>&1; echo {}$?",
        if sudo { "sudo -n " } else { "" },
        action,
        remote_exec::sh_quote(unit),
        EXIT_MARKER
    )
}

#[tauri::command]
async fn ssh_systemctl_action(
    state: tauri::State<'_, SshState>,
    session_id: String,
    unit: String,
    action: String,
) -> Result<SystemctlActionResult, String> {
    // Locked allow-list. Anything not in this list is rejected outright
    // — we never want to dispatch arbitrary subcommands from the UI.
    let valid_action = matches!(action.as_str(), "start" | "stop" | "restart" | "reload" | "status");
    if !valid_action {
        return Err(format!("invalid action: {}", action));
    }
    // Reject hostile unit names. systemd unit names are restricted to
    // `[A-Za-z0-9:_.\\@-]+\.<suffix>` — adding any shell metachar here would
    // otherwise let the caller smuggle in a command.
    if unit.is_empty()
        || unit.len() > 256
        || !unit.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '@' | ':' | '\\'))
    {
        return Err("invalid unit name".to_string());
    }

    // Try plain systemctl first (works if user is root or has polkit rules).
    // If that fails with permission-denied semantics, retry with `sudo -n` —
    // works on hosts that gave this user NOPASSWD sudo. The `-n` ensures we
    // never block on a tty password prompt that nobody can answer.
    let plain_cmd = systemctl_command(&action, &unit, false);
    let (code1, out1) = action_outcome(run_exec_capture(&state, &session_id, &plain_cmd, 30, Some(EXIT_MARKER)).await?);
    let needs_sudo = code1 != 0 && (
        out1.contains("Interactive authentication required")
        || out1.contains("not authorized")
        || out1.contains("polkit")
        || out1.to_lowercase().contains("permission denied")
        || out1.to_lowercase().contains("access denied")
    );

    if code1 == 0 || !needs_sudo {
        return Ok(SystemctlActionResult {
            success: code1 == 0,
            exit_code: code1,
            stdout: out1,
            stderr: String::new(),
            used_sudo: false,
        });
    }

    let sudo_cmd = systemctl_command(&action, &unit, true);
    let (code2, out2) = action_outcome(run_exec_capture(&state, &session_id, &sudo_cmd, 30, Some(EXIT_MARKER)).await?);
    Ok(SystemctlActionResult {
        success: code2 == 0,
        exit_code: code2,
        stdout: out2,
        stderr: String::new(),
        used_sudo: true,
    })
}

/// Signal a process by PID (Ports / Processes tab "kill" action). Tries the
/// user's own `kill` first, then `sudo -n kill` on a permission error — same
/// non-interactive sudo pattern as ssh_systemctl_action. Both the PID (a
/// validated i32) and the signal (an allow-listed name) are interpolated into
/// the shell command, so neither is attacker-controlled free text.
#[tauri::command]
async fn ssh_kill_process(
    state: tauri::State<'_, SshState>,
    session_id: String,
    pid: i32,
    signal: Option<String>,
) -> Result<SystemctlActionResult, String> {
    // Never signal PID <= 1 — that's init / the kernel and would be catastrophic.
    if pid <= 1 {
        return Err("refusing to signal PID <= 1".to_string());
    }
    let sig = signal.unwrap_or_else(|| "TERM".to_string());
    if !matches!(sig.as_str(), "TERM" | "KILL" | "HUP" | "INT") {
        return Err(format!("invalid signal: {}", sig));
    }

    let plain = format!("kill -{} {} 2>&1; echo __SUB_EXITCODE:$?", sig, pid);
    let (code1, out1) = action_outcome(run_exec_capture(&state, &session_id, &plain, 15, Some(EXIT_MARKER)).await?);
    let low = out1.to_lowercase();
    let needs_sudo = code1 != 0
        && (low.contains("not permitted")
            || low.contains("permission denied")
            || low.contains("operation not permitted"));

    if code1 == 0 || !needs_sudo {
        return Ok(SystemctlActionResult {
            success: code1 == 0,
            exit_code: code1,
            stdout: out1,
            stderr: String::new(),
            used_sudo: false,
        });
    }

    let sudo_cmd = format!("sudo -n kill -{} {} 2>&1; echo __SUB_EXITCODE:$?", sig, pid);
    let (code2, out2) = action_outcome(run_exec_capture(&state, &session_id, &sudo_cmd, 15, Some(EXIT_MARKER)).await?);
    Ok(SystemctlActionResult {
        success: code2 == 0,
        exit_code: code2,
        stdout: out2,
        stderr: String::new(),
        used_sudo: true,
    })
}

#[derive(serde::Serialize)]
struct SftpFileEntry {
    name: String,
    path: String,
    is_dir: bool,
    size: u64,
    permissions: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>,
    modified: Option<u64>,
}

#[derive(serde::Serialize)]
struct SftpListResult {
    current_path: String,
    entries: Vec<SftpFileEntry>,
}

pub async fn get_sftp_session(
    state: &SshState,
    session_id: &str,
) -> Result<Arc<russh_sftp::client::SftpSession>, String> {
    sftp_session_for(&state.connections, &state.sftp_sessions, &state.channel_gates, session_id).await
}

type ConnectionMap = Arc<tokio::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<russh::client::Handle<ssh_manager::ClientHandler>>>>>>;
type SftpSessionMap = Arc<tokio::sync::Mutex<std::collections::HashMap<String, Arc<russh_sftp::client::SftpSession>>>>;
pub(crate) type ChannelGateMap = Arc<StdMutex<std::collections::HashMap<String, Arc<ssh_connect::ChannelGate>>>>;

/// The gate of a connection key (see `SshState::channel_gate`).
pub(crate) fn channel_gate_of(gates: &ChannelGateMap, key: &str) -> Arc<ssh_connect::ChannelGate> {
    gates.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(key).cloned().unwrap_or_default()
}

/// One SFTP subsystem on a connection.
async fn open_sftp_on<H: russh::client::Handler>(
    handle: &tokio::sync::Mutex<russh::client::Handle<H>>,
    gate: &ssh_connect::ChannelGate,
) -> Result<russh_sftp::client::SftpSession, String> {
    let channel = ssh_connect::open_feature_channel(handle, gate).await?;
    channel.request_subsystem(true, "sftp").await.map_err(|e| e.to_string())?;
    russh_sftp::client::SftpSession::new(channel.into_stream()).await.map_err(|e| e.to_string())
}

/// `get_sftp_session` for code that holds the two maps rather than the state
/// (live edit's background tasks).
async fn sftp_session_for(
    connections: &ConnectionMap,
    sftp_sessions: &SftpSessionMap,
    gates: &ChannelGateMap,
    session_id: &str,
) -> Result<Arc<russh_sftp::client::SftpSession>, String> {
    // Reuse one SFTP subsystem per SSH session to avoid leaking server-side
    // channels.
    if let Some(s) = sftp_sessions.lock().await.get(session_id) {
        return Ok(Arc::clone(s));
    }

    // Transport preference: when a dedicated `::sftp` connection exists for
    // this session (the per-tab "Dedicated session" toggle), the SFTP
    // subsystem rides IT — but the cache stays keyed by the plain session id,
    // so the frontend never has to re-key anything. The dedicated connection
    // is a pure transport: it appearing/disappearing just invalidates this
    // cache (see the `::sftp` lifecycle hooks) and the next file operation
    // re-opens the subsystem on whatever transport is available.
    let (transport_key, session_arc) = {
        let connections = connections.lock().await;
        let dedicated_key = format!("{}::sftp", session_id);
        if !session_id.contains("::") && connections.contains_key(&dedicated_key) {
            (dedicated_key.clone(), Arc::clone(connections.get(&dedicated_key).unwrap()))
        } else if let Some(sess) = connections.get(session_id) {
            (session_id.to_string(), Arc::clone(sess))
        } else {
            return Err("Session not connected".into());
        }
    };

    // The connection mutex is held only for the bounded open (F-028); the
    // SFTP init below has russh-sftp's own request timeout.
    let sftp = open_sftp_on(&session_arc, &*channel_gate_of(gates, &transport_key)).await?;
    let arc = Arc::new(sftp);

    let mut cache = sftp_sessions.lock().await;
    if let Some(existing) = cache.get(session_id) {
        // Another caller raced us; keep the existing one and drop ours.
        return Ok(Arc::clone(existing));
    }
    // Guard against two races before caching: (a) a reconnect replaced/removed
    // the transport handle while we were opening the subsystem (stale handle),
    // and (b) a dedicated `::sftp` transport APPEARED meanwhile — which changes
    // the preferred transport, so caching this primary-backed subsystem would
    // permanently bypass the dedicated connection. Require both the recomputed
    // preference AND the handle identity to still match the key we opened on.
    let still_current = {
        let connections = connections.lock().await;
        let dedicated_key = format!("{}::sftp", session_id);
        let preferred: &str = if !session_id.contains("::") && connections.contains_key(&dedicated_key) {
            dedicated_key.as_str()
        } else {
            session_id
        };
        transport_key.as_str() == preferred
            && connections.get(&transport_key)
                .map(|c| Arc::ptr_eq(c, &session_arc))
                .unwrap_or(false)
    };
    if !still_current {
        return Err("Session reconnected while opening SFTP — try again".into());
    }
    cache.insert(session_id.to_string(), Arc::clone(&arc));
    Ok(arc)
}

#[tauri::command]
async fn sftp_list_dir(
    state: tauri::State<'_, SshState>,
    session_id: String,
    path: String,
) -> Result<SftpListResult, String> {
    let sftp = get_sftp_session(&state, &session_id).await?;
    let target_path = if path.is_empty() { ".".to_string() } else { path.clone() };
    let canonical_path = sftp.canonicalize(&target_path).await.map_err(|e| e.to_string())?;
    
    let mut read_dir = sftp.read_dir(&canonical_path).await.map_err(|e| e.to_string())?;
    let mut entries = Vec::new();
    while let Some(entry) = read_dir.next() {
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let is_dir = entry.file_type().is_dir();
        let metadata = entry.metadata();
        let size = metadata.size.unwrap_or(0);
        let permissions = metadata.permissions;
        let uid = metadata.uid;
        let gid = metadata.gid;
        let modified = metadata.mtime.map(|t| t as u64);
        
        let entry_path = if canonical_path.ends_with('/') {
            format!("{}{}", canonical_path, name)
        } else {
            format!("{}/{}", canonical_path, name)
        };
        
        entries.push(SftpFileEntry {
            name,
            path: entry_path,
            is_dir,
            size,
            permissions,
            uid,
            gid,
            modified,
        });
    }
    
    // Sort: directories first, then alphabetically
    entries.sort_by(|a, b| {
        if a.is_dir != b.is_dir {
            b.is_dir.cmp(&a.is_dir)
        } else {
            a.name.to_lowercase().cmp(&b.name.to_lowercase())
        }
    });
    
    Ok(SftpListResult {
        current_path: canonical_path,
        entries,
    })
}

#[tauri::command]
async fn sftp_create_dir(
    state: tauri::State<'_, SshState>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    let sftp = get_sftp_session(&state, &session_id).await?;
    sftp.create_dir(path).await.map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn sftp_remove_file(
    state: tauri::State<'_, SshState>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    let sftp = get_sftp_session(&state, &session_id).await?;
    sftp.remove_file(path).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Delete a remote folder and everything in it, as the delete dialog says
/// (F-074). See `remove_remote_tree`.
#[tauri::command]
async fn sftp_remove_dir(
    state: tauri::State<'_, SshState>,
    session_id: String,
    path: String,
) -> Result<(), String> {
    let sftp = get_sftp_session(&state, &session_id).await?;
    remove_remote_tree(&sftp, &path).await
}

/// Delete the remote folder `path` and its contents, depth first, never
/// following a symbolic link: a link inside is removed as a link, and each
/// folder is checked with `lstat` right before it is listed (some servers'
/// listings follow links, and a folder may have been replaced by a link
/// meanwhile). If `path` is itself a link, only the link is removed. An error
/// stops the walk and says how much was already deleted. Between the `lstat`
/// and the listing a folder could still be swapped (SFTP has no `openat`);
/// that needs someone else writing in the tree being deleted.
async fn remove_remote_tree(sftp: &russh_sftp::client::SftpSession, path: &str) -> Result<(), String> {
    let root = deletable_remote_folder(path)?;
    let meta = sftp.symlink_metadata(root).await.map_err(|e| format!("{}: {}", root, e))?;
    if meta.file_type().is_symlink() {
        return sftp.remove_file(root).await.map_err(|e| format!("{}: {}", root, e));
    }
    if !meta.file_type().is_dir() {
        return Err(format!("{} is not a folder", root));
    }
    let mut removed: u64 = 0;
    let failed = |what: &str, e: &dyn std::fmt::Display, removed: u64| {
        if removed == 0 {
            format!("{}: {}", what, e)
        } else {
            format!("Deleted {} item(s), then could not delete {}: {}", removed, what, e)
        }
    };
    // (folder, contents already handled): a folder is removed after what it holds.
    let mut stack: Vec<(String, bool)> = vec![(root.to_string(), false)];
    while let Some((dir, emptied)) = stack.pop() {
        if emptied {
            sftp.remove_dir(&dir).await.map_err(|e| failed(&dir, &e, removed))?;
            removed += 1;
            continue;
        }
        let meta = sftp.symlink_metadata(&dir).await.map_err(|e| failed(&dir, &e, removed))?;
        if !meta.file_type().is_dir() {
            // Not a folder (any more): remove the link or file itself.
            sftp.remove_file(&dir).await.map_err(|e| failed(&dir, &e, removed))?;
            removed += 1;
            continue;
        }
        stack.push((dir.clone(), true));
        for entry in sftp.read_dir(&dir).await.map_err(|e| failed(&dir, &e, removed))? {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            if name.is_empty() || name.contains('/') || name.contains('\0') {
                return Err(failed(&format!("{}/{:?}", dir, name), &"not a single file name", removed));
            }
            let child = format!("{}/{}", dir, name);
            // A listing without types (some servers): the walk's lstat decides.
            let kind = entry.file_type();
            if kind.is_dir() || entry.metadata().permissions.is_none() {
                stack.push((child, false));
            } else {
                sftp.remove_file(&child).await.map_err(|e| failed(&child, &e, removed))?;
                removed += 1;
            }
        }
    }
    Ok(())
}

#[tauri::command]
async fn sftp_rename(
    state: tauri::State<'_, SshState>,
    session_id: String,
    oldpath: String,
    newpath: String,
) -> Result<(), String> {
    let chain = remote_parent_chain(&newpath)?;
    let sftp = get_sftp_session(&state, &session_id).await?;

    // First try the rename as-is — the common case is the target's parent
    // already exists.
    if let Err(first_err) = sftp.rename(&oldpath, &newpath).await {
        // SSH_FX_FAILURE on rename is most commonly "destination parent
        // directory doesn't exist" — user types a path into a subfolder
        // they haven't created yet. Pre-check the parent explicitly so
        // we don't paper over real errors (permission denied, destination
        // already exists, cross-filesystem) with a silent retry that
        // would just swap one confusing message for another.
        let needs_mkdir = match chain.last() {
            Some(parent) => sftp.metadata(parent.as_str()).await.is_err(),
            None => false,
        };
        if !needs_mkdir {
            return Err(format!("rename '{}' -> '{}': {}", oldpath, newpath, first_err));
        }
        // mkdir -p the missing chain. AlreadyExists is treated as success
        // so a parallel rename racing into the same tree doesn't break us.
        for cur in &chain {
            if sftp.metadata(cur.as_str()).await.is_ok() { continue; }
            if let Err(e) = sftp.create_dir(cur).await {
                let msg = e.to_string().to_lowercase();
                if msg.contains("exist") { continue; }
                return Err(format!("create destination parent '{}': {}", cur, e));
            }
        }
        sftp.rename(&oldpath, &newpath).await
            .map_err(|e| format!("rename '{}' -> '{}' (after creating parent): {}", oldpath, newpath, e))?;
    }
    Ok(())
}

/// The folders a rename may create so that `newpath` has its parent: every
/// ancestor below `/`, outermost first. The path is a remote POSIX path, so it
/// is split on `/` only. A relative destination is refused: SFTP resolves it
/// against the session's working folder, and the folders would have been
/// created from `/` instead (F-073); the file browser always sends absolute
/// paths.
fn remote_parent_chain(newpath: &str) -> Result<Vec<String>, String> {
    if !newpath.starts_with('/') {
        return Err(format!("The destination must be an absolute path (starting with /): {}", newpath));
    }
    let trimmed = newpath.trim_end_matches('/');
    let parent = trimmed.rfind('/').map(|i| &trimmed[..i]).unwrap_or("");
    let mut chain = Vec::new();
    let mut cur = String::new();
    for part in parent.split('/').filter(|p| !p.is_empty()) {
        cur.push('/');
        cur.push_str(part);
        chain.push(cur.clone());
    }
    Ok(chain)
}

#[tauri::command]
async fn sftp_set_permissions(
    state: tauri::State<'_, SshState>,
    session_id: String,
    path: String,
    permissions: u32,
) -> Result<(), String> {
    let sftp = get_sftp_session(&state, &session_id).await?;
    sftp.set_metadata(path, mode_change(permissions)).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// The folder `remove_remote_tree` may start from: an absolute path below
/// `/` without `.` or `..` steps (`/.` or `/x/..` would otherwise reach `/`).
fn deletable_remote_folder(path: &str) -> Result<&str, String> {
    let root = path.trim_end_matches('/');
    let steps_ok = root.split('/').skip(1).all(|c| !c.is_empty() && c != "." && c != "..");
    if !path.starts_with('/') || root.is_empty() || !steps_ok {
        return Err(format!("Refusing to delete {:?}: not a plain absolute folder path below /", path));
    }
    Ok(root)
}

/// A SETSTAT that changes the mode only (F-074). Re-sending what a `stat`
/// returned would also re-send the size (truncating a file that grew
/// meanwhile), the owner and the times.
fn mode_change(permissions: u32) -> russh_sftp::protocol::FileAttributes {
    let mut attrs = russh_sftp::protocol::FileAttributes::empty();
    attrs.permissions = Some(permissions & 0o7777);
    attrs
}

/// A SETSTAT that changes the owner and group only (F-074). SFTP sends them
/// as one pair (russh-sftp fills a missing one with 0, i.e. root), so a value
/// the caller leaves out is the current one, and the change is refused when
/// the server did not report it.
fn owner_change(
    uid: Option<u32>,
    gid: Option<u32>,
    current: Option<&russh_sftp::protocol::FileAttributes>,
) -> Result<russh_sftp::protocol::FileAttributes, String> {
    if uid.is_none() && gid.is_none() {
        return Err("Nothing to change: give an owner or a group.".into());
    }
    let mut attrs = russh_sftp::protocol::FileAttributes::empty();
    attrs.uid = uid.or_else(|| current.and_then(|c| c.uid));
    attrs.gid = gid.or_else(|| current.and_then(|c| c.gid));
    if attrs.uid.is_none() || attrs.gid.is_none() {
        return Err("The server did not report the current owner and group, so both must be given.".into());
    }
    Ok(attrs)
}

#[tauri::command]
async fn sftp_set_owner(
    state: tauri::State<'_, SshState>,
    session_id: String,
    path: String,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), String> {
    let sftp = get_sftp_session(&state, &session_id).await?;
    // The value not given is kept: read it (an error here is an error, never
    // a guessed 0).
    let current = if uid.is_none() || gid.is_none() {
        Some(sftp.metadata(&path).await.map_err(|e| format!("[SFTP] METADATA_READ_FAILED: {}", e))?)
    } else {
        None
    };
    let attrs = owner_change(uid, gid, current.as_ref())?;
    sftp.set_metadata(path, attrs).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// Download one remote file into the folder `local_dir`. The webview picks only
/// the folder: the file is named here, after the remote file, because the server
/// chooses that name (see `local_path::download_target`).
#[tauri::command]
async fn sftp_download_file(
    app: tauri::AppHandle,
    state: tauri::State<'_, SshState>,
    session_id: String,
    remote_path: String,
    local_dir: String,
    overwrite: Option<bool>,
) -> Result<(), String> {
    use tauri::Emitter;
    use tokio::io::AsyncReadExt;
    use std::sync::atomic::{AtomicBool, Ordering};

    // Validate the destination BEFORE touching the network: the name must be a
    // plain file name on this OS, land directly in the chosen folder, and pass
    // the write policy (no system folders, start-up files, ~/.ssh, ...).
    let name = local_path::remote_leaf(&remote_path)?.to_string();
    let local_path = local_path::download_target(&local_dir, &name)?;

    // Overwrite protection: when the caller has NOT explicitly opted in
    // (overwrite==Some(true)), refuse to clobber an existing local file.
    // The sentinel error string `EXISTS:<path>` lets the frontend tell
    // the difference between "real failure" and "you would have replaced
    // something" and surface the apply-to-all confirmation modal. A broken
    // symlink counts as existing.
    let exists = std::fs::symlink_metadata(&local_path).is_ok();
    if overwrite != Some(true) && exists {
        return Err(format!("EXISTS:{}", local_path.display()));
    }

    let sftp = get_sftp_session(&state, &session_id).await?;

    // Stat first so we can report a progress percentage. If the server doesn't
    // know the size (some edge SFTP servers omit it), we still report bytes
    // transferred so the UI can show throughput at least.
    let total = match sftp.metadata(&remote_path).await {
        Ok(m) => m.size.unwrap_or(0),
        Err(_) => 0,
    };
    let id = transfer_id();
    let event_name = format!("sftp-transfer-{}", session_id);
    let emit_progress = |bytes: u64, status: &str, error: Option<String>| {
        let _ = app.emit(
            &event_name,
            serde_json::json!({
                "id": id, "name": name, "kind": "download",
                "bytes": bytes, "total": total,
                "status": status, "error": error,
            }),
        );
    };

    // Register a cancel flag the user can flip via `sftp_cancel_transfer`.
    // RAII-removed at the end so the map doesn't pile up across many
    // sequential transfers.
    let cancel = Arc::new(AtomicBool::new(false));
    let cancels_map = Arc::clone(&state.transfer_cancels);
    cancels_map.lock().await.insert(id.clone(), Arc::clone(&cancel));
    struct CancelGuard {
        map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, Arc<AtomicBool>>>>,
        id: String,
    }
    impl Drop for CancelGuard {
        fn drop(&mut self) {
            // Best-effort cleanup; if the lock is contended we'd rather leak
            // a slot than block the drop, but in practice this never blocks.
            if let Ok(mut g) = self.map.try_lock() {
                g.remove(&self.id);
            }
        }
    }
    let _guard = CancelGuard { map: Arc::clone(&cancels_map), id: id.clone() };

    emit_progress(0, "progress", None);

    let mut remote_file = sftp
        .open(&remote_path)
        .await
        .map_err(|e| { emit_progress(0, "error", Some(e.to_string())); format!("Failed to open remote file: {}", e) })?;
    // The download goes to `<name>.<hex>.part` beside the target and replaces
    // it only once complete (F-025): an error or a cancel removes the part and
    // never touches an existing file. Where a symlink at the target points was
    // checked by `download_target`; replacing replaces the link itself.
    let mut part = atomic_transfer::LocalPart::create(&local_path)
        .await
        .map_err(|e| { emit_progress(0, "error", Some(e.to_string())); format!("Failed to create local file: {}", e) })?;

    // 256 KiB chunks: large enough to keep the SSH window pipelined on
    // high-latency links (with window_size=8 MiB we want ~16+ chunks in
    // flight), small enough to keep per-iteration latency low for the
    // progress meter (and the cancel poll).
    let mut buf = vec![0u8; atomic_transfer::CHUNK];
    let mut transferred: u64 = 0;
    let mut last_report = std::time::Instant::now();
    use tokio::io::AsyncWriteExt;
    loop {
        if cancel.load(Ordering::Relaxed) {
            drop(part);
            emit_progress(transferred, "cancelled", None);
            return Err("cancelled".into());
        }
        let n = remote_file
            .read(&mut buf)
            .await
            .map_err(|e| { emit_progress(transferred, "error", Some(e.to_string())); format!("read: {}", e) })?;
        if n == 0 { break; }
        part.file()
            .write_all(&buf[..n])
            .await
            .map_err(|e| { emit_progress(transferred, "error", Some(e.to_string())); format!("write: {}", e) })?;
        transferred += n as u64;
        // Throttle progress events: each one crosses the IPC boundary, and
        // 10 Hz is more than enough for a smooth progress bar.
        if last_report.elapsed() >= std::time::Duration::from_millis(100) {
            emit_progress(transferred, "progress", None);
            last_report = std::time::Instant::now();
        }
    }
    match part.commit(overwrite == Some(true)).await {
        Ok(()) => {}
        Err(atomic_transfer::CommitError::Exists) => {
            emit_progress(transferred, "error", Some("a file with this name appeared meanwhile".into()));
            return Err(format!("EXISTS:{}", local_path.display()));
        }
        Err(atomic_transfer::CommitError::Io(e)) => {
            emit_progress(transferred, "error", Some(e.clone()));
            return Err(format!("save {}: {}", local_path.display(), e));
        }
    }
    emit_progress(transferred, "done", None);
    Ok(())
}

/// Recursive remote directory download. Walks the remote tree under
/// `remote_path`, mirrors its structure into `local_dir/{basename}`, and
/// streams every file across with progress events aggregated under a SINGLE
/// transfer id — so the UI shows one "folder of N files" card instead of one
/// card per file. Cancellation uses the same `transfer_cancels` map as
/// single-file downloads, so the user's Cancel button works identically.
#[tauri::command]
async fn sftp_download_dir(
    app: tauri::AppHandle,
    state: tauri::State<'_, SshState>,
    session_id: String,
    remote_path: String,
    local_dir: String,
    overwrite: Option<bool>,
) -> Result<(), String> {
    use tauri::Emitter;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    // Destination is the PARENT directory. We'll create remote_path's
    // basename underneath it so the user gets `local/{folder}/...`,
    // matching scp -r and rsync semantics. The folder name comes from the
    // server, so it gets the same checks as a downloaded file's name (a
    // listed name `x/..` would otherwise make it `..`), and the folder must
    // pass the write policy (`~/.config/autostart` is a folder too).
    let folder_name = local_path::remote_leaf(&remote_path)?.to_string();
    let local_root = local_path::download_target(&local_dir, &folder_name)?;

    // Overwrite protection for the destination folder: if the target
    // `local_dir/{folder}` already exists, refuse unless explicitly
    // allowed. Per-file confirmation inside the tree would be unworkable
    // for the bulk path — the user picks once at the directory level.
    if overwrite != Some(true) && std::fs::symlink_metadata(&local_root).is_ok() {
        return Err(format!("EXISTS:{}", local_root.display()));
    }

    let sftp = get_sftp_session(&state, &session_id).await?;

    let id = transfer_id();
    let event_name = format!("sftp-transfer-{}", session_id);

    // Register cancel flag early so the user can abort even during the
    // enumeration phase (which can be slow on a deep tree with many dirs).
    let cancel = Arc::new(AtomicBool::new(false));
    let cancels_map = Arc::clone(&state.transfer_cancels);
    cancels_map.lock().await.insert(id.clone(), Arc::clone(&cancel));
    struct CancelGuard {
        map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, Arc<AtomicBool>>>>,
        id: String,
    }
    impl Drop for CancelGuard {
        fn drop(&mut self) {
            if let Ok(mut g) = self.map.try_lock() {
                g.remove(&self.id);
            }
        }
    }
    let _guard = CancelGuard { map: Arc::clone(&cancels_map), id: id.clone() };

    // Entries left out because their names can't be local file names here;
    // reported with every event so the card can say so when it finishes.
    let skipped = AtomicU64::new(0);
    let skipped_ref = &skipped;
    let id_for_emit = id.clone();
    let name_for_emit = folder_name.clone();
    let app_for_emit = app.clone();
    let event_for_emit = event_name.clone();
    let emit_progress = move |bytes: u64, total: u64, status: &str, error: Option<String>| {
        let _ = app_for_emit.emit(
            &event_for_emit,
            serde_json::json!({
                "id": id_for_emit, "name": name_for_emit, "kind": "download",
                "bytes": bytes, "total": total,
                "status": status, "error": error,
                "skipped": skipped_ref.load(Ordering::Relaxed),
            }),
        );
    };

    emit_progress(0, 0, "progress", None);

    // Phase 1: enumerate. Collect every file under remote_path along with
    // its relative path (so we can preserve the tree on the local side) and
    // its size (so the progress bar has a meaningful total). Tracked
    // iteratively with an explicit stack so we don't blow the async-recursion
    // budget on pathological trees.
    let remote_root = remote_path.trim_end_matches('/').to_string();
    let mut files: Vec<(String, String, u64)> = Vec::new(); // (remote, rel, size)
    let mut total_bytes: u64 = 0;
    let mut stack: Vec<String> = vec![remote_root.clone()];

    while let Some(dir) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            emit_progress(0, total_bytes, "cancelled", None);
            return Err("cancelled".into());
        }
        let read = match sftp.read_dir(&dir).await {
            Ok(r) => r,
            Err(e) => {
                emit_progress(0, total_bytes, "error", Some(format!("read_dir {}: {}", dir, e)));
                return Err(format!("read_dir {}: {}", dir, e));
            }
        };
        for entry in read {
            let name = entry.file_name();
            if name == "." || name == ".." { continue; }
            // Skip (and count) any entry whose name isn't a plain file name on
            // this OS. A hostile SFTP server can return `../../x`, `..\x`,
            // `C:x` or `CON` here; joining that onto local_root below would
            // escape the chosen folder (zip-slip → arbitrary local write) or
            // create something Windows treats specially. See local_path.
            if !is_safe_dir_entry_name(&name) {
                skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let full = format!("{}/{}", dir.trim_end_matches('/'), name);
            if entry.file_type().is_dir() {
                stack.push(full);
            } else if entry.file_type().is_file() {
                let size = entry.metadata().size.unwrap_or(0);
                let rel = full.strip_prefix(&remote_root)
                    .map(|s| s.trim_start_matches('/').to_string())
                    .unwrap_or_else(|| name.clone());
                total_bytes = total_bytes.saturating_add(size);
                files.push((full, rel, size));
            }
            // Symlinks and other types skipped — same conservative policy
            // as the mirror module.
        }
    }

    if files.is_empty() {
        // Still create the (empty) destination folder so the UI sees the
        // shape — otherwise the user sees "done" with nothing to show for it.
        let _ = tokio::fs::create_dir_all(&local_root).await;
        emit_progress(0, 0, "done", None);
        return Ok(());
    }

    // Phase 2: download. The local destination tree is rooted at
    // {local_dir}/{folder_name}/... so multi-level files preserve their
    // structure. Create each parent directory lazily right before we open
    // the file.
    if let Err(e) = tokio::fs::create_dir_all(&local_root).await {
        emit_progress(0, total_bytes, "error", Some(format!("create {}: {}", local_root.display(), e)));
        return Err(format!("create root: {}", e));
    }
    // Where the root really is (in a merge it may be a symlink the user made,
    // already checked by download_target): every file must land under it.
    let root_real = match local_root.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            emit_progress(0, total_bytes, "error", Some(format!("{}: {}", local_root.display(), e)));
            return Err(format!("create root: {}", e));
        }
    };

    let mut transferred: u64 = 0;
    let mut last_report = std::time::Instant::now();
    let mut buf = vec![0u8; 256 * 1024];

    for (remote_file_path, rel, size) in &files {
        if cancel.load(Ordering::Relaxed) {
            emit_progress(transferred, total_bytes, "cancelled", None);
            return Err("cancelled".into());
        }

        // Every component of `rel` passed is_safe_dir_entry_name, so joining
        // them one by one builds real nested folders on every OS. Each file is
        // checked where it really lands before any folder is created: it must
        // pass the write policy and stay under the real root (in a merge, a
        // folder that already exists inside may be a symlink to elsewhere).
        // A file that fails is skipped and counted, like an unsafe name.
        let dest = rel.split('/').fold(local_root.clone(), |p, c| p.join(c));
        let dest = match guard_local_path(&dest, LocalAccess::Write) {
            Ok(d) if d.starts_with(&root_real) => d,
            _ => {
                skipped.fetch_add(1, Ordering::Relaxed);
                total_bytes = total_bytes.saturating_sub(*size);
                continue;
            }
        };
        if let Some(parent) = dest.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                emit_progress(transferred, total_bytes, "error",
                    Some(format!("mkdir {}: {}", parent.display(), e)));
                return Err(format!("mkdir {}: {}", parent.display(), e));
            }
        }

        let mut remote_file = match sftp.open(remote_file_path).await {
            Ok(f) => f,
            Err(e) => {
                emit_progress(transferred, total_bytes, "error",
                    Some(format!("open {}: {}", remote_file_path, e)));
                return Err(format!("open {}: {}", remote_file_path, e));
            }
        };
        // Each file goes through a part file beside it (F-025): an error or a
        // cancel leaves any file already there as it was.
        let mut part = match atomic_transfer::LocalPart::create(&dest).await {
            Ok(p) => p,
            Err(e) => {
                emit_progress(transferred, total_bytes, "error",
                    Some(format!("create {}: {}", dest.display(), e)));
                return Err(format!("create {}: {}", dest.display(), e));
            }
        };

        loop {
            if cancel.load(Ordering::Relaxed) {
                drop(part);
                emit_progress(transferred, total_bytes, "cancelled", None);
                return Err("cancelled".into());
            }
            let n = remote_file.read(&mut buf).await
                .map_err(|e| {
                    emit_progress(transferred, total_bytes, "error",
                        Some(format!("read {}: {}", remote_file_path, e)));
                    format!("read {}: {}", remote_file_path, e)
                })?;
            if n == 0 { break; }
            part.file().write_all(&buf[..n]).await
                .map_err(|e| {
                    emit_progress(transferred, total_bytes, "error",
                        Some(format!("write {}: {}", dest.display(), e)));
                    format!("write {}: {}", dest.display(), e)
                })?;
            transferred = transferred.saturating_add(n as u64);
            if last_report.elapsed() >= std::time::Duration::from_millis(100) {
                emit_progress(transferred, total_bytes, "progress", None);
                last_report = std::time::Instant::now();
            }
        }
        // A merge (the user agreed to overwrite) replaces files already there;
        // otherwise a file that appeared meanwhile is left alone and counted.
        match part.commit(overwrite == Some(true)).await {
            Ok(()) => {}
            Err(atomic_transfer::CommitError::Exists) => {
                skipped.fetch_add(1, Ordering::Relaxed);
            }
            Err(atomic_transfer::CommitError::Io(e)) => {
                emit_progress(transferred, total_bytes, "error",
                    Some(format!("save {}: {}", dest.display(), e)));
                return Err(format!("save {}: {}", dest.display(), e));
            }
        }
    }

    emit_progress(transferred, total_bytes, "done", None);
    Ok(())
}

#[tauri::command]
async fn sftp_upload_file(
    app: tauri::AppHandle,
    state: tauri::State<'_, SshState>,
    session_id: String,
    local_path: String,
    remote_path: String,
    overwrite: Option<bool>,
) -> Result<(), String> {
    use tauri::Emitter;
    use std::sync::atomic::{AtomicBool, Ordering};

    // Overwrite protection: stat the remote target first; refuse if it
    // exists and the caller hasn't explicitly opted in. Same `EXISTS:<path>`
    // sentinel as the download path.
    let sftp = get_sftp_session(&state, &session_id).await?;
    if overwrite != Some(true) {
        // lstat: a link at the name counts as existing, even a broken one.
        if sftp.symlink_metadata(&remote_path).await.is_ok() {
            return Err(format!("EXISTS:{}", remote_path));
        }
    }

    // Source must exist and must not be a device or kernel file (reading
    // /dev/zero never ends). Reading system files to upload them is allowed.
    let _guarded_local = guard_local_path(&local_path, LocalAccess::Read)?;

    let total = std::fs::metadata(&local_path)
        .map(|m| m.len())
        .unwrap_or(0);
    let name = std::path::Path::new(&local_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .to_string();
    let id = transfer_id();
    let event_name = format!("sftp-transfer-{}", session_id);
    let emit_progress = |bytes: u64, status: &str, error: Option<String>| {
        let _ = app.emit(
            &event_name,
            serde_json::json!({
                "id": id, "name": name, "kind": "upload",
                "bytes": bytes, "total": total,
                "status": status, "error": error,
            }),
        );
    };

    // Symmetric to sftp_download_file: register a cancel flag and clean it
    // up via RAII so a long-running upload can be stopped from the UI.
    let cancel = Arc::new(AtomicBool::new(false));
    let cancels_map = Arc::clone(&state.transfer_cancels);
    cancels_map.lock().await.insert(id.clone(), Arc::clone(&cancel));
    struct CancelGuard {
        map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, Arc<AtomicBool>>>>,
        id: String,
    }
    impl Drop for CancelGuard {
        fn drop(&mut self) {
            if let Ok(mut g) = self.map.try_lock() {
                g.remove(&self.id);
            }
        }
    }
    let _guard = CancelGuard { map: Arc::clone(&cancels_map), id: id.clone() };

    emit_progress(0, "progress", None);

    // Stream the file from disk in chunks rather than slurping the whole thing
    // into a Vec — keeps memory bounded for multi-GB transfers and lets us
    // emit progress along the way. The upload goes into a hidden part file
    // that replaces the target only once complete (F-025, atomic_transfer).
    let mut transferred: u64 = 0;
    let mut last_report = std::time::Instant::now();
    let result = {
        let mut on_chunk = |offset: u64, chunk: &[u8]| {
            transferred = offset + chunk.len() as u64;
            if last_report.elapsed() >= std::time::Duration::from_millis(100) {
                emit_progress(transferred, "progress", None);
                last_report = std::time::Instant::now();
            }
            !cancel.load(Ordering::Relaxed)
        };
        atomic_transfer::replace_remote_file(
            &sftp, &remote_path, std::path::Path::new(&local_path), overwrite == Some(true), &mut on_chunk,
        ).await
    };
    match result {
        Ok(replaced) => {
            // A note on a finished card: a hidden copy of the old version stayed.
            emit_progress(transferred, "done", replaced.note());
            Ok(())
        }
        Err(atomic_transfer::ReplaceError::Cancelled) => {
            emit_progress(transferred, "cancelled", None);
            Err("cancelled".into())
        }
        Err(atomic_transfer::ReplaceError::Exists) => {
            emit_progress(transferred, "error", Some("a file with this name exists".into()));
            Err(format!("EXISTS:{}", remote_path))
        }
        Err(atomic_transfer::ReplaceError::Failed(e)) => {
            emit_progress(transferred, "error", Some(e.clone()));
            Err(format!("Upload failed: {}", e))
        }
    }
}

/// Recursive directory upload — mirror of sftp_download_dir. Walks the local
/// tree, mkdirs each subdirectory on the remote, then streams every file
/// through the same flags+chunk logic as sftp_upload_file. Cancel flag and
/// EXISTS sentinel match the download path so the UI can reuse its prompt /
/// progress / abort hooks unchanged.
#[tauri::command]
async fn sftp_upload_dir(
    app: tauri::AppHandle,
    state: tauri::State<'_, SshState>,
    session_id: String,
    local_path: String,
    remote_path: String,
    overwrite: Option<bool>,
) -> Result<(), String> {
    use tauri::Emitter;
    use std::sync::atomic::{AtomicBool, Ordering};

    // remote_path is the PARENT directory; we hang the basename of
    // local_path underneath it. Matches scp -r / sftp_download_dir.
    let _guarded_local = guard_local_path(&local_path, LocalAccess::Read)?;

    let local_root = std::path::PathBuf::from(&local_path);
    let folder_name = local_root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("folder")
        .to_string();
    let folder_name = if folder_name.is_empty() { "folder".to_string() } else { folder_name };

    let sftp = get_sftp_session(&state, &session_id).await?;

    // Overwrite gate on the destination folder. Refuse unless the caller
    // explicitly opted in — symmetric with sftp_download_dir.
    let remote_root = format!("{}/{}",
        remote_path.trim_end_matches('/'),
        folder_name);
    if overwrite != Some(true) {
        if sftp.metadata(&remote_root).await.is_ok() {
            return Err(format!("EXISTS:{}", remote_root));
        }
    }

    let id = transfer_id();
    let event_name = format!("sftp-transfer-{}", session_id);

    // Cancel flag registered before the slow enumeration so the user can
    // abort even while we're walking a deep tree.
    let cancel = Arc::new(AtomicBool::new(false));
    let cancels_map = Arc::clone(&state.transfer_cancels);
    cancels_map.lock().await.insert(id.clone(), Arc::clone(&cancel));
    struct CancelGuard {
        map: Arc<tokio::sync::Mutex<std::collections::HashMap<String, Arc<AtomicBool>>>>,
        id: String,
    }
    impl Drop for CancelGuard {
        fn drop(&mut self) {
            if let Ok(mut g) = self.map.try_lock() {
                g.remove(&self.id);
            }
        }
    }
    let _guard = CancelGuard { map: Arc::clone(&cancels_map), id: id.clone() };

    let id_for_emit = id.clone();
    let name_for_emit = folder_name.clone();
    let app_for_emit = app.clone();
    let event_for_emit = event_name.clone();
    let emit_progress = move |bytes: u64, total: u64, status: &str, error: Option<String>| {
        let _ = app_for_emit.emit(
            &event_for_emit,
            serde_json::json!({
                "id": id_for_emit, "name": name_for_emit, "kind": "upload",
                "bytes": bytes, "total": total,
                "status": status, "error": error,
            }),
        );
    };

    emit_progress(0, 0, "progress", None);

    // Phase 1: enumerate. Collect every local file under local_root along
    // with its relative path (POSIX-style for the remote side) and size.
    // Iterative walk with an explicit stack so we never overflow async
    // recursion on pathological trees.
    let mut files: Vec<(std::path::PathBuf, String, u64)> = Vec::new();
    let mut dirs: Vec<String> = Vec::new(); // relative dir paths (POSIX) to mkdir on remote
    let mut total_bytes: u64 = 0;
    let mut stack: Vec<std::path::PathBuf> = vec![local_root.clone()];

    while let Some(dir) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            emit_progress(0, total_bytes, "cancelled", None);
            return Err("cancelled".into());
        }
        let read = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) => {
                emit_progress(0, total_bytes, "error", Some(format!("read_dir {:?}: {}", dir, e)));
                return Err(format!("read_dir {:?}: {}", dir, e));
            }
        };
        for entry in read {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            let rel = path
                .strip_prefix(&local_root)
                .map(|p| p.to_string_lossy().replace('\\', "/"))
                .unwrap_or_default();
            if ft.is_dir() {
                dirs.push(rel);
                stack.push(path);
            } else if ft.is_file() {
                let size = path.metadata().map(|m| m.len()).unwrap_or(0);
                total_bytes = total_bytes.saturating_add(size);
                files.push((path, rel, size));
            }
            // Symlinks and other types skipped — same as sftp_download_dir.
        }
    }

    // Phase 2: mkdir the destination folder, then each enumerated subdir.
    // SFTP's mkdir is per-level; we already collected them in pre-order from
    // the stack walk but order isn't guaranteed shallow-first, so re-sort
    // by path depth to make sure parents are created before children.
    let _ = sftp.create_dir(&remote_root).await;
    dirs.sort_by_key(|d| d.matches('/').count());
    for rel in &dirs {
        if cancel.load(Ordering::Relaxed) {
            emit_progress(0, total_bytes, "cancelled", None);
            return Err("cancelled".into());
        }
        let full = format!("{}/{}", remote_root.trim_end_matches('/'), rel);
        // Tolerate already-exists — a parallel mkdir or an earlier partial
        // run shouldn't abort the whole upload.
        if sftp.metadata(&full).await.is_err() {
            if let Err(e) = sftp.create_dir(&full).await {
                emit_progress(0, total_bytes, "error", Some(format!("mkdir {}: {}", full, e)));
                return Err(format!("mkdir {}: {}", full, e));
            }
        }
    }

    if files.is_empty() {
        emit_progress(0, 0, "done", None);
        return Ok(());
    }

    // Phase 3: stream each file up through a hidden part file that replaces
    // the target only once complete (F-025, atomic_transfer), with a shared
    // progress counter.
    let mut transferred: u64 = 0;
    let mut last_report = std::time::Instant::now();
    // Replaced files whose previous version could not be deleted.
    let mut leftovers: u64 = 0;

    for (local_file_path, rel, _size) in &files {
        if cancel.load(Ordering::Relaxed) {
            emit_progress(transferred, total_bytes, "cancelled", None);
            return Err("cancelled".into());
        }
        let remote_full = format!("{}/{}", remote_root.trim_end_matches('/'), rel);

        let before_file = transferred;
        let result = {
            let mut on_chunk = |offset: u64, chunk: &[u8]| {
                transferred = before_file.saturating_add(offset + chunk.len() as u64);
                if last_report.elapsed() >= std::time::Duration::from_millis(100) {
                    emit_progress(transferred, total_bytes, "progress", None);
                    last_report = std::time::Instant::now();
                }
                !cancel.load(Ordering::Relaxed)
            };
            atomic_transfer::replace_remote_file(&sftp, &remote_full, local_file_path, overwrite == Some(true), &mut on_chunk).await
        };
        match result {
            Ok(replaced) => {
                if replaced.note().is_some() {
                    leftovers += 1;
                }
            }
            Err(atomic_transfer::ReplaceError::Cancelled) => {
                emit_progress(transferred, total_bytes, "cancelled", None);
                return Err("cancelled".into());
            }
            Err(atomic_transfer::ReplaceError::Exists) => {
                emit_progress(transferred, total_bytes, "error",
                    Some(format!("{} exists", remote_full)));
                return Err(format!("EXISTS:{}", remote_full));
            }
            Err(atomic_transfer::ReplaceError::Failed(e)) => {
                emit_progress(transferred, total_bytes, "error",
                    Some(format!("upload {}: {}", remote_full, e)));
                return Err(format!("upload {}: {}", remote_full, e));
            }
        }
    }

    let note = (leftovers > 0).then(|| format!(
        "{} replaced file(s) left their previous version on the server as a hidden .solanum-old file",
        leftovers
    ));
    emit_progress(transferred, total_bytes, "done", note);
    Ok(())
}

/// Flip the cancel flag for an in-flight SFTP transfer. The download / upload
/// loop polls the flag every chunk (every ~256 KiB) and exits with a
/// "cancelled" status event as soon as it sees true. Unknown ids are a no-op
/// — by the time the UI's stop button click reaches us the transfer may have
/// already finished on its own.
#[tauri::command]
async fn sftp_cancel_transfer(
    state: tauri::State<'_, SshState>,
    transfer_id: String,
) -> Result<(), String> {
    if let Some(flag) = state.transfer_cancels.lock().await.get(&transfer_id) {
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    Ok(())
}

/// Bucket the failure modes that can come out of an SSH connect / auth round.
/// Drives both the UI's `is_auth_error` flag (so auto-reconnect only stops
/// on real credential rejection) and the wording of the error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectErrorKind {
    /// Server refused the credentials we presented.
    Auth,
    /// Couldn't agree on KEX / cipher / MAC / host-key algorithm with the
    /// peer. Server is reachable, our crypto preference set doesn't overlap.
    Algorithm,
    /// Host key issue — mismatched, declined by the user, or the prompt
    /// timed out. Distinct from auth: credentials never even got tried.
    HostKey,
    /// Transport-level drop: TCP reset, EOF, peer disconnect, IO error.
    Transport,
    /// Server didn't respond inside our window (handshake / auth / probe).
    Timeout,
    /// We couldn't even reach the box: DNS lookup failed, route missing,
    /// connection refused.
    Unreachable,
    /// A setting or saved item stops the attempt before the network is
    /// involved (a deleted login or key, a bad port, an empty proxy host).
    Config,
    /// Anything russh surfaced that we don't have a categorical bucket for.
    /// Treated as non-auth so the UI keeps trying — a real credential
    /// rejection has a specific variant for it.
    Unknown,
}

impl ConnectErrorKind {
    fn is_auth(self) -> bool {
        matches!(self, Self::Auth)
    }

    /// Whether auto-reconnect should try again (F-030): only for failures
    /// the network may fix by itself.
    fn retry(self) -> bool {
        matches!(self, Self::Transport | Self::Timeout | Self::Unreachable | Self::Unknown)
    }
}

/// Map a russh error onto a `ConnectErrorKind`. Uses enum variants when the
/// information is available (russh exposes most of them), falling back to
/// a string sniff only for the catch-all `_ =>` branch — so a russh upgrade
/// that adds new variants degrades gracefully instead of misreporting them
/// as auth failures.
fn classify_russh_error(e: &russh::Error) -> ConnectErrorKind {
    use russh::Error::*;
    match e {
        // Real credential rejection — the only path that should set
        // is_auth_error so the UI stops auto-retrying.
        NotAuthenticated | NoAuthMethod => ConnectErrorKind::Auth,

        // Algorithm negotiation — server's reachable, we just don't share
        // the cipher / KEX / etc. it asked for.
        NoCommonAlgo { .. } | UnknownAlgo => ConnectErrorKind::Algorithm,

        // Host-key flow: our check refused the key (`UnknownKey` is what
        // russh returns when `check_server_key` says no), or the server's
        // signature didn't verify. KeyChanged carries data so it falls
        // through to the catch-all branch which sniffs the string.
        UnknownKey | WrongServerSig => ConnectErrorKind::HostKey,

        // Transport-level: connection died mid-protocol.
        IO(_) | HUP | Disconnect | SendError => ConnectErrorKind::Transport,

        // Explicit timeouts from russh. A keepalive or inactivity timeout means
        // an ESTABLISHED connection went silent, i.e. a drop, not a slow start.
        ConnectionTimeout | Elapsed(_) => ConnectErrorKind::Timeout,
        KeepaliveTimeout | InactivityTimeout => ConnectErrorKind::Transport,

        // Protocol disagreements that aren't algorithm- or auth-shaped:
        // version skew, packet integrity, decryption — surface as transport
        // so the user is told "connection broke" not "password wrong".
        // `StrictKeyExchangeViolation` / `ChannelOpenFailure` carry data;
        // the `_ =>` fallthrough handles those via the string sniff below.
        Version | Kex | PacketAuth | Inconsistent | IndexOutOfBounds
        | DecryptionError | KexInit
        | WrongChannel | Pending => ConnectErrorKind::Transport,

        // Key-file problems (local cert can't be parsed). Tag as Auth-shaped
        // so the UI doesn't auto-retry a key that will keep failing.
        CouldNotReadKey | Keys(_) => ConnectErrorKind::Auth,

        // Last-resort string sniff for anything russh adds in future
        // versions or for io::Error subtypes the explicit arms above
        // missed. Default to Unknown which the driver treats as non-auth.
        _ => {
            let lc = e.to_string().to_lowercase();
            if lc.contains("connection refused")
                || lc.contains("no route")
                || lc.contains("network is unreachable")
                || lc.contains("dns")
            {
                ConnectErrorKind::Unreachable
            } else if lc.contains("timed out") || lc.contains("timeout") {
                ConnectErrorKind::Timeout
            } else if lc.contains("io error") || lc.contains("eof")
                || lc.contains("disconnect") || lc.contains("reset")
                || lc.contains("broken pipe") || lc.contains("aborted")
            {
                ConnectErrorKind::Transport
            } else if lc.contains("not authenticated") || lc.contains("auth method") {
                ConnectErrorKind::Auth
            } else {
                ConnectErrorKind::Unknown
            }
        }
    }
}

/// Human-readable phrase for an error bucket. Combined with `target` to
/// build the reason string the UI shows next to a failed connection.
fn describe_error_kind(kind: ConnectErrorKind, target: &str) -> String {
    match kind {
        ConnectErrorKind::Auth =>
            "Authentication rejected by server (wrong password, missing key, or account locked).".into(),
        ConnectErrorKind::Algorithm =>
            format!("Negotiation with {} failed: no SSH algorithm in common (the server may only offer legacy or very new algorithms).", target),
        ConnectErrorKind::HostKey =>
            "Host key was not approved (wrong key, declined, or the fingerprint prompt timed out).".into(),
        ConnectErrorKind::Transport =>
            format!("Connection to {} dropped mid-handshake.", target),
        ConnectErrorKind::Timeout =>
            format!("{} did not respond in time.", target),
        ConnectErrorKind::Unreachable =>
            format!("Could not reach {} (DNS lookup, route, or port refusal).", target),
        ConnectErrorKind::Config =>
            format!("The settings for {} are incomplete.", target),
        ConnectErrorKind::Unknown =>
            format!("Connection to {} failed for an unrecognised reason.", target),
    }
}

/// The message for a TCP connect that failed (`ssh_connect::connect_tcp`).
fn describe_tcp_failure(e: ssh_connect::TcpConnectError, host: &str, port: i32, label: &str) -> String {
    match e {
        ssh_connect::TcpConnectError::Resolve(raw) => format!("{}: could not resolve hostname {} ({})", label, host, raw),
        ssh_connect::TcpConnectError::Failed(e) => humanize_network_err(&e.to_string(), host, port, label),
        ssh_connect::TcpConnectError::TimedOut { tried, budget } => format!(
            "{}: {}:{} did not respond within {} seconds{}",
            label,
            host,
            port,
            budget.as_secs(),
            if tried > 1 { format!(" (tried {} addresses)", tried) } else { String::new() }
        ),
    }
}

/// Translate raw socket / SSH error messages into something a human can act
/// on. Most russh / tokio errors come out as "tcp: io error: ..." with the
/// useful detail buried — this lifts the common cases up to a clear sentence
/// while still falling back to the original text for anything unfamiliar.
fn humanize_network_err(raw: &str, host: &str, port: i32, label: &str) -> String {
    let lower = raw.to_lowercase();
    let target = if port > 0 { format!("{}:{}", host, port) } else { host.to_string() };

    if lower.contains("connection refused") {
        return format!("{}: {} refused the connection (is the SSH server running on this port?)", label, target);
    }
    if lower.contains("network is unreachable") || lower.contains("network unreachable") {
        return format!("{}: network is unreachable — check VPN / firewall / internet", label);
    }
    if lower.contains("no route to host") {
        return format!("{}: no route to {} — host is down or blocked", label, target);
    }
    if lower.contains("name or service not known")
        || lower.contains("nodename nor servname")
        || lower.contains("failed to lookup address")
        || lower.contains("no such host")
        || lower.contains("dns")
    {
        return format!("{}: could not resolve hostname {}", label, host);
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return format!("{}: {} did not respond in time", label, target);
    }
    if lower.contains("connection reset") || lower.contains("broken pipe") {
        return format!("{}: {} closed the connection", label, target);
    }
    if lower.contains("permission denied") {
        return format!("{}: permission denied (check key file readability)", label);
    }
    // Fallback — keep the raw detail so power users can still see it.
    format!("{}: {}", label, raw)
}

// Monotonically-increasing per-transfer id. The frontend uses it to group
// progress events into one updatable card per transfer.
fn transfer_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{}-{}", ts, seq)
}

/// Reduce a server-controlled remote path to a safe LOCAL leaf filename for
/// temp staging, with the same per-OS rules as downloads (see `local_path`):
/// no separators, no `.`/`..`, and on Windows no drive markers (a leaf like
/// "C:evil.txt" is drive-relative: `PathBuf::join` would discard the staging
/// folder), device names or trailing dots.
#[cfg_attr(target_os = "android", allow(dead_code))] // Android has no live edit
fn safe_temp_leaf_name(remote_path: &str) -> Result<String, String> {
    let leaf = local_path::remote_leaf(remote_path)?;
    if let Some(why) = local_path::local_name_problem(leaf, local_path::LocalOs::current()) {
        return Err(format!("refusing file with unsafe name: {:?} ({})", leaf, why));
    }
    Ok(leaf.to_string())
}

/// Live edit: download a remote file to a private staging folder, open it on
/// this machine, and upload it back on every save. Opening a file can run
/// hostile code here whatever its type, so Rust asks the user in a native
/// dialog the webview cannot answer (`open_guard::confirm`), after refusing the
/// types that are programs (`open_guard::open_verdict`). `Ok(false)`: the user
/// said no. Errors starting with `[OPEN_REFUSED]` name a type that is never
/// opened.
#[tauri::command]
async fn sftp_open_remote_file(
    app_handle: tauri::AppHandle,
    window: tauri::WebviewWindow,
    state: tauri::State<'_, SshState>,
    session_id: String,
    remote_path: String,
) -> Result<bool, String> {
    // The whole live-edit-in-default-editor feature is desktop-only —
    // Android's intent-based "open with" model would need a Tauri plugin
    // instead, and saving back through SAF doesn't fit the temp-file pattern
    // we depend on. Refuse before anything is downloaded.
    #[cfg(target_os = "android")]
    {
        let _ = (&app_handle, &window, &state, &session_id, &remote_path);
        return Err("Live edit in system editor is not available on Android.".into());
    }
    #[cfg(not(target_os = "android"))]
    {
        let filename = safe_temp_leaf_name(&remote_path)?;
        let platform = open_guard::Platform::current();
        let how = open_guard::open_verdict(&filename, platform, false)
            .map_err(|why| format!("[OPEN_REFUSED] {} Download it instead if you need it.", why))?;
        let sftp = get_sftp_session(&state, &session_id).await?;
        // Size and kind first: nothing is asked or downloaded for a file live
        // edit will not take (F-024). The download is capped as well, in case
        // the server reports less than it sends.
        let meta = sftp.metadata(&remote_path).await.map_err(|e| format!("Failed to read remote file: {}", e))?;
        // Only regular files (when the server says): reading a FIFO would
        // block the session's SFTP subsystem.
        if meta.permissions.is_some() && !meta.file_type().is_file() {
            return Err("Only regular files can be opened for live edit.".into());
        }
        if let Some(why) = meta.size.and_then(live_edit::size_refusal) {
            return Err(why);
        }
        let request = open_guard::confirm_remote_open(&remote_path, &filename, how, platform);
        if !open_guard::confirm(&window, request).await? {
            return Ok(false);
        }

        // Each open gets its own staging folder, watched for saves until the
        // session is disconnected or the profile is locked (live_edit.rs).
        let link: Arc<dyn live_edit::LiveEditLink> = Arc::new(AppLiveEditLink {
            app: app_handle.clone(),
            connections: Arc::clone(&state.connections),
            sftp_sessions: Arc::clone(&state.sftp_sessions),
            channel_gates: Arc::clone(&state.channel_gates),
            targets: Arc::clone(&state.session_targets),
            session_id: session_id.clone(),
        });
        // Some desktops pick the handler by content when the name does not
        // decide (see `open_guard::content_problem`).
        let refuse_content = move |head: &[u8]| {
            open_guard::content_problem(head, platform, false)
                .map(|why| format!("[OPEN_REFUSED] {} Download it instead if you need it.", why))
        };
        state
            .live_edits
            .open_and_launch(link, &session_id, &remote_path, &filename, &refuse_content, |copy| open_guard::launch(copy, how))
            .await?;
        Ok(true)
    }
}

/// Live edit's connection to the app: the session's cached SFTP subsystem
/// (like every other file operation, so a dedicated `::sftp` transport is
/// used when there is one) and `sftp-sync-status-<session>` events.
#[cfg(not(target_os = "android"))]
struct AppLiveEditLink {
    app: tauri::AppHandle,
    connections: ConnectionMap,
    sftp_sessions: SftpSessionMap,
    channel_gates: ChannelGateMap,
    targets: Arc<StdMutex<std::collections::HashMap<String, live_edit::ServerIdentity>>>,
    session_id: String,
}

#[cfg(not(target_os = "android"))]
impl live_edit::LiveEditLink for AppLiveEditLink {
    /// The session's server; with a dedicated `::sftp` connection (which the
    /// file transfers then use) both must be the same one.
    fn target(&self) -> Option<live_edit::ServerIdentity> {
        let targets = self.targets.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let base = targets.get(&self.session_id)?.clone();
        match targets.get(&format!("{}::sftp", self.session_id)) {
            Some(sftp) if *sftp != base => None,
            _ => Some(base),
        }
    }

    fn fetch<'a>(
        &'a self,
        remote: &'a str,
        dest: &'a std::path::Path,
        cap: u64,
    ) -> live_edit::BoxFut<'a, Result<live_edit::Fetched, String>> {
        Box::pin(async move {
            let sftp = sftp_session_for(&self.connections, &self.sftp_sessions, &self.channel_gates, &self.session_id).await?;
            live_edit::fetch_over_sftp(&sftp, remote, dest, cap).await
        })
    }

    fn store<'a>(
        &'a self,
        local: &'a std::path::Path,
        remote: &'a str,
    ) -> live_edit::BoxFut<'a, Result<live_edit::Stored, String>> {
        Box::pin(async move {
            let sftp = sftp_session_for(&self.connections, &self.sftp_sessions, &self.channel_gates, &self.session_id).await?;
            live_edit::store_over_sftp(&sftp, local, remote).await
        })
    }

    fn report(&self, status: live_edit::SyncStatus) {
        use live_edit::StatusKind;
        use tauri::Emitter;
        let kind = match status.kind {
            StatusKind::Synced => "success",
            StatusKind::Failed => "error",
            StatusKind::Note => "info",
            // The end of syncing comes when the tab is closed or the profile
            // locked, after the file browser that listens per session is
            // gone: it goes to the app instead (DesktopApp).
            StatusKind::Stopped | StatusKind::StoppedKept => {
                if status.kept.is_some() {
                    // Also on stderr, so the path is recorded even if no window shows it.
                    eprintln!("[live-edit] {}", status.message);
                }
                let _ = self.app.emit(
                    "live-edit-stopped",
                    serde_json::json!({
                        "message": status.message,
                        "keptPath": status.kept.as_ref().map(|p| p.to_string_lossy().into_owned()),
                        "remotePath": status.remote_path,
                    }),
                );
                return;
            }
        };
        let _ = self.app.emit(
            &format!("sftp-sync-status-{}", self.session_id),
            serde_json::json!({ "status": kind, "message": status.message, "remotePath": status.remote_path }),
        );
    }
}

/// Open a local file in its default app (or, for a script the OS would run,
/// as plain text), after a native confirmation the webview cannot answer. The
/// file may have come from a server. `Ok(false)`: the user said no. Errors
/// starting with `[OPEN_REFUSED]` name a file that is never opened (programs,
/// installers, shortcuts, folders); the UI offers "Show in folder" instead.
#[tauri::command]
async fn local_open_file(window: tauri::WebviewWindow, local_path: String) -> Result<bool, String> {
    #[cfg(target_os = "android")]
    {
        let _ = (&window, local_path);
        return Err("Open-with is not available on Android.".into());
    }
    #[cfg(not(target_os = "android"))]
    {
        let platform = open_guard::Platform::current();
        let checked = open_guard::check_local_open(&local_path, platform)?;
        let request = open_guard::confirm_local_open(&checked.path, checked.how, platform);
        if !open_guard::confirm(&window, request).await? {
            return Ok(false);
        }
        // The dialog can stay up for minutes: check again what the path is
        // now (which file, its type, size, times and mode), and open nothing
        // if anything changed.
        if open_guard::check_local_open(&local_path, platform)? != checked {
            return Err("[OPEN_REFUSED] The file changed while the dialog was open; nothing was opened.".into());
        }
        open_guard::launch(&checked.path, checked.how)?;
        Ok(true)
    }
}

/// The files of `session_id` being live-edited (the file browser's "Live
/// edits" list).
#[tauri::command]
async fn live_edit_list(state: tauri::State<'_, SshState>, session_id: String) -> Result<Vec<live_edit::LiveEditInfo>, String> {
    Ok(state.live_edits.list(&session_id))
}

/// Stops one file's live edit: its last change is uploaded if it can be,
/// then the copy is deleted, or kept and reported through `live-edit-stopped`
/// when it holds changes that did not reach the server. Returns at once; the
/// end is reported like the other ends of syncing.
#[tauri::command]
async fn live_edit_stop(state: tauri::State<'_, SshState>, session_id: String, remote_path: String) -> Result<(), String> {
    state.live_edits.stop_one(&session_id, &remote_path).map(|_| ())
}

/// Live-edit copies the start-up sweep kept because they may hold changes
/// that never reached the server (an earlier run crashed or was quit with
/// them), once, so the window can say where they are (F-061).
#[tauri::command]
async fn live_edit_leftovers(state: tauri::State<'_, SshState>) -> Result<Vec<String>, String> {
    #[cfg(target_os = "android")]
    {
        let _ = &state;
        Ok(Vec::new())
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(state.live_edits.take_leftovers().await.into_iter().map(|p| p.to_string_lossy().into_owned()).collect())
    }
}

#[tauri::command]
async fn local_open_in_explorer(local_path: String) -> Result<(), String> {
    #[cfg(target_os = "android")]
    {
        let _ = local_path;
        return Err("Open-in-Explorer is not available on Android.".into());
    }
    #[cfg(not(target_os = "android"))]
    {
        let safe = guard_local_path(&local_path, LocalAccess::Read)?;
        // macOS: `open <folder>` launches an application bundle (`Foo.app` is
        // a folder). `open -R` selects the item in Finder and runs nothing.
        #[cfg(target_os = "macos")]
        {
            let status = std::process::Command::new("/usr/bin/open")
                .arg("-R")
                .arg(&safe)
                .status()
                .map_err(|e| format!("Failed to open folder: {}", e))?;
            if !status.success() {
                return Err(format!("Failed to open folder: open -R exited with {}", status));
            }
        }
        // Elsewhere the folder itself is opened (`child_env::open_detached`:
        // without Solanum's own variables on Linux, ShellExecuteExW on
        // Windows, not `cmd /c start`, which expands `%VAR%` in the path).
        #[cfg(not(target_os = "macos"))]
        {
            let folder = if safe.is_dir() { Some(safe.as_path()) } else { safe.parent() };
            if let Some(folder) = folder {
                child_env::open_detached(open_guard::shown_path(folder).as_ref()).map_err(|e| format!("Failed to open folder: {}", e))?;
            }
        }
        Ok(())
    }
}

#[derive(serde::Serialize)]
struct LocalFileEntry {
    name: String,
    path: String,
    is_dir: bool,
    size: u64,
    modified: Option<u64>,
}

#[tauri::command]
async fn local_home_dir(app: tauri::AppHandle) -> Result<String, String> {
    #[cfg(target_os = "android")]
    {
        // Android has no "home directory" in the desktop sense — the
        // `directories` crate returns nothing meaningful here. Fall back to
        // whatever the quick-dirs probe picked (Downloads if writable, else
        // app-scoped external storage) so the callers that want *some*
        // starting point still get one instead of an error.
        let dir = android_default_local_dir(app).await?;
        if !dir.is_empty() { return Ok(dir); }
        return Err("Could not resolve home directory".into());
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        directories::UserDirs::new()
            .and_then(|d| d.home_dir().to_str().map(String::from))
            .ok_or_else(|| "Could not resolve home directory".into())
    }
}

#[tauri::command]
async fn local_desktop_dir(app: tauri::AppHandle) -> Result<String, String> {
    #[cfg(target_os = "android")]
    {
        // No Desktop concept on Android — reuse the writable-probe default
        // instead of erroring, so `FilePanel.homePath()` lands somewhere
        // useful on first load.
        let dir = android_default_local_dir(app).await?;
        if !dir.is_empty() { return Ok(dir); }
        return Err("Could not resolve default directory".into());
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        // Falls back to the home directory if a Desktop folder isn't configured
        // for the user (rare on desktop OSes but possible on Linux without XDG).
        if let Some(dirs) = directories::UserDirs::new() {
            if let Some(d) = dirs.desktop_dir().and_then(|p| p.to_str()) {
                return Ok(d.to_string());
            }
            if let Some(h) = dirs.home_dir().to_str() {
                return Ok(h.to_string());
            }
        }
        Err("Could not resolve Desktop directory".into())
    }
}

/// Test whether a directory is actually writable by the current process.
/// On Android, scoped storage means many paths appear readable via
/// `Path::exists()` but writes fail with EACCES — so we probe with a real
/// touch + delete. The probe filename is a random UUID-style token so
/// concurrent runs don't collide, and we tolerate `AlreadyExists` because
/// that still proves the parent is writable. Only called from the Android
/// quick-dirs picker today; the `#[allow]` keeps the desktop build quiet.
#[allow(dead_code)]
fn is_dir_writable(p: &std::path::Path) -> bool {
    if !p.is_dir() { return false; }
    let seq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let probe = p.join(format!(".solanum-probe-{}", seq));
    match std::fs::write(&probe, b"") {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Labeled quick-pick entries for the local file picker on Android.
/// Only writable paths are returned — the frontend uses this to populate a
/// small popover instead of the native rfd picker (which doesn't exist on
/// Android). Order is by preference: user-visible storage first (Downloads,
/// Documents), then app-scoped fallbacks that always work under scoped
/// storage. All returned paths are already canonical, so they pass
/// `guard_local_path` without further massaging.
#[derive(serde::Serialize)]
pub struct AndroidQuickDir {
    pub label: String,
    pub path: String,
}

#[tauri::command]
async fn android_quick_dirs(app: tauri::AppHandle) -> Result<Vec<AndroidQuickDir>, String> {
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        return Ok(Vec::new());
    }
    #[cfg(target_os = "android")]
    {
        // Build the candidate list up front (label + path pairs), then run
        // the writability probe + dedupe in a plain loop. The earlier
        // closure-based version couldn't coexist with the later
        // `out.is_empty()` re-borrow because the closure held a mutable
        // borrow of `out` for the whole function scope.
        let mut candidates: Vec<(String, std::path::PathBuf)> = vec![
            ("Downloads".into(),  std::path::PathBuf::from("/storage/emulated/0/Download")),
            ("Documents".into(),  std::path::PathBuf::from("/storage/emulated/0/Documents")),
            ("DCIM".into(),       std::path::PathBuf::from("/storage/emulated/0/DCIM")),
            ("Pictures".into(),   std::path::PathBuf::from("/storage/emulated/0/Pictures")),
            ("Movies".into(),     std::path::PathBuf::from("/storage/emulated/0/Movies")),
            ("Music".into(),      std::path::PathBuf::from("/storage/emulated/0/Music")),
            ("SD card".into(),    std::path::PathBuf::from("/storage/emulated/0")),
        ];
        // App-scoped external files dir — always writable, survives reboots,
        // and visible to the user through any file manager under
        // Android/data/io.github.joffrey_b.solanum/files. This is the fallback default
        // when everything shared is locked down.
        if let Ok(dir) = app.path().app_local_data_dir() {
            candidates.push(("App storage".into(), dir));
        }
        let mut out: Vec<AndroidQuickDir> = Vec::new();
        let mut seen = std::collections::HashSet::<String>::new();
        for (label, path) in candidates {
            if !is_dir_writable(&path) { continue; }
            let s = path.to_string_lossy().into_owned();
            if seen.insert(s.clone()) {
                out.push(AndroidQuickDir { label, path: s });
            }
        }
        // Internal cache — last-resort, still writable but hidden from the
        // user in most stock file managers. We only add it when nothing else
        // survived the writability probe above.
        if out.is_empty() {
            if let Ok(dir) = app.path().app_cache_dir() {
                if is_dir_writable(&dir) {
                    let s = dir.to_string_lossy().into_owned();
                    out.push(AndroidQuickDir { label: "App cache".into(), path: s });
                }
            }
        }
        Ok(out)
    }
}

/// Preferred default working directory on Android — first writable entry
/// from `android_quick_dirs`. FilePanel calls this on mount so the local
/// pane opens somewhere useful instead of `/` (which lists nothing under
/// scoped storage). Empty string means "leave the current path alone" and
/// is treated as a no-op by the frontend.
#[tauri::command]
async fn android_default_local_dir(app: tauri::AppHandle) -> Result<String, String> {
    let dirs = android_quick_dirs(app).await?;
    Ok(dirs.into_iter().next().map(|d| d.path).unwrap_or_default())
}

/// One resolved entry from an OpenSSH client config `Host` block. The
/// frontend picks a subset of these and turns each into a fresh server row
/// via `save_server` — password/key are left blank so
/// the user configures those after import.
#[derive(serde::Serialize)]
struct ImportedHost {
    /// The alias the user actually types (`ssh <alias>`) — becomes the
    /// server's display name after import.
    host_alias: String,
    /// Resolved `HostName`, or the alias itself if the block didn't set one
    /// (matches OpenSSH's own behaviour when HostName is omitted).
    hostname: String,
    /// Resolved `Port`, defaulting to the standard SSH port.
    port: u16,
    /// Resolved `User`. Empty string when unset — the frontend can fall
    /// back to whatever it uses elsewhere.
    user: String,
    /// Resolved `IdentityFile`. Purely informational for now — the import
    /// flow doesn't auto-attach keys because we'd need to also read and
    /// register them in the vault, which is a separate feature.
    identity_file: Option<String>,
    /// Resolved `ProxyJump`. Informational only; live proxy config still
    /// happens in the Server details panel.
    proxy_jump: Option<String>,
}

/// Read the user's OpenSSH client config (`~/.ssh/config`) and
/// return one `ImportedHost` per non-wildcard alias so the UI can offer a
/// checkbox picker. We deliberately keep the parser dumb: no macro
/// expansion, no `Include` recursion, no token substitution (`%h`/`%u`),
/// no `Match` blocks. Anything we don't understand is skipped silently
/// rather than surfaced as an error — a user's config often has many
/// directives (ForwardAgent, LogLevel, etc.) that are irrelevant to
/// picking a host to import.
///
/// Only that one file is read (the webview cannot name another path), off
/// the main thread, and only if it is a regular file of at most 1 MiB, so a
/// FIFO, a device or a huge file can't hang or exhaust the app.
///
/// Desktop-only. Android has no meaningful `~/.ssh/config` path; its import
/// window offers only the pasted source (`parse_client_import`), and this
/// returns a clear message rather than pretending to look somewhere.
#[tauri::command]
async fn parse_ssh_config() -> Result<Vec<ImportedHost>, String> {
    #[cfg(target_os = "android")]
    {
        Err("There is no ~/.ssh/config on Android: paste a PuTTY, MobaXterm or JSON export instead".into())
    }
    #[cfg(not(target_os = "android"))]
    {
        let config_path = directories::UserDirs::new()
            .map(|u| u.home_dir().join(".ssh").join("config"))
            .ok_or_else(|| "Could not resolve home directory".to_string())?;
        tokio::task::spawn_blocking(move || {
            let contents = read_small_text_file(&config_path, MAX_IMPORT_BYTES)
                .map_err(|why| format!("Could not read your SSH config ({}): {}", config_path.display(), why))?;
            Ok(parse_ssh_config_text(&contents))
        })
        .await
        .map_err(|e| format!("SSH config import failed: {}", e))?
    }
}

/// Upper bound for an SSH config file or a pasted client export.
const MAX_IMPORT_BYTES: u64 = 1024 * 1024;

/// Read a small text file without hanging on a FIFO or a device and without
/// swallowing a huge file: it must be a regular file (a symlink to one is
/// fine, dotfile managers use them) of at most `max` bytes. The reasons
/// returned never contain the path.
#[cfg(not(target_os = "android"))]
fn read_small_text_file(path: &std::path::Path, max: u64) -> Result<String, String> {
    use std::io::Read;
    let meta = fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "no such file".to_string(),
        kind => format!("it can't be read ({})", kind),
    })?;
    if !meta.is_file() {
        return Err("it is not a regular file".into());
    }
    if meta.len() > max {
        return Err(format!("it is larger than {} KiB", max / 1024));
    }
    let file = fs::File::open(path).map_err(|e| format!("it can't be opened ({})", e.kind()))?;
    // It may have grown since the check: never read past the cap.
    let mut buf = Vec::new();
    file.take(max + 1).read_to_end(&mut buf).map_err(|e| format!("it can't be read ({})", e.kind()))?;
    if buf.len() as u64 > max {
        return Err(format!("it is larger than {} KiB", max / 1024));
    }
    String::from_utf8(buf).map_err(|_| "it is not UTF-8 text".to_string())
}

/// The parser behind `parse_ssh_config` (see there for what it understands).
#[cfg(not(target_os = "android"))]
fn parse_ssh_config_text(contents: &str) -> Vec<ImportedHost> {
    // One in-progress Host block. We accumulate resolved fields as we
    // walk the file and emit one ImportedHost per alias when the block
    // ends (either the next `Host` line or EOF).
    struct Block {
        aliases: Vec<String>,
        hostname: Option<String>,
        port: Option<u16>,
        user: Option<String>,
        identity_file: Option<String>,
        proxy_jump: Option<String>,
    }

    // Split `Directive value...` into (directive, rest). OpenSSH treats
    // `=` and whitespace as equivalent separators between the directive
    // name and its argument, so both `Port 2222` and `Port=2222` parse
    // the same way.
    fn split_directive(line: &str) -> (&str, &str) {
        match line.find(|c: char| c.is_whitespace() || c == '=') {
            Some(i) => {
                let key = &line[..i];
                let rest = line[i..]
                    .trim_start_matches(|c: char| c.is_whitespace() || c == '=');
                (key, rest)
            }
            None => (line, ""),
        }
    }

    // Emit one ImportedHost per non-wildcard alias in the block. Wildcard
    // (`*` / `?`) and negation (`!prefix`) aliases are OpenSSH's template
    // mechanism — they don't correspond to a single server the user
    // would want as a row, so we skip them silently.
    fn flush_block(b: &Block, out: &mut Vec<ImportedHost>) {
        for alias in &b.aliases {
            if alias.contains('*') || alias.contains('?') || alias.starts_with('!') {
                continue;
            }
            out.push(ImportedHost {
                host_alias: alias.clone(),
                hostname: b.hostname.clone().unwrap_or_else(|| alias.clone()),
                port: b.port.unwrap_or(22),
                user: b.user.clone().unwrap_or_default(),
                identity_file: b.identity_file.clone(),
                proxy_jump: b.proxy_jump.clone(),
            });
        }
    }

    let mut out: Vec<ImportedHost> = Vec::new();
    let mut cur: Option<Block> = None;

    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, rest) = split_directive(line);
        let key_lc = key.to_ascii_lowercase();
        match key_lc.as_str() {
            "host" => {
                // Close out the previous block before starting a new one.
                if let Some(prev) = cur.take() {
                    flush_block(&prev, &mut out);
                }
                let mut b = Block {
                    aliases: Vec::new(),
                    hostname: None,
                    port: None,
                    user: None,
                    identity_file: None,
                    proxy_jump: None,
                };
                for a in rest.split_whitespace() {
                    b.aliases.push(a.trim_matches('"').to_string());
                }
                cur = Some(b);
            }
            "hostname" | "port" | "user" | "identityfile" | "proxyjump" => {
                if let Some(b) = cur.as_mut() {
                    let val = rest.trim().trim_matches('"');
                    if val.is_empty() {
                        continue;
                    }
                    match key_lc.as_str() {
                        "hostname" => b.hostname = Some(val.to_string()),
                        "port" => {
                            if let Ok(p) = val.parse::<u16>() {
                                b.port = Some(p);
                            }
                        }
                        "user" => b.user = Some(val.to_string()),
                        "identityfile" => b.identity_file = Some(val.to_string()),
                        "proxyjump" => b.proxy_jump = Some(val.to_string()),
                        _ => {}
                    }
                }
            }
            // Include chains, Match blocks, and every other directive
            // are v1-out-of-scope. Ignoring them keeps the parser
            // predictable for the "flat list of hosts" use case.
            _ => {}
        }
    }
    if let Some(last) = cur.take() {
        flush_block(&last, &mut out);
    }

    out
}

/// Parse a blob of text pasted from another SSH client's export and return
/// the same `ImportedHost` shape as `parse_ssh_config`. Auto-detects the
/// format so the frontend only needs one "Paste your export" text area
/// instead of a picker-per-format:
///
///   • Windows Regedit `.reg` export of PuTTY sessions
///     (`HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\...`) —
///     detected by the file's `Windows Registry Editor` header. Each
///     `[HKEY_...\Sessions\<name>]` block becomes one host; HostName,
///     PortNumber, and UserName are decoded from the `"key"=dword:` /
///     `"key"="value"` entries. Percent-decoded so aliases with spaces
///     ("My Prod Box") round-trip.
///
///   • JSON array — either
///     `[{"name":"foo","host":"1.2.3.4","port":22,"user":"root"}, …]`
///     or the Termius-style
///     `[{"label":"foo","address":"1.2.3.4","port":22,"username":"root"}, …]`.
///     Any missing field defaults to the OpenSSH convention.
///
///   • MobaXterm `.mxtsessions` INI (partial) — sessions live under
///     `[Bookmarks_<n>]` with `SessionName=…` and comma-separated fields
///     `HostName,Port,UserName,…`. Best-effort — MobaXterm's schema has
///     drifted across releases so we only trust the first four fields.
///
/// Anything the parser can't recognise is a soft-fail: the returned
/// `Vec` is what we DID find, the message describes what got skipped.
/// The command is desktop+Android — no filesystem access, just text. It runs
/// off the main thread and refuses more than 1 MiB.
#[tauri::command]
async fn parse_client_import(text: String) -> Result<Vec<ImportedHost>, String> {
    if text.len() as u64 > MAX_IMPORT_BYTES {
        return Err(format!("The pasted text is larger than {} KiB; paste fewer sessions at a time.", MAX_IMPORT_BYTES / 1024));
    }
    tokio::task::spawn_blocking(move || parse_client_import_text(text))
        .await
        .map_err(|e| format!("Import failed: {}", e))?
}

/// The parser behind `parse_client_import` (formats listed there).
fn parse_client_import_text(text: String) -> Result<Vec<ImportedHost>, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("Paste an exported session block first.".into());
    }

    // ── JSON array — the most permissive path, so try it first. Two
    //    supported field-name variants (see doc comment). We accept a
    //    generic `serde_json::Value` array rather than a strict struct
    //    so a stray extra field doesn't kill the whole import.
    if trimmed.starts_with('[') {
        let arr: Vec<serde_json::Value> = serde_json::from_str(trimmed)
            .map_err(|e| format!("JSON parse failed: {}", e))?;
        let mut out = Vec::with_capacity(arr.len());
        for (i, v) in arr.iter().enumerate() {
            let obj = v.as_object().ok_or_else(|| {
                format!("Entry #{} is not an object", i + 1)
            })?;
            let get_str = |keys: &[&str]| -> Option<String> {
                for k in keys {
                    if let Some(s) = obj.get(*k).and_then(|x| x.as_str()) {
                        if !s.is_empty() { return Some(s.to_string()); }
                    }
                }
                None
            };
            let get_u16 = |keys: &[&str]| -> Option<u16> {
                for k in keys {
                    if let Some(n) = obj.get(*k).and_then(|x| x.as_u64()) {
                        return u16::try_from(n).ok();
                    }
                    if let Some(s) = obj.get(*k).and_then(|x| x.as_str()) {
                        if let Ok(p) = s.parse::<u16>() { return Some(p); }
                    }
                }
                None
            };
            let alias = get_str(&["name", "label", "title", "alias", "host_alias"])
                .or_else(|| get_str(&["host", "hostname", "address"]))
                .unwrap_or_else(|| format!("imported-{}", i + 1));
            let hostname = get_str(&["host", "hostname", "address"]).unwrap_or_else(|| alias.clone());
            let port = get_u16(&["port"]).unwrap_or(22);
            let user = get_str(&["user", "username"]).unwrap_or_default();
            let identity_file = get_str(&["identity_file", "identityFile", "key", "privateKey"]);
            let proxy_jump = get_str(&["proxy_jump", "proxyJump", "jump"]);
            out.push(ImportedHost {
                host_alias: alias,
                hostname,
                port,
                user,
                identity_file,
                proxy_jump,
            });
        }
        if out.is_empty() {
            return Err("JSON array was valid but contained no entries.".into());
        }
        return Ok(out);
    }

    // ── PuTTY .reg export
    if trimmed.to_ascii_lowercase().contains("windows registry editor")
        || trimmed.contains("[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions")
        || trimmed.contains("[HKEY_USERS\\") && trimmed.contains("SimonTatham\\PuTTY\\Sessions")
    {
        return parse_putty_reg(trimmed);
    }

    // ── MobaXterm .mxtsessions
    if trimmed.contains("[Bookmarks") || trimmed.contains(";SessionName") {
        return parse_mobaxterm_sessions(trimmed);
    }

    Err("Unrecognised format — paste a JSON array, a PuTTY .reg export, or a MobaXterm .mxtsessions block.".into())
}

/// Parse `regedit /e` output of PuTTY's session key. The format is
/// deterministic (one `[...]` header line per session, then `"key"=type:val`
/// lines) so a line-oriented walk covers it. We only pull the three fields
/// that translate to a Solanum row: HostName, PortNumber, UserName.
/// Session-name percent-escapes (%20 for space, etc.) are undone so the
/// alias reads naturally.
fn parse_putty_reg(text: &str) -> Result<Vec<ImportedHost>, String> {
    let mut out: Vec<ImportedHost> = Vec::new();
    let mut current: Option<(String, String, u16, String)> = None; // (alias, host, port, user)
    let close = |cur: &mut Option<(String, String, u16, String)>, out: &mut Vec<ImportedHost>| {
        if let Some((alias, host, port, user)) = cur.take() {
            if !host.is_empty() || !alias.is_empty() {
                out.push(ImportedHost {
                    host_alias: alias.clone(),
                    hostname: if host.is_empty() { alias } else { host },
                    port: if port == 0 { 22 } else { port },
                    user,
                    identity_file: None,
                    proxy_jump: None,
                });
            }
        }
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() { continue; }
        if line.starts_with('[') && line.ends_with(']') {
            close(&mut current, &mut out);
            // Only sessions — skip other PuTTY keys (SshHostKeys, Jumplist).
            let inner = &line[1..line.len() - 1];
            let Some(idx) = inner.rfind("\\Sessions\\") else { continue; };
            let name_raw = &inner[idx + "\\Sessions\\".len()..];
            let name = putty_unescape(name_raw);
            if name.is_empty() { continue; }
            current = Some((name, String::new(), 0, String::new()));
            continue;
        }
        let Some((key, val_raw)) = line.split_once('=') else { continue; };
        let Some(cur) = current.as_mut() else { continue; };
        let key = key.trim().trim_matches('"');
        let val = val_raw.trim();
        match key {
            "HostName" => {
                if let Some(v) = strip_reg_string(val) { cur.1 = v; }
            }
            "PortNumber" => {
                if let Some(n) = strip_reg_dword(val) {
                    if let Ok(p) = u16::try_from(n) { cur.2 = p; }
                }
            }
            "UserName" => {
                if let Some(v) = strip_reg_string(val) { cur.3 = v; }
            }
            _ => {}
        }
    }
    close(&mut current, &mut out);
    if out.is_empty() {
        return Err("No PuTTY sessions found in the pasted text.".into());
    }
    Ok(out)
}

/// PuTTY registry keys with special characters (space, backslash, non-
/// ASCII) are percent-escaped in the exported name. `%20` → space,
/// `%25` → `%`. Anything else is passed through as-is. Not a full URL
/// decoder — PuTTY's escape table is narrower.
fn putty_unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Only treat `%HH` as an escape when both following bytes are ASCII
        // hex digits. The is_ascii_hexdigit guard also keeps the `&s[..]`
        // slice on char boundaries — without it, a `%` before a multi-byte
        // UTF-8 char (e.g. `%€`) would slice mid-codepoint and panic.
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hex = &s[i + 1..i + 3];
            if let Ok(n) = u8::from_str_radix(hex, 16) {
                out.push(n as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// `.reg` string entries look like `"HostName"="1.2.3.4"`. Strip the
/// surrounding quotes and unescape the two sequences .reg uses (`\\` and
/// `\"`). Returns None if the value isn't a quoted string.
fn strip_reg_string(val: &str) -> Option<String> {
    let s = val.trim();
    if !s.starts_with('"') || !s.ends_with('"') || s.len() < 2 { return None; }
    let inner = &s[1..s.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() { out.push(next); }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// `.reg` DWORD entries look like `"PortNumber"=dword:00000016`. The
/// `dword:` prefix is followed by exactly 8 hex chars. Anything else
/// (missing prefix, non-hex, wrong length) returns None so the caller
/// can leave the field at its default rather than propagating an error.
fn strip_reg_dword(val: &str) -> Option<u32> {
    let s = val.trim();
    let stripped = s.strip_prefix("dword:")?;
    u32::from_str_radix(stripped, 16).ok()
}

/// Parse a MobaXterm `.mxtsessions` INI-ish blob. MobaXterm stores each
/// session as one line under a `[Bookmarks_N]` group, formatted roughly
/// `<Title>=#109#0%<hostname>%<port>%<username>%…` with a variable trail
/// of feature flags. We only decode the first three fields — anything
/// past that is version-specific and not worth the complexity for an
/// import flow that leaves password/key blank anyway.
fn parse_mobaxterm_sessions(text: &str) -> Result<Vec<ImportedHost>, String> {
    let mut out: Vec<ImportedHost> = Vec::new();
    let mut in_bookmarks = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') { continue; }
        if line.starts_with('[') {
            in_bookmarks = line.starts_with("[Bookmarks");
            continue;
        }
        if !in_bookmarks { continue; }
        let Some((title, val)) = line.split_once('=') else { continue; };
        // MobaXterm SSH sessions start with `#109#`. Non-SSH bookmark
        // types (telnet, RDP, sftp-only) use different numbers — we
        // don't want to blindly import those as SSH rows.
        if !val.starts_with("#109#") { continue; }
        // Skip the `#109#<N>%` framing and split the payload on `%`.
        let payload = val.split_once('%').map(|(_, rest)| rest).unwrap_or(val);
        let parts: Vec<&str> = payload.split('%').collect();
        if parts.len() < 3 { continue; }
        let hostname = parts[0].trim();
        let port = parts[1].trim().parse::<u16>().unwrap_or(22);
        let user = parts[2].trim().to_string();
        if hostname.is_empty() { continue; }
        out.push(ImportedHost {
            host_alias: title.trim().to_string(),
            hostname: hostname.to_string(),
            port,
            user,
            identity_file: None,
            proxy_jump: None,
        });
    }
    if out.is_empty() {
        return Err("No MobaXterm sessions found in the pasted text.".into());
    }
    Ok(out)
}

#[tauri::command]
async fn local_create_dir(path: String) -> Result<(), String> {
    let safe = guard_local_path(&path, LocalAccess::Write)?;
    std::fs::create_dir_all(&safe).map_err(|e| format!("Failed to create directory: {}", e))
}

#[tauri::command]
async fn local_remove(path: String, is_dir: bool) -> Result<(), String> {
    // `Remove` resolves only the parent: a symlink is deleted itself, never the
    // file it points to.
    let safe = guard_local_path(&path, LocalAccess::Remove)?;
    if std::fs::symlink_metadata(&safe).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        // A Windows directory link is removed with remove_dir.
        std::fs::remove_file(&safe)
            .or_else(|_| std::fs::remove_dir(&safe))
            .map_err(|e| format!("Failed to remove link: {}", e))
    } else if is_dir {
        std::fs::remove_dir_all(&safe).map_err(|e| format!("Failed to remove directory: {}", e))
    } else {
        std::fs::remove_file(&safe).map_err(|e| format!("Failed to remove file: {}", e))
    }
}

#[tauri::command]
async fn local_rename(from: String, to: String) -> Result<(), String> {
    // Moving something away is removing it from where it was (and a symlink is
    // moved itself, not its target).
    let safe_from = guard_local_path(&from, LocalAccess::Remove)?;
    let safe_to = guard_local_path(&to, LocalAccess::Write)?;
    // Same auto-mkdir-parent UX as sftp_rename: moving a file into a
    // subfolder that doesn't exist yet would otherwise fail with a
    // confusing "system cannot find the path specified" / ENOENT.
    if let Some(parent) = safe_to.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create destination parent {:?}: {}", parent, e))?;
        }
    }
    std::fs::rename(&safe_from, &safe_to)
        .map_err(|e| format!("rename {:?} -> {:?}: {}", safe_from, safe_to, e))
}

#[tauri::command]
async fn select_local_folder() -> Result<Option<String>, String> {
    #[cfg(target_os = "android")]
    {
        return Err("Folder picker not available on Android.".into());
    }
    #[cfg(not(target_os = "android"))]
    {
        let folder = rfd::FileDialog::new()
            .set_title("Choose Local Directory")
            .pick_folder();
        Ok(folder.map(|p| p.to_string_lossy().to_string()))
    }
}

// Backs the local pane's "Upload…" button: lets the user pick file(s) to
// upload without first navigating the local pane to wherever they happen to
// live. Same Android gate as select_local_folder, for the same reason — SAF
// content URIs aren't real filesystem paths std::fs can open.
#[tauri::command]
async fn select_local_files() -> Result<Vec<String>, String> {
    #[cfg(target_os = "android")]
    {
        Err("File picker not available on Android.".into())
    }
    #[cfg(not(target_os = "android"))]
    {
        let files = rfd::FileDialog::new()
            .set_title("Choose Files to Upload")
            .pick_files();
        Ok(files
            .unwrap_or_default()
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect())
    }
}

// Backs the OS-level drag-drop-in handler: `tauri://drag-drop` only gives
// raw paths, no metadata, so the frontend can't otherwise tell whether a
// dropped item needs the single-file or the recursive-directory upload
// command. A plain metadata check — no guard_local_path — is enough here:
// this is read-only (nothing is written or exposed beyond a bool the user
// already implied by dragging the item themselves), and the guard's own
// root/system-path refusals would be the wrong call for a type check.
#[tauri::command]
async fn local_path_is_dir(path: String) -> Result<bool, String> {
    let meta = std::fs::metadata(&path).map_err(|e| format!("Failed to read {}: {}", path, e))?;
    Ok(meta.is_dir())
}

#[tauri::command]
async fn local_list_dir(path: String) -> Result<Vec<LocalFileEntry>, String> {
    let safe = guard_local_path(&path, LocalAccess::Read)?;
    if !safe.is_dir() {
        return Err("Path is not a directory".into());
    }

    let mut entries = Vec::new();
    let read_dir = std::fs::read_dir(&safe).map_err(|e| format!("Failed to read directory: {}", e))?;

    for entry in read_dir {
        if let Ok(entry) = entry {
            let metadata = entry.metadata().ok();
            let is_dir = metadata.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);
            let name = entry.file_name().to_string_lossy().to_string();
            let full_path = entry.path().to_string_lossy().to_string();
            
            let modified = metadata.as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::SystemTime::UNIX_EPOCH).ok())
                .map(|d| d.as_secs());

            entries.push(LocalFileEntry {
                name,
                path: full_path,
                is_dir,
                size,
                modified,
            });
        }
    }

    // Sort: directories first, then alphabetically
    entries.sort_by(|a, b| {
        if a.is_dir != b.is_dir {
            b.is_dir.cmp(&a.is_dir)
        } else {
            a.name.to_lowercase().cmp(&b.name.to_lowercase())
        }
    });

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Monitoring commands
// ---------------------------------------------------------------------------

/// Pulls the auth bundle needed to open a monitor session for a node. Returns
/// the resolved (username, password, key_pem, passphrase) following the same
/// "vault vs custom_*" rule the interactive connect path uses — so monitor
/// auth never silently diverges from what the user sees in the form.
fn resolve_node_auth_for_monitor(
    conn: &rusqlite::Connection,
    node_id: i32,
) -> Result<monitor::NodeAuth, String> {
    let mut stmt = conn.prepare("
        SELECT s.host, s.port,
               s.username, c.username,
               s.password, c.password,
               s.key_id,   c.key_id,
               s.auth_type, c.auth_type as cred_auth_type,
               s.proxy_type, s.proxy_host, s.proxy_port,
               s.legacy_algorithms, c.id, s.jump_host_id
        FROM servers s
        LEFT JOIN credentials c ON s.credential_id = c.id
        WHERE s.id = ?1
    ").map_err(|e| e.to_string())?;
    let mut rows = stmt.query([node_id]).map_err(|e| e.to_string())?;
    let row = rows.next().map_err(|e| e.to_string())?.ok_or("node not found")?;

    let host: String = row.get::<_, String>(0).map_err(|e| e.to_string())?;
    let port: i32 = row.get::<_, i32>(1).map_err(|e| e.to_string())?;
    let s_user: Option<String> = row.get(2).ok().flatten();
    let c_user: Option<String> = row.get(3).ok().flatten();
    let s_pass: Option<String> = row.get(4).ok().flatten();
    let c_pass: Option<String> = row.get(5).ok().flatten();
    let s_key:  Option<i32>    = row.get(6).ok().flatten();
    let c_key:  Option<i32>    = row.get(7).ok().flatten();
    let auth_type: String = row.get::<_, Option<String>>(8).ok().flatten().unwrap_or_else(|| "vault".into());
    let cred_auth_type: Option<String> = row.get(9).ok().flatten();
    let proxy_type: String = row.get::<_, Option<String>>(10).ok().flatten().unwrap_or_else(|| "none".into());
    let proxy_host: Option<String> = row.get(11).ok().flatten();
    let proxy_port: Option<i32> = row.get(12).ok().flatten();
    let legacy_algorithms = row.get::<_, i64>(13).map_err(|e| e.to_string())? != 0;
    let credential_found = row.get::<_, Option<i32>>(14).map_err(|e| e.to_string())?.is_some();
    let jump_host_id: Option<i32> = row.get(15).map_err(|e| e.to_string())?;

    let (username, password, key_id) = if auth_type == "vault" {
        (c_user.unwrap_or_default(), c_pass, c_key)
    } else {
        (s_user.unwrap_or_default(), s_pass, s_key)
    };
    let effective_key_id = if auth_type == "vault" {
        if cred_auth_type.as_deref() == Some("key") { key_id } else { None }
    } else if auth_type == "custom_key" {
        key_id
    } else {
        None
    };

    let (private_key, passphrase) = if let Some(kid) = effective_key_id {
        let mut key_stmt = conn.prepare("SELECT private_key, passphrase FROM ssh_keys WHERE id = ?1")
            .map_err(|e| e.to_string())?;
        let mut krows = key_stmt.query([kid]).map_err(|e| e.to_string())?;
        if let Some(r) = krows.next().map_err(|e| e.to_string())? {
            let pk: String = r.get(0).map_err(|e| e.to_string())?;
            let pp: Option<String> = r.get(1).ok().flatten();
            (Some(pk), pp)
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };
    // A deleted login or key is said as such, as on the connect path (N-003).
    if let Some(reason) = missing_identity_reason(&auth_type, credential_found, cred_auth_type.as_deref(), private_key.is_some()) {
        return Err(reason.to_string());
    }

    // Only read for a proxy connection; checked when it is.
    let proxy_port = match proxy_type.as_str() {
        "socks5" | "http" => proxy_port.map(|p| checked_port(p, "Proxy port")).transpose()?,
        _ => None,
    };
    let port = checked_port(port, "Port")?;
    let known_key_types = ssh_manager::known_key_types(conn, &host, port).map_err(|e| e.to_string())?;
    // Through the jump host, as a session goes (F-062).
    let jump = match jump_host_id {
        Some(jid) => {
            let hop = resolve_jump_auth(conn, jid)?.ok_or("The jump host of this server no longer exists.")?;
            let hop_port = checked_port(hop.port, "Jump host port")?;
            let hop_types = ssh_manager::known_key_types(conn, &hop.host, hop_port).map_err(|e| e.to_string())?;
            let (private_key, passphrase) = hop.key.map_or((None, None), |(k, p)| (Some(k), p));
            Some(Box::new(monitor::NodeAuth {
                policy: ssh_connect::AlgorithmPolicy { legacy: hop.legacy_algorithms, known_key_types: hop_types },
                username: if hop.user.trim().is_empty() { "root".into() } else { hop.user },
                host: hop.host,
                port: hop_port,
                password: hop.password,
                private_key,
                passphrase,
                proxy_type: "none".into(),
                proxy_host: None,
                proxy_port: None,
                jump: None,
            }))
        }
        None => None,
    };
    Ok(monitor::NodeAuth {
        jump,
        policy: ssh_connect::AlgorithmPolicy { legacy: legacy_algorithms, known_key_types },
        host,
        port,
        username: if username.trim().is_empty() { "root".into() } else { username },
        password,
        private_key,
        passphrase,
        proxy_type,
        proxy_host: proxy_host.filter(|s| !s.is_empty()),
        proxy_port,
    })
}

fn default_metrics() -> Vec<String> {
    vec!["cpu".into(), "mem".into(), "disk".into(), "load".into()]
}

/// Look up just the display name for a node. Used by the monitor's
/// outage/recovered event payloads so the frontend can show a meaningful
/// toast ("web-01 is offline") without doing another round-trip.
fn fetch_node_name(conn: &rusqlite::Connection, node_id: i32) -> String {
    conn.query_row("SELECT name FROM servers WHERE id = ?1", [node_id], |r| r.get::<_, String>(0))
        .unwrap_or_else(|_| format!("node-{}", node_id))
}

fn load_monitor_config(
    conn: &rusqlite::Connection,
    node_id: i32,
) -> Option<(Vec<String>, Vec<monitor::CustomMetric>, bool)> {
    let mut stmt = conn.prepare("SELECT enabled_metrics, custom_metrics, paused FROM monitor_configs WHERE node_id = ?1").ok()?;
    let mut rows = stmt.query([node_id]).ok()?;
    let row = rows.next().ok()??;
    let json_metrics: String = row.get(0).ok()?;
    let json_customs: String = row.get(1).ok().unwrap_or_else(|| "[]".into());
    let paused: i32 = row.get(2).ok()?;
    let metrics: Vec<String> = serde_json::from_str(&json_metrics).unwrap_or_else(|_| default_metrics());
    let customs: Vec<monitor::CustomMetric> = serde_json::from_str(&json_customs).unwrap_or_default();
    Some((metrics, customs, paused != 0))
}

fn upsert_monitor_config(
    conn: &rusqlite::Connection,
    node_id: i32,
    metrics: &[String],
    customs: &[monitor::CustomMetric],
    paused: bool,
) -> Result<(), String> {
    let json_metrics = serde_json::to_string(metrics).map_err(|e| e.to_string())?;
    let json_customs = serde_json::to_string(customs).map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO monitor_configs (node_id, enabled_metrics, custom_metrics, paused) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(node_id) DO UPDATE SET enabled_metrics=excluded.enabled_metrics, custom_metrics=excluded.custom_metrics, paused=excluded.paused",
        rusqlite::params![node_id, json_metrics, json_customs, if paused { 1 } else { 0 }],
    ).map_err(|e| e.to_string())?;
    Ok(())
}

/// Frontend shape: monitor_list returns this for each known monitor (whether
/// it's been started in the live MonitorMap yet or not). UI uses it to
/// render the sidebar even before the first sample arrives.
#[derive(serde::Serialize)]
struct MonitorRow {
    node_id: i32,
    name: String,
    host: String,
    port: i32,
    enabled_metrics: Vec<String>,
    custom_metrics: Vec<monitor::CustomMetric>,
    paused: bool,
    connected: bool,
    last_error: Option<String>,
    last_sample_ts: Option<u64>,
    /// The card's outage strip reads these two (N-024).
    consecutive_failures: u32,
    outage_since_ms: Option<u64>,
    /// Why the monitor stopped until resumed (F-017).
    auth_failed: Option<String>,
}

fn load_settings_from_db(conn: &rusqlite::Connection) -> monitor::MonitorSettings {
    let mut stmt = match conn.prepare("SELECT json FROM monitor_settings WHERE id = 1") {
        Ok(s) => s,
        Err(_) => return monitor::MonitorSettings::default(),
    };
    let mut rows = match stmt.query([]) {
        Ok(r) => r,
        Err(_) => return monitor::MonitorSettings::default(),
    };
    if let Ok(Some(row)) = rows.next() {
        if let Ok(json) = row.get::<_, String>(0) {
            if let Ok(s) = serde_json::from_str::<monitor::MonitorSettings>(&json) {
                return s.sanitized();
            }
        }
    }
    monitor::MonitorSettings::default()
}

/// Put the open profile's monitor settings (the defaults if it saved none,
/// or no profile is open) in the shared copy the pollers read (F-080).
async fn load_monitor_settings(db_state: &DbState, settings: &SharedSettings) {
    // The std guard is dropped before the tokio lock is awaited (Send).
    let loaded = {
        let guard = db_state.conn.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.as_ref().map(load_settings_from_db)
    };
    *settings.lock().await = loaded.unwrap_or_default();
}

#[tauri::command]
async fn monitor_get_settings(
    db_state: tauri::State<'_, DbState>,
    settings: tauri::State<'_, SharedSettings>,
) -> Result<monitor::MonitorSettings, String> {
    // The vault is the truth while a profile is open; the shared copy follows it.
    let from_db: Option<monitor::MonitorSettings> = {
        let guard = db_state.conn.lock().map_err(|_| "lock")?;
        guard.as_ref().map(load_settings_from_db)
    };
    match from_db {
        Some(saved) => {
            *settings.lock().await = saved.clone();
            Ok(saved)
        }
        None => Ok(settings.lock().await.clone()),
    }
}

#[tauri::command]
async fn monitor_set_settings(
    db_state: tauri::State<'_, DbState>,
    settings: tauri::State<'_, SharedSettings>,
    new_settings: monitor::MonitorSettings,
) -> Result<monitor::MonitorSettings, String> {
    let sane = new_settings.sanitized();
    {
        let guard = db_state.conn.lock().map_err(|_| "lock")?;
        let conn = guard.as_ref().ok_or("db not ready")?;
        let json = serde_json::to_string(&sane).map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT INTO monitor_settings (id, json) VALUES (1, ?1)
             ON CONFLICT(id) DO UPDATE SET json = excluded.json",
            rusqlite::params![json],
        ).map_err(|e| e.to_string())?;
    }
    save_vault_internal(&db_state)?;
    *settings.lock().await = sane.clone();
    Ok(sane)
}

#[tauri::command]
async fn monitor_list(
    db_state: tauri::State<'_, DbState>,
    map: tauri::State<'_, MonitorMap>,
) -> Result<Vec<MonitorRow>, String> {
    // Pull DB rows first so we always include configured-but-paused entries
    // even if they have no live MonitorEntry yet.
    let configs: Vec<(i32, String, String, i32, Vec<String>, Vec<monitor::CustomMetric>, bool)> = {
        let guard = db_state.conn.lock().map_err(|_| "lock")?;
        let conn = guard.as_ref().ok_or("db not ready")?;
        let mut stmt = conn.prepare("
            SELECT mc.node_id, s.name, s.host, s.port, mc.enabled_metrics, mc.custom_metrics, mc.paused
            FROM monitor_configs mc
            JOIN servers s ON s.id = mc.node_id
            ORDER BY s.name COLLATE NOCASE
        ").map_err(|e| e.to_string())?;
        let rows = stmt.query_map([], |r| {
            let metrics_json: String = r.get(4)?;
            let metrics: Vec<String> = serde_json::from_str(&metrics_json).unwrap_or_else(|_| default_metrics());
            let customs_json: String = r.get(5).unwrap_or_else(|_| "[]".into());
            let customs: Vec<monitor::CustomMetric> = serde_json::from_str(&customs_json).unwrap_or_default();
            let paused: i32 = r.get(6)?;
            Ok((r.get::<_, i32>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, i32>(3)?, metrics, customs, paused != 0))
        }).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for row in rows { if let Ok(v) = row { out.push(v); } }
        out
    };

    // Merge live state from MonitorMap on top.
    let live = monitor::list(map.inner().clone()).await;
    let live_by_id: std::collections::HashMap<i32, monitor::MonitorInfo> =
        live.into_iter().map(|m| (m.node_id, m)).collect();

    Ok(configs.into_iter().map(|(node_id, name, host, port, metrics, customs, paused)| {
        let live = live_by_id.get(&node_id);
        MonitorRow {
            node_id,
            name, host, port,
            enabled_metrics: metrics,
            custom_metrics: customs,
            paused,
            connected: live.map(|l| l.connected).unwrap_or(false),
            last_error: live.and_then(|l| l.last_error.clone()),
            last_sample_ts: live.and_then(|l| l.last_sample_ts),
            consecutive_failures: live.map(|l| l.consecutive_failures).unwrap_or(0),
            outage_since_ms: live.and_then(|l| l.outage_since_ms),
            auth_failed: live.and_then(|l| l.auth_failed.clone()),
        }
    }).collect())
}

#[tauri::command]
async fn monitor_add(
    db_state: tauri::State<'_, DbState>,
    node_id: i32,
) -> Result<(), String> {
    // Persist the config row only; the poller doesn't spawn until the user
    // explicitly clicks Resume (per the "no auto-start" rule). We still
    // resolve the auth bundle once here so adding a node with broken auth
    // fails fast instead of silently sitting in a paused state forever.
    {
        let guard = db_state.conn.lock().map_err(|_| "lock")?;
        let conn = guard.as_ref().ok_or("db not ready")?;
        let _ = resolve_node_auth_for_monitor(conn, node_id)?;
        upsert_monitor_config(conn, node_id, &default_metrics(), &[], true)?;
    }
    save_vault_internal(&db_state)?;
    Ok(())
}

#[tauri::command]
async fn monitor_remove(
    db_state: tauri::State<'_, DbState>,
    map: tauri::State<'_, MonitorMap>,
    node_id: i32,
) -> Result<(), String> {
    monitor::stop_monitor(map.inner().clone(), node_id).await;
    {
        let guard = db_state.conn.lock().map_err(|_| "lock")?;
        let conn = guard.as_ref().ok_or("db not ready")?;
        conn.execute("DELETE FROM monitor_configs WHERE node_id=?1", [node_id])
            .map_err(|e| e.to_string())?;
    }
    save_vault_internal(&db_state)?;
    Ok(())
}

#[tauri::command]
async fn monitor_set_metrics(
    db_state: tauri::State<'_, DbState>,
    map: tauri::State<'_, MonitorMap>,
    node_id: i32,
    metrics: Vec<String>,
) -> Result<(), String> {
    {
        let guard = db_state.conn.lock().map_err(|_| "lock")?;
        let conn = guard.as_ref().ok_or("db not ready")?;
        // Preserve current pause state + custom list from row.
        let (_, customs, paused) = load_monitor_config(conn, node_id)
            .unwrap_or((default_metrics(), vec![], true));
        upsert_monitor_config(conn, node_id, &metrics, &customs, paused)?;
    }
    save_vault_internal(&db_state)?;
    // If a live poller exists, hot-update it; otherwise it'll pick up on resume.
    let _ = monitor::set_enabled_metrics(map.inner().clone(), node_id, metrics).await;
    Ok(())
}

#[tauri::command]
async fn monitor_set_custom_metrics(
    db_state: tauri::State<'_, DbState>,
    map: tauri::State<'_, MonitorMap>,
    node_id: i32,
    customs: Vec<monitor::CustomMetric>,
) -> Result<(), String> {
    {
        let guard = db_state.conn.lock().map_err(|_| "lock")?;
        let conn = guard.as_ref().ok_or("db not ready")?;
        let (metrics, _, paused) = load_monitor_config(conn, node_id)
            .unwrap_or((default_metrics(), vec![], true));
        upsert_monitor_config(conn, node_id, &metrics, &customs, paused)?;
    }
    save_vault_internal(&db_state)?;
    let _ = monitor::set_custom_metrics(map.inner().clone(), node_id, customs).await;
    Ok(())
}

#[tauri::command]
async fn monitor_resume(
    app: tauri::AppHandle,
    db_state: tauri::State<'_, DbState>,
    ssh: tauri::State<'_, SshState>,
    map: tauri::State<'_, MonitorMap>,
    settings: tauri::State<'_, SharedSettings>,
    node_id: i32,
) -> Result<(), String> {
    // A lock that runs meanwhile sweeps the monitors before this one is
    // registered; while one runs, nothing new starts.
    let epoch = ssh.epoch();
    if epoch.closing() {
        return Err(ssh_manager::PROFILE_CLOSING_MSG.into());
    }
    // The login is read by the poller at each connect; a node it cannot use
    // stops with the reason on its card (F-017, N-003).
    let (metrics, customs, name) = {
        let guard = db_state.conn.lock().map_err(|_| "lock")?;
        let conn = guard.as_ref().ok_or("db not ready")?;
        let (metrics, customs, _) = load_monitor_config(conn, node_id)
            .ok_or_else(|| format!("Node {} is not in the monitor list", node_id))?;
        upsert_monitor_config(conn, node_id, &metrics, &customs, false)?;
        (metrics, customs, fetch_node_name(conn, node_id))
    };
    save_vault_internal(&db_state)?;

    // If a poller already exists, just hot-flip paused; otherwise spawn one.
    if monitor::set_paused(map.inner().clone(), node_id, false).await.is_err() {
        let poller = monitor_poller(&app, &db_state, &settings, node_id, name);
        monitor::start_monitor(map.inner().clone(), node_id, metrics, customs, false, poller).await;
    }
    // Started after a lock swept the monitors: it would outlive its profile.
    if !epoch.current() {
        monitor::stop_monitor(map.inner().clone(), node_id).await;
    }
    Ok(())
}

/// What a monitor's poller needs from the app (F-017, F-062): its events,
/// the shared settings, how it reads the node's login from the vault (at
/// every connect), and how it reaches the node.
fn monitor_poller(
    app: &tauri::AppHandle,
    db_state: &DbState,
    settings: &SharedSettings,
    node_id: i32,
    node_name: String,
) -> monitor::Poller {
    let db = Arc::clone(&db_state.conn);
    monitor::Poller {
        events: monitor_events(app),
        settings: Arc::clone(settings),
        node_name,
        resolve: Arc::new(move || {
            let guard = db.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let conn = guard.as_ref().ok_or("No profile is open.")?;
            resolve_node_auth_for_monitor(conn, node_id)
        }),
        connect: monitor::network_connector(Arc::clone(&db_state.conn)),
        timing: monitor::PollerTiming::default(),
    }
}

/// The monitor's reports as app events, per node (`monitor-status-<id>`, ...).
fn monitor_events(app: &tauri::AppHandle) -> monitor::MonitorEvents {
    use tauri::Emitter;
    let (status, sample, outage, recovered, stopped) = (app.clone(), app.clone(), app.clone(), app.clone(), app.clone());
    monitor::MonitorEvents {
        status: Arc::new(move |info: &monitor::MonitorInfo| {
            let _ = status.emit(&format!("monitor-status-{}", info.node_id), info);
        }),
        sample: Arc::new(move |s: &monitor::Sample| {
            let _ = sample.emit(&format!("monitor-sample-{}", s.node_id), s);
        }),
        outage: Arc::new(move |o: &monitor::OutageEvent| {
            let _ = outage.emit(&format!("monitor-outage-{}", o.node_id), o);
        }),
        recovered: Arc::new(move |r: &monitor::RecoveredEvent| {
            let _ = recovered.emit(&format!("monitor-recovered-{}", r.node_id), r);
        }),
        stopped: Arc::new(move |e: &monitor::StoppedEvent| {
            let _ = stopped.emit(&format!("monitor-stopped-{}", e.node_id), e);
        }),
    }
}

#[tauri::command]
async fn monitor_pause(
    db_state: tauri::State<'_, DbState>,
    map: tauri::State<'_, MonitorMap>,
    node_id: i32,
) -> Result<(), String> {
    {
        let guard = db_state.conn.lock().map_err(|_| "lock")?;
        let conn = guard.as_ref().ok_or("db not ready")?;
        if let Some((metrics, customs, _)) = load_monitor_config(conn, node_id) {
            upsert_monitor_config(conn, node_id, &metrics, &customs, true)?;
        }
    }
    save_vault_internal(&db_state)?;
    let _ = monitor::set_paused(map.inner().clone(), node_id, true).await;
    Ok(())
}

#[tauri::command]
async fn monitor_pause_all(
    db_state: tauri::State<'_, DbState>,
    map: tauri::State<'_, MonitorMap>,
) -> Result<(), String> {
    {
        let guard = db_state.conn.lock().map_err(|_| "lock")?;
        let conn = guard.as_ref().ok_or("db not ready")?;
        conn.execute("UPDATE monitor_configs SET paused = 1", [])
            .map_err(|e| e.to_string())?;
    }
    save_vault_internal(&db_state)?;
    monitor::pause_all(map.inner().clone()).await;
    Ok(())
}

#[tauri::command]
async fn monitor_resume_all(
    app: tauri::AppHandle,
    db_state: tauri::State<'_, DbState>,
    ssh: tauri::State<'_, SshState>,
    map: tauri::State<'_, MonitorMap>,
    settings: tauri::State<'_, SharedSettings>,
) -> Result<(), String> {
    let epoch = ssh.epoch();
    if epoch.closing() {
        return Err(ssh_manager::PROFILE_CLOSING_MSG.into());
    }
    // Persist all to unpaused first.
    let node_ids: Vec<i32> = {
        let guard = db_state.conn.lock().map_err(|_| "lock")?;
        let conn = guard.as_ref().ok_or("db not ready")?;
        conn.execute("UPDATE monitor_configs SET paused = 0", [])
            .map_err(|e| e.to_string())?;
        let mut stmt = conn.prepare("SELECT node_id FROM monitor_configs").map_err(|e| e.to_string())?;
        let rows = stmt.query_map([], |r| r.get::<_, i32>(0)).map_err(|e| e.to_string())?;
        rows.filter_map(|r| r.ok()).collect()
    };
    save_vault_internal(&db_state)?;

    // Start (or hot-resume) each one.
    for &node_id in &node_ids {
        if monitor::set_paused(map.inner().clone(), node_id, false).await.is_err() {
            // No login is read here: a node the poller cannot log in to
            // stops on its own card instead of ending this loop (N-003).
            let (metrics, customs, name) = {
                let guard = db_state.conn.lock().map_err(|_| "lock")?;
                let conn = guard.as_ref().ok_or("db not ready")?;
                let (metrics, customs, _) = load_monitor_config(conn, node_id)
                    .unwrap_or((default_metrics(), vec![], false));
                (metrics, customs, fetch_node_name(conn, node_id))
            };
            let poller = monitor_poller(&app, &db_state, &settings, node_id, name);
            monitor::start_monitor(map.inner().clone(), node_id, metrics, customs, false, poller).await;
        }
    }
    // Started after a lock swept the monitors: they would outlive their profile.
    if !epoch.current() {
        for node_id in node_ids {
            monitor::stop_monitor(map.inner().clone(), node_id).await;
        }
    }
    Ok(())
}

/// What to do about WebKit's sandbox on this machine.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq)]
enum WebkitSandbox {
    /// Turn WebKit's sandbox on (`WEBKIT_FORCE_SANDBOX=1`).
    Enable,
    /// Touch nothing: the user configured it themselves, or Flatpak/Snap already confine the app.
    LeaveAlone,
    /// The sandbox cannot work here. Keep it off (and say so) instead of showing a blank window.
    Disable(String),
}

/// Decide, without touching the environment, what to do about the sandbox. `bwrap_problem` is only
/// called when it matters (it starts a process), and returns why bubblewrap cannot work, if it can't.
#[cfg(target_os = "linux")]
fn decide_webkit_sandbox(
    user_configured: bool,
    confined_by_packaging: bool,
    appimage: bool,
    bwrap_problem: impl FnOnce() -> Option<String>,
) -> WebkitSandbox {
    if user_configured || confined_by_packaging {
        return WebkitSandbox::LeaveAlone;
    }
    if appimage {
        // An AppImage lives on a FUSE mount that is not visible inside a bubblewrap sandbox.
        return WebkitSandbox::Disable("running from an AppImage".into());
    }
    match bwrap_problem() {
        Some(why) => WebkitSandbox::Disable(why),
        None => WebkitSandbox::Enable,
    }
}

/// `None` if `bwrap` can build the same kind of sandbox WebKit asks for (fresh user, pid, uts, ipc and
/// net namespaces over a read-only view of `/`, with a private /dev and /proc); otherwise why it can't.
/// Typical reasons: bubblewrap is not installed, or the OS forbids unprivileged user namespaces.
#[cfg(target_os = "linux")]
fn bubblewrap_problem() -> Option<String> {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut child = match Command::new("bwrap")
        .args([
            "--unshare-user", "--unshare-pid", "--unshare-uts", "--unshare-ipc", "--unshare-net",
            "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "true",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Some(format!("cannot run `bwrap`: {e}")),
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return None,
            Ok(Some(_)) => {
                let mut msg = String::new();
                if let Some(mut err) = child.stderr.take() {
                    use std::io::Read;
                    let _ = err.read_to_string(&mut msg);
                }
                return Some(format!("`bwrap` failed: {}", msg.trim()));
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Some("`bwrap` did not finish in time".into());
            }
            Err(e) => return Some(format!("cannot wait for `bwrap`: {e}")),
        }
    }
}

/// WebKitGTK can run its web process inside a bubblewrap sandbox, but it does so only when asked:
/// neither Tauri nor wry ask, so by default the web process runs with the user's full privileges.
/// That process renders whatever a remote server can put on screen (terminal output, file names,
/// Docker logs), so if it ever gets a renderer exploit, the sandbox is what stops it from reading
/// `~/.ssh` and the rest of the user's files. This turns it on wherever it can work. Where it can't
/// (no usable `bwrap`, or an AppImage) it stays off and a warning says so on stderr, because forcing
/// it there would leave a blank window. Anyone who sets `WEBKIT_FORCE_SANDBOX` or
/// `WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS` themselves is left alone, and so are Flatpak and Snap
/// (they confine the app themselves). Returns the variable to set, if any.
#[cfg(target_os = "linux")]
fn webkit_sandbox_env() -> Option<(&'static str, &'static str)> {
    const DISABLE: &str = "WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS";
    const FORCE: &str = "WEBKIT_FORCE_SANDBOX";
    let decision = decide_webkit_sandbox(
        std::env::var_os(DISABLE).is_some() || std::env::var_os(FORCE).is_some(),
        std::env::var_os("FLATPAK_ID").is_some() || std::env::var_os("SNAP").is_some(),
        std::env::var_os("APPIMAGE").is_some(),
        bubblewrap_problem,
    );
    match decision {
        WebkitSandbox::Enable => Some((FORCE, "1")),
        WebkitSandbox::LeaveAlone => None,
        WebkitSandbox::Disable(why) => {
            eprintln!(
                "solanum: WebKit's sandbox cannot run here ({why}); continuing WITHOUT it. \
                 Install bubblewrap and allow user namespaces (or use the .deb/.rpm/Arch package instead of the AppImage) to get it."
            );
            // Already the default; stated explicitly so a WebKit that defaults it on can't leave a blank window.
            Some((DISABLE, "1"))
        }
    }
}

/// Argument keys that carry a frontend-made id which ends up in a file name
/// (`live_edit::session_dir_name`) or an event name (`terminal-output-{id}`, `docker-logs-{id}`, ...).
const IPC_ID_KEYS: &[&str] = &["sessionId", "terminalId", "streamId"];

/// True for an id the frontend may use as a session, terminal or log-stream id:
/// 1 to 120 ASCII letters, digits, `-`, `_` or `:` (120, so that `sftp_<hex>`
/// stays within the 255-byte name limit). That is a subset of what
/// Tauri accepts in event names (an emit to an invalid name fails silently) and
/// holds no path separator or `.`, so no id can climb out of a folder.
fn is_valid_ipc_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 120
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':'))
}

/// Refuse a command call whose session, terminal or stream id is malformed,
/// before the command runs. Absent and `null` ids are left to the command.
fn check_ipc_ids(args: &serde_json::Value) -> Result<(), String> {
    let Some(obj) = args.as_object() else { return Ok(()) };
    for key in IPC_ID_KEYS {
        if let Some(serde_json::Value::String(id)) = obj.get(*key) {
            if !is_valid_ipc_id(id) {
                return Err(format!("[IPC] INVALID_ID: {} must be 1-120 letters, digits, '-', '_' or ':'", key));
            }
        }
    }
    Ok(())
}

/// Wrap the generated command dispatcher so every call is checked by
/// `check_ipc_ids` first: one place covers every command that takes one of
/// those ids, including future ones. (`Invoke`'s fields are public but Tauri
/// documents the struct as not stable: if an upgrade breaks this, the build
/// fails here rather than the check silently disappearing.)
fn guard_ipc_ids<R: tauri::Runtime>(
    commands: impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static,
) -> impl Fn(tauri::ipc::Invoke<R>) -> bool + Send + Sync + 'static {
    move |invoke| {
        if let tauri::ipc::InvokeBody::Json(args) = invoke.message.payload() {
            if let Err(e) = check_ipc_ids(args) {
                invoke.resolver.reject(e);
                return true;
            }
        }
        commands(invoke)
    }
}

/// Library entrypoint shared by both the desktop `bin/main.rs` shim and
/// Tauri's Android entry-point macro. Everything that builds the
/// `tauri::Builder`, registers plugins/state/commands, and finally calls
/// `.run(generate_context!())` lives here so the same binary contents
/// ship on both platforms — only the wrapping is different.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // Linux: WebKit's GPU workarounds and sandbox switch must be in the
    // environment before GTK and WebKit's web process start, which read them
    // there. They are Solanum's own: every program it starts gets them
    // removed (`child_env`, F-014). Variables the user set are left alone.
    #[cfg(target_os = "linux")]
    {
        let mut vars = child_env::graphics_workarounds(|name| std::env::var_os(name));
        vars.extend(webkit_sandbox_env());
        child_env::set_for_app_only(&vars);
    }

    let builder = tauri::Builder::default();
    // Save/restore the main window's last size + position to a JSON file
    // in app_data_dir. Keeps the user's preferred geometry across launches
    // without us having to wire setSize/setPosition by hand. Plain plugin —
    // it intercepts window events; no JS-facing commands to lock down.
    // Mobile builds skip this entirely: Android decides window geometry,
    // not us, and the plugin's crate isn't compiled into the Android target.
    #[cfg(not(target_os = "android"))]
    let builder = builder.plugin(tauri_plugin_window_state::Builder::default().build());
    // Cross-platform URL opener — Android (Intent.ACTION_VIEW), Windows
    // (start), macOS (open), Linux (xdg-open). about.rs's open_external_url
    // dispatches through this so the same code path works in the desktop
    // installer AND the Android APK. Capability is granted in default.json.
    let builder = builder.plugin(tauri_plugin_opener::init());
    // Real OS clipboard access for terminal copy/paste — see the dependency
    // comment in Cargo.toml for why navigator.clipboard alone isn't enough.
    // Cross-platform like opener above; capability granted in default.json.
    let builder = builder.plugin(tauri_plugin_clipboard_manager::init());
    // Android: the Kotlin side (the keep-alive service), see `android`.
    #[cfg(target_os = "android")]
    let builder = builder.plugin(android::plugin());
    let ssh_state = SshState::new();
    // Live-edit staging folders left by earlier runs that quit without
    // cleaning up (crash, kill): swept on a thread of its own (F-061).
    #[cfg(not(target_os = "android"))]
    {
        let edits = Arc::clone(&ssh_state.live_edits);
        std::thread::spawn(move || edits.sweep_at_start());
    }
    builder
        .manage(DbState::default())
        .manage(ssh_state)
        // Monitoring state is its own root-level Tauri-managed value, separate
        // from SshState — monitors and interactive sessions own different SSH
        // handles per node and don't share lifecycle.
        .manage::<MonitorMap>(std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())))
        // Mirror tasks live under their own root-managed map — keyed by mirror
        // id, populated by `start_mirror`, drained by the spawned worker on
        // exit. Session teardown calls `mirror::stop_all_for_session` to make
        // sure no orphan watcher is left running after the SSH handle dies.
        .manage::<MirrorMap>(std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())))
        // Global monitor settings live in one shared Arc<Mutex>. Pollers
        // read it at the start of every cycle so interval/threshold changes
        // are hot-applied without restarting any monitor.
        .manage::<SharedSettings>(std::sync::Arc::new(tokio::sync::Mutex::new(monitor::MonitorSettings::default())))
        .invoke_handler(guard_ipc_ids(tauri::generate_handler![
            setup_master_db, persist_vault,
            list_profiles, select_profile, create_profile, delete_profile, close_profile,
            export_profile, import_profile_pick, import_profile_save,
            save_server, save_quick_connect_node, delete_server, add_mirror_to_server, get_servers, get_ssh_keys, set_server_pinned, set_folder_pinned, set_server_notes, set_server_terminal_only, reorder_servers, clone_server, reveal_server_password, reveal_credential_password, reveal_ssh_key,
            get_credentials, generate_ssh_key,
            add_folder, rename_folder, delete_folder, get_folders,
            add_command, edit_command, delete_command, get_commands,
            add_snippet, edit_snippet, delete_snippet, get_snippets,
            cmd_history_add, cmd_history_list, cmd_history_clear,
            add_note, edit_note, delete_note, get_notes,
            mirror_dry_run, start_mirror, stop_mirror, resume_mirror, list_mirrors, pick_local_directory,
            add_credential, edit_credential, delete_credential,
            add_ssh_key, edit_ssh_key, delete_ssh_key, pick_key_file,
            initiate_connection, verify_fingerprint_response, submit_kbi_response, disconnect_session,
            start_tunnel, stop_tunnel, list_tunnels, restart_session_tunnels, persist_session_tunnels,
            open_terminal, write_terminal_data, ack_terminal_output, resize_terminal, close_terminal,
            read_clipboard_text, save_terminal_text,
            ssh_info_probe_section, ssh_info_live_sample, ssh_systemctl_action, ssh_kill_process,
            ssh_iptables_chain, ssh_nft_chain,
            docker::ssh_docker_container_action,
            docker::ssh_docker_inspect,
            docker::ssh_docker_stats,
            docker::ssh_docker_logs,
            docker::ssh_docker_logs_start,
            docker::ssh_docker_logs_stop,
            docker::ssh_docker_networks,
            docker::ssh_docker_containers,
            docker::ssh_docker_images_list,
            docker::ssh_docker_volumes_list,
            docker::ssh_docker_compose_per_container,
            docker::ssh_docker_compose_view,
            docker::ssh_docker_prune,
            docker::ssh_docker_prune_preview,
            docker::open_container_terminal,
            local_shell::list_local_shells,
            local_shell::open_local_terminal,
            select_local_folder, select_local_files, local_path_is_dir, local_list_dir,
            local_home_dir, local_desktop_dir, local_create_dir, local_remove, local_rename,
            android_quick_dirs, android_default_local_dir, android::android_keep_alive,
            android::android_screen_privacy, android::android_set_screen_privacy,
            parse_ssh_config,
            parse_client_import,
            sftp_list_dir, sftp_create_dir, sftp_remove_file, sftp_remove_dir,
            sftp_rename, sftp_set_permissions, sftp_set_owner,
            sftp_download_file, sftp_download_dir, sftp_upload_file, sftp_upload_dir, sftp_cancel_transfer, sftp_open_remote_file,
            local_open_file, local_open_in_explorer, live_edit_leftovers, live_edit_list, live_edit_stop,
            monitor_list, monitor_add, monitor_remove, monitor_set_metrics, monitor_set_custom_metrics,
            monitor_resume, monitor_pause, monitor_resume_all, monitor_pause_all,
            monitor_get_settings, monitor_set_settings,
            about::app_info, about::check_for_updates, about::open_external_url
        ]))
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                shut_down(app);
                // N-035: never let tao's `exit` leave a half torn-down process
                // for the next start to land in.
                #[cfg(target_os = "android")]
                android::end_process_after_shutdown();
            }
        });
}

/// Quitting may take this long; the vault is saved first, so the budget never
/// costs unsaved data.
const EXIT_TEARDOWN_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// The app is quitting (its last window closed, or Cmd+Q): the same teardown
/// as locking (the vault saved, everything stopped), then the live edits'
/// final checks are awaited, so copies in sync are deleted before the process
/// ends (F-013, F-061). Bounded so that quitting never hangs. A process the
/// OS kills gets none of this; the next start's sweep cleans its files.
fn shut_down(app: &tauri::AppHandle) {
    let db = app.state::<DbState>();
    let ssh = app.state::<SshState>();
    let monitors = app.state::<MonitorMap>();
    let mirrors = app.state::<MirrorMap>();
    let settings = app.state::<SharedSettings>();
    let finished = tauri::async_runtime::block_on(async {
        let work = async {
            let finishing = teardown_profile(
                db.inner(),
                ssh.inner(),
                monitors.inner(),
                mirrors.inner(),
                settings.inner(),
                live_edit::StopReason::AppClosed,
            )
            .await;
            for task in finishing {
                let _ = task.await;
            }
        };
        tokio::time::timeout(EXIT_TEARDOWN_BUDGET, work).await.is_ok()
    });
    // The key is wiped even if the budget ran out before the teardown's end.
    clear_profile_state(db.inner());
    // Only once the live edits' final checks are done; otherwise the lock is
    // held until the process ends and the next start sweeps the root.
    if finished {
        ssh.live_edits.release_root();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F-078: russh's `UnknownKey` is our own host-key check saying no, not
    /// an algorithm mismatch.
    #[test]
    fn a_refused_host_key_is_reported_as_a_host_key_problem() {
        assert_eq!(classify_russh_error(&russh::Error::UnknownKey), ConnectErrorKind::HostKey);
        assert_eq!(classify_russh_error(&russh::Error::WrongServerSig), ConnectErrorKind::HostKey);
        assert_eq!(classify_russh_error(&russh::Error::UnknownAlgo), ConnectErrorKind::Algorithm);
    }

    /// F-030: auto-reconnect retries only what the network may fix by itself.
    #[test]
    fn only_network_failures_are_retried() {
        use ConnectErrorKind::*;
        for kind in [Transport, Timeout, Unreachable, Unknown] {
            assert!(kind.retry(), "{kind:?}");
        }
        for kind in [Auth, HostKey, Algorithm, Config] {
            assert!(!kind.retry(), "{kind:?}");
        }
        assert!(Auth.is_auth() && !HostKey.is_auth() && !Config.is_auth());
    }

    #[test]
    fn ids_the_frontend_builds_pass_and_anything_else_is_refused_before_dispatch() {
        // Every id shape the frontend makes today (DesktopApp, SessionView, DockerTab).
        for ok in ["session-12", "session-quick-1696500000000", "session-local-1696500000000",
                   "session-12::sftp", "session-12::fwd", "session-12-term-1696500000000",
                   "session-12-term-0", "session-12-logs-1696500000000-k3j9x2"] {
            assert!(is_valid_ipc_id(ok), "{ok}");
            assert!(check_ipc_ids(&json!({ "sessionId": ok, "terminalId": ok, "streamId": ok })).is_ok());
        }
        let long = "a".repeat(121);
        assert!(is_valid_ipc_id(&"a".repeat(120)));
        for bad in ["", "..", "../../x", "a/b", "a\\b", "web.app", "s p", "caf\u{e9}", "x\u{202E}", long.as_str()] {
            assert!(!is_valid_ipc_id(bad), "{bad:?}");
            for key in IPC_ID_KEYS {
                let err = check_ipc_ids(&json!({ *key: bad })).unwrap_err();
                assert!(err.contains("INVALID_ID") && err.contains(key), "{err}");
            }
        }
        // Absent, null and non-id keys are the command's business.
        assert!(check_ipc_ids(&json!({ "sessionId": null, "path": "../x", "tunnelId": "a/b" })).is_ok());
        assert!(check_ipc_ids(&json!(null)).is_ok());
    }

    /// The app ACL (`permissions/ui-commands.toml`, granted in
    /// `capabilities/default.json`) must let the window call every registered
    /// command except the ones no screen uses yet, nothing else, and nothing
    /// from a remote origin. Checked against the ACL Tauri builds for the app.
    #[test]
    fn ui_commands_permission_grants_exactly_the_registered_commands() {
        const NOT_CALLED_YET: &[&str] = &[];
        let mut ctx: tauri::Context<tauri::Wry> = tauri::generate_context!();
        let acl = ctx.runtime_authority_mut();
        let local = tauri::ipc::Origin::Local;
        let remote = tauri::ipc::Origin::Remote { url: "https://example.com/".parse().unwrap() };

        let src = include_str!("lib.rs");
        let start = src.find("tauri::generate_handler![").unwrap() + "tauri::generate_handler![".len();
        let list = &src[start..start + src[start..].find(']').unwrap()];
        let registered: Vec<&str> = list
            .split(',')
            .map(|s| s.trim().rsplit("::").next().unwrap())
            .filter(|s| !s.is_empty())
            .collect();
        assert!(registered.len() > 100, "{registered:?}");
        for name in &registered {
            let allowed = acl.resolve_access(name, "main", "main", &local).is_some();
            assert_eq!(allowed, !NOT_CALLED_YET.contains(name), "{name}");
            assert!(acl.resolve_access(name, "main", "main", &remote).is_none(), "{name} from a remote origin");
        }
        assert!(acl.resolve_access("no_such_command", "main", "main", &local).is_none());
    }

    #[test]
    fn the_clipboard_is_read_only_while_the_window_has_the_focus() {
        assert!(clipboard_read_allowed::<()>(Ok(true)));
        assert!(!clipboard_read_allowed::<()>(Ok(false)));
        // A platform that cannot report focus must not break paste.
        assert!(clipboard_read_allowed(Err("unsupported")));
    }

    #[test]
    fn a_recursive_delete_starts_only_below_the_root() {
        for bad in ["/", "//", "", "relative", "x/y", "/.", "/x/..", "/x/./y", "/x//y", "/../etc"] {
            assert!(deletable_remote_folder(bad).is_err(), "{bad:?}");
        }
        assert_eq!(deletable_remote_folder("/srv/www/old/").unwrap(), "/srv/www/old");
        assert_eq!(deletable_remote_folder("/tmp/x").unwrap(), "/tmp/x");
    }

    #[test]
    fn mode_and_owner_changes_send_only_what_changes() {
        let m = mode_change(0o102755);
        assert_eq!(m.permissions, Some(0o2755), "the setgid bit is kept, the type bits are not sent");
        assert!(m.size.is_none() && m.uid.is_none() && m.gid.is_none() && m.atime.is_none() && m.mtime.is_none());

        let current = russh_sftp::protocol::FileAttributes {
            size: Some(4096),
            uid: Some(1000),
            gid: Some(33),
            permissions: Some(0o100644),
            mtime: Some(2),
            ..Default::default()
        };
        let o = owner_change(Some(0), None, Some(&current)).unwrap();
        assert_eq!((o.uid, o.gid), (Some(0), Some(33)), "the group stays what it was");
        assert!(o.size.is_none() && o.permissions.is_none() && o.atime.is_none() && o.mtime.is_none());
        let o = owner_change(None, Some(100), Some(&current)).unwrap();
        assert_eq!((o.uid, o.gid), (Some(1000), Some(100)));

        // A group the server did not report never becomes 0 (root).
        let unknown_group = russh_sftp::protocol::FileAttributes { uid: Some(1000), ..Default::default() };
        assert!(owner_change(Some(33), None, Some(&unknown_group)).is_err());
        assert!(owner_change(None, None, Some(&current)).is_err());
        assert!(owner_change(Some(1), Some(2), None).is_ok());
    }

    #[test]
    fn a_rename_destination_must_be_absolute() {
        for relative in ["sub/dir/file", "file", "./x", "../x"] {
            assert!(remote_parent_chain(relative).is_err(), "{relative}");
        }
        assert_eq!(remote_parent_chain("/srv/www/new/index.html").unwrap(), ["/srv", "/srv/www", "/srv/www/new"]);
        assert_eq!(remote_parent_chain("/top.txt").unwrap(), Vec::<String>::new());
        assert_eq!(remote_parent_chain("/a/b/").unwrap(), ["/a"]);
        // A backslash is part of a POSIX name, not a separator.
        assert_eq!(remote_parent_chain("/a\\b/c").unwrap(), ["/a\\b"]);
    }

    #[test]
    fn a_session_id_can_only_name_one_folder_directly_in_the_staging_root() {
        for id in ["../../x", "..", "a/b", "a\\b", "session-1::sftp", "session-1"] {
            let name = live_edit::session_dir_name(id);
            assert!(name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'), "{id}: {name}");
        }
        assert_ne!(live_edit::session_dir_name("a"), live_edit::session_dir_name("b"));
        // The longest id the check allows still makes a legal folder name.
        let longest = "a".repeat(120);
        assert!(is_valid_ipc_id(&longest));
        assert!(live_edit::session_dir_name(&longest).len() <= 255);
    }

    #[test]
    fn ports_outside_1_to_65535_are_refused_instead_of_truncated() {
        for bad in [0, -1, -22, 65536, 70022, i32::MAX, i32::MIN] {
            let err = checked_port(bad, "Port").unwrap_err();
            assert!(err.contains("between 1 and 65535"), "{bad}: {err}");
        }
        for ok in [1, 22, 2222, 65535] {
            assert_eq!(checked_port(ok, "Port").unwrap(), ok as u16);
        }
        // A proxy port matters only when a proxy is in use.
        assert!(checked_proxy_port("socks5", 70000).is_err());
        assert!(checked_proxy_port("http", 0).is_err());
        assert_eq!(checked_proxy_port("http", 3128).unwrap(), 3128);
        assert_eq!(checked_proxy_port("none", -5).unwrap(), 1080);
        assert_eq!(checked_proxy_port("none", 8080).unwrap(), 8080);
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn the_ssh_config_reader_takes_only_a_small_regular_file() {
        let dir = std::env::temp_dir().join(format!("solanum-import-test-{:016x}", rand::thread_rng().gen::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config");
        fs::write(&config, "Host web\n  HostName 192.0.2.10\n  Port 2222\n  User deploy\nHost *\n  User x\n").unwrap();
        let hosts = parse_ssh_config_text(&read_small_text_file(&config, MAX_IMPORT_BYTES).unwrap());
        assert_eq!(hosts.len(), 1);
        assert_eq!((hosts[0].hostname.as_str(), hosts[0].port, hosts[0].user.as_str()), ("192.0.2.10", 2222, "deploy"));

        let big = dir.join("big");
        fs::write(&big, vec![b'#'; MAX_IMPORT_BYTES as usize + 1]).unwrap();
        let reasons = [
            read_small_text_file(&big, MAX_IMPORT_BYTES).unwrap_err(),
            read_small_text_file(&dir, MAX_IMPORT_BYTES).unwrap_err(),
            read_small_text_file(&dir.join("missing"), MAX_IMPORT_BYTES).unwrap_err(),
        ];
        assert!(reasons[0].contains("larger than"), "{}", reasons[0]);
        assert!(reasons[1].contains("not a regular file"), "{}", reasons[1]);
        assert!(reasons[2].contains("no such file"), "{}", reasons[2]);
        for r in &reasons {
            assert!(!r.contains(dir.to_str().unwrap()), "the reason must not echo the path: {r}");
        }
        // A FIFO is refused before it is opened (opening one would block).
        #[cfg(unix)]
        if std::process::Command::new("mkfifo").arg(dir.join("fifo")).status().map(|s| s.success()).unwrap_or(false) {
            assert!(read_small_text_file(&dir.join("fifo"), MAX_IMPORT_BYTES).unwrap_err().contains("not a regular file"));
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn a_pasted_import_is_capped_and_parsed_off_the_main_thread() {
        let err = parse_client_import("[".repeat(MAX_IMPORT_BYTES as usize + 1)).await.err().expect("refused");
        assert!(err.contains("larger than"), "{err}");
        let hosts = parse_client_import(r#"[{"name":"db","host":"192.0.2.5","port":2200,"user":"admin"}]"#.into()).await.unwrap();
        assert_eq!((hosts[0].hostname.as_str(), hosts[0].port), ("192.0.2.5", 2200));
    }

    #[test]
    fn putty_ppk_files_pass_validation_same_as_openssh_and_pem() {
        // The validator only gates on the header; full parsing (including any
        // passphrase) happens at connect time via russh's ssh-key::from_ppk.
        assert!(validate_ssh_private_key("PuTTY-User-Key-File-3: ssh-ed25519\n...").is_ok());
        assert!(validate_ssh_private_key("   PuTTY-User-Key-File-2: ssh-rsa\n...").is_ok());
    }

    #[test]
    fn unrecognized_key_text_is_rejected_with_a_helpful_message() {
        let err = validate_ssh_private_key("not a key at all").unwrap_err();
        assert!(err.contains("UNRECOGNIZED_KEY_FORMAT"), "{err}");
        assert!(err.contains("ppk"), "error should mention ppk as an accepted format: {err}");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod webkit_sandbox_tests {
    use super::*;

    #[test]
    fn the_sandbox_is_turned_on_when_bubblewrap_works() {
        assert_eq!(decide_webkit_sandbox(false, false, false, || None), WebkitSandbox::Enable);
    }

    #[test]
    fn it_stays_off_only_where_the_sandbox_cannot_run() {
        assert_eq!(
            decide_webkit_sandbox(false, false, false, || Some("no user namespaces".into())),
            WebkitSandbox::Disable("no user namespaces".into())
        );
        assert!(matches!(decide_webkit_sandbox(false, false, true, || None), WebkitSandbox::Disable(_)), "AppImage");
    }

    #[test]
    fn a_setting_made_by_the_user_or_the_packaging_is_left_alone_and_nothing_is_probed() {
        for (user, confined) in [(true, false), (false, true), (true, true)] {
            let decision = decide_webkit_sandbox(user, confined, true, || panic!("must not start bwrap"));
            assert_eq!(decision, WebkitSandbox::LeaveAlone);
        }
    }
}

#[cfg(test)]
mod private_file_tests {
    use super::*;

    fn scratch_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("solanum-private-test-{:016x}", rand::thread_rng().gen::<u64>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    fn mode(p: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn a_saved_vault_is_private_to_its_owner_even_over_older_wider_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir();
        let vault = dir.join("p.solanum");
        let tmp = dir.join("p.solanum.tmp");
        for f in [&vault, &tmp] {
            fs::write(f, b"left by an older build").unwrap();
            fs::set_permissions(f, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let mut conn = open_vault_memory_db().unwrap();
        create_vault_schema(&conn).unwrap();
        save_vault_blocking(&mut conn, &test_open_vault(&vault, [9u8; 32])).unwrap();
        assert_eq!(mode(&vault), 0o600, "the vault must be owner-only");
        // Saves write to a fresh random temp name; the old fixed name is not reused
        // (it is swept when the profile is next opened, see profile_lock_tests).
        assert_eq!(fs::read(&tmp).unwrap(), b"left by an older build");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn importing_never_overwrites_an_existing_profile() {
        let dir = scratch_dir();
        let dst = dir.join("work.solanum");
        write_new_profile_file(&dst, b"first", "work").unwrap();
        let err = write_new_profile_file(&dst, b"second", "work").unwrap_err();
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(fs::read(&dst).unwrap(), b"first", "the existing profile must be untouched");
        #[cfg(unix)]
        assert_eq!(mode(&dst), 0o600);
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn importing_does_not_follow_a_symlink_planted_at_the_destination() {
        let dir = scratch_dir();
        let victim = dir.join("victim.txt");
        fs::write(&victim, b"keep me").unwrap();
        let dst = dir.join("evil.solanum");
        std::os::unix::fs::symlink(&victim, &dst).unwrap();
        assert!(write_new_profile_file(&dst, b"overwrite attempt", "evil").is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"keep me");
        let _ = fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod info_command_tests {
    use super::*;

    /// F-096: the unit reaches systemctl as one word after `--`.
    #[test]
    fn a_unit_name_reaches_systemctl_unchanged() {
        assert_eq!(
            systemctl_command("restart", r"systemd-fsck@dev-disk-by\x2duuid-1.service", false),
            r"systemctl restart -- 'systemd-fsck@dev-disk-by\x2duuid-1.service' 2>&1; echo __SUB_EXITCODE:$?"
        );
        assert_eq!(systemctl_command("status", "-.mount", true), "sudo -n systemctl status -- '-.mount' 2>&1; echo __SUB_EXITCODE:$?");
    }

    /// F-096: firewall identifiers that would be read as options are refused.
    #[test]
    fn firewall_identifiers_that_look_like_options_are_refused() {
        for ok in ["INPUT", "DOCKER-USER", "ufw-before-input", "f2b-sshd", "_tbl", "chain.1@x"] {
            assert!(is_safe_fw_ident(ok), "{ok}");
        }
        for bad in ["-F", "--flush", ".x", "a b", "a;b", ""] {
            assert!(!is_safe_fw_ident(bad), "{bad}");
        }
    }

    /// F-039: a session's Info probes open at most two channels at a time; a
    /// probe that finds no slot within its time says so instead of piling up.
    #[tokio::test]
    async fn at_most_two_info_probes_run_at_once() {
        // The server keeps every exec channel open: a slow or stuck probe.
        let (handle, seen) = ssh_test_server::logged_in(ssh_test_server::Script::default()).await;
        let probes = Arc::new(InfoProbes::new());
        // Two probes that hold their slot for 3 s, then two that may wait 1 s:
        // the deadlines never meet, so the outcome does not depend on timing.
        let spawn = |secs: u64| {
            let (probes, handle) = (Arc::clone(&probes), Arc::clone(&handle));
            tokio::spawn(async move { probes.run(&handle, &Default::default(), "sleep 60", secs).await })
        };
        let mut tasks = vec![spawn(3), spawn(3)];
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        tasks.extend([spawn(1), spawn(1)]);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(seen.lock().unwrap().session_opens, 2, "two channels at a time");
        let mut busy = 0;
        for task in tasks {
            if task.await.unwrap().err().is_some_and(|e| e.contains("other probes")) {
                busy += 1;
            }
        }
        assert_eq!(busy, 2, "the other two found no slot within their time");
        assert_eq!(seen.lock().unwrap().session_opens, 2);
    }
}
