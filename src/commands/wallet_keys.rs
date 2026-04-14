use std::ffi::OsStr;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Per-wallet `flock(2)` advisory locking for the `wallet create` path.
///
/// Two simultaneous `btt wallet create --force --name foo` invocations
/// from different processes could interleave the backup-and-rename
/// sequence in [`promote_staged_into_existing`] and lose the user's
/// wallet (see issue #41 for the full race analysis). The fix is a
/// per-wallet-name lock file at `<wallets>/.lock.<name>` held under
/// `flock(LOCK_EX)` for the duration of `create`, so concurrent creates
/// on the same name serialize while creates on different names remain
/// independent.
///
/// We declare `flock` directly via an `extern "C"` block rather than
/// pulling `libc`, `nix`, or `fs2` as a new dependency — see PR #21 for
/// the dep-discipline rationale. `flock(2)`, `LOCK_EX`, and `LOCK_UN`
/// are POSIX and their ABI has been stable on linux, macOS, and BSDs
/// for decades; a one-symbol FFI declaration is safer and smaller than
/// the blast radius of a new transitive crate.
#[cfg(unix)]
mod flock_sys {
    use std::fs::File;
    use std::io;
    use std::os::unix::io::AsRawFd;

    // POSIX advisory lock constants from <sys/file.h>. Stable ABI on
    // linux, macOS, and BSDs — these values have not changed in 30+
    // years. We declare `flock()` directly to avoid pulling `libc` as
    // a new dep; see PR #21.
    extern "C" {
        fn flock(fd: i32, op: i32) -> i32;
    }
    const LOCK_EX: i32 = 2;
    const LOCK_UN: i32 = 8;

    /// Owns a [`File`] handle with a `LOCK_EX` advisory lock held on
    /// its file descriptor. The lock is released on drop — explicitly
    /// via `LOCK_UN` for clarity, and implicitly by `close(2)` when
    /// `File` drops immediately afterwards (a redundancy that is also
    /// a safety net if the explicit call ever fails).
    pub struct LockGuard {
        // Kept alive until drop. The file is never read or written —
        // it exists only as a stable fd to carry the flock.
        _file: File,
    }

    impl LockGuard {
        /// Acquire `LOCK_EX` on `file`'s descriptor. Blocks until the
        /// lock is available. Returns an I/O error if the syscall
        /// fails.
        pub fn acquire(file: File) -> io::Result<LockGuard> {
            let fd = file.as_raw_fd();
            // SAFETY: `fd` is a valid, open file descriptor owned by
            // `file` for the duration of this call. `flock` with
            // `LOCK_EX` has no memory-safety preconditions beyond a
            // valid fd, and we check the return value.
            let rc = unsafe { flock(fd, LOCK_EX) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(LockGuard { _file: file })
        }
    }

    impl Drop for LockGuard {
        fn drop(&mut self) {
            let fd = self._file.as_raw_fd();
            // SAFETY: `fd` is still a valid fd (the `File` has not
            // been dropped yet; it drops immediately after this call
            // returns). `flock` with `LOCK_UN` has no memory-safety
            // preconditions. We ignore the return value — `close(2)`
            // on the file in the `File` drop will release the lock
            // regardless.
            let _ = unsafe { flock(fd, LOCK_UN) };
        }
    }
}

#[cfg(not(unix))]
mod flock_sys {
    use std::fs::File;
    use std::io;

    /// Windows stub: we do not currently implement file locking on
    /// windows. Concurrent `wallet create --force` on windows is
    /// undefined behavior; the race documented in issue #41 is left
    /// unaddressed pending a follow-up that uses `LockFileEx` on the
    /// same sentinel file. Linux/macOS are the primary btt targets.
    pub struct LockGuard;
    impl LockGuard {
        pub fn acquire(_file: File) -> io::Result<LockGuard> {
            Ok(LockGuard)
        }
    }
}

use serde::{Deserialize, Serialize};
use sp_core::crypto::{Pair as TraitPair, Ss58Codec};
use sp_core::sr25519::{Pair, Public, Signature};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::commands::paths;
use crate::error::BttError;

/// One TAO equals 1e9 RAO.
pub const RAO_PER_TAO: u64 = 1_000_000_000;

/// Convert a TAO amount (floating point) to RAO (integer).
/// Returns an error if the amount is negative, NaN, infinite, or overflows u64.
pub fn tao_to_rao(tao: f64) -> Result<u64, BttError> {
    if tao.is_nan() || tao.is_infinite() {
        return Err(BttError::invalid_amount("amount must be a finite number"));
    }
    if tao < 0.0 {
        return Err(BttError::invalid_amount("amount must be non-negative"));
    }
    let rao_f64 = tao * RAO_PER_TAO as f64;
    if rao_f64 > u64::MAX as f64 {
        return Err(BttError::invalid_amount("amount overflows u64 in RAO"));
    }
    Ok(rao_f64 as u64)
}

/// Convert RAO to a human-readable TAO string with up to 9 decimal places.
/// Trailing zeros are trimmed but at least one decimal place is kept.
pub fn rao_to_tao_string(rao: u64) -> String {
    let whole = rao / RAO_PER_TAO;
    let frac = rao % RAO_PER_TAO;
    if frac == 0 {
        format!("{whole}.0")
    } else {
        let raw = format!("{whole}.{frac:09}");
        let trimmed = raw.trim_end_matches('0');
        trimmed.to_string()
    }
}

/// Resolve a coldkey SS58 address from a wallet name.
/// Reads `<config_dir>/wallets/<name>/coldkeypub.txt` — see
/// [`crate::commands::paths::config_dir`] for the per-OS location.
pub fn resolve_coldkey_address(wallet_name: &str) -> Result<String, BttError> {
    let wdir = wallet_path(wallet_name)?;
    if !wdir.exists() {
        return Err(BttError::wallet_not_found(format!(
            "wallet '{wallet_name}' not found at {}",
            wdir.display()
        )));
    }
    let pubkey_path = wdir.join("coldkeypub.txt");

    if !pubkey_path.exists() {
        return Err(BttError::wallet_not_found(format!(
            "coldkeypub.txt not found for wallet '{wallet_name}'"
        )));
    }

    let content = fs::read_to_string(&pubkey_path)
        .map_err(|e| BttError::io(format!("failed to read coldkeypub.txt: {e}")))?;

    extract_ss58_from_content(&content).ok_or_else(|| {
        BttError::parse(format!(
            "could not extract SS58 address from coldkeypub.txt for wallet '{wallet_name}'"
        ))
    })
}

/// Decrypt the coldkey for a wallet and return an sr25519 keypair.
/// Uses the existing load_coldkey infrastructure; prompts for password.
pub fn decrypt_coldkey_interactive(wallet_name: &str) -> Result<Pair, BttError> {
    let wdir = wallet_path(wallet_name)?;
    if !wdir.exists() {
        return Err(BttError::wallet_not_found(format!(
            "wallet '{wallet_name}' not found at {}",
            wdir.display()
        )));
    }

    let coldkey_path = wdir.join("coldkey");
    if !coldkey_path.exists() {
        return Err(BttError::wallet_not_found(format!(
            "coldkey file not found for wallet '{wallet_name}'"
        )));
    }

    // Every btt-produced coldkey on disk is a binary `$NACL` envelope written
    // by `encrypt_key_data` + `write_secure_file`, so the older
    // "try unencrypted JSON first" branch cannot reach any real caller: the
    // UTF-8 check on a `$NACL` blob fails at the first non-ASCII byte of the
    // nonce. The dead branch was a leftover from a pre-encryption prototype
    // and is deleted per NEW-I1 of the PR #3 round-2 review (issue #9).
    // Testing keys that need an unencrypted round-trip go through the private
    // `load_coldkey` / `pair_from_key_json` helpers directly.
    let password = read_password("Enter coldkey password: ")?;
    let pair = load_coldkey(&wdir, &password)?;
    Ok(pair)
}

/// Extract an SS58 address from key file content.
fn extract_ss58_from_content(content: &str) -> Option<String> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(addr) = v.get("ss58Address").and_then(|v| v.as_str()) {
            return Some(addr.to_string());
        }
        if let Some(addr) = v.get("SS58Address").and_then(|v| v.as_str()) {
            return Some(addr.to_string());
        }
        if let Some(addr) = v.get("address").and_then(|v| v.as_str()) {
            return Some(addr.to_string());
        }
    }

    let trimmed = content.trim();
    if trimmed.starts_with('5') && trimmed.len() >= 47 && trimmed.len() <= 49 {
        return Some(trimmed.to_string());
    }

    None
}

// btcli / btwallet on-disk envelope for encrypted coldkeys.
//
// Format: b"$NACL" || nonce (24 bytes) || secretbox_ciphertext
//
// KDF: libsodium `pwhash::argon2i13::derive_key` with
//   OPSLIMIT_SENSITIVE = 8, MEMLIMIT_SENSITIVE = 512 MiB, salt = NACL_SALT.
// Mapped onto the RustCrypto `argon2` crate as
//   Algorithm = Argon2i, Version = V0x13, t_cost = 8, m_cost = 524288 KiB,
//   parallelism = 1, output = 32 bytes.
//
// Reference: opentensor/btwallet src/keyfile.rs (NACL_SALT, derive_key,
// encrypt_keyfile_data, decrypt_keyfile_data).
const NACL_SALT: &[u8; 16] = b"\x13q\x83\xdf\xf1Z\t\xbc\x9c\x90\xb5Q\x879\xe9\xb1";
const NACL_MAGIC: &[u8; 5] = b"$NACL";
const NACL_KEY_LEN: usize = 32;
const NACL_NONCE_LEN: usize = 24;
const ARGON2_T_COST: u32 = 8;
const ARGON2_M_COST_KIB: u32 = 524_288; // 512 MiB
const ARGON2_PARALLELISM: u32 = 1;

// ── Output types ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct CreateResult {
    pub wallet_name: String,
    pub coldkey_ss58: String,
    pub hotkey_ss58: String,
    pub mnemonic: String,
}

#[derive(Serialize)]
pub struct NewColdkeyResult {
    pub wallet_name: String,
    pub ss58_address: String,
    pub mnemonic: String,
}

#[derive(Serialize)]
pub struct NewHotkeyResult {
    pub wallet_name: String,
    pub hotkey_name: String,
    pub ss58_address: String,
    pub mnemonic: String,
}

#[derive(Serialize)]
pub struct RegenResult {
    pub wallet_name: String,
    pub ss58_address: String,
}

#[derive(Serialize)]
pub struct RegenHotkeyResult {
    pub wallet_name: String,
    pub hotkey_name: String,
    pub ss58_address: String,
}

#[derive(Serialize)]
pub struct SignResult {
    pub signature: String,
    pub public_key: String,
    pub ss58_address: String,
}

#[derive(Serialize)]
pub struct VerifyResult {
    pub valid: bool,
}

// ── Key file JSON format (btcli-compatible) ───────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyFileData {
    account_id: String,
    public_key: String,
    secret_phrase: String,
    secret_seed: String,
    ss58_address: String,
}

// ── Public key file format ────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PubKeyFileData {
    account_id: String,
    public_key: String,
    ss58_address: String,
}

// ── Load-path deserialization target ──────────────────────────────────────
//
// When decrypting a coldkey (or reading an unencrypted hotkey), the JSON
// blob is parsed into this struct instead of a free-form `serde_json::Value`.
// `Value` owns `String`s for every string node and does NOT scrub them on
// drop, so routing the decrypted material through it would leave the
// mnemonic and raw seed floating in freed heap chunks until reuse.
//
// `LoadedKeyFile` holds exactly the secret-bearing fields we consume and
// derives `Zeroize` + `ZeroizeOnDrop`, so every `String` byte is overwritten
// with zero before the allocation is returned to the allocator. Non-secret
// hint fields from the on-disk format (accountId, publicKey, ss58Address)
// are intentionally ignored — they carry no value the caller cannot
// rederive from the keypair itself, and omitting them keeps the zeroized
// footprint minimal.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop, Default)]
#[serde(rename_all = "camelCase")]
struct LoadedKeyFile {
    #[serde(default)]
    secret_phrase: Option<String>,
    #[serde(default)]
    secret_seed: Option<String>,
}

// ── Core operations ───────────────────────────────────────────────────────

/// Refuse to overwrite an existing key file unless `force` is set.
///
/// `label` is a short human-readable tag for the key type ("coldkey",
/// "hotkey") used both in the error message and the stderr warning. If
/// the file does not exist, this is a no-op. If it exists and `force` is
/// false, returns a `wallet_not_found`-adjacent `invalid_input` error
/// naming the file and instructing the caller to delete or pass
/// `--force`. If it exists and `force` is true, emits a one-line stderr
/// warning naming the file being destroyed and returns `Ok`. The actual
/// removal is performed atomically by `write_secure_file`.
fn guard_overwrite(path: &Path, label: &str, force: bool) -> Result<(), BttError> {
    if !path.exists() {
        return Ok(());
    }
    if !force {
        return Err(BttError::invalid_input(format!(
            "{label} file already exists at {}: refusing to overwrite. \
             Delete the file or pass --force to destroy and replace it.",
            path.display()
        )));
    }
    let _ = writeln!(
        std::io::stderr(),
        "btt: --force: destroying existing {label} at {}",
        path.display()
    );
    Ok(())
}

/// Refuse to overwrite an existing wallet from `wallet create` unless
/// `force` is set.
///
/// Semantically distinct from `guard_overwrite`: `wallet create` mints a
/// fresh mnemonic for both coldkey and hotkey, so a `--force` run destroys
/// the entire wallet (not just a single key file) without any way to
/// reconstruct it from the command's own inputs. The error is therefore
/// louder, names the wallet, and explicitly warns about irreversibility.
///
/// If neither file exists, this is a no-op. If either file exists and
/// `force` is false, returns an `invalid_input` error naming the wallet
/// and the offending path. If either exists and `force` is true, emits
/// one stderr warning per existing file and returns `Ok` — the actual
/// removal is performed atomically by `write_secure_file`.
fn guard_create_overwrite(
    wallet_name: &str,
    coldkey_path: &Path,
    hotkey_path: &Path,
    force: bool,
) -> Result<(), BttError> {
    let cold_exists = coldkey_path.exists();
    let hot_exists = hotkey_path.exists();
    if !cold_exists && !hot_exists {
        return Ok(());
    }
    if !force {
        // Report the coldkey path preferentially — it is the irreplaceable
        // half of the wallet. If only the hotkey exists, name it instead.
        let (label, path) = if cold_exists {
            ("coldkey", coldkey_path)
        } else {
            ("hotkey", hotkey_path)
        };
        return Err(BttError::invalid_input(format!(
            "refusing to overwrite existing wallet '{}' ({} at {}). \
             Pass --force to destroy the existing wallet and create a new one. \
             THIS IS IRREVERSIBLE — back up the existing mnemonic first if you have not.",
            wallet_name,
            label,
            path.display()
        )));
    }
    if cold_exists {
        let _ = writeln!(
            std::io::stderr(),
            "btt: --force: destroying existing coldkey at {}",
            coldkey_path.display()
        );
    }
    if hot_exists {
        let _ = writeln!(
            std::io::stderr(),
            "btt: --force: destroying existing hotkey at {}",
            hotkey_path.display()
        );
    }
    Ok(())
}

/// Create a new wallet with both coldkey and hotkey.
///
/// Refuses to run if either `<wallet>/coldkey` or
/// `<wallet>/hotkeys/<hotkey_name>` already exists, unless `force` is set.
/// The guard runs before any secret material is generated, so the refusal
/// path never touches the on-disk wallet and never leaves fresh secret
/// bytes on the heap.
///
/// Issue #19: prior to this guard, `write_secure_file` unlinked the target
/// before re-creating it, which defeated the `O_CREAT|O_EXCL` atomicity
/// and caused a second invocation of `wallet create --name <same>` to
/// silently destroy an irrecoverable wallet. See also PR #18 (issue #7)
/// for the same fix on `new-coldkey` / `new-hotkey` / `regen-*`.
///
/// Issue #29 (atomic creation): all three wallet artifacts (coldkey,
/// coldkeypub.txt, hotkey) are staged into a sibling temp directory
/// `<wallets>/.tmp.<name>.<pid>.<nanos>/` and then moved into place with
/// a single `fs::rename`. The rename is atomic on a single filesystem
/// (both paths live under `<wallets>/`), so the target `<wallets>/<name>`
/// directory is either absent or fully populated — never half-written.
/// On any error during staging, the temp dir is removed and the user's
/// wallet directory is never touched. The `.tmp.` prefix is excluded from
/// `wallet list`, so a stale temp dir from a crashed run remains visible
/// on disk (for forensics) without leaking into the user-facing listing.
pub fn create(
    wallet_name: &str,
    hotkey_name: &str,
    n_words: u32,
    password: &str,
    force: bool,
) -> Result<CreateResult, BttError> {
    // Reject wallet names starting with the reserved staging/backup/lock
    // prefixes. `.tmp.` is reserved for the sibling staging dir used by
    // the atomic create path, `.bak.` is reserved for the backup dir
    // used by `promote_staged_into_existing` on the `--force` path, and
    // `.lock.` is reserved for the per-wallet-name `flock(2)` sentinel
    // file used to serialize concurrent `--force` invocations (issue
    // #41). All three prefixes are silently filtered by `wallet list`
    // (see `wallet.rs`), so we refuse to create one at all. The check
    // runs before `validate_n_words` so a bad name fails fast without
    // any further work.
    if wallet_name.starts_with(".tmp.")
        || wallet_name.starts_with(".bak.")
        || wallet_name.starts_with(".lock.")
    {
        return Err(BttError::invalid_input(format!(
            "wallet name '{}' uses a reserved prefix (.tmp., .bak., or .lock.). \
             These prefixes are reserved for atomic-create staging, \
             force-overwrite backups, and per-wallet lock files; pick a \
             different name.",
            wallet_name
        )));
    }

    validate_n_words(n_words)?;

    // Per-wallet `flock(2)` to serialize concurrent `wallet create`
    // invocations on the same wallet name. Held for the full duration
    // of `create` — acquired BEFORE `guard_create_overwrite` so that
    // the check-then-write sequence in the force path is atomic with
    // respect to other btt processes on this host. See issue #41 for
    // the concrete interleaving this closes. The lock file lives at
    // `<wallets>/.lock.<name>`, is created 0600 if absent, and is
    // reused across runs (never auto-cleaned — issue #42 may decide
    // to reap stale lock files alongside `.tmp.*` / `.bak.*`).
    //
    // The lock granularity is per-wallet-name: two `create --name
    // alice` calls serialize, while `create --name alice` and
    // `create --name bob` run in parallel because they acquire
    // different lock files. Locking the whole `wallets/` directory
    // would be overly conservative.
    ensure_wallets_root()?;
    let lock_path = paths::wallets_dir()?.join(format!(".lock.{wallet_name}"));
    let mut lock_open = fs::OpenOptions::new();
    lock_open.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        lock_open.mode(0o600);
    }
    let lock_file = lock_open.open(&lock_path).map_err(|e| {
        BttError::io(format!(
            "failed to open wallet lock file {}: {}",
            lock_path.display(),
            e
        ))
    })?;
    let _lock = flock_sys::LockGuard::acquire(lock_file).map_err(|e| {
        BttError::io(format!(
            "failed to acquire flock on wallet lock file {}: {}",
            lock_path.display(),
            e
        ))
    })?;

    // Resolve paths and refuse overwrite BEFORE generating key material.
    // We check both the coldkey and the hotkey file: either one existing
    // indicates a wallet the user might lose. The error names the wallet
    // and the specific path, and explicitly warns about irreversibility —
    // wallet create generates a new mnemonic, so --force destroys the old
    // wallet entirely. See issue #19.
    let wallet_dir = wallet_path(wallet_name)?;
    let coldkey_path = wallet_dir.join("coldkey");
    let hotkey_path = wallet_dir.join("hotkeys").join(hotkey_name);
    guard_create_overwrite(wallet_name, &coldkey_path, &hotkey_path, force)?;

    // Stage into a sibling temp dir so the final rename is atomic.
    // The temp dir lives inside `<wallets>/` (same filesystem as the
    // target) and uses the `.tmp.` prefix reserved for staging. The
    // `<pid>.<nanos>` suffix keeps concurrent `create` invocations from
    // colliding in the same process and reduces the chance that a stale
    // temp dir from an earlier crashed run collides with a fresh one
    // after a PID wrap. Stale temp dirs are deliberately left on disk —
    // they're intended forensics, not to be auto-cleaned on startup.
    ensure_wallets_root()?;
    let wallets_root = paths::wallets_dir()?;
    let staging_dir = wallets_root.join(temp_staging_name(wallet_name));

    // Drive the staged writes through a helper so the `?` propagation is
    // funneled through a single cleanup point. On any error, remove the
    // staging dir and return the original error.
    let cr = match create_into_staging(
        wallet_name,
        hotkey_name,
        n_words,
        password,
        &staging_dir,
    ) {
        Ok(v) => v,
        Err(e) => {
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(e);
        }
    };

    // Publish. Two paths:
    //
    // 1. Target does not exist: `fs::rename` the staging dir into place.
    //    Single filesystem, so the rename is atomic at the kernel level —
    //    the target is either absent or fully populated.
    //
    // 2. Target already exists AND --force was passed (the only way
    //    this branch can be reached after `guard_create_overwrite`):
    //    run `promote_staged_into_existing`, which renames the old
    //    target to a sibling `.bak.*` dir, renames the staging dir into
    //    place, and then merges any unrelated hotkeys from the backup
    //    back into the new wallet. See the function doc for the exact
    //    algorithm and the crash window between the two renames.
    //
    // The `&& force` gate closes a MEDIUM bug from Round 1: without it,
    // a crash-leftover wallet dir containing only unrelated hotkeys
    // (no coldkey, no named hotkey) would pass `guard_create_overwrite`
    // — it guards on key-file existence, not directory existence — and
    // silently fall into the force path even though the user never
    // asked for it. The no-force branch now falls through to the plain
    // `fs::rename` below, which will refuse with `ENOTEMPTY` if the
    // target dir has any contents and succeed atomically if it is empty.
    if wallet_dir.exists() && force {
        if let Err(e) = promote_staged_into_existing(&staging_dir, &wallet_dir, hotkey_name) {
            // promote_staged_into_existing has already rolled back on
            // rename failure; staging_dir may or may not still exist
            // depending on where it failed. Best-effort cleanup.
            let _ = fs::remove_dir_all(&staging_dir);
            return Err(e);
        }
    } else if let Err(e) = fs::rename(&staging_dir, &wallet_dir) {
        let _ = fs::remove_dir_all(&staging_dir);
        return Err(BttError::io(format!(
            "failed to atomically publish wallet {} ({} -> {}): {}",
            wallet_name,
            staging_dir.display(),
            wallet_dir.display(),
            e
        )));
    }

    Ok(cr)
}

/// --force path: atomically replace the pre-existing `target_dir` with
/// the fully-staged `staging_dir`, then merge any unrelated hotkeys from
/// the old target back into the new one. This is the correct algorithm
/// for force-overwrite. The previous implementation moved three files
/// (`coldkey`, `coldkeypub.txt`, `hotkeys/<name>`) in sequence into the
/// existing target dir; if any step after the first failed, the coldkey
/// had already been replaced and could not be rolled back — i.e. exactly
/// the half-write regression that issue #29 was meant to eliminate,
/// shifted onto the force path.
///
/// The algorithm:
///
///   1. Rename the old target to a sibling `.bak.<basename>.<pid>.<nanos>`
///      directory. After this rename, `target_dir` does not exist on
///      disk; the old contents are fully preserved in the backup.
///
///   2. Rename the staging dir to `target_dir`. This is the atomic
///      publish point: on a single filesystem, `rename(2)` either
///      succeeds or fails with the target absent. If it fails, we roll
///      step 1 back by renaming the backup back into place and return
///      the original error — the user's wallet is untouched.
///
///   3. Merge unrelated hotkeys from `backup/hotkeys/` into
///      `target/hotkeys/`, skipping the just-published `hotkey_name`
///      (the fresh hotkey always wins). This preserves the pre-#29
///      force semantics that other hotkeys under `<wallet>/hotkeys/`
///      survive a `--force` run. The merge is best-effort from an
///      atomicity standpoint: if it fails partway, the new wallet is
///      fully present and the remaining unrelated hotkeys are still
///      reachable from the stale `.bak.*` dir on disk. We surface the
///      error so the user knows manual recovery may be needed.
///
///   4. Remove the now-drained backup dir. Best-effort cleanup — a stale
///      `.bak.*` remaining on disk is acceptable and visible for
///      forensics; `wallet list` filters it out.
///
/// Crash window: between steps 1 and 2 the target name is briefly
/// absent on disk, but the old contents live in the backup. A crash in
/// that window leaves `.bak.*` on disk for manual recovery. Between
/// steps 2 and 3, the new wallet is already live and the old unrelated
/// hotkeys are in the backup.
fn promote_staged_into_existing(
    staging_dir: &Path,
    target_dir: &Path,
    hotkey_name: &str,
) -> Result<(), BttError> {
    // Step 1: move the existing target aside to a sibling backup dir.
    // The backup lives in the same parent directory so it shares a
    // filesystem with `target_dir`, making the rename atomic. The
    // `.bak.` prefix is reserved (`wallet list` skips it, and `create`
    // refuses to create wallet names with this prefix).
    let backup_dir = backup_dir_for(target_dir).ok_or_else(|| {
        BttError::io(format!(
            "cannot derive backup dir for {}: no file name",
            target_dir.display()
        ))
    })?;
    fs::rename(target_dir, &backup_dir).map_err(|e| {
        BttError::io(format!(
            "failed to move existing wallet {} aside to {}: {}",
            target_dir.display(),
            backup_dir.display(),
            e
        ))
    })?;

    // Step 2: atomically publish the staged wallet into place. If this
    // rename fails, roll back by renaming the backup back to the target.
    // The rollback is best-effort: if it itself fails (e.g. the target
    // name was somehow taken between steps), we surface a compound
    // error so the user can locate both halves manually.
    //
    // Test-only failure injection: with `BTT_FAIL_BEFORE_PUBLISH` set,
    // we emulate a failure in the staging rename without having to
    // actually break the filesystem. The rollback path runs and the
    // test verifies the original wallet is restored byte-for-byte.
    #[cfg(test)]
    let publish_result = if std::env::var_os("BTT_FAIL_BEFORE_PUBLISH").is_some() {
        Err(std::io::Error::other(
            "BTT_FAIL_BEFORE_PUBLISH: synthetic failure for issue #29 round-2 tests",
        ))
    } else {
        fs::rename(staging_dir, target_dir)
    };
    #[cfg(not(test))]
    let publish_result = fs::rename(staging_dir, target_dir);
    if let Err(e) = publish_result {
        if let Err(rollback_err) = fs::rename(&backup_dir, target_dir) {
            return Err(BttError::io(format!(
                "failed to publish staged wallet at {} ({}), and rollback \
                 from {} failed ({}); original wallet may be at the backup path",
                target_dir.display(),
                e,
                backup_dir.display(),
                rollback_err
            )));
        }
        return Err(BttError::io(format!(
            "failed to publish staged wallet at {}: {}",
            target_dir.display(),
            e
        )));
    }

    // Step 3: test-only failure injection point. We're past the atomic
    // publish — the new wallet is live — but before the unrelated-hotkey
    // merge. A failure here simulates a hotkey-merge that errors out
    // after the backup-rename/staging-rename atomic pair. The test
    // `wallet_create_force_atomic_on_failure` places the hook here so
    // that it can assert the backup-rollback path in `promote` is NOT
    // triggered (because by this point the publish has already
    // succeeded) — which is the correct post-Round-2 behavior. An
    // earlier-round implementation would have been halfway through a
    // sequential-file rename and left a half-destroyed wallet.
    #[cfg(test)]
    {
        if std::env::var_os("BTT_FAIL_DURING_PROMOTE").is_some() {
            return Err(BttError::io(
                "BTT_FAIL_DURING_PROMOTE: synthetic failure for issue #29 round-2 tests",
            ));
        }
    }

    // Step 4: merge unrelated hotkeys from the backup into the new
    // target. The target's `hotkeys/` subdir already exists (it came
    // from the staging dir, which always creates it). We iterate the
    // backup's hotkeys, skipping the one we just published — the new
    // hotkey always wins over any pre-existing copy — and rename the
    // rest across. Any collision inside `target/hotkeys/` that isn't
    // the freshly-published hotkey would be extremely unusual (we only
    // just created this dir from the staging dir) but we guard against
    // it anyway with an `exists()` check.
    let backup_hotkeys = backup_dir.join("hotkeys");
    if backup_hotkeys.is_dir() {
        let target_hotkeys = target_dir.join("hotkeys");
        // Do NOT call `ensure_secure_dir` here — the target hotkeys dir
        // was created from the staging dir with 0700 already, and if
        // the user has tightened their wallet perms we do not want to
        // relax them back to 0700.
        if !target_hotkeys.is_dir() {
            // Defensive: if for any reason the target hotkeys dir is
            // absent (it shouldn't be), create it at 0700.
            ensure_secure_dir(&target_hotkeys)?;
        }
        let entries = fs::read_dir(&backup_hotkeys).map_err(|e| {
            BttError::io(format!(
                "failed to read backup hotkeys dir {}: {}",
                backup_hotkeys.display(),
                e
            ))
        })?;
        for entry in entries {
            let entry = entry.map_err(|e| {
                BttError::io(format!(
                    "failed to read backup hotkey entry under {}: {}",
                    backup_hotkeys.display(),
                    e
                ))
            })?;
            let name = entry.file_name();
            if name == OsStr::new(hotkey_name) {
                // The new hotkey takes precedence over any pre-existing
                // copy under the same name — skip it.
                continue;
            }
            let from = entry.path();
            let to = target_hotkeys.join(&name);
            if to.exists() {
                // Defensive: shouldn't happen (target hotkeys dir was
                // just created), but if it does, leave the backup entry
                // alone rather than clobbering.
                continue;
            }
            fs::rename(&from, &to).map_err(|e| {
                BttError::io(format!(
                    "failed to merge backup hotkey {} -> {}: {} (new wallet is \
                     live at {}; unrelated hotkeys remain under {})",
                    from.display(),
                    to.display(),
                    e,
                    target_dir.display(),
                    backup_dir.display()
                ))
            })?;
        }
    }

    // Step 5: best-effort cleanup. A leftover `.bak.*` is harmless.
    let _ = fs::remove_dir_all(&backup_dir);

    Ok(())
}

/// Derive the backup directory name used by `promote_staged_into_existing`
/// for a given `target_dir`. Format:
/// `<parent>/.bak.<basename>.<pid>.<nanos>.<counter>`. Shares a process-
/// local atomic counter with `temp_staging_name` so collisions are
/// impossible even under a frozen or backward-running clock.
fn backup_dir_for(target_dir: &Path) -> Option<PathBuf> {
    let parent = target_dir.parent()?;
    let basename = target_dir.file_name()?.to_string_lossy().into_owned();
    let pid = std::process::id();
    let nanos = nanos_since_epoch();
    let counter = next_staging_counter();
    Some(parent.join(format!(".bak.{basename}.{pid}.{nanos}.{counter}")))
}

/// Monotonically-increasing process-local counter used to disambiguate
/// staging and backup directory names when two calls happen inside the
/// same nanosecond (or the system clock is frozen / running backward).
/// Without this, two back-to-back `create` calls inside a single test
/// process could collide on `.tmp.<name>.<pid>.<nanos>` — the clock is
/// not guaranteed to advance between instructions.
fn next_staging_counter() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Nanoseconds since the Unix epoch, or 0 if the system clock is set
/// before 1970. The result is only used for filename disambiguation, so
/// the exact value does not matter as long as `next_staging_counter`
/// also contributes to uniqueness.
fn nanos_since_epoch() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Compute the staging directory name for an atomic `create`.
///
/// Format: `.tmp.<wallet_name>.<pid>.<nanos>.<counter>`. The `.tmp.`
/// prefix is reserved (wallet list ignores it), the pid distinguishes
/// concurrent processes, the nanosecond timestamp distinguishes
/// repeated calls from the same process, and the process-local atomic
/// counter protects against collisions when two calls land in the same
/// nanosecond or the system clock runs backward.
fn temp_staging_name(wallet_name: &str) -> String {
    let pid = std::process::id();
    let nanos = nanos_since_epoch();
    let counter = next_staging_counter();
    format!(".tmp.{wallet_name}.{pid}.{nanos}.{counter}")
}

/// Stage a complete wallet (coldkey + coldkeypub + hotkey) into
/// `staging_dir`. Caller owns the lifecycle of `staging_dir`: on any
/// error returned from this helper, the caller must `remove_dir_all`
/// the staging dir before surfacing the error.
fn create_into_staging(
    wallet_name: &str,
    hotkey_name: &str,
    n_words: u32,
    password: &str,
    staging_dir: &Path,
) -> Result<CreateResult, BttError> {
    let (cold_pair, mut cold_phrase, mut cold_seed) = generate_keypair(n_words)?;
    let cold_ss58 = cold_pair.public().to_ss58check();
    let cold_seed_hex = format!("0x{}", hex::encode(cold_seed));

    // Build the JSON for the coldkey
    let cold_json = build_key_json(&cold_pair, &cold_phrase, &cold_seed_hex);
    let mut cold_json_str = serde_json::to_string(&cold_json)
        .map_err(|e| BttError::io(format!("failed to serialize coldkey: {}", e)))?;

    // 0700 staging dir inside the wallets root. The staging dir inherits
    // the same perms the final wallet directory will carry, so the
    // rename-into-place does not have to chmod afterward.
    ensure_secure_dir(staging_dir)?;

    // Encrypt and write the coldkey into the staging dir.
    let mut encrypted = encrypt_key_data(cold_json_str.as_bytes(), password)?;
    let staged_coldkey = staging_dir.join("coldkey");
    write_secure_file(&staged_coldkey, &encrypted)?;
    encrypted.zeroize();
    cold_json_str.zeroize();

    // Write coldkeypub.txt into the staging dir (unencrypted public
    // info). This must also live in the staging dir so it appears (or
    // not) atomically with the secret files.
    let pub_data = build_pub_key_json(&cold_pair);
    let pub_json_str = serde_json::to_string(&pub_data)
        .map_err(|e| BttError::io(format!("failed to serialize coldkeypub: {}", e)))?;
    write_public_file(&staging_dir.join("coldkeypub.txt"), pub_json_str.as_bytes())?;

    // Generate hotkey
    let (hot_pair, mut hot_phrase, mut hot_seed) = generate_keypair(n_words)?;
    let hot_ss58 = hot_pair.public().to_ss58check();
    let hot_seed_hex = format!("0x{}", hex::encode(hot_seed));

    let hot_json = build_key_json(&hot_pair, &hot_phrase, &hot_seed_hex);
    let mut hot_json_str = serde_json::to_string(&hot_json)
        .map_err(|e| BttError::io(format!("failed to serialize hotkey: {}", e)))?;

    // Write hotkey as an unencrypted file with 0600 perms inside a 0700
    // `hotkeys/` subdir — both inside the staging dir.
    let staged_hotkeys_dir = staging_dir.join("hotkeys");
    ensure_secure_dir(&staged_hotkeys_dir)?;
    let staged_hotkey = staged_hotkeys_dir.join(hotkey_name);
    write_secure_file(&staged_hotkey, hot_json_str.as_bytes())?;
    hot_json_str.zeroize();

    // Issue #29 test-only failure injection. Gate on `cfg(test)` so the
    // release binary has no trace of this knob. The value is read from
    // the process environment so an individual test case can toggle the
    // injection without affecting unrelated wallet_keys tests running in
    // parallel. The scrub below (`cold_phrase`/`cold_seed`/`hot_phrase`/
    // `hot_seed`) runs regardless because `?` / early-return short-circuit
    // here — the caller's cleanup path still unlinks the staging dir.
    #[cfg(test)]
    {
        if std::env::var_os("BTT_FAIL_AFTER_HOTKEY_WRITE").is_some() {
            cold_phrase.zeroize();
            cold_seed.zeroize();
            hot_phrase.zeroize();
            hot_seed.zeroize();
            return Err(BttError::io(
                "BTT_FAIL_AFTER_HOTKEY_WRITE: synthetic failure for issue #29 tests",
            ));
        }
    }

    let mnemonic_out = cold_phrase.clone();

    // Zeroize sensitive material that will not be returned to the caller.
    cold_phrase.zeroize();
    cold_seed.zeroize();
    hot_phrase.zeroize();
    hot_seed.zeroize();

    Ok(CreateResult {
        wallet_name: wallet_name.to_string(),
        coldkey_ss58: cold_ss58,
        hotkey_ss58: hot_ss58,
        mnemonic: mnemonic_out,
    })
}

/// Generate only a new coldkey.
///
/// Refuses to run if `<wallet>/coldkey` already exists unless `force` is set.
pub fn new_coldkey(
    wallet_name: &str,
    n_words: u32,
    password: &str,
    force: bool,
) -> Result<NewColdkeyResult, BttError> {
    validate_n_words(n_words)?;

    // Resolve the target path and refuse overwrite before generating key
    // material. This keeps us from spending CPU on argon2 only to throw
    // the result away, and avoids any window where fresh secret bytes
    // live on the heap alongside a caller-visible error.
    let wallet_dir = wallet_path(wallet_name)?;
    let coldkey_path = wallet_dir.join("coldkey");
    guard_overwrite(&coldkey_path, "coldkey", force)?;

    let (pair, mut phrase, mut seed) = generate_keypair(n_words)?;
    let ss58 = pair.public().to_ss58check();
    let seed_hex = format!("0x{}", hex::encode(seed));

    let json = build_key_json(&pair, &phrase, &seed_hex);
    let mut json_str = serde_json::to_string(&json)
        .map_err(|e| BttError::io(format!("failed to serialize coldkey: {}", e)))?;

    ensure_wallets_root()?;
    ensure_secure_dir(&wallet_dir)?;

    let mut encrypted = encrypt_key_data(json_str.as_bytes(), password)?;
    write_secure_file(&coldkey_path, &encrypted)?;
    encrypted.zeroize();
    json_str.zeroize();

    let pub_data = build_pub_key_json(&pair);
    let pub_json_str = serde_json::to_string(&pub_data)
        .map_err(|e| BttError::io(format!("failed to serialize coldkeypub: {}", e)))?;
    write_public_file(&wallet_dir.join("coldkeypub.txt"), pub_json_str.as_bytes())?;

    let mnemonic_out = phrase.clone();

    phrase.zeroize();
    seed.zeroize();

    Ok(NewColdkeyResult {
        wallet_name: wallet_name.to_string(),
        ss58_address: ss58,
        mnemonic: mnemonic_out,
    })
}

/// Generate a new hotkey for an existing wallet.
///
/// Refuses to run if `<wallet>/hotkeys/<hotkey_name>` already exists unless
/// `force` is set.
pub fn new_hotkey(
    wallet_name: &str,
    hotkey_name: &str,
    n_words: u32,
    force: bool,
) -> Result<NewHotkeyResult, BttError> {
    validate_n_words(n_words)?;

    let wallet_dir = wallet_path(wallet_name)?;
    if !wallet_dir.exists() {
        return Err(BttError::wallet_not_found(format!(
            "wallet '{}' not found at {}",
            wallet_name,
            wallet_dir.display()
        )));
    }

    // Refuse overwrite before generating fresh key material.
    let hotkey_path = wallet_dir.join("hotkeys").join(hotkey_name);
    guard_overwrite(&hotkey_path, "hotkey", force)?;

    let (pair, mut phrase, mut seed) = generate_keypair(n_words)?;
    let ss58 = pair.public().to_ss58check();
    let seed_hex = format!("0x{}", hex::encode(seed));

    let json = build_key_json(&pair, &phrase, &seed_hex);
    let mut json_str = serde_json::to_string(&json)
        .map_err(|e| BttError::io(format!("failed to serialize hotkey: {}", e)))?;

    let hotkeys_dir = wallet_dir.join("hotkeys");
    ensure_secure_dir(&hotkeys_dir)?;
    write_secure_file(&hotkey_path, json_str.as_bytes())?;
    json_str.zeroize();

    let mnemonic_out = phrase.clone();

    phrase.zeroize();
    seed.zeroize();

    Ok(NewHotkeyResult {
        wallet_name: wallet_name.to_string(),
        hotkey_name: hotkey_name.to_string(),
        ss58_address: ss58,
        mnemonic: mnemonic_out,
    })
}

/// Restore a coldkey from mnemonic or seed.
///
/// Refuses to run if `<wallet>/coldkey` already exists unless `force` is set.
pub fn regen_coldkey(
    wallet_name: &str,
    mnemonic: Option<&str>,
    seed_hex: Option<&str>,
    password: &str,
    force: bool,
) -> Result<RegenResult, BttError> {
    // Resolve and guard before deriving any key material from the user's
    // mnemonic/seed. An error here must not leak a partial recovery state.
    let wallet_dir = wallet_path(wallet_name)?;
    let coldkey_path = wallet_dir.join("coldkey");
    guard_overwrite(&coldkey_path, "coldkey", force)?;

    let (pair, mut phrase, mut seed) = recover_keypair(mnemonic, seed_hex)?;
    let ss58 = pair.public().to_ss58check();
    let seed_hex_str = format!("0x{}", hex::encode(seed));

    let json = build_key_json(&pair, &phrase, &seed_hex_str);
    let mut json_str = serde_json::to_string(&json)
        .map_err(|e| BttError::io(format!("failed to serialize coldkey: {}", e)))?;

    ensure_wallets_root()?;
    ensure_secure_dir(&wallet_dir)?;

    let mut encrypted = encrypt_key_data(json_str.as_bytes(), password)?;
    write_secure_file(&coldkey_path, &encrypted)?;
    encrypted.zeroize();
    json_str.zeroize();
    phrase.zeroize();
    seed.zeroize();

    let pub_data = build_pub_key_json(&pair);
    let pub_json_str = serde_json::to_string(&pub_data)
        .map_err(|e| BttError::io(format!("failed to serialize coldkeypub: {}", e)))?;
    write_public_file(&wallet_dir.join("coldkeypub.txt"), pub_json_str.as_bytes())?;

    Ok(RegenResult {
        wallet_name: wallet_name.to_string(),
        ss58_address: ss58,
    })
}

/// Restore a hotkey from mnemonic or seed.
///
/// Refuses to run if `<wallet>/hotkeys/<hotkey_name>` already exists unless
/// `force` is set.
pub fn regen_hotkey(
    wallet_name: &str,
    hotkey_name: &str,
    mnemonic: Option<&str>,
    seed_hex: Option<&str>,
    force: bool,
) -> Result<RegenHotkeyResult, BttError> {
    let wallet_dir = wallet_path(wallet_name)?;
    if !wallet_dir.exists() {
        return Err(BttError::wallet_not_found(format!(
            "wallet '{}' not found at {}",
            wallet_name,
            wallet_dir.display()
        )));
    }

    // Refuse overwrite before deriving any key material.
    let hotkey_path = wallet_dir.join("hotkeys").join(hotkey_name);
    guard_overwrite(&hotkey_path, "hotkey", force)?;

    let (pair, mut phrase, mut seed) = recover_keypair(mnemonic, seed_hex)?;
    let ss58 = pair.public().to_ss58check();
    let seed_hex_str = format!("0x{}", hex::encode(seed));

    let json = build_key_json(&pair, &phrase, &seed_hex_str);
    let mut json_str = serde_json::to_string(&json)
        .map_err(|e| BttError::io(format!("failed to serialize hotkey: {}", e)))?;

    let hotkeys_dir = wallet_dir.join("hotkeys");
    ensure_secure_dir(&hotkeys_dir)?;
    write_secure_file(&hotkey_path, json_str.as_bytes())?;
    json_str.zeroize();
    phrase.zeroize();
    seed.zeroize();

    Ok(RegenHotkeyResult {
        wallet_name: wallet_name.to_string(),
        hotkey_name: hotkey_name.to_string(),
        ss58_address: ss58,
    })
}

/// Sign a message with a key from the wallet.
pub fn sign(
    wallet_name: &str,
    hotkey_name: &str,
    message: &str,
    use_hotkey: bool,
    password: Option<&str>,
) -> Result<SignResult, BttError> {
    let wallet_dir = wallet_path(wallet_name)?;
    if !wallet_dir.exists() {
        return Err(BttError::wallet_not_found(format!(
            "wallet '{}' not found at {}",
            wallet_name,
            wallet_dir.display()
        )));
    }

    let pair = if use_hotkey {
        load_hotkey(&wallet_dir, hotkey_name)?
    } else {
        let pw = password
            .ok_or_else(|| BttError::invalid_input("password required to decrypt coldkey"))?;
        load_coldkey(&wallet_dir, pw)?
    };

    let sig = <Pair as TraitPair>::sign(&pair, message.as_bytes());
    let public = pair.public();
    let ss58 = public.to_ss58check();

    Ok(SignResult {
        signature: format!("0x{}", hex::encode(sig.0)),
        public_key: format!("0x{}", hex::encode(public.0)),
        ss58_address: ss58,
    })
}

/// Verify a signature against a message and SS58 address.
pub fn verify(message: &str, signature_hex: &str, ss58: &str) -> Result<VerifyResult, BttError> {
    let public = Public::from_ss58check(ss58)
        .map_err(|e| BttError::invalid_address(format!("invalid SS58 address: {:?}", e)))?;

    let sig_bytes = parse_hex_bytes(signature_hex)?;
    if sig_bytes.len() != 64 {
        return Err(BttError::invalid_input(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        )));
    }

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from(sig_arr);

    let valid = <Pair as TraitPair>::verify(&signature, message.as_bytes(), &public);

    Ok(VerifyResult { valid })
}

// ── Internal helpers ──────────────────────────────────────────────────────

fn validate_n_words(n: u32) -> Result<(), BttError> {
    // sp-core's `generate_with_phrase` is fixed at 12 words. 24-word support
    // previously relied on a direct `bip39` dep which has been removed per
    // dependency-discipline review; it will return in a follow-up PR.
    if n != 12 {
        return Err(BttError::invalid_input(
            "n-words must be 12 (24-word support pending follow-up)",
        ));
    }
    Ok(())
}

fn wallet_path(name: &str) -> Result<PathBuf, BttError> {
    paths::wallet_dir(name)
}

/// Ensure the config directory and its `wallets/` subdirectory exist at
/// mode 0700. The exact path is OS-dependent — see
/// [`crate::commands::paths::config_dir`].
fn ensure_wallets_root() -> Result<(), BttError> {
    let root = paths::config_dir()?;
    ensure_secure_dir(&root)?;
    ensure_secure_dir(&root.join("wallets"))?;
    Ok(())
}

/// Generate an sr25519 keypair with a BIP39 mnemonic.
/// Uses `sp_core::sr25519::Pair::generate_with_phrase`, which drives BIP39 via
/// the transitive `substrate-bip39` / `parity-bip39` crates — no direct `bip39`
/// dep required. sp-core only exposes 12-word generation; 24-word generation
/// was removed in this PR pending a follow-up that doesn't require pulling a
/// bip39 crate back in for wordlist access.
fn generate_keypair(_n_words: u32) -> Result<(Pair, String, [u8; 32]), BttError> {
    let (pair, phrase, seed) = <Pair as TraitPair>::generate_with_phrase(None);
    Ok((pair, phrase, seed))
}

/// Recover a keypair from either a mnemonic phrase or a hex seed.
fn recover_keypair(
    mnemonic: Option<&str>,
    seed_hex: Option<&str>,
) -> Result<(Pair, String, [u8; 32]), BttError> {
    match (mnemonic, seed_hex) {
        (Some(phrase), None) => {
            let (pair, seed) = Pair::from_phrase(phrase, None).map_err(|e| {
                BttError::crypto(format!("failed to derive keypair from mnemonic: {:?}", e))
            })?;
            Ok((pair, phrase.to_string(), seed))
        }
        (None, Some(hex_str)) => {
            let seed_bytes = parse_hex_bytes(hex_str)?;
            if seed_bytes.len() != 32 {
                return Err(BttError::invalid_input(format!(
                    "seed must be 32 bytes, got {}",
                    seed_bytes.len()
                )));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);
            let pair = Pair::from_seed(&seed);
            Ok((pair, String::new(), seed))
        }
        (Some(_), Some(_)) => Err(BttError::invalid_input(
            "provide either --mnemonic or --seed, not both",
        )),
        (None, None) => Err(BttError::invalid_input(
            "provide either --mnemonic or --seed",
        )),
    }
}

/// Parse a hex string (with optional 0x prefix) into bytes.
///
/// The returned buffer is wrapped in `Zeroizing` because every current
/// caller uses it to reconstruct secret key material (raw seeds on the
/// load / regen paths). Callers that feed in non-secret hex get a
/// harmlessly-scrubbed buffer; callers that feed in secret hex get a
/// guaranteed scrub on drop.
fn parse_hex_bytes(s: &str) -> Result<Zeroizing<Vec<u8>>, BttError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped)
        .map(Zeroizing::new)
        .map_err(|e| BttError::parse(format!("invalid hex: {}", e)))
}

/// Build the btcli-compatible key JSON structure.
fn build_key_json(pair: &Pair, phrase: &str, seed_hex: &str) -> KeyFileData {
    let public = pair.public();
    KeyFileData {
        account_id: format!("0x{}", hex::encode(public.0)),
        public_key: format!("0x{}", hex::encode(public.0)),
        secret_phrase: phrase.to_string(),
        secret_seed: seed_hex.to_string(),
        ss58_address: public.to_ss58check(),
    }
}

/// Build public key JSON (for coldkeypub.txt).
fn build_pub_key_json(pair: &Pair) -> PubKeyFileData {
    let public = pair.public();
    PubKeyFileData {
        account_id: format!("0x{}", hex::encode(public.0)),
        public_key: format!("0x{}", hex::encode(public.0)),
        ss58_address: public.to_ss58check(),
    }
}

/// Derive a 32-byte NaCl secretbox key from a password using libsodium's
/// `argon2i13::derive_key` parameters (Argon2i, v0x13, t=8, m=512 MiB, p=1,
/// hardcoded `NACL_SALT`). Byte-for-byte compatible with btwallet/btcli.
fn derive_key(password: &[u8]) -> Result<Zeroizing<[u8; NACL_KEY_LEN]>, BttError> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(
        ARGON2_M_COST_KIB,
        ARGON2_T_COST,
        ARGON2_PARALLELISM,
        Some(NACL_KEY_LEN),
    )
    .map_err(|e| BttError::crypto(format!("invalid argon2 parameters: {}", e)))?;
    let argon2 = Argon2::new(Algorithm::Argon2i, Version::V0x13, params);

    let mut key = Zeroizing::new([0u8; NACL_KEY_LEN]);
    argon2
        .hash_password_into(password, NACL_SALT, key.as_mut_slice())
        .map_err(|e| BttError::crypto(format!("argon2 key derivation failed: {}", e)))?;
    Ok(key)
}

/// Encrypt key data with the btwallet NaCl envelope:
///   b"$NACL" || nonce (24 bytes) || secretbox_seal(plaintext, nonce, key)
fn encrypt_key_data(plaintext: &[u8], password: &str) -> Result<Vec<u8>, BttError> {
    use rand::RngCore;
    use xsalsa20poly1305::aead::Aead;
    use xsalsa20poly1305::{KeyInit, XSalsa20Poly1305};

    let key = derive_key(password.as_bytes())?;

    let mut nonce_bytes = [0u8; NACL_NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = xsalsa20poly1305::Nonce::from(nonce_bytes);

    let cipher = XSalsa20Poly1305::new(xsalsa20poly1305::Key::from_slice(key.as_slice()));
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| BttError::crypto(format!("encryption failed: {}", e)))?;

    let mut output = Vec::with_capacity(NACL_MAGIC.len() + NACL_NONCE_LEN + ciphertext.len());
    output.extend_from_slice(NACL_MAGIC);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt a btwallet-format NaCl envelope.
///
/// The returned plaintext is wrapped in `Zeroizing<Vec<u8>>` so the decrypted
/// bytes — which, for a real coldkey, contain the JSON-serialized mnemonic
/// and raw seed — are scrubbed when the caller drops the return value. A
/// plain `Vec<u8>` here would rely on `Vec::drop` returning the allocation
/// to the allocator without touching the bytes, leaving the secret sitting
/// in the freed chunk until something else happens to allocate over it.
fn decrypt_key_data(encrypted: &[u8], password: &str) -> Result<Zeroizing<Vec<u8>>, BttError> {
    use xsalsa20poly1305::aead::Aead;
    use xsalsa20poly1305::{KeyInit, XSalsa20Poly1305};

    if !encrypted.starts_with(NACL_MAGIC) {
        return Err(BttError::crypto(
            "unrecognized keyfile format (missing $NACL magic)",
        ));
    }
    let body = &encrypted[NACL_MAGIC.len()..];
    if body.len() < NACL_NONCE_LEN + 16 {
        return Err(BttError::crypto("encrypted data too short"));
    }
    let (nonce_bytes, ciphertext) = body.split_at(NACL_NONCE_LEN);

    let key = derive_key(password.as_bytes())?;

    let nonce = xsalsa20poly1305::Nonce::from_slice(nonce_bytes);
    let cipher = XSalsa20Poly1305::new(xsalsa20poly1305::Key::from_slice(key.as_slice()));

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| BttError::crypto("decryption failed — wrong password or corrupted file"))?;
    Ok(Zeroizing::new(plaintext))
}

/// Create a file at `path` with mode 0600 (unix) atomically via `O_CREAT|O_EXCL`,
/// write `data`, fsync, and close. Fails if the file already exists unless the
/// existing file can be removed first (callers that intend to overwrite should
/// delete first). No TOCTOU window at 0644.
///
/// After the file's own `sync_all()` returns, the parent directory is also
/// opened and `sync_all()`d so the new dirent reaches stable storage. Without
/// this second fsync a power loss between the file's inode checkpoint and
/// the directory's dirent checkpoint can leave the file either orphaned
/// (content on disk, name not visible) or invisible (name gone, content
/// still linked). NEW-L1 from the PR #3 round-2 review (issue #9).
fn write_secure_file(path: &Path, data: &[u8]) -> Result<(), BttError> {
    // If the file exists, remove it first; we want to replace atomically.
    if path.exists() {
        fs::remove_file(path)
            .map_err(|e| BttError::io(format!("failed to remove {}: {}", path.display(), e)))?;
    }

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| BttError::io(format!("failed to create {}: {}", path.display(), e)))?;
    f.write_all(data)
        .map_err(|e| BttError::io(format!("failed to write {}: {}", path.display(), e)))?;
    f.sync_all()
        .map_err(|e| BttError::io(format!("failed to sync {}: {}", path.display(), e)))?;
    sync_parent_dir(path)?;
    Ok(())
}

/// Create a file at `path` with mode 0644 (unix) and write `data`. Used for
/// public-data files (`coldkeypub.txt`) that must be readable by anything on
/// the host but should still carry an explicit, predictable mode rather than
/// whatever the caller's umask happened to produce. NEW-L3 from the PR #3
/// round-2 review (issue #9): the rest of the wallet dir has an explicit-perms
/// posture, and `fs::write` alone leaves the pub file at umask-default
/// (typically 0664 on a user shell). The contents are public so the bit that
/// matters is consistency, not confidentiality.
///
/// As with [`write_secure_file`], the file is fsynced and the parent dir
/// dirent is fsynced afterwards.
fn write_public_file(path: &Path, data: &[u8]) -> Result<(), BttError> {
    if path.exists() {
        fs::remove_file(path)
            .map_err(|e| BttError::io(format!("failed to remove {}: {}", path.display(), e)))?;
    }

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(0o644);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| BttError::io(format!("failed to create {}: {}", path.display(), e)))?;
    f.write_all(data)
        .map_err(|e| BttError::io(format!("failed to write {}: {}", path.display(), e)))?;
    f.sync_all()
        .map_err(|e| BttError::io(format!("failed to sync {}: {}", path.display(), e)))?;
    sync_parent_dir(path)?;
    Ok(())
}

/// Open the parent directory of `path` and `sync_all()` it, so the dirent
/// pointing at the freshly written file reaches stable storage. Silently
/// no-ops if `path` has no parent (a root-level path, which none of our
/// wallet paths are). See [`write_secure_file`] for the durability rationale.
fn sync_parent_dir(path: &Path) -> Result<(), BttError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    // `File::open` on a directory is legal on unix and returns an fd that
    // supports `fsync`. On windows, `File::open` on a directory fails with
    // `ERROR_ACCESS_DENIED`, so gate the call to unix targets. The PR #3
    // durability finding is unix-specific; windows' own crash model is
    // different and not in scope.
    #[cfg(unix)]
    {
        let dir = fs::File::open(parent).map_err(|e| {
            BttError::io(format!(
                "failed to open parent directory {} for fsync: {}",
                parent.display(),
                e
            ))
        })?;
        dir.sync_all().map_err(|e| {
            BttError::io(format!(
                "failed to fsync parent directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
    Ok(())
}

/// Create (or tighten) a directory at `path` with mode 0700 on unix.
fn ensure_secure_dir(path: &Path) -> Result<(), BttError> {
    fs::create_dir_all(path)
        .map_err(|e| BttError::io(format!("failed to create directory {}: {}", path.display(), e)))?;
    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(path, perms).map_err(|e| {
            BttError::io(format!(
                "failed to set permissions on {}: {}",
                path.display(),
                e
            ))
        })?;
    }
    Ok(())
}

/// Load and decrypt a coldkey from a wallet directory.
///
/// The decrypted plaintext never leaves this function as an owned unscoped
/// buffer: the decrypt step hands back a `Zeroizing<Vec<u8>>`, we view it
/// as a UTF-8 slice without a second allocation, and `pair_from_key_json`
/// funnels the bytes into a `LoadedKeyFile` that zeroes itself on drop.
/// When this function returns, every heap region that held the mnemonic
/// or the raw seed has been overwritten with zero.
fn load_coldkey(wallet_dir: &std::path::Path, password: &str) -> Result<Pair, BttError> {
    let coldkey_path = wallet_dir.join("coldkey");
    if !coldkey_path.exists() {
        return Err(BttError::wallet_not_found("coldkey file not found"));
    }

    let encrypted = fs::read(&coldkey_path)
        .map_err(|e| BttError::io(format!("failed to read coldkey: {}", e)))?;

    let decrypted: Zeroizing<Vec<u8>> = decrypt_key_data(&encrypted, password)?;
    // Borrow the plaintext as &str instead of moving it into an owned
    // `String`. An owned `String` here would double the secret footprint
    // and, unlike the `Zeroizing<Vec<u8>>` backing store, would not be
    // scrubbed on drop.
    let json_str = std::str::from_utf8(&decrypted)
        .map_err(|_| BttError::crypto("decrypted coldkey is not valid UTF-8"))?;

    pair_from_key_json(json_str)
}

/// Load a hotkey (unencrypted) from a wallet directory.
///
/// Even though the hotkey file is stored without encryption, its contents
/// still contain a mnemonic / raw seed. Read it as bytes into a
/// `Zeroizing<Vec<u8>>` and view it as a slice, rather than calling
/// `fs::read_to_string` which returns an unscrubbed `String`.
fn load_hotkey(wallet_dir: &std::path::Path, hotkey_name: &str) -> Result<Pair, BttError> {
    let hotkey_path = wallet_dir.join("hotkeys").join(hotkey_name);
    if !hotkey_path.exists() {
        return Err(BttError::wallet_not_found(format!(
            "hotkey '{}' not found",
            hotkey_name
        )));
    }

    let raw: Zeroizing<Vec<u8>> = Zeroizing::new(
        fs::read(&hotkey_path)
            .map_err(|e| BttError::io(format!("failed to read hotkey: {}", e)))?,
    );
    let json_str = std::str::from_utf8(&raw)
        .map_err(|_| BttError::parse("hotkey file is not valid UTF-8"))?;

    pair_from_key_json(json_str)
}

/// Recover a Pair from a btcli-format key JSON string.
/// Tries `secretPhrase` first (mnemonic), then `secretSeed`.
///
/// Deserialization targets `LoadedKeyFile` (which derives
/// `Zeroize + ZeroizeOnDrop`) so that the intermediate owned `String`s are
/// overwritten with zero when this function returns — regardless of
/// whether the recovery succeeds or errors out.
fn pair_from_key_json(json_str: &str) -> Result<Pair, BttError> {
    let loaded: LoadedKeyFile = serde_json::from_str(json_str)
        .map_err(|e| BttError::parse(format!("invalid key JSON: {}", e)))?;

    // Try mnemonic first.
    if let Some(phrase) = loaded.secret_phrase.as_deref() {
        if !phrase.is_empty() {
            // `Pair::from_phrase` returns `(Pair, Seed)`. The seed is a
            // fixed-size array; scrub it immediately on the way out.
            let (pair, mut seed) = Pair::from_phrase(phrase, None).map_err(|e| {
                BttError::crypto(format!("failed to recover from mnemonic: {:?}", e))
            })?;
            seed.zeroize();
            return Ok(pair);
        }
    }

    // Fall back to seed.
    if let Some(seed_str) = loaded.secret_seed.as_deref() {
        if !seed_str.is_empty() {
            // `parse_hex_bytes` now returns `Zeroizing<Vec<u8>>`; the
            // intermediate hex decode is scrubbed on drop.
            let seed_bytes = parse_hex_bytes(seed_str)?;
            if seed_bytes.len() != 32 {
                return Err(BttError::parse("secretSeed must be 32 bytes"));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes);
            let pair = Pair::from_seed(&seed);
            seed.zeroize();
            return Ok(pair);
        }
    }

    Err(BttError::parse(
        "key file contains neither secretPhrase nor secretSeed",
    ))
}

/// Read password from terminal with no echo. Writes the prompt to stderr so
/// that stdout remains a clean JSON channel (`btt wallet create | jq .` works).
/// Backed by `rpassword::prompt_password`, which reads from the controlling
/// TTY when one is available.
pub fn read_password(prompt: &str) -> Result<Zeroizing<String>, BttError> {
    use std::io::Write as _;
    let mut stderr = std::io::stderr();
    let _ = stderr.write_all(prompt.as_bytes());
    let _ = stderr.flush();
    let pw = rpassword::prompt_password("")
        .map_err(|e| BttError::io(format!("failed to read password: {}", e)))?;
    Ok(Zeroizing::new(pw))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::paths::ENV_LOCK;
    use sp_core::Pair as TraitPairAlias;

    // Tests that mutate the config-dir env vars cannot run in parallel
    // because env vars are process-global. `HOME_LOCK` is an alias onto
    // the shared `paths::ENV_LOCK` so we serialize against the resolver
    // tests in `paths::tests` as well.
    static HOME_LOCK: &std::sync::Mutex<()> = &ENV_LOCK;

    /// Pin the btt config directory to `<tmp>` for the duration of the
    /// currently running test. Sets the per-OS env vars that
    /// [`crate::commands::paths::config_dir`] consults so the resolver
    /// returns a path inside `tmp`, and ensures the directory tree exists
    /// so the legacy-fallback branch is never taken.
    ///
    /// Returns the `<tmp>/.../wallets` path — i.e., exactly the parent of
    /// `<wallet_name>` that `wallet_path(name)` will produce.
    ///
    /// Caller must hold `HOME_LOCK`.
    fn seat_home_env(tmp: &std::path::Path) -> PathBuf {
        // Always set HOME (macOS resolver needs it, linux fallback needs
        // it, and some surrounding test code reads it directly).
        std::env::set_var("HOME", tmp.to_str().expect("valid path"));

        // On linux (and BSDs, via the fallback arm), pin
        // XDG_CONFIG_HOME inside tmp so the resolver never looks at the
        // real `$HOME/.config`.
        #[cfg(any(
            target_os = "linux",
            not(any(target_os = "macos", target_os = "windows"))
        ))]
        {
            let xdg = tmp.join("xdg");
            std::env::set_var("XDG_CONFIG_HOME", xdg.to_str().expect("valid path"));
        }

        // On windows, pin APPDATA inside tmp.
        #[cfg(target_os = "windows")]
        {
            let appdata = tmp.join("AppData").join("Roaming");
            std::env::set_var("APPDATA", appdata.to_str().expect("valid path"));
        }

        // Compute what `paths::config_dir()` will now return, and make
        // sure it exists so the legacy-fallback branch (which checks for
        // `$HOME/.bittensor`) is never taken.
        let parent = test_wallets_parent(tmp);
        std::fs::create_dir_all(&parent).expect("create wallets parent");
        parent
    }

    /// Compute the `wallets/` parent dir that `paths::config_dir()` will
    /// resolve to for a given test tmp root, on the host OS.
    fn test_wallets_parent(tmp: &std::path::Path) -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            tmp.join("xdg").join("btt").join("wallets")
        }
        #[cfg(target_os = "macos")]
        {
            tmp.join("Library")
                .join("Application Support")
                .join("btt")
                .join("wallets")
        }
        #[cfg(target_os = "windows")]
        {
            tmp.join("AppData").join("Roaming").join("btt").join("wallets")
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            tmp.join("xdg").join("btt").join("wallets")
        }
    }

    #[test]
    fn generate_12_word_keypair() {
        let (pair, phrase, seed) = generate_keypair(12).expect("12-word generation should work");
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12);
        assert!(!seed.iter().all(|&b| b == 0), "seed should not be all zeros");
        let ss58 = pair.public().to_ss58check();
        assert!(ss58.starts_with('5'), "SS58 address should start with 5");
    }

    #[test]
    fn only_12_word_supported() {
        assert!(validate_n_words(11).is_err());
        assert!(validate_n_words(12).is_ok());
        // 24-word support deferred with bip39 dep removal; see generate_keypair.
        assert!(validate_n_words(24).is_err());
        assert!(validate_n_words(25).is_err());
    }

    #[test]
    fn mnemonic_recovery_roundtrip() {
        let (original, phrase, _seed) =
            generate_keypair(12).expect("generation should work");

        let (recovered, _recovered_phrase, _recovered_seed) =
            recover_keypair(Some(&phrase), None).expect("recovery should work");

        assert_eq!(
            original.public(),
            recovered.public(),
            "recovered key should match original"
        );
    }

    #[test]
    fn seed_recovery_roundtrip() {
        let (_pair, _phrase, seed) = generate_keypair(12).expect("generation should work");
        let seed_hex = format!("0x{}", hex::encode(seed));

        let (recovered, _, recovered_seed) =
            recover_keypair(None, Some(&seed_hex)).expect("seed recovery should work");

        assert_eq!(seed, recovered_seed, "recovered seed should match");
        let pair_from_seed = Pair::from_seed(&seed);
        assert_eq!(
            pair_from_seed.public(),
            recovered.public(),
            "recovered key should match"
        );
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (pair, _phrase, _seed) = generate_keypair(12).expect("generation should work");
        let message = b"test message for signing";

        let sig = <Pair as TraitPairAlias>::sign(&pair, message);
        let valid =
            <Pair as TraitPairAlias>::verify(&sig, &message[..], &pair.public());
        assert!(valid, "signature should verify");

        // Wrong message should fail
        let bad_valid =
            <Pair as TraitPairAlias>::verify(&sig, b"wrong message", &pair.public());
        assert!(!bad_valid, "wrong message should not verify");
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let plaintext = b"sensitive key material here";
        let password = "test-password-123";

        let encrypted = encrypt_key_data(plaintext, password).expect("encryption should work");
        assert!(
            encrypted.starts_with(b"$NACL"),
            "encrypted blob should start with btwallet magic $NACL"
        );
        assert_ne!(&encrypted[..], plaintext, "ciphertext should differ from plaintext");

        let decrypted = decrypt_key_data(&encrypted, password).expect("decryption should work");
        assert_eq!(decrypted.as_slice(), plaintext, "decrypted should match original");
    }

    #[test]
    fn derive_key_matches_libsodium_reference() {
        // Reference vector computed with pynacl:
        //   nacl.pwhash.argon2i.kdf(
        //     32, b"hello-btcli", NACL_SALT,
        //     opslimit=OPSLIMIT_SENSITIVE, memlimit=MEMLIMIT_SENSITIVE)
        // This test pins the argon2i13 parameters to libsodium's SENSITIVE
        // profile. If it ever fails, the btwallet on-disk format will have
        // silently diverged.
        let key = derive_key(b"hello-btcli").expect("argon2 derive");
        let expected =
            hex::decode("39272631c10c56896024d406eef497421dcb6a6be0f2fb71adb7ae39f42456cd")
                .expect("hex");
        assert_eq!(key.as_slice(), expected.as_slice());
    }

    #[test]
    fn decrypts_btwallet_reference_vector() {
        // Fixed reference blob produced by pynacl (libsodium) using exactly
        // the btwallet format:
        //
        //   import nacl.pwhash.argon2i as a, nacl.secret
        //   salt = NACL_SALT
        //   key  = a.kdf(32, b"correct horse battery staple", salt,
        //                opslimit=a.OPSLIMIT_SENSITIVE,
        //                memlimit=a.MEMLIMIT_SENSITIVE)
        //   box  = nacl.secret.SecretBox(key)
        //   ct   = bytes(box.encrypt(plaintext, nonce=bytes(24)))
        //   blob = b"$NACL" + ct
        //
        // The all-zero nonce is chosen only so the vector is reproducible;
        // production encryption uses random nonces. If this test fails, the
        // on-disk envelope has drifted from btwallet.
        let plaintext_hex =
            "7b226163636f756e744964223a2230786465616462656566222c\
             227373353841646472657373223a223546616b6541646472227d";
        let blob_hex = "244e41434c000000000000000000000000000000000000000000000000\
                        fc80b605e3f8a4e8ac1fe620d424cf239c6806fed7365d1bb2142107c6\
                        fa3ed8f7bbc7af9b1e2c3e67f1cb90e58945e8520b7bb1006532a43e77\
                        75d7c439db6f5fc337df";
        let expected_plain =
            hex::decode(plaintext_hex.replace(|c: char| c.is_whitespace(), "")).expect("hex");
        let blob =
            hex::decode(blob_hex.replace(|c: char| c.is_whitespace(), "")).expect("hex");
        let password = "correct horse battery staple";

        // btwallet -> btt: we must be able to decrypt the external blob.
        let decoded = decrypt_key_data(&blob, password).expect("decrypt external blob");
        assert_eq!(decoded.as_slice(), expected_plain.as_slice());

        // btt -> btt round trip: sanity check shape of our own output.
        let enc = encrypt_key_data(&expected_plain, password).expect("encrypt");
        assert!(enc.starts_with(b"$NACL"));
        assert_eq!(enc.len(), 5 + 24 + expected_plain.len() + 16);
        let dec = decrypt_key_data(&enc, password).expect("decrypt");
        assert_eq!(dec.as_slice(), expected_plain.as_slice());
    }

    #[test]
    #[ignore = "helper for producing hex blobs consumed by external libsodium"]
    fn dump_blob_for_python() {
        let pt = b"btt-to-btwallet-interop-check";
        let enc = encrypt_key_data(pt, "roundtrip-pw").expect("encrypt");
        eprintln!("BTT_ENC_BLOB={}", hex::encode(&enc));
    }

    #[test]
    fn decrypt_rejects_missing_magic() {
        // Without the $NACL prefix, decrypt must refuse.
        let fake = vec![0u8; 100];
        assert!(decrypt_key_data(&fake, "pw").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn create_writes_secure_file_perms() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("btt-perm-{}", std::process::id()));
        let wallet_name = "perm-test";

        let original_home = std::env::var("HOME").ok();
        let _ = std::fs::create_dir_all(&tmp);
        let wallets_parent = seat_home_env(&tmp);

        let result = create(wallet_name, "default", 12, "perm-pw", false);

        // Capture paths before cleanup
        let wdir = wallets_parent.join(wallet_name);
        let coldkey = wdir.join("coldkey");
        let hotkey = wdir.join("hotkeys").join("default");

        let coldkey_mode = std::fs::metadata(&coldkey).map(|m| m.permissions().mode() & 0o777);
        let hotkey_mode = std::fs::metadata(&hotkey).map(|m| m.permissions().mode() & 0o777);
        let wdir_mode = std::fs::metadata(&wdir).map(|m| m.permissions().mode() & 0o777);

        // Read first bytes of coldkey to confirm $NACL framing
        let coldkey_bytes = std::fs::read(&coldkey).ok();

        if let Some(h) = original_home {
            std::env::set_var("HOME", &h);
        }
        let _ = std::fs::remove_dir_all(&tmp);

        result.expect("create should work");
        assert_eq!(coldkey_mode.expect("coldkey stat"), 0o600);
        assert_eq!(hotkey_mode.expect("hotkey stat"), 0o600);
        assert_eq!(wdir_mode.expect("wallet dir stat"), 0o700);
        let bytes = coldkey_bytes.expect("coldkey read");
        assert!(
            bytes.starts_with(b"$NACL"),
            "coldkey file should start with $NACL magic"
        );
    }

    #[test]
    fn decrypt_wrong_password_fails() {
        let plaintext = b"sensitive key material";
        let encrypted = encrypt_key_data(plaintext, "correct").expect("encryption should work");
        let result = decrypt_key_data(&encrypted, "wrong");
        assert!(result.is_err(), "wrong password should fail");
    }

    #[test]
    fn key_json_format() {
        let (pair, phrase, seed) = generate_keypair(12).expect("generation should work");
        let seed_hex = format!("0x{}", hex::encode(seed));
        let json = build_key_json(&pair, &phrase, &seed_hex);
        let json_str =
            serde_json::to_string(&json).expect("should serialize");

        let v: serde_json::Value =
            serde_json::from_str(&json_str).expect("should parse");
        assert!(v.get("accountId").is_some());
        assert!(v.get("publicKey").is_some());
        assert!(v.get("secretPhrase").is_some());
        assert!(v.get("secretSeed").is_some());
        assert!(v.get("ss58Address").is_some());

        // Verify we can recover from the JSON
        let recovered = pair_from_key_json(&json_str).expect("should recover");
        assert_eq!(pair.public(), recovered.public());
    }

    // ── Load-path zeroization tests (issue #8) ─────────────────────────
    //
    // These assertions are defense-in-depth checks, not end-to-end memory
    // dumps. We verify the types that hold decrypted secret material
    // actually call `.zeroize()` on their backing buffers. The runtime
    // check is necessarily indirect — once a `String` has been dropped
    // the allocator is free to reuse or return the pages — so we invoke
    // `Zeroize::zeroize` manually and inspect the struct afterward.

    #[test]
    fn loaded_key_file_zeroizes_fields() {
        let json = r#"{
            "secretPhrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "secretSeed": "0x1111111111111111111111111111111111111111111111111111111111111111"
        }"#;

        let mut loaded: LoadedKeyFile =
            serde_json::from_str(json).expect("LoadedKeyFile should deserialize");

        // Sanity: the fields are populated before the scrub.
        assert!(loaded
            .secret_phrase
            .as_deref()
            .expect("secret_phrase deserialized")
            .contains("abandon"));
        assert!(loaded
            .secret_seed
            .as_deref()
            .expect("secret_seed deserialized")
            .starts_with("0x1111"));

        // Manually invoke the scrub and confirm both fields are wiped.
        // `Zeroize for Option<String>` zeros the inner `String` buffer,
        // drops it, and then volatile-writes the `Option` discriminant
        // back to `None`. So after this call both fields are `None`.
        loaded.zeroize();
        assert!(loaded.secret_phrase.is_none());
        assert!(loaded.secret_seed.is_none());
    }

    #[test]
    fn decrypt_key_data_returns_zeroizing_buffer() {
        // Pin the decrypt return type: any refactor that weakens the
        // scrub guarantee (e.g. reverting to `Vec<u8>`) will fail to
        // compile this test.
        fn assert_zeroizing(_: &Zeroizing<Vec<u8>>) {}

        let password = "load-zeroize-test-pw";
        let plaintext = b"{\"secretPhrase\":\"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\"}";
        let encrypted = encrypt_key_data(plaintext, password).expect("encrypt");
        let decrypted = decrypt_key_data(&encrypted, password).expect("decrypt");
        assert_zeroizing(&decrypted);
        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn parse_hex_bytes_returns_zeroizing_buffer() {
        // Same story as `decrypt_key_data`: pin the return type so a
        // future refactor cannot silently strip the scrub.
        fn assert_zeroizing(_: &Zeroizing<Vec<u8>>) {}
        let bytes = parse_hex_bytes("0xdeadbeef").expect("parse");
        assert_zeroizing(&bytes);
    }

    #[test]
    fn pair_from_key_json_load_roundtrip() {
        // End-to-end correctness check for the load path: the same
        // mnemonic produced by `generate_keypair` must reconstruct the
        // same public key when routed back through `pair_from_key_json`
        // (which now goes via the zeroizing `LoadedKeyFile`).
        let (original, phrase, seed) = generate_keypair(12).expect("generate");
        let seed_hex = format!("0x{}", hex::encode(seed));
        let json = build_key_json(&original, &phrase, &seed_hex);
        let json_str = serde_json::to_string(&json).expect("serialize");

        // Mnemonic branch.
        let via_phrase = pair_from_key_json(&json_str).expect("recover via phrase");
        assert_eq!(via_phrase.public(), original.public());

        // Seed branch: strip the phrase so the fallback is exercised.
        let seed_only = serde_json::json!({
            "secretPhrase": "",
            "secretSeed": seed_hex,
        });
        let via_seed =
            pair_from_key_json(&seed_only.to_string()).expect("recover via seed");
        assert_eq!(via_seed.public(), original.public());
    }

    #[test]
    fn load_coldkey_roundtrip_via_create() {
        // The highest-value load-path test: drive the full pipeline
        // (generate → write → decrypt → load → sign) and confirm the
        // ss58 matches the create-time ss58. This exercises
        // `decrypt_key_data`, `load_coldkey`, and `pair_from_key_json`
        // on the zeroized code path.
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("btt-load-zeroize-{}", std::process::id()));
        let wallet_name = "load-zero-test";

        let original_home = std::env::var("HOME").ok();
        std::fs::create_dir_all(&tmp).expect("create tmp root");
        let _wallets_parent = seat_home_env(&tmp);

        let password = "load-zero-pw";
        let cr = create(wallet_name, "default", 12, password, false).expect("create");

        // load_coldkey is private; invoke it indirectly via `sign`.
        let sr =
            sign(wallet_name, "default", "hi", false, Some(password)).expect("sign coldkey");

        if let Some(h) = original_home {
            std::env::set_var("HOME", &h);
        }
        let _ = std::fs::remove_dir_all(&tmp);

        assert_eq!(
            sr.ss58_address, cr.coldkey_ss58,
            "load_coldkey must reproduce the create-time ss58"
        );
    }

    #[test]
    fn parse_hex_with_prefix() {
        let bytes = parse_hex_bytes("0xdeadbeef").expect("should parse");
        assert_eq!(bytes.as_slice(), [0xde, 0xad, 0xbe, 0xef].as_slice());
    }

    #[test]
    fn parse_hex_without_prefix() {
        let bytes = parse_hex_bytes("deadbeef").expect("should parse");
        assert_eq!(bytes.as_slice(), [0xde, 0xad, 0xbe, 0xef].as_slice());
    }

    #[test]
    fn verify_command_valid_signature() {
        let (pair, _phrase, _seed) = generate_keypair(12).expect("generation should work");
        let message = "hello world";
        let sig = <Pair as TraitPairAlias>::sign(&pair, message.as_bytes());
        let sig_hex = format!("0x{}", hex::encode(sig.0));
        let ss58 = pair.public().to_ss58check();

        let result = verify(message, &sig_hex, &ss58).expect("verify should work");
        assert!(result.valid, "valid signature should verify");
    }

    #[test]
    fn verify_command_invalid_signature() {
        let (pair, _phrase, _seed) = generate_keypair(12).expect("generation should work");
        let ss58 = pair.public().to_ss58check();

        let result =
            verify("hello", "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", &ss58)
                .expect("verify should work even with bad sig");
        assert!(!result.valid, "invalid signature should not verify");
    }

    #[test]
    fn create_wallet_roundtrip() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Use a temp directory to avoid polluting the real config dir.
        let tmp = std::env::temp_dir().join(format!("btt-test-{}", std::process::id()));
        let wallet_name = "test-wallet";
        let _wallet_dir = tmp.join(wallet_name);

        // Override the config-dir env vars for this test.
        let original_home = std::env::var("HOME").ok();
        std::fs::create_dir_all(&tmp).expect("create tmp root");
        let _wallets_parent = seat_home_env(&tmp);

        let password = "test-password";
        let result = create(wallet_name, "default", 12, password, false);

        // Restore HOME
        if let Some(h) = original_home {
            std::env::set_var("HOME", &h);
        }

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);

        let result = result.expect("create should work");
        assert_eq!(result.wallet_name, wallet_name);
        assert!(result.coldkey_ss58.starts_with('5'));
        assert!(result.hotkey_ss58.starts_with('5'));
        let words: Vec<&str> = result.mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    // -- TAO/RAO conversion tests --

    #[test]
    fn tao_to_rao_whole_number() {
        assert_eq!(tao_to_rao(1.0).expect("1 TAO"), 1_000_000_000);
    }

    #[test]
    fn tao_to_rao_fractional() {
        assert_eq!(tao_to_rao(0.5).expect("0.5 TAO"), 500_000_000);
    }

    #[test]
    fn tao_to_rao_zero() {
        assert_eq!(tao_to_rao(0.0).expect("0 TAO"), 0);
    }

    #[test]
    fn tao_to_rao_large_amount() {
        let rao = tao_to_rao(21_000_000.0).expect("21M TAO");
        assert_eq!(rao, 21_000_000_000_000_000);
    }

    #[test]
    fn tao_to_rao_negative_fails() {
        assert!(tao_to_rao(-1.0).is_err());
    }

    #[test]
    fn tao_to_rao_nan_fails() {
        assert!(tao_to_rao(f64::NAN).is_err());
    }

    #[test]
    fn tao_to_rao_infinity_fails() {
        assert!(tao_to_rao(f64::INFINITY).is_err());
    }

    #[test]
    fn rao_to_tao_string_whole() {
        assert_eq!(rao_to_tao_string(1_000_000_000), "1.0");
    }

    #[test]
    fn rao_to_tao_string_fractional() {
        assert_eq!(rao_to_tao_string(1_500_000_000), "1.5");
    }

    #[test]
    fn rao_to_tao_string_zero() {
        assert_eq!(rao_to_tao_string(0), "0.0");
    }

    #[test]
    fn rao_to_tao_string_small() {
        assert_eq!(rao_to_tao_string(1), "0.000000001");
    }

    #[test]
    fn rao_to_tao_string_precise() {
        assert_eq!(rao_to_tao_string(100_500_000_000), "100.5");
    }

    #[test]
    fn extract_ss58_from_json_content() {
        let json = r#"{"ss58Address": "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"}"#;
        let addr = extract_ss58_from_content(json);
        assert_eq!(
            addr,
            Some("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string())
        );
    }

    #[test]
    fn extract_ss58_from_raw_content() {
        let raw = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY\n";
        let addr = extract_ss58_from_content(raw);
        assert_eq!(
            addr,
            Some("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string())
        );
    }

    #[test]
    fn extract_ss58_from_empty_returns_none() {
        assert!(extract_ss58_from_content("").is_none());
    }

    #[test]
    fn create_and_sign_roundtrip() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("btt-test-sign-{}", std::process::id()));
        let wallet_name = "sign-test";

        let original_home = std::env::var("HOME").ok();
        std::fs::create_dir_all(&tmp).expect("create tmp root");
        let _wallets_parent = seat_home_env(&tmp);

        let password = "sign-test-pw";
        let cr = create(wallet_name, "default", 12, password, false).expect("create should work");

        // Sign with coldkey
        let sign_result =
            sign(wallet_name, "default", "hello", false, Some(password)).expect("sign coldkey");
        assert_eq!(sign_result.ss58_address, cr.coldkey_ss58);

        // Verify the coldkey signature
        let vr = verify("hello", &sign_result.signature, &sign_result.ss58_address)
            .expect("verify coldkey sig");
        assert!(vr.valid);

        // Sign with hotkey
        let hk_sign = sign(wallet_name, "default", "hello", true, None).expect("sign hotkey");
        assert_eq!(hk_sign.ss58_address, cr.hotkey_ss58);

        // Verify the hotkey signature
        let hk_vr = verify("hello", &hk_sign.signature, &hk_sign.ss58_address)
            .expect("verify hotkey sig");
        assert!(hk_vr.valid);

        if let Some(h) = original_home {
            std::env::set_var("HOME", &h);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── --force / overwrite guard tests ───────────────────────────────
    //
    // These tests share the same shape as the other HOME-mutating tests:
    // take HOME_LOCK, point HOME at a fresh temp directory, exercise the
    // command, then restore HOME and blow the temp directory away. They
    // cover the three interesting points of the guard_overwrite matrix
    // for each subcommand:
    //
    //   1. no flag + no existing file → success (baseline)
    //   2. no flag + existing file    → error (issue #7 root cause)
    //   3. --force  + existing file   → success with a new ss58
    //
    // The fourth point (--force + no existing file) is implicitly
    // covered by case 3 — guard_overwrite short-circuits when the file
    // is absent regardless of the force flag.

    /// Helper: seat the config-dir env vars at a fresh temp dir and
    /// return the temp path. The caller is responsible for restoring
    /// HOME and removing the dir.
    fn seat_home(tag: &str) -> (PathBuf, Option<String>) {
        let tmp = std::env::temp_dir().join(format!(
            "btt-force-{}-{}-{}",
            tag,
            std::process::id(),
            // Distinct-per-test nonce: we never want two tests to alias
            // each other's wallet dir if HOME_LOCK is ever relaxed.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let original_home = std::env::var("HOME").ok();
        std::fs::create_dir_all(&tmp).expect("create tmp root");
        let _ = seat_home_env(&tmp);
        (tmp, original_home)
    }

    fn restore_home(tmp: PathBuf, original: Option<String>) {
        if let Some(h) = original {
            std::env::set_var("HOME", &h);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// Pull the error out of a `Result<T, BttError>` without requiring
    /// `T: Debug` (which our public result types deliberately do not
    /// implement — they carry secret_phrase/secret_seed). Panics with a
    /// custom message if the result is `Ok`.
    fn unwrap_err<T>(r: Result<T, BttError>, ctx: &str) -> BttError {
        match r {
            Ok(_) => panic!("{ctx}: expected error, got Ok"),
            Err(e) => e,
        }
    }

    #[test]
    fn new_coldkey_no_flag_no_file_succeeds() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("nc-ok");

        let result = new_coldkey("w", 12, "pw", false);

        restore_home(tmp, original);
        let result = result.expect("no existing file → should succeed");
        assert!(result.ss58_address.starts_with('5'));
    }

    #[test]
    fn new_coldkey_no_flag_existing_file_errors() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("nc-refuse");

        let first = new_coldkey("w", 12, "pw", false).expect("first create");
        // Second call without --force must refuse and must not touch the
        // existing file. We verify the error is an invalid_input naming
        // the target path, then re-read the wallet dir and confirm the
        // original ss58 is untouched.
        let second = new_coldkey("w", 12, "pw", false);

        let wdir = test_wallets_parent(&tmp).join("w");
        let coldkey_exists = wdir.join("coldkey").exists();
        let pub_after = std::fs::read_to_string(wdir.join("coldkeypub.txt")).ok();

        restore_home(tmp, original);
        assert!(coldkey_exists, "refusal path must preserve existing coldkey");
        let err = unwrap_err(second, "existing file + no force");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("coldkey"),
            "error message should mention coldkey, got: {msg}"
        );
        assert!(
            msg.contains("--force"),
            "error message should mention --force, got: {msg}"
        );
        // coldkeypub.txt should still point at the first key (its JSON
        // content will contain the first ss58).
        let pub_after = pub_after.expect("coldkeypub.txt preserved");
        assert!(
            pub_after.contains(&first.ss58_address),
            "pubkey file should still contain the original ss58"
        );
    }

    #[test]
    fn new_coldkey_force_replaces_existing() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("nc-force");

        let first = new_coldkey("w", 12, "pw", false).expect("first create");
        let second = new_coldkey("w", 12, "pw", true);

        restore_home(tmp, original);
        let second = second.expect("--force + existing file → should succeed");
        assert_ne!(
            first.ss58_address, second.ss58_address,
            "force must yield a fresh keypair"
        );
        assert!(second.ss58_address.starts_with('5'));
    }

    #[test]
    fn new_hotkey_no_flag_no_file_succeeds() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("nh-ok");

        // new_hotkey needs the wallet dir to exist, so bootstrap with a
        // coldkey first.
        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        let result = new_hotkey("w", "default", 12, false);

        restore_home(tmp, original);
        let result = result.expect("no existing hotkey → should succeed");
        assert!(result.ss58_address.starts_with('5'));
    }

    #[test]
    fn new_hotkey_no_flag_existing_file_errors() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("nh-refuse");

        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        let first = new_hotkey("w", "default", 12, false).expect("first hotkey");
        let second = new_hotkey("w", "default", 12, false);

        let wdir = test_wallets_parent(&tmp).join("w");
        let hotkey_file = wdir.join("hotkeys").join("default");
        let preserved = std::fs::read_to_string(&hotkey_file).ok();

        restore_home(tmp, original);
        let err = unwrap_err(second, "existing hotkey + no force");
        let msg = format!("{err:?}");
        assert!(msg.contains("hotkey"), "error should mention hotkey: {msg}");
        assert!(msg.contains("--force"), "error should mention --force: {msg}");
        // The on-disk hotkey JSON must still carry the original ss58.
        let preserved = preserved.expect("hotkey file preserved");
        assert!(
            preserved.contains(&first.ss58_address),
            "refusal path must preserve the original hotkey"
        );
    }

    #[test]
    fn new_hotkey_force_replaces_existing() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("nh-force");

        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        let first = new_hotkey("w", "default", 12, false).expect("first hotkey");
        let second = new_hotkey("w", "default", 12, true);

        restore_home(tmp, original);
        let second = second.expect("--force + existing hotkey → should succeed");
        assert_ne!(
            first.ss58_address, second.ss58_address,
            "force must yield a fresh hotkey"
        );
    }

    #[test]
    fn regen_coldkey_no_flag_existing_file_errors() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("rc-refuse");

        let first = new_coldkey("w", 12, "pw", false).expect("first create");
        // Use the freshly generated mnemonic to drive regen; we don't care
        // about the identity it produces, only that regen refuses.
        let phrase = first.mnemonic.clone();
        let second = regen_coldkey("w", Some(&phrase), None, "pw", false);

        restore_home(tmp, original);
        let err = unwrap_err(second, "existing coldkey + no force (regen)");
        let msg = format!("{err:?}");
        assert!(msg.contains("coldkey"), "error should mention coldkey: {msg}");
        assert!(msg.contains("--force"), "error should mention --force: {msg}");
    }

    #[test]
    fn regen_coldkey_force_replaces_existing() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("rc-force");

        let first = new_coldkey("w", 12, "pw", false).expect("first create");
        // Regen from the *same* mnemonic under --force and assert the
        // operation succeeds and reproduces the same ss58 (mnemonic is
        // deterministic). This is also a lightweight sanity check that
        // the force path is not accidentally generating a different key.
        let regen = regen_coldkey("w", Some(&first.mnemonic), None, "pw", true);

        restore_home(tmp, original);
        let regen = regen.expect("--force + existing coldkey → should succeed");
        assert_eq!(
            regen.ss58_address, first.ss58_address,
            "regen from same mnemonic should reproduce the ss58"
        );
    }

    #[test]
    fn regen_coldkey_no_flag_no_file_succeeds() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("rc-ok");

        // Produce a mnemonic outside the HOME-scoped wallet dir so we can
        // drive regen without having first written a coldkey.
        let (_pair, phrase, _seed) = generate_keypair(12).expect("gen");

        let result = regen_coldkey("w", Some(&phrase), None, "pw", false);

        restore_home(tmp, original);
        let _result = result.expect("no existing file + no force → should succeed");
    }

    #[test]
    fn regen_hotkey_no_flag_existing_file_errors() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("rh-refuse");

        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        let first = new_hotkey("w", "default", 12, false).expect("first hotkey");
        let second = regen_hotkey("w", "default", Some(&first.mnemonic), None, false);

        restore_home(tmp, original);
        let err = unwrap_err(second, "existing hotkey + no force (regen)");
        let msg = format!("{err:?}");
        assert!(msg.contains("hotkey"), "error should mention hotkey: {msg}");
        assert!(msg.contains("--force"), "error should mention --force: {msg}");
    }

    #[test]
    fn regen_hotkey_force_replaces_existing() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("rh-force");

        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        let first = new_hotkey("w", "default", 12, false).expect("first hotkey");
        let regen = regen_hotkey("w", "default", Some(&first.mnemonic), None, true);

        restore_home(tmp, original);
        let regen = regen.expect("--force + existing hotkey → should succeed");
        assert_eq!(
            regen.ss58_address, first.ss58_address,
            "regen from same mnemonic should reproduce the hotkey ss58"
        );
    }

    #[test]
    fn regen_hotkey_no_flag_no_file_succeeds() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("rh-ok");

        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        // Bootstrap wallet dir exists via new_coldkey; no hotkey yet.
        let (_pair, phrase, _seed) = generate_keypair(12).expect("gen");
        let result = regen_hotkey("w", "default", Some(&phrase), None, false);

        restore_home(tmp, original);
        let _result = result.expect("no existing hotkey → should succeed");
    }

    // ── wallet create --force / overwrite guard tests (issue #19) ─────
    //
    // Before this guard, `wallet create` silently destroyed an existing
    // wallet at the target path because `write_secure_file` unlinks
    // before re-creating. These three tests cover the same matrix as the
    // single-key guards above, plus a byte-for-byte preservation check
    // on the refusal path — a user who mis-types a wallet name must not
    // lose key material.

    #[test]
    fn wallet_create_no_flag_no_file_succeeds() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("wc-ok");

        let result = create("w", "default", 12, "pw", false);

        restore_home(tmp, original);
        let result = result.expect("no existing wallet → should succeed");
        assert!(result.coldkey_ss58.starts_with('5'));
        assert!(result.hotkey_ss58.starts_with('5'));
    }

    #[test]
    fn wallet_create_no_flag_existing_wallet_errors_and_preserves_bytes() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("wc-refuse");

        let first = create("w", "default", 12, "pw", false).expect("first create");

        // Snapshot the on-disk wallet files BEFORE the second call so we
        // can prove byte-for-byte preservation if the guard fires.
        let wdir = test_wallets_parent(&tmp).join("w");
        let coldkey_path = wdir.join("coldkey");
        let hotkey_path = wdir.join("hotkeys").join("default");
        let pub_path = wdir.join("coldkeypub.txt");
        let coldkey_before = std::fs::read(&coldkey_path).expect("read coldkey");
        let hotkey_before = std::fs::read(&hotkey_path).expect("read hotkey");
        let pub_before = std::fs::read(&pub_path).expect("read pub");

        // Second call without --force must refuse.
        let second = create("w", "default", 12, "pw", false);

        // Re-read the files and compare byte-for-byte.
        let coldkey_after = std::fs::read(&coldkey_path).expect("re-read coldkey");
        let hotkey_after = std::fs::read(&hotkey_path).expect("re-read hotkey");
        let pub_after = std::fs::read(&pub_path).expect("re-read pub");

        restore_home(tmp, original);
        let err = unwrap_err(second, "existing wallet + no force");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("refusing to overwrite existing wallet"),
            "error should name the refusal, got: {msg}"
        );
        assert!(
            msg.contains("'w'"),
            "error should quote the wallet name, got: {msg}"
        );
        assert!(
            msg.contains("coldkey"),
            "error should name the coldkey file, got: {msg}"
        );
        assert!(
            msg.contains("--force"),
            "error should mention --force, got: {msg}"
        );
        assert!(
            msg.contains("IRREVERSIBLE"),
            "error should warn about irreversibility, got: {msg}"
        );
        // Byte-for-byte preservation: the refusal path must not have
        // modified the on-disk wallet in any way.
        assert_eq!(
            coldkey_before, coldkey_after,
            "coldkey must be preserved byte-for-byte across refusal"
        );
        assert_eq!(
            hotkey_before, hotkey_after,
            "hotkey must be preserved byte-for-byte across refusal"
        );
        assert_eq!(
            pub_before, pub_after,
            "coldkeypub.txt must be preserved byte-for-byte across refusal"
        );
        // And the original ss58 must still be recoverable from the
        // preserved pub file.
        let pub_str = String::from_utf8(pub_after).expect("utf8 pub");
        assert!(
            pub_str.contains(&first.coldkey_ss58),
            "preserved coldkeypub must still carry the original ss58"
        );
    }

    #[test]
    fn wallet_create_force_replaces_existing() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("wc-force");

        let first = create("w", "default", 12, "pw", false).expect("first create");
        let second = create("w", "default", 12, "pw", true);

        restore_home(tmp, original);
        let second = second.expect("--force + existing wallet → should succeed");
        assert_ne!(
            first.coldkey_ss58, second.coldkey_ss58,
            "force must yield a fresh coldkey"
        );
        assert_ne!(
            first.hotkey_ss58, second.hotkey_ss58,
            "force must yield a fresh hotkey"
        );
        assert_ne!(
            first.mnemonic, second.mnemonic,
            "force must yield a fresh mnemonic"
        );
        assert!(second.coldkey_ss58.starts_with('5'));
        assert!(second.hotkey_ss58.starts_with('5'));
    }

    #[test]
    fn wallet_create_no_flag_existing_hotkey_only_errors() {
        // Edge case: if only the hotkey file exists (e.g. a partial
        // wallet from an aborted new-hotkey run, or user-side tampering)
        // the guard must still fire. This documents that `wallet create`
        // refuses on ANY pre-existing key file, not just a coldkey.
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("wc-hotonly");

        // Bootstrap: make a wallet dir with only a hotkey, no coldkey.
        let _cr = new_coldkey("w", 12, "pw", false).expect("bootstrap coldkey");
        let _hk = new_hotkey("w", "default", 12, false).expect("bootstrap hotkey");
        // Delete the coldkey so only the hotkey remains.
        let wdir = test_wallets_parent(&tmp).join("w");
        std::fs::remove_file(wdir.join("coldkey")).expect("rm coldkey");
        std::fs::remove_file(wdir.join("coldkeypub.txt")).expect("rm coldkeypub");

        let second = create("w", "default", 12, "pw", false);

        restore_home(tmp, original);
        let err = unwrap_err(second, "existing hotkey only + no force");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("hotkey"),
            "error should name the hotkey file, got: {msg}"
        );
        assert!(
            msg.contains("--force"),
            "error should mention --force, got: {msg}"
        );
    }

    #[test]
    fn regen_coldkey_from_mnemonic() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = std::env::temp_dir().join(format!("btt-test-regen-{}", std::process::id()));
        let wallet_name = "regen-test";

        let original_home = std::env::var("HOME").ok();
        std::fs::create_dir_all(&tmp).expect("create tmp root");
        let _wallets_parent = seat_home_env(&tmp);

        let password = "regen-pw";
        let cr = create(wallet_name, "default", 12, password, false).expect("create should work");

        // Regenerate the coldkey from the mnemonic. The wallet dir already
        // holds a `coldkey` file from `create` above, so we must pass
        // force=true or the guard would (correctly) refuse.
        let regen = regen_coldkey(wallet_name, Some(&cr.mnemonic), None, password, true)
            .expect("regen should work");
        assert_eq!(regen.ss58_address, cr.coldkey_ss58);

        // Sign with the regenerated coldkey and verify
        let sign_result =
            sign(wallet_name, "default", "regen-msg", false, Some(password)).expect("sign regen");
        let vr = verify("regen-msg", &sign_result.signature, &sign_result.ss58_address)
            .expect("verify regen sig");
        assert!(vr.valid);
        assert_eq!(sign_result.ss58_address, cr.coldkey_ss58);

        if let Some(h) = original_home {
            std::env::set_var("HOME", &h);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Atomic wallet create tests (issue #29) ────────────────────────
    //
    // The stage-and-rename path writes all three wallet artifacts into a
    // `<wallets>/.tmp.<name>.<pid>.<nanos>/` staging directory and then
    // `rename`s that directory into place. These tests cover:
    //
    //   1. Success path leaves a fully-populated target dir and no
    //      leftover staging dirs.
    //   2. Failure path (synthetic, via BTT_FAIL_AFTER_HOTKEY_WRITE) leaves
    //      neither the target dir nor any leftover staging dir on disk.
    //      The test only asserts the target-dir-absence invariant; the
    //      staging dir itself gets `remove_dir_all`'d on the error path.
    //   3. `wallet list` skips `.tmp.*` entries so a stale staging dir
    //      does not surface as a real wallet in the CLI listing.
    //
    // All three tests share the HOME_LOCK because they mutate HOME /
    // XDG_CONFIG_HOME. BTT_FAIL_AFTER_HOTKEY_WRITE is also a process-
    // global env var, so holding HOME_LOCK implicitly serializes access
    // to that too.

    /// Enumerate any `.tmp.*` directories that were left inside the
    /// wallets root. Used by the post-success assertion and the
    /// post-failure assertion to prove the staging dir was removed.
    fn stale_tmp_dirs(wallets_parent: &std::path::Path) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(wallets_parent) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with(".tmp.") {
                    out.push(name);
                }
            }
        }
        out
    }

    #[test]
    fn wallet_create_atomic_on_success() {
        // Sanity: the atomic stage-and-rename path still produces the
        // expected three files in the target dir, and only those files.
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("atomic-ok");

        let result = create("atomic-ok", "default", 12, "pw", false);

        let wallets_parent = test_wallets_parent(&tmp);
        let wdir = wallets_parent.join("atomic-ok");
        let coldkey_exists = wdir.join("coldkey").exists();
        let coldkeypub_exists = wdir.join("coldkeypub.txt").exists();
        let hotkey_exists = wdir.join("hotkeys").join("default").exists();

        restore_home(tmp, original);
        result.expect("create should work");
        assert!(coldkey_exists, "coldkey must exist after success");
        assert!(coldkeypub_exists, "coldkeypub.txt must exist after success");
        assert!(hotkey_exists, "hotkey must exist after success");
    }

    #[test]
    fn wallet_create_no_temp_dir_after_success() {
        // After a successful create, the sibling `.tmp.*` staging dir
        // must have been renamed into place — there should be nothing
        // starting with `.tmp.` left under `<wallets>/`.
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("atomic-clean");

        let _cr = create("atomic-clean", "default", 12, "pw", false)
            .expect("create should work");

        let wallets_parent = test_wallets_parent(&tmp);
        let leftover = stale_tmp_dirs(&wallets_parent);

        restore_home(tmp, original);
        assert!(
            leftover.is_empty(),
            "no .tmp.* staging dirs should remain after success, found: {leftover:?}"
        );
    }

    #[test]
    fn wallet_create_failure_leaves_no_partial() {
        // Inject a failure after the hotkey write via the
        // BTT_FAIL_AFTER_HOTKEY_WRITE env var (test-only hook). The
        // staging dir is fully populated by the time the synthetic
        // error fires, and we must observe:
        //   1. the target `<wallets>/<name>` dir does NOT exist, and
        //   2. no `.tmp.*` staging dir is left behind.
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("atomic-fail");

        std::env::set_var("BTT_FAIL_AFTER_HOTKEY_WRITE", "1");
        let result = create("atomic-fail", "default", 12, "pw", false);
        std::env::remove_var("BTT_FAIL_AFTER_HOTKEY_WRITE");

        let wallets_parent = test_wallets_parent(&tmp);
        let wdir = wallets_parent.join("atomic-fail");
        let target_exists = wdir.exists();
        let leftover = stale_tmp_dirs(&wallets_parent);

        restore_home(tmp, original);
        let err = unwrap_err(result, "BTT_FAIL_AFTER_HOTKEY_WRITE should fail create");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("BTT_FAIL_AFTER_HOTKEY_WRITE"),
            "error should carry the synthetic tag, got: {msg}"
        );
        assert!(
            !target_exists,
            "target wallet dir must not exist after a staged-create failure"
        );
        assert!(
            leftover.is_empty(),
            "no .tmp.* staging dirs should remain after failure, found: {leftover:?}"
        );
    }

    #[test]
    fn wallet_list_skips_temp_dirs() {
        // Plant a `.tmp.*` directory manually inside `<wallets>/` and
        // confirm `wallet::list` does not surface it. This guards against
        // a future refactor that stops filtering dotfile-prefixed
        // entries.
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("atomic-list");

        // Create a real wallet so `list` has at least one entry to
        // compare against, and a sibling `.tmp.*` dir that should be
        // invisible to `list`.
        let _cr = create("real", "default", 12, "pw", false).expect("create");
        let wallets_parent = test_wallets_parent(&tmp);
        let stale = wallets_parent.join(".tmp.real.99999.123456789");
        std::fs::create_dir_all(&stale).expect("plant stale tmp dir");
        std::fs::write(stale.join("coldkeypub.txt"), "{}")
            .expect("plant stale coldkeypub");

        let listing = crate::commands::wallet::list().expect("wallet list");
        let names: Vec<&str> = listing.wallets.iter().map(|w| w.name.as_str()).collect();

        restore_home(tmp, original);
        assert!(names.contains(&"real"), "real wallet should be listed: {names:?}");
        assert!(
            !names.iter().any(|n| n.starts_with(".tmp.")),
            "wallet list must skip .tmp.* staging dirs, got: {names:?}"
        );
    }

    // ── Round-2 force-path atomicity tests (PR #40 reviewer findings) ─
    //
    // These tests target the HIGH finding from the Round-1 review: the
    // original `promote_staged_into_existing` moved three files
    // sequentially into the target dir, so a failure after the first
    // rename left the coldkey replaced with the new one while the new
    // hotkey was still missing. The fix is a rename-based backup-and-
    // publish algorithm; these tests pin the new behavior.

    #[test]
    fn wallet_create_force_atomic_on_failure() {
        // Inject a failure INSIDE promote_staged_into_existing, AFTER
        // the backup rename and AFTER the staging rename but BEFORE
        // the unrelated-hotkey merge. Under the new algorithm, the
        // atomic publish has succeeded by the time the hook fires, so
        // the test actually validates the other half of the invariant:
        // a failure after publish still leaves the new wallet live and
        // readable, and the backup dir with any unrelated hotkeys is
        // still reachable on disk.
        //
        // This is the counterpart to `wallet_create_force_partial_
        // promote_failure_keeps_old` below, which tests the failure
        // path BEFORE the publish.
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("atomic-force-fail");

        // Round 1: create a wallet with two hotkeys — `default` (which
        // the Round 2 force-overwrite will replace) and `keeper`
        // (which must survive into the new wallet via the hotkey
        // merge, unless the injected failure aborts the merge).
        let first =
            create("w", "default", 12, "pw", false).expect("first create");
        let _keeper = new_hotkey("w", "keeper", 12, false).expect("bootstrap keeper hotkey");

        // Round 2: force-create the same wallet, with the failure hook
        // armed so that promote_staged_into_existing returns after the
        // atomic publish but before the hotkey merge.
        std::env::set_var("BTT_FAIL_DURING_PROMOTE", "1");
        let result = create("w", "default", 12, "pw", true);
        std::env::remove_var("BTT_FAIL_DURING_PROMOTE");

        let wallets_parent = test_wallets_parent(&tmp);
        let wdir = wallets_parent.join("w");
        let coldkey_exists = wdir.join("coldkey").exists();
        let new_hotkey_exists = wdir.join("hotkeys").join("default").exists();
        // The new wallet on disk must carry the NEW coldkey ss58, not
        // the old one — the atomic publish succeeded before the hook.
        let pub_after = std::fs::read_to_string(wdir.join("coldkeypub.txt")).ok();
        let bak_dirs = stale_bak_dirs(&wallets_parent);
        let tmp_dirs = stale_tmp_dirs(&wallets_parent);

        restore_home(tmp, original);

        let err = unwrap_err(result, "BTT_FAIL_DURING_PROMOTE should fail create");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("BTT_FAIL_DURING_PROMOTE"),
            "error should carry the synthetic tag, got: {msg}"
        );
        // Atomic publish must have already occurred by the time the hook
        // fires, so the target dir is fully populated with the new key
        // files.
        assert!(coldkey_exists, "new coldkey must exist (atomic publish done)");
        assert!(new_hotkey_exists, "new hotkey must exist (atomic publish done)");
        // No leftover staging dir (it was renamed into place).
        assert!(
            tmp_dirs.is_empty(),
            "no .tmp.* should remain after promote-fail, got: {tmp_dirs:?}"
        );
        // The pubkey file on disk must reflect the NEW coldkey — the
        // old one no longer exists anywhere reachable from
        // `wdir/coldkeypub.txt`. This is the key invariant: the force
        // path did NOT leave a half-written wallet.
        let pub_after = pub_after.expect("coldkeypub.txt present");
        assert!(
            !pub_after.contains(&first.coldkey_ss58),
            "post-failure coldkeypub must NOT carry the pre-overwrite ss58"
        );
        // The backup dir containing the `keeper` hotkey (which was
        // never merged because the hook fired first) is still on disk.
        // A failed merge is recoverable — the user can rescue unrelated
        // hotkeys from the `.bak.*` dir manually.
        assert_eq!(
            bak_dirs.len(),
            1,
            ".bak.* dir must remain on disk for manual recovery, got: {bak_dirs:?}"
        );
    }

    #[test]
    fn wallet_create_force_partial_promote_failure_keeps_old() {
        // The Round-1 reviewer's planted-file PoC proved the OLD
        // sequential-rename algorithm half-wrote the wallet on a mid-
        // sequence failure. Under the NEW backup-and-rename algorithm,
        // that exact PoC (planting a directory at coldkeypub.txt to
        // force EISDIR in the second rename) is no longer reachable
        // — the publish is a single directory-level rename, not a
        // sequence of file renames. So this test pins the NEW
        // invariant: if the publish rename fails (for any reason),
        // promote rolls the backup rename back and the original
        // wallet is preserved byte-for-byte.
        //
        // We drive the publish failure via the `BTT_FAIL_BEFORE_PUBLISH`
        // test hook. It short-circuits `fs::rename(staging, target)`
        // with a synthetic `io::Error` AFTER the backup rename has
        // already succeeded, which is exactly the PoC shape the Round-1
        // reviewer flagged — "first rename succeeds, second rename
        // fails". The test asserts:
        //
        //   1. create returns Err (no silent success);
        //   2. the coldkey/hotkey/coldkeypub bytes on disk are
        //      identical to the pre-sabotage snapshot (rollback ran);
        //   3. the preserved coldkeypub still carries the original
        //      ss58 (not the new one from the aborted second create);
        //   4. no stale `.bak.*` or `.tmp.*` dirs remain.
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("force-partial-fail");

        let first =
            create("w", "default", 12, "pw", false).expect("first create");
        let wallets_parent = test_wallets_parent(&tmp);
        let wdir = wallets_parent.join("w");
        let coldkey_before =
            std::fs::read(wdir.join("coldkey")).expect("read coldkey");
        let hotkey_before = std::fs::read(wdir.join("hotkeys").join("default"))
            .expect("read hotkey");
        let pub_before =
            std::fs::read(wdir.join("coldkeypub.txt")).expect("read coldkeypub");

        std::env::set_var("BTT_FAIL_BEFORE_PUBLISH", "1");
        let second = create("w", "default", 12, "pw", true);
        std::env::remove_var("BTT_FAIL_BEFORE_PUBLISH");

        // Byte-for-byte preservation check on the original wallet.
        let coldkey_after =
            std::fs::read(wdir.join("coldkey")).expect("re-read coldkey");
        let hotkey_after = std::fs::read(wdir.join("hotkeys").join("default"))
            .expect("re-read hotkey");
        let pub_after =
            std::fs::read(wdir.join("coldkeypub.txt")).expect("re-read pub");
        let bak_leftover = stale_bak_dirs(&wallets_parent);
        let tmp_leftover = stale_tmp_dirs(&wallets_parent);

        restore_home(tmp, original);

        let err = unwrap_err(second, "BTT_FAIL_BEFORE_PUBLISH should fail create");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("BTT_FAIL_BEFORE_PUBLISH"),
            "error should carry the synthetic tag, got: {msg}"
        );
        assert_eq!(
            coldkey_before, coldkey_after,
            "original coldkey must be preserved byte-for-byte under promote rollback"
        );
        assert_eq!(
            hotkey_before, hotkey_after,
            "original hotkey must be preserved byte-for-byte under promote rollback"
        );
        assert_eq!(
            pub_before, pub_after,
            "original coldkeypub must be preserved byte-for-byte under promote rollback"
        );
        let pub_str = String::from_utf8(pub_after).expect("utf8");
        assert!(
            pub_str.contains(&first.coldkey_ss58),
            "preserved coldkeypub must still carry the original ss58"
        );
        assert!(
            bak_leftover.is_empty(),
            "no .bak.* should remain after successful rollback, got: {bak_leftover:?}"
        );
        assert!(
            tmp_leftover.is_empty(),
            "no .tmp.* should remain after successful rollback, got: {tmp_leftover:?}"
        );
    }

    #[test]
    fn wallet_create_rejects_reserved_prefix() {
        // `.tmp.`, `.bak.`, and `.lock.` are reserved for staging,
        // backup, and lock sentinel files. A user-facing wallet with
        // any of these prefixes would be invisible to `wallet list`
        // (the list path filters them), so `create` must refuse the
        // name at the door — before validate_n_words, before any key
        // material is generated.
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("reserved-prefix");

        let tmp_result = create(".tmp.foo", "default", 12, "pw", false);
        let bak_result = create(".bak.foo", "default", 12, "pw", false);
        let lock_result = create(".lock.foo", "default", 12, "pw", false);

        restore_home(tmp, original);

        let tmp_err = unwrap_err(tmp_result, ".tmp. name should be rejected");
        let tmp_msg = format!("{tmp_err:?}");
        assert!(
            tmp_msg.contains("reserved prefix"),
            "error should mention reserved prefix, got: {tmp_msg}"
        );
        assert!(
            tmp_msg.contains(".tmp."),
            "error should quote the .tmp. prefix, got: {tmp_msg}"
        );

        let bak_err = unwrap_err(bak_result, ".bak. name should be rejected");
        let bak_msg = format!("{bak_err:?}");
        assert!(
            bak_msg.contains("reserved prefix"),
            "error should mention reserved prefix, got: {bak_msg}"
        );
        assert!(
            bak_msg.contains(".bak."),
            "error should quote the .bak. prefix, got: {bak_msg}"
        );

        let lock_err = unwrap_err(lock_result, ".lock. name should be rejected");
        let lock_msg = format!("{lock_err:?}");
        assert!(
            lock_msg.contains("reserved prefix"),
            "error should mention reserved prefix, got: {lock_msg}"
        );
        assert!(
            lock_msg.contains(".lock."),
            "error should quote the .lock. prefix, got: {lock_msg}"
        );
        assert!(
            matches!(lock_err.code, crate::error::ErrorCode::InvalidInput),
            "reject should be invalid_input, got: {lock_err:?}"
        );
    }

    // ── flock(2) concurrency tests (issue #41) ───────────────────────
    //
    // These tests pin the per-wallet `flock(LOCK_EX)` serialization
    // added in response to the round-2 concurrent-`--force` race.
    // They all take `HOME_LOCK` because they mutate HOME / XDG env
    // vars, and they use `std::thread::scope` + `std::sync::Barrier`
    // to coordinate lock hand-off without spinning or sleeping.

    /// Helper: open (or create) the per-wallet lock file and acquire
    /// `LOCK_EX` on it, using the same code path as `create()`. Used
    /// by the flock tests to prove the lock is held or released at a
    /// given point in time.
    fn acquire_wallet_lock(wallet_name: &str) -> flock_sys::LockGuard {
        let lock_path = paths::wallets_dir()
            .expect("wallets dir")
            .join(format!(".lock.{wallet_name}"));
        let mut open = fs::OpenOptions::new();
        open.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            open.mode(0o600);
        }
        let file = open.open(&lock_path).expect("open lock file");
        flock_sys::LockGuard::acquire(file).expect("flock LOCK_EX")
    }

    #[cfg(unix)]
    #[test]
    fn wallet_create_acquires_lock() {
        // Background thread grabs the per-wallet lock and holds it
        // for ~200ms, then releases. The main thread calls `create`
        // and must block until the background thread lets go. We
        // measure elapsed wall time to confirm the blocking actually
        // occurred (a lock-free implementation would return in ~0ms).
        use std::sync::Barrier;
        use std::time::{Duration, Instant};

        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("flock-acquires");

        let wallet_name = "w-flock-acq";
        let barrier = Barrier::new(2);
        let result: Result<CreateResult, BttError> = std::thread::scope(|s| {
            let bg = s.spawn(|| {
                // Acquire the lock, signal the main thread, sleep,
                // release. The drop at the end of this closure is
                // what releases the flock.
                let _held = acquire_wallet_lock(wallet_name);
                barrier.wait();
                std::thread::sleep(Duration::from_millis(200));
            });
            // Wait until the background thread has the lock.
            barrier.wait();
            let start = Instant::now();
            let r = create(wallet_name, "default", 12, "pw", false);
            let elapsed = start.elapsed();
            bg.join().expect("bg thread");
            // The create call should have blocked for at least most
            // of the 200ms sleep. Use a slack of 100ms to absorb
            // scheduler jitter.
            assert!(
                elapsed >= Duration::from_millis(100),
                "create should have blocked on the flock for ~200ms, \
                 observed {elapsed:?}"
            );
            r
        });

        restore_home(tmp, original);
        let cr = result.expect("create should succeed once lock releases");
        assert!(cr.coldkey_ss58.starts_with('5'));
    }

    #[cfg(unix)]
    #[test]
    fn wallet_create_releases_lock_on_success() {
        // After a successful `create`, a second `flock(LOCK_EX)` call
        // must acquire immediately (no blocking). If the first call
        // leaked the lock, the second acquisition would block forever;
        // we use a thread with a short timeout via a channel to catch
        // that case.
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("flock-release-ok");

        let wallet_name = "w-flock-rel-ok";
        let result = create(wallet_name, "default", 12, "pw", false);

        // Second thread: try to acquire the lock. On success it
        // sends `()`. The main thread waits with a 2s timeout; if
        // it times out the first create must have leaked the lock.
        let (tx, rx) = mpsc::channel();
        let name_owned = wallet_name.to_string();
        let handle = std::thread::spawn(move || {
            let start = Instant::now();
            let _held = acquire_wallet_lock(&name_owned);
            let _ = tx.send(start.elapsed());
            // Drop the guard here, releasing the lock.
        });
        let elapsed = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("lock must be free after successful create");
        handle.join().expect("thread");

        restore_home(tmp, original);
        let _cr = result.expect("create should succeed");
        // Sanity: the second acquisition should be effectively
        // instant — if it took more than 500ms the kernel is under
        // suspicious load, but don't fail the test on that alone.
        assert!(
            elapsed < Duration::from_secs(1),
            "lock reacquire took {elapsed:?}, expected near-zero"
        );
    }

    #[cfg(unix)]
    #[test]
    fn wallet_create_releases_lock_on_error() {
        // Same shape as the success test, but trigger an error inside
        // the create path via `BTT_FAIL_BEFORE_PUBLISH`. The lock must
        // still be released when the error propagates out of `create`.
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("flock-release-err");

        let wallet_name = "w-flock-rel-err";
        // First create to populate the target so the --force path
        // triggers and promote_staged_into_existing runs (which is
        // where BTT_FAIL_BEFORE_PUBLISH fires).
        let _first = create(wallet_name, "default", 12, "pw", false)
            .expect("baseline create");

        std::env::set_var("BTT_FAIL_BEFORE_PUBLISH", "1");
        let result = create(wallet_name, "default", 12, "pw", true);
        std::env::remove_var("BTT_FAIL_BEFORE_PUBLISH");

        // Now attempt to re-acquire the lock from another thread —
        // if the error path leaked the lock, this will hang.
        let (tx, rx) = mpsc::channel();
        let name_owned = wallet_name.to_string();
        let handle = std::thread::spawn(move || {
            let start = Instant::now();
            let _held = acquire_wallet_lock(&name_owned);
            let _ = tx.send(start.elapsed());
        });
        let elapsed = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("lock must be free after errored create");
        handle.join().expect("thread");

        restore_home(tmp, original);
        let err = unwrap_err(result, "BTT_FAIL_BEFORE_PUBLISH should error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("BTT_FAIL_BEFORE_PUBLISH"),
            "expected synthetic failure in error, got: {msg}"
        );
        assert!(
            elapsed < Duration::from_secs(1),
            "lock reacquire took {elapsed:?}, expected near-zero"
        );
    }

    #[cfg(unix)]
    #[test]
    fn wallet_list_skips_lock_files() {
        // Plant a `.lock.example` file manually inside `<wallets>/`
        // and confirm `wallet::list` does not surface it. The file
        // filter (`!path.is_dir()`) is the first line of defense, but
        // we still keep the explicit `.lock.*` skip for defense in
        // depth.
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, original) = seat_home("flock-list-skip");

        // Create a real wallet so `list` has at least one entry.
        let _cr = create("real", "default", 12, "pw", false).expect("create");
        let wallets_parent = test_wallets_parent(&tmp);
        let lock_file = wallets_parent.join(".lock.example");
        std::fs::write(&lock_file, b"").expect("plant lock file");

        let listing = crate::commands::wallet::list().expect("wallet list");
        let names: Vec<&str> = listing.wallets.iter().map(|w| w.name.as_str()).collect();

        restore_home(tmp, original);
        assert!(
            names.contains(&"real"),
            "real wallet should still be listed: {names:?}"
        );
        assert!(
            !names.iter().any(|n| n.starts_with(".lock.")),
            "wallet list must skip .lock.* files, got: {names:?}"
        );
    }

    /// Enumerate any `.bak.*` directories left inside the wallets
    /// root. Counterpart to `stale_tmp_dirs`.
    fn stale_bak_dirs(wallets_parent: &std::path::Path) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(wallets_parent) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if name.starts_with(".bak.") {
                    out.push(name);
                }
            }
        }
        out
    }

    // ── Issue #9 hygiene regression tests ────────────────────────────────
    //
    // NEW-L1 / L2 / L3 from the PR #3 round-2 review. These pin three small
    // but distinct behaviors:
    //   1. `write_secure_file` succeeds end-to-end with the parent-dir fsync
    //      addition (we cannot directly assert durability without a crash
    //      injection harness, so we settle for "the happy path still works").
    //   2. A poisoned `HOME_LOCK` does not wedge subsequent tests.
    //   3. `coldkeypub.txt` lands at exactly 0644 regardless of umask.

    /// NEW-L1: `write_secure_file` must still return `Ok` on a basic write
    /// after the parent-directory fsync addition. We cannot test actual
    /// durability under power loss without a crash injection harness; this
    /// test only covers the success path so a regression in `sync_parent_dir`
    /// (e.g., a missing parent, a permission error on the dir open) cannot
    /// silently break the main write routine.
    #[test]
    fn write_secure_file_success_path_with_parent_fsync() {
        let tmp = std::env::temp_dir().join(format!(
            "btt-wsf-parent-fsync-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&tmp).expect("create tmp");

        let target = tmp.join("secret.bin");
        let data = b"hygiene-regression-payload";
        write_secure_file(&target, data).expect("write_secure_file must succeed");

        let round_trip = std::fs::read(&target).expect("read back");
        assert_eq!(round_trip, data, "written bytes must round-trip");

        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&target)
                .expect("stat")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "secure file must land at 0600");
        }

        // Writing the same path a second time must also succeed (the
        // remove-then-create-new branch + fsync must both hold together).
        write_secure_file(&target, b"second-write").expect("second write");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// NEW-L2: if a test panics while holding `HOME_LOCK`, the lock becomes
    /// poisoned; the canonical Rust pattern is `.unwrap_or_else(|e|
    /// e.into_inner())` so the next acquisition ignores the poison flag and
    /// proceeds. This test deliberately poisons the lock from a sub-thread
    /// and then asserts a subsequent acquisition still works.
    #[test]
    fn home_lock_recovers_from_poisoning() {
        // Poison the lock by panicking inside a thread that holds it.
        let handle = std::thread::spawn(|| {
            let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            panic!("deliberate poison for NEW-L2 regression test");
        });
        // The thread must have panicked; join() returns Err.
        let join_result = handle.join();
        assert!(
            join_result.is_err(),
            "helper thread must panic to poison the lock"
        );

        // The lock is now poisoned. The old `.expect("home lock")` pattern
        // would panic here with `PoisonError`. The new pattern recovers.
        let poisoned = HOME_LOCK.lock();
        assert!(
            poisoned.is_err(),
            "lock must actually be poisoned after the helper's panic, \
             otherwise this test is not exercising the recovery path"
        );
        let _recovered = poisoned.unwrap_or_else(|e| e.into_inner());
        // If we got here, the recovery pattern works: the next test that
        // grabs HOME_LOCK via the standard idiom will not panic.
    }

    /// NEW-L3: `coldkeypub.txt` must be written at explicit mode 0644
    /// regardless of the host's umask. The contents are public so the
    /// bit that matters is consistency with the rest of the wallet dir's
    /// explicit-perms posture.
    #[cfg(unix)]
    #[test]
    fn coldkeypub_txt_mode_is_0644() {
        let _guard = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Force a loose umask so the default-umask path would land at 0666
        // and fail this assertion if `write_public_file` ever regresses
        // to `fs::write`.
        //
        // SAFETY: `umask(2)` is async-signal-safe and unconditionally
        // succeeds; no FFI safety preconditions. We declare the symbol
        // directly to avoid a `libc` dep (see PR #21 dep-discipline).
        extern "C" {
            fn umask(mask: u32) -> u32;
        }
        let old_mask = unsafe { umask(0) };

        let (tmp, original) = seat_home("coldkeypub-mode");
        let result = create("w-pub-mode", "default", 12, "pw", false);

        // Restore the umask before any assertions so a failed assertion
        // does not leak the relaxed mask to sibling tests in the same
        // process. HOME_LOCK serializes HOME-mutating tests so no other
        // test is running concurrently here, but umask is process-global.
        let _ = unsafe { umask(old_mask) };

        let _ = result.expect("wallet create must succeed");
        let wdir = wallet_path("w-pub-mode").expect("wallet_path");
        let pub_path = wdir.join("coldkeypub.txt");
        let meta = std::fs::metadata(&pub_path).expect("stat coldkeypub.txt");
        let mode = meta.permissions().mode() & 0o777;

        restore_home(tmp, original);

        assert_eq!(
            mode, 0o644,
            "coldkeypub.txt must land at exactly 0644, found 0o{mode:o}"
        );
    }
}
