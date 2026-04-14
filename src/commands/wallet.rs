use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::error::BttError;

#[derive(Serialize)]
pub struct WalletList {
    pub wallets: Vec<WalletEntry>,
}

#[derive(Serialize)]
pub struct WalletEntry {
    pub name: String,
    pub coldkey: Option<KeyInfo>,
    pub hotkeys: Vec<KeyInfo>,
}

#[derive(Serialize)]
pub struct KeyInfo {
    pub name: String,
    pub ss58_address: Option<String>,
    pub path: String,
}

/// List wallets found under `<config_dir>/wallets/` — see
/// [`crate::commands::paths::config_dir`] for the per-OS location.
/// Each wallet is a directory containing a `coldkeypub.txt` and `hotkeys/` subdirectory.
pub fn list() -> Result<WalletList, BttError> {
    let wallets_dir = wallets_path()?;

    if !wallets_dir.exists() {
        return Err(BttError::wallet_not_found(format!(
            "wallets directory not found: {}",
            wallets_dir.display()
        )));
    }

    let mut wallets = Vec::new();

    let entries = fs::read_dir(&wallets_dir)
        .map_err(|e| BttError::io(format!("failed to read wallets directory: {}", e)))?;

    for entry in entries {
        let entry = entry
            .map_err(|e| BttError::io(format!("failed to read directory entry: {}", e)))?;

        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let wallet_name = entry
            .file_name()
            .to_string_lossy()
            .to_string();

        // Skip staging, backup, and lock files left behind by
        // `wallet create`. The atomic-create path writes a sibling
        // `.tmp.<wallet>.<pid>.<nanos>.<ctr>` staging dir (issue #29),
        // the `--force` promote path writes a sibling
        // `.bak.<wallet>.<pid>.<nanos>.<ctr>` backup dir during the
        // swap (PR #40), and the per-wallet `flock(2)` sentinel lives
        // at `.lock.<wallet>` (issue #41). All three prefixes are
        // reserved — `wallet_keys::create` refuses to create a wallet
        // whose name starts with any of them. Stale `.tmp.*` / `.bak.*`
        // dirs from a crashed run and persistent `.lock.*` sentinels
        // are deliberately left on disk but must not appear in `wallet
        // list` as if they were real wallets.
        if wallet_name.starts_with(".tmp.")
            || wallet_name.starts_with(".bak.")
            || wallet_name.starts_with(".lock.")
        {
            continue;
        }

        // Read coldkeypub.txt
        let coldkey_path = path.join("coldkeypub.txt");
        let coldkey = if coldkey_path.exists() {
            Some(read_key_file(&coldkey_path, "coldkeypub")?)
        } else {
            None
        };

        // Read hotkeys
        let hotkeys_dir = path.join("hotkeys");
        let mut hotkeys = Vec::new();
        if hotkeys_dir.exists() && hotkeys_dir.is_dir() {
            let hk_entries = fs::read_dir(&hotkeys_dir)
                .map_err(|e| BttError::io(format!("failed to read hotkeys directory: {}", e)))?;

            for hk_entry in hk_entries {
                let hk_entry = hk_entry
                    .map_err(|e| BttError::io(format!("failed to read hotkey entry: {}", e)))?;
                let hk_path = hk_entry.path();
                if hk_path.is_file() {
                    let hk_name = hk_entry
                        .file_name()
                        .to_string_lossy()
                        .to_string();
                    match read_key_file(&hk_path, &hk_name) {
                        Ok(ki) => hotkeys.push(ki),
                        Err(_) => {
                            // Skip malformed hotkey files
                            hotkeys.push(KeyInfo {
                                name: hk_name,
                                ss58_address: None,
                                path: hk_path.to_string_lossy().to_string(),
                            });
                        }
                    }
                }
            }
        }

        hotkeys.sort_by(|a, b| a.name.cmp(&b.name));

        wallets.push(WalletEntry {
            name: wallet_name,
            coldkey,
            hotkeys,
        });
    }

    wallets.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(WalletList { wallets })
}

/// Get the wallets directory path. Per-OS location — see
/// [`crate::commands::paths::config_dir`].
fn wallets_path() -> Result<PathBuf, BttError> {
    crate::commands::paths::wallets_dir()
}

/// Read a Bittensor key file (JSON) and extract the SS58 address.
/// The format is typically: {"accountId": "0x...", "publicKey": "0x...", "secretPhrase": "...", "ss58Address": "5..."}
/// For public key files, it may just be the JSON with ss58Address.
fn read_key_file(path: &PathBuf, name: &str) -> Result<KeyInfo, BttError> {
    let content = fs::read_to_string(path)
        .map_err(|e| BttError::io(format!("failed to read {}: {}", path.display(), e)))?;

    let ss58 = extract_ss58_from_json(&content);

    Ok(KeyInfo {
        name: name.to_string(),
        ss58_address: ss58,
        path: path.to_string_lossy().to_string(),
    })
}

/// Try to extract ss58Address from a JSON string.
fn extract_ss58_from_json(content: &str) -> Option<String> {
    // Try to parse as JSON
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(content) {
        // Check for "ss58Address" field
        if let Some(addr) = v.get("ss58Address").and_then(|v| v.as_str()) {
            return Some(addr.to_string());
        }
        // Some files use "SS58Address"
        if let Some(addr) = v.get("SS58Address").and_then(|v| v.as_str()) {
            return Some(addr.to_string());
        }
        // Try "address"
        if let Some(addr) = v.get("address").and_then(|v| v.as_str()) {
            return Some(addr.to_string());
        }
    }

    // Some coldkeypub.txt files are just the raw SS58 address
    let trimmed = content.trim();
    if trimmed.starts_with('5') && trimmed.len() >= 47 && trimmed.len() <= 49 {
        return Some(trimmed.to_string());
    }

    None
}

// ── wallet cleanup (issue #42) ────────────────────────────────────────────
//
// `btt wallet cleanup` reaps stale staging / backup / lock artefacts left
// under `<wallets>/` by crashed or interrupted `wallet create` runs:
//
//   - `.tmp.<name>.<pid>.<nanos>.<ctr>/` staging dirs from PR #40
//   - `.bak.<name>.<pid>.<nanos>.<ctr>/` backup dirs from PR #40
//   - `.lock.<name>` per-wallet flock sentinels from PR #43
//
// All three prefixes are reserved: `wallet create` refuses to create a
// wallet whose name starts with any of them, and `wallet list` filters
// them out. The cleanup command is the explicit, opt-in sweep.
//
// Safety invariants (non-negotiable — see issue #42 and moorkh's comment):
//
// 1. Only entries whose file name matches the exact reserved-prefix
//    grammar are candidates. A lookalike like `.tmp.foo` (no numeric
//    suffix triple) is NOT touched — it is reported `skipped-no-match`.
//    The grammar lives in [`parse_reserved_entry`] below.
//
// 2. Symlinks are never followed. We `fs::symlink_metadata` the entry
//    and only reap if the metadata says it's a plain directory
//    (for `.tmp.*` / `.bak.*`) or a plain file (for `.lock.*`).
//    A symlink matching the prefix pattern is `skipped-no-match`.
//
// 3. `.lock.*` files are probed with a non-blocking `flock(LOCK_EX |
//    LOCK_NB)` before unlink. If the lock is currently held by another
//    process, `LOCK_NB` returns `EWOULDBLOCK` and we record
//    `skipped-held` — never unlinking a held lock would race any
//    concurrent `wallet create` that depends on it. If the non-blocking
//    acquisition succeeds, the lock is unheld; we release it with
//    `LOCK_UN` and unlink the file. See `cleanup_flock` below.
//
// 4. The scan covers exactly the immediate children of `<wallets>/`.
//    We never recurse into subdirectories hunting for stale entries —
//    the staging/backup/lock dirs only ever live as top-level siblings
//    of real wallet dirs.
//
// 5. When `--wallet <name>` is passed, the name is validated against the
//    same grammar as a wallet name before being interpolated into the
//    match. This rejects path-traversal (`..`, `/`), NUL bytes, and
//    anything that would blow past the reserved-prefix pattern.

/// One scan-result entry.
#[derive(Serialize, Debug, Clone)]
pub struct CleanupEntry {
    /// Absolute path of the candidate on disk.
    pub path: String,
    /// Which of the three reserved prefixes matched.
    pub kind: CleanupKind,
    /// What happened (or would have happened) to the candidate.
    pub action: CleanupAction,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CleanupKind {
    Tmp,
    Bak,
    Lock,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CleanupAction {
    /// Entry was removed from disk.
    Reaped,
    /// Entry matched all filters but `--dry-run` was set.
    KeptDryRun,
    /// `.lock.*` candidate, but another process holds the advisory lock.
    SkippedHeld,
    /// `--older-than` was set and the entry's mtime is newer than the cutoff.
    SkippedTooYoung,
    /// The name loosely resembled a reserved prefix but did not match the
    /// exact grammar, or the entry was a symlink. Never reaped.
    SkippedNoMatch,
}

#[derive(Serialize, Debug)]
pub struct CleanupReport {
    pub entries: Vec<CleanupEntry>,
}

/// Parsed form of a reserved-prefix entry name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReservedEntry {
    kind: CleanupKind,
    /// Wallet name (the `<name>` token inside `.tmp.<name>.*` etc).
    name: String,
}

/// Parse a directory-entry file name into its [`ReservedEntry`] form.
///
/// Accepted grammars:
///
///   - `.tmp.<name>.<pid>.<nanos>.<ctr>` → kind = `Tmp`
///   - `.bak.<name>.<pid>.<nanos>.<ctr>` → kind = `Bak`
///   - `.lock.<name>`                    → kind = `Lock`
///
/// where
///
///   - `<name>` matches the wallet-name grammar: 1..=64 characters from
///     `[A-Za-z0-9_-]`. Names can contain `_` or `-`, but never
///     `.`, `/`, NUL, or anything else — that's what forces the
///     parser to stop at the first `.` after `<name>` and prevents
///     ambiguity between `<name>` and the `<pid>` that follows.
///   - `<pid>` is one or more ASCII digits.
///   - `<nanos>` is 1..=19 ASCII digits (u64 nanos-since-epoch).
///   - `<ctr>` is one or more ASCII digits (the process-local counter).
///
/// Anything that does not match returns `None`. The caller treats `None`
/// as `SkippedNoMatch` — never a candidate for `remove_dir_all`.
fn parse_reserved_entry(name: &str) -> Option<ReservedEntry> {
    // Lock files have the simplest grammar: `.lock.<name>` with no
    // trailing components. Check first so we can short-circuit.
    if let Some(rest) = name.strip_prefix(".lock.") {
        if is_valid_wallet_name(rest) {
            return Some(ReservedEntry {
                kind: CleanupKind::Lock,
                name: rest.to_string(),
            });
        }
        return None;
    }

    let (kind, rest) = if let Some(r) = name.strip_prefix(".tmp.") {
        (CleanupKind::Tmp, r)
    } else if let Some(r) = name.strip_prefix(".bak.") {
        (CleanupKind::Bak, r)
    } else {
        return None;
    };

    // `rest` is `<name>.<pid>.<nanos>.<ctr>`. Split from the right: the
    // last three dot-separated segments are the numeric suffix, and
    // everything before them is `<name>`. Splitting from the right lets
    // `<name>` contain `-` or `_` without ambiguity (it cannot contain
    // `.` — we validate that in `is_valid_wallet_name`).
    let mut tail_segments: [&str; 3] = [""; 3];
    let mut body = rest;
    for slot in tail_segments.iter_mut().rev() {
        let idx = body.rfind('.')?;
        *slot = &body[idx + 1..];
        body = &body[..idx];
    }
    // body is now <name>
    // tail_segments is [<pid>, <nanos>, <ctr>]
    let name_part = body;
    let pid = tail_segments[0];
    let nanos = tail_segments[1];
    let ctr = tail_segments[2];

    if !is_valid_wallet_name(name_part) {
        return None;
    }
    if !is_all_digits(pid) || pid.is_empty() {
        return None;
    }
    if !is_all_digits(nanos) || nanos.is_empty() || nanos.len() > 19 {
        return None;
    }
    if !is_all_digits(ctr) || ctr.is_empty() {
        return None;
    }

    Some(ReservedEntry {
        kind,
        name: name_part.to_string(),
    })
}

/// Wallet-name grammar: 1..=64 characters from `[A-Za-z0-9_-]`.
///
/// This is stricter than the (absent) validation in `wallet_keys::create`,
/// which is deliberate: cleanup is the one path that unlinks things it
/// sees on disk, so we err on the side of refusing ambiguous names.
fn is_valid_wallet_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    s.bytes().all(|b| {
        b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
    })
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Parse `--older-than <duration>` into a [`Duration`]. Accepted grammar:
/// `\d+[smhd]` — for example `60s`, `30m`, `24h`, `7d`. We deliberately
/// hand-roll rather than pull `humantime` (dep discipline).
fn parse_older_than(input: &str) -> Result<Duration, BttError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(BttError::invalid_input(
            "--older-than requires a value like 60s, 30m, 24h, or 7d",
        ));
    }
    let (num_part, unit) = match s.chars().last() {
        Some(c) if matches!(c, 's' | 'm' | 'h' | 'd') => (&s[..s.len() - 1], c),
        _ => {
            return Err(BttError::invalid_input(format!(
                "--older-than: missing unit suffix in '{}' (expected s, m, h, or d)",
                s
            )));
        }
    };
    if num_part.is_empty() || !is_all_digits(num_part) {
        return Err(BttError::invalid_input(format!(
            "--older-than: '{}' must be <digits><s|m|h|d>",
            s
        )));
    }
    let n: u64 = num_part.parse().map_err(|_| {
        BttError::invalid_input(format!(
            "--older-than: '{}' is not a non-negative integer",
            num_part
        ))
    })?;
    let secs_opt: Option<u64> = match unit {
        's' => Some(n),
        'm' => n.checked_mul(60),
        'h' => n.checked_mul(3600),
        'd' => n.checked_mul(86_400),
        _ => unreachable!("unit already validated above"),
    };
    let secs = secs_opt.ok_or_else(|| {
        BttError::invalid_input(format!("--older-than: '{}' overflows u64 seconds", s))
    })?;
    Ok(Duration::from_secs(secs))
}

/// Non-blocking `flock` probe used by the `.lock.*` reap path.
///
/// We duplicate a small extern block here rather than move
/// `wallet_keys::flock_sys` into a shared helper because the two paths
/// want different semantics:
///
///   - `wallet_keys::flock_sys::LockGuard::acquire` takes ownership of a
///     [`File`] and holds a blocking `LOCK_EX` until drop. It is a
///     guard for the wallet-create critical section.
///
///   - [`cleanup_flock::probe_unheld`] below is a one-shot non-blocking
///     probe that answers "is anyone holding this lock right now?". It
///     releases the lock before returning so the subsequent `unlink(2)`
///     does not race a would-be acquirer on another thread.
///
/// Pulling both shapes into a single module would complicate the guard
/// type with a mode parameter and make the wallet_keys::create path
/// harder to reason about. The cost of duplication is one three-line
/// extern block plus three integer constants.
#[cfg(unix)]
mod cleanup_flock {
    use std::fs::File;
    use std::io;
    use std::os::unix::io::AsRawFd;

    // POSIX advisory lock constants from `<sys/file.h>`. `LOCK_NB = 4`
    // is the one constant we need beyond the `wallet_keys::flock_sys`
    // set: it ORs with `LOCK_EX` to make the acquisition non-blocking.
    extern "C" {
        fn flock(fd: i32, op: i32) -> i32;
    }
    const LOCK_EX: i32 = 2;
    const LOCK_UN: i32 = 8;
    const LOCK_NB: i32 = 4;

    /// Try to acquire a non-blocking exclusive lock on `file`. Returns
    ///
    ///   - `Ok(true)`  if the lock was free and we took it (and then
    ///     immediately released it via `LOCK_UN`). Safe to unlink.
    ///   - `Ok(false)` if the lock is held by another process
    ///     (`EWOULDBLOCK` / `EAGAIN`). NOT safe to unlink.
    ///   - `Err(_)`    on any other syscall failure.
    ///
    /// The file is consumed; the caller drops the fd via RAII on return.
    pub fn probe_unheld(file: File) -> io::Result<bool> {
        let fd = file.as_raw_fd();
        // SAFETY: `fd` is a valid, open file descriptor owned by `file`
        // for the duration of this call. `flock` with `LOCK_EX |
        // LOCK_NB` has no memory-safety preconditions beyond a valid
        // fd, and we check the return value.
        let rc = unsafe { flock(fd, LOCK_EX | LOCK_NB) };
        if rc == 0 {
            // We took the lock. Release it explicitly before returning
            // so the subsequent unlink(2) path is not gated on File's
            // drop timing. A failing LOCK_UN is ignored — close(2) in
            // File's drop will release the lock regardless.
            // SAFETY: same as above. fd is still live.
            let _ = unsafe { flock(fd, LOCK_UN) };
            return Ok(true);
        }
        let err = io::Error::last_os_error();
        // EWOULDBLOCK (== EAGAIN on linux) is the "held by someone
        // else" signal. Anything else is a real error and must not be
        // silently treated as "unheld".
        let raw = err.raw_os_error();
        const EWOULDBLOCK: i32 = 11; // linux; matches EAGAIN
        const EAGAIN: i32 = 11;
        if raw == Some(EWOULDBLOCK) || raw == Some(EAGAIN) {
            return Ok(false);
        }
        // On macOS, EWOULDBLOCK is 35. Check that too for portability.
        #[cfg(target_os = "macos")]
        {
            if raw == Some(35) {
                return Ok(false);
            }
        }
        Err(err)
    }
}

#[cfg(not(unix))]
mod cleanup_flock {
    use std::fs::File;
    use std::io;

    /// Windows stub: no flock. We conservatively report the lock as
    /// held so cleanup never unlinks a `.lock.*` file on windows. See
    /// the `wallet_keys::flock_sys` stub for the rationale — concurrent
    /// `wallet create` is itself unsupported on windows today.
    pub fn probe_unheld(_file: File) -> io::Result<bool> {
        Ok(false)
    }
}

/// Parameters for [`cleanup`]. Keeps the signature stable as we add
/// filters without tempting callers to shuffle positional args.
#[derive(Debug, Clone, Default)]
pub struct CleanupOptions {
    pub dry_run: bool,
    pub wallet: Option<String>,
    pub older_than: Option<String>,
}

/// Scan `<wallets>/` for stale `.tmp.*`, `.bak.*`, and `.lock.*` entries
/// and reap the ones that satisfy the safety checks and filters. Returns
/// a machine-readable report suitable for feeding into `jq`.
///
/// See the module-level safety invariants above for what this command
/// will and will not touch.
pub fn cleanup(opts: CleanupOptions) -> Result<CleanupReport, BttError> {
    // Validate `--wallet <name>` BEFORE opening the directory. A bad
    // name with path-traversal bytes must be rejected with a clear
    // error, not silently folded into `skipped-no-match`.
    if let Some(ref n) = opts.wallet {
        if !is_valid_wallet_name(n) {
            return Err(BttError::invalid_input(format!(
                "--wallet '{}' is not a valid wallet name (allowed: 1..=64 chars of [A-Za-z0-9_-])",
                n
            )));
        }
    }

    let older_than: Option<Duration> = match opts.older_than.as_deref() {
        Some(s) => Some(parse_older_than(s)?),
        None => None,
    };

    let wallets_dir = wallets_path()?;
    if !wallets_dir.exists() {
        // Nothing to clean. Return an empty report rather than an
        // error — cleanup on a fresh install is a no-op.
        return Ok(CleanupReport { entries: Vec::new() });
    }

    let read = fs::read_dir(&wallets_dir)
        .map_err(|e| BttError::io(format!("failed to read wallets directory: {}", e)))?;

    let mut entries: Vec<CleanupEntry> = Vec::new();

    for entry in read {
        let entry = entry
            .map_err(|e| BttError::io(format!("failed to read directory entry: {}", e)))?;
        let file_name_os = entry.file_name();
        let file_name = match file_name_os.to_str() {
            Some(s) => s,
            // Non-UTF-8 file name can never match our (ASCII) grammar,
            // so it is definitionally `skipped-no-match`. We only
            // surface it in the report if it at least starts with one
            // of the reserved byte prefixes to avoid drowning the
            // output in unrelated real wallets.
            None => continue,
        };

        // Fast filter: only consider names that could conceivably be a
        // reserved entry. Real wallet dirs never start with `.`, and
        // hidden files unrelated to cleanup are none of our business.
        if !(file_name.starts_with(".tmp.")
            || file_name.starts_with(".bak.")
            || file_name.starts_with(".lock."))
        {
            continue;
        }

        let path = entry.path();
        let parsed = parse_reserved_entry(file_name);
        let parsed = match parsed {
            Some(p) => p,
            None => {
                // Name starts with a reserved prefix but fails the
                // strict grammar (e.g. `.tmp.fooblahblah`). Report it
                // and leave it alone.
                entries.push(CleanupEntry {
                    path: path.display().to_string(),
                    kind: guess_kind_from_prefix(file_name),
                    action: CleanupAction::SkippedNoMatch,
                });
                continue;
            }
        };

        // `--wallet <name>` filter: wallet name must match verbatim.
        if let Some(ref target) = opts.wallet {
            if &parsed.name != target {
                continue;
            }
        }

        // Symlink check: never follow symlinks. `symlink_metadata` does
        // not traverse, so a symlink at this path reports `is_symlink`
        // even if the target is a real directory somewhere else.
        let md = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                // A race could remove the entry between read_dir and
                // this stat. Report as skipped rather than erroring —
                // the rest of the scan is still valuable.
                entries.push(CleanupEntry {
                    path: path.display().to_string(),
                    kind: parsed.kind,
                    action: CleanupAction::SkippedNoMatch,
                });
                let _ = e;
                continue;
            }
        };
        if md.file_type().is_symlink() {
            entries.push(CleanupEntry {
                path: path.display().to_string(),
                kind: parsed.kind,
                action: CleanupAction::SkippedNoMatch,
            });
            continue;
        }
        // Shape check: tmp/bak must be directories, lock must be a file.
        let shape_ok = match parsed.kind {
            CleanupKind::Tmp | CleanupKind::Bak => md.is_dir(),
            CleanupKind::Lock => md.is_file(),
        };
        if !shape_ok {
            entries.push(CleanupEntry {
                path: path.display().to_string(),
                kind: parsed.kind,
                action: CleanupAction::SkippedNoMatch,
            });
            continue;
        }

        // Age filter. If we can't read mtime, treat the entry as too
        // young (i.e. skip) — erring on the side of not reaping.
        if let Some(cutoff) = older_than {
            let mtime = md
                .modified()
                .map_err(|e| BttError::io(format!("stat mtime on {}: {}", path.display(), e)))?;
            let age = SystemTime::now()
                .duration_since(mtime)
                .unwrap_or(Duration::ZERO);
            if age < cutoff {
                entries.push(CleanupEntry {
                    path: path.display().to_string(),
                    kind: parsed.kind,
                    action: CleanupAction::SkippedTooYoung,
                });
                continue;
            }
        }

        // Dry-run: record and move on without touching disk.
        if opts.dry_run {
            entries.push(CleanupEntry {
                path: path.display().to_string(),
                kind: parsed.kind,
                action: CleanupAction::KeptDryRun,
            });
            continue;
        }

        // Reap. `.lock.*` files get a flock probe before unlink; every
        // other kind gets `remove_dir_all`.
        match parsed.kind {
            CleanupKind::Lock => match reap_lock_file(&path) {
                Ok(action) => entries.push(CleanupEntry {
                    path: path.display().to_string(),
                    kind: parsed.kind,
                    action,
                }),
                Err(e) => return Err(e),
            },
            CleanupKind::Tmp | CleanupKind::Bak => {
                fs::remove_dir_all(&path).map_err(|e| {
                    BttError::io(format!(
                        "failed to remove stale dir {}: {}",
                        path.display(),
                        e
                    ))
                })?;
                entries.push(CleanupEntry {
                    path: path.display().to_string(),
                    kind: parsed.kind,
                    action: CleanupAction::Reaped,
                });
            }
        }
    }

    // Deterministic ordering for scripts.
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(CleanupReport { entries })
}

/// Probe a `.lock.*` file with a non-blocking `flock`. If the lock is
/// free, release it and unlink the file; if held, report `SkippedHeld`.
fn reap_lock_file(path: &Path) -> Result<CleanupAction, BttError> {
    let file = match fs::OpenOptions::new().read(true).write(true).open(path) {
        Ok(f) => f,
        Err(e) => {
            return Err(BttError::io(format!(
                "failed to open lock file {} for probe: {}",
                path.display(),
                e
            )));
        }
    };
    let unheld = cleanup_flock::probe_unheld(file).map_err(|e| {
        BttError::io(format!(
            "flock probe on {} failed: {}",
            path.display(),
            e
        ))
    })?;
    if !unheld {
        return Ok(CleanupAction::SkippedHeld);
    }
    fs::remove_file(path).map_err(|e| {
        BttError::io(format!(
            "failed to unlink unheld lock file {}: {}",
            path.display(),
            e
        ))
    })?;
    Ok(CleanupAction::Reaped)
}

/// Best-effort mapping of an unparsed reserved-prefix file name to a
/// [`CleanupKind`] for the `skipped-no-match` report. We only call this
/// for names we already know start with one of the three prefixes.
fn guess_kind_from_prefix(name: &str) -> CleanupKind {
    if name.starts_with(".tmp.") {
        CleanupKind::Tmp
    } else if name.starts_with(".bak.") {
        CleanupKind::Bak
    } else {
        CleanupKind::Lock
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::paths::{seat_config_env_at, wallets_parent_for, EnvGuard, ENV_LOCK};

    // Serialize against every other env-mutating test in the binary.
    static HOME_LOCK: &std::sync::Mutex<()> = &ENV_LOCK;

    fn seat_home(tag: &str) -> (PathBuf, EnvGuard, PathBuf) {
        let tmp = std::env::temp_dir().join(format!(
            "btt-cleanup-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&tmp).expect("tmp root");
        let (guard, parent) = seat_config_env_at(&tmp);
        // `seat_config_env_at` already created `parent` for us.
        let _ = parent;
        let wallets = wallets_parent_for(&tmp);
        (tmp, guard, wallets)
    }

    fn restore(tmp: PathBuf, guard: EnvGuard) {
        drop(guard);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── parser unit tests (no env mutation, run in parallel) ──────────

    #[test]
    fn parser_accepts_canonical_tmp() {
        let p = parse_reserved_entry(".tmp.foo.123.456789.0").expect("valid tmp");
        assert_eq!(p.kind, CleanupKind::Tmp);
        assert_eq!(p.name, "foo");
    }

    #[test]
    fn parser_accepts_canonical_bak() {
        let p = parse_reserved_entry(".bak.bar-baz_qux.9999.12345678901234.42").expect("valid bak");
        assert_eq!(p.kind, CleanupKind::Bak);
        assert_eq!(p.name, "bar-baz_qux");
    }

    #[test]
    fn parser_accepts_canonical_lock() {
        let p = parse_reserved_entry(".lock.alice").expect("valid lock");
        assert_eq!(p.kind, CleanupKind::Lock);
        assert_eq!(p.name, "alice");
    }

    #[test]
    fn parser_rejects_lookalike_tmp_without_numeric_tail() {
        // `.tmp.fooblahblah` has no `.<pid>.<nanos>.<ctr>` triple.
        assert!(parse_reserved_entry(".tmp.fooblahblah").is_none());
    }

    #[test]
    fn parser_rejects_lock_with_bad_name() {
        assert!(parse_reserved_entry(".lock.../etc").is_none());
        assert!(parse_reserved_entry(".lock.a.b").is_none()); // dot in name
        assert!(parse_reserved_entry(".lock.").is_none());
    }

    #[test]
    fn parser_rejects_tmp_with_non_numeric_pid() {
        assert!(parse_reserved_entry(".tmp.foo.abc.456.0").is_none());
    }

    #[test]
    fn parser_rejects_tmp_with_19plus_nanos() {
        // 20 digits: too long.
        assert!(parse_reserved_entry(".tmp.foo.1.12345678901234567890.0").is_none());
    }

    #[test]
    fn parser_rejects_unrelated_prefixes() {
        assert!(parse_reserved_entry("foo").is_none());
        assert!(parse_reserved_entry(".hidden").is_none());
        assert!(parse_reserved_entry(".tmpfoo.1.2.3").is_none()); // no `.` after tmp
    }

    #[test]
    fn duration_parser_accepts_all_units() {
        assert_eq!(parse_older_than("60s").expect("s"), Duration::from_secs(60));
        assert_eq!(parse_older_than("30m").expect("m"), Duration::from_secs(30 * 60));
        assert_eq!(
            parse_older_than("24h").expect("h"),
            Duration::from_secs(24 * 3600)
        );
        assert_eq!(
            parse_older_than("7d").expect("d"),
            Duration::from_secs(7 * 86_400)
        );
    }

    #[test]
    fn duration_parser_rejects_bad_input() {
        assert!(parse_older_than("").is_err());
        assert!(parse_older_than("7").is_err());
        assert!(parse_older_than("d").is_err());
        assert!(parse_older_than("7y").is_err());
        assert!(parse_older_than("-1s").is_err());
        assert!(parse_older_than("7.5h").is_err());
    }

    #[test]
    fn is_valid_wallet_name_checks() {
        assert!(is_valid_wallet_name("foo"));
        assert!(is_valid_wallet_name("foo-bar_baz"));
        assert!(is_valid_wallet_name(&"a".repeat(64)));
        assert!(!is_valid_wallet_name(""));
        assert!(!is_valid_wallet_name(&"a".repeat(65)));
        assert!(!is_valid_wallet_name("foo/bar"));
        assert!(!is_valid_wallet_name(".."));
        assert!(!is_valid_wallet_name("foo.bar"));
        assert!(!is_valid_wallet_name("foo\0bar"));
    }

    // ── end-to-end cleanup tests (HOME_LOCK required) ────────────────

    #[test]
    fn cleanup_reaps_stale_tmp_dir() {
        let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, env, wallets) = seat_home("reap-tmp");

        let stale = wallets.join(".tmp.foo.123.456789.0");
        std::fs::create_dir_all(stale.join("inner")).expect("plant tmp dir");

        let report = cleanup(CleanupOptions::default()).expect("cleanup");

        let exists_after = stale.exists();
        restore(tmp, env);

        assert!(!exists_after, "stale .tmp.* dir should be removed");
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].kind, CleanupKind::Tmp);
        assert_eq!(report.entries[0].action, CleanupAction::Reaped);
    }

    #[test]
    fn cleanup_reaps_stale_bak_dir() {
        let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, env, wallets) = seat_home("reap-bak");

        let stale = wallets.join(".bak.foo.1.2.3");
        std::fs::create_dir_all(&stale).expect("plant bak dir");
        std::fs::write(stale.join("coldkey"), b"stale").expect("plant inner file");

        let report = cleanup(CleanupOptions::default()).expect("cleanup");

        let exists_after = stale.exists();
        restore(tmp, env);

        assert!(!exists_after, "stale .bak.* dir should be removed");
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].kind, CleanupKind::Bak);
        assert_eq!(report.entries[0].action, CleanupAction::Reaped);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_reaps_unheld_lock_file() {
        let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, env, wallets) = seat_home("reap-lock");

        let lock_path = wallets.join(".lock.foo");
        std::fs::write(&lock_path, b"").expect("plant lock file");

        let report = cleanup(CleanupOptions::default()).expect("cleanup");
        let exists_after = lock_path.exists();
        restore(tmp, env);

        assert!(!exists_after, "unheld .lock.* should be removed");
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].kind, CleanupKind::Lock);
        assert_eq!(report.entries[0].action, CleanupAction::Reaped);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_skips_held_lock_file() {
        use std::os::unix::io::AsRawFd;

        let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, env, wallets) = seat_home("skip-held");

        let lock_path = wallets.join(".lock.foo");
        let held = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open lock");

        // Declare our own flock for the test — same shape as
        // wallet_keys::flock_sys::LockGuard::acquire but inlined.
        extern "C" {
            fn flock(fd: i32, op: i32) -> i32;
        }
        const LOCK_EX: i32 = 2;
        const LOCK_UN: i32 = 8;

        let fd = held.as_raw_fd();
        // SAFETY: fd is owned by `held` for the duration of the call.
        let rc = unsafe { flock(fd, LOCK_EX) };
        assert_eq!(rc, 0, "test setup: LOCK_EX must succeed");

        let report = cleanup(CleanupOptions::default()).expect("cleanup");

        // Release our lock before we check the report so a failing
        // assert doesn't leave the test fd holding the lock forever.
        // SAFETY: fd is still live; held still in scope.
        let _ = unsafe { flock(fd, LOCK_UN) };
        drop(held);

        let exists_after = lock_path.exists();
        restore(tmp, env);

        assert!(
            exists_after,
            "held lock file must not be unlinked by cleanup"
        );
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].kind, CleanupKind::Lock);
        assert_eq!(report.entries[0].action, CleanupAction::SkippedHeld);
    }

    #[test]
    fn cleanup_skips_real_wallet() {
        let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, env, wallets) = seat_home("skip-real");

        // Plant a minimal real wallet on disk directly so we don't need
        // to invoke the full `wallet_keys::create` path from this test.
        let real = wallets.join("real-wallet");
        std::fs::create_dir_all(real.join("hotkeys")).expect("plant real wallet");
        std::fs::write(real.join("coldkeypub.txt"), b"5FakeAddress").expect("plant coldkey");

        let report = cleanup(CleanupOptions::default()).expect("cleanup");

        let still_there = real.exists();
        restore(tmp, env);

        assert!(still_there, "real wallet must not be touched by cleanup");
        // The real wallet should not be in the report at all — it
        // doesn't match any reserved prefix, so it never becomes a
        // candidate.
        assert!(
            report.entries.is_empty(),
            "real wallet should not appear in cleanup report: {:?}",
            report.entries
        );
    }

    #[test]
    fn cleanup_skips_lookalike_dir() {
        let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, env, wallets) = seat_home("lookalike");

        let lookalike = wallets.join(".tmp.fooblahblah");
        std::fs::create_dir_all(&lookalike).expect("plant lookalike");

        let report = cleanup(CleanupOptions::default()).expect("cleanup");

        let still_there = lookalike.exists();
        restore(tmp, env);

        assert!(
            still_there,
            "lookalike .tmp.fooblahblah (no numeric tail) must not be reaped"
        );
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].kind, CleanupKind::Tmp);
        assert_eq!(report.entries[0].action, CleanupAction::SkippedNoMatch);
    }

    #[test]
    fn cleanup_dry_run_reaps_nothing() {
        let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, env, wallets) = seat_home("dry-run");

        let stale = wallets.join(".tmp.foo.1.2.3");
        std::fs::create_dir_all(&stale).expect("plant tmp");

        let report = cleanup(CleanupOptions {
            dry_run: true,
            ..Default::default()
        })
        .expect("cleanup");

        let still_there = stale.exists();
        restore(tmp, env);

        assert!(still_there, "--dry-run must not remove anything");
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].action, CleanupAction::KeptDryRun);
    }

    #[test]
    fn cleanup_wallet_filter() {
        let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, env, wallets) = seat_home("wallet-filter");

        let foo = wallets.join(".tmp.foo.1.2.3");
        let bar = wallets.join(".tmp.bar.1.2.3");
        std::fs::create_dir_all(&foo).expect("plant foo");
        std::fs::create_dir_all(&bar).expect("plant bar");

        let report = cleanup(CleanupOptions {
            wallet: Some("foo".to_string()),
            ..Default::default()
        })
        .expect("cleanup");

        let foo_gone = !foo.exists();
        let bar_still = bar.exists();
        restore(tmp, env);

        assert!(foo_gone, ".tmp.foo.* must be reaped when --wallet foo");
        assert!(bar_still, ".tmp.bar.* must survive when --wallet foo");
        assert_eq!(report.entries.len(), 1);
        assert!(report.entries[0].path.contains(".tmp.foo."));
        assert_eq!(report.entries[0].action, CleanupAction::Reaped);
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_older_than_filter() {
        use std::os::unix::fs::MetadataExt;

        let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, env, wallets) = seat_home("older-than");

        let fresh = wallets.join(".tmp.foo.1.2.3");
        let old = wallets.join(".bak.foo.1.2.3");
        std::fs::create_dir_all(&fresh).expect("plant fresh");
        std::fs::create_dir_all(&old).expect("plant old");

        // Backdate `old`'s mtime to 1 hour ago via utimensat. We use
        // the libc-free approach: set file times via `filetime`-like
        // shelling out? No — stick to the stdlib. `std::fs::File::
        // set_modified` is stable on recent rust. Use it.
        let f = std::fs::File::open(&old).expect("open old for mtime");
        let backdated = SystemTime::now() - Duration::from_secs(3600);
        f.set_modified(backdated).expect("set mtime");
        // Sanity check the mtime actually moved.
        let md = std::fs::metadata(&old).expect("stat old");
        let now_secs = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("now")
            .as_secs();
        let old_mtime_secs = md.mtime() as u64;
        assert!(
            now_secs > old_mtime_secs + 60,
            "mtime backdate sanity: expected old mtime to be >60s ago, got now={now_secs} old={old_mtime_secs}"
        );

        let report = cleanup(CleanupOptions {
            older_than: Some("30m".to_string()),
            ..Default::default()
        })
        .expect("cleanup");

        let fresh_still = fresh.exists();
        let old_gone = !old.exists();
        restore(tmp, env);

        assert!(fresh_still, "fresh .tmp.* must be skipped with --older-than 30m");
        assert!(old_gone, "backdated .bak.* must be reaped with --older-than 30m");

        // Report should contain both entries with distinct actions.
        assert_eq!(report.entries.len(), 2);
        let actions: Vec<CleanupAction> = report
            .entries
            .iter()
            .map(|e| e.action)
            .collect();
        assert!(actions.contains(&CleanupAction::Reaped));
        assert!(actions.contains(&CleanupAction::SkippedTooYoung));
    }

    #[test]
    fn cleanup_rejects_traversal_in_wallet_name() {
        // No HOME_LOCK needed: this errors before reading the wallets
        // dir. But the other tests in this module mutate env, so hold
        // the lock defensively so we don't race a concurrent run.
        let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());

        let err = cleanup(CleanupOptions {
            wallet: Some("../etc".to_string()),
            ..Default::default()
        })
        .expect_err("traversal must error");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("valid wallet name"),
            "error should mention wallet name validation, got: {msg}"
        );

        // And a NUL byte.
        let err2 = cleanup(CleanupOptions {
            wallet: Some("foo\0bar".to_string()),
            ..Default::default()
        })
        .expect_err("NUL byte must error");
        let _ = err2;
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_skips_symlink() {
        use std::os::unix::fs::symlink;

        let _g = HOME_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tmp, env, wallets) = seat_home("symlink");

        // Point the symlink at a directory OUTSIDE the wallets dir. If
        // cleanup follows the symlink it will remove_dir_all() the
        // target, which would destroy our tmp sentinel.
        let sentinel = tmp.join("sentinel");
        std::fs::create_dir_all(&sentinel).expect("plant sentinel");
        std::fs::write(sentinel.join("canary"), b"survive").expect("plant canary");

        let link = wallets.join(".tmp.foo.1.2.3");
        symlink(&sentinel, &link).expect("plant symlink");

        let report = cleanup(CleanupOptions::default()).expect("cleanup");

        let link_still = link.exists() || std::fs::symlink_metadata(&link).is_ok();
        let canary_still = sentinel.join("canary").exists();
        restore(tmp, env);

        assert!(link_still, "symlink must not be removed");
        assert!(
            canary_still,
            "symlink target must not be followed (canary still present)"
        );
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].action, CleanupAction::SkippedNoMatch);
    }
}
