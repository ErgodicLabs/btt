//! Per-user btt config / wallet directory resolution.
//!
//! btt stores its on-disk state (wallets, and eventually other config) under
//! a single per-user directory. The location is OS-dependent:
//!
//! | OS      | Path                                                    |
//! | ------- | ------------------------------------------------------- |
//! | linux   | `$XDG_CONFIG_HOME/btt` if set, else `$HOME/.config/btt` |
//! | macOS   | `$HOME/Library/Application Support/btt`                 |
//! | windows | `%APPDATA%\btt`                                         |
//!
//! This module is stdlib-only by design — no `dirs` / `directories` crate.
//! Every dependency on btt's dependency tree is audited, and path resolution
//! does not warrant pulling in third-party code.
//!
//! ## Legacy fallback
//!
//! Earlier versions of btt stored wallets at `$HOME/.bittensor/wallets/`
//! (the btcli-compatible location). If that directory still exists and the
//! new config directory does not, `config_dir()` returns the legacy path so
//! the user can keep loading their wallets, and emits a one-time stderr
//! warning telling them how to migrate. btt never silently moves wallet
//! material on the user's behalf.

use std::env::VarError;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Once;

use crate::error::BttError;

/// Read an environment variable, distinguishing "not set" from "not UTF-8".
///
/// Returns:
/// - `Ok(Some(value))` if the variable is set and valid UTF-8.
/// - `Ok(None)` if the variable is not present.
/// - `Err(BttError)` if the variable is present but contains non-UTF-8 bytes.
fn read_env_var(key: &str) -> Result<Option<String>, BttError> {
    match std::env::var(key) {
        Ok(v) => Ok(Some(v)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(BttError::io(format!(
            "{} contains non-UTF-8 bytes",
            key
        ))),
    }
}

/// Compute the OS-native config directory from explicit env values.
///
/// This is the single source of truth for the per-OS resolver logic.
/// Production callers go through [`config_dir`] / [`native_config_dir`],
/// which read the process environment; tests (and the wallet_keys test
/// helpers) can call this directly with synthetic values to avoid any
/// `cfg(target_os)` branching of their own.
///
/// Inputs:
/// - `home`: value of `$HOME`. Required on linux / macOS / BSDs.
/// - `xdg`: value of `$XDG_CONFIG_HOME`. Consulted only on linux / BSDs.
/// - `appdata`: value of `%APPDATA%`. Required on windows.
///
/// An `Some("")` empty-string input is treated as "not set" (matching the
/// historical behavior of `native_config_dir`), so callers can pass raw
/// env-var reads straight through.
pub(crate) fn config_dir_from_env(
    home: Option<&str>,
    xdg: Option<&str>,
    appdata: Option<&str>,
) -> Result<PathBuf, BttError> {
    #[cfg(target_os = "linux")]
    {
        let _ = appdata;
        if let Some(x) = xdg {
            if !x.is_empty() {
                return Ok(PathBuf::from(x).join("btt"));
            }
        }
        let h = home
            .filter(|s| !s.is_empty())
            .ok_or_else(|| BttError::io("HOME environment variable not set"))?;
        Ok(PathBuf::from(h).join(".config").join("btt"))
    }
    #[cfg(target_os = "macos")]
    {
        let _ = xdg;
        let _ = appdata;
        let h = home
            .filter(|s| !s.is_empty())
            .ok_or_else(|| BttError::io("HOME environment variable not set"))?;
        Ok(PathBuf::from(h)
            .join("Library")
            .join("Application Support")
            .join("btt"))
    }
    #[cfg(target_os = "windows")]
    {
        let _ = home;
        let _ = xdg;
        let a = appdata
            .filter(|s| !s.is_empty())
            .ok_or_else(|| BttError::io("APPDATA environment variable not set"))?;
        Ok(PathBuf::from(a).join("btt"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = appdata;
        // BSDs, Solaris, illumos, etc.: default to the XDG-style linux
        // layout. Users on exotic targets can set `XDG_CONFIG_HOME`
        // explicitly if they want a different location.
        if let Some(x) = xdg {
            if !x.is_empty() {
                return Ok(PathBuf::from(x).join("btt"));
            }
        }
        let h = home
            .filter(|s| !s.is_empty())
            .ok_or_else(|| BttError::io("HOME environment variable not set"))?;
        Ok(PathBuf::from(h).join(".config").join("btt"))
    }
}

/// Compute the OS-native config directory without consulting the filesystem.
///
/// Reads `HOME`, `XDG_CONFIG_HOME`, and `APPDATA` from the process
/// environment and dispatches to [`config_dir_from_env`]. Returns distinct
/// errors for non-UTF-8 env values so users see an actionable diagnostic.
fn native_config_dir() -> Result<PathBuf, BttError> {
    let home = read_env_var("HOME")?;
    let xdg = read_env_var("XDG_CONFIG_HOME")?;
    let appdata = read_env_var("APPDATA")?;
    config_dir_from_env(home.as_deref(), xdg.as_deref(), appdata.as_deref())
}

/// Legacy wallet-root location used by btt prior to this module.
///
/// This is the btcli-compatible path. It is only consulted as a fallback
/// when the new OS-dependent config directory does not yet exist.
///
/// Returns `Ok(None)` if `HOME` is unset or empty; `Err` only if `HOME` is
/// present but non-UTF-8.
fn legacy_dir() -> Result<Option<PathBuf>, BttError> {
    let home = read_env_var("HOME")?;
    Ok(home
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".bittensor")))
}

// Emit the legacy-fallback warning at most once per process.
static LEGACY_WARNING: Once = Once::new();

/// Emit the legacy-fallback migration warning at most once per `once`.
///
/// Writer and `Once` are injected so tests can capture the output and
/// supply a fresh `Once` per test (the static `LEGACY_WARNING` would
/// otherwise "stick" across tests running in the same process).
fn warn_legacy_to(
    out: &mut dyn Write,
    once: &Once,
    legacy: &Path,
    new: &Path,
) {
    once.call_once(|| {
        let _ = writeln!(
            out,
            "btt: legacy wallet directory at {} detected.",
            legacy.display()
        );
        let _ = writeln!(
            out,
            "     Move it to {} to use the new location:",
            new.display()
        );
        let _ = writeln!(out, "         mv {} {}", legacy.display(), new.display());
        let _ = writeln!(
            out,
            "     btt will continue to use the legacy location until the move is performed."
        );
    });
}

/// Production-side wrapper: emit to stderr, gated by the process-wide
/// `LEGACY_WARNING` `Once`.
fn warn_legacy(legacy: &Path, new: &Path) {
    let mut err = std::io::stderr().lock();
    warn_legacy_to(&mut err, &LEGACY_WARNING, legacy, new);
}

/// Resolve the per-user btt config directory.
///
/// Returns the OS-native location in the common case. If that location does
/// not yet exist on disk but the legacy `$HOME/.bittensor` directory does,
/// returns the legacy path and emits a one-time migration warning on stderr.
///
/// The returned path is not guaranteed to exist — callers that need it to
/// exist should create it themselves (with appropriate permissions).
pub fn config_dir() -> Result<PathBuf, BttError> {
    let native = native_config_dir()?;

    // If the native path already exists, use it unconditionally. The user
    // has either migrated or started fresh on the new layout.
    if native.exists() {
        return Ok(native);
    }

    // Native path does not exist. Check for the legacy location.
    if let Some(legacy) = legacy_dir()? {
        if legacy.exists() {
            warn_legacy(&legacy, &native);
            return Ok(legacy);
        }
    }

    // Neither exists. Return the native location — the caller will create
    // it on first write.
    Ok(native)
}

/// Root directory for wallet storage: `<config_dir>/wallets/`.
pub fn wallets_dir() -> Result<PathBuf, BttError> {
    Ok(config_dir()?.join("wallets"))
}

/// Directory for a single named wallet: `<config_dir>/wallets/<name>/`.
pub fn wallet_dir(name: &str) -> Result<PathBuf, BttError> {
    Ok(wallets_dir()?.join(name))
}

/// Process-wide lock for tests that mutate config-dir env vars.
///
/// `config_dir()` reads `HOME`, `XDG_CONFIG_HOME`, and `APPDATA`. Any test
/// that mutates any of these must serialize against every other such test,
/// even across module boundaries within the same test binary. Expose a
/// single shared mutex here so `wallet_keys::tests` and `paths::tests`
/// don't race each other.
#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ── Test helpers (shared with other modules' tests) ──────────────────────

/// Seat the config-dir env vars at `tmp` and return a guard that restores
/// `HOME`, `XDG_CONFIG_HOME`, and `APPDATA` on drop.
///
/// Used by `wallet_keys::tests` and this module's own tests. The caller
/// must hold [`ENV_LOCK`] for the duration of the guard's lifetime — env
/// vars are process-global.
///
/// Returns `(guard, wallets_parent)` where `wallets_parent` is the exact
/// path that [`wallets_dir`] will resolve to for this tmp root on the
/// current OS. The caller can join `<name>` onto it to get a wallet dir.
///
/// The wallets parent is created on disk so [`config_dir`]'s
/// legacy-fallback branch is never taken for this tmp.
#[cfg(test)]
pub(crate) fn seat_config_env_at(tmp: &Path) -> (EnvGuard, PathBuf) {
    let guard = EnvGuard::seat_for(tmp);
    let parent = wallets_parent_for(tmp);
    std::fs::create_dir_all(&parent).expect("create wallets parent");
    (guard, parent)
}

/// Compute the `wallets/` parent dir that [`config_dir`] will resolve to
/// for a given test tmp root, on the current host OS.
///
/// Goes through [`config_dir_from_env`] so there is exactly one site that
/// knows the per-OS resolver shape.
#[cfg(test)]
pub(crate) fn wallets_parent_for(tmp: &Path) -> PathBuf {
    let (home, xdg, appdata) = synthetic_env_for(tmp);
    config_dir_from_env(Some(&home), xdg.as_deref(), appdata.as_deref())
        .expect("synthetic env resolves")
        .join("wallets")
}

/// Compute the synthetic `(HOME, XDG_CONFIG_HOME, APPDATA)` triple that
/// would resolve under `tmp`. On a given OS only one of the three is
/// meaningful, but we return all three so callers can plug them straight
/// into `std::env::set_var`.
#[cfg(test)]
fn synthetic_env_for(tmp: &Path) -> (String, Option<String>, Option<String>) {
    let home = tmp.to_str().expect("tmp is UTF-8").to_string();
    let xdg = Some(
        tmp.join("xdg")
            .to_str()
            .expect("xdg path is UTF-8")
            .to_string(),
    );
    let appdata = Some(
        tmp.join("AppData")
            .join("Roaming")
            .to_str()
            .expect("appdata path is UTF-8")
            .to_string(),
    );
    (home, xdg, appdata)
}

/// Symmetric env-restoring guard for `HOME`, `XDG_CONFIG_HOME`, and
/// `APPDATA`. Saves the original values of all three on construction and
/// restores them on drop, regardless of which one(s) were actually mutated.
///
/// Used by both this module's tests and `wallet_keys::tests`, which is how
/// we fix the old asymmetry where `seat_home_env` set both `HOME` and
/// `XDG_CONFIG_HOME` but only `HOME` was ever restored.
#[cfg(test)]
pub(crate) struct EnvGuard {
    home: Option<String>,
    xdg: Option<String>,
    appdata: Option<String>,
}

#[cfg(test)]
impl EnvGuard {
    /// Capture the current values of all three config env vars. Does not
    /// mutate anything. Useful when a test wants to call arbitrary
    /// `std::env::set_var` / `remove_var` directly and only needs a
    /// drop-time restore.
    pub(crate) fn capture() -> Self {
        Self {
            home: std::env::var("HOME").ok(),
            xdg: std::env::var("XDG_CONFIG_HOME").ok(),
            appdata: std::env::var("APPDATA").ok(),
        }
    }

    /// Capture current values and then seat `HOME`, `XDG_CONFIG_HOME`,
    /// and `APPDATA` at synthetic values under `tmp`. On drop, all three
    /// are restored to their original values.
    fn seat_for(tmp: &Path) -> Self {
        let guard = Self::capture();
        let (home, xdg, appdata) = synthetic_env_for(tmp);
        std::env::set_var("HOME", &home);
        if let Some(x) = xdg.as_deref() {
            std::env::set_var("XDG_CONFIG_HOME", x);
        }
        if let Some(a) = appdata.as_deref() {
            std::env::set_var("APPDATA", a);
        }
        guard
    }
}

#[cfg(test)]
impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
        match &self.xdg {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        match &self.appdata {
            Some(v) => std::env::set_var("APPDATA", v),
            None => std::env::remove_var("APPDATA"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One-off env guard that only touches a single key. Used by tests
    /// that want to exercise the production env-reading path directly.
    struct SingleEnvGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl SingleEnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, original }
        }

        fn unset(key: &'static str) -> Self {
            let original = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, original }
        }
    }

    impl Drop for SingleEnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    // ── Item 4: resolver via synthetic values (no env mutation) ──────

    #[cfg(target_os = "linux")]
    #[test]
    fn resolver_linux_xdg_wins() {
        let p = config_dir_from_env(
            Some("/home/alice"),
            Some("/xdg/root"),
            None,
        )
        .expect("resolve");
        assert_eq!(p, PathBuf::from("/xdg/root/btt"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolver_linux_empty_xdg_falls_back_to_home() {
        let p = config_dir_from_env(Some("/home/bob"), Some(""), None)
            .expect("resolve");
        assert_eq!(p, PathBuf::from("/home/bob/.config/btt"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolver_linux_no_xdg_uses_home() {
        let p = config_dir_from_env(Some("/home/carol"), None, None)
            .expect("resolve");
        assert_eq!(p, PathBuf::from("/home/carol/.config/btt"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolver_linux_missing_home_errors() {
        let err = config_dir_from_env(None, None, None).expect_err("err");
        let msg = format!("{}", err);
        assert!(
            msg.contains("HOME"),
            "expected HOME in error, got {msg:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn resolver_macos_uses_application_support() {
        let p = config_dir_from_env(Some("/Users/alice"), None, None)
            .expect("resolve");
        assert_eq!(
            p,
            PathBuf::from("/Users/alice/Library/Application Support/btt")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn resolver_windows_uses_appdata() {
        let p = config_dir_from_env(
            None,
            None,
            Some(r"C:\Users\alice\AppData\Roaming"),
        )
        .expect("resolve");
        assert_eq!(
            p,
            PathBuf::from(r"C:\Users\alice\AppData\Roaming\btt")
        );
    }

    // ── Legacy env-reading integration tests (exercise native_config_dir) ──

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_respects_xdg_config_home() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _restore = EnvGuard::capture();
        let _xdg = SingleEnvGuard::set("XDG_CONFIG_HOME", "/tmp/xdg-btt-test");
        let p = native_config_dir().expect("resolve");
        assert_eq!(p, PathBuf::from("/tmp/xdg-btt-test/btt"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_falls_back_to_dot_config() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _restore = EnvGuard::capture();
        let _xdg = SingleEnvGuard::unset("XDG_CONFIG_HOME");
        let _home = SingleEnvGuard::set("HOME", "/home/alice");
        let p = native_config_dir().expect("resolve");
        assert_eq!(p, PathBuf::from("/home/alice/.config/btt"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_empty_xdg_is_ignored() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _restore = EnvGuard::capture();
        let _xdg = SingleEnvGuard::set("XDG_CONFIG_HOME", "");
        let _home = SingleEnvGuard::set("HOME", "/home/bob");
        let p = native_config_dir().expect("resolve");
        assert_eq!(p, PathBuf::from("/home/bob/.config/btt"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_uses_application_support() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _restore = EnvGuard::capture();
        let _home = SingleEnvGuard::set("HOME", "/Users/alice");
        let p = native_config_dir().expect("resolve");
        assert_eq!(
            p,
            PathBuf::from("/Users/alice/Library/Application Support/btt")
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_uses_appdata() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _restore = EnvGuard::capture();
        let _appdata =
            SingleEnvGuard::set("APPDATA", r"C:\Users\alice\AppData\Roaming");
        let p = native_config_dir().expect("resolve");
        assert_eq!(p, PathBuf::from(r"C:\Users\alice\AppData\Roaming\btt"));
    }

    // ── Item 5: VarError::NotUnicode distinct error messages ─────────

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_home_not_present_has_distinct_message() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _restore = EnvGuard::capture();
        let _xdg = SingleEnvGuard::unset("XDG_CONFIG_HOME");
        let _home = SingleEnvGuard::unset("HOME");
        let err = native_config_dir().expect_err("must error");
        let msg = format!("{}", err);
        assert!(
            msg.contains("HOME environment variable not set"),
            "expected 'not set' message, got {msg:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_home_not_unicode_has_distinct_message() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let _guard = ENV_LOCK.lock().expect("env lock");
        let _restore = EnvGuard::capture();
        std::env::remove_var("XDG_CONFIG_HOME");
        // 0xFF is invalid UTF-8 — Rust's `std::env::var` will return
        // `VarError::NotUnicode` for this.
        let bad = OsString::from_vec(vec![b'/', b'h', b'o', b'm', b'e', b'/', 0xFF]);
        std::env::set_var("HOME", &bad);
        let err = native_config_dir().expect_err("must error");
        let msg = format!("{}", err);
        assert!(
            msg.contains("non-UTF-8"),
            "expected 'non-UTF-8' message, got {msg:?}"
        );
    }

    // ── Item 2: warn_legacy writes the migration banner ──────────────

    #[test]
    fn warn_legacy_writes_banner_to_writer() {
        let legacy = PathBuf::from("/home/alice/.bittensor");
        let native = PathBuf::from("/home/alice/.config/btt");
        let mut buf: Vec<u8> = Vec::new();
        let once = Once::new();
        warn_legacy_to(&mut buf, &once, &legacy, &native);

        let s = String::from_utf8(buf).expect("utf8");
        assert!(s.contains("legacy wallet directory at /home/alice/.bittensor"));
        assert!(s.contains("/home/alice/.config/btt"));
        assert!(s.contains("mv /home/alice/.bittensor /home/alice/.config/btt"));
        assert!(s.contains("legacy location until the move is performed"));
    }

    // ── Item 3: Once semantics — at most one emission ────────────────

    #[test]
    fn warn_legacy_fires_exactly_once_per_once() {
        let legacy = PathBuf::from("/home/bob/.bittensor");
        let native = PathBuf::from("/home/bob/.config/btt");
        let once = Once::new();

        let mut first: Vec<u8> = Vec::new();
        warn_legacy_to(&mut first, &once, &legacy, &native);
        assert!(!first.is_empty(), "first call should emit");

        let mut second: Vec<u8> = Vec::new();
        warn_legacy_to(&mut second, &once, &legacy, &native);
        assert!(
            second.is_empty(),
            "second call on same Once must emit nothing, got {:?}",
            String::from_utf8_lossy(&second)
        );

        // A fresh Once should emit again.
        let fresh = Once::new();
        let mut third: Vec<u8> = Vec::new();
        warn_legacy_to(&mut third, &fresh, &legacy, &native);
        assert!(!third.is_empty(), "fresh Once should emit");
    }

    // ── EnvGuard symmetric restore (item 1) ──────────────────────────

    #[test]
    fn env_guard_restores_all_three_vars_on_drop() {
        let _lock = ENV_LOCK.lock().expect("env lock");

        // Seed known sentinel values we want to see restored.
        std::env::set_var("HOME", "/orig/home");
        std::env::set_var("XDG_CONFIG_HOME", "/orig/xdg");
        std::env::set_var("APPDATA", r"C:\orig\appdata");

        {
            let tmp = std::env::temp_dir().join("btt-envguard-drop-test");
            let _ = std::fs::remove_dir_all(&tmp);
            std::fs::create_dir_all(&tmp).expect("mkdir tmp");
            let (_guard, _parent) = seat_config_env_at(&tmp);

            // While the guard is live, all three vars should point
            // inside `tmp`.
            assert_eq!(
                std::env::var("HOME").ok().as_deref(),
                Some(tmp.to_str().expect("tmp is UTF-8"))
            );
            assert_ne!(
                std::env::var("XDG_CONFIG_HOME").ok().as_deref(),
                Some("/orig/xdg")
            );
            assert_ne!(
                std::env::var("APPDATA").ok().as_deref(),
                Some(r"C:\orig\appdata")
            );

            let _ = std::fs::remove_dir_all(&tmp);
        }

        // Guard dropped: all three restored.
        assert_eq!(
            std::env::var("HOME").ok().as_deref(),
            Some("/orig/home"),
            "HOME must be restored"
        );
        assert_eq!(
            std::env::var("XDG_CONFIG_HOME").ok().as_deref(),
            Some("/orig/xdg"),
            "XDG_CONFIG_HOME must be restored"
        );
        assert_eq!(
            std::env::var("APPDATA").ok().as_deref(),
            Some(r"C:\orig\appdata"),
            "APPDATA must be restored"
        );

        // Cleanup the sentinels so we don't leak into later tests.
        std::env::remove_var("HOME");
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("APPDATA");
    }

    #[test]
    fn env_guard_restores_unset_vars_to_unset() {
        let _lock = ENV_LOCK.lock().expect("env lock");

        std::env::remove_var("HOME");
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("APPDATA");

        {
            let tmp = std::env::temp_dir().join("btt-envguard-unset-test");
            let _ = std::fs::remove_dir_all(&tmp);
            std::fs::create_dir_all(&tmp).expect("mkdir tmp");
            let (_guard, _parent) = seat_config_env_at(&tmp);
            // All three should be set now.
            assert!(std::env::var("HOME").is_ok());
            assert!(std::env::var("XDG_CONFIG_HOME").is_ok());
            assert!(std::env::var("APPDATA").is_ok());
            let _ = std::fs::remove_dir_all(&tmp);
        }

        assert!(
            std::env::var("HOME").is_err(),
            "HOME should be unset after guard drop"
        );
        assert!(
            std::env::var("XDG_CONFIG_HOME").is_err(),
            "XDG_CONFIG_HOME should be unset after guard drop"
        );
        assert!(
            std::env::var("APPDATA").is_err(),
            "APPDATA should be unset after guard drop"
        );
    }

    // ── Legacy-fallback integration tests ────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_fallback_when_only_old_dir_exists() {
        // Pin the ENV lock *and* build in a tempdir so we don't step on
        // real wallets.
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _restore = EnvGuard::capture();
        let tmp = std::env::temp_dir().join(format!("btt-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("mkdir tmp");
        let legacy = tmp.join(".bittensor");
        std::fs::create_dir_all(&legacy).expect("mkdir legacy");

        std::env::set_var("HOME", tmp.to_str().expect("tmp str"));
        std::env::set_var(
            "XDG_CONFIG_HOME",
            tmp.join(".config").to_str().expect("xdg str"),
        );

        let resolved = config_dir().expect("resolve");
        assert_eq!(resolved, legacy);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_path_wins_when_it_exists() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _restore = EnvGuard::capture();
        let tmp = std::env::temp_dir().join(format!("btt-native-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("mkdir tmp");
        // Both legacy and native exist; native must win.
        let legacy = tmp.join(".bittensor");
        std::fs::create_dir_all(&legacy).expect("mkdir legacy");
        let xdg = tmp.join(".config");
        let native = xdg.join("btt");
        std::fs::create_dir_all(&native).expect("mkdir native");

        std::env::set_var("HOME", tmp.to_str().expect("tmp str"));
        std::env::set_var("XDG_CONFIG_HOME", xdg.to_str().expect("xdg str"));

        let resolved = config_dir().expect("resolve");
        assert_eq!(resolved, native);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
