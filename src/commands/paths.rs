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

use std::path::PathBuf;
use std::sync::Once;

use crate::error::BttError;

/// Legacy wallet-root location used by btt prior to this module.
///
/// This is the btcli-compatible path. It is only consulted as a fallback
/// when the new OS-dependent config directory does not yet exist.
fn legacy_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    if home.is_empty() {
        return None;
    }
    Some(PathBuf::from(home).join(".bittensor"))
}

/// Compute the OS-native config directory without consulting the filesystem.
fn native_config_dir() -> Result<PathBuf, BttError> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return Ok(PathBuf::from(xdg).join("btt"));
            }
        }
        let home = std::env::var("HOME")
            .map_err(|_| BttError::io("HOME environment variable not set"))?;
        Ok(PathBuf::from(home).join(".config").join("btt"))
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME")
            .map_err(|_| BttError::io("HOME environment variable not set"))?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("btt"))
    }
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("APPDATA")
            .map_err(|_| BttError::io("APPDATA environment variable not set"))?;
        Ok(PathBuf::from(appdata).join("btt"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        // BSDs, Solaris, illumos, etc.: default to the XDG-style linux
        // layout. Users on exotic targets can set `XDG_CONFIG_HOME`
        // explicitly if they want a different location.
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            if !xdg.is_empty() {
                return Ok(PathBuf::from(xdg).join("btt"));
            }
        }
        let home = std::env::var("HOME")
            .map_err(|_| BttError::io("HOME environment variable not set"))?;
        Ok(PathBuf::from(home).join(".config").join("btt"))
    }
}

// Emit the legacy-fallback warning at most once per process.
static LEGACY_WARNING: Once = Once::new();

fn warn_legacy(legacy: &std::path::Path, new: &std::path::Path) {
    LEGACY_WARNING.call_once(|| {
        eprintln!(
            "btt: legacy wallet directory at {} detected.",
            legacy.display()
        );
        eprintln!(
            "     Move it to {} to use the new location:",
            new.display()
        );
        eprintln!("         mv {} {}", legacy.display(), new.display());
        eprintln!(
            "     btt will continue to use the legacy location until the move is performed."
        );
    });
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
    if let Some(legacy) = legacy_dir() {
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

#[cfg(test)]
mod tests {
    use super::*;

    struct EnvGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvGuard {
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

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_respects_xdg_config_home() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _xdg = EnvGuard::set("XDG_CONFIG_HOME", "/tmp/xdg-btt-test");
        let p = native_config_dir().expect("resolve");
        assert_eq!(p, PathBuf::from("/tmp/xdg-btt-test/btt"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_falls_back_to_dot_config() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _xdg = EnvGuard::unset("XDG_CONFIG_HOME");
        let _home = EnvGuard::set("HOME", "/home/alice");
        let p = native_config_dir().expect("resolve");
        assert_eq!(p, PathBuf::from("/home/alice/.config/btt"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_empty_xdg_is_ignored() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _xdg = EnvGuard::set("XDG_CONFIG_HOME", "");
        let _home = EnvGuard::set("HOME", "/home/bob");
        let p = native_config_dir().expect("resolve");
        assert_eq!(p, PathBuf::from("/home/bob/.config/btt"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_uses_application_support() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let _home = EnvGuard::set("HOME", "/Users/alice");
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
        let _appdata = EnvGuard::set("APPDATA", r"C:\Users\alice\AppData\Roaming");
        let p = native_config_dir().expect("resolve");
        assert_eq!(p, PathBuf::from(r"C:\Users\alice\AppData\Roaming\btt"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn legacy_fallback_when_only_old_dir_exists() {
        // Pin the ENV lock *and* build in a tempdir so we don't step on
        // real wallets.
        let _guard = ENV_LOCK.lock().expect("env lock");
        let tmp = std::env::temp_dir().join(format!("btt-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("mkdir tmp");
        let legacy = tmp.join(".bittensor");
        std::fs::create_dir_all(&legacy).expect("mkdir legacy");

        let _home = EnvGuard::set("HOME", tmp.to_str().expect("tmp str"));
        let _xdg = EnvGuard::set(
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
        let tmp = std::env::temp_dir().join(format!("btt-native-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("mkdir tmp");
        // Both legacy and native exist; native must win.
        let legacy = tmp.join(".bittensor");
        std::fs::create_dir_all(&legacy).expect("mkdir legacy");
        let xdg = tmp.join(".config");
        let native = xdg.join("btt");
        std::fs::create_dir_all(&native).expect("mkdir native");

        let _home = EnvGuard::set("HOME", tmp.to_str().expect("tmp str"));
        let _xdg_g = EnvGuard::set("XDG_CONFIG_HOME", xdg.to_str().expect("xdg str"));

        let resolved = config_dir().expect("resolve");
        assert_eq!(resolved, native);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
