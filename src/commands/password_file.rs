//! Read a coldkey password from a file on disk.
//!
//! This is the machine-readable counterpart to interactive `rpassword` prompting.
//! It exists so CI, automation, and ephemeral wallet workflows can drive
//! `btt wallet create|new-coldkey|regen-coldkey|sign` non-interactively, without
//! piping passwords through process arguments (visible in `ps`) or environment
//! variables (inherited by children, swept into crash dumps).
//!
//! Security posture
//! ----------------
//! - On unix, we refuse to read a file whose mode is group- or world-readable
//!   (`mode & 0o077 != 0`). This check is not TOCTOU hardening — the expected
//!   password file lives on a user-controlled tmpfs (`/dev/shm/btt-pw`) at
//!   mode 0600, and that posture already closes the TOCTOU window: any file
//!   reachable under that posture is already one of the user's own files.
//!   The check exists as a guard against the user pointing `--password-file`
//!   at something like `/etc/passwd` by accident. Fail-closed. The caller is
//!   instructed to `chmod 600 <path>`.
//! - We refuse anything that is not a regular file. No FIFOs, no character
//!   devices, no directories. A password file is a tiny thing on a tmpfs;
//!   it should not be a pipe.
//! - On non-unix platforms we skip the mode check entirely and rely on the
//!   filesystem's ACLs (NTFS on Windows, etc.). The portable `File::open`
//!   path is used everywhere; there is no libc dependency.
//! - Only the first line (up to the first `\n`, optionally dropping `\r`) is
//!   taken as the password. Content beyond the first newline is discarded,
//!   so `echo "pw" > /dev/shm/pw` works without trailing-whitespace footguns.
//! - The password is returned inside a [`Zeroizing<String>`] so it is wiped
//!   when it drops.
//!
//! The `--password-file` flag is documented in `btt --help`, in `btt skill`,
//! and in the README. Per btt's no-hidden-flags principle, every flag is
//! visible at all three.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use zeroize::Zeroizing;

use crate::error::BttError;

/// Resolve `~` prefixes and `~user`-less tilde expansion against the
/// caller-supplied home directory.
///
/// We deliberately do NOT do arbitrary shell expansion — no `$VAR`
/// substitution, no glob, no `..` magic. A password file path is supposed to
/// be a concrete on-disk location.
///
/// `home` is taken as a parameter (rather than read from `std::env::var`
/// internally) so tests can supply a synthetic value without mutating the
/// process-global env. `std::env::set_var` becomes `unsafe` in Rust 1.82+
/// and is a parallel-test footgun even before that — see issue #14 NEW-L2.
fn expand_tilde(path: &str, home: Option<&str>) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = home {
            return PathBuf::from(home).join(rest);
        }
    }
    if path == "~" {
        if let Some(home) = home {
            return PathBuf::from(home);
        }
    }
    PathBuf::from(path)
}

/// Read a password from a file.
///
/// The file must exist, be a regular file, and on unix must not be
/// other-readable. The first line (stripped of trailing `\n` or `\r\n`) is
/// returned as the password.
pub fn read_password_file(path: &str) -> Result<Zeroizing<String>, BttError> {
    let home = std::env::var("HOME").ok();
    let resolved = expand_tilde(path, home.as_deref());
    read_password_file_inner(&resolved)
}

fn read_password_file_inner(path: &Path) -> Result<Zeroizing<String>, BttError> {
    // Portable open. We previously used O_NOFOLLOW + a stat-before-open
    // TOCTOU pre-check, but the TOCTOU ceremony was belt-and-suspenders
    // given the expected posture (mode 0600 on a 0700 parent owned by the
    // caller): any file that passes the mode check below is by
    // construction one of the user's own files, so swapping doesn't buy
    // an attacker anything. Dropping the libc dep also lets this compile
    // unchanged on non-unix targets.
    let mut file = fs::File::open(path).map_err(|e| {
        BttError::io(format!(
            "failed to open password file {}: {}",
            path.display(),
            e
        ))
    })?;

    // Metadata from the open fd. Using the fd (rather than re-stat'ing the
    // path) means the is_file / mode checks below describe exactly the
    // bytes we read into the buffer.
    let md = file.metadata().map_err(|e| {
        BttError::io(format!(
            "failed to stat password file {}: {}",
            path.display(),
            e
        ))
    })?;

    if !md.is_file() {
        return Err(BttError::io(format!(
            "password file {} is not a regular file (refusing to read FIFO, device, or directory)",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(BttError::io(format!(
                "password file {} has insecure mode {:o}; run `chmod 600 {}` and retry",
                path.display(),
                mode,
                path.display()
            )));
        }
    }

    // Read the whole file into a Zeroizing buffer. Cap at 64 KiB to bound
    // the memory that ends up holding plaintext. A password longer than that
    // is almost certainly a mistake.
    const MAX_FILE_BYTES: u64 = 64 * 1024;
    if md.len() > MAX_FILE_BYTES {
        return Err(BttError::io(format!(
            "password file {} is larger than {} bytes; refusing to read",
            path.display(),
            MAX_FILE_BYTES
        )));
    }

    // `md.len() > MAX_FILE_BYTES` was rejected above, so `md.len()` is
    // already bounded. We size the buffer from `md.len()` directly — no
    // `.min(MAX_FILE_BYTES)` needed. (If that gate is ever removed or
    // reordered, the `Read::take` below remains the authoritative ceiling.)
    let cap = md.len() as usize;
    let mut buf = Zeroizing::new(Vec::<u8>::with_capacity(cap));
    (&mut file)
        .take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| BttError::io(format!("failed to read password file: {}", e)))?;
    // TOCTOU defense-in-depth: this branch only fires if the file grew
    // between `metadata()` and `read_to_end()` — the advisory `md.len()`
    // gate above has already rejected files that were oversize at stat
    // time. In safe Rust backed by a real filesystem `File`, there is no
    // way to reach this branch from a unit test without wrapping the
    // reader in a custom `Read` impl (which would require refactoring
    // `read_password_file_inner` to accept a `Read` — out of scope).
    // The property is enforced by `Read::take(MAX_FILE_BYTES + 1)`
    // regardless of whether this branch is ever unit-test-reachable:
    // `read_to_end` can never push more than `MAX_FILE_BYTES + 1` bytes
    // into `buf`, so the comparison is both necessary and sufficient.
    if buf.len() as u64 > MAX_FILE_BYTES {
        return Err(BttError::invalid_input(format!(
            "password file {} exceeds {} bytes (possibly growing under us); refusing to read",
            path.display(),
            MAX_FILE_BYTES
        )));
    }

    // Strip a leading UTF-8 BOM if present. PowerShell's `Out-File -Encoding
    // utf8` emits a BOM; without this, the BOM bytes get prepended to the
    // password fed to argon2 and the user sees a "wrong password" error with
    // no obvious cause. Byte-level check so no utf-8 validation runs first.
    // Only the leading BOM is special; a BOM later in the file is left alone.
    // We strip at most ONE leading BOM by design: a file beginning with
    // `\xef\xbb\xbf\xef\xbb\xbf` keeps the second BOM as part of the
    // password. PowerShell never emits a double BOM, and silently eating
    // arbitrary numbers of leading BOMs would let a crafted file coerce
    // multiple distinct byte sequences into the same derived key.
    // Issue #28.
    const UTF8_BOM: &[u8] = &[0xef, 0xbb, 0xbf];
    if buf.starts_with(UTF8_BOM) {
        buf.drain(..UTF8_BOM.len());
    }

    // Take everything up to the first `\n`.
    let first_line_end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len());
    let mut first_line: &[u8] = &buf[..first_line_end];
    // Strip a trailing `\r` if the file used CRLF line endings.
    if let Some((&b'\r', rest)) = first_line.split_last() {
        first_line = rest;
    }

    // An empty `first_line` is **not** an error. btcli accepts empty
    // password files as a deliberate "empty password" choice — the
    // btcli-compat workflow's `[empty-password]` vector exercises exactly
    // this. Reverting an earlier guard (PR #39 round 2) that rejected
    // empty inputs: that guard was a btcli-compat regression, caught by
    // the verify job on the PRs that came after it.
    //
    // Three input shapes all resolve to an empty password and are all
    // legitimate user choices:
    //   1. a truly empty (zero-byte) file
    //   2. a file containing only a UTF-8 BOM (\xef\xbb\xbf), which is
    //      stripped above and leaves zero bytes
    //   3. a file containing only `\n` (or BOM + `\n`)
    //
    // An empty password is a weak password, but that is the user's
    // decision and a documented btcli convention. The encryption layer
    // does not crash on a zero-length secret — argon2id with a 0-length
    // input still derives a deterministic key, and that key is bound to
    // the wallet's NACL_SALT, so the result is no less recoverable than
    // any other key derived from a known input. The cryptographic
    // weakness is the user's to accept.

    let as_str = std::str::from_utf8(first_line).map_err(|_| {
        BttError::parse(format!(
            "password file {} does not contain valid UTF-8 on the first line",
            path.display()
        ))
    })?;

    Ok(Zeroizing::new(as_str.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("btt-pwfile-{}-{}", std::process::id(), name))
    }

    #[cfg(unix)]
    fn write_mode(path: &Path, contents: &[u8], mode: u32) {
        let mut f = fs::File::create(path).expect("create");
        f.write_all(contents).expect("write");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[cfg(unix)]
    #[test]
    fn reads_correctly_permissioned_file() {
        let p = tmp_path("ok");
        write_mode(&p, b"hunter2\n", 0o600);
        let pw = read_password_file_inner(&p).expect("read");
        assert_eq!(&*pw, "hunter2");
        fs::remove_file(&p).ok();
    }

    #[cfg(unix)]
    #[test]
    fn strips_lf() {
        let p = tmp_path("lf");
        write_mode(&p, b"abc\n", 0o600);
        let pw = read_password_file_inner(&p).expect("read");
        assert_eq!(&*pw, "abc");
        fs::remove_file(&p).ok();
    }

    #[cfg(unix)]
    #[test]
    fn strips_crlf() {
        let p = tmp_path("crlf");
        write_mode(&p, b"abc\r\n", 0o600);
        let pw = read_password_file_inner(&p).expect("read");
        assert_eq!(&*pw, "abc");
        fs::remove_file(&p).ok();
    }

    #[cfg(unix)]
    #[test]
    fn ignores_content_past_first_newline() {
        let p = tmp_path("multi");
        write_mode(&p, b"secret\nignored\nalso-ignored\n", 0o600);
        let pw = read_password_file_inner(&p).expect("read");
        assert_eq!(&*pw, "secret");
        fs::remove_file(&p).ok();
    }

    #[cfg(unix)]
    #[test]
    fn accepts_no_trailing_newline() {
        let p = tmp_path("notrail");
        write_mode(&p, b"nohup", 0o600);
        let pw = read_password_file_inner(&p).expect("read");
        assert_eq!(&*pw, "nohup");
        fs::remove_file(&p).ok();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_readable() {
        let p = tmp_path("world");
        write_mode(&p, b"pw\n", 0o644);
        let err = read_password_file_inner(&p).expect_err("should refuse");
        assert!(err.message.contains("insecure mode"), "msg: {}", err.message);
        fs::remove_file(&p).ok();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_readable() {
        let p = tmp_path("group");
        write_mode(&p, b"pw\n", 0o640);
        let err = read_password_file_inner(&p).expect_err("should refuse");
        assert!(err.message.contains("insecure mode"), "msg: {}", err.message);
        fs::remove_file(&p).ok();
    }

    #[test]
    fn rejects_missing_file() {
        let p = tmp_path("missing");
        let _ = fs::remove_file(&p);
        let err = read_password_file_inner(&p).expect_err("should fail");
        assert!(
            err.message.contains("failed to open password file"),
            "msg: {}",
            err.message
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_directory() {
        let p = tmp_path("dir");
        let _ = fs::remove_dir_all(&p);
        fs::create_dir(&p).expect("mkdir");
        let err = read_password_file_inner(&p).expect_err("should refuse dir");
        assert!(
            err.message.contains("not a regular file"),
            "msg: {}",
            err.message
        );
        fs::remove_dir(&p).ok();
    }

    #[cfg(unix)]
    #[test]
    fn accepts_symlink_to_mode_0600_file() {
        // The earlier revision of this file (issue #13) refused symlinks
        // outright via `O_NOFOLLOW`. That was dropped: the mode-0600 check
        // on the fd already guarantees the file is one of the caller's
        // own files, so a symlink pointing at such a file poses no risk.
        // Test that the portable `File::open` path accepts a symlink and
        // reads the target's contents.
        let target = tmp_path("sym-target");
        let link = tmp_path("sym-link");
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);
        write_mode(&target, b"pw\n", 0o600);
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let pw = read_password_file_inner(&link).expect("read through symlink");
        assert_eq!(&*pw, "pw");

        fs::remove_file(&link).ok();
        fs::remove_file(&target).ok();
    }

    // ---- issue #27: hard ceiling via Read::take ----

    #[cfg(unix)]
    #[test]
    fn oversize_file_errors() {
        // File of MAX_FILE_BYTES + 100. This exercises the metadata-time
        // advisory gate (`md.len() > MAX_FILE_BYTES`), NOT the read-time
        // `Read::take` ceiling — the advisory gate fires first, so the
        // error message is the "larger than" one, not the "exceeds" one.
        // The read-time `exceeds` branch is a TOCTOU defense-in-depth
        // that only fires if the file grows between `metadata()` and
        // `read_to_end()`; it is unit-test-unreachable in safe Rust
        // without a custom `Read` impl, and is documented as such at its
        // definition site. The property it enforces is guaranteed by
        // `Read::take(MAX_FILE_BYTES + 1)` regardless.
        let p = tmp_path("oversize");
        let n: usize = 64 * 1024 + 100;
        let payload = vec![b'a'; n];
        write_mode(&p, &payload, 0o600);
        let err = read_password_file_inner(&p).expect_err("should refuse");
        assert!(
            err.message.contains("larger than"),
            "expected the advisory md.len() gate wording 'larger than', got: {}",
            err.message
        );
        fs::remove_file(&p).ok();
    }

    #[cfg(unix)]
    #[test]
    fn at_size_limit_succeeds() {
        // File of exactly MAX_FILE_BYTES. The first byte is the password
        // 'x' followed by '\n', then filler. We should get "x" back and no
        // size error. Exercises the take(MAX+1) path returning exactly MAX.
        let p = tmp_path("atlimit");
        let n: usize = 64 * 1024;
        let mut payload = Vec::with_capacity(n);
        payload.extend_from_slice(b"x\n");
        payload.resize(n, b'y');
        write_mode(&p, &payload, 0o600);
        let pw = read_password_file_inner(&p).expect("read at limit");
        assert_eq!(&*pw, "x");
        fs::remove_file(&p).ok();
    }

    // ---- issue #28: strip leading UTF-8 BOM ----

    #[cfg(unix)]
    #[test]
    fn bom_is_stripped() {
        // PowerShell's `Out-File -Encoding utf8` writes \xef\xbb\xbf + bytes.
        // The BOM must not appear in the password we feed to argon2.
        let p = tmp_path("bom");
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0xef, 0xbb, 0xbf]);
        payload.extend_from_slice(b"password\n");
        write_mode(&p, &payload, 0o600);
        let pw = read_password_file_inner(&p).expect("read");
        assert_eq!(&*pw, "password");
        fs::remove_file(&p).ok();
    }

    #[cfg(unix)]
    #[test]
    fn bom_only_at_start() {
        // A BOM later in the file is a real character and must NOT be
        // stripped. Only a leading BOM is special.
        let p = tmp_path("bom-mid");
        let mut payload = Vec::new();
        payload.extend_from_slice(b"password");
        payload.extend_from_slice(&[0xef, 0xbb, 0xbf]);
        payload.extend_from_slice(b"\n");
        write_mode(&p, &payload, 0o600);
        let pw = read_password_file_inner(&p).expect("read");
        assert_eq!(pw.as_bytes(), b"password\xef\xbb\xbf");
        fs::remove_file(&p).ok();
    }

    #[cfg(unix)]
    #[test]
    fn bom_only_file_returns_empty_password() {
        // A file containing ONLY a UTF-8 BOM strips to zero bytes and
        // returns an empty password. This is a deliberate user choice
        // (matching btcli's `[empty-password]` compat vector) and is
        // documented as a weak-but-legitimate posture — see the comment
        // block in `read_password_file_inner` above the str::from_utf8.
        let p = tmp_path("bom-only");
        let payload = vec![0xef, 0xbb, 0xbf];
        write_mode(&p, &payload, 0o600);
        let pw = read_password_file_inner(&p).expect("BOM-only is empty pw, not an error");
        assert_eq!(pw.as_bytes(), b"");
        fs::remove_file(&p).ok();
    }

    #[cfg(unix)]
    #[test]
    fn bom_then_newline_only_returns_empty_password() {
        // Same as bom_only_file_returns_empty_password but with a trailing
        // newline (the more plausible shape PowerShell produces). After the
        // BOM strip and the first-line cut, the result is an empty password.
        let p = tmp_path("bom-nl");
        let payload = vec![0xef, 0xbb, 0xbf, b'\n'];
        write_mode(&p, &payload, 0o600);
        let pw = read_password_file_inner(&p).expect("BOM+\\n is empty pw, not an error");
        assert_eq!(pw.as_bytes(), b"");
        fs::remove_file(&p).ok();
    }

    #[cfg(unix)]
    #[test]
    fn empty_file_returns_empty_password() {
        // Zero-byte password file = empty password. btcli compat. The
        // btcli-compat workflow's `[empty-password]` vector is the
        // canonical test for this; PR #39 round 2's empty-file rejection
        // was a regression that broke that vector. This test pins the
        // restored behavior.
        let p = tmp_path("empty");
        write_mode(&p, b"", 0o600);
        let pw = read_password_file_inner(&p).expect("empty file is empty pw, not an error");
        assert_eq!(pw.as_bytes(), b"");
        fs::remove_file(&p).ok();
    }

    #[test]
    fn expand_tilde_absolute_untouched() {
        let p = expand_tilde("/tmp/foo", Some("/home/alice"));
        assert_eq!(p, PathBuf::from("/tmp/foo"));
        let p = expand_tilde("/tmp/foo", None);
        assert_eq!(p, PathBuf::from("/tmp/foo"));
    }

    #[test]
    fn expand_tilde_relative_untouched() {
        // A relative path with no leading tilde is passed through unchanged
        // regardless of the home value.
        let p = expand_tilde("foo/bar", Some("/home/alice"));
        assert_eq!(p, PathBuf::from("foo/bar"));
        let p = expand_tilde("foo/bar", None);
        assert_eq!(p, PathBuf::from("foo/bar"));
    }

    #[test]
    fn expand_tilde_prefix() {
        // No std::env::set_var here — the home directory is passed in.
        let p = expand_tilde("~/foo", Some("/home/alice"));
        assert_eq!(p, PathBuf::from("/home/alice/foo"));
    }

    #[test]
    fn expand_tilde_bare() {
        let p = expand_tilde("~", Some("/home/alice"));
        assert_eq!(p, PathBuf::from("/home/alice"));
    }

    #[test]
    fn expand_tilde_no_home_returns_unchanged() {
        // When HOME is unset, a tilde path has no expansion target and is
        // passed through unchanged. Caller-side error handling is expected
        // to detect the "~/foo" → "~/foo" no-op and surface it.
        let p = expand_tilde("~/foo", None);
        assert_eq!(p, PathBuf::from("~/foo"));
        let p = expand_tilde("~", None);
        assert_eq!(p, PathBuf::from("~"));
    }
}
