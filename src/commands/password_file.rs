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

/// Resolve `~` prefixes and `~user`-less tilde expansion using `$HOME`.
///
/// We deliberately do NOT do arbitrary shell expansion — no `$VAR`
/// substitution, no glob, no `..` magic. A password file path is supposed to
/// be a concrete on-disk location.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
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
    let resolved = expand_tilde(path);
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

    let mut buf = Zeroizing::new(Vec::<u8>::with_capacity(md.len() as usize));
    file.read_to_end(&mut buf)
        .map_err(|e| BttError::io(format!("failed to read password file: {}", e)))?;

    // Take everything up to the first `\n`.
    let first_line_end = buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len());
    let mut first_line: &[u8] = &buf[..first_line_end];
    // Strip a trailing `\r` if the file used CRLF line endings.
    if let Some((&b'\r', rest)) = first_line.split_last() {
        first_line = rest;
    }

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

    #[test]
    fn expand_tilde_absolute_untouched() {
        let p = expand_tilde("/tmp/foo");
        assert_eq!(p, PathBuf::from("/tmp/foo"));
    }

    #[test]
    fn expand_tilde_relative_untouched() {
        let p = expand_tilde("foo/bar");
        assert_eq!(p, PathBuf::from("foo/bar"));
    }

    #[test]
    fn expand_tilde_prefix() {
        std::env::set_var("HOME", "/home/alice");
        let p = expand_tilde("~/foo");
        assert_eq!(p, PathBuf::from("/home/alice/foo"));
    }
}
