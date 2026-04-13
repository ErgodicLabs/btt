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
//! - On unix, we refuse to read a file whose mode is other-readable
//!   (`mode & 0o077 != 0`). Fail-closed. The caller is instructed to
//!   `chmod 600 <path>`.
//! - We refuse anything that is not a regular file. No FIFOs, no character
//!   devices, no directories. A password file is a tiny thing on a tmpfs;
//!   it should not be a pipe.
//! - On unix, we open with `O_NOFOLLOW` and refuse symlinks entirely. The
//!   user's intent in `--password-file <path>` is "this exact file", not
//!   "whatever `<path>` resolves to". Following symlinks would let an
//!   attacker who can write into the containing directory swap a symlink
//!   pointing at `~/.ssh/id_rsa` (or any other readable secret) between
//!   btt's stat and btt's open. We close the TOCTOU window two ways at
//!   once: refuse symlinks, and derive metadata from the open fd instead
//!   of re-stat'ing the path. See issue #13.
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
use std::os::unix::fs::OpenOptionsExt;
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
    // Order matters for security. Issue #13: the previous implementation
    // called `fs::metadata(path)` first and then `fs::File::open(path)`
    // later, leaving a TOCTOU window in which an attacker with write access
    // to the containing directory could swap a symlink between the two
    // syscalls. btt would validate one file and then read another.
    //
    // The fix is two-fold:
    //   1. Open the file FIRST, with `O_NOFOLLOW` (unix), so symlinks are
    //      refused outright at open() time.
    //   2. Derive metadata from the open fd — `file.metadata()` — rather
    //      than re-stat'ing the path. Once the fd is open, the referent
    //      cannot change under us.
    //
    // On the error paths below, the fd held in `file` is dropped by `?` /
    // early return, which closes it; no fd leak.
    #[cfg(unix)]
    let mut file = {
        let mut opts = fs::OpenOptions::new();
        // O_NOFOLLOW: refuse symlinks outright (issue #13).
        // O_NONBLOCK: don't hang if the caller points us at a FIFO with
        //   no writer — return immediately so `is_file()` below can reject
        //   it. Regular files ignore O_NONBLOCK, so this is a no-op on the
        //   happy path.
        opts.read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        opts.open(path).map_err(|e| {
            // ELOOP is the kernel's signal that `path` was a symlink and
            // O_NOFOLLOW refused it. Surface that plainly so operators
            // aren't left guessing why a perfectly readable-looking file
            // won't open.
            if e.raw_os_error() == Some(libc::ELOOP) {
                BttError::io(format!(
                    "password file {} is a symlink; refusing to follow (O_NOFOLLOW). \
                     Pass the real path or copy the file.",
                    path.display()
                ))
            } else {
                BttError::io(format!(
                    "failed to open password file {}: {}",
                    path.display(),
                    e
                ))
            }
        })?
    };
    #[cfg(not(unix))]
    let mut file = fs::File::open(path).map_err(|e| {
        BttError::io(format!(
            "failed to open password file {}: {}",
            path.display(),
            e
        ))
    })?;

    // Metadata from the open fd. This is what closes the TOCTOU window:
    // whatever we inspect here is exactly what we'll read below.
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
    fn rejects_fifo() {
        // Create a FIFO via the `mkfifo` binary. We carry `libc` as a dep
        // now (issue #13), but shelling out to `mkfifo` keeps the test
        // identical to its pre-#13 form; the point is that `is_file()` on
        // an fd opened via `O_NOFOLLOW | O_NONBLOCK` still rejects pipes.
        let p = tmp_path("fifo");
        let _ = fs::remove_file(&p);
        let status = std::process::Command::new("mkfifo")
            .arg(&p)
            .status();
        // If mkfifo isn't on the runner (highly unusual on linux/macos),
        // skip the test rather than fail it.
        let Ok(status) = status else {
            eprintln!("mkfifo not available; skipping FIFO test");
            return;
        };
        if !status.success() {
            eprintln!("mkfifo failed; skipping FIFO test");
            return;
        }
        // chmod 600 so the permission check doesn't short-circuit with
        // "insecure mode". We want the is_file check to be the one that
        // trips.
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).expect("chmod fifo");
        let err = read_password_file_inner(&p).expect_err("should refuse FIFO");
        assert!(
            err.message.contains("not a regular file"),
            "msg: {}",
            err.message
        );
        fs::remove_file(&p).ok();
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
    fn rejects_symlink_to_regular_file() {
        // Issue #13: even a symlink pointing at a perfectly-permissioned
        // file must be refused. The user asked for the file at `<path>`;
        // if `<path>` is a symlink, we have no way to know whether it was
        // swapped in under us.
        let target = tmp_path("sym-target");
        let link = tmp_path("sym-link");
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);
        write_mode(&target, b"pw\n", 0o600);
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let err = read_password_file_inner(&link).expect_err("should refuse symlink");
        assert!(
            err.message.contains("symlink") && err.message.contains("O_NOFOLLOW"),
            "msg: {}",
            err.message
        );

        fs::remove_file(&link).ok();
        fs::remove_file(&target).ok();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_to_nonexistent_target() {
        // A dangling symlink is also refused at open() time by O_NOFOLLOW.
        // Crucially, the error comes from the open() call, not from a
        // separate stat — so there is no TOCTOU window to race.
        let link = tmp_path("sym-dangling");
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink("/nonexistent/btt-issue-13/nope", &link).expect("symlink");

        let err = read_password_file_inner(&link).expect_err("should refuse dangling symlink");
        assert!(
            err.message.contains("symlink") && err.message.contains("O_NOFOLLOW"),
            "msg: {}",
            err.message
        );

        fs::remove_file(&link).ok();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_in_place_of_regular_file() {
        // Structural test for the TOCTOU fix. The previous (vulnerable)
        // implementation would `fs::metadata(path)` first — which follows
        // symlinks — and then `fs::File::open(path)` later, which also
        // follows symlinks. An attacker could swap the target between the
        // two calls and btt would happily read the attacker's file.
        //
        // The new implementation opens with `O_NOFOLLOW` and takes
        // metadata from the *open fd*. Once the fd is open the referent
        // cannot change. A racing-symlink test is impractical (you can't
        // reliably win a race in CI), so we assert the structural
        // property: when `path` is a symlink at all, the function refuses
        // to open it. This is strictly stronger than "symlinks cannot be
        // swapped mid-op" — swapping is moot when the initial open
        // already fails.
        let target = tmp_path("race-target");
        let link = tmp_path("race-link");
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);
        write_mode(&target, b"attacker\n", 0o600);
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        // Even mode 0600 on the target cannot launder the link.
        let err = read_password_file_inner(&link).expect_err("symlink must be refused");
        assert!(
            err.message.contains("O_NOFOLLOW"),
            "error should name the defense: {}",
            err.message
        );

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
