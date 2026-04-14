#!/usr/bin/env python3
"""
Unit tests for scripts/dep-audit/checksum.py.

Stdlib-only (unittest). No pytest. Run with either:

    python3 -m unittest scripts/dep-audit/test_checksum.py -v
    python3 scripts/dep-audit/test_checksum.py

These tests pin the four follow-up fixes from issue #22:

  LOW-1  path+file:// URL handling — classify_source must return an absolute
         filesystem path so checksum_path doesn't try to re-join it against
         REPO_ROOT (which would produce a nonsense path and hard-fail).

  LOW-2  path-dep manifest exclusions — checksum_path must skip target/,
         .git/, editor swap files (*.swp, *.swo, *~), and .DS_Store so the
         checksum doesn't churn on every build of any future path dep.

  INFO-1 exit code 2 on script error — script-error paths must exit 2,
         distinct from exit 1 (mismatch / new-entry-without-update). Tested
         here by raising the unknown-source-kind error.

  INFO-2 cosmetic — under --update the "**New deps (not yet in DB):**"
         interstitial is suppressed because by the time the report renders
         the entries have been written. The trailing "DB updated" line on
         stderr already tells the operator what changed.
"""

import contextlib
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
CHECKSUM_PY = HERE / "checksum.py"


def _load_checksum_module():
    """
    Load checksum.py as a module despite the parent directory's hyphen
    (which prevents normal `import scripts.dep_audit.checksum`). We load
    by absolute file path via importlib so the test file is fully
    self-contained.
    """
    spec = importlib.util.spec_from_file_location("checksum_under_test", CHECKSUM_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checksum = _load_checksum_module()


class ClassifySourceTests(unittest.TestCase):
    """LOW-1: path+file:// URLs must resolve to an absolute filesystem path."""

    def test_path_file_url_returns_absolute_path(self):
        # Synthetic Cargo.lock-shaped source line for a path dep.
        source = "path+file:///tmp/some-path-dep"
        kind, rest = checksum.classify_source(source)
        self.assertEqual(kind, "path")
        self.assertEqual(rest, "/tmp/some-path-dep")
        # The returned value must be a usable absolute path; pathlib agrees.
        self.assertTrue(Path(rest).is_absolute())

    def test_path_file_url_with_nested_path(self):
        source = "path+file:///home/dev/projects/my-crate"
        kind, rest = checksum.classify_source(source)
        self.assertEqual(kind, "path")
        self.assertEqual(rest, "/home/dev/projects/my-crate")

    def test_registry_source_unchanged(self):
        source = "registry+https://github.com/rust-lang/crates.io-index"
        kind, rest = checksum.classify_source(source)
        self.assertEqual(kind, "registry")
        self.assertTrue(rest.startswith("https://"))

    def test_git_source_unchanged(self):
        source = "git+https://example.invalid/foo?branch=main#" + ("a" * 40)
        kind, rest = checksum.classify_source(source)
        self.assertEqual(kind, "git")
        self.assertTrue(rest.startswith("https://"))

    def test_workspace_source_when_none(self):
        kind, rest = checksum.classify_source(None)
        self.assertEqual(kind, "workspace")
        self.assertEqual(rest, "")


class PathDepExclusionTests(unittest.TestCase):
    """LOW-2: target/, .git/, editor swap files must not enter the manifest."""

    def _build_tree(self, root: Path) -> None:
        # Real source file that MUST be in the manifest.
        (root / "src").mkdir()
        (root / "src" / "lib.rs").write_text("fn main() {}\n", encoding="utf-8")
        (root / "Cargo.toml").write_text("[package]\nname = \"x\"\n", encoding="utf-8")

        # target/ — build artifacts; must be excluded.
        (root / "target").mkdir()
        (root / "target" / "debug").mkdir()
        (root / "target" / "debug" / "build.log").write_text("noise", encoding="utf-8")

        # .git/ — vcs metadata; must be excluded.
        (root / ".git").mkdir()
        (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")

        # Editor swap and OS metadata files; must be excluded.
        (root / "src" / ".lib.rs.swp").write_text("vim noise", encoding="utf-8")
        (root / "src" / "lib.rs.swo").write_text("vim noise", encoding="utf-8")
        (root / "src" / "lib.rs~").write_text("backup noise", encoding="utf-8")
        (root / ".DS_Store").write_text("mac noise", encoding="utf-8")

    def test_excluded_paths_do_not_appear_in_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "fake-path-dep"
            root.mkdir()
            self._build_tree(root)

            # Synthetic pkg dict the way checksum_path consumes it.
            pkg = {"name": "fake", "version": "0.0.0"}
            sha = checksum.checksum_path(pkg, str(root))
            self.assertRegex(sha, r"^[0-9a-f]{64}$")

            # We re-derive the manifest the same way checksum_path does
            # (minus hashing) so we can assert which relpaths were included.
            included = self._collect_relpaths(root)

            # Source files we expect.
            self.assertIn("Cargo.toml", included)
            self.assertIn("src/lib.rs", included)

            # Excluded directories: nothing under them must appear.
            for rel in included:
                self.assertFalse(
                    rel.startswith("target/"),
                    f"target/ should be excluded, found {rel!r}",
                )
                self.assertFalse(
                    rel.startswith(".git/"),
                    f".git/ should be excluded, found {rel!r}",
                )

            # Excluded filename globs: none of these basenames must appear.
            for rel in included:
                base = rel.rsplit("/", 1)[-1]
                self.assertNotEqual(base, ".lib.rs.swp")
                self.assertNotEqual(base, "lib.rs.swo")
                self.assertNotEqual(base, "lib.rs~")
                self.assertNotEqual(base, ".DS_Store")

    def _collect_relpaths(self, root: Path):
        """
        Mirror the walk in checksum_path so we can introspect what would be
        hashed without recomputing the digest by hand.
        """
        import fnmatch

        rels = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                d for d in dirnames if d not in checksum.PATH_DEP_EXCLUDE_DIRS
            ]
            dirnames.sort()
            for fn in sorted(filenames):
                if any(
                    fnmatch.fnmatch(fn, pat)
                    for pat in checksum.PATH_DEP_EXCLUDE_FILE_GLOBS
                ):
                    continue
                full = Path(dirpath) / fn
                rels.append(full.relative_to(root).as_posix())
        return rels

    def test_manifest_stable_when_only_excluded_files_change(self):
        """
        Stronger property: adding more target/ noise must not change the
        digest. This is the actual reason the exclusions exist.
        """
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "fake-path-dep"
            root.mkdir()
            self._build_tree(root)
            pkg = {"name": "fake", "version": "0.0.0"}
            sha_before = checksum.checksum_path(pkg, str(root))

            # Add more excluded noise.
            (root / "target" / "debug" / "more.log").write_text("more", encoding="utf-8")
            (root / ".git" / "objects").mkdir()
            (root / ".git" / "objects" / "abc").write_text("blob", encoding="utf-8")
            (root / "src" / "another.rs.swp").write_text("vim", encoding="utf-8")

            sha_after = checksum.checksum_path(pkg, str(root))
            self.assertEqual(
                sha_before,
                sha_after,
                "checksum must be stable when only excluded paths change",
            )


class ExitCodeTwoTests(unittest.TestCase):
    """INFO-1: script-error paths must exit 2, not 1."""

    def test_unknown_source_kind_exits_two_in_process(self):
        with self.assertRaises(SystemExit) as cm:
            checksum.classify_source("svn+https://example.invalid/repo")
        self.assertEqual(cm.exception.code, 2)

    def test_die_helper_exits_two(self):
        with self.assertRaises(SystemExit) as cm:
            checksum._die("error: synthetic")
        self.assertEqual(cm.exception.code, 2)

    def test_unreadable_lock_exits_two_subprocess(self):
        # Spawn the script with a --lock pointing at a path that does not
        # exist. Should emit an error and exit 2.
        result = subprocess.run(
            [
                sys.executable,
                str(CHECKSUM_PY),
                "--lock",
                "/nonexistent/path/Cargo.lock",
                "--db",
                "/nonexistent/path/checksums.db",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            2,
            f"expected exit 2 on unreadable Cargo.lock, got {result.returncode}; "
            f"stderr={result.stderr!r}",
        )
        self.assertIn("error:", result.stderr)


class UpdateModeInterstitialTests(unittest.TestCase):
    """INFO-2: --update runs must not show the 'Run --update' interstitial."""

    def test_update_run_omits_run_update_interstitial(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            # Minimal valid Cargo.lock with a single registry dep so the
            # script has work to do and the new_entries branch is exercised.
            lock = tdp / "Cargo.lock"
            lock.write_text(
                'version = 4\n'
                '\n'
                '[[package]]\n'
                'name = "synthetic-dep"\n'
                'version = "1.2.3"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                'checksum = "' + ("a" * 64) + '"\n',
                encoding="utf-8",
            )
            db = tdp / "checksums.db"  # does not exist; will be seeded

            # Capture stdout while invoking main(--update).
            buf = io.StringIO()
            err_buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err_buf):
                rc = checksum.main(
                    ["--update", "--lock", str(lock), "--db", str(db)]
                )
            self.assertEqual(rc, 0, f"expected rc=0, got {rc}; out={buf.getvalue()!r}")

            out = buf.getvalue()

            # The "Run --update" interstitial must NOT appear.
            self.assertNotIn("Run `scripts/dep-audit/checksum.py --update`", out)
            self.assertNotIn("CI never runs with --update", out)
            # The "New deps (not yet in DB)" header must also not appear,
            # because by the time the report renders the entries have been
            # written and that framing is stale.
            self.assertNotIn("**New deps (not yet in DB):**", out)
            # Sanity: STATUS line still reported.
            self.assertIn("STATUS: PASS", out)

            # The DB should have been written.
            self.assertTrue(db.exists())
            db_text = db.read_text(encoding="utf-8")
            self.assertIn("synthetic-dep@1.2.3", db_text)

    def test_non_update_run_keeps_run_update_interstitial(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            lock = tdp / "Cargo.lock"
            lock.write_text(
                'version = 4\n'
                '\n'
                '[[package]]\n'
                'name = "synthetic-dep"\n'
                'version = "1.2.3"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                'checksum = "' + ("a" * 64) + '"\n',
                encoding="utf-8",
            )
            db = tdp / "checksums.db"

            buf = io.StringIO()
            err_buf = io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err_buf):
                rc = checksum.main(["--lock", str(lock), "--db", str(db)])

            # Without --update and with a new dep, the script returns 1.
            self.assertEqual(rc, 1)
            out = buf.getvalue()
            # The interstitial IS present in the non-update case.
            self.assertIn("**New deps (not yet in DB):**", out)
            self.assertIn("Run `scripts/dep-audit/checksum.py --update`", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
