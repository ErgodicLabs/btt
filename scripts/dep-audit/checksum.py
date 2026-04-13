#!/usr/bin/env python3
"""
scripts/dep-audit/checksum.py

Dependency checksum tripwire. Detects the class of supply-chain attack that
cargo-audit and cargo-deny do not catch: same dep name, same version,
*different bytes*. This is the failure mode that destroyed btcli in 2024.

Design:
  - The committed database at .cryptid/dep-audit/checksums.db is the source
    of trust. Each line is:
        name@version<TAB>source-kind<TAB>sha256
    sorted lexicographically, deterministic, line-oriented so git diff
    renders readably.
  - On every run we parse Cargo.lock, compute the canonical sha256 for each
    (name, version, source) entry, and compare against the DB.
  - match        -> silent pass
  - mismatch     -> CRITICAL; exit 1; print the dep and both hashes
  - new entry    -> print; exit 1 unless --update was passed. --update
                    writes new entries into the DB, which the dev then
                    commits alongside the Cargo.lock change.

Canonical sha256 per source kind:
  - registry+   -> the `checksum` field that cargo already wrote into
                   Cargo.lock. This is the sha256 of the .crate tarball
                   that cargo itself verifies against the registry at
                   fetch time. Zero network, zero tooling; the strongest
                   possible signal at the lowest possible cost. Same bytes
                   cargo would refuse to build with if the registry served
                   different content.
  - git+        -> the commit SHA embedded in the source URL fragment.
                   Cargo.lock encodes `git+<url>?<rev>#<commit_sha>` and
                   git commits are content-addressed over the tree, so
                   the commit SHA is already a canonical content hash.
                   No checkout required.
  - path+       -> a deterministic sha256 over a sorted manifest of the
                   path dep's tree: sha256 of (relpath, mode, file-sha256)
                   tuples concatenated. Path deps are our own code, so
                   their checksums are expected to change with every
                   in-tree commit; they're tracked so a silently injected
                   path-override dep cannot sneak in unnoticed.

Exit codes:
  0 — all deps match the DB, no new entries (or --update and all writes OK)
  1 — at least one CRITICAL mismatch, or new entries without --update
  2 — script error (unreadable Cargo.lock, unknown source kind, etc.)

The script runs the same way locally and in CI. CI never passes --update;
any new dep without a committed DB entry fails the job. See
scripts/dep-audit/README.md for the operator's guide.
"""

import argparse
import hashlib
import os
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_LOCK = REPO_ROOT / "Cargo.lock"
DEFAULT_DB = REPO_ROOT / ".cryptid" / "dep-audit" / "checksums.db"

DB_HEADER = (
    "# btt dependency checksum database.\n"
    "# Generated and verified by scripts/dep-audit/checksum.py.\n"
    "# Each line: name@version<TAB>source-kind<TAB>sha256\n"
    "# Sorted lexicographically by the full line. Do not edit by hand;\n"
    "# use `scripts/dep-audit/checksum.py --update` to refresh after a\n"
    "# conscious Cargo.lock change, then commit the resulting diff.\n"
    "#\n"
    "# Source kinds:\n"
    "#   registry  — sha256 from Cargo.lock's `checksum` field (the .crate tarball hash)\n"
    "#   git       — the commit SHA embedded in the source URL fragment\n"
    "#   path      — sha256 of a deterministic manifest of the path dep's tree\n"
    "#\n"
    "# A mismatch on any existing line is a CRITICAL supply-chain signal.\n"
    "# See scripts/dep-audit/README.md and issue #6.\n"
)


# ---------------------------------------------------------------------------
# Cargo.lock parser (stdlib-only; Python 3.11 has tomllib but we avoid it
# to keep this script runnable on any Python 3.x without version checks).
# ---------------------------------------------------------------------------

def parse_cargo_lock(path):
    """
    Parse Cargo.lock into a list of dicts with keys: name, version, source,
    checksum. Unset fields are None. Only [[package]] blocks are extracted;
    metadata and other tables are ignored.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"error: cannot read {path}: {exc}")

    packages = []
    current = None
    in_package = False

    for raw in text.splitlines():
        line = raw.rstrip()
        if line == "[[package]]":
            if current is not None:
                packages.append(current)
            current = {"name": None, "version": None, "source": None, "checksum": None}
            in_package = True
            continue
        if line.startswith("[") and line != "[[package]]":
            if current is not None:
                packages.append(current)
                current = None
            in_package = False
            continue
        if not in_package or current is None:
            continue
        m = re.match(r'^(\w+)\s*=\s*"(.*)"\s*$', line)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if key in current:
            current[key] = val
    if current is not None:
        packages.append(current)

    return packages


# ---------------------------------------------------------------------------
# Canonical checksum per source kind
# ---------------------------------------------------------------------------

def classify_source(source):
    """
    Return (kind, rest) where kind is 'registry', 'git', 'path', or 'workspace'
    (the last for packages with no `source` line — the workspace crate itself).
    """
    if source is None:
        return ("workspace", "")
    if source.startswith("registry+"):
        return ("registry", source[len("registry+"):])
    if source.startswith("git+"):
        return ("git", source[len("git+"):])
    if source.startswith("path+"):
        return ("path", source[len("path+"):])
    raise SystemExit(f"error: unknown source kind: {source!r}")


def checksum_registry(pkg):
    """
    Registry deps: use the sha256 cargo already wrote into Cargo.lock.
    This is the hash of the .crate tarball that cargo verifies against the
    registry when fetching. If an attacker republishes different bytes under
    the same version on a non-crates.io registry (or a future crates.io that
    allows overwrites, or on a private index), this value changes and the
    tripwire fires.
    """
    if not pkg.get("checksum"):
        raise SystemExit(
            f"error: registry dep {pkg['name']}@{pkg['version']} has no "
            f"checksum field in Cargo.lock; cannot verify"
        )
    return pkg["checksum"]


def checksum_git(pkg, rest):
    """
    Git deps: Cargo.lock encodes the resolved commit SHA in the URL fragment,
    e.g. git+https://host/repo?branch=main#<40-hex-sha>. Git commits are
    content-addressed over the tree, so the commit SHA itself is a canonical
    content hash. We don't need to check out the tree.
    """
    if "#" not in rest:
        raise SystemExit(
            f"error: git dep {pkg['name']}@{pkg['version']} has no commit "
            f"fragment in source {rest!r}"
        )
    commit = rest.rsplit("#", 1)[1]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise SystemExit(
            f"error: git dep {pkg['name']}@{pkg['version']} has non-sha1 "
            f"commit fragment {commit!r}"
        )
    return commit


def checksum_path(pkg, rest):
    """
    Path deps: compute a deterministic sha256 of a sorted manifest of the
    tree. Path deps are our own code; their checksums are expected to change
    with any in-tree commit. Tracking them prevents a silently injected
    path-override dep from escaping the tripwire.
    """
    root = Path(rest)
    if not root.is_absolute():
        root = (REPO_ROOT / rest).resolve()
    if not root.exists():
        raise SystemExit(
            f"error: path dep {pkg['name']}@{pkg['version']} points at "
            f"{root} which does not exist"
        )
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            full = Path(dirpath) / fn
            if full.is_symlink():
                kind = "l"
                try:
                    target = os.readlink(full)
                except OSError as exc:
                    raise SystemExit(f"error: cannot read symlink {full}: {exc}")
                content_hash = hashlib.sha256(target.encode("utf-8")).hexdigest()
            else:
                kind = "f"
                h = hashlib.sha256()
                try:
                    with open(full, "rb") as fp:
                        for chunk in iter(lambda: fp.read(65536), b""):
                            h.update(chunk)
                except OSError as exc:
                    raise SystemExit(f"error: cannot read {full}: {exc}")
                content_hash = h.hexdigest()
            rel = full.relative_to(root).as_posix()
            entries.append(f"{kind} {rel} {content_hash}")
    entries.sort()
    manifest = "\n".join(entries).encode("utf-8")
    return hashlib.sha256(manifest).hexdigest()


def compute_entry(pkg):
    """
    Return (key, kind, sha) for a parsed package, or None for the workspace
    crate itself (which has no source and is skipped — it is not a dep).
    """
    kind, rest = classify_source(pkg["source"])
    if kind == "workspace":
        return None
    if kind == "registry":
        sha = checksum_registry(pkg)
    elif kind == "git":
        sha = checksum_git(pkg, rest)
    elif kind == "path":
        sha = checksum_path(pkg, rest)
    else:
        raise SystemExit(f"error: unhandled source kind {kind!r}")
    key = f"{pkg['name']}@{pkg['version']}"
    return (key, kind, sha)


# ---------------------------------------------------------------------------
# DB load / save
# ---------------------------------------------------------------------------

def load_db(path):
    """
    Return a dict {key: (kind, sha)}. Missing file -> empty dict.
    """
    db = {}
    if not path.exists():
        return db
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 3:
            raise SystemExit(f"error: malformed DB line in {path}: {raw!r}")
        key, kind, sha = parts
        db[key] = (kind, sha)
    return db


def save_db(path, db):
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{k}\t{v[0]}\t{v[1]}" for k, v in db.items()]
    lines.sort()
    body = DB_HEADER + "\n".join(lines) + "\n"
    path.write_text(body, encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="checksum.py",
        description=(
            "Dependency checksum tripwire. Compares the per-dep sha256 of "
            "the current Cargo.lock against the committed database at "
            ".cryptid/dep-audit/checksums.db. Fires on same-version-"
            "different-bytes supply-chain attacks. See issue #6."
        ),
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help=(
            "Write new-dep entries into the DB. Required when Cargo.lock "
            "adds or changes deps. CI never passes this flag; the dev "
            "runs it locally and commits the DB diff alongside the "
            "Cargo.lock change."
        ),
    )
    parser.add_argument(
        "--lock",
        default=str(DEFAULT_LOCK),
        help=f"path to Cargo.lock (default: {DEFAULT_LOCK})",
    )
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB),
        help=f"path to checksum DB (default: {DEFAULT_DB})",
    )
    parser.add_argument(
        "--report",
        default=None,
        help="optional path to write a Markdown report suitable for a PR comment",
    )
    args = parser.parse_args(argv)

    lock_path = Path(args.lock)
    db_path = Path(args.db)

    try:
        packages = parse_cargo_lock(lock_path)
    except SystemExit:
        raise
    except Exception as exc:
        print(f"error: failed to parse {lock_path}: {exc}", file=sys.stderr)
        return 2

    current = {}
    for pkg in packages:
        if not pkg.get("name") or not pkg.get("version"):
            continue
        entry = compute_entry(pkg)
        if entry is None:
            continue
        key, kind, sha = entry
        prev = current.get(key)
        if prev is not None and prev != (kind, sha):
            # Two [[package]] blocks with the same name+version but different
            # source/sha. Cargo should not produce this; treat as script error.
            print(
                f"error: duplicate package {key} with divergent source/sha: "
                f"{prev} vs {(kind, sha)}",
                file=sys.stderr,
            )
            return 2
        current[key] = (kind, sha)

    db = load_db(db_path)

    matches = []
    mismatches = []  # (key, db_kind, db_sha, cur_kind, cur_sha)
    new_entries = []  # (key, kind, sha)
    stale = []  # in db but no longer in current

    for key, (kind, sha) in sorted(current.items()):
        if key not in db:
            new_entries.append((key, kind, sha))
            continue
        db_kind, db_sha = db[key]
        if (db_kind, db_sha) == (kind, sha):
            matches.append(key)
        else:
            mismatches.append((key, db_kind, db_sha, kind, sha))

    for key in sorted(db):
        if key not in current:
            stale.append(key)

    # --- report --------------------------------------------------------
    report_lines = []
    report_lines.append("### dep-checksum tripwire")
    report_lines.append("")
    report_lines.append(
        f"Tracked: {len(current)} deps; DB entries: {len(db)}; "
        f"matches: {len(matches)}; new: {len(new_entries)}; "
        f"stale: {len(stale)}; mismatches: {len(mismatches)}."
    )
    report_lines.append("")

    if mismatches:
        report_lines.append("**CRITICAL — checksum mismatch on existing entry:**")
        report_lines.append("")
        report_lines.append("```")
        for key, db_kind, db_sha, cur_kind, cur_sha in mismatches:
            report_lines.append(f"  {key}")
            report_lines.append(f"    DB:      {db_kind} {db_sha}")
            report_lines.append(f"    current: {cur_kind} {cur_sha}")
        report_lines.append("```")
        report_lines.append("")
        report_lines.append(
            "Same name, same version, different bytes. This is the "
            "tripwire signal for a maintainer-trust / republish supply-"
            "chain attack. Do not merge until the cause is understood. "
            "See scripts/dep-audit/README.md."
        )
        report_lines.append("")

    if new_entries:
        report_lines.append("**New deps (not yet in DB):**")
        report_lines.append("")
        report_lines.append("```")
        for key, kind, sha in new_entries:
            report_lines.append(f"  {key}  {kind}  {sha}")
        report_lines.append("```")
        report_lines.append("")
        if not args.update:
            report_lines.append(
                "These entries are not in the committed DB. Run "
                "`scripts/dep-audit/checksum.py --update` locally and "
                "commit the resulting DB diff alongside the Cargo.lock "
                "change. CI never runs with --update."
            )
            report_lines.append("")

    if stale:
        report_lines.append("**Stale DB entries (in DB but not in Cargo.lock):**")
        report_lines.append("")
        report_lines.append("```")
        for key in stale:
            report_lines.append(f"  {key}")
        report_lines.append("```")
        report_lines.append("")
        if args.update:
            report_lines.append("Stale entries will be pruned on --update.")
        else:
            report_lines.append(
                "Stale entries are informational only; they do not fail "
                "the check. Run with --update to prune."
            )
        report_lines.append("")

    if not mismatches and not new_entries and not stale:
        report_lines.append("All deps match the committed DB. No drift.")
        report_lines.append("")

    status_fail = bool(mismatches) or (bool(new_entries) and not args.update)
    report_lines.append("STATUS: " + ("FAIL" if status_fail else "PASS"))

    report_text = "\n".join(report_lines) + "\n"
    sys.stdout.write(report_text)
    if args.report:
        Path(args.report).write_text(report_text, encoding="utf-8")

    # --- decide exit + optional DB write ------------------------------
    if mismatches:
        return 1

    if new_entries or stale:
        if args.update:
            new_db = dict(db)
            for key, kind, sha in new_entries:
                new_db[key] = (kind, sha)
            for key in stale:
                new_db.pop(key, None)
            save_db(db_path, new_db)
            print(
                f"\nDB updated: +{len(new_entries)} new, -{len(stale)} stale "
                f"-> {db_path}",
                file=sys.stderr,
            )
            return 0
        if new_entries:
            return 1
        # stale-only without --update is informational; pass
        return 0

    if args.update and not db_path.exists():
        save_db(db_path, current)
        print(f"\nDB seeded at {db_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
