# scripts/dep-audit

Basic dependency audit for btt. Runs `cargo-audit`, `cargo-deny`, and `cargo-outdated` against the current checkout and emits a Markdown summary suitable for posting as a PR comment.

## Why

Per `AGENTS.md` principle 1, every dependency is an attack surface until proven essential. This script is the first line of defense: it surfaces known-bad versions (cargo-audit), license / source / ban policy violations (cargo-deny), and stale direct deps (cargo-outdated). The information goes to a human reviewer who applies the policy.

The same mechanism is wired into CI via `.github/workflows/dep-audit.yml`, which posts the report as a PR comment and fails the job on any cargo-audit advisory or cargo-deny error.

On top of that, the dep-checksum tripwire (`checksum.py`, issue #6) detects the class of supply-chain attack the other tools cannot catch: **same dep, same version, different bytes**. This is the pathway that destroyed btcli in 2024. The tripwire compares every dep in `Cargo.lock` against a committed database of trusted checksums at `.cryptid/dep-audit/checksums.db`, and fires on any drift.

## Usage

Local run:

```
./scripts/dep-audit/audit.sh
python3 scripts/dep-audit/checksum.py
```

`audit.sh` writes a Markdown report to stdout. Exit code is 0 on PASS, 1 on FAIL. PASS means no cargo-audit advisories and no cargo-deny errors. cargo-outdated is informational only.

`checksum.py` writes its own Markdown section to stdout. Exit code is 0 if every dep in `Cargo.lock` matches the committed DB, 1 on any mismatch or uncommitted new entry, 2 on script error.

The scripts must be runnable from any directory inside the repo; they locate the workspace root from their own path.

## Required tools

- `cargo-audit` (rustsec advisory db)
- `cargo-deny` (license/source/ban policy)
- `cargo-outdated` (informational)
- `python3` (for `checksum.py`; stdlib only, no pip deps)

The CI workflow installs the cargo tools automatically and caches the resulting binaries. `python3` is already present on the `ubuntu-latest` runner. For local runs:

```
cargo install --locked cargo-audit cargo-deny cargo-outdated
```

## Configuration

`scripts/dep-audit/deny.toml` — cargo-deny config. License allowlist, banned crates, source allowlist, advisory ignores. Currently permissive; tightens as the project matures.

## Dep-checksum tripwire (issue #6)

### What it catches

`cargo audit` flags known-bad versions against the rustsec advisory DB. `cargo deny` flags policy violations. Neither notices when an attacker republishes different bytes under the same name and same version — the registry overwrite / yank-and-rebuild / compromised-maintainer pathway that destroyed btcli in 2024.

`checksum.py` closes that gap. It computes a canonical sha256 for every dep in `Cargo.lock` and compares against a committed database. Same name, same version, different bytes is a hard failure.

### The database

`.cryptid/dep-audit/checksums.db` is a plain-text, line-oriented, lexicographically sorted file committed into the repo. Each line is:

```
name@version<TAB>source-kind<TAB>sha256
```

Source kinds:

- `registry` — the sha256 that cargo already wrote into `Cargo.lock`'s `checksum` field. This is the hash of the `.crate` tarball cargo verifies against the registry at fetch time. Zero network, zero extra tooling; the strongest possible signal at the lowest possible cost.
- `git` — the 40-char commit SHA embedded in the `Cargo.lock` source URL fragment. Git commits are content-addressed over the tree, so the commit SHA itself is a canonical content hash.
- `path` — sha256 of a deterministic manifest (sorted `relpath + sha256(content)` tuples) of the path dep's tree. Path deps are our own code; tracking them prevents a silently injected path override from escaping the tripwire.

The DB's git history is the audit log. `git log .cryptid/dep-audit/` shows every byte-level dep change with an author, a commit, and a message. Reverting a bad change is just `git revert`.

### Usage

```
# Verify (CI behavior; default)
python3 scripts/dep-audit/checksum.py

# After a conscious Cargo.lock change that adds or changes deps
python3 scripts/dep-audit/checksum.py --update
git add .cryptid/dep-audit/checksums.db Cargo.lock
git commit
```

CI never passes `--update`. Any `Cargo.lock` diff that lacks the corresponding DB diff fails the PR — a `Cargo.lock` change that does not also touch `checksums.db` is mechanically suspect, and a reviewer can read the DB diff directly.

### Three outcomes

- **match** — silent pass.
- **mismatch on an existing entry** — CRITICAL, exit 1. The report prints the dep, the DB sha, and the current sha. Do not merge until the cause is understood.
- **new entry** — exit 1 unless `--update` is passed. Forces a conscious commit of the DB delta.

### Handling a CRITICAL finding

1. Do not merge. Do not `--update` the DB to paper over the finding; that disarms the tripwire.
2. Identify the diverging dep from the report. It prints `dep@version`, `DB sha`, and `current sha`.
3. Determine the cause. Common benign causes: a dep changed source kind (registry to git), a local Cargo registry mirror is serving stale content, a `cargo update` reshuffled a resolution in an unexpected way. Common malicious causes: a maintainer account compromise, a registry overwrite, a moved git ref.
4. If malicious: revert the `Cargo.lock` change, report the upstream to the registry, and file an advisory in this repo. Do not touch the DB.
5. If benign: understand *why* the bytes changed under the same version, document the reason in the commit message, and only then run `--update` and commit the DB diff. The commit message is part of the audit log.

### Flags

- `--update` — write new and stale deltas into the DB. Required after `Cargo.lock` changes. CI never passes this.
- `--lock PATH` — alternate `Cargo.lock` path.
- `--db PATH` — alternate DB path.
- `--report PATH` — also write the Markdown report to a file (CI uses this).

## Files

- `audit.sh`     — cargo-audit / cargo-deny / cargo-outdated dispatcher
- `checksum.py`  — dep-checksum tripwire (issue #6)
- `deny.toml`    — cargo-deny configuration
- `README.md`    — this file

## Related

- `.github/workflows/dep-audit.yml` — CI integration (both scripts run here)
- `.cryptid/dep-audit/checksums.db` — committed trusted checksum database
- Issue #6 — dep-checksum tripwire
- AGENTS.md principle 1 — dependency discipline (the policy this enforces)
