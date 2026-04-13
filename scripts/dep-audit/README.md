# scripts/dep-audit

Basic dependency audit for btt. Runs `cargo-audit`, `cargo-deny`, and `cargo-outdated` against the current checkout and emits a Markdown summary suitable for posting as a PR comment.

## Why

Per `AGENTS.md` principle 1, every dependency is an attack surface until proven essential. This script is the first line of defense: it surfaces known-bad versions (cargo-audit), license / source / ban policy violations (cargo-deny), and stale direct deps (cargo-outdated). The information goes to a human reviewer who applies the policy.

The same mechanism is wired into CI via `.github/workflows/dep-audit.yml`, which posts the report as a PR comment and fails the job on any cargo-audit advisory or cargo-deny error.

This is the *basic* dep audit. The dep-checksum tripwire that detects same-version-different-bytes attacks (issue #6) is layered on later as a separate workflow.

## Usage

Local run:

```
./scripts/dep-audit/audit.sh
```

The script writes the Markdown report to stdout. Exit code is 0 on PASS, 1 on FAIL. PASS means no cargo-audit advisories and no cargo-deny errors. cargo-outdated is informational only.

The script must be run from any directory inside the repo; it locates the workspace root from its own path.

## Required tools

- `cargo-audit` (rustsec advisory db)
- `cargo-deny` (license/source/ban policy)
- `cargo-outdated` (informational)

The CI workflow installs them automatically and caches the resulting binaries. For local runs:

```
cargo install --locked cargo-audit cargo-deny cargo-outdated
```

## Configuration

`scripts/dep-audit/deny.toml` — cargo-deny config. License allowlist, banned crates, source allowlist, advisory ignores. Currently permissive; tightens as the project matures.

## Files

- `audit.sh`     — main script
- `deny.toml`    — cargo-deny configuration
- `README.md`    — this file

## Related

- `.github/workflows/dep-audit.yml` — CI integration
- Issue #6 — dep-checksum tripwire (the next layer)
- AGENTS.md principle 1 — dependency discipline (the policy this enforces)
