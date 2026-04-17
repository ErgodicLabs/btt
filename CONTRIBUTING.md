# Contributing to btt

## Getting started

```bash
git clone git@github.com:ErgodicLabs/btt.git
cd btt
cargo build
cargo test
```

See [docs/developer-guide.md](docs/developer-guide.md) for the full codebase walkthrough: project layout, how to add commands, key abstractions, and testing.

## Before you submit a PR

### Local gates

Run these before every push:

```bash
cargo check
cargo clippy -- -D warnings
```

CI will catch failures, but catching them locally saves a round-trip.

### Code style

- `cargo fmt` — enforced in CI
- `#![deny(clippy::unwrap_used)]` is set crate-wide. Use `.expect("reason")` or propagate with `?`
- No comments explaining what code does. Only add a comment when the *why* is non-obvious

### Commit messages

- Concise, precise. Lower-case first word. No period at the end.
- Format: `area: what changed` (e.g. `stake: add move_stake command`)
- Merge commits only — no squash, no rebase. Preserve full history.

## CI pipeline

Every PR runs the following checks. All must pass before merge.

Four workflows, one with a three-tool matrix and one internal tripwire job.

| Workflow / check | What it does |
|---|---|
| **lint** | `cargo clippy --all-targets --all-features -- -D warnings` + `cargo fmt --check` |
| **tests** | `cargo test --workspace` |
| **btcli-compat** | Builds the release binary, generates signing vectors, and runs `scripts/btcli-compat/check.py` to verify `wallet sign` output against a PyNaCl reference (no `bittensor.*` imports — only the verification surface) |
| **dep-audit → audit (cargo-audit)** | Known-vulnerability scan via `cargo audit`, with ignores pinned in `scripts/dep-audit/rustsec-ignores.jsonl` |
| **dep-audit → audit (cargo-deny)** | License + advisory gate via `cargo deny` against a rendered `deny.toml` |
| **dep-audit → audit (cargo-outdated)** | Informational only; never blocks merge |
| **dep-audit → checksum** | Supply-chain tripwire: `scripts/dep-audit/checksum.py` compares every resolved dep's crate checksum to the committed DB at `.cryptid/dep-audit/checksums.db`. New / stale / mismatched entries fail the job and block merge until the DB is refreshed by intent |
| **dep-audit → combine** | Fails the overall `dep-audit` result if any of the above matrix jobs failed |

## Dependency discipline

New third-party dependencies are treated as high-severity changes. Every new `[dependencies]` entry:

1. Must be justified — explain why the existing dependency set cannot solve the problem
2. Must be reviewed for supply-chain risk (maintainer reputation, download count, transitive dependency tree)
3. Receives extra scrutiny in code review

The guiding principle: btt is a wallet tool that handles private keys. Every dependency is attack surface. Fewer dependencies = smaller blast radius.

Current dependency philosophy:
- **subxt** — substrate chain interaction (unavoidable)
- **sp-core** — sr25519 cryptography (unavoidable)
- **clap** — CLI argument parsing (standard, well-audited)
- **tokio** — async runtime (required by subxt)
- **serde/serde_json** — JSON serialization (standard)
- **xsalsa20poly1305 + argon2** — coldkey encryption (btcli format compatibility)
- **zeroize** — memory scrubbing for key material
- Everything else must earn its place

## Security measures

### Key handling

- Coldkeys are encrypted at rest (Argon2 + XSalsa20Poly1305)
- Key material is zeroized on drop via the `zeroize` crate
- `--password-file` mode refuses to read files with other-readable permissions
- Hotkeys are stored unencrypted (by design — btcli compatibility)

### RPC connection security

- Remote endpoints require `wss://` — plaintext `ws://` is only allowed for loopback addresses
- URL validation is structural (not substring matching) to prevent `ws://localhost.attacker.com` bypasses

### Output security

- All output is structured JSON — no prose that could be confused with prompts
- Error messages never include key material, passwords, or mnemonics
- `--quiet` suppresses warnings but never suppresses command results or errors

### CLI flags

- No hidden flags. Every `#[arg]` is documented and visible in `--help`
- `--force` flags emit explicit destruction warnings to stderr

## JSON output contract

Every command outputs exactly one of:

```json
{"ok": true, "data": { ... }}
```

```json
{"ok": false, "error": {"code": "SCREAMING_SNAKE_CASE", "message": "human-readable"}}
```

Scripts should key on `ok` as the first-line discriminator. Error codes are stable and machine-readable. The `data` shape varies per command but is documented in `--help` and the developer guide.
