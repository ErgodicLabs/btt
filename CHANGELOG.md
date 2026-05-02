# Changelog

All notable changes to btt are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(`MAJOR.MINOR.PATCH`). Per Ergodic Labs policy 2026-05-02, the
`Cargo.toml` `version` and the `vMAJOR.MINOR.PATCH` git tag move
together — bumping one without the other is a release-cutting bug.

The `release.yml` workflow (PR #151) auto-attaches the
`x86_64-unknown-linux-gnu` binary as a release asset whenever a
`v*` tag is pushed.

## [Unreleased]

(Add entries for changes landing on `main` here. Promote the
section heading to `## [vX.Y.Z] — YYYY-MM-DD` when cutting the
release.)

## [v0.1.0] — 2026-05-02

First versioned release. Snapshot of `main` after the verification-
infrastructure thread (PRs #150, #151, #152, #153) closed.

### CLI surface

- `wallet`: list, new-coldkey, regen-coldkey, sign, transfer
- `stake`: add, remove, transfer
- `subnet`: lock-cost, list, metagraph, hyperparameters, info,
  register, create
- `liquidity`: add, remove, modify, list, pool
- `chain`: status, head
- `weights`: set
- `axon`: serve, clear
- `child-hotkey`, `identity`, `swap-coldkey`, `swap-hotkey`,
  `password-file`, `paths`

### Notable

- `subnet info <netuid>` (#150, #152) — dynamic-pricing + identity
  dump for a single subnet, mirroring the existing read-only subnet
  command pattern. dTAO market state (alpha_in/out, tao_in,
  emissions, subnet_volume), tempo + epoch state, full
  `SubnetIdentity` walk (subnet name, github_repo, subnet_url,
  discord, description, logo_url, additional). JSON-default,
  `--pretty` for human-readable.
- `--password-file` flag on the four wallet/stake write-path
  commands (#149) — non-interactive coldkey decrypt for scripted
  use.
- Liquidity command suite (#144) — concentrated-liquidity AMM
  positions for dTAO subnets.
- All extrinsic-submitting commands have been exercised
  end-to-end on testnet (`feedback_done_means_works_on_testnet`).

### CI

- `lint`: clippy `-D warnings`, all targets
- `tests`: stable + nightly cargo test
- `btcli-compat`: end-to-end interop against pinned btcli vectors
- `dep-audit`: cargo-audit, cargo-deny, cargo-outdated, +
  same-version-different-bytes checksum tripwire
- `release.yml` (#151): builds release binary on `workflow_dispatch`
  or `v*` tag, uploads as workflow artifact and (on tag) GitHub
  Release asset.
- `dispatch-run.yml` (#153): maintainer-gated remote runner for
  read-only btt subcommands. Static actor allowlist, closed
  subcommand enum, regex-validated args, audit-log artifact on
  every invocation.

### Dependencies

- subxt 0.50 (`jsonrpsee` + `native` features) for substrate RPC
- jsonrpsee for the HTTP/WS transport
- clap for CLI parsing
- serde / serde_json for IO
- sp-core for AccountId32 / Ss58Codec
- tokio runtime
