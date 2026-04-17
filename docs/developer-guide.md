# btt developer guide

## Project layout

```
src/
  main.rs          — entry point, CLI dispatch, password resolution
  cli.rs           — clap derive structs (Cli, Command, *Action enums)
  error.rs         — BttError type with structured error codes
  output.rs        — JSON envelope printer (success/error)
  rpc.rs           — RPC connection, endpoint resolution, URL validation
  commands/
    mod.rs         — module declarations
    chain.rs       — chain info, balance query, SS58 parsing
    stake.rs       — add/remove/move/transfer/swap stake, Sr25519Signer
    subnet.rs      — list, metagraph, hyperparameters (runtime API)
    wallet.rs      — wallet list, cleanup
    wallet_keys.rs — key generation, encryption, decryption, sign/verify
    transfer.rs    — TAO transfer (Balances::transfer_keep_alive)
    identity.rs    — get/set on-chain identity
    register.rs    — burned_register for subnet UID
    axon.rs        — serve_axon set/reset
    weights.rs     — commit_weights / reveal_weights
    child_hotkey.rs — set_children, get_children, set_childkey_take
    swap_hotkey.rs — swap_hotkey extrinsic
    swap_coldkey.rs — schedule/execute/cancel/dispute coldkey swap
    dynamic_decode.rs — shared helpers for decoding scale_value trees
    password_file.rs  — read password from file (automation)
    paths.rs       — wallet directory resolution, quiet flag
    utils.rs       — TAO/RAO conversion, latency test
    skill.rs       — SKILL.md emission for AI agent integration
```

## How commands work

Every user-facing command follows this path:

1. **cli.rs** defines the clap structs. Top-level `Command` enum has one variant per command group (`Wallet`, `Stake`, `Subnet`, etc.). Each group has its own `*Action` enum with the subcommands and their arguments.

2. **main.rs** dispatches: `match cli.command { Command::Wallet { action } => match action { ... } }`. Each arm calls the corresponding function in `commands/`.

3. **commands/*.rs** implements the logic. The function returns `Result<SomeResultStruct, BttError>`. The caller in `main.rs` calls `output::print_success(&result, pretty)`.

### Adding a new command

1. Add the action variant to the appropriate `*Action` enum in `cli.rs` (or create a new `Command` variant + `*Action` enum for a new group). Include all `#[arg(long)]` fields.

2. Create or extend a file in `commands/`. Implement the function returning `Result<YourResult, BttError>` where `YourResult: Serialize`.

3. Add the dispatch arm in `main.rs`. Follow the existing pattern: resolve endpoint if needed, call the function, `output::print_success`.

4. Add `pub mod your_module;` to `commands/mod.rs` if it's a new file.

5. If the new command group is added to the `Command` enum, add the import in `main.rs` (`use cli::{..., YourAction}`).

## Key abstractions

### RPC connection (`rpc.rs`)

```rust
let api = rpc::connect(&endpoint).await?;
```

Returns `OnlineClient<PolkadotConfig>`. All chain interaction goes through this client. The endpoint is resolved from `--url`, `--network` (finney/test/local), or defaults to finney.

URL validation enforces `wss://` for remote hosts and only allows `ws://` for loopback addresses.

### Dynamic subxt API

btt uses subxt 0.50's **dynamic API** — no compile-time metadata generation. This means:

**Extrinsics:**
```rust
let tx = subxt::dynamic::tx(
    "PalletName",
    "call_name",
    vec![SValue::from_bytes(account_bytes), SValue::u128(amount)],
);
```

**Storage queries:**
```rust
let query = subxt::dynamic::storage::<Vec<SValue>, SValue>("PalletName", "StorageItem");
let at_block = api.at_current_block().await?;
let result = at_block.storage().try_fetch(&query, vec![key1, key2]).await?;
```

**Runtime API calls:**
```rust
let call = subxt::dynamic::runtime_api_call("RuntimeApiName", "method_name", vec![args]);
let result = api.runtime_api().at_latest().await?.call(call).await?;
```

The decoded values are `subxt::dynamic::Value<()>` trees. Use helpers from `dynamic_decode.rs` to extract fields:
- `value.at("field_name")` — access named field (requires `At` trait import)
- `value.at(index)` — access by position
- `value_to_u64(&val)` — coerce to u64
- `compact_value_to_u128(&val)` — unwrap Compact wrapper
- `extract_account_id_field(&val, "field")` — pull 32-byte AccountId

### Transaction submission pattern

Every write command follows this pattern:

```rust
// 1. Decrypt the signing key
let pair = decrypt_coldkey_interactive(wallet)?;
let signer = Sr25519Signer::new(pair);

// 2. Connect
let api = rpc::connect(endpoint).await?;

// 3. Build the extrinsic
let tx = subxt::dynamic::tx("Pallet", "call", vec![...]);

// 4. Submit and wait for finalization
let mut tx_client = api.tx().await?;
let progress = tx_client.sign_and_submit_then_watch_default(&tx, &signer).await?;
let in_block = progress.wait_for_finalized().await?;
in_block.wait_for_success().await?;
```

All steps are wrapped in `tokio::time::timeout` (120s for tx operations, 30s for queries).

`Sr25519Signer` is defined in `stake.rs` and wraps `sp_core::sr25519::Pair` to implement the subxt `Signer` trait.

### Wallet and key management (`wallet_keys.rs`, `paths.rs`)

Wallets are directories under the config path:
- Linux: `$XDG_CONFIG_HOME/btt/wallets/` or `~/.config/btt/wallets/`
- macOS: `~/Library/Application Support/btt/wallets/`
- Legacy: `~/.bittensor/wallets/` (auto-detected, migration warning)

Each wallet directory contains:
- `coldkey` — encrypted JSON (Argon2 + XSalsa20Poly1305)
- `coldkeypub.txt` — plaintext SS58 address
- `hotkeys/<name>` — unencrypted hotkey JSON

Key functions:
- `decrypt_coldkey_interactive(wallet)` — prompts for password, returns `sr25519::Pair`
- `load_hotkey_pair(wallet, hotkey_name)` — loads unencrypted hotkey
- `tao_to_rao(f64) -> Result<u64>` — converts decimal TAO to RAO (1 TAO = 10^9 RAO)
- `rao_to_tao_string(u64) -> String` — formats RAO as TAO decimal string

### Error handling (`error.rs`)

All errors are `BttError` with a machine-readable `ErrorCode` and human-readable message. Constructor shortcuts: `BttError::connection(msg)`, `BttError::query(msg)`, `BttError::submission_failed(msg)`, etc.

Output is always JSON: `{"ok": true, "data": {...}}` or `{"ok": false, "error": {"code": "...", "message": "..."}}`.

### SS58 address parsing (`chain.rs`)

```rust
let account_bytes: Vec<u8> = parse_ss58(ss58_string)?;
```

Returns 32 bytes. Used everywhere an AccountId is needed for extrinsic construction.

## Testing

### Unit tests

Tests live in `#[cfg(test)] mod tests` blocks within each source file. Run with:

```bash
cargo test
```

Key conventions:
- `#![deny(clippy::unwrap_used)]` is set crate-wide — use `.expect("reason")` instead of `.unwrap()`
- Tests that touch the network are not unit tests; unit tests are pure logic

### CI pipeline

The CI matrix runs on every PR:
- **lint**: `cargo clippy --all-targets --all-features -- -D warnings` + `cargo fmt --check`
- **tests**: `cargo test --workspace`
- **btcli-compat**: builds release binary + runs compatibility checks
- **dep-audit**: `cargo audit`, `cargo deny`, `cargo outdated`
- **checksum**: release binary SHA256

All checks must pass before merge.

### Pre-push local gates

Before pushing any branch:

```bash
cargo check
cargo clippy -- -D warnings
```

## Crate policies

- **No `unwrap()`** — enforced by `#![deny(clippy::unwrap_used)]`
- **No hidden CLI flags** — every `#[arg]` is documented and visible
- **Merge commits only** — no squash, no rebase; preserve full commit history
- **JSON output only** — every command outputs structured JSON; `--pretty` for human-readable formatting
- **`--quiet` suppresses warnings, never data** — command results are always emitted
