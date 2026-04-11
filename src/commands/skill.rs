/// Return the SKILL.md content as a static string.
pub fn skill_md() -> &'static str {
    r#"# btt

Minimal, secure Bittensor CLI. Replaces btcli with a statically-compiled Rust binary and zero PyPI exposure.

## Interface

All commands emit JSON to stdout:

```json
{"ok": true, "data": { ... }}
```

On error:

```json
{"ok": false, "error": {"code": "CONNECTION_FAILED", "message": "..."}}
```

Use `--pretty` for human-readable formatting.

## Commands

### Chain

```bash
# Get chain info (name, runtime version, block number)
btt chain info

# Query balance for an SS58 address
btt chain balance <ss58_address>
```

### Wallet

```bash
# List local wallets (reads ~/.bittensor/wallets/)
btt wallet list
```

### Stake

```bash
# List all stakes for a wallet
btt stake list --wallet <name>
btt stake list --ss58 <address>

# Add stake (TAO from coldkey to hotkey on a subnet)
btt stake add --wallet <name> --hotkey <ss58> --netuid <u16> --amount <TAO>

# Remove stake (unstake TAO from hotkey back to coldkey)
btt stake remove --wallet <name> --hotkey <ss58> --netuid <u16> --amount <TAO>
btt stake remove --wallet <name> --hotkey <ss58> --netuid <u16> --all
```

### Skill

```bash
# Emit this document
btt skill
```

## Global Flags

- `--url <wss://...>` — override RPC endpoint
- `--network <finney|test|local>` — shorthand for common endpoints
- `--pretty` — human-readable output
- `--quiet` — suppress non-essential output

## Exit Codes

- `0` — success
- `1` — command error (structured JSON on stdout)
- `2` — fatal internal error

## Security

- No PyPI. No npm. Static Rust binary.
- Never touches private keys. `wallet list` reads public data only.
- All RPC communication over WSS.
- Minimal dependency surface.
"#
}
