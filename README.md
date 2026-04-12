# btt

Minimal, secure Bittensor CLI. Static Rust binary, zero PyPI surface.

## Build

```bash
cargo build --release
```

## Usage

```bash
# Chain info
btt chain info

# Query balance
btt chain balance <ss58_address>

# List local wallets
btt wallet list

# Emit SKILL.md for AI agent integration
btt skill
```

All commands output JSON to stdout. Use `--pretty` for human-readable formatting.
