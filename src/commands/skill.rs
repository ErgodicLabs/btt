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

# Create a new wallet (coldkey + hotkey pair). Prompts for coldkey password
# on stderr; JSON result (including mnemonic) on stdout.
btt wallet create --name <name> [--hotkey default] [--n-words 12]

# Generate only a new coldkey for an existing or new wallet
btt wallet new-coldkey --name <name> [--n-words 12]

# Generate a new hotkey for an existing wallet
btt wallet new-hotkey --name <name> [--hotkey default] [--n-words 12]

# Restore a coldkey from a BIP39 mnemonic or a 0x-prefixed hex seed
btt wallet regen-coldkey --name <name> (--mnemonic "<phrase>" | --seed 0x...)

# Restore a hotkey from a BIP39 mnemonic or hex seed
btt wallet regen-hotkey --name <name> [--hotkey default] \
  (--mnemonic "<phrase>" | --seed 0x...)

# Sign a message with a wallet key. --use-hotkey signs with the (unencrypted)
# hotkey; otherwise the coldkey is decrypted interactively.
btt wallet sign --name <name> --message "<msg>" [--use-hotkey] [--hotkey default]

# Verify a signature against an SS58 address
btt wallet verify --message "<msg>" --signature 0x... --ss58 <address>
```

Coldkeys are encrypted with the btwallet/btcli `$NACL` envelope
(argon2i13 SENSITIVE + xsalsa20poly1305). Hotkey files and coldkey
files are written at mode 0600 inside 0700 wallet directories.

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
- Password prompts go to stderr so stdout stays a clean JSON channel.
- Coldkeys at rest use argon2i13 + xsalsa20poly1305, wire-compatible with btcli.
- All RPC communication over WSS.
- Minimal dependency surface.
"#
}
