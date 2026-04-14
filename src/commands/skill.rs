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
# Refuses to run if <wallet>/coldkey or <wallet>/hotkeys/<hotkey> already
# exists; pass --force to destroy the existing wallet and mint a new one.
btt wallet create --name <name> [--hotkey default] [--n-words 12] \
  [--password-file <path>] [--force]

# Generate only a new coldkey for an existing or new wallet.
# Refuses to run if <wallet>/coldkey already exists; pass --force to
# destroy and replace the existing coldkey.
btt wallet new-coldkey --name <name> [--n-words 12] [--password-file <path>] \
  [--force]

# Generate a new hotkey for an existing wallet.
# Refuses to run if <wallet>/hotkeys/<hotkey> already exists; pass --force
# to destroy and replace the existing hotkey.
btt wallet new-hotkey --name <name> [--hotkey default] [--n-words 12] [--force]

# Restore a coldkey from a BIP39 mnemonic or a 0x-prefixed hex seed.
# Refuses to run if <wallet>/coldkey already exists; pass --force to
# destroy and replace the existing coldkey.
btt wallet regen-coldkey --name <name> (--mnemonic "<phrase>" | --seed 0x...) \
  [--password-file <path>] [--force]

# Restore a hotkey from a BIP39 mnemonic or hex seed.
# Refuses to run if <wallet>/hotkeys/<hotkey> already exists; pass --force
# to destroy and replace the existing hotkey.
btt wallet regen-hotkey --name <name> [--hotkey default] \
  (--mnemonic "<phrase>" | --seed 0x...) [--force]

# Sign a message with a wallet key. --use-hotkey signs with the (unencrypted)
# hotkey; otherwise the coldkey is decrypted interactively (or via
# --password-file, which is ignored when --use-hotkey is set).
btt wallet sign --name <name> --message "<msg>" [--use-hotkey] \
  [--hotkey default] [--password-file <path>]

# Verify a signature against an SS58 address
btt wallet verify --message "<msg>" --signature 0x... --ss58 <address>
```

Coldkeys are encrypted with the btwallet/btcli `$NACL` envelope
(argon2i13 SENSITIVE + xsalsa20poly1305). Hotkey files and coldkey
files are written at mode 0600 inside 0700 wallet directories.

#### `--password-file`

Every command that would normally prompt interactively for the coldkey
password accepts `--password-file <path>` for non-interactive automation.
The file's first line (up to but not including the trailing newline) is
taken as the password; content beyond the first newline is ignored.

On unix, btt refuses to read the file if its mode is other-readable
(`mode & 0o077 != 0`). Ensure the file is mode 0600. Prefer a tmpfs
(`/dev/shm`) so the bytes never hit a physical disk. Shred the file
immediately after the command exits.

Do not use `--password-file` with mainnet wallets unless your filesystem,
process listing, and shell history are all under your control.

#### `--force`

`wallet create`, `new-coldkey`, `new-hotkey`, `regen-coldkey`, and
`regen-hotkey` refuse by default to run when the target key file
already exists. This prevents a second invocation from silently
destroying an existing — possibly irrecoverable — key. Pass `--force`
to acknowledge that the existing key file will be deleted and
replaced. When `--force` is used, btt emits a one-line warning to
stderr naming the file being destroyed, then proceeds.

For `wallet create` specifically, `--force` destroys the entire
wallet (both coldkey and hotkey) and mints a fresh mnemonic — there
is no way to reconstruct the old wallet from the command's own
inputs. The refusal error explicitly warns about irreversibility.

Recovering an overwritten key requires its mnemonic or seed. Back up
both before running any key-generation command with `--force`.

### Stake

Post-dTAO, subtensor tracks per-subnet *alpha* — the subnet's own token —
in `SubtensorModule::Alpha`. Each coldkey/hotkey/netuid position is an
alpha balance, convertible to TAO through the subnet's liquidity pool
(price = SubnetTAO / SubnetAlphaIn). `btt stake list` uses the
`StakeInfoRuntimeApi::get_stake_info_for_coldkey` runtime API, which
resolves alpha shares to alpha balances server-side, then values each
entry in TAO via the head-block pool price.

```bash
# List all stakes for a wallet (alpha per subnet, plus TAO valuation)
btt stake list --wallet <name>
btt stake list --ss58 <address>

# Add stake. add_stake.amount_staked is TaoBalance, so --amount is in TAO.
btt stake add --wallet <name> --hotkey <ss58> --netuid <u16> --amount <TAO>

# Remove stake. remove_stake.amount_unstaked is AlphaBalance, so the
# amount is in alpha. Pick one of:
#   --amount-alpha <N>   Submit N alpha directly.
#   --amount-tao   <N>   Convert ~N TAO -> alpha via head-block price.
#   --all                Unstake the full current alpha balance.
btt stake remove --wallet <name> --hotkey <ss58> --netuid <u16> --amount-alpha <ALPHA>
btt stake remove --wallet <name> --hotkey <ss58> --netuid <u16> --amount-tao <TAO>
btt stake remove --wallet <name> --hotkey <ss58> --netuid <u16> --all
```

Before signing a `remove --all`, btt cross-checks the decrypted keypair's
public address against `coldkeypub.txt` and refuses to sign on mismatch.

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
