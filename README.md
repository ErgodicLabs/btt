# btt

Minimal, secure Bittensor CLI. Static Rust binary, zero PyPI surface.

## Build

```bash
cargo build --release
```

## Output format

btt emits structured JSON to stdout by default. Every successful response
is shaped `{"ok": true, "data": {...}}` and every error is shaped
`{"ok": false, "error": {"code": "...", "message": "..."}}`. Scripts can
rely on `ok` as the first-line discriminator without parsing prose.

Pass `--pretty` for indented, human-readable JSON. Pass `--quiet` to
suppress non-essential stderr chatter (warnings, progress lines) while
keeping the stdout JSON envelope intact.

## Global options

These flags apply to every subcommand and may be passed either before or
after the command path:

| Flag                  | Meaning                                                     |
| --------------------- | ----------------------------------------------------------- |
| `--url <URL>`         | Explicit RPC endpoint URL. Overrides `--network`.           |
| `--network <NETWORK>` | Network shorthand: `finney` (mainnet), `test` (testnet), `local` (local dev node). |
| `--pretty`            | Human-readable (indented) JSON instead of single-line JSON. |
| `--quiet`             | Suppress non-essential stderr output.                       |

If neither `--url` nor `--network` is given, btt falls back to its
built-in default (finney).

## Usage

| Command                  | What it does                                                     |
| ------------------------ | ---------------------------------------------------------------- |
| `chain info`             | Display chain name, runtime version, and current block number.  |
| `chain balance <ss58>`   | Query the free TAO balance for an SS58 address.                 |
| `wallet list`            | List wallets in the btt config directory.                        |
| `wallet create`          | Create a new wallet (coldkey + hotkey pair) and print mnemonic.  |
| `wallet new-coldkey`     | Generate a new coldkey only.                                     |
| `wallet new-hotkey`      | Generate a new hotkey under an existing wallet.                  |
| `wallet regen-coldkey`   | Restore a coldkey from mnemonic or seed.                         |
| `wallet regen-hotkey`    | Restore a hotkey from mnemonic or seed.                          |
| `wallet sign`            | Sign a message with the wallet's coldkey (or hotkey).            |
| `wallet verify`          | Verify a signature against an SS58 address.                      |
| `wallet cleanup`         | Reap stale staging/backup/lock artefacts from crashed runs.      |
| `stake list`             | List all stakes held by a wallet or SS58 address.                |
| `stake add`              | Stake TAO from a coldkey to a hotkey on a subnet.                |
| `stake remove`           | Unstake alpha from a hotkey back to the coldkey on a subnet.     |
| `skill`                  | Emit SKILL.md for AI agent integration.                          |

### Chain

```bash
# Chain info
btt chain info

# Query free balance for an SS58 address
btt chain balance <ss58_address>
```

### Wallet

```bash
# List local wallets
btt wallet list

# Create a new wallet (coldkey + hotkey). Prints the coldkey mnemonic.
btt wallet create --name alice [--hotkey default] [--n-words 12|24] \
                  [--password-file <path>] [--force]

# Generate a new coldkey only.
btt wallet new-coldkey --name alice [--n-words 12|24] \
                       [--password-file <path>] [--force]

# Generate a new hotkey under an existing wallet.
btt wallet new-hotkey --name alice [--hotkey validator] \
                      [--n-words 12|24] [--force]

# Restore a coldkey from mnemonic or seed (exactly one of --mnemonic / --seed).
btt wallet regen-coldkey --name alice \
    --mnemonic "word1 word2 ... word12" \
    [--password-file <path>] [--force]
btt wallet regen-coldkey --name alice --seed 0x<hex> \
    [--password-file <path>] [--force]

# Restore a hotkey from mnemonic or seed (exactly one of --mnemonic / --seed).
btt wallet regen-hotkey --name alice [--hotkey default] \
    --mnemonic "word1 word2 ... word12" [--force]
btt wallet regen-hotkey --name alice [--hotkey default] \
    --seed 0x<hex> [--force]

# Sign a message with the wallet's coldkey (default).
btt wallet sign --name alice --message "hello" [--password-file <path>]

# Sign a message with the hotkey instead of the coldkey.
btt wallet sign --name alice --hotkey default --message "hello" --use-hotkey

# Verify a signature against an SS58 address.
btt wallet verify --ss58 <ss58_address> --message "hello" --signature 0x<hex>

# Reap stale staging/backup/lock artefacts from crashed wallet create runs.
btt wallet cleanup [--dry-run] [--wallet <name>] [--older-than 7d]
```

`wallet create`, `wallet new-coldkey`, and `wallet new-hotkey` all print
the generated mnemonic as part of the JSON response envelope. Treat the
output as secret material: do not run these in a shared terminal, and do
not redirect stdout to a file you will forget about. The mnemonic is the
only way to recover the key if the encrypted wallet file is lost or the
password is forgotten. (Note: as of this writing only the coldkey
mnemonic is surfaced on `wallet create`; the hotkey mnemonic is written
silently to disk. Issue #78 tracks promoting it into the response.)

### Stake

```bash
# List all stakes held by a wallet (reads coldkeypub.txt for the SS58).
btt stake list --wallet alice

# Same, but query by SS58 address directly.
btt stake list --ss58 <ss58_address>

# Stake TAO from a coldkey to a hotkey on a subnet.
# --hotkey takes the hotkey's SS58 address, not a wallet hotkey name.
btt stake add --wallet alice --hotkey <hotkey_ss58> \
              --netuid <n> --amount <tao>

# Unstake alpha back to the coldkey. Pick exactly one denomination:
#   --amount-alpha <n>  submit n alpha directly
#   --amount-tao   <n>  ask to unstake ~n TAO worth; btt converts via the
#                       subnet pool spot price at the head block
#   --all               unstake the full current alpha balance
btt stake remove --wallet alice --hotkey <hotkey_ss58> \
                 --netuid <n> --amount-alpha <n>
btt stake remove --wallet alice --hotkey <hotkey_ss58> \
                 --netuid <n> --amount-tao <n>
btt stake remove --wallet alice --hotkey <hotkey_ss58> \
                 --netuid <n> --all
```

Since dTAO, 1 alpha is not 1 TAO on any non-root subnet. `stake remove`
is deliberately explicit about the denomination to avoid silent slippage
on the submitted extrinsic.

### Skill

```bash
# Emit SKILL.md for AI agent integration
btt skill
```

## Config and wallet directory

btt stores wallets and other per-user state under a single OS-dependent
config directory:

| OS      | Path                                                      |
| ------- | --------------------------------------------------------- |
| linux   | `$XDG_CONFIG_HOME/btt` if set, else `$HOME/.config/btt`   |
| macOS   | `$HOME/Library/Application Support/btt`                   |
| windows | `%APPDATA%\btt`                                           |

Wallets live at `<config_dir>/wallets/<wallet_name>/` and hold a `coldkey`,
`coldkeypub.txt`, and `hotkeys/<hotkey_name>` by the same layout that
btcli uses.

### Legacy path fallback

Earlier versions of btt stored wallets at `$HOME/.bittensor/wallets/` (the
btcli location). If that directory still exists on disk and the new
config directory does not, btt continues to read and write the legacy
location so existing wallets keep working, and prints a one-time warning
to stderr the first time a command resolves the path:

```
btt: legacy wallet directory at /home/alice/.bittensor detected.
     Move it to /home/alice/.config/btt to use the new location:
         mv /home/alice/.bittensor /home/alice/.config/btt
     btt will continue to use the legacy location until the move is performed.
```

btt never moves wallet material on your behalf. Run the `mv` yourself
when you are ready — if you keep a parallel btcli install, you may prefer
to leave the legacy location in place and let both tools share it.

## Non-interactive automation

Commands that prompt for the coldkey password (`wallet create`, `wallet
new-coldkey`, `wallet regen-coldkey`, `wallet sign`) accept a `--password-file
<path>` flag for CI and scripted use. The file's first line (minus the
trailing newline) is taken as the password.

```bash
# Prepare the password on a tmpfs at mode 0600.
umask 077
printf '%s\n' "$BTT_COLDKEY_PW" > /dev/shm/btt-pw
btt wallet create --name compat-test --password-file /dev/shm/btt-pw
shred -u /dev/shm/btt-pw
```

On unix, btt refuses to read the file if its mode is other-readable. The
file must be at most 64 KiB; anything larger is refused outright. A leading
UTF-8 BOM (`\xef\xbb\xbf`) is stripped on read, so password files created by
PowerShell's `Out-File -Encoding utf8` (which prepends a BOM) still match
the password used at wallet creation — but prefer `Set-Content -Encoding
ascii` or equivalent to avoid the ambiguity in the first place.

Do not use `--password-file` with mainnet wallets unless your filesystem,
process listing, and shell history are all under your control.

## Overwrite protection

The key-generation subcommands (`wallet create`, `wallet new-coldkey`,
`wallet new-hotkey`, `wallet regen-coldkey`, `wallet regen-hotkey`) refuse
by default to run when the target key file already exists, and emit an
error naming the file. Pass `--force` to acknowledge that the existing key
will be deleted and replaced; when `--force` is used, btt writes a
one-line warning to stderr naming the file being destroyed. Recovering an
overwritten key requires its mnemonic or seed, so back both up before
forcing.

`wallet create` is a special case: `--force` destroys the entire wallet
(both coldkey and hotkey) and mints a brand new mnemonic. There is no way
to reconstruct the old wallet from the command's own inputs, so the
refusal error explicitly warns about irreversibility. If you only want to
replace one half of a wallet, use `new-coldkey` / `new-hotkey` /
`regen-coldkey` / `regen-hotkey` instead.

## Wallet cleanup

`wallet create`'s atomic staging path (PR #40) writes sibling
`.tmp.<name>.<pid>.<nanos>.<ctr>/` and `.bak.<name>.<pid>.<nanos>.<ctr>/`
directories under `<wallets>/` during a create, and the per-wallet
`flock(2)` path (PR #43) writes a `.lock.<name>` sentinel file. All three
prefixes are reserved — `wallet create` refuses them as names, and
`wallet list` filters them out.

On a crashed or interrupted run, stale `.tmp.*` / `.bak.*` directories
accumulate. `btt wallet cleanup` is the explicit, opt-in sweep:

```bash
# List (and reap) stale entries under <wallets>/
btt wallet cleanup

# Same, but don't remove anything — just emit the JSON report.
btt wallet cleanup --dry-run

# Reap only the staging/backup/lock entries belonging to a specific wallet.
btt wallet cleanup --wallet alice

# Reap only entries whose mtime is older than a duration (s/m/h/d).
btt wallet cleanup --older-than 7d
```

The command uses a strict reserved-prefix grammar match — it will never
`remove_dir_all` anything that does not fit `.tmp.<name>.<pid>.<nanos>.<ctr>`
(or the `.bak.` / `.lock.` analogues). Symlinks are never followed.
`.lock.*` files are probed with a non-blocking `flock(LOCK_EX | LOCK_NB)`
before unlink so that a lock currently held by a concurrent `wallet
create` is reported as `skipped-held` and left on disk. The JSON output
is `{ok: true, data: {entries: [{path, kind, action}, ...]}}` where
`kind` ∈ `tmp` / `bak` / `lock` and `action` is one of `reaped`,
`kept-dry-run`, `skipped-held`, `skipped-too-young`, `skipped-no-match`.

## btcli format compatibility

btt's coldkey envelope (`$NACL` + argon2i13 SENSITIVE + xsalsa20poly1305) is
verified byte-for-byte against the reference primitives (pynacl,
argon2-cffi) in CI by `scripts/btcli-compat/check.py`. The script never
imports `bittensor.*` — it exercises only the verification surface. See
`scripts/btcli-compat/README.md` for how to run it locally.
