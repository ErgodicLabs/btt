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

On unix, btt refuses to read the file if its mode is other-readable. Do not
use `--password-file` with mainnet wallets unless your filesystem, process
listing, and shell history are all under your control.

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

## btcli format compatibility

btt's coldkey envelope (`$NACL` + argon2i13 SENSITIVE + xsalsa20poly1305) is
verified byte-for-byte against the reference primitives (pynacl,
argon2-cffi) in CI by `scripts/btcli-compat/check.py`. The script never
imports `bittensor.*` — it exercises only the verification surface. See
`scripts/btcli-compat/README.md` for how to run it locally.
