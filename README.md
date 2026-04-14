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

# Reap stale staging/backup/lock artefacts from crashed wallet create runs
btt wallet cleanup [--dry-run] [--wallet <name>] [--older-than 7d]

# Emit SKILL.md for AI agent integration
btt skill
```

All commands output JSON to stdout. Use `--pretty` for human-readable formatting.

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
