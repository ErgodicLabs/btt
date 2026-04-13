# btcli-compat

Byte-for-byte verification that btt's coldkey envelope stays wire-compatible
with btcli / btwallet, using only the reference crypto primitives
(`pynacl` + `argon2-cffi`) and never the `bittensor` python package.

## Why it lives here

btt exists because the `bittensor` PyPI package was hijacked in July 2024
and used to steal ~32,000 TAO from users who had btcli installed. The
entire point of btt is that it never imports `bittensor.*` and never asks
python to run anywhere near a user's coldkey. But btt also has to keep
reading and writing the `$NACL` envelope that btcli has historically used,
so that users can migrate without re-encrypting their wallets.

Those two goals are in tension. This directory is how we hold both:

- **Verification is in python**, because the reference primitives
  (`pynacl`, `argon2-cffi`) are thin wrappers over libsodium and the
  reference argon2 C implementation. Their trust surface is small and
  their dependency tree is fixed.
- **Verification runs only in CI**, never in dev environments and never
  in btt's release artifacts. The pinned deps in `btcli-pins.txt` are
  installed fresh on every GitHub Actions runner and discarded when the
  job ends.
- **No `bittensor.*`** is pinned, installed, or imported. Not as a
  direct dep, not as a test helper, not "just for comparison". Ever.

## What `check.py` does

For each of N deterministic `(password, plaintext)` vectors:

1. **Direction A (btt → pynacl):** call `btt wallet regen-coldkey` with
   a known mnemonic and the vector password via `--password-file`, read
   the resulting `coldkey` blob off disk, and decrypt it with pynacl +
   argon2-cffi alone. If the decrypted plaintext contains the known
   mnemonic, the envelope format is a match.
2. **Direction B (pynacl → btt):** take the inner keyfile JSON that btt
   produced (decrypted from its own blob), re-encrypt it with pynacl
   under the vector password, overwrite the coldkey on disk, and then
   run `btt wallet sign --password-file <pw>`. If btt's signature is
   well-formed, btt successfully decrypted the blob we built.

The script writes:

- `report.json` — machine-readable summary of every vector's results.
- `vectors/vector-NN-btt.bin` — the raw blob btt produced.
- `vectors/vector-NN-pynacl.bin` — the raw blob pynacl produced.

It exits 0 on all-pass, non-zero on any failure. CI fails the workflow
accordingly.

## Running it locally

```bash
# Build btt first.
cargo build --release

# Install the pinned verifier deps into a throwaway venv. NEVER install
# these into a system python or a dev venv you'll keep using. The whole
# point is that they live exactly as long as this invocation.
python3 -m venv /tmp/btcli-compat-venv
/tmp/btcli-compat-venv/bin/pip install --require-hashes \
    -r scripts/btcli-compat/btcli-pins.txt

# Run the check.
/tmp/btcli-compat-venv/bin/python scripts/btcli-compat/check.py \
    --btt-binary ./target/release/btt \
    --out-dir ./btcli-compat-out \
    --vector-count 6 \
    --verbose

# Always clean up.
rm -rf /tmp/btcli-compat-venv ./btcli-compat-out
```

The script prints each vector's status to stderr and the report path to
stderr. Exit code reflects the overall result.

## Running it in CI

The `.github/workflows/btcli-compat.yml` workflow runs this check on:

- pull requests that touch `src/commands/wallet_keys.rs`, `Cargo.toml`,
  `Cargo.lock`, `scripts/btcli-compat/**`, or the workflow file itself,
- pushes to `main` (baseline runs),
- a weekly cron (Sunday 03:00 UTC) as a drift detector,
- manual `workflow_dispatch` with optional `vector_count` and `verbose`
  inputs.

Every run uploads `btcli-compat-out/` as a workflow artifact with 90-day
retention, even on failure. Anyone can download the artifact and inspect
the raw blobs.

## When this check fails

A fail here means either:

1. btt changed its envelope format. Fix it in `wallet_keys.rs` or
   acknowledge the migration explicitly (with a version bump and a
   user-visible note).
2. `argon2-cffi` or `pynacl` changed semantics in a hash-pinned
   dependency update. Read the release notes carefully and only re-pin
   after auditing.

Do not disable the check to make CI green. The check IS the feature.
