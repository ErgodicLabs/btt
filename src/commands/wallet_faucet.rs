// SPDX-License-Identifier: Apache-2.0
//
// Wallet faucet — testnet-only proof-of-work tTAO acquisition.
//
// The subtensor `SubtensorModule::faucet` extrinsic credits
// `1_000_000_000_000` rao (1 TAO) to the signing coldkey if the caller
// supplies a valid proof-of-work solution against a recent block hash.
// The pallet uses a fixed difficulty of 1_000_000 and verifies that the
// supplied `work` (the final seal hash) was produced from the block-hash
// lookup of `block_number` combined with the coldkey account bytes.
//
// PoW construction (pallet-authoritative, from
// `opentensor/subtensor` `pallets/subtensor/src/subnets/registration.rs`
// `create_seal_hash`):
//
//     bh32  = chain_get_block_hash(block_number)          // 32 bytes
//     pre64 = bh32 || coldkey_pubkey                      // 64 bytes
//     bh    = keccak256(pre64)                            // 32 bytes
//     pre40 = nonce_le_8 || bh                            // 40 bytes
//     seal  = keccak256(sha256(pre40))                    // 32 bytes
//
// Difficulty check (`hash_meets_difficulty`):
//
//     U256::from_little_endian(seal).overflowing_mul(difficulty).1 == false
//
// i.e. the little-endian U256 view of `seal` multiplied by `difficulty`
// must not overflow U256, which is equivalent to `seal_le < 2^256 / difficulty`.
//
// Origin: `ensure_signed` extracts the coldkey. The pallet further
// requires `current_block_number.saturating_sub(block_number) < 3`, so
// the submission window is ~36 seconds at 12s block time — we solve
// against head, submit immediately, and let the pallet re-verify.
//
// Testnet guard: the faucet is only wired up on the public testnet; on
// mainnet there is no legitimate code path. This command refuses with
// a structured error if any of the following signals indicate mainnet:
//   1. the resolved endpoint URL host matches a known mainnet entrypoint
//      (`entrypoint-finney.opentensor.ai`, `archive.chain.opentensor.ai`,
//      `dev.chain.opentensor.ai`);
//   2. the connected chain's genesis hash equals the hardcoded finney
//      mainnet genesis
//      `0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03`
//      (sourced from `opentensor/subtensor`
//      `pallets/subtensor/src/migrations/migrate_fix_root_claimed_overclaim.rs`).
// `system_chain()` reports "Bittensor" for BOTH mainnet and testnet
// (same chain-spec name, distinct genesis), so it is surfaced in the
// output `signals` block for observability but not used as a block
// condition. See issue #55 and the btcli reference for the canonical
// endpoint list.

//! # Testnet safety
//!
//! The faucet command refuses to submit unless THREE independent safety
//! checks all pass:
//!
//! 1. **URL blocklist** — rejects substring matches against known mainnet
//!    endpoints (see [`check_url_is_not_mainnet`]).
//! 2. **Genesis-hash check** — rejects the finney mainnet genesis hash
//!    fetched via `chain_getBlockHash(0)` after connect (see
//!    [`check_genesis_is_not_mainnet`]).
//! 3. **Signature binding (implicit)** — the signed extrinsic embeds the
//!    genesis hash it was signed against. A malicious RPC that lies about
//!    genesis at handshake time produces an extrinsic whose signature
//!    fails validation on real mainnet, so even a two-guard bypass cannot
//!    materialize a valid mainnet transaction.
//!
//! All three would have to fail for a mainnet extrinsic to submit
//! successfully. The first two are explicit code checks. The third falls
//! out of substrate's extrinsic signing protocol and does not require any
//! btt-side code — it is documented here so future readers understand
//! why the explicit guards are sufficient rather than insufficient.

use std::io::Write as _;
use std::time::{Duration, Instant};

use serde::Serialize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_core::hashing::{keccak_256, sha2_256};
use sp_core::Pair as PairTrait;
use sp_core::U256;
use subxt::ext::scale_value::Value as SValue;

use crate::commands::stake::Sr25519Signer;
use crate::commands::wallet_keys::{decrypt_coldkey_with_password, rao_to_tao_string};
use crate::error::BttError;
use crate::rpc;

/// Fixed difficulty for the faucet PoW, set by the subtensor pallet at
/// `U256::from(1_000_000)` and never varied.
pub(crate) const FAUCET_DIFFICULTY: u64 = 1_000_000;

/// Amount credited to the coldkey by `do_faucet` on success, in rao
/// (1 TAO = 1e9 rao). Matches `balance_to_add: u64 = 1_000_000_000_000`
/// in the pallet, i.e. 1 TAO.
pub(crate) const FAUCET_REWARD_RAO: u64 = 1_000_000_000_000;

/// Hard upper bound on parallel search workers. The solve is embarrassingly
/// parallel — one worker per CPU is the natural sweet spot — but we cap it
/// at 32 so a misreading of `--num-processes` does not spawn hundreds of
/// threads on a shared host. The faucet difficulty is so low (1_000_000
/// expected hashes) that single-thread is already fast, so this is purely
/// a safety rail, not a throughput knob.
pub(crate) const MAX_NUM_PROCESSES: u32 = 32;

/// Hard upper bound on total PoW iterations across all workers. At the
/// pallet difficulty of 1_000_000 the expected number of hashes is
/// ~1M (geometric distribution, mean = difficulty). 1e9 is a 1000×
/// safety margin against a pathologically unlucky run AND against a
/// future difficulty bump to the testnet chain spec.
pub(crate) const MAX_POW_ITERATIONS: u64 = 1_000_000_000;

/// Hard upper bound on wall-clock PoW time. 10 minutes is comfortably
/// above the expected solve time even on a slow ARM chromebook, but
/// caps the CPU burn for a misconfigured testnet where difficulty is
/// unexpectedly astronomical.
pub(crate) const MAX_POW_DURATION: Duration = Duration::from_secs(600);

/// Finney mainnet genesis hash. Hardcoded sentinel for the testnet guard.
/// Source: `opentensor/subtensor` migration modules reference this exact
/// value (see module docs).
pub(crate) const FINNEY_GENESIS_HEX: &str =
    "0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03";

/// Host substrings that positively identify a mainnet entrypoint. Match
/// is case-insensitive and substring-based so `wss://ENTRYPOINT-FINNEY...`
/// and path/query variations all resolve to the blocklist.
pub(crate) const MAINNET_HOST_MARKERS: &[&str] = &[
    "entrypoint-finney.opentensor.ai",
    "archive.chain.opentensor.ai",
    "dev.chain.opentensor.ai",
];

// ── Output types ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct FaucetResult {
    pub action: &'static str,
    pub tx_hash: String,
    pub block: String,
    pub coldkey_ss58: String,
    pub block_number: u64,
    pub nonce: u64,
    pub difficulty: u64,
    /// Hex-encoded seal bytes that were submitted as the `work` argument.
    pub work: String,
    /// Number of hashes executed during the solve.
    pub iterations: u64,
    /// Wall-clock seconds spent on the solve loop, formatted to 3 decimals.
    pub elapsed_secs: String,
    /// Reward credited by the pallet, in rao (smallest unit, 9 decimals).
    pub reward_rao: u64,
    /// Human-readable version of `reward_rao` — "1.0" on success.
    pub reward_tao: String,
    /// The signals the testnet guard inspected, preserved in the success
    /// output for audit trails.
    pub signals: GuardSignals,
}

#[derive(Serialize, Clone, Debug)]
pub struct GuardSignals {
    pub endpoint: String,
    pub chain_name: String,
    pub genesis_hash: String,
}

/// Serializable reason a guard refused. Attached to the structured error
/// so a caller can see which signal fired.
#[derive(Serialize, Debug)]
pub struct GuardFailure {
    pub reason: &'static str,
    pub signals: GuardSignals,
}

// ── Entry point ───────────────────────────────────────────────────────────

/// Parameters for [`run`]. Grouped into a struct to keep the public
/// surface small and to preserve a named call site across the wiring
/// layer.
pub struct FaucetParams<'a> {
    pub endpoint: &'a str,
    pub wallet: &'a str,
    pub password: &'a str,
    pub num_processes: u32,
    pub update_interval: u64,
}

/// Acquire tTAO on the testnet via PoW + `SubtensorModule::faucet`.
///
/// High-level flow:
///
///   1. validate `num_processes` and `update_interval`;
///   2. decrypt the coldkey using the supplied password;
///   3. connect and run the testnet guard (URL + genesis hash);
///   4. fetch the head block and its hash;
///   5. solve the PoW against `(block_hash, coldkey_pubkey)`;
///   6. submit the `faucet(block_number, nonce, work)` extrinsic signed
///      by the coldkey and wait for finalization.
///
/// Output mirrors the stake tx envelope so a caller can `jq` across
/// command families for tx_hash/block.
pub async fn run(params: FaucetParams<'_>) -> Result<FaucetResult, BttError> {
    let FaucetParams {
        endpoint,
        wallet,
        password,
        num_processes,
        update_interval,
    } = params;

    // Parse-level bounds check. `clap` already enforces min=1 via the
    // `value_parser`, but defense in depth.
    if num_processes == 0 {
        return Err(BttError::invalid_input(
            "--num-processes must be >= 1",
        ));
    }
    if num_processes > MAX_NUM_PROCESSES {
        return Err(BttError::invalid_input(format!(
            "--num-processes must be <= {MAX_NUM_PROCESSES}"
        )));
    }
    if update_interval == 0 {
        return Err(BttError::invalid_input(
            "--update-interval must be >= 1",
        ));
    }

    // The solver is strictly single-threaded today; `num_processes` only
    // strides the nonce space so a future parallel implementation can be
    // dropped in without changing the command surface (see `solve_pow`).
    // Warn users who pass >1 expecting multi-core throughput.
    if num_processes > 1 {
        eprintln!(
            "note: --num-processes > 1 strides the nonce space for future parallelism but the current solver is single-threaded"
        );
    }

    // Decrypt the coldkey EARLY so a bad password fails before we open
    // an RPC connection or burn CPU on a PoW.
    let pair = decrypt_coldkey_with_password(wallet, password)?;
    let coldkey_bytes: [u8; 32] = PairTrait::public(&pair).0;
    let coldkey_ss58 = AccountId32::from(coldkey_bytes).to_ss58check();

    // Run the testnet guard. URL check is fully client-side and needs no
    // RPC round-trip; the genesis-hash and chain-name checks require a
    // live connection.
    check_url_is_not_mainnet(endpoint)?;

    let (api, legacy) = rpc::connect_full(endpoint).await?;

    let genesis_hash = api.genesis_hash();
    let genesis_hex = format!("0x{}", hex::encode(genesis_hash.as_ref()));

    // The `system_chain` RPC returns "Bittensor" for BOTH mainnet and
    // testnet, so it cannot be a block condition — we record it for the
    // audit trail and nothing more. A failure here is not fatal either:
    // degrade to "<unknown>" and let the genesis-hash signal carry the
    // refusal logic.
    let chain_name = tokio::time::timeout(rpc::RPC_TIMEOUT, legacy.system_chain())
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_else(|| "<unknown>".to_string());

    let signals = GuardSignals {
        endpoint: endpoint.to_string(),
        chain_name,
        genesis_hash: genesis_hex.clone(),
    };

    check_genesis_is_not_mainnet(&genesis_hex, &signals)?;

    // Fetch head block. `at_current_block()` gives us a ClientAtBlock
    // whose `block_number()` is the u64 we'll use as the PoW salt's
    // block_number. The block hash of THAT same block is what the pallet
    // will look up server-side; we fetch it explicitly via the legacy
    // `chain_getBlockHash(n)` RPC so the two sides agree.
    let at_block = tokio::time::timeout(rpc::RPC_TIMEOUT, api.at_current_block())
        .await
        .map_err(|_| BttError::query("at_current_block() timed out"))?
        .map_err(|e| BttError::query(format!("failed to resolve client at head: {e}")))?;
    let block_number: u64 = at_block.block_number();

    let block_hash_opt = tokio::time::timeout(
        rpc::RPC_TIMEOUT,
        legacy.chain_get_block_hash(Some(block_number.into())),
    )
    .await
    .map_err(|_| BttError::query("chain_getBlockHash timed out"))?
    .map_err(|e| BttError::query(format!("chain_getBlockHash failed: {e}")))?;

    let block_hash = block_hash_opt.ok_or_else(|| {
        BttError::query(format!("no block hash returned for block {block_number}"))
    })?;
    let block_hash_bytes: [u8; 32] = <[u8; 32]>::from(block_hash);

    // Precompute `keccak256(block_hash || coldkey_pubkey)` — the inner
    // hash that the nonce is combined with on every iteration. This is
    // fixed for the entire solve, so hashing it once outside the loop
    // trims ~one hash worth of CPU per candidate.
    let block_and_coldkey_hash = hash_block_and_account(&block_hash_bytes, &coldkey_bytes);

    // Emit a progress event to stderr so a human watching the solve can
    // distinguish "stuck on connect" from "stuck on PoW". This respects
    // the btt invariant that stdout stays a clean JSON channel.
    let _ = writeln!(
        std::io::stderr(),
        "{{\"phase\":\"pow_start\",\"block_number\":{block_number},\"difficulty\":{FAUCET_DIFFICULTY},\"num_processes\":{num_processes},\"update_interval\":{update_interval}}}"
    );

    let solve = solve_pow(
        &block_and_coldkey_hash,
        FAUCET_DIFFICULTY,
        num_processes,
        update_interval,
        MAX_POW_ITERATIONS,
        MAX_POW_DURATION,
    )?;

    let elapsed_secs = format!("{:.3}", solve.elapsed.as_secs_f64());

    let _ = writeln!(
        std::io::stderr(),
        "{{\"phase\":\"pow_done\",\"nonce\":{},\"iterations\":{},\"elapsed_secs\":{}}}",
        solve.nonce, solve.iterations, elapsed_secs
    );

    // Submit the extrinsic. The pallet call signature is
    // `faucet(block_number: u64, nonce: u64, work: Vec<u8>)`.
    let signer = Sr25519Signer::new(pair);
    let work_bytes: Vec<u8> = solve.seal.to_vec();
    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "faucet",
        vec![
            SValue::u128(block_number as u128),
            SValue::u128(solve.nonce as u128),
            SValue::from_bytes(work_bytes.clone()),
        ],
    );

    let mut tx_client = tokio::time::timeout(Duration::from_secs(120), api.tx())
        .await
        .map_err(|_| BttError::submission_failed("resolving transaction client timed out"))?
        .map_err(|e| {
            BttError::submission_failed(format!("failed to resolve transaction client: {e}"))
        })?;

    let progress = tokio::time::timeout(
        Duration::from_secs(120),
        tx_client.sign_and_submit_then_watch_default(&tx, &signer),
    )
    .await
    .map_err(|_| BttError::submission_failed("transaction submission timed out"))?
    .map_err(|e| BttError::submission_failed(format!("failed to submit faucet tx: {e}")))?;

    let tx_hash = format!("{:?}", progress.extrinsic_hash());

    let in_block = tokio::time::timeout(Duration::from_secs(120), progress.wait_for_finalized())
        .await
        .map_err(|_| BttError::submission_failed("waiting for finalization timed out"))?
        .map_err(|e| BttError::submission_failed(format!("faucet tx failed: {e}")))?;

    let block_hash_finalized = format!("{:?}", in_block.block_hash());

    in_block
        .wait_for_success()
        .await
        .map_err(|e| BttError::submission_failed(format!("faucet extrinsic dispatch failed: {e}")))?;

    Ok(FaucetResult {
        action: "faucet",
        tx_hash,
        block: block_hash_finalized,
        coldkey_ss58,
        block_number,
        nonce: solve.nonce,
        difficulty: FAUCET_DIFFICULTY,
        work: format!("0x{}", hex::encode(&work_bytes)),
        iterations: solve.iterations,
        elapsed_secs,
        reward_rao: FAUCET_REWARD_RAO,
        reward_tao: rao_to_tao_string(FAUCET_REWARD_RAO),
        signals,
    })
}

// ── Testnet guard ─────────────────────────────────────────────────────────

/// Reject known mainnet entrypoint hosts by substring match. The check
/// is URL-level only and never calls out over the network, so it runs
/// before any connection is opened.
pub(crate) fn check_url_is_not_mainnet(endpoint: &str) -> Result<(), BttError> {
    let lowered = endpoint.to_ascii_lowercase();
    for marker in MAINNET_HOST_MARKERS {
        if lowered.contains(marker) {
            let failure = GuardFailure {
                reason: "mainnet_url",
                signals: GuardSignals {
                    endpoint: endpoint.to_string(),
                    chain_name: "<not-queried>".to_string(),
                    genesis_hash: "<not-queried>".to_string(),
                },
            };
            let msg = serde_json::to_string(&failure).unwrap_or_else(|_| {
                format!(
                    "refusing to run faucet: resolved endpoint '{endpoint}' matches mainnet marker '{marker}'"
                )
            });
            return Err(BttError::invalid_input(format!(
                "refusing to run faucet: resolved endpoint matches mainnet marker '{marker}'. guard: {msg}"
            )));
        }
    }
    Ok(())
}

/// Reject the finney mainnet genesis hash. This is the authoritative
/// discriminator: chain-spec names collide between mainnet and testnet,
/// but genesis hashes do not.
pub(crate) fn check_genesis_is_not_mainnet(
    genesis_hex: &str,
    signals: &GuardSignals,
) -> Result<(), BttError> {
    if genesis_hex.eq_ignore_ascii_case(FINNEY_GENESIS_HEX) {
        let failure = GuardFailure {
            reason: "mainnet_genesis",
            signals: signals.clone(),
        };
        let msg = serde_json::to_string(&failure)
            .unwrap_or_else(|_| "refusing to run faucet: mainnet genesis".to_string());
        return Err(BttError::invalid_input(format!(
            "refusing to run faucet: connected chain genesis {genesis_hex} matches finney mainnet. guard: {msg}"
        )));
    }
    Ok(())
}

// ── PoW implementation ────────────────────────────────────────────────────

/// Final product of a successful PoW search.
#[derive(Debug)]
pub(crate) struct PowSolution {
    pub nonce: u64,
    pub seal: [u8; 32],
    pub iterations: u64,
    pub elapsed: Duration,
}

/// Compute `keccak256(block_hash || account_pubkey)`. The pallet helper
/// is literally this — see `hash_block_and_hotkey` in
/// `opentensor/subtensor pallets/subtensor/src/subnets/registration.rs`.
pub(crate) fn hash_block_and_account(
    block_hash_bytes: &[u8; 32],
    account_bytes: &[u8; 32],
) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(block_hash_bytes);
    buf[32..].copy_from_slice(account_bytes);
    keccak_256(&buf)
}

/// Produce the seal hash for a candidate nonce. The pallet-authoritative
/// construction is `keccak256(sha256(nonce_le_8 || block_and_account_hash))`.
pub(crate) fn create_seal_hash(
    block_and_account_hash: &[u8; 32],
    nonce: u64,
) -> [u8; 32] {
    let mut buf = [0u8; 40];
    buf[..8].copy_from_slice(&nonce.to_le_bytes());
    buf[8..].copy_from_slice(block_and_account_hash);
    let sha = sha2_256(&buf);
    keccak_256(&sha)
}

/// Does this seal satisfy the difficulty target?
///
/// Pallet-authoritative check: interpret `seal` as a little-endian U256,
/// multiply by difficulty, and accept iff the multiplication does not
/// overflow. That is exactly `num_hash.overflowing_mul(difficulty).1 == false`
/// in `hash_meets_difficulty`. Equivalent to
/// `seal_le_u256 <= U256::MAX / difficulty`.
pub(crate) fn seal_meets_difficulty(seal: &[u8; 32], difficulty: u64) -> bool {
    let num_hash = U256::from_little_endian(seal);
    let (_value, overflowed) = num_hash.overflowing_mul(U256::from(difficulty));
    !overflowed
}

/// Iterate nonces until one produces a seal that meets `difficulty`, or
/// until one of the hard caps fires.
///
/// This is deliberately single-threaded today. The `num_processes`
/// argument is accepted for btcli compatibility and is used to striped
/// the nonce space (worker `i` searches `n*num_processes + i`) so a
/// future parallel implementation can be dropped in without changing
/// the command surface. At the current testnet difficulty of 1_000_000
/// the expected wall time on a single core is already <1s, so the
/// complexity of a thread pool is not yet warranted and a new dep
/// (rayon/crossbeam) would violate the dep-discipline rule.
pub(crate) fn solve_pow(
    block_and_account_hash: &[u8; 32],
    difficulty: u64,
    num_processes: u32,
    update_interval: u64,
    max_iterations: u64,
    max_duration: Duration,
) -> Result<PowSolution, BttError> {
    let stride = u64::from(num_processes.max(1));
    let start = Instant::now();
    let mut nonce: u64 = 0;
    let mut iterations: u64 = 0;

    loop {
        let seal = create_seal_hash(block_and_account_hash, nonce);
        iterations = iterations.saturating_add(1);

        if seal_meets_difficulty(&seal, difficulty) {
            return Ok(PowSolution {
                nonce,
                seal,
                iterations,
                elapsed: start.elapsed(),
            });
        }

        // Iteration cap is checked every iteration so the ceiling is
        // hard — a simple u64 compare is not worth batching. The
        // wall-time check (Instant::now syscall) and the progress
        // report stay batched on `update_interval` boundaries to keep
        // the hot loop lean. `update_interval` must be >= 1.
        if iterations >= max_iterations {
            return Err(BttError::invalid_input(format!(
                "pow timed out: iteration cap {max_iterations} reached after {iterations} attempts"
            )));
        }
        if iterations.is_multiple_of(update_interval) {
            if start.elapsed() >= max_duration {
                return Err(BttError::invalid_input(format!(
                    "pow timed out: wall-clock cap {}s reached after {iterations} attempts",
                    max_duration.as_secs()
                )));
            }
            let _ = writeln!(
                std::io::stderr(),
                "{{\"phase\":\"pow_progress\",\"iterations\":{},\"elapsed_secs\":\"{:.3}\"}}",
                iterations,
                start.elapsed().as_secs_f64()
            );
        }

        // Step by `stride` so a parallel worker layout is a drop-in
        // change. With stride=1 (default) this is just +1.
        nonce = match nonce.checked_add(stride) {
            Some(n) => n,
            None => {
                return Err(BttError::invalid_input(
                    "pow nonce space exhausted without finding a solution",
                ));
            }
        };
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- guard: URL blocklist --

    #[test]
    fn guard_rejects_finney_entrypoint() {
        let err = check_url_is_not_mainnet("wss://entrypoint-finney.opentensor.ai:443")
            .expect_err("finney entrypoint must be rejected");
        assert!(
            err.message.contains("mainnet"),
            "error should mention mainnet, got: {}",
            err.message
        );
    }

    #[test]
    fn guard_rejects_mainnet_archive() {
        assert!(check_url_is_not_mainnet("wss://archive.chain.opentensor.ai:443").is_err());
    }

    #[test]
    fn guard_rejects_mainnet_dev_chain() {
        assert!(check_url_is_not_mainnet("wss://dev.chain.opentensor.ai:443").is_err());
    }

    #[test]
    fn guard_rejects_uppercase_mainnet_url() {
        // Case-insensitive substring match: an uppercased URL must still trip the guard.
        assert!(check_url_is_not_mainnet("wss://ENTRYPOINT-FINNEY.opentensor.ai:443").is_err());
    }

    #[test]
    fn guard_rejects_mainnet_url_with_path_suffix() {
        // Appending a path or query string must not let the URL slip past the check.
        assert!(check_url_is_not_mainnet(
            "wss://entrypoint-finney.opentensor.ai:443/?token=abc"
        )
        .is_err());
    }

    #[test]
    fn guard_accepts_testnet_url() {
        check_url_is_not_mainnet("wss://test.finney.opentensor.ai:443")
            .expect("testnet URL must pass");
    }

    #[test]
    fn guard_accepts_local_url() {
        check_url_is_not_mainnet("ws://127.0.0.1:9944").expect("local URL must pass");
    }

    // -- guard: genesis hash blocklist --

    #[test]
    fn guard_rejects_finney_genesis() {
        let signals = GuardSignals {
            endpoint: "wss://test.finney.opentensor.ai:443".to_string(),
            chain_name: "Bittensor".to_string(),
            genesis_hash: FINNEY_GENESIS_HEX.to_string(),
        };
        let err = check_genesis_is_not_mainnet(FINNEY_GENESIS_HEX, &signals)
            .expect_err("finney genesis must be rejected");
        assert!(err.message.contains("mainnet"));
    }

    #[test]
    fn guard_rejects_finney_genesis_uppercase() {
        // Guard compares case-insensitively because hex is canonical in
        // lowercase but a future caller might uppercase it.
        let upper: String = FINNEY_GENESIS_HEX
            .chars()
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let signals = GuardSignals {
            endpoint: "x".into(),
            chain_name: "x".into(),
            genesis_hash: upper.clone(),
        };
        assert!(check_genesis_is_not_mainnet(&upper, &signals).is_err());
    }

    #[test]
    fn guard_accepts_non_finney_genesis() {
        // Flip one nibble to produce a genesis hash that does NOT match
        // mainnet. The guard must let it through.
        let not_finney =
            "0x0f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03";
        let signals = GuardSignals {
            endpoint: "wss://test.finney.opentensor.ai:443".to_string(),
            chain_name: "Bittensor".to_string(),
            genesis_hash: not_finney.to_string(),
        };
        check_genesis_is_not_mainnet(not_finney, &signals)
            .expect("non-finney genesis must pass");
    }

    // -- PoW: hash construction --

    #[test]
    fn seal_hash_is_stable_for_fixed_inputs() {
        // Two invocations with the same inputs must produce identical seals.
        let bh = [0x11u8; 32];
        let acc = [0x22u8; 32];
        let inner = hash_block_and_account(&bh, &acc);
        let seal_a = create_seal_hash(&inner, 42);
        let seal_b = create_seal_hash(&inner, 42);
        assert_eq!(seal_a, seal_b);
    }

    #[test]
    fn seal_hash_changes_with_nonce() {
        // Different nonces must produce different seals — otherwise the
        // PoW loop could never converge.
        let bh = [0x11u8; 32];
        let acc = [0x22u8; 32];
        let inner = hash_block_and_account(&bh, &acc);
        assert_ne!(create_seal_hash(&inner, 0), create_seal_hash(&inner, 1));
    }

    #[test]
    fn seal_hash_changes_with_block_hash() {
        let acc = [0x22u8; 32];
        let inner_a = hash_block_and_account(&[0x11u8; 32], &acc);
        let inner_b = hash_block_and_account(&[0x12u8; 32], &acc);
        assert_ne!(inner_a, inner_b);
        assert_ne!(create_seal_hash(&inner_a, 0), create_seal_hash(&inner_b, 0));
    }

    // -- PoW: difficulty predicate --

    #[test]
    fn difficulty_one_accepts_any_seal() {
        // With difficulty=1, `num_hash * 1` never overflows, so every
        // seal must be accepted. This pins the semantic: the predicate
        // checks `overflowing_mul`, not `<`.
        let seal = [0xffu8; 32]; // maximum possible LE value
        assert!(seal_meets_difficulty(&seal, 1));
    }

    #[test]
    fn high_difficulty_rejects_max_seal() {
        // A seal of all-ones is U256::MAX; multiplying by any d > 1
        // overflows. The predicate must return false.
        let seal = [0xffu8; 32];
        assert!(!seal_meets_difficulty(&seal, 2));
    }

    #[test]
    fn high_difficulty_accepts_zero_seal() {
        // The zero seal is U256::ZERO; multiplying by any finite d is 0,
        // which never overflows. Accept.
        let seal = [0u8; 32];
        assert!(seal_meets_difficulty(&seal, u64::MAX));
    }

    // -- PoW: solver --

    #[test]
    fn solver_finds_low_difficulty_solution() {
        // With difficulty=1, the very first nonce must solve (any seal
        // trivially meets difficulty=1). Use this to validate the loop
        // plumbing without spending actual compute.
        let bh = [0x11u8; 32];
        let acc = [0x22u8; 32];
        let inner = hash_block_and_account(&bh, &acc);
        let solution = solve_pow(
            &inner,
            1,
            1,
            50,
            1_000,
            Duration::from_secs(5),
        )
        .expect("difficulty 1 must solve");
        assert_eq!(solution.nonce, 0);
        assert_eq!(solution.seal, create_seal_hash(&inner, 0));
        assert_eq!(solution.iterations, 1);
    }

    #[test]
    fn solver_respects_iteration_cap() {
        // Pick a difficulty so hard that U256::MAX / d is vanishingly
        // small; the cap has to fire within a bounded number of tries.
        // u64::MAX is the largest value the pallet uses; for the purpose
        // of this unit test, use difficulty = u64::MAX which means only
        // seals < 1 satisfy — i.e. nothing will solve. Set a tiny
        // iteration cap so we don't wait.
        let bh = [0x11u8; 32];
        let acc = [0x22u8; 32];
        let inner = hash_block_and_account(&bh, &acc);
        let err = solve_pow(
            &inner,
            u64::MAX,
            1,
            5, // update_interval — check the cap every 5 iterations
            5, // iteration cap — must trip on the first check
            Duration::from_secs(60),
        )
        .expect_err("impossible difficulty must time out");
        assert!(
            err.message.contains("iteration cap"),
            "error must mention iteration cap, got: {}",
            err.message
        );
    }

    #[test]
    fn solver_respects_wall_time_cap() {
        // Same impossible difficulty; generous iteration cap, tiny
        // wall-time cap. The time check runs at `update_interval`
        // boundaries, so set it low so the check fires promptly.
        let bh = [0x11u8; 32];
        let acc = [0x22u8; 32];
        let inner = hash_block_and_account(&bh, &acc);
        let err = solve_pow(
            &inner,
            u64::MAX,
            1,
            1_000,
            u64::MAX,
            Duration::from_millis(50),
        )
        .expect_err("impossible difficulty must time out");
        assert!(
            err.message.contains("wall-clock cap")
                || err.message.contains("iteration cap"),
            "error must mention a cap, got: {}",
            err.message
        );
    }

    #[test]
    fn solver_with_moderate_difficulty_converges() {
        // End-to-end regression for the PoW primitive: if sha256 and
        // keccak256 are ever swapped or the LE/BE interpretation of the
        // seal is flipped, this test fails because the solver and the
        // predicate disagree on what a "meeting" seal is.
        //
        // Use difficulty 10_000 (100× easier than the real pallet) so
        // the expected ~10k hashes stay sub-second even in a debug
        // profile under `--test-threads=2`. The real 1_000_000
        // difficulty is covered at runtime by `cargo run` against a
        // live testnet and by the in-loop progress hooks.
        let bh = [0xaa_u8; 32];
        let acc = [0xbb_u8; 32];
        let inner = hash_block_and_account(&bh, &acc);
        let test_difficulty = 10_000u64;
        let solution = solve_pow(
            &inner,
            test_difficulty,
            1,
            10_000,
            5_000_000,
            Duration::from_secs(60),
        )
        .expect("moderate difficulty must solve within the cap");
        // Sanity: re-run the predicate on the returned seal.
        assert!(seal_meets_difficulty(&solution.seal, test_difficulty));
        // And re-run the seal construction to make sure the solver
        // returned the seal it actually tested.
        assert_eq!(
            solution.seal,
            create_seal_hash(&inner, solution.nonce),
            "returned seal must match create_seal_hash(nonce)"
        );
    }
}
