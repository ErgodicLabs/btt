// SPDX-License-Identifier: Apache-2.0
//
// Stake operations — dTAO-aware rewrite.
//
// The pre-dTAO model treated `SubtensorModule::Stake` as a double map of
// `(hotkey, coldkey) -> u64 TAO-rao`. That map is gone. The current ledger
// is per-subnet `alpha` — the subnet's own token — tracked in
// `SubtensorModule::Alpha`, a triple map `(hotkey, coldkey, netuid) -> U64F64`
// *shares*. Shares are translated to alpha balances through the hotkey's
// share pool (`TotalHotkeyShares` / `TotalHotkeyAlpha`), and alpha is
// translated to TAO through the subnet's liquidity pool
// (`SubnetTAO` / `SubnetAlphaIn`, giving price = tao_in / alpha_in).
//
// Rather than walk that three-layer conversion on the client, we call the
// runtime API `StakeInfoRuntimeApi::get_stake_info_for_coldkey`, which
// returns a `Vec<StakeInfo>` with the alpha balance already resolved
// (per subtensor `pallets/subtensor/src/rpc_info/stake_info.rs`). The
// client then queries `SubnetTAO` + `SubnetAlphaIn` once per distinct
// netuid to compute a TAO valuation for display. This matches btcli's
// `stake list` behaviour.
//
// The remove_stake extrinsic takes `amount_unstaked: AlphaBalance` — alpha
// smallest units, NOT TAO smallest units. We expose the flag as
// `--amount-alpha` and offer `--amount-tao` as a convenience that converts
// via the current pool price. `add_stake.amount_staked: TaoBalance` stays
// in TAO (correct under dTAO).

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_core::sr25519;
use sp_core::Pair as PairTrait;
use subxt::dynamic::{At, Value};
use subxt::ext::scale_value::Value as SValue;
use subxt::utils::{AccountId32 as SubxtAccountId32, MultiSignature as SubxtMultiSignature};
use subxt::{OnlineClient, PolkadotConfig};

/// Adapter implementing [`subxt::tx::Signer<PolkadotConfig>`] for an
/// sp-core `sr25519::Pair`.
///
/// subxt 0.38 provided `PairSigner` as part of the `substrate-compat`
/// feature, which wrapped an sp-core pair directly. That feature (and the
/// wasmtime-heavy sp-core path that came with it) was dropped in 0.50;
/// the recommended replacement is either the new `subxt-signer` crate or
/// a local impl of the [`subxt::tx::Signer`] trait. We pick the latter
/// because the wallet layer is already built on sp-core's Pair (for BIP39
/// derivation, Zeroize, and the existing encrypted coldkey.json format),
/// so cloning into a new keypair type would duplicate secret material for
/// no benefit. Keeping sp-core on the owning side means the decrypted key
/// still lives behind sp-core's drop semantics.
pub(crate) struct Sr25519Signer {
    pair: sr25519::Pair,
    account_id: SubxtAccountId32,
}

impl Sr25519Signer {
    pub(crate) fn new(pair: sr25519::Pair) -> Self {
        let pub_bytes: [u8; 32] = PairTrait::public(&pair).0;
        Self {
            pair,
            account_id: SubxtAccountId32::from(pub_bytes),
        }
    }
}

impl subxt::tx::Signer<PolkadotConfig> for Sr25519Signer {
    fn account_id(&self) -> SubxtAccountId32 {
        self.account_id
    }

    fn sign(&self, signer_payload: &[u8]) -> SubxtMultiSignature {
        // sp_core::sr25519::Pair::sign yields a 64-byte sr25519 signature.
        let sig = PairTrait::sign(&self.pair, signer_payload);
        SubxtMultiSignature::Sr25519(sig.0)
    }
}

use crate::commands::chain::parse_ss58;
use crate::commands::dynamic_decode::{extract_account_id_field, value_to_u64};
use crate::commands::wallet_keys::{
    decrypt_coldkey, decrypt_coldkey_interactive, rao_to_tao_string, resolve_coldkey_address,
    tao_to_rao, RAO_PER_TAO,
};
use crate::error::BttError;
use crate::rpc;

/// Timeout for staking RPC operations.
const RPC_TIMEOUT: Duration = rpc::RPC_TIMEOUT;

/// Tighter timeout for individual per-entry fetches inside loops (M-1).
const PER_CALL_TIMEOUT: Duration = Duration::from_secs(10);

// ── Output types ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct StakeListResult {
    pub address: String,
    pub stakes: Vec<StakeEntry>,
}

/// A single (hotkey, coldkey, netuid) staking position.
///
/// Amounts are denominated in *alpha* — the subnet's own token — to 9
/// decimal places, matching the pallet's `AlphaBalance`. A TAO valuation
/// is provided for convenience, computed from the subnet pool's current
/// spot price at the head block. On netuid 0 (root) alpha ≡ TAO, so
/// the two values are always identical there.
#[derive(Serialize)]
pub struct StakeEntry {
    pub hotkey: String,
    pub netuid: u16,
    /// Alpha balance as a decimal string with up to 9 fractional digits.
    pub alpha: String,
    /// Alpha balance in the smallest unit (alpha-rao) for lossless scripts.
    pub alpha_rao: u64,
    /// TAO valuation of `alpha` at the head block's pool price.
    /// `null` if the pool price could not be fetched.
    pub tao_value: Option<String>,
}

#[derive(Serialize)]
pub struct StakeTxResult {
    pub tx_hash: String,
    pub block: String,
    pub action: String,
    /// The alpha amount submitted on the wire (alpha smallest unit).
    /// For `add_stake` this is the tao amount in rao (1:1 on add).
    pub amount_rao: u64,
    /// Human-readable version of `amount_rao`, with 9 decimals. Interpret
    /// according to `amount_unit` — alpha for `remove_stake`, TAO for
    /// `add_stake`.
    pub amount: String,
    /// Either "tao" or "alpha".
    pub amount_unit: &'static str,
    pub hotkey: String,
    pub netuid: u16,
}

// ── list ─────────────────────────────────────────────────────────────────

/// List all stakes for a coldkey address.
///
/// Uses `StakeInfoRuntimeApi::get_stake_info_for_coldkey` which already
/// resolves alpha shares to alpha balances via the hotkey share pool.
/// We then value each entry in TAO using the subnet's current spot price.
pub async fn list(
    endpoint: &str,
    wallet: Option<&str>,
    ss58: Option<&str>,
) -> Result<StakeListResult, BttError> {
    let address = resolve_address(wallet, ss58)?;
    let account_bytes = parse_ss58(&address)?;

    let api = rpc::connect(endpoint).await?;

    // subxt 0.50 pins storage and runtime-api views to a single block
    // snapshot via `at_current_block`; the returned `ClientAtBlock` then
    // exposes `.runtime_apis()` and `.storage()`. We resolve it once up
    // front so the list + the per-netuid price fetches below share one
    // consistent view of chain state.
    let at_block = tokio::time::timeout(RPC_TIMEOUT, api.at_current_block())
        .await
        .map_err(|_| BttError::query("at_current_block() timed out"))?
        .map_err(|e| BttError::query(format!("failed to resolve client at head: {e}")))?;

    // Dynamic runtime API call: StakeInfoRuntimeApi::get_stake_info_for_coldkey.
    // The return type turbofish tells subxt to decode the raw SCALE
    // response into a dynamic `scale_value::Value` for introspection.
    let call = subxt::dynamic::runtime_api_call::<Vec<SValue>, SValue>(
        "StakeInfoRuntimeApi",
        "get_stake_info_for_coldkey",
        vec![SValue::from_bytes(account_bytes)],
    );

    let decoded = tokio::time::timeout(RPC_TIMEOUT, at_block.runtime_apis().call(call))
        .await
        .map_err(|_| BttError::query("get_stake_info_for_coldkey timed out"))?
        .map_err(|e| {
            BttError::query(format!("get_stake_info_for_coldkey runtime call failed: {e}"))
        })?;

    let raw = parse_stake_info_list(&decoded)?;

    // For TAO valuation we need per-netuid pool prices. Batch-fetch them so
    // we make at most one RPC per distinct netuid, with a per-call timeout.
    let storage = at_block.storage();

    let mut prices: BTreeMap<u16, Option<f64>> = BTreeMap::new();
    for entry in &raw {
        if let std::collections::btree_map::Entry::Vacant(slot) = prices.entry(entry.netuid) {
            // Failure of one price fetch must not drop the whole list.
            let price = fetch_subnet_price(&storage, entry.netuid)
                .await
                .ok()
                .flatten();
            slot.insert(price);
        }
    }

    let stakes: Vec<StakeEntry> = raw
        .into_iter()
        .map(|r| {
            let tao_value = prices
                .get(&r.netuid)
                .and_then(|p| p.as_ref())
                .map(|price| alpha_rao_to_tao_string(r.alpha_rao, *price));
            StakeEntry {
                hotkey: AccountId32::new(r.hotkey).to_ss58check(),
                netuid: r.netuid,
                alpha: rao_to_tao_string(r.alpha_rao),
                alpha_rao: r.alpha_rao,
                tao_value,
            }
        })
        .collect();

    Ok(StakeListResult { address, stakes })
}

/// Intermediate parse result for a `StakeInfo` row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawStakeRow {
    hotkey: [u8; 32],
    netuid: u16,
    alpha_rao: u64,
}

/// Decode `Vec<StakeInfo<AccountId32>>` from a dynamic `Value`.
///
/// The subxt dynamic decoder transparently unwraps `Compact<T>`, so
/// `stake: Compact<AlphaBalance>` appears as a plain u64/u128 primitive
/// and `netuid: Compact<NetUid>` appears as u16/u128. We only care about
/// (hotkey, netuid, stake); the other fields (coldkey, locked, emission,
/// tao_emission, drain, is_registered) are skipped.
fn parse_stake_info_list<C: Clone>(value: &Value<C>) -> Result<Vec<RawStakeRow>, BttError> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while let Some(entry) = value.at(idx) {
        idx += 1;

        let hotkey = extract_account_id_field(entry, "hotkey").ok_or_else(|| {
            BttError::parse(format!(
                "StakeInfo[{}]: missing or malformed hotkey field",
                idx - 1
            ))
        })?;

        let netuid_val = entry.at("netuid").ok_or_else(|| {
            BttError::parse(format!("StakeInfo[{}]: missing netuid field", idx - 1))
        })?;
        let netuid = value_to_u64(netuid_val)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| {
                BttError::parse(format!(
                    "StakeInfo[{}]: netuid not decodable as u16",
                    idx - 1
                ))
            })?;

        let stake_val = entry.at("stake").ok_or_else(|| {
            BttError::parse(format!("StakeInfo[{}]: missing stake field", idx - 1))
        })?;
        let alpha_rao = value_to_u64(stake_val).ok_or_else(|| {
            BttError::parse(format!(
                "StakeInfo[{}]: stake not decodable as u64",
                idx - 1
            ))
        })?;

        if alpha_rao > 0 {
            out.push(RawStakeRow {
                hotkey,
                netuid,
                alpha_rao,
            });
        }
    }
    Ok(out)
}

/// Fetch the current spot price of a subnet (TAO per alpha) from the pool
/// reserves: `SubnetTAO[netuid] / SubnetAlphaIn[netuid]`. Returns `Ok(None)`
/// if either reserve is zero or unset. Root (netuid 0) is fixed at 1.0.
///
/// The storage handle is taken generically over the `ClientT` parameter so
/// this helper is compatible with both the owned
/// `OnlineClientAtBlock<PolkadotConfig>` from `at_current_block` and any
/// borrowed variant; the lifetime is elided to let the caller pick.
async fn fetch_subnet_price<ClientT>(
    storage: &subxt::storage::StorageClient<'_, PolkadotConfig, ClientT>,
    netuid: u16,
) -> Result<Option<f64>, BttError>
where
    ClientT: subxt::client::OnlineClientAtBlockT<PolkadotConfig>,
{
    if netuid == 0 {
        return Ok(Some(1.0));
    }

    // 0.50 decouples address-of-entry from key-parts: the address names
    // the pallet + entry, and the keys are supplied at fetch time. Reuse
    // a single address for both maps — same shape, different entry name.
    let tao_addr =
        subxt::dynamic::storage::<Vec<SValue>, SValue>("SubtensorModule", "SubnetTAO");
    let alpha_addr =
        subxt::dynamic::storage::<Vec<SValue>, SValue>("SubtensorModule", "SubnetAlphaIn");
    let key = vec![SValue::u128(netuid as u128)];

    let tao_raw = tokio::time::timeout(
        PER_CALL_TIMEOUT,
        storage.try_fetch(&tao_addr, key.clone()),
    )
    .await
    .map_err(|_| BttError::query(format!("SubnetTAO[{netuid}] fetch timed out")))?
    .map_err(|e| BttError::query(format!("SubnetTAO[{netuid}] fetch failed: {e}")))?;
    let alpha_raw = tokio::time::timeout(
        PER_CALL_TIMEOUT,
        storage.try_fetch(&alpha_addr, key),
    )
    .await
    .map_err(|_| BttError::query(format!("SubnetAlphaIn[{netuid}] fetch timed out")))?
    .map_err(|e| BttError::query(format!("SubnetAlphaIn[{netuid}] fetch failed: {e}")))?;

    let tao_in = match tao_raw {
        Some(v) => match v.decode() {
            Ok(dv) => value_to_u64(&dv).unwrap_or(0),
            Err(_) => return Ok(None),
        },
        None => 0,
    };
    let alpha_in = match alpha_raw {
        Some(v) => match v.decode() {
            Ok(dv) => value_to_u64(&dv).unwrap_or(0),
            Err(_) => return Ok(None),
        },
        None => 0,
    };

    if alpha_in == 0 {
        return Ok(None);
    }

    // Both are u64 rao. price = tao_in_rao / alpha_in_rao (unitless, tao per alpha).
    Ok(Some(tao_in as f64 / alpha_in as f64))
}

/// Convert an alpha-rao amount at a given price (tao per alpha) into a
/// TAO decimal string. Uses f64; result is display-only.
fn alpha_rao_to_tao_string(alpha_rao: u64, price: f64) -> String {
    let alpha_f = alpha_rao as f64 / RAO_PER_TAO as f64;
    let tao = alpha_f * price;
    // Clamp pathological negatives defensively.
    let tao = if tao.is_finite() && tao >= 0.0 { tao } else { 0.0 };
    format!("{tao:.9}")
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

// ── add ──────────────────────────────────────────────────────────────────

/// Add stake: move TAO from coldkey to hotkey on a specific subnet.
///
/// The `add_stake` dispatch takes `amount_staked: TaoBalance` — this flag
/// really is denominated in TAO, so the `tao_to_rao` conversion is correct.
/// Slippage is handled by the subnet pool on submission, not the client.
pub async fn add(
    endpoint: &str,
    wallet: &str,
    hotkey: &str,
    netuid: u16,
    amount_tao: f64,
    password: Option<&str>,
) -> Result<StakeTxResult, BttError> {
    let amount_rao = tao_to_rao(amount_tao)?;
    if amount_rao == 0 {
        return Err(BttError::invalid_amount(
            "stake amount must be greater than zero",
        ));
    }

    let hotkey_bytes = parse_ss58(hotkey)?;

    let pair = decrypt_coldkey(wallet, password)?;
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "add_stake",
        vec![
            SValue::from_bytes(hotkey_bytes),
            SValue::u128(netuid as u128),
            SValue::u128(amount_rao as u128),
        ],
    );

    submit_stake_tx(
        &api,
        &tx,
        &signer,
        StakeTxMeta {
            action: "add_stake",
            amount_rao,
            amount_unit: "tao",
            hotkey,
            netuid,
        },
    )
    .await
}

// ── remove ────────────────────────────────────────────────────────────────

/// Source the user picked for the remove amount. Exactly one must be set,
/// unless `--all` is in play (in which case none are).
#[derive(Debug, Clone, Copy)]
pub enum RemoveAmount {
    /// Explicit alpha balance, in whole-alpha units (f64).
    Alpha(f64),
    /// Explicit TAO intent, converted to alpha at the head block price.
    Tao(f64),
    /// Unstake the full real balance for this (hotkey, coldkey, netuid).
    All,
}

/// Remove stake: unstake alpha from a hotkey back to the coldkey.
///
/// The `remove_stake` dispatch takes `amount_unstaked: AlphaBalance` in
/// alpha smallest units. Whatever the user asked for, this function
/// resolves it to an alpha-rao integer before constructing the extrinsic.
pub async fn remove(
    endpoint: &str,
    wallet: &str,
    hotkey: &str,
    netuid: u16,
    source: RemoveAmount,
    password: Option<&str>,
) -> Result<StakeTxResult, BttError> {
    let hotkey_bytes = parse_ss58(hotkey)?;

    // Decrypt first so a wrong password fails fast, before any RPC work.
    let pair = decrypt_coldkey(wallet, password)?;

    // Cross-check the decrypted pair against coldkeypub.txt (M-3). The
    // public key baked into the cold wallet directory is the canonical
    // identity; if the decrypted keypair disagrees, refuse to sign.
    let derived = AccountId32::from(PairTrait::public(&pair)).to_ss58check();
    let on_disk = resolve_coldkey_address(wallet)?;
    if derived != on_disk {
        return Err(BttError::invalid_input(format!(
            "coldkey mismatch: decrypted key is {derived} but coldkeypub.txt says {on_disk}. \
             refusing to sign — your wallet directory may be tampered with"
        )));
    }
    let coldkey_bytes = PairTrait::public(&pair).0.to_vec();

    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let amount_alpha_rao: u64 = match source {
        RemoveAmount::Alpha(a) => {
            let rao = tao_to_rao(a)?; // alpha has 9 decimals too
            if rao == 0 {
                return Err(BttError::invalid_amount(
                    "--amount-alpha must be greater than zero",
                ));
            }
            rao
        }
        RemoveAmount::Tao(tao) => {
            let at_block = tokio::time::timeout(RPC_TIMEOUT, api.at_current_block())
                .await
                .map_err(|_| BttError::query("at_current_block() timed out"))?
                .map_err(|e| {
                    BttError::query(format!("failed to resolve client at head: {e}"))
                })?;
            let storage = at_block.storage();
            let price = fetch_subnet_price(&storage, netuid).await?.ok_or_else(|| {
                BttError::query(format!(
                    "could not resolve subnet {netuid} pool price for --amount-tao conversion"
                ))
            })?;
            if price <= 0.0 || !price.is_finite() {
                return Err(BttError::query(format!(
                    "subnet {netuid} pool price is invalid ({price})"
                )));
            }
            let alpha_f = tao / price;
            let alpha_rao_f = alpha_f * RAO_PER_TAO as f64;
            if !alpha_rao_f.is_finite() || alpha_rao_f < 0.0 || alpha_rao_f > u64::MAX as f64 {
                return Err(BttError::invalid_amount(
                    "converted alpha amount is out of range",
                ));
            }
            let rao = alpha_rao_f as u64;
            if rao == 0 {
                return Err(BttError::invalid_amount(
                    "converted alpha amount rounds to zero — use --amount-alpha for small positions",
                ));
            }
            rao
        }
        RemoveAmount::All => {
            // Look up the full alpha balance via the runtime API.
            let rao = lookup_alpha_balance(&api, &coldkey_bytes, &hotkey_bytes, netuid).await?;
            if rao == 0 {
                return Err(BttError::invalid_amount(format!(
                    "no alpha balance found for this (hotkey, coldkey, netuid={netuid})"
                )));
            }
            rao
        }
    };

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "remove_stake",
        vec![
            SValue::from_bytes(hotkey_bytes),
            SValue::u128(netuid as u128),
            SValue::u128(amount_alpha_rao as u128),
        ],
    );

    submit_stake_tx(
        &api,
        &tx,
        &signer,
        StakeTxMeta {
            action: "remove_stake",
            amount_rao: amount_alpha_rao,
            amount_unit: "alpha",
            hotkey,
            netuid,
        },
    )
    .await
}

/// Look up the alpha balance for a specific (hotkey, coldkey, netuid) tuple
/// via the runtime API. Returns the u64 alpha-rao balance, or 0 if the
/// triple has no position.
async fn lookup_alpha_balance(
    api: &OnlineClient<PolkadotConfig>,
    coldkey_bytes: &[u8],
    hotkey_bytes: &[u8],
    netuid: u16,
) -> Result<u64, BttError> {
    let call = subxt::dynamic::runtime_api_call::<Vec<SValue>, SValue>(
        "StakeInfoRuntimeApi",
        "get_stake_info_for_hotkey_coldkey_netuid",
        vec![
            SValue::from_bytes(hotkey_bytes),
            SValue::from_bytes(coldkey_bytes),
            SValue::u128(netuid as u128),
        ],
    );

    let at_block = tokio::time::timeout(RPC_TIMEOUT, api.at_current_block())
        .await
        .map_err(|_| BttError::query("at_current_block() timed out"))?
        .map_err(|e| BttError::query(format!("failed to resolve client at head: {e}")))?;

    let decoded = tokio::time::timeout(RPC_TIMEOUT, at_block.runtime_apis().call(call))
        .await
        .map_err(|_| BttError::query("get_stake_info_for_hotkey_coldkey_netuid timed out"))?
        .map_err(|e| BttError::query(format!("runtime call failed: {e}")))?;

    // The pallet wraps the result in Option<StakeInfo>. Dynamically decoded,
    // this shows up as a Variant (Some/None) wrapping the struct. Fall
    // through the variant to the struct, then pull `stake`.
    let inner = decoded.at(0).unwrap_or(&decoded);
    let stake_field = match inner.at("stake") {
        Some(v) => v,
        None => return Ok(0),
    };
    Ok(value_to_u64(stake_field).unwrap_or(0))
}

/// Result-envelope metadata for [`submit_stake_tx`]. Groups the per-call
/// descriptors that get copied into the returned [`StakeTxResult`] so the
/// helper takes a small, semantically-clustered struct instead of seven
/// loose scalars.
struct StakeTxMeta<'a> {
    action: &'static str,
    amount_rao: u64,
    amount_unit: &'static str,
    hotkey: &'a str,
    netuid: u16,
}

/// Sign, submit, finalize, and convert a stake-related extrinsic into a
/// `StakeTxResult` envelope.
async fn submit_stake_tx(
    api: &OnlineClient<PolkadotConfig>,
    tx: &subxt::tx::DynamicPayload<Vec<SValue>>,
    signer: &Sr25519Signer,
    meta: StakeTxMeta<'_>,
) -> Result<StakeTxResult, BttError> {
    // `OnlineClient::tx()` became async in 0.50 — it resolves a
    // `TransactionsClient` bound to the head block so the submit can build
    // the extrinsic extensions (genesis hash, spec version, nonce, etc.)
    // against a concrete metadata snapshot.
    let mut tx_client = tokio::time::timeout(Duration::from_secs(120), api.tx())
        .await
        .map_err(|_| BttError::submission_failed("resolving transaction client timed out"))?
        .map_err(|e| {
            BttError::submission_failed(format!("failed to resolve transaction client: {e}"))
        })?;

    let progress = tokio::time::timeout(
        Duration::from_secs(120),
        tx_client.sign_and_submit_then_watch_default(tx, signer),
    )
    .await
    .map_err(|_| BttError::submission_failed("transaction submission timed out"))?
    .map_err(|e| BttError::submission_failed(format!("failed to submit transaction: {e}")))?;

    let tx_hash = format!("{:?}", progress.extrinsic_hash());

    let in_block = tokio::time::timeout(Duration::from_secs(120), progress.wait_for_finalized())
        .await
        .map_err(|_| BttError::submission_failed("waiting for finalization timed out"))?
        .map_err(|e| BttError::submission_failed(format!("transaction failed: {e}")))?;

    let block_hash = format!("{:?}", in_block.block_hash());

    in_block
        .wait_for_success()
        .await
        .map_err(|e| BttError::submission_failed(format!("extrinsic failed: {e}")))?;

    Ok(StakeTxResult {
        tx_hash,
        block: block_hash,
        action: meta.action.to_string(),
        amount_rao: meta.amount_rao,
        amount: rao_to_tao_string(meta.amount_rao),
        amount_unit: meta.amount_unit,
        hotkey: meta.hotkey.to_string(),
        netuid: meta.netuid,
    })
}

// ── move ──────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct MoveStakeResult {
    pub tx_hash: String,
    pub block: String,
    pub origin_hotkey: String,
    pub destination_hotkey: String,
    pub origin_netuid: u16,
    pub destination_netuid: u16,
    pub amount_alpha_rao: u64,
}

pub struct MoveStakeParams<'a> {
    pub wallet: &'a str,
    pub origin_hotkey: &'a str,
    pub destination_hotkey: &'a str,
    pub origin_netuid: u16,
    pub destination_netuid: u16,
    pub amount_tao: f64,
}

pub async fn move_stake(
    endpoint: &str,
    params: MoveStakeParams<'_>,
) -> Result<MoveStakeResult, BttError> {
    let amount_rao = tao_to_rao(params.amount_tao)?;
    if amount_rao == 0 {
        return Err(BttError::invalid_amount(
            "move amount must be greater than zero",
        ));
    }

    let origin_hotkey_bytes = parse_ss58(params.origin_hotkey)?;
    let dest_hotkey_bytes = parse_ss58(params.destination_hotkey)?;

    let pair = decrypt_coldkey_interactive(params.wallet)?;
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "move_stake",
        vec![
            SValue::from_bytes(origin_hotkey_bytes),
            SValue::from_bytes(dest_hotkey_bytes),
            SValue::u128(params.origin_netuid as u128),
            SValue::u128(params.destination_netuid as u128),
            SValue::u128(amount_rao as u128),
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
    .map_err(|e| BttError::submission_failed(format!("failed to submit transaction: {e}")))?;

    let tx_hash = format!("{:?}", progress.extrinsic_hash());

    let in_block = tokio::time::timeout(Duration::from_secs(120), progress.wait_for_finalized())
        .await
        .map_err(|_| BttError::submission_failed("waiting for finalization timed out"))?
        .map_err(|e| BttError::submission_failed(format!("transaction failed: {e}")))?;

    let block_hash = format!("{:?}", in_block.block_hash());

    in_block
        .wait_for_success()
        .await
        .map_err(|e| BttError::submission_failed(format!("extrinsic failed: {e}")))?;

    Ok(MoveStakeResult {
        tx_hash,
        block: block_hash,
        origin_hotkey: params.origin_hotkey.to_string(),
        destination_hotkey: params.destination_hotkey.to_string(),
        origin_netuid: params.origin_netuid,
        destination_netuid: params.destination_netuid,
        amount_alpha_rao: amount_rao,
    })
}

// ── transfer stake ────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct TransferStakeResult {
    pub tx_hash: String,
    pub block: String,
    pub destination_coldkey: String,
    pub hotkey: String,
    pub netuid: u16,
    pub amount_alpha_rao: u64,
}

pub async fn transfer_stake(
    endpoint: &str,
    wallet: &str,
    dest_coldkey: &str,
    hotkey: &str,
    netuid: u16,
    amount_tao: f64,
    password: Option<&str>,
) -> Result<TransferStakeResult, BttError> {
    let amount_rao = tao_to_rao(amount_tao)?;
    if amount_rao == 0 {
        return Err(BttError::invalid_amount(
            "transfer amount must be greater than zero",
        ));
    }

    let dest_bytes = parse_ss58(dest_coldkey)?;
    let hotkey_bytes = parse_ss58(hotkey)?;

    let pair = decrypt_coldkey(wallet, password)?;
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "transfer_stake",
        vec![
            SValue::from_bytes(dest_bytes),
            SValue::from_bytes(hotkey_bytes),
            SValue::u128(netuid as u128),
            SValue::u128(amount_rao as u128),
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
    .map_err(|e| BttError::submission_failed(format!("failed to submit transaction: {e}")))?;

    let tx_hash = format!("{:?}", progress.extrinsic_hash());

    let in_block = tokio::time::timeout(Duration::from_secs(120), progress.wait_for_finalized())
        .await
        .map_err(|_| BttError::submission_failed("waiting for finalization timed out"))?
        .map_err(|e| BttError::submission_failed(format!("transaction failed: {e}")))?;

    let block_hash = format!("{:?}", in_block.block_hash());

    in_block
        .wait_for_success()
        .await
        .map_err(|e| BttError::submission_failed(format!("extrinsic failed: {e}")))?;

    Ok(TransferStakeResult {
        tx_hash,
        block: block_hash,
        destination_coldkey: dest_coldkey.to_string(),
        hotkey: hotkey.to_string(),
        netuid,
        amount_alpha_rao: amount_rao,
    })
}

// ── swap stake ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct SwapStakeResult {
    pub tx_hash: String,
    pub block: String,
    pub hotkey: String,
    pub origin_netuid: u16,
    pub destination_netuid: u16,
    pub amount_alpha_rao: u64,
}

pub async fn swap_stake(
    endpoint: &str,
    wallet: &str,
    hotkey: &str,
    origin_netuid: u16,
    destination_netuid: u16,
    amount_tao: f64,
) -> Result<SwapStakeResult, BttError> {
    let amount_rao = tao_to_rao(amount_tao)?;
    if amount_rao == 0 {
        return Err(BttError::invalid_amount(
            "swap amount must be greater than zero",
        ));
    }

    let hotkey_bytes = parse_ss58(hotkey)?;

    let pair = decrypt_coldkey_interactive(wallet)?;
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "swap_stake",
        vec![
            SValue::from_bytes(hotkey_bytes),
            SValue::u128(origin_netuid as u128),
            SValue::u128(destination_netuid as u128),
            SValue::u128(amount_rao as u128),
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
    .map_err(|e| BttError::submission_failed(format!("failed to submit transaction: {e}")))?;

    let tx_hash = format!("{:?}", progress.extrinsic_hash());

    let in_block = tokio::time::timeout(Duration::from_secs(120), progress.wait_for_finalized())
        .await
        .map_err(|_| BttError::submission_failed("waiting for finalization timed out"))?
        .map_err(|e| BttError::submission_failed(format!("transaction failed: {e}")))?;

    let block_hash = format!("{:?}", in_block.block_hash());

    in_block
        .wait_for_success()
        .await
        .map_err(|e| BttError::submission_failed(format!("extrinsic failed: {e}")))?;

    Ok(SwapStakeResult {
        tx_hash,
        block: block_hash,
        hotkey: hotkey.to_string(),
        origin_netuid,
        destination_netuid,
        amount_alpha_rao: amount_rao,
    })
}

// ── claim ─────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ClaimResult {
    pub tx_hash: String,
    pub block: String,
    pub netuids: Vec<u16>,
}

pub async fn claim(
    endpoint: &str,
    wallet: &str,
    netuids: &[u16],
) -> Result<ClaimResult, BttError> {
    if netuids.is_empty() {
        return Err(BttError::invalid_input(
            "provide at least one netuid to claim from",
        ));
    }
    if netuids.len() > 5 {
        return Err(BttError::invalid_input(
            "claim_root supports at most 5 subnet IDs per call",
        ));
    }

    let pair = decrypt_coldkey_interactive(wallet)?;
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let netuid_values: Vec<SValue> = netuids.iter().map(|n| SValue::u128(*n as u128)).collect();

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "claim_root",
        vec![SValue::unnamed_composite(netuid_values)],
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
    .map_err(|e| BttError::submission_failed(format!("failed to submit transaction: {e}")))?;

    let tx_hash = format!("{:?}", progress.extrinsic_hash());

    let in_block = tokio::time::timeout(Duration::from_secs(120), progress.wait_for_finalized())
        .await
        .map_err(|_| BttError::submission_failed("waiting for finalization timed out"))?
        .map_err(|e| BttError::submission_failed(format!("transaction failed: {e}")))?;

    let block_hash = format!("{:?}", in_block.block_hash());

    in_block
        .wait_for_success()
        .await
        .map_err(|e| BttError::submission_failed(format!("extrinsic failed: {e}")))?;

    Ok(ClaimResult {
        tx_hash,
        block: block_hash,
        netuids: netuids.to_vec(),
    })
}

// ── helpers ───────────────────────────────────────────────────────────────

/// Resolve an address from either a wallet name or a direct SS58 string.
fn resolve_address(wallet: Option<&str>, ss58: Option<&str>) -> Result<String, BttError> {
    match (wallet, ss58) {
        (Some(w), None) => resolve_coldkey_address(w),
        (None, Some(addr)) => {
            parse_ss58(addr)?;
            Ok(addr.to_string())
        }
        (Some(_), Some(_)) => Err(BttError::invalid_input(
            "provide either --wallet or --ss58, not both",
        )),
        (None, None) => Err(BttError::invalid_input(
            "provide either --wallet or --ss58",
        )),
    }
}

// Decoder helpers (`extract_account_id_field`, `value_to_32_bytes`,
// `value_to_u64`) moved to `crate::commands::dynamic_decode` in issue
// #93. Imported at the top of this file alongside the other
// `dynamic_decode::*` helpers.

// ── U64F64 decoding ───────────────────────────────────────────────────────
//
// Even though the runtime API path uses `get_stake_info_for_coldkey` (which
// resolves shares to alpha server-side), the raw `SubtensorModule::Alpha`
// storage map still holds U64F64 *shares*. Any future code that reads that
// map directly MUST decode the value correctly. The pre-dTAO code grabbed
// the lower 64 bits, which is the *fractional* half of the fixed-point
// encoding — so every whole-number share count read as 0 and every
// fractional count read as a nonsense integer.
//
// The correct layout: U64F64 is a 128-bit little-endian integer where the
// high 64 bits are the integer part and the low 64 bits are the fractional
// part (value * 2^64). We expose these helpers so the decoder is testable
// in isolation.

/// Split a U64F64 raw wire value (as a 128-bit unsigned) into its integer
/// and fractional halves. Exposed for reuse if a future path reads the
/// `SubtensorModule::Alpha` storage map directly instead of going through
/// the runtime API; pinned by the tests below.
#[allow(dead_code)]
pub fn u64f64_split(raw: u128) -> (u64, u64) {
    let int_part = (raw >> 64) as u64;
    let frac_part = raw as u64;
    (int_part, frac_part)
}

/// Convert a U64F64 raw wire value into a floating-point approximation.
/// Display-only; do not use for on-chain arithmetic.
#[allow(dead_code)]
pub fn u64f64_to_f64(raw: u128) -> f64 {
    let (int_part, frac_part) = u64f64_split(raw);
    int_part as f64 + (frac_part as f64 / (2f64.powi(64)))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use subxt::ext::scale_value::{Composite, Primitive, Value as SValue, ValueDef};

    // -- U64F64 decoder: the PoC cases from the barbarian review -----------
    //
    // The stored shape of `U64F64` in substrate-fixed is a 128-bit integer
    // where the value is `raw / 2^64`. Concretely:
    //   5.0   shares -> raw = 5  << 64 = 0x0000000000000005_0000000000000000
    //   5.5   shares -> raw = 5.5<< 64 = 0x0000000000000005_8000000000000000
    //   12345 shares -> raw =12345<<64 = 0x0000000000003039_0000000000000000
    //
    // The old code did `raw_u128 as u64`, keeping only the low 64 bits —
    // i.e. the fractional half. These tests pin the correct decoding so a
    // future change cannot regress to the pre-dTAO shape.

    #[test]
    fn u64f64_whole_5_decodes_as_5() {
        let raw: u128 = 5u128 << 64;
        let (int_part, frac_part) = u64f64_split(raw);
        assert_eq!(int_part, 5);
        assert_eq!(frac_part, 0);
        assert_eq!(u64f64_to_f64(raw), 5.0);
    }

    #[test]
    fn u64f64_half_5_5_decodes_as_5_5_not_2pow63() {
        // 5.5 shares: high 64 = 5, low 64 = 0x8000000000000000 (= 2^63)
        let raw: u128 = (5u128 << 64) | (1u128 << 63);
        let (int_part, frac_part) = u64f64_split(raw);
        assert_eq!(int_part, 5);
        assert_eq!(frac_part, 1u64 << 63);
        let as_f = u64f64_to_f64(raw);
        assert!((as_f - 5.5).abs() < 1e-12, "expected 5.5, got {as_f}");
    }

    #[test]
    fn u64f64_large_whole_12345_decodes_as_12345() {
        let raw: u128 = 12345u128 << 64;
        let (int_part, frac_part) = u64f64_split(raw);
        assert_eq!(int_part, 12345);
        assert_eq!(frac_part, 0);
        assert_eq!(u64f64_to_f64(raw), 12345.0);
    }

    #[test]
    fn u64f64_the_buggy_cast_would_yield_zero_for_whole_numbers() {
        // Documents the bug: casting raw (the u128) to u64 keeps the low
        // half, and the low half is the fractional part. For whole-number
        // shares the fractional part is 0, so the buggy path yields 0.
        let raw: u128 = 5u128 << 64;
        let bug = raw as u64;
        assert_eq!(bug, 0, "bug: whole-number shares collapse to 0");
    }

    #[test]
    fn u64f64_the_buggy_cast_would_yield_2pow63_for_5_5() {
        let raw: u128 = (5u128 << 64) | (1u128 << 63);
        let bug = raw as u64;
        assert_eq!(
            bug,
            9_223_372_036_854_775_808u64,
            "bug: 5.5 shares reads as 2^63 under old decoder"
        );
    }

    // -- parse_stake_info_list: synthetic StakeInfo shape -------------------

    fn synthetic_account(tag: u8) -> SValue<()> {
        // AccountId32 wraps [u8; 32]. Dynamic decode surfaces as an unnamed
        // composite whose first element is a byte-sequence composite of 32
        // u8 primitives.
        let bytes: Vec<SValue<()>> = (0..32)
            .map(|i| SValue::u128((tag.wrapping_add(i as u8)) as u128))
            .collect();
        let inner = SValue {
            value: ValueDef::Composite(Composite::Unnamed(bytes)),
            context: (),
        };
        SValue {
            value: ValueDef::Composite(Composite::Unnamed(vec![inner])),
            context: (),
        }
    }

    fn synthetic_stake_info(tag: u8, netuid: u16, stake: u64) -> SValue<()> {
        // StakeInfo fields in declaration order. Compact<T> is transparent.
        let hotkey = synthetic_account(tag);
        let coldkey = synthetic_account(tag.wrapping_add(64));
        let netuid_v = SValue::u128(netuid as u128);
        let stake_v = SValue::u128(stake as u128);
        let zero = SValue::u128(0);
        let false_v = SValue {
            value: ValueDef::Primitive(Primitive::Bool(false)),
            context: (),
        };
        SValue {
            value: ValueDef::Composite(Composite::Named(vec![
                ("hotkey".to_string(), hotkey),
                ("coldkey".to_string(), coldkey),
                ("netuid".to_string(), netuid_v),
                ("stake".to_string(), stake_v),
                ("locked".to_string(), zero.clone()),
                ("emission".to_string(), zero.clone()),
                ("tao_emission".to_string(), zero.clone()),
                ("drain".to_string(), zero),
                ("is_registered".to_string(), false_v),
            ])),
            context: (),
        }
    }

    #[test]
    fn parse_stake_info_list_extracts_rows() {
        let list = SValue {
            value: ValueDef::Composite(Composite::Unnamed(vec![
                synthetic_stake_info(1, 0, 1_500_000_000),
                synthetic_stake_info(2, 73, 42),
                // zero-stake entry should be filtered out
                synthetic_stake_info(3, 5, 0),
            ])),
            context: (),
        };
        let rows = parse_stake_info_list(&list).expect("parse ok");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].netuid, 0);
        assert_eq!(rows[0].alpha_rao, 1_500_000_000);
        assert_eq!(rows[1].netuid, 73);
        assert_eq!(rows[1].alpha_rao, 42);
        // Sanity: hotkey bytes non-zero, distinct between rows.
        assert_ne!(rows[0].hotkey, rows[1].hotkey);
    }

    #[test]
    fn parse_stake_info_list_rejects_bad_netuid() {
        // netuid that doesn't fit in u16
        let bad = SValue {
            value: ValueDef::Composite(Composite::Unnamed(vec![synthetic_stake_info(
                1,
                0,
                10,
            )])),
            context: (),
        };
        // Corrupt the netuid by building a fresh one with u128::MAX.
        let bad_inner = if let ValueDef::Composite(Composite::Unnamed(ref outer)) = bad.value {
            if let ValueDef::Composite(Composite::Named(ref fields)) = outer[0].value {
                let mut new_fields = fields.clone();
                for field in &mut new_fields {
                    if field.0 == "netuid" {
                        field.1 = SValue::u128(u128::MAX);
                    }
                }
                SValue {
                    value: ValueDef::Composite(Composite::Named(new_fields)),
                    context: (),
                }
            } else {
                unreachable!()
            }
        } else {
            unreachable!()
        };
        let list = SValue {
            value: ValueDef::Composite(Composite::Unnamed(vec![bad_inner])),
            context: (),
        };
        assert!(parse_stake_info_list(&list).is_err());
    }

    #[test]
    fn alpha_rao_to_tao_string_netuid0_identity() {
        // 1.0 alpha at price 1.0 = 1.0 tao
        assert_eq!(alpha_rao_to_tao_string(1_000_000_000, 1.0), "1");
        assert_eq!(alpha_rao_to_tao_string(1_500_000_000, 1.0), "1.5");
    }

    #[test]
    fn alpha_rao_to_tao_string_subnet_at_half_price() {
        // 10 alpha at price 0.5 tao/alpha = 5 tao
        let got = alpha_rao_to_tao_string(10_000_000_000, 0.5);
        assert_eq!(got, "5");
    }

    #[test]
    fn alpha_rao_to_tao_string_handles_zero() {
        assert_eq!(alpha_rao_to_tao_string(0, 0.5), "0");
    }

    // -- resolve_address (pre-existing, kept) ------------------------------

    #[test]
    fn resolve_address_ss58_validates() {
        let valid = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
        let result = resolve_address(None, Some(valid));
        assert!(result.is_ok());
        assert_eq!(result.expect("should resolve"), valid);
    }

    #[test]
    fn resolve_address_invalid_ss58_fails() {
        let invalid = "not-an-address";
        let result = resolve_address(None, Some(invalid));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_address_both_provided_fails() {
        let result = resolve_address(Some("wallet"), Some("5Grw..."));
        assert!(result.is_err());
    }

    #[test]
    fn resolve_address_neither_provided_fails() {
        let result = resolve_address(None, None);
        assert!(result.is_err());
    }

    // -- Sr25519Signer wire-format tripwire ---------------------------------
    //
    // This test exists to catch silent subxt/sp_core API drift. The signer
    // path was hand-rolled in PR #57 when subxt 0.50 dropped `PairSigner`,
    // and at the time of merge the barbarian review verified byte-identical
    // output vs. the old implementation. But neither type-checking nor
    // clippy will notice if a future subxt bump reorders `MultiSignature`
    // variants or changes `sr25519::Signature` layout — the refactor would
    // still compile, and signed extrinsics would silently fail on-chain.
    //
    // The test locks three things:
    //   1. The public key derived from a known seed (catches seed-derivation
    //      drift in sp-core's sr25519 HKDF path).
    //   2. The SCALE variant tag of `subxt::utils::MultiSignature::Sr25519`
    //      (catches variant reordering — Ed25519 = 0, Sr25519 = 1, Ecdsa = 2
    //      per the enum order in subxt-0.50 `utils/multi_signature.rs`).
    //   3. The 64-byte signature body validates against the hard-coded
    //      public key via `sr25519::Pair::verify` (catches any layout or
    //      semantic change in the signature bytes themselves).
    //
    // We cannot assert raw signature bytes because sr25519 signatures are
    // randomised (schnorrkel nonce). Verification closes the loop.
    //
    // If this test fails, DO NOT just re-pin the expected values. First
    // confirm the wire format is actually unchanged by round-tripping
    // against a known-good client, *then* update the pinned values here.
    #[test]
    fn sr25519_signer_wire_format_locked() {
        use sp_core::sr25519;
        use subxt::ext::codec::Encode;
        use subxt::tx::Signer as _;

        // Hard-coded 32-byte seed. Not a well-known dev key — we want the
        // derivation itself under test, not a re-use of //Alice.
        const SEED: [u8; 32] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
        ];

        // The expected sr25519 public key derived from SEED via
        // `sp_core::sr25519::Pair::from_seed`. Locking this catches any
        // change in sp-core's mini-secret → keypair expansion.
        const EXPECTED_PUBKEY_HEX: &str =
            "5e63279eb48e4656a4070ec89346105860d1628bf17c10e76c35f555be5aaf31";

        // Fixed signer payload — the bytes that would normally be the
        // extrinsic signed payload. 32 bytes of 0x42 is simply a fixed
        // input so the verification side of the test is deterministic.
        const SIGNER_PAYLOAD: [u8; 32] = [0x42; 32];

        let pair = sr25519::Pair::from_seed(&SEED);
        let signer = Sr25519Signer::new(pair.clone());

        // (1) Public key lock.
        let derived_pk: [u8; 32] = PairTrait::public(&pair).0;
        assert_eq!(
            hex::encode(derived_pk),
            EXPECTED_PUBKEY_HEX,
            "sr25519 public key derived from fixed seed changed — sp-core derivation drift"
        );

        // (2) SCALE-encoded MultiSignature tripwire. The signer returns a
        // `subxt::utils::MultiSignature`. We SCALE-encode it directly and
        // check:
        //   - byte 0 is the variant tag (must be 0x01 for Sr25519)
        //   - total length is 1 + 64 = 65 bytes (variant tag + sig body)
        let sig = signer.sign(&SIGNER_PAYLOAD);
        let encoded: Vec<u8> = sig.encode();
        assert_eq!(
            encoded.len(),
            65,
            "SCALE-encoded MultiSignature length changed — sig body size or tag width drift"
        );
        assert_eq!(
            encoded[0], 0x01,
            "MultiSignature::Sr25519 variant tag changed — enum variant reorder in subxt"
        );

        // (3) The 64-byte signature body must still verify against the
        // public key under sp-core's sr25519 semantics. This catches any
        // change in the on-wire signature format itself.
        let sig_bytes: [u8; 64] = encoded[1..]
            .try_into()
            .expect("65-byte encoding minus 1-byte tag is 64");
        let sp_sig = sr25519::Signature::from_raw(sig_bytes);
        let sp_pub = sr25519::Public::from_raw(derived_pk);
        assert!(
            <sr25519::Pair as PairTrait>::verify(&sp_sig, SIGNER_PAYLOAD.as_slice(), &sp_pub),
            "SCALE-decoded sig body did not verify — sr25519 signature layout drift"
        );
    }
}

