use std::time::Duration;

use serde::Serialize;
use sp_core::crypto::Ss58Codec;
use sp_core::sr25519;
use sp_core::Pair as PairTrait;
use subxt::dynamic::{At, Value};
use subxt::tx::PairSigner;
use subxt::PolkadotConfig;

use crate::commands::chain::parse_ss58;
use crate::commands::wallet_keys::{
    decrypt_coldkey_interactive, rao_to_tao_string, resolve_coldkey_address, tao_to_rao,
};
use crate::error::BttError;
use crate::rpc;

/// Timeout for staking RPC operations.
const RPC_TIMEOUT: Duration = rpc::RPC_TIMEOUT;

// ── Output types ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct StakeListResult {
    pub address: String,
    pub stakes: Vec<StakeEntry>,
}

#[derive(Serialize)]
pub struct StakeEntry {
    pub hotkey: String,
    pub netuid: u16,
    pub stake_tao: String,
}

#[derive(Serialize)]
pub struct StakeTxResult {
    pub tx_hash: String,
    pub block: String,
    pub action: String,
    pub amount_tao: String,
    pub hotkey: String,
    pub netuid: u16,
}

// ── Commands ──────────────────────────────────────────────────────────────

/// List all stakes for a coldkey address.
///
/// Uses the `SubtensorModule::Alpha` storage map to enumerate stakes.
/// The Alpha storage is a triple map keyed by (hotkey, coldkey, netuid).
/// Since we cannot efficiently iterate a triple map by coldkey alone via
/// the dynamic API without knowing all hotkeys and netuids, we use the
/// runtime API `SubnetInfoRuntimeApi::get_stake_info_for_coldkey` via
/// `state_call` if available, falling back to the `SubtensorModule::Stake`
/// double map (hotkey, coldkey) which gives total stake per hotkey.
pub async fn list(
    endpoint: &str,
    wallet: Option<&str>,
    ss58: Option<&str>,
) -> Result<StakeListResult, BttError> {
    let address = resolve_address(wallet, ss58)?;
    let account_bytes = parse_ss58(&address)?;

    let api = rpc::connect(endpoint).await?;

    // Query the on-chain storage to find all stakes for this coldkey.
    // Strategy: use StakingHotkeys to get the list of hotkeys this coldkey
    // has staked to, then query Alpha for each (hotkey, coldkey, netuid).
    // We iterate over partial keys. This may not return netuid-level granularity,
    // but it gives us the hotkey-level stake amounts.
    let storage = tokio::time::timeout(RPC_TIMEOUT, api.storage().at_latest())
        .await
        .map_err(|_| BttError::query("storage query timed out"))?
        .map_err(|e| BttError::query(format!("failed to get storage: {e}")))?;

    // First approach: try SubtensorModule.Stake partial key iteration
    // SubtensorModule::Stake is a double map (hotkey, coldkey) -> u64
    // We can't efficiently query by coldkey (second key) with partial iteration.
    //
    // Alternative: SubtensorModule::TotalHotkeyStake (map: hotkey -> u64)
    // or SubtensorModule::StakingHotkeys (map: coldkey -> Vec<hotkey>)
    //
    // Best approach for coldkey lookup: use StakingHotkeys to get the list of hotkeys
    // this coldkey has staked to, then query Alpha for each (hotkey, coldkey, netuid).

    let staking_hotkeys_query = subxt::dynamic::storage(
        "SubtensorModule",
        "StakingHotkeys",
        vec![Value::from_bytes(account_bytes.clone())],
    );

    let mut stakes = Vec::new();

    let staking_hotkeys_result = tokio::time::timeout(
        RPC_TIMEOUT,
        storage.fetch(&staking_hotkeys_query),
    )
    .await
    .map_err(|_| BttError::query("StakingHotkeys fetch timed out"))?
    .map_err(|e| BttError::query(format!("failed to fetch StakingHotkeys: {e}")))?;

    if let Some(value) = staking_hotkeys_result {
        let decoded = value
            .to_value()
            .map_err(|e| BttError::parse(format!("failed to decode StakingHotkeys: {e}")))?;

        // The decoded value is a Composite (sequence of AccountId32).
        // Each element is itself a composite of 32 u8 values.
        // Extract them by iterating with .at(index).
        let hotkey_list = extract_account_ids(&decoded);

        // For each hotkey, query Alpha storage for all netuids.
        // Alpha is a triple map: (hotkey, coldkey, netuid) -> u64
        // We iterate over netuids 0..64 (reasonable upper bound for subnet count).
        for hotkey_bytes in &hotkey_list {
            let hotkey_ss58 = sp_core::crypto::AccountId32::new(*hotkey_bytes)
                .to_ss58check();

            for netuid in 0..64u16 {
                let alpha_query = subxt::dynamic::storage(
                    "SubtensorModule",
                    "Alpha",
                    vec![
                        Value::from_bytes(*hotkey_bytes),
                        Value::from_bytes(account_bytes.clone()),
                        Value::u128(netuid as u128),
                    ],
                );

                if let Ok(Some(val)) = storage.fetch(&alpha_query).await {
                    if let Ok(dv) = val.to_value() {
                        if let Some(amount) = dv.as_u128() {
                            if amount > 0 {
                                stakes.push(StakeEntry {
                                    hotkey: hotkey_ss58.clone(),
                                    netuid,
                                    stake_tao: rao_to_tao_string(amount as u64),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // If we got no results from Alpha, try the simpler Stake storage
    // (double map: hotkey, coldkey -> u64, no netuid granularity)
    if stakes.is_empty() {
        if let Some(value) = staking_hotkeys_result_fallback(
            &storage,
            &account_bytes,
        )
        .await?
        {
            stakes = value;
        }
    }

    Ok(StakeListResult {
        address,
        stakes,
    })
}

/// Fallback: query SubtensorModule::Stake for each hotkey found in StakingHotkeys.
async fn staking_hotkeys_result_fallback(
    storage: &subxt::storage::Storage<PolkadotConfig, subxt::OnlineClient<PolkadotConfig>>,
    account_bytes: &[u8],
) -> Result<Option<Vec<StakeEntry>>, BttError> {
    // Re-fetch StakingHotkeys
    let staking_hotkeys_query = subxt::dynamic::storage(
        "SubtensorModule",
        "StakingHotkeys",
        vec![Value::from_bytes(account_bytes)],
    );

    let result = storage
        .fetch(&staking_hotkeys_query)
        .await
        .map_err(|e| BttError::query(format!("failed to fetch StakingHotkeys: {e}")))?;

    let value = match result {
        Some(v) => v,
        None => return Ok(None),
    };

    let decoded = value
        .to_value()
        .map_err(|e| BttError::parse(format!("failed to decode StakingHotkeys: {e}")))?;

    let hotkey_list = extract_account_ids(&decoded);

    let mut stakes = Vec::new();
    for hotkey_bytes in &hotkey_list {
        let hotkey_ss58 =
            sp_core::crypto::AccountId32::new(*hotkey_bytes).to_ss58check();

        let stake_query = subxt::dynamic::storage(
            "SubtensorModule",
            "Stake",
            vec![
                Value::from_bytes(hotkey_bytes),
                Value::from_bytes(account_bytes),
            ],
        );

        if let Ok(Some(val)) = storage.fetch(&stake_query).await {
            if let Ok(dv) = val.to_value() {
                if let Some(amount) = dv.as_u128() {
                    if amount > 0 {
                        stakes.push(StakeEntry {
                            hotkey: hotkey_ss58,
                            netuid: 0, // No netuid info in Stake storage
                            stake_tao: rao_to_tao_string(amount as u64),
                        });
                    }
                }
            }
        }
    }

    if stakes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(stakes))
    }
}

/// Add stake from coldkey to hotkey on a specific subnet.
///
/// Constructs and submits a `SubtensorModule::add_stake(hotkey, netuid, amount_rao)`
/// extrinsic signed by the coldkey.
pub async fn add(
    endpoint: &str,
    wallet: &str,
    hotkey: &str,
    netuid: u16,
    amount_tao: f64,
) -> Result<StakeTxResult, BttError> {
    let amount_rao = tao_to_rao(amount_tao)?;
    if amount_rao == 0 {
        return Err(BttError::invalid_amount("stake amount must be greater than zero"));
    }

    let hotkey_bytes = parse_ss58(hotkey)?;

    // Decrypt coldkey
    let pair = decrypt_coldkey_interactive(wallet)?;
    let signer = PairSigner::<PolkadotConfig, sr25519::Pair>::new(pair);

    let api = rpc::connect(endpoint).await?;

    // Construct the extrinsic
    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "add_stake",
        vec![
            Value::from_bytes(hotkey_bytes),
            Value::u128(netuid as u128),
            Value::u128(amount_rao as u128),
        ],
    );

    // Sign and submit, then wait for inclusion
    let progress = tokio::time::timeout(
        Duration::from_secs(120),
        api.tx().sign_and_submit_then_watch_default(&tx, &signer),
    )
    .await
    .map_err(|_| BttError::submission_failed("transaction submission timed out"))?
    .map_err(|e| BttError::submission_failed(format!("failed to submit transaction: {e}")))?;

    let tx_hash = format!("{:?}", progress.extrinsic_hash());

    let in_block = tokio::time::timeout(
        Duration::from_secs(120),
        progress.wait_for_finalized(),
    )
    .await
    .map_err(|_| BttError::submission_failed("waiting for finalization timed out"))?
    .map_err(|e| BttError::submission_failed(format!("transaction failed: {e}")))?;

    let block_hash = format!("{:?}", in_block.block_hash());

    // Check for success
    in_block
        .wait_for_success()
        .await
        .map_err(|e| BttError::submission_failed(format!("extrinsic failed: {e}")))?;

    Ok(StakeTxResult {
        tx_hash,
        block: block_hash,
        action: "add_stake".to_string(),
        amount_tao: rao_to_tao_string(amount_rao),
        hotkey: hotkey.to_string(),
        netuid,
    })
}

/// Remove stake from hotkey back to coldkey on a specific subnet.
///
/// Constructs and submits a `SubtensorModule::remove_stake(hotkey, netuid, amount_rao)`
/// extrinsic signed by the coldkey.
///
/// If `unstake_all` is true, queries the current stake and unstakes the full amount.
pub async fn remove(
    endpoint: &str,
    wallet: &str,
    hotkey: &str,
    netuid: u16,
    amount_tao: Option<f64>,
    unstake_all: bool,
) -> Result<StakeTxResult, BttError> {
    let hotkey_bytes = parse_ss58(hotkey)?;

    // Decrypt coldkey
    let pair = decrypt_coldkey_interactive(wallet)?;
    let coldkey_ss58 = sp_core::crypto::AccountId32::from(PairTrait::public(&pair)).to_ss58check();
    let coldkey_bytes = parse_ss58(&coldkey_ss58)?;
    let signer = PairSigner::<PolkadotConfig, sr25519::Pair>::new(pair);

    let api = rpc::connect(endpoint).await?;

    let amount_rao = if unstake_all {
        // Query current stake to determine full amount
        let storage = tokio::time::timeout(RPC_TIMEOUT, api.storage().at_latest())
            .await
            .map_err(|_| BttError::query("storage query timed out"))?
            .map_err(|e| BttError::query(format!("failed to get storage: {e}")))?;

        // Try Alpha first (triple map with netuid)
        let alpha_query = subxt::dynamic::storage(
            "SubtensorModule",
            "Alpha",
            vec![
                Value::from_bytes(hotkey_bytes.clone()),
                Value::from_bytes(coldkey_bytes.clone()),
                Value::u128(netuid as u128),
            ],
        );

        let mut found_amount: u64 = 0;

        if let Ok(Some(val)) = storage.fetch(&alpha_query).await {
            if let Ok(dv) = val.to_value() {
                if let Some(amount) = dv.as_u128() {
                    found_amount = amount as u64;
                }
            }
        }

        // Fallback: try Stake storage (no netuid)
        if found_amount == 0 {
            let stake_query = subxt::dynamic::storage(
                "SubtensorModule",
                "Stake",
                vec![
                    Value::from_bytes(hotkey_bytes.clone()),
                    Value::from_bytes(coldkey_bytes),
                ],
            );

            if let Ok(Some(val)) = storage.fetch(&stake_query).await {
                if let Ok(dv) = val.to_value() {
                    if let Some(amount) = dv.as_u128() {
                        found_amount = amount as u64;
                    }
                }
            }
        }

        if found_amount == 0 {
            return Err(BttError::invalid_amount(
                "no stake found for this hotkey/netuid combination",
            ));
        }

        found_amount
    } else {
        let tao = amount_tao.ok_or_else(|| {
            BttError::invalid_amount("--amount is required unless --all is specified")
        })?;
        let rao = tao_to_rao(tao)?;
        if rao == 0 {
            return Err(BttError::invalid_amount("unstake amount must be greater than zero"));
        }
        rao
    };

    // Construct the extrinsic
    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "remove_stake",
        vec![
            Value::from_bytes(hotkey_bytes),
            Value::u128(netuid as u128),
            Value::u128(amount_rao as u128),
        ],
    );

    // Sign and submit
    let progress = tokio::time::timeout(
        Duration::from_secs(120),
        api.tx().sign_and_submit_then_watch_default(&tx, &signer),
    )
    .await
    .map_err(|_| BttError::submission_failed("transaction submission timed out"))?
    .map_err(|e| BttError::submission_failed(format!("failed to submit transaction: {e}")))?;

    let tx_hash = format!("{:?}", progress.extrinsic_hash());

    let in_block = tokio::time::timeout(
        Duration::from_secs(120),
        progress.wait_for_finalized(),
    )
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
        action: "remove_stake".to_string(),
        amount_tao: rao_to_tao_string(amount_rao),
        hotkey: hotkey.to_string(),
        netuid,
    })
}

/// Extract a list of 32-byte AccountId arrays from a decoded dynamic Value.
///
/// The Value from `StakingHotkeys` is a Composite (sequence) where each element
/// is either:
/// - A Composite of 32 u8 values (the AccountId32 bytes), or
/// - A bytes-like value that can be read directly.
///
/// We walk the sequence by index and attempt to extract 32 bytes from each element.
fn extract_account_ids<T>(value: &Value<T>) -> Vec<[u8; 32]> {
    let mut result = Vec::new();
    let mut idx = 0usize;
    while let Some(elem) = value.at(idx) {
        if let Some(bytes) = extract_32_bytes(elem) {
            result.push(bytes);
        }
        idx += 1;
    }
    result
}

/// Try to extract exactly 32 bytes from a Value.
/// Handles both Composite (sequence of u8 values) and direct byte representations.
fn extract_32_bytes<T>(value: &Value<T>) -> Option<[u8; 32]> {
    // Try as a sequence of u8 values
    let mut bytes = Vec::with_capacity(32);
    let mut idx = 0usize;
    while let Some(v) = value.at(idx) {
        if let Some(b) = v.as_u128() {
            if b <= 255 {
                bytes.push(b as u8);
            } else {
                return None;
            }
        } else {
            break;
        }
        idx += 1;
    }

    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Some(arr);
    }

    None
}

/// Resolve an address from either a wallet name or a direct SS58 string.
fn resolve_address(wallet: Option<&str>, ss58: Option<&str>) -> Result<String, BttError> {
    match (wallet, ss58) {
        (Some(w), None) => resolve_coldkey_address(w),
        (None, Some(addr)) => {
            // Validate the SS58 address
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
