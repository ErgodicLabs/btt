use std::time::Duration;

use serde::Serialize;
use sp_core::Pair as PairTrait;
use subxt::ext::scale_value::Value as SValue;

use crate::commands::stake::Sr25519Signer;
use crate::commands::wallet_keys::load_hotkey_pair;
use crate::error::BttError;
use crate::rpc;

#[derive(Serialize)]
pub struct WeightsTxResult {
    pub tx_hash: String,
    pub block: String,
    pub action: String,
    pub hotkey: String,
    pub netuid: u16,
}

pub async fn commit(
    endpoint: &str,
    wallet: &str,
    hotkey_name: &str,
    netuid: u16,
    commit_hash: &str,
) -> Result<WeightsTxResult, BttError> {
    let hash_bytes = parse_commit_hash(commit_hash)?;

    let pair = load_hotkey_pair(wallet, hotkey_name)?;
    let hotkey_ss58 = sp_core::crypto::AccountId32::from(PairTrait::public(&pair)).to_string();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "commit_weights",
        vec![
            SValue::u128(netuid as u128),
            SValue::from_bytes(hash_bytes),
        ],
    );

    let (tx_hash, block_hash) = submit_and_finalize(&api, &tx, &signer).await?;

    Ok(WeightsTxResult {
        tx_hash,
        block: block_hash,
        action: "commit_weights".to_string(),
        hotkey: hotkey_ss58,
        netuid,
    })
}

pub struct RevealParams<'a> {
    pub wallet: &'a str,
    pub hotkey: &'a str,
    pub netuid: u16,
    pub uids: &'a [u16],
    pub values: &'a [u16],
    pub salt: &'a [u16],
    pub version_key: u64,
}

pub async fn reveal(
    endpoint: &str,
    params: RevealParams<'_>,
) -> Result<WeightsTxResult, BttError> {
    let uids = params.uids;
    let values = params.values;
    let salt = params.salt;
    if uids.len() != values.len() {
        return Err(BttError::invalid_input(
            "uids and values must have the same length",
        ));
    }

    let pair = load_hotkey_pair(params.wallet, params.hotkey)?;
    let hotkey_ss58 = sp_core::crypto::AccountId32::from(PairTrait::public(&pair)).to_string();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let uid_values: Vec<SValue> = uids.iter().map(|u| SValue::u128(*u as u128)).collect();
    let weight_values: Vec<SValue> = values.iter().map(|v| SValue::u128(*v as u128)).collect();
    let salt_values: Vec<SValue> = salt.iter().map(|s| SValue::u128(*s as u128)).collect();

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "reveal_weights",
        vec![
            SValue::u128(params.netuid as u128),
            SValue::unnamed_composite(uid_values),
            SValue::unnamed_composite(weight_values),
            SValue::unnamed_composite(salt_values),
            SValue::u128(params.version_key as u128),
        ],
    );

    let (tx_hash, block_hash) = submit_and_finalize(&api, &tx, &signer).await?;

    Ok(WeightsTxResult {
        tx_hash,
        block: block_hash,
        action: "reveal_weights".to_string(),
        hotkey: hotkey_ss58,
        netuid: params.netuid,
    })
}

fn parse_commit_hash(hex_str: &str) -> Result<[u8; 32], BttError> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped)
        .map_err(|e| BttError::invalid_input(format!("invalid commit hash hex: {e}")))?;
    if bytes.len() != 32 {
        return Err(BttError::invalid_input(format!(
            "commit hash must be 32 bytes (64 hex chars), got {} bytes",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

async fn submit_and_finalize(
    api: &subxt::OnlineClient<subxt::PolkadotConfig>,
    tx: &subxt::tx::DynamicPayload<Vec<SValue>>,
    signer: &Sr25519Signer,
) -> Result<(String, String), BttError> {
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

    Ok((tx_hash, block_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_commit_hash_valid() {
        let hash = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let result = parse_commit_hash(hash).expect("valid hash");
        assert_eq!(result[31], 1);
        assert_eq!(result[0], 0);
    }

    #[test]
    fn parse_commit_hash_no_prefix() {
        let hash = "0000000000000000000000000000000000000000000000000000000000000001";
        let result = parse_commit_hash(hash).expect("valid hash without prefix");
        assert_eq!(result[31], 1);
    }

    #[test]
    fn parse_commit_hash_wrong_length() {
        let hash = "0x00";
        assert!(parse_commit_hash(hash).is_err());
    }

    #[test]
    fn parse_commit_hash_invalid_hex() {
        let hash = "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";
        assert!(parse_commit_hash(hash).is_err());
    }
}
