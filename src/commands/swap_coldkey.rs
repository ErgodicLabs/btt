use std::time::Duration;

use serde::Serialize;
use sp_core::Pair as PairTrait;
use subxt::ext::scale_value::Value as SValue;

use crate::commands::chain::parse_ss58;
use crate::commands::stake::Sr25519Signer;
use crate::commands::wallet_keys::decrypt_coldkey_interactive;
use crate::error::BttError;
use crate::rpc;

#[derive(Serialize)]
pub struct SwapColdkeyResult {
    pub tx_hash: String,
    pub block: String,
    pub action: String,
    pub old_coldkey: String,
    pub new_coldkey: String,
}

pub async fn announce(
    endpoint: &str,
    wallet: &str,
    new_coldkey_ss58: &str,
) -> Result<SwapColdkeyResult, BttError> {
    let new_bytes = parse_ss58(new_coldkey_ss58)?;

    let pair = decrypt_coldkey_interactive(wallet)?;
    let old_ss58 = sp_core::crypto::AccountId32::from(PairTrait::public(&pair)).to_string();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "schedule_coldkey_swap",
        vec![SValue::from_bytes(new_bytes)],
    );

    let (tx_hash, block_hash) = submit_and_finalize(&api, &tx, &signer).await?;

    Ok(SwapColdkeyResult {
        tx_hash,
        block: block_hash,
        action: "schedule_coldkey_swap".to_string(),
        old_coldkey: old_ss58,
        new_coldkey: new_coldkey_ss58.to_string(),
    })
}

pub async fn execute(
    endpoint: &str,
    wallet: &str,
) -> Result<SwapColdkeyResult, BttError> {
    let pair = decrypt_coldkey_interactive(wallet)?;
    let old_ss58 = sp_core::crypto::AccountId32::from(PairTrait::public(&pair)).to_string();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "execute_coldkey_swap",
        vec![],
    );

    let (tx_hash, block_hash) = submit_and_finalize(&api, &tx, &signer).await?;

    Ok(SwapColdkeyResult {
        tx_hash,
        block: block_hash,
        action: "execute_coldkey_swap".to_string(),
        old_coldkey: old_ss58.clone(),
        new_coldkey: old_ss58,
    })
}

pub async fn clear(
    endpoint: &str,
    wallet: &str,
) -> Result<SwapColdkeyResult, BttError> {
    let pair = decrypt_coldkey_interactive(wallet)?;
    let old_ss58 = sp_core::crypto::AccountId32::from(PairTrait::public(&pair)).to_string();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "cancel_coldkey_swap",
        vec![],
    );

    let (tx_hash, block_hash) = submit_and_finalize(&api, &tx, &signer).await?;

    Ok(SwapColdkeyResult {
        tx_hash,
        block: block_hash,
        action: "cancel_coldkey_swap".to_string(),
        old_coldkey: old_ss58.clone(),
        new_coldkey: String::new(),
    })
}

pub async fn dispute(
    endpoint: &str,
    wallet: &str,
    target_coldkey_ss58: &str,
) -> Result<SwapColdkeyResult, BttError> {
    let target_bytes = parse_ss58(target_coldkey_ss58)?;

    let pair = decrypt_coldkey_interactive(wallet)?;
    let disputer_ss58 = sp_core::crypto::AccountId32::from(PairTrait::public(&pair)).to_string();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "dispute_coldkey_swap",
        vec![SValue::from_bytes(target_bytes)],
    );

    let (tx_hash, block_hash) = submit_and_finalize(&api, &tx, &signer).await?;

    Ok(SwapColdkeyResult {
        tx_hash,
        block: block_hash,
        action: "dispute_coldkey_swap".to_string(),
        old_coldkey: disputer_ss58,
        new_coldkey: target_coldkey_ss58.to_string(),
    })
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
