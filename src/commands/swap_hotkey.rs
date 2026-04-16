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
pub struct SwapHotkeyResult {
    pub tx_hash: String,
    pub block: String,
    pub old_hotkey: String,
    pub new_hotkey: String,
    pub coldkey: String,
}

pub async fn swap_hotkey(
    endpoint: &str,
    wallet: &str,
    old_hotkey: &str,
    new_hotkey: &str,
) -> Result<SwapHotkeyResult, BttError> {
    let old_bytes = parse_ss58(old_hotkey)?;
    let new_bytes = parse_ss58(new_hotkey)?;

    let pair = decrypt_coldkey_interactive(wallet)?;
    let coldkey_ss58 =
        sp_core::crypto::AccountId32::from(PairTrait::public(&pair)).to_string();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "SubtensorModule",
        "swap_hotkey",
        vec![
            SValue::from_bytes(old_bytes),
            SValue::from_bytes(new_bytes),
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

    Ok(SwapHotkeyResult {
        tx_hash,
        block: block_hash,
        old_hotkey: old_hotkey.to_string(),
        new_hotkey: new_hotkey.to_string(),
        coldkey: coldkey_ss58,
    })
}
