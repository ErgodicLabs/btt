use std::time::Duration;

use serde::Serialize;
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_core::Pair as PairTrait;

use subxt::ext::scale_value::Value as SValue;

use crate::commands::chain::parse_ss58;
use crate::commands::stake::Sr25519Signer;
use crate::commands::wallet_keys::{decrypt_coldkey_interactive, rao_to_tao_string, tao_to_rao};
use crate::error::BttError;
use crate::rpc;

#[derive(Serialize)]
pub struct TransferResult {
    pub tx_hash: String,
    pub block: String,
    pub from: String,
    pub to: String,
    pub amount_rao: u64,
    pub amount: String,
}

pub async fn transfer(
    endpoint: &str,
    wallet: &str,
    dest: &str,
    amount_tao: f64,
) -> Result<TransferResult, BttError> {
    let amount_rao = tao_to_rao(amount_tao)?;
    if amount_rao == 0 {
        return Err(BttError::invalid_amount(
            "transfer amount must be greater than zero",
        ));
    }

    let dest_bytes = parse_ss58(dest)?;

    let pair = decrypt_coldkey_interactive(wallet)?;
    let from_ss58 = AccountId32::from(PairTrait::public(&pair)).to_ss58check();
    let signer = Sr25519Signer::new(pair);

    let api = rpc::connect(endpoint).await?;

    let tx = subxt::dynamic::tx(
        "Balances",
        "transfer_keep_alive",
        vec![
            SValue::unnamed_variant("Id", [SValue::from_bytes(dest_bytes)]),
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

    Ok(TransferResult {
        tx_hash,
        block: block_hash,
        from: from_ss58,
        to: dest.to_string(),
        amount_rao,
        amount: rao_to_tao_string(amount_rao),
    })
}
